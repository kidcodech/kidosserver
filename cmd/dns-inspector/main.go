package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/kidos/kidosserver/pkg/config"
	"github.com/kidos/kidosserver/pkg/dns"
	"github.com/kidos/kidosserver/pkg/events"
	"github.com/kidos/kidosserver/pkg/logging"
	"github.com/kidos/kidosserver/pkg/rules"
)

const (
	queueID      = uint32(0)
	fillPollMS   = 1000
	frameCount   = 4096
	frameSize    = 2048
	fillRingSize = 2048
	compRingSize = 2048
	rxRingSize   = 1024
	txRingSize   = 1024
)

const xskMapName = "xsk_map"

// Magic value to mark processed packets (must match BPF code)
const KidosMagic = 0x4B494453 // "KIDS" in hex

type packetMeta struct {
	magic uint32
}

type inspector struct {
	iface     *net.Interface
	xskMap    *ebpf.Map
	socket    *xdp.Socket
	publisher *events.HTTPPublisher
	rules     *rules.RuleEngine
	frameLen  uint32
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg, err := config.Load(filepath.Join("data", "config.json"))
	if err != nil {
		logging.Fatalf("load config: %v", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		logging.Errorf("increase rlimit: %v", err)
	}

	iface, err := net.InterfaceByName(cfg.Interfaces.Physical)
	if err != nil {
		logging.Fatalf("lookup interface %s: %v", cfg.Interfaces.Physical, err)
	}

	publisher := events.NewHTTPPublisher(events.BuildEndpoint(cfg.Web.Listen, "/api/events"))
	defer publisher.Close()
	go publisher.Run(ctx)

	engine := rules.New(cfg.DNS.Blocklist)

	ins, err := newInspector(iface, engine, publisher)
	if err != nil {
		logging.Fatalf("init inspector: %v", err)
	}
	defer ins.Close()

	logging.Infof("dns inspector ready on %s", iface.Name)

	if err := ins.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		logging.Errorf("run inspector: %v", err)
	}
}

func newInspector(iface *net.Interface, engine *rules.RuleEngine, publisher *events.HTTPPublisher) (*inspector, error) {
	xskMap, err := findKernelMap(xskMapName)
	if err != nil {
		return nil, err
	}

	sockOpts := xdp.SocketOptions{
		NumFrames:              frameCount,
		FrameSize:              frameSize,
		FillRingNumDescs:       fillRingSize,
		CompletionRingNumDescs: compRingSize,
		RxRingNumDescs:         rxRingSize,
		TxRingNumDescs:         txRingSize,
	}

	sock, err := xdp.NewSocket(iface.Index, int(queueID), &sockOpts)
	if err != nil {
		xskMap.Close()
		return nil, fmt.Errorf("create xdp socket: %w", err)
	}

	key := queueID
	fd := uint32(sock.FD())
	if err := xskMap.Update(&key, &fd, ebpf.UpdateAny); err != nil {
		sock.Close()
		xskMap.Close()
		return nil, fmt.Errorf("register xsk fd: %w", err)
	}

	initial := sock.GetDescs(sock.NumFreeFillSlots())
	if len(initial) > 0 {
		sock.Fill(initial)
	}

	return &inspector{
		iface:     iface,
		xskMap:    xskMap,
		socket:    sock,
		publisher: publisher,
		rules:     engine,
		frameLen:  uint32(frameSize),
	}, nil
}

func findKernelMap(target string) (*ebpf.Map, error) {
	var start ebpf.MapID
	for {
		id, err := ebpf.MapGetNextID(start)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("kernel map %s not found", target)
			}
			return nil, fmt.Errorf("iterate maps: %w", err)
		}

		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			return nil, fmt.Errorf("open map id %d: %w", id, err)
		}

		info, err := m.Info()
		if err != nil {
			m.Close()
			return nil, fmt.Errorf("map info id %d: %w", id, err)
		}

		if info.Name == target {
			return m, nil
		}

		m.Close()
		start = id
	}
}

func (i *inspector) Close() {
	key := queueID
	if i.xskMap != nil {
		_ = i.xskMap.Delete(&key)
		i.xskMap.Close()
		i.xskMap = nil
	}
	if i.socket != nil {
		i.socket.Close()
		i.socket = nil
	}
}

// addMagicFlag sets the magic flag in packet metadata to prevent reprocessing
func (i *inspector) addMagicFlag(desc xdp.Desc) {
	frame := i.socket.GetFrame(desc)
	if len(frame) < 34 {
		return
	}

	// Ethernet header (14 bytes) + IPv4 check
	if frame[12] != 0x08 || frame[13] != 0x00 {
		return
	}

	ipHeader := frame[14:]
	if len(ipHeader) < 20 {
		return
	}
	headerLen := int(ipHeader[0]&0x0F) * 4
	if headerLen < 20 || len(ipHeader) < headerLen {
		return
	}

	magic := uint16(KidosMagic & 0xFFFF)
	ipHeader[4] = byte(magic >> 8)
	ipHeader[5] = byte(magic)
	ipHeader[10] = 0
	ipHeader[11] = 0

	csum := ipv4Checksum(ipHeader[:headerLen])
	ipHeader[10] = byte(csum >> 8)
	ipHeader[11] = byte(csum)
}

func (i *inspector) Run(ctx context.Context) error {
	allow := make([]xdp.Desc, 0, 256)
	reuse := make([]xdp.Desc, 0, 256)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if free := i.socket.NumFreeFillSlots(); free > 0 {
			descs := i.socket.GetDescs(free)
			if len(descs) > 0 {
				i.socket.Fill(descs)
			}
		}

		numRx, _, err := i.socket.Poll(fillPollMS)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return fmt.Errorf("poll xdp: %w", err)
		}
		if numRx == 0 {
			continue
		}

		rxDescs := i.socket.Receive(numRx)
		if len(rxDescs) == 0 {
			continue
		}

		allow = allow[:0]
		reuse = reuse[:0]
		now := time.Now().UTC()

		for _, desc := range rxDescs {
			frame := i.socket.GetFrame(desc)
			if int(desc.Len) <= len(frame) {
				frame = frame[:desc.Len]
			}

			pkt, err := dns.Parse(frame)
			if err != nil {
				allow = append(allow, desc)
				continue
			}

			ev := events.Event{
				Kind:          "dns",
				Timestamp:     now,
				SourceIP:      pkt.SourceIP.String(),
				DestinationIP: pkt.Destination.String(),
				Transport:     pkt.Transport,
				Direction:     pkt.Direction,
				Domain:        pkt.Domain,
			}

			if pkt.Direction == "query" && pkt.Domain != "" && i.rules.ShouldBlock(pkt.Domain) {
				ev.Action = "block"
				ev.Reason = "domain blocked"
				i.publisher.Publish(ev)

				desc.Len = i.frameLen
				reuse = append(reuse, desc)
				continue
			}

			ev.Action = "allow"
			ev.Reason = "passed"
			i.publisher.Publish(ev)
			allow = append(allow, desc)
		}

		// For allowed packets: add magic flag and retransmit
		if len(allow) > 0 {
			for idx := range allow {
				i.addMagicFlag(allow[idx])
			}
			i.socket.Transmit(allow)
		}

		// For blocked packets: just consume them (don't retransmit = DROP)
		if len(reuse) > 0 {
			for idx := range reuse {
				reuse[idx].Len = i.frameLen
			}
			i.socket.Fill(reuse)
		}

		if completed := i.socket.NumCompleted(); completed > 0 {
			i.socket.Complete(completed)
		}
	}
}

func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	if len(header)%2 == 1 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
