package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"net"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/kidos/kidosserver/pkg/config"
	"github.com/kidos/kidosserver/pkg/events"
	"github.com/kidos/kidosserver/pkg/logging"
)

type pairStats struct {
	internal string
	external string
	category string
	incoming uint64
	outgoing uint64
	domain   string
}

func main() {
	ifaceName := flag.String("iface", "kidos", "monitor interface")
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	cfg, err := config.Load(filepath.Join("data", "config.json"))
	if err != nil {
		logging.Fatalf("load config: %v", err)
	}

	publisher := events.NewHTTPPublisher(events.BuildEndpoint(cfg.Web.Listen, "/api/events"))
	defer publisher.Close()
	go publisher.Run(ctx)

	if err := monitorLoop(ctx, *ifaceName, publisher); err != nil && !errors.Is(err, context.Canceled) {
		logging.Fatalf("monitor error: %v", err)
	}
}

func monitorLoop(ctx context.Context, iface string, publisher *events.HTTPPublisher) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return err
	}

	if err := netlink.LinkSetUp(link); err != nil {
		logging.Errorf("link up %s: %v", iface, err)
	}

	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	sa := &unix.SockaddrLinklayer{Ifindex: link.Attrs().Index, Protocol: htons(unix.ETH_P_ALL)}
	if err := unix.Bind(fd, sa); err != nil {
		return err
	}

	buf := make([]byte, 65536)
	pairCounts := make(map[string]*pairStats)
	dnsCache := make(map[string]string)
	lastPublish := time.Now()

	logging.Infof("monitor reading packets on %s (ifindex=%d)", iface, link.Attrs().Index)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		pfds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		if _, err := unix.Poll(pfds, -1); err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return err
		}
		if pfds[0].Revents&unix.POLLIN == 0 {
			continue
		}

		n, _, err := unix.Recvfrom(fd, buf, 0)
		if err != nil {
			if errors.Is(err, syscall.EINTR) {
				continue
			}
			return err
		}
		if n <= 0 {
			continue
		}

		frame := buf[:n]
		maybeCacheDNS(frame, dnsCache)

		src, dst := extractIPs(frame)
		if src != "" && dst != "" {
			updatePairCounts(pairCounts, src, dst, dnsCache)
		}

		if time.Since(lastPublish) >= 2*time.Second {
			publishPairCounts(publisher, pairCounts)
			lastPublish = time.Now()
		}
	}
}

func publishPairCounts(publisher *events.HTTPPublisher, counts map[string]*pairStats) {
	if len(counts) == 0 {
		return
	}
	out := make([]events.PairCount, 0, len(counts))
	for _, stats := range counts {
		out = append(out, events.PairCount{
			Category:       stats.category,
			Internal:       stats.internal,
			External:       stats.external,
			ExternalDomain: stats.domain,
			Incoming:       stats.incoming,
			Outgoing:       stats.outgoing,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		totalI := out[i].Incoming + out[i].Outgoing
		totalJ := out[j].Incoming + out[j].Outgoing
		if totalI == totalJ {
			return out[i].Internal+"->"+out[i].External < out[j].Internal+"->"+out[j].External
		}
		return totalI > totalJ
	})

	publisher.Publish(events.Event{
		Kind:       "ip_pair_summary",
		Timestamp:  time.Now().UTC(),
		PairCounts: out,
	})
}

func updatePairCounts(counts map[string]*pairStats, src, dst string, dnsCache map[string]string) {
	key, internalIP, externalIP, category, direction := canonicalPair(src, dst)
	if key == "" {
		return
	}
	stats := counts[key]
	if stats == nil {
		stats = &pairStats{internal: internalIP, external: externalIP, category: category}
		counts[key] = stats
	}
	switch direction {
	case "incoming":
		stats.incoming++
	case "outgoing":
		stats.outgoing++
	}
	if domain := dnsCache[externalIP]; domain != "" {
		stats.domain = domain
	}
}

func canonicalPair(src, dst string) (key, internal, external, category, direction string) {
	srcPrivate := isPrivateIP(src)
	dstPrivate := isPrivateIP(dst)

	switch {
	case srcPrivate && !dstPrivate:
		internal, external = src, dst
		category = "external"
		direction = "outgoing"
	case !srcPrivate && dstPrivate:
		internal, external = dst, src
		category = "external"
		direction = "incoming"
	case srcPrivate && dstPrivate:
		category = "internal"
		if src <= dst {
			internal, external = src, dst
			direction = "outgoing"
		} else {
			internal, external = dst, src
			direction = "incoming"
		}
	default:
		category = "external"
		if src <= dst {
			internal, external = src, dst
			direction = "outgoing"
		} else {
			internal, external = dst, src
			direction = "incoming"
		}
	}

	key = category + "|" + internal + "|" + external
	return
}

func maybeCacheDNS(frame []byte, cache map[string]string) {
	if len(frame) < 14 {
		return
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	switch etherType {
	case unix.ETH_P_IP:
		parseDNSv4(frame, cache)
	case unix.ETH_P_IPV6:
		parseDNSv6(frame, cache)
	}
}

func parseDNSv4(frame []byte, cache map[string]string) {
	if len(frame) < 34 {
		return
	}
	headerLen := int(frame[14]&0x0F) * 4
	if headerLen < 20 || len(frame) < 14+headerLen+8 {
		return
	}
	proto := frame[23]
	if proto != 17 { // UDP
		return
	}
	transportOffset := 14 + headerLen
	if len(frame) < transportOffset+8 {
		return
	}
	srcPort := binary.BigEndian.Uint16(frame[transportOffset : transportOffset+2])
	dstPort := binary.BigEndian.Uint16(frame[transportOffset+2 : transportOffset+4])
	udpLen := int(binary.BigEndian.Uint16(frame[transportOffset+4 : transportOffset+6]))
	if udpLen < 8 || len(frame) < transportOffset+udpLen {
		return
	}
	payload := frame[transportOffset+8 : transportOffset+udpLen]
	parseDNSPayload(srcPort, dstPort, payload, cache)
}

func parseDNSv6(frame []byte, cache map[string]string) {
	const ipv6HeaderLen = 40
	if len(frame) < 14+ipv6HeaderLen+8 {
		return
	}
	nextHeader := frame[14+6]
	if nextHeader != 17 { // UDP
		return
	}
	transportOffset := 14 + ipv6HeaderLen
	srcPort := binary.BigEndian.Uint16(frame[transportOffset : transportOffset+2])
	dstPort := binary.BigEndian.Uint16(frame[transportOffset+2 : transportOffset+4])
	udpLen := int(binary.BigEndian.Uint16(frame[transportOffset+4 : transportOffset+6]))
	if udpLen < 8 || len(frame) < transportOffset+udpLen {
		return
	}
	payload := frame[transportOffset+8 : transportOffset+udpLen]
	parseDNSPayload(srcPort, dstPort, payload, cache)
}

func parseDNSPayload(srcPort, dstPort uint16, payload []byte, cache map[string]string) {
	if srcPort != 53 || len(payload) == 0 {
		return
	}
	var msg mdns.Msg
	if err := msg.Unpack(payload); err != nil {
		return
	}
	if len(msg.Answer) == 0 || len(msg.Question) == 0 {
		return
	}
	domain := strings.TrimSuffix(msg.Question[0].Name, ".")
	if domain == "" {
		return
	}
	for _, ans := range msg.Answer {
		switch rr := ans.(type) {
		case *mdns.A:
			cache[rr.A.String()] = domain
		case *mdns.AAAA:
			cache[rr.AAAA.String()] = domain
		}
	}
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		switch {
		case ip4[0] == 10:
			return true
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return true
		case ip4[0] == 192 && ip4[1] == 168:
			return true
		case ip4[0] == 169 && ip4[1] == 254:
			return true
		}
	}
	return false
}

func extractIPs(frame []byte) (string, string) {
	if len(frame) < 14 {
		return "", ""
	}

	etherType := binary.BigEndian.Uint16(frame[12:14])
	switch etherType {
	case unix.ETH_P_IP:
		if len(frame) < 34 {
			return "", ""
		}
		src := net.IPv4(frame[26], frame[27], frame[28], frame[29])
		dst := net.IPv4(frame[30], frame[31], frame[32], frame[33])
		return src.String(), dst.String()
	case unix.ETH_P_IPV6:
		if len(frame) < 54 {
			return "", ""
		}
		src := make(net.IP, net.IPv6len)
		dst := make(net.IP, net.IPv6len)
		copy(src, frame[22:38])
		copy(dst, frame[38:54])
		return src.String(), dst.String()
	default:
		return "", ""
	}
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}
