package dns

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"

	mdns "github.com/miekg/dns"
)

// ErrNotDNS is returned when the frame does not contain a DNS payload.
var ErrNotDNS = errors.New("not dns")

// Packet captures metadata extracted from a DNS frame.
type Packet struct {
	Message     *mdns.Msg
	Domain      string
	SourceIP    net.IP
	Destination net.IP
	SourcePort  uint16
	DestPort    uint16
	Transport   string
	Direction   string
}

// Parse attempts to decode a raw Ethernet frame into DNS metadata.
func Parse(frame []byte) (*Packet, error) {
	if len(frame) < 14 {
		return nil, ErrNotDNS
	}

	etherType := binary.BigEndian.Uint16(frame[12:14])
	if etherType != 0x0800 { // IPv4 only
		return nil, ErrNotDNS
	}

	if len(frame) < 34 {
		return nil, ErrNotDNS
	}

	ipHeaderLen := int(frame[14]&0x0F) * 4
	if ipHeaderLen < 20 {
		return nil, ErrNotDNS
	}

	totalHeader := 14 + ipHeaderLen
	if len(frame) < totalHeader {
		return nil, ErrNotDNS
	}

	proto := frame[23]
	if proto != 17 { // UDP only for now
		return nil, ErrNotDNS
	}

	udpOffset := totalHeader
	if len(frame) < udpOffset+8 {
		return nil, ErrNotDNS
	}

	srcPort := binary.BigEndian.Uint16(frame[udpOffset : udpOffset+2])
	dstPort := binary.BigEndian.Uint16(frame[udpOffset+2 : udpOffset+4])
	if srcPort != 53 && dstPort != 53 {
		return nil, ErrNotDNS
	}

	udpLen := int(binary.BigEndian.Uint16(frame[udpOffset+4 : udpOffset+6]))
	if udpLen < 8 || len(frame) < udpOffset+udpLen {
		return nil, ErrNotDNS
	}

	payload := frame[udpOffset+8 : udpOffset+udpLen]
	if len(payload) == 0 {
		return nil, ErrNotDNS
	}

	var msg mdns.Msg
	if err := msg.Unpack(payload); err != nil {
		return nil, err
	}

	domain := ""
	if len(msg.Question) > 0 {
		domain = normalize(msg.Question[0].Name)
	}

	direction := "query"
	if srcPort == 53 {
		direction = "response"
	}

	return &Packet{
		Message:     &msg,
		Domain:      domain,
		SourceIP:    net.IP(frame[26:30]).To4(),
		Destination: net.IP(frame[30:34]).To4(),
		SourcePort:  srcPort,
		DestPort:    dstPort,
		Transport:   "udp",
		Direction:   direction,
	}, nil
}

func normalize(domain string) string {
	domain = strings.TrimSuffix(domain, ".")
	return strings.ToLower(domain)
}
