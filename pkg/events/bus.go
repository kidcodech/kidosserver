package events

import (
	"sync"
	"time"
)

// Event models a network-related event surfaced to the UI.
type Event struct {
	Kind            string      `json:"kind"`
	Timestamp       time.Time   `json:"timestamp"`
	SourceIP        string      `json:"sourceIp,omitempty"`
	DestinationIP   string      `json:"destinationIp,omitempty"`
	Transport       string      `json:"transport,omitempty"`
	Direction       string      `json:"direction,omitempty"`
	Domain          string      `json:"domain,omitempty"`
	Action          string      `json:"action,omitempty"`
	Reason          string      `json:"reason,omitempty"`
	Info            string      `json:"info,omitempty"`
	SourcePort      uint16      `json:"sourcePort,omitempty"`
	DestinationPort uint16      `json:"destinationPort,omitempty"`
	Bytes           uint32      `json:"bytes,omitempty"`
	PairCounts      []PairCount `json:"pairCounts,omitempty"`
}

// PairCount captures packet totals between a source and destination IP.
type PairCount struct {
    Category string `json:"category"`
    Internal string `json:"internal"`
    External string `json:"external"`
    ExternalDomain string `json:"externalDomain,omitempty"`
    Incoming uint64 `json:"incoming"`
    Outgoing uint64 `json:"outgoing"`
}

// Bus is a simple pub/sub for events.
type Bus struct {
	mu     sync.RWMutex
	subs   map[chan Event]struct{}
	closed bool
}

// NewBus creates a new event bus.
func NewBus() *Bus {
	return &Bus{subs: make(map[chan Event]struct{})}
}

// Subscribe returns a channel to receive events.
func (b *Bus) Subscribe() chan Event {
	ch := make(chan Event, 64)
	b.mu.Lock()
	if b.closed {
		close(ch)
	} else {
		b.subs[ch] = struct{}{}
	}
	b.mu.Unlock()
	return ch
}

// Unsubscribe removes and closes the channel.
func (b *Bus) Unsubscribe(ch chan Event) {
	if ch == nil {
		return
	}
	b.mu.Lock()
	if _, ok := b.subs[ch]; ok {
		delete(b.subs, ch)
		close(ch)
	}
	b.mu.Unlock()
}

// Publish sends an event to all subscribers.
func (b *Bus) Publish(ev Event) {
	b.mu.RLock()
	for ch := range b.subs {
		select {
		case ch <- ev:
		default:
		}
	}
	b.mu.RUnlock()
}

// Close shuts down and closes all subscriber channels.
func (b *Bus) Close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	for ch := range b.subs {
		close(ch)
	}
	b.subs = nil
	b.closed = true
	b.mu.Unlock()
}
