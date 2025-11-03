package events

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// HTTPPublisher asynchronously forwards events to an HTTP endpoint.
type HTTPPublisher struct {
	client    *http.Client
	endpoint  string
	queue     chan Event
	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewHTTPPublisher creates a publisher targeting the given endpoint.
func NewHTTPPublisher(endpoint string) *HTTPPublisher {
	return &HTTPPublisher{
		client:   &http.Client{Timeout: 5 * time.Second},
		endpoint: endpoint,
		queue:    make(chan Event, 256),
	}
}

// Publish enqueues an event for delivery; drops silently when the queue is full.
func (p *HTTPPublisher) Publish(ev Event) {
	select {
	case p.queue <- ev:
	default:
	}
}

// Run pumps events to the HTTP endpoint until the context is cancelled.
func (p *HTTPPublisher) Run(ctx context.Context) {
	p.wg.Add(1)
	defer p.wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-p.queue:
			if !ok {
				return
			}
			_ = p.send(ev)
		}
	}
}

// Close stops the publisher and waits for outstanding events to flush.
func (p *HTTPPublisher) Close() {
	p.closeOnce.Do(func() {
		close(p.queue)
		p.wg.Wait()
	})
}

func (p *HTTPPublisher) send(ev Event) error {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	buf, err := json.Marshal(ev)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, p.endpoint, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("event publish status %s", resp.Status)
	}
	return nil
}
