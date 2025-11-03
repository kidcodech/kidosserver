package rules

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
)

// RuleEngine manages DNS blocklist rules.
type RuleEngine struct {
	mu        sync.RWMutex
	blocklist map[string]struct{}
}

// New creates an engine from domain list.
func New(domains []string) *RuleEngine {
	eng := &RuleEngine{blocklist: make(map[string]struct{}, len(domains))}
	for _, d := range domains {
		eng.blocklist[normalize(d)] = struct{}{}
	}
	return eng
}

// ShouldBlock reports whether domain must be blocked.
func (r *RuleEngine) ShouldBlock(domain string) bool {
	r.mu.RLock()
	_, ok := r.blocklist[normalize(domain)]
	r.mu.RUnlock()
	return ok
}

// Set replaces the current blocklist.
func (r *RuleEngine) Set(domains []string) {
	m := make(map[string]struct{}, len(domains))
	for _, d := range domains {
		m[normalize(d)] = struct{}{}
	}
	r.mu.Lock()
	r.blocklist = m
	r.mu.Unlock()
}

// List returns current domains.
func (r *RuleEngine) List() []string {
	r.mu.RLock()
	domains := make([]string, 0, len(r.blocklist))
	for d := range r.blocklist {
		domains = append(domains, d)
	}
	r.mu.RUnlock()
	return domains
}

// LoadFromFile loads blocklist from JSON file.
func (r *RuleEngine) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read blocklist: %w", err)
	}
	var domains []string
	if err := json.Unmarshal(data, &domains); err != nil {
		return fmt.Errorf("parse blocklist: %w", err)
	}
	r.Set(domains)
	return nil
}

// SaveToFile writes blocklist to JSON file.
func (r *RuleEngine) SaveToFile(path string) error {
	r.mu.RLock()
	domains := make([]string, 0, len(r.blocklist))
	for d := range r.blocklist {
		domains = append(domains, d)
	}
	r.mu.RUnlock()
	data, err := json.MarshalIndent(domains, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize blocklist: %w", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write blocklist: %w", err)
	}
	return nil
}

func normalize(domain string) string {
	if len(domain) == 0 {
		return domain
	}
	// Very basic normalization: lowercase and trim trailing dot.
	if domain[len(domain)-1] == '.' {
		domain = domain[:len(domain)-1]
	}
	return lowerASCII(domain)
}

func lowerASCII(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}
