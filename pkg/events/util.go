package events

import "strings"

// BuildEndpoint converts a listen address (" :8080" or "127.0.0.1:8080")
// and path into a usable HTTP URL.
func BuildEndpoint(listen, path string) string {
	addr := listen
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		addr = "http://" + addr
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return strings.TrimSuffix(addr, "/") + path
}
