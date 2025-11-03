package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"mime"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"

	"github.com/kidos/kidosserver/pkg/config"
	"github.com/kidos/kidosserver/pkg/events"
	"github.com/kidos/kidosserver/pkg/logging"
	"github.com/kidos/kidosserver/pkg/rules"
)

type apiServer struct {
	cfgPath string
	cfg     config.Config
	rules   *rules.RuleEngine
	bus     *events.Bus
	history []events.Event
	mu      sync.RWMutex
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func main() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	cfgPath := filepath.Join("data", "config.json")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		logging.Fatalf("load config: %v", err)
	}

	// Ensure common static types resolve correctly regardless of system mime settings.
	_ = mime.AddExtensionType(".js", "application/javascript")
	_ = mime.AddExtensionType(".mjs", "application/javascript")
	_ = mime.AddExtensionType(".css", "text/css")

	ruleEngine := rules.New(cfg.DNS.Blocklist)
	bus := events.NewBus()
	defer bus.Close()

	api := &apiServer{
		cfgPath: cfgPath,
		cfg:     cfg,
		rules:   ruleEngine,
		bus:     bus,
		history: make([]events.Event, 0, 256),
	}

	r := mux.NewRouter()
	r.HandleFunc("/api/rules", api.handleListRules).Methods(http.MethodGet)
	r.HandleFunc("/api/rules", api.handleSetRules).Methods(http.MethodPost)
	r.HandleFunc("/api/events", api.handleListEvents).Methods(http.MethodGet)
	r.HandleFunc("/api/events", api.handlePostEvent).Methods(http.MethodPost)
	r.HandleFunc("/ws/dns", api.handleDNSStream)

	// Serve static assets with proper base path
	staticHandler := http.StripPrefix("/static/", http.FileServer(http.Dir("public")))
	r.PathPrefix("/static/").Handler(staticHandler)

	// Serve main page
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("public")))

	srv := &http.Server{
		Addr:    cfg.Web.Listen,
		Handler: r,
	}

	go func() {
		logging.Infof("web server listening on %s", cfg.Web.Listen)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logging.Fatalf("http server: %v", err)
		}
	}()

	<-sigCh
	logging.Infof("shutdown requested")
	if err := srv.Close(); err != nil {
		logging.Errorf("http server close: %v", err)
	}
}

func (a *apiServer) handleListRules(w http.ResponseWriter, r *http.Request) {
	resp := map[string]any{
		"domains": a.rules.List(),
	}
	writeJSON(w, http.StatusOK, resp)
}

type setRulesRequest struct {
	Domains []string `json:"domains"`
}

func (a *apiServer) handleSetRules(w http.ResponseWriter, r *http.Request) {
	var req setRulesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	a.rules.Set(req.Domains)
	a.cfg.DNS.Blocklist = req.Domains
	if err := config.Save(a.cfgPath, a.cfg); err != nil {
		logging.Errorf("save config: %v", err)
	}
	a.recordEvent(events.Event{
		Kind:      "control",
		Timestamp: time.Now().UTC(),
		Action:    "rules-update",
		Reason:    fmt.Sprintf("%d domains", len(req.Domains)),
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
}

func (a *apiServer) handleDNSStream(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logging.Errorf("upgrade websocket: %v", err)
		return
	}

	ch := a.bus.Subscribe()
	defer a.bus.Unsubscribe(ch)
	defer conn.Close()

	snapshot := a.snapshot()
	if err := conn.WriteJSON(map[string]any{"kind": "snapshot", "events": snapshot}); err != nil {
		logging.Errorf("ws snapshot: %v", err)
		return
	}

	for ev := range ch {
		if err := conn.WriteJSON(ev); err != nil {
			logging.Errorf("ws write: %v", err)
			return
		}
	}
}

func (a *apiServer) handleListEvents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"events": a.snapshot()})
}

func (a *apiServer) handlePostEvent(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	var ev events.Event
	if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	a.recordEvent(ev)
	writeJSON(w, http.StatusAccepted, map[string]any{"status": "ok"})
}

func (a *apiServer) recordEvent(ev events.Event) {
	a.mu.Lock()
	const limit = 512
	a.history = append(a.history, ev)
	if len(a.history) > limit {
		a.history = a.history[len(a.history)-limit:]
	}
	a.mu.Unlock()

	if a.bus != nil {
		a.bus.Publish(ev)
	}
}

func (a *apiServer) snapshot() []events.Event {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]events.Event, len(a.history))
	copy(out, a.history)
	return out
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
