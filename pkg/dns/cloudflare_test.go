package dns

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// mockCF is an in-memory Cloudflare API surface sufficient to exercise SyncRecords.
type mockCF struct {
	mu       sync.Mutex
	records  map[string]cfRecord // keyed by record name ("@"/"*")
	requests []mockReq
}

type mockReq struct {
	Method string
	Path   string
	Body   string
}

func newMockCF() *mockCF {
	return &mockCF{records: map[string]cfRecord{}}
}

func (m *mockCF) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m.mu.Lock()
		m.requests = append(m.requests, mockReq{r.Method, r.URL.Path, string(body)})
		m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")

		// List zones.
		if r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/zones") && !strings.Contains(r.URL.Path, "dns_records") {
			json.NewEncoder(w).Encode(cfEnvelope{
				Success: true,
				Result:  mustJSON([]cfZone{{ID: "zone123", Name: "evilpikin.com"}}),
			})
			return
		}

		// List dns_records (no stored record => empty).
		if r.Method == "GET" && strings.Contains(r.URL.Path, "dns_records") {
			m.mu.Lock()
			name := r.URL.Query().Get("name")
			rec, ok := m.records[name]
			m.mu.Unlock()
			if !ok {
				json.NewEncoder(w).Encode(cfEnvelope{Success: true, Result: mustJSON([]cfRecord{})})
				return
			}
			json.NewEncoder(w).Encode(cfEnvelope{Success: true, Result: mustJSON([]cfRecord{rec})})
			return
		}

		// Create.
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "dns_records") {
			var in cfRecord
			json.Unmarshal(body, &in)
			// Cloudflare stores root as FQDN, wildcard as "*".
			stored := in.Name
			if stored == "" {
				stored = "evilpikin.com"
			}
			m.mu.Lock()
			m.records[stored] = cfRecord{ID: "rec-" + stored, Type: "A", Name: stored, Content: in.Content, TTL: in.TTL, Proxied: in.Proxied}
			m.mu.Unlock()
			json.NewEncoder(w).Encode(cfEnvelope{Success: true, Result: mustJSON(cfRecord{ID: "rec-" + stored})})
			return
		}

		// Update (PATCH).
		if r.Method == "PATCH" {
			var in cfRecord
			json.Unmarshal(body, &in)
			m.mu.Lock()
			for k, rec := range m.records {
				if strings.HasSuffix(r.URL.Path, rec.ID) {
					rec.Content = in.Content
					rec.TTL = in.TTL
					rec.Proxied = in.Proxied
					m.records[k] = rec
				}
			}
			m.mu.Unlock()
			json.NewEncoder(w).Encode(cfEnvelope{Success: true, Result: mustJSON(cfRecord{ID: "rec"})})
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}
}

func mustJSON(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// writeSeededRecord seeds an existing (drifted) record so SyncRecords must update it.
func (m *mockCF) seed(name, content string, ttl int, proxied bool) {
	m.mu.Lock()
	m.records[name] = cfRecord{ID: "rec-" + name, Type: "A", Name: name, Content: content, TTL: ttl, Proxied: proxied}
	m.mu.Unlock()
}

func TestSyncRecordsCreates(t *testing.T) {
	mock := newMockCF()
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	m := NewDNSManager("tok", "evilpikin.com", "203.0.113.10")
	m.APIBase = srv.URL

	if err := m.SyncRecords(); err != nil {
		t.Fatalf("SyncRecords: %v", err)
	}

	mock.mu.Lock()
	root := mock.records["evilpikin.com"]
	wild := mock.records["*"]
	mock.mu.Unlock()

	if root.Content != "203.0.113.10" || root.TTL != 60 || root.Proxied {
		t.Fatalf("root record wrong: %+v", root)
	}
	if wild.Content != "203.0.113.10" || wild.TTL != 60 || wild.Proxied {
		t.Fatalf("wildcard record wrong: %+v", wild)
	}
}

func TestSyncRecordsUpdatesDrift(t *testing.T) {
	mock := newMockCF()
	mock.seed("evilpikin.com", "1.2.3.4", 300, true) // drifted: wrong IP, TTL, proxied
	mock.seed("*", "1.2.3.4", 300, false)
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	m := NewDNSManager("tok", "evilpikin.com", "203.0.113.10")
	m.APIBase = srv.URL
	if err := m.SyncRecords(); err != nil {
		t.Fatalf("SyncRecords: %v", err)
	}

	mock.mu.Lock()
	root := mock.records["evilpikin.com"]
	mock.mu.Unlock()
	if root.Content != "203.0.113.10" || root.TTL != 60 || root.Proxied {
		t.Fatalf("root not corrected: %+v", root)
	}
}

func TestSyncRecordsSendsCorrectPayload(t *testing.T) {
	mock := newMockCF()
	srv := httptest.NewServer(mock.handler())
	defer srv.Close()

	m := NewDNSManager("tok", "evilpikin.com", "203.0.113.10")
	m.APIBase = srv.URL
	_ = m.SyncRecords()

	for _, r := range mock.requests {
		if r.Method == "POST" {
			if !strings.Contains(r.Body, `"ttl":60`) || !strings.Contains(r.Body, `"proxied":false`) || !strings.Contains(r.Body, `"203.0.113.10"`) {
				t.Fatalf("create payload missing required fields: %s", r.Body)
			}
		}
	}
}

func TestSyncRecordsAuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		io.WriteString(w, `{"success":false,"errors":[{"code":10000,"message":"invalid token"}]}`)
	}))
	defer srv.Close()

	m := NewDNSManager("bad", "evilpikin.com", "203.0.113.10")
	m.APIBase = srv.URL
	if err := m.SyncRecords(); err == nil {
		t.Fatal("expected error on bad token")
	}
}
