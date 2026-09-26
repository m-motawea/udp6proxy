package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m-motawea/udp6proxy/internal/auth"
	"github.com/m-motawea/udp6proxy/internal/endpoint"
	"github.com/m-motawea/udp6proxy/internal/proxy"
	"github.com/m-motawea/udp6proxy/internal/store"
)

func init() { auth.Iterations = 1000 }

type env struct {
	t     *testing.T
	srv   *Server
	ts    *httptest.Server
	store store.Store
	mgr   *proxy.Manager
	auth  *auth.Service
}

func newEnv(t *testing.T) *env {
	dir := t.TempDir()
	st, err := store.NewFile(filepath.Join(dir, "endpoints.json"))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := auth.Open(filepath.Join(dir, "auth.json"), time.Hour)
	if err := a.AddUser("admin", "adminpass"); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := proxy.NewManager(log)
	t.Cleanup(mgr.Close)
	s := New(Options{Store: st, Manager: mgr, Auth: a, Log: log, Backend: "file", Version: "test"})
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	return &env{t: t, srv: s, ts: ts, store: st, mgr: mgr, auth: a}
}

type resp struct {
	code int
	body map[string]any
	raw  []byte
}

func (e *env) req(c *http.Client, method, path string, body any, hdr map[string]string) resp {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	r, _ := http.NewRequest(method, e.ts.URL+path, rd)
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	if c == nil {
		c = http.DefaultClient
	}
	res, err := c.Do(r)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	out := resp{code: res.StatusCode, raw: raw}
	json.Unmarshal(raw, &out.body)
	return out
}

func (e *env) browser() *http.Client {
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar}
	r := e.req(c, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "adminpass"}, nil)
	if r.code != 200 {
		e.t.Fatalf("login: %d %s", r.code, r.raw)
	}
	return c
}

var ui = map[string]string{"X-Requested-With": "udp6proxy"}

func freeUDPPort(t *testing.T) int {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func TestAuthRequired(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/api/v1/endpoints", "/api/v1/tokens", "/api/v1/users", "/metrics", "/api/v1/status"} {
		if r := e.req(nil, "GET", p, nil, nil); r.code != 401 {
			t.Errorf("%s: %d", p, r.code)
		}
	}
	if r := e.req(nil, "GET", "/api/v1/endpoints", nil, map[string]string{"Authorization": "Bearer u6p_bogus"}); r.code != 401 {
		t.Errorf("bogus token: %d", r.code)
	}
	if r := e.req(nil, "GET", "/healthz", nil, nil); r.code != 200 {
		t.Errorf("healthz: %d", r.code)
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 5; i++ {
		if r := e.req(nil, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "wrong"}, nil); r.code != 401 {
			t.Fatalf("attempt %d: %d", i, r.code)
		}
	}
	r := e.req(nil, "POST", "/api/v1/auth/login", map[string]string{"username": "admin", "password": "adminpass"}, nil)
	if r.code != 429 {
		t.Fatalf("expected 429 after repeated failures, got %d", r.code)
	}
}

func TestCSRFHeaderRequiredForCookieAuth(t *testing.T) {
	e := newEnv(t)
	c := e.browser()
	ep := map[string]any{"name": "wg0", "localPort": freeUDPPort(t), "remoteAddress": "2001:db8::1", "remotePort": 51820}
	if r := e.req(c, "POST", "/api/v1/endpoints", ep, nil); r.code != 403 {
		t.Fatalf("cookie POST without header: %d", r.code)
	}
	if r := e.req(c, "POST", "/api/v1/endpoints", ep, ui); r.code != 201 {
		t.Fatalf("cookie POST with header: %d %s", r.code, r.raw)
	}
	// Logout invalidates the session.
	e.req(c, "POST", "/api/v1/auth/logout", nil, ui)
	if r := e.req(c, "GET", "/api/v1/me", nil, nil); r.code != 401 {
		t.Fatalf("after logout: %d", r.code)
	}
}

func TestEndpointLifecycle(t *testing.T) {
	e := newEnv(t)
	c := e.browser()
	p1, p2 := freeUDPPort(t), freeUDPPort(t)

	// Validation errors come back per field.
	r := e.req(c, "POST", "/api/v1/endpoints", map[string]any{"name": "bad name", "localPort": 0, "remoteAddress": "10.0.0.1", "remotePort": 70000}, ui)
	if r.code != 400 {
		t.Fatalf("validation: %d", r.code)
	}
	fields, _ := r.body["fields"].(map[string]any)
	for _, f := range []string{"name", "localPort", "remoteAddress", "remotePort"} {
		if _, ok := fields[f]; !ok {
			t.Errorf("missing field error %q: %s", f, r.raw)
		}
	}
	// Unknown JSON fields are rejected (catches typos).
	if r := e.req(c, "POST", "/api/v1/endpoints", map[string]any{"name": "x", "locallPort": 1}, ui); r.code != 400 {
		t.Fatalf("unknown field: %d", r.code)
	}

	r = e.req(c, "POST", "/api/v1/endpoints", map[string]any{"name": "wg0", "localPort": p1, "listenAddress": "127.0.0.1", "remoteAddress": "[2001:db8::1]", "remotePort": 51820, "wireguard": true}, ui)
	if r.code != 201 {
		t.Fatalf("create: %d %s", r.code, r.raw)
	}
	if r.body["remoteAddress"] != "2001:db8::1" {
		t.Fatalf("brackets not stripped: %v", r.body["remoteAddress"])
	}
	st, _ := r.body["status"].(map[string]any)
	if st["state"] != "running" {
		t.Fatalf("not running: %s", r.raw)
	}

	// Duplicate name and port conflicts.
	if r := e.req(c, "POST", "/api/v1/endpoints", map[string]any{"name": "wg0", "localPort": p2, "remoteAddress": "::1", "remotePort": 1}, ui); r.code != 409 {
		t.Fatalf("dup name: %d", r.code)
	}
	if r := e.req(c, "POST", "/api/v1/endpoints", map[string]any{"name": "wg1", "localPort": p1, "remoteAddress": "::1", "remotePort": 1}, ui); r.code != 409 {
		t.Fatalf("port conflict: %d %s", r.code, r.raw)
	}

	// PATCH disable.
	r = e.req(c, "PATCH", "/api/v1/endpoints/wg0", map[string]any{"disabled": true}, ui)
	if r.code != 200 || r.body["status"].(map[string]any)["state"] != "disabled" {
		t.Fatalf("disable: %d %s", r.code, r.raw)
	}
	// A disabled endpoint's port can be taken by another endpoint.
	if r := e.req(c, "POST", "/api/v1/endpoints", map[string]any{"name": "wg1", "localPort": p1, "listenAddress": "127.0.0.1", "remoteAddress": "::1", "remotePort": 1}, ui); r.code != 201 {
		t.Fatalf("reuse port of disabled: %d %s", r.code, r.raw)
	}
	// ...but then re-enabling wg0 conflicts.
	if r := e.req(c, "PATCH", "/api/v1/endpoints/wg0", map[string]any{"disabled": false}, ui); r.code != 409 {
		t.Fatalf("re-enable conflict: %d", r.code)
	}
	e.req(c, "DELETE", "/api/v1/endpoints/wg1", nil, ui)

	// PUT (full replace) + rename.
	r = e.req(c, "PUT", "/api/v1/endpoints/wg0", map[string]any{"name": "wg-renamed", "localPort": p2, "listenAddress": "127.0.0.1", "remoteAddress": "2001:db8::2", "remotePort": 51821}, ui)
	if r.code != 200 {
		t.Fatalf("put/rename: %d %s", r.code, r.raw)
	}
	if r := e.req(c, "GET", "/api/v1/endpoints/wg0", nil, nil); r.code != 404 {
		t.Fatalf("old name still exists: %d", r.code)
	}
	r = e.req(c, "GET", "/api/v1/endpoints/wg-renamed", nil, nil)
	if r.code != 200 || r.body["wireguard"] != false || r.body["status"].(map[string]any)["state"] != "running" {
		t.Fatalf("get renamed: %s", r.raw)
	}
	if st := e.mgr.Status(); len(st) != 1 {
		t.Fatalf("manager has %d endpoints", len(st))
	}

	// Sessions + metrics.
	if r := e.req(c, "GET", "/api/v1/endpoints/wg-renamed/sessions", nil, nil); r.code != 200 || strings.TrimSpace(string(r.raw)) != "[]" {
		t.Fatalf("sessions: %d %s", r.code, r.raw)
	}
	if r := e.req(c, "GET", "/metrics", nil, nil); r.code != 200 || !strings.Contains(string(r.raw), `udp6proxy_up{endpoint="wg-renamed"} 1`) {
		t.Fatalf("metrics: %s", r.raw)
	}

	// Delete.
	if r := e.req(c, "DELETE", "/api/v1/endpoints/wg-renamed", nil, ui); r.code != 204 {
		t.Fatalf("delete: %d", r.code)
	}
	if r := e.req(c, "DELETE", "/api/v1/endpoints/wg-renamed", nil, ui); r.code != 404 {
		t.Fatalf("delete again: %d", r.code)
	}
	if st := e.mgr.Status(); len(st) != 0 {
		t.Fatalf("listener not stopped")
	}
}

func TestTokensAndUsers(t *testing.T) {
	e := newEnv(t)
	c := e.browser()
	r := e.req(c, "POST", "/api/v1/tokens", map[string]any{"name": "ci", "ttlDays": 30}, ui)
	if r.code != 201 {
		t.Fatalf("create token: %d %s", r.code, r.raw)
	}
	tok := r.body["token"].(string)
	id := r.body["id"].(string)
	bearer := map[string]string{"Authorization": "Bearer " + tok}
	// Bearer auth needs no CSRF header.
	if r := e.req(nil, "POST", "/api/v1/endpoints", map[string]any{"name": "a", "localPort": freeUDPPort(t), "remoteAddress": "::1", "remotePort": 1}, bearer); r.code != 201 {
		t.Fatalf("bearer create: %d %s", r.code, r.raw)
	}
	r = e.req(nil, "GET", "/api/v1/tokens", nil, bearer)
	if strings.Contains(string(r.raw), tok) || strings.Contains(string(r.raw), `"hash"`) {
		t.Fatal("token list leaks secrets")
	}
	if r := e.req(nil, "GET", "/api/v1/users", nil, bearer); strings.Contains(string(r.raw), "pbkdf2") {
		t.Fatal("user list leaks hashes")
	}

	// Users.
	if r := e.req(c, "POST", "/api/v1/users", map[string]any{"username": "bob", "password": "short"}, ui); r.code != 400 {
		t.Fatalf("weak password: %d", r.code)
	}
	if r := e.req(c, "POST", "/api/v1/users", map[string]any{"username": "bob", "password": "bobpassword"}, ui); r.code != 201 {
		t.Fatalf("create user: %d", r.code)
	}
	if r := e.req(c, "DELETE", "/api/v1/users/admin", nil, ui); r.code != 409 {
		t.Fatalf("self delete: %d", r.code)
	}
	if r := e.req(c, "DELETE", "/api/v1/users/bob", nil, ui); r.code != 204 {
		t.Fatalf("delete bob: %d", r.code)
	}

	// Change own password (wrong current rejected).
	if r := e.req(c, "POST", "/api/v1/me/password", map[string]any{"current": "nope", "new": "newpassword"}, ui); r.code != 400 {
		t.Fatalf("wrong current: %d", r.code)
	}
	if r := e.req(c, "POST", "/api/v1/me/password", map[string]any{"current": "adminpass", "new": "newpassword"}, ui); r.code != 204 {
		t.Fatalf("change pw: %d", r.code)
	}
	if r := e.req(c, "GET", "/api/v1/me", nil, nil); r.code != 401 {
		t.Fatal("session survived password change")
	}

	// Revoke token.
	if r := e.req(nil, "DELETE", "/api/v1/tokens/"+id, nil, bearer); r.code != 204 {
		t.Fatalf("revoke: %d", r.code)
	}
	if r := e.req(nil, "GET", "/api/v1/endpoints", nil, bearer); r.code != 401 {
		t.Fatalf("revoked token still works: %d", r.code)
	}
}

// flakyStore fails List on demand to simulate a Redis outage.
type flakyStore struct {
	store.Store
	fail bool
}

func (f *flakyStore) List(ctx context.Context) ([]endpoint.Endpoint, error) {
	if f.fail {
		return nil, errors.New("connection refused")
	}
	return f.Store.List(ctx)
}

// Regression test for v1 stopping every listener when Redis was unreachable.
func TestStoreOutageKeepsListeners(t *testing.T) {
	e := newEnv(t)
	fs := &flakyStore{Store: e.store}
	e.srv.opt.Store = fs
	ctx := context.Background()
	fs.Put(ctx, endpoint.Endpoint{Name: "wg0", ListenAddress: "127.0.0.1", LocalPort: freeUDPPort(t), RemoteAddress: "::1", RemotePort: 1})
	if err := e.srv.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	fs.fail = true
	if err := e.srv.Reload(ctx); err == nil {
		t.Fatal("expected reload error")
	}
	if st := e.mgr.Status()["wg0"]; st.State != proxy.StateRunning {
		t.Fatalf("listener stopped during store outage: %+v", st)
	}
	c := e.browser()
	if r := e.req(c, "GET", "/api/v1/endpoints", nil, nil); r.code != 200 || !strings.Contains(string(r.raw), "wg0") {
		t.Fatalf("list during outage: %d %s", r.code, r.raw)
	}
	r := e.req(c, "GET", "/api/v1/status", nil, nil)
	if r.body["reloadError"] == "" {
		t.Fatal("status does not report store error")
	}
}

func TestSecurityHeaders(t *testing.T) {
	e := newEnv(t)
	res, err := http.Get(e.ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	for _, h := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"} {
		if res.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
}
