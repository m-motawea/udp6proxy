package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/m-motawea/udp6proxy/internal/auth"
	"github.com/m-motawea/udp6proxy/internal/endpoint"
	"github.com/m-motawea/udp6proxy/internal/proxy"
	"github.com/m-motawea/udp6proxy/internal/store"
)

const (
	sessionCookie = "u6p_session"
	csrfHeader    = "X-Requested-With"
	csrfValue     = "udp6proxy"
	maxBody       = 1 << 20
)

type ctxKey struct{}

func userFrom(r *http.Request) string {
	u, _ := r.Context().Value(ctxKey{}).(string)
	return u
}

// Handler returns the root HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	a := s.requireAuth

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("POST /api/v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /api/v1/auth/logout", s.handleLogout)

	mux.Handle("GET /api/v1/me", a(s.handleMe))
	mux.Handle("POST /api/v1/me/password", a(s.handleMyPassword))
	mux.Handle("GET /api/v1/status", a(s.handleStatus))

	mux.Handle("GET /api/v1/endpoints", a(s.handleListEndpoints))
	mux.Handle("POST /api/v1/endpoints", a(s.handleCreateEndpoint))
	mux.Handle("GET /api/v1/endpoints/{name}", a(s.handleGetEndpoint))
	mux.Handle("PUT /api/v1/endpoints/{name}", a(s.handleUpdateEndpoint(false)))
	mux.Handle("PATCH /api/v1/endpoints/{name}", a(s.handleUpdateEndpoint(true)))
	mux.Handle("DELETE /api/v1/endpoints/{name}", a(s.handleDeleteEndpoint))
	mux.Handle("GET /api/v1/endpoints/{name}/sessions", a(s.handleSessions))

	mux.Handle("GET /api/v1/tokens", a(s.handleListTokens))
	mux.Handle("POST /api/v1/tokens", a(s.handleCreateToken))
	mux.Handle("DELETE /api/v1/tokens/{id}", a(s.handleDeleteToken))

	mux.Handle("GET /api/v1/users", a(s.handleListUsers))
	mux.Handle("POST /api/v1/users", a(s.handleCreateUser))
	mux.Handle("DELETE /api/v1/users/{name}", a(s.handleDeleteUser))
	mux.Handle("PUT /api/v1/users/{name}/password", a(s.handleSetUserPassword))

	mux.Handle("GET /metrics", a(s.handleMetrics))

	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, errStatus(http.StatusNotFound, "no such API route"))
	})
	if s.opt.UI != nil {
		mux.Handle("/", s.opt.UI)
	}
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxBody)
		next.ServeHTTP(w, r)
	})
}

// requireAuth accepts either "Authorization: Bearer <token>" or the session
// cookie. Cookie-authenticated state-changing requests must carry the
// X-Requested-With header, which a cross-site form cannot set (CSRF guard,
// in addition to SameSite=Strict).
func (s *Server) requireAuth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var user string
		if hdr := r.Header.Get("Authorization"); hdr != "" {
			tok, ok := strings.CutPrefix(hdr, "Bearer ")
			if !ok {
				writeErr(w, errStatus(http.StatusUnauthorized, "unsupported authorization scheme"))
				return
			}
			u, ok := s.opt.Auth.VerifyToken(strings.TrimSpace(tok))
			if !ok {
				writeErr(w, errStatus(http.StatusUnauthorized, "invalid or expired token"))
				return
			}
			user = u
		} else if c, err := r.Cookie(sessionCookie); err == nil {
			u, ok := s.opt.Auth.Session(c.Value)
			if !ok {
				writeErr(w, errStatus(http.StatusUnauthorized, "session expired"))
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get(csrfHeader) != csrfValue {
				writeErr(w, errStatus(http.StatusForbidden, "missing %s header", csrfHeader))
				return
			}
			user = u
		} else {
			w.Header().Set("WWW-Authenticate", `Bearer realm="udp6proxy"`)
			writeErr(w, errStatus(http.StatusUnauthorized, "authentication required"))
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, user)))
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var ae *apiError
	if !errors.As(err, &ae) {
		ae = &apiError{Status: http.StatusInternalServerError, Msg: err.Error()}
	}
	writeJSON(w, ae.Status, ae)
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errStatus(http.StatusBadRequest, "invalid JSON body: %v", err)
	}
	return nil
}

// ---- auth ----

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	ip := clientIP(r)
	if wait := s.limiter.blocked(ip); wait > 0 {
		w.Header().Set("Retry-After", fmt.Sprint(int(wait.Seconds())+1))
		writeErr(w, errStatus(http.StatusTooManyRequests, "too many failed logins; try again in %s", wait.Round(time.Second)))
		return
	}
	if err := s.opt.Auth.Authenticate(req.Username, req.Password); err != nil {
		s.limiter.fail(ip)
		s.log.Warn("failed login", "user", req.Username, "ip", ip)
		writeErr(w, errStatus(http.StatusUnauthorized, "invalid username or password"))
		return
	}
	s.limiter.reset(ip)
	id, exp := s.opt.Auth.NewSession(req.Username)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    id,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		Secure:   s.opt.SecureCookies || r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	})
	s.log.Info("login", "user", req.Username, "ip", ip)
	writeJSON(w, http.StatusOK, map[string]any{"username": req.Username, "expires": exp})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.opt.Auth.EndSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"username": userFrom(r)})
}

func (s *Server) handleMyPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	u := userFrom(r)
	if err := s.opt.Auth.Authenticate(u, req.Current); err != nil {
		writeErr(w, &apiError{Status: http.StatusBadRequest, Msg: "current password is wrong", Fields: map[string]string{"current": "is wrong"}})
		return
	}
	if err := s.opt.Auth.SetPassword(u, req.New); err != nil {
		writeErr(w, authErr(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func authErr(err error) error {
	switch {
	case errors.Is(err, auth.ErrWeakPassword), errors.Is(err, auth.ErrBadUsername):
		return errStatus(http.StatusBadRequest, "%s", err)
	case errors.Is(err, auth.ErrUserExists), errors.Is(err, auth.ErrLastUser):
		return errStatus(http.StatusConflict, "%s", err)
	case errors.Is(err, auth.ErrUserNotFound), errors.Is(err, auth.ErrTokenNotFound):
		return errStatus(http.StatusNotFound, "%s", err)
	}
	return err
}

// ---- status ----

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	s.stateMu.Lock()
	lastReload, reloadErr := s.lastReload, s.reloadErr
	s.stateMu.Unlock()
	counts := map[string]int{}
	for _, st := range s.opt.Manager.Status() {
		counts[st.State]++
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":     s.opt.Version,
		"backend":     s.opt.Backend,
		"started":     s.started,
		"uptime":      time.Since(s.started).Round(time.Second).String(),
		"lastReload":  lastReload,
		"reloadError": reloadErr,
		"endpoints":   counts,
	})
}

// ---- endpoints ----

func (s *Server) handleListEndpoints(w http.ResponseWriter, r *http.Request) {
	eps, err := s.opt.Store.List(r.Context())
	if err != nil {
		// Store unreachable: show what is actually running so operators can
		// still see traffic. Writes will fail until the store is back.
		eps = s.opt.Manager.Specs()
		if len(eps) == 0 {
			writeErr(w, fmt.Errorf("store: %w", err))
			return
		}
		w.Header().Set("X-Udp6proxy-Stale", "true")
	}
	writeJSON(w, http.StatusOK, s.views(eps))
}

func (s *Server) handleGetEndpoint(w http.ResponseWriter, r *http.Request) {
	e, err := s.opt.Store.Get(r.Context(), r.PathValue("name"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, errStatus(http.StatusNotFound, "endpoint %q not found", r.PathValue("name")))
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, s.views([]endpoint.Endpoint{e})[0])
}

func (s *Server) handleCreateEndpoint(w http.ResponseWriter, r *http.Request) {
	var e endpoint.Endpoint
	if err := decode(r, &e); err != nil {
		writeErr(w, err)
		return
	}
	e, err := s.save(r.Context(), "", e)
	if err != nil {
		writeErr(w, err)
		return
	}
	s.log.Info("endpoint created", "endpoint", e.Name, "by", userFrom(r))
	writeJSON(w, http.StatusCreated, s.views([]endpoint.Endpoint{e})[0])
}

// PUT replaces the endpoint; PATCH merges the given fields into it. A
// different "name" in the body renames the endpoint.
func (s *Server) handleUpdateEndpoint(merge bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		var e endpoint.Endpoint
		if merge {
			cur, err := s.opt.Store.Get(r.Context(), name)
			if errors.Is(err, store.ErrNotFound) {
				writeErr(w, errStatus(http.StatusNotFound, "endpoint %q not found", name))
				return
			}
			if err != nil {
				writeErr(w, err)
				return
			}
			e = cur
		}
		body, err := readAll(r)
		if err != nil {
			writeErr(w, err)
			return
		}
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&e); err != nil {
			writeErr(w, errStatus(http.StatusBadRequest, "invalid JSON body: %v", err))
			return
		}
		if !merge && e.Name == "" {
			e.Name = name
		}
		e, err = s.save(r.Context(), name, e)
		if err != nil {
			writeErr(w, err)
			return
		}
		s.log.Info("endpoint updated", "endpoint", e.Name, "by", userFrom(r))
		writeJSON(w, http.StatusOK, s.views([]endpoint.Endpoint{e})[0])
	}
}

func readAll(r *http.Request) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(r.Body); err != nil {
		return nil, errStatus(http.StatusBadRequest, "reading body: %v", err)
	}
	return buf.Bytes(), nil
}

func (s *Server) handleDeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := s.remove(r.Context(), name); err != nil {
		writeErr(w, err)
		return
	}
	s.log.Info("endpoint deleted", "endpoint", name, "by", userFrom(r))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if _, err := s.opt.Store.Get(r.Context(), name); errors.Is(err, store.ErrNotFound) {
		writeErr(w, errStatus(http.StatusNotFound, "endpoint %q not found", name))
		return
	}
	sess := s.opt.Manager.Sessions(name)
	if sess == nil {
		sess = []proxy.SessionInfo{}
	}
	sort.Slice(sess, func(i, j int) bool { return sess[i].LastSeen.After(sess[j].LastSeen) })
	writeJSON(w, http.StatusOK, sess)
}

// ---- tokens ----

type tokenView struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Username string     `json:"username"`
	Hint     string     `json:"hint"`
	Created  time.Time  `json:"created"`
	Expires  *time.Time `json:"expires,omitempty"`
	LastUsed *time.Time `json:"lastUsed,omitempty"`
}

func toTokenView(t auth.Token) tokenView {
	return tokenView{ID: t.ID, Name: t.Name, Username: t.Username, Hint: t.Hint, Created: t.Created, Expires: t.Expires, LastUsed: t.LastUsed}
}

func (s *Server) handleListTokens(w http.ResponseWriter, r *http.Request) {
	toks := s.opt.Auth.ListTokens()
	out := make([]tokenView, len(toks))
	for i, t := range toks {
		out[i] = toTokenView(t)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string `json:"name"`
		TTLDays int    `json:"ttlDays"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if req.TTLDays < 0 || req.TTLDays > 3650 {
		writeErr(w, errStatus(http.StatusBadRequest, "ttlDays must be between 0 (never expires) and 3650"))
		return
	}
	plain, t, err := s.opt.Auth.CreateToken(userFrom(r), req.Name, time.Duration(req.TTLDays)*24*time.Hour)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeErr(w, authErr(err))
		} else {
			writeErr(w, errStatus(http.StatusBadRequest, "%s", err))
		}
		return
	}
	s.log.Info("token created", "token", t.ID, "name", t.Name, "by", userFrom(r))
	writeJSON(w, http.StatusCreated, struct {
		tokenView
		Token string `json:"token"`
	}{toTokenView(t), plain})
}

func (s *Server) handleDeleteToken(w http.ResponseWriter, r *http.Request) {
	if err := s.opt.Auth.DeleteToken(r.PathValue("id")); err != nil {
		writeErr(w, authErr(err))
		return
	}
	s.log.Info("token revoked", "token", r.PathValue("id"), "by", userFrom(r))
	w.WriteHeader(http.StatusNoContent)
}

// ---- users ----

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	type view struct {
		Username string    `json:"username"`
		Created  time.Time `json:"created"`
	}
	us := s.opt.Auth.ListUsers()
	out := make([]view, len(us))
	for i, u := range us {
		out[i] = view{u.Username, u.Created}
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if err := s.opt.Auth.AddUser(req.Username, req.Password); err != nil {
		writeErr(w, authErr(err))
		return
	}
	s.log.Info("user created", "user", req.Username, "by", userFrom(r))
	writeJSON(w, http.StatusCreated, map[string]string{"username": req.Username})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == userFrom(r) {
		writeErr(w, errStatus(http.StatusConflict, "you cannot delete your own account"))
		return
	}
	if err := s.opt.Auth.DeleteUser(name); err != nil {
		writeErr(w, authErr(err))
		return
	}
	s.log.Info("user deleted", "user", name, "by", userFrom(r))
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSetUserPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, err)
		return
	}
	if err := s.opt.Auth.SetPassword(r.PathValue("name"), req.Password); err != nil {
		writeErr(w, authErr(err))
		return
	}
	s.log.Info("password reset", "user", r.PathValue("name"), "by", userFrom(r))
	w.WriteHeader(http.StatusNoContent)
}

// ---- metrics (Prometheus text format) ----

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	st := s.opt.Manager.Status()
	names := make([]string, 0, len(st))
	for n := range st {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	metric := func(name, typ, help string, val func(proxy.Status) (float64, bool)) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
		for _, n := range names {
			if v, ok := val(st[n]); ok {
				fmt.Fprintf(&b, "%s{endpoint=%q} %g\n", name, n, v)
			}
		}
	}
	stat := func(f func(*proxy.Stats) float64) func(proxy.Status) (float64, bool) {
		return func(s proxy.Status) (float64, bool) {
			if s.Stats == nil {
				return 0, false
			}
			return f(s.Stats), true
		}
	}
	metric("udp6proxy_up", "gauge", "1 if the endpoint listener is running.", func(s proxy.Status) (float64, bool) {
		if s.State == proxy.StateRunning {
			return 1, true
		}
		return 0, true
	})
	metric("udp6proxy_rx_packets_total", "counter", "Packets received from IPv4 clients.", stat(func(s *proxy.Stats) float64 { return float64(s.RxPackets) }))
	metric("udp6proxy_rx_bytes_total", "counter", "Bytes received from IPv4 clients.", stat(func(s *proxy.Stats) float64 { return float64(s.RxBytes) }))
	metric("udp6proxy_tx_packets_total", "counter", "Packets sent back to IPv4 clients.", stat(func(s *proxy.Stats) float64 { return float64(s.TxPackets) }))
	metric("udp6proxy_tx_bytes_total", "counter", "Bytes sent back to IPv4 clients.", stat(func(s *proxy.Stats) float64 { return float64(s.TxBytes) }))
	metric("udp6proxy_dropped_total", "counter", "Packets dropped (filter or session limit).", stat(func(s *proxy.Stats) float64 { return float64(s.Dropped) }))
	metric("udp6proxy_errors_total", "counter", "Socket errors.", stat(func(s *proxy.Stats) float64 { return float64(s.Errors) }))
	metric("udp6proxy_sessions", "gauge", "Active client sessions.", stat(func(s *proxy.Stats) float64 { return float64(s.Sessions) }))
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	w.Write([]byte(b.String()))
}

// ---- login rate limiting ----

type loginLimiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	fails  map[string][]time.Time
}

func newLoginLimiter(max int, window time.Duration) *loginLimiter {
	return &loginLimiter{max: max, window: window, fails: map[string][]time.Time{}}
}

func (l *loginLimiter) prune(ip string, now time.Time) []time.Time {
	f := l.fails[ip]
	i := 0
	for i < len(f) && now.Sub(f[i]) > l.window {
		i++
	}
	f = f[i:]
	if len(f) == 0 {
		delete(l.fails, ip)
	} else {
		l.fails[ip] = f
	}
	return f
}

func (l *loginLimiter) blocked(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	f := l.prune(ip, now)
	if len(f) < l.max {
		return 0
	}
	return l.window - now.Sub(f[0])
}

func (l *loginLimiter) fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.fails) > 10000 { // bound memory under a spray attack
		l.fails = map[string][]time.Time{}
	}
	l.fails[ip] = append(l.fails[ip], time.Now())
}

func (l *loginLimiter) reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, ip)
}
