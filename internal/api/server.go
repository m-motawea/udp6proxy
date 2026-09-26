// Package api implements the management HTTP API, reconciliation loop and
// serves the embedded web UI.
package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/m-motawea/udp6proxy/internal/auth"
	"github.com/m-motawea/udp6proxy/internal/endpoint"
	"github.com/m-motawea/udp6proxy/internal/proxy"
	"github.com/m-motawea/udp6proxy/internal/store"
)

// Options configure a Server.
type Options struct {
	Store         store.Store
	Manager       *proxy.Manager
	Auth          *auth.Service
	Log           *slog.Logger
	Backend       string
	Version       string
	SecureCookies bool
	// UI serves the web UI at "/" when non-nil.
	UI http.Handler
}

// Server owns the desired-state loop and the HTTP API.
type Server struct {
	opt     Options
	log     *slog.Logger
	started time.Time

	// writeMu serialises validate+write+apply so concurrent API calls cannot
	// both claim the same port.
	writeMu sync.Mutex

	stateMu    sync.Mutex
	lastReload time.Time
	reloadErr  string
	reloadWake chan struct{}

	limiter *loginLimiter
}

// New creates a Server.
func New(opt Options) *Server {
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	return &Server{
		opt:        opt,
		log:        opt.Log,
		started:    time.Now(),
		reloadWake: make(chan struct{}, 1),
		limiter:    newLoginLimiter(5, 15*time.Minute),
	}
}

// Reload reads the store and applies it. If the store cannot be read the
// running configuration is kept as-is (v1 stopped every listener when Redis
// was unreachable).
func (s *Server) Reload(ctx context.Context) error {
	eps, err := s.opt.Store.List(ctx)
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if err != nil {
		if s.reloadErr != err.Error() {
			s.log.Error("cannot read endpoint store; keeping current configuration", "err", err)
		}
		s.reloadErr = err.Error()
		return err
	}
	if s.reloadErr != "" {
		s.log.Info("endpoint store reachable again")
	}
	s.reloadErr = ""
	s.lastReload = time.Now()
	s.opt.Manager.Apply(eps)
	return nil
}

// TriggerReload asks the loop to reload soon (e.g. on SIGHUP).
func (s *Server) TriggerReload() {
	select {
	case s.reloadWake <- struct{}{}:
	default:
	}
}

// Run reloads every interval until ctx is cancelled. It also retries
// endpoints that failed to start (e.g. port temporarily in use).
func (s *Server) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.reloadWake:
		}
		s.writeMu.Lock()
		rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		s.Reload(rctx)
		cancel()
		s.writeMu.Unlock()
	}
}

// ---- endpoint operations (shared by handlers) ----

type endpointView struct {
	endpoint.Endpoint
	Status *proxy.Status `json:"status,omitempty"`
}

func (s *Server) views(eps []endpoint.Endpoint) []endpointView {
	st := s.opt.Manager.Status()
	out := make([]endpointView, len(eps))
	for i, e := range eps {
		out[i] = endpointView{Endpoint: e}
		if v, ok := st[e.Name]; ok {
			v := v
			out[i].Status = &v
		}
	}
	return out
}

type apiError struct {
	Status int               `json:"-"`
	Msg    string            `json:"error"`
	Fields map[string]string `json:"fields,omitempty"`
}

func (e *apiError) Error() string { return e.Msg }

func errStatus(code int, format string, a ...any) *apiError {
	return &apiError{Status: code, Msg: fmt.Sprintf(format, a...)}
}

// save validates e and writes it, replacing oldName (which may differ from
// e.Name for renames, or be "" for creates).
func (s *Server) save(ctx context.Context, oldName string, e endpoint.Endpoint) (endpoint.Endpoint, error) {
	e.Normalize()
	if err := e.Validate(); err != nil {
		var ve *endpoint.ValidationError
		if errors.As(err, &ve) {
			return e, &apiError{Status: http.StatusBadRequest, Msg: "validation failed", Fields: ve.Fields}
		}
		return e, err
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	all, err := s.opt.Store.List(ctx)
	if err != nil {
		return e, fmt.Errorf("store: %w", err)
	}
	exists := func(n string) bool {
		for _, x := range all {
			if x.Name == n {
				return true
			}
		}
		return false
	}
	if oldName == "" && exists(e.Name) {
		return e, errStatus(http.StatusConflict, "endpoint %q already exists", e.Name)
	}
	if oldName != "" && !exists(oldName) {
		return e, errStatus(http.StatusNotFound, "endpoint %q not found", oldName)
	}
	if oldName != "" && oldName != e.Name && exists(e.Name) {
		return e, errStatus(http.StatusConflict, "endpoint %q already exists", e.Name)
	}
	others := all[:0:0]
	for _, x := range all {
		if x.Name != oldName {
			others = append(others, x)
		}
	}
	if err := endpoint.CheckConflicts(e, others); err != nil {
		return e, &apiError{Status: http.StatusConflict, Msg: err.Error(), Fields: map[string]string{"localPort": "already in use by another endpoint"}}
	}
	if err := s.opt.Store.Put(ctx, e); err != nil {
		return e, fmt.Errorf("store: %w", err)
	}
	if oldName != "" && oldName != e.Name {
		if err := s.opt.Store.Delete(ctx, oldName); err != nil && !errors.Is(err, store.ErrNotFound) {
			return e, fmt.Errorf("store: %w", err)
		}
	}
	s.Reload(ctx)
	return e, nil
}

func (s *Server) remove(ctx context.Context, name string) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.opt.Store.Delete(ctx, name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return errStatus(http.StatusNotFound, "endpoint %q not found", name)
		}
		return fmt.Errorf("store: %w", err)
	}
	s.Reload(ctx)
	return nil
}
