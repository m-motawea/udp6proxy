package proxy

import (
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/m-motawea/udp6proxy/internal/endpoint"
)

// Runtime states reported for an endpoint.
const (
	StateRunning  = "running"
	StateDisabled = "disabled"
	StateError    = "error"
)

// Status is the runtime state of one endpoint.
type Status struct {
	State string    `json:"state"`
	Error string    `json:"error,omitempty"`
	Since time.Time `json:"since"`
	Stats *Stats    `json:"stats,omitempty"`
}

// Manager reconciles running listeners against a desired endpoint set.
// It is safe for concurrent use.
type Manager struct {
	log  *slog.Logger
	opts []ListenerOption

	mu        sync.Mutex
	specs     map[string]endpoint.Endpoint
	listeners map[string]*Listener
	status    map[string]Status
}

// NewManager creates an empty manager.
func NewManager(log *slog.Logger, opts ...ListenerOption) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{
		log:       log,
		opts:      append([]ListenerOption{WithLogger(log)}, opts...),
		specs:     map[string]endpoint.Endpoint{},
		listeners: map[string]*Listener{},
		status:    map[string]Status{},
	}
}

// Apply makes the running set match desired. Unchanged endpoints keep
// running untouched (their sessions survive); changed ones are restarted;
// endpoints that previously failed to start are retried.
func (m *Manager) Apply(desired []endpoint.Endpoint) {
	m.mu.Lock()
	defer m.mu.Unlock()

	want := make(map[string]endpoint.Endpoint, len(desired))
	for _, e := range desired {
		want[e.Name] = e
	}

	// Stop first so ports are free for endpoints that move onto them.
	for name, spec := range m.specs {
		n, ok := want[name]
		if ok && n.RuntimeEqual(spec) {
			m.specs[name] = n // pick up description changes
			continue
		}
		if l := m.listeners[name]; l != nil {
			l.Close()
			delete(m.listeners, name)
		}
		delete(m.specs, name)
		delete(m.status, name)
	}

	names := make([]string, 0, len(want))
	for name := range want {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		spec := want[name]
		if _, ok := m.specs[name]; ok && (m.listeners[name] != nil || spec.Disabled) {
			continue
		}
		m.specs[name] = spec
		if spec.Disabled {
			m.status[name] = Status{State: StateDisabled, Since: time.Now()}
			continue
		}
		l, err := StartListener(spec, m.opts...)
		if err != nil {
			prev := m.status[name]
			if prev.State != StateError || prev.Error != err.Error() {
				m.log.Error("failed to start endpoint", "endpoint", name, "err", err)
				prev = Status{State: StateError, Error: err.Error(), Since: time.Now()}
			}
			m.status[name] = prev
			continue
		}
		m.listeners[name] = l
		m.status[name] = Status{State: StateRunning, Since: time.Now()}
	}
}

// Status returns runtime status (with stats) for every known endpoint.
func (m *Manager) Status() map[string]Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string]Status, len(m.status))
	for name, st := range m.status {
		if l := m.listeners[name]; l != nil {
			s := l.Stats()
			st.Stats = &s
		}
		out[name] = st
	}
	return out
}

// Specs returns the endpoint definitions the manager is currently applying.
func (m *Manager) Specs() []endpoint.Endpoint {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]endpoint.Endpoint, 0, len(m.specs))
	for _, e := range m.specs {
		out = append(out, e)
	}
	endpoint.Sort(out)
	return out
}

// Sessions returns active sessions for an endpoint (nil if not running).
func (m *Manager) Sessions(name string) []SessionInfo {
	m.mu.Lock()
	l := m.listeners[name]
	m.mu.Unlock()
	if l == nil {
		return nil
	}
	return l.Sessions()
}

// Close stops every listener.
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, l := range m.listeners {
		l.Close()
		delete(m.listeners, name)
	}
	m.specs = map[string]endpoint.Endpoint{}
	m.status = map[string]Status{}
}
