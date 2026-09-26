// Package endpoint defines the proxy endpoint model and its validation rules.
package endpoint

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// DefaultIdleTimeout is used when an endpoint does not set IdleTimeout.
// WireGuard peers with PersistentKeepalive=25 refresh sessions well within it.
const DefaultIdleTimeout = 180

var nameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,62}$`)
var hostRe = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$`)

// Endpoint is one IPv4 -> IPv6 UDP forwarding rule.
//
// JSON field names are camelCase; because encoding/json matches keys
// case-insensitively, records written by udp6proxy v1 ("LocalPort",
// "RemoteAddress", ...) decode into this struct unchanged.
type Endpoint struct {
	Name          string `json:"name" toml:"Name"`
	Description   string `json:"description,omitempty" toml:"Description"`
	ListenAddress string `json:"listenAddress,omitempty" toml:"ListenAddress"`
	LocalPort     int    `json:"localPort" toml:"LocalPort"`
	RemoteAddress string `json:"remoteAddress" toml:"RemoteAddress"`
	RemotePort    int    `json:"remotePort" toml:"RemotePort"`
	WireGuard     bool   `json:"wireguard" toml:"WireGuard"`
	Disabled      bool   `json:"disabled,omitempty" toml:"Disabled"`
	// IdleTimeout is the number of seconds without traffic after which a
	// client session (and its IPv6 socket) is closed. 0 means default.
	IdleTimeout int `json:"idleTimeout,omitempty" toml:"IdleTimeout"`
}

// Normalize trims whitespace and strips brackets around IPv6 literals.
func (e *Endpoint) Normalize() {
	e.Name = strings.TrimSpace(e.Name)
	e.Description = strings.TrimSpace(e.Description)
	e.ListenAddress = strings.TrimSpace(e.ListenAddress)
	ra := strings.TrimSpace(e.RemoteAddress)
	ra = strings.TrimSuffix(strings.TrimPrefix(ra, "["), "]")
	e.RemoteAddress = ra
}

// EffectiveIdleTimeout returns IdleTimeout or the default.
func (e Endpoint) EffectiveIdleTimeout() int {
	if e.IdleTimeout <= 0 {
		return DefaultIdleTimeout
	}
	return e.IdleTimeout
}

// EffectiveListenAddress returns the IPv4 listen address ("0.0.0.0" if unset).
func (e Endpoint) EffectiveListenAddress() string {
	if e.ListenAddress == "" {
		return "0.0.0.0"
	}
	return e.ListenAddress
}

// RuntimeEqual reports whether two endpoints would produce an identical
// running listener (description changes do not require a restart).
func (e Endpoint) RuntimeEqual(o Endpoint) bool {
	return e.Name == o.Name &&
		e.EffectiveListenAddress() == o.EffectiveListenAddress() &&
		e.LocalPort == o.LocalPort &&
		e.RemoteAddress == o.RemoteAddress &&
		e.RemotePort == o.RemotePort &&
		e.WireGuard == o.WireGuard &&
		e.Disabled == o.Disabled &&
		e.EffectiveIdleTimeout() == o.EffectiveIdleTimeout()
}

// ValidationError lists every problem found with an endpoint.
type ValidationError struct {
	Fields map[string]string `json:"fields"`
}

func (v *ValidationError) Error() string {
	keys := make([]string, 0, len(v.Fields))
	for k := range v.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+": "+v.Fields[k])
	}
	return "invalid endpoint: " + strings.Join(parts, "; ")
}

// Validate checks a single endpoint (call Normalize first).
func (e Endpoint) Validate() error {
	f := map[string]string{}
	if !nameRe.MatchString(e.Name) {
		f["name"] = "must be 1-63 chars of letters, digits, '.', '_' or '-' and start with a letter or digit"
	}
	if e.LocalPort < 1 || e.LocalPort > 65535 {
		f["localPort"] = "must be between 1 and 65535"
	}
	if e.RemotePort < 1 || e.RemotePort > 65535 {
		f["remotePort"] = "must be between 1 and 65535"
	}
	if e.ListenAddress != "" {
		a, err := netip.ParseAddr(e.ListenAddress)
		if err != nil || !a.Is4() {
			f["listenAddress"] = "must be an IPv4 address (or empty for all interfaces)"
		}
	}
	if e.RemoteAddress == "" {
		f["remoteAddress"] = "is required"
	} else if a, err := netip.ParseAddr(e.RemoteAddress); err == nil {
		if a.Is4() || a.Is4In6() {
			f["remoteAddress"] = "must be an IPv6 address or a hostname with an AAAA record"
		} else if a.Zone() != "" && !a.IsLinkLocalUnicast() {
			f["remoteAddress"] = "zones are only valid for link-local addresses"
		}
	} else if !hostRe.MatchString(e.RemoteAddress) || len(e.RemoteAddress) > 253 {
		f["remoteAddress"] = "must be an IPv6 address or a valid hostname"
	}
	if e.IdleTimeout != 0 && (e.IdleTimeout < 10 || e.IdleTimeout > 86400) {
		f["idleTimeout"] = "must be between 10 and 86400 seconds (or 0 for default)"
	}
	if len(e.Description) > 200 {
		f["description"] = "must be at most 200 characters"
	}
	if len(f) > 0 {
		return &ValidationError{Fields: f}
	}
	return nil
}

// ErrConflict is returned when an endpoint collides with another.
var ErrConflict = errors.New("conflict")

// CheckConflicts verifies that candidate does not bind the same local
// address/port as any other enabled endpoint in existing. An endpoint with the
// same name as candidate is ignored (it is being replaced).
func CheckConflicts(candidate Endpoint, existing []Endpoint) error {
	if candidate.Disabled {
		return nil
	}
	for _, o := range existing {
		if o.Name == candidate.Name || o.Disabled || o.LocalPort != candidate.LocalPort {
			continue
		}
		a, b := candidate.EffectiveListenAddress(), o.EffectiveListenAddress()
		if a == b || a == "0.0.0.0" || b == "0.0.0.0" {
			return fmt.Errorf("%w: local port %d is already used by endpoint %q", ErrConflict, o.LocalPort, o.Name)
		}
	}
	return nil
}

// Sort orders endpoints by name.
func Sort(eps []Endpoint) {
	sort.Slice(eps, func(i, j int) bool { return eps[i].Name < eps[j].Name })
}
