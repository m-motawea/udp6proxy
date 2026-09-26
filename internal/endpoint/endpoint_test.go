package endpoint

import (
	"encoding/json"
	"errors"
	"testing"
)

func valid() Endpoint {
	return Endpoint{Name: "wg0", LocalPort: 12345, RemoteAddress: "2001:db8::1", RemotePort: 51820}
}

func TestValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatal(err)
	}
	ok := []func(*Endpoint){
		func(e *Endpoint) { e.RemoteAddress = "vpn.example.com" },
		func(e *Endpoint) { e.RemoteAddress = "fe80::1%eth0" },
		func(e *Endpoint) { e.ListenAddress = "192.0.2.1" },
		func(e *Endpoint) { e.IdleTimeout = 30 },
	}
	for i, f := range ok {
		e := valid()
		f(&e)
		if err := e.Validate(); err != nil {
			t.Errorf("ok[%d]: %v", i, err)
		}
	}
	bad := map[string]func(*Endpoint){
		"name":          func(e *Endpoint) { e.Name = "-x" },
		"localPort":     func(e *Endpoint) { e.LocalPort = 0 },
		"remotePort":    func(e *Endpoint) { e.RemotePort = 65536 },
		"remoteAddress": func(e *Endpoint) { e.RemoteAddress = "192.0.2.1" },
		"listenAddress": func(e *Endpoint) { e.ListenAddress = "::1" },
		"idleTimeout":   func(e *Endpoint) { e.IdleTimeout = 5 },
	}
	for field, f := range bad {
		e := valid()
		f(&e)
		var ve *ValidationError
		if err := e.Validate(); !errors.As(err, &ve) || ve.Fields[field] == "" {
			t.Errorf("%s: expected field error, got %v", field, err)
		}
	}
	e := valid()
	e.RemoteAddress = "::ffff:192.0.2.1"
	if e.Validate() == nil {
		t.Error("IPv4-mapped address accepted")
	}
}

func TestNormalize(t *testing.T) {
	e := Endpoint{Name: " wg0 ", RemoteAddress: " [2001:db8::1] "}
	e.Normalize()
	if e.Name != "wg0" || e.RemoteAddress != "2001:db8::1" {
		t.Fatalf("%+v", e)
	}
}

func TestConflicts(t *testing.T) {
	a := valid()
	b := valid()
	b.Name = "b"
	if !errors.Is(CheckConflicts(b, []Endpoint{a}), ErrConflict) {
		t.Fatal("same port not detected")
	}
	b.ListenAddress = "127.0.0.1"
	if CheckConflicts(b, []Endpoint{a}) == nil {
		t.Fatal("0.0.0.0 overlaps every address")
	}
	a.ListenAddress = "127.0.0.2"
	if err := CheckConflicts(b, []Endpoint{a}); err != nil {
		t.Fatalf("distinct addresses conflict: %v", err)
	}
	a.ListenAddress = "127.0.0.1"
	a.Disabled = true
	if err := CheckConflicts(b, []Endpoint{a}); err != nil {
		t.Fatal("disabled endpoint conflicts")
	}
	if CheckConflicts(a, []Endpoint{a}) != nil {
		t.Fatal("self conflict")
	}
}

// v1 stored capitalised JSON keys in Redis; they must still decode.
func TestLegacyJSON(t *testing.T) {
	var e Endpoint
	err := json.Unmarshal([]byte(`{"Name":"wg0","WireGuard":true,"RemoteAddress":"::1","RemotePort":23456,"LocalPort":12345}`), &e)
	if err != nil || e.Name != "wg0" || !e.WireGuard || e.RemotePort != 23456 || e.LocalPort != 12345 {
		t.Fatalf("%+v %v", e, err)
	}
}

func TestRuntimeEqual(t *testing.T) {
	a, b := valid(), valid()
	b.Description = "x"
	b.ListenAddress = "0.0.0.0"
	b.IdleTimeout = DefaultIdleTimeout
	if !a.RuntimeEqual(b) {
		t.Fatal("equivalent endpoints differ")
	}
	b.WireGuard = true
	if a.RuntimeEqual(b) {
		t.Fatal("wireguard change ignored")
	}
}
