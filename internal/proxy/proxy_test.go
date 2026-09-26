package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/m-motawea/udp6proxy/internal/endpoint"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// echoServer replies "<source addr>|<payload>" so tests can see which upstream
// socket a packet arrived on. Stands in for the IPv6 peer (udp4 in tests).
func echoServer(t *testing.T, prefix []byte) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := c.ReadFromUDP(buf)
			if err != nil {
				return
			}
			var out []byte
			out = append(out, prefix...)
			out = append(out, []byte(addr.String()+"|")...)
			out = append(out, buf[:n]...)
			c.WriteToUDP(out, addr)
		}
	}()
	return c
}

func startTestListener(t *testing.T, remote *net.UDPConn, wg bool, opts ...ListenerOption) *Listener {
	t.Helper()
	ra := remote.LocalAddr().(*net.UDPAddr)
	ep := endpoint.Endpoint{Name: "t", ListenAddress: "127.0.0.1", LocalPort: 0, RemoteAddress: "127.0.0.1", RemotePort: ra.Port, WireGuard: wg, IdleTimeout: 10}
	opts = append([]ListenerOption{withUpstreamNetwork("udp4"), WithLogger(quietLog())}, opts...)
	l, err := StartListener(ep, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	return l
}

func client(t *testing.T, l *Listener) *net.UDPConn {
	t.Helper()
	c, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(l.LocalAddr()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func roundTrip(t *testing.T, c *net.UDPConn, msg []byte) (string, bool) {
	t.Helper()
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 65535)
	n, err := c.Read(buf)
	if err != nil {
		return "", false
	}
	return string(buf[:n]), true
}

func wgData(n int) []byte {
	b := make([]byte, n)
	b[0] = wgTransportData
	return b
}

func TestIsWireGuard(t *testing.T) {
	init := make([]byte, 148)
	init[0] = 1
	resp := make([]byte, 92)
	resp[0] = 2
	cookie := make([]byte, 64)
	cookie[0] = 3
	cases := []struct {
		name string
		b    []byte
		want bool
	}{
		{"initiation", init, true},
		{"response", resp, true},
		{"cookie", cookie, true},
		{"keepalive", wgData(32), true},
		{"data", wgData(1440), true},
		{"empty", nil, false},
		{"short", []byte{4, 0}, false},
		{"bad type 0", append([]byte{0, 0, 0, 0}, make([]byte, 28)...), false},
		{"bad type 5", append([]byte{5, 0, 0, 0}, make([]byte, 28)...), false},
		{"reserved set", append([]byte{4, 0, 1, 0}, make([]byte, 28)...), false},
		{"initiation wrong size", init[:147], false},
		{"data unaligned", wgData(33), false},
		{"dns-ish", []byte("\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"), false},
		// The v1 filter accepted this (any header > 00000000).
		{"text", []byte("hello world, not wireguard......"), false},
	}
	for _, c := range cases {
		if got := IsWireGuard(c.b); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestForwardAndReply(t *testing.T) {
	remote := echoServer(t, nil)
	l := startTestListener(t, remote, false)
	c := client(t, l)
	got, ok := roundTrip(t, c, []byte("ping"))
	if !ok || !strings.HasSuffix(got, "|ping") {
		t.Fatalf("unexpected reply %q ok=%v", got, ok)
	}
	st := l.Stats()
	if st.RxPackets != 1 || st.TxPackets != 1 || st.Sessions != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

// Regression test for v1's shared endAddr: replies must go to the client that
// sent the request, and each client must have its own upstream socket.
func TestMultipleClientsIsolated(t *testing.T) {
	remote := echoServer(t, nil)
	l := startTestListener(t, remote, false)
	a, b := client(t, l), client(t, l)

	ra, ok := roundTrip(t, a, []byte("from-a"))
	if !ok || !strings.HasSuffix(ra, "|from-a") {
		t.Fatalf("a: %q", ra)
	}
	rb, ok := roundTrip(t, b, []byte("from-b"))
	if !ok || !strings.HasSuffix(rb, "|from-b") {
		t.Fatalf("b: %q", rb)
	}
	// a talks again after b: v1 would have sent this reply to b.
	ra2, ok := roundTrip(t, a, []byte("again-a"))
	if !ok || !strings.HasSuffix(ra2, "|again-a") {
		t.Fatalf("a2: %q", ra2)
	}
	srcA := strings.Split(ra, "|")[0]
	srcB := strings.Split(rb, "|")[0]
	if srcA == srcB {
		t.Fatalf("clients share upstream socket %s", srcA)
	}
	if n := len(l.Sessions()); n != 2 {
		t.Fatalf("sessions = %d", n)
	}
}

func TestWireGuardFilterDrops(t *testing.T) {
	remote := echoServer(t, nil)
	l := startTestListener(t, remote, true)
	c := client(t, l)
	if _, ok := roundTrip(t, c, []byte("not wireguard at all............")); ok {
		t.Fatal("non-WireGuard packet was forwarded")
	}
	if l.Stats().Dropped != 1 {
		t.Fatalf("dropped = %d", l.Stats().Dropped)
	}
	if l.Stats().Sessions != 0 {
		t.Fatal("dropped packet created a session")
	}
}

func TestWireGuardPassesAndFiltersReplies(t *testing.T) {
	// Remote replies with a WireGuard-shaped prefix so the reply is a valid
	// transport message only when the total length stays aligned; the echo
	// adds "addr|" so we make the remote reply garbage and expect a drop.
	remote := echoServer(t, []byte("garbage"))
	l := startTestListener(t, remote, true)
	c := client(t, l)
	if _, ok := roundTrip(t, c, wgData(32)); ok {
		t.Fatal("non-WireGuard reply was delivered")
	}
	deadline := time.Now().Add(time.Second)
	for l.Stats().Dropped == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	st := l.Stats()
	if st.RxPackets != 1 || st.Dropped != 1 {
		t.Fatalf("stats: %+v", st)
	}
}

func TestLargeDatagram(t *testing.T) {
	remote := echoServer(t, nil)
	l := startTestListener(t, remote, false)
	c := client(t, l)
	payload := bytes.Repeat([]byte("x"), 9000) // v1 truncated at 1500
	got, ok := roundTrip(t, c, payload)
	if !ok || !strings.HasSuffix(got, string(payload)) {
		t.Fatalf("large datagram not relayed intact (len %d)", len(got))
	}
}

func TestSessionLimit(t *testing.T) {
	remote := echoServer(t, nil)
	l := startTestListener(t, remote, false, WithMaxSessions(1))
	a, b := client(t, l), client(t, l)
	if _, ok := roundTrip(t, a, []byte("a")); !ok {
		t.Fatal("first client failed")
	}
	if _, ok := roundTrip(t, b, []byte("b")); ok {
		t.Fatal("second client should be refused")
	}
}

func TestIdleExpiry(t *testing.T) {
	remote := echoServer(t, nil)
	l := startTestListener(t, remote, false)
	c := client(t, l)
	roundTrip(t, c, []byte("x"))
	l.expire(time.Now().Add(11 * time.Second))
	if n := l.Stats().Sessions; n != 0 {
		t.Fatalf("sessions after expiry = %d", n)
	}
	if _, ok := roundTrip(t, c, []byte("y")); !ok {
		t.Fatal("client could not reconnect after expiry")
	}
}

func TestCloseIsIdempotentAndReleasesPort(t *testing.T) {
	remote := echoServer(t, nil)
	l := startTestListener(t, remote, false)
	c := client(t, l)
	roundTrip(t, c, []byte("x"))
	addr := l.LocalAddr()
	l.Close()
	l.Close()
	pc, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		t.Fatalf("port not released: %v", err)
	}
	pc.Close()
}

func freePort(t *testing.T) int {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func TestManagerReconcile(t *testing.T) {
	remote := echoServer(t, nil)
	rport := remote.LocalAddr().(*net.UDPAddr).Port
	m := NewManager(quietLog(), withUpstreamNetwork("udp4"))
	defer m.Close()

	p1, p2 := freePort(t), freePort(t)
	a := endpoint.Endpoint{Name: "a", ListenAddress: "127.0.0.1", LocalPort: p1, RemoteAddress: "127.0.0.1", RemotePort: rport}
	b := endpoint.Endpoint{Name: "b", ListenAddress: "127.0.0.1", LocalPort: p2, RemoteAddress: "127.0.0.1", RemotePort: rport, Disabled: true}
	m.Apply([]endpoint.Endpoint{a, b})
	st := m.Status()
	if st["a"].State != StateRunning || st["b"].State != StateDisabled {
		t.Fatalf("status %+v", st)
	}
	la := m.listeners["a"]

	// Description-only change must not restart the listener.
	a.Description = "hello"
	m.Apply([]endpoint.Endpoint{a, b})
	if m.listeners["a"] != la {
		t.Fatal("listener restarted on description change")
	}

	// Enable b, change a's port -> a restarted, b started.
	p3 := freePort(t)
	a.LocalPort = p3
	b.Disabled = false
	m.Apply([]endpoint.Endpoint{a, b})
	st = m.Status()
	if st["a"].State != StateRunning || st["b"].State != StateRunning {
		t.Fatalf("status %+v", st)
	}
	if m.listeners["a"] == la || m.listeners["a"].LocalAddr().Port() != uint16(p3) {
		t.Fatal("a not restarted on new port")
	}

	// Remove a.
	m.Apply([]endpoint.Endpoint{b})
	if _, ok := m.Status()["a"]; ok {
		t.Fatal("a still present")
	}
}

func TestManagerRetriesFailedStart(t *testing.T) {
	remote := echoServer(t, nil)
	rport := remote.LocalAddr().(*net.UDPAddr).Port
	blocker, _ := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	port := blocker.LocalAddr().(*net.UDPAddr).Port

	m := NewManager(quietLog(), withUpstreamNetwork("udp4"))
	defer m.Close()
	e := endpoint.Endpoint{Name: "x", ListenAddress: "127.0.0.1", LocalPort: port, RemoteAddress: "127.0.0.1", RemotePort: rport}
	m.Apply([]endpoint.Endpoint{e})
	if st := m.Status()["x"]; st.State != StateError || st.Error == "" {
		t.Fatalf("expected error state, got %+v", st)
	}
	blocker.Close()
	m.Apply([]endpoint.Endpoint{e})
	if st := m.Status()["x"]; st.State != StateRunning {
		t.Fatalf("expected running after retry, got %+v", st)
	}
}
