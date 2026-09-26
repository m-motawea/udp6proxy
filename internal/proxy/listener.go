// Package proxy implements the IPv4 -> IPv6 UDP forwarding engine.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/m-motawea/udp6proxy/internal/endpoint"
)

const (
	maxDatagram        = 65535
	defaultMaxSessions = 4096
	resolveInterval    = 60 * time.Second
	errLogInterval     = 10 * time.Second
)

// Resolver looks up the IPv6 address for a hostname.
type Resolver func(ctx context.Context, host string) (netip.Addr, error)

// DefaultResolver resolves AAAA records via the system resolver.
func DefaultResolver(ctx context.Context, host string) (netip.Addr, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip6", host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if a.Is6() && !a.Is4In6() {
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no AAAA record for %s", host)
}

// Stats are cumulative counters for one listener.
type Stats struct {
	RxPackets     uint64 `json:"rxPackets"` // client -> remote
	RxBytes       uint64 `json:"rxBytes"`
	TxPackets     uint64 `json:"txPackets"` // remote -> client
	TxBytes       uint64 `json:"txBytes"`
	Dropped       uint64 `json:"dropped"`
	Errors        uint64 `json:"errors"`
	Sessions      int    `json:"sessions"`
	SessionsTotal uint64 `json:"sessionsTotal"`
	Remote        string `json:"remote,omitempty"` // currently resolved remote address
}

// SessionInfo describes one active client session.
type SessionInfo struct {
	Client    string    `json:"client"`
	Upstream  string    `json:"upstream"` // local IPv6 source address used for this client
	Remote    string    `json:"remote"`
	Created   time.Time `json:"created"`
	LastSeen  time.Time `json:"lastSeen"`
	RxPackets uint64    `json:"rxPackets"`
	RxBytes   uint64    `json:"rxBytes"`
	TxPackets uint64    `json:"txPackets"`
	TxBytes   uint64    `json:"txBytes"`
}

type counters struct {
	rxPackets, rxBytes, txPackets, txBytes atomic.Uint64
}

type session struct {
	client   netip.AddrPort
	remote   netip.AddrPort
	conn     *net.UDPConn
	created  time.Time
	lastSeen atomic.Int64 // unix nanos
	counters
}

func (s *session) touch() { s.lastSeen.Store(time.Now().UnixNano()) }

// Listener forwards datagrams arriving on one IPv4 UDP port to one IPv6
// destination. Every distinct IPv4 client gets its own upstream IPv6 socket,
// so replies are always delivered to the client they belong to and the remote
// peer sees each client as a distinct source port.
type Listener struct {
	ep          endpoint.Endpoint
	log         *slog.Logger
	resolve     Resolver
	maxSessions int
	idle        time.Duration
	upstreamNet string

	conn *net.UDPConn

	mu       sync.Mutex
	sessions map[netip.AddrPort]*session
	remote   netip.AddrPort
	closed   bool

	counters
	dropped, errors, sessionsTotal atomic.Uint64

	errMu      sync.Mutex
	lastErrLog time.Time
	suppressed int

	done chan struct{}
	wg   sync.WaitGroup
}

// ListenerOption customises a Listener.
type ListenerOption func(*Listener)

// WithResolver overrides DNS resolution (used in tests).
func WithResolver(r Resolver) ListenerOption { return func(l *Listener) { l.resolve = r } }

// WithMaxSessions caps concurrent client sessions.
func WithMaxSessions(n int) ListenerOption { return func(l *Listener) { l.maxSessions = n } }

// withUpstreamNetwork overrides the upstream socket family. Tests use "udp4"
// because CI sandboxes frequently lack IPv6.
func withUpstreamNetwork(n string) ListenerOption { return func(l *Listener) { l.upstreamNet = n } }

// WithLogger sets the logger.
func WithLogger(lg *slog.Logger) ListenerOption { return func(l *Listener) { l.log = lg } }

// StartListener binds the IPv4 socket and starts forwarding. On error nothing
// is left open.
func StartListener(ep endpoint.Endpoint, opts ...ListenerOption) (*Listener, error) {
	l := &Listener{
		ep:          ep,
		log:         slog.Default(),
		resolve:     DefaultResolver,
		maxSessions: defaultMaxSessions,
		upstreamNet: "udp6",
		idle:        time.Duration(ep.EffectiveIdleTimeout()) * time.Second,
		sessions:    make(map[netip.AddrPort]*session),
		done:        make(chan struct{}),
	}
	for _, o := range opts {
		o(l)
	}
	l.log = l.log.With("endpoint", ep.Name)

	remote, err := l.resolveRemote()
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", ep.RemoteAddress, err)
	}
	l.remote = remote

	laddr, err := netip.ParseAddr(ep.EffectiveListenAddress())
	if err != nil {
		return nil, fmt.Errorf("listen address: %w", err)
	}
	conn, err := net.ListenUDP("udp4", net.UDPAddrFromAddrPort(netip.AddrPortFrom(laddr, uint16(ep.LocalPort))))
	if err != nil {
		return nil, err
	}
	l.conn = conn

	l.wg.Add(2)
	go l.readLoop()
	go l.janitor()
	l.log.Info("listener started", "listen", conn.LocalAddr().String(), "remote", remote.String(), "wireguard", ep.WireGuard)
	return l, nil
}

// LocalAddr returns the bound IPv4 address.
func (l *Listener) LocalAddr() netip.AddrPort {
	return l.conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func (l *Listener) resolveRemote() (netip.AddrPort, error) {
	port := uint16(l.ep.RemotePort)
	if a, err := netip.ParseAddr(l.ep.RemoteAddress); err == nil {
		return netip.AddrPortFrom(a, port), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	a, err := l.resolve(ctx, l.ep.RemoteAddress)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(a, port), nil
}

// Close stops the listener and all its sessions and waits for goroutines.
func (l *Listener) Close() {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.closed = true
	sessions := l.sessions
	l.sessions = map[netip.AddrPort]*session{}
	l.mu.Unlock()

	close(l.done)
	l.conn.Close()
	for _, s := range sessions {
		s.conn.Close()
	}
	l.wg.Wait()
	l.log.Info("listener stopped")
}

func (l *Listener) logErr(msg string, err error) {
	l.errors.Add(1)
	l.errMu.Lock()
	defer l.errMu.Unlock()
	if time.Since(l.lastErrLog) < errLogInterval {
		l.suppressed++
		return
	}
	l.log.Warn(msg, "err", err, "suppressed", l.suppressed)
	l.lastErrLog = time.Now()
	l.suppressed = 0
}

func (l *Listener) readLoop() {
	defer l.wg.Done()
	buf := make([]byte, maxDatagram)
	consecutive := 0
	for {
		n, addr, err := l.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			l.logErr("read from client failed", err)
			if consecutive++; consecutive > 100 {
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}
		consecutive = 0
		pkt := buf[:n]
		if l.ep.WireGuard && !IsWireGuard(pkt) {
			l.dropped.Add(1)
			continue
		}
		client := netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())
		s, err := l.getSession(client)
		if err != nil {
			l.dropped.Add(1)
			l.logErr("cannot create session", err)
			continue
		}
		s.touch()
		if _, err := s.conn.Write(pkt); err != nil {
			l.logErr("write to remote failed", err)
			continue
		}
		s.rxPackets.Add(1)
		s.rxBytes.Add(uint64(n))
		l.rxPackets.Add(1)
		l.rxBytes.Add(uint64(n))
	}
}

var errTooManySessions = errors.New("session limit reached")

func (l *Listener) getSession(client netip.AddrPort) (*session, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if s, ok := l.sessions[client]; ok {
		return s, nil
	}
	if l.closed {
		return nil, net.ErrClosed
	}
	if len(l.sessions) >= l.maxSessions {
		return nil, errTooManySessions
	}
	conn, err := net.DialUDP(l.upstreamNet, nil, net.UDPAddrFromAddrPort(l.remote))
	if err != nil {
		return nil, err
	}
	s := &session{client: client, remote: l.remote, conn: conn, created: time.Now()}
	s.touch()
	l.sessions[client] = s
	l.sessionsTotal.Add(1)
	l.wg.Add(1)
	go l.sessionLoop(s)
	l.log.Debug("session opened", "client", client.String(), "upstream", conn.LocalAddr().String())
	return s, nil
}

func (l *Listener) sessionLoop(s *session) {
	defer l.wg.Done()
	buf := make([]byte, maxDatagram)
	consecutive := 0
	for {
		n, err := s.conn.Read(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// ECONNREFUSED is ICMP port-unreachable from the remote; it is
			// expected while the peer is down and is not worth logging.
			if !errors.Is(err, syscall.ECONNREFUSED) {
				l.logErr("read from remote failed", err)
			}
			if consecutive++; consecutive > 100 {
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}
		consecutive = 0
		pkt := buf[:n]
		if l.ep.WireGuard && !IsWireGuard(pkt) {
			l.dropped.Add(1)
			continue
		}
		s.touch()
		if _, err := l.conn.WriteToUDPAddrPort(pkt, s.client); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			l.logErr("write to client failed", err)
			continue
		}
		s.txPackets.Add(1)
		s.txBytes.Add(uint64(n))
		l.txPackets.Add(1)
		l.txBytes.Add(uint64(n))
	}
}

func (l *Listener) janitor() {
	defer l.wg.Done()
	sweep := l.idle / 4
	if sweep > 15*time.Second {
		sweep = 15 * time.Second
	}
	if sweep < time.Second {
		sweep = time.Second
	}
	t := time.NewTicker(sweep)
	defer t.Stop()
	lastResolve := time.Now()
	_, isLiteral := netip.ParseAddr(l.ep.RemoteAddress)
	for {
		select {
		case <-l.done:
			return
		case now := <-t.C:
			l.expire(now)
			if isLiteral != nil && now.Sub(lastResolve) >= resolveInterval {
				lastResolve = now
				if r, err := l.resolveRemote(); err != nil {
					l.logErr("re-resolve remote failed", err)
				} else {
					l.mu.Lock()
					if r != l.remote {
						l.log.Info("remote address changed", "old", l.remote.String(), "new", r.String())
						l.remote = r
					}
					l.mu.Unlock()
				}
			}
		}
	}
}

func (l *Listener) expire(now time.Time) {
	cutoff := now.Add(-l.idle).UnixNano()
	var stale []*session
	l.mu.Lock()
	for k, s := range l.sessions {
		// Sessions pinned to an outdated remote address are retired as soon
		// as they go quiet for a moment so clients move to the new address.
		if s.lastSeen.Load() < cutoff || (s.remote != l.remote && s.lastSeen.Load() < now.Add(-5*time.Second).UnixNano()) {
			stale = append(stale, s)
			delete(l.sessions, k)
		}
	}
	l.mu.Unlock()
	for _, s := range stale {
		s.conn.Close()
		l.log.Debug("session closed", "client", s.client.String())
	}
}

// Stats returns a snapshot of the listener counters.
func (l *Listener) Stats() Stats {
	l.mu.Lock()
	n := len(l.sessions)
	remote := l.remote
	l.mu.Unlock()
	return Stats{
		RxPackets:     l.rxPackets.Load(),
		RxBytes:       l.rxBytes.Load(),
		TxPackets:     l.txPackets.Load(),
		TxBytes:       l.txBytes.Load(),
		Dropped:       l.dropped.Load(),
		Errors:        l.errors.Load(),
		Sessions:      n,
		SessionsTotal: l.sessionsTotal.Load(),
		Remote:        remote.String(),
	}
}

// Sessions lists active client sessions.
func (l *Listener) Sessions() []SessionInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]SessionInfo, 0, len(l.sessions))
	for _, s := range l.sessions {
		out = append(out, SessionInfo{
			Client:    s.client.String(),
			Upstream:  s.conn.LocalAddr().String(),
			Remote:    s.remote.String(),
			Created:   s.created,
			LastSeen:  time.Unix(0, s.lastSeen.Load()),
			RxPackets: s.rxPackets.Load(),
			RxBytes:   s.rxBytes.Load(),
			TxPackets: s.txPackets.Load(),
			TxBytes:   s.txBytes.Load(),
		})
	}
	return out
}
