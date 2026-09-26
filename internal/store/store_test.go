package store

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/m-motawea/udp6proxy/internal/endpoint"
	"github.com/m-motawea/udp6proxy/internal/redisc"
)

func exercise(t *testing.T, s Store) {
	ctx := context.Background()
	if eps, err := s.List(ctx); err != nil || len(eps) != 0 {
		t.Fatalf("initial list: %v %v", eps, err)
	}
	a := endpoint.Endpoint{Name: "wg0", LocalPort: 1, RemoteAddress: "::1", RemotePort: 2, WireGuard: true}
	b := endpoint.Endpoint{Name: "a-first", LocalPort: 3, RemoteAddress: "example.com", RemotePort: 4}
	for _, e := range []endpoint.Endpoint{a, b} {
		if err := s.Put(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	eps, err := s.List(ctx)
	if err != nil || len(eps) != 2 || eps[0].Name != "a-first" {
		t.Fatalf("list: %+v %v", eps, err)
	}
	a.Description = "updated"
	if err := s.Put(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "wg0")
	if err != nil || got != a {
		t.Fatalf("get: %+v %v", got, err)
	}
	if _, err := s.Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	if err := s.Delete(ctx, "wg0"); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "wg0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete: %v", err)
	}
	n, err := Seed(ctx, s, []endpoint.Endpoint{b, a})
	if err != nil || n != 1 {
		t.Fatalf("seed: %d %v", n, err)
	}
}

func TestFileStore(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "endpoints.json")
	s, err := NewFile(p)
	if err != nil {
		t.Fatal(err)
	}
	exercise(t, s)
	if _, err := os.Stat(p); err != nil {
		t.Fatal(err)
	}
	// Corrupt file must surface an error rather than look empty.
	os.WriteFile(p, []byte("{nope"), 0o600)
	if _, err := s.List(context.Background()); err == nil {
		t.Fatal("expected parse error")
	}
}

func startRedis(t *testing.T) *redisc.Client {
	t.Helper()
	bin, err := exec.LookPath("redis-server")
	if err != nil {
		t.Skip("redis-server not installed")
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	cmd := exec.Command(bin, "--port", fmt.Sprint(port), "--save", "", "--appendonly", "no", "--requirepass", "s3cret")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	c := redisc.New(redisc.Options{Addr: fmt.Sprintf("127.0.0.1:%d", port), Password: "s3cret", DB: 2})
	t.Cleanup(func() { c.Close() })
	for i := 0; i < 50; i++ {
		if _, err := c.Do(context.Background(), "PING"); err == nil {
			return c
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("redis did not start")
	return nil
}

func TestRedisStore(t *testing.T) {
	c := startRedis(t)
	exercise(t, NewRedis(c, "u6p:"))
}

func TestRedisLegacyImport(t *testing.T) {
	c := startRedis(t)
	ctx := context.Background()
	// v1 wrote keys like this (capitalised field names, empty prefix).
	c.Do(ctx, "SET", "wg0", `{"Name":"wg0","WireGuard":true,"RemoteAddress":"2001:db8::1","RemotePort":23456,"LocalPort":12345}`)
	c.Do(ctx, "SET", "unrelated", "hello")
	c.Do(ctx, "HSET", "somehash", "a", "b")
	r := NewRedis(c, "")
	n, err := r.ImportLegacy(ctx, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil || n != 1 {
		t.Fatalf("import: %d %v", n, err)
	}
	e, err := r.Get(ctx, "wg0")
	if err != nil || !e.WireGuard || e.LocalPort != 12345 || e.RemoteAddress != "2001:db8::1" {
		t.Fatalf("imported: %+v %v", e, err)
	}
	// Second run is a no-op because the hash now exists.
	if n, _ := r.ImportLegacy(ctx, slog.Default()); n != 0 {
		t.Fatalf("re-import: %d", n)
	}
}

func TestRedisReconnect(t *testing.T) {
	c := startRedis(t)
	ctx := context.Background()
	c.Do(ctx, "CLIENT", "KILL", "TYPE", "normal") // kills our own connection
	if _, err := c.Do(ctx, "PING"); err != nil {
		t.Fatalf("did not reconnect: %v", err)
	}
	if _, err := c.Do(ctx, "NOSUCHCMD"); err == nil {
		t.Fatal("expected error reply")
	}
	if _, err := c.Do(ctx, "PING"); err != nil {
		t.Fatalf("stream out of sync after error reply: %v", err)
	}
}
