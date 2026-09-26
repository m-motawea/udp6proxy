package cli

import (
	"bytes"
	"io"
	"log/slog"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/m-motawea/udp6proxy/internal/api"
	"github.com/m-motawea/udp6proxy/internal/auth"
	"github.com/m-motawea/udp6proxy/internal/proxy"
	"github.com/m-motawea/udp6proxy/internal/store"
)

func init() { auth.Iterations = 1000 }

func setup(t *testing.T) (*httptest.Server, func(stdin string, args ...string) (int, string, string)) {
	dir := t.TempDir()
	st, _ := store.NewFile(filepath.Join(dir, "endpoints.json"))
	a, _ := auth.Open(filepath.Join(dir, "auth.json"), time.Hour)
	a.AddUser("admin", "adminpass")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := proxy.NewManager(log)
	t.Cleanup(mgr.Close)
	srv := api.New(api.Options{Store: st, Manager: mgr, Auth: a, Log: log, Backend: "file", Version: "test"})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	t.Setenv("UDP6PROXY_CONFIG", filepath.Join(dir, "cli.json"))
	t.Setenv("UDP6PROXY_SERVER", "")
	t.Setenv("UDP6PROXY_TOKEN", "")
	t.Setenv("UDP6PROXY_PASSWORD", "")
	run := func(stdin string, args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := Run(Env{Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb}, args)
		return code, out.String(), errb.String()
	}
	return ts, run
}

func TestCLIFlow(t *testing.T) {
	ts, run := setup(t)

	if code, _, errs := run("", "--server", ts.URL, "endpoint", "ls"); code == 0 || !strings.Contains(errs, "login") {
		t.Fatalf("unauthenticated ls should fail with a login hint: %d %q", code, errs)
	}
	if code, _, errs := run("admin\nwrong\n", "login", "--server", ts.URL); code == 0 {
		t.Fatalf("wrong password accepted: %s", errs)
	}
	code, out, errs := run("admin\nadminpass\n", "login", "--server", ts.URL)
	if code != 0 || !strings.Contains(out, "Logged in") {
		t.Fatalf("login: %d %s %s", code, out, errs)
	}

	// Saved token is used without --server now.
	t.Setenv("UDP6PROXY_SERVER", ts.URL)
	code, out, errs = run("", "endpoint", "add", "wg0", "--port", "0", "--remote", "[2001:db8::1]:51821", "--listen", "127.0.0.1", "--desc", "frankfurt")
	if code != 1 || !strings.Contains(errs, "localPort") {
		t.Fatalf("port 0 should be rejected with a field error: %d %s %s", code, out, errs)
	}
	code, out, errs = run("", "endpoint", "add", "wg0", "--port", "40123", "--remote", "[2001:db8::1]:51821", "--listen", "127.0.0.1", "--desc", "frankfurt")
	if code != 0 || !strings.Contains(out, "[2001:db8::1]:51821") {
		t.Fatalf("add: %d %s %s", code, out, errs)
	}
	code, out, _ = run("", "endpoint", "ls")
	if code != 0 || !strings.Contains(out, "wg0") || !strings.Contains(out, "running") || !strings.Contains(out, "yes") {
		t.Fatalf("ls: %s", out)
	}
	code, out, errs = run("", "endpoint", "set", "wg0", "--wireguard=false", "--idle", "60")
	if code != 0 {
		t.Fatalf("set: %s %s", out, errs)
	}
	code, out, _ = run("", "endpoint", "get", "wg0", "-o", "json")
	if code != 0 || !strings.Contains(out, `"wireguard": false`) || !strings.Contains(out, `"idleTimeout": 60`) || !strings.Contains(out, "frankfurt") {
		t.Fatalf("get json: %s", out)
	}
	if code, out, _ := run("", "endpoint", "disable", "wg0"); code != 0 || !strings.Contains(out, "disabled") {
		t.Fatalf("disable: %s", out)
	}
	if _, out, _ := run("", "endpoint", "get", "wg0"); !strings.Contains(out, "disabled") {
		t.Fatalf("state after disable: %s", out)
	}
	if code, _, _ := run("", "endpoint", "set", "wg0"); code == 0 {
		t.Fatal("set without flags should fail")
	}
	if code, _, _ := run("n\n", "endpoint", "rm", "wg0"); code == 0 {
		t.Fatal("rm without confirmation should abort")
	}
	if code, out, _ := run("", "endpoint", "rm", "-y", "wg0"); code != 0 || !strings.Contains(out, "deleted") {
		t.Fatalf("rm: %s", out)
	}

	// Tokens and users.
	code, out, _ = run("", "token", "create", "ci", "--ttl-days", "7")
	if code != 0 || !strings.HasPrefix(out, auth.TokenPrefix) {
		t.Fatalf("token create: %s", out)
	}
	tok := strings.TrimSpace(out)
	if code, out, _ := run("", "--token", tok, "status"); code != 0 || !strings.Contains(out, "file") {
		t.Fatalf("status with explicit token: %s", out)
	}
	if code, out, _ := run("", "token", "ls"); code != 0 || !strings.Contains(out, "ci") {
		t.Fatalf("token ls: %s", out)
	}
	if code, _, errs := run("bobpassword\n", "user", "add", "bob", "--password-stdin"); code != 0 {
		t.Fatalf("user add: %s", errs)
	}
	if _, out, _ := run("", "user", "ls"); !strings.Contains(out, "bob") {
		t.Fatalf("user ls: %s", out)
	}
	if code, _, _ := run("", "bogus"); code != 2 {
		t.Fatal("unknown command should exit 2")
	}
}
