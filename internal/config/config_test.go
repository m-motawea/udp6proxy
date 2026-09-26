package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "config.toml")
	os.WriteFile(p, []byte(body), 0o600)
	return p
}

// The exact v1 README example must keep working.
func TestLegacyConfig(t *testing.T) {
	p := write(t, `
[Redis]
Address = "127.0.0.1"
Port = 6379
Password = ""
DB = 0
Prefix = ""
Update = 60

[[Endpoint]]
Name = "wg0"
RemoteAddress = "2604:a8:40:d0::1875:7102"
RemotePort = 23456
LocalPort = 12345
WireGuard = true
`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Storage.Backend != "redis" || c.Storage.ReloadInterval != 60 || *c.Server.Listen != "127.0.0.1:8080" {
		t.Fatalf("defaults: %+v %+v", c.Storage, c.Server)
	}
	if len(c.Endpoint) != 1 || !c.Endpoint[0].WireGuard || c.Endpoint[0].LocalPort != 12345 {
		t.Fatalf("endpoint: %+v", c.Endpoint)
	}
	if c.Storage.StateDir != filepath.Dir(p) {
		t.Fatalf("state dir %q", c.Storage.StateDir)
	}
}

func TestDefaultsAndErrors(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "missing.toml"))
	if err != nil || c.Storage.Backend != "file" || c.Storage.ReloadInterval != 10 {
		t.Fatalf("missing file: %+v %v", c, err)
	}
	c, err = Load(write(t, "[Server]\nListen = \"\"\n"))
	if err != nil || *c.Server.Listen != "" {
		t.Fatal("empty Listen should disable API")
	}
	bad := map[string]string{
		"unknown key":   "[Server]\nListn = \"x\"\n",
		"bad backend":   "[Storage]\nBackend = \"etcd\"\n",
		"tls half":      "[Server]\nTLSCert = \"a\"\n",
		"bad endpoint":  "[[Endpoint]]\nName = \"x\"\nLocalPort = 1\nRemoteAddress = \"1.2.3.4\"\nRemotePort = 1\n",
		"dup endpoint":  "[[Endpoint]]\nName = \"x\"\nLocalPort = 1\nRemoteAddress = \"::1\"\nRemotePort = 1\n[[Endpoint]]\nName = \"x\"\nLocalPort = 2\nRemoteAddress = \"::1\"\nRemotePort = 1\n",
		"port conflict": "[[Endpoint]]\nName = \"x\"\nLocalPort = 1\nRemoteAddress = \"::1\"\nRemotePort = 1\n[[Endpoint]]\nName = \"y\"\nLocalPort = 1\nRemoteAddress = \"::1\"\nRemotePort = 1\n",
	}
	for name, body := range bad {
		if _, err := Load(write(t, body)); err == nil {
			t.Errorf("%s: expected error", name)
		} else if !strings.Contains(err.Error(), "") {
			t.Error(err)
		}
	}
}
