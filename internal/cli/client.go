// Package cli implements the udp6proxy command-line client.
package cli

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Settings are persisted by "udp6proxy login".
type Settings struct {
	Server   string `json:"server"`
	Token    string `json:"token"`
	Insecure bool   `json:"insecure,omitempty"`
}

func settingsPath() (string, error) {
	if p := os.Getenv("UDP6PROXY_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "udp6proxy", "cli.json"), nil
}

func loadSettings() (Settings, error) {
	var s Settings
	p, err := settingsPath()
	if err != nil {
		return s, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return s, err
	}
	return s, json.Unmarshal(data, &s)
}

func saveSettings(s Settings) (string, error) {
	p, err := settingsPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	data, _ := json.MarshalIndent(s, "", "  ")
	return p, os.WriteFile(p, append(data, '\n'), 0o600)
}

// Client talks to the management API.
type Client struct {
	base  string
	token string
	http  *http.Client
}

func newClient(server, token string, insecure bool) *Client {
	jar, _ := cookiejar.New(nil)
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	return &Client{
		base:  strings.TrimRight(server, "/"),
		token: token,
		http:  &http.Client{Timeout: 20 * time.Second, Transport: tr, Jar: jar},
	}
}

// APIError is a non-2xx response.
type APIError struct {
	Status int
	Msg    string            `json:"error"`
	Fields map[string]string `json:"fields"`
}

func (e *APIError) Error() string {
	if len(e.Fields) == 0 {
		return e.Msg
	}
	var b strings.Builder
	b.WriteString(e.Msg)
	for k, v := range e.Fields {
		fmt.Fprintf(&b, "\n  %s: %s", k, v)
	}
	return b.String()
}

func (c *Client) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Requested-With", "udp6proxy")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 16<<20))
	if err != nil {
		return err
	}
	if res.StatusCode >= 300 {
		ae := &APIError{Status: res.StatusCode}
		if json.Unmarshal(data, ae) != nil || ae.Msg == "" {
			ae.Msg = fmt.Sprintf("HTTP %d: %s", res.StatusCode, strings.TrimSpace(string(data)))
		}
		if res.StatusCode == http.StatusUnauthorized {
			ae.Msg += " (run \"udp6proxy login\")"
		}
		return ae
	}
	if out == nil || res.StatusCode == http.StatusNoContent {
		return nil
	}
	if raw, ok := out.(*json.RawMessage); ok {
		*raw = append((*raw)[:0], data...)
		return nil
	}
	return json.Unmarshal(data, out)
}

var errUsage = errors.New("usage")
