package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"
)

// Env holds CLI I/O so commands are testable.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}

type ctx struct {
	Env
	server   string
	token    string
	insecure bool
	json     bool
	client   *Client
}

const Usage = `udp6proxy — IPv4 → IPv6 UDP proxy

Daemon:
  udp6proxy serve [-c config.toml]         run the proxy, API and web UI
  udp6proxy passwd [-c config.toml] USER   set/reset a user's password offline
  udp6proxy version

Client (talks to the API; configure with "login" or UDP6PROXY_SERVER/UDP6PROXY_TOKEN):
  udp6proxy login [--server URL] [--user NAME | --token TOKEN]
  udp6proxy logout
  udp6proxy status

  udp6proxy endpoint ls
  udp6proxy endpoint get NAME
  udp6proxy endpoint add NAME --port N --remote ADDR [--remote-port N] [flags]
  udp6proxy endpoint set NAME [flags]          change only the given fields
  udp6proxy endpoint enable|disable NAME
  udp6proxy endpoint rm NAME [-y]
  udp6proxy endpoint sessions NAME

    endpoint flags:
      --port N            IPv4 port to listen on
      --listen ADDR       IPv4 address to bind (default all interfaces)
      --remote ADDR       IPv6 address or hostname ("[addr]:port" also accepted)
      --remote-port N     remote UDP port (default 51820 on add)
      --wireguard[=bool]  only relay well-formed WireGuard packets (default true on add)
      --idle SECONDS      session idle timeout (0 = default 180)
      --desc TEXT         description
      --disabled[=bool]   create/keep the endpoint disabled
      --rename NEW        (set only) rename the endpoint

  udp6proxy token ls | create NAME [--ttl-days N] | rm ID
  udp6proxy user  ls | add NAME | passwd NAME | rm NAME

Global flags: --server URL, --token TOKEN, --insecure (skip TLS verification), -o json
`

// Run executes a client command. args excludes the program name.
func Run(env Env, args []string) int {
	c := &ctx{Env: env}
	args, err := c.globalFlags(args)
	if err != nil {
		fmt.Fprintln(env.Stderr, "error:", err)
		return 2
	}
	if len(args) == 0 {
		fmt.Fprint(env.Stdout, Usage)
		return 0
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "help", "-h", "--help":
		fmt.Fprint(env.Stdout, Usage)
		return 0
	case "login":
		err = c.login(rest)
	case "logout":
		err = c.logout()
	case "status":
		err = c.withClient(c.status)
	case "endpoint", "endpoints", "ep":
		err = c.withClient(func() error { return c.endpoint(rest) })
	case "token", "tokens":
		err = c.withClient(func() error { return c.tokenCmd(rest) })
	case "user", "users":
		err = c.withClient(func() error { return c.userCmd(rest) })
	default:
		fmt.Fprintf(env.Stderr, "unknown command %q\n\n%s", cmd, Usage)
		return 2
	}
	if errors.Is(err, errUsage) {
		fmt.Fprint(env.Stderr, Usage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(env.Stderr, "error:", err)
		return 1
	}
	return 0
}

// globalFlags strips --server/--token/--insecure/-o from anywhere in args.
func (c *ctx) globalFlags(args []string) ([]string, error) {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if !strings.HasPrefix(a, "-") {
			out = append(out, a)
			continue
		}
		take := func() (string, error) {
			if hasVal {
				return val, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag %s needs a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		switch name {
		case "server":
			c.server, err = take()
		case "token":
			// "login --token" is handled by login itself.
			if len(out) > 0 && out[0] == "login" {
				out = append(out, a)
				continue
			}
			c.token, err = take()
		case "insecure":
			c.insecure = !hasVal || val == "true"
		case "o", "output":
			var v string
			v, err = take()
			if v != "json" && v != "table" {
				return nil, fmt.Errorf("-o must be json or table")
			}
			c.json = v == "json"
		default:
			out = append(out, a)
		}
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (c *ctx) resolve() error {
	s, err := loadSettings()
	if err != nil {
		return err
	}
	if c.server == "" {
		c.server = os.Getenv("UDP6PROXY_SERVER")
	}
	if c.server == "" {
		c.server = s.Server
	}
	if c.server == "" {
		c.server = "http://127.0.0.1:8080"
	}
	if c.token == "" {
		c.token = os.Getenv("UDP6PROXY_TOKEN")
	}
	if c.token == "" && strings.TrimRight(s.Server, "/") == strings.TrimRight(c.server, "/") {
		c.token = s.Token
	}
	c.insecure = c.insecure || s.Insecure
	c.client = newClient(c.server, c.token, c.insecure)
	return nil
}

func (c *ctx) withClient(f func() error) error {
	if err := c.resolve(); err != nil {
		return err
	}
	return f()
}

func (c *ctx) table() *tabwriter.Writer { return tabwriter.NewWriter(c.Stdout, 0, 0, 2, ' ', 0) }

func (c *ctx) printJSON(v any) error {
	enc := json.NewEncoder(c.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// parse parses flags interspersed with positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	fs.SetOutput(io.Discard)
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

// ---------- login ----------

func (c *ctx) login(args []string) error {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	user := fs.String("user", "", "username")
	token := fs.String("token", "", "API token")
	pwStdin := fs.Bool("password-stdin", false, "read password from stdin")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	if err := c.resolve(); err != nil {
		return err
	}
	if u, err := url.Parse(c.server); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("--server must be a URL like https://proxy.example.com:8080")
	}
	cl := newClient(c.server, "", c.insecure)

	if *token != "" {
		cl.token = *token
		var me struct{ Username string }
		if err := cl.do("GET", "/api/v1/me", nil, &me); err != nil {
			return err
		}
		p, err := saveSettings(Settings{Server: c.server, Token: *token, Insecure: c.insecure})
		if err != nil {
			return err
		}
		fmt.Fprintf(c.Stdout, "Logged in to %s as %s (token saved to %s)\n", c.server, me.Username, p)
		return nil
	}

	in := bufio.NewReader(c.Stdin)
	if *user == "" {
		fmt.Fprint(c.Stderr, "Username: ")
		line, _ := in.ReadString('\n')
		*user = strings.TrimSpace(line)
	}
	pw, err := c.readPassword(in, "Password: ", *pwStdin)
	if err != nil {
		return err
	}
	if err := cl.do("POST", "/api/v1/auth/login", map[string]string{"username": *user, "password": pw}, nil); err != nil {
		return err
	}
	host, _ := os.Hostname()
	var tok struct {
		Token string `json:"token"`
		Name  string `json:"name"`
	}
	name := "cli@" + host
	if err := cl.do("POST", "/api/v1/tokens", map[string]any{"name": name, "ttlDays": 0}, &tok); err != nil {
		return err
	}
	cl.do("POST", "/api/v1/auth/logout", nil, nil)
	p, err := saveSettings(Settings{Server: c.server, Token: tok.Token, Insecure: c.insecure})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.Stdout, "Logged in to %s as %s. Created API token %q (saved to %s)\n", c.server, *user, name, p)
	return nil
}

// readPassword reads a line without echo when stdin is a terminal.
func (c *ctx) readPassword(in *bufio.Reader, prompt string, fromStdin bool) (string, error) {
	if env := os.Getenv("UDP6PROXY_PASSWORD"); env != "" && !fromStdin {
		return env, nil
	}
	f, isFile := c.Stdin.(*os.File)
	tty := false
	if isFile && !fromStdin {
		if st, err := f.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
			tty = true
		}
	}
	if tty {
		fmt.Fprint(c.Stderr, prompt)
		cmd := exec.Command("stty", "-echo")
		cmd.Stdin = f
		if cmd.Run() == nil {
			defer func() {
				restore := exec.Command("stty", "echo")
				restore.Stdin = f
				restore.Run()
				fmt.Fprintln(c.Stderr)
			}()
		}
	}
	line, err := in.ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("reading password: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (c *ctx) logout() error {
	p, err := settingsPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Fprintln(c.Stdout, "Logged out (the API token remains valid until revoked with \"udp6proxy token rm\").")
	return nil
}

// ---------- status ----------

func (c *ctx) status() error {
	var s map[string]any
	if err := c.client.do("GET", "/api/v1/status", nil, &s); err != nil {
		return err
	}
	if c.json {
		return c.printJSON(s)
	}
	w := c.table()
	fmt.Fprintf(w, "Server:\t%s\n", c.server)
	fmt.Fprintf(w, "Version:\t%v\n", s["version"])
	fmt.Fprintf(w, "Backend:\t%v\n", s["backend"])
	fmt.Fprintf(w, "Uptime:\t%v\n", s["uptime"])
	if e, _ := s["reloadError"].(string); e != "" {
		fmt.Fprintf(w, "Store error:\t%s\n", e)
	}
	if m, ok := s["endpoints"].(map[string]any); ok {
		var parts []string
		for _, k := range []string{"running", "disabled", "error"} {
			if v, ok := m[k]; ok {
				parts = append(parts, fmt.Sprintf("%v %s", v, k))
			}
		}
		if len(parts) == 0 {
			parts = []string{"none"}
		}
		fmt.Fprintf(w, "Endpoints:\t%s\n", strings.Join(parts, ", "))
	}
	return w.Flush()
}

// ---------- endpoints ----------

type epStats struct {
	RxPackets, RxBytes, TxPackets, TxBytes, Dropped, Errors, SessionsTotal uint64
	Sessions                                                               int
	Remote                                                                 string
}

type epView struct {
	Name          string `json:"name"`
	Description   string `json:"description"`
	ListenAddress string `json:"listenAddress"`
	LocalPort     int    `json:"localPort"`
	RemoteAddress string `json:"remoteAddress"`
	RemotePort    int    `json:"remotePort"`
	WireGuard     bool   `json:"wireguard"`
	Disabled      bool   `json:"disabled"`
	IdleTimeout   int    `json:"idleTimeout"`
	Status        *struct {
		State string    `json:"state"`
		Error string    `json:"error"`
		Since time.Time `json:"since"`
		Stats *epStats  `json:"stats"`
	} `json:"status"`
}

func (e epView) listen() string {
	a := e.ListenAddress
	if a == "" {
		a = "0.0.0.0"
	}
	return fmt.Sprintf("%s:%d", a, e.LocalPort)
}

func (e epView) remote() string {
	return net.JoinHostPort(e.RemoteAddress, strconv.Itoa(e.RemotePort))
}

func (e epView) state() string {
	if e.Status == nil {
		return "pending"
	}
	return e.Status.State
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func (c *ctx) endpoint(args []string) error {
	if len(args) == 0 {
		args = []string{"ls"}
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "ls", "list":
		return c.epList()
	case "get", "show":
		if len(rest) != 1 {
			return errUsage
		}
		return c.epGet(rest[0])
	case "add", "create":
		return c.epWrite(rest, true)
	case "set", "update", "edit":
		return c.epWrite(rest, false)
	case "enable", "disable":
		if len(rest) != 1 {
			return errUsage
		}
		if err := c.client.do("PATCH", "/api/v1/endpoints/"+url.PathEscape(rest[0]), map[string]bool{"disabled": sub == "disable"}, nil); err != nil {
			return err
		}
		fmt.Fprintf(c.Stdout, "Endpoint %s %sd\n", rest[0], sub)
		return nil
	case "rm", "delete", "del":
		fs := flag.NewFlagSet("rm", flag.ContinueOnError)
		yes := fs.Bool("y", false, "do not ask for confirmation")
		pos, err := parse(fs, rest)
		if err != nil || len(pos) != 1 {
			return errUsage
		}
		if !*yes {
			fmt.Fprintf(c.Stderr, "Delete endpoint %s? [y/N] ", pos[0])
			line, _ := bufio.NewReader(c.Stdin).ReadString('\n')
			if a := strings.ToLower(strings.TrimSpace(line)); a != "y" && a != "yes" {
				return errors.New("aborted")
			}
		}
		if err := c.client.do("DELETE", "/api/v1/endpoints/"+url.PathEscape(pos[0]), nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(c.Stdout, "Endpoint %s deleted\n", pos[0])
		return nil
	case "sessions":
		if len(rest) != 1 {
			return errUsage
		}
		return c.epSessions(rest[0])
	}
	return errUsage
}

func (c *ctx) epList() error {
	if c.json {
		var raw json.RawMessage
		if err := c.client.do("GET", "/api/v1/endpoints", nil, &raw); err != nil {
			return err
		}
		_, err := c.Stdout.Write(append(raw, '\n'))
		return err
	}
	var eps []epView
	if err := c.client.do("GET", "/api/v1/endpoints", nil, &eps); err != nil {
		return err
	}
	if len(eps) == 0 {
		fmt.Fprintln(c.Stdout, "No endpoints. Add one with: udp6proxy endpoint add NAME --port N --remote ADDR")
		return nil
	}
	w := c.table()
	fmt.Fprintln(w, "NAME\tSTATE\tLISTEN\tREMOTE\tWG\tSESSIONS\tIN\tOUT\tDROPPED")
	for _, e := range eps {
		sess, in, out, drop := "-", "-", "-", "-"
		if e.Status != nil && e.Status.Stats != nil {
			s := e.Status.Stats
			sess, in, out, drop = strconv.Itoa(s.Sessions), humanBytes(s.RxBytes), humanBytes(s.TxBytes), strconv.FormatUint(s.Dropped, 10)
		}
		wg := "no"
		if e.WireGuard {
			wg = "yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", e.Name, e.state(), e.listen(), e.remote(), wg, sess, in, out, drop)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	for _, e := range eps {
		if e.Status != nil && e.Status.Error != "" {
			fmt.Fprintf(c.Stderr, "! %s: %s\n", e.Name, e.Status.Error)
		}
	}
	return nil
}

func (c *ctx) epGet(name string) error {
	var raw json.RawMessage
	if err := c.client.do("GET", "/api/v1/endpoints/"+url.PathEscape(name), nil, &raw); err != nil {
		return err
	}
	if c.json {
		_, err := c.Stdout.Write(append(raw, '\n'))
		return err
	}
	var e epView
	if err := json.Unmarshal(raw, &e); err != nil {
		return err
	}
	w := c.table()
	fmt.Fprintf(w, "Name:\t%s\n", e.Name)
	if e.Description != "" {
		fmt.Fprintf(w, "Description:\t%s\n", e.Description)
	}
	fmt.Fprintf(w, "State:\t%s\n", e.state())
	if e.Status != nil && e.Status.Error != "" {
		fmt.Fprintf(w, "Error:\t%s\n", e.Status.Error)
	}
	fmt.Fprintf(w, "Listen:\t%s\n", e.listen())
	fmt.Fprintf(w, "Remote:\t%s\n", e.remote())
	fmt.Fprintf(w, "WireGuard only:\t%v\n", e.WireGuard)
	idle := e.IdleTimeout
	if idle == 0 {
		idle = 180
	}
	fmt.Fprintf(w, "Idle timeout:\t%ds\n", idle)
	if e.Status != nil && e.Status.Stats != nil {
		s := e.Status.Stats
		fmt.Fprintf(w, "Resolved remote:\t%s\n", s.Remote)
		fmt.Fprintf(w, "Sessions:\t%d active, %d total\n", s.Sessions, s.SessionsTotal)
		fmt.Fprintf(w, "In:\t%d packets, %s\n", s.RxPackets, humanBytes(s.RxBytes))
		fmt.Fprintf(w, "Out:\t%d packets, %s\n", s.TxPackets, humanBytes(s.TxBytes))
		fmt.Fprintf(w, "Dropped / errors:\t%d / %d\n", s.Dropped, s.Errors)
	}
	return w.Flush()
}

// optBool is a bool flag that records whether it was set.
type optBool struct {
	set, val bool
}

func (b *optBool) String() string { return strconv.FormatBool(b.val) }
func (b *optBool) Set(s string) error {
	v, err := strconv.ParseBool(s)
	b.set, b.val = true, v
	return err
}
func (b *optBool) IsBoolFlag() bool { return true }

func (c *ctx) epWrite(args []string, create bool) error {
	fs := flag.NewFlagSet("endpoint", flag.ContinueOnError)
	port := fs.Int("port", 0, "")
	listen := fs.String("listen", "", "")
	remote := fs.String("remote", "", "")
	remotePort := fs.Int("remote-port", 0, "")
	idle := fs.Int("idle", 0, "")
	desc := fs.String("desc", "", "")
	rename := fs.String("rename", "", "")
	var wg, disabled optBool
	fs.Var(&wg, "wireguard", "")
	fs.Var(&disabled, "disabled", "")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errUsage
	}
	name := pos[0]
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	// Accept --remote "[2001:db8::1]:51820".
	if strings.HasPrefix(*remote, "[") {
		if h, p, err := net.SplitHostPort(*remote); err == nil {
			*remote = h
			if !set["remote-port"] {
				if n, err := strconv.Atoi(p); err == nil {
					*remotePort = n
					set["remote-port"] = true
				}
			}
		}
	}

	body := map[string]any{}
	if set["port"] {
		body["localPort"] = *port
	}
	if set["listen"] {
		body["listenAddress"] = *listen
	}
	if set["remote"] {
		body["remoteAddress"] = *remote
	}
	if set["remote-port"] {
		body["remotePort"] = *remotePort
	}
	if set["idle"] {
		body["idleTimeout"] = *idle
	}
	if set["desc"] {
		body["description"] = *desc
	}
	if wg.set {
		body["wireguard"] = wg.val
	}
	if disabled.set {
		body["disabled"] = disabled.val
	}

	var out epView
	if create {
		if set["rename"] {
			return errors.New("--rename is only valid with \"endpoint set\"")
		}
		body["name"] = name
		if !set["remote-port"] {
			body["remotePort"] = 51820
		}
		if !wg.set {
			body["wireguard"] = true
		}
		if err := c.client.do("POST", "/api/v1/endpoints", body, &out); err != nil {
			return err
		}
		fmt.Fprintf(c.Stdout, "Endpoint %s created: %s -> %s (%s)\n", out.Name, out.listen(), out.remote(), out.state())
	} else {
		if set["rename"] {
			body["name"] = *rename
		}
		if len(body) == 0 {
			return errors.New("nothing to change; pass at least one flag")
		}
		if err := c.client.do("PATCH", "/api/v1/endpoints/"+url.PathEscape(name), body, &out); err != nil {
			return err
		}
		fmt.Fprintf(c.Stdout, "Endpoint %s updated: %s -> %s (%s)\n", out.Name, out.listen(), out.remote(), out.state())
	}
	if out.Status != nil && out.Status.Error != "" {
		fmt.Fprintf(c.Stderr, "warning: endpoint saved but failed to start: %s\n", out.Status.Error)
	}
	return nil
}

func (c *ctx) epSessions(name string) error {
	var raw json.RawMessage
	if err := c.client.do("GET", "/api/v1/endpoints/"+url.PathEscape(name)+"/sessions", nil, &raw); err != nil {
		return err
	}
	if c.json {
		_, err := c.Stdout.Write(append(raw, '\n'))
		return err
	}
	var ss []struct {
		Client, Upstream  string
		LastSeen, Created time.Time
		RxBytes, TxBytes  uint64
	}
	if err := json.Unmarshal(raw, &ss); err != nil {
		return err
	}
	if len(ss) == 0 {
		fmt.Fprintln(c.Stdout, "No active sessions.")
		return nil
	}
	w := c.table()
	fmt.Fprintln(w, "CLIENT\tUPSTREAM\tIN\tOUT\tLAST SEEN\tAGE")
	for _, s := range ss {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s ago\t%s\n", s.Client, s.Upstream, humanBytes(s.RxBytes), humanBytes(s.TxBytes),
			time.Since(s.LastSeen).Round(time.Second), time.Since(s.Created).Round(time.Second))
	}
	return w.Flush()
}

// ---------- tokens ----------

func (c *ctx) tokenCmd(args []string) error {
	if len(args) == 0 {
		args = []string{"ls"}
	}
	switch args[0] {
	case "ls", "list":
		var raw json.RawMessage
		if err := c.client.do("GET", "/api/v1/tokens", nil, &raw); err != nil {
			return err
		}
		if c.json {
			_, err := c.Stdout.Write(append(raw, '\n'))
			return err
		}
		var toks []struct {
			ID, Name, Username, Hint string
			Created                  time.Time
			Expires, LastUsed        *time.Time
		}
		json.Unmarshal(raw, &toks)
		w := c.table()
		fmt.Fprintln(w, "ID\tNAME\tOWNER\tTOKEN\tCREATED\tLAST USED\tEXPIRES")
		for _, t := range toks {
			last, exp := "never", "never"
			if t.LastUsed != nil {
				last = t.LastUsed.Local().Format("2006-01-02 15:04")
			}
			if t.Expires != nil {
				exp = t.Expires.Local().Format("2006-01-02")
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", t.ID, t.Name, t.Username, t.Hint, t.Created.Local().Format("2006-01-02"), last, exp)
		}
		return w.Flush()
	case "create", "add":
		fs := flag.NewFlagSet("token", flag.ContinueOnError)
		ttl := fs.Int("ttl-days", 0, "")
		pos, err := parse(fs, args[1:])
		if err != nil || len(pos) != 1 {
			return errUsage
		}
		var t struct{ ID, Token string }
		if err := c.client.do("POST", "/api/v1/tokens", map[string]any{"name": pos[0], "ttlDays": *ttl}, &t); err != nil {
			return err
		}
		if c.json {
			return c.printJSON(t)
		}
		fmt.Fprintf(c.Stderr, "Token %s created. Copy it now; it will not be shown again:\n", t.ID)
		fmt.Fprintln(c.Stdout, t.Token)
		return nil
	case "rm", "revoke", "delete":
		if len(args) != 2 {
			return errUsage
		}
		if err := c.client.do("DELETE", "/api/v1/tokens/"+url.PathEscape(args[1]), nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(c.Stdout, "Token %s revoked\n", args[1])
		return nil
	}
	return errUsage
}

// ---------- users ----------

func (c *ctx) userCmd(args []string) error {
	if len(args) == 0 {
		args = []string{"ls"}
	}
	in := bufio.NewReader(c.Stdin)
	switch args[0] {
	case "ls", "list":
		var raw json.RawMessage
		if err := c.client.do("GET", "/api/v1/users", nil, &raw); err != nil {
			return err
		}
		if c.json {
			_, err := c.Stdout.Write(append(raw, '\n'))
			return err
		}
		var us []struct {
			Username string
			Created  time.Time
		}
		json.Unmarshal(raw, &us)
		w := c.table()
		fmt.Fprintln(w, "USERNAME\tCREATED")
		for _, u := range us {
			fmt.Fprintf(w, "%s\t%s\n", u.Username, u.Created.Local().Format("2006-01-02 15:04"))
		}
		return w.Flush()
	case "add", "create":
		fs := flag.NewFlagSet("user", flag.ContinueOnError)
		pwStdin := fs.Bool("password-stdin", false, "")
		pos, err := parse(fs, args[1:])
		if err != nil || len(pos) != 1 {
			return errUsage
		}
		pw, err := c.readPassword(in, "Password for "+pos[0]+": ", *pwStdin)
		if err != nil {
			return err
		}
		if err := c.client.do("POST", "/api/v1/users", map[string]string{"username": pos[0], "password": pw}, nil); err != nil {
			return err
		}
		fmt.Fprintf(c.Stdout, "User %s created\n", pos[0])
		return nil
	case "passwd", "password":
		fs := flag.NewFlagSet("user", flag.ContinueOnError)
		pwStdin := fs.Bool("password-stdin", false, "")
		pos, err := parse(fs, args[1:])
		if err != nil || len(pos) != 1 {
			return errUsage
		}
		pw, err := c.readPassword(in, "New password for "+pos[0]+": ", *pwStdin)
		if err != nil {
			return err
		}
		if err := c.client.do("PUT", "/api/v1/users/"+url.PathEscape(pos[0])+"/password", map[string]string{"password": pw}, nil); err != nil {
			return err
		}
		fmt.Fprintf(c.Stdout, "Password for %s updated\n", pos[0])
		return nil
	case "rm", "delete":
		if len(args) != 2 {
			return errUsage
		}
		if err := c.client.do("DELETE", "/api/v1/users/"+url.PathEscape(args[1]), nil, nil); err != nil {
			return err
		}
		fmt.Fprintf(c.Stdout, "User %s deleted\n", args[1])
		return nil
	}
	return errUsage
}
