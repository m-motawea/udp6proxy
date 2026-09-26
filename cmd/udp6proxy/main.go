// Command udp6proxy relays IPv4 UDP traffic (typically WireGuard) to IPv6-only
// hosts, with a management API, web UI and CLI.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/m-motawea/udp6proxy/internal/api"
	"github.com/m-motawea/udp6proxy/internal/auth"
	"github.com/m-motawea/udp6proxy/internal/cli"
	"github.com/m-motawea/udp6proxy/internal/config"
	"github.com/m-motawea/udp6proxy/internal/proxy"
	"github.com/m-motawea/udp6proxy/internal/redisc"
	"github.com/m-motawea/udp6proxy/internal/store"
	"github.com/m-motawea/udp6proxy/internal/web"
)

// version is set with -ldflags "-X main.version=v2.0.0".
var version = ""

func getVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 7 {
				return "dev-" + s.Value[:7]
			}
		}
		if v := bi.Main.Version; v != "" && v != "(devel)" && !strings.Contains(v, "+dirty") {
			return v
		}
	}
	return "dev"
}

func main() {
	args := os.Args[1:]
	env := cli.Env{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}

	// v1 compatibility: "udp6proxy config.toml" or no args with ./config.toml.
	if len(args) == 1 && strings.HasSuffix(args[0], ".toml") {
		args = []string{"serve", "-c", args[0]}
	}
	if len(args) == 0 {
		if _, err := os.Stat("config.toml"); err == nil {
			args = []string{"serve", "-c", "config.toml"}
		}
	}

	if len(args) > 0 {
		switch args[0] {
		case "serve", "server", "daemon":
			os.Exit(serve(args[1:]))
		case "passwd":
			os.Exit(passwd(env, args[1:]))
		case "version", "--version", "-v":
			fmt.Println("udp6proxy", getVersion())
			return
		}
	}
	os.Exit(cli.Run(env, args))
}

func loadConfig(fs *flag.FlagSet, args []string) (*config.Config, error) {
	path := fs.String("c", defaultConfigPath(), "config file")
	fs.StringVar(path, "config", *path, "config file")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return config.Load(*path)
}

func defaultConfigPath() string {
	if p := os.Getenv("UDP6PROXY_CONFIG_FILE"); p != "" {
		return p
	}
	if _, err := os.Stat("config.toml"); err == nil {
		return "config.toml"
	}
	return "/etc/udp6proxy/config.toml"
}

func newLogger(level string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn", "warning":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
}

func openStore(ctx context.Context, cfg *config.Config, log *slog.Logger) (store.Store, error) {
	if cfg.Storage.Backend == "file" {
		return store.NewFile(filepath.Join(cfg.Storage.StateDir, "endpoints.json"))
	}
	opt := redisc.Options{
		Addr:     net.JoinHostPort(cfg.Redis.Address, strconv.Itoa(cfg.Redis.Port)),
		Username: cfg.Redis.Username,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	}
	if cfg.Redis.TLS {
		opt.TLS = &tls.Config{ServerName: cfg.Redis.Address, MinVersion: tls.VersionTLS12}
	}
	r := store.NewRedis(redisc.New(opt), cfg.Redis.Prefix)
	if err := r.Ping(ctx); err != nil {
		log.Warn("redis not reachable at startup; will keep retrying", "addr", opt.Addr, "err", err)
		return r, nil
	}
	if n, err := r.ImportLegacy(ctx, log); err != nil {
		log.Warn("legacy redis import failed", "err", err)
	} else if n > 0 {
		log.Info("imported v1 endpoints into redis hash; the old per-endpoint keys can be deleted", "count", n, "hash", cfg.Redis.Prefix+"endpoints")
	}
	return r, nil
}

func serve(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	log := newLogger(cfg.LogLevel)
	slog.SetDefault(log)
	log.Info("starting udp6proxy", "version", getVersion(), "config", cfg.Path(), "backend", cfg.Storage.Backend, "stateDir", cfg.Storage.StateDir)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	st, err := openStore(ctx, cfg, log)
	if err != nil {
		log.Error("cannot open store", "err", err)
		return 1
	}
	defer st.Close()
	if len(cfg.Endpoint) > 0 {
		if n, err := store.Seed(ctx, st, cfg.Endpoint); err != nil {
			log.Warn("could not seed endpoints from config file", "err", err)
		} else if n > 0 {
			log.Info("seeded endpoints from config file", "count", n)
		}
	}

	authSvc, err := auth.Open(filepath.Join(cfg.Storage.StateDir, "auth.json"), time.Duration(cfg.Server.SessionHours)*time.Hour)
	if err != nil {
		log.Error("cannot open auth store", "err", err)
		return 1
	}
	defer authSvc.Flush()
	if !authSvc.HasUsers() {
		pw := os.Getenv("UDP6PROXY_ADMIN_PASSWORD")
		generated := pw == ""
		if generated {
			pw = auth.RandomPassword()
		}
		if err := authSvc.AddUser("admin", pw); err != nil {
			log.Error("cannot create admin user", "err", err)
			return 1
		}
		if generated {
			fmt.Fprintf(os.Stderr, "\n  Created initial user \"admin\" with password: %s\n  Change it in the web UI or with \"udp6proxy passwd admin\".\n\n", pw)
		} else {
			log.Info("created initial user admin from UDP6PROXY_ADMIN_PASSWORD")
		}
	}

	mgr := proxy.NewManager(log)
	defer mgr.Close()

	srv := api.New(api.Options{
		Store:         st,
		Manager:       mgr,
		Auth:          authSvc,
		Log:           log,
		Backend:       cfg.Storage.Backend,
		Version:       getVersion(),
		SecureCookies: cfg.Server.SecureCookies,
		UI:            web.Handler(),
	})
	srv.Reload(ctx)

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			log.Info("SIGHUP: reloading endpoints")
			srv.TriggerReload()
		}
	}()
	go srv.Run(ctx, cfg.ReloadInterval())

	var httpSrv *http.Server
	errc := make(chan error, 1)
	if listen := *cfg.Server.Listen; listen != "" {
		httpSrv = &http.Server{
			Addr:              listen,
			Handler:           srv.Handler(),
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		ln, err := net.Listen("tcp", listen)
		if err != nil {
			log.Error("cannot listen for API", "addr", listen, "err", err)
			return 1
		}
		tlsOn := cfg.Server.TLSCert != ""
		scheme := "http"
		if tlsOn {
			scheme = "https"
		}
		if host, _, _ := net.SplitHostPort(listen); !tlsOn && !isLoopback(host) {
			log.Warn("API/UI is served over plain HTTP on a non-loopback address; passwords and tokens travel in clear text. Set Server.TLSCert/TLSKey or put it behind a TLS reverse proxy.")
		}
		log.Info("web UI and API listening", "url", fmt.Sprintf("%s://%s/", scheme, ln.Addr()))
		go func() {
			if tlsOn {
				errc <- httpSrv.ServeTLS(ln, cfg.Server.TLSCert, cfg.Server.TLSKey)
			} else {
				errc <- httpSrv.Serve(ln)
			}
		}()
	} else {
		log.Info("API/UI disabled (Server.Listen is empty)")
	}

	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			log.Error("API server failed", "err", err)
			return 1
		}
	}
	if httpSrv != nil {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(sctx)
	}
	return 0
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// passwd sets a user's password directly in the state dir (for recovery when
// nobody can log in). Creates the user if missing.
func passwd(env cli.Env, args []string) int {
	fs := flag.NewFlagSet("passwd", flag.ContinueOnError)
	cfg, err := loadConfig(fs, args)
	if err != nil {
		fmt.Fprintln(env.Stderr, "error:", err)
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(env.Stderr, "usage: udp6proxy passwd [-c config.toml] USER")
		return 2
	}
	user := fs.Arg(0)
	svc, err := auth.Open(filepath.Join(cfg.Storage.StateDir, "auth.json"), time.Hour)
	if err != nil {
		fmt.Fprintln(env.Stderr, "error:", err)
		return 1
	}
	pw := os.Getenv("UDP6PROXY_PASSWORD")
	if pw == "" {
		fmt.Fprintf(env.Stderr, "New password for %s: ", user)
		pw, err = readSecret()
		if err != nil {
			fmt.Fprintln(env.Stderr, "error:", err)
			return 1
		}
	}
	if svc.UserExists(user) {
		err = svc.SetPassword(user, pw)
	} else {
		err = svc.AddUser(user, pw)
	}
	if err != nil {
		fmt.Fprintln(env.Stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(env.Stdout, "Password for %s saved. Restart the daemon if it is running so it picks up the change.\n", user)
	return 0
}

func readSecret() (string, error) {
	if st, err := os.Stdin.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		off := execStty("-echo")
		if off == nil {
			defer func() { execStty("echo"); fmt.Fprintln(os.Stderr) }()
		}
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
