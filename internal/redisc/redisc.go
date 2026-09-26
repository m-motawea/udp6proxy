// Package redisc is a deliberately small Redis (RESP2) client covering the
// handful of commands udp6proxy needs. It keeps the binary dependency-free.
package redisc

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// Options configure a Client.
type Options struct {
	Addr     string
	Username string
	Password string
	DB       int
	TLS      *tls.Config
	Timeout  time.Duration // dial + per-command I/O timeout (default 5s)
}

// Client is safe for concurrent use; commands are serialised over a single
// connection which is transparently re-established after errors.
type Client struct {
	opt  Options
	mu   sync.Mutex
	conn net.Conn
	rd   *bufio.Reader
}

// Error is an error reply from the server.
type Error string

func (e Error) Error() string { return "redis: " + string(e) }

// Nil is returned for nil bulk replies.
var Nil = errors.New("redis: nil")

// New creates a client. No connection is made until the first command.
func New(opt Options) *Client {
	if opt.Timeout == 0 {
		opt.Timeout = 5 * time.Second
	}
	return &Client{opt: opt}
}

func (c *Client) connect(ctx context.Context) error {
	d := net.Dialer{Timeout: c.opt.Timeout}
	var conn net.Conn
	var err error
	if c.opt.TLS != nil {
		td := tls.Dialer{NetDialer: &d, Config: c.opt.TLS}
		conn, err = td.DialContext(ctx, "tcp", c.opt.Addr)
	} else {
		conn, err = d.DialContext(ctx, "tcp", c.opt.Addr)
	}
	if err != nil {
		return err
	}
	c.conn, c.rd = conn, bufio.NewReader(conn)
	if c.opt.Password != "" {
		args := []string{"AUTH", c.opt.Password}
		if c.opt.Username != "" {
			args = []string{"AUTH", c.opt.Username, c.opt.Password}
		}
		if _, err := c.roundTrip(args); err != nil {
			c.drop()
			return err
		}
	}
	if c.opt.DB != 0 {
		if _, err := c.roundTrip([]string{"SELECT", strconv.Itoa(c.opt.DB)}); err != nil {
			c.drop()
			return err
		}
	}
	return nil
}

func (c *Client) drop() {
	if c.conn != nil {
		c.conn.Close()
	}
	c.conn, c.rd = nil, nil
}

// Do runs a command and returns the decoded reply: string, int64, []any, nil
// (for nil bulk/array) or an Error.
func (c *Client) Do(ctx context.Context, args ...string) (any, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for attempt := 0; attempt < 2; attempt++ {
		if c.conn == nil {
			if err := c.connect(ctx); err != nil {
				return nil, err
			}
		}
		v, err := c.roundTrip(args)
		var rerr Error
		if err == nil || errors.As(err, &rerr) {
			return v, err
		}
		// I/O error: reconnect once (the server may have closed an idle conn).
		c.drop()
		if attempt == 1 || ctx.Err() != nil {
			return nil, err
		}
	}
	return nil, errors.New("unreachable")
}

func (c *Client) roundTrip(args []string) (any, error) {
	c.conn.SetDeadline(time.Now().Add(c.opt.Timeout))
	buf := make([]byte, 0, 64)
	buf = append(buf, '*')
	buf = strconv.AppendInt(buf, int64(len(args)), 10)
	buf = append(buf, '\r', '\n')
	for _, a := range args {
		buf = append(buf, '$')
		buf = strconv.AppendInt(buf, int64(len(a)), 10)
		buf = append(buf, '\r', '\n')
		buf = append(buf, a...)
		buf = append(buf, '\r', '\n')
	}
	if _, err := c.conn.Write(buf); err != nil {
		return nil, err
	}
	return readReply(c.rd)
}

func readLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return "", fmt.Errorf("redis: malformed line %q", line)
	}
	return line[:len(line)-2], nil
}

func readReply(r *bufio.Reader) (any, error) {
	line, err := readLine(r)
	if err != nil {
		return nil, err
	}
	if line == "" {
		return nil, errors.New("redis: empty reply")
	}
	switch line[0] {
	case '+':
		return line[1:], nil
	case '-':
		return nil, Error(line[1:])
	case ':':
		return strconv.ParseInt(line[1:], 10, 64)
	case '$':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		b := make([]byte, n+2)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		return string(b[:n]), nil
	case '*':
		n, err := strconv.Atoi(line[1:])
		if err != nil {
			return nil, err
		}
		if n < 0 {
			return nil, nil
		}
		out := make([]any, n)
		for i := range out {
			// Keep reading even after an element error so the stream stays in sync.
			v, err := readReply(r)
			var rerr Error
			if err != nil && !errors.As(err, &rerr) {
				return nil, err
			}
			if err != nil {
				out[i] = rerr
			} else {
				out[i] = v
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("redis: unexpected reply type %q", line[0])
}

// Close closes the connection.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.drop()
	return nil
}

// String runs a command expecting a bulk/simple string. Nil bulk -> Nil.
func (c *Client) String(ctx context.Context, args ...string) (string, error) {
	v, err := c.Do(ctx, args...)
	if err != nil {
		return "", err
	}
	switch s := v.(type) {
	case string:
		return s, nil
	case nil:
		return "", Nil
	}
	return "", fmt.Errorf("redis: unexpected %T reply", v)
}

// Int runs a command expecting an integer reply.
func (c *Client) Int(ctx context.Context, args ...string) (int64, error) {
	v, err := c.Do(ctx, args...)
	if err != nil {
		return 0, err
	}
	n, ok := v.(int64)
	if !ok {
		return 0, fmt.Errorf("redis: unexpected %T reply", v)
	}
	return n, nil
}

// Strings runs a command expecting an array of bulk strings.
func (c *Client) Strings(ctx context.Context, args ...string) ([]string, error) {
	v, err := c.Do(ctx, args...)
	if err != nil {
		return nil, err
	}
	return toStrings(v)
}

func toStrings(v any) ([]string, error) {
	if v == nil {
		return nil, nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("redis: unexpected %T reply", v)
	}
	out := make([]string, len(arr))
	for i, x := range arr {
		s, ok := x.(string)
		if !ok && x != nil {
			return nil, fmt.Errorf("redis: unexpected %T element", x)
		}
		out[i] = s
	}
	return out, nil
}

// Scan iterates SCAN with MATCH pattern and returns all keys.
func (c *Client) Scan(ctx context.Context, match string) ([]string, error) {
	cursor := "0"
	var keys []string
	for {
		v, err := c.Do(ctx, "SCAN", cursor, "MATCH", match, "COUNT", "500")
		if err != nil {
			return nil, err
		}
		arr, ok := v.([]any)
		if !ok || len(arr) != 2 {
			return nil, fmt.Errorf("redis: bad SCAN reply")
		}
		cursor, _ = arr[0].(string)
		ks, err := toStrings(arr[1])
		if err != nil {
			return nil, err
		}
		keys = append(keys, ks...)
		if cursor == "0" || cursor == "" {
			return keys, nil
		}
	}
}
