package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/m-motawea/udp6proxy/internal/endpoint"
	"github.com/m-motawea/udp6proxy/internal/redisc"
)

// Redis stores endpoints as JSON values in a single hash, "<prefix>endpoints".
//
// v1 stored one string key per endpoint ("<prefix><name>") and discovered
// them with KEYS, which blocks Redis and, with an empty prefix, picked up
// every key in the database. On first use Redis imports those legacy keys
// into the hash (see ImportLegacy); the old keys are left untouched.
type Redis struct {
	c      *redisc.Client
	prefix string
}

// NewRedis wraps a client.
func NewRedis(c *redisc.Client, prefix string) *Redis {
	return &Redis{c: c, prefix: prefix}
}

func (r *Redis) key() string { return r.prefix + "endpoints" }

func (r *Redis) List(ctx context.Context) ([]endpoint.Endpoint, error) {
	kv, err := r.c.Strings(ctx, "HGETALL", r.key())
	if err != nil {
		return nil, err
	}
	out := make([]endpoint.Endpoint, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		var e endpoint.Endpoint
		if err := json.Unmarshal([]byte(kv[i+1]), &e); err != nil {
			return nil, fmt.Errorf("endpoint %q: %w", kv[i], err)
		}
		e.Name = kv[i]
		out = append(out, e)
	}
	endpoint.Sort(out)
	return out, nil
}

func (r *Redis) Get(ctx context.Context, name string) (endpoint.Endpoint, error) {
	s, err := r.c.String(ctx, "HGET", r.key(), name)
	if errors.Is(err, redisc.Nil) {
		return endpoint.Endpoint{}, ErrNotFound
	}
	if err != nil {
		return endpoint.Endpoint{}, err
	}
	var e endpoint.Endpoint
	if err := json.Unmarshal([]byte(s), &e); err != nil {
		return endpoint.Endpoint{}, err
	}
	e.Name = name
	return e, nil
}

func (r *Redis) Put(ctx context.Context, e endpoint.Endpoint) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	_, err = r.c.Do(ctx, "HSET", r.key(), e.Name, string(b))
	return err
}

func (r *Redis) Delete(ctx context.Context, name string) error {
	n, err := r.c.Int(ctx, "HDEL", r.key(), name)
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *Redis) Close() error { return r.c.Close() }

// Ping checks connectivity.
func (r *Redis) Ping(ctx context.Context) error {
	_, err := r.c.Do(ctx, "PING")
	return err
}

// ImportLegacy copies v1 per-key endpoints into the hash if the hash does not
// exist yet. Keys that are not valid endpoint JSON are skipped.
func (r *Redis) ImportLegacy(ctx context.Context, log *slog.Logger) (int, error) {
	exists, err := r.c.Int(ctx, "EXISTS", r.key())
	if err != nil || exists > 0 {
		return 0, err
	}
	keys, err := r.c.Scan(ctx, r.prefix+"*")
	if err != nil {
		return 0, err
	}
	n := 0
	for _, k := range keys {
		if k == r.key() {
			continue
		}
		typ, err := r.c.String(ctx, "TYPE", k)
		if err != nil || typ != "string" {
			continue
		}
		val, err := r.c.String(ctx, "GET", k)
		if err != nil {
			continue
		}
		var e endpoint.Endpoint
		if json.Unmarshal([]byte(val), &e) != nil {
			continue
		}
		e.Normalize()
		if e.Name == "" {
			e.Name = k[len(r.prefix):]
		}
		if e.Validate() != nil {
			continue
		}
		if err := r.Put(ctx, e); err != nil {
			return n, err
		}
		n++
		log.Info("imported legacy v1 endpoint from redis", "key", k, "endpoint", e.Name)
	}
	return n, nil
}
