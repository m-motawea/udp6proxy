// Package store persists endpoint definitions.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/m-motawea/udp6proxy/internal/endpoint"
)

// ErrNotFound is returned when an endpoint does not exist.
var ErrNotFound = errors.New("endpoint not found")

// Store is a persistent set of endpoints keyed by name.
type Store interface {
	List(ctx context.Context) ([]endpoint.Endpoint, error)
	Get(ctx context.Context, name string) (endpoint.Endpoint, error)
	// Put creates or replaces an endpoint.
	Put(ctx context.Context, e endpoint.Endpoint) error
	Delete(ctx context.Context, name string) error
	Close() error
}

// Seed adds endpoints that do not exist yet. Existing entries win so that
// changes made via the UI/API are not reverted on restart.
func Seed(ctx context.Context, s Store, eps []endpoint.Endpoint) (added int, err error) {
	for _, e := range eps {
		_, err := s.Get(ctx, e.Name)
		if err == nil {
			continue
		}
		if !errors.Is(err, ErrNotFound) {
			return added, err
		}
		if err := s.Put(ctx, e); err != nil {
			return added, err
		}
		added++
	}
	return added, nil
}

// File stores endpoints in a JSON file, written atomically.
type File struct {
	path string
	mu   sync.Mutex
}

type fileDoc struct {
	Version   int                 `json:"version"`
	Endpoints []endpoint.Endpoint `json:"endpoints"`
}

// NewFile opens (or lazily creates) a JSON endpoint store.
func NewFile(path string) (*File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, err
	}
	f := &File{path: path}
	if _, err := f.load(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *File) load() (map[string]endpoint.Endpoint, error) {
	data, err := os.ReadFile(f.path)
	if os.IsNotExist(err) {
		return map[string]endpoint.Endpoint{}, nil
	}
	if err != nil {
		return nil, err
	}
	var doc fileDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", f.path, err)
	}
	m := make(map[string]endpoint.Endpoint, len(doc.Endpoints))
	for _, e := range doc.Endpoints {
		m[e.Name] = e
	}
	return m, nil
}

func (f *File) save(m map[string]endpoint.Endpoint) error {
	doc := fileDoc{Version: 1, Endpoints: make([]endpoint.Endpoint, 0, len(m))}
	for _, e := range m {
		doc.Endpoints = append(doc.Endpoints, e)
	}
	endpoint.Sort(doc.Endpoints)
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(f.path, append(data, '\n'), 0o640)
}

// WriteFileAtomic writes via a temp file + rename so readers never see a
// partially written file.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (f *File) List(context.Context) ([]endpoint.Endpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.load()
	if err != nil {
		return nil, err
	}
	out := make([]endpoint.Endpoint, 0, len(m))
	for _, e := range m {
		out = append(out, e)
	}
	endpoint.Sort(out)
	return out, nil
}

func (f *File) Get(_ context.Context, name string) (endpoint.Endpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.load()
	if err != nil {
		return endpoint.Endpoint{}, err
	}
	e, ok := m[name]
	if !ok {
		return endpoint.Endpoint{}, ErrNotFound
	}
	return e, nil
}

func (f *File) Put(_ context.Context, e endpoint.Endpoint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.load()
	if err != nil {
		return err
	}
	m[e.Name] = e
	return f.save(m)
}

func (f *File) Delete(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.load()
	if err != nil {
		return err
	}
	if _, ok := m[name]; !ok {
		return ErrNotFound
	}
	delete(m, name)
	return f.save(m)
}

func (f *File) Close() error { return nil }
