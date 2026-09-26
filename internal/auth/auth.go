// Package auth manages users, API tokens and web sessions.
//
// Users and tokens persist in a JSON file (mode 0600). Passwords are hashed
// with PBKDF2-HMAC-SHA256; API tokens are random 256-bit secrets of which
// only the SHA-256 digest is stored. Web sessions live in memory.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Iterations is the PBKDF2 work factor (OWASP 2023 recommendation). Tests
// lower it.
var Iterations = 600_000

const (
	TokenPrefix       = "u6p_"
	MinPasswordLength = 8
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserExists         = errors.New("user already exists")
	ErrUserNotFound       = errors.New("user not found")
	ErrTokenNotFound      = errors.New("token not found")
	ErrLastUser           = errors.New("cannot delete the last user")
	ErrWeakPassword       = fmt.Errorf("password must be at least %d characters", MinPasswordLength)
	ErrBadUsername        = errors.New("username must be 1-32 chars of letters, digits, '.', '_' or '-'")
)

var usernameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$`)

// User is an account allowed to manage the proxy.
type User struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"passwordHash"`
	Created      time.Time `json:"created"`
}

// Token is a long-lived API credential (for the CLI and automation).
type Token struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	Username string     `json:"username"`
	Hash     string     `json:"hash"`
	Hint     string     `json:"hint"` // first characters, for display
	Created  time.Time  `json:"created"`
	Expires  *time.Time `json:"expires,omitempty"`
	LastUsed *time.Time `json:"lastUsed,omitempty"`
}

type session struct {
	username string
	expires  time.Time
}

type doc struct {
	Users  []User  `json:"users"`
	Tokens []Token `json:"tokens"`
}

// Service is safe for concurrent use.
type Service struct {
	path       string
	sessionTTL time.Duration

	mu       sync.Mutex
	users    map[string]User
	tokens   map[string]Token // by ID
	byHash   map[string]string
	sessions map[string]session
	lastSave time.Time
}

// Open loads (or creates) the auth file.
func Open(path string, sessionTTL time.Duration) (*Service, error) {
	s := &Service{
		path:       path,
		sessionTTL: sessionTTL,
		users:      map[string]User{},
		tokens:     map[string]Token{},
		byHash:     map[string]string{},
		sessions:   map[string]session{},
	}
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		var d doc
		if err := json.Unmarshal(data, &d); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for _, u := range d.Users {
			s.users[u.Username] = u
		}
		for _, t := range d.Tokens {
			s.tokens[t.ID] = t
			s.byHash[t.Hash] = t.ID
		}
	}
	return s, nil
}

func (s *Service) saveLocked() error {
	d := doc{Users: s.listUsersLocked(), Tokens: s.listTokensLocked()}
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	s.lastSave = time.Now()
	return os.Rename(tmp, s.path)
}

// ---- passwords ----

func pbkdf2(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hLen := prf.Size()
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	buf := make([]byte, 4)
	for b := 1; b <= blocks; b++ {
		prf.Reset()
		prf.Write(salt)
		buf[0], buf[1], buf[2], buf[3] = byte(b>>24), byte(b>>16), byte(b>>8), byte(b)
		prf.Write(buf)
		u := prf.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}

// HashPassword returns an encoded PBKDF2 hash.
func HashPassword(pw string) string {
	salt := randomBytes(16)
	key := pbkdf2([]byte(pw), salt, Iterations, 32)
	enc := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", Iterations, enc.EncodeToString(salt), enc.EncodeToString(key))
}

// CheckPassword verifies pw against an encoded hash in constant time.
func CheckPassword(encoded, pw string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(parts[1])
	if err != nil || iter < 1 {
		return false
	}
	enc := base64.RawStdEncoding
	salt, err1 := enc.DecodeString(parts[2])
	want, err2 := enc.DecodeString(parts[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got := pbkdf2([]byte(pw), salt, iter, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// dummyHash is checked for unknown users so response timing does not reveal
// which usernames exist.
var dummyHash = sync.OnceValue(func() string { return HashPassword("dummy-password") })

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// RandomPassword returns a random, URL-safe password.
func RandomPassword() string { return base64.RawURLEncoding.EncodeToString(randomBytes(15)) }

// ---- users ----

// HasUsers reports whether any user exists.
func (s *Service) HasUsers() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.users) > 0
}

// AddUser creates a user.
func (s *Service) AddUser(username, password string) error {
	if !usernameRe.MatchString(username) {
		return ErrBadUsername
	}
	if len(password) < MinPasswordLength {
		return ErrWeakPassword
	}
	h := HashPassword(password)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[username]; ok {
		return ErrUserExists
	}
	s.users[username] = User{Username: username, PasswordHash: h, Created: time.Now().UTC()}
	return s.saveLocked()
}

// SetPassword changes a password and ends that user's web sessions.
func (s *Service) SetPassword(username, password string) error {
	if len(password) < MinPasswordLength {
		return ErrWeakPassword
	}
	h := HashPassword(password)
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[username]
	if !ok {
		return ErrUserNotFound
	}
	u.PasswordHash = h
	s.users[username] = u
	s.dropSessionsLocked(username)
	return s.saveLocked()
}

// DeleteUser removes a user with their tokens and sessions.
func (s *Service) DeleteUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[username]; !ok {
		return ErrUserNotFound
	}
	if len(s.users) == 1 {
		return ErrLastUser
	}
	delete(s.users, username)
	for id, t := range s.tokens {
		if t.Username == username {
			delete(s.tokens, id)
			delete(s.byHash, t.Hash)
		}
	}
	s.dropSessionsLocked(username)
	return s.saveLocked()
}

// UserExists reports whether username exists.
func (s *Service) UserExists(username string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.users[username]
	return ok
}

// ListUsers returns users sorted by name (hashes included; callers must not
// expose them).
func (s *Service) ListUsers() []User {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listUsersLocked()
}

func (s *Service) listUsersLocked() []User {
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// Authenticate checks a username/password pair.
func (s *Service) Authenticate(username, password string) error {
	s.mu.Lock()
	u, ok := s.users[username]
	s.mu.Unlock()
	if !ok {
		CheckPassword(dummyHash(), password)
		return ErrInvalidCredentials
	}
	if !CheckPassword(u.PasswordHash, password) {
		return ErrInvalidCredentials
	}
	return nil
}

// ---- sessions ----

// NewSession creates a web session and returns its opaque ID.
func (s *Service) NewSession(username string) (string, time.Time) {
	id := base64.RawURLEncoding.EncodeToString(randomBytes(32))
	exp := time.Now().Add(s.sessionTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Opportunistic cleanup.
	now := time.Now()
	for k, v := range s.sessions {
		if now.After(v.expires) {
			delete(s.sessions, k)
		}
	}
	s.sessions[sha(id)] = session{username: username, expires: exp}
	return id, exp
}

// Session returns the user for a session ID.
func (s *Service) Session(id string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := sha(id)
	v, ok := s.sessions[k]
	if !ok {
		return "", false
	}
	if time.Now().After(v.expires) {
		delete(s.sessions, k)
		return "", false
	}
	return v.username, true
}

// EndSession deletes a session.
func (s *Service) EndSession(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sha(id))
}

func (s *Service) dropSessionsLocked(username string) {
	for k, v := range s.sessions {
		if v.username == username {
			delete(s.sessions, k)
		}
	}
}

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// ---- tokens ----

// CreateToken issues a new API token and returns its plaintext once.
func (s *Service) CreateToken(username, name string, ttl time.Duration) (string, Token, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return "", Token{}, errors.New("token name must be 1-64 characters")
	}
	plain := TokenPrefix + base64.RawURLEncoding.EncodeToString(randomBytes(32))
	t := Token{
		ID:       hex.EncodeToString(randomBytes(6)),
		Name:     name,
		Username: username,
		Hash:     sha(plain),
		Hint:     plain[:len(TokenPrefix)+4] + "…",
		Created:  time.Now().UTC(),
	}
	if ttl > 0 {
		exp := t.Created.Add(ttl)
		t.Expires = &exp
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[username]; !ok {
		return "", Token{}, ErrUserNotFound
	}
	s.tokens[t.ID] = t
	s.byHash[t.Hash] = t.ID
	return plain, t, s.saveLocked()
}

// VerifyToken returns the owning user of a valid token.
func (s *Service) VerifyToken(plain string) (string, bool) {
	if !strings.HasPrefix(plain, TokenPrefix) {
		return "", false
	}
	h := sha(plain)
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.byHash[h]
	if !ok {
		return "", false
	}
	t := s.tokens[id]
	now := time.Now().UTC()
	if t.Expires != nil && now.After(*t.Expires) {
		return "", false
	}
	if _, ok := s.users[t.Username]; !ok {
		return "", false
	}
	if t.LastUsed == nil || now.Sub(*t.LastUsed) > time.Minute {
		t.LastUsed = &now
		s.tokens[id] = t
		if now.Sub(s.lastSave) > time.Minute {
			_ = s.saveLocked()
		}
	}
	return t.Username, true
}

// ListTokens returns all tokens (hashes included; callers must not expose them).
func (s *Service) ListTokens() []Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.listTokensLocked()
}

func (s *Service) listTokensLocked() []Token {
	out := make([]Token, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

// DeleteToken revokes a token.
func (s *Service) DeleteToken(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return ErrTokenNotFound
	}
	delete(s.tokens, id)
	delete(s.byHash, t.Hash)
	return s.saveLocked()
}

// Flush persists pending token last-used timestamps.
func (s *Service) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked()
}
