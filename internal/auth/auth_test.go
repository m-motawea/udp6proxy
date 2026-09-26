package auth

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func init() { Iterations = 1000 }

func TestPBKDF2Vectors(t *testing.T) {
	// RFC 7914 §11 / widely published PBKDF2-HMAC-SHA256 vectors.
	cases := []struct {
		iter int
		want string
	}{
		{1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(pbkdf2([]byte("password"), []byte("salt"), c.iter, 32))
		if got != c.want {
			t.Errorf("iter %d: got %s", c.iter, got)
		}
	}
}

func TestPasswordHash(t *testing.T) {
	h := HashPassword("correct horse")
	if !CheckPassword(h, "correct horse") || CheckPassword(h, "wrong") {
		t.Fatal("hash check failed")
	}
	if h == HashPassword("correct horse") {
		t.Fatal("salt not random")
	}
	for _, bad := range []string{"", "x$1$a$b", "pbkdf2-sha256$0$AA$AA", "pbkdf2-sha256$1$!!$AA"} {
		if CheckPassword(bad, "x") {
			t.Fatalf("accepted malformed hash %q", bad)
		}
	}
}

func TestUsersTokensSessions(t *testing.T) {
	p := filepath.Join(t.TempDir(), "auth.json")
	s, err := Open(p, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser("admin", "short"); !errors.Is(err, ErrWeakPassword) {
		t.Fatalf("weak password accepted: %v", err)
	}
	if err := s.AddUser("bad name", "longenough"); !errors.Is(err, ErrBadUsername) {
		t.Fatalf("bad username accepted: %v", err)
	}
	if err := s.AddUser("admin", "longenough"); err != nil {
		t.Fatal(err)
	}
	if err := s.AddUser("admin", "longenough"); !errors.Is(err, ErrUserExists) {
		t.Fatal("duplicate user accepted")
	}
	if s.Authenticate("admin", "longenough") != nil || s.Authenticate("admin", "nope") == nil || s.Authenticate("ghost", "longenough") == nil {
		t.Fatal("authenticate")
	}
	if err := s.DeleteUser("admin"); !errors.Is(err, ErrLastUser) {
		t.Fatal("deleted last user")
	}

	plain, tok, err := s.CreateToken("admin", "cli", 0)
	if err != nil || !strings.HasPrefix(plain, TokenPrefix) {
		t.Fatal(err)
	}
	if u, ok := s.VerifyToken(plain); !ok || u != "admin" {
		t.Fatal("token not verified")
	}
	if _, ok := s.VerifyToken(plain + "x"); ok {
		t.Fatal("tampered token accepted")
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), plain) {
		t.Fatal("plaintext token persisted")
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Fatalf("auth file mode %v", fi.Mode().Perm())
	}

	// Reload from disk.
	s2, err := Open(p, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.VerifyToken(plain); !ok {
		t.Fatal("token lost on reload")
	}
	if err := s2.DeleteToken(tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := s2.VerifyToken(plain); ok {
		t.Fatal("revoked token accepted")
	}

	// Expired token.
	exp, _, _ := s2.CreateToken("admin", "short-lived", time.Nanosecond)
	time.Sleep(time.Millisecond)
	if _, ok := s2.VerifyToken(exp); ok {
		t.Fatal("expired token accepted")
	}

	// Sessions end on password change.
	id, _ := s2.NewSession("admin")
	if u, ok := s2.Session(id); !ok || u != "admin" {
		t.Fatal("session missing")
	}
	s2.SetPassword("admin", "newpassword")
	if _, ok := s2.Session(id); ok {
		t.Fatal("session survived password change")
	}

	// Deleting a user removes their tokens.
	s2.AddUser("bob", "bobpassword")
	bt, _, _ := s2.CreateToken("bob", "bob-cli", 0)
	s2.DeleteUser("bob")
	if _, ok := s2.VerifyToken(bt); ok {
		t.Fatal("deleted user's token still valid")
	}
}
