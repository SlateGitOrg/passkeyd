package credstore

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/archit2501/passkeyd/cose"
	"github.com/archit2501/passkeyd/webauthn"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), filepath.Join(t.TempDir(), "creds.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

var t0 = time.Date(2026, 3, 1, 10, 0, 0, 0, time.UTC)

func sampleCred(id string, user []byte) webauthn.Credential {
	return webauthn.Credential{
		ID: []byte(id), UserHandle: user, PublicKey: []byte{0xa1, 0x01, 0x02}, Algorithm: cose.AlgEdDSA,
		SignCount: 5, UVInitialized: true, BackupEligible: true, BackupState: false,
		Transports: []string{"internal", "hybrid"}, AAGUID: [16]byte{1, 2, 3},
		AttestationFormat: "packed", AttestationType: webauthn.AttestationSelf, AttestationTrusted: false,
		CreatedAt: t0, LastUsedAt: t0,
	}
}

func TestUserAndCredentialRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	u := User{Handle: []byte("h1"), Name: "alice", DisplayName: "Alice", CreatedAt: t0}
	c := sampleCred("cred-1", u.Handle)
	if err := s.RegisterUser(ctx, u, c); err != nil {
		t.Fatal(err)
	}
	got, err := s.UserByName(ctx, "alice")
	if err != nil || string(got.Handle) != "h1" || got.DisplayName != "Alice" || !got.CreatedAt.Equal(t0) {
		t.Fatalf("user %+v %v", got, err)
	}
	if byHandle, err := s.UserByHandle(ctx, []byte("h1")); err != nil || byHandle.Name != "alice" {
		t.Fatal(err)
	}
	gc, err := s.Credential(ctx, []byte("cred-1"))
	if err != nil {
		t.Fatal(err)
	}
	if gc.Algorithm != cose.AlgEdDSA || gc.SignCount != 5 || !gc.UVInitialized || !gc.BackupEligible || gc.BackupState ||
		len(gc.Transports) != 2 || gc.AAGUID != c.AAGUID || gc.AttestationType != webauthn.AttestationSelf || !gc.CreatedAt.Equal(t0) {
		t.Fatalf("credential %+v", gc)
	}
	c2 := sampleCred("cred-2", u.Handle)
	c2.Transports = nil
	c2.CreatedAt = t0.Add(time.Hour)
	if err := s.AddCredential(ctx, c2); err != nil {
		t.Fatal(err)
	}
	list, err := s.CredentialsByUser(ctx, u.Handle)
	if err != nil || len(list) != 2 || string(list[1].ID) != "cred-2" || list[1].Transports != nil {
		t.Fatalf("list %+v %v", list, err)
	}
	if ok, _ := s.CredentialExists(ctx, []byte("cred-2")); !ok {
		t.Fatal("exists")
	}
	if ok, _ := s.CredentialExists(ctx, []byte("nope")); ok {
		t.Fatal("not exists")
	}
	users, creds, err := s.Stats(ctx)
	if err != nil || users != 1 || creds != 2 {
		t.Fatalf("stats %d %d %v", users, creds, err)
	}
}

func TestConstraintErrors(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	u := User{Handle: []byte("h1"), Name: "alice", DisplayName: "A", CreatedAt: t0}
	if err := s.RegisterUser(ctx, u, sampleCred("c1", u.Handle)); err != nil {
		t.Fatal(err)
	}
	// Same name, new handle: rejected, and the credential must not leak in.
	u2 := User{Handle: []byte("h2"), Name: "alice", DisplayName: "A2", CreatedAt: t0}
	if err := s.RegisterUser(ctx, u2, sampleCred("c2", u2.Handle)); !errors.Is(err, ErrUserExists) {
		t.Fatal(err)
	}
	if ok, _ := s.CredentialExists(ctx, []byte("c2")); ok {
		t.Fatal("RegisterUser must be atomic")
	}
	if err := s.CreateUser(ctx, u2); !errors.Is(err, ErrUserExists) {
		t.Fatal(err)
	}
	u3 := User{Handle: []byte("h3"), Name: "bob", DisplayName: "B", CreatedAt: t0}
	if err := s.RegisterUser(ctx, u3, sampleCred("c1", u3.Handle)); !errors.Is(err, ErrDuplicateCredential) {
		t.Fatal(err)
	}
	if _, err := s.UserByName(ctx, "bob"); !errors.Is(err, ErrNotFound) {
		t.Fatal("rolled back user must not exist")
	}
	if err := s.AddCredential(ctx, sampleCred("c9", []byte("ghost"))); err == nil {
		t.Fatal("foreign key must reject credentials for unknown users")
	}
	if _, err := s.Credential(ctx, []byte("zz")); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if _, err := s.UserByHandle(ctx, []byte("zz")); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestUpdateAfterLoginCompareAndSwap(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	u := User{Handle: []byte("h"), Name: "a", DisplayName: "a", CreatedAt: t0}
	c := sampleCred("c", u.Handle)
	if err := s.RegisterUser(ctx, u, c); err != nil {
		t.Fatal(err)
	}
	next := c
	next.SignCount, next.BackupState, next.LastUsedAt = 6, true, t0.Add(time.Minute)
	if err := s.UpdateAfterLogin(ctx, next, 5); err != nil {
		t.Fatal(err)
	}
	// A second login verified against the old counter loses the race.
	stale := c
	stale.SignCount = 6
	if err := s.UpdateAfterLogin(ctx, stale, 5); !errors.Is(err, ErrConcurrentUpdate) {
		t.Fatalf("got %v", err)
	}
	got, _ := s.Credential(ctx, c.ID)
	if got.SignCount != 6 || !got.BackupState || !got.LastUsedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("got %+v", got)
	}
	missing := sampleCred("missing", u.Handle)
	if err := s.UpdateAfterLogin(ctx, missing, 5); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.FlagClone(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Credential(ctx, c.ID); !got.CloneWarning {
		t.Fatal("clone flag not stored")
	}
	if err := s.FlagClone(ctx, []byte("nope")); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	if err := s.DeleteCredential(ctx, c.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteCredential(ctx, c.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

// TestConcurrentCounterRace runs many concurrent updates against the same
// previous counter: exactly one may win.
func TestConcurrentCounterRace(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	u := User{Handle: []byte("h"), Name: "a", DisplayName: "a", CreatedAt: t0}
	c := sampleCred("c", u.Handle)
	if err := s.RegisterUser(ctx, u, c); err != nil {
		t.Fatal(err)
	}
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)
	for i := range 16 {
		wg.Go(func() {
			n := c
			n.SignCount = uint32(10 + i)
			if err := s.UpdateAfterLogin(ctx, n, 5); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			} else if !errors.Is(err, ErrConcurrentUpdate) {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d concurrent updates won", wins)
	}
}

func TestReopenKeepsDataAndRejectsNewerSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "x.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateUser(ctx, User{Handle: []byte("h"), Name: "a", DisplayName: "a", CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.ExecContext(ctx, "PRAGMA user_version = 99"); err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if _, err := Open(ctx, path); err == nil {
		t.Fatal("newer schema must be refused")
	}
	mem, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = mem.Close() }()
	if err := mem.CreateUser(ctx, User{Handle: []byte("h"), Name: "a", DisplayName: "a", CreatedAt: t0}); err != nil {
		t.Fatal(err)
	}
	if _, err := mem.UserByName(ctx, "a"); err != nil {
		t.Fatal("in-memory store must share one connection")
	}
}

func TestClosedStoreErrors(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	_ = s.Close()
	if _, err := s.CredentialsByUser(ctx, []byte("h")); err == nil {
		t.Fatal("expected error")
	}
	if _, err := s.CredentialExists(ctx, []byte("h")); err == nil {
		t.Fatal("expected error")
	}
	if _, _, err := s.Stats(ctx); err == nil {
		t.Fatal("expected error")
	}
	if err := s.UpdateAfterLogin(ctx, sampleCred("c", nil), 0); err == nil {
		t.Fatal("expected error")
	}
	if err := s.FlagClone(ctx, []byte("c")); err == nil {
		t.Fatal("expected error")
	}
	if err := s.RegisterUser(ctx, User{}, webauthn.Credential{}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := s.UserByName(ctx, "a"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("closed db is not 'not found'")
	}
	if _, err := s.Credential(ctx, []byte("c")); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatal("closed db is not 'not found'")
	}
	if err := s.CreateUser(ctx, User{}); err == nil || errors.Is(err, ErrUserExists) {
		t.Fatal("closed db error")
	}
	if err := s.AddCredential(ctx, webauthn.Credential{}); err == nil || errors.Is(err, ErrDuplicateCredential) {
		t.Fatal("closed db error")
	}
	if _, err := Open(ctx, filepath.Join(t.TempDir(), "missing-dir", "x.db")); err == nil {
		t.Fatal("open in a missing directory must fail")
	}
}
