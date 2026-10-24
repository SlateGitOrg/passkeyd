package challenge

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func newClock() *clock { return &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)} }

func TestPutTakeSingleUse(t *testing.T) {
	c := newClock()
	s := New[string](Options{TTL: time.Minute, Now: c.now})
	key, exp, err := s.Put("session-a")
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 43 || !exp.Equal(c.now().Add(time.Minute)) || s.TTL() != time.Minute {
		t.Fatalf("key %q exp %v", key, exp)
	}
	v, err := s.Take(key)
	if err != nil || v != "session-a" {
		t.Fatalf("take: %v %v", v, err)
	}
	if _, err := s.Take(key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second take must fail, got %v", err)
	}
	if _, err := s.Take("never-issued"); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
}

func TestExpiry(t *testing.T) {
	c := newClock()
	s := New[int](Options{TTL: time.Minute, Now: c.now})
	k1, _, _ := s.Put(1)
	c.advance(59 * time.Second)
	k2, _, _ := s.Put(2)
	c.advance(time.Second) // k1 now exactly at expiry
	if _, err := s.Take(k1); !errors.Is(err, ErrExpired) {
		t.Fatalf("k1: %v", err)
	}
	if _, err := s.Take(k1); !errors.Is(err, ErrNotFound) {
		t.Fatal("expired entries are removed on Take")
	}
	if v, err := s.Take(k2); err != nil || v != 2 {
		t.Fatalf("k2: %v %v", v, err)
	}
}

func TestSweepAndCapacity(t *testing.T) {
	c := newClock()
	s := New[int](Options{TTL: time.Minute, MaxEntries: 3, Now: c.now})
	for i := range 3 {
		if _, _, err := s.Put(i); err != nil {
			t.Fatal(err)
		}
		c.advance(10 * time.Second)
	}
	if _, _, err := s.Put(99); !errors.Is(err, ErrFull) {
		t.Fatalf("expected ErrFull, got %v", err)
	}
	c.advance(35 * time.Second) // first entry (t=0) expires at t=60; now t=65
	if _, _, err := s.Put(4); err != nil {
		t.Fatalf("put after expiry should sweep: %v", err)
	}
	if s.Len() != 3 {
		t.Fatalf("len %d", s.Len())
	}
	c.advance(time.Hour)
	if n := s.Sweep(); n != 3 || s.Len() != 0 {
		t.Fatalf("swept %d, len %d", n, s.Len())
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestKeyGenerationFailures(t *testing.T) {
	if _, _, err := New[int](Options{Rand: failReader{}}).Put(1); err == nil {
		t.Fatal("expected error")
	}
	// A constant Rand produces the same key twice: the store must refuse.
	s := New[int](Options{Rand: bytes.NewReader(make([]byte, 2*KeySize))})
	if _, _, err := s.Put(1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Put(2); err == nil {
		t.Fatal("duplicate key must be rejected")
	}
}

// TestHeapInvariantRandomOps interleaves random puts, takes, sweeps and
// clock moves and checks the store against a simple model.
func TestHeapInvariantRandomOps(t *testing.T) {
	c := newClock()
	s := New[int](Options{TTL: 30 * time.Second, MaxEntries: 1 << 20, Now: c.now})
	r := rand.New(rand.NewPCG(7, 7))
	model := map[string]time.Time{}
	var keys []string
	for i := range 20000 {
		switch r.IntN(4) {
		case 0, 1:
			k, exp, err := s.Put(i)
			if err != nil {
				t.Fatal(err)
			}
			model[k] = exp
			keys = append(keys, k)
		case 2:
			if len(keys) == 0 {
				continue
			}
			k := keys[r.IntN(len(keys))]
			_, err := s.Take(k)
			exp, live := model[k]
			delete(model, k)
			switch {
			case !live && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrExpired):
				t.Fatalf("op %d: taken key returned %v", i, err)
			case live && c.now().Before(exp) && err != nil:
				t.Fatalf("op %d: live key failed: %v", i, err)
			case live && !c.now().Before(exp) && err == nil:
				t.Fatalf("op %d: expired key succeeded", i)
			}
		default:
			c.advance(time.Duration(r.IntN(3000)) * time.Millisecond)
		}
		if i%1000 == 0 {
			s.Sweep()
			for k, exp := range model {
				if !c.now().Before(exp) {
					delete(model, k)
				}
			}
			if s.Len() != len(model) {
				t.Fatalf("op %d: store has %d entries, model %d", i, s.Len(), len(model))
			}
			for j, e := range s.byExp {
				if e.index != j {
					t.Fatalf("heap index corrupted at %d", j)
				}
				if l := 2*j + 1; l < len(s.byExp) && s.byExp[l].expires.Before(e.expires) {
					t.Fatalf("heap order violated at %d", j)
				}
			}
		}
	}
}

func TestConcurrentTakeIsExactlyOnce(t *testing.T) {
	s := New[int](Options{})
	key, _, _ := s.Put(1)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for range 64 {
		wg.Go(func() {
			if _, err := s.Take(key); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("%d goroutines took the same challenge", wins)
	}
}

func BenchmarkPutTake(b *testing.B) {
	s := New[int](Options{MaxEntries: 1 << 22})
	// Pre-fill so heap operations work on a realistic population.
	for i := range 100000 {
		if _, _, err := s.Put(i); err != nil {
			b.Fatal(err)
		}
	}
	b.ResetTimer()
	for i := 0; b.Loop(); i++ {
		k, _, err := s.Put(i)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := s.Take(k); err != nil {
			b.Fatal(fmt.Sprint(err))
		}
	}
}
