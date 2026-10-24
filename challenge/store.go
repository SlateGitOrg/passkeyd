// Package challenge is an in-memory, expiring, single-use store for
// in-flight ceremony state (WebAuthn challenges and their session data).
//
// Each entry is addressed by an unguessable random key, expires after a TTL,
// and can be taken exactly once: Take removes the entry, so a captured
// response can never be replayed against the same challenge. Expired entries
// are evicted lazily from a min-heap ordered by expiry, so every operation is
// O(log n) amortized and memory is bounded by MaxEntries.
package challenge

import (
	"container/heap"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Errors returned by Store.
var (
	ErrNotFound = errors.New("challenge: unknown or already used")
	ErrExpired  = errors.New("challenge: expired")
	ErrFull     = errors.New("challenge: store is at capacity")
)

// Options configures a Store.
type Options struct {
	// TTL is how long an entry stays valid. Default 5 minutes.
	TTL time.Duration
	// MaxEntries bounds the number of live entries. Default 100000.
	MaxEntries int
	// Now returns the current time. Default time.Now.
	Now func() time.Time
	// Rand generates keys. Default crypto/rand.
	Rand io.Reader
}

// KeySize is the number of random bytes in a key (256 bits).
const KeySize = 32

type entry[T any] struct {
	key     string
	val     T
	expires time.Time
	index   int // position in the heap
}

// expiryHeap is a min-heap of entries ordered by expiry time.
type expiryHeap[T any] []*entry[T]

func (h expiryHeap[T]) Len() int           { return len(h) }
func (h expiryHeap[T]) Less(i, j int) bool { return h[i].expires.Before(h[j].expires) }
func (h expiryHeap[T]) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index = i
	h[j].index = j
}
func (h *expiryHeap[T]) Push(x any) {
	e := x.(*entry[T])
	e.index = len(*h)
	*h = append(*h, e)
}
func (h *expiryHeap[T]) Pop() any {
	old := *h
	n := len(old)
	e := old[n-1]
	old[n-1] = nil
	e.index = -1
	*h = old[:n-1]
	return e
}

// Store is a concurrency-safe expiring single-use store.
type Store[T any] struct {
	mu    sync.Mutex
	items map[string]*entry[T]
	byExp expiryHeap[T]
	opts  Options
}

// New returns an empty Store.
func New[T any](opts Options) *Store[T] {
	if opts.TTL <= 0 {
		opts.TTL = 5 * time.Minute
	}
	if opts.MaxEntries <= 0 {
		opts.MaxEntries = 100000
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Rand == nil {
		opts.Rand = rand.Reader
	}
	return &Store[T]{items: map[string]*entry[T]{}, opts: opts}
}

// TTL returns the configured entry lifetime.
func (s *Store[T]) TTL() time.Duration { return s.opts.TTL }

// Put stores val under a fresh random key and returns the key and its
// expiry time.
func (s *Store[T]) Put(val T) (string, time.Time, error) {
	raw := make([]byte, KeySize)
	if _, err := io.ReadFull(s.opts.Rand, raw); err != nil {
		return "", time.Time{}, fmt.Errorf("challenge: generating key: %w", err)
	}
	key := base64.RawURLEncoding.EncodeToString(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opts.Now()
	s.sweepLocked(now)
	if len(s.items) >= s.opts.MaxEntries {
		return "", time.Time{}, ErrFull
	}
	if _, dup := s.items[key]; dup {
		// 2^-256 odds; only reachable with a broken Rand.
		return "", time.Time{}, errors.New("challenge: key collision")
	}
	e := &entry[T]{key: key, val: val, expires: now.Add(s.opts.TTL)}
	heap.Push(&s.byExp, e)
	s.items[key] = e
	return key, e.expires, nil
}

// Take removes and returns the entry for key. A second Take of the same key
// returns ErrNotFound; an entry past its expiry returns ErrExpired.
func (s *Store[T]) Take(key string) (T, error) {
	var zero T
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.items[key]
	if !ok {
		return zero, ErrNotFound
	}
	delete(s.items, key)
	heap.Remove(&s.byExp, e.index)
	if !s.opts.Now().Before(e.expires) {
		return zero, ErrExpired
	}
	return e.val, nil
}

// Len returns the number of entries, including expired ones not yet swept.
func (s *Store[T]) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// Sweep removes all expired entries and returns how many were removed.
func (s *Store[T]) Sweep() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sweepLocked(s.opts.Now())
}

func (s *Store[T]) sweepLocked(now time.Time) int {
	n := 0
	for len(s.byExp) > 0 && !now.Before(s.byExp[0].expires) {
		e := heap.Pop(&s.byExp).(*entry[T])
		delete(s.items, e.key)
		n++
	}
	return n
}
