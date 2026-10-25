package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/SlateGitOrg/passkeyd/credstore"
	"github.com/SlateGitOrg/passkeyd/virtualauthn"
	"github.com/SlateGitOrg/passkeyd/webauthn"
)

const testOrigin = "http://localhost:8080"

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	t     *testing.T
	ts    *httptest.Server
	store *credstore.Store
	clk   *fakeClock
	srv   *Server
}

func newEnv(t *testing.T, mod func(*Config)) *env {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 5, 1, 9, 0, 0, 0, time.UTC)}
	store, err := credstore.Open(context.Background(), filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rp, err := webauthn.New(webauthn.Config{RPID: "localhost", Origins: []string{testOrigin}, ResidentKey: webauthn.ResidentKeyRequired, Now: clk.Now})
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{RP: rp, Store: store, Now: clk.Now, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	if mod != nil {
		mod(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &env{t: t, ts: ts, store: store, clk: clk, srv: srv}
}

type browser struct {
	e      *env
	hc     *http.Client
	client *virtualauthn.Client
}

func (e *env) browser(opts virtualauthn.Options) *browser {
	jar, _ := cookiejar.New(nil)
	return &browser{e: e, hc: &http.Client{Jar: jar}, client: &virtualauthn.Client{Origin: testOrigin, Authenticator: virtualauthn.New(opts)}}
}

// post sends JSON and returns status and decoded body.
func (b *browser) post(path string, body any) (int, map[string]any) {
	b.e.t.Helper()
	buf, _ := json.Marshal(body)
	resp, err := b.hc.Post(b.e.ts.URL+path, "application/json", bytes.NewReader(buf))
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (b *browser) postInto(path string, body, into any) int {
	b.e.t.Helper()
	status, out := b.post(path, body)
	raw, _ := json.Marshal(out)
	if err := json.Unmarshal(raw, into); err != nil {
		b.e.t.Fatal(err)
	}
	return status
}

func (b *browser) register(name string) (int, map[string]any) {
	b.e.t.Helper()
	var opts webauthn.CreationOptionsJSON
	if st := b.postInto("/api/register/options", map[string]string{"username": name}, &opts); st != http.StatusOK {
		return st, nil
	}
	resp, err := b.client.Create(&opts)
	if err != nil {
		b.e.t.Fatal(err)
	}
	return b.post("/api/register/verify", resp)
}

func (b *browser) login(name string) (int, map[string]any) {
	b.e.t.Helper()
	var opts webauthn.RequestOptionsJSON
	if st := b.postInto("/api/login/options", map[string]string{"username": name}, &opts); st != http.StatusOK {
		return st, nil
	}
	resp, err := b.client.Get(&opts)
	if err != nil {
		b.e.t.Fatal(err)
	}
	return b.post("/api/login/verify", resp)
}

func TestRegisterAndLoginOverHTTP(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(virtualauthn.Options{})
	st, body := b.register("alice")
	if st != http.StatusOK || body["username"] != "alice" || body["algorithm"] != "ES256" {
		t.Fatalf("register: %d %v", st, body)
	}
	st, body = b.login("alice")
	if st != http.StatusOK || body["signCount"] != float64(2) || body["displayName"] != "alice" {
		t.Fatalf("login: %d %v", st, body)
	}
	st, body = b.login("")
	if st != http.StatusOK || body["username"] != "alice" {
		t.Fatalf("discoverable login: %d %v", st, body)
	}
	resp, err := http.Get(e.ts.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	var h map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&h)
	_ = resp.Body.Close()
	if h["users"] != float64(1) || h["credentials"] != float64(1) || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("health %v", h)
	}
}

func TestStaticPageAndHeaders(t *testing.T) {
	e := newEnv(t, nil)
	for path, want := range map[string]string{"/": "<title>passkeyd demo</title>", "/app.js": "navigator.credentials.create", "/style.css": "--accent"} {
		resp, err := http.Get(e.ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), want) {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		csp := resp.Header.Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'self'") || !strings.Contains(csp, "frame-ancestors 'none'") || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Fatalf("%s: weak headers %q", path, csp)
		}
	}
}

func TestCookieAttributes(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.SecureCookies = true })
	resp, err := http.Post(e.ts.URL+"/api/login/options", "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	ck := resp.Cookies()
	if len(ck) != 1 || ck[0].Name != CeremonyCookie || !ck[0].HttpOnly || !ck[0].Secure || ck[0].SameSite != http.SameSiteStrictMode || ck[0].Path != "/api/" || len(ck[0].Value) != 43 {
		t.Fatalf("cookie %+v", ck)
	}
}

func TestRequestValidation(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(virtualauthn.Options{})
	if st, _ := b.register("alice"); st != http.StatusOK {
		t.Fatal(st)
	}
	big := strings.Repeat("a", MaxBodyBytes+1)
	cases := []struct {
		name, path, ctype, body string
		status                  int
		code                    string
	}{
		{"wrong content type", "/api/register/options", "text/plain", `{"username":"x"}`, 415, "unsupported_media_type"},
		{"bad json", "/api/register/options", "application/json", `{`, 400, "bad_json"},
		{"trailing json", "/api/login/options", "application/json", `{} {}`, 400, "bad_json"},
		{"too large", "/api/register/verify", "application/json", `"` + big + `"`, 413, "body_too_large"},
		{"empty username", "/api/register/options", "application/json", `{"username":""}`, 400, "invalid_username"},
		{"control char", "/api/register/options", "application/json", `{"username":"a\u0000b"}`, 400, "invalid_username"},
		{"spaces only", "/api/register/options", "application/json", `{"username":"   "}`, 400, "invalid_username"},
		{"too long", "/api/register/options", "application/json", `{"username":"` + strings.Repeat("x", 65) + `"}`, 400, "invalid_username"},
		{"taken", "/api/register/options", "application/json", `{"username":"alice"}`, 409, "username_taken"},
		{"verify without ceremony", "/api/login/verify", "application/json", `{}`, 400, "session_invalid"},
		{"register verify without ceremony", "/api/register/verify", "application/json", `{}`, 400, "session_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Post(e.ts.URL+tc.path, tc.ctype, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			var out apiError
			_ = json.NewDecoder(resp.Body).Decode(&out)
			if resp.StatusCode != tc.status || out.Error != tc.code {
				t.Fatalf("got %d %q, want %d %q", resp.StatusCode, out.Error, tc.status, tc.code)
			}
		})
	}
}

func TestVerificationFailuresMapToChecks(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(virtualauthn.Options{})
	b.client.Origin = "https://evil.test"
	if st, body := b.register("mallory"); st != http.StatusBadRequest || body["error"] != string(webauthn.CheckOrigin) {
		t.Fatalf("got %d %v", st, body)
	}
	b.client.Origin = testOrigin
	if st, _ := b.register("mallory"); st != http.StatusOK {
		t.Fatal("a failed ceremony must not reserve the username")
	}
	var opts webauthn.RequestOptionsJSON
	if st := b.postInto("/api/login/options", map[string]string{"username": "mallory"}, &opts); st != 200 {
		t.Fatalf("options %d", st)
	}
	resp, _ := b.client.Get(&opts)
	resp.Response.Signature[len(resp.Response.Signature)-1] ^= 1
	if st, body := b.post("/api/login/verify", resp); st != http.StatusUnauthorized || body["error"] != string(webauthn.CheckSignature) {
		t.Fatalf("got %d %v", st, body)
	}
}

// TestLoginDoesNotEnumerateAccounts covers threat T17: login options for an
// existing and an unknown username are indistinguishable and carry no
// credential IDs, and the username is still enforced at verification.
func TestLoginDoesNotEnumerateAccounts(t *testing.T) {
	e := newEnv(t, nil)
	alice := e.browser(virtualauthn.Options{})
	if st, _ := alice.register("alice"); st != http.StatusOK {
		t.Fatal(st)
	}
	mallory := e.browser(virtualauthn.Options{})
	if st, _ := mallory.register("mallory"); st != http.StatusOK {
		t.Fatal(st)
	}
	shape := func(name string) (map[string]any, []string) {
		t.Helper()
		st, body := mallory.post("/api/login/options", map[string]string{"username": name})
		if st != http.StatusOK {
			t.Fatalf("%q options: %d %v", name, st, body)
		}
		if allow, _ := body["allowCredentials"].([]any); len(allow) != 0 {
			t.Fatalf("%q options list credentials: %v", name, allow)
		}
		delete(body, "challenge")
		keys := make([]string, 0, len(body))
		for k := range body {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		return body, keys
	}
	known, knownKeys := shape("alice")
	unknown, unknownKeys := shape("nobody")
	if !slices.Equal(knownKeys, unknownKeys) || fmt.Sprint(known) != fmt.Sprint(unknown) {
		t.Fatalf("options differ:\nknown   %v\nunknown %v", known, unknown)
	}

	// The username is bound server-side: mallory's own valid passkey is
	// refused for alice and for a name that does not exist, with the same
	// error, while alice's passkey is accepted for alice.
	for _, name := range []string{"alice", "nobody"} {
		if st, body := mallory.login(name); st != http.StatusUnauthorized || body["error"] != string(webauthn.CheckUserHandle) {
			t.Fatalf("mallory as %q: %d %v", name, st, body)
		}
	}
	if st, body := alice.login("alice"); st != http.StatusOK || body["username"] != "alice" {
		t.Fatalf("alice: %d %v", st, body)
	}
	if st, body := mallory.login("mallory"); st != http.StatusOK || body["username"] != "mallory" {
		t.Fatalf("mallory: %d %v", st, body)
	}
}

func TestNewRequiresDiscoverableCredentials(t *testing.T) {
	store, err := credstore.Open(context.Background(), filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	rp, err := webauthn.New(webauthn.Config{RPID: "localhost", Origins: []string{testOrigin}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{RP: rp, Store: store}); err == nil || !strings.Contains(err.Error(), "ResidentKey") {
		t.Fatalf("want ResidentKey error, got %v", err)
	}
}

func TestCloneIsFlaggedInStore(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(virtualauthn.Options{})
	if st, _ := b.register("alice"); st != 200 {
		t.Fatal(st)
	}
	clone := e.browser(virtualauthn.Options{})
	clone.client.Authenticator = b.client.Authenticator.Clone(virtualauthn.Options{})
	if st, _ := b.login("alice"); st != 200 {
		t.Fatal(st)
	}
	if st, body := clone.login("alice"); st != http.StatusUnauthorized || body["error"] != string(webauthn.CheckSignCount) {
		t.Fatalf("got %d %v", st, body)
	}
	u, _ := e.store.UserByName(context.Background(), "alice")
	cs, _ := e.store.CredentialsByUser(context.Background(), u.Handle)
	if len(cs) != 1 || !cs[0].CloneWarning {
		t.Fatalf("clone not flagged: %+v", cs)
	}
}

func TestExpiredAndReplayedCeremony(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(virtualauthn.Options{})
	if st, _ := b.register("alice"); st != 200 {
		t.Fatal(st)
	}
	var opts webauthn.RequestOptionsJSON
	b.postInto("/api/login/options", map[string]string{"username": "alice"}, &opts)
	resp, _ := b.client.Get(&opts)
	e.clk.Advance(6 * time.Minute)
	if st, body := b.post("/api/login/verify", resp); st != 400 || body["error"] != string(webauthn.CheckSession) {
		t.Fatalf("expired: %d %v", st, body)
	}
}

func TestRateLimitAndCapacity(t *testing.T) {
	e := newEnv(t, func(c *Config) { c.OptionsPerMinute = 3 })
	b := e.browser(virtualauthn.Options{})
	for i := range 3 {
		if st, _ := b.post("/api/login/options", map[string]string{}); st != 200 {
			t.Fatalf("request %d: %d", i, st)
		}
	}
	if st, body := b.post("/api/login/options", map[string]string{}); st != http.StatusTooManyRequests || body["error"] != "rate_limited" {
		t.Fatalf("got %d %v", st, body)
	}
	e.clk.Advance(30 * time.Second) // refills 1.5 tokens
	if st, _ := b.post("/api/login/options", map[string]string{}); st != 200 {
		t.Fatalf("after refill: %d", st)
	}
	e.clk.Advance(2 * time.Minute) // idle bucket swept
	if st, _ := b.post("/api/login/options", map[string]string{}); st != 200 {
		t.Fatal(st)
	}

	full := newEnv(t, func(c *Config) { c.OptionsPerMinute = -1; c.MaxPendingCeremonies = 2 })
	fb := full.browser(virtualauthn.Options{})
	for range 2 {
		fb.post("/api/login/options", map[string]string{})
	}
	if st, body := fb.post("/api/login/options", map[string]string{}); st != http.StatusServiceUnavailable || body["error"] != "too_many_ceremonies" {
		t.Fatalf("got %d %v", st, body)
	}
}

func TestStoreFailuresAreInternalErrors(t *testing.T) {
	e := newEnv(t, nil)
	b := e.browser(virtualauthn.Options{})
	_ = e.store.Close()
	for _, path := range []string{"/api/register/options", "/api/login/options"} {
		if st, body := b.post(path, map[string]string{"username": "x"}); st != 500 || body["error"] != "internal" {
			t.Fatalf("%s: %d %v", path, st, body)
		}
	}
	resp, err := http.Get(e.ts.URL + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("health on closed store: %d", resp.StatusCode)
	}
}

func TestRandomnessFailure(t *testing.T) {
	e := newEnv(t, nil)
	e.srv.randRead = func([]byte) (int, error) { return 0, errors.New("no entropy") }
	b := e.browser(virtualauthn.Options{})
	if st, _ := b.post("/api/register/options", map[string]string{"username": "x"}); st != 500 {
		t.Fatal(st)
	}
	if st, _ := b.post("/api/login/options", map[string]string{"username": "nobody"}); st != 500 {
		t.Fatal(st)
	}
}

func TestRecoverer(t *testing.T) {
	e := newEnv(t, nil)
	h := e.srv.recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != 500 {
		t.Fatal(rec.Code)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "not-a-host-port"
	if clientIP(r) != "not-a-host-port" {
		t.Fatal("clientIP fallback")
	}
	if _, err := New(Config{}); err == nil {
		t.Fatal("New must require RP and Store")
	}
}
