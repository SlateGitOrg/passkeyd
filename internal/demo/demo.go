// Package demo runs the offline end-to-end scenario behind `passkeyd demo`:
// it replays the WebAuthn Level 3 spec vectors, starts the real HTTP server
// on a loopback port with a temporary SQLite database, and drives it with
// virtual authenticators through registrations, logins and a set of attacks
// that must be refused.
package demo

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/archit2501/passkeyd/cose"
	"github.com/archit2501/passkeyd/credstore"
	"github.com/archit2501/passkeyd/server"
	"github.com/archit2501/passkeyd/virtualauthn"
	"github.com/archit2501/passkeyd/webauthn"
)

// Options configures a demo run.
type Options struct {
	// VectorsPath is the extracted spec vector file
	// (testdata/webauthn-l3-vectors.json).
	VectorsPath string
	// WorkDir holds the temporary database; it is created and removed.
	WorkDir string
}

// Summary counts the scenario's expectations.
type Summary struct {
	Passed, Failed int
	VectorsOK      int
}

// ErrExpectation is returned when any step did not behave as expected.
var ErrExpectation = errors.New("demo: one or more expectations failed")

const (
	rpID   = "localhost"
	origin = "http://localhost:8080"
)

// clock is a settable time source shared by the server and relying party,
// so the demo can show ceremony expiry without sleeping.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type runner struct {
	out     *tabwriter.Writer
	sum     Summary
	baseURL string
	clk     *clock
}

func (r *runner) record(ok bool, verdict, step, detail string) {
	mark := "PASS"
	if !ok {
		mark = "FAIL"
		r.sum.Failed++
	} else {
		r.sum.Passed++
	}
	_, _ = fmt.Fprintf(r.out, "  %s\t%s\t%s\t%s\n", mark, verdict, step, detail)
}

// Run executes the scenario, writing a transcript to w.
func Run(ctx context.Context, w io.Writer, opts Options) (Summary, error) {
	r := &runner{out: tabwriter.NewWriter(w, 0, 0, 2, ' ', 0), clk: &clock{t: time.Now().UTC().Truncate(time.Second)}}

	_, _ = fmt.Fprintln(w, "== 1. WebAuthn Level 3 spec vectors (section 16) ==")
	if err := r.vectors(opts.VectorsPath); err != nil {
		return r.sum, err
	}
	_ = r.out.Flush()

	dir, err := os.MkdirTemp(opts.WorkDir, "passkeyd-demo-")
	if err != nil {
		return r.sum, err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	store, err := credstore.Open(ctx, filepath.Join(dir, "demo.db"))
	if err != nil {
		return r.sum, err
	}
	defer func() { _ = store.Close() }()

	// Each user gets a differently configured authenticator.
	aliceAuth := virtualauthn.New(virtualauthn.Options{Attestation: virtualauthn.AttestPackedX5C, AAGUID: [16]byte{0xa1, 0x1c, 0xe0}})
	bobAuth := virtualauthn.New(virtualauthn.Options{Algorithms: []cose.Algorithm{cose.AlgEdDSA}})
	carolAuth := virtualauthn.New(virtualauthn.Options{Attestation: virtualauthn.AttestPackedSelf, BackupEligible: true, BackupState: true, ZeroCounter: true})
	root, err := aliceAuth.AttestationRoot()
	if err != nil {
		return r.sum, err
	}
	anchors := x509.NewCertPool()
	anchors.AddCert(root)

	rp, err := webauthn.New(webauthn.Config{
		RPID: rpID, RPName: "passkeyd demo", Origins: []string{origin},
		Attestation: &webauthn.AttestationPolicy{AllowNone: true, AllowSelf: true, AllowBasic: true, TrustAnchors: anchors},
		Now:         r.clk.Now,
	})
	if err != nil {
		return r.sum, err
	}
	srv, err := server.New(server.Config{RP: rp, Store: store, Now: r.clk.Now})
	if err != nil {
		return r.sum, err
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	r.baseURL = ts.URL

	_, _ = fmt.Fprintf(w, "\n== 2. Ceremonies over HTTP (server %s, RP ID %q, origin %s, SQLite %s) ==\n", ts.URL, rpID, origin, "demo.db")
	alice, bob, carol := r.newUser(aliceAuth), r.newUser(bobAuth), r.newUser(carolAuth)
	r.expectOK("register alice", "packed x5c / ES256", func() (map[string]any, error) { return alice.register("alice", "Alice") }, "algorithm", "attestation", "trusted")
	r.expectOK("register bob", "none / EdDSA", func() (map[string]any, error) { return bob.register("bob", "Bob") }, "algorithm", "attestation")
	r.expectOK("register carol", "packed self / synced", func() (map[string]any, error) { return carol.register("carol", "Carol") }, "attestation", "backupEligible")
	r.expectOK("login alice", "by username", func() (map[string]any, error) { return alice.login("alice") }, "username", "signCount")
	r.expectOK("login alice", "again, counter grows", func() (map[string]any, error) { return alice.login("alice") }, "signCount")
	r.expectOK("login bob", "discoverable", func() (map[string]any, error) { return bob.login("") }, "username", "userVerified")
	r.expectOK("login carol", "zero counter is fine", func() (map[string]any, error) { return carol.login("carol") }, "username", "signCount", "backupState")
	_ = r.out.Flush()

	_, _ = fmt.Fprintln(w, "\n== 3. Attacks that must be refused ==")
	r.expectDenied("phishing origin", "client on evil origin", webauthn.CheckOrigin, func() error {
		mallory := r.newUser(aliceAuth)
		mallory.client.Origin = "https://login-localhost.evil.test"
		_, err := mallory.login("alice")
		return err
	})
	r.expectDenied("duplicate username", "register alice again", "username_taken", func() error {
		_, err := r.newUser(virtualauthn.New(virtualauthn.Options{})).register("alice", "Mallory")
		return err
	})
	var captured *webauthn.AuthenticationResponseJSON
	r.expectDenied("replay, same cookie", "resubmit a used response", webauthn.CheckSession, func() error {
		resp, err := alice.loginCapture("alice")
		if err != nil {
			return err
		}
		captured = resp
		if err := alice.post("/api/login/verify", resp, nil); err != nil {
			return fmt.Errorf("first submission should succeed: %w", err)
		}
		return alice.post("/api/login/verify", resp, nil)
	})
	r.expectDenied("replay, new ceremony", "captured response vs fresh challenge", webauthn.CheckChallenge, func() error {
		if err := alice.post("/api/login/options", map[string]string{"username": "alice"}, nil); err != nil {
			return err
		}
		return alice.post("/api/login/verify", captured, nil)
	})
	r.expectDenied("tampered signature", "flip one signature bit", webauthn.CheckSignature, func() error {
		return alice.loginMutate("alice", func(a *webauthn.AuthenticationResponseJSON) {
			a.Response.Signature[len(a.Response.Signature)-1] ^= 1
		})
	})
	r.expectDenied("expired ceremony", "answer after 6 minutes", webauthn.CheckSession, func() error {
		resp, err := alice.loginCapture("alice")
		if err != nil {
			return err
		}
		r.clk.Advance(6 * time.Minute)
		return alice.post("/api/login/verify", resp, nil)
	})
	r.expectDenied("wrong RP ID", "credential minted for another site", webauthn.CheckRPIDHash, func() error {
		dave := r.newUser(virtualauthn.New(virtualauthn.Options{}))
		dave.rpOverride = "evil.test"
		_, err := dave.register("dave", "Dave")
		return err
	})
	clone := aliceAuth.Clone(virtualauthn.Options{})
	r.expectOK("login alice", "original authenticator", func() (map[string]any, error) { return alice.login("alice") }, "signCount")
	r.expectDenied("cloned authenticator", "copy replays an old counter", webauthn.CheckSignCount, func() error {
		_, err := r.newUser(clone).login("alice")
		return err
	})
	_ = r.out.Flush()

	_, _ = fmt.Fprintln(w, "\n== 4. Stored state ==")
	users, creds, err := store.Stats(ctx)
	if err != nil {
		return r.sum, err
	}
	_, _ = fmt.Fprintf(w, "  users=%d credentials=%d\n", users, creds)
	for _, name := range []string{"alice", "bob", "carol"} {
		u, err := store.UserByName(ctx, name)
		if err != nil {
			return r.sum, err
		}
		cs, err := store.CredentialsByUser(ctx, u.Handle)
		if err != nil {
			return r.sum, err
		}
		for _, c := range cs {
			_, _ = fmt.Fprintf(r.out, "  %s\t%s\tattestation=%s\tsignCount=%d\tBE=%v\tcloneWarning=%v\n",
				name, c.Algorithm, c.AttestationType, c.SignCount, c.BackupEligible, c.CloneWarning)
		}
	}
	aliceUser, _ := store.UserByName(ctx, "alice")
	aliceCreds, _ := store.CredentialsByUser(ctx, aliceUser.Handle)
	r.record(len(aliceCreds) == 1 && aliceCreds[0].CloneWarning, "flagged", "clone detection persisted", "alice's credential carries clone_warning=1")
	_ = r.out.Flush()

	_, _ = fmt.Fprintf(w, "\nSummary: %d expectations met, %d failed, %d spec vectors verified\n", r.sum.Passed, r.sum.Failed, r.sum.VectorsOK)
	if r.sum.Failed > 0 {
		return r.sum, ErrExpectation
	}
	return r.sum, nil
}

func (r *runner) expectOK(step, how string, fn func() (map[string]any, error), fields ...string) {
	res, err := fn()
	if err != nil {
		r.record(false, "error", step, how+": "+err.Error())
		return
	}
	parts := []string{how}
	for _, f := range fields {
		parts = append(parts, fmt.Sprintf("%s=%v", f, res[f]))
	}
	r.record(true, "accepted", step, strings.Join(parts, "  "))
}

func (r *runner) expectDenied(step, how string, want webauthn.Check, fn func() error) {
	err := fn()
	var ae *apiError
	switch {
	case err == nil:
		r.record(false, "ACCEPTED", step, how+": expected "+string(want))
	case errors.As(err, &ae) && ae.Code == string(want):
		r.record(true, "refused", step, fmt.Sprintf("%s -> HTTP %d %s", how, ae.Status, ae.Code))
	default:
		r.record(false, "wrong-error", step, fmt.Sprintf("%s: %v (want %s)", how, err, want))
	}
}

// vectors replays every registration/authentication pair from the spec.
func (r *runner) vectors(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("demo: reading spec vectors: %w", err)
	}
	var file struct {
		Vectors map[string]map[string]map[string]string `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		return fmt.Errorf("demo: parsing spec vectors: %w", err)
	}
	h := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	rootDER := file.Vectors["attestation-root-cert"]["registration"]["attestation_ca_cert"]
	root, err := x509.ParseCertificate(h(rootDER))
	if err != nil {
		return fmt.Errorf("demo: spec attestation root: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rp, err := webauthn.New(webauthn.Config{
		RPID: "example.org", Origins: []string{"https://example.org"}, AllowCrossOrigin: true,
		TopOrigins:  []string{"https://example.com"},
		Attestation: &webauthn.AttestationPolicy{AllowNone: true, AllowSelf: true, AllowBasic: true, TrustAnchors: pool},
		Now:         func() time.Time { return now },
	})
	if err != nil {
		return err
	}
	names := make([]string, 0, len(file.Vectors))
	for n := range file.Vectors {
		if n != "attestation-root-cert" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		reg, auth := file.Vectors[name]["registration"], file.Vectors[name]["authentication"]
		credID := h(reg["credential_id"])
		res, err := rp.FinishRegistration(&webauthn.SessionData{
			Ceremony: webauthn.CeremonyRegistration, Challenge: h(reg["challenge"]), UserHandle: []byte("u"),
			UserVerification: webauthn.UVPreferred, Algorithms: webauthn.DefaultAlgorithms, Expires: now.Add(time.Minute),
		}, &webauthn.RegistrationResponseJSON{
			ID: webauthn.EncodeURL(credID), RawID: credID, Type: "public-key",
			Response: webauthn.AttestationResponseJSON{ClientDataJSON: h(reg["clientDataJSON"]), AttestationObject: h(reg["attestationObject"])},
		}, nil)
		if name == "packed-ed448" {
			ok := webauthn.CheckOf(err) == webauthn.CheckAlgorithm
			r.record(ok, "refused", name, "Ed448 is not implemented -> "+string(webauthn.CheckOf(err)))
			continue
		}
		if err != nil {
			r.record(false, "error", name, err.Error())
			continue
		}
		cred := res.Credential
		_, err = rp.FinishLogin(&webauthn.SessionData{
			Ceremony: webauthn.CeremonyAuthentication, Challenge: h(auth["challenge"]), UserHandle: []byte("u"),
			UserVerification: webauthn.UVPreferred, Expires: now.Add(time.Minute),
		}, &webauthn.AuthenticationResponseJSON{
			ID: webauthn.EncodeURL(credID), RawID: credID, Type: "public-key",
			Response: webauthn.AssertionResponseJSON{ClientDataJSON: h(auth["clientDataJSON"]), AuthenticatorData: h(auth["authenticatorData"]), Signature: h(auth["signature"])},
		}, func([]byte) (*webauthn.Credential, error) { return &cred, nil })
		if err != nil {
			r.record(false, "error", name, "authentication: "+err.Error())
			continue
		}
		r.sum.VectorsOK++
		r.record(true, "verified", name, fmt.Sprintf("%s  attestation=%s  trusted=%v  credIdLen=%d",
			cred.Algorithm, res.Attestation.Type, res.Attestation.Trusted, len(credID)))
	}
	return nil
}

// apiError is a non-2xx answer from the server.
type apiError struct {
	Status  int
	Code    string `json:"error"`
	Message string `json:"message"`
}

func (e *apiError) Error() string { return fmt.Sprintf("HTTP %d %s: %s", e.Status, e.Code, e.Message) }

// user is one browser: a cookie jar plus a virtual client.
type user struct {
	r           *runner
	hc          *http.Client
	client      *virtualauthn.Client
	rpOverride string
}

func (r *runner) newUser(a *virtualauthn.Authenticator) *user {
	jar, _ := cookiejar.New(nil)
	return &user{r: r, hc: &http.Client{Jar: jar, Timeout: 10 * time.Second}, client: &virtualauthn.Client{Origin: origin, Authenticator: a}}
}

func (u *user) post(path string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	resp, err := u.hc.Post(u.r.baseURL+path, "application/json", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		ae := &apiError{Status: resp.StatusCode}
		_ = json.Unmarshal(data, ae)
		return ae
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func (u *user) register(name, display string) (map[string]any, error) {
	var opts webauthn.CreationOptionsJSON
	if err := u.post("/api/register/options", map[string]string{"username": name, "displayName": display}, &opts); err != nil {
		return nil, err
	}
	if u.rpOverride != "" {
		opts.RP.ID = u.rpOverride
	}
	resp, err := u.client.Create(&opts)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	return out, u.post("/api/register/verify", resp, &out)
}

func (u *user) loginCapture(name string) (*webauthn.AuthenticationResponseJSON, error) {
	var opts webauthn.RequestOptionsJSON
	if err := u.post("/api/login/options", map[string]string{"username": name}, &opts); err != nil {
		return nil, err
	}
	return u.client.Get(&opts)
}

func (u *user) login(name string) (map[string]any, error) {
	resp, err := u.loginCapture(name)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	return out, u.post("/api/login/verify", resp, &out)
}

func (u *user) loginMutate(name string, mut func(*webauthn.AuthenticationResponseJSON)) error {
	resp, err := u.loginCapture(name)
	if err != nil {
		return err
	}
	mut(resp)
	return u.post("/api/login/verify", resp, nil)
}
