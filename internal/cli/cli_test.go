package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a goroutine-safe bytes.Buffer.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuffer) String() string { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func run(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := Run(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func vectors(t *testing.T) map[string]map[string]map[string]string {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/webauthn-l3-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Vectors map[string]map[string]map[string]string `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.Vectors
}

func TestUsageAndVersion(t *testing.T) {
	if code, _, errs := run(); code != 2 || !strings.Contains(errs, "Usage:") {
		t.Fatal(code)
	}
	if code, out, _ := run("version"); code != 0 || out != "passkeyd "+Version+"\n" {
		t.Fatal(out)
	}
	if code, out, _ := run("help"); code != 0 || !strings.Contains(out, "inspect") {
		t.Fatal(out)
	}
	if code, _, errs := run("frobnicate"); code != 2 || !strings.Contains(errs, "unknown command") {
		t.Fatal(errs)
	}
	if code, _, _ := run("serve", "-h"); code != 0 {
		t.Fatal("help flag should exit 0")
	}
	if code, _, errs := run("serve", "extra"); code != 2 || !strings.Contains(errs, "unexpected arguments") {
		t.Fatal(errs)
	}
	if code, _, _ := run("demo", "-nope"); code != 2 && code != 1 {
		t.Fatal(code)
	}
}

func TestInspect(t *testing.T) {
	v := vectors(t)
	packed := v["packed-es256"]["registration"]["attestationObject"]
	code, out, errs := run("inspect", packed)
	if code != 0 {
		t.Fatal(errs)
	}
	for _, want := range []string{"fmt: packed", "attStmt.alg: ES256", "OU=Authenticator Attestation", "publicKey.alg: ES256 (valid)", "flags:"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	self := v["packed-self-es256"]["registration"]["attestationObject"]
	if code, out, _ := run("inspect", "-kind", "attestation", self); code != 0 || !strings.Contains(out, "attStmt.sig: h'") {
		t.Fatal(out)
	}
	ad := v["none-es256"]["authentication"]["authenticatorData"]
	if code, out, _ := run("inspect", ad); code != 0 || !strings.Contains(out, "authenticator data (37 bytes)") {
		t.Fatal(out)
	}
	if code, out, _ := run("inspect", "-kind", "cbor", "a26161016162820203"); code != 0 || !strings.Contains(out, `{"a": 1, "b": [2, 3]}`) {
		t.Fatal(out)
	}
	// auto falls back to plain CBOR; base64url input is accepted.
	if code, out, _ := run("inspect", "omFhAWFiggID"); code != 0 || !strings.Contains(out, `"b": [2, 3]`) {
		t.Fatal(out)
	}
	ed := v["packed-ed448"]["registration"]["attestationObject"]
	if code, out, _ := run("inspect", "-kind", "attestation", ed); code != 0 || !strings.Contains(out, "INVALID") {
		t.Fatal(out)
	}
	for _, args := range [][]string{{"inspect"}, {"inspect", "zz!"}, {"inspect", "-kind", "nope", "00"}, {"inspect", "  "}} {
		if code, _, _ := run(args...); code != 2 {
			t.Errorf("%v: code %d", args, code)
		}
	}
	if code, _, _ := run("inspect", "-kind", "authdata", "00"); code != 1 {
		t.Error("short authdata must fail")
	}
	if code, _, _ := run("inspect", "-kind", "attestation", "a0"); code != 1 {
		t.Error("non-attestation map must fail")
	}
	if code, _, _ := run("inspect", "ff"); code != 1 {
		t.Error("garbage must fail")
	}
}

func TestInspectStdin(t *testing.T) {
	var out, errb bytes.Buffer
	if err := inspect([]string{"-"}, strings.NewReader("a1 01 02\n"), &out, &errb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "{1: 2}") {
		t.Fatal(out.String())
	}
	x5c := "a363666d74667061636b65646761747453746d74a3" + "63616c6726" + "63736967" + "4101" + "63783563" + "81" + "4101" + "6861757468446174615825000000000000000000000000000000000000000000000000000000000000000001" + "00000000"
	b, _ := hex.DecodeString(x5c)
	out.Reset()
	if err := describeAttestation(&out, b); err != nil || !strings.Contains(out.String(), "unparseable certificate") {
		t.Fatalf("%v %s", err, out.String())
	}
}

func TestDemoCommand(t *testing.T) {
	code, out, errs := run("demo", "-vectors", "../../testdata/webauthn-l3-vectors.json")
	if code != 0 || !strings.Contains(out, "0 failed") {
		t.Fatalf("code %d\n%s\n%s", code, out, errs)
	}
}

func writeAnchor(t *testing.T, dir string) string {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "anchors.pem")
	data := append(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestServeLifecycle(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PASSKEYD_LOG_FORMAT", "json")
	t.Setenv("PASSKEYD_REQUIRE_TRUSTED", "true")
	t.Setenv("PASSKEYD_RATE_LIMIT", "5")
	ctx, cancel := context.WithCancel(context.Background())
	var out, errs syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, []string{"serve", "-addr", "127.0.0.1:0", "-db", filepath.Join(dir, "p.db"),
			"-trust-anchors", writeAnchor(t, dir), "-clone-policy", "flag", "-origins", "https://localhost, http://localhost:8080"}, &out, &errs)
	}()
	re := regexp.MustCompile(`listening on (http://[0-9.:]+)`)
	var base string
	for range 200 {
		if m := re.FindStringSubmatch(out.String()); m != nil {
			base = m[1]
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if base == "" {
		cancel()
		t.Fatalf("server did not start: %s %s", out.String(), errs.String())
	}
	resp, err := http.Get(base + "/api/health")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	cancel()
	if code := <-done; code != 0 {
		t.Fatalf("exit %d: %s", code, errs.String())
	}
	if !strings.Contains(out.String(), "passkeyd stopped") || !strings.Contains(errs.String(), `"msg":"http"`) {
		t.Fatalf("out %q errs %q", out.String(), errs.String())
	}
}

func TestServeConfigErrors(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "x.db")
	empty := filepath.Join(dir, "empty.pem")
	_ = os.WriteFile(empty, []byte("nothing"), 0o600)
	bad := filepath.Join(dir, "bad.pem")
	_ = os.WriteFile(bad, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2}}), 0o600)
	cases := []struct {
		args []string
		code int
	}{
		{[]string{"-log-level", "loud"}, 2},
		{[]string{"-log-format", "xml"}, 2},
		{[]string{"-clone-policy", "ignore"}, 2},
		{[]string{"-trust-anchors", filepath.Join(dir, "missing.pem")}, 1},
		{[]string{"-trust-anchors", empty}, 1},
		{[]string{"-trust-anchors", bad}, 1},
		{[]string{"-rp-id", "Bad Host"}, 1},
		{[]string{"-db", filepath.Join(dir, "no", "such", "dir.db")}, 1},
		{[]string{"-addr", "256.0.0.1:99999"}, 1},
	}
	for _, tc := range cases {
		args := append([]string{"serve", "-db", db}, tc.args...)
		if code, _, errs := run(args...); code != tc.code {
			t.Errorf("%v: code %d (%s)", tc.args, code, errs)
		}
	}
	t.Setenv("PASSKEYD_DEVICE_BOUND", "not-a-bool")
	t.Setenv("PASSKEYD_RATE_LIMIT", "many")
	c, err := parseServeFlags(nil, &bytes.Buffer{})
	if err != nil || c.deviceBound || c.rateLimit != 30 {
		t.Fatalf("invalid env values must fall back to defaults: %+v %v", c, err)
	}
}
