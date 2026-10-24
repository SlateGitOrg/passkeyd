package webauthn

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/archit2501/passkeyd/cose"
)

type specVectors struct {
	Vectors map[string]struct {
		Registration   map[string]string `json:"registration"`
		Authentication map[string]string `json:"authentication"`
	} `json:"vectors"`
}

func readSpecVectors() (specVectors, error) {
	var v specVectors
	raw, err := os.ReadFile("../testdata/webauthn-l3-vectors.json")
	if err != nil {
		return v, err
	}
	err = json.Unmarshal(raw, &v)
	return v, err
}

func loadSpecVectors(tb testing.TB) specVectors {
	tb.Helper()
	v, err := readSpecVectors()
	if err != nil {
		tb.Fatal(err)
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestSpecVectors replays every registration+authentication pair from the
// WebAuthn Level 3 test vectors (section 16): the relying party must accept
// each one, report the expected attestation type, verify x5c chains against
// the published attestation root, and reject Ed448 (unsupported here).
func TestSpecVectors(t *testing.T) {
	vs := loadSpecVectors(t)
	root, err := x509.ParseCertificate(unhex(t, vs.Vectors["attestation-root-cert"].Registration["attestation_ca_cert"]))
	if err != nil {
		t.Fatal(err)
	}
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rp, err := New(Config{
		RPID:             "example.org",
		Origins:          []string{"https://example.org"},
		AllowCrossOrigin: true,
		TopOrigins:       []string{"https://example.com"},
		Attestation:      &AttestationPolicy{AllowNone: true, AllowSelf: true, AllowBasic: true, TrustAnchors: anchors, RequireTrusted: true},
		Now:              func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		typ AttestationType
		alg cose.Algorithm
	}{
		"none-es256":                    {AttestationNone, cose.AlgES256},
		"packed-self-es256":             {AttestationSelf, cose.AlgES256},
		"none-es256-crossOrigin":        {AttestationNone, cose.AlgES256},
		"none-es256-topOrigin":          {AttestationNone, cose.AlgES256},
		"none-es256-long-credential-id": {AttestationNone, cose.AlgES256},
		"packed-es256":                  {AttestationBasic, cose.AlgES256},
		"packed-es384":                  {AttestationBasic, cose.AlgES384},
		"packed-es512":                  {AttestationBasic, cose.AlgES512},
		"packed-rs256":                  {AttestationBasic, cose.AlgRS256},
		"packed-eddsa":                  {AttestationBasic, cose.AlgEdDSA},
	}
	names := make([]string, 0, len(vs.Vectors))
	for n := range vs.Vectors {
		names = append(names, n)
	}
	sort.Strings(names)
	checked := 0
	for _, name := range names {
		if name == "attestation-root-cert" {
			continue
		}
		v := vs.Vectors[name]
		t.Run(name, func(t *testing.T) {
			reg := v.Registration
			credID := unhex(t, reg["credential_id"])
			sess := &SessionData{
				Ceremony: CeremonyRegistration, Challenge: unhex(t, reg["challenge"]),
				UserHandle: []byte("user"), UserVerification: UVPreferred,
				Algorithms: DefaultAlgorithms, Expires: now.Add(time.Minute),
			}
			resp := &RegistrationResponseJSON{
				ID: EncodeURL(credID), RawID: credID, Type: "public-key",
				Response: AttestationResponseJSON{
					ClientDataJSON:    unhex(t, reg["clientDataJSON"]),
					AttestationObject: unhex(t, reg["attestationObject"]),
				},
			}
			res, err := rp.FinishRegistration(sess, resp, nil)
			if name == "packed-ed448" {
				if CheckOf(err) != CheckAlgorithm {
					t.Fatalf("Ed448 must be rejected with %s, got %v", CheckAlgorithm, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("registration: %v", err)
			}
			w := want[name]
			if res.Attestation.Type != w.typ || res.Credential.Algorithm != w.alg {
				t.Fatalf("got %s/%v, want %s/%v", res.Attestation.Type, res.Credential.Algorithm, w.typ, w.alg)
			}
			if w.typ == AttestationBasic && !res.Attestation.Trusted {
				t.Fatal("x5c chain should verify against the published root")
			}
			if res.Credential.AAGUID != [16]byte(unhex(t, reg["aaguid"])) {
				t.Fatal("AAGUID mismatch")
			}

			auth := v.Authentication
			lsess := &SessionData{
				Ceremony: CeremonyAuthentication, Challenge: unhex(t, auth["challenge"]),
				UserVerification: UVPreferred, Expires: now.Add(time.Minute),
				UserHandle: []byte("user"),
			}
			lresp := &AuthenticationResponseJSON{
				ID: EncodeURL(credID), RawID: credID, Type: "public-key",
				Response: AssertionResponseJSON{
					ClientDataJSON:    unhex(t, auth["clientDataJSON"]),
					AuthenticatorData: unhex(t, auth["authenticatorData"]),
					Signature:         unhex(t, auth["signature"]),
				},
			}
			cred := res.Credential
			lres, err := rp.FinishLogin(lsess, lresp, func([]byte) (*Credential, error) { return &cred, nil })
			if err != nil {
				t.Fatalf("authentication: %v", err)
			}
			if lres.CloneWarning {
				t.Fatal("unexpected clone warning")
			}
			// The same assertion with one signature byte flipped must fail.
			bad := append([]byte(nil), lresp.Response.Signature...)
			bad[len(bad)-1] ^= 0x01
			lresp.Response.Signature = bad
			if _, err := rp.FinishLogin(lsess, lresp, func([]byte) (*Credential, error) { return &cred, nil }); CheckOf(err) != CheckSignature {
				t.Fatalf("tampered signature: %v", err)
			}
			checked++
		})
	}
	if checked != len(want) {
		t.Fatalf("verified %d vectors, want %d", checked, len(want))
	}
}
