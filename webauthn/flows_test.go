package webauthn_test

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/archit2501/passkeyd/cbor"
	"github.com/archit2501/passkeyd/cose"
	"github.com/archit2501/passkeyd/virtualauthn"
	"github.com/archit2501/passkeyd/webauthn"
)

func TestFlowsAllModesAndAlgorithms(t *testing.T) {
	algs := []cose.Algorithm{cose.AlgES256, cose.AlgEdDSA, cose.AlgES384, cose.AlgES512, cose.AlgRS256}
	modes := []virtualauthn.AttestationMode{virtualauthn.AttestNone, virtualauthn.AttestPackedSelf, virtualauthn.AttestPackedX5C}
	wantType := map[virtualauthn.AttestationMode]webauthn.AttestationType{
		virtualauthn.AttestNone:       webauthn.AttestationNone,
		virtualauthn.AttestPackedSelf: webauthn.AttestationSelf,
		virtualauthn.AttestPackedX5C:  webauthn.AttestationBasic,
	}
	for _, mode := range modes {
		for _, alg := range algs {
			t.Run(mode.String()+"/"+alg.String(), func(t *testing.T) {
				if alg == cose.AlgRS256 && testing.Short() {
					t.Skip("RSA key generation is slow")
				}
				aaguid := [16]byte{0xaa, 0x01}
				h := newHarness(t, func(c *webauthn.Config) { c.Algorithms = []cose.Algorithm{alg} },
					virtualauthn.Options{Attestation: mode, AAGUID: aaguid})
				cred := h.register()
				if cred.Algorithm != alg || cred.AttestationType != wantType[mode] || cred.AAGUID != aaguid {
					t.Fatalf("credential %+v", cred)
				}
				if cred.SignCount != 1 || !cred.UVInitialized || cred.BackupEligible {
					t.Fatalf("initial state %+v", cred)
				}
				for i := range 3 {
					res, err := h.login(&cred)
					if err != nil {
						t.Fatalf("login %d: %v", i, err)
					}
					if res.Credential.SignCount != uint32(i+2) || res.CloneWarning || !res.UserVerified {
						t.Fatalf("login %d result %+v", i, res)
					}
					cred = res.Credential
				}
			})
		}
	}
}

func TestTrustedX5C(t *testing.T) {
	auth := virtualauthn.New(x5c)
	root, err := auth.AttestationRoot()
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	h := newHarness(t, func(c *webauthn.Config) {
		c.Attestation = &webauthn.AttestationPolicy{AllowBasic: true, TrustAnchors: pool, RequireTrusted: true}
	}, x5c)
	h.auth = auth
	h.client.Authenticator = auth
	o, s := h.beginReg()
	res, err := h.finishReg(s, h.create(o))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Attestation.Trusted || len(res.Attestation.TrustPath) != 1 || !res.Credential.AttestationTrusted {
		t.Fatalf("attestation %+v", res.Attestation)
	}
}

func TestDiscoverableLogin(t *testing.T) {
	h := newHarness(t, nil, none)
	cred := h.register()
	o, s := h.beginLogin(nil)
	if len(o.AllowCredentials) != 0 || o.RPID != rpID {
		t.Fatalf("options %+v", o)
	}
	res, err := h.finishLogin(s, h.get(o))
	if err != nil {
		t.Fatal(err)
	}
	if string(res.Credential.UserHandle) != string(cred.UserHandle) {
		t.Fatal("wrong user")
	}
}

func TestZeroCounterNeverFlagsClone(t *testing.T) {
	h := newHarness(t, nil, virtualauthn.Options{ZeroCounter: true, BackupEligible: true, BackupState: true})
	cred := h.register()
	if cred.SignCount != 0 || !cred.BackupEligible || !cred.BackupState {
		t.Fatalf("cred %+v", cred)
	}
	for range 3 {
		res, err := h.login(&cred)
		if err != nil || res.CloneWarning || res.Credential.SignCount != 0 {
			t.Fatalf("res %+v err %v", res, err)
		}
	}
}

func TestCounterJumpToZeroIsRegression(t *testing.T) {
	h := newHarness(t, nil, none)
	cred := h.register()
	if err := h.auth.SetCounter(cred.ID, 0); err != nil {
		t.Fatal(err)
	}
	// Authenticator now increments to 1, stored counter is 1: regression.
	if _, err := h.login(&cred); webauthn.CheckOf(err) != webauthn.CheckSignCount {
		t.Fatalf("got %v", err)
	}
	if err := h.auth.SetCounter([]byte("nope"), 1); !errors.Is(err, virtualauthn.ErrNoCredential) {
		t.Fatal(err)
	}
}

func TestClonePolicyFlag(t *testing.T) {
	h := newHarness(t, func(c *webauthn.Config) { c.ClonePolicy = webauthn.CloneFlag }, none)
	cred := h.register()
	clone := h.auth.Clone(none)
	if _, err := h.login(&cred); err != nil {
		t.Fatal(err)
	}
	h.client.Authenticator = clone
	res, err := h.login(&cred)
	if err != nil {
		t.Fatalf("CloneFlag must not reject: %v", err)
	}
	if !res.CloneWarning || !res.Credential.CloneWarning || res.Credential.SignCount != 2 || res.PreviousSignCount != 2 {
		t.Fatalf("res %+v", res)
	}
}

func TestUserVerificationRequiredAndUVInitialized(t *testing.T) {
	h := newHarness(t, nil, virtualauthn.Options{NoUserVerification: true})
	cred := h.register()
	if cred.UVInitialized {
		t.Fatal("UV should not be initialized")
	}
	h.client.Authenticator = h.auth.Clone(none)
	res, err := h.login(&cred)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Credential.UVInitialized {
		t.Fatal("UV login should initialize UV")
	}
	h2 := newHarness(t, func(c *webauthn.Config) { c.UserVerification = webauthn.UVRequired }, none)
	cred2 := h2.register()
	if _, err := h2.login(&cred2); err != nil {
		t.Fatal(err)
	}
	h2.client.Authenticator = h2.auth.Clone(virtualauthn.Options{NoUserVerification: true})
	if _, err := h2.login(&cred2); webauthn.CheckOf(err) != webauthn.CheckUserVerified {
		t.Fatalf("got %v", err)
	}
}

func TestCrossOriginAllowed(t *testing.T) {
	h := newHarness(t, func(c *webauthn.Config) {
		c.AllowCrossOrigin, c.TopOrigins = true, []string{"https://partner.test"}
	}, none)
	h.client.CrossOrigin, h.client.TopOrigin = true, "https://partner.test"
	cred := h.register()
	if _, err := h.login(&cred); err != nil {
		t.Fatal(err)
	}
}

func TestExtensionsAccepted(t *testing.T) {
	ext := cbor.Encode(cbor.NewMap(cbor.Pair{Key: cbor.NewText("credProtect"), Value: cbor.NewUint(1)}))
	h := newHarness(t, nil, virtualauthn.Options{AuthDataHook: func(ad []byte) []byte {
		ad[32] |= 0x80
		return append(ad, ext...)
	}})
	cred := h.register()
	if _, err := h.login(&cred); err != nil {
		t.Fatal(err)
	}
	ad, err := webauthn.ParseAuthenticatorData(append(make([]byte, 32), append([]byte{0x81, 0, 0, 0, 0}, 0x01)...))
	if err == nil || ad != nil {
		t.Fatal("extensions that are not a map must fail")
	}
}

func TestNewConfigValidation(t *testing.T) {
	bad := []webauthn.Config{
		{},
		{RPID: "Example.org", Origins: []string{origin}},
		{RPID: "example.org:443", Origins: []string{origin}},
		{RPID: rpID},
		{RPID: rpID, Origins: []string{""}},
		{RPID: rpID, Origins: []string{"https://example.org/login"}},
		{RPID: rpID, Origins: []string{"https://example.org/"}},
		{RPID: rpID, Origins: []string{"https://example.com"}},
		{RPID: rpID, Origins: []string{"http://example.org"}},
		{RPID: rpID, Origins: []string{"https://%zz"}},
		{RPID: rpID, Origins: []string{origin}, UserVerification: "always"},
		{RPID: rpID, Origins: []string{origin}, Algorithms: []cose.Algorithm{-65535}},
	}
	for i, c := range bad {
		if _, err := webauthn.New(c); !errors.Is(err, webauthn.ErrConfig) {
			t.Errorf("case %d: got %v", i, err)
		}
	}
	good := []webauthn.Config{
		{RPID: "localhost", Origins: []string{"http://localhost:8080"}},
		{RPID: rpID, Origins: []string{"https://login.example.org", "android:apk-key-hash:abc"}},
	}
	for i, c := range good {
		rp, err := webauthn.New(c)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		eff := rp.Config()
		if eff.UserVerification != webauthn.UVPreferred || eff.Conveyance != webauthn.ConveyanceNone || eff.Timeout != 5*time.Minute ||
			len(eff.Algorithms) != 5 || eff.RPName != c.RPID || !eff.Attestation.AllowNone {
			t.Fatalf("defaults not applied: %+v", eff)
		}
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("entropy exhausted") }

func TestBeginRegistration(t *testing.T) {
	h := newHarness(t, func(c *webauthn.Config) { c.ResidentKey = webauthn.ResidentKeyRequired }, none)
	cred := h.register()
	opts, sess, err := h.rp.BeginRegistration(webauthn.User{ID: []byte{1}, Name: "bob"}, []webauthn.Credential{cred})
	if err != nil {
		t.Fatal(err)
	}
	if opts.User.DisplayName != "bob" || len(opts.ExcludeCredentials) != 1 || !opts.AuthenticatorSelection.RequireResidentKey ||
		len(opts.Challenge) != webauthn.ChallengeSize || sess.Expires != h.now.Add(5*time.Minute) {
		t.Fatalf("opts %+v sess %+v", opts, sess)
	}
	raw, err := json.Marshal(opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"pubKeyCredParams":[{"type":"public-key","alg":-7}`, `"residentKey":"required"`, `"attestation":"none"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("options JSON lacks %s: %s", want, raw)
		}
	}
	for _, u := range []webauthn.User{{Name: "x"}, {ID: make([]byte, 65), Name: "x"}, {ID: []byte{1}}} {
		if _, _, err := h.rp.BeginRegistration(u, nil); !errors.Is(err, webauthn.ErrInvalidUser) {
			t.Errorf("user %+v: %v", u, err)
		}
	}
	rp, _ := webauthn.New(webauthn.Config{RPID: rpID, Origins: []string{origin}, Rand: errReader{}})
	if _, _, err := rp.BeginRegistration(webauthn.User{ID: []byte{1}, Name: "x"}, nil); err == nil {
		t.Fatal("expected entropy error")
	}
	if _, _, err := rp.BeginLogin(nil, nil); err == nil {
		t.Fatal("expected entropy error")
	}
}

func TestURLBytesJSON(t *testing.T) {
	var b webauthn.URLBytes
	if err := json.Unmarshal([]byte(`"AQID"`), &b); err != nil || string(b) != "\x01\x02\x03" {
		t.Fatalf("%v %v", b, err)
	}
	for _, in := range []string{`"AQI="`, `"+/8"`, `5`, `"A"`} {
		if err := json.Unmarshal([]byte(in), &b); err == nil {
			t.Errorf("%s should be rejected", in)
		}
	}
	out, _ := json.Marshal(webauthn.URLBytes{0xfb, 0xff})
	if string(out) != `"-_8"` {
		t.Fatalf("got %s", out)
	}
}

func TestMisc(t *testing.T) {
	if f := webauthn.Flags(0x5d); f.String() != "UP|UV|BE|BS|AT" {
		t.Fatalf("flags %s", f)
	}
	if webauthn.Flags(0).String() != "-" {
		t.Fatal("empty flags")
	}
	c := webauthn.Credential{AAGUID: [16]byte{0: 0xab, 15: 0xcd}}
	if c.AAGUIDString() != "ab000000-0000-0000-0000-0000000000cd" {
		t.Fatal(c.AAGUIDString())
	}
	if webauthn.CheckOf(errors.New("x")) != "" || webauthn.CheckOf(nil) != "" {
		t.Fatal("CheckOf on non-verify error")
	}
	e := &webauthn.VerifyError{Check: webauthn.CheckOrigin, Detail: "d", Err: errors.New("cause")}
	if e.Error() != "webauthn: origin_mismatch: d: cause" || errors.Unwrap(e) == nil {
		t.Fatal(e.Error())
	}
	if errors.Is(e, errors.New("x")) || errors.Is(e, webauthn.ErrCheck(webauthn.CheckSignature)) {
		t.Fatal("Is must only match the same check")
	}
	if virtualauthn.AttestationMode(9).String() != "none" {
		t.Fatal("mode string")
	}
	if len(webauthn.AllChecks()) != 34 {
		t.Fatalf("AllChecks has %d entries", len(webauthn.AllChecks()))
	}
}
