package webauthn_test

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/archit2501/passkeyd/cbor"
	"github.com/archit2501/passkeyd/cose"
	"github.com/archit2501/passkeyd/virtualauthn"
	"github.com/archit2501/passkeyd/webauthn"
)

const (
	rpID   = "example.org"
	origin = "https://example.org"
)

type harness struct {
	t      testing.TB
	rp     *webauthn.RelyingParty
	auth   *virtualauthn.Authenticator
	client *virtualauthn.Client
	now    time.Time
	user   webauthn.User
	store  map[string]webauthn.Credential
}

func newHarness(t testing.TB, cfgMod func(*webauthn.Config), opts virtualauthn.Options) *harness {
	t.Helper()
	h := &harness{
		t:     t,
		now:   time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC),
		user:  webauthn.User{ID: []byte("user-0001"), Name: "alice", DisplayName: "Alice"},
		store: map[string]webauthn.Credential{},
	}
	cfg := webauthn.Config{RPID: rpID, RPName: "Example", Origins: []string{origin}, Now: func() time.Time { return h.now }}
	if cfgMod != nil {
		cfgMod(&cfg)
	}
	rp, err := webauthn.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	h.rp = rp
	h.auth = virtualauthn.New(opts)
	h.client = &virtualauthn.Client{Origin: origin, Authenticator: h.auth}
	return h
}

func (h *harness) beginReg() (*webauthn.CreationOptionsJSON, *webauthn.SessionData) {
	h.t.Helper()
	opts, sess, err := h.rp.BeginRegistration(h.user, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	return opts, sess
}

func (h *harness) create(opts *webauthn.CreationOptionsJSON) *webauthn.RegistrationResponseJSON {
	h.t.Helper()
	resp, err := h.client.Create(opts)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func (h *harness) exists(id []byte) (bool, error) {
	_, ok := h.store[string(id)]
	return ok, nil
}

func (h *harness) finishReg(sess *webauthn.SessionData, resp *webauthn.RegistrationResponseJSON) (*webauthn.RegistrationResult, error) {
	res, err := h.rp.FinishRegistration(sess, resp, h.exists)
	if err == nil {
		h.store[string(res.Credential.ID)] = res.Credential
	}
	return res, err
}

// register runs a full successful registration.
func (h *harness) register() webauthn.Credential {
	h.t.Helper()
	opts, sess := h.beginReg()
	res, err := h.finishReg(sess, h.create(opts))
	if err != nil {
		h.t.Fatalf("registration: %v", err)
	}
	return res.Credential
}

func (h *harness) lookup(id []byte) (*webauthn.Credential, error) {
	c, ok := h.store[string(id)]
	if !ok {
		return nil, nil
	}
	return &c, nil
}

func (h *harness) beginLogin(cred *webauthn.Credential) (*webauthn.RequestOptionsJSON, *webauthn.SessionData) {
	h.t.Helper()
	var (
		handle []byte
		allow  []webauthn.Credential
	)
	if cred != nil {
		handle, allow = cred.UserHandle, []webauthn.Credential{*cred}
	}
	opts, sess, err := h.rp.BeginLogin(handle, allow)
	if err != nil {
		h.t.Fatal(err)
	}
	return opts, sess
}

func (h *harness) get(opts *webauthn.RequestOptionsJSON) *webauthn.AuthenticationResponseJSON {
	h.t.Helper()
	resp, err := h.client.Get(opts)
	if err != nil {
		h.t.Fatal(err)
	}
	return resp
}

func (h *harness) finishLogin(sess *webauthn.SessionData, resp *webauthn.AuthenticationResponseJSON) (*webauthn.LoginResult, error) {
	res, err := h.rp.FinishLogin(sess, resp, h.lookup)
	if err == nil {
		h.store[string(res.Credential.ID)] = res.Credential
	}
	return res, err
}

// login runs a full login for cred and returns the error, if any.
func (h *harness) login(cred *webauthn.Credential) (*webauthn.LoginResult, error) {
	h.t.Helper()
	opts, sess := h.beginLogin(cred)
	return h.finishLogin(sess, h.get(opts))
}

// rewriteAttObj decodes an attestation object, lets fn edit it and
// re-encodes it.
func rewriteAttObj(t *testing.T, raw []byte, fn func(format *string, stmt *cbor.Value, authData *[]byte)) []byte {
	t.Helper()
	v, err := cbor.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := v.LookupText("fmt")
	format, _ := f.Text()
	stmt, _ := v.LookupText("attStmt")
	adV, _ := v.LookupText("authData")
	ad, _ := adV.Bytes()
	fn(&format, &stmt, &ad)
	return cbor.Encode(cbor.NewMap(
		cbor.Pair{Key: cbor.NewText("fmt"), Value: cbor.NewText(format)},
		cbor.Pair{Key: cbor.NewText("attStmt"), Value: stmt},
		cbor.Pair{Key: cbor.NewText("authData"), Value: cbor.NewBytes(ad)},
	))
}

// stmtWith returns stmt with key set to val (added or replaced) or removed
// when val is the zero Value.
func stmtWith(stmt cbor.Value, key string, val cbor.Value) cbor.Value {
	pairs, _ := stmt.Map()
	out := []cbor.Pair{}
	found := false
	for _, p := range pairs {
		if k, _ := p.Key.Text(); k == key {
			found = true
			if val.Kind() != cbor.KindInvalid {
				out = append(out, cbor.Pair{Key: p.Key, Value: val})
			}
			continue
		}
		out = append(out, p)
	}
	if !found && val.Kind() != cbor.KindInvalid {
		out = append(out, cbor.Pair{Key: cbor.NewText(key), Value: val})
	}
	return cbor.NewMap(out...)
}

func flipLast(b []byte) []byte {
	c := bytes.Clone(b)
	c[len(c)-1] ^= 0x01
	return c
}

func clearFlag(mask byte) func([]byte) []byte {
	return func(ad []byte) []byte { ad[32] &^= mask; return ad }
}

// negativeCase is one hostile or non-conforming response and the Check that
// must reject it.
type negativeCase struct {
	name  string
	check webauthn.Check
	run   func(t *testing.T) error
}

// regCase builds a case that registers with the given config/options and
// lets mut tamper with the session, options, or response.
func regCase(name string, check webauthn.Check, cfgMod func(*webauthn.Config), opts virtualauthn.Options,
	before func(h *harness, o *webauthn.CreationOptionsJSON, s *webauthn.SessionData),
	after func(t *testing.T, h *harness, r *webauthn.RegistrationResponseJSON) *webauthn.SessionData) negativeCase {
	return negativeCase{name: name, check: check, run: func(t *testing.T) error {
		h := newHarness(t, cfgMod, opts)
		o, s := h.beginReg()
		if before != nil {
			before(h, o, s)
		}
		r := h.create(o)
		if after != nil {
			if s2 := after(t, h, r); s2 != nil {
				s = s2
			}
		}
		_, err := h.finishReg(s, r)
		return err
	}}
}

// loginCase registers a credential, then runs a login that mut tampers with.
func loginCase(name string, check webauthn.Check, cfgMod func(*webauthn.Config), opts virtualauthn.Options,
	mut func(t *testing.T, h *harness, cred *webauthn.Credential, o *webauthn.RequestOptionsJSON, s *webauthn.SessionData) *webauthn.AuthenticationResponseJSON) negativeCase {
	return negativeCase{name: name, check: check, run: func(t *testing.T) error {
		h := newHarness(t, cfgMod, opts)
		cred := h.register()
		o, s := h.beginLogin(&cred)
		resp := mut(t, h, &cred, o, s)
		_, err := h.finishLogin(s, resp)
		return err
	}}
}

func editAttObj(fn func(format *string, stmt *cbor.Value, authData *[]byte)) func(*testing.T, *harness, *webauthn.RegistrationResponseJSON) *webauthn.SessionData {
	return func(t *testing.T, _ *harness, r *webauthn.RegistrationResponseJSON) *webauthn.SessionData {
		r.Response.AttestationObject = rewriteAttObj(t, r.Response.AttestationObject, fn)
		return nil
	}
}

func certHook(fn func(*x509.Certificate)) virtualauthn.Options {
	return virtualauthn.Options{Attestation: virtualauthn.AttestPackedX5C, CertHook: fn}
}

var (
	self = virtualauthn.Options{Attestation: virtualauthn.AttestPackedSelf}
	x5c  = virtualauthn.Options{Attestation: virtualauthn.AttestPackedX5C}
	none = virtualauthn.Options{}
)

func hookClientData(fn func(*webauthn.CollectedClientData)) func(*harness, *webauthn.CreationOptionsJSON, *webauthn.SessionData) {
	return func(h *harness, _ *webauthn.CreationOptionsJSON, _ *webauthn.SessionData) {
		h.client.ClientDataHook = fn
	}
}

func negativeCases() []negativeCase {
	oidAAGUID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}
	return []negativeCase{
		// --- session ---
		regCase("expired session", webauthn.CheckSession, nil, none, nil,
			func(_ *testing.T, h *harness, _ *webauthn.RegistrationResponseJSON) *webauthn.SessionData {
				h.now = h.now.Add(6 * time.Minute)
				return nil
			}),
		regCase("login session used for registration", webauthn.CheckSession, nil, none, nil,
			func(_ *testing.T, h *harness, _ *webauthn.RegistrationResponseJSON) *webauthn.SessionData {
				_, s := h.beginLogin(nil)
				return s
			}),
		{"nil session", webauthn.CheckSession, func(t *testing.T) error {
			h := newHarness(t, nil, none)
			_, err := h.rp.FinishLogin(nil, &webauthn.AuthenticationResponseJSON{}, h.lookup)
			return err
		}},
		// --- response shape ---
		regCase("wrong credential type", webauthn.CheckResponseShape, nil, none, nil,
			func(_ *testing.T, _ *harness, r *webauthn.RegistrationResponseJSON) *webauthn.SessionData {
				r.Type = "password"
				return nil
			}),
		regCase("id differs from rawId", webauthn.CheckResponseShape, nil, none, nil,
			func(_ *testing.T, _ *harness, r *webauthn.RegistrationResponseJSON) *webauthn.SessionData {
				r.ID = "AAAA"
				return nil
			}),
		regCase("empty rawId", webauthn.CheckResponseShape, nil, none, nil,
			func(_ *testing.T, _ *harness, r *webauthn.RegistrationResponseJSON) *webauthn.SessionData {
				r.RawID, r.ID = nil, ""
				return nil
			}),
		{"nil registration response", webauthn.CheckResponseShape, func(t *testing.T) error {
			h := newHarness(t, nil, none)
			_, s := h.beginReg()
			_, err := h.rp.FinishRegistration(s, nil, nil)
			return err
		}},
		// --- client data ---
		regCase("clientDataJSON not JSON", webauthn.CheckClientDataJSON, nil, none, nil,
			func(_ *testing.T, _ *harness, r *webauthn.RegistrationResponseJSON) *webauthn.SessionData {
				r.Response.ClientDataJSON = []byte("{not json")
				return nil
			}),
		regCase("clientDataJSON empty", webauthn.CheckClientDataJSON, nil, none, nil,
			func(_ *testing.T, _ *harness, r *webauthn.RegistrationResponseJSON) *webauthn.SessionData {
				r.Response.ClientDataJSON = nil
				return nil
			}),
		regCase("get type in create", webauthn.CheckClientDataType, nil, none,
			hookClientData(func(cd *webauthn.CollectedClientData) { cd.Type = webauthn.ClientDataGet }), nil),
		regCase("different challenge", webauthn.CheckChallenge, nil, none,
			hookClientData(func(cd *webauthn.CollectedClientData) {
				cd.Challenge = webauthn.EncodeURL([]byte("replayed-old-challenge"))
			}), nil),
		regCase("padded challenge", webauthn.CheckChallenge, nil, none,
			hookClientData(func(cd *webauthn.CollectedClientData) { cd.Challenge += "=" }), nil),
		regCase("phishing origin", webauthn.CheckOrigin, nil, none,
			hookClientData(func(cd *webauthn.CollectedClientData) { cd.Origin = "https://example.org.evil.test" }), nil),
		regCase("cross-origin iframe", webauthn.CheckCrossOrigin, nil, none,
			hookClientData(func(cd *webauthn.CollectedClientData) { cd.CrossOrigin = true }), nil),
		regCase("unexpected top origin", webauthn.CheckTopOrigin,
			func(c *webauthn.Config) { c.AllowCrossOrigin, c.TopOrigins = true, []string{"https://partner.test"} }, none,
			hookClientData(func(cd *webauthn.CollectedClientData) { cd.CrossOrigin, cd.TopOrigin = true, "https://evil.test" }), nil),
		regCase("top origin on same-origin ceremony", webauthn.CheckTopOrigin,
			func(c *webauthn.Config) { c.AllowCrossOrigin, c.TopOrigins = true, []string{"https://partner.test"} }, none,
			hookClientData(func(cd *webauthn.CollectedClientData) { cd.TopOrigin = "https://partner.test" }), nil),
		// --- attestation object ---
		regCase("attestationObject not CBOR", webauthn.CheckAttestationObject, nil, none, nil,
			func(_ *testing.T, _ *harness, r *webauthn.RegistrationResponseJSON) *webauthn.SessionData {
				r.Response.AttestationObject = []byte{0xa3, 0x63}
				return nil
			}),
		regCase("attestationObject empty", webauthn.CheckAttestationObject, nil, none, nil,
			func(_ *testing.T, _ *harness, r *webauthn.RegistrationResponseJSON) *webauthn.SessionData {
				r.Response.AttestationObject = nil
				return nil
			}),
		regCase("attestationObject missing authData", webauthn.CheckAttestationObject, nil, none, nil,
			func(_ *testing.T, _ *harness, r *webauthn.RegistrationResponseJSON) *webauthn.SessionData {
				r.Response.AttestationObject = cbor.Encode(cbor.NewMap(
					cbor.Pair{Key: cbor.NewText("fmt"), Value: cbor.NewText("none")},
					cbor.Pair{Key: cbor.NewText("attStmt"), Value: cbor.NewMap()},
					cbor.Pair{Key: cbor.NewText("authdata"), Value: cbor.NewBytes(nil)},
				))
				return nil
			}),
		regCase("fmt not text", webauthn.CheckAttestationObject, nil, none, nil,
			func(_ *testing.T, _ *harness, r *webauthn.RegistrationResponseJSON) *webauthn.SessionData {
				r.Response.AttestationObject = cbor.Encode(cbor.NewMap(
					cbor.Pair{Key: cbor.NewText("fmt"), Value: cbor.NewInt(1)},
					cbor.Pair{Key: cbor.NewText("attStmt"), Value: cbor.NewMap()},
					cbor.Pair{Key: cbor.NewText("authData"), Value: cbor.NewBytes(nil)},
				))
				return nil
			}),
		regCase("authData not bytes", webauthn.CheckAttestationObject, nil, none, nil,
			func(_ *testing.T, _ *harness, r *webauthn.RegistrationResponseJSON) *webauthn.SessionData {
				r.Response.AttestationObject = cbor.Encode(cbor.NewMap(
					cbor.Pair{Key: cbor.NewText("fmt"), Value: cbor.NewText("none")},
					cbor.Pair{Key: cbor.NewText("attStmt"), Value: cbor.NewMap()},
					cbor.Pair{Key: cbor.NewText("authData"), Value: cbor.NewText("x")},
				))
				return nil
			}),
		regCase("attStmt not a map", webauthn.CheckAttestationObject, nil, none, nil,
			editAttObj(func(_ *string, stmt *cbor.Value, _ *[]byte) { *stmt = cbor.NewArray() })),
		// --- authenticator data ---
		regCase("authData truncated", webauthn.CheckAuthData, nil, none, nil,
			editAttObj(func(_ *string, _ *cbor.Value, ad *[]byte) { *ad = (*ad)[:30] })),
		regCase("authData trailing bytes", webauthn.CheckAuthData, nil, none, nil,
			editAttObj(func(_ *string, _ *cbor.Value, ad *[]byte) { *ad = append(*ad, 0x00) })),
		regCase("ED flag without extensions", webauthn.CheckAuthData, nil,
			virtualauthn.Options{AuthDataHook: func(ad []byte) []byte { ad[32] |= 0x80; return ad }}, nil, nil),
		regCase("credential key truncated", webauthn.CheckAuthData, nil, none, nil,
			editAttObj(func(_ *string, _ *cbor.Value, ad *[]byte) { *ad = (*ad)[:len(*ad)-5] })),
		loginCase("AT flag in assertion", webauthn.CheckAuthData, nil, none,
			func(t *testing.T, h *harness, _ *webauthn.Credential, o *webauthn.RequestOptionsJSON, _ *webauthn.SessionData) *webauthn.AuthenticationResponseJSON {
				r := h.get(o)
				r.Response.AuthenticatorData[32] |= 0x40
				return r
			}),
		regCase("wrong RP ID", webauthn.CheckRPIDHash, nil, none,
			func(_ *harness, o *webauthn.CreationOptionsJSON, _ *webauthn.SessionData) { o.RP.ID = "evil.test" }, nil),
		loginCase("wrong RP ID at login", webauthn.CheckRPIDHash, nil, none,
			func(t *testing.T, h *harness, _ *webauthn.Credential, o *webauthn.RequestOptionsJSON, _ *webauthn.SessionData) *webauthn.AuthenticationResponseJSON {
				// The RP ID hash is checked before the signature.
				r := h.get(o)
				r.Response.AuthenticatorData[0] ^= 0xff
				return r
			}),
		regCase("user not present", webauthn.CheckUserPresent, nil,
			virtualauthn.Options{AuthDataHook: clearFlag(0x01)}, nil, nil),
		regCase("user not verified when required", webauthn.CheckUserVerified,
			func(c *webauthn.Config) { c.UserVerification = webauthn.UVRequired },
			virtualauthn.Options{NoUserVerification: true}, nil, nil),
		regCase("BS without BE", webauthn.CheckBackupFlags, nil,
			virtualauthn.Options{BackupState: true}, nil, nil),
		regCase("synced credential under device-bound policy", webauthn.CheckBackupPolicy,
			func(c *webauthn.Config) { c.RejectBackupEligible = true },
			virtualauthn.Options{BackupEligible: true, BackupState: true}, nil, nil),
		// --- attested credential data ---
		regCase("AT flag missing at registration", webauthn.CheckAttestedCredential, nil,
			virtualauthn.Options{AuthDataHook: func(ad []byte) []byte { ad = ad[:37]; ad[32] &^= 0x40; return ad }}, nil, nil),
		regCase("empty credential ID", webauthn.CheckAttestedCredential, nil,
			virtualauthn.Options{AuthDataHook: func(ad []byte) []byte {
				out := append(bytes.Clone(ad[:53]), 0, 0)
				return append(out, ad[55+32:]...)
			}}, nil, nil),
		regCase("credential ID over 1023 bytes", webauthn.CheckCredentialIDLength, nil,
			virtualauthn.Options{AuthDataHook: func(ad []byte) []byte {
				out := binary.BigEndian.AppendUint16(bytes.Clone(ad[:53]), 1024)
				out = append(out, make([]byte, 1024)...)
				return append(out, ad[55+32:]...)
			}}, nil, nil),
		regCase("rawId differs from attested ID", webauthn.CheckCredentialIDMismatch, nil, none, nil,
			func(_ *testing.T, _ *harness, r *webauthn.RegistrationResponseJSON) *webauthn.SessionData {
				r.RawID = []byte("another-credential")
				r.ID = webauthn.EncodeURL(r.RawID)
				return nil
			}),
		regCase("public key off curve", webauthn.CheckPublicKey, nil,
			virtualauthn.Options{AuthDataHook: func(ad []byte) []byte { ad[len(ad)-1] ^= 0x01; return ad }}, nil, nil),
		regCase("unrequested algorithm", webauthn.CheckAlgorithm, nil, none,
			func(_ *harness, o *webauthn.CreationOptionsJSON, s *webauthn.SessionData) {
				o.PubKeyCredParams = []webauthn.CredentialParameter{{Type: "public-key", Alg: int64(cose.AlgEdDSA)}}
				s.Algorithms = []cose.Algorithm{cose.AlgES256}
			}, nil),
		regCase("self attestation alg mismatch", webauthn.CheckAlgorithm, nil, self, nil,
			editAttObj(func(_ *string, stmt *cbor.Value, _ *[]byte) {
				*stmt = stmtWith(*stmt, "alg", cbor.NewInt(int64(cose.AlgES384)))
			})),
		regCase("unsupported x5c attestation alg", webauthn.CheckAlgorithm, nil, x5c, nil,
			editAttObj(func(_ *string, stmt *cbor.Value, _ *[]byte) { *stmt = stmtWith(*stmt, "alg", cbor.NewInt(-65535)) })),
		// --- attestation statement ---
		regCase("unknown format", webauthn.CheckAttestationFormat, nil, none, nil,
			editAttObj(func(f *string, _ *cbor.Value, _ *[]byte) { *f = "tpm" })),
		regCase("ECDAA statement", webauthn.CheckAttestationFormat, nil, self, nil,
			editAttObj(func(_ *string, stmt *cbor.Value, _ *[]byte) {
				*stmt = stmtWith(*stmt, "ecdaaKeyId", cbor.NewBytes([]byte{1}))
			})),
		regCase("none with statement", webauthn.CheckAttestationStatement, nil, none, nil,
			editAttObj(func(_ *string, stmt *cbor.Value, _ *[]byte) { *stmt = stmtWith(*stmt, "sig", cbor.NewBytes([]byte{1})) })),
		regCase("packed without sig", webauthn.CheckAttestationStatement, nil, self, nil,
			editAttObj(func(_ *string, stmt *cbor.Value, _ *[]byte) { *stmt = stmtWith(*stmt, "sig", cbor.Value{}) })),
		regCase("packed alg not int", webauthn.CheckAttestationStatement, nil, self, nil,
			editAttObj(func(_ *string, stmt *cbor.Value, _ *[]byte) { *stmt = stmtWith(*stmt, "alg", cbor.NewText("ES256")) })),
		regCase("packed sig not bytes", webauthn.CheckAttestationStatement, nil, self, nil,
			editAttObj(func(_ *string, stmt *cbor.Value, _ *[]byte) { *stmt = stmtWith(*stmt, "sig", cbor.NewInt(1)) })),
		regCase("packed unknown member", webauthn.CheckAttestationStatement, nil, self, nil,
			editAttObj(func(_ *string, stmt *cbor.Value, _ *[]byte) { *stmt = stmtWith(*stmt, "extra", cbor.NewInt(1)) })),
		regCase("packed non-text key", webauthn.CheckAttestationStatement, nil, self, nil,
			editAttObj(func(_ *string, stmt *cbor.Value, _ *[]byte) {
				pairs, _ := stmt.Map()
				*stmt = cbor.NewMap(append(pairs, cbor.Pair{Key: cbor.NewInt(1), Value: cbor.NewInt(1)})...)
			})),
		regCase("x5c empty", webauthn.CheckAttestationStatement, nil, x5c, nil,
			editAttObj(func(_ *string, stmt *cbor.Value, _ *[]byte) { *stmt = stmtWith(*stmt, "x5c", cbor.NewArray()) })),
		regCase("x5c element not bytes", webauthn.CheckAttestationStatement, nil, x5c, nil,
			editAttObj(func(_ *string, stmt *cbor.Value, _ *[]byte) {
				*stmt = stmtWith(*stmt, "x5c", cbor.NewArray(cbor.NewText("cert")))
			})),
		regCase("self attestation bad signature", webauthn.CheckAttestationSignature, nil, self, nil,
			editAttObj(func(_ *string, stmt *cbor.Value, _ *[]byte) {
				s, _ := stmt.LookupText("sig")
				b, _ := s.Bytes()
				*stmt = stmtWith(*stmt, "sig", cbor.NewBytes(flipLast(b)))
			})),
		regCase("x5c bad signature", webauthn.CheckAttestationSignature, nil, x5c, nil,
			editAttObj(func(_ *string, stmt *cbor.Value, _ *[]byte) {
				s, _ := stmt.LookupText("sig")
				b, _ := s.Bytes()
				*stmt = stmtWith(*stmt, "sig", cbor.NewBytes(flipLast(b)))
			})),
		regCase("x5c signature over different authData", webauthn.CheckAttestationSignature, nil, x5c, nil,
			editAttObj(func(_ *string, _ *cbor.Value, ad *[]byte) { (*ad)[33]++ })),
		// --- attestation certificate ---
		regCase("x5c garbage DER", webauthn.CheckAttestationCert, nil, x5c, nil,
			editAttObj(func(_ *string, stmt *cbor.Value, _ *[]byte) {
				*stmt = stmtWith(*stmt, "x5c", cbor.NewArray(cbor.NewBytes([]byte{0x30, 0x01})))
			})),
		regCase("cert wrong OU", webauthn.CheckAttestationCert, nil,
			certHook(func(c *x509.Certificate) { c.Subject.OrganizationalUnit = []string{"Sales"} }), nil, nil),
		regCase("cert missing country", webauthn.CheckAttestationCert, nil,
			certHook(func(c *x509.Certificate) { c.Subject.Country = []string{"USA"} }), nil, nil),
		regCase("cert missing O", webauthn.CheckAttestationCert, nil,
			certHook(func(c *x509.Certificate) { c.Subject.Organization = nil }), nil, nil),
		regCase("cert empty CN", webauthn.CheckAttestationCert, nil,
			certHook(func(c *x509.Certificate) { c.Subject.CommonName = "" }), nil, nil),
		regCase("cert is a CA", webauthn.CheckAttestationCert, nil,
			certHook(func(c *x509.Certificate) { c.IsCA = true; c.KeyUsage |= x509.KeyUsageCertSign }), nil, nil),
		regCase("cert AAGUID extension critical", webauthn.CheckAttestationCert, nil,
			certHook(func(c *x509.Certificate) { c.ExtraExtensions[0].Critical = true }), nil, nil),
		regCase("cert AAGUID extension malformed", webauthn.CheckAttestationCert, nil,
			certHook(func(c *x509.Certificate) {
				c.ExtraExtensions = []pkix.Extension{{Id: oidAAGUID, Value: []byte{0x04, 0x02, 0x01, 0x02}}}
			}), nil, nil),
		regCase("cert AAGUID differs", webauthn.CheckAAGUID, nil,
			certHook(func(c *x509.Certificate) {
				v, _ := asn1.Marshal(bytes.Repeat([]byte{0xee}, 16))
				c.ExtraExtensions = []pkix.Extension{{Id: oidAAGUID, Value: v}}
			}), nil, nil),
		// --- trust and policy ---
		regCase("x5c not chaining to anchors", webauthn.CheckAttestationTrust,
			func(c *webauthn.Config) {
				other, _ := virtualauthn.New(none).AttestationRoot()
				pool := x509.NewCertPool()
				pool.AddCert(other)
				c.Attestation = &webauthn.AttestationPolicy{AllowBasic: true, TrustAnchors: pool}
			}, x5c, nil, nil),
		regCase("x5c with no anchors but trust required", webauthn.CheckAttestationTrust,
			func(c *webauthn.Config) {
				c.Attestation = &webauthn.AttestationPolicy{AllowBasic: true, RequireTrusted: true}
			}, x5c, nil, nil),
		regCase("none not allowed", webauthn.CheckAttestationPolicy,
			func(c *webauthn.Config) {
				c.Attestation = &webauthn.AttestationPolicy{AllowSelf: true, AllowBasic: true}
			}, none, nil, nil),
		regCase("self not allowed", webauthn.CheckAttestationPolicy,
			func(c *webauthn.Config) {
				c.Attestation = &webauthn.AttestationPolicy{AllowNone: true, AllowBasic: true}
			}, self, nil, nil),
		regCase("basic not allowed", webauthn.CheckAttestationPolicy,
			func(c *webauthn.Config) {
				c.Attestation = &webauthn.AttestationPolicy{AllowNone: true, AllowSelf: true}
			}, x5c, nil, nil),
		// --- uniqueness ---
		{"credential ID already registered", webauthn.CheckCredentialUnique, func(t *testing.T) error {
			h := newHarness(t, nil, none)
			o, s := h.beginReg()
			r := h.create(o)
			if _, err := h.finishReg(s, r); err != nil {
				t.Fatal(err)
			}
			o2, s2 := h.beginReg()
			r2 := h.create(o2)
			// Replay the first credential's attested data under a fresh challenge
			// is impossible (signature), so model a colliding ID via the store.
			h.store[string(r2.RawID)] = webauthn.Credential{ID: r2.RawID}
			_, err := h.rp.FinishRegistration(s2, r2, h.exists)
			return err
		}},
		{"uniqueness lookup fails", webauthn.CheckCredentialUnique, func(t *testing.T) error {
			h := newHarness(t, nil, none)
			o, s := h.beginReg()
			_, err := h.rp.FinishRegistration(s, h.create(o), func([]byte) (bool, error) { return false, errors.New("db down") })
			return err
		}},
		// --- authentication ---
		loginCase("credential outside allowCredentials", webauthn.CheckCredentialAllowed, nil, none,
			func(t *testing.T, h *harness, _ *webauthn.Credential, o *webauthn.RequestOptionsJSON, _ *webauthn.SessionData) *webauthn.AuthenticationResponseJSON {
				h.register()             // a second credential, newer than the allowed one
				o.AllowCredentials = nil // client ignores the allow list and picks the newest
				return h.get(o)
			}),
		loginCase("unknown credential", webauthn.CheckCredentialUnknown, nil, none,
			func(t *testing.T, h *harness, cred *webauthn.Credential, o *webauthn.RequestOptionsJSON, _ *webauthn.SessionData) *webauthn.AuthenticationResponseJSON {
				delete(h.store, string(cred.ID))
				return h.get(o)
			}),
		{"credential lookup error", webauthn.CheckCredentialUnknown, func(t *testing.T) error {
			h := newHarness(t, nil, none)
			cred := h.register()
			o, s := h.beginLogin(&cred)
			_, err := h.rp.FinishLogin(s, h.get(o), func([]byte) (*webauthn.Credential, error) { return nil, errors.New("db down") })
			return err
		}},
		loginCase("credential of another user", webauthn.CheckUserHandle, nil, none,
			func(t *testing.T, h *harness, _ *webauthn.Credential, o *webauthn.RequestOptionsJSON, s *webauthn.SessionData) *webauthn.AuthenticationResponseJSON {
				s.UserHandle = []byte("user-0002")
				return h.get(o)
			}),
		loginCase("userHandle of another user", webauthn.CheckUserHandle, nil, none,
			func(t *testing.T, h *harness, _ *webauthn.Credential, o *webauthn.RequestOptionsJSON, _ *webauthn.SessionData) *webauthn.AuthenticationResponseJSON {
				r := h.get(o)
				r.Response.UserHandle = []byte("user-0002")
				return r
			}),
		loginCase("discoverable login without userHandle", webauthn.CheckUserHandle, nil, none,
			func(t *testing.T, h *harness, _ *webauthn.Credential, o *webauthn.RequestOptionsJSON, s *webauthn.SessionData) *webauthn.AuthenticationResponseJSON {
				s.UserHandle, s.AllowCredentials = nil, nil
				r := h.get(o)
				r.Response.UserHandle = nil
				return r
			}),
		loginCase("create type in get", webauthn.CheckClientDataType, nil, none,
			func(t *testing.T, h *harness, _ *webauthn.Credential, o *webauthn.RequestOptionsJSON, _ *webauthn.SessionData) *webauthn.AuthenticationResponseJSON {
				h.client.ClientDataHook = func(cd *webauthn.CollectedClientData) { cd.Type = webauthn.ClientDataCreate }
				return h.get(o)
			}),
		loginCase("replayed assertion from an earlier ceremony", webauthn.CheckChallenge, nil, none,
			func(t *testing.T, h *harness, cred *webauthn.Credential, o *webauthn.RequestOptionsJSON, s *webauthn.SessionData) *webauthn.AuthenticationResponseJSON {
				captured := h.get(o)
				_, fresh := h.beginLogin(cred)
				*s = *fresh // the attacker replays the captured response into a new ceremony
				return captured
			}),
		loginCase("BE flag changed", webauthn.CheckBackupEligibility, nil, none,
			func(t *testing.T, h *harness, _ *webauthn.Credential, o *webauthn.RequestOptionsJSON, _ *webauthn.SessionData) *webauthn.AuthenticationResponseJSON {
				h.client.Authenticator = h.auth.Clone(virtualauthn.Options{BackupEligible: true})
				return h.get(o)
			}),
		loginCase("user not present at login", webauthn.CheckUserPresent, nil, none,
			func(t *testing.T, h *harness, _ *webauthn.Credential, o *webauthn.RequestOptionsJSON, _ *webauthn.SessionData) *webauthn.AuthenticationResponseJSON {
				h.client.Authenticator = h.auth.Clone(virtualauthn.Options{AuthDataHook: clearFlag(0x01)})
				return h.get(o)
			}),
		loginCase("tampered signature", webauthn.CheckSignature, nil, none,
			func(t *testing.T, h *harness, _ *webauthn.Credential, o *webauthn.RequestOptionsJSON, _ *webauthn.SessionData) *webauthn.AuthenticationResponseJSON {
				r := h.get(o)
				r.Response.Signature = flipLast(r.Response.Signature)
				return r
			}),
		loginCase("authData edited after signing", webauthn.CheckSignature, nil, none,
			func(t *testing.T, h *harness, _ *webauthn.Credential, o *webauthn.RequestOptionsJSON, _ *webauthn.SessionData) *webauthn.AuthenticationResponseJSON {
				r := h.get(o)
				r.Response.AuthenticatorData[36] += 10 // bump the counter
				return r
			}),
		loginCase("stored key corrupt", webauthn.CheckPublicKey, nil, none,
			func(t *testing.T, h *harness, cred *webauthn.Credential, o *webauthn.RequestOptionsJSON, _ *webauthn.SessionData) *webauthn.AuthenticationResponseJSON {
				c := h.store[string(cred.ID)]
				c.PublicKey = []byte{0xa0}
				h.store[string(cred.ID)] = c
				return h.get(o)
			}),
		loginCase("cloned authenticator counter regression", webauthn.CheckSignCount, nil, none,
			func(t *testing.T, h *harness, cred *webauthn.Credential, o *webauthn.RequestOptionsJSON, _ *webauthn.SessionData) *webauthn.AuthenticationResponseJSON {
				clone := h.auth.Clone(none)
				if _, err := h.login(cred); err != nil { // original advances to 2
					t.Fatal(err)
				}
				h.client.Authenticator = clone // clone is still at 1 -> sends 2 again
				return h.get(o)
			}),
	}
}

func TestNegativeChecks(t *testing.T) {
	for _, tc := range negativeCases() {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.run(t)
			if err == nil {
				t.Fatalf("accepted; want %s", tc.check)
			}
			if got := webauthn.CheckOf(err); got != tc.check {
				t.Fatalf("rejected by %q (%v); want %q", got, err, tc.check)
			}
			if !errors.Is(err, webauthn.ErrCheck(tc.check)) {
				t.Fatalf("errors.Is(err, ErrCheck(%s)) is false", tc.check)
			}
		})
	}
}

// TestEveryCheckHasANegativeTest enforces the project rule: each
// verification check is exercised by at least one rejecting test.
func TestEveryCheckHasANegativeTest(t *testing.T) {
	covered := map[webauthn.Check]int{}
	for _, tc := range negativeCases() {
		covered[tc.check]++
	}
	for _, c := range webauthn.AllChecks() {
		if covered[c] == 0 {
			t.Errorf("check %q has no negative test", c)
		}
	}
	if len(covered) != len(webauthn.AllChecks()) {
		t.Errorf("negative tests reference %d checks, AllChecks has %d", len(covered), len(webauthn.AllChecks()))
	}
}
