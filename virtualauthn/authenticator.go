// Package virtualauthn is a software WebAuthn authenticator and client for
// tests, demos and lab work. It creates real key pairs (ES256, ES384, ES512,
// EdDSA/Ed25519, RS256), produces CTAP2-canonical attestation objects in the
// none, packed-self and packed-x5c formats, and signs assertions with a
// per-credential signature counter.
//
// It is deliberately permissive where a real client would refuse (it does
// not check that the RP ID matches the origin, and exposes hooks to tamper
// with client data, authenticator data and attestation certificates) so that
// tests can produce every kind of hostile response. Never use it to protect
// a real account: private keys live in process memory.
package virtualauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"slices"
	"sync"
	"time"

	"github.com/archit2501/passkeyd/cbor"
	"github.com/archit2501/passkeyd/cose"
)

// AttestationMode selects the attestation statement format.
type AttestationMode int

// Attestation modes.
const (
	AttestNone AttestationMode = iota
	AttestPackedSelf
	AttestPackedX5C
)

// String names the mode.
func (m AttestationMode) String() string {
	switch m {
	case AttestPackedSelf:
		return "packed-self"
	case AttestPackedX5C:
		return "packed-x5c"
	default:
		return "none"
	}
}

// Options configures an Authenticator. The zero value is a valid
// user-verifying, device-bound authenticator with "none" attestation.
type Options struct {
	AAGUID      [16]byte
	Attestation AttestationMode
	// NoUserVerification clears the UV flag in every response.
	NoUserVerification bool
	// BackupEligible and BackupState set the BE and BS flags.
	BackupEligible bool
	BackupState    bool
	// Algorithms restricts the authenticator to these algorithms. Default:
	// ES256, EdDSA, ES384, ES512, RS256.
	Algorithms []cose.Algorithm
	// ZeroCounter keeps the signature counter at 0, as many synced passkey
	// providers do.
	ZeroCounter bool
	// Rand is the randomness source. Default crypto/rand.
	Rand io.Reader
	// AuthDataHook, if set, may rewrite authenticator data before it is
	// signed (for tests that need a validly signed but non-conforming
	// response).
	AuthDataHook func(authData []byte) []byte
	// CertHook, if set, may modify the attestation certificate template
	// before it is issued (packed-x5c only).
	CertHook func(tmpl *x509.Certificate)
}

// Authenticator is a software authenticator holding discoverable credentials.
// It is safe for concurrent use.
type Authenticator struct {
	opts Options

	mu    sync.Mutex
	creds []*credential

	caCert   *x509.Certificate
	attCert  *x509.Certificate
	attKey   *ecdsa.PrivateKey
	initOnce sync.Once
	initErr  error
}

type credential struct {
	id         []byte
	rpID       string
	userHandle []byte
	alg        cose.Algorithm
	signer     crypto.Signer
	counter    uint32
}

// New returns an authenticator configured by opts.
func New(opts Options) *Authenticator {
	if opts.Rand == nil {
		opts.Rand = rand.Reader
	}
	return &Authenticator{opts: opts}
}

// ErrNoCredential is returned by GetAssertion when no credential matches.
var ErrNoCredential = errors.New("virtualauthn: no matching credential")

// ErrUnsupportedAlgorithm is returned when none of the requested algorithms
// is implemented.
var ErrUnsupportedAlgorithm = errors.New("virtualauthn: no supported algorithm requested")

// supported lists the algorithms this authenticator can generate keys for.
var supported = []cose.Algorithm{cose.AlgES256, cose.AlgEdDSA, cose.AlgES384, cose.AlgES512, cose.AlgRS256}

// AttestationRoot returns the self-signed root certificate that issues the
// authenticator's attestation certificate (packed-x5c mode). Relying
// parties use it as a trust anchor.
func (a *Authenticator) AttestationRoot() (*x509.Certificate, error) {
	if err := a.initAttestation(); err != nil {
		return nil, err
	}
	return a.caCert, nil
}

func (a *Authenticator) initAttestation() error {
	a.initOnce.Do(func() { a.initErr = a.buildAttestationPKI() })
	return a.initErr
}

// oidFIDOGenCeAAGUID is the id-fido-gen-ce-aaguid certificate extension.
var oidFIDOGenCeAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

func (a *Authenticator) buildAttestationPKI() error {
	r := a.opts.Rand
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), r)
	if err != nil {
		return err
	}
	notBefore := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2124, 1, 1, 0, 0, 0, 0, time.UTC)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "passkeyd virtual attestation root", Organization: []string{"passkeyd lab"}, Country: []string{"AA"}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(r, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	if a.caCert, err = x509.ParseCertificate(caDER); err != nil {
		return err
	}
	if a.attKey, err = ecdsa.GenerateKey(elliptic.P256(), r); err != nil {
		return err
	}
	aaguidExt, err := asn1.Marshal(a.opts.AAGUID[:])
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country:            []string{"AA"},
			Organization:       []string{"passkeyd lab"},
			OrganizationalUnit: []string{"Authenticator Attestation"},
			CommonName:         "passkeyd virtual authenticator",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtraExtensions:       []pkix.Extension{{Id: oidFIDOGenCeAAGUID, Value: aaguidExt}},
	}
	if a.opts.CertHook != nil {
		a.opts.CertHook(tmpl)
	}
	der, err := x509.CreateCertificate(r, tmpl, a.caCert, &a.attKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	a.attCert, err = x509.ParseCertificate(der)
	return err
}

func (a *Authenticator) generate(alg cose.Algorithm) (crypto.Signer, error) {
	r := a.opts.Rand
	switch alg {
	case cose.AlgES256:
		return ecdsa.GenerateKey(elliptic.P256(), r)
	case cose.AlgES384:
		return ecdsa.GenerateKey(elliptic.P384(), r)
	case cose.AlgES512:
		return ecdsa.GenerateKey(elliptic.P521(), r)
	case cose.AlgEdDSA:
		_, priv, err := ed25519.GenerateKey(r)
		return priv, err
	case cose.AlgRS256:
		return rsa.GenerateKey(r, 2048)
	}
	return nil, ErrUnsupportedAlgorithm
}

// sign produces a WebAuthn-format signature (DER for ECDSA).
func sign(r io.Reader, s crypto.Signer, alg cose.Algorithm, msg []byte) ([]byte, error) {
	switch alg {
	case cose.AlgEdDSA:
		return s.Sign(r, msg, crypto.Hash(0))
	case cose.AlgES384:
		d := sha512.Sum384(msg)
		return s.Sign(r, d[:], crypto.SHA384)
	case cose.AlgES512:
		d := sha512.Sum512(msg)
		return s.Sign(r, d[:], crypto.SHA512)
	default: // ES256, RS256
		d := sha256.Sum256(msg)
		return s.Sign(r, d[:], crypto.SHA256)
	}
}

func (a *Authenticator) flags(at bool) byte {
	f := byte(0x01) // UP
	if !a.opts.NoUserVerification {
		f |= 0x04
	}
	if a.opts.BackupEligible {
		f |= 0x08
	}
	if a.opts.BackupState {
		f |= 0x10
	}
	if at {
		f |= 0x40
	}
	return f
}

// Credential is the result of MakeCredential.
type Credential struct {
	ID                []byte
	AttestationObject []byte
	Algorithm         cose.Algorithm
}

// MakeCredential creates a new credential scoped to rpID for userHandle,
// using the first algorithm in algs that it supports, and returns the
// attestation object over clientDataHash.
func (a *Authenticator) MakeCredential(rpID string, userHandle, clientDataHash []byte, algs []cose.Algorithm) (*Credential, error) {
	own := a.opts.Algorithms
	if len(own) == 0 {
		own = supported
	}
	idx := slices.IndexFunc(algs, func(x cose.Algorithm) bool { return slices.Contains(own, x) && slices.Contains(supported, x) })
	if idx < 0 {
		return nil, ErrUnsupportedAlgorithm
	}
	alg := algs[idx]
	signer, err := a.generate(alg)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 32)
	if _, err := io.ReadFull(a.opts.Rand, id); err != nil {
		return nil, err
	}
	coseKey, err := cose.EncodeKey(signer.Public(), alg)
	if err != nil {
		return nil, err
	}
	cred := &credential{id: id, rpID: rpID, userHandle: bytes.Clone(userHandle), alg: alg, signer: signer}
	if !a.opts.ZeroCounter {
		cred.counter = 1
	}

	rpHash := sha256.Sum256([]byte(rpID))
	ad := make([]byte, 0, 37+18+len(id)+len(coseKey))
	ad = append(ad, rpHash[:]...)
	ad = append(ad, a.flags(true))
	ad = binary.BigEndian.AppendUint32(ad, cred.counter)
	ad = append(ad, a.opts.AAGUID[:]...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(id))) //nolint:gosec // id is 32 bytes
	ad = append(ad, id...)
	ad = append(ad, coseKey...)
	if a.opts.AuthDataHook != nil {
		ad = a.opts.AuthDataHook(ad)
	}

	stmt, format, err := a.attest(cred, ad, clientDataHash)
	if err != nil {
		return nil, err
	}
	obj := cbor.EncodeCanonical(cbor.NewMap(
		cbor.Pair{Key: cbor.NewText("fmt"), Value: cbor.NewText(format)},
		cbor.Pair{Key: cbor.NewText("attStmt"), Value: stmt},
		cbor.Pair{Key: cbor.NewText("authData"), Value: cbor.NewBytes(ad)},
	))
	a.mu.Lock()
	a.creds = append(a.creds, cred)
	a.mu.Unlock()
	return &Credential{ID: bytes.Clone(id), AttestationObject: obj, Algorithm: alg}, nil
}

func (a *Authenticator) attest(cred *credential, authData, clientDataHash []byte) (cbor.Value, string, error) {
	msg := append(bytes.Clone(authData), clientDataHash...)
	switch a.opts.Attestation {
	case AttestPackedSelf:
		sig, err := sign(a.opts.Rand, cred.signer, cred.alg, msg)
		if err != nil {
			return cbor.Value{}, "", err
		}
		return cbor.NewMap(
			cbor.Pair{Key: cbor.NewText("alg"), Value: cbor.NewInt(int64(cred.alg))},
			cbor.Pair{Key: cbor.NewText("sig"), Value: cbor.NewBytes(sig)},
		), "packed", nil
	case AttestPackedX5C:
		if err := a.initAttestation(); err != nil {
			return cbor.Value{}, "", err
		}
		sig, err := sign(a.opts.Rand, a.attKey, cose.AlgES256, msg)
		if err != nil {
			return cbor.Value{}, "", err
		}
		return cbor.NewMap(
			cbor.Pair{Key: cbor.NewText("alg"), Value: cbor.NewInt(int64(cose.AlgES256))},
			cbor.Pair{Key: cbor.NewText("sig"), Value: cbor.NewBytes(sig)},
			cbor.Pair{Key: cbor.NewText("x5c"), Value: cbor.NewArray(cbor.NewBytes(a.attCert.Raw))},
		), "packed", nil
	default:
		return cbor.NewMap(), "none", nil
	}
}

// Assertion is the result of GetAssertion.
type Assertion struct {
	CredentialID      []byte
	AuthenticatorData []byte
	Signature         []byte
	UserHandle        []byte
}

// GetAssertion signs clientDataHash with a credential for rpID. If allow is
// non-empty only those credential IDs are eligible; otherwise the most
// recently created discoverable credential for rpID is used.
func (a *Authenticator) GetAssertion(rpID string, clientDataHash []byte, allow [][]byte) (*Assertion, error) {
	a.mu.Lock()
	var cred *credential
	for i := len(a.creds) - 1; i >= 0; i-- {
		c := a.creds[i]
		if c.rpID != rpID {
			continue
		}
		if len(allow) > 0 && !slices.ContainsFunc(allow, func(id []byte) bool { return bytes.Equal(id, c.id) }) {
			continue
		}
		cred = c
		break
	}
	if cred == nil {
		a.mu.Unlock()
		return nil, ErrNoCredential
	}
	if !a.opts.ZeroCounter {
		cred.counter++
	}
	counter := cred.counter
	a.mu.Unlock()

	rpHash := sha256.Sum256([]byte(rpID))
	ad := make([]byte, 0, 37)
	ad = append(ad, rpHash[:]...)
	ad = append(ad, a.flags(false))
	ad = binary.BigEndian.AppendUint32(ad, counter)
	if a.opts.AuthDataHook != nil {
		ad = a.opts.AuthDataHook(ad)
	}
	sig, err := sign(a.opts.Rand, cred.signer, cred.alg, append(bytes.Clone(ad), clientDataHash...))
	if err != nil {
		return nil, err
	}
	return &Assertion{CredentialID: bytes.Clone(cred.id), AuthenticatorData: ad, Signature: sig, UserHandle: bytes.Clone(cred.userHandle)}, nil
}

// Clone returns a new authenticator holding copies of every credential,
// including private keys and counters, with the given options. It models a
// cloned (extracted) authenticator for clone-detection tests and demos.
func (a *Authenticator) Clone(opts Options) *Authenticator {
	b := New(opts)
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range a.creds {
		cp := *c
		b.creds = append(b.creds, &cp)
	}
	return b
}

// SetCounter overwrites the signature counter of credential id (lab use:
// simulates authenticator state rollback).
func (a *Authenticator) SetCounter(id []byte, counter uint32) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, c := range a.creds {
		if bytes.Equal(c.id, id) {
			c.counter = counter
			return nil
		}
	}
	return fmt.Errorf("%w: %x", ErrNoCredential, id)
}
