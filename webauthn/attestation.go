package webauthn

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/archit2501/passkeyd/cbor"
	"github.com/archit2501/passkeyd/cose"
)

// AttestationType classifies the attestation a credential was registered with.
type AttestationType string

// Attestation types (WebAuthn section 6.5.4). Packed attestation with a
// certificate chain is reported as "basic"; distinguishing Basic from AttCA
// needs authenticator metadata this library does not consume.
const (
	AttestationNone  AttestationType = "none"
	AttestationSelf  AttestationType = "self"
	AttestationBasic AttestationType = "basic"
)

// AttestationResult is the outcome of attestation statement verification.
type AttestationResult struct {
	Format string
	Type   AttestationType
	// TrustPath is the x5c chain (leaf first) for basic attestation.
	TrustPath []*x509.Certificate
	// Trusted is true when TrustPath verified against configured anchors.
	Trusted bool
}

// attestationObject is the decoded top-level attestation object map.
type attestationObject struct {
	Format   string
	AuthData []byte
	Stmt     cbor.Value
}

func parseAttestationObject(raw []byte) (*attestationObject, *VerifyError) {
	if len(raw) == 0 {
		return nil, fail(CheckAttestationObject, "empty attestationObject")
	}
	v, err := cbor.Decode(raw)
	if err != nil {
		return nil, failWrap(CheckAttestationObject, err, "")
	}
	if v.Kind() != cbor.KindMap || v.Len() != 3 {
		return nil, fail(CheckAttestationObject, "must be a map of fmt, attStmt and authData")
	}
	fmtV, ok1 := v.LookupText("fmt")
	stmt, ok2 := v.LookupText("attStmt")
	adV, ok3 := v.LookupText("authData")
	if !ok1 || !ok2 || !ok3 {
		return nil, fail(CheckAttestationObject, "missing fmt, attStmt or authData")
	}
	format, ok := fmtV.Text()
	if !ok {
		return nil, fail(CheckAttestationObject, "fmt is not a text string")
	}
	ad, ok := adV.Bytes()
	if !ok {
		return nil, fail(CheckAttestationObject, "authData is not a byte string")
	}
	if stmt.Kind() != cbor.KindMap {
		return nil, fail(CheckAttestationObject, "attStmt is not a map")
	}
	return &attestationObject{Format: format, AuthData: ad, Stmt: stmt}, nil
}

// verifyAttestation dispatches on the attestation statement format and then
// applies the configured attestation policy.
func (rp *RelyingParty) verifyAttestation(obj *attestationObject, ad *AuthenticatorData, credKey *cose.Key, clientDataHash []byte) (*AttestationResult, *VerifyError) {
	var (
		res *AttestationResult
		ve  *VerifyError
	)
	switch obj.Format {
	case "none":
		if obj.Stmt.Len() != 0 {
			return nil, fail(CheckAttestationStatement, "none attestation must have an empty attStmt")
		}
		res = &AttestationResult{Format: "none", Type: AttestationNone}
	case "packed":
		res, ve = rp.verifyPacked(obj, ad, credKey, clientDataHash)
		if ve != nil {
			return nil, ve
		}
	default:
		return nil, fail(CheckAttestationFormat, "format %q", obj.Format)
	}
	pol := rp.cfg.Attestation
	switch res.Type {
	case AttestationNone:
		if !pol.AllowNone {
			return nil, fail(CheckAttestationPolicy, "attestation type none is not accepted")
		}
	case AttestationSelf:
		if !pol.AllowSelf {
			return nil, fail(CheckAttestationPolicy, "self attestation is not accepted")
		}
	case AttestationBasic:
		if !pol.AllowBasic {
			return nil, fail(CheckAttestationPolicy, "basic attestation is not accepted")
		}
		if pol.RequireTrusted && !res.Trusted {
			return nil, fail(CheckAttestationTrust, "no trust anchors configured for attestation certificates")
		}
	}
	return res, nil
}

// packedStatement is the parsed packed attStmt (WebAuthn section 8.2).
type packedStatement struct {
	Alg cose.Algorithm
	Sig []byte
	X5C [][]byte
}

func parsePackedStatement(stmt cbor.Value) (*packedStatement, *VerifyError) {
	pairs, _ := stmt.Map()
	ps := &packedStatement{}
	var haveAlg, haveSig bool
	for _, p := range pairs {
		key, ok := p.Key.Text()
		if !ok {
			return nil, fail(CheckAttestationStatement, "non-text key in packed attStmt")
		}
		switch key {
		case "alg":
			i, ok := p.Value.Int()
			if !ok {
				return nil, fail(CheckAttestationStatement, "alg is not an integer")
			}
			ps.Alg, haveAlg = cose.Algorithm(i), true
		case "sig":
			b, ok := p.Value.Bytes()
			if !ok {
				return nil, fail(CheckAttestationStatement, "sig is not a byte string")
			}
			ps.Sig, haveSig = b, true
		case "x5c":
			items, ok := p.Value.Array()
			if !ok || len(items) == 0 {
				return nil, fail(CheckAttestationStatement, "x5c must be a non-empty array")
			}
			for _, it := range items {
				b, ok := it.Bytes()
				if !ok {
					return nil, fail(CheckAttestationStatement, "x5c element is not a byte string")
				}
				ps.X5C = append(ps.X5C, b)
			}
		case "ecdaaKeyId":
			return nil, fail(CheckAttestationFormat, "ECDAA attestation was removed from WebAuthn")
		default:
			return nil, fail(CheckAttestationStatement, "unexpected attStmt member %q", key)
		}
	}
	if !haveAlg || !haveSig {
		return nil, fail(CheckAttestationStatement, "packed attStmt requires alg and sig")
	}
	return ps, nil
}

func (rp *RelyingParty) verifyPacked(obj *attestationObject, ad *AuthenticatorData, credKey *cose.Key, clientDataHash []byte) (*AttestationResult, *VerifyError) {
	ps, ve := parsePackedStatement(obj.Stmt)
	if ve != nil {
		return nil, ve
	}
	signed := make([]byte, 0, len(obj.AuthData)+len(clientDataHash))
	signed = append(append(signed, obj.AuthData...), clientDataHash...)

	if len(ps.X5C) == 0 {
		// Self attestation: signed by the credential key itself.
		if ps.Alg != credKey.Alg {
			return nil, fail(CheckAlgorithm, "self attestation alg %v differs from credential alg %v", ps.Alg, credKey.Alg)
		}
		if err := credKey.Verify(signed, ps.Sig); err != nil {
			return nil, failWrap(CheckAttestationSignature, err, "self attestation")
		}
		return &AttestationResult{Format: "packed", Type: AttestationSelf}, nil
	}

	certs := make([]*x509.Certificate, 0, len(ps.X5C))
	for i, der := range ps.X5C {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, failWrap(CheckAttestationCert, err, "x5c[%d]", i)
		}
		certs = append(certs, c)
	}
	leaf := certs[0]
	if !ps.Alg.Supported() {
		return nil, fail(CheckAlgorithm, "attestation alg %v is not supported", ps.Alg)
	}
	if err := cose.VerifySignature(ps.Alg, leaf.PublicKey, signed, ps.Sig); err != nil {
		return nil, failWrap(CheckAttestationSignature, err, "x5c attestation")
	}
	if ve := checkPackedCert(leaf, ad.AttestedCredential.AAGUID); ve != nil {
		return nil, ve
	}
	res := &AttestationResult{Format: "packed", Type: AttestationBasic, TrustPath: certs}
	if anchors := rp.cfg.Attestation.TrustAnchors; anchors != nil {
		inter := x509.NewCertPool()
		for _, c := range certs[1:] {
			inter.AddCert(c)
		}
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:         anchors,
			Intermediates: inter,
			CurrentTime:   rp.cfg.Now(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			return nil, failWrap(CheckAttestationTrust, err, "")
		}
		res.Trusted = true
	}
	return res, nil
}

// oidFIDOGenCeAAGUID is id-fido-gen-ce-aaguid.
var oidFIDOGenCeAAGUID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

var errSubject = errors.New("attestation certificate subject")

// checkPackedCert enforces the packed attestation certificate requirements
// of WebAuthn section 8.2.1.
func checkPackedCert(c *x509.Certificate, aaguid [16]byte) *VerifyError {
	if c.Version != 3 {
		return fail(CheckAttestationCert, "version %d, want 3", c.Version)
	}
	s := c.Subject
	switch {
	case len(s.Country) != 1 || len(s.Country[0]) != 2:
		return failWrap(CheckAttestationCert, errSubject, "C must be a two-letter country code")
	case len(s.Organization) != 1 || s.Organization[0] == "":
		return failWrap(CheckAttestationCert, errSubject, "O must name the vendor")
	case len(s.OrganizationalUnit) != 1 || s.OrganizationalUnit[0] != "Authenticator Attestation":
		return failWrap(CheckAttestationCert, errSubject, "OU must be \"Authenticator Attestation\"")
	case s.CommonName == "":
		return failWrap(CheckAttestationCert, errSubject, "CN must not be empty")
	}
	if c.BasicConstraintsValid && c.IsCA {
		return fail(CheckAttestationCert, "attestation certificate must not be a CA")
	}
	for _, ext := range c.Extensions {
		if !ext.Id.Equal(oidFIDOGenCeAAGUID) {
			continue
		}
		if ext.Critical {
			return fail(CheckAttestationCert, "AAGUID extension must not be critical")
		}
		var certAAGUID []byte
		if rest, err := asn1.Unmarshal(ext.Value, &certAAGUID); err != nil || len(rest) != 0 || len(certAAGUID) != 16 {
			return fail(CheckAttestationCert, "malformed AAGUID extension")
		}
		if !bytes.Equal(certAAGUID, aaguid[:]) {
			return fail(CheckAAGUID, "certificate AAGUID %x differs from authenticator data %x", certAAGUID, aaguid)
		}
	}
	return nil
}

func fmtAAGUID(a [16]byte) string {
	return fmt.Sprintf("%x-%x-%x-%x-%x", a[0:4], a[4:6], a[6:8], a[8:10], a[10:16])
}
