// Package cose parses and encodes COSE_Key public keys (RFC 9052 / RFC 9053,
// RFC 8230 for RSA) and verifies the signature formats WebAuthn uses.
//
// Supported algorithms: ES256, ES384, ES512 (ECDSA with DER signatures, as
// WebAuthn specifies), EdDSA over Ed25519 (alg -8, and the fully-specified
// Ed25519 identifier -19), and RS256 (RSASSA-PKCS1-v1_5 with SHA-256).
// Ed448 keys parse as ErrUnsupportedAlgorithm because the Go standard library
// has no Ed448 implementation.
package cose

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"

	"github.com/SlateGitOrg/passkeyd/cbor"
)

// Algorithm is a COSE algorithm identifier.
type Algorithm int64

// Algorithm identifiers from the IANA COSE Algorithms registry.
const (
	AlgES256   Algorithm = -7
	AlgEdDSA   Algorithm = -8
	AlgEd25519 Algorithm = -19
	AlgES384   Algorithm = -35
	AlgES512   Algorithm = -36
	AlgRS256   Algorithm = -257
)

// String returns the registry name of the algorithm.
func (a Algorithm) String() string {
	switch a {
	case AlgES256:
		return "ES256"
	case AlgEdDSA:
		return "EdDSA"
	case AlgEd25519:
		return "Ed25519"
	case AlgES384:
		return "ES384"
	case AlgES512:
		return "ES512"
	case AlgRS256:
		return "RS256"
	default:
		return fmt.Sprintf("alg(%d)", int64(a))
	}
}

// Supported reports whether a is implemented by this package.
func (a Algorithm) Supported() bool {
	switch a {
	case AlgES256, AlgEdDSA, AlgEd25519, AlgES384, AlgES512, AlgRS256:
		return true
	}
	return false
}

// KeyType is a COSE key type (kty).
type KeyType int64

// Key types.
const (
	KeyTypeOKP KeyType = 1
	KeyTypeEC2 KeyType = 2
	KeyTypeRSA KeyType = 3
)

// Curve is a COSE elliptic curve identifier.
type Curve int64

// Curves.
const (
	CurveP256    Curve = 1
	CurveP384    Curve = 2
	CurveP521    Curve = 3
	CurveEd25519 Curve = 6
	CurveEd448   Curve = 7
)

// COSE_Key map labels (RFC 9052 section 7.1, RFC 9053 section 7).
const (
	labelKty = 1
	labelAlg = 3
	labelCrv = -1 // also RSA "n"
	labelX   = -2 // also RSA "e"
	labelY   = -3
)

// Errors.
var (
	ErrMalformedKey         = errors.New("cose: malformed COSE_Key")
	ErrUnsupportedAlgorithm = errors.New("cose: unsupported algorithm or curve")
	ErrInvalidKey           = errors.New("cose: invalid public key")
	ErrBadSignature         = errors.New("cose: signature verification failed")
)

// RSA modulus bounds accepted by ParseKey.
const (
	MinRSABits = 2048
	MaxRSABits = 8192
)

// Key is a parsed COSE public key.
type Key struct {
	Alg   Algorithm
	Type  KeyType
	Curve Curve // zero for RSA
	// Public is *ecdsa.PublicKey, ed25519.PublicKey or *rsa.PublicKey.
	Public crypto.PublicKey
	// Raw is the exact encoded COSE_Key the key was parsed from.
	Raw []byte
}

// ParseKey decodes a complete encoded COSE_Key.
func ParseKey(data []byte) (*Key, error) {
	v, err := cbor.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedKey, err)
	}
	return KeyFromValue(v)
}

// KeyFromValue builds a Key from a decoded COSE_Key map. The map must carry
// kty and alg (WebAuthn requires alg) and the parameters for its type.
func KeyFromValue(v cbor.Value) (*Key, error) {
	if v.Kind() != cbor.KindMap {
		return nil, fmt.Errorf("%w: not a map", ErrMalformedKey)
	}
	kty, err := intParam(v, labelKty)
	if err != nil {
		return nil, err
	}
	algInt, err := intParam(v, labelAlg)
	if err != nil {
		return nil, err
	}
	k := &Key{Alg: Algorithm(algInt), Type: KeyType(kty), Raw: v.Raw()}
	switch k.Type {
	case KeyTypeEC2:
		err = k.parseEC2(v)
	case KeyTypeOKP:
		err = k.parseOKP(v)
	case KeyTypeRSA:
		err = k.parseRSA(v)
	default:
		return nil, fmt.Errorf("%w: key type %d", ErrUnsupportedAlgorithm, kty)
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

func intParam(v cbor.Value, label int64) (int64, error) {
	p, ok := v.LookupInt(label)
	if !ok {
		return 0, fmt.Errorf("%w: missing label %d", ErrMalformedKey, label)
	}
	i, ok := p.Int()
	if !ok {
		return 0, fmt.Errorf("%w: label %d is not an integer", ErrMalformedKey, label)
	}
	return i, nil
}

func bytesParam(v cbor.Value, label int64) ([]byte, error) {
	p, ok := v.LookupInt(label)
	if !ok {
		return nil, fmt.Errorf("%w: missing label %d", ErrMalformedKey, label)
	}
	b, ok := p.Bytes()
	if !ok {
		return nil, fmt.Errorf("%w: label %d is not a byte string", ErrMalformedKey, label)
	}
	return b, nil
}

func ecCurve(c Curve) (elliptic.Curve, Algorithm, bool) {
	switch c {
	case CurveP256:
		return elliptic.P256(), AlgES256, true
	case CurveP384:
		return elliptic.P384(), AlgES384, true
	case CurveP521:
		return elliptic.P521(), AlgES512, true
	}
	return nil, 0, false
}

func (k *Key) parseEC2(v cbor.Value) error {
	crv, err := intParam(v, labelCrv)
	if err != nil {
		return err
	}
	k.Curve = Curve(crv)
	curve, alg, ok := ecCurve(k.Curve)
	if !ok {
		return fmt.Errorf("%w: EC2 curve %d", ErrUnsupportedAlgorithm, crv)
	}
	if k.Alg != alg {
		return fmt.Errorf("%w: alg %v does not match curve %d", ErrUnsupportedAlgorithm, k.Alg, crv)
	}
	x, err := bytesParam(v, labelX)
	if err != nil {
		return err
	}
	y, err := bytesParam(v, labelY)
	if err != nil {
		return err
	}
	size := (curve.Params().BitSize + 7) / 8
	if len(x) != size || len(y) != size {
		return fmt.Errorf("%w: coordinate length %d/%d, want %d", ErrInvalidKey, len(x), len(y), size)
	}
	point := make([]byte, 0, 1+2*size)
	point = append(append(append(point, 4), x...), y...)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidKey, err)
	}
	k.Public = pub
	return nil
}

func (k *Key) parseOKP(v cbor.Value) error {
	crv, err := intParam(v, labelCrv)
	if err != nil {
		return err
	}
	k.Curve = Curve(crv)
	if k.Curve != CurveEd25519 {
		return fmt.Errorf("%w: OKP curve %d", ErrUnsupportedAlgorithm, crv)
	}
	if k.Alg != AlgEdDSA && k.Alg != AlgEd25519 {
		return fmt.Errorf("%w: alg %v with Ed25519 key", ErrUnsupportedAlgorithm, k.Alg)
	}
	x, err := bytesParam(v, labelX)
	if err != nil {
		return err
	}
	if len(x) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: Ed25519 key of %d bytes", ErrInvalidKey, len(x))
	}
	k.Public = ed25519.PublicKey(bytes.Clone(x))
	return nil
}

func (k *Key) parseRSA(v cbor.Value) error {
	if k.Alg != AlgRS256 {
		return fmt.Errorf("%w: alg %v with RSA key", ErrUnsupportedAlgorithm, k.Alg)
	}
	n, err := bytesParam(v, labelCrv)
	if err != nil {
		return err
	}
	e, err := bytesParam(v, labelX)
	if err != nil {
		return err
	}
	if len(n) == 0 || n[0] == 0 || len(e) == 0 || len(e) > 4 || e[0] == 0 {
		return fmt.Errorf("%w: RSA parameters not minimally encoded", ErrInvalidKey)
	}
	nInt := new(big.Int).SetBytes(n)
	if bits := nInt.BitLen(); bits < MinRSABits || bits > MaxRSABits {
		return fmt.Errorf("%w: RSA modulus of %d bits", ErrInvalidKey, bits)
	}
	eInt := new(big.Int).SetBytes(e).Int64()
	if eInt < 3 || eInt%2 == 0 {
		return fmt.Errorf("%w: RSA exponent %d", ErrInvalidKey, eInt)
	}
	k.Public = &rsa.PublicKey{N: nInt, E: int(eInt)}
	return nil
}

// Verify checks sig over signed with the key's algorithm. ECDSA signatures
// must be ASN.1 DER encoded, as WebAuthn requires.
func (k *Key) Verify(signed, sig []byte) error {
	return VerifySignature(k.Alg, k.Public, signed, sig)
}

// VerifySignature checks sig over signed using pub and alg. It is also used
// for attestation certificates, whose public key arrives via X.509.
func VerifySignature(alg Algorithm, pub crypto.PublicKey, signed, sig []byte) error {
	switch alg {
	case AlgES256, AlgES384, AlgES512:
		ec, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: %v needs an ECDSA key", ErrInvalidKey, alg)
		}
		if want := curveForAlg(alg); ec.Curve != want {
			return fmt.Errorf("%w: %v needs curve %s", ErrInvalidKey, alg, want.Params().Name)
		}
		if !ecdsa.VerifyASN1(ec, digest(alg, signed), sig) {
			return ErrBadSignature
		}
		return nil
	case AlgEdDSA, AlgEd25519:
		ed, ok := pub.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("%w: %v needs an Ed25519 key", ErrInvalidKey, alg)
		}
		if len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed, signed, sig) {
			return ErrBadSignature
		}
		return nil
	case AlgRS256:
		r, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%w: %v needs an RSA key", ErrInvalidKey, alg)
		}
		if err := rsa.VerifyPKCS1v15(r, crypto.SHA256, digest(alg, signed), sig); err != nil {
			return ErrBadSignature
		}
		return nil
	default:
		return fmt.Errorf("%w: %v", ErrUnsupportedAlgorithm, alg)
	}
}

func curveForAlg(alg Algorithm) elliptic.Curve {
	switch alg {
	case AlgES384:
		return elliptic.P384()
	case AlgES512:
		return elliptic.P521()
	default:
		return elliptic.P256()
	}
}

func digest(alg Algorithm, msg []byte) []byte {
	switch alg {
	case AlgES384:
		h := sha512.Sum384(msg)
		return h[:]
	case AlgES512:
		h := sha512.Sum512(msg)
		return h[:]
	default:
		h := sha256.Sum256(msg)
		return h[:]
	}
}

// EncodeKey encodes pub as a CTAP2-canonical COSE_Key with the given alg.
func EncodeKey(pub crypto.PublicKey, alg Algorithm) ([]byte, error) {
	var pairs []cbor.Pair
	add := func(label int64, v cbor.Value) { pairs = append(pairs, cbor.Pair{Key: cbor.NewInt(label), Value: v}) }
	switch p := pub.(type) {
	case *ecdsa.PublicKey:
		var crv Curve
		switch p.Curve {
		case elliptic.P256():
			crv = CurveP256
		case elliptic.P384():
			crv = CurveP384
		case elliptic.P521():
			crv = CurveP521
		default:
			return nil, fmt.Errorf("%w: curve %s", ErrUnsupportedAlgorithm, p.Curve.Params().Name)
		}
		if _, want, _ := ecCurve(crv); want != alg {
			return nil, fmt.Errorf("%w: alg %v does not match curve", ErrUnsupportedAlgorithm, alg)
		}
		raw, err := p.Bytes()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidKey, err)
		}
		size := (len(raw) - 1) / 2
		add(labelKty, cbor.NewInt(int64(KeyTypeEC2)))
		add(labelAlg, cbor.NewInt(int64(alg)))
		add(labelCrv, cbor.NewInt(int64(crv)))
		add(labelX, cbor.NewBytes(raw[1:1+size]))
		add(labelY, cbor.NewBytes(raw[1+size:]))
	case ed25519.PublicKey:
		if alg != AlgEdDSA && alg != AlgEd25519 {
			return nil, fmt.Errorf("%w: alg %v with Ed25519 key", ErrUnsupportedAlgorithm, alg)
		}
		add(labelKty, cbor.NewInt(int64(KeyTypeOKP)))
		add(labelAlg, cbor.NewInt(int64(alg)))
		add(labelCrv, cbor.NewInt(int64(CurveEd25519)))
		add(labelX, cbor.NewBytes(p))
	case *rsa.PublicKey:
		if alg != AlgRS256 {
			return nil, fmt.Errorf("%w: alg %v with RSA key", ErrUnsupportedAlgorithm, alg)
		}
		add(labelKty, cbor.NewInt(int64(KeyTypeRSA)))
		add(labelAlg, cbor.NewInt(int64(alg)))
		add(labelCrv, cbor.NewBytes(p.N.Bytes()))
		add(labelX, cbor.NewBytes(big.NewInt(int64(p.E)).Bytes()))
	default:
		return nil, fmt.Errorf("%w: key type %T", ErrUnsupportedAlgorithm, pub)
	}
	return cbor.EncodeCanonical(cbor.NewMap(pairs...)), nil
}
