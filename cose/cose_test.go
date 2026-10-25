package cose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"testing"

	"github.com/SlateGitOrg/passkeyd/cbor"
)

func ecKey(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestRoundTripAndVerify(t *testing.T) {
	msg := []byte("authenticatorData||clientDataHash")
	p256, p384, p521 := ecKey(t, elliptic.P256()), ecKey(t, elliptic.P384()), ecKey(t, elliptic.P521())
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(priv crypto.Signer, h crypto.Hash, m []byte) []byte {
		var d []byte
		switch h {
		case crypto.SHA256:
			s := sha256.Sum256(m)
			d = s[:]
		case crypto.SHA384:
			s := sha512.Sum384(m)
			d = s[:]
		case crypto.SHA512:
			s := sha512.Sum512(m)
			d = s[:]
		default:
			d = m
		}
		sig, err := priv.Sign(rand.Reader, d, h)
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	cases := []struct {
		alg  Algorithm
		pub  crypto.PublicKey
		sig  []byte
		kty  KeyType
		name string
	}{
		{AlgES256, &p256.PublicKey, sign(p256, crypto.SHA256, msg), KeyTypeEC2, "ES256"},
		{AlgES384, &p384.PublicKey, sign(p384, crypto.SHA384, msg), KeyTypeEC2, "ES384"},
		{AlgES512, &p521.PublicKey, sign(p521, crypto.SHA512, msg), KeyTypeEC2, "ES512"},
		{AlgEdDSA, edPub, sign(edPriv, crypto.Hash(0), msg), KeyTypeOKP, "EdDSA"},
		{AlgEd25519, edPub, sign(edPriv, crypto.Hash(0), msg), KeyTypeOKP, "Ed25519"},
		{AlgRS256, &rsaKey.PublicKey, sign(rsaKey, crypto.SHA256, msg), KeyTypeRSA, "RS256"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enc, err := EncodeKey(tc.pub, tc.alg)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := cbor.DecodeWith(enc, cbor.Options{Canonical: true}); err != nil {
				t.Fatalf("EncodeKey output is not canonical: %v", err)
			}
			k, err := ParseKey(enc)
			if err != nil {
				t.Fatal(err)
			}
			if k.Alg != tc.alg || k.Type != tc.kty || string(k.Raw) != string(enc) || !tc.alg.Supported() || tc.alg.String() != tc.name {
				t.Fatalf("parsed %+v", k)
			}
			if err := k.Verify(msg, tc.sig); err != nil {
				t.Fatalf("verify: %v", err)
			}
			if err := k.Verify(append([]byte{0}, msg...), tc.sig); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("tampered message: %v", err)
			}
		})
	}
}

func enc(pairs ...cbor.Pair) []byte { return cbor.Encode(cbor.NewMap(pairs...)) }

func p(label int64, v cbor.Value) cbor.Pair { return cbor.Pair{Key: cbor.NewInt(label), Value: v} }

func TestParseKeyErrors(t *testing.T) {
	k := ecKey(t, elliptic.P256())
	raw, _ := k.PublicKey.Bytes()
	x, y := cbor.NewBytes(raw[1:33]), cbor.NewBytes(raw[33:])
	badY := make([]byte, 32)
	copy(badY, raw[33:])
	badY[31] ^= 1
	small, _ := rsa.GenerateKey(rand.Reader, 1024)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	n2048 := make([]byte, 256)
	n2048[0] = 0xc1
	n2048[255] = 1
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"not cbor", []byte{0xff}, ErrMalformedKey},
		{"not a map", cbor.Encode(cbor.NewArray()), ErrMalformedKey},
		{"missing kty", enc(p(3, cbor.NewInt(-7))), ErrMalformedKey},
		{"missing alg", enc(p(1, cbor.NewInt(2))), ErrMalformedKey},
		{"alg not int", enc(p(1, cbor.NewInt(2)), p(3, cbor.NewText("ES256"))), ErrMalformedKey},
		{"unknown kty", enc(p(1, cbor.NewInt(4)), p(3, cbor.NewInt(-7))), ErrUnsupportedAlgorithm},
		{"ec missing crv", enc(p(1, cbor.NewInt(2)), p(3, cbor.NewInt(-7))), ErrMalformedKey},
		{"ec unknown crv", enc(p(1, cbor.NewInt(2)), p(3, cbor.NewInt(-7)), p(-1, cbor.NewInt(8))), ErrUnsupportedAlgorithm},
		{"ec alg/curve mismatch", enc(p(1, cbor.NewInt(2)), p(3, cbor.NewInt(-35)), p(-1, cbor.NewInt(1)), p(-2, x), p(-3, y)), ErrUnsupportedAlgorithm},
		{"ec missing x", enc(p(1, cbor.NewInt(2)), p(3, cbor.NewInt(-7)), p(-1, cbor.NewInt(1)), p(-3, y)), ErrMalformedKey},
		{"ec missing y", enc(p(1, cbor.NewInt(2)), p(3, cbor.NewInt(-7)), p(-1, cbor.NewInt(1)), p(-2, x)), ErrMalformedKey},
		{"ec x not bytes", enc(p(1, cbor.NewInt(2)), p(3, cbor.NewInt(-7)), p(-1, cbor.NewInt(1)), p(-2, cbor.NewInt(1)), p(-3, y)), ErrMalformedKey},
		{"ec short x", enc(p(1, cbor.NewInt(2)), p(3, cbor.NewInt(-7)), p(-1, cbor.NewInt(1)), p(-2, cbor.NewBytes(raw[1:32])), p(-3, y)), ErrInvalidKey},
		{"ec point off curve", enc(p(1, cbor.NewInt(2)), p(3, cbor.NewInt(-7)), p(-1, cbor.NewInt(1)), p(-2, x), p(-3, cbor.NewBytes(badY))), ErrInvalidKey},
		{"okp ed448", enc(p(1, cbor.NewInt(1)), p(3, cbor.NewInt(-8)), p(-1, cbor.NewInt(7)), p(-2, cbor.NewBytes(make([]byte, 57)))), ErrUnsupportedAlgorithm},
		{"okp missing crv", enc(p(1, cbor.NewInt(1)), p(3, cbor.NewInt(-8))), ErrMalformedKey},
		{"okp wrong alg", enc(p(1, cbor.NewInt(1)), p(3, cbor.NewInt(-7)), p(-1, cbor.NewInt(6)), p(-2, cbor.NewBytes(edPub))), ErrUnsupportedAlgorithm},
		{"okp short key", enc(p(1, cbor.NewInt(1)), p(3, cbor.NewInt(-8)), p(-1, cbor.NewInt(6)), p(-2, cbor.NewBytes(edPub[:31]))), ErrInvalidKey},
		{"okp missing x", enc(p(1, cbor.NewInt(1)), p(3, cbor.NewInt(-8)), p(-1, cbor.NewInt(6))), ErrMalformedKey},
		{"rsa wrong alg", enc(p(1, cbor.NewInt(3)), p(3, cbor.NewInt(-7))), ErrUnsupportedAlgorithm},
		{"rsa missing n", enc(p(1, cbor.NewInt(3)), p(3, cbor.NewInt(-257))), ErrMalformedKey},
		{"rsa missing e", enc(p(1, cbor.NewInt(3)), p(3, cbor.NewInt(-257)), p(-1, cbor.NewBytes(n2048))), ErrMalformedKey},
		{"rsa small modulus", enc(p(1, cbor.NewInt(3)), p(3, cbor.NewInt(-257)), p(-1, cbor.NewBytes(small.N.Bytes())), p(-2, cbor.NewBytes([]byte{1, 0, 1}))), ErrInvalidKey},
		{"rsa even exponent", enc(p(1, cbor.NewInt(3)), p(3, cbor.NewInt(-257)), p(-1, cbor.NewBytes(n2048)), p(-2, cbor.NewBytes([]byte{4}))), ErrInvalidKey},
		{"rsa leading zero", enc(p(1, cbor.NewInt(3)), p(3, cbor.NewInt(-257)), p(-1, cbor.NewBytes(append([]byte{0}, n2048...))), p(-2, cbor.NewBytes([]byte{3}))), ErrInvalidKey},
		{"rsa huge exponent", enc(p(1, cbor.NewInt(3)), p(3, cbor.NewInt(-257)), p(-1, cbor.NewBytes(n2048)), p(-2, cbor.NewBytes([]byte{1, 0, 0, 0, 1}))), ErrInvalidKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseKey(tc.in); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := KeyFromValue(cbor.NewText("x")); !errors.Is(err, ErrMalformedKey) {
		t.Fatal(err)
	}
}

func TestVerifySignatureErrors(t *testing.T) {
	p256 := ecKey(t, elliptic.P256())
	p384 := ecKey(t, elliptic.P384())
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	msg := []byte("m")
	cases := []struct {
		name string
		alg  Algorithm
		pub  crypto.PublicKey
		sig  []byte
		want error
	}{
		{"es256 with ed key", AlgES256, edPub, nil, ErrInvalidKey},
		{"es256 with p384 key", AlgES256, &p384.PublicKey, nil, ErrInvalidKey},
		{"es384 garbage sig", AlgES384, &p384.PublicKey, []byte{1, 2, 3}, ErrBadSignature},
		{"eddsa with ec key", AlgEdDSA, &p256.PublicKey, nil, ErrInvalidKey},
		{"eddsa short sig", AlgEdDSA, edPub, []byte{1}, ErrBadSignature},
		{"rs256 with ec key", AlgRS256, &p256.PublicKey, nil, ErrInvalidKey},
		{"unknown alg", Algorithm(-65535), &p256.PublicKey, nil, ErrUnsupportedAlgorithm},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifySignature(tc.alg, tc.pub, msg, tc.sig); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	n2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err := VerifySignature(AlgRS256, &n2048.PublicKey, msg, make([]byte, 256)); !errors.Is(err, ErrBadSignature) {
		t.Fatal(err)
	}
	if Algorithm(-1).Supported() || Algorithm(-1).String() != "alg(-1)" {
		t.Fatal("unknown algorithm metadata")
	}
}

func TestEncodeKeyErrors(t *testing.T) {
	p256 := ecKey(t, elliptic.P256())
	p224 := ecKey(t, elliptic.P224())
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	r, _ := rsa.GenerateKey(rand.Reader, 2048)
	cases := []struct {
		name string
		pub  crypto.PublicKey
		alg  Algorithm
	}{
		{"ec alg mismatch", &p256.PublicKey, AlgES384},
		{"p224", &p224.PublicKey, AlgES256},
		{"ed with es256", edPub, AlgES256},
		{"rsa with es256", &r.PublicKey, AlgES256},
		{"unknown type", "not a key", AlgES256},
	}
	for _, tc := range cases {
		if _, err := EncodeKey(tc.pub, tc.alg); !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("%s: got %v", tc.name, err)
		}
	}
}

func FuzzParseKey(f *testing.F) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	seed, _ := EncodeKey(&k.PublicKey, AlgES256)
	f.Add(seed)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	seed2, _ := EncodeKey(edPub, AlgEdDSA)
	f.Add(seed2)
	f.Fuzz(func(t *testing.T, data []byte) {
		key, err := ParseKey(data)
		if err != nil {
			return
		}
		if key.Public == nil || !key.Alg.Supported() {
			t.Fatalf("accepted key without usable public key: %+v", key)
		}
		_ = key.Verify([]byte("x"), []byte("y"))
	})
}
