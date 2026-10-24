package virtualauthn

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/archit2501/passkeyd/cbor"
	"github.com/archit2501/passkeyd/cose"
	"github.com/archit2501/passkeyd/webauthn"
)

func TestMakeCredentialIsCanonicalCBOR(t *testing.T) {
	for _, mode := range []AttestationMode{AttestNone, AttestPackedSelf, AttestPackedX5C} {
		a := New(Options{Attestation: mode})
		h := sha256.Sum256([]byte("cd"))
		c, err := a.MakeCredential("example.org", []byte("u"), h[:], []cose.Algorithm{-65535, cose.AlgEdDSA})
		if err != nil {
			t.Fatal(err)
		}
		if c.Algorithm != cose.AlgEdDSA || len(c.ID) != 32 {
			t.Fatalf("credential %+v", c)
		}
		if _, err := cbor.DecodeWith(c.AttestationObject, cbor.Options{Canonical: true}); err != nil {
			t.Fatalf("%v: attestation object not CTAP2 canonical: %v", mode, err)
		}
	}
}

func TestErrors(t *testing.T) {
	a := New(Options{})
	if _, err := a.MakeCredential("example.org", nil, nil, []cose.Algorithm{-65535}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatal(err)
	}
	if _, err := a.GetAssertion("example.org", nil, nil); !errors.Is(err, ErrNoCredential) {
		t.Fatal(err)
	}
	c, err := a.MakeCredential("example.org", []byte("u"), make([]byte, 32), []cose.Algorithm{cose.AlgES256})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetAssertion("other.org", nil, nil); !errors.Is(err, ErrNoCredential) {
		t.Fatal("credential must be scoped to its RP ID")
	}
	if _, err := a.GetAssertion("example.org", nil, [][]byte{[]byte("x")}); !errors.Is(err, ErrNoCredential) {
		t.Fatal("allow list must filter")
	}
	as, err := a.GetAssertion("example.org", make([]byte, 32), [][]byte{c.ID})
	if err != nil || string(as.UserHandle) != "u" || as.AuthenticatorData[36] != 2 {
		t.Fatalf("%+v %v", as, err)
	}
	cl := &Client{Origin: "https://example.org", Authenticator: a}
	if _, err := cl.Create(&webauthn.CreationOptionsJSON{}); !errors.Is(err, ErrNoRPID) {
		t.Fatal(err)
	}
	if _, err := cl.Get(&webauthn.RequestOptionsJSON{}); !errors.Is(err, ErrNoRPID) {
		t.Fatal(err)
	}
	if _, err := cl.Create(&webauthn.CreationOptionsJSON{RP: webauthn.RPEntity{ID: "example.org"}}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatal(err)
	}
	if _, err := cl.Get(&webauthn.RequestOptionsJSON{RPID: "none.org"}); !errors.Is(err, ErrNoCredential) {
		t.Fatal(err)
	}
}

func TestAttestationRootIsStable(t *testing.T) {
	a := New(Options{Attestation: AttestPackedX5C})
	r1, err := a.AttestationRoot()
	if err != nil {
		t.Fatal(err)
	}
	r2, _ := a.AttestationRoot()
	if r1 != r2 || !r1.IsCA {
		t.Fatal("root must be generated once and be a CA")
	}
}
