package webauthn_test

import (
	"testing"

	"github.com/archit2501/passkeyd/cose"
	"github.com/archit2501/passkeyd/virtualauthn"
	"github.com/archit2501/passkeyd/webauthn"
)

// benchRegistration measures FinishRegistration (client data, CBOR,
// authenticator data, COSE key and attestation verification).
func benchRegistration(b *testing.B, alg cose.Algorithm, mode virtualauthn.AttestationMode) {
	h := newHarness(b, func(c *webauthn.Config) { c.Algorithms = []cose.Algorithm{alg} }, virtualauthn.Options{Attestation: mode})
	o, s := h.beginReg()
	r := h.create(o)
	b.ResetTimer()
	for b.Loop() {
		if _, err := h.rp.FinishRegistration(s, r, nil); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFinishRegistrationNoneES256(b *testing.B) {
	benchRegistration(b, cose.AlgES256, virtualauthn.AttestNone)
}

func BenchmarkFinishRegistrationPackedX5CES256(b *testing.B) {
	benchRegistration(b, cose.AlgES256, virtualauthn.AttestPackedX5C)
}

func BenchmarkFinishRegistrationNoneEdDSA(b *testing.B) {
	benchRegistration(b, cose.AlgEdDSA, virtualauthn.AttestNone)
}

// benchLogin measures FinishLogin. The stored counter is reset each
// iteration so the same signed assertion stays valid.
func benchLogin(b *testing.B, alg cose.Algorithm) {
	h := newHarness(b, func(c *webauthn.Config) { c.Algorithms = []cose.Algorithm{alg} }, virtualauthn.Options{})
	cred := h.register()
	o, s := h.beginLogin(&cred)
	r := h.get(o)
	lookup := func([]byte) (*webauthn.Credential, error) { c := cred; return &c, nil }
	b.ResetTimer()
	for b.Loop() {
		if _, err := h.rp.FinishLogin(s, r, lookup); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFinishLoginES256(b *testing.B) { benchLogin(b, cose.AlgES256) }

func BenchmarkFinishLoginEdDSA(b *testing.B) { benchLogin(b, cose.AlgEdDSA) }

func BenchmarkFinishLoginRS256(b *testing.B) { benchLogin(b, cose.AlgRS256) }
