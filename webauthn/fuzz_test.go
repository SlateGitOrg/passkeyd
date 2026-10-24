package webauthn

import (
	"encoding/hex"
	"testing"
	"time"
)

func FuzzParseAuthenticatorData(f *testing.F) {
	vs := loadSpecVectors(f)
	for _, v := range vs.Vectors {
		if ad := v.Authentication["authenticatorData"]; ad != "" {
			b, _ := hex.DecodeString(ad)
			f.Add(b)
		}
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		ad, err := ParseAuthenticatorData(raw)
		if err != nil {
			return
		}
		if len(ad.Raw) != len(raw) || (ad.AttestedCredential != nil) != ad.Flags.Has(FlagAttestedCredentialData) {
			t.Fatalf("inconsistent parse: %+v", ad)
		}
		if ad.AttestedCredential != nil && len(ad.AttestedCredential.CredentialID) > MaxCredentialIDLength {
			t.Fatal("credential ID limit not enforced")
		}
	})
}

// FuzzFinishRegistration feeds arbitrary attestation objects through the
// full registration ceremony with a valid client data and session. It must
// never panic and never accept an object whose signature it did not verify.
func FuzzFinishRegistration(f *testing.F) {
	vs := loadSpecVectors(f)
	none := vs.Vectors["none-es256"].Registration
	self := vs.Vectors["packed-self-es256"].Registration
	for _, reg := range []map[string]string{none, self} {
		b, _ := hex.DecodeString(reg["attestationObject"])
		f.Add(b)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rp, err := New(Config{RPID: "example.org", Origins: []string{"https://example.org"}, Now: func() time.Time { return now }})
	if err != nil {
		f.Fatal(err)
	}
	challenge, _ := hex.DecodeString(self["challenge"])
	cdj, _ := hex.DecodeString(self["clientDataJSON"])
	credID, _ := hex.DecodeString(self["credential_id"])
	f.Fuzz(func(t *testing.T, attObj []byte) {
		sess := &SessionData{Ceremony: CeremonyRegistration, Challenge: challenge, UserHandle: []byte("u"),
			UserVerification: UVPreferred, Algorithms: DefaultAlgorithms, Expires: now.Add(time.Minute)}
		resp := &RegistrationResponseJSON{ID: EncodeURL(credID), RawID: credID, Type: "public-key",
			Response: AttestationResponseJSON{ClientDataJSON: cdj, AttestationObject: attObj}}
		res, err := rp.FinishRegistration(sess, resp, nil)
		if err == nil && res.Attestation.Type != AttestationNone && res.Attestation.Type != AttestationSelf && res.Attestation.Type != AttestationBasic {
			t.Fatalf("accepted with unknown attestation type %q", res.Attestation.Type)
		}
		if err != nil && CheckOf(err) == "" {
			t.Fatalf("error without a Check: %v", err)
		}
	})
}
