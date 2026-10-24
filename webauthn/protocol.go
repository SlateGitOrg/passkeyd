package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
)

// URLBytes is a byte slice that marshals to unpadded base64url JSON, the
// encoding WebAuthn Level 3 uses for binary fields (PublicKeyCredential
// toJSON / parseCreationOptionsFromJSON).
type URLBytes []byte

// MarshalJSON encodes b as an unpadded base64url string.
func (b URLBytes) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

// UnmarshalJSON accepts unpadded base64url. Padding and the standard
// alphabet are rejected so every byte string has one textual form.
func (b *URLBytes) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	dec, err := DecodeURL(s)
	if err != nil {
		return err
	}
	*b = dec
	return nil
}

// DecodeURL decodes strict unpadded base64url.
func DecodeURL(s string) ([]byte, error) {
	if strings.ContainsAny(s, "=+/") {
		return nil, errors.New("webauthn: base64url value must be unpadded and URL-safe")
	}
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

// EncodeURL encodes b as unpadded base64url.
func EncodeURL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// UserVerification is a UserVerificationRequirement.
type UserVerification string

// User verification requirements.
const (
	UVRequired    UserVerification = "required"
	UVPreferred   UserVerification = "preferred"
	UVDiscouraged UserVerification = "discouraged"
)

// ResidentKey is a ResidentKeyRequirement.
type ResidentKey string

// Resident key requirements.
const (
	ResidentKeyRequired    ResidentKey = "required"
	ResidentKeyPreferred   ResidentKey = "preferred"
	ResidentKeyDiscouraged ResidentKey = "discouraged"
)

// Conveyance is an AttestationConveyancePreference.
type Conveyance string

// Attestation conveyance preferences.
const (
	ConveyanceNone     Conveyance = "none"
	ConveyanceIndirect Conveyance = "indirect"
	ConveyanceDirect   Conveyance = "direct"
)

// RPEntity is PublicKeyCredentialRpEntity.
type RPEntity struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// UserEntityJSON is PublicKeyCredentialUserEntityJSON.
type UserEntityJSON struct {
	ID          URLBytes `json:"id"`
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName"`
}

// CredentialParameter is PublicKeyCredentialParameters.
type CredentialParameter struct {
	Type string `json:"type"`
	Alg  int64  `json:"alg"`
}

// CredentialDescriptorJSON is PublicKeyCredentialDescriptorJSON.
type CredentialDescriptorJSON struct {
	Type       string   `json:"type"`
	ID         URLBytes `json:"id"`
	Transports []string `json:"transports,omitempty"`
}

// AuthenticatorSelection is AuthenticatorSelectionCriteria.
type AuthenticatorSelection struct {
	ResidentKey        ResidentKey      `json:"residentKey,omitempty"`
	RequireResidentKey bool             `json:"requireResidentKey"`
	UserVerification   UserVerification `json:"userVerification,omitempty"`
}

// CreationOptionsJSON is PublicKeyCredentialCreationOptionsJSON, ready for
// PublicKeyCredential.parseCreationOptionsFromJSON in the browser.
type CreationOptionsJSON struct {
	RP                     RPEntity                   `json:"rp"`
	User                   UserEntityJSON             `json:"user"`
	Challenge              URLBytes                   `json:"challenge"`
	PubKeyCredParams       []CredentialParameter      `json:"pubKeyCredParams"`
	Timeout                int64                      `json:"timeout,omitempty"`
	ExcludeCredentials     []CredentialDescriptorJSON `json:"excludeCredentials"`
	AuthenticatorSelection AuthenticatorSelection     `json:"authenticatorSelection"`
	Attestation            Conveyance                 `json:"attestation"`
}

// RequestOptionsJSON is PublicKeyCredentialRequestOptionsJSON.
type RequestOptionsJSON struct {
	Challenge        URLBytes                   `json:"challenge"`
	Timeout          int64                      `json:"timeout,omitempty"`
	RPID             string                     `json:"rpId"`
	AllowCredentials []CredentialDescriptorJSON `json:"allowCredentials"`
	UserVerification UserVerification           `json:"userVerification"`
}

// AttestationResponseJSON is AuthenticatorAttestationResponseJSON. Only the
// fields the relying party verifies are decoded.
type AttestationResponseJSON struct {
	ClientDataJSON    URLBytes `json:"clientDataJSON"`
	AttestationObject URLBytes `json:"attestationObject"`
	Transports        []string `json:"transports,omitempty"`
}

// RegistrationResponseJSON is RegistrationResponseJSON (the toJSON() form of
// a PublicKeyCredential returned by navigator.credentials.create).
type RegistrationResponseJSON struct {
	ID                      string                  `json:"id"`
	RawID                   URLBytes                `json:"rawId"`
	Type                    string                  `json:"type"`
	Response                AttestationResponseJSON `json:"response"`
	AuthenticatorAttachment string                  `json:"authenticatorAttachment,omitempty"`
	ClientExtensionResults  map[string]any          `json:"clientExtensionResults"`
}

// AssertionResponseJSON is AuthenticatorAssertionResponseJSON.
type AssertionResponseJSON struct {
	ClientDataJSON    URLBytes `json:"clientDataJSON"`
	AuthenticatorData URLBytes `json:"authenticatorData"`
	Signature         URLBytes `json:"signature"`
	UserHandle        URLBytes `json:"userHandle,omitempty"`
}

// AuthenticationResponseJSON is AuthenticationResponseJSON (the toJSON()
// form of a PublicKeyCredential returned by navigator.credentials.get).
type AuthenticationResponseJSON struct {
	ID                      string                `json:"id"`
	RawID                   URLBytes              `json:"rawId"`
	Type                    string                `json:"type"`
	Response                AssertionResponseJSON `json:"response"`
	AuthenticatorAttachment string                `json:"authenticatorAttachment,omitempty"`
	ClientExtensionResults  map[string]any        `json:"clientExtensionResults"`
}

// checkCredentialShape validates the common PublicKeyCredential fields.
func checkCredentialShape(id string, rawID []byte, typ string) *VerifyError {
	if typ != "public-key" {
		return fail(CheckResponseShape, "type %q, want \"public-key\"", typ)
	}
	if len(rawID) == 0 {
		return fail(CheckResponseShape, "empty rawId")
	}
	if id != EncodeURL(rawID) {
		return fail(CheckResponseShape, "id does not match rawId")
	}
	return nil
}
