package webauthn

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"slices"
)

// Client data types.
const (
	ClientDataCreate = "webauthn.create"
	ClientDataGet    = "webauthn.get"
)

// CollectedClientData is the parsed clientDataJSON (WebAuthn section 5.8.1).
// Unknown members (such as the spec's own "extraData" probe) are ignored, as
// the specification requires.
type CollectedClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
	TopOrigin   string `json:"topOrigin,omitempty"`
}

// verifyClientData runs the client data steps shared by both ceremonies and
// returns SHA-256(clientDataJSON).
func (rp *RelyingParty) verifyClientData(raw []byte, wantType string, challenge []byte) ([]byte, *VerifyError) {
	var cd CollectedClientData
	if len(raw) == 0 {
		return nil, fail(CheckClientDataJSON, "empty clientDataJSON")
	}
	if err := json.Unmarshal(raw, &cd); err != nil {
		return nil, failWrap(CheckClientDataJSON, err, "")
	}
	if cd.Type != wantType {
		return nil, fail(CheckClientDataType, "type %q, want %q", cd.Type, wantType)
	}
	got, err := DecodeURL(cd.Challenge)
	if err != nil {
		return nil, failWrap(CheckChallenge, err, "challenge is not base64url")
	}
	if len(challenge) == 0 || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return nil, fail(CheckChallenge, "challenge does not match the session")
	}
	if !slices.Contains(rp.cfg.Origins, cd.Origin) {
		return nil, fail(CheckOrigin, "origin %q is not allowed", cd.Origin)
	}
	if cd.CrossOrigin && !rp.cfg.AllowCrossOrigin {
		return nil, fail(CheckCrossOrigin, "ceremony ran in a cross-origin iframe")
	}
	if cd.TopOrigin != "" {
		if !cd.CrossOrigin {
			return nil, fail(CheckTopOrigin, "topOrigin present on a same-origin ceremony")
		}
		if !slices.Contains(rp.cfg.TopOrigins, cd.TopOrigin) {
			return nil, fail(CheckTopOrigin, "top origin %q is not allowed", cd.TopOrigin)
		}
	}
	h := sha256.Sum256(raw)
	return h[:], nil
}
