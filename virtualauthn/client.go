package virtualauthn

import (
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/SlateGitOrg/passkeyd/cose"
	"github.com/SlateGitOrg/passkeyd/webauthn"
)

// Client plays the browser's role: it builds clientDataJSON, calls the
// authenticator and serializes the result in the WebAuthn Level 3 JSON form
// (PublicKeyCredential.toJSON()).
type Client struct {
	Origin        string
	Authenticator *Authenticator
	// CrossOrigin and TopOrigin are copied into clientDataJSON.
	CrossOrigin bool
	TopOrigin   string
	// ClientDataHook, if set, may modify client data before serialization.
	ClientDataHook func(*webauthn.CollectedClientData)
	// Transports are reported in registration responses.
	Transports []string
}

func (c *Client) clientData(typ string, challenge []byte) ([]byte, error) {
	cd := webauthn.CollectedClientData{
		Type:        typ,
		Challenge:   webauthn.EncodeURL(challenge),
		Origin:      c.Origin,
		CrossOrigin: c.CrossOrigin,
		TopOrigin:   c.TopOrigin,
	}
	if c.ClientDataHook != nil {
		c.ClientDataHook(&cd)
	}
	return json.Marshal(cd)
}

// ErrNoRPID is returned when creation options lack an RP ID.
var ErrNoRPID = errors.New("virtualauthn: options carry no RP ID")

// Create performs navigator.credentials.create() with the given options.
func (c *Client) Create(opts *webauthn.CreationOptionsJSON) (*webauthn.RegistrationResponseJSON, error) {
	if opts.RP.ID == "" {
		return nil, ErrNoRPID
	}
	cdj, err := c.clientData(webauthn.ClientDataCreate, opts.Challenge)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(cdj)
	algs := make([]cose.Algorithm, 0, len(opts.PubKeyCredParams))
	for _, p := range opts.PubKeyCredParams {
		algs = append(algs, cose.Algorithm(p.Alg))
	}
	cred, err := c.Authenticator.MakeCredential(opts.RP.ID, opts.User.ID, h[:], algs)
	if err != nil {
		return nil, err
	}
	return &webauthn.RegistrationResponseJSON{
		ID:    webauthn.EncodeURL(cred.ID),
		RawID: cred.ID,
		Type:  "public-key",
		Response: webauthn.AttestationResponseJSON{
			ClientDataJSON:    cdj,
			AttestationObject: cred.AttestationObject,
			Transports:        c.Transports,
		},
		AuthenticatorAttachment: "platform",
		ClientExtensionResults:  map[string]any{},
	}, nil
}

// Get performs navigator.credentials.get() with the given options.
func (c *Client) Get(opts *webauthn.RequestOptionsJSON) (*webauthn.AuthenticationResponseJSON, error) {
	if opts.RPID == "" {
		return nil, ErrNoRPID
	}
	cdj, err := c.clientData(webauthn.ClientDataGet, opts.Challenge)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(cdj)
	allow := make([][]byte, 0, len(opts.AllowCredentials))
	for _, d := range opts.AllowCredentials {
		allow = append(allow, d.ID)
	}
	as, err := c.Authenticator.GetAssertion(opts.RPID, h[:], allow)
	if err != nil {
		return nil, err
	}
	return &webauthn.AuthenticationResponseJSON{
		ID:    webauthn.EncodeURL(as.CredentialID),
		RawID: as.CredentialID,
		Type:  "public-key",
		Response: webauthn.AssertionResponseJSON{
			ClientDataJSON:    cdj,
			AuthenticatorData: as.AuthenticatorData,
			Signature:         as.Signature,
			UserHandle:        as.UserHandle,
		},
		AuthenticatorAttachment: "platform",
		ClientExtensionResults:  map[string]any{},
	}, nil
}
