package webauthn

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/SlateGitOrg/passkeyd/cose"
)

// User is the account a credential is being registered for.
type User struct {
	// ID is the opaque user handle, 1 to 64 bytes. It must not contain
	// personally identifying information.
	ID          []byte
	Name        string
	DisplayName string
}

// Credential is the relying party's record of a registered public key
// credential (WebAuthn "credential record").
type Credential struct {
	ID                 []byte
	UserHandle         []byte
	PublicKey          []byte // encoded COSE_Key
	Algorithm          cose.Algorithm
	SignCount          uint32
	UVInitialized      bool
	BackupEligible     bool
	BackupState        bool
	Transports         []string
	AAGUID             [16]byte
	AttestationFormat  string
	AttestationType    AttestationType
	AttestationTrusted bool
	CloneWarning       bool
	CreatedAt          time.Time
	LastUsedAt         time.Time
}

// AAGUIDString formats the AAGUID as a UUID.
func (c *Credential) AAGUIDString() string { return fmtAAGUID(c.AAGUID) }

// MaxUserHandleLength is the WebAuthn limit on user handles.
const MaxUserHandleLength = 64

// ErrInvalidUser reports an unusable User passed to BeginRegistration.
var ErrInvalidUser = errors.New("webauthn: invalid user")

// BeginRegistration starts a registration ceremony for user. Credentials in
// exclude are listed so the authenticator refuses to create a second
// credential for the same account.
func (rp *RelyingParty) BeginRegistration(user User, exclude []Credential) (*CreationOptionsJSON, *SessionData, error) {
	if len(user.ID) == 0 || len(user.ID) > MaxUserHandleLength {
		return nil, nil, fmt.Errorf("%w: user handle must be 1-%d bytes", ErrInvalidUser, MaxUserHandleLength)
	}
	if user.Name == "" {
		return nil, nil, fmt.Errorf("%w: empty user name", ErrInvalidUser)
	}
	if user.DisplayName == "" {
		user.DisplayName = user.Name
	}
	challenge, err := rp.newChallenge()
	if err != nil {
		return nil, nil, err
	}
	params := make([]CredentialParameter, 0, len(rp.cfg.Algorithms))
	for _, a := range rp.cfg.Algorithms {
		params = append(params, CredentialParameter{Type: "public-key", Alg: int64(a)})
	}
	excl := make([]CredentialDescriptorJSON, 0, len(exclude))
	for _, c := range exclude {
		excl = append(excl, CredentialDescriptorJSON{Type: "public-key", ID: c.ID, Transports: c.Transports})
	}
	opts := &CreationOptionsJSON{
		RP:                 RPEntity{ID: rp.cfg.RPID, Name: rp.cfg.RPName},
		User:               UserEntityJSON{ID: user.ID, Name: user.Name, DisplayName: user.DisplayName},
		Challenge:          challenge,
		PubKeyCredParams:   params,
		Timeout:            rp.cfg.Timeout.Milliseconds(),
		ExcludeCredentials: excl,
		AuthenticatorSelection: AuthenticatorSelection{
			ResidentKey:        rp.cfg.ResidentKey,
			RequireResidentKey: rp.cfg.ResidentKey == ResidentKeyRequired,
			UserVerification:   rp.cfg.UserVerification,
		},
		Attestation: rp.cfg.Conveyance,
	}
	sess := &SessionData{
		Ceremony:         CeremonyRegistration,
		Challenge:        challenge,
		UserHandle:       bytes.Clone(user.ID),
		UserName:         user.Name,
		UserVerification: rp.cfg.UserVerification,
		Algorithms:       slices.Clone(rp.cfg.Algorithms),
		Expires:          rp.cfg.Now().Add(rp.cfg.Timeout),
	}
	return opts, sess, nil
}

// CredentialExistsFunc reports whether a credential ID is already
// registered to any user.
type CredentialExistsFunc func(id []byte) (bool, error)

// RegistrationResult is a verified new credential plus attestation details.
type RegistrationResult struct {
	Credential  Credential
	Attestation AttestationResult
}

// FinishRegistration verifies a registration response against the session
// created by BeginRegistration (WebAuthn section 7.1). exists may be nil;
// when set, it enforces global credential ID uniqueness.
func (rp *RelyingParty) FinishRegistration(sess *SessionData, resp *RegistrationResponseJSON, exists CredentialExistsFunc) (*RegistrationResult, error) {
	res, ve := rp.finishRegistration(sess, resp, exists)
	if ve != nil {
		rp.cfg.Logger.Info("registration rejected", "check", string(ve.Check), "detail", ve.Detail)
		return nil, ve
	}
	rp.cfg.Logger.Info("registration verified",
		"credential", EncodeURL(res.Credential.ID), "alg", res.Credential.Algorithm.String(),
		"attestation", string(res.Attestation.Type), "trusted", res.Attestation.Trusted)
	return res, nil
}

func (rp *RelyingParty) finishRegistration(sess *SessionData, resp *RegistrationResponseJSON, exists CredentialExistsFunc) (*RegistrationResult, *VerifyError) {
	if ve := rp.checkSession(sess, CeremonyRegistration); ve != nil {
		return nil, ve
	}
	if resp == nil {
		return nil, fail(CheckResponseShape, "missing response")
	}
	if ve := checkCredentialShape(resp.ID, resp.RawID, resp.Type); ve != nil {
		return nil, ve
	}
	clientDataHash, ve := rp.verifyClientData(resp.Response.ClientDataJSON, ClientDataCreate, sess.Challenge)
	if ve != nil {
		return nil, ve
	}
	obj, ve := parseAttestationObject(resp.Response.AttestationObject)
	if ve != nil {
		return nil, ve
	}
	ad, err := ParseAuthenticatorData(obj.AuthData)
	if err != nil {
		return nil, authDataCheck(err)
	}
	if ve := rp.checkFlags(ad, sess.UserVerification); ve != nil {
		return nil, ve
	}
	acd := ad.AttestedCredential
	if acd == nil {
		return nil, fail(CheckAttestedCredential, "AT flag not set at registration")
	}
	if len(acd.CredentialID) == 0 {
		return nil, fail(CheckAttestedCredential, "empty credential ID")
	}
	if !bytes.Equal(acd.CredentialID, resp.RawID) {
		return nil, fail(CheckCredentialIDMismatch, "rawId differs from the attested credential ID")
	}
	key, err := cose.KeyFromValue(acd.PublicKey)
	if err != nil {
		if errors.Is(err, cose.ErrUnsupportedAlgorithm) {
			return nil, failWrap(CheckAlgorithm, err, "")
		}
		return nil, failWrap(CheckPublicKey, err, "")
	}
	if !slices.Contains(sess.Algorithms, key.Alg) {
		return nil, fail(CheckAlgorithm, "credential algorithm %v was not requested", key.Alg)
	}
	att, ve := rp.verifyAttestation(obj, ad, key, clientDataHash)
	if ve != nil {
		return nil, ve
	}
	if exists != nil {
		dup, err := exists(acd.CredentialID)
		if err != nil {
			return nil, failWrap(CheckCredentialUnique, err, "lookup failed")
		}
		if dup {
			return nil, fail(CheckCredentialUnique, "credential ID is already registered")
		}
	}
	now := rp.cfg.Now()
	cred := Credential{
		ID:                 bytes.Clone(acd.CredentialID),
		UserHandle:         bytes.Clone(sess.UserHandle),
		PublicKey:          bytes.Clone(key.Raw),
		Algorithm:          key.Alg,
		SignCount:          ad.SignCount,
		UVInitialized:      ad.Flags.Has(FlagUserVerified),
		BackupEligible:     ad.Flags.Has(FlagBackupEligible),
		BackupState:        ad.Flags.Has(FlagBackupState),
		Transports:         slices.Clone(resp.Response.Transports),
		AAGUID:             acd.AAGUID,
		AttestationFormat:  att.Format,
		AttestationType:    att.Type,
		AttestationTrusted: att.Trusted,
		CreatedAt:          now,
		LastUsedAt:         now,
	}
	return &RegistrationResult{Credential: cred, Attestation: *att}, nil
}
