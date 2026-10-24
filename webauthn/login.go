package webauthn

import (
	"bytes"
	"slices"

	"github.com/archit2501/passkeyd/cose"
)

// BeginLogin starts an authentication ceremony. With a non-empty allow list
// the client may only use those credentials and the response must come from
// userHandle's account; with an empty list the ceremony is a discoverable
// ("passkey") login and the authenticator chooses the account.
func (rp *RelyingParty) BeginLogin(userHandle []byte, allow []Credential) (*RequestOptionsJSON, *SessionData, error) {
	challenge, err := rp.newChallenge()
	if err != nil {
		return nil, nil, err
	}
	descs := make([]CredentialDescriptorJSON, 0, len(allow))
	ids := make([][]byte, 0, len(allow))
	for _, c := range allow {
		descs = append(descs, CredentialDescriptorJSON{Type: "public-key", ID: c.ID, Transports: c.Transports})
		ids = append(ids, bytes.Clone(c.ID))
	}
	opts := &RequestOptionsJSON{
		Challenge:        challenge,
		Timeout:          rp.cfg.Timeout.Milliseconds(),
		RPID:             rp.cfg.RPID,
		AllowCredentials: descs,
		UserVerification: rp.cfg.UserVerification,
	}
	sess := &SessionData{
		Ceremony:         CeremonyAuthentication,
		Challenge:        challenge,
		UserHandle:       bytes.Clone(userHandle),
		AllowCredentials: ids,
		UserVerification: rp.cfg.UserVerification,
		Expires:          rp.cfg.Now().Add(rp.cfg.Timeout),
	}
	return opts, sess, nil
}

// CredentialLookupFunc returns the stored credential with the given ID, or
// (nil, nil) if there is none.
type CredentialLookupFunc func(id []byte) (*Credential, error)

// LoginResult is the outcome of a successful authentication ceremony.
type LoginResult struct {
	// Credential is the stored record with SignCount, BackupState,
	// UVInitialized, CloneWarning and LastUsedAt updated; persist it.
	Credential Credential
	// PreviousSignCount is the counter value before this login, for
	// compare-and-swap persistence.
	PreviousSignCount uint32
	UserVerified      bool
	// CloneWarning is set when the counter regressed under CloneFlag.
	CloneWarning bool
}

// FinishLogin verifies an authentication response (WebAuthn section 7.2).
func (rp *RelyingParty) FinishLogin(sess *SessionData, resp *AuthenticationResponseJSON, lookup CredentialLookupFunc) (*LoginResult, error) {
	res, ve := rp.finishLogin(sess, resp, lookup)
	if ve != nil {
		rp.cfg.Logger.Info("authentication rejected", "check", string(ve.Check), "detail", ve.Detail)
		return nil, ve
	}
	if res.CloneWarning {
		rp.cfg.Logger.Warn("signature counter regressed; possible cloned authenticator",
			"credential", EncodeURL(res.Credential.ID), "stored", res.PreviousSignCount)
	}
	rp.cfg.Logger.Info("authentication verified", "credential", EncodeURL(res.Credential.ID), "sign_count", res.Credential.SignCount)
	return res, nil
}

func (rp *RelyingParty) finishLogin(sess *SessionData, resp *AuthenticationResponseJSON, lookup CredentialLookupFunc) (*LoginResult, *VerifyError) {
	if ve := rp.checkSession(sess, CeremonyAuthentication); ve != nil {
		return nil, ve
	}
	if resp == nil {
		return nil, fail(CheckResponseShape, "missing response")
	}
	if ve := checkCredentialShape(resp.ID, resp.RawID, resp.Type); ve != nil {
		return nil, ve
	}
	if len(sess.AllowCredentials) > 0 && !slices.ContainsFunc(sess.AllowCredentials, func(id []byte) bool { return bytes.Equal(id, resp.RawID) }) {
		return nil, fail(CheckCredentialAllowed, "credential was not in allowCredentials")
	}
	stored, err := lookup(resp.RawID)
	if err != nil {
		return nil, failWrap(CheckCredentialUnknown, err, "lookup failed")
	}
	if stored == nil {
		return nil, fail(CheckCredentialUnknown, "no credential with this ID")
	}
	// Identify the user: a known user must own the credential, and a
	// returned userHandle must match the credential's owner. Discoverable
	// logins (no user in the session) require the userHandle.
	if len(sess.UserHandle) > 0 && !bytes.Equal(sess.UserHandle, stored.UserHandle) {
		return nil, fail(CheckUserHandle, "credential belongs to a different user")
	}
	if len(resp.Response.UserHandle) > 0 && !bytes.Equal(resp.Response.UserHandle, stored.UserHandle) {
		return nil, fail(CheckUserHandle, "userHandle does not own this credential")
	}
	if len(sess.UserHandle) == 0 && len(resp.Response.UserHandle) == 0 {
		return nil, fail(CheckUserHandle, "discoverable login without userHandle")
	}
	clientDataHash, ve := rp.verifyClientData(resp.Response.ClientDataJSON, ClientDataGet, sess.Challenge)
	if ve != nil {
		return nil, ve
	}
	ad, err := ParseAuthenticatorData(resp.Response.AuthenticatorData)
	if err != nil {
		return nil, authDataCheck(err)
	}
	if ad.AttestedCredential != nil {
		return nil, fail(CheckAuthData, "AT flag set in an assertion")
	}
	if ve := rp.checkFlags(ad, sess.UserVerification); ve != nil {
		return nil, ve
	}
	if ad.Flags.Has(FlagBackupEligible) != stored.BackupEligible {
		return nil, fail(CheckBackupEligibility, "BE flag changed from %v to %v", stored.BackupEligible, !stored.BackupEligible)
	}
	key, err := cose.ParseKey(stored.PublicKey)
	if err != nil {
		return nil, failWrap(CheckPublicKey, err, "stored credential key")
	}
	signed := make([]byte, 0, len(ad.Raw)+len(clientDataHash))
	signed = append(append(signed, ad.Raw...), clientDataHash...)
	if err := key.Verify(signed, resp.Response.Signature); err != nil {
		return nil, failWrap(CheckSignature, err, "")
	}

	res := &LoginResult{Credential: *stored, PreviousSignCount: stored.SignCount, UserVerified: ad.Flags.Has(FlagUserVerified)}
	c := &res.Credential
	if ad.SignCount != 0 || stored.SignCount != 0 {
		if ad.SignCount > stored.SignCount {
			c.SignCount = ad.SignCount
		} else {
			if rp.cfg.ClonePolicy == CloneReject {
				return nil, fail(CheckSignCount, "counter %d is not greater than stored %d; possible cloned authenticator", ad.SignCount, stored.SignCount)
			}
			res.CloneWarning = true
			c.CloneWarning = true
		}
	}
	c.BackupState = ad.Flags.Has(FlagBackupState)
	if res.UserVerified {
		c.UVInitialized = true
	}
	c.LastUsedAt = rp.cfg.Now()
	return res, nil
}
