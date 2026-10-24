package webauthn

import (
	"errors"
	"fmt"
)

// Check names one verification step of a WebAuthn ceremony. Every failure the
// relying party reports carries exactly one Check, so callers (and tests) can
// tell precisely which rule rejected a response.
type Check string

// Verification checks, roughly in the order the ceremonies apply them
// (WebAuthn Level 3, sections 7.1 and 7.2).
const (
	CheckSession              Check = "session_invalid"
	CheckResponseShape        Check = "response_malformed"
	CheckClientDataJSON       Check = "client_data_malformed"
	CheckClientDataType       Check = "client_data_type"
	CheckChallenge            Check = "challenge_mismatch"
	CheckOrigin               Check = "origin_mismatch"
	CheckCrossOrigin          Check = "cross_origin_not_allowed"
	CheckTopOrigin            Check = "top_origin_mismatch"
	CheckAttestationObject    Check = "attestation_object_malformed"
	CheckAuthData             Check = "authenticator_data_malformed"
	CheckRPIDHash             Check = "rp_id_hash_mismatch"
	CheckUserPresent          Check = "user_not_present"
	CheckUserVerified         Check = "user_not_verified"
	CheckBackupFlags          Check = "backup_flags_inconsistent"
	CheckBackupPolicy         Check = "backup_policy"
	CheckAttestedCredential   Check = "attested_credential_data"
	CheckCredentialIDLength   Check = "credential_id_length"
	CheckCredentialIDMismatch Check = "credential_id_mismatch"
	CheckPublicKey            Check = "public_key_invalid"
	CheckAlgorithm            Check = "algorithm_not_allowed"
	CheckAttestationFormat    Check = "attestation_format_unsupported"
	CheckAttestationStatement Check = "attestation_statement_malformed"
	CheckAttestationSignature Check = "attestation_signature_invalid"
	CheckAttestationCert      Check = "attestation_certificate_invalid"
	CheckAAGUID               Check = "aaguid_mismatch"
	CheckAttestationTrust     Check = "attestation_untrusted"
	CheckAttestationPolicy    Check = "attestation_type_not_allowed"
	CheckCredentialUnique     Check = "credential_already_registered"
	CheckCredentialAllowed    Check = "credential_not_allowed"
	CheckCredentialUnknown    Check = "credential_unknown"
	CheckUserHandle           Check = "user_handle_mismatch"
	CheckBackupEligibility    Check = "backup_eligibility_changed"
	CheckSignature            Check = "signature_invalid"
	CheckSignCount            Check = "sign_count_regression"
)

// AllChecks lists every Check. The test suite asserts that each one has a
// dedicated negative test.
func AllChecks() []Check {
	return []Check{
		CheckSession, CheckResponseShape, CheckClientDataJSON, CheckClientDataType,
		CheckChallenge, CheckOrigin, CheckCrossOrigin, CheckTopOrigin,
		CheckAttestationObject, CheckAuthData, CheckRPIDHash, CheckUserPresent,
		CheckUserVerified, CheckBackupFlags, CheckBackupPolicy, CheckAttestedCredential,
		CheckCredentialIDLength, CheckCredentialIDMismatch, CheckPublicKey, CheckAlgorithm,
		CheckAttestationFormat, CheckAttestationStatement, CheckAttestationSignature,
		CheckAttestationCert, CheckAAGUID, CheckAttestationTrust, CheckAttestationPolicy,
		CheckCredentialUnique, CheckCredentialAllowed, CheckCredentialUnknown,
		CheckUserHandle, CheckBackupEligibility, CheckSignature, CheckSignCount,
	}
}

// VerifyError reports a failed verification step.
type VerifyError struct {
	Check  Check
	Detail string
	Err    error // optional underlying cause
}

func (e *VerifyError) Error() string {
	msg := "webauthn: " + string(e.Check)
	if e.Detail != "" {
		msg += ": " + e.Detail
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

// Unwrap returns the underlying cause, if any.
func (e *VerifyError) Unwrap() error { return e.Err }

// Is lets errors.Is(err, CheckX) style matching work via ErrCheck.
func (e *VerifyError) Is(target error) bool {
	var t *VerifyError
	if errors.As(target, &t) {
		return t.Check == e.Check && t.Detail == "" && t.Err == nil
	}
	return false
}

// ErrCheck returns a sentinel that matches any VerifyError for c with
// errors.Is, e.g. errors.Is(err, webauthn.ErrCheck(webauthn.CheckOrigin)).
func ErrCheck(c Check) error { return &VerifyError{Check: c} }

// CheckOf extracts the Check from err, or "" if err is not a VerifyError.
func CheckOf(err error) Check {
	var ve *VerifyError
	if errors.As(err, &ve) {
		return ve.Check
	}
	return ""
}

func fail(c Check, format string, args ...any) *VerifyError {
	return &VerifyError{Check: c, Detail: fmt.Sprintf(format, args...)}
}

func failWrap(c Check, err error, format string, args ...any) *VerifyError {
	return &VerifyError{Check: c, Detail: fmt.Sprintf(format, args...), Err: err}
}
