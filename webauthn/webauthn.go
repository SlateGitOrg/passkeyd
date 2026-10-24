// Package webauthn implements the relying-party side of the WebAuthn Level 3
// registration and authentication ceremonies.
//
// The package is storage-agnostic: Begin* methods return options for the
// browser plus a SessionData that the caller must keep server-side (see the
// challenge package) and hand back to the matching Finish* method. Every
// rejection is a *VerifyError naming the Check that failed.
package webauthn

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/archit2501/passkeyd/cose"
)

// ClonePolicy decides what happens when a signature counter goes backwards.
type ClonePolicy int

// Clone policies.
const (
	// CloneReject fails the ceremony with CheckSignCount (default).
	CloneReject ClonePolicy = iota
	// CloneFlag lets the login succeed but marks the credential, so the
	// application can apply its own risk response.
	CloneFlag
)

// AttestationPolicy controls which attestation types registration accepts.
type AttestationPolicy struct {
	// AllowNone accepts the "none" format (no attestation).
	AllowNone bool
	// AllowSelf accepts packed self attestation.
	AllowSelf bool
	// AllowBasic accepts packed attestation with an x5c certificate chain.
	AllowBasic bool
	// TrustAnchors, when non-nil, is the set of roots an x5c chain must
	// verify against. Chains that do not verify fail CheckAttestationTrust.
	TrustAnchors *x509.CertPool
	// RequireTrusted rejects x5c attestation when TrustAnchors is nil
	// (nothing to anchor to), instead of recording it as unverified.
	RequireTrusted bool
}

// PermissiveAttestation accepts every supported attestation type and
// records x5c chains as unverified when no trust anchors are configured.
// Appropriate for consumer passkey deployments, which request "none".
var PermissiveAttestation = AttestationPolicy{AllowNone: true, AllowSelf: true, AllowBasic: true}

// Config configures a RelyingParty.
type Config struct {
	// RPID is the relying party identifier, a registrable domain such as
	// "example.org" (or "localhost" for development).
	RPID string
	// RPName is the human-readable name shown by authenticators.
	RPName string
	// Origins are the exact origins allowed in clientDataJSON, e.g.
	// "https://example.org". Web origins must be same-site with RPID.
	Origins []string
	// AllowCrossOrigin accepts ceremonies from cross-origin iframes.
	AllowCrossOrigin bool
	// TopOrigins are the allowed embedding origins when crossOrigin is true
	// and the client reports topOrigin.
	TopOrigins []string
	// UserVerification is requested in options and enforced when "required".
	UserVerification UserVerification
	// ResidentKey is requested at registration. Default "preferred".
	ResidentKey ResidentKey
	// Conveyance is the attestation preference sent to the client. Default "none".
	Conveyance Conveyance
	// Algorithms lists acceptable credential algorithms in preference order.
	// Default: ES256, EdDSA, ES384, ES512, RS256.
	Algorithms []cose.Algorithm
	// Attestation decides which attestation types are accepted.
	// The zero value is replaced by PermissiveAttestation.
	Attestation *AttestationPolicy
	// RejectBackupEligible refuses credentials whose BE flag is set
	// (synced passkeys), for deployments that require device-bound keys.
	RejectBackupEligible bool
	// ClonePolicy handles signature counter regressions. Default CloneReject.
	ClonePolicy ClonePolicy
	// Timeout is how long a ceremony may take. Default 5 minutes.
	Timeout time.Duration
	// Now returns the current time. Default time.Now.
	Now func() time.Time
	// Rand is the randomness source for challenges. Default crypto/rand.
	Rand io.Reader
	// Logger receives structured ceremony logs. Default: discard.
	Logger *slog.Logger
}

// DefaultAlgorithms is the default credential algorithm preference list.
var DefaultAlgorithms = []cose.Algorithm{cose.AlgES256, cose.AlgEdDSA, cose.AlgES384, cose.AlgES512, cose.AlgRS256}

// ChallengeSize is the number of random bytes in each challenge (the spec
// requires at least 16).
const ChallengeSize = 32

// RelyingParty runs WebAuthn ceremonies. It holds no mutable state and is
// safe for concurrent use.
type RelyingParty struct {
	cfg      Config
	rpIDHash [32]byte
}

// ErrConfig reports an invalid Config.
var ErrConfig = errors.New("webauthn: invalid config")

// New validates cfg, applies defaults and returns a RelyingParty.
func New(cfg Config) (*RelyingParty, error) {
	if cfg.RPID == "" || strings.ContainsAny(cfg.RPID, "/:@ ") || strings.ToLower(cfg.RPID) != cfg.RPID {
		return nil, fmt.Errorf("%w: RPID %q must be a lowercase host name", ErrConfig, cfg.RPID)
	}
	if cfg.RPName == "" {
		cfg.RPName = cfg.RPID
	}
	if len(cfg.Origins) == 0 {
		return nil, fmt.Errorf("%w: at least one origin is required", ErrConfig)
	}
	for _, o := range cfg.Origins {
		if err := checkOrigin(o, cfg.RPID); err != nil {
			return nil, err
		}
	}
	if cfg.UserVerification == "" {
		cfg.UserVerification = UVPreferred
	}
	switch cfg.UserVerification {
	case UVRequired, UVPreferred, UVDiscouraged:
	default:
		return nil, fmt.Errorf("%w: user verification %q", ErrConfig, cfg.UserVerification)
	}
	if cfg.ResidentKey == "" {
		cfg.ResidentKey = ResidentKeyPreferred
	}
	if cfg.Conveyance == "" {
		cfg.Conveyance = ConveyanceNone
	}
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = DefaultAlgorithms
	}
	for _, a := range cfg.Algorithms {
		if !a.Supported() {
			return nil, fmt.Errorf("%w: algorithm %v is not supported", ErrConfig, a)
		}
	}
	if cfg.Attestation == nil {
		p := PermissiveAttestation
		cfg.Attestation = &p
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Rand == nil {
		cfg.Rand = rand.Reader
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &RelyingParty{cfg: cfg, rpIDHash: sha256.Sum256([]byte(cfg.RPID))}, nil
}

// checkOrigin requires web origins to be bare scheme://host[:port] values on
// the RP ID or one of its subdomains, and https unless the host is localhost.
// Non-web origins (e.g. "android:apk-key-hash:...") are accepted verbatim.
func checkOrigin(origin, rpID string) error {
	if !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://") {
		if origin == "" {
			return fmt.Errorf("%w: empty origin", ErrConfig)
		}
		return nil
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%w: origin %q must be scheme://host[:port]", ErrConfig, origin)
	}
	if strings.HasSuffix(origin, "/") {
		return fmt.Errorf("%w: origin %q must not end with a slash", ErrConfig, origin)
	}
	host := u.Hostname()
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return fmt.Errorf("%w: origin %q is not on RP ID %q", ErrConfig, origin, rpID)
	}
	if u.Scheme == "http" && host != "localhost" {
		return fmt.Errorf("%w: origin %q must use https", ErrConfig, origin)
	}
	return nil
}

// Config returns the effective configuration (with defaults applied).
func (rp *RelyingParty) Config() Config { return rp.cfg }

func (rp *RelyingParty) newChallenge() ([]byte, error) {
	c := make([]byte, ChallengeSize)
	if _, err := io.ReadFull(rp.cfg.Rand, c); err != nil {
		return nil, fmt.Errorf("webauthn: generating challenge: %w", err)
	}
	return c, nil
}

// Ceremony identifies which ceremony a session belongs to.
type Ceremony string

// Ceremonies.
const (
	CeremonyRegistration   Ceremony = "registration"
	CeremonyAuthentication Ceremony = "authentication"
)

// SessionData is the server-side state of one in-flight ceremony. It must
// never be sent to the client.
type SessionData struct {
	Ceremony         Ceremony         `json:"ceremony"`
	Challenge        []byte           `json:"challenge"`
	UserHandle       []byte           `json:"userHandle,omitempty"`
	UserName         string           `json:"userName,omitempty"`
	AllowCredentials [][]byte         `json:"allowCredentials,omitempty"`
	UserVerification UserVerification `json:"userVerification"`
	Algorithms       []cose.Algorithm `json:"algorithms,omitempty"`
	Expires          time.Time        `json:"expires"`
}

func (rp *RelyingParty) checkSession(s *SessionData, want Ceremony) *VerifyError {
	if s == nil || len(s.Challenge) == 0 {
		return fail(CheckSession, "missing session")
	}
	if s.Ceremony != want {
		return fail(CheckSession, "session is for %s, not %s", s.Ceremony, want)
	}
	if !rp.cfg.Now().Before(s.Expires) {
		return fail(CheckSession, "session expired at %s", s.Expires.UTC().Format(time.RFC3339))
	}
	return nil
}

// checkFlags applies the RP ID hash, UP, UV and backup-flag rules common to
// both ceremonies.
func (rp *RelyingParty) checkFlags(ad *AuthenticatorData, uv UserVerification) *VerifyError {
	if ad.RPIDHash != rp.rpIDHash {
		return fail(CheckRPIDHash, "authenticator data is not scoped to RP ID %q", rp.cfg.RPID)
	}
	if !ad.Flags.Has(FlagUserPresent) {
		return fail(CheckUserPresent, "UP flag not set")
	}
	if uv == UVRequired && !ad.Flags.Has(FlagUserVerified) {
		return fail(CheckUserVerified, "UV flag not set but user verification is required")
	}
	if ad.Flags.Has(FlagBackupState) && !ad.Flags.Has(FlagBackupEligible) {
		return fail(CheckBackupFlags, "BS set without BE")
	}
	if rp.cfg.RejectBackupEligible && ad.Flags.Has(FlagBackupEligible) {
		return fail(CheckBackupPolicy, "backup-eligible (synced) credentials are not accepted")
	}
	return nil
}
