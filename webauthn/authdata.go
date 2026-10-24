package webauthn

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/archit2501/passkeyd/cbor"
)

// Flags is the authenticator data flags byte (WebAuthn section 6.1).
type Flags byte

// Flag bits.
const (
	FlagUserPresent            Flags = 0x01 // UP
	FlagUserVerified           Flags = 0x04 // UV
	FlagBackupEligible         Flags = 0x08 // BE
	FlagBackupState            Flags = 0x10 // BS
	FlagAttestedCredentialData Flags = 0x40 // AT
	FlagExtensionData          Flags = 0x80 // ED
)

// Has reports whether all bits in f2 are set.
func (f Flags) Has(f2 Flags) bool { return f&f2 == f2 }

// String renders the set flags, e.g. "UP|UV|AT".
func (f Flags) String() string {
	names := []struct {
		f Flags
		n string
	}{{FlagUserPresent, "UP"}, {FlagUserVerified, "UV"}, {FlagBackupEligible, "BE"}, {FlagBackupState, "BS"}, {FlagAttestedCredentialData, "AT"}, {FlagExtensionData, "ED"}}
	s := ""
	for _, n := range names {
		if f.Has(n.f) {
			if s != "" {
				s += "|"
			}
			s += n.n
		}
	}
	if s == "" {
		return "-"
	}
	return s
}

// MaxCredentialIDLength is the WebAuthn limit on credential ID size.
const MaxCredentialIDLength = 1023

// Minimum authenticator data size: rpIdHash(32) + flags(1) + signCount(4).
const authDataMinLen = 37

// AuthenticatorData is the parsed authenticator data structure.
type AuthenticatorData struct {
	RPIDHash  [32]byte
	Flags     Flags
	SignCount uint32
	// AttestedCredential is present iff the AT flag is set.
	AttestedCredential *AttestedCredentialData
	// Extensions holds the authenticator extension outputs map when the ED
	// flag is set; its Kind is KindInvalid otherwise.
	Extensions cbor.Value
	// Raw is the exact input, which signatures cover.
	Raw []byte
}

// AttestedCredentialData is the variable part of registration authenticator
// data. The public key is kept as a decoded CBOR value; the ceremony converts
// it with cose.KeyFromValue so it can report algorithm problems precisely.
type AttestedCredentialData struct {
	AAGUID       [16]byte
	CredentialID []byte
	PublicKey    cbor.Value
}

var (
	errAuthDataShort      = errors.New("authenticator data too short")
	errCredentialIDLength = errors.New("credential ID longer than 1023 bytes")
)

// ParseAuthenticatorData parses authenticator data. Errors wrap the reason;
// the ceremony layer maps them to Checks.
func ParseAuthenticatorData(raw []byte) (*AuthenticatorData, error) {
	if len(raw) < authDataMinLen {
		return nil, fmt.Errorf("%w: %d bytes", errAuthDataShort, len(raw))
	}
	ad := &AuthenticatorData{Raw: raw}
	copy(ad.RPIDHash[:], raw[:32])
	ad.Flags = Flags(raw[32])
	ad.SignCount = binary.BigEndian.Uint32(raw[33:37])
	rest := raw[authDataMinLen:]

	if ad.Flags.Has(FlagAttestedCredentialData) {
		if len(rest) < 18 {
			return nil, fmt.Errorf("%w: attested credential data truncated", errAuthDataShort)
		}
		acd := &AttestedCredentialData{}
		copy(acd.AAGUID[:], rest[:16])
		idLen := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if idLen > MaxCredentialIDLength {
			return nil, fmt.Errorf("%w: %d", errCredentialIDLength, idLen)
		}
		if idLen > len(rest) {
			return nil, fmt.Errorf("%w: credential ID truncated", errAuthDataShort)
		}
		acd.CredentialID = rest[:idLen]
		rest = rest[idLen:]
		pk, after, err := cbor.DecodeFirst(rest)
		if err != nil {
			return nil, fmt.Errorf("credential public key: %w", err)
		}
		acd.PublicKey = pk
		rest = after
		ad.AttestedCredential = acd
	}
	if ad.Flags.Has(FlagExtensionData) {
		ext, after, err := cbor.DecodeFirst(rest)
		if err != nil {
			return nil, fmt.Errorf("extensions: %w", err)
		}
		if ext.Kind() != cbor.KindMap {
			return nil, errors.New("extensions: not a map")
		}
		ad.Extensions = ext
		rest = after
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("%d trailing bytes", len(rest))
	}
	return ad, nil
}

// authDataCheck maps a ParseAuthenticatorData error to a VerifyError.
func authDataCheck(err error) *VerifyError {
	if errors.Is(err, errCredentialIDLength) {
		return failWrap(CheckCredentialIDLength, err, "")
	}
	return failWrap(CheckAuthData, err, "")
}
