package cli

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/archit2501/passkeyd/cbor"
	"github.com/archit2501/passkeyd/cose"
	"github.com/archit2501/passkeyd/webauthn"
)

// decodeInput accepts hex (with optional whitespace) or unpadded base64url.
func decodeInput(s string) ([]byte, error) {
	s = strings.Join(strings.Fields(s), "")
	if s == "" {
		return nil, fmt.Errorf("%w: empty input", errUsage)
	}
	if len(s)%2 == 0 {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	b, err := webauthn.DecodeURL(strings.TrimRight(s, "="))
	if err != nil {
		return nil, fmt.Errorf("%w: input is neither hex nor base64url", errUsage)
	}
	return b, nil
}

func inspect(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	fs.SetOutput(stderr)
	kind := fs.String("kind", "auto", "attestation|authdata|cbor|auto")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return fmt.Errorf("%w: inspect takes exactly one argument", errUsage)
	}
	text := fs.Arg(0)
	if text == "-" {
		b, err := io.ReadAll(io.LimitReader(stdin, 1<<20))
		if err != nil {
			return err
		}
		text = string(b)
	}
	data, err := decodeInput(text)
	if err != nil {
		return err
	}
	var out bytes.Buffer
	switch *kind {
	case "attestation":
		err = describeAttestation(&out, data)
	case "authdata":
		err = describeAuthData(&out, data, "")
	case "cbor":
		err = describeCBOR(&out, data)
	case "auto":
		if err = describeAttestation(&out, data); err != nil {
			out.Reset()
			if err = describeAuthData(&out, data, ""); err != nil {
				out.Reset()
				err = describeCBOR(&out, data)
			}
		}
	default:
		return fmt.Errorf("%w: unknown kind %q", errUsage, *kind)
	}
	if err != nil {
		return err
	}
	_, err = stdout.Write(out.Bytes())
	return err
}

func describeCBOR(w io.Writer, data []byte) error {
	v, err := cbor.DecodeWith(data, cbor.GenericOptions)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "cbor (%d bytes): %s\n", len(data), cbor.Diagnostic(v))
	return nil
}

func describeAttestation(w io.Writer, data []byte) error {
	v, err := cbor.Decode(data)
	if err != nil {
		return err
	}
	f, ok1 := v.LookupText("fmt")
	stmt, ok2 := v.LookupText("attStmt")
	ad, ok3 := v.LookupText("authData")
	format, okf := f.Text()
	raw, okb := ad.Bytes()
	if !ok1 || !ok2 || !ok3 || !okf || !okb {
		return fmt.Errorf("not an attestation object")
	}
	_, _ = fmt.Fprintf(w, "attestation object (%d bytes)\n  fmt: %s\n", len(data), format)
	if pairs, ok := stmt.Map(); ok {
		for _, p := range pairs {
			k, _ := p.Key.Text()
			switch k {
			case "alg":
				i, _ := p.Value.Int()
				_, _ = fmt.Fprintf(w, "  attStmt.alg: %v\n", cose.Algorithm(i))
			case "x5c":
				items, _ := p.Value.Array()
				for i, it := range items {
					der, _ := it.Bytes()
					if c, err := x509.ParseCertificate(der); err == nil {
						_, _ = fmt.Fprintf(w, "  attStmt.x5c[%d]: subject=%q issuer=%q notAfter=%s\n", i, c.Subject.String(), c.Issuer.String(), c.NotAfter.Format("2006-01-02"))
					} else {
						_, _ = fmt.Fprintf(w, "  attStmt.x5c[%d]: unparseable certificate (%v)\n", i, err)
					}
				}
			default:
				_, _ = fmt.Fprintf(w, "  attStmt.%s: %s\n", k, cbor.Diagnostic(p.Value))
			}
		}
	}
	return describeAuthData(w, raw, "  ")
}

func describeAuthData(w io.Writer, data []byte, indent string) error {
	ad, err := webauthn.ParseAuthenticatorData(data)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(w, "%sauthenticator data (%d bytes)\n", indent, len(data))
	_, _ = fmt.Fprintf(w, "%s  rpIdHash:  %x\n", indent, ad.RPIDHash)
	_, _ = fmt.Fprintf(w, "%s  flags:     0x%02x %s\n", indent, byte(ad.Flags), ad.Flags)
	_, _ = fmt.Fprintf(w, "%s  signCount: %d\n", indent, ad.SignCount)
	if acd := ad.AttestedCredential; acd != nil {
		c := webauthn.Credential{AAGUID: acd.AAGUID}
		_, _ = fmt.Fprintf(w, "%s  aaguid:    %s\n", indent, c.AAGUIDString())
		_, _ = fmt.Fprintf(w, "%s  credentialId (%d bytes): %s\n", indent, len(acd.CredentialID), webauthn.EncodeURL(acd.CredentialID))
		_, _ = fmt.Fprintf(w, "%s  publicKey: %s\n", indent, cbor.Diagnostic(acd.PublicKey))
		if k, err := cose.KeyFromValue(acd.PublicKey); err == nil {
			_, _ = fmt.Fprintf(w, "%s  publicKey.alg: %v (valid)\n", indent, k.Alg)
		} else {
			_, _ = fmt.Fprintf(w, "%s  publicKey: INVALID: %v\n", indent, err)
		}
	}
	if ad.Extensions.Kind() == cbor.KindMap {
		_, _ = fmt.Fprintf(w, "%s  extensions: %s\n", indent, cbor.Diagnostic(ad.Extensions))
	}
	return nil
}
