// Package cli implements the passkeyd command: serve, demo, inspect, version.
package cli

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/SlateGitOrg/passkeyd/credstore"
	"github.com/SlateGitOrg/passkeyd/internal/demo"
	"github.com/SlateGitOrg/passkeyd/server"
	"github.com/SlateGitOrg/passkeyd/webauthn"
)

// Version is the release version, overridable with -ldflags.
var Version = "0.1.0"

const usage = `passkeyd - WebAuthn relying party library and server

Usage:
  passkeyd serve   [flags]            run the HTTP server (flags also read PASSKEYD_* env vars)
  passkeyd demo    [-vectors path]    offline end-to-end demo with virtual authenticators
  passkeyd inspect [-kind k] <data>   decode an attestation object, authenticator data or CBOR
                                      (<data> is hex or base64url; "-" reads stdin)
  passkeyd version

Run "passkeyd <command> -h" for command flags.
`

// Run executes the command line args and returns the process exit code.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprint(stderr, usage)
		return 2
	}
	var err error
	switch args[0] {
	case "serve":
		err = serve(ctx, args[1:], stdout, stderr)
	case "demo":
		err = runDemo(ctx, args[1:], stdout, stderr)
	case "inspect":
		err = inspect(args[1:], os.Stdin, stdout, stderr)
	case "version", "-version", "--version":
		_, _ = fmt.Fprintf(stdout, "passkeyd %s\n", Version)
		return 0
	case "help", "-h", "-help", "--help":
		_, _ = fmt.Fprint(stdout, usage)
		return 0
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
	switch {
	case err == nil:
		return 0
	case errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, errUsage):
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return 2
	default:
		_, _ = fmt.Fprintln(stderr, "error:", err)
		return 1
	}
}

var errUsage = errors.New("usage")

func env(name, def string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return def
}

func envBool(name string, def bool) bool {
	if v, ok := os.LookupEnv(name); ok {
		b, err := strconv.ParseBool(v)
		if err == nil {
			return b
		}
	}
	return def
}

func envInt(name string, def int) int {
	if v, ok := os.LookupEnv(name); ok {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return def
}

type serveConfig struct {
	addr, rpID, rpName, origins, db, uv, conveyance, anchors, clonePolicy, logLevel, logFormat string
	requireTrusted, deviceBound                                                                bool
	rateLimit                                                                                  int
}

func parseServeFlags(args []string, stderr io.Writer) (*serveConfig, error) {
	c := &serveConfig{}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&c.addr, "addr", env("PASSKEYD_ADDR", "localhost:8080"), "listen address")
	fs.StringVar(&c.rpID, "rp-id", env("PASSKEYD_RP_ID", "localhost"), "relying party ID (registrable domain)")
	fs.StringVar(&c.rpName, "rp-name", env("PASSKEYD_RP_NAME", "passkeyd"), "relying party display name")
	fs.StringVar(&c.origins, "origins", env("PASSKEYD_ORIGINS", "http://localhost:8080"), "comma-separated allowed origins")
	fs.StringVar(&c.db, "db", env("PASSKEYD_DB", "passkeyd.db"), "SQLite database path")
	fs.StringVar(&c.uv, "uv", env("PASSKEYD_UV", "preferred"), "user verification: required|preferred|discouraged")
	fs.StringVar(&c.conveyance, "attestation", env("PASSKEYD_ATTESTATION", "none"), "attestation conveyance: none|indirect|direct")
	fs.StringVar(&c.anchors, "trust-anchors", env("PASSKEYD_TRUST_ANCHORS", ""), "PEM file of attestation root certificates")
	fs.BoolVar(&c.requireTrusted, "require-trusted", envBool("PASSKEYD_REQUIRE_TRUSTED", false), "reject x5c attestation that does not chain to -trust-anchors")
	fs.BoolVar(&c.deviceBound, "device-bound", envBool("PASSKEYD_DEVICE_BOUND", false), "reject backup-eligible (synced) credentials")
	fs.StringVar(&c.clonePolicy, "clone-policy", env("PASSKEYD_CLONE_POLICY", "reject"), "signature counter regression: reject|flag")
	fs.IntVar(&c.rateLimit, "rate-limit", envInt("PASSKEYD_RATE_LIMIT", 30), "ceremony starts per minute per IP (-1 disables)")
	fs.StringVar(&c.logLevel, "log-level", env("PASSKEYD_LOG_LEVEL", "info"), "debug|info|warn|error")
	fs.StringVar(&c.logFormat, "log-format", env("PASSKEYD_LOG_FORMAT", "text"), "text|json")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if fs.NArg() != 0 {
		return nil, fmt.Errorf("%w: unexpected arguments %v", errUsage, fs.Args())
	}
	return c, nil
}

func newLogger(level, format string, w io.Writer) (*slog.Logger, error) {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		return nil, fmt.Errorf("%w: log level %q", errUsage, level)
	}
	opts := &slog.HandlerOptions{Level: lv}
	switch format {
	case "text":
		return slog.New(slog.NewTextHandler(w, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(w, opts)), nil
	}
	return nil, fmt.Errorf("%w: log format %q", errUsage, format)
}

func loadAnchors(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	n := 0
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("trust anchor %d: %w", n+1, err)
		}
		pool.AddCert(cert)
		n++
	}
	if n == 0 {
		return nil, fmt.Errorf("%s contains no PEM certificates", path)
	}
	return pool, nil
}

func buildRP(c *serveConfig, logger *slog.Logger) (*webauthn.RelyingParty, bool, error) {
	anchors, err := loadAnchors(c.anchors)
	if err != nil {
		return nil, false, err
	}
	var clone webauthn.ClonePolicy
	switch c.clonePolicy {
	case "reject":
		clone = webauthn.CloneReject
	case "flag":
		clone = webauthn.CloneFlag
	default:
		return nil, false, fmt.Errorf("%w: clone policy %q", errUsage, c.clonePolicy)
	}
	origins := strings.Split(c.origins, ",")
	secure := false
	for i, o := range origins {
		origins[i] = strings.TrimSpace(o)
		secure = secure || strings.HasPrefix(origins[i], "https://")
	}
	rp, err := webauthn.New(webauthn.Config{
		RPID: c.rpID, RPName: c.rpName, Origins: origins,
		UserVerification: webauthn.UserVerification(c.uv),
		Conveyance:       webauthn.Conveyance(c.conveyance),
		Attestation: &webauthn.AttestationPolicy{
			AllowNone: true, AllowSelf: true, AllowBasic: true,
			TrustAnchors: anchors, RequireTrusted: c.requireTrusted,
		},
		RejectBackupEligible: c.deviceBound,
		ResidentKey:          webauthn.ResidentKeyRequired,
		ClonePolicy:          clone,
		Logger:               logger,
	})
	return rp, secure, err
}

func serve(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	c, err := parseServeFlags(args, stderr)
	if err != nil {
		return err
	}
	logger, err := newLogger(c.logLevel, c.logFormat, stderr)
	if err != nil {
		return err
	}
	rp, secure, err := buildRP(c, logger)
	if err != nil {
		return err
	}
	store, err := credstore.Open(ctx, c.db)
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()
	srv, err := server.New(server.Config{RP: rp, Store: store, Logger: logger, SecureCookies: secure, OptionsPerMinute: c.rateLimit})
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", c.addr)
	if err != nil {
		return err
	}
	hs := &http.Server{
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelWarn),
	}
	_, _ = fmt.Fprintf(stdout, "passkeyd %s listening on http://%s (RP ID %q, origins %s, db %s)\n", Version, ln.Addr(), c.rpID, c.origins, c.db)
	errc := make(chan error, 1)
	go func() { errc <- hs.Serve(ln) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if err := hs.Shutdown(shutCtx); err != nil {
		return err
	}
	_, _ = fmt.Fprintln(stdout, "passkeyd stopped")
	return nil
}

func runDemo(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("demo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	vectors := fs.String("vectors", "testdata/webauthn-l3-vectors.json", "path to the extracted spec vectors")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, err := demo.Run(ctx, stdout, demo.Options{VectorsPath: *vectors})
	return err
}
