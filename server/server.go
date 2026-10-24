// Package server exposes the relying party over HTTP: a JSON API for the
// two WebAuthn ceremonies plus the static demo page.
//
// API (all JSON, POST bodies limited to 64 KiB):
//
//	POST /api/register/options  {"username","displayName"} -> PublicKeyCredentialCreationOptionsJSON
//	POST /api/register/verify   RegistrationResponseJSON    -> {"status":"ok",...}
//	POST /api/login/options     {"username"?}               -> PublicKeyCredentialRequestOptionsJSON
//	POST /api/login/verify      AuthenticationResponseJSON  -> {"status":"ok",...}
//	GET  /api/health                                         -> {"status":"ok","users":N,"credentials":M}
//
// Ceremony state lives server-side in a challenge.Store; the browser only
// holds an opaque, HttpOnly, SameSite=Strict cookie naming it.
package server

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
	"unicode"

	"github.com/archit2501/passkeyd/challenge"
	"github.com/archit2501/passkeyd/credstore"
	"github.com/archit2501/passkeyd/web"
	"github.com/archit2501/passkeyd/webauthn"
)

// CeremonyCookie names the cookie that carries the ceremony key.
const CeremonyCookie = "passkeyd_ceremony"

// MaxBodyBytes bounds every request body.
const MaxBodyBytes = 64 << 10

// Config wires a Server.
type Config struct {
	RP     *webauthn.RelyingParty
	Store  *credstore.Store
	Logger *slog.Logger
	// SecureCookies sets the Secure attribute (required on https origins).
	SecureCookies bool
	// OptionsPerMinute limits ceremony starts per client IP. Zero means 30;
	// negative disables the limit.
	OptionsPerMinute int
	// MaxPendingCeremonies bounds in-flight ceremonies. Zero means 100000.
	MaxPendingCeremonies int
	// Now returns the current time. Default time.Now.
	Now func() time.Time
}

// pending is what the challenge store holds per ceremony.
type pending struct {
	Session     webauthn.SessionData
	DisplayName string
}

// Server is the HTTP front end.
type Server struct {
	rp       *webauthn.RelyingParty
	store    *credstore.Store
	log      *slog.Logger
	pending  *challenge.Store[pending]
	limiter  *rateLimiter
	secure   bool
	now      func() time.Time
	randRead func([]byte) (int, error)
}

// New validates cfg and returns a Server.
func New(cfg Config) (*Server, error) {
	if cfg.RP == nil || cfg.Store == nil {
		return nil, errors.New("server: RP and Store are required")
	}
	// Login options never list credentials (see loginOptions), so every
	// credential must be discoverable or its owner could not sign in.
	if rk := cfg.RP.Config().ResidentKey; rk != webauthn.ResidentKeyRequired {
		return nil, fmt.Errorf("server: RP must set ResidentKey %q (got %q)", webauthn.ResidentKeyRequired, rk)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.OptionsPerMinute == 0 {
		cfg.OptionsPerMinute = 30
	}
	s := &Server{
		rp:    cfg.RP,
		store: cfg.Store,
		log:   cfg.Logger,
		pending: challenge.New[pending](challenge.Options{
			TTL: cfg.RP.Config().Timeout, MaxEntries: cfg.MaxPendingCeremonies, Now: cfg.Now,
		}),
		secure:   cfg.SecureCookies,
		now:      cfg.Now,
		randRead: rand.Read,
	}
	if cfg.OptionsPerMinute > 0 {
		s.limiter = newRateLimiter(cfg.OptionsPerMinute, time.Minute, cfg.Now)
	}
	return s, nil
}

// Handler returns the HTTP handler with all middleware applied.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(web.FS))
	mux.HandleFunc("GET /api/health", s.health)
	mux.Handle("POST /api/register/options", s.limited(s.jsonOnly(s.registerOptions)))
	mux.Handle("POST /api/register/verify", s.jsonOnly(s.registerVerify))
	mux.Handle("POST /api/login/options", s.limited(s.jsonOnly(s.loginOptions)))
	mux.Handle("POST /api/login/verify", s.jsonOnly(s.loginVerify))
	return s.recoverer(s.accessLog(securityHeaders(mux)))
}

// apiError is the JSON error body.
type apiError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiError{Error: code, Message: msg})
}

// decode reads a JSON body strictly: size-limited and a single value.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body exceeds 64 KiB")
			return false
		}
		writeError(w, http.StatusBadRequest, "bad_json", err.Error())
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "bad_json", "trailing data after JSON value")
		return false
	}
	return true
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	users, creds, err := s.store.Stats(r.Context())
	if err != nil {
		s.log.Error("health check failed", "err", err)
		writeError(w, http.StatusServiceUnavailable, "store_unavailable", "credential store unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "users": users, "credentials": creds, "pending_ceremonies": s.pending.Len()})
}

// validName accepts 1-64 printable, non-space-only characters.
func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	nonSpace := false
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
		if !unicode.IsSpace(r) {
			nonSpace = true
		}
	}
	return nonSpace
}

type registerOptionsRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
}

func (s *Server) registerOptions(w http.ResponseWriter, r *http.Request) {
	var req registerOptionsRequest
	if !decode(w, r, &req) {
		return
	}
	if req.DisplayName == "" {
		req.DisplayName = req.Username
	}
	if !validName(req.Username) || !validName(req.DisplayName) {
		writeError(w, http.StatusBadRequest, "invalid_username", "username and display name must be 1-64 printable characters")
		return
	}
	if _, err := s.store.UserByName(r.Context(), req.Username); err == nil {
		writeError(w, http.StatusConflict, "username_taken", "that username is already registered")
		return
	} else if !errors.Is(err, credstore.ErrNotFound) {
		s.internal(w, "user lookup", err)
		return
	}
	// The user handle is random, never derived from the username, so it
	// reveals nothing when authenticators store or sync it.
	handle := make([]byte, 32)
	if _, err := s.randRead(handle); err != nil {
		s.internal(w, "user handle", err)
		return
	}
	opts, sess, err := s.rp.BeginRegistration(webauthn.User{ID: handle, Name: req.Username, DisplayName: req.DisplayName}, nil)
	if err != nil {
		s.internal(w, "begin registration", err)
		return
	}
	if !s.startCeremony(w, pending{Session: *sess, DisplayName: req.DisplayName}) {
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

func (s *Server) registerVerify(w http.ResponseWriter, r *http.Request) {
	var resp webauthn.RegistrationResponseJSON
	if !decode(w, r, &resp) {
		return
	}
	p, ok := s.takeCeremony(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	res, err := s.rp.FinishRegistration(&p.Session, &resp, func(id []byte) (bool, error) { return s.store.CredentialExists(ctx, id) })
	if err != nil {
		s.verifyFailed(w, http.StatusBadRequest, err)
		return
	}
	user := credstore.User{Handle: p.Session.UserHandle, Name: p.Session.UserName, DisplayName: p.DisplayName, CreatedAt: s.now()}
	switch err := s.store.RegisterUser(ctx, user, res.Credential); {
	case errors.Is(err, credstore.ErrUserExists):
		writeError(w, http.StatusConflict, "username_taken", "that username was registered concurrently")
		return
	case errors.Is(err, credstore.ErrDuplicateCredential):
		writeError(w, http.StatusConflict, string(webauthn.CheckCredentialUnique), "credential ID is already registered")
		return
	case err != nil:
		s.internal(w, "store registration", err)
		return
	}
	c := res.Credential
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "ok",
		"username":       user.Name,
		"credentialId":   webauthn.EncodeURL(c.ID),
		"algorithm":      c.Algorithm.String(),
		"attestation":    string(c.AttestationType),
		"trusted":        c.AttestationTrusted,
		"aaguid":         c.AAGUIDString(),
		"backupEligible": c.BackupEligible,
		"signCount":      c.SignCount,
	})
}

type loginOptionsRequest struct {
	Username string `json:"username"`
}

func (s *Server) loginOptions(w http.ResponseWriter, r *http.Request) {
	var req loginOptionsRequest
	if !decode(w, r, &req) {
		return
	}
	// The options never list credentials (allowCredentials is always
	// empty), so the response is the same whether or not the username
	// exists and hands out no credential IDs. The username is bound on the
	// server side instead: the session carries the account's user handle,
	// and FinishLogin rejects an assertion from any credential that account
	// does not own. An unknown username is bound to a fresh random handle
	// that owns nothing, so it fails the same check as somebody else's
	// passkey. This relies on discoverable credentials, which New enforces.
	var handle []byte
	if req.Username != "" {
		u, err := s.store.UserByName(r.Context(), req.Username)
		switch {
		case err == nil:
			handle = u.Handle
		case errors.Is(err, credstore.ErrNotFound):
			handle = make([]byte, 32)
			if _, err := s.randRead(handle); err != nil {
				s.internal(w, "user handle", err)
				return
			}
		default:
			s.internal(w, "user lookup", err)
			return
		}
	}
	opts, sess, err := s.rp.BeginLogin(handle, nil)
	if err != nil {
		s.internal(w, "begin login", err)
		return
	}
	if !s.startCeremony(w, pending{Session: *sess}) {
		return
	}
	writeJSON(w, http.StatusOK, opts)
}

func (s *Server) loginVerify(w http.ResponseWriter, r *http.Request) {
	var resp webauthn.AuthenticationResponseJSON
	if !decode(w, r, &resp) {
		return
	}
	p, ok := s.takeCeremony(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	lookup := func(id []byte) (*webauthn.Credential, error) {
		c, err := s.store.Credential(ctx, id)
		if errors.Is(err, credstore.ErrNotFound) {
			return nil, nil
		}
		return c, err
	}
	res, err := s.rp.FinishLogin(&p.Session, &resp, lookup)
	if err != nil {
		if webauthn.CheckOf(err) == webauthn.CheckSignCount {
			if ferr := s.store.FlagClone(ctx, resp.RawID); ferr != nil {
				s.log.Error("flag clone", "err", ferr)
			}
			s.log.Warn("possible cloned authenticator", "credential", webauthn.EncodeURL(resp.RawID))
		}
		s.verifyFailed(w, http.StatusUnauthorized, err)
		return
	}
	switch err := s.store.UpdateAfterLogin(ctx, res.Credential, res.PreviousSignCount); {
	case errors.Is(err, credstore.ErrConcurrentUpdate):
		writeError(w, http.StatusConflict, "concurrent_login", "the credential was used concurrently; try again")
		return
	case err != nil:
		s.internal(w, "update credential", err)
		return
	}
	u, err := s.store.UserByHandle(ctx, res.Credential.UserHandle)
	if err != nil {
		s.internal(w, "user lookup", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":       "ok",
		"username":     u.Name,
		"displayName":  u.DisplayName,
		"credentialId": webauthn.EncodeURL(res.Credential.ID),
		"signCount":    res.Credential.SignCount,
		"userVerified": res.UserVerified,
		"backupState":  res.Credential.BackupState,
		"cloneWarning": res.CloneWarning,
	})
}

// startCeremony stores p and sets the ceremony cookie.
func (s *Server) startCeremony(w http.ResponseWriter, p pending) bool {
	key, _, err := s.pending.Put(p)
	if errors.Is(err, challenge.ErrFull) {
		writeError(w, http.StatusServiceUnavailable, "too_many_ceremonies", "too many sign-in attempts in flight; retry shortly")
		return false
	}
	if err != nil {
		s.internal(w, "store ceremony", err)
		return false
	}
	// Secure is configurable only so http://localhost development works;
	// the CLI enables it whenever an https origin is configured.
	http.SetCookie(w, &http.Cookie{ //nolint:gosec // G124: see comment above
		// MaxAge (relative) rather than Expires (absolute) so client clock
		// skew cannot drop or extend the cookie; the server-side entry
		// enforces the real deadline.
		Name: CeremonyCookie, Value: key, Path: "/api/", MaxAge: int(s.pending.TTL().Seconds()),
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode,
	})
	return true
}

// takeCeremony consumes the ceremony named by the cookie (single use) and
// clears the cookie.
func (s *Server) takeCeremony(w http.ResponseWriter, r *http.Request) (pending, bool) {
	c, err := r.Cookie(CeremonyCookie)
	if err != nil {
		writeError(w, http.StatusBadRequest, string(webauthn.CheckSession), "no ceremony in progress")
		return pending{}, false
	}
	http.SetCookie(w, &http.Cookie{Name: CeremonyCookie, Value: "", Path: "/api/", MaxAge: -1, //nolint:gosec // G124: clearing cookie, same attributes as above
		HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode})
	p, err := s.pending.Take(c.Value)
	if err != nil {
		writeError(w, http.StatusBadRequest, string(webauthn.CheckSession), "ceremony expired or already completed")
		return pending{}, false
	}
	return p, true
}

func (s *Server) verifyFailed(w http.ResponseWriter, status int, err error) {
	check := webauthn.CheckOf(err)
	if check == "" {
		s.internal(w, "verify", err)
		return
	}
	writeError(w, status, string(check), err.Error())
}

func (s *Server) internal(w http.ResponseWriter, what string, err error) {
	s.log.Error("internal error", "op", what, "err", err)
	writeError(w, http.StatusInternalServerError, "internal", fmt.Sprintf("%s failed", what))
}
