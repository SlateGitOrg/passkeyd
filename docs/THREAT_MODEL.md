# Threat model

Scope: the `webauthn` library and the `passkeyd serve` HTTP front end, deployed
as a single relying party (RP) with its own SQLite database. All demos and
tests run against local fixtures and software authenticators. None of them
touches third-party systems.

## Assets

| Asset | Why it matters |
|---|---|
| Account control | A successful assertion means "this user is present" |
| Credential records (public key, counter, flags, user handle) | Tampering with them enables impersonation or blocks a user out; they contain no secrets |
| Ceremony state (challenge, expected user) | If it leaks or can be replayed, freshness is gone |
| Server availability | Logins depend on it |
| User privacy (usernames, account existence) | Enumeration helps phishing |

## Trust boundaries

1. **Browser to server.** Every byte of the JSON body is attacker-controlled.
   This includes clientDataJSON, the attestation object, authenticator data
   and the signature.
2. **Authenticator to browser.** The RP cannot trust the authenticator's
   output except through signatures and, optionally, attestation chains.
3. **Server to SQLite file.** The database is trusted. Anyone who can write
   it can register keys.
4. **Operator configuration.** The RP ID, origins and trust anchors are
   trusted inputs.

## Threats and mitigations

| # | Threat | Mitigation in passkeyd | Test evidence |
|---|---|---|---|
| T1 | **Phishing / relay from a look-alike origin** | Exact origin allow-list (`origin_mismatch`). The browser scopes credentials to the RP ID, and the RP checks `rpIdHash == SHA-256(rpId)` (`rp_id_hash_mismatch`). Config refuses origins that are not on the RP ID, and refuses plain http except on localhost | `phishing origin`, `wrong RP ID` (negative tests and demo) |
| T2 | **Replay of a captured response** | Challenges are 32 random bytes and the challenge store is single-use (`Take` deletes). The cookie is cleared on use, the challenge is compared in constant time, and there is a TTL in both the store and `SessionData.Expires` | `replayed assertion`, `replay, same cookie`, `replay, new ceremony`, `expired session` |
| T3 | **Cross-origin iframe abuse** | `crossOrigin` is rejected unless enabled; `topOrigin` must be on an allow-list | `cross-origin iframe`, `unexpected top origin` |
| T4 | **Cloned or extracted authenticator** | Signature counter must strictly increase when either side is non-zero (`sign_count_regression`). The server flags the credential (`clone_warning=1`) | `cloned authenticator counter regression`, demo §3 |
| T5 | **Concurrent replay racing the counter** | Compare-and-swap on `sign_count` in SQLite. The loser gets 409 | `TestConcurrentCounterRace`, `TestUpdateAfterLoginCompareAndSwap` |
| T6 | **Signature forgery or authenticator data tampering** | Signature over `authData ‖ SHA-256(clientDataJSON)` with the stored key. ECDSA must be DER; key and algorithm consistency is enforced | `tampered signature`, `authData edited after signing` |
| T7 | **UV downgrade** (malware clears UV) | `UserVerification: required` enforces the UV flag in both ceremonies | `user not verified when required` |
| T8 | **Backup-flag manipulation** | BS without BE is rejected; BE may not change after registration; optional device-bound policy | `BS without BE`, `BE flag changed`, `synced credential under device-bound policy` |
| T9 | **Credential substitution** (assertion from another user's credential) | The session's user must own the credential (the HTTP server binds the username this way); a returned userHandle must own it; discoverable logins require a userHandle; library callers may also pass an allow-list | `credential of another user`, `userHandle of another user`, `credential outside allowCredentials` |
| T10 | **Credential ID collision or takeover at registration** | rawId must equal the attested ID; IDs are globally unique (checked in the RP and enforced by a PRIMARY KEY) | `rawId differs from attested ID`, `credential ID already registered` |
| T11 | **Malicious CBOR or COSE input** (parser crash, memory blow-up, CPU blow-up) | Length checks before allocation, depth and item limits, O(k) duplicate detection, a 64 KiB body cap, UTF-8 validation, and rejection of trailing data | `TestDecodeErrors`, `TestLargeMapDuplicateDetection`, 4 fuzz targets |
| T12 | **Fake attestation** (claims to be a certified authenticator) | x5c structure checks (§8.2.1), AAGUID binding, chain verification against operator-supplied anchors, `RequireTrusted` | `cert *` cases, `x5c not chaining to anchors`, `cert AAGUID differs` |
| T13 | **CSRF on ceremony endpoints** | `Content-Type: application/json` is required, and a cross-site request with that type needs a CORS preflight, which the server never approves. Cookies are `SameSite=Strict` | `TestRequestValidation` (415 case) |
| T14 | **XSS on the demo page** | CSP `default-src 'self'` with no inline script or style. Results are written with `textContent` only. `frame-ancestors 'none'` blocks clickjacking | `TestStaticPageAndHeaders` |
| T15 | **Session fixation** | The ceremony key is generated by the server; a client-chosen value matches nothing in the store | by construction (`challenge.Store.Put`) |
| T16 | **DoS by starting many ceremonies** | Per-IP token bucket (default 30 per minute), a store capacity cap (503 rather than evicting someone's ceremony), lazy expiry | `TestRateLimitAndCapacity`, `TestSweepAndCapacity` |
| T17 | **Account enumeration via login** | Login options never list credentials: `allowCredentials` is empty for every username, so options for an existing and an unknown account are identical and reveal no credential IDs. The username is bound on the server: the session carries the account's user handle (an unknown name gets a random handle that owns nothing), so another person's passkey fails with `user_handle_mismatch` for both. The server requires `ResidentKey: required` so every credential can sign in without being listed | `TestLoginDoesNotEnumerateAccounts`, `TestNewRequiresDiscoverableCredentials` |
| T18 | **Database disclosure** | Only public keys and metadata are stored, so they cannot be replayed as passwords can. User handles are random, not derived from usernames | design |
| T19 | **Error-message oracle** | Errors name the failing check, but checks run in a fixed order and none of them reveals secret data. The challenge comparison is constant-time | design |

## Residual risks and non-goals

- **Registration reveals whether a username exists** (`username_taken`). This
  is inherent to a self-service sign-up flow. Deployments that care should add
  email verification or rate limiting by account.
- **Login timing may differ slightly between existing and unknown
  usernames.** The two paths do the same single indexed lookup and return
  identical options, but no constant-time guarantee is made across a database
  hit and a miss. With registration already revealing names, this is not
  worth more machinery.
- **Non-discoverable credentials cannot sign in through the HTTP server.**
  Because login options never list credentials (T17), the server requires
  `ResidentKey: required`; an authenticator that cannot store a discoverable
  credential fails at registration. The library still supports allow-list
  logins for callers that accept the enumeration trade-off.
- **Synced passkeys report a counter of 0**, so T4 gives no signal for them.
  Detection then depends on the passkey provider.
- **Attestation trust is only as good as the anchors** the operator supplies.
  There is no FIDO MDS revocation or status checking.
- **No login session.** After a successful assertion the server returns JSON
  and keeps no session. Session management, account recovery and step-up
  authentication are outside this project.
- **Behind a reverse proxy**, per-IP rate limiting sees a single IP, because
  `X-Forwarded-For` is deliberately not trusted.
- **Compromised client device or browser.** A malicious browser can drive the
  user's authenticator for the real origin. WebAuthn does not defend against
  that, and neither does passkeyd.
- **TLS termination** is the operator's job. The CLI marks cookies Secure when
  an https origin is configured, but it does not serve TLS itself.
- **Software authenticator keys** (`virtualauthn`) live in process memory. The
  package exists for tests and labs and must never protect a real account.
