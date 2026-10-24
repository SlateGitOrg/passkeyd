// Package credstore persists users and WebAuthn credential records in
// SQLite (via the pure-Go modernc.org/sqlite driver, so no cgo is needed).
//
// Signature counters are updated with compare-and-swap semantics: an update
// only applies if the stored counter still equals the value the ceremony
// verified against, so two concurrent logins that replay the same counter
// cannot both succeed.
package credstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/archit2501/passkeyd/cose"
	"github.com/archit2501/passkeyd/webauthn"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// Errors.
var (
	ErrNotFound            = errors.New("credstore: not found")
	ErrUserExists          = errors.New("credstore: user name already taken")
	ErrDuplicateCredential = errors.New("credstore: credential ID already registered")
	ErrConcurrentUpdate    = errors.New("credstore: credential changed concurrently")
)

// User is an account.
type User struct {
	Handle      []byte
	Name        string
	DisplayName string
	CreatedAt   time.Time
}

// Store is a SQLite-backed credential repository. It is safe for concurrent use.
type Store struct {
	db *sql.DB
}

// migrations are applied in order; the index+1 is the schema version.
var migrations = []string{
	`CREATE TABLE users (
		handle       BLOB PRIMARY KEY,
		name         TEXT NOT NULL UNIQUE,
		display_name TEXT NOT NULL,
		created_at   INTEGER NOT NULL
	);
	CREATE TABLE credentials (
		id                  BLOB PRIMARY KEY,
		user_handle         BLOB NOT NULL REFERENCES users(handle) ON DELETE CASCADE,
		public_key          BLOB NOT NULL,
		alg                 INTEGER NOT NULL,
		sign_count          INTEGER NOT NULL CHECK (sign_count BETWEEN 0 AND 4294967295),
		uv_initialized      INTEGER NOT NULL,
		backup_eligible     INTEGER NOT NULL,
		backup_state        INTEGER NOT NULL,
		transports          TEXT NOT NULL,
		aaguid              BLOB NOT NULL,
		attestation_format  TEXT NOT NULL,
		attestation_type    TEXT NOT NULL,
		attestation_trusted INTEGER NOT NULL,
		clone_warning       INTEGER NOT NULL DEFAULT 0,
		created_at          INTEGER NOT NULL,
		last_used_at        INTEGER NOT NULL
	);
	CREATE INDEX credentials_by_user ON credentials(user_handle);`,
}

// Open opens (creating if needed) the database at path and applies
// migrations. path ":memory:" gives a private in-memory database.
func Open(ctx context.Context, path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	if path != ":memory:" {
		dsn += "&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("credstore: open: %w", err)
	}
	if path == ":memory:" {
		// Each connection would otherwise get its own empty database.
		db.SetMaxOpenConns(1)
	}
	s := &Store{db: db}
	if err := s.migrate(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("credstore: migrate: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("credstore: read schema version: %w", err)
	}
	if version > len(migrations) {
		return fmt.Errorf("credstore: database schema version %d is newer than this binary (%d)", version, len(migrations))
	}
	for i := version; i < len(migrations); i++ {
		if _, err := tx.ExecContext(ctx, migrations[i]); err != nil {
			return fmt.Errorf("credstore: migration %d: %w", i+1, err)
		}
		if _, err := tx.ExecContext(ctx, fmt.Sprintf("PRAGMA user_version = %d", i+1)); err != nil {
			return fmt.Errorf("credstore: set schema version: %w", err)
		}
	}
	return tx.Commit()
}

func millis(t time.Time) int64 { return t.UnixMilli() }

func fromMillis(ms int64) time.Time { return time.UnixMilli(ms).UTC() }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// isUnique reports a UNIQUE / PRIMARY KEY constraint violation.
func isUnique(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func insertUser(ctx context.Context, e execer, u User) error {
	_, err := e.ExecContext(ctx, `INSERT INTO users(handle, name, display_name, created_at) VALUES (?, ?, ?, ?)`,
		u.Handle, u.Name, u.DisplayName, millis(u.CreatedAt))
	if isUnique(err) {
		return ErrUserExists
	}
	if err != nil {
		return fmt.Errorf("credstore: insert user: %w", err)
	}
	return nil
}

func insertCredential(ctx context.Context, e execer, c webauthn.Credential) error {
	_, err := e.ExecContext(ctx, `INSERT INTO credentials(
		id, user_handle, public_key, alg, sign_count, uv_initialized, backup_eligible, backup_state,
		transports, aaguid, attestation_format, attestation_type, attestation_trusted, clone_warning,
		created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.ID, c.UserHandle, c.PublicKey, int64(c.Algorithm), int64(c.SignCount), b2i(c.UVInitialized),
		b2i(c.BackupEligible), b2i(c.BackupState), strings.Join(c.Transports, ","), c.AAGUID[:],
		c.AttestationFormat, string(c.AttestationType), b2i(c.AttestationTrusted), b2i(c.CloneWarning),
		millis(c.CreatedAt), millis(c.LastUsedAt))
	if isUnique(err) {
		return ErrDuplicateCredential
	}
	if err != nil {
		return fmt.Errorf("credstore: insert credential: %w", err)
	}
	return nil
}

// CreateUser inserts a user. A taken name returns ErrUserExists.
func (s *Store) CreateUser(ctx context.Context, u User) error { return insertUser(ctx, s.db, u) }

// RegisterUser atomically creates a user together with their first
// credential, so a failed registration never leaves an account without a
// credential behind.
func (s *Store) RegisterUser(ctx context.Context, u User, c webauthn.Credential) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("credstore: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := insertUser(ctx, tx, u); err != nil {
		return err
	}
	if err := insertCredential(ctx, tx, c); err != nil {
		return err
	}
	return tx.Commit()
}

// AddCredential stores a credential for an existing user.
func (s *Store) AddCredential(ctx context.Context, c webauthn.Credential) error {
	return insertCredential(ctx, s.db, c)
}

const userCols = `handle, name, display_name, created_at`

func scanUser(row *sql.Row) (*User, error) {
	var (
		u  User
		ms int64
	)
	if err := row.Scan(&u.Handle, &u.Name, &u.DisplayName, &ms); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("credstore: scan user: %w", err)
	}
	u.CreatedAt = fromMillis(ms)
	return &u, nil
}

// UserByName looks a user up by name.
func (s *Store) UserByName(ctx context.Context, name string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE name = ?`, name))
}

// UserByHandle looks a user up by handle.
func (s *Store) UserByHandle(ctx context.Context, handle []byte) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE handle = ?`, handle))
}

const credCols = `id, user_handle, public_key, alg, sign_count, uv_initialized, backup_eligible, backup_state,
	transports, aaguid, attestation_format, attestation_type, attestation_trusted, clone_warning, created_at, last_used_at`

type scanner interface{ Scan(dest ...any) error }

func scanCredential(r scanner) (*webauthn.Credential, error) {
	var (
		c                              webauthn.Credential
		alg, count, created, used      int64
		uv, be, bs, trusted, clone     int
		transports, attFormat, attType string
		aaguid                         []byte
	)
	err := r.Scan(&c.ID, &c.UserHandle, &c.PublicKey, &alg, &count, &uv, &be, &bs,
		&transports, &aaguid, &attFormat, &attType, &trusted, &clone, &created, &used)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("credstore: scan credential: %w", err)
	}
	c.Algorithm = cose.Algorithm(alg)
	c.SignCount = uint32(count) //nolint:gosec // CHECK constraint bounds sign_count to uint32
	c.UVInitialized, c.BackupEligible, c.BackupState = uv == 1, be == 1, bs == 1
	if transports != "" {
		c.Transports = strings.Split(transports, ",")
	}
	copy(c.AAGUID[:], aaguid)
	c.AttestationFormat = attFormat
	c.AttestationType = webauthn.AttestationType(attType)
	c.AttestationTrusted, c.CloneWarning = trusted == 1, clone == 1
	c.CreatedAt, c.LastUsedAt = fromMillis(created), fromMillis(used)
	return &c, nil
}

// Credential returns the credential with the given ID.
func (s *Store) Credential(ctx context.Context, id []byte) (*webauthn.Credential, error) {
	return scanCredential(s.db.QueryRowContext(ctx, `SELECT `+credCols+` FROM credentials WHERE id = ?`, id))
}

// CredentialExists reports whether a credential ID is registered.
func (s *Store) CredentialExists(ctx context.Context, id []byte) (bool, error) {
	var n int
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM credentials WHERE id = ?`, id).Scan(&n); err != nil {
		return false, fmt.Errorf("credstore: exists: %w", err)
	}
	return n > 0, nil
}

// CredentialsByUser lists a user's credentials, oldest first.
func (s *Store) CredentialsByUser(ctx context.Context, handle []byte) ([]webauthn.Credential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+credCols+` FROM credentials WHERE user_handle = ? ORDER BY created_at, id`, handle)
	if err != nil {
		return nil, fmt.Errorf("credstore: list credentials: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []webauthn.Credential
	for rows.Next() {
		c, err := scanCredential(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("credstore: list credentials: %w", err)
	}
	return out, nil
}

// UpdateAfterLogin persists the post-login state of c (counter, flags, last
// use) only if the stored counter still equals prevSignCount. Otherwise it
// returns ErrConcurrentUpdate and the caller must treat the login as failed.
func (s *Store) UpdateAfterLogin(ctx context.Context, c webauthn.Credential, prevSignCount uint32) error {
	res, err := s.db.ExecContext(ctx, `UPDATE credentials
		SET sign_count = ?, backup_state = ?, uv_initialized = ?, clone_warning = ?, last_used_at = ?
		WHERE id = ? AND sign_count = ?`,
		int64(c.SignCount), b2i(c.BackupState), b2i(c.UVInitialized), b2i(c.CloneWarning), millis(c.LastUsedAt),
		c.ID, int64(prevSignCount))
	if err != nil {
		return fmt.Errorf("credstore: update credential: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("credstore: update credential: %w", err)
	}
	if n == 0 {
		if _, err := s.Credential(ctx, c.ID); errors.Is(err, ErrNotFound) {
			return ErrNotFound
		}
		return ErrConcurrentUpdate
	}
	return nil
}

// FlagClone marks a credential as suspected cloned.
func (s *Store) FlagClone(ctx context.Context, id []byte) error {
	return s.execOne(ctx, `UPDATE credentials SET clone_warning = 1 WHERE id = ?`, id)
}

// DeleteCredential removes a credential.
func (s *Store) DeleteCredential(ctx context.Context, id []byte) error {
	return s.execOne(ctx, `DELETE FROM credentials WHERE id = ?`, id)
}

func (s *Store) execOne(ctx context.Context, q string, args ...any) error {
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return fmt.Errorf("credstore: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return fmt.Errorf("credstore: %w", err)
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Stats returns the number of users and credentials.
func (s *Store) Stats(ctx context.Context) (users, credentials int, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM users), (SELECT count(*) FROM credentials)`).Scan(&users, &credentials)
	if err != nil {
		err = fmt.Errorf("credstore: stats: %w", err)
	}
	return users, credentials, err
}
