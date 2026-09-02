package integration_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// TestTheRawTokenNeverReachesTheDatabase is the storage half of the session rule.
func TestTheRawTokenNeverReachesTheDatabase(t *testing.T) {
	store, pool := freshStore(t)
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	_, token := openSession(t, store, account.ID, iam.SurfacePublic, time.Now().UTC())

	// Every text column of every table is searched for the token.
	const query = `SELECT string_agg(value, ' ') FROM (
		SELECT id::text AS value FROM account_sessions
		UNION ALL SELECT encode(token_fingerprint, 'base64') FROM account_sessions
		UNION ALL SELECT encode(token_fingerprint, 'hex') FROM account_sessions
		UNION ALL SELECT surface FROM account_sessions
		UNION ALL SELECT address FROM account_email_identities
		UNION ALL SELECT encoded_hash FROM account_password_credentials
		UNION ALL SELECT kind FROM account_security_events
	) AS everything`
	var stored *string
	if err := pool.QueryRow(context.Background(), query).Scan(&stored); err != nil {
		t.Fatalf("reading the database failed: %v", err)
	}
	if stored != nil && strings.Contains(*stored, token.Reveal()) {
		t.Fatal("the raw token is stored in the database")
	}

	var fingerprint []byte
	if err := pool.QueryRow(context.Background(), `SELECT token_fingerprint FROM account_sessions`).Scan(&fingerprint); err != nil {
		t.Fatalf("reading the fingerprint failed: %v", err)
	}
	if len(fingerprint) != 32 {
		t.Fatalf("the stored fingerprint is %d bytes", len(fingerprint))
	}
	// A truncation would store a prefix of the token rather than a digest of it.
	if bytes.HasPrefix([]byte(token.Reveal()), fingerprint) {
		t.Fatal("the stored value is a prefix of the token, not a digest of it")
	}

	// Two tokens differing only in their last byte must not share a stored value.
	// A prefix or truncation would give them the same one.
	body := make([]byte, 32) // the adopted token size, restated here
	for i := range body {
		body[i] = byte(i)
	}
	first, err := session.ParseToken(base64.RawURLEncoding.EncodeToString(body))
	if err != nil {
		t.Fatalf("building a probe token failed: %v", err)
	}
	body[len(body)-1] ^= 0xff
	second, err := session.ParseToken(base64.RawURLEncoding.EncodeToString(body))
	if err != nil {
		t.Fatalf("building a probe token failed: %v", err)
	}
	if first.Fingerprint() == second.Fingerprint() {
		t.Fatal("two tokens differing at the end share a stored value; the whole token is not digested")
	}
}

func TestAnUnknownTokenResolvesToNothing(t *testing.T) {
	store, _ := freshStore(t)
	_, stranger := drawn(t)
	if _, err := store.Resolve(context.Background(), stranger, time.Now().UTC()); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatalf("got %v, want nothing usable", err)
	}
}

func TestAResolvedSessionCarriesTheAuthorityHeldRightNow(t *testing.T) {
	store, _ := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, iam.KindCreator, iam.StatusActive, iam.RoleViewer, iam.RoleCreator)
	_, token := openSession(t, store, account.ID, iam.SurfacePublic, now)

	resolved, err := store.Resolve(context.Background(), token, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("a live session was refused: %v", err)
	}
	if resolved.Principal.Account != account.ID || resolved.Principal.Surface != iam.SurfacePublic {
		t.Fatalf("the principal is %+v", resolved.Principal)
	}
	if err := iam.Authorize(resolved.Principal, iam.PermissionStreamBroadcast); err != nil {
		t.Errorf("a creator was refused its own permission: %v", err)
	}
	if err := iam.Authorize(resolved.Principal, iam.PermissionPayoutRead); !errors.Is(err, iam.ErrDenied) {
		t.Error("a creator session obtained an operator permission")
	}
}

// TestGrantsAreReadAgainOnEveryResolution keeps a session from carrying an
// authority the account no longer holds.
func TestGrantsAreReadAgainOnEveryResolution(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, iam.KindCreator, iam.StatusActive, iam.RoleViewer, iam.RoleCreator)
	_, token := openSession(t, store, account.ID, iam.SurfacePublic, now)

	before, err := store.Resolve(context.Background(), token, now)
	if err != nil {
		t.Fatalf("resolving failed: %v", err)
	}
	if err := iam.Authorize(before.Principal, iam.PermissionStreamBroadcast); err != nil {
		t.Fatalf("the creator permission was missing before the change: %v", err)
	}

	const revoke = `DELETE FROM account_role_grants WHERE account_id = $1 AND role = 'creator'`
	if _, err := pool.Exec(context.Background(), revoke, account.ID.String()); err != nil {
		t.Fatalf("removing the grant failed: %v", err)
	}

	after, err := store.Resolve(context.Background(), token, now)
	if err != nil {
		t.Fatalf("the session stopped resolving after a grant was removed: %v", err)
	}
	if err := iam.Authorize(after.Principal, iam.PermissionStreamBroadcast); !errors.Is(err, iam.ErrDenied) {
		t.Fatal("the removed grant is still carried by the live session")
	}
	if err := iam.Authorize(after.Principal, iam.PermissionOwnSessionRenew); err != nil {
		t.Errorf("the remaining grant was lost: %v", err)
	}
}

func TestAnExpiredSessionResolvesToNothing(t *testing.T) {
	store, _ := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	sess, token := openSession(t, store, account.ID, iam.SurfacePublic, now)

	if _, err := store.Resolve(context.Background(), token, sess.IdleExpiresAt); !errors.Is(err, authstore.ErrNotFound) {
		t.Error("a session was accepted at its idle expiry")
	}
	if _, err := store.Resolve(context.Background(), token, sess.AbsoluteExpiresAt); !errors.Is(err, authstore.ErrNotFound) {
		t.Error("a session was accepted at its absolute expiry")
	}
}

func TestRevokingOneSessionLeavesTheOthersAlone(t *testing.T) {
	store, _ := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	first, firstToken := openSession(t, store, account.ID, iam.SurfacePublic, now)
	_, secondToken := openSession(t, store, account.ID, iam.SurfacePublic, now)

	if err := store.RevokeSession(context.Background(), first.ID, now.Add(time.Minute)); err != nil {
		t.Fatalf("revoking failed: %v", err)
	}
	if _, err := store.Resolve(context.Background(), firstToken, now.Add(2*time.Minute)); !errors.Is(err, authstore.ErrNotFound) {
		t.Error("a revoked session still resolves")
	}
	if _, err := store.Resolve(context.Background(), secondToken, now.Add(2*time.Minute)); err != nil {
		t.Errorf("revoking one session affected another: %v", err)
	}
	if err := store.RevokeSession(context.Background(), first.ID, now.Add(3*time.Minute)); !errors.Is(err, authstore.ErrNotFound) {
		t.Error("revoking twice reported success the second time")
	}
}

func TestRevokingEveryLiveSessionOfAnAccountIsImmediate(t *testing.T) {
	store, _ := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	other := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)

	var tokens []session.Token
	for range 4 {
		_, token := openSession(t, store, account.ID, iam.SurfacePublic, now)
		tokens = append(tokens, token)
	}
	_, spared := openSession(t, store, other.ID, iam.SurfacePublic, now)

	affected, err := store.RevokeAccountSessions(context.Background(), account.ID, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("revoking failed: %v", err)
	}
	if affected != 4 {
		t.Fatalf("%d sessions were revoked, want 4", affected)
	}
	for i, token := range tokens {
		if _, err := store.Resolve(context.Background(), token, now.Add(2*time.Minute)); !errors.Is(err, authstore.ErrNotFound) {
			t.Errorf("session %d still resolves after a global revocation", i)
		}
	}
	if _, err := store.Resolve(context.Background(), spared, now.Add(2*time.Minute)); err != nil {
		t.Errorf("another account's session was revoked: %v", err)
	}
}

// TestASurfaceIsAlwaysBoundToTheAccountKindAtEveryBoundary applies the matrix at
// creation, at session creation and at resolution rather than trusting a caller.
func TestASurfaceIsAlwaysBoundToTheAccountKindAtEveryBoundary(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()

	// A non-operator account may not be granted an operator role.
	address, err := iam.NormaliseEmail("kind-probe@example.com")
	if err != nil {
		t.Fatalf("normalising failed: %v", err)
	}
	_, err = store.CreateAccount(context.Background(), authstore.NewAccount{
		Kind: iam.KindCreator, Status: iam.StatusActive, Email: address,
		Roles: []iam.Role{iam.RoleOperatorFinance},
	}, now)
	if !errors.Is(err, iam.ErrInvalid) {
		t.Fatalf("a creator account was granted an operator role: %v", err)
	}

	viewer := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	operator := newAccount(t, store, iam.KindOperator, iam.StatusActive, iam.RoleOperatorFinance)

	// A viewer account may not open an operator session, whichever path is used.
	if _, _, err := session.Issue(viewer.ID, iam.KindViewer, iam.SurfaceOperator, lifetimes(), now); err == nil {
		t.Error("a viewer account issued an operator session")
	}
	handmade := mustSession(t, viewer.ID, now)
	handmade.Surface = iam.SurfaceOperator
	if _, err := store.ReplaceSession(context.Background(), nil, handmade, password.FirstRevision, handmade.CreatedAt); err == nil {
		t.Error("the store accepted an operator session for a viewer account")
	}

	// An operator session resolves to operator authority, and to nothing public.
	_, operatorToken := openSession(t, store, operator.ID, iam.SurfaceOperator, now)
	resolved, err := store.Resolve(context.Background(), operatorToken, now)
	if err != nil {
		t.Fatalf("an operator session was refused: %v", err)
	}
	if err := iam.Authorize(resolved.Principal, iam.PermissionPayoutRead); err != nil {
		t.Errorf("an operator was refused its own permission: %v", err)
	}
	if err := iam.Authorize(resolved.Principal, iam.PermissionStreamBroadcast); !errors.Is(err, iam.ErrDenied) {
		t.Error("an operator session carried a public permission")
	}

	// A row written straight into the database with an impossible surface is
	// refused on resolution, whatever wrote it.
	sess, token := openSession(t, store, viewer.ID, iam.SurfacePublic, now)
	const forge = `UPDATE account_sessions SET surface = 'operator' WHERE id = $1`
	if _, err := pool.Exec(context.Background(), forge, sess.ID.String()); err != nil {
		t.Fatalf("forging the row failed: %v", err)
	}
	if _, err := store.Resolve(context.Background(), token, now); !errors.Is(err, authstore.ErrNotFound) {
		t.Fatal("a forged operator session for a viewer account resolved")
	}
}

// TestNoWritePathStoresAnInvalidSessionRecord: creation and rotation refuse the same
// session shapes, and a refused rotation leaves the predecessor usable.
func TestNoWritePathStoresAnInvalidSessionRecord(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	operator := newAccount(t, store, iam.KindOperator, iam.StatusActive, iam.RoleOperatorFinance)

	revoked := now.Add(-time.Minute)
	successorIDSession, _ := drawn(t)
	successorID := successorIDSession.ID

	cases := map[string]func(s *session.Session){
		"zero session identifier":       func(s *session.Session) { s.ID = session.ID{} },
		"zero account":                  func(s *session.Session) { s.Account = iam.AccountID{} },
		"zero fingerprint":              func(s *session.Session) { s.Fingerprint = session.Fingerprint{} },
		"already revoked":               func(s *session.Session) { s.RevokedAt = &revoked },
		"already rotated":               func(s *session.Session) { s.RotatedTo = &successorID },
		"zero creation instant":         func(s *session.Session) { s.CreatedAt = time.Time{} },
		"zero activity instant":         func(s *session.Session) { s.LastActiveAt = time.Time{} },
		"zero idle expiry":              func(s *session.Session) { s.IdleExpiresAt = time.Time{} },
		"zero absolute expiry":          func(s *session.Session) { s.AbsoluteExpiresAt = time.Time{} },
		"activity before creation":      func(s *session.Session) { s.LastActiveAt = s.CreatedAt.Add(-time.Hour) },
		"idle expiry before creation":   func(s *session.Session) { s.IdleExpiresAt = s.CreatedAt.Add(-time.Hour) },
		"idle expiry at the activity":   func(s *session.Session) { s.IdleExpiresAt = s.LastActiveAt },
		"absolute expiry at creation":   func(s *session.Session) { s.AbsoluteExpiresAt = s.CreatedAt },
		"idle beyond absolute":          func(s *session.Session) { s.IdleExpiresAt = s.AbsoluteExpiresAt.Add(time.Hour) },
		"unknown surface":               func(s *session.Session) { s.Surface = "edge" },
		"empty surface":                 func(s *session.Session) { s.Surface = "" },
		"surface the kind may not open": func(s *session.Session) { s.Surface = iam.SurfaceOperator },
		"account of another kind":       func(s *session.Session) { s.Account = operator.ID },
	}

	for name, tamper := range cases {
		t.Run("creation refuses "+name, func(t *testing.T) {
			sess := mustSession(t, account.ID, now)
			tamper(&sess)
			if _, err := store.ReplaceSession(context.Background(), nil, sess, password.FirstRevision, sess.CreatedAt); err == nil {
				t.Fatal("the record was stored")
			}
			assertNoSuccessorStored(t, pool, sess.ID)
		})

		t.Run("rotation refuses "+name, func(t *testing.T) {
			previous, previousToken := openSession(t, store, account.ID, iam.SurfacePublic, now)
			successor := mustSession(t, account.ID, now.Add(time.Minute))
			tamper(&successor)

			if err := store.Rotate(context.Background(), previous.ID, successor, successor.CreatedAt); err == nil {
				t.Fatal("the rotation was accepted")
			}
			assertNoSuccessorStored(t, pool, successor.ID)
			if _, err := store.Resolve(context.Background(), previousToken, now.Add(2*time.Minute)); err != nil {
				t.Fatalf("a refused rotation invalidated the predecessor: %v", err)
			}
			assertNoRotationEvent(t, pool, account.ID)
		})
	}
}

// TestASessionAlreadyUnusableAtItsOwnCreationIsRefused covers the record that
// would otherwise be stored dead, taking its predecessor with it.
func TestASessionAlreadyUnusableAtItsOwnCreationIsRefused(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	previous, previousToken := openSession(t, store, account.ID, iam.SurfacePublic, now)

	// Both expiries are in the past relative to the record's own creation.
	dead := mustSession(t, account.ID, now.Add(time.Minute))
	dead.CreatedAt = now.Add(time.Hour)
	dead.LastActiveAt = dead.CreatedAt

	if err := store.Rotate(context.Background(), previous.ID, dead, dead.CreatedAt); err == nil {
		t.Fatal("a session already past both expiries was stored by a rotation")
	}
	assertNoSuccessorStored(t, pool, dead.ID)
	if _, err := store.Resolve(context.Background(), previousToken, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("the predecessor was invalidated: %v", err)
	}
}
