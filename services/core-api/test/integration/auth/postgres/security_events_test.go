package integration_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/password"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

// TestSecurityEventsRecordWhatHappenedAndNothingElse keeps credentials, tokens
// and fingerprints out of the event trail.
func TestSecurityEventsRecordWhatHappenedAndNothingElse(t *testing.T) {
	store, pool := freshStore(t)
	now := time.Now().UTC()
	account := newAccountAt(t, store, now, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
	sess, token := openSession(t, store, account.ID, iam.SurfacePublic, now.Add(time.Second))

	const secret = "s3cr3t-event-probe"
	if err := store.SetPassword(context.Background(), account.ID, password.NewEncoded("$argon2id$v=19$m=19456,t=2,p=1$BBBBBBBBBBBBBBBBBBBBBB$"+strings.Repeat("B", 43)), now.Add(time.Minute)); err != nil {
		t.Fatalf("changing the credential failed: %v", err)
	}
	if err := store.RevokeSession(context.Background(), sess.ID, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("revoking failed: %v", err)
	}
	if err := store.Suspend(context.Background(), account.ID, now.Add(3*time.Minute)); err != nil {
		t.Fatalf("suspending failed: %v", err)
	}

	events, err := store.Events(context.Background(), account.ID)
	if err != nil {
		t.Fatalf("reading events failed: %v", err)
	}
	want := []string{"credential_created", "session_created", "credential_changed", "session_revoked", "account_suspended"}
	if len(events) != len(want) {
		t.Fatalf("recorded %d events, want %d: %+v", len(events), len(want), events)
	}
	for i, kind := range want {
		if events[i].Kind != kind {
			t.Errorf("event %d is %q, want %q", i, events[i].Kind, kind)
		}
	}

	// The whole event table is searched for anything it must never hold.
	const dump = `SELECT coalesce(string_agg(kind || ' ' || coalesce(account_id::text, '') || ' ' || coalesce(session_id::text, ''), ' '), '')
		FROM account_security_events`
	var recorded string
	if err := pool.QueryRow(context.Background(), dump).Scan(&recorded); err != nil {
		t.Fatalf("reading the event table failed: %v", err)
	}
	for label, forbidden := range map[string]string{
		"the session token":   token.Reveal(),
		"a probe secret":      secret,
		"an encoded password": "$argon2id$",
	} {
		if strings.Contains(recorded, forbidden) {
			t.Errorf("the event trail carries %s", label)
		}
	}
}
