package session_test

import (
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/auth/session"
	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
)

func lifetimes() session.Lifetimes {
	return session.Lifetimes{Absolute: 12 * time.Hour, Idle: 30 * time.Minute, ActivityInterval: time.Minute}
}

func mustAccount(t *testing.T) iam.AccountID {
	t.Helper()
	id, err := iam.NewAccountID()
	if err != nil {
		t.Fatalf("drawing an account identifier failed: %v", err)
	}
	return id
}

func issue(t *testing.T, now time.Time) (session.Session, session.Token) {
	t.Helper()
	sess, token, err := session.Issue(mustAccount(t), iam.KindViewer, iam.SurfacePublic, lifetimes(), now)
	if err != nil {
		t.Fatalf("issuing a session failed: %v", err)
	}
	return sess, token
}

// issuedCSRF takes a CSRF token from a throwaway session, the only way this
// package hands one out.
func issuedCSRF(t *testing.T) session.CSRFToken {
	t.Helper()
	sess, _ := issue(t, time.Unix(1_700_000_000, 0).UTC())
	return sess.CSRF
}

func viewerKind() iam.Kind { return iam.KindViewer }

func operatorKind() iam.Kind { return iam.KindOperator }

func zeroAccount() iam.AccountID { return iam.AccountID{} }
