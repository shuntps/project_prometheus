package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// TestActivityAndReplacementDoNotDeadlockInEitherOrder is the same property for the
// operation that revokes a session while establishing its replacement.
func TestActivityAndReplacementDoNotDeadlockInEitherOrder(t *testing.T) {
	t.Run("activity holds the authority first", func(t *testing.T) {
		store, pool := freshStore(t)
		now := time.Now().UTC().Truncate(time.Second)
		account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
		sess, _ := openSession(t, store, account.ID, iam.SurfacePublic, now)
		successor := successorOf(t, sess, now.Add(10*time.Minute))
		ctx := context.Background()

		cyclesBefore := deadlocksBroken(t, pool)
		release, abandon := suspendSession(t, pool, sess.ID)
		defer abandon()

		activity := make(chan error, 1)
		go func() {
			_, err := store.RecordActivity(ctx, sess.ID, now.Add(10*time.Minute), lifetimes())
			activity <- err
		}()
		activityPID := waitForLockWait(t, activityLockFragment)

		replacement := make(chan error, 1)
		go func() {
			_, err := store.ReplaceSession(ctx, &sess.ID, successor, now.Add(10*time.Minute))
			replacement <- err
		}()
		replacementPID := waitForLockWait(t, authorityFragment)
		if activityPID == replacementPID {
			t.Fatalf("both operations were observed on one backend %d", activityPID)
		}

		release()
		activityErr, replacementErr := <-activity, <-replacement
		if broken := deadlocksBroken(t, pool) - cyclesBefore; broken != 0 {
			t.Fatalf("PostgreSQL broke %d lock cycle(s): %v / %v", broken, activityErr, replacementErr)
		}
		if activityErr != nil {
			t.Fatalf("the renewal that linearised first failed: %v", activityErr)
		}
		if replacementErr != nil {
			t.Fatalf("the replacement that followed failed: %v", replacementErr)
		}
		if revoked, _ := lifecycleOf(t, pool, sess.ID); !revoked {
			t.Error("the replaced session was left live")
		}
	})

	t.Run("replacement holds the authority first", func(t *testing.T) {
		store, pool := freshStore(t)
		now := time.Now().UTC().Truncate(time.Second)
		account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
		sess, _ := openSession(t, store, account.ID, iam.SurfacePublic, now)
		successor := successorOf(t, sess, now.Add(10*time.Minute))
		ctx := context.Background()

		cyclesBefore := deadlocksBroken(t, pool)
		release, abandon := suspendSession(t, pool, sess.ID)
		defer abandon()

		replacement := make(chan error, 1)
		go func() {
			_, err := store.ReplaceSession(ctx, &sess.ID, successor, now.Add(10*time.Minute))
			replacement <- err
		}()
		replacementPID := waitForLockWait(t, revocationFragment)

		activity := make(chan error, 1)
		go func() {
			_, err := store.RecordActivity(ctx, sess.ID, now.Add(10*time.Minute), lifetimes())
			activity <- err
		}()
		activityPID := waitForLockWait(t, authorityFragment)
		if activityPID == replacementPID {
			t.Fatalf("both operations were observed on one backend %d", activityPID)
		}
		activeBefore, idleBefore, _ := deadlines(t, pool, sess.ID)

		release()
		replacementErr, activityErr := <-replacement, <-activity
		if broken := deadlocksBroken(t, pool) - cyclesBefore; broken != 0 {
			t.Fatalf("PostgreSQL broke %d lock cycle(s): %v / %v", broken, activityErr, replacementErr)
		}
		if replacementErr != nil {
			t.Fatalf("the replacement that linearised first failed: %v", replacementErr)
		}
		if !errors.Is(activityErr, authstore.ErrNotFound) {
			t.Fatalf("the renewal returned %v after the revocation committed, want the unusable-record answer", activityErr)
		}
		if active, idle, _ := deadlines(t, pool, sess.ID); !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
			t.Errorf("a revoked session was renewed: %s / %s", active, idle)
		}
	})
}
