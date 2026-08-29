package integration_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/iam"
	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// TestActivityAndRotationDoNotDeadlockInEitherOrder takes the account family before
// the session in both, so the second arrival waits rather than holding what the first needs.
func TestActivityAndRotationDoNotDeadlockInEitherOrder(t *testing.T) {
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
		activityPID := waitForLockWait(t, pool, activityLockFragment)

		rotation := make(chan error, 1)
		go func() { rotation <- store.Rotate(ctx, sess.ID, successor, now.Add(10*time.Minute)) }()
		rotationPID := waitForLockWait(t, pool, authorityFragment)
		if activityPID == rotationPID {
			t.Fatalf("both operations were observed on one backend %d", activityPID)
		}

		release()
		activityErr, rotationErr := <-activity, <-rotation
		if broken := deadlocksBroken(t, pool) - cyclesBefore; broken != 0 {
			t.Fatalf("PostgreSQL broke %d lock cycle(s): %v / %v", broken, activityErr, rotationErr)
		}
		if activityErr != nil {
			t.Fatalf("the renewal that linearised first failed: %v", activityErr)
		}
		if rotationErr != nil {
			t.Fatalf("the rotation that followed failed: %v", rotationErr)
		}
		if _, rotated := lifecycleOf(t, pool, sess.ID); !rotated {
			t.Error("the rotation left no successor on the previous session")
		}
	})

	t.Run("rotation holds the authority first", func(t *testing.T) {
		store, pool := freshStore(t)
		now := time.Now().UTC().Truncate(time.Second)
		account := newAccount(t, store, iam.KindViewer, iam.StatusActive, iam.RoleViewer)
		sess, _ := openSession(t, store, account.ID, iam.SurfacePublic, now)
		successor := successorOf(t, sess, now.Add(10*time.Minute))
		ctx := context.Background()

		cyclesBefore := deadlocksBroken(t, pool)
		release, abandon := suspendSession(t, pool, sess.ID)
		defer abandon()

		rotation := make(chan error, 1)
		go func() { rotation <- store.Rotate(ctx, sess.ID, successor, now.Add(10*time.Minute)) }()
		rotationPID := waitForLockWait(t, pool, rotationLockFragment)

		activity := make(chan error, 1)
		go func() {
			_, err := store.RecordActivity(ctx, sess.ID, now.Add(10*time.Minute), lifetimes())
			activity <- err
		}()
		activityPID := waitForLockWait(t, pool, authorityFragment)
		if activityPID == rotationPID {
			t.Fatalf("both operations were observed on one backend %d", activityPID)
		}
		activeBefore, idleBefore, _ := deadlines(t, pool, sess.ID)

		release()
		rotationErr, activityErr := <-rotation, <-activity
		if broken := deadlocksBroken(t, pool) - cyclesBefore; broken != 0 {
			t.Fatalf("PostgreSQL broke %d lock cycle(s): %v / %v", broken, activityErr, rotationErr)
		}
		if rotationErr != nil {
			t.Fatalf("the rotation that linearised first failed: %v", rotationErr)
		}
		// The session it would have renewed no longer exists as a live record.
		if !errors.Is(activityErr, authstore.ErrNotFound) {
			t.Fatalf("the renewal returned %v after the rotation committed, want the unusable-record answer", activityErr)
		}
		if active, idle, _ := deadlines(t, pool, sess.ID); !active.Equal(activeBefore) || !idle.Equal(idleBefore) {
			t.Errorf("a rotated session was renewed: %s / %s", active, idle)
		}
	})
}
