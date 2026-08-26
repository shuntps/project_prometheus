package httpapi_test

import (
	"context"
	"errors"
	"sync/atomic"
)

// stubStore reproduces an outage, a recovery and a check that never returns. The
// real adapter runs against a real server in the persistence and app packages.
type stubStore struct {
	available atomic.Bool
	calls     atomic.Int64
	hang      atomic.Bool
}

func newStubStore(available bool) *stubStore {
	s := &stubStore{}
	s.available.Store(available)
	return s
}

func (s *stubStore) Check(ctx context.Context) error {
	s.calls.Add(1)
	if s.hang.Load() {
		<-ctx.Done()
		return ctx.Err()
	}
	if !s.available.Load() {
		return errors.New("store refused the check")
	}
	return nil
}
