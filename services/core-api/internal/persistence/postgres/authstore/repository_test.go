package authstore_test

import (
	"testing"

	"github.com/shuntps/project_prometheus/services/core-api/internal/persistence/postgres/authstore"
)

// TestARepositoryWithoutAStoreIsRefused keeps an unusable adapter from reaching a
// use case. It needs no database: the refusal precedes every call.
func TestARepositoryWithoutAStoreIsRefused(t *testing.T) {
	repository, err := authstore.NewRepository(nil)
	if err == nil {
		t.Fatal("a repository was built without a store")
	}
	if repository != (authstore.Repository{}) {
		t.Error("the refused construction handed back a usable adapter")
	}
}

// TestAStoreWithoutAPoolIsRefused keeps an unusable store from being built at
// all: its first query would panic on the nil pool, far from this wiring.
func TestAStoreWithoutAPoolIsRefused(t *testing.T) {
	store, err := authstore.New(nil)
	if err == nil {
		t.Fatal("a store was built without a pool")
	}
	if store != nil {
		t.Error("the refused construction handed back a store")
	}
}
