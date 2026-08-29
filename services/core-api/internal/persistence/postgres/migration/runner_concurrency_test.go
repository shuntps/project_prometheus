package migration

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestConcurrentRunnersApplyEachMigrationOnce exercises the advisory lock against
// a real server: several runners start at once on an empty schema.
func TestConcurrentRunnersApplyEachMigrationOnce(t *testing.T) {
	pool := freshPool(t)
	migrations, err := Load()
	if err != nil {
		t.Fatalf("loading failed: %v", err)
	}

	const runners = 8
	start := make(chan struct{})
	results := make(chan Result, runners)
	failures := make(chan error, runners)

	var wg sync.WaitGroup
	for range runners {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			result, err := Apply(ctx, pool, migrations)
			if err != nil {
				failures <- err
				return
			}
			results <- result
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	close(failures)

	for err := range failures {
		t.Fatalf("a concurrent runner failed: %v", err)
	}
	total := 0
	for result := range results {
		total += len(result.Applied)
	}
	if total != len(migrations) {
		t.Fatalf("%d migrations were applied in total, want exactly %d", total, len(migrations))
	}
	if got := recorded(t, pool); len(got) != len(migrations) {
		t.Fatalf("the ledger holds %v", got)
	}
}
