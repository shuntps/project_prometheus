package httpfixture_test

import (
	"testing"
	"time"

	"github.com/shuntps/project_prometheus/services/core-api/internal/testsupport/httpfixture"
	"github.com/shuntps/project_prometheus/services/core-api/internal/transport/httpapi"
)

// TestMustAppFillsOnlyWhatTheCallerLeftUnset keeps the fixture from silently
// deciding a bound a suite chose deliberately.
func TestMustAppFillsOnlyWhatTheCallerLeftUnset(t *testing.T) {
	chosen := 3 * time.Second
	opts := httpapi.Options{
		RateLimit:    httpfixture.DirectPolicy(100),
		CheckTimeout: chosen,
		ReadTimeout:  chosen,
		WriteTimeout: chosen,
		IdleTimeout:  chosen,
	}
	if app := httpfixture.MustApp(t, &opts); app == nil {
		t.Fatal("no application was built")
	}
	for name, got := range map[string]time.Duration{
		"CheckTimeout": opts.CheckTimeout, "ReadTimeout": opts.ReadTimeout,
		"WriteTimeout": opts.WriteTimeout, "IdleTimeout": opts.IdleTimeout,
	} {
		if got != chosen {
			t.Errorf("%s became %s, want the requested %s", name, got, chosen)
		}
	}

	empty := httpapi.Options{RateLimit: httpfixture.DirectPolicy(100)}
	if app := httpfixture.MustApp(t, &empty); app == nil {
		t.Fatal("no application was built")
	}
	for name, got := range map[string]time.Duration{
		"CheckTimeout": empty.CheckTimeout, "ReadTimeout": empty.ReadTimeout,
		"WriteTimeout": empty.WriteTimeout, "IdleTimeout": empty.IdleTimeout,
	} {
		if got != httpfixture.DefaultTimeout {
			t.Errorf("%s stayed %s, want the fixture default %s", name, got, httpfixture.DefaultTimeout)
		}
	}
	if empty.Logger == nil || empty.Readiness == nil || empty.Persistence == nil {
		t.Error("the fixture left a required dependency unset")
	}
}
