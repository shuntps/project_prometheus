package ratelimit

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"
)

// countingReader records what the constructor asked of the entropy source, and
// fails deliberately after a chosen number of bytes.
type countingReader struct {
	calls     int
	requested int
	yield     int
	err       error
}

func (r *countingReader) Read(p []byte) (int, error) {
	r.calls++
	r.requested += len(p)
	if r.err != nil {
		return 0, r.err
	}
	n := min(r.yield, len(p))
	r.yield -= n
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

func usablePolicy() AuthPolicy {
	return AuthPolicy{
		ClientAttempts: 10, IdentityAttempts: 5,
		Window: 15 * time.Minute, Capacity: MinAuthCapacity,
	}
}

// TestAFailedEntropyDrawBuildsNoLimiter keeps a limiter from existing with key
// material the source never supplied.
func TestAFailedEntropyDrawBuildsNoLimiter(t *testing.T) {
	sentinel := errors.New("the entropy source is unavailable")
	for name, reader := range map[string]*countingReader{
		"the source fails":       {err: sentinel},
		"the source is empty":    {yield: 0},
		"the source falls short": {yield: 8},
	} {
		t.Run(name, func(t *testing.T) {
			limiter, err := newAuthLimiter(usablePolicy(), reader)
			if err == nil {
				t.Fatal("a limiter was built without its key material")
			}
			if limiter != nil {
				t.Fatal("a partially initialised limiter was returned")
			}
			if !errors.Is(err, errEntropy) {
				t.Fatalf("the refusal %v is not the fixed entropy refusal", err)
			}
			if strings.Contains(err.Error(), sentinel.Error()) {
				t.Errorf("the refusal %q carries the source's own failure", err)
			}
		})
	}
}

// TestThePolicyIsSettledBeforeAnyEntropyIsDrawn keeps an unusable policy from
// consuming the process entropy source at all.
func TestThePolicyIsSettledBeforeAnyEntropyIsDrawn(t *testing.T) {
	reader := &countingReader{yield: 1024}
	limiter, err := newAuthLimiter(AuthPolicy{}, reader)
	if err == nil || limiter != nil {
		t.Fatal("the zero policy built a limiter")
	}
	if reader.calls != 0 {
		t.Fatalf("the entropy source was read %d time(s) for a policy that was refused", reader.calls)
	}
}

// TestTheDrawnSecretIsTheWholeKeyLength keeps a shorter draw from silently
// producing a weaker key.
func TestTheDrawnSecretIsTheWholeKeyLength(t *testing.T) {
	reader := &countingReader{yield: 1024}
	limiter, err := newAuthLimiter(usablePolicy(), reader)
	if err != nil {
		t.Fatalf("building the limiter failed: %v", err)
	}
	if len(limiter.secret) != 32 {
		t.Fatalf("the secret is %d bytes, want 32", len(limiter.secret))
	}
	if reader.requested < len(limiter.secret) {
		t.Fatalf("the source was asked for %d bytes for a %d-byte secret", reader.requested, len(limiter.secret))
	}
}

// TestEachPublicLimiterDrawsDistinctKeyMaterial: two limiters built through the
// only public way in must not share key material.
func TestEachPublicLimiterDrawsDistinctKeyMaterial(t *testing.T) {
	first, err := NewAuthLimiter(usablePolicy())
	if err != nil {
		t.Fatalf("building the limiter failed: %v", err)
	}
	second, err := NewAuthLimiter(usablePolicy())
	if err != nil {
		t.Fatalf("building the second limiter failed: %v", err)
	}
	if string(first.secret) == string(second.secret) {
		t.Fatal("two limiters share their secret, so it is not drawn per instance")
	}
	if len(first.secret) != 32 || len(second.secret) != 32 {
		t.Fatalf("secrets are %d and %d bytes, want 32", len(first.secret), len(second.secret))
	}
}

// TestTheLimiterExportsOnlyWhatProductionCalls keeps an accessor from being
// added back for a test's convenience: every exported method is listed here.
func TestTheLimiterExportsOnlyWhatProductionCalls(t *testing.T) {
	limiter, err := NewAuthLimiter(usablePolicy())
	if err != nil {
		t.Fatalf("building the limiter failed: %v", err)
	}
	want := map[string]bool{"Allow": true}
	got := map[string]bool{}
	typ := reflect.TypeOf(limiter)
	for i := range typ.NumMethod() {
		got[typ.Method(i).Name] = true
	}
	for name := range got {
		if !want[name] {
			t.Errorf("*AuthLimiter exports %q, which no production caller uses", name)
		}
	}
	for name := range want {
		if !got[name] {
			t.Errorf("*AuthLimiter no longer exports %q", name)
		}
	}
}
