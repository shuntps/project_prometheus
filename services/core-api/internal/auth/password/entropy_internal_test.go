package password

import (
	"errors"
	"io"
	"strings"
	"testing"
)

// countingReader records what the hasher asked of the entropy source, and fails
// deliberately after a chosen number of bytes.
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

func usable() (Params, Policy) {
	return Params{MemoryKiB: FloorMemoryKiB, Iterations: FloorIterations, Lanes: FloorLanes},
		Policy{MinCodePoints: SingleFactorMinimum}
}

const internalProbe = "correct horse battery staple"

// TestAFailedEntropyDrawDerivesNothing keeps a representation from existing with
// salt the source never supplied. Hash draws the entropy, not the constructor.
func TestAFailedEntropyDrawDerivesNothing(t *testing.T) {
	sentinel := errors.New("the entropy source is unavailable")
	for name, reader := range map[string]*countingReader{
		"the source fails":       {err: sentinel},
		"the source is empty":    {yield: 0},
		"the source falls short": {yield: 8},
	} {
		t.Run(name, func(t *testing.T) {
			params, policy := usable()
			hasher, err := newHasher(params, policy, reader)
			if err != nil || hasher == nil {
				t.Fatalf("the constructor drew entropy it should not have: %v", err)
			}
			encoded, err := hasher.Hash(internalProbe)
			if !errors.Is(err, ErrEntropy) {
				t.Fatalf("Hash gave %v, want the fixed entropy sentinel", err)
			}
			if !encoded.IsZero() {
				t.Error("a representation was returned without its salt")
			}
			if strings.Contains(err.Error(), sentinel.Error()) {
				t.Errorf("the refusal %q carries the source's own failure", err)
			}
			if reader.requested < int(SaltLength) {
				t.Errorf("the source was asked for %d bytes for a %d-byte salt", reader.requested, SaltLength)
			}
		})
	}
}

// TestAnUnusablePasswordIsRefusedBeforeAnyEntropyIsDrawn keeps a refusal the
// policy decides from consuming the process entropy source.
func TestAnUnusablePasswordIsRefusedBeforeAnyEntropyIsDrawn(t *testing.T) {
	params, policy := usable()
	for name, plaintext := range map[string]string{
		"too short":     "short",
		"too large":     strings.Repeat("a", MaxBytes+1),
		"invalid UTF-8": "long enough password \xff\xfe",
	} {
		t.Run(name, func(t *testing.T) {
			reader := &countingReader{yield: 1024}
			hasher, err := newHasher(params, policy, reader)
			if err != nil {
				t.Fatalf("building the hasher failed: %v", err)
			}
			if _, err := hasher.Hash(plaintext); !errors.Is(err, ErrUnusable) {
				t.Fatalf("Hash gave %v, want an unusable refusal", err)
			}
			if reader.calls != 0 {
				t.Fatalf("the entropy source was read %d time(s) for a password that was refused", reader.calls)
			}
		})
	}
}

// TestAnInvalidPolicyIsRefusedByTheConstructor covers the branch no test reached.
func TestAnInvalidPolicyIsRefusedByTheConstructor(t *testing.T) {
	params, _ := usable()
	for name, policy := range map[string]Policy{
		"zero value":          {},
		"under the minimum":   {MinCodePoints: SingleFactorMinimum - 1},
		"multi factor only":   {MinCodePoints: MultiFactorMinimum},
		"beyond the byte cap": {MinCodePoints: MaxBytes + 1},
	} {
		t.Run(name, func(t *testing.T) {
			hasher, err := newHasher(params, policy, &countingReader{yield: 1024})
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("the constructor gave %v, want a policy refusal", err)
			}
			if hasher != nil {
				t.Error("a hasher was built on a policy the package refuses")
			}
		})
	}
}
