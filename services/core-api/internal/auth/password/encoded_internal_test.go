package password

import "testing"

// TestTheBoundOnAStoredRepresentationComesFromTheGrammar keeps the limit derived
// from what this package writes rather than chosen by hand.
func TestTheBoundOnAStoredRepresentationComesFromTheGrammar(t *testing.T) {
	widest := len(encode(
		Params{MemoryKiB: ceilingMemoryKiB, Iterations: ceilingIterations, Lanes: ceilingLanes},
		make([]byte, SaltLength), make([]byte, KeyLength)))
	narrowest := len(encode(
		Params{MemoryKiB: FloorMemoryKiB, Iterations: FloorIterations, Lanes: FloorLanes},
		make([]byte, SaltLength), make([]byte, KeyLength)))
	if maxEncodedLength != widest {
		t.Fatalf("the bound is %d, want the widest the grammar writes, %d", maxEncodedLength, widest)
	}
	if narrowest > maxEncodedLength {
		t.Fatalf("the narrowest representation, %d, is above the bound %d", narrowest, maxEncodedLength)
	}
	t.Logf("the grammar writes %d..%d characters; the bound is %d", narrowest, widest, maxEncodedLength)
}
