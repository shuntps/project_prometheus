package ratelimit

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// AuthPolicy bounds attempts on two dimensions. Both must permit one, so varying
// only the client or only the identifier never yields a fresh quota.
type AuthPolicy struct {
	// ClientAttempts bounds attempts from one resolved client per window.
	ClientAttempts int
	// IdentityAttempts bounds attempts against one presented identifier per
	// window, whatever client makes them.
	IdentityAttempts int
	Window           time.Duration
	// Capacity bounds the counters of **one** dimension. Each dimension holds its
	// own table, so an instance holds at most twice this many counters.
	Capacity int
}

// errEntropy is fixed: a caller learns that no limiter was built and nothing
// about the source that failed.
var errEntropy = errors.New("rate limit policy: no counter key could be drawn")

const (
	MinAuthAttempts = 1
	MaxAuthAttempts = 10_000
	MinAuthWindow   = time.Second
	MaxAuthWindow   = 24 * time.Hour
	MinAuthCapacity = 1_024
	MaxAuthCapacity = 4_194_304
)

// Validate refuses any policy that would leave an authentication journey without
// a bound on either dimension.
func (p AuthPolicy) Validate() error {
	var problems []string
	if p.ClientAttempts < MinAuthAttempts || p.ClientAttempts > MaxAuthAttempts {
		problems = append(problems, fmt.Sprintf("ClientAttempts must be between %d and %d", MinAuthAttempts, MaxAuthAttempts))
	}
	if p.IdentityAttempts < MinAuthAttempts || p.IdentityAttempts > MaxAuthAttempts {
		problems = append(problems, fmt.Sprintf("IdentityAttempts must be between %d and %d", MinAuthAttempts, MaxAuthAttempts))
	}
	if p.Window < MinAuthWindow || p.Window > MaxAuthWindow {
		problems = append(problems, fmt.Sprintf("Window must be between %s and %s", MinAuthWindow, MaxAuthWindow))
	}
	if p.Capacity < MinAuthCapacity || p.Capacity > MaxAuthCapacity {
		problems = append(problems, fmt.Sprintf("Capacity must be between %d and %d", MinAuthCapacity, MaxAuthCapacity))
	}
	if len(problems) > 0 {
		return fmt.Errorf("authentication rate limit policy: %s", strings.Join(problems, "; "))
	}
	return nil
}

// AuthLimiter enforces an AuthPolicy for one process, per instance: n processes
// multiply the effective allowance by n. Each dimension owns its table.
type AuthLimiter struct {
	policy AuthPolicy
	// secret keys both dimensions. It is drawn once per process and never leaves
	// it, so a counter key discloses neither the address nor the client.
	secret []byte

	mu         sync.Mutex
	clients    dimension
	identities dimension
}

// NewAuthLimiter refuses an invalid policy rather than running unbounded. It is
// the only way in, and it always draws from the process entropy source.
func NewAuthLimiter(policy AuthPolicy) (*AuthLimiter, error) {
	return newAuthLimiter(policy, rand.Reader)
}

// newAuthLimiter takes the entropy source so that the failure path stays
// provable. It is unexported: no caller outside this package may choose it.
func newAuthLimiter(policy AuthPolicy, random io.Reader) (*AuthLimiter, error) {
	// The policy is settled before any entropy is drawn, so an unusable policy
	// never consumes from the source.
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	secret := make([]byte, sha256.Size)
	if _, err := io.ReadFull(random, secret); err != nil {
		return nil, errEntropy
	}
	return &AuthLimiter{
		policy:     policy,
		secret:     secret,
		clients:    dimension{buckets: make(map[string]*authBucket)},
		identities: dimension{buckets: make(map[string]*authBucket)},
	}, nil
}

func (l *AuthLimiter) counterKey(value string) string { return counterKey(l.secret, value) }

// Allow charges the client and the identifier together, and charges nothing when
// either is exhausted, so a refusal cannot delay the other's recovery.
func (l *AuthLimiter) Allow(client, identifier string, now time.Time) bool {
	clientKey := l.counterKey(client)
	identityKey := l.counterKey(identifier)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.clients.admits(clientKey, l.policy.ClientAttempts, l.policy.Capacity, now) != admitted {
		return false
	}
	if l.identities.admits(identityKey, l.policy.IdentityAttempts, l.policy.Capacity, now) != admitted {
		return false
	}
	l.clients.charge(clientKey, now, l.policy.Window)
	l.identities.charge(identityKey, now, l.policy.Window)
	return true
}
