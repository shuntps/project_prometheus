package ratelimit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// counterKey derives a dimension's key. The result is keyed and of fixed length,
// so it cannot be recomputed from a candidate value outside this process.
func counterKey(secret []byte, value string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(value))))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// ClientPolicy bounds attempts from one resolved client and declares no second
// dimension. A key an attacker chooses would hand out a fresh counter per
// attempt and would fill the table with values nobody else can use.
type ClientPolicy struct {
	Attempts int
	Window   time.Duration
	// Capacity bounds the single table this policy owns.
	Capacity int
}

// Validate refuses any policy that would leave a journey without a bound.
func (p ClientPolicy) Validate() error {
	var problems []string
	if p.Attempts < MinAuthAttempts || p.Attempts > MaxAuthAttempts {
		problems = append(problems, fmt.Sprintf("Attempts must be between %d and %d", MinAuthAttempts, MaxAuthAttempts))
	}
	if p.Window < MinAuthWindow || p.Window > MaxAuthWindow {
		problems = append(problems, fmt.Sprintf("Window must be between %s and %s", MinAuthWindow, MaxAuthWindow))
	}
	if p.Capacity < MinAuthCapacity || p.Capacity > MaxAuthCapacity {
		problems = append(problems, fmt.Sprintf("Capacity must be between %d and %d", MinAuthCapacity, MaxAuthCapacity))
	}
	if len(problems) > 0 {
		return fmt.Errorf("client rate limit policy: %s", strings.Join(problems, "; "))
	}
	return nil
}

// ClientLimiter enforces a ClientPolicy for one process, per instance: n
// processes multiply the effective allowance by n. It owns exactly one table.
type ClientLimiter struct {
	policy ClientPolicy
	// secret keys the dimension. It is drawn once per process and never leaves
	// it, so a counter key discloses nothing about the client.
	secret []byte

	mu      sync.Mutex
	clients dimension
}

// NewClientLimiter refuses an invalid policy rather than running unbounded. It is
// the only way in, and it always draws from the process entropy source.
func NewClientLimiter(policy ClientPolicy) (*ClientLimiter, error) {
	return newClientLimiter(policy, rand.Reader)
}

// newClientLimiter takes the entropy source so that the failure path stays
// provable. It is unexported: no caller outside this package may choose it.
func newClientLimiter(policy ClientPolicy, random io.Reader) (*ClientLimiter, error) {
	// The policy is settled before any entropy is drawn, so an unusable policy
	// never consumes from the source.
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	secret := make([]byte, sha256.Size)
	if _, err := io.ReadFull(random, secret); err != nil {
		return nil, errEntropy
	}
	return &ClientLimiter{
		policy:  policy,
		secret:  secret,
		clients: dimension{buckets: make(map[string]*authBucket)},
	}, nil
}

// Allow charges the client dimension and nothing else.
func (l *ClientLimiter) Allow(client string, now time.Time) bool {
	key := counterKey(l.secret, client)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.clients.admits(key, l.policy.Attempts, l.policy.Capacity, now) != admitted {
		return false
	}
	l.clients.charge(key, now, l.policy.Window)
	return true
}
