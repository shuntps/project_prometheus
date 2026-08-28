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
	// identityKey makes the identifier dimension irreversible. It is drawn once
	// per process and never leaves it, so a counter key discloses no address.
	identityKey []byte

	mu         sync.Mutex
	clients    dimension
	identities dimension
}

// dimension is one bounded table of counters. It keeps the earliest deadline it
// holds, so a refusal costs a comparison rather than a pass over every counter.
type dimension struct {
	buckets    map[string]*authBucket
	nextExpiry time.Time
	// sweeps counts the cleanup passes performed. It exists for the proof that
	// refusals are amortised and is deliberately not exported.
	sweeps int
}

type authBucket struct {
	count   int
	resetAt time.Time
}

// NewAuthLimiter refuses an invalid policy rather than running unbounded.
func NewAuthLimiter(policy AuthPolicy, random io.Reader) (*AuthLimiter, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if random == nil {
		random = rand.Reader
	}
	key := make([]byte, sha256.Size)
	if _, err := io.ReadFull(random, key); err != nil {
		return nil, fmt.Errorf("authentication rate limit policy: no identity key could be drawn")
	}
	return &AuthLimiter{
		policy:      policy,
		identityKey: key,
		clients:     dimension{buckets: make(map[string]*authBucket)},
		identities:  dimension{buckets: make(map[string]*authBucket)},
	}, nil
}

// Policy returns the enforced policy.
func (l *AuthLimiter) Policy() AuthPolicy { return l.policy }

// IdentityKey derives the counter key for a presented identifier. The result is
// keyed, so it cannot be recomputed from a candidate address outside this process.
func (l *AuthLimiter) IdentityKey(identifier string) string {
	mac := hmac.New(sha256.New, l.identityKey)
	mac.Write([]byte(strings.ToLower(strings.TrimSpace(identifier))))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Allow charges the client and the identifier together, and charges nothing when
// either is exhausted, so a refusal cannot delay the other's recovery.
func (l *AuthLimiter) Allow(client, identifier string, now time.Time) bool {
	identityKey := l.IdentityKey(identifier)

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.clients.admits(client, l.policy.ClientAttempts, l.policy.Capacity, now) != admitted {
		return false
	}
	if l.identities.admits(identityKey, l.policy.IdentityAttempts, l.policy.Capacity, now) != admitted {
		return false
	}
	l.clients.charge(client, now, l.policy.Window)
	l.identities.charge(identityKey, now, l.policy.Window)
	return true
}

type verdict int

const (
	admitted verdict = iota
	exhausted
	noRoom
)

// admits decides one dimension without charging it. An unseen key needs a free
// slot, and a full table is only scanned once its earliest deadline has passed.
func (d *dimension) admits(key string, limit, capacity int, now time.Time) verdict {
	if bucket, held := d.buckets[key]; held {
		if !now.Before(bucket.resetAt) || bucket.count < limit {
			return admitted
		}
		return exhausted
	}
	if len(d.buckets) < capacity {
		return admitted
	}
	// No counter can have expired before the earliest deadline held, so refusing
	// costs one comparison however many refusals arrive inside that interval.
	if !d.nextExpiry.IsZero() && now.Before(d.nextExpiry) {
		return noRoom
	}
	d.sweep(now)
	if len(d.buckets) < capacity {
		return admitted
	}
	// Every counter is still inside its window. Dropping one would discard a bound
	// somebody is currently under, which is exactly what flooding would buy.
	return noRoom
}

// sweep drops expired counters and recomputes the earliest deadline, so later
// refusals short-circuit again. It never runs once per refusal.
func (d *dimension) sweep(now time.Time) {
	d.sweeps++
	var earliest time.Time
	for key, bucket := range d.buckets {
		if !now.Before(bucket.resetAt) {
			delete(d.buckets, key)
			continue
		}
		if earliest.IsZero() || bucket.resetAt.Before(earliest) {
			earliest = bucket.resetAt
		}
	}
	d.nextExpiry = earliest
}

func (d *dimension) charge(key string, now time.Time, window time.Duration) {
	if bucket, held := d.buckets[key]; held && now.Before(bucket.resetAt) {
		bucket.count++
		return
	}
	reset := now.Add(window)
	d.buckets[key] = &authBucket{count: 1, resetAt: reset}
	if d.nextExpiry.IsZero() || reset.Before(d.nextExpiry) {
		d.nextExpiry = reset
	}
}

// Size reports how many counters the instance currently holds across both
// dimensions.
func (l *AuthLimiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.clients.buckets) + len(l.identities.buckets)
}
