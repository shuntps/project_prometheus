package ratelimit

import "time"

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
