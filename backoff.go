package main

import (
	"math"
	"sync"
	"time"
)

type backoff struct {
	lock    sync.Mutex
	attempt uint64
	// Factor is the multiplying factor for each increment step
	Factor float64
	// Min and Max are the minimum and maximum values of the counter
	Min, Max time.Duration
}

const (
	maxInt64           = float64(math.MaxInt64 - 512)
	defaultMinDuration = 1 * time.Second
	defaultMaxDuration = 100 * time.Second
	defaultFactor      = 2
)

// newBackoff initialises and returns a new Backoff
func newBackoff(min, max time.Duration, factor float64) *backoff {
	// In case of 0 min/max values apply defaults
	if min <= 0 {
		min = defaultMinDuration
	}
	if max <= 0 {
		max = defaultMaxDuration
	}
	if factor <= 0 {
		factor = defaultFactor
	}
	return &backoff{
		lock:   sync.Mutex{},
		Min:    min,
		Max:    max,
		Factor: factor,
	}
}

// Duration returns the next backoff duration and increments attempt
func (b *backoff) Duration() time.Duration {
	b.lock.Lock()
	d := b.forAttempt(float64(b.attempt))
	b.attempt = b.attempt + 1
	b.lock.Unlock()
	return d
}

func (b *backoff) forAttempt(attempt float64) time.Duration {
	if b.Min >= b.Max {
		return b.Max
	}
	//calculate this duration
	minf := float64(b.Min)
	durf := minf * math.Pow(b.Factor, attempt)
	//ensure float64 wont overflow int64
	if durf > maxInt64 {
		return b.Max
	}
	dur := time.Duration(durf)
	//keep within bounds
	if dur < b.Min {
		return b.Min
	}
	if dur > b.Max {
		return b.Max
	}
	return dur
}

// Reset restarts the current attempt counter at zero.
func (b *backoff) Reset() {
	b.lock.Lock()
	b.attempt = 0
	b.lock.Unlock()
}
