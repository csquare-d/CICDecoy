package main

import (
	"fmt"
	"log/slog"
	"math"
	"math/rand"
	"sync"
	"time"
)

// RetryPolicy controls exponential backoff for transient failures.
type RetryPolicy struct {
	MaxRetries  int
	BaseBackoff time.Duration
	MaxBackoff  time.Duration
	Jitter      bool
}

// DefaultRetryPolicy returns a RetryPolicy with sensible defaults.
func DefaultRetryPolicy() RetryPolicy {
	return RetryPolicy{
		MaxRetries:  3,
		BaseBackoff: 1 * time.Second,
		MaxBackoff:  30 * time.Second,
		Jitter:      true,
	}
}

// Backoff returns the wait duration for the given attempt (0-indexed).
// The formula is min(baseBackoff * 2^attempt [+ jitter], maxBackoff).
// Jitter adds 0–50% of BaseBackoff to prevent thundering herd.
func (rp RetryPolicy) Backoff(attempt int) time.Duration {
	exp := math.Pow(2, float64(attempt))
	d := time.Duration(float64(rp.BaseBackoff) * exp)

	if rp.Jitter {
		// Add 0–50% of BaseBackoff.
		jitter := time.Duration(rand.Float64() * 0.5 * float64(rp.BaseBackoff))
		d += jitter
	}

	if d > rp.MaxBackoff {
		return rp.MaxBackoff
	}
	return d
}

// CircuitState represents the three states of a circuit breaker.
type CircuitState int

const (
	CircuitClosed   CircuitState = iota // normal operation
	CircuitOpen                         // all sends blocked
	CircuitHalfOpen                     // testing with limited sends
)

// String returns the human-readable name of the circuit state.
func (s CircuitState) String() string {
	switch s {
	case CircuitClosed:
		return "closed"
	case CircuitOpen:
		return "open"
	case CircuitHalfOpen:
		return "half-open"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// CircuitBreaker protects an output sink from cascading failures.
// It tracks consecutive failures and, once a threshold is reached,
// trips open to shed load. After a cooldown period it moves to
// half-open, allowing a limited number of probes through before
// fully closing again.
type CircuitBreaker struct {
	mu               sync.Mutex
	state            CircuitState
	failureCount     int
	successCount     int
	failureThreshold int
	successThreshold int
	openTimeout      time.Duration
	lastFailureTime  time.Time
	logger           *slog.Logger
}

// NewCircuitBreaker creates a CircuitBreaker with the given thresholds.
// Zero/negative values are replaced with sensible defaults.
func NewCircuitBreaker(failureThreshold, successThreshold int, openTimeout time.Duration, logger *slog.Logger) *CircuitBreaker {
	if failureThreshold <= 0 {
		failureThreshold = 5
	}
	if successThreshold <= 0 {
		successThreshold = 2
	}
	if openTimeout <= 0 {
		openTimeout = 30 * time.Second
	}
	return &CircuitBreaker{
		state:            CircuitClosed,
		failureThreshold: failureThreshold,
		successThreshold: successThreshold,
		openTimeout:      openTimeout,
		logger:           logger,
	}
}

// Allow reports whether the circuit breaker permits a request.
// In closed and half-open states the request is allowed. In the
// open state, Allow checks whether openTimeout has elapsed since
// the last failure; if so it transitions to half-open and allows
// the request, otherwise it rejects.
func (cb *CircuitBreaker) Allow() bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed, CircuitHalfOpen:
		return true
	case CircuitOpen:
		if time.Since(cb.lastFailureTime) >= cb.openTimeout {
			cb.setState(CircuitHalfOpen)
			cb.successCount = 0
			return true
		}
		return false
	default:
		return false
	}
}

// RecordSuccess signals a successful request to the circuit breaker.
// In half-open: increments the success counter and closes the circuit
// once the success threshold is met. In closed: resets the failure count.
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitHalfOpen:
		cb.successCount++
		if cb.successCount >= cb.successThreshold {
			cb.setState(CircuitClosed)
			cb.failureCount = 0
			cb.successCount = 0
		}
	case CircuitClosed:
		cb.failureCount = 0
	}
}

// RecordFailure signals a failed request. In closed state: increments
// the failure counter and trips the breaker open once the threshold is
// reached. In half-open: immediately trips back to open.
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.lastFailureTime = time.Now()

	switch cb.state {
	case CircuitClosed:
		cb.failureCount++
		if cb.failureCount >= cb.failureThreshold {
			cb.setState(CircuitOpen)
		}
	case CircuitHalfOpen:
		cb.setState(CircuitOpen)
	}
}

// State returns the current circuit state.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// String returns the human-readable name of the current circuit state.
func (cb *CircuitBreaker) String() string {
	return cb.State().String()
}

// setState transitions the circuit breaker and logs the change.
// Caller must hold cb.mu.
func (cb *CircuitBreaker) setState(new CircuitState) {
	old := cb.state
	cb.state = new
	cb.logger.Info("circuit breaker state change",
		"from", old.String(),
		"to", new.String(),
	)
}
