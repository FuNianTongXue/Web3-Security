package middleware

import (
	"sync"
	"time"
)

type RateLimiter struct {
	requestsPerMinute int
	mu                sync.Mutex
	buckets           map[string]*rateLimitBucket
}

type rateLimitBucket struct {
	count       int
	windowStart time.Time
}

func NewRateLimiter(requestsPerMinute int) *RateLimiter {
	limit := requestsPerMinute
	if limit <= 0 {
		limit = 60
	}
	return &RateLimiter{
		requestsPerMinute: limit,
		buckets:           make(map[string]*rateLimitBucket),
	}
}

func (l *RateLimiter) Allow(clientID string) bool {
	if l == nil {
		return true
	}
	id := clientID
	if id == "" {
		id = "anonymous"
	}

	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	bucket, ok := l.buckets[id]
	if !ok {
		l.buckets[id] = &rateLimitBucket{count: 1, windowStart: now}
		return true
	}

	if now.Sub(bucket.windowStart) >= time.Minute {
		bucket.count = 1
		bucket.windowStart = now
		return true
	}

	if bucket.count >= l.requestsPerMinute {
		return false
	}

	bucket.count++
	return true
}
