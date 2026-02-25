package middleware

import (
	"context"
	"net/http/httptest"
	"testing"
)

func TestRateLimiterAllow(t *testing.T) {
	rl := NewRateLimiter(2)
	if !rl.Allow("client-a") {
		t.Fatalf("first request should pass")
	}
	if !rl.Allow("client-a") {
		t.Fatalf("second request should pass")
	}
	if rl.Allow("client-a") {
		t.Fatalf("third request should be limited")
	}
	if !rl.Allow("client-b") {
		t.Fatalf("different client should not be limited")
	}
}

func TestGetClientIdentifier(t *testing.T) {
	t.Run("user id in context first", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		ctx := context.WithValue(r.Context(), "user_id", "u-123")
		r = r.WithContext(ctx)
		if got := getClientIdentifier(r); got != "u-123" {
			t.Fatalf("identifier mismatch: %s", got)
		}
	})

	t.Run("xff first ip", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("X-Forwarded-For", "203.0.113.5, 10.0.0.1")
		if got := getClientIdentifier(r); got != "203.0.113.5" {
			t.Fatalf("identifier mismatch: %s", got)
		}
	})

	t.Run("remote addr strips port", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = "198.51.100.12:54321"
		if got := getClientIdentifier(r); got != "198.51.100.12" {
			t.Fatalf("identifier mismatch: %s", got)
		}
	})
}
