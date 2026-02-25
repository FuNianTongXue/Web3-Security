package auth

import "testing"

func TestNewJWTManagerWithoutEnv(t *testing.T) {
	t.Setenv("JWT_SECRET", "")
	m := NewJWTManager()
	if m == nil {
		t.Fatalf("manager should not be nil")
	}
	if len(m.secretKey) == 0 {
		t.Fatalf("secret key should not be empty")
	}
}

func TestJWTGenerateAndValidate(t *testing.T) {
	t.Setenv("JWT_SECRET", "unit-test-secret")
	m := NewJWTManager()
	token, err := m.GenerateAccessToken("u1", "alice", "alice@example.com", "admin")
	if err != nil {
		t.Fatalf("generate token failed: %v", err)
	}
	claims, err := m.ValidateToken(token)
	if err != nil {
		t.Fatalf("validate token failed: %v", err)
	}
	if claims.UserID != "u1" || claims.Username != "alice" || claims.Role != "admin" {
		t.Fatalf("unexpected claims: %#v", claims)
	}
}
