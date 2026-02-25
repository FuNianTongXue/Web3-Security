// internal/auth/password.go
package auth

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"regexp"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrWeakPassword     = errors.New("password does not meet security requirements")
	ErrPasswordMismatch = errors.New("password does not match")
)

// PasswordPolicy defines password strength requirements
type PasswordPolicy struct {
	MinLength      int
	RequireUpper   bool
	RequireLower   bool
	RequireNumber  bool
	RequireSpecial bool
}

// DefaultPasswordPolicy returns a secure default policy
func DefaultPasswordPolicy() PasswordPolicy {
	return PasswordPolicy{
		MinLength:      12,
		RequireUpper:   true,
		RequireLower:   true,
		RequireNumber:  true,
		RequireSpecial: true,
	}
}

// ValidatePasswordStrength checks if password meets policy requirements
func ValidatePasswordStrength(password string, policy PasswordPolicy) error {
	if len(password) < policy.MinLength {
		return fmt.Errorf("%w: minimum length is %d characters", ErrWeakPassword, policy.MinLength)
	}

	if policy.RequireUpper {
		if matched, _ := regexp.MatchString(`[A-Z]`, password); !matched {
			return fmt.Errorf("%w: must contain at least one uppercase letter", ErrWeakPassword)
		}
	}

	if policy.RequireLower {
		if matched, _ := regexp.MatchString(`[a-z]`, password); !matched {
			return fmt.Errorf("%w: must contain at least one lowercase letter", ErrWeakPassword)
		}
	}

	if policy.RequireNumber {
		if matched, _ := regexp.MatchString(`[0-9]`, password); !matched {
			return fmt.Errorf("%w: must contain at least one number", ErrWeakPassword)
		}
	}

	if policy.RequireSpecial {
		if matched, _ := regexp.MatchString(`[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]`, password); !matched {
			return fmt.Errorf("%w: must contain at least one special character", ErrWeakPassword)
		}
	}

	// Check for common weak passwords
	commonPasswords := []string{
		"password", "Password123!", "Admin123!", "Welcome123!",
		"123456", "qwerty", "abc123", "letmein",
	}
	for _, weak := range commonPasswords {
		if password == weak {
			return fmt.Errorf("%w: password is too common", ErrWeakPassword)
		}
	}

	return nil
}

// HashPassword creates a bcrypt hash of the password
func HashPassword(password string) (string, error) {
	// Validate password strength before hashing
	if err := ValidatePasswordStrength(password, DefaultPasswordPolicy()); err != nil {
		return "", err
	}

	// Use bcrypt with cost factor of 12 (recommended for 2025)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}

	return string(hash), nil
}

// VerifyPassword compares a password with its hash using constant-time comparison
func VerifyPassword(hashedPassword, password string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return ErrPasswordMismatch
	}
	return nil
}

// IsPasswordHashCurrent checks if the hash uses current cost factor
func IsPasswordHashCurrent(hashedPassword string) bool {
	cost, err := bcrypt.Cost([]byte(hashedPassword))
	if err != nil {
		return false
	}
	return cost >= 12
}

// ConstantTimeCompare performs constant-time string comparison
func ConstantTimeCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
