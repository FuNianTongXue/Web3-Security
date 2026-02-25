// internal/validation/validator.go
package validation

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/microcosm-cc/bluemonday"
)

var (
	validate  *validator.Validate
	sanitizer *bluemonday.Policy
)

func init() {
	validate = validator.New()
	sanitizer = bluemonday.StrictPolicy()

	// Register custom validators
	validate.RegisterValidation("project_name", validateProjectName)
	validate.RegisterValidation("branch_name", validateBranchName)
	validate.RegisterValidation("safe_path", validateSafePath)
}

// Validate performs validation on a struct
func Validate(v interface{}) error {
	return validate.Struct(v)
}

// SanitizeHTML removes all HTML tags and returns clean text
func SanitizeHTML(input string) string {
	return sanitizer.Sanitize(input)
}

// SanitizeString removes potentially dangerous characters
func SanitizeString(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Trim whitespace
	input = strings.TrimSpace(input)

	// Remove control characters except newline and tab
	var result strings.Builder
	for _, r := range input {
		if r >= 32 || r == '\n' || r == '\t' {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// ValidateSafePath ensures path doesn't contain path traversal attempts
func ValidateSafePath(basePath, userPath string) (string, error) {
	// Clean the path
	cleanPath := filepath.Clean(userPath)

	// Check for path traversal attempts
	if strings.Contains(cleanPath, "..") {
		return "", fmt.Errorf("path traversal detected")
	}

	// Join with base path
	fullPath := filepath.Join(basePath, cleanPath)

	// Get absolute paths
	absBase, err := filepath.Abs(basePath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve base path: %w", err)
	}

	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", fmt.Errorf("failed to resolve path: %w", err)
	}

	// Ensure the path is within base directory
	if !strings.HasPrefix(absPath, absBase+string(filepath.Separator)) &&
		absPath != absBase {
		return "", fmt.Errorf("path is outside base directory")
	}

	return absPath, nil
}

// Custom validator functions

func validateProjectName(fl validator.FieldLevel) bool {
	name := fl.Field().String()

	// Must be 1-200 characters
	if len(name) < 1 || len(name) > 200 {
		return false
	}

	// Must contain only alphanumeric, spaces, hyphens, underscores, dots
	matched, _ := regexp.MatchString(`^[a-zA-Z0-9\s\-_.]+$`, name)
	return matched
}

func validateBranchName(fl validator.FieldLevel) bool {
	branch := fl.Field().String()

	// Git branch name rules
	if len(branch) == 0 || len(branch) > 255 {
		return false
	}

	// Cannot start with dot or slash
	if strings.HasPrefix(branch, ".") || strings.HasPrefix(branch, "/") {
		return false
	}

	// Cannot end with .lock
	if strings.HasSuffix(branch, ".lock") {
		return false
	}

	// Cannot contain certain characters
	invalid := []string{"..", "~", "^", ":", "?", "*", "[", "\\", " "}
	for _, char := range invalid {
		if strings.Contains(branch, char) {
			return false
		}
	}

	return true
}

func validateSafePath(fl validator.FieldLevel) bool {
	path := fl.Field().String()

	// Empty path is valid (optional field)
	if path == "" {
		return true
	}

	// Check for path traversal
	if strings.Contains(path, "..") {
		return false
	}

	// Check for absolute paths (should be relative)
	if filepath.IsAbs(path) {
		return false
	}

	return true
}

// ValidateEmail checks if email format is valid
func ValidateEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// ValidateURL checks if URL is valid and uses HTTPS
func ValidateURL(url string) bool {
	if !strings.HasPrefix(url, "https://") {
		return false
	}

	urlRegex := regexp.MustCompile(`^https://[a-zA-Z0-9\-.]+(:[0-9]+)?(/.*)?$`)
	return urlRegex.MatchString(url)
}

// ValidateUUID checks if string is a valid UUID
func ValidateUUID(uuid string) bool {
	uuidRegex := regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	return uuidRegex.MatchString(strings.ToLower(uuid))
}

// SQLInjectionCheck performs basic SQL injection detection
func SQLInjectionCheck(input string) bool {
	// Common SQL injection patterns
	patterns := []string{
		`(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)`,
		`(?i)(or|and)\s+\d+\s*=\s*\d+`,
		`(?i)';|--|\*|\/\*|\*\/|xp_|sp_`,
	}

	for _, pattern := range patterns {
		matched, _ := regexp.MatchString(pattern, input)
		if matched {
			return true
		}
	}

	return false
}

// XSSCheck performs basic XSS detection
func XSSCheck(input string) bool {
	// Common XSS patterns
	patterns := []string{
		`(?i)<script`,
		`(?i)javascript:`,
		`(?i)onerror\s*=`,
		`(?i)onload\s*=`,
		`(?i)<iframe`,
	}

	for _, pattern := range patterns {
		matched, _ := regexp.MatchString(pattern, input)
		if matched {
			return true
		}
	}

	return false
}
