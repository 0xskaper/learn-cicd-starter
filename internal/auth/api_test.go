package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	// Test cases table
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectError error
	}{
		{
			name: "Valid API Key",
			headers: http.Header{
				"Authorization": []string{"ApiKey abc123"},
			},
			expectedKey: "abc123",
			expectError: nil,
		},
		{
			name:        "Missing Authorization Header",
			headers:     http.Header{},
			expectedKey: "",
			expectError: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Wrong Authorization Format",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			expectedKey: "",
			expectError: errors.New("malformed authorization header"),
		},
		{
			name: "Insufficient Parts in Authorization",
			headers: http.Header{
				"Authorization": []string{"ApiKey"},
			},
			expectedKey: "",
			expectError: errors.New("malformed authorization header"),
		},
	}

	// Execute test cases
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GetAPIKey(tc.headers)

			// Check error
			if tc.expectError != nil {
				if err == nil {
					t.Fatalf("expected error %v, got nil", tc.expectError)
				}
				if err.Error() != tc.expectError.Error() {
					t.Fatalf("expected error message '%v', got '%v'", tc.expectError, err)
				}
			} else {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			}

			// Check key
			if key != tc.expectedKey {
				t.Fatalf("expected key '%s', got '%s'", tc.expectedKey, key)
			}
		})
	}
}
