package output

import (
	"encoding/json"
	"testing"
	"time"
)

// TestNewTestSummary tests summary calculation
func TestNewTestSummary(t *testing.T) {
	results := []TestResult{
		{TestName: "Test 1", Status: StatusPass, Duration: 100 * time.Millisecond},
		{TestName: "Test 2", Status: StatusPass, Duration: 200 * time.Millisecond},
		{TestName: "Test 3", Status: StatusFail, Duration: 150 * time.Millisecond, Error: "Test failed"},
		{TestName: "Test 4", Status: StatusWarn, Duration: 50 * time.Millisecond},
	}

	summary := NewTestSummary(results)

	if summary.Total != 4 {
		t.Errorf("Expected Total 4, got %d", summary.Total)
	}
	if summary.Passed != 2 {
		t.Errorf("Expected Passed 2, got %d", summary.Passed)
	}
	if summary.Failed != 1 {
		t.Errorf("Expected Failed 1, got %d", summary.Failed)
	}
	if summary.Warnings != 1 {
		t.Errorf("Expected Warnings 1, got %d", summary.Warnings)
	}
}

// TestPrintConsole tests that console printing doesn't crash
func TestPrintConsole(t *testing.T) {
	// This test just verifies that PrintConsole doesn't crash
	// We create a minimal report and try to print it
	report := &TestReport{
		Config: Config{
			Endpoint: "https://s3.example.com",
			Bucket:   "test-bucket",
			Region:   "us-east-1",
			AuthType: "sigv4",
			Timeout:  30,
		},
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Duration:  time.Second,
		Results: []TestResult{
			{
				TestName: "Test 1",
				Status:   StatusPass,
				Duration: 100 * time.Millisecond,
			},
		},
		Summary: NewTestSummary([]TestResult{
			{
				TestName: "Test 1",
				Status:   StatusPass,
				Duration: 100 * time.Millisecond,
			},
		}),
	}

	// This should not crash
	PrintConsole(report)
}

// TestPrintJSON tests that JSON printing doesn't crash
func TestPrintJSON(t *testing.T) {
	// This test just verifies that PrintJSON doesn't crash
	report := &TestReport{
		Config: Config{
			Endpoint: "https://s3.example.com",
			Bucket:   "test-bucket",
			Region:   "us-east-1",
			AuthType: "sigv4",
			Timeout:  30,
		},
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Duration:  time.Second,
		Results: []TestResult{
			{
				TestName: "Test 1",
				Status:   StatusPass,
				Duration: 100 * time.Millisecond,
			},
		},
		Summary: NewTestSummary([]TestResult{
			{
				TestName: "Test 1",
				Status:   StatusPass,
				Duration: 100 * time.Millisecond,
			},
		}),
	}

	// Write to a temporary file so the test does not litter the repo
	tmpFile := t.TempDir() + "/test-output.json"

	err := PrintJSON(report, tmpFile)
	if err != nil {
		t.Errorf("PrintJSON returned error: %v", err)
	}
}

// TestFormatPrincipal tests principal formatting across every accepted
// principal encoding, decoded from real JSON
func TestFormatPrincipal(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected string
	}{
		{"wildcard string", `"*"`, "*"},
		{"object wildcard", `{"AWS": "*"}`, "*"},
		{"array wildcard", `{"AWS": ["*"]}`, "*"},
		{"object single", `{"AWS": "arn:aws:iam::123456789012:user/Admin"}`, "arn:aws:iam::123456789012:user/Admin"},
		{"array values", `{"AWS": ["arn:1", "arn:2"]}`, "arn:1, arn:2"},
		{"canonical user", `{"AWS": {"CanonicalUser": {"ID": "123", "DisplayName": "admin@example.com"}}}`, "CanonicalUser (123)"},
		{"group uri", `{"Group": {"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}}`, "Group (http://acs.amazonaws.com/groups/global/AllUsers)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var principal Principal
			if err := json.Unmarshal([]byte(tt.json), &principal); err != nil {
				t.Fatalf("failed to unmarshal %s: %v", tt.json, err)
			}
			result := formatPrincipal(principal)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}
