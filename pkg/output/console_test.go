package output

import (
	"testing"
	"time"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// TestNewTestSummary tests summary calculation
func TestNewTestSummary(t *testing.T) {
	results := []output.TestResult{
		{TestName: "Test 1", Status: output.StatusPass, Duration: 100 * time.Millisecond},
		{TestName: "Test 2", Status: output.StatusPass, Duration: 200 * time.Millisecond},
		{TestName: "Test 3", Status: output.StatusFail, Duration: 150 * time.Millisecond, Error: "Test failed"},
		{TestName: "Test 4", Status: output.StatusWarn, Duration: 50 * time.Millisecond},
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
	report := &output.TestReport{
		Config: output.Config{
			Endpoint: "https://s3.example.com",
			Bucket:   "test-bucket",
			Region:   "us-east-1",
			AuthType: "sigv4",
			Timeout:  30,
		},
		StartTime: output.TimeNow(),
		EndTime:   output.TimeNow(),
		Duration:  time.Second,
		Results: []output.TestResult{
			{
				TestName: "Test 1",
				Status:   output.StatusPass,
				Duration: 100 * time.Millisecond,
			},
		},
		Summary: output.NewTestSummary([]output.TestResult{
			{
				TestName: "Test 1",
				Status:   output.StatusPass,
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
	report := &output.TestReport{
		Config: output.Config{
			Endpoint: "https://s3.example.com",
			Bucket:   "test-bucket",
			Region:   "us-east-1",
			AuthType: "sigv4",
			Timeout:  30,
		},
		StartTime: output.TimeNow(),
		EndTime:   output.TimeNow(),
		Duration:  time.Second,
		Results: []output.TestResult{
			{
				TestName: "Test 1",
				Status:   output.StatusPass,
				Duration: 100 * time.Millisecond,
			},
		},
		Summary: output.NewTestSummary([]output.TestResult{
			{
				TestName: "Test 1",
				Status:   output.StatusPass,
				Duration: 100 * time.Millisecond,
			},
		}),
	}

	// This should not crash
	err := PrintJSON(report, "test-output.json")
	if err != nil {
		t.Errorf("PrintJSON returned error: %v", err)
	}
}

// TestFormatPrincipal tests principal formatting
func TestFormatPrincipal(t *testing.T) {
	tests := []struct {
		principal map[string]interface{}
		expected  string
	}{
		{
			principal: map[string]interface{}{"AWS": "*"},
			expected:  "*",
		},
		{
			principal: map[string]interface{}{"AWS": "arn:aws:iam::123456789012:user/Admin"},
			expected:  "arn:aws:iam::123456789012:user/Admin",
		},
		{
			principal: map[string]interface{}{"AWS": []string{"*"}},
			expected:  "*",
		},
		{
			principal: map[string]interface{}{"AWS": map[string]interface{}{"CanonicalUser": map[string]interface{}{"ID": "123", "DisplayName": "admin@example.com"}}},
			expected:  "CanonicalUser (123)",
		},
		{
			principal: map[string]interface{}{"Group": map[string]interface{}{"URI": "http://acs.amazonaws.com/groups/global/AllUsers"}},
			expected:  "Group (http://acs.amazonaws.com/groups/global/AllUsers)",
		},
		{
			principal: map[string]interface{}{},
			expected:  "*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatPrincipal(tt.principal)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}
