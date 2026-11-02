package output

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestMaskAccessKey verifies access key masking for reports and logs
func TestMaskAccessKey(t *testing.T) {
	tests := []struct {
		key      string
		expected string
	}{
		{"", ""},
		{"AKIA", "****"},
		{"AKI", "****"},
		{"AKIAIOSFODNN7EXAMPLE", "AKIA…"},
		{"wJalrXUtnFEMI", "wJal…"},
	}
	for _, tt := range tests {
		if got := MaskAccessKey(tt.key); got != tt.expected {
			t.Errorf("MaskAccessKey(%q) = %q, want %q", tt.key, got, tt.expected)
		}
	}
}

// newCredentialReport builds a report whose config carries real-looking secrets
func newCredentialReport() *TestReport {
	config := Config{
		Endpoint:        "https://s3.example.com",
		Bucket:          "test-bucket",
		AccessKey:       "AKIAIOSFODNN7EXAMPLE",
		SecretKey:       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		AccessKeyMasked: MaskAccessKey("AKIAIOSFODNN7EXAMPLE"),
		AuthType:        "sigv4",
		Region:          "us-east-1",
		Timeout:         30,
	}
	return &TestReport{
		Config:    config,
		StartTime: time.Now(),
		EndTime:   time.Now(),
		Results:   []TestResult{{TestName: "DNS Resolution Check", Status: StatusPass}},
		Summary:   TestSummary{Total: 1, Passed: 1},
	}
}

// TestPrintJSON_DoesNotLeakCredentials verifies the JSON report never
// contains the secret key or the full access key
func TestPrintJSON_DoesNotLeakCredentials(t *testing.T) {
	report := newCredentialReport()
	path := filepath.Join(t.TempDir(), "report.json")

	if err := PrintJSON(report, path); err != nil {
		t.Fatalf("PrintJSON failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}
	content := string(data)

	if strings.Contains(content, report.Config.SecretKey) {
		t.Error("JSON report contains the secret key")
	}
	if strings.Contains(content, report.Config.AccessKey) {
		t.Error("JSON report contains the full access key")
	}
	if !strings.Contains(content, `"accessKey": "AKIA…"`) {
		t.Errorf("JSON report should contain the masked access key, got:\n%s", content)
	}
}

// TestPrintJSONWithRemediation_DoesNotLeakCredentials verifies the extended
// report is equally free of credentials
func TestPrintJSONWithRemediation_DoesNotLeakCredentials(t *testing.T) {
	report := newCredentialReport()
	path := filepath.Join(t.TempDir(), "report-extended.json")

	if err := PrintJSONWithRemediation(report, path); err != nil {
		t.Fatalf("PrintJSONWithRemediation failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read report: %v", err)
	}
	content := string(data)

	if strings.Contains(content, report.Config.SecretKey) {
		t.Error("extended JSON report contains the secret key")
	}
	if strings.Contains(content, report.Config.AccessKey) {
		t.Error("extended JSON report contains the full access key")
	}
}

// TestPrintJSON_ReportFilePermissions verifies reports are written with
// owner-only permissions. Windows does not support Unix permission bits,
// so the mode assertion runs only on Unix-like platforms.
func TestPrintJSON_ReportFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits are not enforced on Windows")
	}

	report := newCredentialReport()
	path := filepath.Join(t.TempDir(), "report-perms.json")

	if err := PrintJSON(report, path); err != nil {
		t.Fatalf("PrintJSON failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat report: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("report file mode is %o, want 0600", perm)
	}

	// Pre-existing looser files must be tightened on rewrite
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatalf("failed to loosen permissions: %v", err)
	}
	if err := PrintJSON(report, path); err != nil {
		t.Fatalf("PrintJSON rewrite failed: %v", err)
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatalf("failed to stat report: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("report file mode after rewrite is %o, want 0600", perm)
	}
}

// TestConfigJSONRoundTrip verifies the struct tags directly on platforms
// where file permissions cannot be checked
func TestConfigJSONRoundTrip(t *testing.T) {
	config := Config{
		AccessKey:       "AKIAIOSFODNN7EXAMPLE",
		SecretKey:       "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		AccessKeyMasked: "AKIA…",
		Endpoint:        "https://s3.example.com",
	}

	data, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	content := string(data)

	if strings.Contains(content, config.SecretKey) {
		t.Error("marshaled config contains the secret key")
	}
	if strings.Contains(content, config.AccessKey) {
		t.Error("marshaled config contains the full access key")
	}
	if !strings.Contains(content, `"accessKey":"AKIA…"`) {
		t.Errorf("marshaled config should carry the masked access key, got %s", content)
	}
}
