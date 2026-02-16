package checker

import (
	"testing"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// TestNewDNSChecker tests the constructor
func TestNewDNSChecker(t *testing.T) {
	config := output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		Timeout:   30,
		Verbose:   true,
	}

	checker := NewDNSChecker(config, "s3.example.com")

	if checker.Config.Endpoint != config.Endpoint {
		t.Errorf("Expected Endpoint '%s', got '%s'", config.Endpoint, checker.Config.Endpoint)
	}
	if checker.Hostname != "s3.example.com" {
		t.Errorf("Expected Hostname 's3.example.com', got '%s'", checker.Hostname)
	}
	if checker.verbose == nil || !checker.verbose.enabled {
		t.Errorf("Expected verbose logger to be enabled")
	}
}

// TestDNSCheckerName tests the Name method
func TestDNSCheckerName(t *testing.T) {
	config := output.Config{}
	checker := NewDNSChecker(config, "example.com")

	if checker.Name() != "DNS Resolution Check" {
		t.Errorf("Expected name 'DNS Resolution Check', got '%s'", checker.Name())
	}
}

// TestDNSCheck_Success tests successful DNS resolution
func TestDNSCheck_Success(t *testing.T) {
	// Use a known hostname that should resolve
	config := output.Config{
		Endpoint: "https://s3.amazonaws.com",
		Timeout:  30,
	}
	checker := NewDNSChecker(config, "s3.amazonaws.com")

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s", result.Status)
	}
	if result.Error != "" {
		t.Errorf("Expected no error, got '%s'", result.Error)
	}
	if result.Details == nil {
		t.Error("Expected details to be populated")
	}
}

// TestDNSCheck_IPAddress tests handling of direct IP addresses
func TestDNSCheck_IPAddress(t *testing.T) {
	config := output.Config{
		Endpoint: "https://192.168.1.100",
		Timeout:  30,
	}
	checker := NewDNSChecker(config, "192.168.1.100")

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS for IP address, got %s", result.Status)
	}
	if result.Error != "" {
		t.Errorf("Expected no error for IP address, got '%s'", result.Error)
	}
}

// TestDNSCheck_Timeout tests DNS timeout behavior
func TestDNSCheck_Timeout(t *testing.T) {
	// Use a hostname that will likely timeout
	// This test is difficult to implement reliably without mocking
	// For now, we'll skip it
	t.Skip("DNS timeout test requires mocking")
}

// TestDNSCheck_Failure tests DNS resolution failure
func TestDNSCheck_Failure(t *testing.T) {
	// Use a hostname that doesn't exist
	config := output.Config{
		Endpoint: "https://this-domain-definitely-does-not-exist-12345.com",
		Timeout:  5, // Short timeout for faster test
	}
	checker := NewDNSChecker(config, "this-domain-definitely-does-not-exist-12345.com")

	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected status FAIL, got %s", result.Status)
	}
	if result.Error == "" {
		t.Error("Expected error message for non-existent domain")
	}
}

// TestDNSCheck_ReverseDNS tests reverse DNS lookup
func TestDNSCheck_ReverseDNS(t *testing.T) {
	// Use a hostname that should have reverse DNS
	config := output.Config{
		Endpoint: "https://s3.amazonaws.com",
		Timeout:  30,
	}
	checker := NewDNSChecker(config, "s3.amazonaws.com")

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s", result.Status)
	}

	details, ok := result.Details.(output.DNSResult)
	if !ok {
		t.Fatal("Expected DNSResult in details")
	}

	// Reverse DNS may or may not be populated depending on the DNS server
	// We just verify the test doesn't crash
	_ = details.ReverseDNS
}

// TestDNSCheck_MultipleIPs tests handling of multiple IP addresses
func TestDNSCheck_MultipleIPs(t *testing.T) {
	// Use a hostname that typically returns multiple IPs
	config := output.Config{
		Endpoint: "https://s3.amazonaws.com",
		Timeout:  30,
	}
	checker := NewDNSChecker(config, "s3.amazonaws.com")

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s", result.Status)
	}

	details, ok := result.Details.(output.DNSResult)
	if !ok {
		t.Fatal("Expected DNSResult in details")
	}

	if len(details.IPs) == 0 {
		t.Error("Expected at least one IP address")
	}
}

// TestDNSCheck_EmptyHostname tests handling of empty hostname
func TestDNSCheck_EmptyHostname(t *testing.T) {
	config := output.Config{
		Endpoint: "https://",
		Timeout:  30,
	}
	checker := NewDNSChecker(config, "")

	result := checker.Check()

	// Empty hostname should fail
	if result.Status != output.StatusFail {
		t.Errorf("Expected status FAIL for empty hostname, got %s", result.Status)
	}
}

// TestIsIPAddress tests the IP address detection helper
func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"2001:db8::1", true},
		{"example.com", false},
		{"s3.amazonaws.com", false},
		{"localhost", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			checker := &DNSChecker{}
			result := checker.isIPAddress(tt.input)
			if result != tt.expected {
				t.Errorf("isIPAddress(%q) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

// TestDNSCheck_ContextTimeout tests that context timeout is respected
func TestDNSCheck_ContextTimeout(t *testing.T) {
	// This test would require mocking the DNS resolver
	// For now, we'll skip it
	t.Skip("Context timeout test requires mocking DNS resolver")
}

// TestDNSCheck_VerboseLogging tests verbose logging
func TestDNSCheck_VerboseLogging(t *testing.T) {
	config := output.Config{
		Endpoint: "https://s3.amazonaws.com",
		Timeout:  30,
		Verbose:  true,
	}
	checker := NewDNSChecker(config, "s3.amazonaws.com")

	// This test just verifies that verbose mode doesn't cause crashes
	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s", result.Status)
	}
}

// TestDNSCheck_NonStandardPort tests DNS resolution with non-standard port
func TestDNSCheck_NonStandardPort(t *testing.T) {
	config := output.Config{
		Endpoint: "https://s3.example.com:9000",
		Timeout:  30,
	}
	checker := NewDNSChecker(config, "s3.example.com")

	result := checker.Check()

	// Port should not affect DNS resolution
	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s", result.Status)
	}
}

// TestDNSCheck_IPv6Address tests handling of IPv6 addresses
func TestDNSCheck_IPv6Address(t *testing.T) {
	config := output.Config{
		Endpoint: "https://[2001:db8::1]",
		Timeout:  30,
	}
	checker := NewDNSChecker(config, "2001:db8::1")

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS for IPv6 address, got %s", result.Status)
	}
}

// TestDNSCheck_ResolutionTime tests that resolution time is measured
func TestDNSCheck_ResolutionTime(t *testing.T) {
	config := output.Config{
		Endpoint: "https://s3.amazonaws.com",
		Timeout:  30,
	}
	checker := NewDNSChecker(config, "s3.amazonaws.com")

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s", result.Status)
	}

	details, ok := result.Details.(output.DNSResult)
	if !ok {
		t.Fatal("Expected DNSResult in details")
	}

	if details.ResolutionTime == 0 {
		t.Error("Expected resolution time to be measured")
	}
}

// TestDNSCheck_Duration tests that duration is measured
func TestDNSCheck_Duration(t *testing.T) {
	config := output.Config{
		Endpoint: "https://s3.amazonaws.com",
		Timeout:  30,
	}
	checker := NewDNSChecker(config, "s3.amazonaws.com")

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s", result.Status)
	}

	if result.Duration == 0 {
		t.Error("Expected duration to be measured")
	}
}
