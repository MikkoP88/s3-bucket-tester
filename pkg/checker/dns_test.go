package checker

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// stubResolver is a deterministic DNS resolver for tests.
type stubResolver struct {
	ips       []net.IPAddr
	names     []string
	lookupErr error
	block     bool // simulate a resolver that hangs until the context deadline
}

func (s *stubResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if s.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if s.lookupErr != nil {
		return nil, s.lookupErr
	}
	return s.ips, nil
}

func (s *stubResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	if s.block {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return s.names, nil
}

// newDNSCheckerWithStub builds a DNSChecker wired to a stub resolver.
func newDNSCheckerWithStub(stub *stubResolver) *DNSChecker {
	config := output.Config{
		Endpoint: "https://s3.example.com",
		Timeout:  5,
	}
	checker := NewDNSChecker(config, "s3.example.com")
	checker.resolver = stub
	return checker
}

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
	if checker.resolver == nil {
		t.Error("Expected default resolver to be set")
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
	checker := newDNSCheckerWithStub(&stubResolver{
		ips: []net.IPAddr{
			{IP: net.ParseIP("192.0.2.10")},
			{IP: net.ParseIP("192.0.2.11")},
		},
	})

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s (error: %s)", result.Status, result.Error)
	}
	if result.Error != "" {
		t.Errorf("Expected no error, got '%s'", result.Error)
	}
	details, ok := result.Details.(output.DNSResult)
	if !ok {
		t.Fatal("Expected DNSResult in details")
	}
	if len(details.IPs) != 2 {
		t.Errorf("Expected 2 IP addresses, got %d", len(details.IPs))
	}
	if details.Hostname != "s3.example.com" {
		t.Errorf("Expected hostname 's3.example.com', got '%s'", details.Hostname)
	}
}

// TestDNSCheck_IPAddress tests handling of direct IP addresses
func TestDNSCheck_IPAddress(t *testing.T) {
	checker := newDNSCheckerWithStub(&stubResolver{
		names: []string{"host.example.com."},
	})
	checker.Hostname = "192.168.1.100"

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS for IP address, got %s (error: %s)", result.Status, result.Error)
	}
	details, ok := result.Details.(output.DNSResult)
	if !ok {
		t.Fatal("Expected DNSResult in details")
	}
	if details.ReverseDNS != "host.example.com." {
		t.Errorf("Expected reverse DNS 'host.example.com.', got '%s'", details.ReverseDNS)
	}
}

// TestDNSCheck_Timeout tests DNS timeout behavior
func TestDNSCheck_Timeout(t *testing.T) {
	checker := newDNSCheckerWithStub(&stubResolver{block: true})
	checker.Config.Timeout = 1

	start := time.Now()
	result := checker.Check()
	elapsed := time.Since(start)

	if result.Status != output.StatusFail {
		t.Errorf("Expected status FAIL on resolver timeout, got %s", result.Status)
	}
	if elapsed > 3*time.Second {
		t.Errorf("Expected check to respect the timeout, took %v", elapsed)
	}
}

// TestDNSCheck_Failure tests DNS resolution failure
func TestDNSCheck_Failure(t *testing.T) {
	checker := newDNSCheckerWithStub(&stubResolver{
		lookupErr: errors.New("lookup this-domain-does-not-exist: no such host"),
	})

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
	checker := newDNSCheckerWithStub(&stubResolver{
		ips:   []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}},
		names: []string{"s3.example.com."},
	})

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s (error: %s)", result.Status, result.Error)
	}
	details, ok := result.Details.(output.DNSResult)
	if !ok {
		t.Fatal("Expected DNSResult in details")
	}
	if details.ReverseDNS != "s3.example.com." {
		t.Errorf("Expected reverse DNS 's3.example.com.', got '%s'", details.ReverseDNS)
	}
}

// TestDNSCheck_MultipleIPs tests handling of multiple IP addresses
func TestDNSCheck_MultipleIPs(t *testing.T) {
	checker := newDNSCheckerWithStub(&stubResolver{
		ips: []net.IPAddr{
			{IP: net.ParseIP("192.0.2.1")},
			{IP: net.ParseIP("192.0.2.2")},
			{IP: net.ParseIP("2001:db8::1")},
		},
	})

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s (error: %s)", result.Status, result.Error)
	}
	details, ok := result.Details.(output.DNSResult)
	if !ok {
		t.Fatal("Expected DNSResult in details")
	}
	if len(details.IPs) != 3 {
		t.Errorf("Expected 3 IP addresses, got %d", len(details.IPs))
	}
}

// TestDNSCheck_EmptyHostname tests handling of empty hostname
func TestDNSCheck_EmptyHostname(t *testing.T) {
	checker := newDNSCheckerWithStub(&stubResolver{
		lookupErr: errors.New("lookup : no such host"),
	})
	checker.Hostname = ""

	result := checker.Check()

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
	checker := newDNSCheckerWithStub(&stubResolver{block: true})
	checker.Config.Timeout = 1

	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected status FAIL on context timeout, got %s", result.Status)
	}
	if result.Error == "" {
		t.Error("Expected an error describing the timeout")
	}
}

// TestDNSCheck_VerboseLogging tests verbose logging
func TestDNSCheck_VerboseLogging(t *testing.T) {
	checker := newDNSCheckerWithStub(&stubResolver{
		ips: []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}},
	})
	checker.Config.Verbose = true
	checker.verbose = NewVerboseLogger(true)

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s (error: %s)", result.Status, result.Error)
	}
}

// TestDNSCheck_NonStandardPort tests DNS resolution is independent of the port
func TestDNSCheck_NonStandardPort(t *testing.T) {
	checker := newDNSCheckerWithStub(&stubResolver{
		ips: []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}},
	})
	checker.Config.Endpoint = "https://s3.example.com:9000"

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s (error: %s)", result.Status, result.Error)
	}
}

// TestDNSCheck_IPv6Address tests handling of IPv6 addresses
func TestDNSCheck_IPv6Address(t *testing.T) {
	checker := newDNSCheckerWithStub(&stubResolver{})
	checker.Hostname = "2001:db8::1"

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS for IPv6 address, got %s (error: %s)", result.Status, result.Error)
	}
	details, ok := result.Details.(output.DNSResult)
	if !ok {
		t.Fatal("Expected DNSResult in details")
	}
	if len(details.IPs) != 1 || details.IPs[0] != "2001:db8::1" {
		t.Errorf("Expected IP '2001:db8::1', got %v", details.IPs)
	}
}

// TestDNSCheck_ResolutionTime tests that resolution time is measured
func TestDNSCheck_ResolutionTime(t *testing.T) {
	checker := newDNSCheckerWithStub(&stubResolver{
		ips: []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}},
	})

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s (error: %s)", result.Status, result.Error)
	}
	details, ok := result.Details.(output.DNSResult)
	if !ok {
		t.Fatal("Expected DNSResult in details")
	}
	// Resolution time can legitimately be 0ms on a stub; just ensure the field exists
	if details.ResolutionTime < 0 {
		t.Errorf("Expected non-negative resolution time, got %d", details.ResolutionTime)
	}
}

// TestDNSCheck_Duration tests that duration is measured
func TestDNSCheck_Duration(t *testing.T) {
	checker := newDNSCheckerWithStub(&stubResolver{
		ips: []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}},
	})

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s (error: %s)", result.Status, result.Error)
	}
	if result.Duration < 0 {
		t.Errorf("Expected non-negative duration, got %v", result.Duration)
	}
}
