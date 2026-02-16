package checker

import (
	"net"
	"testing"
	"time"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// TestNewTCPChecker tests the constructor
func TestNewTCPChecker(t *testing.T) {
	config := output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		Timeout:   30,
		Verbose:   true,
	}

	checker := NewTCPChecker(config, "s3.example.com", 443)

	if checker.Config.Endpoint != config.Endpoint {
		t.Errorf("Expected Endpoint '%s', got '%s'", config.Endpoint, checker.Config.Endpoint)
	}
	if checker.Host != "s3.example.com" {
		t.Errorf("Expected Host 's3.example.com', got '%s'", checker.Host)
	}
	if checker.Port != 443 {
		t.Errorf("Expected Port 443, got %d", checker.Port)
	}
	if checker.verbose == nil || !checker.verbose.enabled {
		t.Errorf("Expected verbose logger to be enabled")
	}
}

// TestTCPCheckerName tests the Name method
func TestTCPCheckerName(t *testing.T) {
	config := output.Config{}
	checker := NewTCPChecker(config, "example.com", 443)

	if checker.Name() != "TCP Connectivity Check" {
		t.Errorf("Expected name 'TCP Connectivity Check', got '%s'", checker.Name())
	}
}

// TestTCPCheck_Success tests successful TCP connection
func TestTCPCheck_Success(t *testing.T) {
	// Start a simple TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)

	config := output.Config{
		Endpoint: "https://127.0.0.1",
		Timeout:  5,
	}
	checker := NewTCPChecker(config, "127.0.0.1", addr.Port)

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

// TestTCPCheck_Timeout tests connection timeout
func TestTCPCheck_Timeout(t *testing.T) {
	// Use a non-routable IP that will timeout
	// 198.51.100.1 is TEST-NET-2 (documentation only, will timeout)
	config := output.Config{
		Endpoint: "https://198.51.100.1",
		Timeout:  2, // Short timeout for faster test
	}
	checker := NewTCPChecker(config, "198.51.100.1", 80)

	result := checker.Check()

	// Should timeout and fail
	if result.Status != output.StatusFail {
		t.Errorf("Expected status FAIL for timeout, got %s", result.Status)
	}
	if result.Error == "" {
		t.Error("Expected error message for timeout")
	}
}

// TestTCPCheck_Refused tests connection refused
func TestTCPCheck_Refused(t *testing.T) {
	// Try to connect to a port that's not listening
	config := output.Config{
		Endpoint: "https://127.0.0.1",
		Timeout:  2,
	}
	checker := NewTCPChecker(config, "127.0.0.1", 12345)

	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected status FAIL for connection refused, got %s", result.Status)
	}
	if result.Error == "" {
		t.Error("Expected error message for connection refused")
	}
}

// TestTCPCheck_Unreachable tests host unreachable
func TestTCPCheck_Unreachable(t *testing.T) {
	// Use a non-routable IP
	// 192.0.2.1 is TEST-NET-1 (documentation only, will be unreachable)
	config := output.Config{
		Endpoint: "https://192.0.2.1",
		Timeout:  2,
	}
	checker := NewTCPChecker(config, "192.0.2.1", 80)

	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected status FAIL for unreachable host, got %s", result.Status)
	}
}

// TestTCPCheck_ConnectionDetails tests that connection details are captured
func TestTCPCheck_ConnectionDetails(t *testing.T) {
	// Start a simple TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)

	config := output.Config{
		Endpoint: "https://127.0.0.1",
		Timeout:  5,
	}
	checker := NewTCPChecker(config, "127.0.0.1", addr.Port)

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s", result.Status)
	}

	details, ok := result.Details.(output.TCPResult)
	if !ok {
		t.Fatal("Expected TCPResult in details")
	}

	if !details.Connected {
		t.Error("Expected Connected to be true")
	}
	if details.Host != "127.0.0.1" {
		t.Errorf("Expected Host '127.0.0.1', got '%s'", details.Host)
	}
	if details.Port != addr.Port {
		t.Errorf("Expected Port %d, got %d", addr.Port, details.Port)
	}
	if details.ConnectionTime == 0 {
		t.Error("Expected ConnectionTime to be measured")
	}
	if details.LocalAddr == "" {
		t.Error("Expected LocalAddr to be populated")
	}
	if details.RemoteAddr == "" {
		t.Error("Expected RemoteAddr to be populated")
	}
}

// TestTCPCheck_InvalidPort tests handling of invalid port
func TestTCPCheck_InvalidPort(t *testing.T) {
	config := output.Config{
		Endpoint: "https://127.0.0.1",
		Timeout:  5,
	}
	checker := NewTCPChecker(config, "127.0.0.1", 99999)

	result := checker.Check()

	// Invalid port should fail
	if result.Status != output.StatusFail {
		t.Errorf("Expected status FAIL for invalid port, got %s", result.Status)
	}
}

// TestTCPCheck_EmptyHostname tests handling of empty hostname
func TestTCPCheck_EmptyHostname(t *testing.T) {
	config := output.Config{
		Endpoint: "https://",
		Timeout:  5,
	}
	checker := NewTCPChecker(config, "", 443)

	result := checker.Check()

	// Empty hostname should fail
	if result.Status != output.StatusFail {
		t.Errorf("Expected status FAIL for empty hostname, got %s", result.Status)
	}
}

// TestTCPCheck_VerboseLogging tests verbose logging
func TestTCPCheck_VerboseLogging(t *testing.T) {
	// Start a simple TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)

	config := output.Config{
		Endpoint: "https://127.0.0.1",
		Timeout:  5,
		Verbose:  true,
	}
	checker := NewTCPChecker(config, "127.0.0.1", addr.Port)

	// This test just verifies that verbose mode doesn't cause crashes
	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s", result.Status)
	}
}

// TestTCPCheck_Duration tests that duration is measured
func TestTCPCheck_Duration(t *testing.T) {
	// Start a simple TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)

	config := output.Config{
		Endpoint: "https://127.0.0.1",
		Timeout:  5,
	}
	checker := NewTCPChecker(config, "127.0.0.1", addr.Port)

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s", result.Status)
	}

	if result.Duration == 0 {
		t.Error("Expected duration to be measured")
	}
}

// TestTCPCheck_HTTPSPort tests connection to HTTPS port
func TestTCPCheck_HTTPSPort(t *testing.T) {
	// Start a listener on port 443
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)

	config := output.Config{
		Endpoint: "https://127.0.0.1",
		Timeout:  5,
	}
	checker := NewTCPChecker(config, "127.0.0.1", addr.Port)

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s", result.Status)
	}
}

// TestTCPCheck_HTTPPort tests connection to HTTP port
func TestTCPCheck_HTTPPort(t *testing.T) {
	// Start a listener on port 80
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)

	config := output.Config{
		Endpoint: "http://127.0.0.1",
		Timeout:  5,
	}
	checker := NewTCPChecker(config, "127.0.0.1", addr.Port)

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s", result.Status)
	}
}

// TestTCPCheck_IPv6Address tests handling of IPv6 addresses
func TestTCPCheck_IPv6Address(t *testing.T) {
	// Skip IPv6 test if not supported
	if !supportsIPv6() {
		t.Skip("IPv6 not supported on this system")
	}

	// Start a listener on IPv6
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Fatalf("Failed to create IPv6 listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)

	config := output.Config{
		Endpoint: "https://[::1]",
		Timeout:  5,
	}
	checker := NewTCPChecker(config, "::1", addr.Port)

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS for IPv6, got %s", result.Status)
	}
}

// supportsIPv6 checks if IPv6 is supported
func supportsIPv6() bool {
	conn, err := net.Dial("tcp6", "[::1]:80")
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// TestTCPCheck_TimeoutFromConfig tests that timeout from config is used
func TestTCPCheck_TimeoutFromConfig(t *testing.T) {
	// Start a simple TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)

	config := output.Config{
		Endpoint: "https://127.0.0.1",
		Timeout:  10,
	}
	checker := NewTCPChecker(config, "127.0.0.1", addr.Port)

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s", result.Status)
	}

	// Verify timeout was used
	if result.Duration > 10*time.Second {
		t.Errorf("Expected duration to be less than config timeout, got %v", result.Duration)
	}
}
