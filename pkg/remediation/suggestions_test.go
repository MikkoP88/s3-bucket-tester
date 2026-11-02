package remediation

import (
	"errors"
	"strings"
	"testing"
)

// TestGetRemediation_DNS_NoSuchHost tests DNS no such host remediation
func TestGetRemediation_DNS_NoSuchHost(t *testing.T) {
	err := errors.New("lookup s3.example.com: no such host")
	remediation := GetRemediation("DNS Resolution Check", err)

	if remediation == nil {
		t.Error("Expected remediation for DNS no such host error")
	}

	if remediation.Error != err.Error() {
		t.Errorf("Expected error '%s', got '%s'", err.Error(), remediation.Error)
	}

	if remediation.Cause == "" {
		t.Error("Expected cause to be set")
	}

	if remediation.Suggestion == "" {
		t.Error("Expected suggestion to be set")
	}
}

// TestGetRemediation_DNS_Timeout tests DNS timeout remediation
func TestGetRemediation_DNS_Timeout(t *testing.T) {
	err := errors.New("lookup s3.example.com: i/o timeout")
	remediation := GetRemediation("DNS Resolution Check", err)

	if remediation == nil {
		t.Error("Expected remediation for DNS timeout error")
	}

	if remediation.Error != err.Error() {
		t.Errorf("Expected error '%s', got '%s'", err.Error(), remediation.Error)
	}

	if len(remediation.Commands) == 0 {
		t.Error("Expected at least one command")
	}
}

// TestGetRemediation_TCP_ConnectionRefused tests TCP connection refused remediation
func TestGetRemediation_TCP_ConnectionRefused(t *testing.T) {
	err := errors.New("dial tcp 192.168.1.1:9000: connect: connection refused")
	remediation := GetRemediation("TCP Connectivity Check", err)

	if remediation == nil {
		t.Error("Expected remediation for TCP connection refused error")
	}

	if remediation.Error != err.Error() {
		t.Errorf("Expected error '%s', got '%s'", err.Error(), remediation.Error)
	}

	if len(remediation.Commands) == 0 {
		t.Error("Expected at least one command")
	}
}

// TestGetRemediation_TLS_CertificateExpired tests TLS certificate expired remediation
func TestGetRemediation_TLS_CertificateExpired(t *testing.T) {
	err := errors.New("x509: certificate has expired or is not yet valid")
	remediation := GetRemediation("SSL/TLS Certificate Check", err)

	if remediation == nil {
		t.Error("Expected remediation for TLS certificate expired error")
	}

	if remediation.Error != err.Error() {
		t.Errorf("Expected error '%s', got '%s'", err.Error(), remediation.Error)
	}

	if len(remediation.Commands) == 0 {
		t.Error("Expected at least one command")
	}
}

// TestGetRemediation_Auth_AccessDenied tests auth access denied remediation
func TestGetRemediation_Auth_AccessDenied(t *testing.T) {
	err := errors.New("403 Forbidden")
	remediation := GetRemediation("Bucket Authentication Check", err)

	if remediation == nil {
		t.Error("Expected remediation for auth access denied error")
	}

	if remediation.Error != err.Error() {
		t.Errorf("Expected error '%s', got '%s'", err.Error(), remediation.Error)
	}

	if len(remediation.Commands) == 0 {
		t.Error("Expected at least one command")
	}
}

// TestGetRemediation_UnknownError tests unknown error remediation
func TestGetRemediation_UnknownError(t *testing.T) {
	err := errors.New("some unknown error")
	remediation := GetRemediation("Unknown Test", err)

	if remediation == nil {
		t.Error("Expected remediation for unknown error")
	}

	if remediation.Error != err.Error() {
		t.Errorf("Expected error '%s', got '%s'", err.Error(), remediation.Error)
	}

	if remediation.Cause == "" {
		t.Error("Expected cause to be set")
	}

	if remediation.Suggestion == "" {
		t.Error("Expected suggestion to be set")
	}
}

// TestFormatRemediation tests remediation formatting
func TestFormatRemediation(t *testing.T) {
	remediation := &Remediation{
		Error:      "Test error",
		Cause:      "Test cause",
		Suggestion: "Test suggestion",
		Commands:   []string{"command1", "command2"},
	}

	formatted := FormatRemediation(remediation)

	// Matches the indented block FormatRemediation prints under a console header
	expected := "\n  Error: Test error\n  Cause: Test cause\n  Suggestion: Test suggestion\n  Commands to try:\n    - command1\n    - command2"
	if formatted != expected {
		t.Errorf("Expected formatted string to match, got:\n%s", formatted)
	}
}

// TestGetDNSRemediation tests DNS-specific remediation
func TestGetDNSRemediation(t *testing.T) {
	err := errors.New("lookup s3.example.com: no such host")
	remediation := getDNSRemediation(err.Error(), strings.ToLower(err.Error()))

	if remediation == nil {
		t.Error("Expected DNS remediation for no such host error")
	}

	if remediation.Cause != "The hostname does not exist or DNS resolution failed" {
		t.Errorf("Expected cause 'The hostname does not exist or DNS resolution failed', got '%s'", remediation.Cause)
	}

	if len(remediation.Commands) == 0 {
		t.Error("Expected at least one command")
	}
}

// TestGetTCPRemediation tests TCP-specific remediation
func TestGetTCPRemediation(t *testing.T) {
	err := errors.New("dial tcp 192.168.1.1:9000: connect: connection refused")
	remediation := getTCPRemediation(err.Error(), strings.ToLower(err.Error()))

	if remediation == nil {
		t.Error("Expected TCP remediation for connection refused error")
	}

	if remediation.Cause != "The target port is closed or no service is listening" {
		t.Errorf("Expected cause 'The target port is closed or no service is listening', got '%s'", remediation.Cause)
	}

	if len(remediation.Commands) == 0 {
		t.Error("Expected at least one command")
	}
}

// TestGetTLSRemediation tests TLS-specific remediation
func TestGetTLSRemediation(t *testing.T) {
	err := errors.New("x509: certificate has expired or is not yet valid")
	remediation := getTLSRemediation(err.Error(), strings.ToLower(err.Error()))

	if remediation == nil {
		t.Error("Expected TLS remediation for certificate expired error")
	}

	if remediation.Cause != "The SSL/TLS certificate has expired" {
		t.Errorf("Expected cause 'The SSL/TLS certificate has expired', got '%s'", remediation.Cause)
	}

	if len(remediation.Commands) == 0 {
		t.Error("Expected at least one command")
	}
}

// TestGetAuthRemediation tests auth-specific remediation
func TestGetAuthRemediation(t *testing.T) {
	err := errors.New("403 Forbidden")
	remediation := getAuthRemediation(err.Error(), strings.ToLower(err.Error()))

	if remediation == nil {
		t.Error("Expected auth remediation for access denied error")
	}

	if remediation.Cause != "Forbidden - request blocked by security policy" {
		t.Errorf("Expected cause 'Forbidden - request blocked by security policy', got '%s'", remediation.Cause)
	}

	if len(remediation.Commands) == 0 {
		t.Error("Expected at least one command")
	}
}
