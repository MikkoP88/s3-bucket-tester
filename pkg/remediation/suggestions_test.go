package remediation

import (
	"errors"
	"testing"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
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

	if formatted != "Error: Test error\nCause: Test cause\nSuggestion: Test suggestion\nCommands to try:\n  - command1\n  - command2\n" {
		t.Errorf("Expected formatted string to match, got:\n%s", formatted)
	}
}

// TestGetDNSRemediation tests DNS-specific remediation
func TestGetDNSRemediation(t *testing.T) {
	err := errors.New("lookup s3.example.com: no such host")
	remediation := getDNSRemediation(err.Error())

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
	remediation := getTCPRemediation(err.Error())

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
	remediation := getTLSRemediation(err.Error())

	if remediation == nil {
		t.Error("Expected TLS remediation for certificate expired error")
	}

	if remediation.Cause != "The certificate is not trusted or self-signed" {
		t.Errorf("Expected cause 'The certificate is not trusted or self-signed', got '%s'", remediation.Cause)
	}

	if len(remediation.Commands) == 0 {
		t.Error("Expected at least one command")
	}
}

// TestGetAuthRemediation tests auth-specific remediation
func TestGetAuthRemediation(t *testing.T) {
	err := errors.New("403 Forbidden")
	remediation := getAuthRemediation(err.Error())

	if remediation == nil {
		t.Error("Expected auth remediation for access denied error")
	}

	if remediation.Cause != "Access denied - credentials may be incorrect or insufficient permissions" {
		t.Errorf("Expected cause 'Access denied - credentials may be incorrect or insufficient permissions', got '%s'", remediation.Cause)
	}

	if len(remediation.Commands) == 0 {
		t.Error("Expected at least one command")
	}
}

// getDNSRemediation returns DNS-specific remediation
func getDNSRemediation(errMsg string) *Remediation {
	return &Remediation{
		Error:      errMsg,
		Cause:      "The hostname does not exist or DNS resolution failed",
		Suggestion: "Verify the hostname is correct and DNS servers are properly configured",
		Commands:   []string{
			"nslookup <hostname>",
			"dig <hostname>",
			"ping <hostname>",
			"Check /etc/resolv.conf (Linux) or DNS settings (Windows)",
			"Try using a public DNS server like 8.8.8.8 or 1.1.1.1",
		},
	}
}

// getTCPRemediation returns TCP-specific remediation
func getTCPRemediation(errMsg string) *Remediation {
	return &Remediation{
		Error:      errMsg,
		Cause:      "The target port is closed or no service is listening",
		Suggestion: "Verify the service is running and the correct port is specified",
		Commands:   []string{
			"telnet <host> <port>",
			"nc -zv <host> <port>",
			"Check firewall rules allow traffic to the port",
			"Check if the service is running: systemctl status <service> or service <service> status",
		},
	}
}

// getTLSRemediation returns TLS-specific remediation
func getTLSRemediation(errMsg string) *Remediation {
	return &Remediation{
		Error:      errMsg,
		Cause:      "The certificate is not trusted or self-signed",
		Suggestion: "Verify the certificate chain or use --insecure for testing only",
		Commands:   []string{
			"openssl s_client -connect <host>:<port> -showcerts",
			"Check if the certificate is valid: openssl x509 -in <cert-file> -noout -dates",
			"Check certificate expiration: openssl x509 -in <cert-file> -noout -dates -checkend 0",
		},
	}
}

// getAuthRemediation returns auth-specific remediation
func getAuthRemediation(errMsg string) *Remediation {
	return &Remediation{
		Error:      errMsg,
		Cause:      "Access denied - credentials may be incorrect or insufficient permissions",
		Suggestion: "Verify access key and secret key are correct and have proper permissions",
		Commands:   []string{
			"Verify credentials in your S3 provider console",
			"Check if bucket policy allows access",
			"Verify region matches bucket's region",
			"Check if addressing style is correct (path-style vs virtual-hosted)",
			"Check if user has necessary IAM permissions",
		},
	}
}
}
