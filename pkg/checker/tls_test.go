package checker

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// generateTestCert creates a self-signed certificate from the given template.
func generateTestCert(t *testing.T, template *x509.Certificate) (tls.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(1)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}, cert, key
}

// signTestCert creates a leaf certificate signed by the given CA.
func signTestCert(t *testing.T, template, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	if template.SerialNumber == nil {
		template.SerialNumber = big.NewInt(2)
	}

	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startTLSTestServer starts an httptest TLS server using the given certificate chain.
func startTLSTestServer(t *testing.T, cert tls.Certificate) *httptest.Server {
	t.Helper()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server
}

// tlsServerHostPort extracts host and port from an httptest server URL.
func tlsServerHostPort(t *testing.T, server *httptest.Server) (string, int) {
	t.Helper()

	host, portStr, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatalf("Failed to parse server URL: %v", err)
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		t.Fatalf("Failed to parse port: %v", err)
	}
	return host, port
}

// validTLSCertTemplate returns a certificate template valid from now to now+365d.
func validTLSCertTemplate(commonName string, dnsNames []string, ips []net.IP) *x509.Certificate {
	now := time.Now()
	return &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"s3-bucket-tester"}},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}
}

// TestNewTLSChecker tests the constructor
func TestNewTLSChecker(t *testing.T) {
	config := output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		Timeout:   30,
		Verbose:   true,
	}

	checker := NewTLSChecker(config, "s3.example.com", 443)

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

// TestTLSCheckerName tests the Name method
func TestTLSCheckerName(t *testing.T) {
	config := output.Config{}
	checker := NewTLSChecker(config, "example.com", 443)

	if checker.Name() != "SSL/TLS Certificate Check" {
		t.Errorf("Expected name 'SSL/TLS Certificate Check', got '%s'", checker.Name())
	}
}

// TestTLSVersionToString tests TLS version formatting
func TestTLSVersionToString(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tlsVersionToString(tt.version)
			if result != tt.expected {
				t.Errorf("tlsVersionToString(%d) = %v, want %v", tt.version, result, tt.expected)
			}
		})
	}
}

// TestTLSCheck_Success tests a TLS handshake against a local server
func TestTLSCheck_Success(t *testing.T) {
	cert, _, _ := generateTestCert(t, validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}))
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: true}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	// The test certificate is locally generated and untrusted, so even a
	// fully successful handshake is WARN: the chain cannot be verified.
	// PASS requires a chain trusted by the local trust store.
	if result.Status != output.StatusWarn {
		t.Errorf("Expected WARN for unverified chain, got %s (error: %s)", result.Status, result.Error)
	}
	if result.Details == nil {
		t.Fatal("Expected details to be populated")
	}
}

// TestTLSCheck_CertificateExpired tests expired certificate detection
func TestTLSCheck_CertificateExpired(t *testing.T) {
	now := time.Now()
	template := validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	template.NotBefore = now.Add(-96 * time.Hour)
	template.NotAfter = now.Add(-48 * time.Hour)
	cert, _, _ := generateTestCert(t, template)
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: true}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	details, ok := result.Details.(output.TLSResult)
	if !ok {
		t.Fatalf("Expected TLSResult details, got %T", result.Details)
	}
	if !details.Certificate.IsExpired {
		t.Error("Expected certificate to be marked expired")
	}
	if details.Certificate.DaysUntilExpiry >= 0 {
		t.Errorf("Expected negative days until expiry, got %d", details.Certificate.DaysUntilExpiry)
	}
	// An expired certificate must fail even with verification disabled
	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL for expired certificate, got %s", result.Status)
	}
}

// TestTLSCheck_CertificateNotYetValid tests that a certificate whose
// validity starts in the future fails even with verification disabled
func TestTLSCheck_CertificateNotYetValid(t *testing.T) {
	now := time.Now()
	template := validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	template.NotBefore = now.Add(48 * time.Hour)
	template.NotAfter = now.Add(96 * time.Hour)
	cert, _, _ := generateTestCert(t, template)
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: true}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL for not-yet-valid certificate, got %s", result.Status)
	}
	if !strings.Contains(result.Error, "not yet valid") {
		t.Errorf("Expected not-yet-valid error, got '%s'", result.Error)
	}
}

// TestTLSCheck_CertificateExpired_VerifyEnabled tests that an expired cert fails verification.
// A locally generated cert is also untrusted, so Go reports the unknown-authority error,
// but the check must FAIL either way.
func TestTLSCheck_CertificateExpired_VerifyEnabled(t *testing.T) {
	now := time.Now()
	template := validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	template.NotBefore = now.Add(-96 * time.Hour)
	template.NotAfter = now.Add(-48 * time.Hour)
	cert, _, _ := generateTestCert(t, template)
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: false}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL for expired certificate with verification enabled, got %s", result.Status)
	}
	if !strings.Contains(result.Error, "expired") && !strings.Contains(result.Error, "authority") {
		t.Errorf("Expected expiry or trust error, got '%s'", result.Error)
	}
}

// TestTLSCheck_CertificateNearExpiry tests near-expiry calculation
func TestTLSCheck_CertificateNearExpiry(t *testing.T) {
	template := validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	template.NotAfter = time.Now().Add(15 * 24 * time.Hour)
	cert, _, _ := generateTestCert(t, template)
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: true}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	details, ok := result.Details.(output.TLSResult)
	if !ok {
		t.Fatalf("Expected TLSResult details, got %T", result.Details)
	}
	if details.Certificate.IsExpired {
		t.Error("Expected certificate to not be expired")
	}
	if details.Certificate.DaysUntilExpiry < 14 || details.Certificate.DaysUntilExpiry > 16 {
		t.Errorf("Expected ~15 days until expiry, got %d", details.Certificate.DaysUntilExpiry)
	}
	// Near expiry (under 30 days) is a warning, not a pass
	if result.Status != output.StatusWarn {
		t.Errorf("Expected WARN for near-expiry certificate, got %s", result.Status)
	}
	if len(result.Warnings) == 0 {
		t.Error("Expected near-expiry warning to be reported")
	}
}

// TestTLSCheck_InsecureSkipVerify tests insecure mode records unverified status
// as a warning: the handshake succeeds but the result must not claim PASS
func TestTLSCheck_InsecureSkipVerify(t *testing.T) {
	cert, _, _ := generateTestCert(t, validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}))
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: true}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	if result.Status != output.StatusWarn {
		t.Errorf("Expected WARN in insecure mode, got %s (error: %s)", result.Status, result.Error)
	}
	if !strings.Contains(result.Error, "--insecure") {
		t.Errorf("Expected error to mention --insecure, got '%s'", result.Error)
	}
	details, ok := result.Details.(output.TLSResult)
	if !ok {
		t.Fatalf("Expected TLSResult details, got %T", result.Details)
	}
	if details.Verified {
		t.Error("Expected Verified to be false in insecure mode")
	}
}

// TestTLSCheck_MinTLSVersion tests that negotiated version is TLS 1.2 or higher
func TestTLSCheck_MinTLSVersion(t *testing.T) {
	cert, _, _ := generateTestCert(t, validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}))
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: true}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	details, ok := result.Details.(output.TLSResult)
	if !ok {
		t.Fatalf("Expected TLSResult details, got %T", result.Details)
	}
	if details.TLSVersion != "TLS 1.2" && details.TLSVersion != "TLS 1.3" {
		t.Errorf("Expected TLS 1.2 or 1.3, got '%s'", details.TLSVersion)
	}
}

// TestTLSCheck_CertificateChain tests certificate chain parsing
func TestTLSCheck_CertificateChain(t *testing.T) {
	caTLSCert, caParsed, caKey := generateTestCert(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA", Organization: []string{"s3-bucket-tester"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	})

	leafTemplate := validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	leaf := signTestCert(t, leafTemplate, caParsed, caKey)
	// Present leaf followed by CA so the client sees the full chain
	leaf.Certificate = append(leaf.Certificate, caTLSCert.Certificate[0])

	server := startTLSTestServer(t, leaf)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: true}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	details, ok := result.Details.(output.TLSResult)
	if !ok {
		t.Fatalf("Expected TLSResult details, got %T", result.Details)
	}
	if len(details.PeerCerts) < 2 {
		t.Errorf("Expected at least 2 peer certificates, got %d", len(details.PeerCerts))
	}
	if len(details.Certificate.Chain) < 1 {
		t.Error("Expected certificate chain to be populated")
	}
}

// TestTLSCheck_SANs tests Subject Alternative Names extraction
func TestTLSCheck_SANs(t *testing.T) {
	cert, _, _ := generateTestCert(t, validTLSCertTemplate("s3.example.com", []string{"s3.example.com", "example.com"}, nil))
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: true}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	details, ok := result.Details.(output.TLSResult)
	if !ok {
		t.Fatalf("Expected TLSResult details, got %T", result.Details)
	}
	sans := strings.Join(details.Certificate.SANs, ",")
	if !strings.Contains(sans, "s3.example.com") || !strings.Contains(sans, "example.com") {
		t.Errorf("Expected SANs to contain both names, got '%s'", sans)
	}
}

// TestTLSCheck_Timeout tests that an unresponsive server results in FAIL
func TestTLSCheck_Timeout(t *testing.T) {
	// Listener that accepts connections but closes them immediately,
	// making the TLS handshake fail without any network dependency.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	config := output.Config{Timeout: 5, Insecure: true}
	checker := NewTLSChecker(config, "127.0.0.1", ln.Addr().(*net.TCPAddr).Port)

	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL for unresponsive server, got %s", result.Status)
	}
}

// TestTLSCheck_ConnectionRefused tests connection refused
func TestTLSCheck_ConnectionRefused(t *testing.T) {
	// Reserve a port and release it so nothing is listening on it
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	config := output.Config{Timeout: 5}
	checker := NewTLSChecker(config, "127.0.0.1", port)

	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL for connection refused, got %s", result.Status)
	}
}

// TestTLSCheck_CertificateInfo tests certificate information extraction
func TestTLSCheck_CertificateInfo(t *testing.T) {
	template := validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	cert, parsed, _ := generateTestCert(t, template)
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: true}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	details, ok := result.Details.(output.TLSResult)
	if !ok {
		t.Fatalf("Expected TLSResult details, got %T", result.Details)
	}
	if details.Certificate.Subject != parsed.Subject.String() {
		t.Errorf("Expected subject '%s', got '%s'", parsed.Subject.String(), details.Certificate.Subject)
	}
	if details.Certificate.Issuer == "" {
		t.Error("Expected issuer to be populated")
	}
	if details.Certificate.NotBefore.IsZero() || details.Certificate.NotAfter.IsZero() {
		t.Error("Expected validity dates to be populated")
	}
	if details.Certificate.SignatureAlgorithm == "" {
		t.Error("Expected signature algorithm to be populated")
	}
}

// TestTLSCheck_VerboseLogging tests verbose logging does not crash
func TestTLSCheck_VerboseLogging(t *testing.T) {
	cert, _, _ := generateTestCert(t, validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}))
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: true, Verbose: true}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	if result.Details == nil {
		t.Error("Expected details to be populated")
	}
}

// TestTLSCheck_Duration tests that duration is measured
func TestTLSCheck_Duration(t *testing.T) {
	cert, _, _ := generateTestCert(t, validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}))
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: true}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	if result.Duration <= 0 {
		t.Error("Expected duration to be measured")
	}
}

// TestTLSCheck_EmptyHostname tests handling of empty hostname
func TestTLSCheck_EmptyHostname(t *testing.T) {
	config := output.Config{Timeout: 5}
	checker := NewTLSChecker(config, "", 443)

	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL for empty hostname, got %s", result.Status)
	}
}

// TestTLSCheck_InvalidPort tests handling of invalid port
func TestTLSCheck_InvalidPort(t *testing.T) {
	config := output.Config{Timeout: 5}
	checker := NewTLSChecker(config, "127.0.0.1", 99999)

	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL for invalid port, got %s", result.Status)
	}
}

// TestTLSCheck_IPv6Address tests handling of IPv6 addresses
func TestTLSCheck_IPv6Address(t *testing.T) {
	if !supportsIPv6() {
		t.Skip("IPv6 not supported on this system")
	}

	cert, _, _ := generateTestCert(t, validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("::1")}))
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("Cannot listen on IPv6: %v", err)
	}
	server.Listener = ln
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	t.Cleanup(server.Close)

	port := ln.Addr().(*net.TCPAddr).Port

	config := output.Config{Timeout: 10, Insecure: true}
	checker := NewTLSChecker(config, "::1", port)

	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected PASS over IPv6, got %s (error: %s)", result.Status, result.Error)
	}
}

// TestTLSCheck_HostnameMismatch tests that a certificate issued for another
// name fails verification. The locally generated cert is also untrusted, so
// Go's verifier reports the trust failure; the key assertion is that the
// check does not PASS for a name that does not match the connection host.
func TestTLSCheck_HostnameMismatch(t *testing.T) {
	// Certificate is valid for example.com, but we connect to 127.0.0.1
	cert, _, _ := generateTestCert(t, validTLSCertTemplate("example.com", []string{"example.com"}, nil))
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: false}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL for hostname mismatch, got %s", result.Status)
	}
	if !strings.Contains(result.Error, "valid for") && !strings.Contains(result.Error, "authority") {
		t.Errorf("Expected hostname or trust verification error, got '%s'", result.Error)
	}
}

// TestTLSCheck_SelfSignedCertificate tests self-signed certificate handling with verification enabled
func TestTLSCheck_SelfSignedCertificate(t *testing.T) {
	cert, _, _ := generateTestCert(t, validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}))
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: false}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL for untrusted self-signed certificate, got %s", result.Status)
	}
	if !strings.Contains(result.Error, "authority") {
		t.Errorf("Expected unknown-authority error, got '%s'", result.Error)
	}
	// The insecure fallback should still capture certificate details for diagnostics
	details, ok := result.Details.(output.TLSResult)
	if !ok {
		t.Fatalf("Expected TLSResult details from fallback, got %T", result.Details)
	}
	if details.Verified {
		t.Error("Expected Verified to be false for untrusted certificate")
	}
}

// TestTLSCheck_CertificateFields tests certificate field extraction
func TestTLSCheck_CertificateFields(t *testing.T) {
	cert, _, _ := generateTestCert(t, validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}))
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: true}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	details, ok := result.Details.(output.TLSResult)
	if !ok {
		t.Fatalf("Expected TLSResult details, got %T", result.Details)
	}
	if details.Host != host {
		t.Errorf("Expected Host '%s', got '%s'", host, details.Host)
	}
	if details.Port != port {
		t.Errorf("Expected Port %d, got %d", port, details.Port)
	}
}

// TestTLSCheck_CertificateExpiryCalculation tests days until expiry calculation
func TestTLSCheck_CertificateExpiryCalculation(t *testing.T) {
	// Test with certificate expiring in 30 days
	notAfter := time.Now().Add(30 * 24 * time.Hour)
	daysUntil := int(time.Until(notAfter).Hours() / 24)

	if daysUntil < 29 || daysUntil > 31 {
		t.Errorf("Expected days until expiry to be ~30, got %d", daysUntil)
	}

	// Test with expired certificate
	notAfterExpired := time.Now().Add(-1 * time.Hour)
	daysUntilExpired := int(time.Until(notAfterExpired).Hours() / 24)

	if daysUntilExpired > 0 {
		t.Errorf("Expected negative days for expired cert, got %d", daysUntilExpired)
	}
}

// TestTLSCheck_TLSCipherSuite tests cipher suite detection
func TestTLSCheck_TLSCipherSuite(t *testing.T) {
	cert, _, _ := generateTestCert(t, validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}))
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: true}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	details, ok := result.Details.(output.TLSResult)
	if !ok {
		t.Fatalf("Expected TLSResult details, got %T", result.Details)
	}
	if details.CipherSuite == "" {
		t.Error("Expected cipher suite to be populated")
	}
}

// TestTLSCheck_ConnectionDetails tests connection details are captured
func TestTLSCheck_ConnectionDetails(t *testing.T) {
	cert, _, _ := generateTestCert(t, validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}))
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: true}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	details, ok := result.Details.(output.TLSResult)
	if !ok {
		t.Fatalf("Expected TLSResult details, got %T", result.Details)
	}
	if details.TLSVersion == "" {
		t.Error("Expected TLS version to be recorded")
	}
	if details.CipherSuite == "" {
		t.Error("Expected cipher suite to be recorded")
	}
}

// TestTLSCheck_VerifiedFlag tests verification status reporting
func TestTLSCheck_VerifiedFlag(t *testing.T) {
	cert, _, _ := generateTestCert(t, validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")}))
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: true}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	details, ok := result.Details.(output.TLSResult)
	if !ok {
		t.Fatalf("Expected TLSResult details, got %T", result.Details)
	}
	if details.Verified {
		t.Error("Expected Verified to be false for a self-signed certificate in insecure mode")
	}
	if details.VerifyError != "" {
		t.Errorf("Expected empty VerifyError in insecure mode, got '%s'", details.VerifyError)
	}
}

// TestTLSCheck_CertificateSerialNumber tests serial number extraction
func TestTLSCheck_CertificateSerialNumber(t *testing.T) {
	template := validTLSCertTemplate("localhost", []string{"localhost"}, []net.IP{net.ParseIP("127.0.0.1")})
	template.SerialNumber = big.NewInt(123456789)
	cert, _, _ := generateTestCert(t, template)
	server := startTLSTestServer(t, cert)
	host, port := tlsServerHostPort(t, server)

	config := output.Config{Endpoint: server.URL, Timeout: 10, Insecure: true}
	checker := NewTLSChecker(config, host, port)

	result := checker.Check()

	details, ok := result.Details.(output.TLSResult)
	if !ok {
		t.Fatalf("Expected TLSResult details, got %T", result.Details)
	}
	if details.Certificate.SerialNumber != "123456789" {
		t.Errorf("Expected serial number '123456789', got '%s'", details.Certificate.SerialNumber)
	}
}
