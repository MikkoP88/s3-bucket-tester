package checker

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// TLSChecker performs SSL/TLS certificate checks
type TLSChecker struct {
	BaseChecker
	Host    string
	Port    int
	verbose *VerboseLogger
}

// NewTLSChecker creates a new TLS checker
func NewTLSChecker(config output.Config, host string, port int) *TLSChecker {
	return &TLSChecker{
		BaseChecker: NewBaseChecker(config),
		Host:        host,
		Port:        port,
		verbose:     NewVerboseLogger(config.Verbose),
	}
}

// Name returns the name of the checker
func (c *TLSChecker) Name() string {
	return "SSL/TLS Certificate Check"
}

// Check performs the TLS certificate check
func (c *TLSChecker) Check() output.TestResult {
	startTime := time.Now()

	c.verbose.LogSection("Starting SSL/TLS Certificate Check")

	result := output.TestResult{
		TestName: c.Name(),
		Status:   output.StatusPass,
		Duration: time.Since(startTime),
	}

	// Create address
	address := fmt.Sprintf("%s:%d", c.Host, c.Port)

	c.verbose.LogMessage("Attempting TLS connection to: %s", address)
	c.verbose.LogMessage("Server name: %s", c.Host)
	c.verbose.LogMessage("Insecure skip verify: %v", c.Config.Insecure)
	c.verbose.LogMessage("Minimum TLS version: TLS 1.2")

	// Create TLS config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: c.Config.Insecure,
		ServerName:         c.Host,
		MinVersion:         tls.VersionTLS12,
	}

	// Set dial timeout
	timeout := time.Duration(c.Config.Timeout) * time.Second

	// Create connection
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: timeout},
		"tcp",
		address,
		tlsConfig,
	)

	if err != nil {
		c.verbose.LogMessage("TLS connection failed: %v", err)
		// TLS check should continue even on failure, but mark as failed
		result.Status = output.StatusFail
		result.Error = err.Error()
		result.Duration = time.Since(startTime)

		// Try to get some certificate info even on failure
		if certErr := c.tryGetCertificateInfo(address, &result); certErr != nil {
			// If we can't get any info, return with the original error
			c.verbose.LogMessage("Could not retrieve certificate info: %v", certErr)
			return result
		}
		return result
	}
	defer conn.Close()

	c.verbose.LogMessage("TLS connection established successfully")

	// Get connection state
	state := conn.ConnectionState()

	c.verbose.LogMessage("TLS Version: %s", tlsVersionToString(state.Version))
	c.verbose.LogMessage("Cipher Suite: %s", tls.CipherSuiteName(state.CipherSuite))

	// Extract certificate info
	peerCerts := make([]output.CertificateInfo, 0, len(state.PeerCertificates))
	for _, cert := range state.PeerCertificates {
		peerCerts = append(peerCerts, output.NewCertificateInfo(cert))
	}

	c.verbose.LogMessage("Number of certificates: %d", len(peerCerts))

	// Create TLS result
	tlsResult := output.TLSResult{
		Host:        c.Host,
		Port:        c.Port,
		Certificate: peerCerts[0], // Primary certificate
		Verified:    state.VerifiedChains != nil && len(state.VerifiedChains) > 0,
		TLSVersion:  tlsVersionToString(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		PeerCerts:   peerCerts,
	}

	c.verbose.LogMessage("Certificate Subject: %s", tlsResult.Certificate.Subject)
	c.verbose.LogMessage("Certificate Issuer: %s", tlsResult.Certificate.Issuer)
	c.verbose.LogMessage("Certificate Valid From: %s", tlsResult.Certificate.NotBefore.Format("2006-01-02 15:04:05"))
	c.verbose.LogMessage("Certificate Valid Until: %s", tlsResult.Certificate.NotAfter.Format("2006-01-02 15:04:05"))
	c.verbose.LogMessage("Certificate Verified: %v", tlsResult.Verified)
	c.verbose.LogMessage("Days until expiry: %d", tlsResult.Certificate.DaysUntilExpiry)

	// Add certificate chain info
	if len(state.PeerCertificates) > 1 {
		c.verbose.LogMessage("Certificate chain length: %d", len(state.PeerCertificates)-1)
		chain := make([]output.CertificateInfo, 0, len(state.PeerCertificates)-1)
		for i := 1; i < len(state.PeerCertificates); i++ {
			chain = append(chain, output.NewCertificateInfo(state.PeerCertificates[i]))
		}
		tlsResult.Certificate.Chain = chain
	}

	result.Details = tlsResult
	result.Duration = time.Since(startTime)

	c.verbose.LogMessage("TLS check completed in %v", result.Duration)

	return result
}

// tryGetCertificateInfo attempts to get certificate info even on connection failure
func (c *TLSChecker) tryGetCertificateInfo(address string, result *output.TestResult) error {
	c.verbose.LogMessage("Attempting to retrieve certificate info with insecure connection...")

	// Try with a more permissive config
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         c.Host,
		MinVersion:         tls.VersionTLS10,
	}

	conn, err := tls.Dial("tcp", address, tlsConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	state := conn.ConnectionState()

	if len(state.PeerCertificates) > 0 {
		certInfo := output.NewCertificateInfo(state.PeerCertificates[0])
		tlsResult := output.TLSResult{
			Host:        c.Host,
			Port:        c.Port,
			Certificate: certInfo,
			Verified:    false,
			TLSVersion:  tlsVersionToString(state.Version),
			CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		}
		result.Details = tlsResult
		c.verbose.LogMessage("Retrieved certificate info (unverified)")
	}

	return nil
}

// tlsVersionToString converts TLS version number to string
func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// GetCertificateWarnings returns warnings for certificate issues
func (c *TLSChecker) GetCertificateWarnings(tlsResult output.TLSResult) []string {
	var warnings []string

	// Check for expired certificate
	if tlsResult.Certificate.IsExpired {
		warnings = append(warnings, "Certificate has expired!")
	}

	// Check for certificate expiring soon
	if tlsResult.Certificate.DaysUntilExpiry > 0 && tlsResult.Certificate.DaysUntilExpiry < 30 {
		if tlsResult.Certificate.DaysUntilExpiry < 7 {
			warnings = append(warnings, fmt.Sprintf("Certificate expires in %d days! Renew immediately.", tlsResult.Certificate.DaysUntilExpiry))
		} else {
			warnings = append(warnings, fmt.Sprintf("Certificate expires in %d days. Plan for renewal.", tlsResult.Certificate.DaysUntilExpiry))
		}
	}

	// Check for weak TLS version
	if tlsResult.TLSVersion == "TLS 1.0" || tlsResult.TLSVersion == "TLS 1.1" {
		warnings = append(warnings, fmt.Sprintf("Using %s which is deprecated. Upgrade to TLS 1.2 or higher.", tlsResult.TLSVersion))
	}

	return warnings
}
