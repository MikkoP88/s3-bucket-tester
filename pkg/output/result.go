package output

import (
	"crypto/x509"
	"time"
)

// Status represents the test result status
type Status string

const (
	StatusPass Status = "PASS"
	StatusFail Status = "FAIL"
	StatusWarn Status = "WARN"
	StatusSkip Status = "SKIP"
)

// TestResult represents a single test result
type TestResult struct {
	TestName string        `json:"testName"`
	Status   Status        `json:"status"`
	Duration time.Duration `json:"duration"`
	Error    string        `json:"error,omitempty"`
	Details  interface{}   `json:"details,omitempty"`
}

// DNSResult contains DNS resolution details
type DNSResult struct {
	IPs            []string `json:"ips"`
	ResolutionTime int64    `json:"resolutionTimeMs"`
	Hostname       string   `json:"hostname"`
	ReverseDNS     string   `json:"reverseDns,omitempty"`
}

// TCPResult contains TCP connectivity details
type TCPResult struct {
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Connected      bool   `json:"connected"`
	ConnectionTime int64  `json:"connectionTimeMs"`
	LocalAddr      string `json:"localAddr,omitempty"`
	RemoteAddr     string `json:"remoteAddr,omitempty"`
}

// CertificateInfo contains SSL/TLS certificate details
type CertificateInfo struct {
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	NotBefore          time.Time `json:"notBefore"`
	NotAfter           time.Time `json:"notAfter"`
	SANs               []string  `json:"sans"`
	SerialNumber       string    `json:"serialNumber"`
	SignatureAlgorithm string    `json:"signatureAlgorithm"`
	DNSNames           []string  `json:"dnsNames"`
	EmailAddresses     []string  `json:"emailAddresses"`
	IPAddresses        []string  `json:"ipAddresses"`
	URIs               []string  `json:"uris"`
	IsExpired          bool      `json:"isExpired"`
	DaysUntilExpiry    int       `json:"daysUntilExpiry"`
	Chain              []CertificateInfo `json:"chain,omitempty"`
}

// TLSResult contains TLS certificate check details
type TLSResult struct {
	Host          string            `json:"host"`
	Port          int               `json:"port"`
	Certificate   CertificateInfo   `json:"certificate"`
	Verified      bool              `json:"verified"`
	VerifyError   string            `json:"verifyError,omitempty"`
	TLSVersion    string            `json:"tlsVersion"`
	CipherSuite   string            `json:"cipherSuite"`
	PeerCerts     []CertificateInfo `json:"peerCerts"`
}

// AuthResult contains authentication check details
type AuthResult struct {
	Success       bool   `json:"success"`
	AuthType      string `json:"authType"`
	BucketExists  bool   `json:"bucketExists"`
	AccessGranted bool   `json:"accessGranted"`
	StatusCode    int    `json:"statusCode"`
	ResponseTime  int64  `json:"responseTimeMs"`
	Provider      string `json:"provider,omitempty"`
	Endpoint      string `json:"endpoint"`
}

// TestSummary contains the overall test summary
type TestSummary struct {
	Total    int `json:"total"`
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
	Warnings int `json:"warnings"`
	Skipped  int `json:"skipped"`
}

// TestReport contains the complete test report
type TestReport struct {
	Config     Config      `json:"config"`
	StartTime  time.Time   `json:"startTime"`
	EndTime    time.Time   `json:"endTime"`
	Duration   time.Duration `json:"duration"`
	Results    []TestResult `json:"results"`
	Summary    TestSummary  `json:"summary"`
}

// Config contains the test configuration
type Config struct {
	Endpoint       string `json:"endpoint"`
	Bucket         string `json:"bucket"`
	Region         string `json:"region"`
	AccessKey      string `json:"accessKey"`
	SecretKey      string `json:"secretKey"`
	AuthType       string `json:"authType"`
	Port           int    `json:"port"`
	Insecure       bool   `json:"insecure"`
	Timeout        int    `json:"timeout"`
	OutputFormat   string `json:"outputFormat"`
	OutputFile     string `json:"outputFile"`
	FollowRedirect bool   `json:"followRedirect"`
	MaxRedirects   int    `json:"maxRedirects"`
	Verbose        bool   `json:"verbose"`
	PathStyle      bool   `json:"pathStyle"`
}

// NewCertificateInfo creates a CertificateInfo from x509.Certificate
func NewCertificateInfo(cert *x509.Certificate) CertificateInfo {
	info := CertificateInfo{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
		SerialNumber:       cert.SerialNumber.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
	}

	// Extract SANs
	for _, name := range cert.DNSNames {
		info.DNSNames = append(info.DNSNames, name)
		info.SANs = append(info.SANs, name)
	}

	for _, email := range cert.EmailAddresses {
		info.EmailAddresses = append(info.EmailAddresses, email)
		info.SANs = append(info.SANs, email)
	}

	for _, ip := range cert.IPAddresses {
		info.IPAddresses = append(info.IPAddresses, ip.String())
		info.SANs = append(info.SANs, ip.String())
	}

	for _, uri := range cert.URIs {
		info.URIs = append(info.URIs, uri.String())
		info.SANs = append(info.SANs, uri.String())
	}

	// Check expiration
	now := time.Now()
	info.IsExpired = now.After(cert.NotAfter)
	info.DaysUntilExpiry = int(cert.NotAfter.Sub(now).Hours() / 24)

	return info
}

// NewTestSummary creates a test summary from results
func NewTestSummary(results []TestResult) TestSummary {
	summary := TestSummary{}
	for _, result := range results {
		summary.Total++
		switch result.Status {
		case StatusPass:
			summary.Passed++
		case StatusFail:
			summary.Failed++
		case StatusWarn:
			summary.Warnings++
		case StatusSkip:
			summary.Skipped++
		}
	}
	return summary
}
