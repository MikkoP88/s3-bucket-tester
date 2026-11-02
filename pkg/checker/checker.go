package checker

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// Checker defines the interface for all test checkers
type Checker interface {
	// Name returns the name of the checker
	Name() string

	// Check performs the check and returns a TestResult
	Check() output.TestResult
}

// BaseChecker provides common functionality for all checkers
type BaseChecker struct {
	Config output.Config
}

// NewBaseChecker creates a new base checker
func NewBaseChecker(config output.Config) BaseChecker {
	return BaseChecker{Config: config}
}

// newSecureHTTPClient builds the shared HTTP client used by the auth and
// policy checkers: request timeout, optional insecure TLS, and redirect
// handling that is off by default and, when enabled, restricted to HTTPS
// targets on the original host or its subdomains.
func newSecureHTTPClient(config output.Config) *http.Client {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.Insecure,
		},
	}
	return &http.Client{
		Timeout:   time.Duration(config.Timeout) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !config.FollowRedirect {
				return http.ErrUseLastResponse
			}
			if len(via) >= config.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", config.MaxRedirects)
			}
			return validateRedirect(via[0], req)
		},
	}
}

// validateRedirect enforces that a redirect target stays on HTTPS and does
// not leave the original host (subdomains of the original host are allowed).
func validateRedirect(original, next *http.Request) error {
	if next.URL.Scheme != "https" {
		return fmt.Errorf("blocked redirect to non-HTTPS protocol: %s", next.URL.Scheme)
	}
	origHost := strings.ToLower(original.URL.Hostname())
	nextHost := strings.ToLower(next.URL.Hostname())
	if nextHost != origHost && !strings.HasSuffix(nextHost, "."+origHost) {
		return fmt.Errorf("blocked redirect to different host: %s", nextHost)
	}
	return nil
}
