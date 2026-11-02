package checker

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// authTestConfig returns a config pointing at the given test server URL.
// Path-style addressing is used so requests resolve against 127.0.0.1.
func authTestConfig(serverURL string, mutate func(*output.Config)) output.Config {
	config := output.Config{
		Endpoint:  serverURL,
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true,
		Timeout:   5,
	}
	if mutate != nil {
		mutate(&config)
	}
	return config
}

// authTLSTestServer starts an HTTPS test server with the given handler and
// a self-signed certificate valid for 127.0.0.1, returning its URL. Use with
// Insecure: true in the config.
func authTLSTestServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	cert, _, _ := generateTestCert(t, validTLSCertTemplate("localhost", nil, []net.IP{net.ParseIP("127.0.0.1")}))
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server.URL
}

// s3ErrorXML returns an S3-style XML error body.
func s3ErrorXML(code, message string) string {
	return fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message><Resource>/test-bucket</Resource><RequestId>TESTREQUEST</RequestId></Error>`, code, message)
}

// authResultDetails extracts AuthResult from a TestResult.
func authResultDetails(t *testing.T, result output.TestResult) output.AuthResult {
	t.Helper()
	details, ok := result.Details.(output.AuthResult)
	if !ok {
		t.Fatalf("Expected Details to be AuthResult, got %T", result.Details)
	}
	return details
}

// TestNewAuthChecker tests the constructor
func TestNewAuthChecker(t *testing.T) {
	config := output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true,
		Timeout:   30,
		Verbose:   true,
	}

	checker := NewAuthChecker(config)

	if checker.Endpoint != config.Endpoint {
		t.Errorf("Expected Endpoint '%s', got '%s'", config.Endpoint, checker.Endpoint)
	}
	if checker.Bucket != config.Bucket {
		t.Errorf("Expected Bucket '%s', got '%s'", config.Bucket, checker.Bucket)
	}
	if checker.AccessKey != config.AccessKey {
		t.Errorf("Expected AccessKey '%s', got '%s'", config.AccessKey, checker.AccessKey)
	}
	if checker.SecretKey != config.SecretKey {
		t.Errorf("Expected SecretKey '%s', got '%s'", config.SecretKey, checker.SecretKey)
	}
	if checker.Region != config.Region {
		t.Errorf("Expected Region '%s', got '%s'", config.Region, checker.Region)
	}
	if checker.AuthType != "sigv4" {
		t.Errorf("Expected AuthType 'sigv4', got '%s'", checker.AuthType)
	}
	if checker.PathStyle != config.PathStyle {
		t.Errorf("Expected PathStyle %v, got %v", config.PathStyle, checker.PathStyle)
	}
	if checker.verbose == nil || !checker.verbose.enabled {
		t.Errorf("Expected verbose logger to be enabled")
	}
}

// TestAuthCheckerName tests the Name method
func TestAuthCheckerName(t *testing.T) {
	config := output.Config{}
	checker := NewAuthChecker(config)

	if checker.Name() != "Bucket Authentication Check" {
		t.Errorf("Expected name 'Bucket Authentication Check', got '%s'", checker.Name())
	}
}

// TestAuthChecker_AuthTypeNormalization tests that auth type is normalized to lowercase
func TestAuthChecker_AuthTypeNormalization(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"sigv4", "sigv4"},
		{"SIGV4", "sigv4"},
		{"SigV4", "sigv4"},
		{"sigv2", "sigv2"},
		{"SIGV2", "sigv2"},
		{"SigV2", "sigv2"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			config := output.Config{
				AuthType: tt.input,
			}
			checker := NewAuthChecker(config)

			if checker.AuthType != tt.expected {
				t.Errorf("Expected AuthType '%s', got '%s'", tt.expected, checker.AuthType)
			}
		})
	}
}

// TestAuthCheck_SigV4_Success tests successful SigV4 authentication
func TestAuthCheck_SigV4_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, nil))
	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected PASS, got %s (error: %s)", result.Status, result.Error)
	}
	details := authResultDetails(t, result)
	if !details.Success {
		t.Error("Expected Success to be true")
	}
	if !details.BucketExists {
		t.Error("Expected BucketExists to be true")
	}
	if !details.AccessGranted {
		t.Error("Expected AccessGranted to be true")
	}
}

// TestAuthCheck_SigV2_Success tests that SigV2-signed requests reach the server and succeed
func TestAuthCheck_SigV2_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, func(c *output.Config) {
		c.AuthType = "sigv2"
	}))
	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected PASS, got %s (error: %s)", result.Status, result.Error)
	}
	details := authResultDetails(t, result)
	if details.AuthType != "SIGV2" {
		t.Errorf("Expected AuthType 'SIGV2', got '%s'", details.AuthType)
	}
}

// TestAuthCheck_InvalidAccessKey tests invalid access key handling (server rejects with 403)
func TestAuthCheck_InvalidAccessKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		// HEAD responses carry no body, matching real S3 behavior
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, nil))
	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL, got %s", result.Status)
	}
	if !strings.Contains(result.Error, "HTTP 403") {
		t.Errorf("Expected error to contain 'HTTP 403', got '%s'", result.Error)
	}
	details := authResultDetails(t, result)
	if details.AccessGranted {
		t.Error("Expected AccessGranted to be false")
	}
}

// TestAuthCheck_InvalidSecretKey tests invalid secret key handling (server rejects with 403)
func TestAuthCheck_InvalidSecretKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, nil))
	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL, got %s", result.Status)
	}
	if !strings.Contains(result.Error, "HTTP 403") {
		t.Errorf("Expected error to contain 'HTTP 403', got '%s'", result.Error)
	}
}

// TestAuthCheck_AccessDenied tests 403 response handling
func TestAuthCheck_AccessDenied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, s3ErrorXML("AccessDenied", "Access Denied"))
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, nil))
	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL, got %s", result.Status)
	}
	details := authResultDetails(t, result)
	if !details.BucketExists {
		t.Error("Expected BucketExists to be true (403 implies the bucket exists)")
	}
	if details.AccessGranted {
		t.Error("Expected AccessGranted to be false")
	}
}

// TestAuthCheck_NotFound tests 404 response handling
func TestAuthCheck_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, s3ErrorXML("NoSuchBucket", "The specified bucket does not exist"))
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, nil))
	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL, got %s", result.Status)
	}
	details := authResultDetails(t, result)
	if details.BucketExists {
		t.Error("Expected BucketExists to be false")
	}
}

// TestAuthCheck_PathStyle tests path-style addressing: bucket must appear in the request path
func TestAuthCheck_PathStyle(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, func(c *output.Config) {
		c.PathStyle = true
	}))
	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected PASS, got %s (error: %s)", result.Status, result.Error)
	}
	if gotPath != "/test-bucket" {
		t.Errorf("Expected path '/test-bucket', got '%s'", gotPath)
	}
}

// TestAuthCheck_VirtualHosted tests virtual-hosted URL construction (unit test on createRequest)
func TestAuthCheck_VirtualHosted(t *testing.T) {
	checker := NewAuthChecker(output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: false,
	})

	req, err := checker.createRequest()
	if err != nil {
		t.Fatalf("createRequest failed: %v", err)
	}
	if req.URL.String() != "https://test-bucket.s3.example.com" {
		t.Errorf("Expected URL 'https://test-bucket.s3.example.com', got '%s'", req.URL.String())
	}
	if req.Host != "test-bucket.s3.example.com" {
		t.Errorf("Expected Host 'test-bucket.s3.example.com', got '%s'", req.Host)
	}
}

// TestAuthCheck_RedirectHandling tests that HTTPS redirects on the same host
// are followed when enabled
func TestAuthCheck_RedirectHandling(t *testing.T) {
	finalHit := false
	var mu sync.Mutex
	serverURL := authTLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/final" {
			http.Redirect(w, r, "/final", http.StatusMovedPermanently)
			return
		}
		mu.Lock()
		finalHit = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))

	checker := NewAuthChecker(authTestConfig(serverURL, func(c *output.Config) {
		c.Insecure = true
		c.FollowRedirect = true
		c.MaxRedirects = 3
	}))
	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected PASS, got %s (error: %s)", result.Status, result.Error)
	}
	mu.Lock()
	defer mu.Unlock()
	if !finalHit {
		t.Error("Expected redirect target to be reached")
	}
}

// TestAuthCheck_MaxRedirects tests maximum redirects enforcement
func TestAuthCheck_MaxRedirects(t *testing.T) {
	serverURL := authTLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))

	checker := NewAuthChecker(authTestConfig(serverURL, func(c *output.Config) {
		c.Insecure = true
		c.FollowRedirect = true
		c.MaxRedirects = 2
	}))
	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL, got %s", result.Status)
	}
	if !strings.Contains(result.Error, "stopped after 2 redirects") {
		t.Errorf("Expected error to mention redirect limit, got '%s'", result.Error)
	}
}

// TestAuthCheck_NoRedirects tests that a 301 is returned as-is when redirects are disabled
func TestAuthCheck_NoRedirects(t *testing.T) {
	targetHit := false
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/final" {
			http.Redirect(w, r, "/final", http.StatusMovedPermanently)
			return
		}
		mu.Lock()
		targetHit = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, func(c *output.Config) {
		c.FollowRedirect = false
	}))
	result := checker.Check()

	details := authResultDetails(t, result)
	if details.StatusCode != http.StatusMovedPermanently {
		t.Errorf("Expected StatusCode 301, got %d", details.StatusCode)
	}
	if details.Success {
		t.Error("Expected Details.Success to be false for a 301 response")
	}
	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL for an un-followed 301 response, got %s", result.Status)
	}
	mu.Lock()
	defer mu.Unlock()
	if targetHit {
		t.Error("Expected redirect target NOT to be reached when redirects are disabled")
	}
}

// TestAuthCheck_Timeout tests request timeout
func TestAuthCheck_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, func(c *output.Config) {
		c.Timeout = 1
	}))
	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL, got %s", result.Status)
	}
}

// TestAuthCheck_InsecureTLS tests that TLS connections succeed with verification disabled
func TestAuthCheck_InsecureTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, func(c *output.Config) {
		c.Insecure = true
	}))
	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected PASS, got %s (error: %s)", result.Status, result.Error)
	}
}

// TestAuthCheck_EmptyBucket tests empty bucket handling does not panic
func TestAuthCheck_EmptyBucket(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, func(c *output.Config) {
		c.Bucket = ""
	}))
	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected PASS, got %s (error: %s)", result.Status, result.Error)
	}
}

// TestAuthCheck_EmptyAccessKey tests a request with an empty access key is still sent and rejected by the server
func TestAuthCheck_EmptyAccessKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, s3ErrorXML("AccessDenied", "Access Denied"))
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, func(c *output.Config) {
		c.AccessKey = ""
	}))
	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL, got %s", result.Status)
	}
}

// TestAuthCheck_EmptySecretKey tests a request with an empty secret key is still sent and rejected by the server
func TestAuthCheck_EmptySecretKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, s3ErrorXML("AccessDenied", "Access Denied"))
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, func(c *output.Config) {
		c.SecretKey = ""
	}))
	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL, got %s", result.Status)
	}
}

// TestAuthCheck_EmptyEndpoint tests empty endpoint handling
func TestAuthCheck_EmptyEndpoint(t *testing.T) {
	checker := NewAuthChecker(authTestConfig("", nil))
	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL, got %s", result.Status)
	}
	if !strings.Contains(result.Error, "failed to create request") {
		t.Errorf("Expected 'failed to create request' error, got '%s'", result.Error)
	}
}

// TestAuthCheck_Duration tests that duration is measured
func TestAuthCheck_Duration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, nil))
	result := checker.Check()

	if result.Duration < 50*time.Millisecond {
		t.Errorf("Expected duration >= 50ms, got %v", result.Duration)
	}
}

// TestAuthCheck_VerboseLogging tests that verbose mode does not break the check
func TestAuthCheck_VerboseLogging(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, func(c *output.Config) {
		c.Verbose = true
	}))
	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected PASS, got %s (error: %s)", result.Status, result.Error)
	}
}

// TestAuthCheck_RequestCreation tests that the request is created correctly
func TestAuthCheck_RequestCreation(t *testing.T) {
	checker := NewAuthChecker(output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true,
	})

	req, err := checker.createRequest()
	if err != nil {
		t.Fatalf("createRequest failed: %v", err)
	}
	if req.Method != "HEAD" {
		t.Errorf("Expected method HEAD, got %s", req.Method)
	}
	if req.Header.Get("User-Agent") != "s3-bucket-tester/1.0" {
		t.Errorf("Expected User-Agent 's3-bucket-tester/1.0', got '%s'", req.Header.Get("User-Agent"))
	}
	if req.Header.Get("Date") == "" {
		t.Error("Expected Date header to be set")
	}
}

// TestAuthCheck_URLBuilding tests URL construction for both addressing styles
func TestAuthCheck_URLBuilding(t *testing.T) {
	tests := []struct {
		name      string
		pathStyle bool
		endpoint  string
		expected  string
	}{
		{"path-style", true, "https://s3.example.com", "https://s3.example.com/test-bucket"},
		{"virtual-hosted", false, "https://s3.example.com", "https://test-bucket.s3.example.com"},
		{"path-style with port", true, "http://s3.example.com:9000", "http://s3.example.com:9000/test-bucket"},
		{"virtual-hosted with port", false, "http://s3.example.com:9000", "http://test-bucket.s3.example.com:9000"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checker := NewAuthChecker(output.Config{
				Endpoint:  tt.endpoint,
				Bucket:    "test-bucket",
				AccessKey: "test-key",
				SecretKey: "test-secret",
				Region:    "us-east-1",
				AuthType:  "sigv4",
				PathStyle: tt.pathStyle,
			})
			req, err := checker.createRequest()
			if err != nil {
				t.Fatalf("createRequest failed: %v", err)
			}
			if req.URL.String() != tt.expected {
				t.Errorf("Expected URL '%s', got '%s'", tt.expected, req.URL.String())
			}
		})
	}
}

// TestAuthCheck_SigV4Signature tests SigV4 Authorization header structure
func TestAuthCheck_SigV4Signature(t *testing.T) {
	checker := NewAuthChecker(output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true,
	})

	req, err := checker.createRequest()
	if err != nil {
		t.Fatalf("createRequest failed: %v", err)
	}
	if err := checker.addSigV4Auth(req); err != nil {
		t.Fatalf("addSigV4Auth failed: %v", err)
	}

	authHeader := req.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 Credential=test-key/") {
		t.Errorf("Expected AWS4-HMAC-SHA256 credential prefix, got '%s'", authHeader)
	}
	if !strings.Contains(authHeader, "/us-east-1/s3/aws4_request") {
		t.Errorf("Expected credential scope to contain region and service, got '%s'", authHeader)
	}
	if !strings.Contains(authHeader, "SignedHeaders=host;x-amz-content-sha256;x-amz-date") {
		t.Errorf("Expected SignedHeaders, got '%s'", authHeader)
	}
	// Signature must be a 64-character hex string
	idx := strings.LastIndex(authHeader, "Signature=")
	if idx == -1 {
		t.Fatalf("Expected Signature component in '%s'", authHeader)
	}
	sig := authHeader[idx+len("Signature="):]
	if len(sig) != 64 {
		t.Errorf("Expected 64-char hex signature, got %d chars: '%s'", len(sig), sig)
	}
}

// TestAuthCheck_SigV2Signature tests SigV2 query parameter structure
func TestAuthCheck_SigV2Signature(t *testing.T) {
	checker := NewAuthChecker(output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv2",
		PathStyle: true,
	})

	req, err := checker.createRequest()
	if err != nil {
		t.Fatalf("createRequest failed: %v", err)
	}
	if err := checker.addSigV2Auth(req); err != nil {
		t.Fatalf("addSigV2Auth failed: %v", err)
	}

	query := req.URL.RawQuery
	if !strings.Contains(query, "AWSAccessKeyId=test-key") {
		t.Errorf("Expected AWSAccessKeyId in query, got '%s'", query)
	}
	if !strings.Contains(query, "Signature=") {
		t.Errorf("Expected Signature in query, got '%s'", query)
	}
	if !strings.Contains(query, "Expires=") {
		t.Errorf("Expected Expires in query, got '%s'", query)
	}
}

// TestAuthCheck_BucketExists tests bucket existence mapping from status codes
func TestAuthCheck_BucketExists(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		exists     bool
	}{
		{"200 means exists", http.StatusOK, true},
		{"403 means exists", http.StatusForbidden, true},
		{"404 means missing", http.StatusNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			checker := NewAuthChecker(authTestConfig(server.URL, nil))
			result := checker.Check()
			details := authResultDetails(t, result)
			if details.BucketExists != tt.exists {
				t.Errorf("Expected BucketExists %v, got %v", tt.exists, details.BucketExists)
			}
		})
	}
}

// TestAuthCheck_AccessGranted tests access mapping from status codes
func TestAuthCheck_AccessGranted(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		granted    bool
	}{
		{"200 means granted", http.StatusOK, true},
		{"403 means denied", http.StatusForbidden, false},
		{"404 means denied", http.StatusNotFound, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			checker := NewAuthChecker(authTestConfig(server.URL, nil))
			result := checker.Check()
			details := authResultDetails(t, result)
			if details.AccessGranted != tt.granted {
				t.Errorf("Expected AccessGranted %v, got %v", tt.granted, details.AccessGranted)
			}
		})
	}
}

// TestAuthCheck_StatusCode tests status code recording and the explicit
// verdict mapping: only 200 passes, other 2xx warn, everything else fails
func TestAuthCheck_StatusCode(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantStatus output.Status
	}{
		{"200", http.StatusOK, output.StatusPass},
		{"204", http.StatusNoContent, output.StatusWarn},
		{"301", http.StatusMovedPermanently, output.StatusFail},
		{"302", http.StatusFound, output.StatusFail},
		{"307", http.StatusTemporaryRedirect, output.StatusFail},
		{"400", http.StatusBadRequest, output.StatusFail},
		{"403", http.StatusForbidden, output.StatusFail},
		{"404", http.StatusNotFound, output.StatusFail},
		{"429", http.StatusTooManyRequests, output.StatusFail},
		{"500", http.StatusInternalServerError, output.StatusFail},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer server.Close()

			checker := NewAuthChecker(authTestConfig(server.URL, nil))
			result := checker.Check()
			details := authResultDetails(t, result)
			if details.StatusCode != tt.statusCode {
				t.Errorf("Expected StatusCode %d, got %d", tt.statusCode, details.StatusCode)
			}
			if result.Status != tt.wantStatus {
				t.Errorf("Expected status %s, got %s", tt.wantStatus, result.Status)
			}
			// Invariant: a response that is not 2xx must never PASS
			if !details.Success && result.Status == output.StatusPass {
				t.Errorf("PASS reported for unsuccessful response (HTTP %d)", tt.statusCode)
			}
		})
	}
}

// TestAuthCheck_ResponseTime tests response time measurement
func TestAuthCheck_ResponseTime(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, nil))
	result := checker.Check()
	details := authResultDetails(t, result)
	if details.ResponseTime < 0 {
		t.Errorf("Expected non-negative response time, got %d", details.ResponseTime)
	}
}

// TestAuthCheck_ProviderDetection tests provider detection from the Server header
func TestAuthCheck_ProviderDetection(t *testing.T) {
	tests := []struct {
		serverHeader string
		expected     string
	}{
		{"AmazonS3", "AWS S3"},
		{"MinIO", "MinIO"},
		{"StorageGRID", "NetApp StorageGRID"},
		{"nginx", "Unknown S3-Compatible"},
	}

	for _, tt := range tests {
		t.Run(tt.serverHeader, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", tt.serverHeader)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			checker := NewAuthChecker(authTestConfig(server.URL, nil))
			result := checker.Check()
			details := authResultDetails(t, result)
			if details.Provider != tt.expected {
				t.Errorf("Expected provider '%s', got '%s'", tt.expected, details.Provider)
			}
		})
	}
}

// TestAuthCheck_RegionHandling tests that the region appears in the SigV4 credential scope
func TestAuthCheck_RegionHandling(t *testing.T) {
	checker := NewAuthChecker(output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "eu-central-1",
		AuthType:  "sigv4",
		PathStyle: true,
	})

	req, err := checker.createRequest()
	if err != nil {
		t.Fatalf("createRequest failed: %v", err)
	}
	if err := checker.addSigV4Auth(req); err != nil {
		t.Fatalf("addSigV4Auth failed: %v", err)
	}

	authHeader := req.Header.Get("Authorization")
	if !strings.Contains(authHeader, "/eu-central-1/s3/aws4_request") {
		t.Errorf("Expected region 'eu-central-1' in credential scope, got '%s'", authHeader)
	}
}

// TestAuthCheck_DefaultTimeout tests that no timeout is applied when Timeout is unset
func TestAuthCheck_DefaultTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, func(c *output.Config) {
		c.Timeout = 0
	}))
	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected PASS with no timeout configured, got %s (error: %s)", result.Status, result.Error)
	}
}

// TestAuthCheck_CustomTimeout tests that a custom timeout is enforced
func TestAuthCheck_CustomTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, func(c *output.Config) {
		c.Timeout = 1
	}))
	result := checker.Check()

	if result.Status != output.StatusFail {
		t.Errorf("Expected FAIL with 1s timeout and 3s server delay, got %s", result.Status)
	}
}

// TestAuthCheck_FollowRedirects tests that the follow-redirects flag allows a single redirect
func TestAuthCheck_FollowRedirects(t *testing.T) {
	redirects := 0
	var mu sync.Mutex
	serverURL := authTLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/final" {
			mu.Lock()
			redirects++
			mu.Unlock()
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	checker := NewAuthChecker(authTestConfig(serverURL, func(c *output.Config) {
		c.Insecure = true
		c.FollowRedirect = true
		c.MaxRedirects = 5
	}))
	result := checker.Check()

	if result.Status != output.StatusPass {
		t.Errorf("Expected PASS, got %s (error: %s)", result.Status, result.Error)
	}
	mu.Lock()
	defer mu.Unlock()
	if redirects != 1 {
		t.Errorf("Expected exactly 1 redirect hop, got %d", redirects)
	}
}
