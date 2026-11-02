package checker

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// AuthChecker performs bucket authentication checks
type AuthChecker struct {
	BaseChecker
	Endpoint  string
	Bucket    string
	AccessKey string
	SecretKey string
	Region    string
	AuthType  string
	PathStyle bool
	verbose   *VerboseLogger
}

// timeNow is the clock used by request signing. Tests replace it with a
// fixed value to verify signatures against published AWS test vectors.
var timeNow = time.Now

// NewAuthChecker creates a new auth checker
func NewAuthChecker(config output.Config) *AuthChecker {
	return &AuthChecker{
		BaseChecker: NewBaseChecker(config),
		Endpoint:    config.Endpoint,
		Bucket:      config.Bucket,
		AccessKey:   config.AccessKey,
		SecretKey:   config.SecretKey,
		Region:      config.Region,
		AuthType:    strings.ToLower(config.AuthType),
		PathStyle:   config.PathStyle,
		verbose:     NewVerboseLogger(config.Verbose),
	}
}

// Name returns the name of the checker
func (c *AuthChecker) Name() string {
	return "Bucket Authentication Check"
}

// Check performs the authentication check
func (c *AuthChecker) Check() output.TestResult {
	startTime := time.Now()

	c.verbose.LogSection("Starting Bucket Authentication Check")

	result := output.TestResult{
		TestName: c.Name(),
		Status:   output.StatusPass,
		Duration: time.Since(startTime),
	}

	// Create HTTP client with shared transport and redirect policy
	client := newSecureHTTPClient(c.Config)

	// Create request
	req, err := c.createRequest()
	if err != nil {
		c.verbose.LogMessage("Failed to create request: %v", err)
		result.Status = output.StatusFail
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}

	c.verbose.LogMessage("Request created successfully")
	c.verbose.LogMessage("Endpoint: %s", c.Endpoint)
	c.verbose.LogMessage("Bucket: %s", c.Bucket)
	c.verbose.LogMessage("Auth Type: %s", strings.ToUpper(c.AuthType))
	c.verbose.LogMessage("Path Style: %v", c.PathStyle)

	// Add authentication headers based on auth type
	if c.AuthType == "sigv2" {
		c.verbose.LogMessage("Using AWS Signature Version 2 authentication")
		if err := c.addSigV2Auth(req); err != nil {
			c.verbose.LogMessage("Failed to add SigV2 auth: %v", err)
			result.Status = output.StatusFail
			result.Error = fmt.Sprintf("failed to add SigV2 auth: %v", err)
			result.Duration = time.Since(startTime)
			return result
		}
	} else {
		// Default to SigV4
		c.verbose.LogMessage("Using AWS Signature Version 4 authentication")
		if err := c.addSigV4Auth(req); err != nil {
			c.verbose.LogMessage("Failed to add SigV4 auth: %v", err)
			result.Status = output.StatusFail
			result.Error = fmt.Sprintf("failed to add SigV4 auth: %v", err)
			result.Duration = time.Since(startTime)
			return result
		}
	}

	// Log the request
	c.verbose.LogRequest(req)

	// Send request
	c.verbose.LogMessage("Sending request to S3 endpoint...")
	resp, err := client.Do(req)
	if err != nil {
		c.verbose.LogMessage("Request failed: %v", err)
		result.Status = output.StatusFail
		result.Error = fmt.Sprintf("request failed: %v", err)
		result.Duration = time.Since(startTime)
		return result
	}
	defer resp.Body.Close()

	c.verbose.LogMessage("Request completed successfully")

	// Log the response
	c.verbose.LogResponse(resp)

	// Read response body (bounded; oversized bodies are treated as empty)
	body, readErr := readLimited(resp.Body, maxAuthBodySize)
	if readErr != nil {
		c.verbose.LogMessage("Failed to read response body: %v", readErr)
		body = nil
	}

	// Log response body if present and verbose
	if c.verbose != nil && c.verbose.enabled && len(body) > 0 {
		fmt.Println("\nResponse Body:")
		fmt.Println(strings.Repeat("-", 70))
		bodyStr := string(body)

		// Try to beautify JSON
		var jsonBody interface{}
		if json.Unmarshal(body, &jsonBody) == nil {
			// Successfully parsed as JSON, format it nicely
			formatted, err := json.MarshalIndent(jsonBody, "", "  ")
			if err == nil {
				fmt.Println(string(formatted))
			} else {
				fmt.Println(bodyStr)
			}
		} else if strings.TrimSpace(bodyStr) != "" && strings.HasPrefix(strings.TrimSpace(bodyStr), "<") {
			// XML - try to beautify
			formattedXML, err := beautifyXML(body)
			if err == nil {
				fmt.Println(formattedXML)
			} else {
				fmt.Println(bodyStr)
			}
		} else {
			fmt.Println(bodyStr)
		}
	}

	// Parse response
	authResult := output.AuthResult{
		Success:      resp.StatusCode >= 200 && resp.StatusCode < 300,
		AuthType:     strings.ToUpper(c.AuthType),
		StatusCode:   resp.StatusCode,
		ResponseTime: time.Since(startTime).Milliseconds(),
		Provider:     c.detectProvider(resp),
		Endpoint:     c.Endpoint,
		ResponseBody: string(body),
	}

	// Explicit verdict mapping: 200 is the only PASS. Anything else —
	// unexpected 2xx, redirects (not followed by default), auth denials,
	// missing buckets, other client/server errors — must never report a
	// successful authenticated check.
	switch {
	case resp.StatusCode == http.StatusOK:
		authResult.BucketExists = true
		authResult.AccessGranted = true
		result.Status = output.StatusPass
		c.verbose.LogMessage("Bucket exists and access is granted")

	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// 2xx but not 200: the endpoint answered, but this is not the
		// response a bucket HEAD request expects
		authResult.BucketExists = true
		result.Status = output.StatusWarn
		result.Error = fmt.Sprintf("unexpected status code %d from bucket request", resp.StatusCode)
		c.verbose.LogMessage("Unexpected 2xx status code: %d", resp.StatusCode)

	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		location := resp.Header.Get("Location")
		result.Status = output.StatusFail
		result.Error = fmt.Sprintf("unexpected redirect (HTTP %d) to %q: redirects are not followed by default (see --follow-redirects)", resp.StatusCode, location)
		c.verbose.LogMessage("Redirect response (HTTP %d) treated as failure", resp.StatusCode)

	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		authResult.BucketExists = true
		authResult.AccessGranted = false
		result.Status = output.StatusFail
		c.verbose.LogMessage("Bucket exists but access is denied (%d)", resp.StatusCode)

	case resp.StatusCode == http.StatusNotFound:
		authResult.BucketExists = false
		authResult.AccessGranted = false
		result.Status = output.StatusFail
		c.verbose.LogMessage("Bucket not found (404)")

	default:
		result.Status = output.StatusFail
		c.verbose.LogMessage("Unexpected status code: %d", resp.StatusCode)
	}

	// Parse error response bodies (4xx/5xx) for provider detail
	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if err := xml.Unmarshal(body, &errResp); err == nil && errResp.Code != "" {
			result.Error = fmt.Sprintf("%s: %s", errResp.Code, errResp.Message)
			c.verbose.LogMessage("Error response: %s - %s", errResp.Code, errResp.Message)
		} else if result.Error == "" {
			result.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body))
			c.verbose.LogMessage("Error response: HTTP %d", resp.StatusCode)
		}
	}

	c.verbose.LogMessage("Provider detected: %s", authResult.Provider)
	c.verbose.LogMessage("Response time: %dms", authResult.ResponseTime)

	result.Details = authResult
	result.Duration = time.Since(startTime)

	c.verbose.LogMessage("Authentication check completed in %v", result.Duration)

	return result
}

// cleanHost removes default ports from host (443 for HTTPS, 80 for HTTP)
func cleanHost(host string, scheme string) string {
	// Remove default ports
	if scheme == "https" && strings.HasSuffix(host, ":443") {
		return host[:len(host)-4]
	}
	if scheme == "http" && strings.HasSuffix(host, ":80") {
		return host[:len(host)-3]
	}
	return host
}

// createRequest creates the HTTP request for authentication check
func (c *AuthChecker) createRequest() (*http.Request, error) {
	// Parse endpoint
	endpointURL, err := url.Parse(c.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}

	// Clean host by removing default ports
	cleanHost := cleanHost(endpointURL.Host, endpointURL.Scheme)

	// Build bucket URL based on addressing style
	var bucketURL string
	var hostHeader string

	if c.PathStyle {
		// Path-style addressing: https://endpoint/bucket
		bucketURL = fmt.Sprintf("%s://%s/%s", endpointURL.Scheme, cleanHost, c.Bucket)
		hostHeader = cleanHost
	} else {
		// Virtual-hosted addressing (default): https://bucket.endpoint
		bucketURL = fmt.Sprintf("%s://%s.%s", endpointURL.Scheme, c.Bucket, cleanHost)
		hostHeader = fmt.Sprintf("%s.%s", c.Bucket, cleanHost)
	}

	// Create HEAD request to check bucket existence
	req, err := http.NewRequest("HEAD", bucketURL, nil)
	if err != nil {
		return nil, err
	}

	// Set headers
	req.Header.Set("Host", hostHeader)
	req.Header.Set("User-Agent", "s3-bucket-tester/1.0")
	req.Header.Set("Date", timeNow().UTC().Format(time.RFC1123))

	return req, nil
}

// signer returns the shared request signer for this checker
func (c *AuthChecker) signer() Signer {
	return Signer{AccessKey: c.AccessKey, SecretKey: c.SecretKey, Region: c.Region}
}

// addSigV4Auth adds AWS Signature Version 4 authentication
func (c *AuthChecker) addSigV4Auth(req *http.Request) error {
	return c.signer().SignV4(req, timeNow())
}

// addSigV2Auth adds AWS Signature Version 2 query authentication
func (c *AuthChecker) addSigV2Auth(req *http.Request) error {
	now := timeNow()
	s := c.signer()
	resource := s.BuildCanonicalResource(req, c.Bucket, c.PathStyle)
	return s.SignV2Query(req, resource, now.Add(15*time.Minute))
}

// detectProvider attempts to detect the S3 provider
func (c *AuthChecker) detectProvider(resp *http.Response) string {
	server := resp.Header.Get("Server")
	switch {
	case strings.Contains(server, "AmazonS3"):
		return "AWS S3"
	case strings.Contains(server, "MinIO"):
		return "MinIO"
	case strings.Contains(server, "StorageGRID"):
		return "NetApp StorageGRID"
	default:
		return "Unknown S3-Compatible"
	}
}

// ErrorResponse represents an S3 error response
type ErrorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource"`
	RequestID string   `xml:"RequestId"`
}
