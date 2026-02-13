package checker

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
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

	// Create HTTP client with custom transport for insecure TLS
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: c.Config.Insecure,
		},
	}
	client := &http.Client{
		Timeout:   time.Duration(c.Config.Timeout) * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if !c.Config.FollowRedirect {
				return http.ErrUseLastResponse
			}
			if len(via) >= c.Config.MaxRedirects {
				return fmt.Errorf("stopped after %d redirects", c.Config.MaxRedirects)
			}
			return nil
		},
	}

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

	// Read response body
	body, _ := io.ReadAll(resp.Body)

	// Parse response
	authResult := output.AuthResult{
		Success:      resp.StatusCode >= 200 && resp.StatusCode < 300,
		AuthType:     strings.ToUpper(c.AuthType),
		StatusCode:   resp.StatusCode,
		ResponseTime: time.Since(startTime).Milliseconds(),
		Provider:     c.detectProvider(resp),
		Endpoint:     c.Endpoint,
	}

	// Check bucket existence and access
	if resp.StatusCode == 200 {
		authResult.BucketExists = true
		authResult.AccessGranted = true
		c.verbose.LogMessage("Bucket exists and access is granted")
	} else if resp.StatusCode == 403 {
		authResult.BucketExists = true
		authResult.AccessGranted = false
		c.verbose.LogMessage("Bucket exists but access is denied (403)")
	} else if resp.StatusCode == 404 {
		authResult.BucketExists = false
		authResult.AccessGranted = false
		c.verbose.LogMessage("Bucket not found (404)")
	} else {
		c.verbose.LogMessage("Unexpected status code: %d", resp.StatusCode)
	}

	// Parse error response for more details
	if resp.StatusCode >= 400 {
		var errResp ErrorResponse
		if err := xml.Unmarshal(body, &errResp); err == nil {
			result.Error = fmt.Sprintf("%s: %s", errResp.Code, errResp.Message)
			c.verbose.LogMessage("Error response: %s - %s", errResp.Code, errResp.Message)
		} else {
			result.Error = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(body))
			c.verbose.LogMessage("Error response: HTTP %d", resp.StatusCode)
		}
		result.Status = output.StatusFail
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
	req.Header.Set("Date", time.Now().UTC().Format(time.RFC1123))

	return req, nil
}

// addSigV4Auth adds AWS Signature Version 4 authentication
func (c *AuthChecker) addSigV4Auth(req *http.Request) error {
	// Get current time
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	// Set headers
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")

	// Create canonical request
	// Use the actual request path for canonical URI (important for path-style addressing)
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}
	canonicalQueryString := ""
	canonicalHeaders := fmt.Sprintf("host:%s\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:%s\n", req.Host, amzDate)
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"

	payloadHash := "UNSIGNED-PAYLOAD"

	canonicalRequest := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s",
		req.Method,
		canonicalURI,
		canonicalQueryString,
		canonicalHeaders,
		signedHeaders,
		payloadHash)

	// Create string to sign
	credentialScope := fmt.Sprintf("%s/%s/s3/aws4_request", dateStamp, c.Region)
	stringToSign := fmt.Sprintf("AWS4-HMAC-SHA256\n%s\n%s\n%s",
		amzDate,
		credentialScope,
		hashSHA256(canonicalRequest))

	// Calculate signature
	signingKey := c.getSignatureKey(dateStamp)
	signature := hmacSHA256(signingKey, stringToSign)

	// Create authorization header
	authorizationHeader := fmt.Sprintf("AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.AccessKey,
		credentialScope,
		signedHeaders,
		hex.EncodeToString(signature))

	req.Header.Set("Authorization", authorizationHeader)

	return nil
}

// addSigV2Auth adds AWS Signature Version 2 authentication
func (c *AuthChecker) addSigV2Auth(req *http.Request) error {
	// Get current time
	now := time.Now().UTC()

	// Set headers
	req.Header.Set("Date", now.Format(time.RFC1123))

	// Create canonical string
	canonicalString := c.createSigV2CanonicalString(req)

	// Calculate signature
	signature := hmacSHA256([]byte(c.SecretKey), canonicalString)

	// Add signature to query string
	if req.URL.RawQuery == "" {
		req.URL.RawQuery = fmt.Sprintf("AWSAccessKeyId=%s&Signature=%s&Expires=%d",
			url.QueryEscape(c.AccessKey),
			url.QueryEscape(hex.EncodeToString(signature)),
			now.Add(15*time.Minute).Unix())
	} else {
		req.URL.RawQuery = fmt.Sprintf("%s&AWSAccessKeyId=%s&Signature=%s&Expires=%d",
			req.URL.RawQuery,
			url.QueryEscape(c.AccessKey),
			url.QueryEscape(hex.EncodeToString(signature)),
			now.Add(15*time.Minute).Unix())
	}

	return nil
}

// createSigV2CanonicalString creates the canonical string for SigV2
func (c *AuthChecker) createSigV2CanonicalString(req *http.Request) string {
	var buf bytes.Buffer

	// HTTP Verb
	buf.WriteString(req.Method)
	buf.WriteString("\n")

	// Content-MD5 (empty if not present)
	buf.WriteString("\n")

	// Content-Type (empty if not present)
	buf.WriteString("\n")

	// Date
	buf.WriteString(req.Header.Get("Date"))
	buf.WriteString("\n")

	// CanonicalizedResource
	// For SigV2, the resource path should include the bucket
	canonicalizedResource := c.getCanonicalizedResource(req)
	buf.WriteString(canonicalizedResource)

	return buf.String()
}

// getCanonicalizedResource returns the canonicalized resource for SigV2
func (c *AuthChecker) getCanonicalizedResource(req *http.Request) string {
	var buf bytes.Buffer

	// For path-style addressing, the path already includes /bucket
	// For virtual-hosted addressing, we need to prepend /bucket
	if c.PathStyle {
		buf.WriteString(req.URL.Path)
		if req.URL.Path == "" {
			buf.WriteString("/")
		}
	} else {
		// Virtual-hosted style: prepend /bucket to the path
		buf.WriteString("/")
		buf.WriteString(c.Bucket)
		if req.URL.Path != "" && req.URL.Path != "/" {
			buf.WriteString(req.URL.Path)
		}
	}

	// Add sub-resources if any
	// Note: For HEAD request to check bucket existence, we typically don't have sub-resources

	return buf.String()
}

// getSignatureKey derives the signing key for SigV4
func (c *AuthChecker) getSignatureKey(dateStamp string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+c.SecretKey), dateStamp)
	kRegion := hmacSHA256(kDate, c.Region)
	kService := hmacSHA256(kRegion, "s3")
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}

// hashSHA256 returns the SHA256 hash of the input
func hashSHA256(input string) string {
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// hmacSHA256 returns the HMAC-SHA256 of the input with the key
func hmacSHA256(key []byte, input string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(input))
	return mac.Sum(nil)
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
