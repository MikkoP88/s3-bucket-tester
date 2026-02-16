package checker

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// VerboseLogger handles verbose logging for HTTP requests and responses
type VerboseLogger struct {
	enabled bool
}

// NewVerboseLogger creates a new verbose logger
func NewVerboseLogger(enabled bool) *VerboseLogger {
	return &VerboseLogger{enabled: enabled}
}

// LogRequest logs HTTP request details
func (v *VerboseLogger) LogRequest(req *http.Request) {
	if !v.enabled {
		return
	}

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("HTTP REQUEST")
	fmt.Println(strings.Repeat("=", 70))

	// Dump request
	fmt.Printf("%s %s %s\n", req.Method, req.URL.String(), req.Proto)
	for key, values := range req.Header {
		for _, value := range values {
			fmt.Printf("%s: %s\n", key, value)
		}
	}

	fmt.Println(strings.Repeat("-", 70))
}

// LogResponse logs HTTP response details
func (v *VerboseLogger) LogResponse(resp *http.Response) {
	if !v.enabled {
		return
	}

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("HTTP RESPONSE")
	fmt.Println(strings.Repeat("=", 70))

	// Read and store body for logging
	var bodyBytes []byte
	if resp.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Error reading response body: %v\n", err)
		}
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// Dump response
	fmt.Printf("%s %s\n", resp.Proto, resp.Status)
	for key, values := range resp.Header {
		for _, value := range values {
			fmt.Printf("%s: %s\n", key, value)
		}
	}

	// Log body if present
	if len(bodyBytes) > 0 {
		fmt.Println("\nResponse Body:")
		fmt.Println(strings.Repeat("-", 70))
		// Limit body output for readability
		bodyStr := string(bodyBytes)

		// Try to beautify JSON
		var jsonBody interface{}
		if json.Unmarshal(bodyBytes, &jsonBody) == nil {
			// Successfully parsed as JSON, format it nicely
			formatted, err := json.MarshalIndent(jsonBody, "", "  ")
			if err == nil {
				fmt.Println(string(formatted))
			} else {
				fmt.Println(bodyStr)
			}
		} else if strings.TrimSpace(bodyStr) != "" && strings.HasPrefix(strings.TrimSpace(bodyStr), "<") {
			// XML - try to beautify
			formattedXML, err := beautifyXML(bodyBytes)
			if err == nil {
				fmt.Println(formattedXML)
			} else {
				// If beautification fails, show as-is
				fmt.Printf("%s\n", bodyStr)
			}
		} else {
			// Plain text or other format
			if len(bodyStr) > 2000 {
				fmt.Println(bodyStr[:2000] + "\n... (truncated, " + fmt.Sprintf("%d", len(bodyBytes)) + " bytes total)")
			} else {
				fmt.Println(bodyStr)
			}
		}
	}

	fmt.Println(strings.Repeat("=", 70))
}

// LogMessage logs a general message
func (v *VerboseLogger) LogMessage(format string, args ...interface{}) {
	if !v.enabled {
		return
	}
	fmt.Printf("\n[VERBOSE] "+format+"\n", args...)
}

// LogSection logs a section header
func (v *VerboseLogger) LogSection(title string) {
	if !v.enabled {
		return
	}
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", 70))
}

// beautifyXML attempts to beautify XML content with proper indentation
func beautifyXML(data []byte) (string, error) {
	// First, try to unmarshal to a generic interface to validate XML
	var v interface{}
	if err := xml.Unmarshal(data, &v); err != nil {
		return "", err
	}

	// Re-marshal with indentation
	formatted, err := xml.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}

	// Add XML declaration if it was in the original
	xmlDecl := ""
	if bytes.HasPrefix(data, []byte("<?xml")) {
		xmlDecl = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
	}

	// Check if the formatted output is empty or too short (can happen with empty elements)
	result := xmlDecl + string(formatted)
	if len(result) < len(data)/2 {
		// If beautification produces significantly shorter result, fall back to original
		// This happens when xml.MarshalIndent to interface{} loses structure
		return simpleXMLBeautify(string(data)), nil
	}

	return result, nil
}

// simpleXMLBeautify provides basic XML indentation without full parsing
func simpleXMLBeautify(xmlStr string) string {
	var result strings.Builder
	indent := 0
	i := 0
	firstElement := true
	tagStack := make([]string, 0, 10)

	for i < len(xmlStr) {
		// Skip whitespace
		if xmlStr[i] <= ' ' {
			i++
			continue
		}

		if xmlStr[i] == '<' {
			// Check for closing tag
			if i+1 < len(xmlStr) && xmlStr[i+1] == '/' {
				// Closing tag
				indent--
				if indent < 0 {
					indent = 0
				}

				// Check if this is an empty element (no text content between tags)
				if len(tagStack) > 0 && tagStack[len(tagStack)-1] == "empty" {
					// Empty element, put closing tag on same line
					tagStack = tagStack[:len(tagStack)-1]
					result.WriteString("</")
					i += 2
					// Copy tag name
					for i < len(xmlStr) && xmlStr[i] != '>' {
						result.WriteByte(xmlStr[i])
						i++
					}
					if i < len(xmlStr) {
						result.WriteByte('>')
						i++
					}
				} else {
					// Non-empty element, put closing tag on new line
					result.WriteByte('\n')
					result.WriteString(strings.Repeat("  ", indent))
					result.WriteString("</")
					i += 2
					// Copy tag name
					for i < len(xmlStr) && xmlStr[i] != '>' {
						result.WriteByte(xmlStr[i])
						i++
					}
					if i < len(xmlStr) {
						result.WriteByte('>')
						i++
					}
				}
			} else if i+1 < len(xmlStr) && xmlStr[i+1] == '?' {
				// Processing instruction (<?xml ... ?>)
				if !firstElement {
					result.WriteByte('\n')
				}
				result.WriteString(strings.Repeat("  ", indent))
				result.WriteString("<?")
				i += 2
				for i < len(xmlStr) && !(xmlStr[i] == '?' && i+1 < len(xmlStr) && xmlStr[i+1] == '>') {
					result.WriteByte(xmlStr[i])
					i++
				}
				if i < len(xmlStr) {
					result.WriteString("?>")
					i += 2
				}
				firstElement = false
			} else if i+3 < len(xmlStr) && xmlStr[i:i+4] == "<!--" {
				// Comment
				result.WriteByte('\n')
				result.WriteString(strings.Repeat("  ", indent))
				result.WriteString("<!--")
				i += 4
				for i < len(xmlStr) && !(xmlStr[i] == '-' && i+2 < len(xmlStr) && xmlStr[i+1] == '-' && xmlStr[i+2] == '>') {
					result.WriteByte(xmlStr[i])
					i++
				}
				if i < len(xmlStr) {
					result.WriteString("-->")
					i += 3
				}
			} else {
				// Opening tag
				if !firstElement {
					result.WriteByte('\n')
				}
				result.WriteString(strings.Repeat("  ", indent))
				result.WriteByte('<')
				i++
				// Copy tag name
				for i < len(xmlStr) && xmlStr[i] != '>' && xmlStr[i] != ' ' && xmlStr[i] != '/' {
					result.WriteByte(xmlStr[i])
					i++
				}
				// Copy attributes if any
				for i < len(xmlStr) && xmlStr[i] != '>' {
					result.WriteByte(xmlStr[i])
					i++
				}
				// Check for self-closing tag
				if i > 0 && xmlStr[i-1] == '/' {
					result.WriteByte('>')
					i++
				} else if i < len(xmlStr) {
					result.WriteByte('>')
					i++
					// Check if next is closing tag (empty element)
					if i < len(xmlStr) && xmlStr[i] == '<' && i+1 < len(xmlStr) && xmlStr[i+1] == '/' {
						// Empty element, mark it
						tagStack = append(tagStack, "empty")
					} else {
						indent++
						tagStack = append(tagStack, "non-empty")
					}
				}
				firstElement = false
			}
		} else {
			// Text content - keep on same line as opening tag
			for i < len(xmlStr) && xmlStr[i] != '<' {
				ch := xmlStr[i]
				if ch > ' ' {
					result.WriteByte(ch)
				}
				i++
			}
			// Mark as non-empty if we found text content
			if len(tagStack) > 0 {
				tagStack[len(tagStack)-1] = "non-empty"
			}
		}
	}

	return strings.TrimSpace(result.String())
}

// AccessControlPolicy represents an S3 ACL document
type AccessControlPolicy struct {
	Owner  OwnerInfo         `xml:"Owner"`
	Grants []output.ACLGrant `xml:"AccessControlList>Grant"`
}

// OwnerInfo represents bucket owner information
type OwnerInfo struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

// PolicyChecker performs bucket policy and ACL checks
type PolicyChecker struct {
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

// NewPolicyChecker creates a new policy checker
func NewPolicyChecker(config output.Config) *PolicyChecker {
	return &PolicyChecker{
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
func (c *PolicyChecker) Name() string {
	return "Bucket Policy & ACL Check"
}

// Check performs the policy and ACL check
func (c *PolicyChecker) Check() output.TestResult {
	startTime := time.Now()

	c.verbose.LogSection("Starting Bucket Policy & ACL Check")

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

	// Get bucket policy
	policyStartTime := time.Now()
	c.verbose.LogMessage("Fetching bucket policy...")
	policyResult, err := c.getBucketPolicy(client)
	if err != nil {
		c.verbose.LogMessage("Error fetching bucket policy: %v", err)
		policyResult.Error = err.Error()
	}
	c.verbose.LogMessage("Bucket Policy check completed in %v", time.Since(policyStartTime))

	// Get bucket ACL
	aclStartTime := time.Now()
	c.verbose.LogMessage("Fetching bucket ACL...")
	aclResult, err := c.getBucketACL(client)
	if err != nil {
		c.verbose.LogMessage("Error fetching bucket ACL: %v", err)
		aclResult.Error = err.Error()
	}
	c.verbose.LogMessage("Bucket ACL check completed in %v", time.Since(aclStartTime))

	// Combine results
	details := output.PolicyACLResult{
		Policy: policyResult,
		ACL:    aclResult,
	}

	result.Details = details
	result.Duration = time.Since(startTime)

	c.verbose.LogMessage("Policy & ACL check completed in %v", result.Duration)

	// Determine status based on results
	if policyResult.Error != "" && aclResult.Error != "" {
		result.Status = output.StatusFail
		result.Error = "access denied: " + policyResult.Error + "; " + aclResult.Error
	} else if policyResult.Error != "" {
		result.Status = output.StatusWarn
		result.Error = "Policy check failed: " + policyResult.Error
	} else if aclResult.Error != "" {
		result.Status = output.StatusWarn
		result.Error = "ACL check failed: " + aclResult.Error
	}

	c.verbose.LogMessage("Check completed with status: %s", result.Status)

	return result
}

// getBucketPolicy retrieves the bucket policy
func (c *PolicyChecker) getBucketPolicy(client *http.Client) (output.PolicyResult, error) {
	result := output.PolicyResult{
		HasPolicy: false,
	}

	// Build URL
	policyURL, err := c.buildBucketURL("?policy")
	if err != nil {
		return result, fmt.Errorf("failed to build URL: %w", err)
	}

	// Create request
	req, err := http.NewRequest("GET", policyURL, nil)
	if err != nil {
		return result, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication headers
	if c.AuthType == "sigv4" {
		err = c.signRequestV4(req)
		if err != nil {
			return result, fmt.Errorf("failed to sign request: %w", err)
		}
	} else if c.AuthType == "sigv2" {
		err = c.signRequestV2(req)
		if err != nil {
			return result, fmt.Errorf("failed to sign request: %w", err)
		}
	}

	c.verbose.LogRequest(req)

	// Send request
	c.verbose.LogMessage("Sending request to S3 endpoint...")
	resp, err := client.Do(req)
	if err != nil {
		c.verbose.LogMessage("Request failed: %v", err)
		return result, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	c.verbose.LogMessage("Request completed successfully")

	c.verbose.LogResponse(resp)

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, fmt.Errorf("failed to read response body: %w", err)
	}

	// Store response body for verbose output
	result.ResponseBody = string(bodyBytes)

	// Handle response
	if resp.StatusCode == http.StatusOK {
		var policyDoc output.BucketPolicy
		if err := json.Unmarshal(bodyBytes, &policyDoc); err != nil {
			return result, fmt.Errorf("failed to parse policy: %w", err)
		}

		result.HasPolicy = true
		result.PolicyDocument = &policyDoc
		result.StatementCount = len(policyDoc.Statement)

		// Extract actions, principals, resources
		for _, stmt := range policyDoc.Statement {
			// Extract actions based on effect
			if stmt.Effect == "Allow" {
				if actions, ok := stmt.Action.([]string); ok {
					result.AllowedActions = append(result.AllowedActions, actions...)
				} else if action, ok := stmt.Action.(string); ok {
					result.AllowedActions = append(result.AllowedActions, action)
				}
			} else if stmt.Effect == "Deny" {
				if actions, ok := stmt.Action.([]string); ok {
					result.DeniedActions = append(result.DeniedActions, actions...)
				} else if action, ok := stmt.Action.(string); ok {
					result.DeniedActions = append(result.DeniedActions, action)
				}
			}

			// Extract principals
			if principalAWS, ok := stmt.Principal["AWS"]; ok {
				if principals, ok := principalAWS.([]string); ok {
					result.Principals = append(result.Principals, principals...)
				} else if principal, ok := principalAWS.(string); ok {
					result.Principals = append(result.Principals, principal)
				}
			} else if principal, ok := stmt.Principal["*"].(string); ok {
				result.Principals = append(result.Principals, principal)
			}

			// Extract resources
			if resources, ok := stmt.Resource.([]string); ok {
				result.Resources = append(result.Resources, resources...)
			} else if resource, ok := stmt.Resource.(string); ok {
				result.Resources = append(result.Resources, resource)
			}

			// Extract conditions
			if stmt.Condition != nil {
				for key, val := range stmt.Condition {
					result.Conditions = append(result.Conditions, fmt.Sprintf("%s: %v", key, val))
				}
			}
		}

		return result, nil
	} else if resp.StatusCode == http.StatusNotFound {
		// No policy exists
		return result, nil
	} else if resp.StatusCode == http.StatusForbidden {
		// Access denied
		var errorResp ErrorResponse
		if err := xml.Unmarshal(bodyBytes, &errorResp); err == nil {
			return result, fmt.Errorf("access denied: %s", errorResp.Message)
		}
		return result, fmt.Errorf("access denied")
	}

	return result, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

// getBucketACL retrieves the bucket ACL
func (c *PolicyChecker) getBucketACL(client *http.Client) (output.ACLResult, error) {
	result := output.ACLResult{}

	// Build URL
	aclURL, err := c.buildBucketURL("?acl")
	if err != nil {
		return result, fmt.Errorf("failed to build URL: %w", err)
	}

	// Create request
	req, err := http.NewRequest("GET", aclURL, nil)
	if err != nil {
		return result, fmt.Errorf("failed to create request: %w", err)
	}

	// Add authentication headers
	if c.AuthType == "sigv4" {
		err = c.signRequestV4(req)
		if err != nil {
			return result, fmt.Errorf("failed to sign request: %w", err)
		}
	} else if c.AuthType == "sigv2" {
		err = c.signRequestV2(req)
		if err != nil {
			return result, fmt.Errorf("failed to sign request: %w", err)
		}
	}

	c.verbose.LogRequest(req)

	// Send request
	c.verbose.LogMessage("Sending request to S3 endpoint...")
	resp, err := client.Do(req)
	if err != nil {
		c.verbose.LogMessage("Request failed: %v", err)
		return result, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	c.verbose.LogMessage("Request completed successfully")

	c.verbose.LogResponse(resp)

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return result, fmt.Errorf("failed to read response body: %w", err)
	}

	// Store response body for verbose output
	result.ResponseBody = string(bodyBytes)

	// Handle response
	if resp.StatusCode == http.StatusOK {
		var acl AccessControlPolicy
		if err := xml.Unmarshal(bodyBytes, &acl); err != nil {
			return result, fmt.Errorf("failed to parse ACL: %w", err)
		}

		result.Owner = output.ACLGrant{
			Grantee: output.ACLGrantee{
				ID:          acl.Owner.ID,
				DisplayName: acl.Owner.DisplayName,
				Type:        "CanonicalUser",
			},
			Permission: "FULL_CONTROL",
		}
		result.Grants = acl.Grants

		// Check for public access
		for _, grant := range acl.Grants {
			if grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AllUsers" {
				if grant.Permission == "READ" {
					result.PublicRead = true
				} else if grant.Permission == "WRITE" {
					result.PublicWrite = true
				}
			} else if grant.Grantee.URI == "http://acs.amazonaws.com/groups/global/AuthenticatedUsers" {
				if grant.Permission == "READ" {
					result.AuthUsersRead = true
				}
			}
		}

		return result, nil
	} else if resp.StatusCode == http.StatusForbidden {
		// Access denied
		var errorResp ErrorResponse
		if err := xml.Unmarshal(bodyBytes, &errorResp); err == nil {
			return result, fmt.Errorf("access denied: %s", errorResp.Message)
		}
		return result, fmt.Errorf("access denied")
	}

	return result, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
}

// extractActions extracts actions from policy statement
func (c *PolicyChecker) extractActions(action interface{}) []string {
	var actions []string
	switch v := action.(type) {
	case string:
		actions = append(actions, v)
	case []string:
		actions = append(actions, v...)
	case []interface{}:
		for _, a := range v {
			if str, ok := a.(string); ok {
				actions = append(actions, str)
			}
		}
	}
	return actions
}

// extractPrincipals extracts principals from policy statement
func (c *PolicyChecker) extractPrincipals(principal map[string]interface{}) []string {
	var principals []string
	if aws, ok := principal["AWS"]; ok {
		switch v := aws.(type) {
		case string:
			principals = append(principals, v)
		case []string:
			principals = append(principals, v...)
		case []interface{}:
			for _, p := range v {
				if str, ok := p.(string); ok {
					principals = append(principals, str)
				}
			}
		}
	}
	return principals
}

// extractResources extracts resources from policy statement
func (c *PolicyChecker) extractResources(resource interface{}) []string {
	var resources []string
	switch v := resource.(type) {
	case string:
		resources = append(resources, v)
	case []string:
		resources = append(resources, v...)
	}
	return resources
}

// buildBucketURL builds the bucket URL
func (c *PolicyChecker) buildBucketURL(query string) (string, error) {
	if c.PathStyle {
		return fmt.Sprintf("%s/%s%s", c.Endpoint, c.Bucket, query), nil
	}
	return fmt.Sprintf("https://%s.%s%s", c.Bucket, strings.TrimPrefix(c.Endpoint, "https://"), query), nil
}

// addSigV4Auth adds SigV4 authentication to the request
func (c *PolicyChecker) addSigV4Auth(req *http.Request) error {
	return c.signRequestV4(req)
}

// addSigV2Auth adds SigV2 authentication to the request
func (c *PolicyChecker) addSigV2Auth(req *http.Request) error {
	return c.signRequestV2(req)
}

// signRequestV4 signs the request using AWS Signature Version 4
func (c *PolicyChecker) signRequestV4(req *http.Request) error {
	// Get current time
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	// Set required headers
	req.Header.Set("Host", req.Host)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")

	// Create canonical request
	canonicalURI := req.URL.Path
	if canonicalURI == "" {
		canonicalURI = "/"
	}

	// Build canonical query string properly
	// Query parameters must be URL-encoded and sorted alphabetically
	canonicalQueryString := c.buildCanonicalQueryString(req.URL.RawQuery)

	canonicalHeaders := "host:" + req.Host + "\n" + "x-amz-content-sha256:UNSIGNED-PAYLOAD\n" + "x-amz-date:" + amzDate + "\n"
	signedHeaders := "host;x-amz-content-sha256;x-amz-date"

	payloadHash := "UNSIGNED-PAYLOAD"

	canonicalRequest := req.Method + "\n" +
		canonicalURI + "\n" +
		canonicalQueryString + "\n" +
		canonicalHeaders + "\n" +
		signedHeaders + "\n" +
		payloadHash

	// Create string to sign
	algorithm := "AWS4-HMAC-SHA256"
	credentialScope := dateStamp + "/" + c.Region + "/s3/aws4_request"
	stringToSign := algorithm + "\n" +
		amzDate + "\n" +
		credentialScope + "\n" +
		hashSHA256(canonicalRequest)

	// Calculate signature
	signingKey := getSignatureKey(c.SecretKey, dateStamp, c.Region, "s3")
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	// Add authorization header
	authorizationHeader := algorithm + " Credential=" + c.AccessKey + "/" + credentialScope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + signature
	req.Header.Set("Authorization", authorizationHeader)

	return nil
}

// buildCanonicalQueryString builds the canonical query string according to AWS SigV4 spec
func (c *PolicyChecker) buildCanonicalQueryString(rawQuery string) string {
	if rawQuery == "" {
		return ""
	}

	// Parse the query string
	values, err := url.ParseQuery(rawQuery)
	if err != nil {
		// If parsing fails, return the raw query as-is
		return rawQuery
	}

	// Build canonical query string
	// Parameters must be URL-encoded and sorted alphabetically
	var params []string
	for key, vals := range values {
		// URL-encode the key
		encodedKey := url.QueryEscape(key)
		if len(vals) == 0 {
			// Parameter without value: use "key=" format
			params = append(params, encodedKey+"=")
		} else {
			// Parameter with value(s): use "key=value" format
			for _, val := range vals {
				encodedVal := url.QueryEscape(val)
				params = append(params, encodedKey+"="+encodedVal)
			}
		}
	}

	// Sort parameters alphabetically
	sort.Strings(params)

	// Join with "&"
	return strings.Join(params, "&")
}

// signRequestV2 signs the request using AWS Signature Version 2
func (c *PolicyChecker) signRequestV2(req *http.Request) error {
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
			hex.EncodeToString(signature),
			now.Add(15*time.Minute).Unix())
	} else {
		req.URL.RawQuery = fmt.Sprintf("%s&AWSAccessKeyId=%s&Signature=%s&Expires=%d",
			req.URL.RawQuery,
			url.QueryEscape(c.AccessKey),
			hex.EncodeToString(signature),
			now.Add(15*time.Minute).Unix())
	}

	return nil
}

// createSigV2CanonicalString creates the canonical string for SigV2
func (c *PolicyChecker) createSigV2CanonicalString(req *http.Request) string {
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
	canonicalizedResource := c.getCanonicalizedResource(req)
	buf.WriteString(canonicalizedResource)

	return buf.String()
}

// getCanonicalizedResource returns the canonicalized resource for SigV2
func (c *PolicyChecker) getCanonicalizedResource(req *http.Request) string {
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
	if req.URL.RawQuery != "" {
		buf.WriteString("?")
		buf.WriteString(req.URL.RawQuery)
	}

	return buf.String()
}

// getSignatureKey derives the signing key for SigV4
func getSignatureKey(key, dateStamp, regionName, serviceName string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+key), dateStamp)
	kRegion := hmacSHA256(kDate, regionName)
	kService := hmacSHA256(kRegion, serviceName)
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}
