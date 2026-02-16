package checker

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// TestPolicyCheckerName tests the Name method
func TestPolicyCheckerName(t *testing.T) {
	config := output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
	}

	checker := NewPolicyChecker(config)
	if checker.Name() != "Bucket Policy & ACL Check" {
		t.Errorf("Expected name 'Bucket Policy & ACL Check', got '%s'", checker.Name())
	}
}

// TestNewPolicyChecker tests the constructor
func TestNewPolicyChecker(t *testing.T) {
	config := output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true,
		Verbose:   true,
	}

	checker := NewPolicyChecker(config)

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
	if checker.AuthType != strings.ToLower(config.AuthType) {
		t.Errorf("Expected AuthType '%s', got '%s'", strings.ToLower(config.AuthType), checker.AuthType)
	}
	if checker.PathStyle != config.PathStyle {
		t.Errorf("Expected PathStyle %v, got %v", config.PathStyle, checker.PathStyle)
	}
}

// TestGetBucketPolicy_Success tests successful policy retrieval
func TestGetBucketPolicy_Success(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check for policy endpoint
		if strings.Contains(r.URL.Path, "test-bucket") && strings.Contains(r.URL.RawQuery, "policy") {
			policy := output.BucketPolicy{
				Version: "2012-10-17",
				ID:      "TestPolicy",
				Statement: []output.Statement{
					{
						Sid:    "PublicRead",
						Effect: "Allow",
						Principal: map[string]interface{}{
							"AWS": "*",
						},
						Action:   []string{"s3:GetObject"},
						Resource: []string{"arn:aws:s3:::test-bucket/*"},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(policy)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := output.Config{
		Endpoint:  server.URL,
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true, // Use path-style for mock server
	}
	checker := NewPolicyChecker(config)

	// Create HTTP client
	client := &http.Client{Timeout: 5 * time.Second}

	result, err := checker.getBucketPolicy(client)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !result.HasPolicy {
		t.Error("Expected HasPolicy to be true")
	}
	if result.StatementCount != 1 {
		t.Errorf("Expected StatementCount 1, got %d", result.StatementCount)
	}
	if len(result.AllowedActions) != 1 || result.AllowedActions[0] != "s3:GetObject" {
		t.Errorf("Expected AllowedActions ['s3:GetObject'], got %v", result.AllowedActions)
	}
	if len(result.Principals) != 1 || result.Principals[0] != "*" {
		t.Errorf("Expected Principals ['*'], got %v", result.Principals)
	}
}

// TestGetBucketPolicy_NotFound tests policy retrieval when no policy exists
func TestGetBucketPolicy_NotFound(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "policy") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := output.Config{
		Endpoint:  server.URL,
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true, // Use path-style for mock server
	}
	checker := NewPolicyChecker(config)

	client := &http.Client{Timeout: 5 * time.Second}

	result, err := checker.getBucketPolicy(client)
	if err != nil {
		t.Fatalf("Expected no error for 404, got %v", err)
	}

	if result.HasPolicy {
		t.Error("Expected HasPolicy to be false for 404")
	}
	if result.Error != "" {
		t.Errorf("Expected no error for 404, got '%s'", result.Error)
	}
}

// TestGetBucketPolicy_AccessDenied tests policy retrieval with access denied
func TestGetBucketPolicy_AccessDenied(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "policy") {
			errorResp := ErrorResponse{
				Code:    "AccessDenied",
				Message: "Access Denied",
			}
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			xml.NewEncoder(w).Encode(errorResp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := output.Config{
		Endpoint:  server.URL,
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true, // Use path-style for mock server
	}
	checker := NewPolicyChecker(config)

	client := &http.Client{Timeout: 5 * time.Second}

	result, err := checker.getBucketPolicy(client)
	if err == nil {
		t.Fatal("Expected error for 403, got nil")
	}

	if !strings.Contains(result.Error, "AccessDenied") {
		t.Errorf("Expected error to contain 'AccessDenied', got '%s'", result.Error)
	}
}

// TestGetBucketPolicy_MultipleStatements tests policy with multiple statements
func TestGetBucketPolicy_MultipleStatements(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "policy") {
			policy := output.BucketPolicy{
				Version: "2012-10-17",
				Statement: []output.Statement{
					{
						Sid:    "AllowRead",
						Effect: "Allow",
						Principal: map[string]interface{}{
							"AWS": "arn:aws:iam::123456789012:user/test-user",
						},
						Action:   []string{"s3:GetObject", "s3:ListBucket"},
						Resource: []string{"arn:aws:s3:::test-bucket/*"},
					},
					{
						Sid:    "DenyDelete",
						Effect: "Deny",
						Principal: map[string]interface{}{
							"AWS": "*",
						},
						Action:   "s3:DeleteObject",
						Resource: "arn:aws:s3:::test-bucket/*",
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(policy)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := output.Config{
		Endpoint:  server.URL,
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true, // Use path-style for mock server
	}
	checker := NewPolicyChecker(config)

	client := &http.Client{Timeout: 5 * time.Second}

	result, err := checker.getBucketPolicy(client)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.StatementCount != 2 {
		t.Errorf("Expected StatementCount 2, got %d", result.StatementCount)
	}
	if len(result.AllowedActions) != 2 {
		t.Errorf("Expected 2 AllowedActions, got %d", len(result.AllowedActions))
	}
	if len(result.DeniedActions) != 1 || result.DeniedActions[0] != "s3:DeleteObject" {
		t.Errorf("Expected DeniedActions ['s3:DeleteObject'], got %v", result.DeniedActions)
	}
}

// TestGetBucketACL_Success tests successful ACL retrieval
func TestGetBucketACL_Success(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "acl") {
			acl := AccessControlPolicy{
				Owner: OwnerInfo{
					ID:          "owner-id-123",
					DisplayName: "BucketOwner",
				},
				Grants: []output.ACLGrant{
					{
						Grantee: output.ACLGrantee{
							ID:          "owner-id-123",
							DisplayName: "BucketOwner",
							Type:        "CanonicalUser",
						},
						Permission: "FULL_CONTROL",
					},
					{
						Grantee: output.ACLGrantee{
							URI:  "http://acs.amazonaws.com/groups/global/AllUsers",
							Type: "Group",
						},
						Permission: "READ",
					},
				},
			}
			w.Header().Set("Content-Type", "application/xml")
			xml.NewEncoder(w).Encode(acl)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := output.Config{
		Endpoint:  server.URL,
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true, // Use path-style for mock server
	}
	checker := NewPolicyChecker(config)

	client := &http.Client{Timeout: 5 * time.Second}

	result, err := checker.getBucketACL(client)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Owner.Grantee.ID != "owner-id-123" {
		t.Errorf("Expected Owner ID 'owner-id-123', got '%s'", result.Owner.Grantee.ID)
	}
	if len(result.Grants) != 2 {
		t.Errorf("Expected 2 grants, got %d", len(result.Grants))
	}
	if !result.PublicRead {
		t.Error("Expected PublicRead to be true")
	}
	if result.PublicWrite {
		t.Error("Expected PublicWrite to be false")
	}
}

// TestGetBucketACL_PublicWrite tests ACL with public write access
func TestGetBucketACL_PublicWrite(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "acl") {
			acl := AccessControlPolicy{
				Owner: OwnerInfo{
					ID:          "owner-id-123",
					DisplayName: "BucketOwner",
				},
				Grants: []output.ACLGrant{
					{
						Grantee: output.ACLGrantee{
							ID:          "owner-id-123",
							DisplayName: "BucketOwner",
							Type:        "CanonicalUser",
						},
						Permission: "FULL_CONTROL",
					},
					{
						Grantee: output.ACLGrantee{
							URI:  "http://acs.amazonaws.com/groups/global/AllUsers",
							Type: "Group",
						},
						Permission: "WRITE",
					},
				},
			}
			w.Header().Set("Content-Type", "application/xml")
			xml.NewEncoder(w).Encode(acl)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := output.Config{
		Endpoint:  server.URL,
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true, // Use path-style for mock server
	}
	checker := NewPolicyChecker(config)

	client := &http.Client{Timeout: 5 * time.Second}

	result, err := checker.getBucketACL(client)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !result.PublicWrite {
		t.Error("Expected PublicWrite to be true")
	}
	if result.PublicRead {
		t.Error("Expected PublicRead to be false")
	}
}

// TestGetBucketACL_AuthUsersRead tests ACL with authenticated users read access
func TestGetBucketACL_AuthUsersRead(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "acl") {
			acl := AccessControlPolicy{
				Owner: OwnerInfo{
					ID:          "owner-id-123",
					DisplayName: "BucketOwner",
				},
				Grants: []output.ACLGrant{
					{
						Grantee: output.ACLGrantee{
							ID:          "owner-id-123",
							DisplayName: "BucketOwner",
							Type:        "CanonicalUser",
						},
						Permission: "FULL_CONTROL",
					},
					{
						Grantee: output.ACLGrantee{
							URI:  "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
							Type: "Group",
						},
						Permission: "READ",
					},
				},
			}
			w.Header().Set("Content-Type", "application/xml")
			xml.NewEncoder(w).Encode(acl)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := output.Config{
		Endpoint:  server.URL,
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true, // Use path-style for mock server
	}
	checker := NewPolicyChecker(config)

	client := &http.Client{Timeout: 5 * time.Second}

	result, err := checker.getBucketACL(client)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !result.AuthUsersRead {
		t.Error("Expected AuthUsersRead to be true")
	}
	if result.PublicRead || result.PublicWrite {
		t.Error("Expected no public read/write access")
	}
}

// TestGetBucketACL_AccessDenied tests ACL retrieval with access denied
func TestGetBucketACL_AccessDenied(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "acl") {
			errorResp := ErrorResponse{
				Code:    "AccessDenied",
				Message: "Access Denied",
			}
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			xml.NewEncoder(w).Encode(errorResp)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := output.Config{
		Endpoint:  server.URL,
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true, // Use path-style for mock server
	}
	checker := NewPolicyChecker(config)

	client := &http.Client{Timeout: 5 * time.Second}

	result, err := checker.getBucketACL(client)
	if err == nil {
		t.Fatal("Expected error for 403, got nil")
	}

	if !strings.Contains(result.Error, "AccessDenied") {
		t.Errorf("Expected error to contain 'AccessDenied', got '%s'", result.Error)
	}
}

// TestExtractActions tests the extractActions helper function
func TestExtractActions(t *testing.T) {
	config := output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
	}
	checker := NewPolicyChecker(config)

	// Test with string
	actions := checker.extractActions("s3:GetObject")
	if len(actions) != 1 || actions[0] != "s3:GetObject" {
		t.Errorf("Expected ['s3:GetObject'], got %v", actions)
	}

	// Test with []string
	actions = checker.extractActions([]string{"s3:GetObject", "s3:PutObject"})
	if len(actions) != 2 {
		t.Errorf("Expected 2 actions, got %d", len(actions))
	}

	// Test with []interface{}
	actions = checker.extractActions([]interface{}{"s3:GetObject", "s3:DeleteObject"})
	if len(actions) != 2 {
		t.Errorf("Expected 2 actions, got %d", len(actions))
	}
}

// TestExtractPrincipals tests the extractPrincipals helper function
func TestExtractPrincipals(t *testing.T) {
	config := output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
	}
	checker := NewPolicyChecker(config)

	// Test with string
	principal := map[string]interface{}{
		"AWS": "*",
	}
	principals := checker.extractPrincipals(principal)
	if len(principals) != 1 || principals[0] != "*" {
		t.Errorf("Expected ['*'], got %v", principals)
	}

	// Test with []string
	principal = map[string]interface{}{
		"AWS": []string{"arn:aws:iam::123456789012:user/user1", "arn:aws:iam::123456789012:user/user2"},
	}
	principals = checker.extractPrincipals(principal)
	if len(principals) != 2 {
		t.Errorf("Expected 2 principals, got %d", len(principals))
	}
}

// TestExtractResources tests the extractResources helper function
func TestExtractResources(t *testing.T) {
	config := output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
	}
	checker := NewPolicyChecker(config)

	// Test with string
	resources := checker.extractResources("arn:aws:s3:::test-bucket/*")
	if len(resources) != 1 || resources[0] != "arn:aws:s3:::test-bucket/*" {
		t.Errorf("Expected ['arn:aws:s3:::test-bucket/*'], got %v", resources)
	}

	// Test with []string
	resources = checker.extractResources([]string{"arn:aws:s3:::test-bucket/*", "arn:aws:s3:::test-bucket"})
	if len(resources) != 2 {
		t.Errorf("Expected 2 resources, got %d", len(resources))
	}
}

// TestBuildBucketURL tests the buildBucketURL helper function
func TestBuildBucketURL(t *testing.T) {
	config := output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
	}
	checker := NewPolicyChecker(config)

	// Test virtual-hosted style
	url, err := checker.buildBucketURL("?policy")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !strings.Contains(url, "test-bucket.s3.example.com") {
		t.Errorf("Expected virtual-hosted URL, got '%s'", url)
	}

	// Test path-style
	checker.PathStyle = true
	url, err = checker.buildBucketURL("?policy")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if !strings.Contains(url, "s3.example.com/test-bucket") {
		t.Errorf("Expected path-style URL, got '%s'", url)
	}
}

// TestCheck_CombinedResults tests the Check method with combined policy and ACL results
func TestCheck_CombinedResults(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "policy") {
			policy := output.BucketPolicy{
				Version: "2012-10-17",
				Statement: []output.Statement{
					{
						Sid:    "AllowRead",
						Effect: "Allow",
						Principal: map[string]interface{}{
							"AWS": "*",
						},
						Action:   []string{"s3:GetObject"},
						Resource: []string{"arn:aws:s3:::test-bucket/*"},
					},
				},
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(policy)
			return
		}
		if strings.Contains(r.URL.RawQuery, "acl") {
			acl := AccessControlPolicy{
				Owner: OwnerInfo{
					ID:          "owner-id-123",
					DisplayName: "BucketOwner",
				},
				Grants: []output.ACLGrant{
					{
						Grantee: output.ACLGrantee{
							ID:          "owner-id-123",
							DisplayName: "BucketOwner",
							Type:        "CanonicalUser",
						},
						Permission: "FULL_CONTROL",
					},
				},
			}
			w.Header().Set("Content-Type", "application/xml")
			xml.NewEncoder(w).Encode(acl)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := output.Config{
		Endpoint:  server.URL,
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true, // Use path-style for mock server
	}
	checker := NewPolicyChecker(config)

	result := checker.Check()

	if result.TestName != "Bucket Policy & ACL Check" {
		t.Errorf("Expected test name 'Bucket Policy & ACL Check', got '%s'", result.TestName)
	}
	if result.Status != output.StatusPass {
		t.Errorf("Expected status PASS, got %s", result.Status)
	}

	// Check that details contain both policy and ACL
	details, ok := result.Details.(output.PolicyACLResult)
	if !ok {
		t.Fatal("Expected details to contain Policy and ACL")
	}

	if !details.Policy.HasPolicy {
		t.Error("Expected policy to be present")
	}
	if details.ACL.Error != "" {
		t.Errorf("Expected no ACL error, got '%s'", details.ACL.Error)
	}
}

// TestCheck_PolicyAccessDenied tests Check when policy access is denied
func TestCheck_PolicyAccessDenied(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "policy") {
			errorResp := ErrorResponse{
				Code:    "AccessDenied",
				Message: "Access Denied",
			}
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(http.StatusForbidden)
			xml.NewEncoder(w).Encode(errorResp)
			return
		}
		if strings.Contains(r.URL.RawQuery, "acl") {
			acl := AccessControlPolicy{
				Owner: OwnerInfo{
					ID:          "owner-id-123",
					DisplayName: "BucketOwner",
				},
				Grants: []output.ACLGrant{
					{
						Grantee: output.ACLGrantee{
							ID:          "owner-id-123",
							DisplayName: "BucketOwner",
							Type:        "CanonicalUser",
						},
						Permission: "FULL_CONTROL",
					},
				},
			}
			w.Header().Set("Content-Type", "application/xml")
			xml.NewEncoder(w).Encode(acl)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	config := output.Config{
		Endpoint:  server.URL,
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true, // Use path-style for mock server
	}
	checker := NewPolicyChecker(config)

	result := checker.Check()

	// When policy fails with 403 but ACL succeeds, status should be WARN
	if result.Status != output.StatusWarn {
		t.Errorf("Expected status WARN for policy 403, got %s", result.Status)
	}
	if result.Error == "" {
		t.Error("Expected error message to be set")
	}
}

// TestCheck_BothAccessDenied tests Check when both policy and ACL access is denied
func TestCheck_BothAccessDenied(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		errorResp := ErrorResponse{
			Code:    "AccessDenied",
			Message: "Access Denied",
		}
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusForbidden)
		xml.NewEncoder(w).Encode(errorResp)
	}))
	defer server.Close()

	config := output.Config{
		Endpoint:  server.URL,
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true, // Use path-style for mock server
	}
	checker := NewPolicyChecker(config)

	result := checker.Check()

	// When both fail, status should be FAIL
	if result.Status != output.StatusFail {
		t.Errorf("Expected status FAIL for both 403, got %s", result.Status)
	}
}

// TestSigV4Authentication tests SigV4 authentication headers
func TestSigV4Authentication(t *testing.T) {
	config := output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:    "us-east-1",
		AuthType:  "sigv4",
	}
	checker := NewPolicyChecker(config)

	req, err := http.NewRequest("GET", "https://test-bucket.s3.example.com?policy", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	err = checker.addSigV4Auth(req)
	if err != nil {
		t.Fatalf("Failed to add SigV4 auth: %v", err)
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		t.Error("Expected Authorization header to be set")
	}
	if !strings.Contains(authHeader, "AWS4-HMAC-SHA256") {
		t.Errorf("Expected AWS4-HMAC-SHA256 in auth header, got '%s'", authHeader)
	}
	if !strings.Contains(authHeader, "Credential=AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Expected credential in auth header, got '%s'", authHeader)
	}
}

// TestSigV2Authentication tests SigV2 authentication headers
func TestSigV2Authentication(t *testing.T) {
	config := output.Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "AKIAIOSFODNN7EXAMPLE",
		SecretKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:    "us-east-1",
		AuthType:  "sigv2",
	}
	checker := NewPolicyChecker(config)

	req, err := http.NewRequest("GET", "https://s3.example.com/test-bucket?policy", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	err = checker.addSigV2Auth(req)
	if err != nil {
		t.Fatalf("Failed to add SigV2 auth: %v", err)
	}

	// SigV2 adds auth via query string
	if req.URL.RawQuery == "" {
		t.Error("Expected query string to be set for SigV2 auth")
	}
	if !strings.Contains(req.URL.RawQuery, "AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Expected AWSAccessKeyId in query string, got '%s'", req.URL.RawQuery)
	}
	if !strings.Contains(req.URL.RawQuery, "Signature=") {
		t.Errorf("Expected Signature in query string, got '%s'", req.URL.RawQuery)
	}
}
