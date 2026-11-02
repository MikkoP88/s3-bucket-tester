package checker

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// TestReadLimited verifies the bounded reader: inputs at or under the limit
// pass, larger inputs error
func TestReadLimited(t *testing.T) {
	small := strings.Repeat("a", 100)
	data, err := readLimited(strings.NewReader(small), 128)
	if err != nil || string(data) != small {
		t.Errorf("expected small input to pass, got data=%d err=%v", len(data), err)
	}

	exact := strings.Repeat("b", 128)
	data, err = readLimited(strings.NewReader(exact), 128)
	if err != nil || len(data) != 128 {
		t.Errorf("expected limit-sized input to pass, got len=%d err=%v", len(data), err)
	}

	big := strings.Repeat("c", 129)
	_, err = readLimited(strings.NewReader(big), 128)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected oversized input to error, got %v", err)
	}
}

// TestGetBucketPolicy_OversizedBody verifies policy responses beyond the
// size limit are rejected instead of being read into memory unbounded
func TestGetBucketPolicy_OversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(make([]byte, 2*maxPolicyBodySize)); err != nil {
			t.Errorf("failed to write oversized body: %v", err)
		}
	}))
	defer server.Close()

	checker := NewPolicyChecker(output.Config{
		Endpoint:  server.URL,
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
		AuthType:  "sigv4",
		PathStyle: true,
		Timeout:   5,
	})

	client := &http.Client{Timeout: 5 * time.Second}
	result, err := checker.getBucketPolicy(client)
	if err == nil {
		t.Fatalf("expected oversized policy body to error, got result %+v", result)
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected size-limit error, got: %v", err)
	}
}

// TestValidateRedirect verifies the redirect target policy: HTTPS only,
// original host or its subdomains only
func TestValidateRedirect(t *testing.T) {
	original, _ := http.NewRequest("GET", "https://s3.example.com/bucket", nil)

	tests := []struct {
		name    string
		target  string
		wantErr bool
	}{
		{"same host https", "https://s3.example.com/other", false},
		{"subdomain https", "https://data.s3.example.com/other", false},
		{"same host http downgrade", "http://s3.example.com/other", true},
		{"different host https", "https://evil.example.net/collect", true},
		{"parent domain", "https://example.com/collect", true},
		{"sibling domain", "https://other.s3.example.com.evil.net/collect", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next, _ := http.NewRequest("GET", tt.target, nil)
			err := validateRedirect(original, next)
			if tt.wantErr && err == nil {
				t.Errorf("expected redirect to %s to be blocked", tt.target)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected redirect to %s to be allowed, got: %v", tt.target, err)
			}
		})
	}
}

// TestSecureHTTPClient_DefaultNoFollow verifies redirects are not followed
// when the config leaves them disabled
func TestSecureHTTPClient_DefaultNoFollow(t *testing.T) {
	finalHit := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/final" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		finalHit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := newSecureHTTPClient(output.Config{Timeout: 5})
	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected 302 returned as-is, got %d", resp.StatusCode)
	}
	if finalHit {
		t.Error("redirect target must not be reached when redirects are disabled")
	}
}

// TestSecureHTTPClient_BlocksCrossHostRedirect verifies a redirect to a
// different host is blocked even when following is enabled. The foreign
// target never receives a connection: the block happens client-side.
func TestSecureHTTPClient_BlocksCrossHostRedirect(t *testing.T) {
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://evil.example.net/collect", http.StatusFound)
	}))
	defer source.Close()

	client := newSecureHTTPClient(output.Config{Timeout: 5, Insecure: true, FollowRedirect: true, MaxRedirects: 5})
	resp, err := client.Get(source.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected cross-host redirect to be blocked")
	}
	if !strings.Contains(err.Error(), "blocked redirect to different host") {
		t.Errorf("expected host-block error, got: %v", err)
	}
}

// TestSecureHTTPClient_BlocksHTTPDowngrade verifies an http:// redirect
// target is blocked even on the same host
func TestSecureHTTPClient_BlocksHTTPDowngrade(t *testing.T) {
	var plainURL string
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plainURL+"/downgraded", http.StatusFound)
	}))
	defer source.Close()
	// Same host as the TLS source server, but downgraded to plain HTTP
	plainURL = "http://" + strings.TrimPrefix(source.URL, "https://")

	client := newSecureHTTPClient(output.Config{Timeout: 5, Insecure: true, FollowRedirect: true, MaxRedirects: 5})
	resp, err := client.Get(source.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected HTTP downgrade redirect to be blocked")
	}
	if !strings.Contains(err.Error(), "blocked redirect to non-HTTPS protocol") {
		t.Errorf("expected downgrade-block error, got: %v", err)
	}
}

// TestSecureHTTPClient_FollowsSameHostHTTPS verifies same-host HTTPS
// redirects are still followed when enabled
func TestSecureHTTPClient_FollowsSameHostHTTPS(t *testing.T) {
	finalHit := false
	serverURL := authTLSTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/final" {
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		finalHit = true
		w.WriteHeader(http.StatusOK)
	}))

	client := newSecureHTTPClient(output.Config{Timeout: 5, Insecure: true, FollowRedirect: true, MaxRedirects: 5})
	resp, err := client.Get(serverURL)
	if err != nil {
		t.Fatalf("same-host HTTPS redirect should be followed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 after following redirect, got %d", resp.StatusCode)
	}
	if !finalHit {
		t.Error("redirect target should have been reached")
	}
}
