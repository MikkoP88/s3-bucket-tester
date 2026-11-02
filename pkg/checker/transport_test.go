package checker

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

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
