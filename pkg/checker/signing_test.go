package checker

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// Example credentials from the AWS S3 documentation pages for signing
// requests (published examples, not real credentials).
const (
	vectorAccessKey = "AKIAIOSFODNN7EXAMPLE"
	vectorSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// TestSignV2Query_AWSExampleVector verifies the SigV2 query-authentication
// signature against the example published in the AWS S3 documentation
// ("Signing and Authenticating REST Requests", query string authentication):
// a GET of /photos/puppy.jpg on the johnsmith example bucket with
// Expires=1175139620 signs to NpgCjnDzrM+WFzoENXmpNDUsSn8=.
func TestSignV2Query_AWSExampleVector(t *testing.T) {
	req, err := http.NewRequest("GET", "http://johnsmith.s3.amazonaws.com/photos/puppy.jpg", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	// createRequest sets a Date header; query auth must drop it
	req.Header.Set("Date", "Tue, 27 Mar 2007 19:36:42 +0000")

	signer := Signer{AccessKey: vectorAccessKey, SecretKey: vectorSecretKey, Region: "us-east-1"}
	resource := signer.BuildCanonicalResource(req, "johnsmith", false)
	if resource != "/johnsmith/photos/puppy.jpg" {
		t.Fatalf("BuildCanonicalResource = %q, want /johnsmith/photos/puppy.jpg", resource)
	}

	expires := time.Unix(1175139620, 0).UTC()
	if err := signer.SignV2Query(req, resource, expires); err != nil {
		t.Fatalf("SignV2Query failed: %v", err)
	}

	if got := req.Header.Get("Date"); got != "" {
		t.Errorf("Date header = %q, want omitted on query-authenticated requests", got)
	}
	q := req.URL.Query()
	if got := q.Get("AWSAccessKeyId"); got != vectorAccessKey {
		t.Errorf("AWSAccessKeyId = %q, want %q", got, vectorAccessKey)
	}
	if got := q.Get("Expires"); got != "1175139620" {
		t.Errorf("Expires = %q, want 1175139620", got)
	}
	if got := q.Get("Signature"); got != "NpgCjnDzrM+WFzoENXmpNDUsSn8=" {
		t.Errorf("Signature = %q, want NpgCjnDzrM+WFzoENXmpNDUsSn8= (AWS example vector)", got)
	}
}

// TestSignV2Query_StringToSignParts verifies that Content-MD5 and
// Content-Type headers flow into the string-to-sign on their designated
// lines. The string-to-sign shape matches the AWS header-authentication
// examples, which place Content-MD5 and Content-Type on lines two and three.
func TestSignV2Query_StringToSignParts(t *testing.T) {
	req, err := http.NewRequest("PUT", "http://s3.example.com/bucket/photo.jpg", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	req.Header.Set("Content-Type", "image/jpeg")
	req.Header.Set("Content-MD5", "qtBd2c0KgfIaW3Nscd0R9A==")

	signer := Signer{AccessKey: "test-key", SecretKey: "test-secret", Region: "us-east-1"}
	expires := time.Unix(1700000000, 0).UTC()
	if err := signer.SignV2Query(req, "/bucket/photo.jpg", expires); err != nil {
		t.Fatalf("SignV2Query failed: %v", err)
	}

	stringToSign := "PUT\nqtBd2c0KgfIaW3Nscd0R9A==\nimage/jpeg\n1700000000\n/bucket/photo.jpg"
	mac := hmac.New(sha1.New, []byte("test-secret"))
	mac.Write([]byte(stringToSign))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	if got := req.URL.Query().Get("Signature"); got != want {
		t.Errorf("Signature = %q, want %q (recomputed from string-to-sign %q)", got, want, stringToSign)
	}
}

// TestBuildCanonicalResource verifies the SigV2 canonicalized resource:
// bucket placement per addressing style, the trailing slash for
// virtual-hosted bucket roots, and inclusion of recognized sub-resources
// only, sorted, with values.
func TestBuildCanonicalResource(t *testing.T) {
	tests := []struct {
		name         string
		url          string
		bucket       string
		pathStyle    bool
		wantResource string
	}{
		{
			name:         "path-style object",
			url:          "http://s3.example.com/johnsmith/photos/puppy.jpg",
			bucket:       "johnsmith",
			pathStyle:    true,
			wantResource: "/johnsmith/photos/puppy.jpg",
		},
		{
			name:         "path-style bucket with acl",
			url:          "http://s3.example.com/test-bucket?acl",
			bucket:       "test-bucket",
			pathStyle:    true,
			wantResource: "/test-bucket?acl",
		},
		{
			name:         "path-style bucket without query",
			url:          "http://s3.example.com/test-bucket",
			bucket:       "test-bucket",
			pathStyle:    true,
			wantResource: "/test-bucket",
		},
		{
			name:         "virtual-hosted object",
			url:          "http://test-bucket.s3.example.com/photos/puppy.jpg",
			bucket:       "test-bucket",
			pathStyle:    false,
			wantResource: "/test-bucket/photos/puppy.jpg",
		},
		{
			name:         "virtual-hosted root with empty path",
			url:          "http://test-bucket.s3.example.com?policy",
			bucket:       "test-bucket",
			pathStyle:    false,
			wantResource: "/test-bucket/?policy",
		},
		{
			name:         "virtual-hosted root with slash path",
			url:          "http://test-bucket.s3.example.com/?policy",
			bucket:       "test-bucket",
			pathStyle:    false,
			wantResource: "/test-bucket/?policy",
		},
		{
			name:         "virtual-hosted root without query",
			url:          "http://test-bucket.s3.example.com",
			bucket:       "test-bucket",
			pathStyle:    false,
			wantResource: "/test-bucket/",
		},
		{
			name:         "sub-resource with value",
			url:          "http://s3.example.com/test-bucket?versionId=abc123",
			bucket:       "test-bucket",
			pathStyle:    true,
			wantResource: "/test-bucket?versionId=abc123",
		},
		{
			name:         "unrecognized query parameters excluded",
			url:          "http://s3.example.com/test-bucket?prefix=photos&max-keys=50&acl",
			bucket:       "test-bucket",
			pathStyle:    true,
			wantResource: "/test-bucket?acl",
		},
		{
			name:         "multiple sub-resources sorted",
			url:          "http://s3.example.com/test-bucket?tagging&acl",
			bucket:       "test-bucket",
			pathStyle:    true,
			wantResource: "/test-bucket?acl&tagging",
		},
		{
			name:         "response-header override included",
			url:          "http://s3.example.com/test-bucket?response-content-type=text%2Fplain&prefix=x",
			bucket:       "test-bucket",
			pathStyle:    true,
			wantResource: "/test-bucket?response-content-type=text/plain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tt.url, nil)
			if err != nil {
				t.Fatalf("NewRequest failed: %v", err)
			}
			signer := Signer{}
			got := signer.BuildCanonicalResource(req, tt.bucket, tt.pathStyle)
			if got != tt.wantResource {
				t.Errorf("BuildCanonicalResource = %q, want %q", got, tt.wantResource)
			}
		})
	}
}

// TestSigV4SigningKey re-derives the SigV4 signing key independently from
// the algorithm documented in "Creating a signing key" (AWS general
// reference): HMAC chain AWS4<secret> -> date -> region -> service ->
// aws4_request. Written inline so a reordered or mis-input stage in
// sigV4SigningKey fails this test.
func TestSigV4SigningKey(t *testing.T) {
	hm := func(key []byte, data string) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(data))
		return mac.Sum(nil)
	}

	tests := []struct {
		secret string
		date   string
		region string
	}{
		{vectorSecretKey, "20130524", "us-east-1"},
		{"another-secret", "20260102", "eu-central-1"},
	}

	for _, tt := range tests {
		kDate := hm([]byte("AWS4"+tt.secret), tt.date)
		kRegion := hm(kDate, tt.region)
		kService := hm(kRegion, "s3")
		want := hm(kService, "aws4_request")

		got := sigV4SigningKey(tt.secret, tt.date, tt.region)
		if !hmac.Equal(got, want) {
			t.Errorf("sigV4SigningKey(%q, %q, %q) = %x, want %x", tt.secret, tt.date, tt.region, got, want)
		}
	}
}

// TestSignV4_WireConsistency signs a request with a fixed clock, sends it
// to a test server, and re-derives the Authorization header server-side
// from the values that actually went on the wire (Host, path, query,
// x-amz-date). This proves the signature covers exactly what is sent.
func TestSignV4_WireConsistency(t *testing.T) {
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	var wire struct {
		method     string
		host       string
		path       string
		query      string
		auth       string
		date       string
		payloadSha string
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire.method = r.Method
		wire.host = r.Host
		wire.path = r.URL.Path
		wire.query = r.URL.RawQuery
		wire.auth = r.Header.Get("Authorization")
		wire.date = r.Header.Get("X-Amz-Date")
		wire.payloadSha = r.Header.Get("X-Amz-Content-Sha256")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	req, err := http.NewRequest("GET", server.URL+"/test-bucket/photos/puppy.jpg?acl", nil)
	if err != nil {
		t.Fatalf("NewRequest failed: %v", err)
	}
	signer := Signer{AccessKey: "test-key", SecretKey: "test-secret", Region: "us-east-1"}
	if err := signer.SignV4(req, fixed); err != nil {
		t.Fatalf("SignV4 failed: %v", err)
	}
	if _, err := http.DefaultClient.Do(req); err != nil {
		t.Fatalf("request failed: %v", err)
	}

	if wire.date != "20260102T030405Z" {
		t.Errorf("X-Amz-Date = %q, want 20260102T030405Z", wire.date)
	}
	if wire.payloadSha != "UNSIGNED-PAYLOAD" {
		t.Errorf("X-Amz-Content-Sha256 = %q, want UNSIGNED-PAYLOAD", wire.payloadSha)
	}
	if wire.query != "acl" {
		t.Fatalf("wire query = %q, want acl", wire.query)
	}

	// Independent re-derivation from wire values
	testSHA256Hex := func(s string) string {
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	hm := func(key []byte, data string) []byte {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(data))
		return mac.Sum(nil)
	}

	canonicalRequest := strings.Join([]string{
		wire.method,
		wire.path,
		"acl=",
		fmt.Sprintf("host:%s\nx-amz-content-sha256:UNSIGNED-PAYLOAD\nx-amz-date:%s\n", wire.host, wire.date),
		"host;x-amz-content-sha256;x-amz-date",
		"UNSIGNED-PAYLOAD",
	}, "\n")

	dateStamp := wire.date[:8]
	scope := dateStamp + "/us-east-1/s3/aws4_request"
	stringToSign := "AWS4-HMAC-SHA256\n" + wire.date + "\n" + scope + "\n" + testSHA256Hex(canonicalRequest)

	kDate := hm([]byte("AWS4test-secret"), dateStamp)
	kRegion := hm(kDate, "us-east-1")
	kService := hm(kRegion, "s3")
	kSigning := hm(kService, "aws4_request")
	signature := hex.EncodeToString(hm(kSigning, stringToSign))

	wantAuth := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=test-key/%s, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=%s",
		scope, signature)
	if wire.auth != wantAuth {
		t.Errorf("Authorization =\n  %s\nwant\n  %s", wire.auth, wantAuth)
	}
}

// TestAddSigV2Auth_WireSignature runs the full checker-level SigV2 path
// (createRequest + addSigV2Auth with an injected clock) against a test
// server and re-derives the signature from what the server received.
func TestAddSigV2Auth_WireSignature(t *testing.T) {
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	orig := timeNow
	timeNow = func() time.Time { return fixed }
	t.Cleanup(func() { timeNow = orig })

	var wire struct {
		method string
		query  url.Values
		date   string
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire.method = r.Method
		wire.query = r.URL.Query()
		wire.date = r.Header.Get("Date")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	checker := NewAuthChecker(authTestConfig(server.URL, func(c *output.Config) {
		c.AuthType = "sigv2"
	}))

	req, err := checker.createRequest()
	if err != nil {
		t.Fatalf("createRequest failed: %v", err)
	}
	if req.Header.Get("Date") == "" {
		t.Fatal("createRequest should set a Date header before signing")
	}
	if err := checker.addSigV2Auth(req); err != nil {
		t.Fatalf("addSigV2Auth failed: %v", err)
	}
	if got := req.Header.Get("Date"); got != "" {
		t.Errorf("Date header = %q after signing, want omitted on query-authenticated requests", got)
	}
	if _, err := http.DefaultClient.Do(req); err != nil {
		t.Fatalf("request failed: %v", err)
	}

	// Re-derive the signature from the wire: path-style HEAD /test-bucket
	expires := wire.query.Get("Expires")
	stringToSign := wire.method + "\n\n\n" + expires + "\n/test-bucket"
	mac := hmac.New(sha1.New, []byte("test-secret"))
	mac.Write([]byte(stringToSign))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	if got := wire.query.Get("Signature"); got != want {
		t.Errorf("wire Signature = %q, want %q (string-to-sign %q)", got, want, stringToSign)
	}
	if expires != fmt.Sprintf("%d", fixed.Add(15*time.Minute).Unix()) {
		t.Errorf("wire Expires = %q, want fixed clock + 15 minutes", expires)
	}
	if got := wire.query.Get("AWSAccessKeyId"); got != "test-key" {
		t.Errorf("wire AWSAccessKeyId = %q, want test-key", got)
	}
	if wire.date != "" {
		t.Errorf("wire Date header = %q, want empty (not sent)", wire.date)
	}
}
