package checker

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

// captureStdout runs fn with os.Stdout redirected to a pipe and returns
// everything it printed
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("failed to close pipe writer: %v", err)
	}
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("failed to read captured output: %v", err)
	}
	return string(data)
}

// TestRedactAuthorization_SigV4 verifies the SigV4 Authorization header keeps
// only the algorithm, a masked access key, and the signed headers list
func TestRedactAuthorization_SigV4(t *testing.T) {
	value := "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261102/us-east-1/s3/aws4_request, SignedHeaders=host;x-amz-date, Signature=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	got := redactAuthorization(value)

	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE/20261102") {
		t.Errorf("credential scope leaked: %s", got)
	}
	if strings.Contains(got, "deadbeef") {
		t.Errorf("signature leaked: %s", got)
	}
	if !strings.Contains(got, "Credential=AKIA…") {
		t.Errorf("masked access key missing: %s", got)
	}
	if !strings.Contains(got, "SignedHeaders=host;x-amz-date") {
		t.Errorf("signed headers list should be preserved: %s", got)
	}
}

// TestRedactAuthorization_NonSigV4 verifies unknown or SigV2-style schemes
// are redacted entirely
func TestRedactAuthorization_NonSigV4(t *testing.T) {
	for _, value := range []string{
		"AWS AKIAIOSFODNN7EXAMPLE:frJOtQkQOvXhYQBUHcV5rQ==",
		"Bearer sometoken",
		"",
	} {
		if got := redactAuthorization(value); got != "[REDACTED]" && got != "" {
			t.Errorf("redactAuthorization(%q) = %q, want [REDACTED]", value, got)
		}
	}
}

// TestRedactURLString_SigV2Params verifies SigV2 query authentication is masked
func TestRedactURLString_SigV2Params(t *testing.T) {
	raw := "http://s3.example.com/bucket?policy&AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Signature=abc123def456&Expires=1762000000"

	got := redactURLString(raw)

	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("access key leaked in URL: %s", got)
	}
	if strings.Contains(got, "abc123def456") {
		t.Errorf("signature leaked in URL: %s", got)
	}

	// Values are re-encoded by url.Values.Encode (ellipsis as %E2%80%A6,
	// brackets as %5B/%5D), so assert on the parsed query values
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("redacted URL does not parse: %v", err)
	}
	q := u.Query()
	if key := q.Get("AWSAccessKeyId"); key != "AKIA…" {
		t.Errorf("AWSAccessKeyId = %q, want masked AKIA…", key)
	}
	if sig := q.Get("Signature"); sig != "[REDACTED]" {
		t.Errorf("Signature = %q, want [REDACTED]", sig)
	}
	if _, has := q["policy"]; !has {
		t.Errorf("non-auth query parameter dropped: %s", got)
	}
}

// TestRedactURLString_SigV4PresignedParams verifies pre-signed URL params are masked
func TestRedactURLString_SigV4PresignedParams(t *testing.T) {
	raw := "https://s3.example.com/bucket/file.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE/20261102/us-east-1/s3/aws4_request&X-Amz-Signature=fedcba9876543210"

	got := redactURLString(raw)

	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("access key leaked in URL: %s", got)
	}
	if strings.Contains(got, "fedcba9876543210") {
		t.Errorf("signature leaked in URL: %s", got)
	}
}

// TestRedactURLString_NoAuthParams verifies URLs without authentication
// material pass through untouched
func TestRedactURLString_NoAuthParams(t *testing.T) {
	raw := "https://s3.example.com/bucket?policy&acl"
	if got := redactURLString(raw); got != raw {
		t.Errorf("URL without auth params was modified: %s", got)
	}
}

// TestLogRequest_RedactsAuthMaterial verifies the wired logger emits no
// Authorization or SigV2 query material
func TestLogRequest_RedactsAuthMaterial(t *testing.T) {
	req, err := http.NewRequest("GET", "http://s3.example.com/bucket?policy&AWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Signature=abc123def456&Expires=1762000000", nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261102/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=deadbeefdeadbeef")

	logger := NewVerboseLogger(true)
	out := captureStdout(t, func() { logger.LogRequest(req) })

	if strings.Contains(out, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("full access key leaked in verbose log:\n%s", out)
	}
	if strings.Contains(out, "abc123def456") || strings.Contains(out, "deadbeef") {
		t.Errorf("signature leaked in verbose log:\n%s", out)
	}
	if !strings.Contains(out, "Credential=AKIA…") {
		t.Errorf("masked credential missing in verbose log:\n%s", out)
	}
}
