package config

import (
	"os"
	"testing"

	"github.com/s3-bucket-tester/s3tester/pkg/checker"
)

// TestParseFlags_Basic tests basic flag parsing
func TestParseFlags_Basic(t *testing.T) {
	// Save original os.Args
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	args := []string{
		"--endpoint", "https://s3.example.com",
		"--bucket", "test-bucket",
		"--access-key", "test-key",
		"--secret-key", "test-secret",
	}

	config, err := ParseFlags(args)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if config.Endpoint != "https://s3.example.com" {
		t.Errorf("Expected Endpoint 'https://s3.example.com', got '%s'", config.Endpoint)
	}
	if config.Bucket != "test-bucket" {
		t.Errorf("Expected Bucket 'test-bucket', got '%s'", config.Bucket)
	}
	if config.AccessKey != "test-key" {
		t.Errorf("Expected AccessKey 'test-key', got '%s'", config.AccessKey)
	}
	if config.SecretKey != "test-secret" {
		t.Errorf("Expected SecretKey 'test-secret', got '%s'", config.SecretKey)
	}
}

// TestParseFlags_Provider tests provider flag
func TestParseFlags_Provider(t *testing.T) {
	// Save original os.Args
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	args := []string{
		"--endpoint", "aws",
		"--bucket", "test-bucket",
		"--access-key", "test-key",
		"--secret-key", "test-secret",
		"--region", "us-east-1",
	}

	config, err := ParseFlags(args)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if config.Provider != "aws" {
		t.Errorf("Expected Provider 'aws', got '%s'", config.Provider)
	}
}

// TestParseFlags_PathStyle tests path-style flag
func TestParseFlags_PathStyle(t *testing.T) {
	// Save original os.Args
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	args := []string{
		"--endpoint", "https://s3.example.com",
		"--bucket", "test-bucket",
		"--access-key", "test-key",
		"--secret-key", "test-secret",
		"--path-style",
	}

	config, err := ParseFlags(args)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if !config.PathStyle {
		t.Error("Expected PathStyle to be true")
	}
}

// TestParseFlags_VirtualHosted tests virtual-hosted flag
func TestParseFlags_VirtualHosted(t *testing.T) {
	// Save original os.Args
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	args := []string{
		"--endpoint", "https://s3.example.com",
		"--bucket", "test-bucket",
		"--access-key", "test-key",
		"--secret-key", "test-secret",
		"--virtual-hosted",
	}

	config, err := ParseFlags(args)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if !config.VirtualHosted {
		t.Error("Expected VirtualHosted to be true")
	}
}

// TestParseFlags_CheckPolicy tests check-policy flag
func TestParseFlags_CheckPolicy(t *testing.T) {
	// Save original os.Args
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	args := []string{
		"--endpoint", "https://s3.example.com",
		"--bucket", "test-bucket",
		"--access-key", "test-key",
		"--secret-key", "test-secret",
		"--check-policy",
	}

	config, err := ParseFlags(args)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if !config.CheckPolicy {
		t.Error("Expected CheckPolicy to be true")
	}
}

// TestParseFlags_MissingValue tests missing flag values
func TestParseFlags_MissingValue(t *testing.T) {
	// Save original os.Args
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	tests := []struct {
		name  string
		args  []string
	}{
		{"Missing endpoint value", []string{"--endpoint"}},
		{"Missing bucket value", []string{"--bucket"}},
		{"Missing access-key value", []string{"--access-key"}},
		{"Missing secret-key value", []string{"--secret-key"}},
		{"Missing region value", []string{"--region"}},
		{"Missing auth-type value", []string{"--auth-type"}},
		{"Missing timeout value", []string{"--timeout"}},
		{"Missing output-file value", []string{"--output-file"}},
		{"Missing max-redirects value", []string{"--max-redirects"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseFlags(tt.args)

			if err == nil {
				t.Errorf("Expected error for %s", tt.name)
			}
		})
	}

// TestParseFlags_Insecure tests insecure flag
func TestParseFlags_Insecure(t *testing.T) {
	// Save original os.Args
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	args := []string{
		"--endpoint", "https://s3.example.com",
		"--bucket", "test-bucket",
		"--access-key", "test-key",
		"--secret-key", "test-secret",
		"--insecure",
	}

	config, err := ParseFlags(args)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if !config.Insecure {
		t.Error("Expected Insecure to be true")
	}
}

// TestParseFlags_Verbose tests verbose flag
func TestParseFlags_Verbose(t *testing.T) {
	// Save original os.Args
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	args := []string{
		"--endpoint", "https://s3.example.com",
		"--bucket", "test-bucket",
		"--access-key", "test-key",
		"--secret-key", "test-secret",
		"--verbose",
	}

	config, err := ParseFlags(args)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if !config.Verbose {
		t.Error("Expected Verbose to be true")
	}
}

// TestParseFlags_DefaultValues tests that default values are applied
func TestParseFlags_DefaultValues(t *testing.T) {
	// Save original os.Args
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	args := []string{
		"--endpoint", "https://s3.example.com",
		"--bucket", "test-bucket",
		"--access-key", "test-key",
		"--secret-key", "test-secret",
	}

	config, err := ParseFlags(args)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Check default values
	if config.Region != "us-east-1" {
		t.Errorf("Expected default Region 'us-east-1', got '%s'", config.Region)
	}
	if config.AuthType != "sigv4" {
		t.Errorf("Expected default AuthType 'sigv4', got '%s'", config.AuthType)
	}
	if config.Timeout != 30 {
		t.Errorf("Expected default Timeout 30, got %d", config.Timeout)
	}
	if config.FollowRedirect != true {
		t.Error("Expected default FollowRedirect to be true")
	}
	if config.MaxRedirects != 10 {
		t.Error("Expected default MaxRedirects 10, got %d", config.MaxRedirects)
	}
	if config.Verbose != false {
		t.Error("Expected default Verbose to be false")
	}
}

// TestParseFlags_AllProviders tests all built-in providers
func TestParseFlags_AllProviders(t *testing.T) {
	providers := []string{"aws", "aws-legacy", "wasabi", "wasabi-legacy", "b2", "b2-legacy", "ibm", "do"}

	for _, provider := range providers {
		// Save original os.Args
		oldArgs := os.Args
		defer func() {
			os.Args = oldArgs
		}()

		args := []string{
			"--endpoint", provider,
			"--bucket", "test-bucket",
			"--access-key", "test-key",
			"--secret-key", "test-secret",
		}

		config, err := ParseFlags(args)

		if err != nil {
			t.Errorf("Expected no error for provider '%s', got %v", provider, err)
		}

		if config.Provider != provider {
			t.Errorf("Expected Provider '%s', got '%s'", provider, config.Provider)
		}
	}
}

// TestParseFlags_NoRedirects tests no-redirects flag
func TestParseFlags_NoRedirects(t *testing.T) {
	// Save original os.Args
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	args := []string{
		"--endpoint", "https://s3.example.com",
		"--bucket", "test-bucket",
		"--access-key", "test-key",
		"--secret-key", "test-secret",
		"--no-redirects",
	}

	config, err := ParseFlags(args)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if config.FollowRedirect {
		t.Error("Expected FollowRedirect to be false")
	}
}

// TestParseFlags_FollowRedirects tests follow-redirects flag
func TestParseFlags_FollowRedirects(t *testing.T) {
	// Save original os.Args
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	args := []string{
		"--endpoint", "https://s3.example.com",
		"--bucket", "test-bucket",
		"--access-key", "test-key",
		"--secret-key", "test-secret",
		"--follow-redirects",
	}

	config, err := ParseFlags(args)

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if !config.FollowRedirect {
		t.Error("Expected FollowRedirect to be true")
	}
}

// TestParseFlags_EmptyArgs tests empty arguments
func TestParseFlags_EmptyArgs(t *testing.T) {
	// Save original os.Args
	oldArgs := os.Args
	defer func() {
		os.Args = oldArgs
	}()

	args := []string{}

	config, err := ParseFlags(args)

	// Empty args should return default config
	if err != nil {
		t.Errorf("Expected no error for empty args, got %v", err)
	}

	if config.Endpoint != "" {
		t.Errorf("Expected empty Endpoint, got '%s'", config.Endpoint)
	}
}
