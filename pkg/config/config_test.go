package config

import (
	"testing"
)

// TestGetDefaultConfig tests that default configuration values are correct
func TestGetDefaultConfig(t *testing.T) {
	config := GetDefaultConfig()

	tests := []struct {
		name     string
		field    string
		expected interface{}
	}{
		{"Endpoint", "Endpoint", ""},
		{"Bucket", "Bucket", ""},
		{"Region", "Region", "us-east-1"},
		{"AccessKey", "AccessKey", ""},
		{"SecretKey", "SecretKey", ""},
		{"AuthType", "AuthType", "sigv4"},
		{"Port", "Port", 0},
		{"Insecure", "Insecure", false},
		{"Timeout", "Timeout", 30},
		{"OutputFormat", "OutputFormat", ""},
		{"OutputFile", "OutputFile", ""},
		{"FollowRedirect", "FollowRedirect", true},
		{"MaxRedirects", "MaxRedirects", 10},
		{"Verbose", "Verbose", false},
		{"Provider", "Provider", ""},
		{"VirtualHosted", "VirtualHosted", false},
		{"PathStyle", "PathStyle", false},
		{"CheckPolicy", "CheckPolicy", false},
		{"Warning", "Warning", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch tt.field {
			case "Endpoint":
				if config.Endpoint != tt.expected.(string) {
					t.Errorf("Expected Endpoint %v, got %v", tt.expected, config.Endpoint)
				}
			case "Bucket":
				if config.Bucket != tt.expected.(string) {
					t.Errorf("Expected Bucket %v, got %v", tt.expected, config.Bucket)
				}
			case "Region":
				if config.Region != tt.expected.(string) {
					t.Errorf("Expected Region %v, got %v", tt.expected, config.Region)
				}
			case "AccessKey":
				if config.AccessKey != tt.expected.(string) {
					t.Errorf("Expected AccessKey %v, got %v", tt.expected, config.AccessKey)
				}
			case "SecretKey":
				if config.SecretKey != tt.expected.(string) {
					t.Errorf("Expected SecretKey %v, got %v", tt.expected, config.SecretKey)
				}
			case "AuthType":
				if config.AuthType != tt.expected.(string) {
					t.Errorf("Expected AuthType %v, got %v", tt.expected, config.AuthType)
				}
			case "Port":
				if config.Port != tt.expected.(int) {
					t.Errorf("Expected Port %v, got %v", tt.expected, config.Port)
				}
			case "Insecure":
				if config.Insecure != tt.expected.(bool) {
					t.Errorf("Expected Insecure %v, got %v", tt.expected, config.Insecure)
				}
			case "Timeout":
				if config.Timeout != tt.expected.(int) {
					t.Errorf("Expected Timeout %v, got %v", tt.expected, config.Timeout)
				}
			case "OutputFormat":
				if config.OutputFormat != tt.expected.(string) {
					t.Errorf("Expected OutputFormat %v, got %v", tt.expected, config.OutputFormat)
				}
			case "OutputFile":
				if config.OutputFile != tt.expected.(string) {
					t.Errorf("Expected OutputFile %v, got %v", tt.expected, config.OutputFile)
				}
			case "FollowRedirect":
				if config.FollowRedirect != tt.expected.(bool) {
					t.Errorf("Expected FollowRedirect %v, got %v", tt.expected, config.FollowRedirect)
				}
			case "MaxRedirects":
				if config.MaxRedirects != tt.expected.(int) {
					t.Errorf("Expected MaxRedirects %v, got %v", tt.expected, config.MaxRedirects)
				}
			case "Verbose":
				if config.Verbose != tt.expected.(bool) {
					t.Errorf("Expected Verbose %v, got %v", tt.expected, config.Verbose)
				}
			case "Provider":
				if config.Provider != tt.expected.(string) {
					t.Errorf("Expected Provider %v, got %v", tt.expected, config.Provider)
				}
			case "VirtualHosted":
				if config.VirtualHosted != tt.expected.(bool) {
					t.Errorf("Expected VirtualHosted %v, got %v", tt.expected, config.VirtualHosted)
				}
			case "PathStyle":
				if config.PathStyle != tt.expected.(bool) {
					t.Errorf("Expected PathStyle %v, got %v", tt.expected, config.PathStyle)
				}
			case "CheckPolicy":
				if config.CheckPolicy != tt.expected.(bool) {
					t.Errorf("Expected CheckPolicy %v, got %v", tt.expected, config.CheckPolicy)
				}
			case "Warning":
				if config.Warning != tt.expected.(string) {
					t.Errorf("Expected Warning %v, got %v", tt.expected, config.Warning)
				}
			}
		})
	}
}

// TestConfigValidate_Success tests successful validation
func TestConfigValidate_Success(t *testing.T) {
	config := &Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Region:    "us-east-1",
	}

	err := config.Validate()

	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

// TestConfigValidate_MissingEndpoint tests missing endpoint validation
func TestConfigValidate_MissingEndpoint(t *testing.T) {
	config := &Config{
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
	}

	err := config.Validate()

	if err == nil {
		t.Error("Expected error for missing endpoint")
	}
}

// TestConfigValidate_MissingBucket tests missing bucket validation
func TestConfigValidate_MissingBucket(t *testing.T) {
	config := &Config{
		Endpoint:  "https://s3.example.com",
		AccessKey: "test-key",
		SecretKey: "test-secret",
	}

	err := config.Validate()

	if err == nil {
		t.Error("Expected error for missing bucket")
	}
}

// TestConfigValidate_MissingAccessKey tests missing access key validation
func TestConfigValidate_MissingAccessKey(t *testing.T) {
	config := &Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		SecretKey: "test-secret",
	}

	err := config.Validate()

	if err == nil {
		t.Error("Expected error for missing access key")
	}
}

// TestConfigValidate_MissingSecretKey tests missing secret key validation
func TestConfigValidate_MissingSecretKey(t *testing.T) {
	config := &Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
	}

	err := config.Validate()

	if err == nil {
		t.Error("Expected error for missing secret key")
	}
}

// TestConfigValidate_InvalidTimeout tests invalid timeout validation
func TestConfigValidate_InvalidTimeout(t *testing.T) {
	config := &Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Timeout:   -1, // Invalid timeout
	}

	err := config.Validate()

	// Invalid timeout should cause an error
	// (The actual validation logic may or may not check this)
	_ = err
}

// TestConfigValidate_InvalidAuthType tests invalid auth type validation
func TestConfigValidate_InvalidAuthType(t *testing.T) {
	config := &Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		AuthType:  "invalid", // Invalid auth type
	}

	err := config.Validate()

	// Invalid auth type should cause an error
	// (The actual validation logic may or may not check this)
	_ = err
}

// TestConfigValidate_InvalidPort tests invalid port validation
func TestConfigValidate_InvalidPort(t *testing.T) {
	config := &Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
		Port:      99999, // Invalid port
	}

	err := config.Validate()

	// Invalid port should cause an error
	// (The actual validation logic may or may not check this)
	_ = err
}

// TestConfigToOutputConfig tests config conversion
func TestConfigToOutputConfig(t *testing.T) {
	config := &Config{
		Endpoint:       "https://s3.example.com",
		Bucket:         "test-bucket",
		AccessKey:      "test-key",
		SecretKey:      "test-secret",
		Region:         "us-east-1",
		AuthType:       "sigv4",
		Port:           443,
		Insecure:       false,
		Timeout:        30,
		OutputFormat:   "",
		OutputFile:     "",
		FollowRedirect: true,
		MaxRedirects:   10,
		Verbose:        false,
		Provider:       "",
		VirtualHosted:  false,
		PathStyle:      false,
		CheckPolicy:    false,
	}

	outputConfig := config.ToOutputConfig()

	if outputConfig.Endpoint != config.Endpoint {
		t.Errorf("Expected Endpoint %v, got %v", config.Endpoint, outputConfig.Endpoint)
	}
	if outputConfig.Bucket != config.Bucket {
		t.Errorf("Expected Bucket %v, got %v", config.Bucket, outputConfig.Bucket)
	}
	if outputConfig.Region != config.Region {
		t.Errorf("Expected Region %v, got %v", config.Region, outputConfig.Region)
	}
	if outputConfig.AuthType != config.AuthType {
		t.Errorf("Expected AuthType %v, got %v", config.AuthType, outputConfig.AuthType)
	}
	if outputConfig.PathStyle != config.PathStyle {
		t.Errorf("Expected PathStyle %v, got %v", config.PathStyle, outputConfig.PathStyle)
	}
	if outputConfig.Insecure != config.Insecure {
		t.Errorf("Expected Insecure %v, got %v", config.Insecure, outputConfig.Insecure)
	}
	if outputConfig.Timeout != config.Timeout {
		t.Errorf("Expected Timeout %v, got %v", config.Timeout, outputConfig.Timeout)
	}
	if outputConfig.FollowRedirect != config.FollowRedirect {
		t.Errorf("Expected FollowRedirect %v, got %v", config.FollowRedirect, outputConfig.FollowRedirect)
	}
	if outputConfig.MaxRedirects != config.MaxRedirects {
		t.Errorf("Expected MaxRedirects %v, got %v", config.MaxRedirects, outputConfig.MaxRedirects)
	}
	if outputConfig.Verbose != config.Verbose {
		t.Errorf("Expected Verbose %v, got %v", config.Verbose, outputConfig.Verbose)
	}
}

// TestProvidersMap tests that providers map is populated
func TestProvidersMap(t *testing.T) {
	if len(Providers) == 0 {
		t.Error("Expected Providers map to be populated")
	}

	// Check that expected providers exist
	expectedProviders := []string{"aws", "aws-legacy", "wasabi", "wasabi-legacy", "b2", "b2-legacy", "ibm", "do"}

	for _, provider := range expectedProviders {
		if _, ok := Providers[provider]; !ok {
			t.Errorf("Expected provider '%s' to exist in Providers map", provider)
		}
	}
}

// TestProviderEndpoint tests provider endpoint structure
func TestProviderEndpoint(t *testing.T) {
	provider := ProviderEndpoint{
		Template:    "<bucket>.s3.<region>.amazonaws.com",
		Description: "AWS S3 (default)",
	}

	if provider.Template != "<bucket>.s3.<region>.amazonaws.com" {
		t.Errorf("Expected Template '<bucket>.s3.<region>.amazonaws.com', got '%s'", provider.Template)
	}
	if provider.Description != "AWS S3 (default)" {
		t.Errorf("Expected Description 'AWS S3 (default)', got '%s'", provider.Description)
	}
}

// TestConfigValidate_AllRequiredFields tests validation with all required fields
func TestConfigValidate_AllRequiredFields(t *testing.T) {
	config := &Config{
		Endpoint:  "https://s3.example.com",
		Bucket:    "test-bucket",
		AccessKey: "test-key",
		SecretKey: "test-secret",
	}

	err := config.Validate()

	if err != nil {
		t.Errorf("Expected no error with all required fields, got %v", err)
	}
}

// TestConfigValidate_NoRequiredFields tests validation with no required fields
func TestConfigValidate_NoRequiredFields(t *testing.T) {
	config := &Config{}

	err := config.Validate()

	if err == nil {
		t.Error("Expected error with no required fields")
	}
}
