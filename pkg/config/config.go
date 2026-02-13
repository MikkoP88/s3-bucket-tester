package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// Config holds the application configuration
type Config struct {
	Endpoint       string
	Bucket         string
	Region         string
	AccessKey      string
	SecretKey      string
	AuthType       string
	Port           int
	Insecure       bool
	Timeout        int
	OutputFormat   string
	OutputFile     string
	FollowRedirect bool
	MaxRedirects   int
	Verbose        bool
	Warning        string

	// New fields
	Provider      string
	VirtualHosted bool
	PathStyle     bool
}

// ProviderEndpoint defines endpoint templates for built-in providers
type ProviderEndpoint struct {
	Template    string
	Description string
}

// Built-in providers
var Providers = map[string]ProviderEndpoint{
	"aws": {
		Template:    "<bucket>.s3.<region>.amazonaws.com",
		Description: "AWS S3 (virtual-hosted, default)",
	},
	"aws-legacy": {
		Template:    "s3.<region>.amazonaws.com/<bucket>",
		Description: "AWS S3 (path-style, legacy)",
	},
	"wasabi": {
		Template:    "<bucket>.s3.<region>.wasabisys.com",
		Description: "Wasabi (virtual-hosted)",
	},
	"wasabi-legacy": {
		Template:    "s3.<region>.wasabisys.com/<bucket>",
		Description: "Wasabi (path-style, legacy)",
	},
	"b2": {
		Template:    "<bucket>.s3.<region>.backblazeb2.com",
		Description: "Backblaze B2 (virtual-hosted)",
	},
	"b2-legacy": {
		Template:    "s3.<region>.backblazeb2.com/<bucket>",
		Description: "Backblaze B2 (path-style, legacy)",
	},
	"ibm": {
		Template:    "<bucket>.<region>.objectstorage.cloud.ibm.com",
		Description: "IBM Cloud Object Storage (virtual-hosted)",
	},
	"do": {
		Template:    "<bucket>.<region>.digitaloceanspaces.com",
		Description: "DigitalOcean Spaces (virtual-hosted)",
	},
}

// GetDefaultConfig returns the default configuration
func GetDefaultConfig() *Config {
	return &Config{
		Endpoint:       "",
		Bucket:         "",
		Region:         "us-east-1",
		AccessKey:      "",
		SecretKey:      "",
		AuthType:       "sigv4",
		Port:           0,
		Insecure:       false,
		Timeout:        30,
		OutputFormat:   "",
		OutputFile:     "",
		FollowRedirect: true,
		MaxRedirects:   10,
		Verbose:        false,

		// New fields
		Provider:      "",
		VirtualHosted: false,
		PathStyle:     false,
	}
}

// Validate validates the configuration
func (c *Config) Validate() error {
	// Check required fields
	if c.Endpoint == "" && c.Provider == "" {
		return fmt.Errorf("endpoint or provider is required")
	}
	if c.Bucket == "" {
		return fmt.Errorf("bucket is required")
	}
	if c.AccessKey == "" {
		return fmt.Errorf("access-key is required")
	}
	if c.SecretKey == "" {
		return fmt.Errorf("secret-key is required")
	}

	// Resolve provider to endpoint if needed
	if c.Endpoint == "" && c.Provider != "" {
		if err := c.ResolveProviderEndpoint(); err != nil {
			return err
		}
	}

	// Add protocol if not present (for custom endpoints)
	if c.Endpoint != "" && !strings.HasPrefix(c.Endpoint, "http://") && !strings.HasPrefix(c.Endpoint, "https://") {
		if c.Insecure {
			c.Endpoint = "http://" + c.Endpoint
		} else {
			c.Endpoint = "https://" + c.Endpoint
		}
	}

	// Validate endpoint URL
	if _, err := url.Parse(c.Endpoint); err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	}

	// Validate auth type
	authType := strings.ToLower(c.AuthType)
	if authType != "sigv4" && authType != "sigv2" {
		return fmt.Errorf("invalid auth-type: must be 'sigv4' or 'sigv2'")
	}

	// Validate port
	if c.Port < 0 || c.Port > 65535 {
		return fmt.Errorf("invalid port: must be between 0 and 65535 (0 = auto-detect)")
	}

	// Validate timeout
	if c.Timeout < 1 {
		return fmt.Errorf("invalid timeout: must be greater than 0")
	}

	// Validate max redirects
	if c.MaxRedirects < 0 {
		return fmt.Errorf("invalid max-redirects: must be 0 or greater")
	}

	// Validate addressing style
	if c.PathStyle {
		// Check if endpoint uses a known virtual-hosted provider
		for _, provider := range []string{"aws", "wasabi", "b2", "ibm", "do", "your-objectstorage.com"} {
			if strings.Contains(c.Endpoint, provider) || strings.Contains(c.Endpoint, "cloudhubone.com") {
				c.Warning = "Warning: --path-style addressing may not be supported by this provider. Try removing --path-style flag."
			}
		}
	}

	return nil
}

// ResolveProviderEndpoint resolves the endpoint from provider template
func (c *Config) ResolveProviderEndpoint() error {
	provider, ok := Providers[c.Provider]
	if !ok {
		return fmt.Errorf("unknown provider: %s", c.Provider)
	}

	// Replace placeholders in template
	endpoint := provider.Template
	endpoint = strings.ReplaceAll(endpoint, "<bucket>", c.Bucket)
	endpoint = strings.ReplaceAll(endpoint, "<region>", c.Region)

	// Add protocol if not present
	if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
		if c.Insecure {
			endpoint = "http://" + endpoint
		} else {
			endpoint = "https://" + endpoint
		}
	}

	// Apply addressing style
	c.Endpoint = c.applyAddressingStyle(endpoint)
	return nil
}

// applyAddressingStyle applies virtual-hosted or path-style addressing
func (c *Config) applyAddressingStyle(endpoint string) string {
	// If endpoint is already a full URL, parse it
	if strings.Contains(endpoint, "://") {
		parts := strings.Split(endpoint, "://")
		if len(parts) == 2 {
			protocol := parts[0]
			hostPath := parts[1]

			// Check if it's path-style (bucket in path)
			if c.PathStyle {
				// Already path-style or needs conversion
				if !strings.HasPrefix(hostPath, c.Bucket+"/") {
					// Convert to path-style
					hostPath = c.Bucket + "/" + hostPath
				}
			} else {
				// Virtual-hosted (default)
				// Ensure bucket is in host
				if !strings.HasPrefix(hostPath, c.Bucket+".") {
					hostPath = c.Bucket + "." + hostPath
				}
			}

			return protocol + "://" + hostPath
		}
	}

	// Remove protocol prefix
	endpoint = strings.TrimPrefix(endpoint, "http://")
	endpoint = strings.TrimPrefix(endpoint, "https://")

	// Remove path
	if idx := strings.Index(endpoint, "/"); idx != -1 {
		endpoint = endpoint[:idx]
	}

	return endpoint
}

// ParseHostname extracts hostname from endpoint URL
func ParseHostname(endpoint string) string {
	// Remove protocol prefix
	endpoint = strings.TrimPrefix(endpoint, "http://")
	endpoint = strings.TrimPrefix(endpoint, "https://")

	// Remove port
	if idx := strings.Index(endpoint, ":"); idx != -1 {
		endpoint = endpoint[:idx]
	}

	// Remove path
	if idx := strings.Index(endpoint, "/"); idx != -1 {
		endpoint = endpoint[:idx]
	}

	return endpoint
}

// ParsePort extracts port from endpoint URL
func ParsePort(endpoint string) int {
	// Remove protocol prefix first
	originalEndpoint := endpoint
	endpoint = strings.TrimPrefix(endpoint, "http://")
	endpoint = strings.TrimPrefix(endpoint, "https://")

	// Extract port from URL
	if idx := strings.Index(endpoint, ":"); idx != -1 {
		portStr := endpoint[idx+1:]
		// Remove path
		if idx2 := strings.Index(portStr, "/"); idx2 != -1 {
			portStr = portStr[:idx2]
		}
		var port int
		fmt.Sscanf(portStr, "%d", &port)
		if port > 0 && port <= 65535 {
			return port
		}
	}

	// Default ports based on protocol
	if strings.HasPrefix(originalEndpoint, "https://") {
		return 443
	}
	if strings.HasPrefix(originalEndpoint, "http://") {
		return 80
	}

	// Check if it's an IP address
	if net.ParseIP(endpoint) != nil {
		return 443 // Default to HTTPS for IPs
	}

	return 443 // Default to HTTPS
}

// ToOutputConfig converts config to output config
func (c *Config) ToOutputConfig() output.Config {
	return output.Config{
		Endpoint:       c.Endpoint,
		Bucket:         c.Bucket,
		Region:         c.Region,
		AccessKey:      c.AccessKey,
		SecretKey:      c.SecretKey,
		AuthType:       c.AuthType,
		Port:           c.Port,
		Insecure:       c.Insecure,
		Timeout:        c.Timeout,
		OutputFormat:   c.OutputFormat,
		OutputFile:     c.OutputFile,
		FollowRedirect: c.FollowRedirect,
		MaxRedirects:   c.MaxRedirects,
		Verbose:        c.Verbose,
		PathStyle:      c.PathStyle,
	}
}
