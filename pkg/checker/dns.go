package checker

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// DNSChecker performs DNS resolution checks
type DNSChecker struct {
	BaseChecker
	Hostname string
	verbose  *VerboseLogger
}

// NewDNSChecker creates a new DNS checker
func NewDNSChecker(config output.Config, hostname string) *DNSChecker {
	return &DNSChecker{
		BaseChecker: NewBaseChecker(config),
		Hostname:    hostname,
		verbose:     NewVerboseLogger(config.Verbose),
	}
}

// Name returns the name of the checker
func (c *DNSChecker) Name() string {
	return "DNS Resolution Check"
}

// Check performs the DNS resolution check
func (c *DNSChecker) Check() output.TestResult {
	startTime := time.Now()

	c.verbose.LogSection("Starting DNS Resolution Check")

	// Handle IP addresses directly
	if c.isIPAddress(c.Hostname) {
		c.verbose.LogMessage("Hostname is an IP address: %s", c.Hostname)
		return c.handleIPCheck(startTime)
	}

	c.verbose.LogMessage("Resolving hostname: %s", c.Hostname)

	// Perform DNS lookup
	result := output.TestResult{
		TestName: c.Name(),
		Status:   output.StatusPass,
		Duration: time.Since(startTime),
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Config.Timeout)*time.Second)
	defer cancel()

	// Resolve hostname
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, c.Hostname)
	if err != nil {
		c.verbose.LogMessage("DNS resolution failed: %v", err)
		result.Status = output.StatusFail
		result.Error = err.Error()
		result.Duration = time.Since(startTime)
		return result
	}

	// Extract IP addresses
	ipStrings := make([]string, 0, len(ips))
	for _, ip := range ips {
		ipStrings = append(ipStrings, ip.IP.String())
	}

	c.verbose.LogMessage("DNS resolution successful")
	c.verbose.LogMessage("Resolved %d IP address(es):", len(ips))
	for i, ip := range ipStrings {
		c.verbose.LogMessage("  [%d] %s", i+1, ip)
	}

	// Perform reverse DNS lookup for first IP
	var reverseDNS string
	if len(ips) > 0 {
		names, err := net.LookupAddr(ips[0].IP.String())
		if err == nil && len(names) > 0 {
			reverseDNS = names[0]
			c.verbose.LogMessage("Reverse DNS for %s: %s", ips[0].IP.String(), reverseDNS)
		} else {
			c.verbose.LogMessage("Reverse DNS lookup failed for %s: %v", ips[0].IP.String(), err)
		}
	}

	// Create DNS result
	dnsResult := output.DNSResult{
		IPs:            ipStrings,
		ResolutionTime: time.Since(startTime).Milliseconds(),
		Hostname:       c.Hostname,
		ReverseDNS:     reverseDNS,
	}

	result.Details = dnsResult
	result.Duration = time.Since(startTime)

	c.verbose.LogMessage("DNS resolution completed in %dms", dnsResult.ResolutionTime)

	return result
}

// isIPAddress checks if the given string is an IP address
func (c *DNSChecker) isIPAddress(s string) bool {
	return net.ParseIP(s) != nil
}

// handleIPCheck handles the case when hostname is an IP address
func (c *DNSChecker) handleIPCheck(startTime time.Time) output.TestResult {
	c.verbose.LogMessage("No DNS resolution needed - hostname is already an IP address")

	result := output.TestResult{
		TestName: c.Name(),
		Status:   output.StatusPass,
		Duration: time.Since(startTime),
	}

	ip := net.ParseIP(c.Hostname)
	if ip == nil {
		c.verbose.LogMessage("Invalid IP address: %s", c.Hostname)
		result.Status = output.StatusFail
		result.Error = fmt.Sprintf("invalid IP address: %s", c.Hostname)
		result.Duration = time.Since(startTime)
		return result
	}

	c.verbose.LogMessage("Using IP address directly: %s", c.Hostname)

	// Perform reverse DNS lookup
	names, err := net.LookupAddr(c.Hostname)
	var reverseDNS string
	if err == nil && len(names) > 0 {
		reverseDNS = names[0]
		c.verbose.LogMessage("Reverse DNS for %s: %s", c.Hostname, reverseDNS)
	} else {
		c.verbose.LogMessage("Reverse DNS lookup failed for %s: %v", c.Hostname, err)
	}

	// Create DNS result
	dnsResult := output.DNSResult{
		IPs:            []string{c.Hostname},
		ResolutionTime: time.Since(startTime).Milliseconds(),
		Hostname:       c.Hostname,
		ReverseDNS:     reverseDNS,
	}

	result.Details = dnsResult
	result.Duration = time.Since(startTime)

	c.verbose.LogMessage("DNS check completed in %dms", dnsResult.ResolutionTime)

	return result
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

	// Remove path
	if idx := strings.Index(endpoint, "/"); idx != -1 {
		endpoint = endpoint[:idx]
	}

	// Check if it's an IP address
	if net.ParseIP(endpoint) != nil {
		return 443 // Default to HTTPS for IPs
	}

	return 443 // Default to HTTPS
}
