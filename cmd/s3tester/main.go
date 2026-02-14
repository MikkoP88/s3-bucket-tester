package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/s3-bucket-tester/s3tester/pkg/checker"
	"github.com/s3-bucket-tester/s3tester/pkg/config"
	"github.com/s3-bucket-tester/s3tester/pkg/output"
	"github.com/s3-bucket-tester/s3tester/pkg/remediation"
)

const (
	ExitCodeSuccess = 0
	ExitCodeFailed  = 1
	ExitCodeConfig  = 2
	ExitCodeError   = 3
)

func main() {
	// Parse command-line flags
	cfg, err := config.ParseFlags(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(ExitCodeConfig)
	}

	// Validate configuration
	fmt.Fprintf(os.Stderr, "DEBUG: Before validation, Endpoint=%s, PathStyle=%v\n", cfg.Endpoint, cfg.PathStyle)
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "Configuration error: %v\n", err)
		os.Exit(ExitCodeConfig)
	}

	// Print debug information about detected provider
	if cfg.Verbose {
		fmt.Fprintf(os.Stderr, "DEBUG: Detected provider: %s\n", cfg.DetectedProvider)
		if cfg.ProviderCapabilities != nil {
			fmt.Fprintf(os.Stderr, "DEBUG: Provider name: %s\n", cfg.ProviderCapabilities.Name)
			fmt.Fprintf(os.Stderr, "DEBUG: Policy support: %s\n", cfg.ProviderCapabilities.PolicySupport)
			fmt.Fprintf(os.Stderr, "DEBUG: ACL support: %s\n", cfg.ProviderCapabilities.ACLSupport)

			// For custom providers, show "Unknown" instead of false
			if cfg.DetectedProvider == "custom" {
				fmt.Fprintf(os.Stderr, "DEBUG: Virtual-host support: Unknown\n")
				fmt.Fprintf(os.Stderr, "DEBUG: Path-style support: Unknown\n")
			} else {
				fmt.Fprintf(os.Stderr, "DEBUG: Virtual-host support: %v\n", cfg.ProviderCapabilities.VirtualHostSupport)
				fmt.Fprintf(os.Stderr, "DEBUG: Path-style support: %v\n", cfg.ProviderCapabilities.PathStyleSupport)
			}
			fmt.Fprintf(os.Stderr, "DEBUG: Notes: %s\n", cfg.ProviderCapabilities.Notes)
		}
	}

	warningCount := 0
	if cfg.Warning != "" {
		warningCount = strings.Count(cfg.Warning, "\n") + 1
	}
	fmt.Fprintf(os.Stderr, "DEBUG: After validation, WarningCount=%d\n", warningCount)

	// Print warning if any
	if cfg.Warning != "" {
		fmt.Fprintf(os.Stderr, "\n%s\n", cfg.Warning)
	}

	// Convert to output config
	outputConfig := cfg.ToOutputConfig()

	// Extract hostname and port from endpoint
	hostname := checker.ParseHostname(cfg.Endpoint)
	port := cfg.Port

	// Create test report
	report := &output.TestReport{
		Config:    outputConfig,
		StartTime: time.Now(),
		Results:   make([]output.TestResult, 0, 5), // Up to 5 tests if policy check is enabled
	}

	// Run tests
	runTests(report, hostname, port, cfg.CheckPolicy)

	// Calculate summary
	report.EndTime = time.Now()
	report.Duration = report.EndTime.Sub(report.StartTime)
	report.Summary = output.NewTestSummary(report.Results)

	// Print console output (always)
	output.PrintConsole(report)

	// Print JSON output if output file is specified
	if cfg.OutputFile != "" {
		if err := output.PrintJSON(report, cfg.OutputFile); err != nil {
			fmt.Fprintf(os.Stderr, "\nWarning: Failed to write JSON output: %v\n", err)
		} else {
			fmt.Printf("\nJSON output saved to: %s\n", cfg.OutputFile)
		}
	}

	// Print remediations for failed tests
	printRemediations(report.Results)

	// Exit with appropriate code
	if report.Summary.Failed > 0 {
		os.Exit(ExitCodeFailed)
	}
	os.Exit(ExitCodeSuccess)
}

// runTests runs all tests and populates the report
func runTests(report *output.TestReport, hostname string, port int, checkPolicy bool) {
	// Test 1: DNS Resolution Check
	dnsChecker := checker.NewDNSChecker(report.Config, hostname)
	dnsResult := dnsChecker.Check()
	report.Results = append(report.Results, dnsResult)

	// Test 2: TCP Connectivity Check
	tcpChecker := checker.NewTCPChecker(report.Config, hostname, port)
	tcpResult := tcpChecker.Check()
	report.Results = append(report.Results, tcpResult)

	// Test 3: SSL/TLS Certificate Check (continue even if failed)
	tlsChecker := checker.NewTLSChecker(report.Config, hostname, port)
	tlsResult := tlsChecker.Check()
	report.Results = append(report.Results, tlsResult)

	// Test 4: Bucket Authentication Check
	authChecker := checker.NewAuthChecker(report.Config)
	authResult := authChecker.Check()
	report.Results = append(report.Results, authResult)

	// Test 5: Bucket Policy & ACL Check (optional)
	if checkPolicy {
		policyChecker := checker.NewPolicyChecker(report.Config)
		policyResult := policyChecker.Check()
		report.Results = append(report.Results, policyResult)
	}
}

// printRemediations prints remediation suggestions for failed tests
func printRemediations(results []output.TestResult) {
	hasFailures := false
	for _, result := range results {
		if result.Status == output.StatusFail && result.Error != "" {
			hasFailures = true
			break
		}
	}

	if !hasFailures {
		return
	}

	fmt.Println(strings.Repeat("=", 50))
	fmt.Println(bold("Remediation Suggestions"))
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println()

	for _, result := range results {
		if result.Status == output.StatusFail && result.Error != "" {
			rem := remediation.GetRemediation(result.TestName, fmt.Errorf(result.Error))
			if rem != nil {
				fmt.Printf("%s:\n", bold(result.TestName))
				fmt.Println(remediation.FormatRemediation(rem))
				fmt.Println()
			}
		}
	}
}

// bold returns bold text (helper function)
func bold(s string) string {
	return fmt.Sprintf("\033[1m%s\033[0m", s)
}
