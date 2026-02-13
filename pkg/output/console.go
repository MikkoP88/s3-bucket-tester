package output

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
)

var (
	// Color definitions
	bold      = color.New(color.Bold).SprintFunc()
	green     = color.New(color.FgGreen).SprintFunc()
	red       = color.New(color.FgRed).SprintFunc()
	yellow    = color.New(color.FgYellow).SprintFunc()
	cyan      = color.New(color.FgCyan).SprintFunc()
	white     = color.New(color.FgWhite).SprintFunc()
	gray      = color.New(color.FgHiBlack).SprintFunc()
	passIcon  = green("✓")
	failIcon  = red("✗")
	warnIcon  = yellow("⚠")
	skipIcon  = gray("-")
)

// PrintConsole prints the test report to console
func PrintConsole(report *TestReport) {
	// Print header
	printHeader()

	// Print configuration
	printConfig(report.Config)

	// Print separator
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println(bold("Running Tests..."))
	fmt.Println(strings.Repeat("=", 50))

	// Print results
	for i, result := range report.Results {
		printResult(i+1, len(report.Results), result)
	}

	// Print separator
	fmt.Println(strings.Repeat("=", 50))

	// Print summary
	printSummary(report.Summary)

	// Print footer
	fmt.Println()
}

// printHeader prints the tool header
func printHeader() {
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println(bold("S3 Bucket Tester"))
	fmt.Println(strings.Repeat("=", 50))
	fmt.Println()
}

// printConfig prints the test configuration
func printConfig(config Config) {
	fmt.Println(bold("Configuration:"))
	fmt.Printf("  %s: %s\n", cyan("Endpoint"), white(config.Endpoint))
	fmt.Printf("  %s: %s\n", cyan("Bucket"), white(config.Bucket))
	fmt.Printf("  %s: %s\n", cyan("Region"), white(config.Region))
	fmt.Printf("  %s: %s\n", cyan("Auth Type"), white(strings.ToUpper(config.AuthType)))
	fmt.Printf("  %s: %d\n", cyan("Port"), config.Port)
	fmt.Printf("  %s: %ds\n", cyan("Timeout"), config.Timeout)
	
	// Show addressing style
	if config.PathStyle {
		fmt.Printf("  %s: %s\n", cyan("Addressing Style"), white("Path-style"))
	} else {
		fmt.Printf("  %s: %s\n", cyan("Addressing Style"), white("Virtual-hosted (default)"))
	}
	
	if config.Insecure {
		fmt.Printf("  %s: %s\n", cyan("TLS Verify"), red("Disabled"))
	}
	fmt.Println()
}

// printResult prints a single test result
func printResult(index, total int, result TestResult) {
	// Format progress
	progress := fmt.Sprintf("[%d/%d]", index, total)

	// Format test name with status
	var statusIcon string
	switch result.Status {
	case StatusPass:
		statusIcon = passIcon
	case StatusFail:
		statusIcon = failIcon
	case StatusWarn:
		statusIcon = warnIcon
	case StatusSkip:
		statusIcon = skipIcon
	}

	// Print test line
	fmt.Printf("%s %s", gray(progress), white(result.TestName))
	fmt.Printf(" %s\n", strings.Repeat(".", 45-len(result.TestName)-len(progress)))
	fmt.Printf("  %s %s\n", statusIcon, statusColor(result.Status)(result.Status))

	// Print details based on test type
	if result.Error != "" {
		fmt.Printf("  %s: %s\n", red("Error"), result.Error)
	}

	switch result.TestName {
	case "DNS Resolution Check":
		printDNSResult(result)
	case "TCP Connectivity Check":
		printTCPResult(result)
	case "SSL/TLS Certificate Check":
		printTLSResult(result)
	case "Bucket Authentication Check":
		printAuthResult(result)
	}

	fmt.Println()
}

// printDNSResult prints DNS check result details
func printDNSResult(result TestResult) {
	if details, ok := result.Details.(DNSResult); ok {
		fmt.Printf("  %s: %s\n", cyan("Hostname"), white(details.Hostname))
		if len(details.IPs) > 0 {
			fmt.Printf("  %s: %s\n", cyan("Resolved IPs"), white(strings.Join(details.IPs, ", ")))
		}
		if details.ReverseDNS != "" {
			fmt.Printf("  %s: %s\n", cyan("Reverse DNS"), white(details.ReverseDNS))
		}
		fmt.Printf("  %s: %dms\n", cyan("Resolution time"), details.ResolutionTime)
	}
}

// printTCPResult prints TCP check result details
func printTCPResult(result TestResult) {
	if details, ok := result.Details.(TCPResult); ok {
		fmt.Printf("  %s: %s:%d\n", cyan("Connected to"), white(details.Host), details.Port)
		if details.Connected {
			fmt.Printf("  %s: %s\n", cyan("Local address"), white(details.LocalAddr))
			fmt.Printf("  %s: %s\n", cyan("Remote address"), white(details.RemoteAddr))
		}
		fmt.Printf("  %s: %dms\n", cyan("Connection time"), details.ConnectionTime)
	}
}

// printTLSResult prints TLS check result details
func printTLSResult(result TestResult) {
	if details, ok := result.Details.(TLSResult); ok {
		cert := details.Certificate
		fmt.Printf("  %s: %s\n", cyan("Subject"), white(cert.Subject))
		fmt.Printf("  %s: %s\n", cyan("Issuer"), white(cert.Issuer))
		fmt.Printf("  %s: %s to %s\n", cyan("Valid from"), white(cert.NotBefore.Format("2006-01-02")), white(cert.NotAfter.Format("2006-01-02")))
		fmt.Printf("  %s: %s\n", cyan("TLS Version"), white(details.TLSVersion))
		fmt.Printf("  %s: %s\n", cyan("Cipher Suite"), white(details.CipherSuite))

		// SANs
		if len(cert.SANs) > 0 {
			fmt.Printf("  %s: %s\n", cyan("SANs"), white(strings.Join(cert.SANs, ", ")))
		}

		// Serial number
		if cert.SerialNumber != "" {
			fmt.Printf("  %s: %s\n", cyan("Serial Number"), white(cert.SerialNumber))
		}

		// Signature algorithm
		if cert.SignatureAlgorithm != "" {
			fmt.Printf("  %s: %s\n", cyan("Signature Algorithm"), white(cert.SignatureAlgorithm))
		}

		// Days until expiry
		days := cert.DaysUntilExpiry
		if days < 0 {
			fmt.Printf("  %s: %s\n", red("Certificate Status"), red("EXPIRED"))
		} else if days < 30 {
			fmt.Printf("  %s: %s (%d days remaining)\n", yellow("Certificate Status"), yellow("Expiring Soon"), days)
		} else {
			fmt.Printf("  %s: %s (%d days remaining)\n", green("Certificate Status"), green("Valid"), days)
		}

		// Verification status
		if details.Verified {
			fmt.Printf("  %s: %s\n", cyan("Verification"), green("Verified"))
		} else {
			fmt.Printf("  %s: %s\n", cyan("Verification"), red("Not Verified"))
		}

		// Certificate chain
		if len(cert.Chain) > 0 {
			fmt.Printf("  %s: %d certificate(s)\n", cyan("Certificate Chain"), len(cert.Chain))
			for i, chainCert := range cert.Chain {
				fmt.Printf("    %d. %s\n", i+1, white(chainCert.Issuer))
			}
		}
	}
}

// printAuthResult prints auth check result details
func printAuthResult(result TestResult) {
	if details, ok := result.Details.(AuthResult); ok {
		fmt.Printf("  %s: %s\n", cyan("Auth Type"), white(details.AuthType))
		fmt.Printf("  %s: %s\n", cyan("Provider"), white(details.Provider))
		fmt.Printf("  %s: %s\n", cyan("Endpoint"), white(details.Endpoint))

		if details.BucketExists {
			fmt.Printf("  %s: %s\n", cyan("Bucket Exists"), green("Yes"))
		} else {
			fmt.Printf("  %s: %s\n", cyan("Bucket Exists"), red("No"))
		}

		if details.AccessGranted {
			fmt.Printf("  %s: %s\n", cyan("Access Granted"), green("Yes"))
		} else {
			fmt.Printf("  %s: %s\n", cyan("Access Granted"), red("No"))
		}

		fmt.Printf("  %s: %d\n", cyan("Status Code"), details.StatusCode)
		fmt.Printf("  %s: %dms\n", cyan("Response time"), details.ResponseTime)
	}
}

// printSummary prints the test summary
func printSummary(summary TestSummary) {
	fmt.Println(bold("Test Summary"))
	fmt.Printf("  Total: %s | Passed: %s | Failed: %s | Warnings: %s\n",
		white(fmt.Sprintf("%d", summary.Total)),
		green(fmt.Sprintf("%d", summary.Passed)),
		red(fmt.Sprintf("%d", summary.Failed)),
		yellow(fmt.Sprintf("%d", summary.Warnings)))

	fmt.Println()

	if summary.Failed == 0 && summary.Warnings == 0 {
		fmt.Println(green("All tests passed successfully!"))
	} else if summary.Failed == 0 {
		fmt.Println(yellow("Tests completed with warnings."))
	} else {
		fmt.Println(red("Some tests failed. Please review the errors above."))
	}
}

// statusColor returns the color function for a given status
func statusColor(status Status) func(a ...interface{}) string {
	switch status {
	case StatusPass:
		return green
	case StatusFail:
		return red
	case StatusWarn:
		return yellow
	case StatusSkip:
		return gray
	default:
		return white
	}
}

// FormatDuration formats a duration for display
func FormatDuration(d time.Duration) string {
	if d < time.Millisecond {
		return fmt.Sprintf("%dµs", d.Microseconds())
	} else if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	} else {
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
}
