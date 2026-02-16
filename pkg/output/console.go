package output

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
)

// formatPrincipal formats a principal value for display
func formatPrincipal(principal map[string]interface{}) string {
	var parts []string

	for _, value := range principal {
		switch v := value.(type) {
		case string:
			parts = append(parts, v)
		case []string:
			parts = append(parts, v...)
		case []interface{}:
			for _, item := range v {
				if s, ok := item.(string); ok {
					parts = append(parts, s)
				}
			}
		}
	}

	if len(parts) == 0 {
		return "*"
	}

	return strings.Join(parts, ", ")
}

// formatAction formats an action value for display (can be string or []string)
func formatAction(action interface{}) string {
	switch v := action.(type) {
	case string:
		return v
	case []string:
		return strings.Join(v, ", ")
	case []interface{}:
		var parts []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprintf("%v", action)
	}
}

// formatResource formats a resource value for display (can be string or []string)
func formatResource(resource interface{}) string {
	switch v := resource.(type) {
	case string:
		return v
	case []string:
		return strings.Join(v, ", ")
	case []interface{}:
		var parts []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	default:
		return fmt.Sprintf("%v", resource)
	}
}

// formatCondition formats a condition map for display
func formatCondition(condition map[string]interface{}) string {
	if len(condition) == 0 {
		return "-"
	}

	var parts []string
	for key, value := range condition {
		switch v := value.(type) {
		case string:
			parts = append(parts, fmt.Sprintf("%s: %s", key, v))
		case map[string]interface{}:
			var subParts []string
			for subKey, subValue := range v {
				subParts = append(subParts, fmt.Sprintf("%s=%v", subKey, subValue))
			}
			parts = append(parts, fmt.Sprintf("%s: {%s}", key, strings.Join(subParts, ", ")))
		default:
			parts = append(parts, fmt.Sprintf("%s: %v", key, v))
		}
	}

	return strings.Join(parts, "; ")
}

var (
	// Color definitions
	bold     = color.New(color.Bold).SprintFunc()
	green    = color.New(color.FgGreen).SprintFunc()
	red      = color.New(color.FgRed).SprintFunc()
	yellow   = color.New(color.FgYellow).SprintFunc()
	cyan     = color.New(color.FgCyan).SprintFunc()
	white    = color.New(color.FgWhite).SprintFunc()
	gray     = color.New(color.FgHiBlack).SprintFunc()
	passIcon = green("✓")
	failIcon = red("✗")
	warnIcon = yellow("⚠")
	skipIcon = gray("-")
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
		printResult(i+1, len(report.Results), result, report.Config)
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
func printResult(index, total int, result TestResult, config Config) {
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
		fmt.Printf("\n  %s: %s\n", red("Error"), result.Error)
	}

	switch result.TestName {
	case "DNS Resolution Check":
		printDNSResult(result)
	case "TCP Connectivity Check":
		printTCPResult(result)
	case "SSL/TLS Certificate Check":
		printTLSResult(result)
	case "Bucket Authentication Check":
		printAuthResult(result, config)
	case "Bucket Policy & ACL Check":
		printPolicyResult(result, config)
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
func printAuthResult(result TestResult, config Config) {
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

		// Print response body if verbose mode is enabled
		printResponseBody(config, "Response Body", details.ResponseBody)
	}
}

// printPolicyResult prints policy and ACL check result details
func printPolicyResult(result TestResult, config Config) {
	details, ok := result.Details.(PolicyACLResult)
	if !ok {
		return
	}

	// Print Bucket Policy section (on same line as status)
	fmt.Printf("  %s:\n", cyan("Bucket Policy"))
	if details.Policy.Error != "" {
		fmt.Printf("    %s: %s\n", red("Error"), details.Policy.Error)
	} else if details.Policy.HasPolicy {
		fmt.Printf("    %s: %s\n", cyan("Has Policy"), green("Yes"))
		fmt.Printf("    %s: %d\n", cyan("Statements"), details.Policy.StatementCount)

		if len(details.Policy.AllowedActions) > 0 {
			fmt.Printf("    %s: %s\n", cyan("Allowed Actions"), white(strings.Join(details.Policy.AllowedActions, ", ")))
		}
		if len(details.Policy.DeniedActions) > 0 {
			fmt.Printf("    %s: %s\n", cyan("Denied Actions"), white(strings.Join(details.Policy.DeniedActions, ", ")))
		}
		if len(details.Policy.Principals) > 0 {
			fmt.Printf("    %s: %s\n", cyan("Principals"), white(strings.Join(details.Policy.Principals, ", ")))
		}
		if len(details.Policy.Resources) > 0 {
			fmt.Printf("    %s: %s\n", cyan("Resources"), white(strings.Join(details.Policy.Resources, ", ")))
		}

		// Show policy document details if available
		if details.Policy.PolicyDocument != nil {
			fmt.Printf("    %s: %s\n", cyan("Policy Version"), white(details.Policy.PolicyDocument.Version))
			if details.Policy.PolicyDocument.ID != "" {
				fmt.Printf("    %s: %s\n", cyan("Policy ID"), white(details.Policy.PolicyDocument.ID))
			}

			// Show individual statements
			if len(details.Policy.PolicyDocument.Statement) > 0 {
				fmt.Printf("    %s:\n", cyan("Policy Statements"))
				for i, stmt := range details.Policy.PolicyDocument.Statement {
					sid := stmt.Sid
					if sid == "" {
						sid = "-"
					}
					fmt.Printf("      [%d] %s: %s\n", i+1, cyan("SID"), white(sid))
					fmt.Printf("          %s: %s\n", cyan("Effect"), white(stmt.Effect))

					// Show principal
					principalStr := formatPrincipal(stmt.Principal)
					fmt.Printf("          %s: %s\n", cyan("Principal"), white(principalStr))

					// Show action
					if stmt.Action != nil {
						actionStr := formatAction(stmt.Action)
						fmt.Printf("          %s: %s\n", cyan("Action"), white(actionStr))
					}

					// Show resource
					if stmt.Resource != nil {
						resourceStr := formatResource(stmt.Resource)
						fmt.Printf("          %s: %s\n", cyan("Resource"), white(resourceStr))
					}

					// Show condition
					if len(stmt.Condition) > 0 {
						conditionStr := formatCondition(stmt.Condition)
						fmt.Printf("          %s: %s\n", cyan("Condition"), white(conditionStr))
					}
				}
			}
		}
	} else {
		fmt.Printf("    %s: %s\n", cyan("Has Policy"), yellow("No (default policy applies)"))
	}

	// Print Bucket ACL section
	fmt.Printf("  %s:\n", cyan("Bucket ACL"))

	// Add note for custom endpoint or non-supported provider
	if config.CheckPolicy && config.ProviderCapabilities != nil {
		if config.DetectedProvider == "custom" || config.ProviderCapabilities.ACLSupport != "Full" {
			fmt.Printf("    %s: %s\n", yellow("Note"), yellow("Your provider may not fully support policy ACL operations."))
		}
	}

	if details.ACL.Error != "" {
		fmt.Printf("    %s: %s\n", red("Error"), details.ACL.Error)
	} else {
		// Owner
		ownerName := details.ACL.Owner.Grantee.DisplayName
		if ownerName == "" {
			ownerName = details.ACL.Owner.Grantee.ID
		}
		fmt.Printf("    %s: %s (%s)\n", cyan("Owner"), white(ownerName), white(details.ACL.Owner.Grantee.Type))

		// Public access
		fmt.Printf("    %s: ", cyan("Public Access"))
		if details.ACL.PublicRead {
			fmt.Printf("%s ", red("READ"))
		}
		if details.ACL.PublicWrite {
			fmt.Printf("%s ", red("WRITE"))
		}
		if !details.ACL.PublicRead && !details.ACL.PublicWrite {
			fmt.Printf("%s ", green("None"))
		}
		fmt.Println()

		// Authenticated users read
		if details.ACL.AuthUsersRead {
			fmt.Printf("    %s: %s\n", cyan("Auth Users Read"), yellow("Yes"))
		}

		// Grants
		if len(details.ACL.Grants) > 0 {
			fmt.Printf("    %s:\n", cyan("Grants"))
			for _, grant := range details.ACL.Grants {
				granteeName := grant.Grantee.DisplayName
				if granteeName == "" {
					granteeName = grant.Grantee.ID
					if granteeName == "" && grant.Grantee.URI != "" {
						// Parse URI to get group name
						if strings.Contains(grant.Grantee.URI, "AllUsers") {
							granteeName = "AllUsers"
						} else if strings.Contains(grant.Grantee.URI, "AuthenticatedUsers") {
							granteeName = "AuthenticatedUsers"
						} else {
							granteeName = grant.Grantee.URI
						}
					}
				}
				fmt.Printf("      - %s: %s\n", white(granteeName), white(grant.Permission))
			}
		}
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

// FormatResponseBody formats a response body for display, attempting to beautify JSON/XML
func FormatResponseBody(body string) string {
	if body == "" {
		return ""
	}

	bodyBytes := []byte(body)

	// Try to format as JSON
	var jsonBody interface{}
	if err := json.Unmarshal(bodyBytes, &jsonBody); err == nil {
		formatted, err := json.MarshalIndent(jsonBody, "", "  ")
		if err == nil {
			return string(formatted)
		}
	}

	// Try to format as XML
	if strings.HasPrefix(strings.TrimSpace(body), "<") {
		var decodedXML interface{}
		if err := xml.Unmarshal(bodyBytes, &decodedXML); err == nil {
			formatted, err := xml.MarshalIndent(decodedXML, "", "  ")
			if err == nil {
				// Add XML declaration
				return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + string(formatted)
			}
		}
	}

	// Return as-is if not JSON or XML
	return body
}

// printResponseBody prints the response body if verbose mode is enabled
func printResponseBody(config Config, label string, body string) {
	if !config.Verbose || body == "" {
		return
	}

	fmt.Printf("  %s:\n", cyan(label))
	fmt.Println(strings.Repeat("-", 46))

	// Format the body
	formatted := FormatResponseBody(body)

	// Truncate if too long
	maxLen := 5000
	if len(formatted) > maxLen {
		fmt.Println(formatted[:maxLen])
		fmt.Printf("\n  ... (truncated, %d bytes total)\n", len(body))
	} else {
		fmt.Println(formatted)
	}
	fmt.Println()
}
