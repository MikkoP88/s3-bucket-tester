package remediation

import (
	"fmt"
	"strings"
	"time"
)

// Remediation provides fix suggestions for test failures
type Remediation struct {
	Error      string
	Cause      string
	Suggestion string
	Commands   []string
}

// GetRemediation returns remediation suggestions based on error type
func GetRemediation(testName string, err error) *Remediation {
	if err == nil {
		return nil
	}

	errMsg := err.Error()
	lowerErrMsg := strings.ToLower(errMsg)

	switch testName {
	case "DNS Resolution Check":
		return getDNSRemediation(errMsg, lowerErrMsg)
	case "TCP Connectivity Check":
		return getTCPRemediation(errMsg, lowerErrMsg)
	case "SSL/TLS Certificate Check":
		return getTLSRemediation(errMsg, lowerErrMsg)
	case "Bucket Authentication Check":
		return getAuthRemediation(errMsg, lowerErrMsg)
	default:
		return &Remediation{
			Error:      errMsg,
			Cause:      "Unknown error",
			Suggestion: "Please check the error details and try again.",
		}
	}
}

// getDNSRemediation provides DNS-specific remediation
func getDNSRemediation(errMsg, lowerErrMsg string) *Remediation {
	r := &Remediation{Error: errMsg}

	switch {
	case strings.Contains(lowerErrMsg, "no such host") || strings.Contains(lowerErrMsg, "nxdomain"):
		r.Cause = "The hostname does not exist or DNS resolution failed"
		r.Suggestion = "Verify the hostname is correct and DNS servers are properly configured"
		r.Commands = []string{
			"nslookup <hostname>",
			"dig <hostname>",
			"ping <hostname>",
		}
	case strings.Contains(lowerErrMsg, "timeout"):
		r.Cause = "DNS query timed out"
		r.Suggestion = "Check your network connection and DNS server settings"
		r.Commands = []string{
			"Check /etc/resolv.conf (Linux) or DNS settings (Windows)",
			"Try using a public DNS server like 8.8.8.8 or 1.1.1.1",
		}
	case strings.Contains(lowerErrMsg, "refused"):
		r.Cause = "DNS server refused the query"
		r.Suggestion = "Check DNS server configuration and firewall rules"
		r.Commands = []string{
			"Verify DNS server is running",
			"Check firewall rules allow DNS (UDP 53)",
		}
	case strings.Contains(lowerErrMsg, "i/o timeout"):
		r.Cause = "DNS I/O operation timed out"
		r.Suggestion = "Check network connectivity and DNS server status"
		r.Commands = []string{
			"Test network connectivity with ping",
			"Verify DNS server is accessible",
		}
	default:
		r.Cause = "DNS resolution failed"
		r.Suggestion = "Check hostname spelling and network connectivity"
		r.Commands = []string{
			"Verify hostname is correct",
			"Check network connection",
		}
	}

	return r
}

// getTCPRemediation provides TCP-specific remediation
func getTCPRemediation(errMsg, lowerErrMsg string) *Remediation {
	r := &Remediation{Error: errMsg}

	switch {
	case strings.Contains(lowerErrMsg, "connection refused"):
		r.Cause = "The target port is closed or no service is listening"
		r.Suggestion = "Verify the service is running and the correct port is specified"
		r.Commands = []string{
			"telnet <host> <port>",
			"nc -zv <host> <port>",
			"Test-NetConnection -ComputerName <host> -Port <port> (PowerShell)",
		}
	case strings.Contains(lowerErrMsg, "timeout"):
		r.Cause = "Connection timed out"
		r.Suggestion = "Check firewall rules, network connectivity, and endpoint availability"
		r.Commands = []string{
			"Check firewall rules allow traffic to the port",
			"Verify network connectivity with traceroute/tracert",
			"Confirm the endpoint service is running",
		}
	case strings.Contains(lowerErrMsg, "network is unreachable"):
		r.Cause = "Network routing issue"
		r.Suggestion = "Check network configuration and routing table"
		r.Commands = []string{
			"route print (Windows) or ip route (Linux)",
			"ping <host> to check connectivity",
			"traceroute <host> to trace route",
		}
	case strings.Contains(lowerErrMsg, "no route to host"):
		r.Cause = "No network route to the target host"
		r.Suggestion = "Check network configuration and VPN settings"
		r.Commands = []string{
			"Check default gateway configuration",
			"Verify VPN connection if applicable",
			"Check routing table for correct routes",
		}
	case strings.Contains(lowerErrMsg, "connection reset"):
		r.Cause = "Connection was reset by the remote host"
		r.Suggestion = "The remote host closed the connection unexpectedly"
		r.Commands = []string{
			"Wait a moment and retry",
			"Check if the service is being restarted",
			"Review server logs for issues",
		}
	default:
		r.Cause = "TCP connection failed"
		r.Suggestion = "Verify the host and port are correct and network is accessible"
		r.Commands = []string{
			"telnet <host> <port>",
			"ping <host>",
			"Check firewall rules",
		}
	}

	return r
}

// getTLSRemediation provides TLS-specific remediation
func getTLSRemediation(errMsg, lowerErrMsg string) *Remediation {
	r := &Remediation{Error: errMsg}

	switch {
	case strings.Contains(lowerErrMsg, "certificate has expired"):
		r.Cause = "The SSL/TLS certificate has expired"
		r.Suggestion = "Renew the certificate on the server"
		r.Commands = []string{
			"Check certificate expiry: openssl s_client -connect <host>:<port> -servername <host> -showcerts",
			"Renew certificate through your certificate authority",
			"Update endpoint to use renewed certificate",
		}
	case strings.Contains(lowerErrMsg, "certificate is not yet valid"):
		r.Cause = "The certificate's validity period has not started"
		r.Suggestion = "Check system time and certificate validity period"
		r.Commands = []string{
			"Verify system time is correct: date (Linux/Mac) or w32tm /query (Windows)",
			"Check certificate validity period: openssl x509 -in cert.pem -noout -dates",
		}
	case strings.Contains(lowerErrMsg, "certificate signed by unknown authority"):
		r.Cause = "The certificate is signed by an unknown or untrusted CA"
		r.Suggestion = "Add the CA certificate to your trust store or use --insecure flag"
		r.Commands = []string{
			"Add CA certificate to system trust store",
			"Windows: Import certificate to 'Trusted Root Certification Authorities' via certmgr.msc",
			"Linux: Copy CA cert to /usr/local/share/ca-certificates/ and run update-ca-certificates",
			"Use --insecure flag to skip verification (not recommended for production)",
		}
	case strings.Contains(lowerErrMsg, "certificate name mismatch") || strings.Contains(lowerErrMsg, "does not match"):
		r.Cause = "Certificate name does not match the hostname"
		r.Suggestion = "Use the correct hostname that matches the certificate's Subject Alternative Names (SANs)"
		r.Commands = []string{
			"Check certificate SANs: openssl s_client -connect <host>:<port> -servername <host> -showcerts",
			"Use the hostname from the certificate's Subject or SANs",
			"Verify DNS records point to the correct IP address",
		}
	case strings.Contains(lowerErrMsg, "no tls version"):
		r.Cause = "No compatible TLS version negotiated"
		r.Suggestion = "The server may not support modern TLS versions"
		r.Commands = []string{
			"Check server TLS configuration",
			"Test with specific TLS version: openssl s_client -connect <host>:<port> -tls1_2",
			"Update server to support TLS 1.2 or higher",
		}
	case strings.Contains(lowerErrMsg, "handshake failure"):
		r.Cause = "TLS handshake failed"
		r.Suggestion = "Check certificate chain and server configuration"
		r.Commands = []string{
			"Check certificate chain: openssl s_client -connect <host>:<port> -showcerts",
			"Verify intermediate certificates are installed",
			"Check server supports your client's TLS version",
		}
	case strings.Contains(lowerErrMsg, "bad certificate"):
		r.Cause = "The certificate is invalid or malformed"
		r.Suggestion = "The server certificate is invalid or corrupted"
		r.Commands = []string{
			"View certificate details: openssl s_client -connect <host>:<port> -showcerts",
			"Regenerate the certificate on the server",
		}
	case strings.Contains(lowerErrMsg, "certificate verify failed"):
		r.Cause = "Certificate verification failed"
		r.Suggestion = "Check if the certificate is trusted and valid"
		r.Commands = []string{
			"Check certificate chain: openssl s_client -connect <host>:<port> -showcerts",
			"Use --insecure flag to skip verification (not recommended)",
		}
	default:
		r.Cause = "TLS certificate validation failed"
		r.Suggestion = "Check certificate details and server configuration"
		r.Commands = []string{
			"View certificate: openssl s_client -connect <host>:<port> -showcerts",
			"Check certificate validity: openssl x509 -in cert.pem -noout -dates",
		}
	}

	return r
}

// getAuthRemediation provides authentication-specific remediation
func getAuthRemediation(errMsg, lowerErrMsg string) *Remediation {
	r := &Remediation{Error: errMsg}

	switch {
	case strings.Contains(lowerErrMsg, "invalidaccesskeyid"):
		r.Cause = "The access key ID is invalid or does not exist"
		r.Suggestion = "Verify the access key ID is correct and the user exists in the S3 provider"
		r.Commands = []string{
			"Verify access key ID in S3 console or provider UI",
			"Check IAM user exists: aws iam get-user --user-name <username>",
			"Create new access key if needed: aws iam create-access-key --user-name <username>",
			"Verify user has programmatic access to S3",
		}
	case strings.Contains(lowerErrMsg, "signaturedoesnotmatch"):
		r.Cause = "Signature calculation failed - credentials or region mismatch"
		r.Suggestion = "Check secret key, region, and endpoint configuration"
		r.Commands = []string{
			"Verify secret key is correct (check for typos)",
			"Verify region matches the bucket's region",
			"Verify endpoint URL is correct",
			"Check if path-style addressing is required: some providers require path-style URLs",
			"Verify system time is synchronized: w32tm /query (Windows) or ntpdate -q (Linux)",
		}
	case strings.Contains(lowerErrMsg, "accessdenied"):
		r.Cause = "Access denied - insufficient permissions"
		r.Suggestion = "Grant required IAM permissions to the user/role for this bucket"
		r.Commands = []string{
			"Review IAM user permissions: aws iam list-attached-user-policies --user-name <username>",
			"Review bucket policy: aws s3api get-bucket-policy --bucket <bucket>",
			"Review bucket ACL: aws s3api get-bucket-acl --bucket <bucket>",
			"Grant s3:* permission to user: aws iam attach-user-policy --user-name <username> --policy-arn <arn>",
			"Grant specific bucket permissions: aws s3api put-bucket-policy --bucket <bucket> --policy file://policy.json",
		}
	case strings.Contains(lowerErrMsg, "nosuchbucket"):
		r.Cause = "The specified bucket does not exist"
		r.Suggestion = "Verify the bucket name and region are correct"
		r.Commands = []string{
			"List buckets to verify: aws s3 ls (AWS CLI) or mc ls (MinIO)",
			"Check bucket name spelling",
			"Verify region matches the bucket's actual region",
			"Check if path-style addressing is required: s3.amazonaws.com/<bucket> vs <bucket>.s3.amazonaws.com",
		}
	case strings.Contains(lowerErrMsg, "allaccessdisabled"):
		r.Cause = "All access to the bucket has been disabled"
		r.Suggestion = "Check bucket policy and ACL settings - public access may be blocked"
		r.Commands = []string{
			"Check bucket policy: aws s3api get-bucket-policy --bucket <bucket>",
			"Check bucket ACL: aws s3api get-bucket-acl --bucket <bucket>",
			"Enable public access if required: aws s3api put-bucket-acl --bucket <bucket> --acl public-read",
		}
	case strings.Contains(lowerErrMsg, "requesttimetoolarge"):
		r.Cause = "Request time is too far in the future or past"
		r.Suggestion = "Synchronize system time with NTP server"
		r.Commands = []string{
			"Sync time on Windows: w32tm /resync",
			"Sync time on Linux: ntpdate -u pool.ntp.org",
			"Sync time on macOS: sntp -s pool.ntp.org",
		}
	case strings.Contains(lowerErrMsg, "requestexpired"):
		r.Cause = "The request has expired (STS temporary credentials)"
		r.Suggestion = "STS temporary credentials have expired - use new credentials"
		r.Commands = []string{
			"Get new temporary credentials if using assumed role: aws sts assume-role --role-arn <arn>",
			"Get new temporary credentials if using user: aws sts get-session-token",
			"Check if STS keys need rotation in your organization",
		}
	case strings.Contains(lowerErrMsg, "missingauthenticationtoken"):
		r.Cause = "Authentication token is missing or invalid"
		r.Suggestion = "Provide valid authentication credentials"
		r.Commands = []string{
			"Verify access key and secret key are provided",
			"Check if session token is required and provided",
			"Verify temporary credentials are still valid",
		}
	case strings.Contains(lowerErrMsg, "malformedxml"):
		r.Cause = "The server returned malformed XML response"
		r.Suggestion = "The server response could not be parsed - endpoint may not be S3-compatible"
		r.Commands = []string{
			"Verify endpoint is S3-compatible",
			"Test with curl: curl -v <endpoint>",
			"Check server logs for errors",
		}
	case strings.Contains(lowerErrMsg, "internalerror"):
		r.Cause = "Internal server error"
		r.Suggestion = "The S3 provider is experiencing an issue - try again later"
		r.Commands = []string{
			"Wait a moment and retry the request",
			"Check provider status page for known issues",
			"Review server logs if you have access",
		}
	case strings.Contains(lowerErrMsg, "slowdown") || strings.Contains(lowerErrMsg, "servicemavailable"):
		r.Cause = "The S3 service is temporarily unavailable or slow"
		r.Suggestion = "The S3 service is experiencing issues - try again later"
		r.Commands = []string{
			"Wait a few moments and retry",
			"Check provider status page: https://status.aws.amazonaws.com/ (AWS)",
			"Check provider status page for your specific provider",
		}
	case strings.Contains(lowerErrMsg, "403"):
		r.Cause = "Forbidden - request blocked by security policy"
		r.Suggestion = "The request was blocked - check security policies and WAF rules"
		r.Commands = []string{
			"Review bucket policy for explicit deny statements",
			"Check if IP is blocked by WAF or security group",
			"Verify user/role permissions for S3 access",
		}
	case strings.Contains(lowerErrMsg, "503"):
		r.Cause = "Service Unavailable - the S3 service is down"
		r.Suggestion = "The S3 service is temporarily unavailable - try again later"
		r.Commands = []string{
			"Check provider status page",
			"Wait and retry the request",
			"Verify if the service is down in your region only",
		}
	default:
		r.Cause = "Authentication failed"
		r.Suggestion = "Check credentials, region, endpoint configuration, and IAM permissions"
		r.Commands = []string{
			"Verify access key and secret key are correct",
			"Check region matches the bucket's region",
			"Verify endpoint URL is correct",
			"Verify addressing style matches provider requirements",
			"Check IAM user/role has required permissions",
			"Review bucket policy and ACLs",
			"Check system time is synchronized",
		}
	}

	return r
}

// FormatRemediation formats a remediation for display
func FormatRemediation(r *Remediation) string {
	if r == nil {
		return ""
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("\n  Error: %s\n", r.Error))
	sb.WriteString(fmt.Sprintf("  Cause: %s\n", r.Cause))
	sb.WriteString(fmt.Sprintf("  Suggestion: %s", r.Suggestion))

	if len(r.Commands) > 0 {
		sb.WriteString("\n  Commands to try:")
		for _, cmd := range r.Commands {
			sb.WriteString(fmt.Sprintf("\n    - %s", cmd))
		}
	}

	return sb.String()
}

// GetCertificateWarnings returns warnings for certificate issues
func GetCertificateWarnings(certValidUntil time.Time, daysUntilExpiry int) []string {
	var warnings []string

	if daysUntilExpiry < 0 {
		warnings = append(warnings, "Certificate has expired!")
	} else if daysUntilExpiry < 7 {
		warnings = append(warnings, fmt.Sprintf("Certificate expires in %d days! Renew immediately.", daysUntilExpiry))
	} else if daysUntilExpiry < 30 {
		warnings = append(warnings, fmt.Sprintf("Certificate expires in %d days. Plan for renewal.", daysUntilExpiry))
	}

	return warnings
}
