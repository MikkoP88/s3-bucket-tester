# S3 Bucket Tester

A cross-platform CLI tool built in Go to test S3-compatible storage providers (AWS, MinIO, NetApp StorageGrid, Hetzner, etc.) with comprehensive connectivity and authentication checks.

## Table of Contents

- [Features](#features)
- [License](#license)
- [Validated Providers](#validated-providers)
- [Installation](#installation)
- [Usage](#usage)
- [Addressing Styles](#addressing-styles)
- [Command-Line Options](#command-line-options)
- [Output Format](#output-format)
- [Exit Codes](#exit-codes)
- [Remediation Suggestions](#remediation-suggestions)
- [Supported Providers](#supported-providers)
- [Architecture](#architecture)
- [Building](#building)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Support](#support)

## Features

- **Cross-platform**: Works on Windows, Linux, and macOS without any OS extensions
- **Single static binary**: No external dependencies required
- **Multi-provider support**: AWS S3, MinIO, NetApp StorageGrid, Hetzner S3, and any S3-compatible storage
- **Dual authentication**: Supports AWS SigV4 (default) and SigV2
- **Addressing styles**: Both path-style and virtual-hosted addressing
- **Redirect handling**: Follows HTTP redirects with configurable limits
- **DNS & IP support**: Works with both hostnames and IP addresses
- **Verbose logging**: Detailed debugging information
- **JSON output**: Optional machine-readable output format
- **Remediation suggestions**: Automatic fix suggestions for failed tests

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### License Summary

The MIT License is a permissive free software license that allows:
- ✅ Commercial use
- ✅ Modification
- ✅ Distribution
- ✅ Private use
- ✅ Sublicensing

**Requirements:**
- Include the original copyright and license notice
- Provide the license text when distributing

### Dependency Licenses

All project dependencies use permissive licenses compatible with MIT:

| Dependency | Version | License | Compatible |
|------------|---------|---------|------------|
| github.com/fatih/color | v1.16.0 | MIT | ✅ Yes |
| github.com/mattn/go-colorable | v0.1.13 | MIT | ✅ Yes |
| github.com/mattn/go-isatty | v0.0.20 | MIT | ✅ Yes |
| golang.org/x/sys | v0.15.0 | BSD-3-Clause | ✅ Yes |

**No license conflicts detected.** All dependencies are fully compatible with the MIT License.

## Validated Providers

The S3 Bucket Tester has been validated against the following providers:

### MinIO

- **Addressing Style**: Path-style
- **Status**: ✅ Fully Validated
- **Endpoint Example**: `http://localhost:9000`
- **Notes**: MinIO works correctly with path-style addressing. Use the `--path-style` flag when testing MinIO instances.

```bash
s3tester \
  --endpoint http://localhost:9000 \
  --bucket test-bucket \
  --access-key minioadmin \
  --secret-key minioadmin \
  --path-style
```

### Hetzner S3

- **Addressing Styles**: Path-style and Virtual-hosted
- **Status**: ✅ Fully Validated
- **Endpoint Examples**:
  - Virtual-hosted: `https://<bucket>.your-objectstorage.com`
  - Path-style: `https://your-objectstorage.com`

**Virtual-hosted style example:**
```bash
s3tester \
  --endpoint https://your-objectstorage.com \
  --bucket my-bucket \
  --access-key YOUR_ACCESS_KEY \
  --secret-key YOUR_SECRET_KEY \
  --region nbg1
```

**Path-style example:**
```bash
s3tester \
  --endpoint https://your-objectstorage.com \
  --bucket my-bucket \
  --access-key YOUR_ACCESS_KEY \
  --secret-key YOUR_SECRET_KEY \
  --path-style \
  --region nbg1
```

### Other Tested Providers

The tool is designed to work with any S3-compatible provider. While the above providers have been specifically validated, the following have also been tested by users:

- AWS S3 (all regions)
- Wasabi Cloud Storage
- Backblaze B2
- DigitalOcean Spaces
- IBM Cloud Object Storage
- NetApp StorageGRID

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/s3-bucket-tester/s3tester.git
cd s3tester

# Build for your platform
make build

# Or build for all platforms
make build-all
```

### Pre-built Binaries

Download the appropriate binary from the [Releases](https://github.com/s3-bucket-tester/s3tester/releases) page.

Available platforms:
- Windows (amd64)
- Linux (amd64, arm64)
- macOS (amd64, arm64)

## Usage

### Basic Usage

```bash
s3tester \
  --endpoint https://s3.amazonaws.com \
  --bucket my-test-bucket \
  --access-key AKIAIOSFODNN7EXAMPLE \
  --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### MinIO Example (Path-style)

```bash
s3tester \
  --endpoint http://localhost:9000 \
  --bucket test-bucket \
  --access-key minioadmin \
  --secret-key minioadmin \
  --path-style \
  --insecure
```

### Hetzner S3 Example (Virtual-hosted)

```bash
s3tester \
  --endpoint https://your-objectstorage.com \
  --bucket my-bucket \
  --access-key YOUR_ACCESS_KEY \
  --secret-key YOUR_SECRET_KEY \
  --region nbg1
```

### Hetzner S3 Example (Path-style)

```bash
s3tester \
  --endpoint https://your-objectstorage.com \
  --bucket my-bucket \
  --access-key YOUR_ACCESS_KEY \
  --secret-key YOUR_SECRET_KEY \
  --path-style \
  --region nbg1
```

### With IP Address

```bash
s3tester \
  --endpoint https://192.168.1.100:9000 \
  --bucket test-bucket \
  --access-key AKIAIOSFODNN7EXAMPLE \
  --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```

### With JSON Output

```bash
s3tester \
  --endpoint https://s3.amazonaws.com \
  --bucket my-test-bucket \
  --access-key AKIAIOSFODNN7EXAMPLE \
  --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  --output-file results.json
```

### With SigV2 Authentication

```bash
s3tester \
  --endpoint https://s3.amazonaws.com \
  --bucket my-test-bucket \
  --access-key AKIAIOSFODNN7EXAMPLE \
  --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  --auth-type sigv2
```

### With Verbose Output

```bash
s3tester \
  --endpoint https://s3.amazonaws.com \
  --bucket my-test-bucket \
  --access-key AKIAIOSFODNN7EXAMPLE \
  --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY \
  --verbose
```

## Addressing Styles

S3-compatible storage providers support two different addressing styles for bucket access:

### Virtual-hosted Style (Default)

In virtual-hosted style, the bucket name is part of the hostname:

```
https://<bucket-name>.<endpoint>
```

**Example:**
```
https://my-bucket.s3.amazonaws.com
```

**Use when:**
- Using AWS S3
- Using providers with DNS wildcard support
- Bucket names are DNS-compliant

**Command:**
```bash
s3tester \
  --endpoint https://s3.amazonaws.com \
  --bucket my-bucket \
  --access-key KEY \
  --secret-key SECRET
```

### Path-style

In path-style, the bucket name is part of the URL path:

```
https://<endpoint>/<bucket-name>
```

**Example:**
```
https://s3.amazonaws.com/my-bucket
```

**Use when:**
- Using MinIO
- Using Hetzner S3 with path-style
- Bucket names contain dots (.)
- Provider doesn't support DNS wildcards
- Testing with IP addresses

**Command:**
```bash
s3tester \
  --endpoint https://s3.amazonaws.com \
  --bucket my-bucket \
  --access-key KEY \
  --secret-key SECRET \
  --path-style
```

### Comparison

| Feature | Virtual-hosted | Path-style |
|---------|---------------|------------|
| URL Format | `https://<bucket>.<endpoint>` | `https://<endpoint>/<bucket>` |
| DNS Wildcard Support | Required | Not Required |
| Bucket Names with Dots | Problematic | Works |
| IP Address Support | No | Yes |
| MinIO Support | Limited | Full |
| Hetzner Support | Yes | Yes |

## Command-Line Options

### Required Flags

| Flag | Description | Example |
|------|-------------|---------|
| `--endpoint` | S3 endpoint URL or built-in provider shortcut | `https://s3.amazonaws.com` |
| `--bucket` | Bucket name to test | `my-test-bucket` |
| `--access-key` | Access key ID | `AKIAIOSFODNN7EXAMPLE` |
| `--secret-key` | Secret access key | `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY` |

### Addressing Style Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--virtual-hosted` | Use virtual-hosted addressing (URL: `https://<bucket>.<endpoint>`) | Default |
| `--path-style` | Use path-style addressing (URL: `https://<endpoint>/<bucket>`) | - |

### Optional Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--region` | AWS region | `us-east-1` |
| `--auth-type` | Authentication type (sigv4/sigv2) | `sigv4` |
| `--port` | Custom port | Auto-detected from endpoint |
| `--insecure` | Skip TLS verification | `false` |
| `--timeout` | Request timeout in seconds | `30` |
| `--output-file` | Save JSON output to file | - |
| `--follow-redirects` | Follow HTTP redirects | `true` |
| `--no-redirects` | Do not follow HTTP redirects | - |
| `--max-redirects` | Maximum redirects to follow | `10` |
| `--verbose` | Enable verbose output | `false` |
| `--help, -h` | Show help message | - |
| `--version` | Show version information | - |

### Built-in Provider Shortcuts

Use these with the `--endpoint` flag:

| Provider | Shortcut | Addressing Style | Description |
|----------|----------|-----------------|-------------|
| AWS S3 | `aws` | Virtual-hosted | AWS S3 (default) |
| AWS Legacy | `aws-legacy` | Path-style | AWS S3 (legacy) |
| Wasabi | `wasabi` | Virtual-hosted | Wasabi Cloud Storage |
| Wasabi Legacy | `wasabi-legacy` | Path-style | Wasabi (legacy) |
| Backblaze B2 | `b2` | Virtual-hosted | Backblaze B2 |
| B2 Legacy | `b2-legacy` | Path-style | Backblaze B2 (legacy) |
| IBM Cloud | `ibm` | Virtual-hosted | IBM Cloud Object Storage |
| DigitalOcean | `do` | Virtual-hosted | DigitalOcean Spaces |

**Example using built-in provider:**
```bash
s3tester --endpoint aws --region us-east-1 \
         --bucket my-bucket \
         --access-key KEY \
         --secret-key SECRET
```

## Output Format

### Console Output (Always Displayed)

```
==================================================
S3 Bucket Tester
==================================================

Configuration:
  Endpoint:    https://s3.amazonaws.com
  Bucket:      my-test-bucket
  Region:      us-east-1
  Auth Type:   SIGV4
  Port:        443
  Timeout:     30s

==================================================
Running Tests...
==================================================

[1/4] DNS Resolution Check.......................... ✓ PASS
  Hostname: s3.amazonaws.com
  Resolved IPs: 52.216.132.141, 52.216.132.85
  Resolution time: 15ms

[2/4] TCP Connectivity Check......................... ✓ PASS
  Connected to: s3.amazonaws.com:443
  Local address: 192.168.1.100:54321
  Remote address: 52.216.132.141:443
  Connection time: 45ms

[3/4] SSL/TLS Certificate Check...................... ✓ PASS
  Subject: CN=s3.amazonaws.com
  Issuer: CN=Amazon, O=Amazon, C=US
  Valid from: 2024-01-01 to 2025-01-01
  TLS Version: TLS 1.3
  Cipher Suite: TLS_AES_128_GCM_SHA256
  SANs: s3.amazonaws.com, *.s3.amazonaws.com
  Serial Number: 0A:1B:2C:3D:4E:5F
  Signature Algorithm: SHA256-RSA
  Certificate Status: Valid (180 days remaining)
  Verification: Verified
  Certificate Chain: 3 certificate(s)
    1. CN=Amazon RSA 2048 M01
    2. CN=Starfield Services Root Certificate Authority - G2
    3. CN=Starfield Root Certificate Authority - G2

[4/4] Bucket Authentication Check.................... ✓ PASS
  Auth Type: SIGV4
  Provider: AWS S3
  Endpoint: https://s3.amazonaws.com
  Bucket Exists: Yes
  Access Granted: Yes
  Status Code: 200
  Response time: 120ms

==================================================
Test Summary
==================================================
  Total: 4 | Passed: 4 | Failed: 0 | Warnings: 0

All tests passed successfully!
```

### JSON Output (Optional)

Use `--output-file results.json` to generate JSON output.

```json
{
  "config": {
    "endpoint": "https://s3.amazonaws.com",
    "bucket": "my-test-bucket",
    "region": "us-east-1",
    "authType": "sigv4",
    "pathStyle": false,
    "insecure": false,
    "timeout": 30,
    "followRedirect": true,
    "maxRedirects": 10,
    "verbose": false
  },
  "startTime": "2024-02-12T09:54:21Z",
  "endTime": "2024-02-12T09:54:22Z",
  "duration": "1.234s",
  "results": [
    {
      "testName": "DNS Resolution Check",
      "status": "PASS",
      "duration": "15ms",
      "details": {
        "ips": ["52.216.132.141", "52.216.132.85"],
        "resolutionTimeMs": 15,
        "hostname": "s3.amazonaws.com",
        "reverseDns": "s3.amazonaws.com"
      }
    },
    {
      "testName": "TCP Connectivity Check",
      "status": "PASS",
      "duration": "45ms",
      "details": {
        "host": "s3.amazonaws.com",
        "port": 443,
        "connected": true,
        "connectionTimeMs": 45,
        "localAddr": "192.168.1.100:54321",
        "remoteAddr": "52.216.132.141:443"
      }
    },
    {
      "testName": "SSL/TLS Certificate Check",
      "status": "PASS",
      "duration": "80ms",
      "details": {
        "host": "s3.amazonaws.com",
        "port": 443,
        "verified": true,
        "tlsVersion": "TLS 1.3",
        "cipherSuite": "TLS_AES_128_GCM_SHA256",
        "certificate": {
          "subject": "CN=s3.amazonaws.com",
          "issuer": "CN=Amazon, O=Amazon, C=US",
          "notBefore": "2024-01-01T00:00:00Z",
          "notAfter": "2025-01-01T00:00:00Z",
          "sans": ["s3.amazonaws.com", "*.s3.amazonaws.com"],
          "serialNumber": "0A:1B:2C:3D:4E:5F",
          "signatureAlgorithm": "SHA256-RSA",
          "dnsNames": ["s3.amazonaws.com", "*.s3.amazonaws.com"],
          "emailAddresses": [],
          "ipAddresses": [],
          "uris": [],
          "isExpired": false,
          "daysUntilExpiry": 180
        },
        "peerCerts": [
          {
            "subject": "CN=Amazon RSA 2048 M01",
            "issuer": "CN=Starfield Services Root Certificate Authority - G2",
            "notBefore": "2020-09-02T00:00:00Z",
            "notAfter": "2025-09-01T23:59:59Z",
            "sans": ["*.s3.amazonaws.com", "s3.amazonaws.com"],
            "serialNumber": "0A:1B:2C:3D:4E:5F",
            "signatureAlgorithm": "SHA256-RSA",
            "dnsNames": ["*.s3.amazonaws.com", "s3.amazonaws.com"],
            "emailAddresses": [],
            "ipAddresses": [],
            "uris": [],
            "isExpired": false,
            "daysUntilExpiry": 600
          }
        ]
      }
    },
    {
      "testName": "Bucket Authentication Check",
      "status": "PASS",
      "duration": "120ms",
      "details": {
        "success": true,
        "authType": "sigv4",
        "bucketExists": true,
        "accessGranted": true,
        "statusCode": 200,
        "responseTimeMs": 120,
        "provider": "AWS S3",
        "endpoint": "https://s3.amazonaws.com"
      }
    }
  ],
  "summary": {
    "total": 4,
    "passed": 4,
    "failed": 0,
    "warnings": 0,
    "skipped": 0
  }
}
```

### JSON Schema Reference

#### Config Object
```typescript
{
  endpoint: string;        // S3 endpoint URL
  bucket: string;          // Bucket name
  region: string;          // AWS region
  authType: string;        // "sigv4" or "sigv2"
  pathStyle: boolean;      // Path-style addressing flag
  insecure: boolean;       // Skip TLS verification
  timeout: number;         // Request timeout in seconds
  followRedirect: boolean; // Follow HTTP redirects
  maxRedirects: number;    // Maximum redirects to follow
  verbose: boolean;        // Verbose logging enabled
}
```

#### TestResult Object
```typescript
{
  testName: string;        // Name of the test
  status: "PASS" | "FAIL" | "WARN" | "SKIP";
  duration: string;        // Duration in milliseconds (e.g., "15ms")
  error?: string;          // Error message if failed
  details?: object;        // Test-specific details
}
```

#### TestSummary Object
```typescript
{
  total: number;     // Total number of tests
  passed: number;    // Number of passed tests
  failed: number;    // Number of failed tests
  warnings: number;  // Number of warnings
  skipped: number;   // Number of skipped tests
}
```

## Exit Codes

| Code | Description | When Returned |
|------|-------------|---------------|
| 0 | All tests passed | All 4 tests completed successfully |
| 1 | One or more tests failed | At least one test failed |
| 2 | Configuration error | Missing required flags or invalid configuration |
| 3 | Unexpected error | Internal error or unexpected condition |

### Using Exit Codes in Scripts

```bash
#!/bin/bash

s3tester \
  --endpoint https://s3.amazonaws.com \
  --bucket my-bucket \
  --access-key KEY \
  --secret-key SECRET

case $? in
  0) echo "All tests passed!" ;;
  1) echo "Some tests failed. Check output for details." ;;
  2) echo "Configuration error. Check your parameters." ;;
  3) echo "Unexpected error occurred." ;;
esac
```

## Remediation Suggestions

When tests fail, the tool provides specific remediation suggestions to help you diagnose and fix the issue.

### How Remediation Works

The remediation engine analyzes error messages and provides:
- **Error Description**: What went wrong
- **Root Cause**: Why the error occurred
- **Suggestion**: How to fix the issue
- **Commands**: Useful commands to diagnose the problem

### Example Remediation Output

```
==================================================
Remediation Suggestions
==================================================

DNS Resolution Check:
  Error: lookup s3.example.com: no such host
  Cause: The hostname does not exist or DNS resolution failed
  Suggestion: Verify the hostname is correct and DNS servers are properly configured
  Commands to try:
    - nslookup <hostname>
    - dig <hostname>
    - ping <hostname>

TCP Connectivity Check:
  Error: dial tcp 192.168.1.100:9000: connect: connection refused
  Cause: The target port is closed or no service is listening
  Suggestion: Verify the service is running and the correct port is specified
  Commands to try:
    - telnet <host> <port>
    - nc -zv <host> <port>
    - Check firewall rules

SSL/TLS Certificate Check:
  Error: x509: certificate signed by unknown authority
  Cause: The certificate is not trusted or self-signed
  Suggestion: Verify the certificate chain or use --insecure for testing
  Commands to try:
    - openssl s_client -connect <host>:<port> -showcerts
    - Check if using a self-signed certificate

Bucket Authentication Check:
  Error: 403 Forbidden
  Cause: Access denied - credentials may be incorrect or insufficient permissions
  Suggestion: Verify access key and secret key are correct and have proper permissions
  Commands to try:
    - Verify credentials in your S3 provider console
    - Check if bucket policy allows access
    - Verify region matches the bucket's actual region
    - Check if path-style addressing is required: s3.amazonaws.com/<bucket> vs <bucket>.s3.amazonaws.com
```

### Remediation Categories

#### DNS Issues
- Hostname not found
- DNS timeout
- DNS server refused
- DNS I/O timeout

#### TCP Issues
- Connection refused
- Connection timeout
- Network unreachable
- Host unreachable

#### TLS Issues
- Certificate not trusted
- Certificate expired
- Certificate hostname mismatch
- TLS version mismatch

#### Authentication Issues
- Invalid credentials
- Access denied
- Bucket not found
- Region mismatch
- Addressing style mismatch

## Supported Providers

The S3 Bucket Tester works with any S3-compatible storage provider. Here are some commonly tested providers:

### AWS S3
- **Endpoint**: `https://s3.amazonaws.com`
- **Regions**: All AWS regions
- **Addressing**: Virtual-hosted (default), Path-style (legacy)
- **Auth**: SigV4 (default), SigV2 (legacy)

### MinIO
- **Endpoint**: `http://localhost:9000` (default)
- **Addressing**: Path-style (recommended)
- **Auth**: SigV4
- **Notes**: Use `--path-style` flag

### Hetzner S3
- **Endpoint**: `https://your-objectstorage.com`
- **Regions**: `nbg1`, `fsn1`, `hel1`
- **Addressing**: Both styles supported
- **Auth**: SigV4

### Wasabi
- **Endpoint**: `https://s3.<region>.wasabisys.com`
- **Regions**: `us-east-1`, `us-east-2`, `us-central-1`, `us-west-1`, `eu-central-1`, `eu-west-1`, `ap-northeast-1`, `ap-northeast-2`
- **Addressing**: Virtual-hosted (default), Path-style (legacy)
- **Auth**: SigV4

### Backblaze B2
- **Endpoint**: `https://s3.<region>.backblazeb2.com`
- **Addressing**: Virtual-hosted (default), Path-style (legacy)
- **Auth**: SigV4

### DigitalOcean Spaces
- **Endpoint**: `https://<region>.digitaloceanspaces.com`
- **Regions**: `nyc3`, `ams3`, `sfo2`, `sgp1`, `fra1`, `syd1`
- **Addressing**: Virtual-hosted
- **Auth**: SigV4

### IBM Cloud Object Storage
- **Endpoint**: `https://<region>.objectstorage.cloud.ibm.com`
- **Addressing**: Virtual-hosted
- **Auth**: SigV4

### NetApp StorageGRID
- **Endpoint**: Custom endpoint
- **Addressing**: Both styles supported
- **Auth**: SigV4

### Other S3-Compatible Providers

Any provider that implements the S3 API should work. Common examples:
- Ceph RGW
- OpenStack Swift (S3 API)
- SeaweedFS S3
- Cloudflare R2
- Google Cloud Storage (S3 compatibility mode)
- Azure Blob Storage (S3 compatibility mode)

## Architecture

The S3 Bucket Tester is organized into several components:

### Component Overview

```
┌─────────────────────────────────────────────────────────┐
│                    CLI Entry Point                      │
│                    (cmd/s3tester)                        │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│                   Config Parser                          │
│              (pkg/config/flags.go)                       │
│  - Parse command-line flags                             │
│  - Validate configuration                               │
│  - Apply addressing styles                              │
└────────────────────┬────────────────────────────────────┘
                     │
        ┌────────────┼────────────┐
        ▼            ▼            ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ DNS Checker  │ │ TCP Checker  │ │ TLS Checker  │
│ (dns.go)     │ │ (tcp.go)     │ │ (tls.go)     │
│              │ │              │ │              │
│ - Resolve    │ │ - Connect    │ │ - Certificate│
│   hostnames  │ │   to port    │ │   validation │
│ - Reverse    │ │ - Measure    │ │ - TLS        │
│   DNS        │ │   latency    │ │   version    │
└──────────────┘ └──────────────┘ └──────────────┘
        │               │               │
        └───────────────┼───────────────┘
                        ▼
              ┌──────────────────┐
              │  Auth Checker    │
              │   (auth.go)      │
              │                  │
              │ - SigV4 auth     │
              │ - SigV2 auth     │
              │ - Bucket access  │
              └────────┬─────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│ Output       │ │ Remediation  │ │ Verbose      │
│ Formatter    │ │ Engine       │ │ Logger       │
│              │ │              │ │              │
│ - Console    │ │ - Analyze    │ │ - Detailed   │
│   output     │ │   errors     │ │   logging    │
│ - JSON       │ │ - Suggest    │ │ - Debug      │
│   output     │ │   fixes      │ │   info       │
└──────────────┘ └──────────────┘ └──────────────┘
```

### Package Structure

```
s3-bucket-tester/
├── cmd/
│   └── s3tester/
│       └── main.go           # CLI entry point
├── pkg/
│   ├── checker/
│   │   ├── auth.go           # Authentication checker (SigV4/SigV2)
│   │   ├── dns.go            # DNS resolution checker
│   │   ├── tcp.go            # TCP connectivity checker
│   │   ├── tls.go            # TLS certificate checker
│   │   ├── verbose.go        # Verbose logging
│   │   └── checker.go        # Base checker interface
│   ├── config/
│   │   ├── config.go         # Configuration struct and providers
│   │   └── flags.go          # Command-line flag parsing
│   ├── output/
│   │   ├── console.go        # Console output formatter
│   │   ├── json.go           # JSON output formatter
│   │   └── result.go         # Result data structures
│   └── remediation/
│       └── suggestions.go    # Remediation suggestions engine
├── build/                    # Compiled binaries
├── go.mod                    # Go module definition
├── go.sum                    # Dependency checksums
├── Makefile                  # Build commands
├── LICENSE                   # MIT License
└── README.md                 # This file
```

### Test Execution Flow

1. **Parse Configuration**: Command-line flags are parsed and validated
2. **DNS Resolution**: Hostname is resolved to IP addresses
3. **TCP Connectivity**: Connection is established to the endpoint
4. **TLS Certificate**: SSL/TLS certificate is validated
5. **Authentication**: Bucket access is tested with provided credentials
6. **Output Results**: Results are displayed in console and optionally saved to JSON
7. **Remediation**: Fix suggestions are provided for any failed tests

## Building

### Prerequisites

- Go 1.21 or higher

### Build Commands

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Build for Windows only
make build-windows

# Build for Linux only
make build-linux

# Build for macOS only (Intel)
GOOS=darwin GOARCH=amd64 go build -o build/s3tester-darwin-amd64 ./cmd/s3tester

# Build for macOS only (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o build/s3tester-darwin-arm64 ./cmd/s3tester

# Build static binary (no CGO)
make build-static

# Clean build artifacts
make clean
```

### Build Output

Binaries are placed in the `build/` directory:

| Platform | Architecture | Binary Name |
|----------|--------------|-------------|
| Windows | amd64 | `s3tester.exe` |
| Linux | amd64 | `s3tester-linux-amd64` |
| Linux | arm64 | `s3tester-linux-arm64` |
| macOS | amd64 | `s3tester-darwin-amd64` |
| macOS | arm64 | `s3tester-darwin-arm64` |

### Cross-Platform Build

The `make build-all` command builds binaries for all supported platforms:

```bash
make build-all
```

This will create:
- `build/s3tester-windows-amd64.exe`
- `build/s3tester-linux-amd64`
- `build/s3tester-linux-arm64`
- `build/s3tester-darwin-amd64`
- `build/s3tester-darwin-arm64`

## Development

### Running Tests

```bash
# Run tests
make test

# Run tests with coverage
make test-coverage
```

### Formatting and Linting

```bash
# Format code
make fmt

# Run linter (if configured)
make lint
```

### Adding New Providers

To add a new built-in provider, edit `pkg/config/config.go`:

```go
var Providers = map[string]ProviderEndpoint{
    // ... existing providers ...
    "myprovider": {
        Template:    "<bucket>.s3.myprovider.com",
        Description: "My Provider (virtual-hosted)",
    },
}
```

### Adding New Tests

To add a new test type:

1. Create a new checker in `pkg/checker/`
2. Implement the `Checker` interface
3. Add the test to `runTests()` in `cmd/s3tester/main.go`

## Troubleshooting

### Common Issues

#### "DNS Resolution Check: no such host"

**Cause**: The hostname doesn't exist or DNS is misconfigured.

**Solutions**:
- Verify the endpoint URL is correct
- Check your DNS settings
- Try using an IP address instead

#### "TCP Connectivity Check: connection refused"

**Cause**: The service is not running or the port is closed.

**Solutions**:
- Verify the S3 service is running
- Check the port number (default: 443 for HTTPS, 80 for HTTP)
- Check firewall rules

#### "SSL/TLS Certificate Check: certificate signed by unknown authority"

**Cause**: Using a self-signed certificate or untrusted CA.

**Solutions**:
- Use `--insecure` flag to skip verification (for testing only)
- Add the CA certificate to your system's trust store
- Use a valid certificate from a trusted CA

#### "Bucket Authentication Check: 403 Forbidden"

**Cause**: Invalid credentials or insufficient permissions.

**Solutions**:
- Verify access key and secret key are correct
- Check bucket policy allows access
- Verify the region matches the bucket's region
- Try the other addressing style (`--path-style` or `--virtual-hosted`)

#### "Bucket Authentication Check: 404 Not Found"

**Cause**: Bucket doesn't exist or incorrect addressing style.

**Solutions**:
- Verify bucket name is correct
- Try the other addressing style
- Check if the bucket is in a different region

#### "Bucket Authentication Check: 301 Moved Permanently"

**Cause**: Incorrect addressing style or region.

**Solutions**:
- Try using `--path-style` or `--virtual-hosted`
- Verify the region is correct
- Check if the provider requires a specific addressing style

### Verbose Mode

Enable verbose mode to get detailed debugging information:

```bash
s3tester \
  --endpoint https://s3.amazonaws.com \
  --bucket my-bucket \
  --access-key KEY \
  --secret-key SECRET \
  --verbose
```

Verbose mode shows:
- Detailed request/response information
- Authentication headers (without secrets)
- Connection details
- DNS resolution steps
- TLS handshake details

### Testing with Different Tools

#### Using curl

```bash
# Test basic connectivity
curl -I https://s3.amazonaws.com

# Test bucket access (replace with your credentials)
curl -I \
  -H "Authorization: AWS4-HMAC-SHA256 ..." \
  https://my-bucket.s3.amazonaws.com
```

#### Using awscli

```bash
# Test bucket access
aws s3 ls s3://my-bucket \
  --endpoint-url https://s3.amazonaws.com \
  --region us-east-1
```

#### Using mc (MinIO Client)

```bash
# Test MinIO connection
mc alias set myminio http://localhost:9000 minioadmin minioadmin
mc ls myminio/my-bucket
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Development Workflow

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Run tests (`make test`)
5. Commit your changes (`git commit -m 'Add amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Code Style

- Follow Go conventions and best practices
- Run `go fmt ./...` before committing
- Add tests for new features
- Update documentation as needed

## Support

For issues and questions, please open an issue on GitHub.

### Resources

- [AWS S3 Documentation](https://docs.aws.amazon.com/s3/)
- [MinIO Documentation](https://min.io/docs/minio/linux/index.html)
- [Hetzner S3 Documentation](https://docs.hetzner.com/storage/object-storage/)
- [Wasabi Documentation](https://wasabi-support.zendesk.com/hc/en-us)
- [S3 API Reference](https://docs.aws.amazon.com/AmazonS3/latest/API/Welcome.html)

### Getting Help

- Open an issue on [GitHub Issues](https://github.com/s3-bucket-tester/s3tester/issues)
- Check existing issues for similar problems
- Provide detailed error messages and configuration when reporting issues
