package config

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/s3-bucket-tester/s3tester/pkg/checker"
)

// ParseFlags parses command-line flags and returns the configuration
func ParseFlags(args []string) (*Config, error) {
	config := GetDefaultConfig()

	// Parse flags
	for i := 0; i < len(args); i++ {
		arg := args[i]

		switch {
		case arg == "--help" || arg == "-h":
			printHelp()
			os.Exit(0)
		case arg == "--version":
			fmt.Println("s3-bucket-tester version 1.0.0")
			os.Exit(0)
		case arg == "--endpoint":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--endpoint requires a value")
			}
			value := args[i+1]
			// Check if value is a built-in provider name
			if _, ok := Providers[value]; ok {
				config.Provider = value
			} else {
				config.Endpoint = value
			}
			i++
		case arg == "--bucket":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--bucket requires a value")
			}
			config.Bucket = args[i+1]
			i++
		case arg == "--access-key":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--access-key requires a value")
			}
			config.AccessKey = args[i+1]
			i++
		case arg == "--secret-key":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--secret-key requires a value")
			}
			config.SecretKey = args[i+1]
			i++
		case arg == "--region":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--region requires a value")
			}
			config.Region = args[i+1]
			i++
		case arg == "--auth-type":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--auth-type requires a value")
			}
			config.AuthType = args[i+1]
			i++
		case arg == "--insecure":
			config.Insecure = true
		case arg == "--timeout":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--timeout requires a value")
			}
			var timeout int
			fmt.Sscanf(args[i+1], "%d", &timeout)
			config.Timeout = timeout
			i++
		case arg == "--output-file":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--output-file requires a value")
			}
			config.OutputFile = args[i+1]
			i++
		case arg == "--follow-redirects":
			config.FollowRedirect = true
		case arg == "--no-redirects":
			config.FollowRedirect = false
		case arg == "--max-redirects":
			if i+1 >= len(args) {
				return nil, fmt.Errorf("--max-redirects requires a value")
			}
			var maxRedirects int
			fmt.Sscanf(args[i+1], "%d", &maxRedirects)
			config.MaxRedirects = maxRedirects
			i++
		case arg == "--verbose":
			config.Verbose = true
		case arg == "--virtual-hosted":
			config.VirtualHosted = true
		case arg == "--path-style":
			config.PathStyle = true
		case strings.HasPrefix(arg, "--"):
			return nil, fmt.Errorf("unknown flag: %s", arg)
		}
	}

	// Auto-detect port from endpoint
	if config.Endpoint != "" {
		config.Port = checker.ParsePort(config.Endpoint)
	}

	return config, nil
}

// printHelp prints the help message
func printHelp() {
	fmt.Println(`S3 Bucket Tester - Test S3-compatible storage providers

USAGE:
    s3tester [FLAGS]

REQUIRED FLAGS:
    --bucket <name>        Bucket name to test
    --access-key <key>     Access key ID
    --secret-key <key>     Secret access key

ENDPOINT FLAGS (required):
    --endpoint <url>       S3 endpoint URL or built-in provider shortcut

    Built-in providers (use with --endpoint):
        aws                    <bucket>.s3.<region>.amazonaws.com
        aws-legacy             s3.<region>.amazonaws.com/<bucket>
        wasabi                 <bucket>.s3.<region>.wasabisys.com
        wasabi-legacy          s3.<region>.wasabisys.com/<bucket>
        b2                     <bucket>.s3.<region>.backblazeb2.com
        b2-legacy              s3.<region>.backblazeb2.com/<bucket>
        ibm                    <bucket>.<region>.objectstorage.cloud.ibm.com
        do                     <bucket>.<region>.digitaloceanspaces.com

    Custom endpoint examples:
        https://s3.example.com
        http://localhost:9000
        s3.example.com
        s3.example.com:9000
        192.168.1.10:8080

ADDRESSING STYLE FLAGS:
    --virtual-hosted        Use virtual-hosted addressing (default)
                            URL format: https://<bucket>.<endpoint>
    --path-style            Use path-style addressing
                            URL format: https://<endpoint>/<bucket>

OPTIONAL FLAGS:
    --region <region>      AWS region (default: us-east-1)
    --auth-type <type>     Authentication type: sigv4 or sigv2 (default: sigv4)
    --insecure             Skip TLS certificate verification (not recommended)
    --timeout <seconds>    Request timeout in seconds (default: 30)
    --output-file <file>   Save JSON output to file
    --follow-redirects     Follow HTTP redirects (default: true)
    --no-redirects         Do not follow HTTP redirects
    --max-redirects <n>    Maximum redirects to follow (default: 10)
    --verbose              Enable verbose output
    --help, -h             Show this help message
    --version              Show version information

EXAMPLES:
    # Using built-in provider (AWS)
    s3tester --endpoint aws --region us-east-1 \
             --bucket my-bucket \
             --access-key KEY \
             --secret-key SECRET

    # Using custom insecure endpoint
    s3tester --endpoint 192.168.0.10:9000 \
             --bucket my-bucket \
             --access-key KEY \
             --secret-key SECRET \
             --insecure

    # Using path-style addressing
    s3tester --endpoint s3.example.com \
             --bucket my-bucket \
             --access-key KEY \
             --secret-key SECRET \
             --path-style

    # With JSON output
    s3tester --endpoint aws --region us-east-1 \
             --bucket my-bucket \
             --access-key KEY \
             --secret-key SECRET \
             --output-file results.json

    # Using SigV2 authentication
    s3tester --endpoint s3.example.com:9000 \
             --bucket my-bucket \
             --access-key KEY \
             --secret-key SECRET \
             --auth-type sigv2`)
}

// ListProviders prints all available built-in providers
func ListProviders() {
	fmt.Println("Built-in providers:")
	fmt.Println()

	// Sort provider names
	var names []string
	for name := range Providers {
		names = append(names, name)
	}
	sort.Strings(names)

	// Print providers
	for _, name := range names {
		provider := Providers[name]
		fmt.Printf("  %-15s  %s\n", name, provider.Description)
	}
}
