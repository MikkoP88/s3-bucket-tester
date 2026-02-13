package checker

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"strings"
)

// VerboseLogger handles verbose logging for HTTP requests and responses
type VerboseLogger struct {
	enabled bool
}

// NewVerboseLogger creates a new verbose logger
func NewVerboseLogger(enabled bool) *VerboseLogger {
	return &VerboseLogger{enabled: enabled}
}

// LogRequest logs the HTTP request details
func (v *VerboseLogger) LogRequest(req *http.Request) {
	if !v.enabled {
		return
	}

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("HTTP REQUEST")
	fmt.Println(strings.Repeat("=", 70))

	// Dump request
	dump, err := httputil.DumpRequestOut(req, false)
	if err == nil {
		fmt.Println(string(dump))
	} else {
		// Fallback to manual logging
		fmt.Printf("%s %s %s\n", req.Method, req.URL.String(), req.Proto)
		fmt.Printf("Host: %s\n", req.Host)
		for key, values := range req.Header {
			for _, value := range values {
				fmt.Printf("%s: %s\n", key, value)
			}
		}
	}

	fmt.Println(strings.Repeat("-", 70))
}

// LogResponse logs the HTTP response details
func (v *VerboseLogger) LogResponse(resp *http.Response) {
	if !v.enabled {
		return
	}

	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println("HTTP RESPONSE")
	fmt.Println(strings.Repeat("=", 70))

	// Read and store body for logging
	var bodyBytes []byte
	if resp.Body != nil {
		bodyBytes, _ = io.ReadAll(resp.Body)
		resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// Dump response
	dump, err := httputil.DumpResponse(resp, false)
	if err == nil {
		fmt.Println(string(dump))
	} else {
		// Fallback to manual logging
		fmt.Printf("%s %s\n", resp.Proto, resp.Status)
		for key, values := range resp.Header {
			for _, value := range values {
				fmt.Printf("%s: %s\n", key, value)
			}
		}
	}

	// Log body if present
	if len(bodyBytes) > 0 {
		fmt.Println("\nResponse Body:")
		fmt.Println(strings.Repeat("-", 70))
		// Limit body output for readability
		bodyStr := string(bodyBytes)
		if len(bodyStr) > 2000 {
			fmt.Println(bodyStr[:2000] + "\n... (truncated, " + fmt.Sprintf("%d", len(bodyStr)) + " bytes total)")
		} else {
			fmt.Println(bodyStr)
		}
	}

	fmt.Println(strings.Repeat("=", 70))
}

// LogMessage logs a general message
func (v *VerboseLogger) LogMessage(format string, args ...interface{}) {
	if !v.enabled {
		return
	}
	fmt.Printf("\n[VERBOSE] "+format+"\n", args...)
}

// LogSection logs a section header
func (v *VerboseLogger) LogSection(title string) {
	if !v.enabled {
		return
	}
	fmt.Println("\n" + strings.Repeat("=", 70))
	fmt.Println(title)
	fmt.Println(strings.Repeat("=", 70))
}
