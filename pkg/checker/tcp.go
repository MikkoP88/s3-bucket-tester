package checker

import (
	"fmt"
	"net"
	"time"

	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// TCPChecker performs TCP connectivity checks
type TCPChecker struct {
	BaseChecker
	Host    string
	Port    int
	verbose *VerboseLogger
}

// NewTCPChecker creates a new TCP checker
func NewTCPChecker(config output.Config, host string, port int) *TCPChecker {
	return &TCPChecker{
		BaseChecker: NewBaseChecker(config),
		Host:        host,
		Port:        port,
		verbose:     NewVerboseLogger(config.Verbose),
	}
}

// Name returns the name of the checker
func (c *TCPChecker) Name() string {
	return "TCP Connectivity Check"
}

// Check performs the TCP connectivity check
func (c *TCPChecker) Check() output.TestResult {
	startTime := time.Now()

	c.verbose.LogSection("Starting TCP Connectivity Check")

	result := output.TestResult{
		TestName: c.Name(),
		Status:   output.StatusPass,
		Duration: time.Since(startTime),
	}

	// Create address
	address := fmt.Sprintf("%s:%d", c.Host, c.Port)

	c.verbose.LogMessage("Attempting TCP connection to: %s", address)
	c.verbose.LogMessage("Timeout: %ds", c.Config.Timeout)

	// Set dial timeout
	timeout := time.Duration(c.Config.Timeout) * time.Second

	// Attempt connection
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		c.verbose.LogMessage("TCP connection failed: %v", err)
		result.Status = output.StatusFail
		result.Error = err.Error()
		result.Duration = time.Since(startTime)
		return result
	}
	defer conn.Close()

	c.verbose.LogMessage("TCP connection established successfully")

	// Get connection details
	localAddr := conn.LocalAddr().String()
	remoteAddr := conn.RemoteAddr().String()

	c.verbose.LogMessage("Local address: %s", localAddr)
	c.verbose.LogMessage("Remote address: %s", remoteAddr)

	// Create TCP result
	tcpResult := output.TCPResult{
		Host:           c.Host,
		Port:           c.Port,
		Connected:      true,
		ConnectionTime: time.Since(startTime).Milliseconds(),
		LocalAddr:      localAddr,
		RemoteAddr:     remoteAddr,
	}

	result.Details = tcpResult
	result.Duration = time.Since(startTime)

	c.verbose.LogMessage("TCP connection check completed in %dms", tcpResult.ConnectionTime)

	return result
}
