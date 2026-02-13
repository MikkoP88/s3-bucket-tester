package checker

import (
	"github.com/s3-bucket-tester/s3tester/pkg/output"
)

// Checker defines the interface for all test checkers
type Checker interface {
	// Name returns the name of the checker
	Name() string

	// Check performs the check and returns a TestResult
	Check() output.TestResult
}

// BaseChecker provides common functionality for all checkers
type BaseChecker struct {
	Config output.Config
}

// NewBaseChecker creates a new base checker
func NewBaseChecker(config output.Config) BaseChecker {
	return BaseChecker{Config: config}
}
