package output

import (
	"encoding/json"
	"os"
	"time"
)

// PrintJSON prints the test report as JSON to a file
func PrintJSON(report *TestReport, outputFile string) error {
	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	// Write to file if specified
	if outputFile != "" {
		return os.WriteFile(outputFile, data, 0644)
	}

	// Otherwise print to stdout
	_, err = os.Stdout.Write(data)
	return err
}

// PrintJSONWithRemediation prints the test report as JSON with remediation suggestions
func PrintJSONWithRemediation(report *TestReport, outputFile string) error {
	// Create extended report with remediations
	type ExtendedTestResult struct {
		TestName      string        `json:"testName"`
		Status        Status        `json:"status"`
		Duration      string        `json:"duration"`
		Error         string        `json:"error,omitempty"`
		Details       interface{}   `json:"details,omitempty"`
		Remediation   interface{}   `json:"remediation,omitempty"`
		Warnings      []string      `json:"warnings,omitempty"`
	}

	type ExtendedTestReport struct {
		Config     Config                `json:"config"`
		StartTime  string                `json:"startTime"`
		EndTime    string                `json:"endTime"`
		Duration   string                `json:"duration"`
		Results    []ExtendedTestResult  `json:"results"`
		Summary    TestSummary           `json:"summary"`
	}

	// Convert results
	extendedResults := make([]ExtendedTestResult, len(report.Results))
	for i, result := range report.Results {
		extendedResults[i] = ExtendedTestResult{
			TestName: result.TestName,
			Status:   result.Status,
			Duration: result.Duration.String(),
			Error:    result.Error,
			Details:  result.Details,
		}
	}

	// Create extended report
	extendedReport := ExtendedTestReport{
		Config:     report.Config,
		StartTime:  report.StartTime.Format(time.RFC3339),
		EndTime:    report.EndTime.Format(time.RFC3339),
		Duration:   report.Duration.String(),
		Results:    extendedResults,
		Summary:    report.Summary,
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(extendedReport, "", "  ")
	if err != nil {
		return err
	}

	// Write to file
	return os.WriteFile(outputFile, data, 0644)
}
