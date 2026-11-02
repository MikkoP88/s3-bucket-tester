package output

import (
	"encoding/json"
	"os"
	"time"
)

// writeReportFile writes report data with owner-only permissions. The extra
// Chmod also tightens report files that already exist with looser modes.
func writeReportFile(outputFile string, data []byte) error {
	f, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(outputFile, 0600)
}

// PrintJSON prints the test report as JSON to a file
func PrintJSON(report *TestReport, outputFile string) error {
	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	// Write to file if specified
	if outputFile != "" {
		return writeReportFile(outputFile, data)
	}

	// Otherwise print to stdout
	_, err = os.Stdout.Write(data)
	return err
}

// PrintJSONWithRemediation prints the test report as JSON with remediation suggestions
func PrintJSONWithRemediation(report *TestReport, outputFile string) error {
	// Create extended report with remediations
	type ExtendedTestResult struct {
		TestName    string      `json:"testName"`
		Status      Status      `json:"status"`
		Duration    string      `json:"duration"`
		Error       string      `json:"error,omitempty"`
		Details     interface{} `json:"details,omitempty"`
		Remediation interface{} `json:"remediation,omitempty"`
		Warnings    []string    `json:"warnings,omitempty"`
	}

	type ExtendedTestReport struct {
		Config    Config               `json:"config"`
		StartTime string               `json:"startTime"`
		EndTime   string               `json:"endTime"`
		Duration  string               `json:"duration"`
		Results   []ExtendedTestResult `json:"results"`
		Summary   TestSummary          `json:"summary"`
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
		Config:    report.Config,
		StartTime: report.StartTime.Format(time.RFC3339),
		EndTime:   report.EndTime.Format(time.RFC3339),
		Duration:  report.Duration.String(),
		Results:   extendedResults,
		Summary:   report.Summary,
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(extendedReport, "", "  ")
	if err != nil {
		return err
	}

	// Write to file
	return writeReportFile(outputFile, data)
}
