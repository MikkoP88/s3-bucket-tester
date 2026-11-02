package config

import (
	"errors"
	"strings"
	"testing"
)

// fakeEnv builds a getenv function from a variable map
func fakeEnv(vars map[string]string) func(string) string {
	return func(key string) string {
		return vars[key]
	}
}

// TestApplyEnvCredentials_Precedence verifies S3TESTER_* wins over AWS_*
func TestApplyEnvCredentials_Precedence(t *testing.T) {
	config := &Config{}
	config.applyEnvCredentials(fakeEnv(map[string]string{
		"S3TESTER_ACCESS_KEY":    "tool-access",
		"S3TESTER_SECRET_ACCESS_KEY": "tool-secret",
		"AWS_ACCESS_KEY_ID":      "aws-access",
		"AWS_SECRET_ACCESS_KEY":  "aws-secret",
	}))

	if config.AccessKey != "tool-access" {
		t.Errorf("expected S3TESTER_ACCESS_KEY to win, got %q", config.AccessKey)
	}
	if config.SecretKey != "tool-secret" {
		t.Errorf("expected S3TESTER_SECRET_ACCESS_KEY to win, got %q", config.SecretKey)
	}
}

// TestApplyEnvCredentials_AWSFallback verifies AWS_* fills when S3TESTER_* unset
func TestApplyEnvCredentials_AWSFallback(t *testing.T) {
	config := &Config{}
	config.applyEnvCredentials(fakeEnv(map[string]string{
		"AWS_ACCESS_KEY_ID":     "aws-access",
		"AWS_SECRET_ACCESS_KEY": "aws-secret",
	}))

	if config.AccessKey != "aws-access" {
		t.Errorf("expected AWS_ACCESS_KEY_ID fallback, got %q", config.AccessKey)
	}
	if config.SecretKey != "aws-secret" {
		t.Errorf("expected AWS_SECRET_ACCESS_KEY fallback, got %q", config.SecretKey)
	}
}

// TestApplyEnvCredentials_FlagsWin verifies values already set (from flags)
// are not overwritten by the environment
func TestApplyEnvCredentials_FlagsWin(t *testing.T) {
	config := &Config{AccessKey: "flag-access", SecretKey: "flag-secret"}
	config.applyEnvCredentials(fakeEnv(map[string]string{
		"AWS_ACCESS_KEY_ID":     "aws-access",
		"AWS_SECRET_ACCESS_KEY": "aws-secret",
	}))

	if config.AccessKey != "flag-access" {
		t.Errorf("flag value must win, got %q", config.AccessKey)
	}
	if config.SecretKey != "flag-secret" {
		t.Errorf("flag value must win, got %q", config.SecretKey)
	}
}

// TestResolveCredentials_PromptsForMissing verifies the hidden prompt fills
// credentials still missing after the environment, when stdin is a terminal
func TestResolveCredentials_PromptsForMissing(t *testing.T) {
	config := &Config{AccessKey: "flag-access"}
	var prompts []string
	promptHidden := func(prompt string) (string, error) {
		prompts = append(prompts, prompt)
		return "prompted-secret", nil
	}

	config.resolveCredentials(
		fakeEnv(nil),
		func() bool { return true },
		promptHidden,
	)

	if config.SecretKey != "prompted-secret" {
		t.Errorf("expected prompted secret, got %q", config.SecretKey)
	}
	if len(prompts) != 1 {
		t.Fatalf("expected prompt only for the missing secret, got %d prompts", len(prompts))
	}
	if !strings.Contains(prompts[0], "Secret Access Key") {
		t.Errorf("expected secret prompt, got %q", prompts[0])
	}
}

// TestResolveCredentials_NoPromptWhenComplete verifies no prompt fires when
// both credentials are already resolved
func TestResolveCredentials_NoPromptWhenComplete(t *testing.T) {
	config := &Config{AccessKey: "a", SecretKey: "s"}
	promptHidden := func(prompt string) (string, error) {
		t.Errorf("unexpected prompt: %s", prompt)
		return "", errors.New("should not be called")
	}

	config.resolveCredentials(
		fakeEnv(nil),
		func() bool { return true },
		promptHidden,
	)
}

// TestResolveCredentials_NoPromptWhenNotTerminal verifies non-interactive
// runs (CI, pipes) never block on a prompt
func TestResolveCredentials_NoPromptWhenNotTerminal(t *testing.T) {
	config := &Config{}
	promptHidden := func(prompt string) (string, error) {
		t.Errorf("unexpected prompt in non-interactive run: %s", prompt)
		return "", errors.New("should not be called")
	}

	config.resolveCredentials(
		fakeEnv(map[string]string{"AWS_ACCESS_KEY_ID": "aws-access"}),
		func() bool { return false },
		promptHidden,
	)

	if config.AccessKey != "aws-access" {
		t.Errorf("expected env access key, got %q", config.AccessKey)
	}
	if config.SecretKey != "" {
		t.Errorf("expected empty secret left for Validate to report, got %q", config.SecretKey)
	}
}

// TestValidate_MissingCredentialErrorMentionsSources verifies the error
// guides users to flags, environment, and the prompt
func TestValidate_MissingCredentialErrorMentionsSources(t *testing.T) {
	config := &Config{
		Endpoint: "https://s3.example.com",
		Bucket:   "test-bucket",
		AuthType: "sigv4",
		Timeout:  30,
	}

	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for missing credentials")
	}
	for _, want := range []string{"--access-key", "S3TESTER_ACCESS_KEY", "AWS_ACCESS_KEY_ID"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}
