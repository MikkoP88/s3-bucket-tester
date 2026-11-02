package config

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// Credential environment variables. Tool-specific S3TESTER_* variables take
// precedence over the standard AWS_* ones so a shared AWS environment can be
// overridden per tool.
const (
	envAccessKey    = "S3TESTER_ACCESS_KEY"
	envSecretKey    = "S3TESTER_SECRET_ACCESS_KEY"
	envAWSAccessKey = "AWS_ACCESS_KEY_ID"
	envAWSSecretKey = "AWS_SECRET_ACCESS_KEY"
)

// ResolveCredentials fills in credentials missing after flag parsing, in
// order: environment variables, then a hidden terminal prompt (only when
// stdin is an interactive terminal, so CI and piped runs never block).
func (c *Config) ResolveCredentials() {
	c.resolveCredentials(os.Getenv, stdinIsTerminal, hiddenPrompt)
}

// resolveCredentials is the testable core of ResolveCredentials.
func (c *Config) resolveCredentials(getenv func(string) string, isTerminal func() bool, promptHidden func(string) (string, error)) {
	c.applyEnvCredentials(getenv)
	if isTerminal != nil && promptHidden != nil && (c.AccessKey == "" || c.SecretKey == "") && isTerminal() {
		c.promptForMissingCredentials(promptHidden)
	}
}

// applyEnvCredentials fills missing credentials from environment variables
// (S3TESTER_* first, then AWS_*). Values already set from flags win.
func (c *Config) applyEnvCredentials(getenv func(string) string) {
	if c.AccessKey == "" {
		c.AccessKey = firstNonEmpty(getenv(envAccessKey), getenv(envAWSAccessKey))
	}
	if c.SecretKey == "" {
		c.SecretKey = firstNonEmpty(getenv(envSecretKey), getenv(envAWSSecretKey))
	}
}

// promptForMissingCredentials prompts on the terminal for credentials still
// missing. promptHidden is expected to read a hidden value (x/term.ReadPassword).
func (c *Config) promptForMissingCredentials(promptHidden func(string) (string, error)) {
	if c.AccessKey == "" {
		if v, err := promptHidden("Access Key ID: "); err == nil {
			c.AccessKey = strings.TrimSpace(v)
		}
	}
	if c.SecretKey == "" {
		if v, err := promptHidden("Secret Access Key: "); err == nil {
			c.SecretKey = strings.TrimSpace(v)
		}
	}
}

// stdinIsTerminal reports whether stdin is an interactive terminal.
func stdinIsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// hiddenPrompt writes the prompt to stderr (keeping stdout parseable) and
// reads a hidden value from the terminal.
func hiddenPrompt(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Fprintln(os.Stderr)
	return string(secret), nil
}

// firstNonEmpty returns the first non-empty value.
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
