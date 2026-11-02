# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Credential resolution beyond CLI flags: `S3TESTER_ACCESS_KEY`/`S3TESTER_SECRET_ACCESS_KEY`
  and `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY` environment variables, then a hidden
  interactive prompt (only when stdin is a terminal). Flags win over environment, and
  non-interactive runs never block on the prompt.
- Masked access key (`accessKey`, e.g. `AKIA…`) in JSON reports as a replacement for
  the removed plaintext fields.

### Changed

- **Security:** JSON reports no longer serialize credentials. The secret key is never
  written; the access key appears only in masked form.
- **Security:** Report files are written with owner-only permissions (`0600`), and
  pre-existing report files are tightened on rewrite.
- **Security:** Verbose logging no longer prints authentication material.
  `Authorization` headers are reduced to the signing algorithm plus a masked
  credential identifier, and SigV2/SigV4 URL authentication parameters are redacted.
- Raise Go toolchain requirement to 1.26 (`golang.org/x/term` dependency); upgrade
  `golang.org/x/sys` v0.15.0 → v0.49.0, remediating GO-2026-5024.
- `Validate()` errors and `--help` document all credential sources.

### Fixed

- Test suite repaired: all packages compile again, 46 skipped tests were replaced
  with deterministic `httptest`/generated-certificate/stub-resolver tests, live
  network calls were removed from the suite, and `go vet` is clean (IPv6-safe
  dial addressing).
- Policy parsing: array-valued `Action`/`Resource` fields and object-shaped
  principals are extracted instead of silently dropped; 403 policy/ACL responses
  populate the result error with the S3 error code.
- `ToOutputConfig()` no longer panics when `Validate()` was not called first.
- Console output renders structured principals (`CanonicalUser`, group URIs)
  instead of falling back to `*`.
- Non-constant format string in an `fmt.Errorf` call replaced with `errors.New`.

## [1.1.1] - 2026-02-16

### Added

- Bucket policy and ACL check (`--check-policy`) with comprehensive provider
  support, including a provider policy/ACL support table and per-provider
  capability warnings.

## [1.1.0] - 2026-02-14

### Added

- Verbose response body logging for the bucket authentication check.
- Provider-specific warnings and verbose debug information.

### Fixed

- DEBUG and warning messages are only printed when `--verbose` is used.

## [1.0.1] - 2026-02-13

### Fixed

- `--insecure` flag behavior and SigV2 authentication.

## [1.0.0] - 2026-02-13

### Added

- Initial release: DNS, TCP, TLS, and authentication checks for S3-compatible
  storage, with virtual-hosted and path-style addressing, built-in provider
  shortcuts, JSON reports, and remediation suggestions.
