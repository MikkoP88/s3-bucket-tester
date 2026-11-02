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
- `--fail-on-public-read` / `--fail-on-public-write` flags: escalate public-access
  findings from WARN to FAIL (with `--check-policy`).
- `--strict` flag: exit code 1 when any test reports WARN.
- `warnings` field on test results, printed in console output.
- Signing regression tests: the exact SigV2 signature is pinned against the
  AWS-published example vector, and SigV4 keys and signatures are re-derived
  independently and validated against the wire values a test server receives.

### Changed

- **Security:** JSON reports no longer serialize credentials. The secret key is never
  written; the access key appears only in masked form.
- **Security:** HTTP redirects are no longer followed by default. Opting in with
  `--follow-redirects` restricts targets to HTTPS on the original host or its
  subdomains, preventing signed-request redirection.
- **Security:** Report files are written with owner-only permissions (`0600`), and
  pre-existing report files are tightened on rewrite.
- **Security:** Verbose logging no longer prints authentication material.
  `Authorization` headers are reduced to the signing algorithm plus a masked
  credential identifier, and SigV2/SigV4 URL authentication parameters are redacted.
- Raise Go toolchain requirement to 1.26 (`golang.org/x/term` dependency); upgrade
  `golang.org/x/sys` v0.15.0 → v0.49.0, remediating GO-2026-5024.
- `Validate()` errors and `--help` document all credential sources.
- **Security:** the authentication check passes only on an HTTP 200 response;
  unexpected 2xx responses warn, and redirects and 4xx/5xx responses fail.
- **Security:** TLS checks fail on expired or not-yet-valid certificates even
  with `--insecure`; unverified chains warn instead of passing.
- **Security:** the policy/ACL check reports public-access findings (AllUsers /
  AuthenticatedUsers grants including FULL_CONTROL, wildcard-principal Allow
  statements) as WARN; PASS requires zero findings.
- Exit code 3 now signals report-write failures (previously only a console warning).
- Request signing is consolidated into one shared signer for the authentication and
  policy checks, replacing two divergent copies of the SigV2/SigV4 logic; the
  duplicate `ParseHostname`/`ParsePort` helpers in `pkg/config` were removed.

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
- Bucket policy parsing accepts every AWS `Principal` encoding (wildcard string,
  object, array, nested structured forms); a bare wildcard no longer fails the
  whole document parse, and unparseable principals error instead of looking safe.
- TLS fallback certificate retrieval dials with the configured timeout and a
  TLS 1.2 floor instead of an unbounded TLS 1.0-capable connection; an empty
  peer certificate list fails cleanly instead of panicking.
- Bucket URL construction goes through `net/url`: `http://` endpoints, explicit
  ports and endpoint path prefixes are preserved, and TLS dials use IPv6-safe
  host/port formatting.
- **Security:** SigV2 query authentication now follows the S3 REST authentication
  specification: HMAC-SHA1 digest with Base64 encoding and the `Expires` value in
  the string-to-sign, instead of HMAC-SHA256 hex over the `Date` header (rejected
  by every S3 provider). The `Date` header is omitted on query-authenticated
  requests per the specification.
- SigV2 canonicalized resources: virtual-hosted bucket roots sign with a trailing
  slash (`/bucket/?policy`) and `response-*` header-override parameters count as
  sub-resources, matching the AWS canonicalization examples.

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
