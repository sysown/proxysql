# PR 6122 Review-Fix Implementation Plan

## Objective

Resolve every valid unresolved review thread on PR 6122 without weakening the
mandatory vendored-OpenSSL or single-OpenSSL-core contracts.

## Global constraints

- OpenSSL 3.5.7 remains mandatory, vendored, static, and LFS-backed.
- The ProxySQL executable is the sole owner of the OpenSSL core.
- Runtime-loaded plugins must not embed or dynamically link another OpenSSL.
- Explicit operator CA settings take precedence over environment and platform defaults.
- Do not vendor a CA bundle.
- Do not weaken Codecov thresholds or existing CI coverage requirements.
- Use failing regression tests before behavioral fixes where practical.

## Task 1: Build and validation contracts

- Make the `test/deps` OpenSSL bridge always reevaluate the incremental
  `deps/Makefile` target without forcing connector rebuilds.
- Extend the system-OpenSSL audit to recognize compact Make assignments,
  forwarded linker selectors, `-l:` filenames, and explicit system library paths.
- Fix the LFS workflow validator's single-line checkout parsing and require
  non-persisted credentials on every validated checkout.
- Replace destructive consumer-test stub cleanup with empty-directory-only cleanup.
- Keep the build-contract and consumer-contract tests separately scoped; document
  why the existing review request to merge their scope is rejected.

## Task 2: Executable/plugin linkage ownership

- Separate executable symbol-export flags from archive force-load flags.
- Export executable symbols correctly on Darwin.
- Make the executable force-load and export the vendored static libcurl.
- Remove the GenAI plugin's embedded libcurl and resolve curl imports from the executable.
- Check all plugin-defined symbols for embedded OpenSSL sentinels, including hidden symbols.
- Check that GenAI curl imports are satisfied by executable exports.
- Add Linux fixture tests and portable Make-contract checks for Darwin flags.

## Task 3: Portable default trust store

- Preserve explicit connector `ssl_ca` and `ssl_capath` as highest priority.
- Preserve OpenSSL's `SSL_CERT_FILE` and `SSL_CERT_DIR` overrides.
- When neither is set, resolve a readable platform CA bundle/directory at runtime
  across Debian/Ubuntu, RHEL/Fedora, SUSE, FreeBSD, and macOS conventions.
- Fall back to `SSL_CTX_set_default_verify_paths()` only after platform resolution.
- Add focused tests for priority, successful resolution, and safe fallback.

## Task 4: Test correctness and documentation

- Keep the certificate-duration TAP plan consistent on version mismatch.
- Prevent test-only OpenSSL version macros from propagating to shared prerequisites.
- Clarify that `OPENSSL_ROOT_DIR` is permitted only as a fixed vendored CMake hint.
- Clarify compile-time header, runtime string, and numeric version expectations.

## Task 5: Verification and review closure

- Run the focused build-contract, consumer-contract, workflow, linkage-fixture,
  version-unit, and trust-store tests.
- Run relevant dry-run builds and a real Linux executable/GenAI plugin build.
- Run the broader control-test suite appropriate to the touched files.
- Obtain an independent final diff review.
- Commit and push only after fresh verification, then reply to or resolve review
  threads with the implemented disposition.
