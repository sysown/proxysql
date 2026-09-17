# PR 6151 Review Remediation Design

## Scope

Resolve the actionable review findings on PR 6151 without changing the
`mysql-server_version_by_interface` contract. The catalog remains loosely
correlated with `mysql-interfaces`, exact token matches override the scalar
`mysql-server_version`, and unmatched listeners use the scalar fallback.

## Chosen Approach

Validate the complete initial-handshake payload as a `size_t` before assigning
it to MySQL's 24-bit packet-length field. Reject only payloads larger than the
protocol maximum (`0xFFFFFF`); do not introduce an arbitrary version-string
limit. This protects both the existing scalar variable and the new per-interface
catalog while preserving every configuration that can be represented on the
wire.

The rejected alternatives are a small global version-string cap, which would
break existing scalar configurations without a protocol reason, and validating
only catalog values, which would leave the existing scalar path vulnerable.

## Test Resource Ownership

The self-launching TAP test will create its runtime directory atomically with
`mkdtemp` and give cleanup to an RAII owner immediately. Every return path,
including partial setup failures, will therefore remove the directory. The
connection helper in the dollar-quote regression test will close an initialized
MySQL handle before returning a failed connection.

Test-only listener tokens that are merely unordered-map keys will use a neutral
non-temporary path. This removes misleading static-analysis findings without
changing the behavior under test.

## Lint Contracts

The repository-owned lint runner will:

- fail early with an actionable message when `envsubst` is unavailable;
- execute the pre-push hook contract test as part of the canonical suite; and
- document the `gettext`/`gettext-base` dependency.

The hook contract will compare canonical physical paths so that macOS's
`/var` to `/private/var` resolution does not produce a false failure. Coverage
toolchain validation will match actual workflow `run:` entries and actual
runner invocations rather than accepting comments or unrelated strings.

The lint workflow will declare read-only contents permission explicitly.

## Documentation Corrections

Existing implementation-plan headings will use a valid Markdown hierarchy, and
the socket listener example will consistently expect `8.1.4`, matching the
implemented exact-token mapping.

## Verification

Regression tests will first demonstrate the missing packet-boundary rejection
and lint-contract gaps. Focused protocol/unit and shell tests will then pass,
followed by the complete repository lint runner and the relevant PROXYSQL31
build/test targets. The final diff will be checked against every review thread;
incorrect `/tmp` map-key findings will be resolved by the neutral test tokens,
not by production-code changes.
