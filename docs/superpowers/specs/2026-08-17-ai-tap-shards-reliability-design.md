# AI TAP Shards Reliability Design

## Purpose

PR #6107 will become the consolidated repair for the GenAI/MCP failures exposed
by `CI-ai-g1` and `CI-ai-g2` under the label-selected ASAN build. The work covers
the complete configuration and test-execution contract represented by parent
issue #6098, rather than stopping after the first variable-initialization defect
in #6099.

The final pull request must make the two AI shards trustworthy: a green result
means every declared test was present and passed, while a missing, stale, or
broken test remains a visible failure. MySQL 9.0 and 9.5 binlog-reader failures
are unrelated and remain outside this design.

## Non-Negotiable Test Visibility

The 22 entries currently assigned to `ai-g1` and the 22 entries currently
assigned to `ai-g2` remain registered. No test may be removed, silently omitted,
or converted into an unconditional skip to make CI green.

For an unfiltered shard run, the harness must reconcile all of these counts:

- 22 tests declared by `groups.json`;
- 22 corresponding executable test programs discovered across the configured
  TAP work directories;
- 22 programs executed;
- 22 programs passed.

Any mismatch is a hard failure that lists the exact missing, skipped, or failed
programs. Developer runs that explicitly select tests with include/exclude or
shuffle controls validate the selected subset instead of requiring all 22.

Tests whose assumptions refer to deleted helpers or obsolete interfaces are
updated to exercise the supported replacement. Compatibility aliases are not
added to production merely to preserve an obsolete test vocabulary.

## Observed Failure Layers

The failures form a single ordered contract:

1. A fresh plugin database lacked canonical `mcp-*` and `genai-*` rows, making
   `SET` an ineffective update. The existing #6107 commits repair this layer by
   seeding missing defaults without overwriting operator values.
2. Once `SET mcp-enabled=true` works, the MCP listener starts, but common health
   probes omit bearer authentication and several tests disagree with the group
   TLS configuration.
3. `LOAD MCP VARIABLES TO RUNTIME` changes plugin state without publishing the
   active MCP snapshot in `runtime_global_variables`.
4. Shell tests depend on a deleted helper, a host-only loopback address, a path
   excluded from the AI sparse checkout, or an unavailable `sqlite3` CLI.
5. GenAI, NL2SQL, and vector tests assert obsolete names, schemas, timing order,
   or model-dependent similarity outcomes.
6. Eleven GenAI unit tests remain declared in the groups but are intentionally
   not built by the central GenAI handoff, and the harness currently validates
   only executables it happened to discover.

Fixing only an earlier layer leaves the same test program failing at the next
layer. PR #6107 therefore covers all six layers and validates them together.

## Runtime Variable Contract

Plugin startup continues to seed missing MCP and GenAI defaults into configdb
and admindb using transactional `INSERT OR IGNORE`. Existing operator values
remain authoritative, retries are idempotent, and any failed seed transaction
rolls back.

`LOAD MCP VARIABLES TO RUNTIME` gains a second, atomic publication step:

1. Read and validate the complete MCP configuration from admindb.
2. Apply it to the plugin's runtime handler.
3. In a transaction on admindb, replace the `mcp-*` rows in
   `runtime_global_variables` with values read back from the successfully loaded
   handler.
4. Commit the runtime view only after every row has been bound and inserted.

If validation, handler application, SQL preparation, binding, stepping, or
commit fails, the command reports failure and must not expose a partially
updated runtime view. Repeated loads replace old MCP rows without duplicates.
Unrelated runtime variables are untouched.

The same helper used by the admin command is exercised through the real plugin
lifecycle unit fixture. Tests cover initial publication, changed values,
repeated load, and rollback behavior.

## Canonical MCP Test Configuration

The AI group owns a canonical MCP baseline that is saved to disk and restored by
the existing per-test ProxySQL reconfiguration:

- MCP listens on the environment-provided port, normally 6071;
- HTTP is the default transport for integration tests;
- both config and query endpoints receive an explicit, non-empty test bearer
  token;
- MySQL and PostgreSQL target/auth profiles use the isolated infrastructure
  hostnames and credentials;
- MCP is enabled only after variables and profiles are complete.

The token is exported through the AI group environment so C++, shell, and
helper-based clients share one source of truth. Tests that exercise negative
authentication temporarily replace or clear the token and restore the
canonical baseline before exit. Tests that exercise TLS explicitly opt into it
for that case and restore HTTP afterward.

`MCPClient::check_server()` continues to probe `/mcp/config`, but it sends the
same `Authorization: Bearer ...` header as normal tool calls when a token is
configured. Its response check uses the HTTP/JSON-RPC result rather than a
substring that cannot distinguish authentication and protocol failures. Client
unit coverage proves that authenticated readiness includes the header and that
missing or incorrect credentials remain rejected by endpoint tests.

## Maintained Integration Tests

The existing test names and shard memberships remain stable while their
internals are aligned with the supported interfaces:

- `genai_module-t` validates canonical GenAI variables, loading, saving, and
  persistence instead of the removed `genai-var1`/`genai-var2` sample surface.
- `mcp_runtime_variables-t` validates exact MCP runtime projection and reload
  behavior rather than tolerating an absent view.
- MCP concurrency, query, stats, and show tests use the canonical authenticated
  client/setup and leave the shared runtime state recoverable.
- `nl2sql_unit_base-t` uses the names exported by the current GenAI variable
  handler and validates their current defaults and accepted values.
- `vector_features-t` addresses the current vector store schema and APIs rather
  than removed `ai_*` columns.
- `vector_db_performance-t` retains representative small/medium/large workloads
  but replaces relative timing and model-semantic assertions with deterministic
  insert/search correctness, result-shape, and bounded-completion assertions.

The four shell tests keep their current registered names. A maintained helper is
provided at the shared path they source. It centralizes TAP output, admin SQL,
authenticated MCP calls, endpoint readiness, and environment-derived host/port
selection. The Claude headless fixture uses `proxysql`, not container-local
`127.0.0.1`, and validates a repository-owned test configuration without
requiring a real external Claude invocation. Tests needing SQLite use Python's
standard `sqlite3` module, already present in the runner, rather than adding an
undeclared CLI dependency. Required MCP fixtures live under paths already
included in the AI checkout/handoff.

Missing prerequisites fail once with a precise message identifying the path,
command, or environment value; they do not cascade into misleading endpoint
failures.

## Complete GenAI Unit-Test Handoff

The eleven GenAI unit programs registered in `ai-g1` or `ai-g2` must survive the
central build handoff. The reusable workflow deliberately sets
`SKIP_GENAI_UNIT_TESTS=1` to protect disk-constrained runners, so the source-side
build introduces a narrowly scoped AI-shard target instead of re-enabling all
fourteen large GenAI unit binaries for every ProxySQL 4.0 matrix variant.

For the ProxySQL 4.0 GCOV TAP build, that target:

1. compiles the common GenAI implementation objects once with the build's
   sanitizer/coverage/debug flags instead of compiling 30-plus sources once per
   test;
2. links only the eleven unit programs declared by the AI shards, sequentially
   to cap peak disk and memory usage;
3. stages the resulting executables in a regular `tap_tests_*` work directory
   under `test/tap/`, outside the workflow's broad deletion of
   `test/tap/tests/unit/*-t`;
4. preserves symbols needed for sanitizer diagnostics while using compressed
   debug information where supported;
5. emits and verifies a manifest naming every staged program before the test
   handoff is packed.

The test runner discovers that staged work directory through its existing
`tap_tests_*` mechanism. The manifest is also checked against `groups.json`, so
adding a future GenAI unit test to an AI shard without updating the build
contract fails during the central build rather than disappearing from CI.

## Harness Reconciliation

`proxysql-tester.py` accumulates discovery and result state across every regular
TAP work directory before validating a group. It compares the union of
discovered basenames with the group members selected after version and explicit
developer filters.

The summary distinguishes:

- declared and executed successfully;
- declared and executed unsuccessfully;
- declared but missing from the handoff;
- explicitly filtered by a developer;
- unexpected duplicate executables with the same basename.

Missing and duplicate programs are failures in an unfiltered CI shard.
Validation no longer limits expectations to the binaries found in the current
directory, which is the behavior that hid the eleven missing GenAI tests.

## Error Handling and Isolation

All SQL changes are checked and transactional at the narrowest database
boundary. Test helpers report transport, HTTP authentication, JSON-RPC, and MCP
tool errors separately so a refused request is not mislabeled as an absent
listener.

Each integration test starts from the disk-backed canonical group configuration
that the harness reloads before execution. Tests modifying MCP variables,
profiles, rules, or endpoint tokens use scoped cleanup paths that run on both
success and failure. The group cleanup hook remains a final safety net, not the
primary isolation mechanism.

No production behavior is weakened to accommodate tests: endpoint tokens remain
mandatory, negative authentication remains covered, and TLS verification is
changed only in test clients using locally generated certificates.

## Verification

Implementation follows a red-green cycle for each boundary:

- lifecycle unit regression for startup seeding and runtime projection;
- MCP client unit regression proving authenticated readiness requests;
- group setup contract tests for transport, token, host, and profile values;
- shell-test fixture tests for helper availability and environment-derived
  targets;
- harness tests proving missing and duplicate group executables fail;
- Makefile/handoff contract tests proving all eleven AI GenAI unit executables
  are staged without enabling the three unrelated GenAI unit programs;
- focused local execution of every repaired integration test through
  `run-tests-isolated.bash`;
- full local or CI execution of `ai-g1` and `ai-g2`, each reporting 22/22;
- final label-selected ASAN CI run with no sanitizer diagnostics.

Adjacent GenAI plugin unit suites and the normal non-ASAN build remain green.
The existing `CI-unit-tests-asan-coverage` workflow is not changed.

## Pull Request and Issue Scope

PR #6107 is retitled and rewritten after the consolidated implementation is
coherent. It covers parent #6098 and work items #6099 through #6103, plus the
applicable failures recorded in #5531 through #5533. An older issue is closed
only if all of its recorded failures are actually resolved; otherwise the PR
links the addressed portion and leaves the residual issue open.

The final PR description reports exact per-shard execution totals, targeted test
totals, sanitizer status, and any external behavior intentionally left for a
separate scope. MySQL 9.0/9.5 binlog-reader readiness is explicitly identified
as unrelated and is neither modified nor claimed as fixed.
