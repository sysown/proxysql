# ProxySQL Codecov Unit-Coverage Merge Design

## Problem

ProxySQL publishes two coverage streams to Codecov:

1. TAP integration workflows upload `tap-*` reports from a checkout nested at
   `proxysql/`.
2. The unit-test ASAN/GCOV workflow uploads a `unit-tests` report from a
   checkout at the workspace root.

The repository contains `codecov.yml` with the server-side fix
`proxysql/::`, which is intended to normalize the TAP paths before they are
merged with unit-test paths. The Codecov action currently auto-discovers no
configuration in these workflow layouts. The TAP coverage therefore remains
under a separate path namespace, while the unit-test baseline becomes the only
coverage for `lib/`. When the unit-test report is accepted, the project total
can fall sharply even though the unit tests themselves ran and produced LCOV.

## Goal

Ensure that every intended coverage upload explicitly loads the repository's
Codecov configuration so TAP and unit-test reports merge onto the same source
paths. Keep Codecov service outages non-blocking.

## Non-goals

- Do not change the unit-test suite, its test selection, or its coverage scope.
- Do not change the TAP coverage producer or rewrite its existing path
  normalization.
- Do not introduce a project coverage threshold.
- Do not make a Codecov outage fail a test workflow.

## Design

### Explicit configuration paths

Pass the Codecov action's `codecov_yml_path` input instead of relying on
autodiscovery:

- `.github/workflows/CI-unit-tests-asan-coverage.yml` runs from the repository
  root, so it uses `codecov.yml`.
- The 43 TAP workflows on the `GH-Actions` branch check the repository out to
  `proxysql/`, so they use `proxysql/codecov.yml`.

All existing upload flags and report paths remain unchanged. The existing
`fixes: proxysql/::` rule then maps TAP paths such as
`proxysql/lib/MySQL_Monitor.cpp` to `lib/MySQL_Monitor.cpp`, allowing Codecov to
combine them with the unit-test report.

### Failure behavior

Keep `fail_ci_if_error: false` on every upload. A Codecov API, authentication,
or processing outage may warn in the workflow but must not fail the tests.
Report generation remains the responsibility of the local coverage scripts;
this change only fixes configuration loading and report merging.

### Regression protection

Add repository-side checks for the workflow contract:

- The unit workflow explicitly references `codecov.yml`.
- TAP upload workflows explicitly reference `proxysql/codecov.yml`.
- Uploads retain `fail_ci_if_error: false`.
- The unit workflow retains the `unit-tests` flag.

Verification will also inspect a completed GitHub Actions run and Codecov API
totals to confirm that the `unit-tests` flag has nonzero sessions and that the
project report contains merged `lib/` coverage rather than only the unit-test
baseline.

## Files and branch surfaces

- Modify `.github/workflows/CI-unit-tests-asan-coverage.yml` on the `v3.0`
  change branch.
- Modify the Codecov upload blocks in the 43 Codecov workflows on the
  `GH-Actions` workflow branch. These are the reusable workflows invoked by
  the `v3.0` caller workflows.
- Add a focused workflow-contract test or validation script on `v3.0` if the
  repository's existing CI tooling can run it without adding a new parser
  dependency.

## Verification

Before implementation is handed off:

1. Validate YAML/workflow syntax and the contract checks locally.
2. Confirm no unrelated files changed.
3. Run the unit coverage workflow and at least one TAP coverage workflow.
4. Confirm both uploads report success in their logs.
5. Query Codecov for the `unit-tests` flag and project totals; verify that the
   unit flag has sessions and that `lib/` totals reflect merged TAP plus unit
   coverage.
