# MySQL 8.4 Binlog Reader Coverage Design

## Purpose

Make the existing real binlog-reader TAP workload contribute daemon GCOV data
to Codecov.  The workload must keep using `mysql84-binlog-g1` and its
`infra-dbdeployer-mysql84-binlog` topology, which starts the actual
`proxysql_binlog_reader` processes used through the configured GTID ports.

## Workflow contract

Follow the established group-name convention:

- The v3.0 caller is named `CI-mysql84-binlog-g1` and delegates to
  `ci-mysql84-binlog-g1.yml` on the `GH-Actions` branch.
- The reusable workflow checks out the triggering SHA, restores the existing
  `ubuntu24-tap-genai-gcov` build handoff, sets `TAP_GROUP=mysql84-binlog-g1`
  and `COVERAGE=1`, and uses the normal isolated runner.
- It requires the generated `ci_infra_logs/ci-mysql84-binlog-g1/coverage-report/`
  LCOV file to be non-empty before uploading that single file to Codecov.
- The Codecov name identifies the binlog TAP group, while the shared
  `integration-tests` flag allows it to merge with other daemon TAP uploads.

## Scope boundaries

This does not move `test_binlog_reader-t` into a non-binlog group and does not
replace its traffic with a synthetic helper.  The existing TAP workload is the
coverage source.  The feature is delivered as two linked pull requests because
the caller lives on v3.0 while reusable workflows live on `GH-Actions`.

## Verification

The existing group-registration lints must recognize the group.  A focused
local `mysql84-binlog-g1` run with `COVERAGE=1` must pass the binlog-reader TAP
and produce a non-empty LCOV report.  The reusable workflow is validated with
the existing Codecov workflow validator and static YAML checks.
