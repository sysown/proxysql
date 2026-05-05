# CI-mysql84-gr-g[1-9] Workflows

## Summary

Create GitHub Actions CI workflow files for MySQL 8.4 Group Replication (GR)
test groups.  Currently `mysql84-gr-g1` is the only GR subgroup defined in
`groups.json` and there are no CI workflows for any GR group.  This spec adds
CI workflows for `mysql84-gr-g1` through `mysql84-gr-g9` and populates g2–g9
with one smoke-test each.

## Architecture (confirmed by requester)

Two-branch split matching the existing pattern:

| Branch | File pattern | Role |
|--------|-------------|------|
| `v3.0` | `.github/workflows/CI-mysql84-gr-gX.yml` | Thin wrapper, references reusable on `GH-Actions` |
| `GH-Actions` | `.github/workflows/ci-mysql84-gr-gX.yml` | Reusable workflow with the actual test execution |

No new group directories or infra directories are needed. All `mysql84-gr-gN`
groups resolve to the same base group `test/tap/groups/mysql84-gr/` and the
same infrastructure `infra-dbdeployer-mysql84-gr`.

## Changes

### v3.0 branch

**New wrapper workflows** — 9 files:

`.github/workflows/CI-mysql84-gr-g1.yml` … `.github/workflows/CI-mysql84-gr-g9.yml`

Identical pattern to `CI-mysql84-g1.yml`: triggers on `CI-trigger` or
`workflow_dispatch`, delegates to `ci-mysql84-gr-gX.yml@GH-Actions`.

**Updated `groups.json`** — add `mysql84-gr-gX` to one existing test per
group (smoke-test to verify the workflow runs):

| Group | Test | Rationale |
|-------|------|-----------|
| g1 | *(already has 16 tests)* | — |
| g2 | `reg_test_3847_admin_lock-t` | Admin-level locking, backend-agnostic |
| g3 | `mysql-set_wait_timeout-t` | Basic SET variable, works on any backend |
| g4 | `deprecate_eof_cache-t` | Protocol-level EOF deprecation, backend-agnostic |
| g5 | `test_cluster1-t` | ProxySQL internal cluster, backend-agnostic |
| g6 | `prepare_statement_err3024-t` | Prepared statement error handling, backend-agnostic |
| g7 | `savepoint-948-t` | Standard savepoint SQL, works on GR |
| g8 | `test_greeting_capabilities-t` | Handshake capability parsing, backend-agnostic |
| g9 | `test_query_timeout-t` | Query timeout mechanism, backend-agnostic |

### GH-Actions branch

**New reusable workflows** — 9 files:

`.github/workflows/ci-mysql84-gr-g1.yml` … `.github/workflows/ci-mysql84-gr-g9.yml`

Based on `ci-mysql84-g1.yml` with the following substitutions:

| Workflow field | g1 value | gX value |
|----------------|----------|----------|
| `name` | `CI-mysql84-g1` | `CI-mysql84-gr-gX` |
| `env.SHA` (same) | — | — |
| `matrix.infradb` | `mysql84` | `mysql84` (cosmetic) |
| `INFRA_ID` | `ci-mysql84-g1` | `ci-mysql84-gr-gX` |
| `TAP_GROUP` | `mysql84-g1` | `mysql84-gr-gX` |
| `BLDCACHE` key suffix | `ubuntu22-tap_src` | same |
| Cache restore key | `ubuntu22-tap_test` | same |

## test selection rationale

All 9 groups share the same base group directory (`mysql84-gr/`) which
provides `env.sh` → `DEFAULT_MYSQL_INFRA=infra-dbdeployer-mysql84-gr`,
`infras.lst`, and the `pre-proxysql.bash` hook that configures ProxySQL for
Group Replication (reader/writer hostgroups, GR-aware monitor).

The selected tests are backend-agnostic: they test Admin, SET, protocol err
handling, ProxySQL cluster, prepared statements, savepoints, greeting
capabilities, and query timeouts. None depend on replication-specific
topology.

## Future work

"A lot later" — add more tests to each GR subgroup and potentially add g2–g9
for other MySQL version families (mysql90-gr, mysql95-gr, etc.).
