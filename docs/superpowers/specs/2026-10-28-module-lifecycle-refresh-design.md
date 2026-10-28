# Refresh STOP/START safety and selective module startup

## Intent and authorization

Resume the ideas in PRs #5217 and #4960 on current `v3.0`, as requested on
2026-10-28. The maintainer accepted the proposed order (lifecycle safety, then
selective startup) and explicitly requested a proper plan and implementation.
The old PRs remain references; do not merge, close, or rewrite them as part of
local implementation. Also preserve relevant coverage from #5222 / issue #5218.

## Approach

Use two independently reviewable changes. Rebasing the old branches would carry
forward outdated lifecycle assumptions and, in #5217, an unconditional disabled
statistics-refresh block. A single combined replacement would obscure which
behavior is a bug fix and which is an optional startup feature.

1. Reproduce STOP/START and stopped-state Admin failures on the exact current
   commit, then fix the proven lifecycle defects while retaining normal runtime
   statistics refresh. Extend coverage to both Admin protocols, repeated cycles,
   concurrent clients, and initial `--no-start`.
2. Add startup-only per-protocol worker/Admin/monitor controls from #4960,
   defaulting to enabled. Authentication and hostgroup managers remain available;
   disabling workers means no worker threads, not merely no listening sockets.
   Test mixed configurations through the lifecycle established by change 1.

## Contracts

- Preserve `doc/agents/invariants.md`: in particular, core LOAD SERVERS commands
  remain successful and cannot be vetoed by disabled modules or plugin state.
- Preserve the default all-enabled behavior and the existing `--no-monitor` and
  `--no-start` switches. Command-line options override configuration settings.
- Support MySQL and PostgreSQL equally. Do not add fake empty results with the
  wrong schema, disable normal statistics refresh, or use timeout expiry as
  permission to destroy objects still used by Admin threads.
- Do not reuse or duplicate the old STOP state machine without reproducing its
  necessity. Reuse current Admin-client draining and TLS ownership mechanisms.
- Run tests against private daemons with temporary datadirs and dynamically
  allocated loopback ports; never issue STOP against an existing service.
- Keep the two production changes and their regression coverage separable in git.

## Decisions to confirm through reproduction

Current STOP waits for main-thread reload, but the newer teardown waits for all
Admin clients; inspect and reproduce any resulting circular wait. The old Admin
object is destroyed on reload, so any fix must avoid dereferencing it afterward
and must define response/session lifetime explicitly in the tests and change log.

Stopped-state queries must never access missing processors. Preserve usable Admin
configuration operations; retain existing errors for operations that already
require a running processor. Do not introduce a blanket LOAD rejection.

Selective controls are `--mysql-workers`, `--pgsql-workers`, `--mysql-admin`,
`--pgsql-admin`, `--mysql-monitor`, `--pgsql-monitor`, with corresponding top-level
boolean configuration entries. Reject invalid explicit values rather than silently
accepting misspellings. Monitor startup permission remains distinct from the
persisted runtime `monitor_enabled` setting; do not overwrite a saved false with
true during startup.

## Verification

Build a fresh DEBUG v3.1 daemon and run isolated lifecycle probes before and after
each fix. Compile changed core paths in Stable and v4.0 as resources permit.
Use focused unit coverage for option parsing and no-worker behavior where needed,
plus process-level tests proving listener/thread state and lifecycle progress.
Record exact commands, outcomes, and any limitations in the implementation plan.
