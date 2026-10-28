# Module Lifecycle Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the still-useful ideas of #5217 and #4960 with focused, tested changes on current v3.0.

**Architecture:** Keep current Admin-thread draining and the existing reload phases. Fix proven lifecycle defects first, then introduce startup permissions for the six worker/Admin/monitor components without removing shared authentication or hostgroup managers.

**Tech Stack:** C++17, GNU Make, DEBUG v3.1 builds; isolated process-level regression probes and the existing TAP infrastructure.

**Spec:** `docs/superpowers/specs/2026-10-28-module-lifecycle-refresh-design.md`

## Global Constraints

- Core LOAD SERVERS commands remain successful and cannot be vetoed by disabled modules or plugin state.
- Preserve all-enabled defaults, `--no-monitor`, `--no-start`, and CLI precedence over configuration.
- No blanket runtime-statistics suppression or fabricated result schemas.
- Test private daemons only; temporary datadirs and dynamically allocated loopback ports.
- Keep lifecycle and selective-startup changes independently reviewable.

## Review Focus

- STOP called by an Admin client must not wait for teardown that waits for that same client.
- Initial --no-start and post-STOP Admin reads must handle missing query processors.
- Simultaneous STOP/START and runtime queries must not outlive their Admin/module objects.
- Disabled workers must create no worker/idle threads and must not cause watchdog or shutdown hangs.
- CLI/config precedence, invalid booleans, and saved monitor_enabled=false must remain correct.

### Task 1: Establish exact baseline and regression probes

**Files:** Create `test/infra/control/test_module_lifecycle.py`; inspect `lib/Admin_Handler.cpp`, `lib/ProxySQL_Admin.cpp`, `src/main.cpp`.

**Interfaces:** Consumes an explicit ProxySQL binary path; produces bounded subprocess tests using mysql and psql clients against private daemons, with captured startup/shutdown logs on failure.

- [ ] Build baseline: `PROXYSQL31=1 make debug -j4` in the isolated worktree. Expected: DEBUG daemon built from b16ff6025, or record and resolve exact build failures.
- [ ] Add independent tests for initial --no-start runtime-query access, STOP acknowledgement/reconnect, repeated STOP/START, both Admin protocols, and concurrent runtime readers.
- [ ] Run `python3 test/infra/control/test_module_lifecycle.py src/proxysql`; record exact failing operations and daemon logs. Expected: demonstrate failures before production changes.

### Task 2: Fix reproduced lifecycle defects

**Files:** Modify `lib/Admin_Handler.cpp`, `lib/ProxySQL_Admin.cpp`, and `src/main.cpp` only where the baseline establishes necessity; add small declarations in `include/` only if required.

**Interfaces:** Consumes existing `ProxySQL_Admin::shutdown_threads()` and the Admin SQL lock helpers. Produces safe STOP response/session lifetime and stopped-state query handling for both Admin protocols.

- [ ] Resolve each reproduced failure through a targeted test: first the STOP circular wait, then processor access in --no-start/stopped state, then concurrent START/STOP behavior.
- [ ] Preserve core LOAD SERVERS behavior; test both commands while stopped. Check normal runtime statistics still refresh after START with an actual configured rule.
- [ ] Rebuild DEBUG daemon and run the full lifecycle probe. Expected: all lifecycle cases pass, no process crashes, bounded cleanup.
- [ ] Commit production fix and regression coverage separately, referencing #5186 and the prior work in #5217/#5222.

### Task 3: Implement selective module startup

**Files:** Modify `include/proxysql_glovars.hpp`, `lib/ProxySQL_GloVars.cpp`, `lib/MySQL_Thread.cpp`, `lib/PgSQL_Thread.cpp`, `lib/ProxySQL_Admin.cpp`, `src/main.cpp`; extend the lifecycle probe and add operator documentation in `doc/`.

**Interfaces:** Adds startup-only `mysql_workers`, `pgsql_workers`, `mysql_admin`, `pgsql_admin` booleans alongside existing monitor permissions. Six CLI options accept true/false or 1/0; corresponding top-level config booleans are read before CLI overrides. Disabled workers expose zero effective threads without weakening normal positive thread validation.

- [ ] Add failing coverage for each missing switch, invalid values, defaults, and CLI overriding configuration in both directions.
- [ ] Implement parsing and effective permissions, preserving `--no-monitor` compatibility and persisted monitor settings.
- [ ] Add failing mixed-mode lifecycle coverage; implement zero-worker startup/listener/watchdog/shutdown handling and selective Admin listeners.
- [ ] Run worker/Admin combinations and monitor combinations, including --no-start plus STOP/START where at least one Admin interface is available. Verify shared authentication/HGM operations still work and disabled workers remain disabled after START.
- [ ] Rebuild and run all lifecycle/module probes; document startup semantics and commit this feature separately, crediting #4960.

### Task 4: Review and prepare replacements

**Files:** Final branch diff and this plan's verification record.

**Interfaces:** Produces clean local commit ranges suitable for two replacement PRs; no merge or old-PR closure.

- [ ] Check `git diff --check`; review invariants and both protocol paths.
- [ ] Run focused tests and compile other tier paths affected by the changes; record concrete limits if full integration infrastructure is unavailable.
- [ ] Perform an independent whole-change code review, address material findings with failing-then-passing regressions.
- [ ] Report branch/commit boundaries, test evidence, and replacement PR descriptions. Publish new branches/PRs only when authorized; retain links and attribution to previous work.

## Progress and evidence

- Worktree: `/data/rene/proxysql7/.worktrees/stop-start-refresh`; branch `v3.0-5186-refresh`; base `b16ff6025`.
- Baseline DEBUG v3.1 build started from a fresh worktree with independent dependencies and objects.
