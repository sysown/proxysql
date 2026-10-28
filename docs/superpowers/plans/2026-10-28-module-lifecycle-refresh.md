# Module Lifecycle Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

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

- [x] Build baseline: `PROXYSQL31=1 make debug -j4` in the isolated worktree. Expected: DEBUG daemon built from b16ff6025, or record and resolve exact build failures.
- [x] Add independent tests for initial --no-start runtime-query access, STOP acknowledgement/reconnect, repeated STOP/START, both Admin protocols, and concurrent runtime readers.
- [x] Run `python3 test/infra/control/test_module_lifecycle.py src/proxysql`; record exact failing operations and daemon logs. Expected: demonstrate failures before production changes.

### Task 2: Fix reproduced lifecycle defects

**Files:** Modify `lib/Admin_Handler.cpp`, `lib/ProxySQL_Admin.cpp`, and `src/main.cpp` only where the baseline establishes necessity; add small declarations in `include/` only if required.

**Interfaces:** Consumes existing `ProxySQL_Admin::shutdown_threads()` and the Admin SQL lock helpers. Produces safe STOP response/session lifetime and stopped-state query handling for both Admin protocols.

- [x] Resolve each reproduced failure through a targeted test: first the STOP circular wait, then processor access in --no-start/stopped state, then concurrent START/STOP behavior.
- [x] Preserve core LOAD SERVERS behavior; test both commands while stopped. Check normal runtime statistics still refresh after START with an actual configured rule.
- [x] Rebuild DEBUG daemon and run the full lifecycle probe. Expected: all lifecycle cases pass, no process crashes, bounded cleanup.
- [x] Commit production fix and regression coverage separately, referencing #5186 and the prior work in #5217/#5222.

### Task 3: Implement selective module startup

**Files:** Modify `include/proxysql_glovars.hpp`, `lib/ProxySQL_GloVars.cpp`, `lib/MySQL_Thread.cpp`, `lib/PgSQL_Thread.cpp`, `lib/ProxySQL_Admin.cpp`, `src/main.cpp`; extend the lifecycle probe and add operator documentation in `doc/`.

**Interfaces:** Adds startup-only `mysql_workers`, `pgsql_workers`, `mysql_admin`, `pgsql_admin` booleans at the `ProxySQL_GlobalVariables` class tail to preserve existing field offsets; existing monitor permissions stay in `global`. Six CLI options accept true/false or 1/0; corresponding top-level config booleans are read before CLI overrides. Disabled workers expose zero effective threads without weakening normal positive thread validation.

- [x] Add failing coverage for each missing switch, invalid values, defaults, and CLI overriding configuration in both directions.
- [x] Implement parsing and effective permissions, preserving `--no-monitor` compatibility and persisted monitor settings.
- [x] Add failing mixed-mode lifecycle coverage; implement zero-worker startup/listener/watchdog/shutdown handling and selective Admin listeners.
- [x] Run worker/Admin combinations and monitor combinations, including --no-start plus STOP/START where at least one Admin interface is available. Verify shared authentication/HGM operations still work and disabled workers remain disabled after START.
- [x] Rebuild and run all lifecycle/module probes; document startup semantics and commit this feature separately, crediting #4960.

### Task 4: Review and prepare replacements

**Files:** Final branch diff and this plan's verification record.

**Interfaces:** Produces clean local commit ranges suitable for two replacement PRs; no merge or old-PR closure.

- [x] Check `git diff --check`; review invariants and both protocol paths.
- [x] Run focused tests and compile other tier paths affected by the changes; record concrete limits if full integration infrastructure is unavailable.
- [x] Perform an independent whole-change code review, address material findings with failing-then-passing regressions.
- [ ] Report branch/commit boundaries, test evidence, and replacement PR descriptions. Publish new branches/PRs only when authorized; retain links and attribution to previous work.

## Progress and evidence

- Worktree: `/data/rene/proxysql7/.worktrees/stop-start-refresh`; branch `v3.0-5186-refresh`; base `b16ff6025`.
- Baseline DEBUG v3.1 build started from a fresh worktree with independent dependencies and objects.


## Validation and implementation decisions

Baseline on b16ff6025 reproduced eight absent-query-processor crashes across the
two Admin protocols, STOP timeouts on both protocols, and NULL stopped-state
Prometheus output. The six lifecycle tests passed after the fixes. The module
suite now contains eleven tests, including all sixteen worker/Admin combinations
(with idle threads), all four monitor permissions through STOP/START, initial
no-start with mixed permissions, graceful shutdown, CLI/config precedence,
invalid input, and repeated option handling.

Two local branch boundaries preserve separate review:

- `v3.0-5186-refresh`: lifecycle fix and its regression probe.
- `v3.0-4951-refresh`: selective startup, documentation, expanded process probes,
  and the registered legacy-layout unit test; stacked on the lifecycle branch.

Material decisions:

- STOP acknowledges the request asynchronously and disconnects existing Admin
  clients during reload. Waiting synchronously deadlocks against client draining;
  callers reconnect to the rebuilt Admin interface before continuing.
- Monitor objects are constructed before Admin accepts connections so stopped
  LOAD SERVERS keeps succeeding. This moves data allocation earlier, but does
  not start monitor threads before START.
- Startup monitor permissions do not overwrite persisted `monitor_enabled`.
  Shared Auth/HGM objects remain available when workers are disabled.
- All occurrences of a component CLI option are validated; the last valid value
  wins. The bundled parser's first-occurrence accessor silently ignored later
  invalid or conflicting values, as reproduced by new failing tests.
- New permission fields are appended to the class tail. A compiler probe and
  registered unit test caught the legacy `global.start_mutex` offset changing
  from 16 to 24 before this correction; both checks passed after it.

Independent review of b16ff6025..a64cecc15 found no lifecycle blocker and identified
repeated-option validation, now corrected with RED/GREEN tests. Its other reviewed
conditions were left unchanged: v4's sole managed validator caller excludes
`threads`; processor TLS init/end calls already use thread-local state; STOP uses
normal session response flushing in the initial implementation. The subsequent
review follow-up below supersedes that last ruling with a bounded response drain
and real TLS/backpressure regression evidence.
The last point means a client unable to receive a reply can observe a disconnect.

Commands and final outcomes are recorded below as verification completes. The
v4 checks are compilation-only; no installed-plugin integration run is claimed.

- `test/infra/control/run-ci-lint.bash`: passed before the final layout unit was
  added; the final pre-push run will also validate its registration.
- Stable DEBUG build: passed.
- `startup_permissions_layout_unit-t`: failed before the layout correction;
  passed after it, and registered in `unit-tests-g1`.
- v4 compilation checks: all seven changed production translation units and the
  legacy-layout probe passed with PROXYSQL40/31/FFTO/TSDB/ED25519/DEBUG enabled.
- DEBUG v3.1 AddressSanitizer run before the layout-only correction: lifecycle
  6/6 and module 11/11 passed with `detect_leaks=0`; a final run follows.


Final local verification (2026-10-28):

| Check | Outcome |
| --- | --- |
| Stable DEBUG build, final field placement | Passed |
| Stable lifecycle process suite | 6/6 passed |
| Stable module process suite | 11/11 passed |
| DEBUG v3.1 ASAN build, final field placement | Passed |
| ASAN lifecycle process suite | 6/6 passed |
| ASAN module process suite | 11/11 passed |
| Registered legacy-layout unit | RED before field move, GREEN afterward |
| V4 changed production files and layout probe | 8 compile checks passed |
| Repository CI lint before final registration | Passed; final push runs hook again |
| `git diff --check`, group format and source registration | Passed |

ASAN command prefix: `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:halt_on_error=1`.
Full backend TAP and installed-plugin integration are not claimed. Draft PRs
allow those CI/reviewer checks to proceed without merging the old branches.

## Review follow-up (2026-10-28)

- Reproduced explicit stopped runtime SAVE reporting success: 64 failing cases
  across both Admin protocols, both dialects, all four aliases, initial no-start
  and post-STOP. Dispatch now reports unavailable runtime state; LOAD is unchanged.
- STOP now drains protocol/TLS output before initiating shutdown, with a one-second
  limit for stalled peers. Real MySQL/PgSQL stream socketpair tests exercise partial
  writes, full sockets, stalled readers, staged packets, real TLS ciphertext
  retries and pending BIO bytes (20/20). The real TLS test reproduced duplicate
  PgSQL plaintext after ciphertext EAGAIN (2 failing assertions); PgSQL now
  accounts for consumed plaintext on retry, matching the existing MySQL fix.
- DEBUG v3.1 ASAN build succeeded; lifecycle probe passed 7/7 with
  `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1`. The lifecycle probe and drain
  tests are registered in unit-tests-g1 so CI coverage executes these paths.
- The failed legacy-g3 v4/MySQL57 coverage attempt timed out deploying backend
  replicas before TAP. Host diagnostics showed I/O full pressure averaging 70.83%
  over 60 seconds. The single retry passed infrastructure startup; tests pending.

- DEBUG Stable build succeeded; the expanded drain unit passed 20/20. V4.0
  syntax checks passed for all previously modified production units and the layout
  probe. Independent review found no remaining material issue after TLS expansion.

### Startup persistence follow-up

- New private-daemon regression reproduced four failures: disabled runtime SAVE
  wrote zero for both dialects and enabled relaunch fell back to four workers
  instead of the configured MySQL=3/PgSQL=5.
- Separate configured counts at each handler class tail retain positive runtime
  serialization and saved values. Actual worker counts remain zero when denied.
  Validation remains 1..255 with either permission.
- The test checks memory, runtime, disk, STOP/START with workers denied, then a
  physical relaunch using the saved database with workers enabled. Existing
  combination/precedence tests check actual listeners alongside configured values.
- `module_startup_unit-t` registers all startup probes in the CI coverage suite.
- Independent review found no material production issue; operator documentation
  now distinguishes configured values from effective Worker status counts.

### Final follow-up verification

Production/test source: `50ecfe4d9` (includes lifecycle fixes `530545b84` and
startup persistence fix `b8bab7760`). No backend service was used by these probes.

| Check | DEBUG Stable | DEBUG v3.1 ASAN |
| --- | --- | --- |
| Top-level `make debug -j4` | Passed | Passed |
| `admin_response_drain_unit-t` | 20/20 | 20/20 |
| `module_lifecycle_unit-t` | 7 Python cases + TAP wrapper passed | 7 Python cases + TAP wrapper passed |
| `module_startup_unit-t` | 12 Python cases + TAP wrapper passed | 12 Python cases + TAP wrapper passed |
| `startup_permissions_layout_unit-t` | 1/1 | 1/1 |

Build prefixes were `NOJEMALLOC=1` for Stable and
`NOJEMALLOC=1 WITHASAN=1 PROXYSQL31=1` for sanitizer builds. Sanitizer execution
used `ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:halt_on_error=1`. Unit harness
objects were rebuilt when changing build flags.

V4.0 compile-only checks passed for all eight changed production translation
units, a global-prefix layout probe, and the four relevant unit-test sources.
These do not establish installed-plugin/backend integration. The lifecycle
follow-up push passed the complete pre-push CI lint suite. Fresh remote matrix
and coverage results remain pending; neither replacement is marked ready and
the old PRs remain open.

### Static-analysis follow-up

SonarCloud flagged the new test fixture's forced TLS 1.2 maximum. The fixture now
requires TLS 1.3 without capping future versions, uses explicit lambda captures,
and documents frontend stream ownership. The touched PURGE timestamp validation
uses an early error exit to keep nesting within the quality rule; a new TO 0
regression preserves invalid-timestamp errors.

After these changes, fresh DEBUG Stable and v3.1 ASAN builds succeeded. The drain
test passed 20/20 with real TLS 1.3 in both builds, and the stopped configuration/
statistics case (including valid/invalid PURGE, both Admin protocols/dialects)
passed in both. The changed production and unit-test translation units also
passed v4.0 compilation checks. Independent review found no actionable issue.
The tested contents were preserved when committing the shared fix on the
lifecycle branch and merging it into startup. Fresh Sonar/matrix/coverage results
are still pending, so both replacements remain drafts.

### Standalone runner portability

Two further review findings concerned optional host prerequisites and non-Linux
builds. Both probes now emit TAP skips on non-Linux, or when Python/SQL clients
are absent, before launching any daemon. The shared helper propagates child exit
statuses, using 77 only for prerequisite skips. Missing daemon/script assets,
launch failures, signals, and regression failures remain test failures. Coverage
CI still installs all required tools before execution.

Verification after this test-only change:

- With prerequisites: Stable lifecycle 7/7 and startup 12/12, including both TAP
  wrappers, passed again. Production code is unchanged from the earlier ASAN run.
- Before the fix, missing Python made both wrappers fail; afterward, both missing
  Python and missing SQL clients emitted successful TAP skips for both wrappers.
- Compiling each wrapper's non-Linux conditional branch emitted a TAP skip. This
  was a Linux-host simulation, not an actual macOS/FreeBSD runtime test.
- Six build dependency probes confirmed both targets require the daemon on Linux
  and omit it on Darwin/FreeBSD. Both wrappers passed v4.0 syntax compilation.
- An invalid daemon path still produced a failing TAP assertion, as required.
- Independent review found no actionable issue.
