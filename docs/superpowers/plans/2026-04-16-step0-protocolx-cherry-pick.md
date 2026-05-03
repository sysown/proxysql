# Step 0 — ProtocolX plugin infrastructure cherry-pick — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Cherry-pick the plugin ABI, plugin loader, config wiring, admin-table/command registry, and the `mysqlx` reference-plugin scaffold from `origin/ProtocolX` onto the `v3.0-genai-plugin` branch, so that subsequent steps have a working plugin infrastructure to move GenAI into.

**Architecture:** Sequential cherry-pick of 17 commits from `origin/ProtocolX` in five logical batches (ABI+loader → lifecycle wiring → table/command registry → ABI polish → mysqlx scaffold). After each batch: clean build + run the relevant unit test that landed with that batch. Merge commit `5c1549dcc` on ProtocolX is deliberately skipped — it is a conflict-resolution commit, not new content. The final state is an additive change: core ProxySQL compiles and runs identically when no `plugins = (...)` is configured, and the `mysqlx` plugin loads/starts/stops successfully when it is.

**Tech Stack:** C++17, GNU Make, libconfig (cnf parser), `dlopen`/`dlsym`, SQLite3, TAP test framework, Docker (unused in Step 0 but present for context).

**Branch:** `v3.0-genai-plugin` (worktree at `.worktrees/v3.0-genai-plugin`, base `origin/v3.0 = 13ff9d767`).

**Spec reference:** `docs/superpowers/specs/2026-04-16-genai-plugin-carveout-design.md`, section "Migration sequence → Step 0".

---

## File Structure

This step **adds** the following files (via cherry-pick) — no new files are authored in this plan:

| Path | Role |
|---|---|
| `include/ProxySQL_Plugin.h` | Plugin ABI header: descriptor struct, services callbacks, `proxysql_plugin_descriptor_v1` C entry point, ABI version constant |
| `include/ProxySQL_PluginManager.h` | Plugin manager class: dlopen-based load, init/start/stop lifecycle, command/table registry |
| `lib/ProxySQL_PluginManager.cpp` | Plugin manager implementation |
| `test/tap/test_helpers/fake_plugin.cpp` | Minimal fake plugin used by unit tests |
| `test/tap/tests/unit/plugin_manager_unit-t.cpp` | Unit test: load/init/start/stop lifecycle |
| `test/tap/tests/unit/plugin_config_unit-t.cpp` | Unit test: `plugins = (...)` cnf parsing |
| `test/tap/tests/unit/plugin_registry_unit-t.cpp` | Unit test: table/command registration, conflict rejection |
| `plugins/mysqlx/` | mysqlx reference plugin (scaffold only — headers, Makefile, minimal `.cpp` with descriptor stub) |
| `test/tap/tests/test_mysqlx_plugin_load-t.cpp` | Smoke test: mysqlx descriptor resolves |

This step **modifies** the following existing files (via cherry-pick):

| Path | What changes |
|---|---|
| `include/proxysql_admin.h` | Plugin table/command registration member hooks on `ProxySQL_Admin` |
| `include/proxysql_glovars.hpp` | Adds `std::vector<std::string> plugin_modules` to glovars |
| `lib/ProxySQL_GloVars.cpp` | libconfig parser for the `plugins = (...)` directive |
| `lib/ProxySQL_Admin.cpp` | Table/command registry plumbing (~24 lines added) |
| `lib/Admin_Bootstrap.cpp` | Plugin-table creation during admin init |
| `lib/Admin_Handler.cpp` | Plugin-command dispatch in SQL handler |
| `lib/Makefile` | Builds `plugin_manager` object; wires test helper |
| `src/main.cpp` | `LoadConfiguredPlugins()` / `StartConfiguredPlugins()` / `StopConfiguredPlugins()` in startup/shutdown (~60 lines added) |
| `test/tap/tests/unit/Makefile` | Builds the three new unit tests |
| `Makefile` | (Only if `mysqlx` scaffold is cherry-picked) adds `plugins/mysqlx && make` to build flavors and clean targets |

**Conflict risk zones.** Cherry-picking adds content that on `v3.0` (this branch's base) sits next to existing GenAI-related code. Commit `cd15afdd1` adds ~24 lines to `lib/ProxySQL_Admin.cpp` which has 19 GENAI references; commit `804771271` adds ~60 lines to `src/main.cpp` which is ~95 KLOC and has GenAI init/shutdown calls. Conflicts are likely textual, not semantic — ProtocolX's additions go alongside, not on top of, GenAI code. Resolution is straightforward ("accept both"). No functional changes to GenAI code in this step.

---

## Cherry-pick Commit Batches

| Batch | Commits | Purpose |
|---|---|---|
| 1 | `7e1a12b8f`, `da7e18271` | ABI header + plugin manager + first unit test |
| 2 | `804771271`, `80fa6bee2` | Config file wiring, main.cpp lifecycle hooks |
| 3 | `cd15afdd1`, `fd5f02947`, `123bb7eaf`, `243051660`, `d036ba832`, `5dd717a8f`, `9b87260b7`, `7cc246c71` | Admin table/command registry + 7 hardening fixes |
| 4 | `d34fb3816`, `0143f8a4f` | Registry refactor + ABI constraint documentation |
| 5 | `19d48bdc1`, `ba45e631c`, `11aca2427` | mysqlx reference-plugin scaffold |

---

## Task 1: Pre-flight verification

**Files:** none (environment check only)

- [ ] **Step 1.1: Confirm worktree and branch**

Run:
```bash
cd /home/rene/aa/ab/proxysql/.worktrees/v3.0-genai-plugin
git rev-parse --abbrev-ref HEAD
git log --oneline -1
git status --short
```

Expected:
- Branch: `v3.0-genai-plugin`
- Head: `fb186a1d5 docs: add design for GenAI plugin carve-out` (or later if intermediate commits exist)
- Status: clean (no uncommitted changes)

If status is not clean, stop and escalate.

- [ ] **Step 1.2: Ensure origin/ProtocolX is fetched and reachable**

Run:
```bash
git fetch origin ProtocolX
git rev-parse origin/ProtocolX
```

Expected: succeeds and prints a SHA. If fetch fails, check network / remote config before continuing.

- [ ] **Step 1.3: Verify every target commit is reachable from origin/ProtocolX**

Run:
```bash
for sha in 7e1a12b8f da7e18271 804771271 80fa6bee2 cd15afdd1 fd5f02947 123bb7eaf 243051660 d036ba832 5dd717a8f 9b87260b7 7cc246c71 d34fb3816 0143f8a4f 19d48bdc1 ba45e631c 11aca2427; do
  git merge-base --is-ancestor "$sha" origin/ProtocolX && echo "OK $sha" || echo "MISSING $sha"
done
```

Expected: 17 lines, all starting with `OK`. Any `MISSING` → stop, escalate, do not proceed.

- [ ] **Step 1.4: Record baseline for rollback**

Run:
```bash
git rev-parse HEAD > /tmp/step0_baseline_sha.txt
cat /tmp/step0_baseline_sha.txt
```

Expected: the SHA from Step 1.1 appears in `/tmp/step0_baseline_sha.txt`. If anything goes catastrophically wrong later, `git reset --hard $(cat /tmp/step0_baseline_sha.txt)` returns the branch to this state. (**Do not use this unless explicitly directed** — `git reset --hard` is destructive. Prefer `git cherry-pick --abort` or reverting specific commits.)

- [ ] **Step 1.5: Verify a clean baseline build works**

Run:
```bash
make 2>&1 | tail -20
```

Expected: build succeeds (exit 0). This confirms the base is healthy before cherry-picks — if it already fails, the cherry-picks aren't the cause of any downstream break.

Build uses `-j` auto-detected from `nproc`. This takes ~5–15 minutes on first run (because of `deps/` compilation). On subsequent runs, only `lib/` and `src/` rebuild.

---

## Task 2: Cherry-pick Batch 1 — ABI header + plugin manager

**Files** (newly created by the cherry-pick):
- Create: `include/ProxySQL_Plugin.h`
- Create: `include/ProxySQL_PluginManager.h`
- Create: `lib/ProxySQL_PluginManager.cpp`
- Create: `test/tap/test_helpers/fake_plugin.cpp`
- Create: `test/tap/tests/unit/plugin_manager_unit-t.cpp`
- Modify: `lib/Makefile`, `test/tap/tests/unit/Makefile`

- [ ] **Step 2.1: Cherry-pick the ABI + loader**

Run:
```bash
git cherry-pick 7e1a12b8f da7e18271
```

Expected: two commits applied with no conflicts (all files are new — no existing file on `v3.0` by these names).

If a conflict appears (unexpected): inspect the conflicting file with `git status`, resolve manually (these commits should not touch any pre-existing core file), then `git cherry-pick --continue`. If unsure, `git cherry-pick --abort` and escalate.

- [ ] **Step 2.2: Verify the new files are present and compile-ready**

Run:
```bash
ls -l include/ProxySQL_Plugin.h include/ProxySQL_PluginManager.h lib/ProxySQL_PluginManager.cpp
head -5 include/ProxySQL_Plugin.h
```

Expected: all three files exist; header starts with a copyright/license banner.

- [ ] **Step 2.3: Build**

Run:
```bash
make 2>&1 | tail -30
```

Expected: build succeeds. The newly-added `lib/ProxySQL_PluginManager.cpp` now contributes to `libproxysql.a`. Build time: incremental, 1–3 minutes.

If build fails: read the first error message. If it's a missing symbol from an unreferenced plugin manager method, the issue is the cherry-pick is partial — check `git log --oneline -3` shows both `7e1a12b8f` and `da7e18271` applied.

- [ ] **Step 2.4: Build the plugin-manager unit test**

Run:
```bash
cd test/tap && make build_tap_test_debug 2>&1 | tail -10
cd /home/rene/aa/ab/proxysql/.worktrees/v3.0-genai-plugin
```

Expected: test binaries build, including `test/tap/tests/unit/plugin_manager_unit-t`.

- [ ] **Step 2.5: Run the plugin-manager unit test**

Run:
```bash
./test/tap/tests/unit/plugin_manager_unit-t 2>&1 | tail -20
```

Expected: all TAP lines show `ok`. Final summary shows `# Result: PASS` (or equivalent).

If it fails: read the TAP output. The test loads `test/tap/test_helpers/fake_plugin.so`. If that shared object is missing, the test helper did not build — verify `test/tap/test_helpers/` has a built `fake_plugin.so`.

Commit note: `git cherry-pick` already committed Batch 1 in Step 2.1. No additional commit.

---

## Task 3: Cherry-pick Batch 2 — config wiring + main.cpp lifecycle

**Files:**
- Modify: `include/proxysql_glovars.hpp`
- Modify: `lib/ProxySQL_GloVars.cpp`
- Modify: `src/main.cpp`
- Create: `test/tap/tests/unit/plugin_config_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`

- [ ] **Step 3.1: Cherry-pick the config + lifecycle wiring**

Run:
```bash
git cherry-pick 804771271 80fa6bee2
```

Expected: both commits apply. `src/main.cpp` gets ~60 lines added (pure addition — new functions `LoadConfiguredPlugins`, `StartConfiguredPlugins`, `StopConfiguredPlugins`, plus call sites in the startup/shutdown blocks).

**If conflict in `src/main.cpp`:**
- `src/main.cpp` on `v3.0` has GenAI init/shutdown calls (`GloMCPH->init()`, `GloGATH->init()`, `GloAI = new ...` around lines 922–971, plus corresponding shutdown).
- ProtocolX adds the plugin lifecycle calls in the same regions.
- Resolution: keep BOTH sets of calls. Order: call plugin `Load` **before** GenAI init; call plugin `Start` **after** GenAI start; call plugin `Stop` **before** GenAI shutdown (mirror of init). If the commit's patch context makes a specific ordering obvious, follow the patch; otherwise use this rule.
- After resolving: `git add src/main.cpp && git cherry-pick --continue`.

**If conflict in `lib/ProxySQL_GloVars.cpp`:**
- Likely a libconfig schema registration site. Accept both sides — adding `plugins` to the known-directives list does not conflict semantically with anything on `v3.0`.

- [ ] **Step 3.2: Build**

Run:
```bash
make 2>&1 | tail -30
```

Expected: build succeeds. `src/main.cpp` recompiles (this is the slow one — 30–60 seconds on its own because it's ~95 KLOC).

If build fails with `undefined reference to LoadConfiguredPlugins` or similar: Batch 1 was not applied first. Check `git log --oneline -5`.

- [ ] **Step 3.3: Build unit tests**

Run:
```bash
cd test/tap && make build_tap_test_debug 2>&1 | tail -5
cd /home/rene/aa/ab/proxysql/.worktrees/v3.0-genai-plugin
```

Expected: `test/tap/tests/unit/plugin_config_unit-t` builds.

- [ ] **Step 3.4: Run the plugin-config unit test**

Run:
```bash
./test/tap/tests/unit/plugin_config_unit-t 2>&1 | tail -20
```

Expected: all TAP lines `ok`; final PASS summary.

- [ ] **Step 3.5: Confirm previously-added test still passes (regression check)**

Run:
```bash
./test/tap/tests/unit/plugin_manager_unit-t 2>&1 | tail -5
```

Expected: still PASS. Catches any accidental regression from the lifecycle wiring.

---

## Task 4: Cherry-pick Batch 3 — admin table/command registry

**Files:**
- Modify: `include/proxysql_admin.h`
- Modify: `lib/ProxySQL_Admin.cpp`
- Modify: `lib/Admin_Bootstrap.cpp`
- Modify: `lib/Admin_Handler.cpp`
- Modify: `lib/ProxySQL_PluginManager.cpp`, `include/ProxySQL_PluginManager.h` (each hardening commit touches these)
- Create: `test/tap/tests/unit/plugin_registry_unit-t.cpp`
- Modify: `test/tap/tests/unit/Makefile`

- [ ] **Step 4.1: Cherry-pick the 8 commits in order**

Run:
```bash
git cherry-pick cd15afdd1 fd5f02947 123bb7eaf 243051660 d036ba832 5dd717a8f 9b87260b7 7cc246c71
```

Expected: all 8 commits apply. The series-of-fixes (commits 2–8 of this batch) iteratively polish the registry added by `cd15afdd1`.

**If conflict in `lib/ProxySQL_Admin.cpp`:**
- `v3.0` has ~19 GENAI blocks in this file; ProtocolX adds ~24 lines of registry plumbing.
- Read the incoming patch: `git show cd15afdd1 -- lib/ProxySQL_Admin.cpp` to see the exact additions.
- The registry additions are new methods/fields, not modifications of existing ones — they should not textually collide with GENAI blocks.
- Resolution: accept both; ensure the new registry code sits outside any `#ifdef PROXYSQLGENAI` block.
- `git add lib/ProxySQL_Admin.cpp && git cherry-pick --continue`.

**If conflict in `lib/Admin_Handler.cpp`:**
- v3.0 has `GloMCPH->has_variable()` / `GloGATH->has_variable()` calls in the command dispatcher.
- ProtocolX adds a plugin-command dispatcher path to the same function.
- Resolution: keep both; ProtocolX's dispatcher should be an `else if` branch next to the existing core commands. GenAI calls are unchanged.
- `git add lib/Admin_Handler.cpp && git cherry-pick --continue`.

- [ ] **Step 4.2: Build**

Run:
```bash
make 2>&1 | tail -30
```

Expected: succeeds. If it fails on a `ProxySQL_PluginServices` member mismatch: a partial cherry-pick left a stale header/impl. Run `git log --oneline -10` to verify all 8 commits are present; if one is missing, `git cherry-pick` it individually.

- [ ] **Step 4.3: Build unit tests**

Run:
```bash
cd test/tap && make build_tap_test_debug 2>&1 | tail -5
cd /home/rene/aa/ab/proxysql/.worktrees/v3.0-genai-plugin
```

Expected: `plugin_registry_unit-t` builds.

- [ ] **Step 4.4: Run registry unit test + regression tests**

Run:
```bash
./test/tap/tests/unit/plugin_registry_unit-t 2>&1 | tail -20
./test/tap/tests/unit/plugin_manager_unit-t 2>&1 | tail -5
./test/tap/tests/unit/plugin_config_unit-t 2>&1 | tail -5
```

Expected: all three PASS.

---

## Task 5: Cherry-pick Batch 4 — ABI polish

**Files:**
- Modify: `lib/ProxySQL_PluginManager.cpp`, `include/ProxySQL_PluginManager.h`
- Modify: `include/ProxySQL_Plugin.h` (documentation comments added by `0143f8a4f`)
- Possibly modify: `lib/Admin_Handler.cpp` (auth comparison hardening in `0143f8a4f`)

- [ ] **Step 5.1: Cherry-pick the two commits**

Run:
```bash
git cherry-pick d34fb3816 0143f8a4f
```

Expected: both apply. These are small refactors — `d34fb3816` removes a `PLUGIN` prefix gate from command matching; `0143f8a4f` adds a documentation comment about C++ stdlib ABI coupling and hardens `PLAIN` auth string comparison.

If conflict in `lib/Admin_Handler.cpp` (from the PLAIN auth change): the auth comparison site is an established v3.0 code site. Accept ProtocolX's version — it replaces a raw comparison with a length-checked one, which is strictly safer and does not affect GenAI.

- [ ] **Step 5.2: Build**

Run:
```bash
make 2>&1 | tail -20
```

Expected: succeeds.

- [ ] **Step 5.3: Full unit test re-run**

Run:
```bash
./test/tap/tests/unit/plugin_manager_unit-t 2>&1 | tail -5
./test/tap/tests/unit/plugin_config_unit-t 2>&1 | tail -5
./test/tap/tests/unit/plugin_registry_unit-t 2>&1 | tail -5
```

Expected: all PASS.

---

## Task 6: Cherry-pick Batch 5 — mysqlx reference-plugin scaffold

**Files:**
- Create: `plugins/mysqlx/` (directory with Makefile, `include/`, `src/`, `proto/` subdirs — protobuf files included)
- Modify: `Makefile` (top-level) — adds `plugins/mysqlx` to build flavors and clean targets
- Create: `test/tap/tests/test_mysqlx_plugin_load-t.cpp` (smoke test if present in commits)

- [ ] **Step 6.1: Cherry-pick the scaffold**

Run:
```bash
git cherry-pick 19d48bdc1 ba45e631c 11aca2427
```

Expected: all three apply. `19d48bdc1` adds the directory and minimal `mysqlx_plugin.cpp` with a descriptor stub; `ba45e631c` adds Makefile dependency tracking so mysqlx rebuilds when the ABI header changes; `11aca2427` adds `-pthread` and a guard that errors on `MYSQLX` admin commands when the plugin isn't loaded.

**If conflict in top-level `Makefile`:**
- v3.0's `Makefile` has GenAI-specific targets and tier feature flags.
- ProtocolX adds `cd plugins/mysqlx && make` lines to each build flavor (`build_release`, `build_debug`, etc.).
- Resolution: accept both. Put the mysqlx build calls after the core `lib/` and `src/` builds (they depend on `libproxysql.a` via the ABI header, not the archive).
- `git add Makefile && git cherry-pick --continue`.

- [ ] **Step 6.2: Build core + plugins**

Run:
```bash
make 2>&1 | tail -30
```

Expected: succeeds. The top-level `make` now also builds `plugins/mysqlx/libmysqlx_plugin.so` (or similar name).

If mysqlx build fails on a missing `protoc` / protobuf: the scaffold commit assumes protobuf is installed. On CI runners this may need a package install; on the dev machine check `which protoc` and install if missing (`apt-get install protobuf-compiler`). If the mysqlx scaffold at this commit-range does not actually require `protoc` (the scaffold commit may have empty proto files), the failure is different and points to a missing system lib.

- [ ] **Step 6.3: Check that `genai.so` plugin config doesn't exist yet**

Run:
```bash
grep -l "^plugins" etc/proxysql.cnf 2>/dev/null || echo "no plugins directive in default cnf — good"
```

Expected: no `plugins` directive in the default cnf file. Step 0 does not enable any plugin by default.

- [ ] **Step 6.4: Run any mysqlx smoke tests that landed with the scaffold**

Run:
```bash
ls test/tap/tests/test_mysqlx_plugin_load-t* 2>/dev/null && \
  (cd test/tap && make build_tap_test_debug 2>&1 | tail -5) && \
  ls test/tap/tests/test_mysqlx_plugin_load-t 2>/dev/null && \
  ./test/tap/tests/test_mysqlx_plugin_load-t 2>&1 | tail -20
```

Expected: if the smoke test source exists, it builds and passes. If the scaffold commits at this range did not include the smoke test, the `ls` call prints nothing — skip without error.

---

## Task 7: End-to-end plugin-load smoke test

**Files:** none (runtime verification)

- [ ] **Step 7.1: Build release binary**

Run:
```bash
make 2>&1 | tail -5
ls -la src/proxysql
```

Expected: `src/proxysql` exists and is executable.

- [ ] **Step 7.2: Determine how the loader resolves plugin names/paths**

Run:
```bash
grep -nE "dlopen|LoadPlugin|plugin_modules" lib/ProxySQL_PluginManager.cpp | head -20
```

Expected: a call site showing how a string from `plugin_modules` is turned into a filesystem path for `dlopen`. Three common patterns:
- Bare name (`mysqlx`) resolved via a search path (e.g., `./plugins/mysqlx/libmysqlx_plugin.so`)
- Absolute or relative path taken verbatim
- Bare name + a fixed prefix/suffix (`lib` + name + `.so`)

Record the pattern (one sentence) before writing the cnf. If unsure, peek at any example cnf that ships on `origin/ProtocolX`:
```bash
git show origin/ProtocolX:etc/proxysql.cnf 2>/dev/null | grep -A2 -iE "^plugins"
```

- [ ] **Step 7.3: Create a minimal cnf enabling the mysqlx plugin**

Run:
```bash
cat > /tmp/proxysql_step0_smoke.cnf <<'EOF'
datadir="/tmp/proxysql_step0_smoke_data"
admin_variables= {
  mysql_ifaces="0.0.0.0:16032"
  admin_credentials="admin:admin"
}
mysql_variables= {
  interfaces="0.0.0.0:16033"
}
# Replace MYSQLX_REF with whatever Step 7.2 determined is the correct form
plugins = ( "MYSQLX_REF" )
EOF
mkdir -p /tmp/proxysql_step0_smoke_data
# Substitute the actual reference:
sed -i 's|MYSQLX_REF|mysqlx|' /tmp/proxysql_step0_smoke.cnf  # or adjust to path form if needed
cat /tmp/proxysql_step0_smoke.cnf
```

Expected: cnf file written with the correct plugin reference for the resolution pattern discovered in Step 7.2. Data dir created.

- [ ] **Step 7.4: Start proxysql with the cnf and verify plugin load**

First confirm the available flags:
```bash
./src/proxysql --help 2>&1 | head -30
```

Then run (foreground mode with `-f`):
```bash
./src/proxysql -c /tmp/proxysql_step0_smoke.cnf -f 2>&1 | tee /tmp/proxysql_step0.log &
PROXYSQL_PID=$!
sleep 3
grep -E "plugin|mysqlx|Plugin" /tmp/proxysql_step0.log | head -20
```

Expected: log lines indicate `mysqlx` plugin loaded (exact wording depends on `log_message` calls in the loader — look for "loaded", "started", or "plugin").

- [ ] **Step 7.5: Stop proxysql cleanly**

Run:
```bash
kill $PROXYSQL_PID
wait $PROXYSQL_PID 2>/dev/null
grep -E "plugin|mysqlx|Plugin" /tmp/proxysql_step0.log | tail -10
```

Expected: log lines show plugin stopped cleanly before shutdown finishes. No "segfault" / "assertion failed" anywhere in the log.

- [ ] **Step 7.6: Negative test — confirm core works with no plugins configured**

Run:
```bash
sed -i 's/^plugins =.*/# plugins = ( "mysqlx" )/' /tmp/proxysql_step0_smoke.cnf
./src/proxysql -c /tmp/proxysql_step0_smoke.cnf -f --idle-threads 2>&1 | tee /tmp/proxysql_step0_noplugin.log &
PROXYSQL_PID=$!
sleep 3
grep -E "plugin|mysqlx" /tmp/proxysql_step0_noplugin.log
kill $PROXYSQL_PID
wait $PROXYSQL_PID 2>/dev/null
```

Expected: no "plugin loaded" messages (plugin manager initialized with an empty list is OK; no individual plugin load). ProxySQL starts and shuts down normally.

- [ ] **Step 7.7: Cleanup**

Run:
```bash
rm -rf /tmp/proxysql_step0_smoke_data /tmp/proxysql_step0*.cnf /tmp/proxysql_step0*.log
```

Expected: cleanup succeeds.

---

## Task 8: Full unit-test regression sweep

**Files:** none (test execution)

- [ ] **Step 8.1: Build debug + unit tests**

Run:
```bash
make debug 2>&1 | tail -5
cd test/tap && make build_tap_test_debug 2>&1 | tail -5
cd /home/rene/aa/ab/proxysql/.worktrees/v3.0-genai-plugin
```

Expected: both succeed.

- [ ] **Step 8.2: Run ALL unit tests**

Run:
```bash
cd test/tap/tests/unit
for t in *-t; do
  [ -x "$t" ] || continue
  echo "=== $t ==="
  ./"$t" 2>&1 | tail -3
done
cd /home/rene/aa/ab/proxysql/.worktrees/v3.0-genai-plugin
```

Expected: every test ends with PASS or `# ok`. Any FAIL → investigate. If a pre-existing test now fails, it likely means a cherry-pick landed something that changed existing behavior — compare against the pre-cherry-pick baseline saved in `/tmp/step0_baseline_sha.txt`.

The three plugin unit tests (`plugin_manager_unit-t`, `plugin_config_unit-t`, `plugin_registry_unit-t`) plus any pre-existing unit tests should all pass. The expected count is whatever `test/tap/tests/unit/` had before this work, plus the three new ones.

---

## Task 9: Final state verification and documentation touch-up

**Files:**
- Potentially modify: `CLAUDE.md` (only if adding a "Plugins" section is appropriate at this stage)

- [ ] **Step 9.1: Confirm commit history matches the expected sequence**

Run:
```bash
git log --oneline origin/v3.0..HEAD | head -30
```

Expected: 17 cherry-picked commits + the 1 pre-existing design-doc commit (`fb186a1d5`), in the reverse chronological order the cherry-picks were applied. Cherry-pick commits may have new SHAs (expected — cherry-pick rewrites the tree metadata) but their subject lines should match the ones listed in the batch table at the top of this plan.

- [ ] **Step 9.2: Sanity-check that no GenAI code was modified**

Run:
```bash
git diff origin/v3.0 HEAD -- lib/ include/ src/main.cpp | grep -c "GENAI" || echo "0 GENAI lines changed — good"
```

Expected: `0 GENAI lines changed — good` (or count is 0). If the diff contains GENAI changes, a cherry-pick conflict resolution accidentally touched GenAI code — investigate before proceeding.

- [ ] **Step 9.3: Leave a trailing commit documenting Step 0 completion**

Run:
```bash
git log --oneline origin/v3.0..HEAD > /tmp/step0_commit_list.txt
wc -l /tmp/step0_commit_list.txt
```

Then:
```bash
cat > /tmp/step0_done_note.txt <<'EOF'
chore: complete Step 0 — ProtocolX plugin infrastructure cherry-pick

Plugin ABI (include/ProxySQL_Plugin.h), loader
(ProxySQL_PluginManager), config wiring (plugins = (...) directive),
admin table/command registry, and the mysqlx reference-plugin scaffold
are now on this branch.

Core ProxySQL continues to build and run identically when no plugin is
configured. The mysqlx plugin loads, starts, and stops cleanly when it
is.

Next step: Step 1 (plugins/genai/ skeleton) — see
docs/superpowers/specs/2026-04-16-genai-plugin-carveout-design.md
section "Migration sequence → Step 1".
EOF
git commit --allow-empty -F /tmp/step0_done_note.txt
rm /tmp/step0_done_note.txt /tmp/step0_commit_list.txt /tmp/step0_baseline_sha.txt
```

Expected: empty commit lands with the given message. Rationale: this makes Step 0 easy to identify as a boundary in `git log` and gives a clear attach point for PR description references.

- [ ] **Step 9.4: Push branch (do NOT force-push)**

Run:
```bash
git push -u origin v3.0-genai-plugin
```

Expected: push succeeds; remote branch `v3.0-genai-plugin` now tracks this local branch.

If the remote rejects (non-fast-forward): **stop and escalate**. Do not `--force`. A non-fast-forward indicates someone else committed to this branch name or the local branch diverged — investigate before overwriting.

Note: feedback memory `feedback_no-force-push.md` applies. Never `--force` unless the user explicitly asks.

---

## Self-review checklist (for the engineer running this plan)

After Task 9 completes, confirm:

- [ ] 17 cherry-picked commits + 1 design-doc commit + 1 chore commit = 19 commits ahead of `origin/v3.0`.
- [ ] `make` succeeds from a clean state.
- [ ] All three plugin unit tests pass (`plugin_manager_unit-t`, `plugin_config_unit-t`, `plugin_registry_unit-t`).
- [ ] mysqlx plugin loads and stops cleanly in the Task 7 smoke test.
- [ ] No GenAI (`#ifdef PROXYSQLGENAI` or `GloMCPH/GloGATH/GloAI`) code was modified by this step.
- [ ] Branch is pushed to `origin/v3.0-genai-plugin`.

If all checks pass, Step 0 is complete and the plan for Step 1 (plugin skeleton for `plugins/genai/`) can be written.

---

## Known risks / escalation triggers

Escalate to the human reviewer (do not attempt workaround) if:

1. A cherry-pick in Batch 3 conflicts in `lib/ProxySQL_Admin.cpp` in a way that is not a clean textual separation between registry methods and GENAI blocks (i.e., if the same lines are being modified by both).
2. Any unit test that passed at the baseline fails after cherry-picks and the failure mentions `plugin` or `Plugin` — may indicate an ABI regression on ProtocolX that needs upstream fix.
3. `make` fails with an error about protobuf / `protoc` and the dev machine does not have protobuf installed. (Install `protobuf-compiler` — this is a Makefile dependency, not a code issue.)
4. Task 7 smoke test shows the mysqlx plugin failing to load with `dlopen` errors. May indicate a missing shared library or a Makefile issue (e.g., `-rdynamic` not set in the main binary). Stop and investigate; do not move on to Step 1 until this works.
5. A merge conflict appears in a file that was NOT listed in "File Structure" above. This means a cherry-pick is touching something unexpected — read the commit in full before deciding.
