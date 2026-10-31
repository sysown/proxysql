# Cluster Simulator Optional Comment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make omitted expected cluster-state comments behave as wildcards while preserving exact matching for explicitly supplied comments and improving mismatch diagnostics.

**Architecture:** Add a presence bit to the shared `server_status` tuple, populate it while parsing expected and runtime JSON, and consume it in comparison and JSON projection. Exercise the shared functions with a focused TAP unit binary and then validate the existing simulator end to end.

**Tech Stack:** C++11-compatible tuple-based state model, nlohmann JSON, ProxySQL TAP test framework, GNU Make, isolated cluster-simulator CI infrastructure.

## Global Constraints

- Base the dedicated branch on the latest `origin/v3.0`.
- Omitted comments are wildcards; explicit comments, including empty strings, remain exact.
- Do not change checksum inputs or ProxySQL runtime behavior.
- Do not modify or include PR #6017 changes.

---

### Task 1: Add the focused failing regression

**Files:**
- Create: `test/deps/cluster_simulator/tests/common_utils_unit-t.cpp`
- Modify: `test/deps/cluster_simulator/Makefile`
- Modify: `test/infra/control/cluster-simulator-ci.bash`

**Interfaces:**
- Consumes: `server_status`, `matching_server_status()`, and `cluster_status_to_json()` from `lib/common_utils.h`.
- Produces: `common_utils_unit-t`, a focused TAP binary runnable through `make check` and executed by the cluster-simulator CI build.

- [ ] **Step 1: Add assertions for omitted, explicit, different, and explicitly empty comments plus JSON projection.**
- [ ] **Step 2: Add `make check` to the cluster-simulator CI build path.**
- [ ] **Step 3: Build and run the focused binary.**

  Run: `make -C test/deps/cluster_simulator check -j"$(nproc)"`

  Expected: FAIL because the current tuple cannot distinguish omitted from explicitly empty comments and diagnostics omit comments.

### Task 2: Preserve comment presence and apply the semantic contract

**Files:**
- Modify: `test/deps/cluster_simulator/lib/common_utils.h`
- Modify: `test/deps/cluster_simulator/lib/common_utils.cpp`

**Interfaces:**
- Produces: `MYSQL_SERVER_STATUS_T::COMMENT_IS_SET` and a nine-element `server_status` whose final boolean records comment presence.
- Preserves: all existing public helper names and checksum behavior.

- [ ] **Step 1: Extend `server_status` and its index enum with the presence bit.**
- [ ] **Step 2: Set the bit in `extract_cluster_status()` using `m_mysql_server.contains("comment")`.**
- [ ] **Step 3: Compare comments only when the expected presence bit is true.**
- [ ] **Step 4: Serialize comments only when their presence bit is true.**
- [ ] **Step 5: Rebuild and rerun `common_utils_unit-t`.**

  Expected: all focused TAP assertions pass.

### Task 3: Document and verify the shared behavior

**Files:**
- Modify: `test/deps/cluster_simulator/README.md`

**Interfaces:**
- Documents: optional expected-state fields and omission-as-wildcard semantics.

- [ ] **Step 1: Update the payload-format documentation with the exact optional-field contract.**
- [ ] **Step 2: Build the cluster simulator with bounded parallelism.**
- [ ] **Step 3: Run the Galera simulator group repeatedly in a unique isolated infrastructure.**
- [ ] **Step 4: Run at least one additional shared-comparator simulator family.**
- [ ] **Step 5: Run `git diff --check`, inspect the full diff, and verify the worktree contains only this fix.**
- [ ] **Step 6: Commit the implementation with a focused message.**
- [ ] **Step 7: Push the dedicated branch and open a draft PR against `v3.0` describing the CI evidence and independence from PR #6017.**
