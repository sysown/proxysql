# Digest-text merge helper + PgSQL dead MySQL code removal — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lock in the #6437 digest-text leak fix with a unit-tested shared helper, and remove the dead MySQL code from the PgSQL classes (#6453).

**Architecture:** A new header-only `merge_digest_text_maps()` replaces the two inline `emplace`+`free` fold-backs in `get_query_digests_v2()`; `digest_stats_unit-t` exercises it. Separately, three `#if 0` blocks, their declarations, four dead `SETTING_*` switch cases and the unused `match_regexes[2]` slot are deleted from the PgSQL classes.

**Tech Stack:** C++17, ProxySQL `lib/`, TAP unit-test harness.

**Spec:** `docs/superpowers/specs/2026-10-12-digest-text-merge-and-pgsql-deadcode-design.md`

---

### Task 1: Header-only merge helper

**Files:**
- Create: `include/digest_text_merge.h`
- Modify: `lib/Query_Processor.cpp` (include + two fold-back sites)

- [ ] **Step 1: Create `include/digest_text_merge.h`** with `merge_digest_text_maps(umap_query_digest_text&, umap_query_digest_text&, std::vector<char*>* = nullptr)` that keeps `dst`'s pointer and frees or defers the incoming duplicate, then clears `src`.
- [ ] **Step 2:** Include it from `lib/Query_Processor.cpp`.
- [ ] **Step 3:** Replace the first fold-back loop with `merge_digest_text_maps(digest_text_umap_aux, digest_text_umap_aux_2);`.
- [ ] **Step 4:** Replace the second fold-back loop with the deferred form: collect into `texts_to_free`, call the helper with `&texts_to_free`, `pthread_rwlock_unlock`, then free.
- [ ] **Step 5:** Compile-check `Query_Processor.cpp`.

### Task 2: Regression unit test

**Files:**
- Modify: `test/tap/tests/unit/digest_stats_unit-t.cpp`

- [ ] **Step 1:** Include `digest_text_merge.h`.
- [ ] **Step 2:** Add `test_merge_digest_text_maps_eager()` and `test_merge_digest_text_maps_deferred()`.
- [ ] **Step 3:** Bump `plan()` and call the new tests.
- [ ] **Step 4:** Build and run `digest_stats_unit-t`.

### Task 3: Remove dead PgSQL MySQL handlers

**Files:**
- Modify: `lib/PgSQL_Session.cpp` (three `#if 0` blocks)
- Modify: `include/PgSQL_Session.h` (two `#if 0` blocks)

- [ ] **Step 1:** Delete the `#if 0` blocks and any now-empty surrounding whitespace.
- [ ] **Step 2:** Confirm no references to the deleted handlers remain.

### Task 4: Remove dead SETTING states and match_regexes[2]

**Files:**
- Modify: `lib/PgSQL_Session.cpp` (switch cases)
- Modify: `lib/PgSQL_Thread.cpp` (array init/teardown)

- [ ] **Step 1:** Remove the four dead `case` labels, keep `SETTING_VARIABLE`.
- [ ] **Step 2:** Shrink `match_regexes` to three slots and renumber the `client_encoding|names` regex to `[2]`.
- [ ] **Step 3:** Compile-check the PgSQL translation units.
- [ ] **Step 4:** `grep` confirms no `mysql_variable_name` reference remains under PgSQL files.

### Task 5: Commit

- [ ] **Step 1:** Commit docs, helper+test, and cleanup as separate atomic commits.
