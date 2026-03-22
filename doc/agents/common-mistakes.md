# Common Mistakes by AI Coding Agents

Patterns observed across multiple AI agent interactions on the ProxySQL codebase, with root cause analysis and prevention strategies.

## 1. Wrong Branch Target

**Symptom:** PR targets `v3.0` (main) instead of the feature branch.

**Root cause:** Agents prioritize technical content over administrative instructions. Even when branch info is present in the issue, agents often skim past it while focusing on code requirements, then use heuristics (e.g., most recent branch, default branch) to fill the gap they don't realize they have.

**Prevention:** Place git workflow instructions **at the very top** of the issue, before the technical description. Agents read top-down with decreasing attention — administrative details buried after exciting code specs will be skipped.

```
### FIRST: Git workflow (do this before reading anything else)
- Create branch `v3.0-XXXX` from `v3.0-5473`
- PR target: `v3.0-5473`
```

**Detection:** Check `gh pr view <number> --json baseRefName` after PR creation.

---

## 2. Reimplemented Functions in Test Files

**Symptom:** Test file contains copy-pasted reimplementations of the functions under test. Tests validate the copy, not the real production code.

**Root cause:** Agent doesn't know the build system links tests against `libproxysql.a`, so it creates standalone tests that don't depend on the library.

**Prevention:**
- Explain that tests link against `libproxysql.a` (the real functions are available at link time)
- Add to DO NOT list: "Do NOT reimplement extracted functions in the test file"
- Provide the Makefile rule that shows the linking

**Detection:** `grep -c "static.*calculate_eviction\|static.*evaluate_pool" test_file.cpp` — if > 0, functions were reimplemented.

---

## 3. Test Files in Wrong Directory

**Symptom:** Test placed in `test/tap/tests/` (E2E test directory) instead of `test/tap/tests/unit/` (unit test directory).

**Root cause:** Agent sees existing test files in `test/tap/tests/` and follows that pattern. Doesn't know about the `unit/` subdirectory.

**Prevention:** Specify the exact file path including directory in the issue deliverables.

**Detection:** `ls test/tap/tests/*unit*` should return nothing — unit tests belong in `test/tap/tests/unit/`.

---

## 4. Manual TAP Symbol Stubs

**Symptom:** Test file manually defines `noise_failures`, `noise_failure_mutex`, `stop_noise_tools()`, `get_noise_tools_count()`.

**Root cause:** Agent compiles `tap.cpp` which references these symbols. Without the harness, the agent must define them. This is a signal the agent isn't using the harness.

**Prevention:**
- Explain that `test_globals.cpp` already provides all TAP stubs
- Add to DO NOT list: "Do NOT define noise_failures or stop_noise_tools"

**Detection:** `grep -c "noise_failures\|stop_noise_tools" test_file.cpp` — if > 0, harness not used.

---

## 5. Merged Instead of Rebased

**Symptom:** PR diff includes dozens of unrelated files because the agent ran `git merge <upstream>` into its branch.

**Root cause:** Agent's default strategy for incorporating upstream changes is merge. This creates a merge commit that brings all upstream changes into the PR diff.

**Prevention:** Explicit instruction: "Use `git rebase`, NOT `git merge`."

**Detection:** `git log --merges <branch> --not <base>` — any merge commits indicate merging.

---

## 6. Circular Include Dependencies

**Symptom:** Production code compiles on the agent's machine (or doesn't get tested) but fails in CI or on other platforms with "unknown type name" errors.

**Root cause:** ProxySQL has circular include chains (`proxysql.h` → `cpp.h` → `MySQL_HostGroups_Manager.h` → `Base_HostGroups_Manager.h` → `proxysql.h`). Placing new declarations in these headers can result in the declarations being invisible depending on include order.

**Prevention:**
- Create standalone headers with their own include guards (e.g., `ConnectionPoolDecision.h`)
- Explicitly warn about the circular chain in the issue
- Require `make build_lib -j4` as a verification step

**Detection:** Compilation failure with "unknown type name" for a type that clearly exists in a header.

---

## 7. Modified Existing Test Files Instead of Creating New Ones

**Symptom:** Agent adds tests to an existing test file instead of creating a new one for the new feature.

**Root cause:** Agent sees a test file for a related component and assumes new tests belong there.

**Prevention:** Specify the exact test file name in the issue: "Create `test/tap/tests/unit/my_feature_unit-t.cpp`."

---

## 8. Didn't Verify Compilation

**Symptom:** PR contains code that doesn't compile. Agent submitted without building.

**Root cause:** Some agents don't have access to the build environment, or don't run the build as part of their workflow.

**Prevention:**
- Add explicit verification step: "`make build_lib -j4` must exit with code 0"
- Add to acceptance criteria as a hard requirement

---

## 9. Overly Broad Changes

**Symptom:** Agent refactors callers, updates documentation, fixes unrelated bugs, or "improves" code outside the task scope.

**Root cause:** Agent optimizes for perceived quality/completeness and makes changes it considers beneficial.

**Prevention:**
- Explicitly scope: "Only modify `<list of files>`"
- Add: "Do not refactor code outside the scope of this task"
- Add: "Do not fix pre-existing issues you notice — file separate issues for those"

---

## Summary: Red Flags in Agent PRs

Quick checks to run on any agent-generated PR:

```bash
# Wrong base branch?
gh pr view <PR> --json baseRefName -q '.baseRefName'

# Test in wrong directory?
gh pr diff <PR> | grep "^+++ b/test/tap/tests/[^u]"

# Reimplemented functions?
gh pr diff <PR> | grep "^+static.*calculate_\|^+static.*evaluate_\|^+static.*should_"

# Manual TAP stubs?
gh pr diff <PR> | grep "^+.*noise_failures\|^+.*stop_noise_tools"

# Merge commits?
gh pr view <PR> --json commits --jq '.commits[].messageHeadline' | grep -i merge

# Unrelated files changed?
gh pr diff <PR> | grep "^+++ b/" | grep -v "<expected_files_pattern>"
```
