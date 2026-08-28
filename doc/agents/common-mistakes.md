# Common Mistakes by AI Coding Agents

Patterns observed across multiple AI agent interactions on the ProxySQL codebase, with root cause analysis and prevention strategies.

## Pre-Push Checklist

Apply to every push:

1. **Code compiles.** `make -j$(nproc) debug` for core changes; `make build_tap_test_debug` for test/header changes. Never push a header-touching change without a build. (§8)
2. **Unit tests pass — if fast.** `for t in test/tap/tests/unit/*-t; do "$t"; done`. Run this when the binaries are already built and exercise it costs seconds, not when it forces a fresh build that takes 10+ minutes. The goal is "fast feedback that core didn't break", not "exhaustive verification of every edge".
3. **Vendored-library bumps validated through the real consumer.** Library's own test suite is necessary but insufficient. (§10)
4. **Failing tests investigated, not dismissed.** No "flaky" / "baseline" / "pre-existing" labels without a deterministic mechanism attached. (§11)
5. **Comprehensive claims backed by exhaustive probes.** When the fix is "comprehensive" / "all at once" / "one bump", the catalogue of inputs that were probed must exist *before* the fix list. (§12)
6. **CI red lights diagnosed before reacting.** Real test failure vs status-reporter / cache-race / auth blip. The PR-status column hides which step actually failed. (§13)

---

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

**Root cause:** Some agents don't have access to the build environment, or don't run the build as part of their workflow. Even agents with access skip it under time pressure, especially after "small" edits that "obviously" shouldn't break.

**Prevention:**
- Add explicit verification step: "`make build_lib -j$(nproc)` must exit with code 0"
- For changes touching headers, `lib/` core, or any type signature: a full `make -j$(nproc) debug` is required (header changes can break translation units the agent didn't read).
- Use `-j$(nproc)` not bare `make` / `make debug` — the debug target doesn't auto-parallelize and silently runs single-threaded on multi-core hosts, turning a 3-minute build into 25 minutes.
- For changes touching test code: `make build_tap_test_debug` to confirm all test binaries still link.

**Detection:** `ls -la src/proxysql lib/libproxysql.a` mtimes vs the last source change; if older, no build happened.

---

## 9. Overly Broad Changes

**Symptom:** Agent refactors callers, updates documentation, fixes unrelated bugs, or "improves" code outside the task scope.

**Root cause:** Agent optimizes for perceived quality/completeness and makes changes it considers beneficial.

**Prevention:**
- Explicitly scope: "Only modify `<list of files>`"
- Add: "Do not refactor code outside the scope of this task"
- Add: "Do not fix pre-existing issues you notice — file separate issues for those"

---

## 10. Validate Dependency Fixes via the Real Consumer Before Tagging

**Symptom:** Library tag (e.g. ParserSQL v1.0.X) ships, downstream bump pulls it in, downstream tests immediately surface a regression the library's own test suite didn't catch. Cycle repeats with v1.0.X+1, v1.0.X+2.

**Root cause:** Library test suite is necessary but insufficient — it tests what the library author thought to test, not what the actual consumer exercises. Tagging based on "library tests pass" ships hopes, not fixes.

**Prevention:** Before tagging any release of a vendored / sibling library, the validation gate **must include the downstream consumer's tests**. Concretely for ParserSQL ↔ ProxySQL:

1. Apply fix to local ParserSQL working tree (don't commit yet).
2. `make lib` in ParserSQL → produces `libsqlparser.a`.
3. Copy `libsqlparser.a` (and any changed headers) into `deps/parsersql/parsersql/` of a local ProxySQL checkout.
4. Force-rebuild ProxySQL: `rm -f lib/libproxysql.a src/proxysql && make -j$(nproc) debug`.
5. Build + run the integration test: `make -C test/tap/tests setparser_parsersql_test-t && ./test/tap/tests/setparser_parsersql_test-t`.
6. Build + run the regex-parser-equivalent tests too (shared fixtures): `setparser_test`, `setparser_test2`, `setparser_test3`.
7. **Only after all of the above are green**: commit to ParserSQL, push, PR, merge, tag.
8. Regenerate the tarball from the tag, drop into `deps/parsersql/`, re-run the full validation against the *official* tarball one final time.

**Detection:** Any new ParserSQL tag pushed within 24 hours of a same-day tag-bump-then-retag cycle on the proxysql side is a sign the integration-test gate was skipped.

---

## 11. Don't Dismiss Failing Tests as "Pre-existing" / "Baseline" / "Flaky"

**Symptom:** Agent encounters a failing test, classifies it as "known baseline failure, not introduced by this PR", and moves on without investigation. The test is actually exposing a real bug the codebase had been hiding.

**Root cause:** The "flaky" / "baseline" label is a research-stopping shortcut. It conflates "happens often" with "we understand why and have decided not to fix". Most of the time only the first is true.

The `set_parser_algorithm_3-g1` group is a recent example: reported as "every PR fails this — must be a pre-existing baseline issue, ignore". It turned out PR #5760 had recently fixed a CI infra bug (`ensure-infras.bash` not dispatching `pre-proxysql.sql` hooks), which made the group actually run its `SET *_parser_algorithm=3` setup for the first time, exposing genuine ParserSQL bugs that had been silently hidden by the broken hook dispatcher. Those bugs were real and got fixed in 10 commits across ParserSQL v1.0.4–1.0.6.

**Prevention:**
- "Pre-existing" doesn't mean "ignore". It means "investigate at the project-history level: when did this start failing, what changed, is it a real bug being exposed".
- "Flaky" is not a diagnosis — it's the *absence* of a diagnosis. Either find the deterministic mechanism behind the timing (then it stops being flaky) or document the analysis inline in the test so the next person doesn't have to redo it (see the comment block in `test/tap/tests/reg_test_4072-show-warnings-t.cpp` for an example).
- Before dismissing: run the test in isolation, read the proxysql.log artifact (not just the TAP summary), trace the failure to a specific line and either a code bug or an environmental cause.

**Detection:** Search agent commits for `// known flaky`, "pre-existing failure", "baseline noise" — each is a research-stopper that should be replaced with either a deterministic root cause or an inline analysis comment.

---

## 12. Exhaustive Probe Before Declaring "Comprehensive Fix"

**Symptom:** Agent claims to have "fixed all issues", ships a tag/release, and then immediately finds more issues that should have been caught in the same pass.

**Root cause:** Agent investigates only the symptoms it was pointed at, fixes those, then declares done. The user asked for "comprehensive" — the agent delivered "fixed the cases that were reported". Subsequent probing reveals adjacent / related forms that have the same class of bug.

This is what produced the ParserSQL v1.0.4 → v1.0.5 → v1.0.6 churn in a single session: each release "fixed everything" until the next round of probing found more.

**Prevention:** When asked to fix something "comprehensively" / "all at once" / "with one bump":

1. **Catalogue the full surface area first.** For SET parsing: every form documented by the dialect (PG `SET SCHEMA`, `SET SEED`, `SET ROLE`, `SET CONSTRAINTS`, `SET TIME ZONE`, `SET SESSION CHARACTERISTICS`, `SET LOCAL`, `SET pg_catalog.X`, etc.). For SQL parsing in general: an AST-dumper probe over a curated catalogue of variants — quoted/unquoted, scoped/unscoped, expression-RHS, function-call-RHS, subquery-RHS, empty-RHS, truncated, etc.
2. **Probe ALL of them, dump the AST, record the result.** Do not stop at "the failing cases I was shown".
3. **Only after the probe sweep is complete**, list the fixes. Anything outside the catalogue is a known gap, called out as such.

**Detection:** If a tag bump is followed by another tag bump from the same author within hours, the first tag was claimed-comprehensive but wasn't probed comprehensively.

---

## 13. Distinguish Test Failure from CI Infrastructure Failure

**Symptom:** Agent reports "CI is failing on this PR" and starts investigating PR code, when the actual failure is in the CI plumbing (auth, runners, caches, status reporters) and the test step itself passed.

**Root cause:** The PR-status view summarizes the job's *exit code*, not which step failed. A status-reporter step failure (e.g., `LouisBrunner/checks-action` returning 401 from the GitHub API) marks the whole job as failure even though the tests passed. Same pattern for cache-restore failures: tests didn't run because deps weren't ready, but the job exits with "failure" indistinguishably from "tests ran and failed".

**Prevention:** Before assuming "the tests failed", look at the job's step list:

```bash
gh run view <run-id> --repo sysown/proxysql | grep -E "^  [✓X-]"
```

- `✓ Run <name> tests` followed by `X Run LouisBrunner/checks-action` → tests passed, status reporter failed. Re-trigger CI; don't touch the PR.
- `X Cache restore src` near the top → build cache wasn't ready (parallel `workflow_run` race); tests never ran. Re-trigger or dispatch builds first.
- `X Run <name> tests` → genuine test failure. Pull the TAP summary and the proxysql.log artifact.

**Detection:** `gh run view <run-id> --log 2>&1 | grep -E "SUMMARY: 'tests' PASS|FAIL log"` — if `SUMMARY: 'tests' PASS .../... FAIL 0/...` appears, the tests passed regardless of the job's overall exit code.

---

## 14. Don't Understand the Test Before "Fixing" It

**Symptom:** Agent debugs a failing test by adjusting assertions / increasing timeouts / disabling cases until the test passes, without understanding what the test was originally trying to verify.

**Root cause:** "Make CI green" is a tempting proxy goal. The actual goal is "make the codebase correct"; CI green is supposed to be the *evidence*. When the evidence and the cause are confused, the fix can make CI green while breaking the test's purpose.

`reg_test_4072-show-warnings-t` is a recent example: it's a regression test for a specific crash (issue #4072: "ProxySQL crashes if client is not able to keep up while a query produces warnings"). The `usleep(10)` per row in the fetch loop is *load-bearing* — it creates the slow-consumer back-pressure the crash needed to reproduce. "Removing the sleep to make the test fast" would silently defeat the test's purpose.

**Prevention:**
- Before changing a failing test: read its docstring, its referenced issue, its assertion text. State (in writing, in the commit message or inline comment) what the test is verifying and why each "odd" thing it does is there.
- Distinguish "the test's intent is violated" (real regression — fix the code) from "the test's assertion is stricter than its stated intent" (assertion overreach — fix the assertion, keep the docstring).
- For any test change, the commit message must include both: (a) what the test verifies, and (b) why this change preserves that verification.

**Detection:** Test changes whose commit message says "fix flaky test" / "increase timeout" / "skip failing cases" without quoting the test's docstring or assertion are red flags.

---

## 15. Don't Insert New Values in Public-API Enums — Append at End

**Symptom:** Adding a new enum value in the middle of a `NodeType` / `TokenType` / similar enum segfaults consumers that index arrays by enum value.

**Root cause:** Enum values are dense ordinals. Inserting a new value renumbers every subsequent value. Any code that does `array[(int)NodeType::X]` now indexes the wrong slot; any code with a `switch (n->type)` that relied on the numeric layout still type-checks fine but executes the wrong branch.

This bit me when adding `NODE_SET_ROLE` / `NODE_SET_SESSION_AUTHORIZATION` / `NODE_SET_CONSTRAINTS` in the middle of `NodeType` in ParserSQL — ProxySQL segfaulted at runtime because indexes baked into compiled code shifted.

**Prevention:**
- Append new enum values at the end, never insert in the middle.
- If logical grouping requires non-end insertion, audit and refactor every consumer that depends on the enum's numeric ordering: arrays-keyed-by-enum, switch statements with `default` fallthrough, serialized values on disk or the wire.

**Detection:** `git diff` shows the new enum value at a non-last position **and** any `switch` statement / array using that enum type as index changes its baked-in instruction sequence size in the linker output. Static check: ensure new enum values appear in the last group of lines before the closing `};`.

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
