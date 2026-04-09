Title: ProxySQL Static Analysis Design
Date: 2026-04-09
Author: OpenCode (assistant) + Rene

Summary
-------
This design defines an incremental static analysis rollout for the ProxySQL codebase. The goal is to catch bugs and modernize C++ usage with minimal disruption by starting with a focused target (lib/*.cpp and include/*.h) and enabling clang-tidy and cppcheck with a baseline/suppression strategy and CI integration.

Goals & Success Criteria
-----------------------
- Goals:
  - Surface real bugs and risky patterns (null-deref, use-after-free, incorrect APIs).
  - Apply low-risk, automated modernizations where safe (nullptr, override, loop-convert).
  - Prevent regressions via CI that blocks new warnings for the chosen scope.
- Success criteria (initial):
  - CI annotates PRs with clang-tidy/cppcheck findings for files under lib/ and include/.
  - No new warnings are introduced in PRs for the scoped files (baseline vs new).
  - Team triages high-severity findings within the first release cycle.

Scope
-----
- Initial scope (Phase 1): lib/*.cpp and include/*.h — core library and public headers.
- Expansion plan: after stabilization, expand to test/, tools/, scripts/, and finally repository-wide.

Tools & Checks
--------------
- clang-tidy (primary):
  - Use a repo-top .clang-tidy file to configure checks.
  - Initial recommended checks:
    - clang-analyzer-*
    - bugprone-*
    - performance-*
    - modernize-use-nullptr
    - modernize-use-override
    - modernize-loop-convert
    - modernize-pass-by-value
    - readability-braces-around-statements
  - Start conservative with modernize checks; add more once noise is controlled.
  - Allow developers to run `clang-tidy -fix` locally; CI will not auto-fix.

- cppcheck (complementary):
  - Run with: `--enable=warning,performance,portability,style --std=c++17 --project=compile_commands.json --inline-suppr`
  - Do not enable `--inconclusive` initially.

Compilation Database
--------------------
- clang-tidy requires compile_commands.json. Two capture options:
  1. Preferred for current Makefile-based build: use Bear to capture the build:
     `bear -- make -j$(nproc)`
  2. If moving to CMake: use `CMAKE_EXPORT_COMPILE_COMMANDS=1` with Ninja/CMake.
- Provide helper scripts under scripts/lint/ to generate compile_commands.json and other artifacts.

Baseline & Suppression Strategy
--------------------------------
- One-time baseline: run clang-tidy and cppcheck across the initial scope and commit normalized outputs to `lint/`:
  - lint/baseline-clang-tidy.txt
  - lint/baseline-cppcheck.txt
- CI compares current warnings to baseline and only fails on new/changed warnings.
- Suppressions:
  - Prefer fixing issues when feasible.
  - Use `// NOLINT(reason)` sparingly for clang-tidy false positives or legacy constraints.
  - Use cppcheck inline suppressions or a central suppression config when absolutely necessary.
  - Maintain a short `lint/SUPPRESSIONS.md` documenting suppression policy and examples.

CI Integration (High-Level)
--------------------------
- Add `.github/workflows/CI-static-analysis.yml` with a job that:
  - Installs clang-tidy, cppcheck, and Bear.
  - Generates compile_commands.json (via Bear) for the build.
  - Runs clang-tidy and cppcheck limited to the initial scope.
  - Exports results (clang-tidy `-export-fixes`, cppcheck `--xml`) and normalizes a text report.
  - Compares report to baseline and posts annotations to the PR.
  - Initial mode: annotate only (do not fail the job). Later: fail on new warnings.

Developer Workflow
------------------
- Provide `make lint` target and `scripts/lint/run-local.sh` that:
  - Generates compile_commands.json (via Bear or from an existing build dir).
  - Runs clang-tidy on target files and cppcheck project scan.
- Optional lightweight pre-commit hook: run clang-format and lint only on staged/changed files. Keep hook fast.
- Encourage `clang-tidy -fix` locally for safe automated modernizations.

Rollout Roadmap
----------------
- Phase 0 (baseline):
  - Capture compile_commands.json and run full scans for initial scope.
  - Commit baseline reports to lint/.
- Phase 1 (annotation):
  - CI annotates PRs for the scoped files (no failures yet).
- Phase 2 (triage & fix):
  - Triage high-severity warnings, fix where feasible, add targeted suppressions.
- Phase 3 (enforcement):
  - Enable CI to fail on new warnings for scoped files.
- Phase 4 (expand scope):
  - Incrementally add additional directories to the scope.
- Phase 5 (optional):
  - Add clang-format enforcement if desired.

Metrics & Maintenance
---------------------
- Track:
  - Total warnings by tool and severity for the scoped files.
  - New warnings introduced per PR.
  - Trend over time (weekly). Keep metrics in a small CSV or JSON under lint/metrics/.
- Maintenance tasks:
  - Update .clang-tidy to add/remove checks as noise is tuned.
  - Refresh baseline files when making bulk safe fixes.
  - Keep scripts under scripts/lint/ in repo and executable by contributors.

Open Questions
--------------
1. Confirm initial scope: lib/*.cpp and include/*.h (recommended). — Approved.
2. Use Bear to capture compile_commands.json for the initial capture? — Approved.
3. CI policy: annotation-first, then fail on new findings. — Approved.

Acceptance / Next Steps
----------------------
I will:
1. Commit this design document at docs/superpowers/specs/2026-04-09-linting-design.md (done).
2. Wait for your review. If you request changes, I will update the doc.
3. After you approve the spec file contents, I will invoke the writing-plans skill to produce an implementation plan.

Document History
----------------
- 2026-04-09: Initial design committed.
