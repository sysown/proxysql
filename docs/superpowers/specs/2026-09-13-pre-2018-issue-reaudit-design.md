# Pre-2018 issue re-audit

## Objective

Correct the status of the open pre-2018 issues tracked by GitHub issue #5851 and
replace its stale priority queue with an evidence-backed top-ten list.

## Scope

- Inspect all GitHub issues in `sysown/proxysql` that are open and were created
  before 2018-01-01.
- Compare each issue's original report with current source, tests, Git history,
  release tags, and issue discussion.
- Close only issues whose original behavior is demonstrably fixed. Every closure
  receives an issue-specific comment citing the relevant implementation,
  regression coverage, or release.
- Add a dated #5851 comment that records newly closed issues, issues intentionally
  left open, and the revised top-ten priority list.

## Priority method

Rank still-open issues by: (1) present correctness and user impact, (2)
operational impact, and (3) implementation readiness. Do not promote issues
which require an unresolved product or security design decision unless they are
urgent.

## Safeguards

- Age or inactivity is never closure evidence.
- A related feature is insufficient: the original requested behavior must be
  covered.
- Record uncertainty as remaining open rather than closing it.
