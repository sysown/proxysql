# Issue tracker: GitHub

Issues and specs live in `sysown/proxysql` on GitHub.
Use the `gh` CLI with `--repo sysown/proxysql` to select the
correct repository explicitly.

## Operations

- Create: `gh issue create --repo sysown/proxysql --title "..." --body-file <file>`
- Read: `gh issue view <number> --repo sysown/proxysql --json number,title,body,labels,comments`
- List: `gh issue list --repo sysown/proxysql --state open --json number,title,body,labels`
- Comment: `gh issue comment <number> --repo sysown/proxysql --body-file <file>`
- Label: `gh issue edit <number> --repo sysown/proxysql --add-label "..."` or `--remove-label "..."`
- Close: `gh issue close <number> --repo sysown/proxysql --comment "..."`

When a skill says "publish to the issue tracker", create a GitHub issue.
When it says "fetch the relevant ticket", read the GitHub issue.

## Pull requests as a triage surface

**PRs as a request surface: no.**

## Wayfinding

A map is an issue labelled `wayfinder:map`. Child tickets use
`wayfinder:research`, `wayfinder:prototype`, `wayfinder:grilling`,
or `wayfinder:task`.

Link children using GitHub sub-issues. If unavailable, use a task list
in the map and `Part of #<map>` in each child.

Record blockers using GitHub issue dependencies. If unavailable,
use `Blocked by: #<number>` in the child body.

Select the first open, unassigned child in map order with no open
blockers. Claim it by assigning yourself. On resolution, comment,
close it, and add a result summary and link to the map's Decisions-so-far.
