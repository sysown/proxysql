# Issue tracker: GitHub

Issues and specs live in `sysown/proxysql` on GitHub.
Use the `gh` CLI with `--repo sysown/proxysql` to select the
correct repository explicitly.

## Operations

- Create: `gh issue create --repo sysown/proxysql --title "..." --body-file <file>`
- Read: `gh issue view <number> --repo sysown/proxysql --json number,title,body,labels,comments`
- Browse up to 100 open issues: `gh issue list --repo sysown/proxysql --state open --limit 100 --json number,title,body,labels`
- Enumerate all open issues: `gh api --paginate 'repos/sysown/proxysql/issues?state=open&per_page=100' --jq '.[] | select(.pull_request == null) | {number,title,body,labels,assignees}'`
- Assign to yourself: `gh issue edit <number> --repo sysown/proxysql --add-assignee @me`
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

The map body has a `## Children` section for the ordered child links when
sub-issues are unavailable, and a `## Decisions so far` section containing
dated bullets with the decision, rationale and supporting issue/PR link.

Record blockers using GitHub issue dependencies. If unavailable,
use `Blocked by: #<number>` in the child body.

Read the map's actual children and their current status, preserving map order.
Paginate API collections when enumerating children or blockers; the bounded
browse command is not a complete work queue. Select the first open, unassigned
child with no open blockers and claim it by assigning yourself. On resolution,
comment, close it, and add a dated result summary and link to the map's
`Decisions so far` section.
