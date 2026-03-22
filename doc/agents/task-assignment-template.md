# Task Assignment Template for AI Agents

Use this template when writing GitHub issues that will be assigned to AI coding agents. The goal is to eliminate ambiguity — agents interpret every gap in the most expedient way possible.

## Core Principle

**Describe the HOW as precisely as the WHAT.** Intent is what you write for a human who can ask questions. Unambiguous instructions are what you write for an agent that cannot.

---

## Template

```markdown
## Task: <one-line description>

### Context
<Why this task exists. Link to parent issue. What problem it solves.>

### Deliverables
- [ ] New file: `<exact/path/to/file>` — <what it does>
- [ ] New file: `<exact/path/to/file>` — <what it does>
- [ ] Modified: `<exact/path/to/file>` — <what changes>

### Git workflow
- Create branch `<branch-name>` from `<base-branch>`
- PR target: `<target-branch>`
- If upstream changes needed: `git rebase`, NOT `git merge`

### Implementation details
<Describe the approach. Include function signatures, struct definitions,
or pseudocode. The more concrete, the fewer wrong turns.>

### Build & verification
```bash
<exact command to build>    # Must exit 0
<exact command to test>     # Must show all tests passing
```

### DO NOT
- <anti-pattern 1 — explain why>
- <anti-pattern 2 — explain why>
- <anti-pattern 3 — explain why>

### Reference files
Study these before starting:
- `<path>` — for <what pattern to follow>
- `<path>` — for <what pattern to follow>

### Acceptance criteria
- [ ] <binary verifiable criterion with exact command or check>
- [ ] <binary verifiable criterion>
- [ ] <binary verifiable criterion>
```

---

## Checklist for the Orchestrator

Before publishing the issue, verify each of these:

### 1. Did I specify WHERE?
- [ ] Exact file paths for every new file
- [ ] Exact file paths for every modified file
- [ ] Directory that files go in (not just the repo root)
- [ ] Files that should NOT be modified

### 2. Did I specify HOW?
- [ ] Code template or skeleton (includes, boilerplate, structure)
- [ ] Build system integration (Makefile rules, CMake, etc.)
- [ ] How the new code connects to existing code (linking, imports)
- [ ] Pattern to follow (reference file)

### 3. Did I specify the environment?
- [ ] Base branch to create from
- [ ] Target branch for PR
- [ ] Branch naming convention
- [ ] Git workflow (rebase vs merge)
- [ ] Build command to verify compilation
- [ ] Test command to verify functionality

### 4. Did I provide reference examples?
- [ ] At least one existing file that follows the desired pattern
- [ ] Pointed to it explicitly ("follow the pattern in `<file>`")

### 5. Did I write a DO NOT list?
- [ ] Listed known anti-patterns for this specific task
- [ ] Explained WHY each is wrong (agents ignore rules they don't understand)

### 6. Are acceptance criteria binary?
- [ ] Each criterion is answerable with pass/fail
- [ ] Each criterion can be verified with a specific command or file check
- [ ] No subjective criteria ("well-structured", "clean", "appropriate")

### 7. Did I anticipate the agent's likely mistakes?
- [ ] Asked: "If I had no context beyond this issue and the repo, what would I get wrong?"
- [ ] Added explicit instructions to prevent each predicted mistake

### 8. Did I scope the blast radius?
- [ ] Defined what's in scope
- [ ] Defined what's out of scope
- [ ] Separated production code from test code expectations
- [ ] Limited the task to one clear deliverable (or ordered multiple steps explicitly)

---

## Common Mistakes Agents Make (and how to prevent them)

| Agent behavior | Root cause | Prevention |
|---|---|---|
| Uses wrong branch | No branch specified | Explicit branch instructions |
| Places files in wrong directory | No directory specified | Exact file paths |
| Reimplements code instead of linking | Doesn't know the build system | Explain linking model, provide Makefile snippet |
| Creates workarounds for missing infra | Doesn't know infra exists | Reference existing infrastructure files |
| Merges instead of rebasing | No git workflow specified | Explicit "rebase, NOT merge" |
| Modifies unrelated files | Scope too broad | "DO NOT modify files outside `<list>`" |
| Satisfies letter but not spirit | Ambiguous requirements | Make the spirit explicit in DO NOT list |
| Doesn't verify compilation | No verification step | Explicit build command in acceptance criteria |

---

## Example: Good vs Bad Issue

### Bad issue
> Extract the server selection algorithm from HostGroups Manager and write unit tests for it.

### Good issue
> **Task:** Extract server selection into `select_server_from_candidates()`
>
> **Deliverables:**
> - New file: `include/ServerSelection.h` — struct + function declaration
> - Modified: `lib/Base_HostGroups_Manager.cpp` — call extracted function
> - New file: `test/tap/tests/unit/server_selection_unit-t.cpp` — 15+ test cases
> - Modified: `test/tap/tests/unit/Makefile` — register test
>
> **Git:** Branch `v3.0-5492` from `v3.0-5473`. PR targets `v3.0-5473`.
>
> **DO NOT:** Reimplement functions in test. Place test in `test/tap/tests/`.
>
> **Reference:** `include/ConnectionPoolDecision.h`, `test/tap/tests/unit/connection_pool_unit-t.cpp`
>
> **Verify:** `make build_lib -j4` exits 0. `./server_selection_unit-t` shows "Test took" with no failures.
