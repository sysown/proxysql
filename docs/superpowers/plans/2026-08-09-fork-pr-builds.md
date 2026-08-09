# Safe Fork Pull Request Builds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Run the four existing build variants for approved fork PRs without executing fork code in the privileged `workflow_run` cascade.

**Architecture:** The existing `CI-trigger` → `CI-builds` cascade remains for same-repository heads and is skipped for fork heads. A fork-only direct `pull_request` caller invokes the shared build reusable workflow in an untrusted mode. That mode preserves build commands and matrix entries while removing privileged state transfers.

**Tech Stack:** GitHub Actions YAML, reusable workflows on `GH-Actions`, Bash validation.

## Global Constraints

- Fork builds run `debian12,-dbg`, `ubuntu22,-tap`, `ubuntu24,-tap-genai-gcov`, and `ubuntu22,-tap-mysqlx`.
- Fork code uses `pull_request`, `contents: read`, no inherited secrets, and GitHub-hosted runners only.
- Fork builds must not use shared cache operations, handoff or diagnostic artifact uploads, or `LouisBrunner/checks-action`.
- Never set `allow-unsafe-pr-checkout: true`.
- Same-repository CI behavior remains unchanged.

---

### Task 1: Add a cross-branch CI workflow validator

**Files:**

- Create: `test/infra/control/validate-fork-pr-builds.bash`

**Interfaces:**

- Consumes: base ref `$1`, GH-Actions ref `$2`.
- Produces: exit status 0 only when the trusted caller, fork caller, and reusable workflow satisfy the isolation contract.

- [ ] **Step 1: Write the failing test script**

```bash
#!/usr/bin/env bash
set -euo pipefail

base_ref=${1:?usage: $0 <base-ref> <gh-actions-ref>}
actions_ref=${2:?usage: $0 <base-ref> <gh-actions-ref>}
export BASE_BUILDS="$base_ref:.github/workflows/CI-builds.yml"
export FORK_BUILDS="$base_ref:.github/workflows/CI-builds-fork.yml"
export REUSABLE_BUILDS="$actions_ref:.github/workflows/ci-builds.yml"

ruby <<'RUBY'
require 'open3'
require 'yaml'

def workflow(ref)
  output, status = Open3.capture2('git', 'show', ref)
  raise "cannot read #{ref}" unless status.success?
  YAML.load(output)
end

def assert(condition, message)
  raise message unless condition
end

base = workflow(ENV.fetch('BASE_BUILDS'))
fork = workflow(ENV.fetch('FORK_BUILDS'))
reusable = workflow(ENV.fetch('REUSABLE_BUILDS'))

base_run = base.fetch('jobs').fetch('run')
assert(base_run.fetch('if').include?('head_repository.full_name == github.repository'), 'trusted CI-builds lacks same-repository guard')
assert(base_run.fetch('permissions') == 'write-all', 'trusted CI-builds permission changed')
assert(base_run.fetch('secrets') == 'inherit', 'trusted CI-builds secret handoff changed')

fork_event = fork['on'] || fork[true]
fork_run = fork.fetch('jobs').fetch('run')
assert(fork_event.key?('pull_request'), 'fork workflow is not pull_request-triggered')
assert(fork.fetch('permissions') == { 'contents' => 'read' }, 'fork workflow permissions are not exactly contents: read')
assert(fork_run.fetch('if').include?('head.repo.fork'), 'fork workflow is not restricted to fork heads')
assert(fork_run.fetch('uses').match?(%r{\Asysown/proxysql/\.github/workflows/ci-builds\.yml@[0-9a-f]{40}\z}), 'fork workflow does not pin the reusable workflow to a full commit SHA')
assert(fork_run.fetch('with').fetch('trusted') == false, 'fork workflow does not select untrusted mode')
fork.fetch('jobs').each_value do |job|
  assert(!job.key?('secrets'), 'fork workflow inherits or passes secrets')
  assert(!job.key?('permissions'), 'fork job overrides read-only workflow permissions')
end

reusable_event = reusable['on'] || reusable.fetch(true)
inputs = reusable_event.fetch('workflow_call').fetch('inputs')
assert(inputs.fetch('trusted').fetch('default') == true, 'reusable workflow lacks trusted=true default')
builds = reusable.fetch('jobs').fetch('builds')
runs_on = builds.fetch('runs-on')
assert(runs_on.match?(/\A\$\{\{\s*inputs\.trusted\s*&&\s*\(/) && runs_on.match?(/\)\s*\|\|\s*'ubuntu-24\.04'\s*\}\}\z/), 'untrusted mode does not force ubuntu-24.04')
actual_matrix = builds.fetch('strategy').fetch('matrix').fetch('include').map { |entry| [entry.fetch('dist'), entry.fetch('type')] }.sort
expected_matrix = [['debian12', '-dbg'], ['ubuntu22', '-tap'], ['ubuntu22', '-tap-mysqlx'], ['ubuntu24', '-tap-genai-gcov']].sort
assert(actual_matrix == expected_matrix, "unexpected build matrix: #{actual_matrix.inspect}")

privileged_steps = reusable.fetch('jobs').values.flat_map { |job| job.fetch('steps', []) }.select do |step|
  step.fetch('uses', '').include?('LouisBrunner/checks-action') ||
    step.fetch('uses', '').include?('actions/cache/') ||
    step.fetch('uses', '').include?('actions/upload-artifact') ||
    step.fetch('name', '').match?(/Pack (bin|test) cache|Pack src \+ matrix for handoff|Upload handoff|Archive artifacts/)
end
assert(!privileged_steps.empty?, 'no privileged steps discovered')
privileged_steps.each do |step|
  condition = step.fetch('if', '')
  assert(condition.match?(/\A\$\{\{\s*inputs\.trusted\s*&&/) && !condition.include?('||'), "privileged step is not trusted-gated: #{step['name'] || step['uses']}")
end

def contains_unsafe_checkout?(value)
  case value
  when Hash
    value.any? { |key, child| (key.to_s == 'allow-unsafe-pr-checkout' && child == true) || contains_unsafe_checkout?(child) }
  when Array
    value.any? { |child| contains_unsafe_checkout?(child) }
  else
    false
  end
end

assert(![base, fork, reusable].any? { |workflow| contains_unsafe_checkout?(workflow) }, 'unsafe fork checkout enabled')
RUBY
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `bash test/infra/control/validate-fork-pr-builds.bash HEAD origin/GH-Actions`

Expected: FAIL because the fork workflow and the reusable-workflow input do not exist. Once the implementation exists, this test semantically rejects absent or changed matrix pairs, fork callers with broader permissions or secrets, changes to the trusted caller's permission/secret contract, and privileged reusable-workflow steps that are not guarded by `inputs.trusted`.

- [ ] **Step 3: Commit the test**

```bash
git add test/infra/control/validate-fork-pr-builds.bash
git commit -m "test(ci): validate fork PR build isolation"
```

### Task 2: Add untrusted mode to the shared reusable workflow

**Files:**

- Modify on a branch from `origin/GH-Actions`: `.github/workflows/ci-builds.yml`

**Interfaces:**

- Consumes: `workflow_call.inputs.trusted`, a boolean with default `true`.
- Produces: existing trusted behavior for true; the same four builds without privileged operations for false.

- [ ] **Step 1: Create the GH-Actions worktree and extend the validator before changing the reusable workflow**

From the primary checkout, create the sibling worktree and branch:

```bash
git worktree add .worktrees/ci-fork-pr-builds-actions -b ci/fork-pr-builds-actions origin/GH-Actions
```

Add checks that require `inputs.trusted` to guard the cache restore/save/packing steps, both `LouisBrunner/checks-action` steps, every handoff upload, and the diagnostic artifact upload.

- [ ] **Step 2: Confirm the extended test fails**

Run from `.worktrees/ci-fork-pr-builds-actions`:

```bash
bash ../ci-fork-pr-builds/test/infra/control/validate-fork-pr-builds.bash ci/fork-pr-builds HEAD
```

Expected: FAIL because `ci-builds.yml` has no `trusted` input or guards.

- [ ] **Step 3: Implement the minimal reusable-workflow change**

Add the input:

```yaml
workflow_call:
  inputs:
    trigger:
      type: string
    trusted:
      description: Whether the caller may use privileged CI infrastructure.
      required: false
      type: boolean
      default: true
```

When `trusted` is false, force `runs-on: ubuntu-24.04`. Express the runner selection as a positive `inputs.trusted && (trusted-runner-selection) || 'ubuntu-24.04'` condition. Gate both `LouisBrunner/checks-action` steps, cache restore/pack/save steps, handoff pack/upload steps, and failure artifact upload with a positive `${{ inputs.trusted && ... }}` condition that contains no `||`. Keep `Checkout repository`, `Build`, and `Check build` active; skipped cache restore leaves the existing cache-hit condition true.

- [ ] **Step 4: Verify the reusable workflow**

```bash
ruby -e 'require "yaml"; YAML.load_file(".github/workflows/ci-builds.yml")'
git diff --check
bash ../ci-fork-pr-builds/test/infra/control/validate-fork-pr-builds.bash ci/fork-pr-builds HEAD
```

Expected: YAML and whitespace checks pass; the validator still fails only because the base fork caller is absent.

- [ ] **Step 5: Commit the reusable change**

```bash
git add .github/workflows/ci-builds.yml
git commit -m "ci: add untrusted fork build mode"
```

### Task 3: Add the fork caller and gate the trusted cascade

**Files:**

- Modify: `.github/workflows/CI-builds.yml`
- Modify: `.github/workflows/CI-trigger.yml`
- Create: `.github/workflows/CI-builds-fork.yml`

**Interfaces:**

- Consumes: `github.event.workflow_run.head_repository.full_name` and `github.event.pull_request.head.repo.fork`.
- Produces: direct restricted builds for forks; unchanged trusted cascading builds for same-repository PRs.

- [ ] **Step 1: Add the trusted-workflow guards**

Set the existing `CI-builds` job condition to:

```yaml
if: ${{ !github.event.workflow_run || github.event.workflow_run.head_repository.full_name == github.repository }}
```

Set the `CI-trigger` reusable caller job condition to:

```yaml
if: ${{ !github.event.pull_request || !github.event.pull_request.head.repo.fork }}
```

- [ ] **Step 2: Add the fork-only caller**

Create `.github/workflows/CI-builds-fork.yml`:

```yaml
name: CI-builds-fork

on:
  pull_request:
    paths-ignore:
      - '.github/**'
      - '**.md'

permissions:
  contents: read

jobs:
  run:
    if: ${{ github.event.pull_request.head.repo.fork }}
    uses: sysown/proxysql/.github/workflows/ci-builds.yml@GH-Actions
    with:
      trusted: false
```

Do not add `secrets: inherit`, `permissions: write-all`, or a custom checkout to this caller.

- [ ] **Step 3: Run the validator and YAML checks**

```bash
for workflow in .github/workflows/CI-builds.yml .github/workflows/CI-builds-fork.yml .github/workflows/CI-trigger.yml; do
  ruby -e 'require "yaml"; YAML.load_file(ARGV.fetch(0))' "$workflow"
done
git diff --check
bash test/infra/control/validate-fork-pr-builds.bash HEAD ci/fork-pr-builds-actions
```

Expected: all commands exit 0.

- [ ] **Step 4: Commit the base-branch change**

```bash
git add .github/workflows/CI-builds.yml .github/workflows/CI-builds-fork.yml .github/workflows/CI-trigger.yml test/infra/control/validate-fork-pr-builds.bash
git commit -m "ci: run fork PR builds in restricted workflow"
```

### Task 4: Security review and deployment sequencing

**Files:**

- Verify: the base-branch commit from Task 3 and GH-Actions commit from Task 2.

**Interfaces:**

- Consumes: both branch heads.
- Produces: a merge order that never leaves a caller referring to a missing reusable input.

- [ ] **Step 1: Inspect for privilege regressions**

```bash
git diff origin/v3.0...ci/fork-pr-builds -- .github/workflows test/infra/control/validate-fork-pr-builds.bash
git -C ../ci-fork-pr-builds-actions diff origin/GH-Actions...ci/fork-pr-builds-actions -- .github/workflows/ci-builds.yml
```

Confirm the fork caller and untrusted path contain no `allow-unsafe-pr-checkout: true`, `secrets: inherit`, or `permissions: write-all`.

- [ ] **Step 2: Re-run all validation**

```bash
bash test/infra/control/validate-fork-pr-builds.bash ci/fork-pr-builds ci/fork-pr-builds-actions
git diff --check origin/v3.0...ci/fork-pr-builds
git -C ../ci-fork-pr-builds-actions diff --check origin/GH-Actions...ci/fork-pr-builds-actions
```

- [ ] **Step 3: Merge in dependency order**

Merge the GH-Actions reusable-workflow change first, then the v3.0 caller change. Confirm a controlled fork PR runs four `CI-builds-fork` jobs on GitHub-hosted runners while `CI-builds` skips its privileged job.
