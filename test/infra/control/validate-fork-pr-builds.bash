#!/usr/bin/env bash
set -euo pipefail

base_ref=${1:?usage: $0 <base-ref> <gh-actions-ref>}
actions_ref=${2:?usage: $0 <base-ref> <gh-actions-ref>}
export BASE_BUILDS="$base_ref:.github/workflows/CI-builds.yml"
export FORK_BUILDS="$base_ref:.github/workflows/CI-builds-fork.yml"
export REUSABLE_BUILDS="$actions_ref:.github/workflows/ci-builds.yml"

ruby <<'RUBY'
require 'yaml'

def workflow(ref)
  YAML.load(`git show #{ref}`)
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
assert(fork_run.fetch('uses') == 'sysown/proxysql/.github/workflows/ci-builds.yml@GH-Actions', 'fork workflow uses the wrong reusable workflow')
assert(fork_run.fetch('with').fetch('trusted') == false, 'fork workflow does not select untrusted mode')
assert(!fork_run.key?('secrets'), 'fork workflow inherits or passes secrets')

reusable_event = reusable['on'] || reusable.fetch(true)
inputs = reusable_event.fetch('workflow_call').fetch('inputs')
assert(inputs.fetch('trusted').fetch('default') == true, 'reusable workflow lacks trusted=true default')
builds = reusable.fetch('jobs').fetch('builds')
assert(builds.fetch('runs-on').include?('inputs.trusted'), 'untrusted mode does not force hosted runner selection')
actual_matrix = builds.fetch('strategy').fetch('matrix').fetch('include').map { |entry| [entry.fetch('dist'), entry.fetch('type')] }.sort
expected_matrix = [['debian12', '-dbg'], ['ubuntu22', '-tap'], ['ubuntu22', '-tap-mysqlx'], ['ubuntu24', '-tap-genai-gcov']].sort
assert(actual_matrix == expected_matrix, "unexpected build matrix: #{actual_matrix.inspect}")

privileged_steps = builds.fetch('steps').select do |step|
  step.fetch('uses', '').include?('LouisBrunner/checks-action') ||
    step.fetch('uses', '').include?('actions/cache/') ||
    step.fetch('uses', '').include?('actions/upload-artifact') ||
    step.fetch('name', '').match?(/Pack (bin|test|src \+ matrix) cache|Upload handoff|Archive artifacts/)
end
assert(!privileged_steps.empty?, 'no privileged steps discovered')
privileged_steps.each do |step|
  assert(step.fetch('if', '').include?('inputs.trusted'), "privileged step is not trusted-gated: #{step['name'] || step['uses']}")
end

raw = [base, fork, reusable].map(&:to_s).join
assert(!raw.include?('allow-unsafe-pr-checkout: true'), 'unsafe fork checkout enabled')
RUBY
