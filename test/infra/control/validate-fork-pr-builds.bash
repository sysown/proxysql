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
# Snapshot of the matrix as of the callee SHA pinned by CI-builds-fork.yml.
# Refresh this together with that pin. It was four entries until
# 64b1465a9 / 308c14d67 (2026-09-06) retired the duplicate legs.
expected_matrix = [['ubuntu24', '-tap-genai-gcov']].sort
assert(actual_matrix == expected_matrix, "unexpected build matrix: #{actual_matrix.inspect}")

privileged_steps = reusable.fetch('jobs').values.flat_map { |job| job.fetch('steps', []) }.select do |step|
  step.fetch('uses', '').include?('LouisBrunner/checks-action') ||
    step.fetch('uses', '').include?('actions/cache/') ||
    step.fetch('uses', '').include?('actions/upload-artifact') ||
    step.fetch('name', '').match?(/Pack (bin|test) cache|Pack src \+ matrix for handoff|Upload handoff|Archive artifacts/)
end
assert(!privileged_steps.empty?, 'no privileged steps discovered')

# A privileged step is safe when its gate cannot be satisfied without
# inputs.trusted. The dangerous shape is a TOP-LEVEL `||`, as in
# `inputs.trusted && a || b` or `(inputs.trusted && a) || b`, where the
# right operand can be true on its own and bypass the guard. A `||`
# nested inside parentheses is already covered by the leading
# `inputs.trusted &&` prefix -- e.g. the `Archive artifacts` gate
# `inputs.trusted && failure() && !cancelled() && (a || b)` -- so only a
# `||` at paren depth 0 counts against the step.
def top_level_disjunction?(condition)
  depth = 0
  index = 0
  while index < condition.length
    case condition[index]
    when '(' then depth += 1
    when ')' then depth -= 1
    when '|'
      return true if condition[index + 1] == '|' && depth.zero?
      index += 1
    end
    index += 1
  end
  false
end

privileged_steps.each do |step|
  condition = step.fetch('if', '')
  assert(condition.match?(/\A\$\{\{\s*inputs\.trusted\s*&&/) && !top_level_disjunction?(condition), "privileged step is not trusted-gated: #{step['name'] || step['uses']}")
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
