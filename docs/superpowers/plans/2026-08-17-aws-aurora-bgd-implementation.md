# AWS Aurora Blue/Green Deployment Implementation Plan

> **For agentic workers:** Phase 3 uses incremental test-after development with
> characterization coverage. Use `superpowers:receiving-code-review`
> before addressing review feedback. Use the `gh` CLI for every GitHub review,
> comment, reply, check, and review-trigger operation.

This plan coordinates the implementation of the three approved specifications
under `docs/superpowers/specs/aws-aurora-blue-green/`.

**Goal:** Implement AWS Aurora MySQL blue/green deployment handling through
three review-gated phases, complete the configuration and simulator
prerequisites first, implement and verify the monitor/FSM in gated slices, and finish with a
real-Aurora user acceptance test before the PR is made ready to merge.

**Branch:** `feat/aws-aurora-bgd`

**Base:** current `upstream/v3.0`

**Pull request:** [sysown/proxysql#6044](https://github.com/sysown/proxysql/pull/6044),
from `feat/aws-aurora-bgd` to `v3.0`. Keep the PR draft until all three phases,
all review gates, and the real-Aurora acceptance gate pass.

## Authoritative Inputs

- `docs/superpowers/specs/aws-aurora-blue-green/2026-07-31-aurora-bgd-configuration-runtime-cluster-sync-design.md`
- `docs/superpowers/specs/aws-aurora-blue-green/2026-07-31-aurora-bgd-cluster-simulator-testing-design.md`
- `docs/superpowers/specs/aws-aurora-blue-green/2026-07-31-aurora-bgd-monitor-fsm-design.md`
- `RDS_Topology_metadata.pdf` (AWS-team-provided topology-status contract)
- `aurora-bgd-switchover-analysis/RESULTS-20260730T073724Z.md`
- `aurora-bgd-switchover-analysis/PLAN.md`
- `doc/AWS_Blue_Green/RDS_BGD_Monitor.md`
- `doc/AWS_Blue_Green/RDS_BGD_Simulator.md`

The AWS-team-provided topology document is authoritative for status-to-routing
semantics. The recorded Aurora observation is the ground truth for the other
observed external behavior and corroborates those status semantics. Simulator
tests prove how ProxySQL responds to the contract and observations; they do not
prove that AWS produces the observed details. If a later real-Aurora result
contradicts either source, stop, update the design decision with the user, and
only then update simulator expectations and implementation.

## Global Constraints

- Every Aurora hostgroups row is user-created.
- Green hostgroups are either both configured or both `NULL`; do not introduce
  explicit/automatic mode terminology or a mode column.
- Add only `green_writer_hostgroup` and `green_reader_hostgroup` as configured
  columns and runtime-only `bgd_status` as monitor state.
- SAVE, disk/config export, and ProxySQL Cluster synchronization must exclude
  `bgd_status`.
- Reuse RDS BGD behavior wherever its semantics match Aurora; retain the
  Aurora-specific three-probe, all-member mapping, and completion-latch rules.
- `TEST_AURORA` enables ordinary Aurora and Aurora BGD simulation. Do not add a
  separate simulator feature flag or CI group.
- Keep the existing ordinary Aurora JSON payload schema and all 33 scenarios.
- Keep all RDS Multi-AZ BGD behavior and all 22 RDS BGD TAP binaries green.
- Phase 3 implements one coherent behavior slice at a time, then adds focused
  scenarios and runs the nearest characterization regressions before the next
  slice.
- Use the current timestamp for every new commit. Do not rewrite dates.

## Phase-Specific Development Protocol

### Phases 1 and 2: prerequisite implementation and verification

Configuration/runtime integration and the simulator are prerequisites for
test-driving the Aurora FSM. They do not use the strict red-green-refactor
cycle. Implement each coherent contract slice, run the existing consumer
regressions, and commit only after verification passes. The simulator is test
infrastructure and does not receive tests whose subject is the simulator itself.
Do not claim that these phases were developed through TDD.

No Aurora BGD FSM behavior is implemented in Phase 1 or Phase 2.

### Phase 3: incremental test-after development with characterization coverage

Every Phase 3 implementation gate follows this sequence:

1. Record the externally observable behaviors and assertions for the gate.
2. Implement the complete, coherent production slice for those behaviors.
3. Compile once after the slice is structurally complete.
4. Add focused interactive scenarios for the recorded behaviors.
5. Run the focused scenarios until they pass.
6. Run the nearest ordinary Aurora and RDS characterization regressions.
7. Fix any issue before starting the next gate, then commit the production and
   scenario changes together with a narrow commit message.

Tests are not deliberately run in an expected-failure state. They remain
contract-driven because their expected observations are recorded before the
implementation is written. Existing RDS BGD tests characterize shared
placement, DNS, connection-retirement, rollback, and cleanup behavior while
Aurora scenarios cover the Aurora-specific worker and FSM contract.

## Pull Request and Review Workflow

### Initial publication

The feature branch contains only the three approved design specifications when
the draft PR is opened. Phase-one implementation begins only after the draft PR
exists.

### GitHub writing style and attribution

Every GitHub message drafted by Codex and posted through the user's account
must read like a concise maintainer response, not an agent activity report.
This applies to PR descriptions, submitted reviews, top-level comments, inline
replies, and reviewer-invocation comments.

- Lead with the outcome. For an accepted review comment, use the form
  `Fixed in <commit>. <Short summary of the change and resulting behavior.>`
- For a disputed comment, state the directly relevant technical reason and
  evidence briefly. Do not narrate the investigation process.
- Do not list routine validation commands, internal workflow steps, tool names,
  or exhaustive checks unless the reviewer asks for them or a specific result
  is necessary to support the answer.
- Keep the tone natural and professional. Avoid status-report language such as
  "documentation verification completed" and do not use an emoji in the
  attribution.
- End every message with the following exact footer as its own final paragraph,
  separated from the message by one blank line:

  ```html
  <sub>[Drafted by Codex · AI agent]</sub>
  ```

The footer requirement is prospective; do not edit existing GitHub messages
solely to add it. When invoking a reviewer, keep its required trigger at the
start of the message and put the footer in the final paragraph.

### Gate after every phase

After the phase acceptance commands pass:

1. Push every commit created during the phase to
   `upstream/feat/aws-aurora-bgd`. A phase normally contains multiple commits,
   especially Phase 3's gated implementation slices.
2. Use `gh` to check whether Codex, CodeRabbit, and Gitar started automatically.
   Manually invoke any missing reviewer. Codex and Gitar accept optional
   natural-language instructions, so request a phase commit range, a full PR
   review, or a focused review of named files, subsystems, contracts, or risks.
   CodeRabbit uses its documented incremental or full-review command.
3. Record the phase's base and head commits locally. The base is the commit
   immediately before the phase's first commit; the head is the last pushed
   phase commit. Use those exact SHAs in phase-scoped review requests.
4. Keep the agent session live for one to two hours. Start a background review
   watcher or a long-running `gh` command, poll it at bounded intervals, and
   re-read the PR when it completes. Do not end the work session merely because
   reviewers need time.
5. Use `gh` to inspect check results, submitted reviews, inline comments, and
   unresolved review threads.
6. Classify every comment using the review dispositions below. A reviewer is
   not presumed correct and may lack the full feature context.
7. Implement each accepted correction. Phase 3 behavior fixes return to the
   affected gate, add or adjust focused coverage, and run the nearest
   regressions. Phase 1 and Phase 2 fixes follow their focused verification
   protocol.
8. Commit and push each coherent review-fix set.
9. Reply to accepted or disputed inline feedback in its original thread using
   `gh api`. For a fix, name the commit and summarize the resulting behavior;
   for a dispute, give the short technical reason no change is appropriate.
   Follow the GitHub writing and attribution rules above.
10. Wait for the reviewer to resolve every actionable thread. A reply, pushed
   commit, or green check does not count as resolution.
11. Proceed when required checks are green and no actionable review thread
    remains unresolved. Intentionally deferred nitpicks or theoretical comments
    listed in the local deferred-review file do not block the next phase.

### Review dispositions

- **Applicable correctness, security, compatibility, or spec issue:** verify it,
  fix it, test it, reply with evidence, and wait for reviewer resolution.
- **Incorrect or not applicable:** reply in the inline thread with concrete
  source, test, and specification evidence. Do not change correct code merely
  to satisfy the comment. Wait for reviewer resolution; escalate to the user if
  a technically answered blocking thread remains unresolved.
- **Already postponed or outside approved scope:** reply with the scope boundary
  when useful and record the item in
  `.todo/AWS_AURORA_BGD_DEFERRED_REVIEW_NOTES.md`.
- **Nitpick, speculative defense, or theoretical hardening with no present
  failure mode:** it may remain unresolved without a reply. Record the comment,
  rationale, and revisit condition in the local deferred-review file so the
  user can audit the classification.
- **Ambiguous or potentially valuable but design-changing:** do not silently
  defer or implement it. Ask the user for a decision.

If a reviewer repeatedly leaves a corrected actionable thread unresolved, a
bot cannot re-evaluate, reviewers disagree about the contract, or a suggestion
requires a new design decision, stop and ask the user for direction. State the
exact thread, fix commit, verification, and remaining blocker.

### Reviewer invocation rules

- **Codex:** `@codex review` is the review trigger. Append natural-language
  instructions for a commit range, a full PR pass, a subsystem, or a specific
  risk.
- **CodeRabbit:** `@coderabbitai review` is incremental from CodeRabbit's last
  review; `@coderabbitai full review` starts again across the complete PR.
  `pause`, `resume`, and `help` are available controls. Do not use
  `@coderabbitai resolve` to bypass the requirement that actionable feedback be
  addressed and independently re-evaluated.
- **Gitar:** new PRs and pushes normally trigger it automatically. If it does
  not start, mention the installed `@gitar-bot` account with a natural-language
  request. Optional instructions may specify an exact commit range, ask for a
  full review, and name the desired focus. Gitar's exact operational commands
  (`unblock`, `auto-apply:on|off`, and `display:verbose|compact`) are not review
  scope commands; do not substitute them for the natural-language request.

### GitHub CLI commands

```bash
export GH_REPO=sysown/proxysql
PR_NUMBER=6044

# Save these values at the phase boundary. PHASE_BASE is the commit immediately
# before the first phase commit; PHASE_HEAD is the final pushed phase commit.
PHASE_BASE='replace-with-full-base-sha'
PHASE_HEAD='replace-with-full-head-sha'

# First inspect whether each reviewer already started. Do not send duplicate
# requests to reviewers that are already running or have reviewed PHASE_HEAD.
gh pr view "$PR_NUMBER" --comments
gh api --paginate "repos/{owner}/{repo}/pulls/$PR_NUMBER/reviews"

# Codex: the exact trigger is `@codex review`; text after it can focus the pass.
gh pr comment "$PR_NUMBER" --body \
  "@codex review commits $PHASE_BASE through $PHASE_HEAD. Focus on the current phase's approved design contract, regressions, and missing tests.

<sub>[Drafted by Codex · AI agent]</sub>"

# Use this form when a fresh review of the entire PR is required.
gh pr comment "$PR_NUMBER" --body \
  '@codex review the full PR. Focus on cross-phase integration, regressions, and compliance with the approved specifications.

<sub>[Drafted by Codex · AI agent]</sub>'

# CodeRabbit has distinct formal incremental and full-review commands. Its
# incremental command reviews changes since its previous review, not an
# arbitrary SHA supplied by us.
gh pr comment "$PR_NUMBER" --body '@coderabbitai review

<sub>[Drafted by Codex · AI agent]</sub>'
gh pr comment "$PR_NUMBER" --body '@coderabbitai full review

<sub>[Drafted by Codex · AI agent]</sub>'

# Gitar accepts natural-language instructions. The installed GitHub account on
# this repository is @gitar-bot.
gh pr comment "$PR_NUMBER" --body \
  "@gitar-bot review commits $PHASE_BASE through $PHASE_HEAD. Focus on the current phase's approved design contract, regressions, and missing tests.

<sub>[Drafted by Codex · AI agent]</sub>"

# Use this form when a fresh review of the entire PR is required.
gh pr comment "$PR_NUMBER" --body \
  '@gitar-bot perform a full review of the PR. Focus on cross-phase integration, regressions, and compliance with the approved specifications.

<sub>[Drafted by Codex · AI agent]</sub>'

# Wait for CI while the review watcher below monitors reviewer activity.
gh pr checks "$PR_NUMBER" --watch --interval 60

# Read PR conversation, formal reviews, and inline review comments.
gh pr view "$PR_NUMBER" --comments
gh api --paginate "repos/{owner}/{repo}/pulls/$PR_NUMBER/reviews"
gh api --paginate "repos/{owner}/{repo}/pulls/$PR_NUMBER/comments"

# Read thread-level resolution state. Re-run after every review update.
gh api graphql \
  -F owner=sysown \
  -F name=proxysql \
  -F number="$PR_NUMBER" \
  -f query='query($owner:String!,$name:String!,$number:Int!){
    repository(owner:$owner,name:$name){
      pullRequest(number:$number){
        reviewThreads(first:100){
          nodes{
            id isResolved isOutdated
            comments(first:100){nodes{id databaseId url author{login} body}}
          }
        }
      }
    }
  }'

# Reply to an inline review comment in its existing thread.
COMMENT_ID=123456789
gh api --method POST \
  "repos/{owner}/{repo}/pulls/$PR_NUMBER/comments/$COMMENT_ID/replies" \
  -f body='Fixed in <commit>. <Short summary of the change and resulting behavior.>

<sub>[Drafted by Codex · AI agent]</sub>'

# Keep the agent session live while reviewers work. Run this watcher in a
# persistent/background command, poll its PID/log at least once per minute,
# and perform the full reads above again when it exits.
REVIEW_WATCH_LOG=.todo/aws-aurora-bgd-review-watch.log
(
  deadline=$(( $(date +%s) + 7200 ))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    date -u +'%Y-%m-%dT%H:%M:%SZ'
    gh pr checks "$PR_NUMBER" || true
    gh api "repos/{owner}/{repo}/pulls/$PR_NUMBER/reviews" --jq 'length'
    gh api "repos/{owner}/{repo}/pulls/$PR_NUMBER/comments" --jq 'length'
    sleep 60
  done
) >"$REVIEW_WATCH_LOG" 2>&1 &
REVIEW_WATCH_PID=$!

git status --short --branch
git log --oneline upstream/v3.0..HEAD
```

## Phase 1: Configuration, Runtime Status, and Cluster Sync

### Deliverable

The configured Aurora table contains the two nullable green hostgroups; the
runtime table contains those fields plus node-local `bgd_status`; every load,
save, upgrade, config-file, and cluster-sync path follows the approved column
projection.

### Primary files

- `include/ProxySQL_Admin_Tables_Definitions.h`: Admin, runtime, and upgrade
  schema definitions.
- `include/MySQL_HostGroups_Manager.h`: HGM table schema, `AWS_Aurora_Info`
  configured fields, and status publication API.
- `lib/MySQL_HostGroups_Manager.cpp`: row parsing, validation, runtime ownership,
  resultset checksum, status preservation, and HGM table materialization.
- `lib/ProxySQL_Admin.cpp`: LOAD and SAVE projections and runtime table dump.
- `lib/ProxySQL_Config.cpp`: configuration-file import and export projections.
- ProxySQL Cluster Aurora table checksum/fetch/insert code located through
  `mysql_aws_aurora_hostgroups` references in `lib/ProxySQL_Admin.cpp` and the
  cluster synchronization TAP coverage.
- `test/tap/tests/unit/config_write_unit-t.cpp`: configuration export coverage.
- `test/tap/tests/test_cluster_sync-t.cpp`: Aurora configured-column cluster
  synchronization coverage.

### Interfaces produced for later phases

```cpp
// SQL NULL is represented internally by -1.
int AWS_Aurora_Info::green_writer_hostgroup;
int AWS_Aurora_Info::green_reader_hostgroup;

// Publishes only the node-local runtime value for one user-created Aurora row.
void MySQL_HostGroups_Manager::update_aws_aurora_bgd_status(
    int writer_hostgroup,
    const std::string& bgd_status
);
```

The Phase 3 Aurora FSM publishes only these values through the runtime status
API:

```text
NONE
AVAILABLE
SWITCHOVER_INITIATED
SWITCHOVER_IN_PROGRESS
SWITCHOVER_IN_POST_PROCESSING
SWITCHOVER_COMPLETED
```

### Task 1.1: Schema and validation

- [x] Add the new Admin/HGM/runtime definitions and in-place disk schema
  migration on ProxySQL startup.
- [x] Add a focused schema test that asserts configured and runtime column
  order, `NULL` defaults, paired-null validation, four-hostgroup uniqueness,
  and runtime-only `bgd_status`.
- [x] Verify per-row isolation: report each invalid writer hostgroup and its
  conflicting fields, atomically publish the filtered valid set, and safely
  remove any previously active worker whose row becomes invalid.
- [x] Run the focused test and the Admin table unit suite.
- [x] Commit as `feat: add Aurora BGD hostgroup schema`.

### Task 1.2: Runtime ownership and status publication

- [x] Extend `AWS_Aurora_Info`, its constructor/update paths, HGM parsing, and
  runtime materialization. Implement `update_aws_aurora_bgd_status()`.
- [x] Add focused tests for loading both configured values, preserving SQL
  `NULL` as `-1`, initializing new runtime rows to `NONE`, preserving status on
  an unrelated reload, covering reload-before-status and status-before-reload
  ordering, and removing status with the owning row.
- [x] Run the focused tests and ordinary Aurora monitor regressions.
- [x] Commit as `feat: publish Aurora BGD runtime status`.

### Task 1.3: Persistence and configuration-file projections

- [x] Replace relevant `SELECT *` and positional copies with explicit
  configured-column projections in Admin, HGM, and ProxySQL_Config paths.
- [x] Add round-trip tests proving both green hostgroups survive
  memory/runtime/disk/config-file operations while `bgd_status` never enters
  persistent configuration.
- [x] Run `config_write_unit-t` plus focused LOAD/SAVE round trips.
- [x] Commit as `feat: persist Aurora BGD configuration fields`.

### Task 1.4: ProxySQL Cluster synchronization

- [x] Include both green hostgroups in cluster checksum/fetch/insert projections
  and exclude `bgd_status`.
- [x] Extend the Aurora block in `test_cluster_sync-t.cpp` to synchronize one
  configured green pair with a non-NULL comment and one paired-NULL row with a
  NULL comment.
- [x] Verify configured values converge. Defer peer-local status retention to
  Phase 3, when worker-driven status transitions exist.
- [x] Commit as `feat: synchronize Aurora BGD configuration`.

### Phase 1 finalization

- [x] Require the canonical 17-column Aurora candidate projection and remove
  the unsupported legacy-normalization test while retaining all row and
  cross-row validation.
- [x] Keep `BQE1()` generic. Copy `mysql_aws_aurora_hostgroups` between main
  and disk with dedicated, explicit configured-column statements.
- [x] Restore the established Aurora monitor lifecycle invariant. Test runtime
  table merging through a helper with explicit dependencies rather than
  bypassing monitor publication when `GloMyMon` is NULL.
- [x] Keep the Phase 1 status publisher as the specified string interface but
  remove its duplicate vocabulary whitelist and defensive invalid-input test;
  the Phase 3 Aurora FSM owns the typed status vocabulary.
- [x] Replace raw `calloc(sizeof(ProxySQL_Admin))` member-call fixtures and the
  uncontrolled reload/status race with legitimate fixtures and deterministic
  ordering coverage.
- [x] Cover disk persistence with current main/disk schemas, one configured
  green pair, one paired-NULL row, and no ignored SQLite errors.
- [x] Consolidate Aurora cluster synchronization into one flow containing a
  configured-green/non-NULL-comment row and a paired-NULL/NULL-comment row.
  Remove the Admin-mirror-only status test.
- [x] In Phase 3, after worker-driven transitions exist, add the genuine
  two-peer test: publish different HGM statuses, perform configuration sync,
  and verify that both node-local statuses remain unchanged.
- [x] Run the focused unit tests, cluster integration test, ordinary Aurora
  regression coverage, full Phase 1 CI-equivalent checks, and `git diff --check`.

### Phase 1 acceptance

- All schema, upgrade, LOAD/SAVE, config-file, and cluster tests pass.
- Ordinary Aurora configuration remains backward compatible with both new
  values `NULL`.
- `git diff --check` is clean.
- Push, request reviews, and complete the phase review gate before Phase 2.

## Phase 2: Shared AWS Simulator Services

### Deliverable

Both RDS BGD and Aurora BGD use the shared `AWS_BGD_*` topology service;
ordinary Aurora and Aurora BGD use the accepted-backend-to-replica-set service;
the existing ordinary Aurora JSON suite and RDS BGD TAP suite retain their
semantics.

### Primary files

- `include/SQLite3_Server.h` and `src/SQLite3_Server.cpp`: TEST-mode tables,
  accepted backend extraction, production-query interception, response routing,
  errors, and probe logs.
- `test/tap/tap/cluster_simulator.h` and `.cpp`: shared SQLite control client.
- Create `test/tap/tap/bgd_simulator.h` and `.cpp`: engine-neutral topology,
  Aurora replica, read-only, probe-log, transaction, and cleanup operations.
- `test/tap/tap/rds_bgd_simulator.h` and `.cpp`: retain only RDS deployment
  fixture types and consume `BGD_Simulator`.
- Create `test/tap/tap/aurora_bgd_simulator.h` and `.cpp`: Aurora endpoint,
  member, membership-set, and rename fixture types.
- `test/deps/cluster_simulator/lib/aurora_utils.h` and `.cpp`: publish existing
  JSON payload state into the new replica service without changing JSON.
- `test/deps/cluster_simulator/cluster_simulator.cpp`: pass
  `CLUSTER_SIM_HOST_FILE` state publication through the new service.
- `test/tap/groups/cluster_sim_aurora/add-hosts`: fixed Aurora BGD aliases.
- `test/tap/tests/Makefile` and `test/tap/groups/groups.json`: build and register
  focused contracts and later Aurora BGD tests in the existing group.

### Interfaces produced for Phase 3

```cpp
struct BGD_Topology_Row {
    std::string id;
    std::string endpoint;
    int port;
    std::string role;
    std::string status;
};

struct Aurora_Replica_Row {
    std::string server_id;
    std::string session_id;
    double cpu;
    std::string last_update_timestamp;
    double replica_lag_in_milliseconds;
    bool is_current;
};

class BGD_Simulator : public Cluster_Simulator {
public:
    int topology_update(std::vector<Endpoint>, std::vector<BGD_Topology_Row>);
    int topology_delete(std::vector<Endpoint>);
    int topology_drop(std::vector<Endpoint>);
    int topology_error(std::vector<Endpoint>, int, std::string);
    int replica_update(
        std::string replica_set_id,
        std::vector<Aurora_Replica_Row> rows,
        std::vector<Endpoint> backends
    );
    int replica_drop(std::vector<Endpoint>);
    int replica_error(std::vector<Endpoint>, int, std::string);
    int cleanup();
};
```

Probe-log checkpoint/read/wait interfaces expose topology and replica probe
kind, accepted backend IP/port, TLS state, and replica-set identifier exactly
as defined by the simulator specification.

### Task 2.1: Shared topology service rename

- [x] Rename tables, query handling, and the generic helper to `AWS_BGD_*` and
  `BGD_Simulator`; keep RDS deployment fixtures engine-specific.
- [x] Run all 22 `test_rds_bgd_*-t` binaries.
- [x] Commit as `refactor: share AWS BGD simulator topology`.

### Task 2.2: Aurora replica service

- [x] Implement `AWS_AURORA_REPLICA_CONTROL`,
  `AWS_AURORA_REPLICA_PROBE_LOG`, and the new `REPLICA_HOST_STATUS` schema.
- [x] Intercept only recognized production Aurora monitor queries and retain
  their requested result columns/filtering/order.
- [x] Verify the service through the unchanged ordinary Aurora production-query
  scenarios and the existing RDS BGD consumer suite.
- [x] Commit as `feat: add Aurora replica simulator service`.

### Task 2.3: Simulator helper and Aurora fixtures

- [x] Implement the transactional `BGD_Simulator` replica, error, log, endpoint
  predicate, and cleanup APIs plus the Aurora model types.
- [x] Build the helper APIs and model types for use by the Phase 3 interactive
  Aurora BGD scenarios; do not add tests of the simulator helper itself.
- [x] Commit as `test: add Aurora BGD simulator controls`.

### Task 2.4: Ordinary Aurora compatibility adapter

- [x] Keep JSON unchanged; use each `DOMAIN_NAME` as its `REPLICA_SET_ID`, set
  `IS_CURRENT=1`, and atomically map all member IPs from the host file.
- [x] Run `test_cluster_sim_aurora-t` and confirm all 11 payload files and 33
  scenario objects pass.
- [x] Commit as `test: migrate Aurora scenarios to replica sets`.

### Phase 2 acceptance

- Focused simulator contracts pass under the intended feature flags.
- All 33 ordinary Aurora cases pass with unchanged JSON schemas.
- All 22 RDS Multi-AZ BGD TAP binaries pass.
- Combined `testall` builds with no new simulator feature flag or group.
- `git diff --check` is clean.
- Push, request reviews, and complete the phase review gate before Phase 3.
- Phase 2 is the prerequisite completion point. Strict red-green-refactor does
  not begin until this review gate is complete.

## Phase 3: Aurora Monitor Loop and FSM — Gated Test-After Development

### Deliverable

The existing per-writer Aurora worker owns ordinary Aurora monitoring and the
Aurora BGD FSM, drives the three probes, maps every target member, applies
idempotent routing actions, and reaches the completed rearm latch exactly as
defined by the approved monitor/FSM specification.

### Primary files

- `include/MySQL_Monitor.hpp`: Aurora BGD state, snapshots, pairs, action flags,
  probe state, and monitor method declarations.
- `lib/MySQL_Monitor.cpp`: worker integration, probe scheduling, topology and
  membership parsing, transitions, routing, rollback, reload, and teardown.
- `include/MySQL_HostGroups_Manager.h` and
  `lib/MySQL_HostGroups_Manager.cpp`: reuse existing writer/reader placement and
  connection-drain behavior; add only narrowly required Aurora BGD actions.
- `include/DNS_Cache.hpp` and `lib/DNS_Cache.cpp`: reuse RDS BGD pin insertion
  and explicit removal behavior.
- `test/tap/tap/aurora_bgd_tap.h`: Aurora deployment, simulator publication,
  configuration, status, and probe primitives.
- `test/tap/tap/aurora_bgd_scenario_tap.h`: shared scenario setup, routing,
  placement, runtime-row, status, and pool helpers.
- Focused `test/tap/tests/test_aurora_bgd_*-t.cpp` scenario binaries, registered
  together with `test_cluster_sim_aurora-t` in `cluster_sim_aurora-g1`.

### Simulator scenario organization

The Aurora BGD scripts follow the corresponding RDS BGD scripts: one focused
domain responsibility per binary, coherent assertions grouped in named test
functions, setup failures reported as diagnostics, and an exact TAP plan in
`main()`.

```cpp
struct TestState {
	// One deployment and only the state needed by this script.
};

int test_<focused_observation>(Context&, TestState&);

int main() {
	plan(<exact assertion count>);
	// Connect once, run focused functions, clean up, return exit_status().
}
```

Use descriptive snake_case function names. Name state members for their domain
objects and name booleans for the condition they represent. A function may use
several TAP assertions when they describe one coherent result. Compound SQL
checks may feed one assertion when the equivalent RDS test treats the combined
state as one outcome.

The simulator suite stays within these boundaries:

- Do not modify production behavior merely to satisfy a simulator scenario. If
  a scenario reveals a production gap, stop and review it with the user.
- Do not test the simulator framework itself.
- Do not start a second ProxySQL process or add Aurora-specific ClusterSync
  coverage; the generic ClusterSync unit and integration coverage is sufficient.
- Do not invent Aurora domain cases without an RDS BGD analogue. Adapt shared
  RDS cases only where Aurora's three probes, all-member mapping, or completion
  latch requires an Aurora-specific observation.
- Do not model membership changes after `SWITCHOVER_INITIATED`; AWS prevents
  cluster membership changes after switchover begins.
- Do not duplicate persistence, generic ClusterSync, or simulator-service
  behavior already covered by their owning tests.
- Keep exhaustive malformed-metadata matrices, endpoint rename/IP-churn chains,
  forced ordinary-probe failures, held clients across cutover, and global
  auto-discovery toggles outside this suite. The focused RDS-shaped scenarios
  cover the approved Aurora domain contract.

### Focused simulator scripts

| Script | TAP plan | Focus and externally observable assertions |
| --- | ---: | --- |
| `test_aurora_bgd_smoke-t.cpp` | 3 | AVAILABLE is published while ordinary production probing remains active; the worker probes a target-cluster endpoint and its target replica set. |
| `test_aurora_bgd_automatic_discovery-t.cpp` | 5 | Paired-NULL green hostgroups admit discovery without generating configuration; absent topology remains `NONE`; AVAILABLE is later discovered; repeated polling keeps one runtime row. |
| `test_aurora_bgd_probe_tls-t.cpp` | 2 | TLS production rows produce encrypted topology and target-membership probes. |
| `test_aurora_bgd_writer_switchover-t.cpp` | 12 | AVAILABLE and INITIATED preserve placement; IN_PROGRESS demotes only the source writer; POST_PROCESSING pins mapped members, drains the old writer free pool, and routes writer traffic to the mapped target; repetition is idempotent. |
| `test_aurora_bgd_reader_policy-t.cpp` | 2 | Mapped source readers remain ONLINE and reader-hostgroup routes reach their mapped targets during POST_PROCESSING. |
| `test_aurora_bgd_green_pool_cleanup-t.cpp` | 5 | Rollback preserves green pools; completion drains ONLINE and SHUNNED green pools; OFFLINE_SOFT and OFFLINE_HARD pools and configured rows remain present. |
| `test_aurora_bgd_reader_switchover_cleanup-t.cpp` | 7 | Completion restores canonical writer placement, removes pins, resumes the ordinary probe, publishes `SWITCHOVER_COMPLETED`, and does not replay cleanup; a successful empty topology rearms to `NONE`. |
| `test_aurora_bgd_late_entry_writer_phases-t.cpp` | 7 | First observation of INITIATED, IN_PROGRESS, or POST_PROCESSING applies only the effects belonging to that observed phase. |
| `test_aurora_bgd_late_entry_completed-t.cpp` | 5 | First observation of COMPLETED performs no-op cleanup when no effects exist, creates no pins, publishes the completion latch, and rearms after a successful empty topology. |
| `test_aurora_bgd_rollback-t.cpp` | 8 | Rollback from INITIATED, IN_PROGRESS, and POST_PROCESSING restores the effects applied by each phase and resumes ordinary probing. |
| `test_aurora_bgd_topology_empty_absent-t.cpp` | 4 | Present-but-empty topology and a successful result without the deployment cancel an active pre-completion switchover, restore the writer, publish `NONE`, and keep probing live. |
| `test_aurora_bgd_topology_errors-t.cpp` | 2 | Topology and target-membership query errors retain active state, applied placement, and the last complete member map. |
| `test_aurora_bgd_worker_config_refresh-t.cpp` | 4 | An unrelated server reload and an in-place Aurora configuration refresh preserve active status, cached membership, and applied pins. |
| `test_aurora_bgd_config_refresh_after_completion-t.cpp` | 3 | Completion directly from IN_PROGRESS restores the writer; configuration refresh preserves the completion latch; an empty topology still rearms it. |
| `test_aurora_bgd_disable_during_switchover-t.cpp` | 4 | Deactivating the owning Aurora row during IN_PROGRESS restores canonical placement and publishes the inactive runtime row in `NONE`. |
| `test_aurora_bgd_remove_during_switchover-t.cpp` | 5 | Removing the owning Aurora row during IN_PROGRESS restores canonical placement and removes the runtime row. |
| `test_aurora_bgd_repeated_deployment-t.cpp` | 4 | A completed worker accepts a different deployment fingerprint, uses only the new member map and pins, routes to the new target, and cleans up without stale-map reuse. |
| `test_aurora_bgd_concurrent_isolation-t.cpp` | 9 | Three writer workers independently reach AVAILABLE, advance through different phases, and preserve each other's state, placement, and pins. |

The group contains 91 Aurora BGD assertions across these 18 scripts plus the
unchanged ordinary Aurora regression. It uses the existing
`cluster_sim_aurora` environment and one ProxySQL process.

### Gate 3.1: Discovery, mapping, and three-probe ownership

- [x] Add per-writer Aurora BGD worker state and schedule the ordinary Aurora,
  topology, and target-membership probes in `NONE`/`AVAILABLE`.
- [x] Implement the last-complete snapshot, normalized `SERVER_ID` pairing,
  reader session continuity, cached IPs, and fail-closed validation.
- [x] Add the smoke, automatic-discovery, and probe-TLS scripts to characterize
  AVAILABLE discovery, user-created paired-NULL configuration, probe ownership,
  target membership, and TLS inheritance.
- [x] Keep ordinary Aurora's 33 scenarios as characterization coverage for
  production membership parsing and placement.
- [x] Commit as `feat: add Aurora BGD discovery and member mapping`.

### Gate 3.2: Active switchover routing

- [x] Implement status publication, production-probe suspension, rollback-state
  capture, fast cadence, and RDS-style idempotent writer demotion.
- [x] Implement idempotent per-member pinning, connection retirement, monitor
  pool purge, canonical writer restoration, and unchanged reader eligibility.
- [x] Add the writer-switchover and reader-policy scripts to characterize
  placement, pinning, pool retirement, target routing, reader eligibility, and
  repeated POST_PROCESSING behavior.
- [x] Treat each per-member flag as action-applied bookkeeping; do not wait for
  asynchronously retired used connections to close.
- [x] Assert no target-writability gate and no reader shun/unshun behavior.
- [x] Commit as `feat: handle Aurora BGD active switchover`.

### Gate 3.3: Completion cleanup and terminal latch

- [x] Implement immediate effect-driven cleanup using the existing map and
  worker state, including writer reconciliation, DNS-entry removal,
  production-probe resume, configured cadence, `SWITCHOVER_COMPLETED`
  publication, fingerprint retention, and successful-drain transition to
  `NONE`.
- [x] Add the green-pool-cleanup, reader-switchover-cleanup,
  late-entry-completed, config-refresh-after-completion, and
  repeated-deployment scripts to characterize effect-driven cleanup and rearm.
- [x] Verify cleanup replays no skipped phase, waits for neither DNS verification
  nor physical connection closure, and never repeats for the same completed
  result.
- [x] Commit as `feat: complete Aurora BGD switchover`.

### Gate 3.4: Rollback, reload, removal, and concurrency

- [x] Implement idempotent rollback and lifecycle preservation/cleanup using
  per-writer state and per-member action flags.
- [x] Add the late-entry-writer-phases, rollback, topology-empty-absent,
  topology-errors, worker-config-refresh, disable-during-switchover,
  remove-during-switchover, and concurrent-isolation scripts.
- [x] Verify errors retain state and never masquerade as cancellation,
  reader-less membership, topology drain, or completion.
- [x] Commit as `feat: harden Aurora BGD lifecycle handling`.

### Phase 3 acceptance

- Every monitor/FSM requirement maps to a focused scenario whose expected
  observations were recorded before its implementation gate.
- The 18 Aurora BGD scripts and ordinary Aurora regression are registered only
  in `cluster_sim_aurora-g1`, and the group runs with one ProxySQL process.
- All Aurora BGD, ordinary Aurora, RDS BGD, read-only, DNS, pool-retirement,
  configuration, and cluster-sync regressions pass.
- Combined simulator CI passes and `git diff --check` is clean.
- Push, request reviews, and complete the phase review gate.

## Final Real-Aurora User Acceptance Gate

Run this only after Phase 3 reviews are resolved. Use the existing observation
scripts as the direct-Aurora evidence harness and add a separate ProxySQL-path
driver rather than changing the recorded 2026-07-30 result.

The acceptance run must verify:

1. ProxySQL publishes every expected `bgd_status` transition.
2. Ordinary production Aurora probes stop during the three active phases and
   resume after cleanup.
3. The old writer is not used for writes after fencing and no dual-writer
   routing interval is observed.
4. Writer and reader client traffic reaches promoted target members using the
   cached mapping during canonical DNS disruption.
5. Established connections, free pools, and retired connections follow the
   designed cutover behavior.
6. All traffic pins are removed at TARGET completion and the FSM returns to
   `NONE` only after a successful topology drain observation.
7. A separate transaction-enabled run records application-visible transaction
   errors and confirms ProxySQL does not transparently replay an active
   transaction.

Archive timestamps, ProxySQL logs, runtime/Admin snapshots, backend identities,
DNS results, and client outcomes. Compare invariants and ordering, not exact
durations, with `RESULTS-20260730T073724Z.md`.

If the acceptance run passes, push the evidence-backed fixes, complete one final
review cycle, convert the draft PR to ready for review, and merge only after
required human approval and CI success. If it fails because AWS contradicts an
assumption, keep the PR draft and return to design review before changing code.
