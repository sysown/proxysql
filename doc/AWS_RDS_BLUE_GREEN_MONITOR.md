# AWS RDS Blue/Green Monitor

**Document status:** AUTHOR VALIDATION REQUIRED

**Applies to:** Amazon RDS Multi-AZ DB instance blue/green deployment monitoring

**Primary monitor entry points:** `include/MySQL_Monitor.hpp`,
`lib/MySQL_Monitor.cpp`

**Related implementation:** `include/DNS_Cache.hpp`, `lib/DNS_Cache.cpp`,
`include/MySQL_HostGroups_Manager.h`, `lib/MySQL_HostGroups_Manager.cpp`,
`include/mysql_connection.h`, `lib/mysql_connection.cpp`,
`lib/MySrvConnList.cpp`, `lib/ProxySQL_Admin.cpp`, `lib/ProxySQL_Config.cpp`, and
`include/ProxySQL_Admin_Tables_Definitions.h`. This is the non-exhaustive
side-effect/configuration surface referenced by later `SOURCE-CODE` sections.

## Purpose

This document defines the AWS observations, current ProxySQL behavior, and
safety requirements for the AWS RDS blue/green deployment monitor introduced
by [PR #5861](https://github.com/sysown/proxysql/pull/5861).

The document is intentionally explicit about evidence. AWS behavior for which
this review has not recorded author evidence is not presented as an operational
guarantee. This evidence status does not imply that the author originally
inferred, assumed, or failed to observe the behavior.

## Evidence Labels

| Label | Dimension | Meaning |
|---|---|---|
| `SOURCE-CODE` | Provenance | Direct description of current implementation; it does not validate an external AWS claim. |
| `AUTHOR-VALIDATED` | External evidence | AWS behavior confirmed by the feature author from observed deployment evidence. |
| `REVIEW-VALIDATION-PENDING` | Review evidence | An external claim present in the PR, source comments, or implementation contract for which this review has not yet recorded the author's evidence or correction. It does not characterize how the author derived the claim. |
| `PROPOSED-POLICY` | Intent | Intended ProxySQL safety behavior for later hardening PRs. |

Labels may be combined. `SOURCE-CODE, REVIEW-VALIDATION-PENDING` means the
current code or comments encode an external claim whose supporting evidence has
not yet been recorded in this review. `SOURCE-CODE` alone must be used only for
internal mechanics and never promotes an external claim.

A `REVIEW-VALIDATION-PENDING` claim must be promoted to `AUTHOR-VALIDATED` or
corrected before the deterministic controller simulator is accepted.

## Scope

This document covers:

- Detection of blue/green topology through `mysql.rds_topology`.
- Mapping of configured blue writer and reader servers to green servers.
- Green address resolution and direct topology probing.
- Writer and reader switchover handling.
- DNS pinning, hostgroup changes, and backend connection draining.
- Successful finalization, cancellation rollback, and worker replacement.
- Explicit and automatic green-hostgroup configuration.

This document does not define Aurora monitoring, Group Replication monitoring,
Galera monitoring, or PostgreSQL behavior.

## Terminology

The table includes current implementation terms and proposed hardening
concepts; proposed concepts are explicitly labeled.

| Term | Definition |
|---|---|
| Blue | The source deployment before switchover. |
| Green | The target deployment before switchover. |
| Observation | The result of one topology query or lifecycle event. |
| Controller state | `PROPOSED-POLICY`: ProxySQL's progress and policy across observations. |
| External effect | A DNS, hostgroup, monitor, or connection change visible outside controller bookkeeping. |
| Effect ledger | `PROPOSED-POLICY`: The identities and results of external effects requiring retry or cleanup. |
| Finalization | `PROPOSED-POLICY`: Cleanup on the proposed successful-completion path after observed writer completion and the accepted reader-completion signal. |
| Rollback | `PROPOSED-POLICY`: Restoration after cancellation or topology disappearance before observed writer completion. |

## Topology Shape

`SOURCE-CODE`: `parse_aws_rds_topology` sets `blue_green` once, from the first
fetched row, when the role and status columns exist and that row's cells for
both columns are non-NULL. Empty strings still meet this current non-NULL test.
Later rows do not re-evaluate or reverse the classification.

`SOURCE-CODE, REVIEW-VALIDATION-PENDING`: The implementation expects actual RDS
blue/green rows to use the source and target role values and recognized target
status values listed below. This review has not yet recorded the author's
supporting evidence for that external contract.

Role values:

```text
BLUE_GREEN_DEPLOYMENT_SOURCE
BLUE_GREEN_DEPLOYMENT_TARGET
```

Target status values:

```text
AVAILABLE
SWITCHOVER_INITIATED
SWITCHOVER_IN_PROGRESS
SWITCHOVER_IN_POST_PROCESSING
SWITCHOVER_COMPLETED
```

`SOURCE-CODE`: If there is no row, either column is absent, or either first-row
cell is NULL, `blue_green` remains false. Later malformed rows do not change a
true first-row classification. Other RDS topology shapes may be processed by
the Multi-AZ Cluster discovery path.

## Observation Model

`PROPOSED-POLICY`: The hardened controller design distinguishes the following
observation and lifecycle-event vocabulary. `SOURCE-CODE`: The
`TOPOLOGY_ABSENT` inputs correspond to the current table-existence query and
`ER_NO_SUCH_TABLE` metadata-fetch paths, but these observations are not the
current implementation state enum.

| Observation | Meaning |
|---|---|
| `TOPOLOGY_ABSENT` | The existence query returns zero rows, or a metadata fetch reports `ER_NO_SUCH_TABLE`. The table is not available; this is not a generic failure. |
| `TOPOLOGY_EMPTY` | A successful metadata query returns zero topology rows. |
| `AVAILABLE` | The target reports the recognized `AVAILABLE` status. |
| `WRITER_INITIATED` | The target reports the recognized `SWITCHOVER_INITIATED` status. |
| `WRITER_IN_PROGRESS` | The target reports the recognized `SWITCHOVER_IN_PROGRESS` status. |
| `WRITER_POST_PROCESSING` | The target reports the recognized `SWITCHOVER_IN_POST_PROCESSING` status. |
| `WRITER_COMPLETED` | The target reports the recognized `SWITCHOVER_COMPLETED` status. |
| `UNKNOWN_STATUS` | The target has a non-empty, unrecognized status. |
| `MALFORMED_TOPOLOGY` | The target, endpoint, role, status, or required identity is missing. |
| `QUERY_FAILED` | The query times out, the connection fails, or SQL reports an error other than documented absence. |
| `CONFIG_CHANGED` | The monitor result-set checksum or generation changes and may replace the worker without losing deployment state. |
| `CONFIG_REMOVED` | The configuration is disabled or removed; outstanding effects require rollback before the context is removed. |
| `WORKER_RESTARTED` | A replacement worker attaches to and resumes the existing context. |

`PROPOSED-POLICY`: `TOPOLOGY_ABSENT`, `TOPOLOGY_EMPTY`, and `QUERY_FAILED` are
not interchangeable. Query failure never proves cancellation or completion.

## Lifecycle Claims Pending Author Validation

`SOURCE-CODE, REVIEW-VALIDATION-PENDING`: Current code and comments describe
this lifecycle; the review has not yet recorded the author's supporting
evidence:

```text
Two rows:
  SOURCE = blue
  TARGET = green
  status = AVAILABLE

Two rows:
  status = SWITCHOVER_INITIATED
    -> SWITCHOVER_IN_PROGRESS
    -> SWITCHOVER_IN_POST_PROCESSING

One target row:
  status = SWITCHOVER_COMPLETED

Zero rows or missing table:
  interpreted as reader DNS propagation complete only if writer completion
  was observed first
```

Every external lifecycle statement remains `REVIEW-VALIDATION-PENDING` until
the feature author records supporting evidence or a correction.

## Current ProxySQL State Machine

`SOURCE-CODE`: This is the nominal ordering encoded by the enum names and the
lifecycle currently described by the implementation. The external lifecycle
claims remain `REVIEW-VALIDATION-PENDING`, and the arrows are not enforced
transition edges:

```text
NONE
  -> AVAILABLE
  -> WRITER_SWITCHOVER_INITIATED
  -> WRITER_SWITCHOVER_IN_PROGRESS
  -> WRITER_SWITCHOVER_POST_PROCESSING
  -> WRITER_SWITCHOVER_COMPLETED
  -> READER_SWITCHOVER_IN_PROGRESS
  -> SWITCHOVER_COMPLETED
  -> NONE
```

`SOURCE-CODE`: The current handler converts the target status and compares enum
ordering with the stored status. A lower value is treated as a backward
transition: the handler runs the current rollback cleanup, and only an observed
`AVAILABLE` phase is then re-entered and initialized. Forward transitions do
not require their immediate predecessor, so a worker can still first observe
`WRITER_SWITCHOVER_POST_PROCESSING` and perform setup in that phase.

`SOURCE-CODE`: An unknown non-empty target status converts to `NONE`. From an
active higher-valued state this is treated as a backward transition and invokes
rollback cleanup. An empty target status takes an earlier path that directly
sets `NONE` and does not invoke rollback cleanup. A special guard ignores a
repeated raw `WRITER_SWITCHOVER_COMPLETED` while local state is
`READER_SWITCHOVER_IN_PROGRESS`. A newly observed
`WRITER_SWITCHOVER_COMPLETED` is first stored and then immediately advanced to
`READER_SWITCHOVER_IN_PROGRESS` in the same handler call.

`SOURCE-CODE`: `READER_SWITCHOVER_IN_PROGRESS` and `SWITCHOVER_COMPLETED` are
ProxySQL-inferred and cleanup states, not raw AWS status strings.

`SOURCE-CODE`: Phase transitions currently perform these actions:

| Phase or observation | Current action |
|---|---|
| `AVAILABLE` | Set the next-check interval to 250 ms; build the blue/green mapping; resolve green IPs; optionally add the green writer to its configured hostgroup. |
| `WRITER_SWITCHOVER_INITIATED` | On transition, set the next-check interval to 100 ms; invoke mapping, green-IP resolution, and optional green-writer setup; suppress read-only checks for the deployment hostgroups. |
| `WRITER_SWITCHOVER_IN_PROGRESS` | On transition, set the next-check interval to 100 ms; invoke the same setup; suppress read-only checks; demote the mapped blue writer to read-only. |
| `WRITER_SWITCHOVER_POST_PROCESSING` | On transition, set the next-check interval to 100 ms; invoke the same setup; enable or sustain read-only suppression; pin mapped blue names to resolved green IPs; drain matching connections; configure writer placement; shun unmapped readers. |
| `WRITER_SWITCHOVER_COMPLETED` | Enter the inferred reader phase; remove the writer DNS-cache entry; retain mapped reader pins until the topology drains; reset the next-check interval override to the baseline value of `0`. |
| `READER_SWITCHOVER_IN_PROGRESS` plus empty or absent topology | Run successful cleanup: reconcile configured writer membership in the reader hostgroup; unshun recorded readers; remove DNS-cache entries and purge monitor-pool connections for recorded shunned readers and all mapped pairs; drain configured green hostgroups; clear worker bookkeeping; transition through `SWITCHOVER_COMPLETED` to `NONE`. |
| Empty or absent topology from any other non-`NONE` state | Run rollback cleanup: conditionally restore a writer demoted during `WRITER_SWITCHOVER_IN_PROGRESS` or `WRITER_SWITCHOVER_POST_PROCESSING`, then run the common hostgroup, DNS-cache, monitor-pool, green-hostgroup, and worker-state cleanup before entering `NONE`. |
| Recognized backward status transition | Run rollback cleanup. If the new raw status is `AVAILABLE`, re-enter `AVAILABLE`, set the 250 ms interval, and rebuild mapping, resolution, and optional green-writer placement. Other backward statuses leave the worker in `NONE` after cleanup. |
| Worker exit with non-`NONE` state | Run rollback cleanup before destroying the worker-local state. A replacement worker starts with a new state instance. |

### Current Phase-Equality Behavior

`SOURCE-CODE`: After status conversion, the handler returns immediately when
the converted status equals the stored status. Phase actions run on transition,
not on every observation. Consequently, a transient mapping or DNS failure is
not retried while the same phase continues. This records current behavior, not
desired behavior.

### Current Topology-Absence Behavior

`SOURCE-CODE`: If local state is `READER_SWITCHOVER_IN_PROGRESS`,
`aws_rds_bgd_handle_topology_absent` runs the full current successful cleanup.
For every other non-`NONE` state, it calls the same cleanup helper with
`rollback=true`.

`SOURCE-CODE`: Rollback conditionally moves a writer demoted during
`WRITER_SWITCHOVER_IN_PROGRESS` or `WRITER_SWITCHOVER_POST_PROCESSING` back to
the writer role. It then runs the common completion hostgroup action, unshuns
recorded readers, removes DNS-cache entries and purges monitor-pool connections
for recorded shunned readers and all mapped pairs, drains configured green
hostgroups, clears the worker bookkeeping, and enters `NONE`, which clears
read-only suppression.

`SOURCE-CODE`: The current rollback is a one-shot best-effort procedure. Its
effect operations do not return an action result to this controller, there is no
owned effect ledger, and the worker state is cleared even when external state
has not been verified. This is why the proposed reconciliation and ownership
invariants remain necessary.

`SOURCE-CODE`: The interval result depends on the caller path:

- A metadata fetch reporting `ER_NO_SUCH_TABLE` sets
  `next_check_interval_ms` to `0` before calling the helper.
- Successful or rollback cleanup resets the interval as part of state cleanup.
- If the helper is called while state is already `NONE`, it performs no cleanup;
  an existence query or successful empty metadata query does not independently
  reset an existing interval override in that case.

`SOURCE-CODE`: PR 1 documents this current behavior. PR 1 does not change this.

### Current Worker Lifetime

`SOURCE-CODE`: State lives on the per-writer-hostgroup worker stack. A monitor
result-set checksum change terminates the worker. If its state is non-`NONE`,
the exit path runs the one-shot rollback cleanup before discarding the state.
The mapping, shunned-reader records, probe target, and cleanup identities are
not transferred to the replacement; the replacement starts with a fresh state.
The current design therefore chooses cleanup-on-detach rather than
deployment-lifetime state continuity.

### Current Source Anchors

`SOURCE-CODE`: The source entry points for the current mechanics are
`parse_aws_rds_topology`, `handle_aws_rds_bgd`,
`aws_rds_bgd_handle_topology_absent`,
`handle_aws_rds_bgd_post_switchover`, and `monitor_RDS_BGD_thread_HG`. These
entry points should be reviewed with this document whenever behavior changes.

## External Effects And Cleanup Ledger

`PROPOSED-POLICY`: Every externally visible effect must have a stable identity
and a cleanup record before the effect is considered applied.

`PROPOSED-POLICY`: Every mutable effect uses the same stable ownership key:
deployment ID, deployment generation, action ID, and resource ID. The resource
ID identifies the effect-specific resource and does not change when its value
changes. Mutable result data is recorded separately and includes the before
value, intended or applied value, last observed value, and command result. In
particular, a resolved IP, its resolution source, and its expiry are result
data, not stable identity.

`PROPOSED-POLICY`: An effect has one of these states:

- `PENDING`: The intended value is not yet verified as applied.
- `APPLIED`: The intended value is verified, but cleanup or handoff remains.
- `REVERTED`: Compare-and-restore verified the owned effect was undone.
- `COMMITTED`: An irreversible effect was verified complete, or ownership of a
  retained effect was explicitly handed off to desired runtime configuration.
- `CONFLICT`: The resource no longer has the value applied by this owner, so
  automatic restoration would overwrite a newer value or owner.

`PROPOSED-POLICY`: The active cleanup ledger contains only unsettled,
controller-owned effects in `PENDING`, `APPLIED`, or `CONFLICT`. `REVERTED` and
`COMMITTED` entries leave the active ledger; they may remain as audit
tombstones outside it.

`PROPOSED-POLICY`: Cleanup uses compare-and-restore. An inverse action is
applied only when the resource still equals the applied value owned by the
ledger entry. Otherwise the effect becomes `CONFLICT`, remains in the active
ledger, and exposes `FAULTED`; cleanup does not overwrite newer configuration
or another owner.

`PROPOSED-POLICY`: A transitional effect superseded by the accepted desired
post-success state becomes `COMMITTED` only after the controller verifies an
explicit handoff of the resource and its intended value into desired runtime
configuration. A conflict or permanent inability to complete that handoff
enters `FAULTED` with the active ledger retained.

| Effect | Required identity | Successful postcondition | Required recovery |
|---|---|---|---|
| Blue/green mapping | Common owner key; resource identity is the blue endpoint, green endpoint, and role within the deployment. | All required endpoints are mapped; endpoint and role values are recorded as result data. | Clear the owned mapping or reconstruct it from a new complete observation. |
| Green resolution | Common owner key; resource identity is the green hostname and probe purpose. | A complete writer probe target is available; resolved IP, source, and expiry are recorded as result data. | Retry resolution or clear the incomplete owned result. |
| Direct probe | Common owner key; resource identity is the deployment probe slot, with host or IP, port, and SSL mode recorded as intended and applied result data. | Topology checks use the mapped writer endpoint. | Compare-and-restore the configured blue probe candidates. |
| Green writer placement | Common owner key; resource identity is the hostgroup and server. | The intended server is present with the mapped options, recorded as the applied value. | Compare-and-restore the prior placement, or mark `COMMITTED` only after explicit handoff of the retained placement into desired runtime configuration. |
| Monitor suppression | Common owner key; resource identity is the affected hostgroup and monitor scope. | Read-only monitoring skips only the intended servers. | Compare-and-restore the prior suppression value. |
| Blue writer demotion | Common owner key; resource identity is the server and affected placement; original and applied role and placement are result data. | The temporary role and placement are visible. | During rollback, compare-and-restore the original role and placement. After observed writer completion, successful finalization or `SAFE_TEARDOWN` reconciles and hands off the role and placement to accepted desired post-switchover runtime configuration, then marks the effect `COMMITTED`; it never restores obsolete blue solely because completion was observed or configuration was removed. A conflict or permanent inability to settle enters `FAULTED` with the active ledger retained. |
| DNS pin | Common owner key; resource identity is the hostname; pinned IP is applied result data. | Lookup returns the owned pinned IP. | Compare-and-restore only when the action owner still owns the pin. |
| Connection drain | Common owner key; resource identity is the server and drain generation. | Every connection predating the drain generation is verified retired and cannot be reused. | Never revert; mark `COMMITTED` only after every connection predating the generation is verified retired. |
| Reader shun | Common owner key; resource identity is the hostgroup, hostname, and port; previous status is before-value result data. | The intended reader is `SHUNNED_AWS_BGD`. | Compare-and-restore the recorded prior status. |
| Writer reader-hostgroup membership | Common owner key; resource identity is the writer server and reader hostgroup; original and applied membership are result data. | Membership matches the transition policy. | Compare-and-restore the configured membership. |

`PROPOSED-POLICY`: The effect ledger is stored as keyed sets or maps. Repeated
observations cannot create duplicate records or ambiguous effect ownership.

## Required Controller Invariants

`PROPOSED-POLICY`: The hardened controller must maintain the following safety
and liveness invariants. They describe intended behavior, not the current
implementation.

### Safety

1. `IDLE` has no unsettled temporary effects in the active cleanup ledger;
   settled audit tombstones may remain outside it.
2. Every visible controller-owned effect remains in the active cleanup ledger
   until it is `REVERTED` or `COMMITTED`.
3. Worker termination cannot destroy the only cleanup record for an effect.
4. Repeated observations retry incomplete actions.
5. Completed actions are not reapplied without a new action generation.
6. An unknown or malformed observation, or a query failure, preserves the last
   safe state and causes no destructive transition.
7. Topology disappearance before observed writer completion selects rollback.
8. Successful finalization requires observed writer completion.
9. A drained connection cannot become reusable.
10. A direct target includes the writer host or IP, port, and SSL mode.
11. Persistent configuration, runtime configuration, the hostgroup manager,
    and exported configuration agree on nullability.
12. Rollback and successful finalization are idempotent.
13. A stale worker cannot apply a result to a newer deployment generation.
14. No deployment-registry lock is held during DNS, SQLite, hostgroup-manager,
    connection-pool, or socket operations.

### Liveness

`PROPOSED-POLICY`: Liveness holds under fair scheduling, eventual recovery of
retryable dependencies, and unchanged effect ownership. A permanent failure or
ownership conflict converges to externally visible `FAULTED` with the active
ledger retained, rather than an unsafe overwrite or infinite silent retry.

1. Transient DNS failure remains retryable.
2. Under these liveness conditions, a cancelled deployment eventually restores
   the blue configuration; a permanent failure or ownership conflict instead
   exposes `FAULTED` while retaining its active ledger.
3. Under these liveness conditions, successful completion eventually removes
   temporary pins and shuns; a permanent failure or ownership conflict instead
   exposes `FAULTED` while retaining its active ledger.
4. Worker replacement resumes the deployment or safely rolls it back.
5. Failure for one blue/green pair does not hide other pairs.
6. Fast polling is bounded and has an observable reason.
7. Configuration removal cannot abandon outstanding effects.

## Proposed Controller Model

`PROPOSED-POLICY`: Controller state is separate from the raw AWS status. The
following state diagram is policy subject to author validation; it is not the
current implementation enum.

```text
IDLE
  -> TRACKING
  -> PREPARING
  -> CUTOVER
  -> REPOINTING
  -> AWAITING_READER_DNS
  -> FINALIZING_SUCCESS
  -> IDLE only when the active cleanup ledger is settled and empty

Any active state + topology disappears before observed writer completion
  -> ROLLING_BACK
  -> IDLE only when the active cleanup ledger is settled and empty

Any state at or after observed writer completion + configuration removal
  -> SAFE_TEARDOWN
  -> IDLE only when the active cleanup ledger is settled and empty

Any state + permanent failure or unrecoverable inconsistency
  -> FAULTED with the active cleanup ledger and deployment context retained
```

### Observation-Driven Transitions

`PROPOSED-POLICY`: The controller applies the following transitions from
observations and lifecycle events. The accepted reader-completion signal is a
symbolic policy input pending author validation; it may ultimately be defined
as empty or absent topology after observed writer completion.

`PROPOSED-POLICY`: Each deployment context has a configuration-management mode
orthogonal to its raw AWS phase. `ACTIVE` means validated configuration still
manages the deployment. `CONFIG_DISABLED` is the explicit-disable form of the
existing `CONFIG_REMOVED` lifecycle event. Either event latches
`REMOVAL_REQUESTED` as a cleanup request. Raw topology observations never clear
`REMOVAL_REQUESTED`. Only an explicit, validated re-add or re-enable of the
same deployment under a new configuration generation may request a return to
`ACTIVE`, and only after ownership and configuration reconciliation succeeds.

`PROPOSED-POLICY`: Permanent-failure and ownership-conflict rules have highest
precedence. The latched management mode and `ROLLING_BACK` rules are evaluated
next, before repeated, regressed, or generic forward-phase mappings. An
eligible forward-mapping state therefore excludes `ROLLING_BACK`, `FAULTED`,
`FINALIZING_SUCCESS`, and `SAFE_TEARDOWN`.

`PROPOSED-POLICY`: The normal recognized-phase mappings below apply only to an
initial or forward observation. An observation equal to the recorded phase
uses the repeated-phase rule. An observation lower than the highest trusted
completion evidence uses the regression rule and never causes a reverse
transition. For a newly observed deployment, its initial `IDLE` context is a
pre-completion nonterminal context for these mappings.

| Controller state and input | Required transition or action |
|---|---|
| Any + permanent failure or ownership conflict | Enter `FAULTED` with the active ledger and deployment context retained. |
| Any + `QUERY_FAILED` | Preserve state and effects, then retry. |
| Any + `UNKNOWN_STATUS` or `MALFORMED_TOPOLOGY` | Preserve state, expose the input, and make no destructive transition; action-result or error policy may enter `FAULTED` when the condition is classified permanent. |
| `ROLLING_BACK` + any pre-completion recognized phase | Remain in `ROLLING_BACK` and record the observation for diagnostics; do not resume cutover unless validated configuration explicitly re-enables the deployment and ownership reconciliation accepts it. |
| `ROLLING_BACK` + `WRITER_COMPLETED` | Stop or cancel pending rollback commands that would restore obsolete blue or remove the promoted target, latch writer-completion evidence, and enter `SAFE_TEARDOWN` when management mode is `REMOVAL_REQUESTED`; otherwise select an author-validated post-completion recovery or finalization path. |
| `ROLLING_BACK` + `TOPOLOGY_ABSENT` or `TOPOLOGY_EMPTY` | Remain in `ROLLING_BACK` and continue reconciling rollback effects. |
| `REMOVAL_REQUESTED` + any observation at or after writer completion | Enter or remain in `SAFE_TEARDOWN`; never apply a generic `AWAITING_READER_DNS` transition or restore blue solely from the raw phase. |
| Any + repeated observation of the same phase | Keep the controller state and reconcile incomplete effects. |
| Any + a regressed recognized phase | Preserve the highest trusted completion evidence and active effects, expose the regression, and make no reverse destructive transition until an author-validated policy decides how to handle it. |
| `IDLE` or `TRACKING` + `AVAILABLE` | Enter or remain in `TRACKING`; reconcile mapping, resolution, and preparation without applying cutover effects. |
| Any eligible forward-mapping state + `WRITER_INITIATED` | Enter `PREPARING`; record the latest observation and reconstruct or reconcile prerequisites. |
| Any eligible forward-mapping state + `WRITER_IN_PROGRESS` | Enter `CUTOVER`; record the latest observation and reconstruct or reconcile prerequisites and required cutover actions. |
| Any eligible forward-mapping state + `WRITER_POST_PROCESSING` | Enter `REPOINTING`; record the latest observation and reconstruct or reconcile all unmet prerequisites and repoint actions. |
| Any eligible forward-mapping state + `WRITER_COMPLETED` | Enter `AWAITING_READER_DNS`; record writer-completion evidence, then reconstruct and verify every unmet prerequisite effect or establish that it is obsolete under an author-validated policy; never infer that a skipped action succeeded. |
| Any pre-completion state + `TOPOLOGY_ABSENT` or `TOPOLOGY_EMPTY` | Enter `ROLLING_BACK`. |
| `ACTIVE` + `AWAITING_READER_DNS` + `ACCEPTED_READER_COMPLETION_SIGNAL` | Enter `FINALIZING_SUCCESS`. |
| `ACTIVE` + `CONFIG_CHANGED` | Preserve the deployment context and active ledger, then reconcile validated new configuration. |
| Any pre-completion state + `CONFIG_REMOVED` or `CONFIG_DISABLED` | Latch `REMOVAL_REQUESTED` and enter `ROLLING_BACK`. |
| Any state at or after observed writer completion + `CONFIG_REMOVED` or `CONFIG_DISABLED` | Latch `REMOVAL_REQUESTED` and enter `SAFE_TEARDOWN`; never restore blue solely because configuration was removed or disabled. |
| `REMOVAL_REQUESTED` + ordinary `CONFIG_CHANGED` or raw topology | Preserve `REMOVAL_REQUESTED`; do not resume generic forward processing. |
| `REMOVAL_REQUESTED` + explicit validated re-add or re-enable | Start a new configuration generation, reconcile ownership and configuration, and return to `ACTIVE` at the controller state appropriate to retained trusted evidence only after reconciliation accepts ownership. |
| Any + `WORKER_RESTARTED` | Attach the new worker generation to the same deployment context, state, and active ledger. |
| `ROLLING_BACK` + active ledger settled and empty | Enter `IDLE`. |
| `FINALIZING_SUCCESS` or `SAFE_TEARDOWN` + active ledger settled and empty | Enter `IDLE`. |

`PROPOSED-POLICY`: Every action execution returns one classified result:

- `SUCCEEDED`: The command changed the owned resource and verification observed
  the intended value.
- `ALREADY_SATISFIED`: Verification found the owned intended value without
  needing to repeat the command.
- `RETRYABLE_FAILURE`: The effect remains pending for a later reconciliation.
- `PERMANENT_FAILURE`: Policy cannot safely complete or retry the effect; enter
  `FAULTED` with the active ledger retained.
- `OWNERSHIP_CONFLICT`: The resource does not equal the value applied by this
  owner; retain the entry as `CONFLICT` and enter `FAULTED` without overwriting
  it.
- `STALE_RESULT`: The result belongs to an older deployment or worker
  generation and must not mutate current state or effects.

`PROPOSED-POLICY`: Repetition count alone does not make a failure permanent.
The executor classification and author-validated error policy determine
whether a failure is retryable or permanent.

### Reconciliation

`PROPOSED-POLICY`: Phase changes update controller status and emit an
observable log record, but actions are reconciled on every poll.
Actions returning `RETRYABLE_FAILURE` remain pending. Completed actions return
`ALREADY_SATISFIED` instead of repeating the effect, and stale results are
discarded. Advancing an observation does not prove that its actions completed.

### Successful Finalization

`PROPOSED-POLICY`: Successful finalization is selected only when management
mode remains `ACTIVE` after observed writer completion and the controller has
the reader-completion signal accepted by policy after author validation. It
then removes temporary DNS pins, reconciles reader status and writer
reader-hostgroup membership, reconciles writer role and placement with the
accepted desired post-switchover runtime configuration, drains obsolete
green-hostgroup connections, clears the direct probe and monitor suppression,
and clears mapping and resolution records. Successfully restored reversible
entries become `REVERTED`. Connection drains become `COMMITTED` only after
every connection predating the drain generation is verified retired. Any
retained green placement becomes `COMMITTED` only after explicit handoff into
desired runtime configuration. The blue-writer-demotion record becomes
`COMMITTED` only after the controller verifies handoff of writer role and
placement into the accepted desired post-switchover runtime configuration; it
never restores obsolete blue solely after observed writer completion. A
conflict or permanent inability to complete that handoff enters `FAULTED` with
the active ledger retained. The controller enters `IDLE` only when the active
cleanup ledger is settled and empty; settled audit tombstones may remain
outside it.

`PROPOSED-POLICY`: Successful finalization uses the ordered per-effect
settlement checklist in **Safe Teardown** wherever it applies. Its terminal
desired configuration is the accepted `ACTIVE` post-switchover configuration,
rather than removal intent, but it uses the same evidence gate, ownership
checks, dependency ordering, and `FAULTED` behavior.

### Safe Teardown

`PROPOSED-POLICY`: `SAFE_TEARDOWN` is selected when management mode is
`REMOVAL_REQUESTED` at or after observed writer completion. It settles effects
against the accepted terminal post-switchover removal intent and never restores
blue merely because configuration was removed or disabled.

`PROPOSED-POLICY`: Reader-related DNS pins, reader shuns, writer
reader-hostgroup membership, and direct-probe protection cannot be cleared
before the accepted reader-completion evidence or an author-validated
equivalent is observed. The dispatcher-owned cleanup executor continues
observing through a retained complete probe target and deployment context even
after the configured worker is removed. If accepted evidence cannot be
obtained, or an effect cannot be settled safely because of permanent failure or
ownership conflict, the controller enters externally visible `FAULTED`,
retains the active ledger and context, and does not clear effects merely to
reach `IDLE`.

`PROPOSED-POLICY`: After the evidence gate is satisfied, the controller settles
effects in this order:

1. DNS pins: Remove each pin only when the action owner still owns its applied
   value.
2. Reader shuns: Compare-and-restore each prior value or hand it off to the
   accepted terminal desired configuration. A missing resource that removal
   intent deliberately deleted may be `ALREADY_SATISFIED` only after ownership
   validation.
3. Writer reader-hostgroup membership, blue writer demotion, and
   green writer placement: Reconcile and hand them off to the accepted terminal
   post-switchover configuration or removal intent, then mark them `COMMITTED`.
   An ownership conflict or permanent settlement failure enters `FAULTED`.
4. Monitor suppression: Clear it only after DNS, reader, and routing-placement
   protection are settled.
5. Direct probe: Clear it only after it is no longer needed to obtain evidence
   or complete cleanup.
6. Connection drain: Mark it `COMMITTED` only after every connection predating
   the drain generation is verified retired.
7. Blue/green mapping and green resolution records: Commit or clear them only
   after every dependent effect is settled.

`PROPOSED-POLICY`: The deployment context enters `IDLE` and becomes eligible
for removal only when the active cleanup ledger is empty.

### Cancellation Rollback

`PROPOSED-POLICY`: Topology absence before observed writer completion enters
rollback. Rollback removes owned DNS pins; restores the configured blue probe
candidates, recorded reader statuses, and recorded hostgroup placement;
compare-and-restores the original blue writer role and placement; clears
monitor suppression; removes temporary green placement according to the
validated placement policy; and clears mapping and resolution records. The
controller marks a reversible entry `REVERTED` only after compare-and-restore
verifies the inverse. An irreversible drain or explicitly handed-off retained
placement becomes `COMMITTED` under the ledger rules. The controller enters
`IDLE` only when the active cleanup ledger is settled and empty; a conflict
instead retains the active ledger in `FAULTED`.

### Query And Data Errors

`PROPOSED-POLICY`: Query and data errors select the following recovery
behavior; they do not imply successful completion.

| Condition | Required controller behavior |
|---|---|
| Query timeout or connection failure | Preserve state and retry. |
| Unknown status | Preserve state, expose the unknown value, and make no destructive transition. |
| Malformed topology | Preserve state, expose the malformed input, and make no destructive transition. |
| DNS failure | Keep the resolution action pending. |
| Required mapping missing | Keep the mapping action pending. |
| One reader action fails | Retain completed reader actions and retry the failed reader action. |
| Permanent action failure | Enter `FAULTED` with the active cleanup ledger retained. |
| Ownership conflict | Enter `FAULTED` with the conflicting entry and active ledger retained; do not overwrite the resource. |
| Repeated rollback failure | Remain in `ROLLING_BACK` while classified retryable, or enter `FAULTED` when classified permanent; repetition count alone is not permanent, and the controller never enters `IDLE` with an unsettled entry. |

## Worker And Configuration Lifetime

`PROPOSED-POLICY`: Controller state and its effect ledger have deployment
lifetime, not worker-stack lifetime.

```text
dispatcher creates or retrieves deployment context
  -> worker generation N attaches
  -> configuration checksum changes
  -> generation N detaches; deployment context remains
  -> worker generation N+1 attaches and resumes reconciliation
```

`PROPOSED-POLICY`: Configuration changes update the deployment context without
clearing it. Disabling or removing configuration before observed writer
completion latches `REMOVAL_REQUESTED` and requests rollback. At or after
observed writer completion, removal latches `REMOVAL_REQUESTED` and enters
`SAFE_TEARDOWN`, including when `FINALIZING_SUCCESS` had already begun; it never
restores blue solely because configuration was removed.

`PROPOSED-POLICY`: Post-completion configuration removal follows the evidence
gate and ordered settlement checklist in **Safe Teardown**. The terminal desired
configuration reflects validated removal intent. The same checklist reconciles
writer role and placement and marks the demotion record `COMMITTED` only after
verified handoff; it never compare-and-restores obsolete blue after observed
writer completion.

`PROPOSED-POLICY`: When a configuration worker is removed, the dispatcher
retains or starts an independent cleanup executor until the active ledger is
settled or an externally visible `FAULTED` state is reached. The dispatcher
removes the deployment context only after it reaches `IDLE` with a settled,
empty active ledger. It does not erase a context in `FAULTED`.

`PROPOSED-POLICY`: Durable SQLite persistence is unnecessary only if every
controller-owned effect is proven to disappear, revert, or be reconstructable
after a full ProxySQL process restart. This includes DNS pins, runtime shuns,
monitor suppression, backend connections and their drain generations,
green writer placement, blue writer demotion,
writer reader-hostgroup membership, and the direct probe target. If any effect
does not meet that condition, the controller persists its ledger or provides
deterministic startup recovery.
Whether the condition holds requires author validation and is not a guarantee
of current behavior.

## Configuration Model

The feature has blue writer and reader hostgroups and optional green writer
and reader hostgroups.

| Green writer hostgroup | Green reader hostgroup | Intended semantics |
|---|---|---|
| `NULL` | `NULL` | Automatic discovery. |
| Value | Value | Explicit green hostgroups. |
| Value | `NULL` | Validation decision required. |
| `NULL` | Value | Validation decision required. |

`PROPOSED-POLICY`: Persistent Admin, runtime Admin, Hostgroup Manager (HGM),
configuration import and export, `LOAD` and `SAVE`, and cluster representation
preserve the same accepted `NULL` and value combinations. Rejected
combinations fail explicitly and retain the previous valid configuration.

`PROPOSED-POLICY`: Configuration updates have generations. Configuration
removal latches `REMOVAL_REQUESTED`. Re-adding or re-enabling the deployment
creates a new validated generation and must reconcile ownership before
resuming controller processing.

## Author Validation Checklist

The original author must confirm or correct every answer below before work on
the deterministic simulator begins.

| ID | Question | Safe default until validated |
|---|---|---|
| AWS-01a | Can the source row be missing before `WRITER_COMPLETED`? | Treat a missing required row identity as `MALFORMED_TOPOLOGY`; preserve state and make no destructive transition. |
| AWS-01b | Can the source row be missing after `WRITER_COMPLETED`? | Do not treat a missing source row alone as reader completion; use the accepted reader-completion signal. |
| AWS-01c | Can the target row be missing from a successful, nonempty result? | Treat a missing target row as `MALFORMED_TOPOLOGY`; preserve state and expose the malformed input. |
| AWS-01d | Can `TOPOLOGY_EMPTY` occur at each phase? | Before observed writer completion, enter `ROLLING_BACK`; afterward, treat it as the accepted reader-completion signal only if the author validates that meaning. |
| AWS-01e | Can `TOPOLOGY_ABSENT` occur at each phase? | Apply the same pre-completion and post-completion boundary policy as `TOPOLOGY_EMPTY`, but retain it as a distinct event. |
| AWS-02a | Can AWS cancellation occur before observed writer completion? | Enter `ROLLING_BACK` with the owned effect ledger retained. |
| AWS-02b | Can AWS cancellation occur after observed writer completion? | Use `FINALIZING_SUCCESS` or `SAFE_TEARDOWN` according to management mode and accepted evidence; never restore blue solely because of cancellation. |
| AWS-03 | Do `TOPOLOGY_EMPTY` and `TOPOLOGY_ABSENT` have the same phase-specific meaning? | Keep them distinct until the author validates their meanings. |
| AWS-04 | What is the exact timing relationship between source-row removal and writer DNS change? | Never infer DNS state from row count. |
| AWS-05a | How long and through which phases is the target row retained? | Treat retention only as observation evidence, not reader completion, and record the exact author-validated phase lifecycle. |
| AWS-05b | What exact observation is the accepted reader-completion signal? | Do not finalize until the author validates an explicit signal or equivalence. |
| AWS-06 | When is the green hostname retired? | Retain a complete owned probe target while it is needed for observation or cleanup. |
| AWS-07 | What is the authoritative source for the green writer port in automatic and explicit modes? | The complete direct tuple uses the green writer host or IP and green writer port from the same mapped identity; keep the action pending or enter visible `FAULTED` if unavailable; never use `hpa[0]`. |
| AWS-08 | What is the authoritative source for the green writer SSL mode in automatic and explicit modes? | The complete direct tuple uses the green writer SSL mode from the same mapped identity; keep the action pending or enter visible `FAULTED` if unavailable; never use an arbitrary row. |
| AWS-09 | Is incomplete reader mapping expected? | Track and reconcile each reader independently. |
| AWS-10 | Is green writer placement temporary or persistent? | Record owned before-value and applied-value, then settle through rollback or verified handoff. |
| AWS-11a | What happens when ProxySQL configuration is removed before observed writer completion? | Latch `REMOVAL_REQUESTED`, enter `ROLLING_BACK`, and retain the dispatcher-owned cleanup executor and deployment context. |
| AWS-11b | What happens when ProxySQL configuration is removed after observed writer completion? | Latch `REMOVAL_REQUESTED`, enter `SAFE_TEARDOWN`, never restore blue solely because of removal, and retain the dispatcher-owned cleanup executor and deployment context. |
| AWS-12a | What happens when the first observation is `WRITER_POST_PROCESSING`? | Reconstruct prerequisites and ownership or enter visible `FAULTED`. |
| AWS-12b | What happens when the first observation is `WRITER_COMPLETED`? | Record writer-completion evidence; reconstruct and verify skipped effects or enter a safe visible fault; never assume they succeeded. |
| AWS-13 | What is each effect's observed external state after a full ProxySQL process restart, and how is its ownership ledger independently recovered? | Persist ownership before mutation or perform deterministic startup reconstruction; block reconciliation or enter visible `FAULTED` until ownership is recovered. |
| CFG-01a | Is a green writer hostgroup value with a `NULL` green reader hostgroup valid? | Reject the combination until its precise meaning is accepted. |
| CFG-01b | Is a `NULL` green writer hostgroup with a green reader hostgroup value valid? | Reject the combination until its precise meaning is accepted. |

### Probe Target Validation Matrix

| Mode | Host/IP source | Port source | SSL source | Author decision/evidence |
|---|---|---|---|---|
| Automatic | Author validation required | Author validation required | Author validation required | Validation required. |
| Explicit | Author validation required | Author validation required | Author validation required | Validation required. |

`PROPOSED-POLICY`: A direct probe target is a complete host or IP, port, and
SSL tuple from the same mapped green writer identity, never from an arbitrary
monitor row. An unresolved field keeps the action pending or enters an
externally visible `FAULTED` state according to the accepted error policy.

### Restart Validation Matrix

| Effect | Observed external state after restart | Ledger recovery mechanism | Required reconciliation or settlement | Required evidence |
|---|---|---|---|---|
| DNS pins | Author validation required | Author decision required: persisted record or deterministic startup reconstruction. | Compare the observed value with the recovered before-value and applied-value. If observed equals the before-value, including absent when before was absent, mark `REVERTED`. If observed still equals the owned applied pin, owner-safely remove it, restore a nonempty recorded before-value when required, verify, then mark `REVERTED`. If observed is a different value or owner, enter `FAULTED` with the ledger retained and never overwrite it. DNS pins have no handoff path. | Full-restart trace, DNS lookup, and recovered ownership proof. |
| Reader shuns | Author validation required | Author decision required: persisted record or deterministic startup reconstruction. | Inspect current status plus before-value, applied-value, and ownership; compare-and-restore, hand off, or enter `FAULTED`. | Full-restart trace, runtime reader status, and recovered ownership proof. |
| Monitor suppression | Author validation required | Author decision required: persisted record or deterministic startup reconstruction. | Inspect or reconstruct the suppression marker, or explicitly clear it only under a verified safe state. | Full-restart trace, monitor-suppression state, and recovered ownership proof. |
| Active connections and drain generations | Author validation required | Author decision required: persisted record or deterministic startup reconstruction. | Inspect live connections and their drain generations; never revive or reuse a pre-generation connection. | Full-restart trace, connection-generation inventory, and recovered ownership proof. |
| Green placement | Author validation required | Author decision required: persisted record or deterministic startup reconstruction. | Inspect current placement and ownership; compare, hand off, roll back, or enter `FAULTED`. | Full-restart trace, runtime hostgroup placement, and recovered ownership proof. |
| Blue demotion | Author validation required | Author decision required: persisted record or deterministic startup reconstruction. | Inspect current writer role and ownership; compare, hand off, roll back, or enter `FAULTED`. | Full-restart trace, runtime writer role, and recovered ownership proof. |
| Writer reader-hostgroup membership | Author validation required | Author decision required: persisted record or deterministic startup reconstruction. | Inspect current membership and ownership; compare, hand off, roll back, or enter `FAULTED`. | Full-restart trace, runtime membership, and recovered ownership proof. |
| Direct probe | Author validation required | Author decision required: persisted record or deterministic startup reconstruction. | Reconstruct the complete owned green writer host or IP, port, and SSL tuple; if reconstruction fails, block reconciliation or enter visible `FAULTED`. | Full-restart trace, active probe target, and recovered ownership proof. |
| Mapping and resolution | Author validation required | Author decision required: persisted record or deterministic startup reconstruction. | Reconstruct stable resource identities and resolution results before any dependent action runs. | Full-restart trace, mapping and resolution records, and recovered ownership proof. |

`PROPOSED-POLICY`: After restart, the controller cannot mutate or clear an
effect until its ownership record has been persisted or deterministically
reconstructed. Startup blocks reconciliation or enters externally visible
`FAULTED` with a diagnostic until ownership is recovered; it never assumes an
effect disappeared.

## Test Mapping For Later PRs

| Requirement | Named unit/simulator case | Named Admin/TAP case | Observable postcondition |
|---|---|---|---|
| Complete lifecycle | `happy_path_explicit`, `happy_path_auto` | `test_lifecycle` | Controller reaches `IDLE` with an empty active ledger and the correct backend configuration. |
| Same-phase retry with injected failure | `dns_retry_same_post` | `repeated_post` | The second attempt applies the effect exactly once. |
| Direct, skipped, repeated, and regressed phases | `late_entry_each_phase`, `regressed_phase` | `late_start` | Prerequisites are reconstructed and no destructive reverse transition occurs. |
| Unknown, malformed, and query-failure observations | `invalid_observation_preserves_state` | `injected_query_errors` | State and effects remain unchanged and the error is visible. |
| Pre-completion cancellation in every controller state | `cancel_each_precompletion_state` | `cancel_precompletion_post` | Controller selects `ROLLING_BACK`, restores only owned pre-completion effects, and leaves no stale routing. |
| Post-completion cancellation or removal | `cancel_or_remove_postcompletion` | `cancel_or_remove_after_completed` | Controller selects `FINALIZING_SUCCESS` or `SAFE_TEARDOWN` according to management mode and accepted evidence; owned reversible DNS pins become `REVERTED`; reader shuns become `REVERTED` when their prior status is restored or `COMMITTED` after verified handoff to the accepted terminal configuration; drains and explicitly handed-off retained routing effects become `COMMITTED`; the active cleanup ledger is empty; obsolete blue is never restored. |
| Successful-cleanup idempotence | `repeat_finalization` | `repeated_empty` | No effect is duplicated and the active ledger is empty. |
| Rollback idempotence | `repeat_rollback` | `repeated_absence` | No effect is duplicated and the active ledger is empty. |
| Worker replacement after every effect | `restart_after_each_effect` | `restart_post` | The replacement uses the same ledger and rejects the stale generation. |
| Configuration generation change | `config_generation_change` | `admin_load_update` | The deployment context is retained and reconciled. |
| Pre-completion configuration removal | `remove_config_precompletion` | `remove_during_post_before_completion` | Rollback completes through the dispatcher-owned executor. |
| Post-completion configuration removal | `remove_config_postcompletion` | `remove_after_completed` | Safe teardown completes without restoring blue. |
| DNS failure and recovery | `dns_fail_then_recover` | `controlled_resolver_fixture` | Resolution remains pending, then creates one owned DNS pin after recovery. |
| Partial reader progress | `one_reader_fails` | `multiple_reader_fixture` | The successful reader action remains recorded as `APPLIED` and is not reissued; only the failed reader action retries. |
| Ownership conflict | `compare_restore_conflict` | `external_admin_mutation` | Controller enters `FAULTED`, retains the ledger, and leaves the newer value unchanged. |
| Stale action result | `stale_worker_result` | `forced_worker_refresh` | The stale result is rejected without mutating current state or effects. |
| Deployment isolation | `two_deployments_interleaved` | `two_hostgroup_fixture` | No effect or ownership record crosses deployment boundaries. |
| Effect settlement | `irreversible_and_handoff_settlement` | `final_runtime_query` | Every effect is settled as `COMMITTED` or `REVERTED`; the active cleanup ledger is empty; optional audit tombstones exist only outside the active ledger. |
| Drain-generation concurrency | `drain_generation_barriers` | `active_traffic` | Pre-generation connections are never reused and post-generation connections remain usable. |
| Bounded polling | `fake_clock_retry_bounds` | `monitor_timing_logs` | No zero-delay retry loop occurs and the retry reason is visible. |
| Registry locking | `executor_runs_without_context_lock` | `diagnostic_assertion` | No external callback runs while the deployment-context registry lock is held. |
| Configuration `NULL` and value representations | `config_matrix_roundtrip` | `config_import_admin_load_save_cluster` | Exact values round-trip, or rejection is explicit and preserves the previous valid configuration. |
| Heterogeneous endpoint tuple | `writer_endpoint_tuple` | `distinct_blue_green_writer_port_ssl` | The fixture's blue and green writer port and SSL values differ, and the direct target uses the complete mapped green writer host or IP, port, and SSL tuple. |
| Process-restart recovery | `restart_effect_matrix` | `proxysql_restart_fixture` | External state follows the author-accepted matrix and ledger ownership is independently recovered before mutation; otherwise startup blocks reconciliation or enters visible `FAULTED`. |
| Second deployment after cancellation and success | `second_after_cancel_and_success` | `two_sequential_lifecycles` | The new generation has no stale ownership or effects from the prior deployment. |

## Review Gate

The document status remains **AUTHOR VALIDATION REQUIRED** until the original
author:

1. Provides evidence for or corrects every `REVIEW-VALIDATION-PENDING` claim.
2. Answers every item in the **Author Validation Checklist** and completes
   every author decision in both validation matrices.
3. Confirms that the safe defaults do not contradict observed AWS behavior.
4. Approves the observation vocabulary and transition precedence for the
   deterministic simulator.
5. Confirms the accepted reader-completion signal and configuration-removal
   behavior.
6. Records every answer, correction, evidence URL or trace, and resulting
   policy disposition in this document's checklist and matrices.

The status changes only after no checklist or matrix decision and no external
`REVIEW-VALIDATION-PENDING` claim remains unresolved. PR2 must use only policy
recorded as accepted in this document and must not define additional production
policy.
