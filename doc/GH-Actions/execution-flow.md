# CI execution flow

## Current source callers

```mermaid
flowchart TD
    E[Pull request, maintained-branch push, or manual build] --> B[CI-builds]
    B --> P[Plan configurations on a hosted runner]
    P --> C[Compile inside the packaging container]
    C --> V[Read actual binary version inside that container]
    V --> H[Publish immutable handoff and metadata]
    H --> F[Finalize manifest and accepted producer]
    F --> D[Native workflow_run completion event]
    D --> X[Hosted consumer context: bind the exact producer and select a runner pool]
    X --> T[Restore handoff and execute tests]
    T --> R[Publish results]
```

The build command must succeed; `pipefail` prevents `tee` from hiding a failed producer. The existing container-success log check is also retained because older product Makefiles do not propagate the container exit status. Source checkout uses the pull request head SHA, not the merge SHA. Planning, finalization and binding do not queue on the self-hosted test pool.

The producer publishes acceptance only after required builds and manifest publication succeed. Consumers validate the source repository, source revision and producer run. A failed-job rerun may accept the original immutable execution; the acceptance artifact is associated with the new completion attempt while its producer binding still names the retained build. Explicit manual consumer dispatch continues to require an exact producer run and attempt.

The trusted build entry rejects fork pull requests. Completion callers require the producer repository to match before starting a privileged reusable workflow; consumers still require the matching acceptance artifact. The caller validator evaluates foreign and fork event paths, so a disjunction cannot bypass the guards.

The shared consumer-binding code identifies native completion by the workflow file path, not the dynamic run title. Caller YAML separately suppresses duplicate legacy build completion with `github.event.workflow_run.event != 'workflow_run'`. Workflow concurrency groups include the producer repository, so rejected foreign events cannot cancel trusted runs with matching branch names. Superseded and closed-PR cancellation recognizes both entry workflows.

## Legacy callers

Older maintained branches still start `CI-trigger`, so the shared adapter remains available:

```mermaid
flowchart LR
    L[Legacy CI-trigger] -->|in_progress| B[CI-builds legacy route]
    B -->|completion observed by adapter| A[CI-trigger publishes accepted producer]
    A -->|completed| C[Consumers]
```

The default build workflow retains its legacy subscription. Consumers listen to both entry workflows, but skip completion of a build whose own event was `workflow_run`: that legacy build is followed by acceptance on `CI-trigger`. This prevents duplicate fanout while letting current source callers avoid the polling runner entirely.

Deploy the shared engine PR before the paired source-caller PR. Do not remove the legacy adapter until the remaining maintained callers have migrated.

## Runner and runtime responsibilities

One selector runs within the existing hosted consumer context. It observes pool demand; it does not reserve capacity. Eligibility is passed as an explicit boolean, including when runner configuration is absent. The previous hosted image choices and API-failure policies are preserved. The run-listing failure policy is configurable; an unreadable jobs listing conservatively treats the pool as full and selects the hosted runner. Test userspace belongs to the container image, not this capacity decision.

Current exceptions remain explicit: MySQLX end-to-end testing starts dbdeployer on the hosted VM and installs `libaio1t64`, `libnuma1`, `libncurses6`, and `libtinfo6`. It creates a `libaio.so.1` compatibility link for MySQL. Sanitizer workflows set the host kernel's `vm.mmap_rnd_bits=28`. These are existing runtime requirements, not reasons for the generic hosted fallback to require a particular Ubuntu release.

## Artifact guarantees

Handoffs, manifests and consumer bindings have matching retention. Compiled test executables are retained; applicability is handled by the runner.

The shared control branch implements restoration in [`restore_handoff()`](https://github.com/sysown/proxysql/blob/GH-Actions/.github/scripts/ci_tier_artifacts.py#L328); this is separate from source-branch artifact helpers. That implementation deliberately retains its two streaming passes. The first rejects unsafe members and corrupt trailing compressed data before anything is installed in the checkout; the second extracts with path and link filtering. Removing the first pass would weaken the existing reject-before-write guarantee, while staging a complete build for later publication would introduce additional filesystem and disk-budget complexity. Checksums and execution/source/tier binding remain enforced.
