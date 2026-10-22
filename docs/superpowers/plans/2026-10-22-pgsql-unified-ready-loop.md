# PostgreSQL unified ready-loop experiment

Approved direction: the in-chat ready-session scheduler design, followed by the user's instruction to try it and commit regularly with detailed descriptions.

Goal: combine frontend input handling, backend response processing, and connection waiter scheduling without the current full-stage dispatch barriers.

Constraints: preserve native backend protocol; benchmark 42-row ~4KB results at50clients/64backend cap/TLS first, then500clients/10backend cap/plaintext. One proxy worker CPU0,16pgbench threads, fixed client/backend CPU placement and performance governor. Preserve TLS retention10 and plaintext retention100. No repository test edits, per the user's earlier benchmark-first instruction. Keep clean baseline binaries and restore them after measurements. Experimental behavior must be opt-in.

- [x] Commit existing inline-handoff and early-dispatch snapshots separately.
- [ ] Implement captured I/O events and a ready-session queue, immediate post-handler waiter scheduling, attachment generations and deferred deletion. Retain legacy maintenance processing.
- [ ] Bound scheduler visits and optionally refresh readiness with zero-time polling between work batches. Carry runnable work without blocking; invalidate carried references during unregister.
- [ ] Build, run live smoke workloads, inspect source diff and commit the runnable prototype with detailed behavior/limitations.
- [ ] Run matched baseline/queue/queue+refresh benchmarks. Record actual pool use, creation/errors, zero-failure checks, binary hashes and exact commits.
- [ ] Commit benchmark methods/findings and restore clean runtime. Preserve incomplete prototypes separately from final averages.

Review focus: stale backend events after pool reassignment; descriptor/session lifetime during dispatch; duplicate runnable sessions; waiter fairness and no-capacity retries; buffered runnable work surviving queue budget; maintenance/kill handling. This remains an experimental benchmark branch, with no claim of multiworker or multi-hostgroup qualification.
