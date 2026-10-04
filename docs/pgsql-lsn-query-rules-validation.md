# PostgreSQL LSN selection validation

Validation completed on 2026-10-04 in the dedicated
`feat/pgsql-lsn-causal-reads` worktree. Schema/configuration, monitor/history,
hostgroup integration and native protocol changes were implemented and reviewed
by separate agents, then tested together. See the
[operator documentation](pgsql-lsn-query-rules.md) for configuration and
reproduction commands.

## Builds and test results

| Check | Result |
| --- | --- |
| Final 3.0, 3.1 and 4.0 debug builds | All passed; separate build outputs for each tier |
| 3.1 affected unit/regression suites | 19 binaries, 1,095 assertions passed |
| 3.0 query rules, migration, config, cluster and server-runtime suites | 5 binaries, 291 assertions passed |
| 4.0 query rules, migration, config, cluster and server-runtime suites | 5 binaries, 361 assertions passed |
| Native PostgreSQL 17 endpoint smoke, 3.1 | 27/27 passed |
| Native PostgreSQL 17 endpoint smoke, 4.0 | 27/27 passed |
| Live schema/upgrade/cluster matrix across all three tiers | 104/104 passed |
| Pure history manager with ASan, UBSan and leak detection | 38/38 passed |
| Standalone coverage builds of manager, probe and monitor | 38/38, 58/58 and 21/21 passed |
| TAP group Makefile dependency tests | 5/5 passed |
| Preprocessed legacy/extended schema checks and Python compilation | Passed |
| Git whitespace/error checks | Passed |

The 3.1 run includes all seven LSN suites, disk upgrade, config serialization,
cluster synchronization, server runtime, existing monitor lifecycle, worker
waiters, query processor, transaction state, named portal teardown, command
completion, response framing and cache allocation tests. These are the affected
suites, not the full repository test suite.

The live endpoint test uses a primary and two physical replicas. It verifies
rule activation after an earlier source execution, HG0, duplicate endpoint
memberships, an idle WAL page boundary, ordinary reads against a lagging
replica, an unchanged cache hit, lagged-destination acquisition timeout without
changing hostgroups, catch-up and selection, COPY, explicit commit, native
extended execution, incompatible transaction refusal and rollback, old-source
history expiry with a stuck replica, cancellation, monitor restart and pool
exhaustion. PostgreSQL application statement logs contain no feature-generated
LSN or identity queries.

The cluster matrix verifies exact ordered projections, source HG0 and NULL,
valid negative rule IDs, populated legacy disk migration, canonical DDL and
deleted-ID sequence watermarks. It exercises actual same-tier and both
3.1↔4.0 PostgreSQL rule pulls, with unrelated enabled synchronization modules
remaining unchanged. All four legacy/extended directions reject without
changing runtime, memory, disk or checksums. Unit tests additionally cover
revoking stale donor eligibility immediately on a compatibility transition,
failed checksum fetches and forced refresh when the global checksum is equal.

## Review corrections

Review and live testing found issues that were corrected before the final
runs: failed extended frames surviving causal refusal or acquisition timeout;
selecting the wrong retained backend during transaction cleanup; a resolved
target skipping later source-history resets; valid retained source history
becoming unusable after a probe failure; signed rule IDs being rejected;
quadratic hostgroup retention work; deadlines using a stale housekeeping clock;
idle WAL header positions preventing a caught-up replica from qualifying; and
stale cluster donor eligibility during a compatibility transition.

Regression tests cover these corrections. Native refusal closes affected
transaction sockets before frontend recovery and preserves unrelated idle
connections. Cache code and the original native initialization sequence remain
unchanged from the base implementation.

## Measurements and limits

The final standalone coverage run executed 93.0% of manager implementation
lines, 98.0% of probe lines and 85.7% of monitor lines. Taken-branch coverage was
66.8%, 76.7% and 53.6%, respectively, including compiler exception edges. Real
blocked DNS, TLS/GSS failure injection, full native application sanitizers and
TSan were not run.

A warm-cache benchmark calling the actual debug-built completion helper and
monotonic clock measured a median 32.32 ns per stable-endpoint completion on
this machine; locating the last of 101 frontend backend records took 268.22 ns.
This is a local helper measurement, not a throughput or production latency
claim. The production retention-method harness measured approximately
0.6–0.7 ms per tick for 1,000 endpoints after removing Cartesian membership
copies, with one sample per endpoint. Representative end-to-end comparison
against the base build, full-window RSS and worker wake overhead remain
unmeasured.

Age pruning bounds numeric samples to the configured window plus one older
anchor, independently of stuck or unavailable peers. Removed-endpoint identity
tombstones remain in the registry; metadata can therefore grow with lifetime
endpoint churn. No bounded tombstone reclamation policy is claimed.

Configured `init_connect` was excluded from the live fixture after reproducing
an existing base-path problem: its native dispatcher case is commented out.
That unrelated behavior was not changed. Completion units verify that this
feature leaves initialization state, pending buffers and deadlines untouched;
the live run covers ordinary session settings on fresh and reused connections.

WAL header normalization is limited to inspected PostgreSQL 14–18 layouts with
reported alignment of 4 or 8. Other layouts retain the conservative raw
insertion position. Live replication used PostgreSQL 17; no separate forced
asynchronous-commit/flush-lag experiment was run. Stable physical endpoints
and external failover fencing remain deployment assumptions.

Detailed logs and isolated reproduction artifacts are retained locally under
`.superpowers/sdd/2026-10-04-pgsql-lsn-query-rules/`, including
`verification-final31.txt`, `live31-final27.log`,
`smoke40-final27-independent.log`, `cluster-smoke-lifecycle-final.tap`,
`cluster-tier-unit-*.tap`, review reports, coverage and sanitizer logs.
