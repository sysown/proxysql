# Independent architecture-diagram review

Reviewed 2026-10-18 on `docs/invariants-expansion`, against production source
`f8ada9117166db4b8e2f83e5ed5909b183bb8a5d` and the current uncommitted diagrams.
Three fresh reviewers independently traced the assigned diagrams to implementation sources.
They received the review requirements and repository location, not the drafting conversation.
Reviewers made no checkout changes. The author subsequently applied the three corrections
below during PR preparation and rechecked the changed diagrams against the cited source.

## Assessment

Initial review of all 25 diagrams found **22 supported, 3 needing correction, none classified
unproven**: **two Important documentation errors and one Minor precision correction**.
All three findings are now corrected. The ledger identifies the author-verified corrections
separately from the diagrams supported in the independent review. These are documentation
findings, not newly discovered production-code defects. Closing them does not close the
broader gaps in the [coverage audit](architecture-coverage-audit.md).

Subsequent automated review also identified an ambiguous edge from background cache maintenance
to the cache-insertion step. The author clarified it as eviction/reclamation, with a separate
flow from stored entries. The original independent verdict and the later clarification are
distinguished in the ledger below.

## Findings

### Important: current SQL projections are incorrectly shown feeding historical storage

Location: [administration responsibilities diagram](../ai-generated/architecture/ADMINISTRATION-AND-STATISTICS.md#L76).

The arrow `projections -->|selected export| historical` identifies current SQL projections
as an input to historical export. Actual digest saving obtains/reset-detaches the aggregate
maps directly from the relevant Query Processor, then inserts those records into history.
Periodic global/pool/cache sampling likewise reads the runtime producer APIs directly.

Evidence:

- [FlushDigestTableToDisk owner access](../../lib/ProxySQL_Admin.cpp#L1108), including
  [map detachment](../../lib/ProxySQL_Admin.cpp#L1114) and
  [history inserts](../../lib/ProxySQL_Admin.cpp#L1127).
- [Periodic owner sampling](../../lib/ProxySQL_Admin.cpp#L2749).
- [Current digest projection](../../lib/ProxySQL_Admin_Stats.cpp#L2021) is a separate consumer.

Why it matters: an implementer could infer that persistence requires refreshing or copying the
materialized `stats_*` tables, and overlook that digest export consumes the owner's aggregates.

Smallest correction: remove the projections-to-history arrow; label the existing services-to-history
arrow as selected owner sampling / digest export. No production change is needed.

Resolution: applied during PR preparation; historical sampling/export now comes from runtime owners.

### Important: local-cache hit and direct shared-return paths are missing

Location: [backend overview diagram](../ai-generated/architecture/BACKEND-MANAGEMENT.md#L30).

The worker-local cache has a miss edge to HGM but no hit edge to the attached connection.
The only depicted release path also passes through retained local cache inventory. Actual
checkout can hit locally, and `push_MyConn_local()` only retains selected releases; others
return directly to HGM. Publication of retained local inventory is a distinct later operation.

Evidence: [MySQL checkout](../../lib/MySQL_Session.cpp#L10042),
[PostgreSQL checkout](../../lib/PgSQL_Session.cpp#L5544),
[MySQL local retention/direct return](../../lib/MySQL_Thread.cpp#L7497),
[PostgreSQL equivalent](../../lib/PgSQL_Thread.cpp#L6257), and
[retained-cache publication](../../lib/MySQL_Thread.cpp#L7549).

Why it matters: these paths define connection ownership, pool accounting and availability
to other workers. A retained local connection remains accounted as used by HGM and is not
available through the shared free pool; a direct shared return changes that availability
immediately. Omitting the local hit also hides acquisition without a shared-pool checkout.
Conflating these transitions can mislead changes to pooling, synchronization, capacity
handling and statistics. Adjacent prose does not make an incomplete ownership diagram safe
to use as an architectural reference. This finding is Important, as clarified by the
maintainer after the initial review; it is a documentation defect, not evidence of a
production-code defect.

Smallest correction: add `LC -->|hit| B`, qualify the B-to-LC edge as conditional local
retention, and add B-to-HGM for direct shared return.

Resolution: applied during PR preparation; local hits, conditional retention, direct shared return
and later publication of retained inventory are separate edges.

### Minor: post-readiness traffic-listener startup needs core-protocol scope

Location: [startup diagram, line 476](../ai-generated/architecture/VISUAL-GUIDE.md#L477).

The label "Open traffic listeners" follows extension start and runtime-ready processing.
That order describes the core MySQL/PostgreSQL listeners. Plugin listeners can already
be open: mysqlx reconciles/binds listeners and starts its threads during plugin start,
before the core runtime-ready callback/gate sequence.

Evidence: [core orchestration](../../src/main.cpp#L1907),
[mysqlx start](../../plugins/mysqlx/src/mysqlx_plugin.cpp#L200),
[listener reconciliation](../../plugins/mysqlx/src/mysqlx_listener_reconcile.cpp#L143), and
[listen call](../../plugins/mysqlx/src/mysqlx_thread.cpp#L366).

Why it matters: the broad label can suggest one universal traffic-admission boundary.
The surrounding text already acknowledges distinct readiness signals, so this is a
scope correction rather than a product startup defect.

Smallest correction: rename the node to "Open core MySQL/PostgreSQL traffic listeners."

Resolution: applied during PR preparation with the core-protocol scope explicit in the node.

## Per-diagram ledger

"Supported" means consistent with the inspected source at the stated abstraction level,
including the qualifications adjacent to the diagram. It does not prove exhaustive runtime
correctness, race freedom or complete coverage of every optional deployment.

| Diagram | Reviewer area | Verdict | Principal source evidence |
| --- | --- | --- | --- |
| Visual §1: deployment | Management/statistics | Supported | Local Session/HGM acquisition and Cluster metadata/configuration paths |
| Visual §2: product modules | Management/statistics | Supported | Worker-to-Session dispatch; Session policy/cache/account/HGM consumers; Admin installs |
| Visual §3: execution contexts | Backend/lifecycle | Supported | main worker/supervisor/watchdog construction; Admin client handlers; background tasks |
| Visual §4: configuration representations | Management/statistics | Supported | Admin bootstrap/copy; owner commits/worker refresh; direct runtime-only Cluster apply |
| Visual §5: ordinary login/backend acquisition | Runtime | Supported | MySQL protocol credential verification; Session admission/attachment and later setup |
| Visual §6: identity responsibilities | Runtime | Supported | Account policy, LDAP mapping, backend policy/provider calls, separate PostgreSQL credentials |
| Visual §7: query-policy evaluation | Runtime | Supported | QP version refresh, rule matching/hits/action accumulation, Session enforcement |
| Visual §8: result-cache execution | Runtime | Clarified after automated review | Session lookup/store eligibility; separate background eviction/reclamation path |
| Visual §9: backend acquisition | Backend/lifecycle | Supported | Local lookup/HGM fallback, fit selection, exclusive attachment before setup |
| Visual §10: conceptual reuse states | Backend/lifecycle | Supported | finishQuery/disconnect guards; reset-success versus failure; unsafe-batch cleanup |
| Visual §11: PostgreSQL extended protocol | Runtime | Supported | Typed frame dispatch, local Bind/cache completions, backend translation and release guards |
| Visual §12: monitoring | Backend/lifecycle | Supported | HGM target publication; protocol probes/actions/history and resource eligibility |
| Visual §13: statistics flows | Management/statistics | Supported | Owner-based SQL projection/history, registry/TSDB, separate circular buffers and files |
| Visual §14: embedded storage | Management/statistics | Supported | Admin database handles/attachments and separate Statistics connections |
| Visual §15: Cluster sequence | Management/statistics | Supported | Metadata/thresholds, expected-checksum validation, local apply and optional persistence |
| Visual §16: startup | Backend/lifecycle | Corrected — author verified | Core listener scope explicit; plugin listeners can open during extension start |
| Visual §17: shutdown/reload | Backend/lifecycle | Supported | Admin drain, plugin retirement/pinning, bootstrap cancellation, joins, runtime reconstruction |
| Visual §18: composition | Backend/lifecycle | Supported | Executable tier implications, plugin recipes/selection and reserved ABI contract |
| Runtime §1: collaborators | Runtime | Supported | Session-to-QP return, attached connection/driver execution, separate configuration installs |
| Runtime §4: common request flow | Runtime | Supported | Normal/local/cache/forward paths and guarded error/retry/release consumers |
| Backend §1: resource relationships | Backend/lifecycle | Corrected — author verified | Local hit, retained local release, direct shared return and publication are distinct |
| Administration: responsibilities | Management/statistics | Corrected — author verified | Owner sampling/digest export feeds history; SQL projection remains a separate consumer |
| Administration: configuration transitions | Management/statistics | Supported | Explicit copy, apply, runtime projection/save and family-specific Cluster paths |
| Administration: events/files/buffer/digests | Management/statistics | Supported | Distinct file/circular-buffer output, drain destinations and separate digest extraction |
| Layout: build graph | Backend/lifecycle | Supported | Top-level deps/lib/src/TAP/plugin target prerequisites and core link targets |

## Source anchors behind supported assessments

- Runtime: [ordinary login](../../lib/MySQL_Protocol.cpp#L4046),
  [Session acquisition](../../lib/MySQL_Session.cpp#L10042),
  [policy refresh](../../lib/Query_Processor.cpp#L2855),
  [rule hits](../../lib/Query_Processor.cpp#L3013),
  [cache storage](../../lib/Query_Cache.cpp#L610),
  [PostgreSQL frame dispatch](../../lib/PgSQL_Session.cpp#L8166).
- Backend/lifecycle: [HGM checkout](../../lib/MySQL_HostGroups_Manager.cpp#L3021),
  [PostgreSQL checkout](../../lib/PgSQL_HostGroups_Manager.cpp#L2899),
  [reuse guards](../../lib/MySQL_Session.cpp#L10883),
  [shutdown](../../src/main.cpp#L2018),
  [manager retirement](../../lib/ProxySQL_PluginManager.cpp#L2441),
  [build orchestration](../../Makefile#L420).
- Management/statistics: [configuration copy](../../lib/ProxySQL_Admin.cpp#L6493),
  [Cluster direct runtime apply](../../lib/ProxySQL_Cluster.cpp#L2076),
  [metrics refresh](../../lib/ProxySQL_Admin.cpp#L2970),
  [Statistics storage](../../lib/ProxySQL_Statistics.cpp#L138),
  [query-event drain](../../lib/MySQL_Logger.cpp#L2264),
  [Cluster checksums](../../lib/ProxySQL_Cluster.cpp#L1226).

## Declined to judge and verification limits

Reviewers did not treat every conceptual omission as a defect. They did not certify exhaustive
authentication cryptography, external provider implementations, database permissions, all native/libpq
edge cases, retained-pointer synchronization, performance, crash durability or deployment selection.
They did not decide future architecture/consistency contracts from current implementation.

This was source-semantic review. No runtime tests, builds or new rendering were performed by the
reviewers; the earlier rendering checks are recorded separately in
[the architecture verification record](../ai-generated/architecture/VERIFICATION.md).
