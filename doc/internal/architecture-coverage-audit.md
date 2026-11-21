# Architecture coverage audit against the documentation tree

Audited 2026-10-18 on `docs/invariants-expansion`, against source
`f8ada9117166db4b8e2f83e5ed5909b183bb8a5d` and the uncommitted refreshed architecture.

## Assessment and scope

**Yes: existing specialist documents contain important architecture that the refresh either
only names or omits.** Several gaps concern core correctness, not additional feature lists.
The present chapters substantially improve the old baseline, but diagram correctness and
broad module coverage do not establish that the important contracts of each area are covered.

The inventory before adding this report contained **149 files: 140 Markdown documents,
five text documents and four test-support shell scripts**. Three parallel read-only audits
covered security/runtime, optional services, and monitoring/statistics/operations. The
consolidating review also checked documentation navigation, release history, agent guidance,
and the refreshed collection. Important claims were traced to owning source and consumers.
This is a coverage audit with targeted source verification, not a line-by-line accuracy
certification of every specialist guide or an execution of their tests.

A topic counts as adequately represented when a reader can identify its responsibility,
important collaborators, ownership/lifetime, and consequences for implementation. Merely
naming a feature is insufficient. Specialist command catalogs, recipes and implementation
algorithms need links rather than duplication. Optional services belong under their actual
product composition; their documentation volume does not determine their architectural rank.

The earlier local-cache diagram finding is now **Important**, reflecting its effect on
ownership, accounting and cross-worker availability. See the corrected
[diagram review](architecture-diagram-review.md). The initial audit did not edit the diagrams.
The three diagram findings were subsequently corrected during PR preparation, as recorded
in that review.

## Important gaps in the core runtime and backend model

### 1. Passthrough authentication: a credential verdict cannot come from compatible reuse

The [runtime identity table](../ai-generated/architecture/RUNTIME-ARCHITECTURE.md#L212)
mentions a backend probe and verified-credential cache. It does not explain the relationship
that makes that probe valid: it must obtain a **fresh connection through ordinary pool
acquisition**, subject to capacity and creation throttling. Reusing a connection compatible
by username could accept a wrong password without authenticating it. Authentication failure
must not be treated like an ordinary retryable query failure.

The separate credential cache is process-memory state, including sensitive credential material;
its locking, TTL and invalidation are distinct from configured user tables and pooled sockets.
It is not persisted or synchronized through Cluster. These are authentication authority and
resource-lifetime boundaries, not incidental variable descriptions.

Evidence: [passthrough contract, pool interaction](passthrough_authentication.md#L212),
[cache lifecycle](passthrough_authentication.md#L317),
[probe rules](passthrough_authentication.md#L353),
[freshness rationale in Session](../../lib/MySQL_Session.cpp#L2282),
[forced-fresh acquisition](../../lib/MySQL_Session.cpp#L2643), and
[cache owner](../../lib/MySQL_Passthrough_Auth_Cache.cpp#L92).

Treatment: expand the authentication flow with the fresh-pool probe and cache authority/lifetime;
link the verified specialist sections. Its older draft/phasing labels need qualification.

### 2. TLS: transport termination is covered, trust-policy ownership is not

The [transport section](../ai-generated/architecture/RUNTIME-ARCHITECTURE.md#L116)
correctly separates frontend and backend SSL lifetimes. The
[backend configuration discussion](../ai-generated/architecture/BACKEND-MANAGEMENT.md#L541)
names SSL parameters. Missing is the trust-policy graph: who owns server/user policy, how
precedence selects it, when a connection copies it, and which traffic, monitor and cancellation
paths consume it. Encryption-only REQUIRE and CA verification are consequentially different.
Changing frontend/global TLS settings cannot be assumed to change trust on existing backend
connections.

Evidence: [PostgreSQL SSL policy and precedence](../pgsql_servers_ssl_params.md#L87),
[HGM returns policy copies](../../lib/PgSQL_HostGroups_Manager.cpp#L4504),
[per-connection native TLS context](../../lib/PgSQL_Connection.cpp#L2318),
[verification modes](../../lib/PgSQL_Connection.cpp#L2380),
[monitor consumer](../../lib/PgSQL_Monitor.cpp#L454), and
[cancellation policy snapshot](../../lib/PgSQL_Connection.cpp#L6247).

The associated [vendored OpenSSL guide](../vendored_openssl.md#L153) also describes trust-store
snapshot ownership and crypto-library composition, which the
[dependency row](../ai-generated/architecture/PROJECT-LAYOUT.md#L181) does not explain.
The [connector patch](../../deps/mariadb-client-library/x509cache.patch#L156) implements a
per-thread, reference-counted trust cache keyed by actual file contents as well as filenames;
reload failure and CRL-mutating paths have explicit isolation behavior. This belongs in a
compact security/dependency explanation with specialist links, not an exhaustive patch tutorial.

Qualification: the guide's universal executable-owned OpenSSL claim needs further verification.
The [core flags](../../common_mk/openssl_flags.mk#L1),
[GenAI build](../../plugins/genai/Makefile#L124) and
[mysqlx build](../../plugins/mysqlx/Makefile#L160) demonstrate that approach, but
[DuckDB's recipe](../../plugins/duckdb/Makefile#L229) explicitly links vendored SSL/crypto libraries.
That difference does not by itself prove duplicate runtime crypto state; do not promote the
universal claim without checking the resulting linkage.

Treatment: add a trust-policy/resource view alongside authentication and transport, with build
and backend-driver qualifications.

### 3. Tracked user variables: logical state, materialized state and interpretation context

The [frontend-continuity section](../ai-generated/architecture/RUNTIME-ARCHITECTURE.md#L406)
mentions post-backend-OK tracking. It omits the important model in the
[user-variable design](../mysql-user-variable-tracking.md#L92): separate frontend desired and
backend materialized maps, pool matching, ordered replay, and retirement on replay failure.
Surplus backend variable names require the supported cleanup path; assigning NULL does not
remove a user variable. Already-compatible state still does not require a reset.

Raw literals depend on the context in which the database accepted them. Charset/collation or
SQL-mode changes can require affinity rather than reinterpretation/replay. Hidden writes by
stored routines/triggers are explicitly outside the supported model. A generic “synchronize
settings” description does not expose those limits and could lead to cross-session leakage or
running a query with incorrectly reconstructed state.

Evidence: [pooling/replay](../mysql-user-variable-tracking.md#L92),
[unsafe operations and context](../mysql-user-variable-tracking.md#L129),
[draining existing tracked state](../mysql-user-variable-tracking.md#L156),
[map clearing](../../lib/mysql_connection.cpp#L3485),
[synchronization](../../lib/MySQL_Session.cpp#L3174), and
[post-OK commit](../../lib/MySQL_Session.cpp#L7306).

Treatment: summarize the narrow opt-in literal model and its ownership/context contract under
session virtualization; retain limits, examples and parser details in the specialist guide.

### 4. Pool measurements: logical wait episodes are not retry-attempt counts

The [backend chapter](../ai-generated/architecture/BACKEND-MANAGEMENT.md#L265) explains
waiting/scheduling, and [its statistics section](../ai-generated/architecture/BACKEND-MANAGEMENT.md#L440)
names acquisition/wait measurements. The
[generic reset discussion](../ai-generated/architecture/ADMINISTRATION-AND-STATISTICS.md#L428)
does not identify the lifetime model documented in [Stats Tables](../Stats_Tables.md#L177).

The missing relationship is between session-owned wait episodes, hostgroup-owned atomic totals,
SQL reset windows and lifetime Prometheus counters. A successful local-cache hit is an acquisition.
Repeated checkout attempts during one wait do not create multiple logical waits. The Session
owns closing/cancelling the episode; a reset advances SQL counter baselines rather than clearing
lifetime totals or zeroing the live waiter gauge. Export also changes duration units.

This matters independently of pool scheduling correctness: otherwise an implementation can
inflate waits per retry, omit local hits, leak a live waiter on teardown or break monotonic
Prometheus counters when resetting SQL statistics.

Evidence: [SQL measurement semantics](../Stats_Tables.md#L883),
[totals, baselines and episode owner](../../include/HostgroupPoolStats.h#L16),
[local/shared acquisition attribution](../../lib/MySQL_Session.cpp#L10117),
[request-end closure](../../lib/MySQL_Session.cpp#L10579),
[SQL projection/reset](../../lib/Base_HostGroups_Manager.cpp#L215), and
[lifetime export/units](../../lib/MySQL_HostGroups_Manager.cpp#L4010).
PostgreSQL has corresponding consumers in
[checkout](../../lib/PgSQL_Session.cpp#L5605),
[request end](../../lib/PgSQL_Session.cpp#L6027) and
[export](../../lib/PgSQL_HostGroups_Manager.cpp#L3588).

Treatment: add the ownership/episode model next to waiting and explain the two counter lifetimes
in the statistics chapter. This is not a request to reproduce the metric catalog.

### 5. RDS Blue/Green: migration effects have an owner and outlive writer completion

The [monitor table](../ai-generated/architecture/BACKEND-MANAGEMENT.md#L397) names the migration
state machine, and the chapter mentions read-only suppression, DNS pins and draining. The
[feature contract](../AWS_Blue_Green/RDS_BGD_Monitor.md#L243) contains a substantially more
important ownership/lifetime model:

- One worker owns migration state for one blue writer hostgroup. Configuration changes normally
  refresh it in place, with phase-dependent reconstruction or rollback/restart.
- Writer completion and reader cleanup are distinct. Reader pins/shuns can remain after the writer
  pin is removed; a generic probe failure and a topology drain have different consequences.
- Draining deletes free sockets and marks used sockets for retirement on release. It does not
  migrate live transactions or immediately cancel every owned socket.
- Cleanup is one-shot/best-effort. Restart does not recover a durable ledger of outstanding effects;
  successful completion and rollback do not have identical effects.

Someone implementing a generic “recreate monitor on configuration change” rule or clearing all
state on writer completion could discard ownership of outstanding DNS and routing effects.

Evidence: [phase contract](../AWS_Blue_Green/RDS_BGD_Monitor.md#L330),
[retirement](../AWS_Blue_Green/RDS_BGD_Monitor.md#L420),
[cleanup](../AWS_Blue_Green/RDS_BGD_Monitor.md#L462),
[refresh/restart](../AWS_Blue_Green/RDS_BGD_Monitor.md#L547),
[worker-local owner](../../lib/MySQL_Monitor.cpp#L6851),
[in-place refresh](../../lib/MySQL_Monitor.cpp#L7428),
[separate reader phase](../../lib/MySQL_Monitor.cpp#L7730), and
[cleanup/drain implementation](../../lib/MySQL_Monitor.cpp#L7849).

Treatment: one backend subsection explaining owner, phases and effect lifetime, linked to the
full contract and [simulator architecture](../AWS_Blue_Green/RDS_BGD_Simulator.md).

## Important gaps within optional product compositions

### 6. MCP is a separate execution and authentication surface

The [GenAI inventory row](../ai-generated/architecture/ARCHITECTURE-OVERVIEW.md#L356)
and [generic optional-endpoint wording](../ai-generated/architecture/ADMINISTRATION-AND-STATISTICS.md#L334)
do not explain the implemented service. Its management interface is absent from the interface
table. The missing flow is HTTP(S)/JSON-RPC dispatch, endpoint Bearer authentication, separate
config/stats/admin/query/RAG handlers, target/auth configuration snapshots, and plugin-owned
backend pools/direct MySQL or libpq execution. Endpoint credentials and database credentials
are separate. MCP query rules are not evidence that requests traverse the ordinary Session/QP
pipeline.

This is a concrete trust/execution boundary. Treating MCP as only another statistics exporter
or another core traffic listener would assign policy and connection ownership incorrectly.

Evidence: [MCP request architecture](../MCP/Architecture.md#L121),
[target/auth/rule model](../MCP/Architecture.md#L216),
[current mandatory-token contract](../MCP/VARIABLES.md#L47),
[target profiles](../MCP/VARIABLES.md#L147),
[server](../../plugins/genai/src/ProxySQL_MCP_Server.cpp#L29),
[endpoint authentication](../../plugins/genai/src/MCP_Endpoint.cpp#L67),
[direct connection creation](../../plugins/genai/src/tool_handlers/Query_Tool_Handler.cpp#L409),
[target resolution](../../plugins/genai/src/tool_handlers/Query_Tool_Handler.cpp#L535), and
[pool identity](../../plugins/genai/src/tool_handlers/Query_Tool_Handler.cpp#L744).

Treatment: an explicit optional-service section/flow with its interfaces, owners and specialist
links. Keep it subordinate to product composition, rather than equating its scope with the
entire traffic-serving runtime.

### 7. Discovery and RAG have distinct data authorities and storage flows

“Schema discovery/vector/LLM integration” in the same inventory row does not explain:

- Deterministic metadata harvesting versus external-agent semantic annotations in the catalog.
- Persistent source/document/chunk records versus FTS/vector indexes.
- Indexed retrieval versus optional refetch from authoritative backend rows.
- External ingestion tooling versus work performed by the running plugin.

The [embedded-storage diagram](../ai-generated/architecture/VISUAL-GUIDE.md#L407) does not
represent these stores. Missing authority and ingestion boundaries can lead an agent to treat an
index as the source of truth or place external orchestration inside core worker execution.

Evidence: [two-phase discovery](../Two_Phase_Discovery_Implementation.md#L51),
[RAG data model](../RAG/architecture-data-model.md#L14),
[retrieval/refetch](../RAG/architecture-runtime-retrieval.md#L39),
[current store creation](../../plugins/genai/src/AI_Features_Manager.cpp#L171),
[retrieval consumer](../../plugins/genai/src/tool_handlers/RAG_Tool_Handler.cpp#L1899),
[source-specific refetch](../../plugins/genai/src/tool_handlers/RAG_Tool_Handler.cpp#L2819), and
[external ingestion tool](../../RAG_POC/rag_ingest.cpp#L14).

Treatment: explain these flows beneath the GenAI/MCP subsystem, link the specialist designs,
and distinguish implemented behavior from their v0/v1 blueprint hardening proposals.

### 8. Plugin query hooks can enforce admission, not merely observe — corrected

The audited overview called the GenAI hooks “anomaly-observation query hooks.” The
[runtime scope note](../ai-generated/architecture/RUNTIME-ARCHITECTURE.md#L668) named the
simple-query hook without explaining its effect. The implemented synchronous hook can return
ALLOW or DENY; the core Session emits the protocol error and ends the selected request path.
This is a misleading boundary description, not just a missing feature name.

Evidence: [specialist blocking design](../ANOMALY_DETECTION/ARCHITECTURE.md#L128),
[current plugin callback](../../plugins/genai/src/plugin_hooks.cpp#L38),
[MySQL denial consumer](../../lib/MySQL_Session.cpp#L6162), and
[PostgreSQL denial consumer](../../lib/PgSQL_Session.cpp#L2396).

Treatment: describe the optional enforcement step and feature gates with its actual simple-query
scope. Do not imply binary/extended/fast-forward coverage or working vector threat matching.
The plugin's unavailable/disabled behavior also belongs with that boundary.

Resolution during PR preparation: the overview now identifies the denial capability, and the
runtime chapter explains ALLOW/DENY, Session-owned errors and unavailable/disabled behavior.

## Other consequential additions that need compact treatment and direct links

| Topic | Existing coverage and missing relationship | Specialist/source evidence |
| --- | --- | --- |
| Metric identity | The shared registry is covered, but independent MySQL/PostgreSQL owners do not imply distinct exported metrics. Family name plus label identity must distinguish protocol owners. | [Protocol labels](../PROMETHEUS_PROTOCOL_LABELS.md#L20), [registration](../../include/prometheus_helpers.h#L34), [cache metric maps](../../lib/Query_Cache.cpp#L327). |
| TLS-secret logging | Absent from logging architecture. This is a separate concurrent handshake secret sink, with runtime activation/rotation and consumers outside query-event/audit logging. Qualify native PostgreSQL coverage rather than copying “all connections.” | [Developer guide](../ssl_keylog/ssl_keylog_developer_guide.md#L32), [user guide](../ssl_keylog/ssl_keylog_user_guide.md#L181), [owner/callback](../../lib/proxysql_sslkeylog.cpp#L112), [Admin rotation](../../lib/ProxySQL_Admin.cpp#L5406). |
| Credential capabilities | Authentication mechanisms are covered, but frontend public-key verification does not necessarily supply backend credentials. MySQL `$ED$` public-key-only accounts cannot establish backend authentication or supply passthrough secrets. RSA publication also has node-local key and snapshot semantics. | [ED25519](../ed25519_authentication.md#L16), [backend refusal](../../lib/mysql_connection.cpp#L1150), [RSA lifecycle](../caching_sha2_password_rsa.md#L70), [atomic publication](../../lib/MySQL_Thread.cpp#L1712). |
| Physical frontend identity | X.509/SPIFFE is named, but certificate evidence belongs to the physical connection and is combined with account/password policy, including cold/warm passthrough paths. | [X.509 contract](../frontend_x509_authentication.md#L19), [protocol policy](../../lib/MySQL_Protocol.cpp#L121). |
| Router ownership/publication | Generic bootstrap/reconciliation wording omits the scoped ownership ledger, collision handling and main/disk/runtime publication. This is a shipped configuration-service consumer, distinct from the uninstalled discovery-controller seam. | [Router contract](../mysql-router-plugin.md#L23), [scoped ownership](../mysql-router-plugin.md#L126), [apply consumer](../../plugins/mysql_router/src/bootstrap.cpp#L682), [readiness gates](../../plugins/mysql_router/src/plugin.cpp#L121). |
| Locality-provider teardown | Selection and stale degradation are covered. The manager retains a provider lease between refreshes, so it must stop/join before registry shutdown waits for leases. | [Provider lifetime](../aws-locality-awareness.md#L94), [shutdown order](../../src/main.cpp#L2042), [registry retirement](../../lib/Aws_Locality_Manager.cpp#L420). |
| mysqlx/DuckDB boundaries | Separate/embedded execution is already identified. Add specialist navigation and concise identity, policy, pool and resource boundaries; do not duplicate protocol manuals. mysqlx does not inherit core QP/cache policy merely by being in the same process. | [mysqlx runtime](../mysqlx/ARCHITECTURE.md#L88), [identity overlay](../mysqlx/README.md#L257), [policy limits](../mysqlx/README.md#L565), [DuckDB security](../duckdb/security.md#L7), [resources](../duckdb/operations.md#L60). |

## Coverage ledger for the remaining documentation

The findings above account for partially covered security, pooling, topology and optional-service
families. This ledger records areas that do not justify claiming another missing major subsystem.
Where several files form one family, examples, API catalogs, tests and historical summaries were
considered together with its architecture document.

| Documents/family | Coverage disposition |
| --- | --- |
| `ffto_design.md` | Represented in runtime forwarding/observation and statistics. Link design details; its performance target is not a measured result. |
| `mysql-prepared-query-cache-prototype.md`, `pgsql-extended-query-cache-prototype.md` | Implemented tier-gated paths are represented, including state-sensitive keys/eligibility. “Prototype” filenames do not mean absent implementation. Preserve current native/libpq portal qualifications. |
| `query_rules_groups_documentation.md` | Capture/rewrite behavior is represented; syntax/examples belong in a direct specialist link. |
| `query_rules_regex_engines.md` | Engines and worker-local compilation are represented; add navigation to version/migration/failure semantics. No need to reproduce compatibility tables. |
| `killed_client_connections_documentation.md` | Cancellation versus final cleanup is represented. Worker-marking details need a specialist link; old `KILL QUERY` claims require source qualification. |
| `internal/ProxySQL_Authentication.md`, `internal/MySQL_Connection.md`, `internal/MySQL_Session.md` | Core login/driver/Session responsibilities are represented. Historical transition charts and explicitly unfinished diagrams are not missing product architecture. |
| `internal/MySQL_Logging_Prepared_Statements_Parameters.md` | Prepared logging/lifetime is mentioned; add specialist navigation for optional parameter capture and sensitive values. Binary-format details remain separate. |
| `internal/pgsql_advanced_query_logging_architecture.md` | Bounded buffer, drain, SQL history and periodic/explicit dumping are substantially covered. |
| `Stats_Tables.md` | Broad producer/projection/reset/history architecture is covered. The consequential pool measurement model is finding 4; the full table catalog stays separate. |
| All seven `tsdb/` documents | Sampling, registry conversion, SQLite/locking, rollup/retention, independent probes and REST-origin UI are covered. Catalogs/recipes remain specialist references; two old guides give a stale UI port. |
| `proxysql_cluster/proxysql_cluster_working.md` | Synchronization mechanism and current server representations are substantially covered. No missing peer-coordination subsystem should be inferred. |
| `AWS_Blue_Green/RDS_BGD_Simulator.md`, `Read_Only_Testing.md`, `Aurora_Automated_Testing.md` | Simulator/test architecture and setup recipes. Link from the relevant monitor feature; they do not introduce separate production modules. |
| `coredump_filters_documentation.md`, `internal/debug_filters.md` | Missing navigation for narrow diagnostic facilities. A short diagnostics map suffices; neither warrants a top-level runtime subsystem. Coredump reset wording is internally inconsistent. |
| `internal/PROXYSQLTEST.md` | Explicitly incomplete internal benchmark commands; no separate production-architecture gap. |
| `internal/Stats_API.txt`, `internal/global_variables.txt`, `internal/command_line_options.txt` | Current ownership/resultset/version/bootstrap architecture is covered. Historical proposed class/API names should not be restored. |
| `internal/query_parser.txt`, `internal/Standard_ProxySQL_Admin.txt` | Historic/superseded interface descriptions; current parser and Admin chapters cover the responsibilities. |
| `GH-Actions/README.md`, `tap_test_guide.md`, `BUILD-MACOS.md`, `RELEASE_NOTES_WORKFLOW.md` | Development/CI/platform/editorial guides. Project Layout delegates to current CI/infrastructure/conventions; detailed recipes need no product-architecture duplication. Some old commands/flag-tracking claims require qualification. |
| `ANOMALY_DETECTION/{README,ARCHITECTURE,API,TESTING}.md` | Finding 8 covers the current responsibility gap. Old direct-core integration/API paths and vector claims need current-plugin qualification. |
| `GENAI.md`, all four `LLM_Bridge/` documents | Provider internals are relevant source material; obsolete prefix/socketpair/NL2SQL entry paths are not missing current architecture. |
| All five `VECTOR_FEATURES/` documents | Storage/embedding concepts support finding 7. Setup/tests stay separate; advertised NL2SQL and vector-threat paths do not prove current consumers. |
| All twelve `RAG/` documents and four root `rag*.md` guides | Findings 6–7 cover the active architectural gap. Ingestion recipes, prompts, Doxygen inventories and historical completion summaries need no separate architecture chapter. |
| All eight `MCP/` documents | Findings 6–7 cover server/auth/target/query/discovery/retrieval and stats-tool consumer boundaries. Conceptual agents and old implementation plans need explicit status. |
| `Two_Phase_Discovery_Implementation.md`, `multi_agent_database_discovery.md` | Separate deterministic catalog harvesting from external semantic agents. Do not turn conceptual multi-agent orchestration into proxy worker architecture. |
| All ten `duckdb/` documents | Embedded engine and canonical guide link already present. Trust/resources merit a compact boundary statement; API/operator recipes remain separate. |
| All four `mysqlx/` documents | Separate runtime already acknowledged; improve navigation and the boundaries listed above. Comparisons and inventories mix implementation eras. |
| `mysql-router-plugin.md` | Concrete ownership/reconciliation/publication example needed; detailed CLI/TLS/operator procedures remain specialist. |
| `SQLite3-Server.md` | The overview already distinguishes the standalone server from Admin; Project Layout maps its source. Add the guide link, with current database-lifetime qualification. |
| `PLUGIN_API.md`, all three `plugin-chassis/` documents | Lifecycle/schema/tier/manager boundaries are substantially represented. Add direct links for ABI details and review requirements; historical phase counts are not current architecture. |
| `vector-search-test/README.md` and four shell scripts | Test-support artifacts, not an additional production subsystem. |
| Nine `release_notes/` documents | Historical changes map to covered runtime, pool, parser, monitoring, stats and watchdog areas. Release chronology is not a current architecture contract. |
| Eight `agents/` documents, `AI-DOCUMENTATION-FRAMEWORK.md` | Contracts, conventions and documentation governance are separate from descriptive architecture. Preserve their references and status; do not equate every older internal guide with verified current truth. |
| `README.md`, `architecture.md`, `ai-generated/DOCUMENTATION-INDEX.md` | Navigation/status. The unrefreshed portion of the old generated index still advertises nonexistent/historical inventories; it is not coverage evidence. |
| Refreshed architecture, its verification record and six `internal/architecture-*` notes | Audit targets/evidence, not independent specialist coverage. Old enhancement/test/release guides remain explicitly historical. |

## Existing documents that must not be imported as current design

- [GENAI](../GENAI.md#L15) and [LLM bridge](../LLM_Bridge/ARCHITECTURE.md#L3) describe removed
  frontend prefix/socketpair execution. The source explicitly records the removals in
  [MySQL Session](../../lib/MySQL_Session.cpp#L7066).
- The old [MCP architecture auth example](../MCP/Architecture.md#L418) permits empty tokens.
  The [current endpoint](../../plugins/genai/src/MCP_Endpoint.cpp#L108) refuses them; current
  [VARIABLES](../MCP/VARIABLES.md#L47) documents the fail-closed behavior.
- The AI handler's advertised conversion entry returns a
  [deprecation error](../../plugins/genai/src/AI_Tool_Handler.cpp#L201). Older tool lists do
  not establish active LLM/NL2SQL entry points.
- Vector anomaly matching is not established: the
  [detector initializes no vector database](../../plugins/genai/src/Anomaly_Detector.cpp#L83)
  and [similarity checking exits without it](../../plugins/genai/src/Anomaly_Detector.cpp#L427).
  Preserve the implemented pattern/rate blocking hook without claiming the unwired path.
- The [discovery agent design](../MCP/Database_Discovery_Agent.md#L1) explicitly calls itself
  conceptual. External-agent plans are not descriptions of in-process execution contexts.
- Old TSDB [overview](../tsdb/embedded_tsdb_overview.md#L33) and
  [endpoint guide](../tsdb/ui_endpoints.md#L7) place the UI on the legacy web port. The refreshed
  [REST-origin account](../ai-generated/architecture/ADMINISTRATION-AND-STATISTICS.md#L600)
  follows current source/regression coverage.

## Navigation and next revision priorities

The architecture collection mostly links its own chapters and production source. An explicit
link inventory of the entry point and seven refreshed references found only four non-investigation
documents under `doc/`: invariants, agent conventions, CI architecture and the DuckDB guide.
Most specialist contracts above are therefore hard to discover from the refreshed architecture.
Source citations are valuable, but do not replace links to the feature contracts that explain why
an ownership or cleanup rule exists.

Revise in this order:

1. Completed during PR preparation: correct the local/shared pool ownership diagram, statistics
   history arrow and core-listener scope. Preserve the original finding severities in the review.
2. Close the core trust, credential-probe, state-replay, measurement and migration-lifetime gaps
   above, with concise flow/ownership explanations and direct specialist references.
3. Give the optional MCP/GenAI subsystem an explicit execution/storage/trust view. Query-hook
   admission effects are now described; keep legacy and conceptual paths clearly excluded.
4. Add the smaller cross-cutting relationships and specialist navigation, including Router,
   mysqlx, crypto/secret logging and retained-provider lifetime.

The initial audit changed this report and the severity classification in the diagram review.
PR preparation subsequently corrected the three diagram findings and the query-hook description;
the remaining coverage findings stay open. No production code or new normative invariants were
changed by the audit/preparation. No builds, integration tests or benchmarks were run;
source/link checks do not establish runtime correctness.

Automated review subsequently exposed an overbroad claim that all earlier visual coverage was
retained. The visual guide now includes an explicit topic mapping: some material moved to chapters,
some detailed diagrams were not reverified, and the older legacy/Group Replication bootstrap and
Kubernetes/multi-region deployment detail remains outside the verified refresh. This adds a scope
qualification to the inventory audit above rather than certifying that every old diagram was replaced.
