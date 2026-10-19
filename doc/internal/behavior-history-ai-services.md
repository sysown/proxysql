# AI services behavior history: GenAI, MCP, discovery, RAG and anomaly detection

Research window: integrations dated 2025-10-19 through 2026-10-19, from
`70228332135431229940279e49b6db186c6e4241` to
`9516441f7bd6fdb93f255f1881db19ca9ee56778` (END). This is a source audit,
not a record of runtime tests or maintainer approval. Existing invariants I-1–I-3
remain requirements; none of the choices below permits a plugin to veto a core
LOAD, change its reply, or change Stable behavior.

The investigation follows the research skill's primary-source method. It reads
the old `lib/`/`include/` implementations as well as `plugins/genai/`, callers,
constructors, command adapters, target connections, and storage consumers.
Architecture prose and agent-authored plans provide navigation and stated intent,
not approval evidence. Source links below name immutable commits. Confidence is
**high for the stated source path**, and does not establish runtime reliability.

The first AI integration is [0524363322, #5339](https://github.com/sysown/proxysql/commit/0524363322d4ebdc2e6473d0a9059a5556cc0e73).
Its actual first parent is `27f13ca18d8aa0a6dd82a235b6ef274ea444fc00` (D0).
The MCP/GenAI/RAG/anomaly implementation files do not exist in
[D0's lib tree](https://github.com/sysown/proxysql/tree/27f13ca18d8aa0a6dd82a235b6ef274ea444fc00/lib).
Thus “no service before introduction” below means that immediately preceding
integrated state, rather than a comparison only with the twelve-month baseline.
Subsequent comparisons name their real first parents where behavior already existed.

## Activation and scope

At END these are v4.0 services in the selected `genai` plugin. Packaging the
plugin is separate from selecting it; the chassis and plugin-selection decisions
are covered by the administration audit. The service defaults are
`mcp-enabled=false`, `genai-enabled=false`, `genai-llm_enabled=false`, and
`genai-anomaly_enabled=false`. MCP configuration/statistics/backend-query services
can run with MCP enabled while AI features remain disabled. MCP defaults to TLS
on port 6071 and empty endpoint tokens; an empty token **refuses** POST requests.
RAG availability additionally depends on an initialized AI vector store, but the
separate `genai-rag_enabled` variable is currently not enforced: see C-03.
[MCP defaults](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/MCP_Thread.cpp#L48-L67),
[AI defaults](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/GenAI_Thread.cpp#L165-L209),
[AI initialization gate](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/AI_Features_Manager.cpp#L426-L455),
[listener gate](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/plugin_main.cpp#L902-L980).

## Decisions to confirm

These questions concern externally meaningful policy or compatibility. They do
not ask for approval of the ignored controls, incomplete implementations, or
data-loss paths listed separately below. Each can be answered independently.

### AI-01 — Removal of the MySQL GenAI and LLM query syntax

**Before:** Immediately before the May carve-out, at
`40ee836fc0cebdc2dfc2f71dd29922dcf5d259be`, MySQL's COM_QUERY handling intercepted
`GENAI: {…}` and `LLM: prompt` and returned model results or local errors.
Those escape hatches had been introduced in #5339. **After:**
[65c522e635, #5701](https://github.com/sysown/proxysql/commit/65c522e635606c74884828a1c28db7becfda15fa)
removes that dispatch, its session state and submission path. At END the normal
MySQL query-policy path has no replacement prefix dispatch, the plugin query hook
only allows/denies anomaly checks, and the advertised MCP `ai_nl2sql_convert`
returns a deprecation error. An application issuing `LLM: summarize …` therefore
no longer obtains an LLM response through that syntax. This is an opt-in v4.0
compatibility change; it is not an automatic rewrite of ordinary client SQL.
[Before dispatch](https://github.com/sysown/proxysql/blob/40ee836fc0cebdc2dfc2f71dd29922dcf5d259be/lib/MySQL_Session.cpp#L7318-L7340),
[END normal path](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L8515-L8523),
[END hook](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/plugin_hooks.cpp#L38-L84),
[END MCP consumer](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/AI_Tool_Handler.cpp#L201-L216).

**Question:** Should the MySQL `GENAI:` and `LLM:` syntax remain removed? **Yes / No.**

### AI-02 — Authority conveyed by a configuration endpoint token

**Before:** In #5752's actual parent,
`939962837a07f641321dd2538635e8a74735c03f`, the configuration endpoint offered MCP
variable helpers but no general `query` tool. **After:**
[9719d4ae05, #5752](https://github.com/sysown/proxysql/commit/9719d4ae0591d8de905b9456df08c3e95117d220)
adds `query`. END permits single SELECT/WITH/VALUES and INSERT/UPDATE/DELETE/REPLACE
statements against the Admin SQLite handle, without a table allowlist or per-call
database identity. DDL, transaction-control tokens, ATTACH and PRAGMA are rejected.
Consequently the configuration token authorizes reading credential-bearing tables
and editing configuration rows such as `mysql_servers`; the SQL command does not
itself install those rows into runtime. Existing getters also reveal endpoint
tokens. This is a privilege boundary beyond choosing a variable syntax, and does
not duplicate the administration audit's SET behavior questions.
[Before tools](https://github.com/sysown/proxysql/blob/939962837a07f641321dd2538635e8a74735c03f/plugins/genai/src/tool_handlers/Config_Tool_Handler.cpp#L36),
[END statement policy](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Config_Tool_Handler.cpp#L75-L111),
[END validation and executor](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Config_Tool_Handler.cpp#L207-L243),
[END Admin consumer](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Config_Tool_Handler.cpp#L464-L515).

**Question:** Should possession of the configuration endpoint token grant these
general Admin-table read and DML permissions? **Yes / No.**

### AI-03 — Bearer credentials in URL parameters

**Before:** D0 has no MCP HTTP service. #5339 introduces per-endpoint bearer
authentication and the `token` query-argument fallback. **After:** END still
accepts `?token=…` when Authorization is absent, for every registered endpoint.
An existing Authorization header takes precedence; a mismatched header does not
fall back to the URL token. Authentication is checked for each POST against the
current endpoint token; this path has no authentication cache or user/session
identity. A client can call `/mcp/query?token=…`, placing the credential in its URL.
The intervening empty-token hardening is a correction, C-01, rather than a request
to restore unauthenticated access.
[Introduced fallback](https://github.com/sysown/proxysql/blob/0524363322d4ebdc2e6473d0a9059a5556cc0e73/lib/MCP_Endpoint.cpp#L60-L74),
[END token selection and validation](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/MCP_Endpoint.cpp#L67-L140),
[END per-POST check](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/MCP_Endpoint.cpp#L421-L461).

**Question:** Should MCP continue accepting bearer credentials in URL parameters?
**Yes / No.**

### AI-04 — Stateless, POST-only MCP transport

**Before:** D0 has no MCP transport; #5339 adds it. **After:** END returns 405
for GET and DELETE, 200 for CORS OPTIONS, and handles JSON-RPC through authenticated
POST. Initialize advertises protocol `2025-06-18`; the implementation does not
issue or require an MCP session ID, retain an initialized-session state, offer SSE,
or terminate sessions. A caller can POST `tools/call` without a preceding initialize,
provided the token is valid. TLS is on by default and uses ProxySQL's certificate;
missing certificate material leaves the webserver uninitialized and start refuses
it, while the operator can explicitly choose plain HTTP. The meaningful compatibility boundary
is the supported transport/lifecycle, not a promise inferred from an MCP label.
[Initial transport](https://github.com/sysown/proxysql/blob/0524363322d4ebdc2e6473d0a9059a5556cc0e73/lib/MCP_Endpoint.cpp#L132),
[END methods](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/MCP_Endpoint.cpp#L143-L210),
[END dispatch and initialize](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/MCP_Endpoint.cpp#L319-L372),
[END TLS construction](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/ProxySQL_MCP_Server.cpp#L29-L65).

**Question:** Is this stateless POST-only lifecycle the intended supported MCP
contract? **Yes / No.**

### AI-05 — Direct backend targets and an implicit default target

**Before:** #5386's parent `28b1114cd986f15ef308bfc1b2b8fd06b325cee5` uses one
MySQL connection configuration (`mcp-mysql_hosts`, ports and credentials).
**After:** [10ff1322ba, #5386](https://github.com/sysown/proxysql/commit/10ff1322ba16401c94a819f355b4a1f35749d9d7)
introduces MySQL/PostgreSQL logical target/auth profiles. At END an active target
with a matching auth profile resolves a weighted-random ONLINE backend from its
hostgroup, and MCP's own database client connects directly to that server. It does
not send the query through the normal MySQL/PostgreSQL frontend query pipeline.
The first executable target becomes the default when `target_id` is omitted;
the installed contexts are iterated from an unordered map, so this is not a
configured stable priority. An added second target can therefore change which
database an otherwise unchanged request addresses. Explicit target selection is
already required for static discovery.
[Before pool](https://github.com/sysown/proxysql/blob/28b1114cd986f15ef308bfc1b2b8fd06b325cee5/lib/Query_Tool_Handler.cpp#L311-L386),
[END context enumeration](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/MCP_Thread.cpp#L450-L457),
[END target selection](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Query_Tool_Handler.cpp#L535-L670),
[END direct connection](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Query_Tool_Handler.cpp#L409-L497).

**Question:** With multiple executable targets, should an omitted `target_id`
**A)** select an implicit default, or **B)** return an error requiring a target?

### AI-06 — MCP SQL rules may rewrite or acknowledge without executing

**Before:** D0 has no MCP SQL execution. #5339 introduces a separate MCP query-rule
pipeline. **After:** END evaluates those operator-installed rules for
`run_sql_readonly` and `explain_sql`. `OK_msg` returns success immediately without
database execution; `error_msg` blocks; `new_query` replaces the submitted SQL,
then read-only validation runs on the replacement. Empty rules mean no rewrite.
This is an explicit MCP rule mechanism, not an LLM autonomously transforming
ordinary proxy traffic. For example, an OK rule can turn `SELECT balance …` into
a successful text acknowledgment, while a rewrite can change its selected rows.
[Initial consumer](https://github.com/sysown/proxysql/blob/0524363322d4ebdc2e6473d0a9059a5556cc0e73/lib/Query_Tool_Handler.cpp#L1733-L1778),
[END readonly consumer](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Query_Tool_Handler.cpp#L2667-L2726),
[END explain consumer](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Query_Tool_Handler.cpp#L2792-L2835).

**Question:** Should these MCP rules retain both SQL replacement and successful
acknowledgment without execution? **Yes / No.**

### AI-07 — Statistics pagination has a bounded offset as well as page size

**Before:** #5410's parent `2b710e518f3876f2c2046f26b4ec257d0bb9072b` has the
older Observe handler and no Stats handler. **After:**
[d683dd7b8b, #5410](https://github.com/sysown/proxysql/commit/d683dd7b8b4ac1fffd723d30ff811e49952909fd)
adds the current statistics tool family. END reads live processlist and digest
snapshots, defaults requested pages to 100 rows, and caps each page and the offset
at the configured cap (default 200, hard ceiling 1000). This is an effective depth
limit: `offset=5000` uses offset 200 under defaults, rather than paging to row
5000. Total matched cardinality is reported independently of the returned page;
the processlist count and data use separate snapshots, not one atomic observation.
[Old Observe source](https://github.com/sysown/proxysql/blob/2b710e518f3876f2c2046f26b4ec257d0bb9072b/lib/Observe_Tool_Handler.cpp),
[END processlist pagination](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Stats_Tool_Handler.cpp#L1447-L1515),
[END query pagination and metadata](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Stats_Tool_Handler.cpp#L1664-L1743),
[END hard caps](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Stats_Tool_Handler.cpp#L87-L102).

**Question:** Should statistics browsing **A)** remain limited to a capped offset,
or **B)** allow all offsets while keeping each returned page bounded?

### AI-08 — Historical tools read specific stores rather than merge history

**Before:** #5410's actual parent has no Stats history tools. **After:** END
`show_query_log` defaults to the in-memory MySQL events table; only `source=disk`
chooses persistent history. There is no automatic fallback or merged view when
memory contains no rows. System/cache/connection-history tools query disk history,
using raw or hourly tables according to their interval map; PostgreSQL cache and
connection-history requests are explicitly unsupported. Thus a successful empty
memory-log response says nothing about older persisted events. Logging retention
and producer policy belong to the observability audit; this question concerns
what MCP asks the consumer to select.
[Introducing integration](https://github.com/sysown/proxysql/commit/d683dd7b8b4ac1fffd723d30ff811e49952909fd),
[END event source choice](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Stats_Tool_Handler.cpp#L3603-L3662),
[END system history](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Stats_Tool_Handler.cpp#L3087-L3170),
[END protocol boundary](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Stats_Tool_Handler.cpp#L3179-L3190).

**Question:** Should MCP keep requiring an explicit disk source to retrieve
persisted query events? **Yes / No.**

### AI-09 — Failure contract for incomplete history and discovery responses

**Before:** D0 has no discovery service. #5339 introduces staged metadata harvest;
#5410 later introduces system-history tools. **After:** END MySQL metadata fetch
helpers can convert query errors into empty vectors, while the outer harvest
returns a completed run when every stage returns nonnegative counts. The MCP
adapter also falls back to success containing only run/target/protocol if harvest
statistics cannot be parsed. Separately, system-history CPU/memory SQL errors
yield empty component arrays within a successful response. An agent can mistake
missing metadata for an empty schema or unavailable CPU samples for no activity.
The silent-success cases need correction regardless of the answer; the unresolved
policy is whether useful partial results should remain available with explicit
failure metadata.
[Initial harvest orchestration](https://github.com/sysown/proxysql/blob/0524363322d4ebdc2e6473d0a9059a5556cc0e73/lib/Static_Harvester.cpp#L1281-L1329),
[END metadata fetch](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/Static_Harvester.cpp#L450-L483),
[END completion](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/Static_Harvester.cpp#L1281-L1328),
[END MCP fallback](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Query_Tool_Handler.cpp#L1918-L1971),
[END history error handling](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Stats_Tool_Handler.cpp#L3108-L3166).

**Question:** On incomplete source data should these tools **A)** fail the whole
request, or **B)** return the available data with explicit per-component errors
and an incomplete marker?

### AI-10 — RAG token authority includes refetching complete source rows

**Before:** In #5752's parent the `rag.fetch_from_source` branch returns
success-shaped mock rows assembled from the stored primary key and requested
column names, without connecting to the source. **After:** #5752 implements live
MySQL/PostgreSQL refetch. END looks up an enabled source and nondeleted document
in the local RAG database, uses stored source credentials to dial the backend
directly, and queries the stored primary key plus the source's `where_sql`.
Absent a caller column list it selects `*`, including columns that were never
included in the indexed document. The endpoint token is the authorization boundary;
there is no mapping of token holders to individual source/document permissions.
Results are current source rows rather than the indexed snapshot, with defaults
of 10 documents/200000 output bytes and hard upper limits of 100/1000000. This can
expose additional live fields to a consumer originally given access to excerpts.
[Before placeholder](https://github.com/sysown/proxysql/blob/939962837a07f641321dd2538635e8a74735c03f/plugins/genai/src/tool_handlers/RAG_Tool_Handler.cpp#L2370-L2433),
[END source lookup](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/RAG_Tool_Handler.cpp#L1008-L1078),
[END direct SELECT](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/RAG_Tool_Handler.cpp#L1081-L1146),
[END batching and bounds](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/RAG_Tool_Handler.cpp#L2819-L2917).

**Question:** Should a RAG endpoint token authorize live refetch of every column
from every enabled source? **Yes / No.**

### AI-11 — RAG source deletion removes search entries but retains document text

**Before:** In #5746's parent `15c67a9e9152c2d5257aec7d98780f74e6697f71`, the
standalone ingester skips existing document IDs and does not reconcile removed
source rows. **After:** [d16e32c5e1, #5746](https://github.com/sysown/proxysql/commit/d16e32c5e12d6a5d14ef35462c0353331062b547)
adds change detection and missing-document reconciliation. At END the removal
path sets `rag_documents.deleted=1` and physically removes chunks, FTS and vector
rows, but leaves the document's title/body/metadata/primary key in its persistent
row. A source deletion therefore does not erase the stored document content.
This is an explicitly run standalone `RAG_POC` ingestion utility, not a background
daemon task. Its incremental reconciliation and changed-document implementation
have separate correctness defects, C-06; those are not choices to retain.
[Before skip behavior](https://github.com/sysown/proxysql/blob/15c67a9e9152c2d5257aec7d98780f74e6697f71/RAG_POC/rag_ingest.cpp#L1668-L1682),
[END tombstones and index deletion](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/RAG_POC/rag_ingest.cpp#L1781-L1807),
[END retained document fields](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/RAG_POC/rag_ingest.cpp#L1920-L1937).

**Question:** For a confirmed deleted source row, should ingestion **A)** retain
the document text in a tombstone, or **B)** erase its stored text and metadata?

### AI-12 — Enabling anomaly detection also enables blocking by default

**Before:** D0 has no AI anomaly interception. #5339 adds MySQL analysis; immediately
before #5701 the detector is owned by the in-core AI manager and only the MySQL
session invokes it. **After:** #5701 registers one plugin detector for both MySQL
and PostgreSQL query hooks. END requires the plugin to be started plus
`genai-enabled=true` and `genai-anomaly_enabled=true`; the detector then defaults
to `auto_block=true`, `log_only=false`, risk threshold 70 and rate limit 100.
Three regex/keyword matches produce risk 0.9 and can reject ordinary quoted/commented
SQL. Rate-limit detection also sets should_block independently of the risk threshold.
The hooks return a MySQL 1313/HY000 or PostgreSQL insufficient-privilege error when
denying a selected simple query; they do not provide blanket prepared/extended-query
coverage. No detector/not-started/disabled allows traffic. Detected stage failures
can also contribute no anomaly rather than a denial. Exposed tuning, log-only and
embedding controls do not currently all reach that detector (C-05), so the observed
defaults must not be described as effective operator-adjustable policy.
[Initial detector defaults and scoring](https://github.com/sysown/proxysql/blob/0524363322d4ebdc2e6473d0a9059a5556cc0e73/lib/Anomaly_Detector.cpp#L76-L85),
[Before owner](https://github.com/sysown/proxysql/blob/40ee836fc0cebdc2dfc2f71dd29922dcf5d259be/lib/AI_Features_Manager.cpp#L406-L425),
[END protocol registration](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/plugin_main.cpp#L292-L308),
[END activation and denial](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/plugin_hooks.cpp#L38-L84),
[END risk scoring](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/Anomaly_Detector.cpp#L205-L249),
[END MySQL hook consumer](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/MySQL_Session.cpp#L6211-L6249),
[END PostgreSQL hook consumer](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/PgSQL_Session.cpp#L2390-L2433),
[END block combination](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/Anomaly_Detector.cpp#L730-L754).

**Question:** Once anomaly detection is enabled, should its default be **A)**
blocking matching queries, or **B)** observation only until blocking is separately enabled?

## Corrections, limitations and superseded mechanisms

These are source findings and follow-up work, not additional approval requests.

**C-01 — Empty MCP tokens no longer permit anonymous POST.** #5339 originally
allowed an empty configured token. [08cc2dbaa5](https://github.com/sysown/proxysql/commit/08cc2dbaa51a4c457ed7df419ec381f4b1d45f0d)
changes this to refusal on every endpoint and removes MySQL multi-statement
capability from backend connections. It adds single-statement/read-only checks
to query and explain paths. The old permissive behavior is superseded. The
validator remains a broad substring blacklist: `SELECT 'updated'` is rejected
because it contains UPDATE. Nor is it proof that every permitted SELECT has no
side effects (for example database functions). This requires precise supported-SQL
documentation and correctness/security review, not a vote to allow writes through
a tool expressly called readonly.
[END authentication](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/MCP_Endpoint.cpp#L94-L113),
[END validator](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Query_Tool_Handler.cpp#L1218-L1336).

**C-02 — Advertised MCP SQL budgets and profile permissions are not enforced.**
`run_sql_readonly` parses then discards `max_rows` and `timeout_sec`; a query-rule
timeout merely changes the unused local. The target/auth join retains profile
row/time limits and explain/discovery flags, but `refresh_target_registry` drops
them when constructing QueryTarget and execution never checks those flags.
Likewise auth-profile `use_ssl`/`ssl_mode` are stored/projected but not propagated
through this join/dial path. This does not prove a particular negotiated TLS mode;
it proves those configured controls are not applied there. MySQL uses fixed
five-second connect/read/write socket timeouts and `mysql_store_result`, and
PostgreSQL uses a fixed connection timeout plus synchronous PQexec with no target
statement deadline; both serialize full results. Correctness follow-up: honor
the promised controls or remove the claims. No approval option legitimizes silently
ignoring them.
[Profile join](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/MCP_Thread.cpp#L536-L552),
[Target construction](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Query_Tool_Handler.cpp#L613-L629),
[discarded arguments](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Query_Tool_Handler.cpp#L2642-L2649),
[unused rule timeout](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Query_Tool_Handler.cpp#L2704-L2726),
[full backend execution](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Query_Tool_Handler.cpp#L884-L1020).

**C-03 — RAG's off switch and advertised aggregate limits are incomplete.**
`genai_rag_enabled` appears only in the variable field, defaults/getter/setter;
neither handler construction nor execute_tool consults it. With MCP+GenAI enabled,
a vector store and a valid RAG token, `rag-enabled=false` does not independently
disable RAG. The handler reads response_max_bytes and timeout_ms but does not use
them to bound general retrieval execution/output. It does enforce query byte
length and k/candidate clamps, and live refetch has its own output checks. Do not
equate a variable's existence with an effective control.
[RAG variables](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/GenAI_Thread.cpp#L493-L520),
[handler creation](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/ProxySQL_MCP_Server.cpp#L181-L207),
[dependency refresh](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/RAG_Tool_Handler.cpp#L413-L424),
[execute gate](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/RAG_Tool_Handler.cpp#L1645-L1652).

**C-04 — The LLM bridge is not a surviving automatic SQL transformation service.**
The initial `LLM:` handler sends a generic prompt and returns text; it does not
execute generated SQL as ordinary client traffic. After the carve-out, END's
`process_json_query` can still call LLM_Bridge from its worker loop, but all
production submission/registration of that former session transport is gone.
`ai_nl2sql_convert` is an error stub with a stale suggestion to use `LLM:`.
Cache and provider machinery must therefore be described as implemented internal
code without a verified surviving public LLM invocation path. `select_model` picks
the configured openai/anthropic provider, not a local/cloud budget router; exposed
local preference/budget/hourly-limit variables do not make that routing happen.
The internal semantic cache keys lookup by prompt embedding alone, with threshold
85, no user/schema/provider/model namespace and no automatic eviction found; this
is a latent design concern if a public caller is restored, rather than a current
client-facing cache guarantee. sqlite-rembed removal #5616 changes supporting
extension availability, not the plugin's actual HTTP embedding consumer.
[Old LLM result path](https://github.com/sysown/proxysql/blob/40ee836fc0cebdc2dfc2f71dd29922dcf5d259be/lib/MySQL_Session.cpp#L3993-L4075),
[END worker consumer](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/GenAI_Thread.cpp#L1497-L1511),
[END cache lookup](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/LLM_Bridge.cpp#L171-L221),
[END provider choice](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/LLM_Bridge.cpp#L317-L331).

**C-05 — Anomaly settings and rate accounting need correction.** The plugin
constructs a separate detector and never copies the GenAI threshold/rate/auto-block/
log-only settings into its internal config. No production assignment attaches its
vector_db, so embedding-pattern analysis returns no anomaly even though the
embedding function pointer is installed. `log_only` inside analyze changes only
the log branch; it does not clear should_block. Rate accounting increments once
in check_rate_limiting and again in update_user_statistics, uses a 3600-second
inactivity reset (not the commented per-minute window), and keys by user@IP
without schema or protocol. This can reject sustained normal traffic much sooner
than a “100 queries per minute” claim suggests. These deficiencies already existed
in part before extraction; the carve-out does not ratify them.
[detector creation](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/plugin_main.cpp#L302-L319),
[vector gate](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/Anomaly_Detector.cpp#L417-L433),
[first rate increment](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/Anomaly_Detector.cpp#L278-L314),
[second increment](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/Anomaly_Detector.cpp#L603-L619),
[log-only handling](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/Anomaly_Detector.cpp#L730-L755).

**C-06 — RAG ingestion reconciliation can delete unchanged documents; updates
do not implement a real upsert.** #5746 adds seen_doc_ids for the rows returned by
the watermark-filtered source SELECT, then compares that set against every active
document for the source. An incremental pass returning only row B therefore marks
previously indexed, unchanged row A deleted and removes A's chunks/FTS/vectors.
For a changed existing document, the code leaves its primary-key row in place,
marks it deleted, and calls plain INSERT into the same primary key, rather than
UPDATE/UPSERT. The source transaction wrapper catches exceptions and attempts
rollback, but the MySQLDB execution helper exits via fatal on query failure, so
the catch path is not universal failure recovery. These are source-traced defects,
not verified runtime outcomes. Actual deletion reconciliation must distinguish a
complete source enumeration from an incremental change page.
[incremental filter](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/RAG_POC/rag_ingest.cpp#L1607-L1613),
[changed-document path](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/RAG_POC/rag_ingest.cpp#L1691-L1731),
[plain INSERT](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/RAG_POC/rag_ingest.cpp#L1031-L1054),
[missing-document comparison](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/RAG_POC/rag_ingest.cpp#L1781-L1803),
[transaction wrapper](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/RAG_POC/rag_ingest.cpp#L2280-L2316),
[query failure helper](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/RAG_POC/rag_ingest.cpp#L390-L402).

**C-07 — RAG embedding/index claims need narrower wording.** The standalone
ingester defaults embeddings off, but enabling them without provider selection
uses deterministic hash-based stub vectors; any provider string other than
`openai` also falls back to stub. Runtime RAG search uses the configured HTTP
embedding service, not that stub, and a vector-search embedding error returns an
error rather than automatically falling back to FTS. AI initialization logs failed
FTS/vec table creation and continues, so successful module start does not establish
those retrieval capabilities. The `rag.search_vector` schema advertises precomputed
query embeddings, but the execution path always generates one from query text.
These are implementation/validation gaps. No automatic cache eviction, document
TTL or ingestion scheduler was found on the live RAG paths.
[ingester defaults](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/RAG_POC/rag_ingest.cpp#L530-L541),
[provider fallback](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/RAG_POC/rag_ingest.cpp#L1319-L1328),
[runtime embedding and error](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/RAG_Tool_Handler.cpp#L1896-L1908),
[nonfatal index creation](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/AI_Features_Manager.cpp#L296-L333),
[persistent store](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/AI_Features_Manager.cpp#L42-L74),
[catalog path](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/ProxySQL_MCP_Server.cpp#L83-L91).

**C-08 — MCP persistence/restart and ownership fixes supersede intermediate
extraction behavior.** #6107 seeds missing variable rows from real constructors
without overwriting configured values and rebuilds/rebinds runtime dependencies.
#6170 restores saved profiles/rules before listener exposure; failure to load
query rules prevents exposing that MCP listener, while profile installation
remains best effort. Disk-to-memory LOAD no longer applies runtime state or reopens
the listener. Inactive/unresolved target profiles remain visible with skip reasons
instead of disappearing silently. Empty query-rule snapshots clear installed
rules rather than retaining old policy. Later #6048/#6440/#6470 fix drain order,
resource ownership and Admin lock bookkeeping. These are plugin-owned operations;
they do not reopen I-1–I-3 or grant a veto over core SERVERS LOAD.
[default seeding](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/plugin_main.cpp#L141-L229),
[staging-only LOAD](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/plugin_commands.cpp#L269-L305),
[listener rule gate](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/plugin_main.cpp#L959-L980),
[profile diagnostics](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/MCP_Thread.cpp#L494-L567).

**C-09 — Tool discovery is not proof of implemented side effects.** END
admin_kill_query/admin_flush_cache/admin_reload and cache mutation tools include
success-shaped not-implemented responses. Config reload is also a success-shaped
stub. They must not be presented as implemented query cancellation/cache flush/
reload behavior. The obsolete Observe/MySQL handler files remain in the plugin
tree, but the server registers the dedicated Config/Stats/Query/Admin/Cache/AI/RAG
handlers, not every class present on disk.
[Admin stubs](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Admin_Tool_Handler.cpp#L135-L152),
[config reload stub](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/tool_handlers/Config_Tool_Handler.cpp#L451-L461),
[registered endpoints](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/plugins/genai/src/ProxySQL_MCP_Server.cpp#L148-L207).

## Integration coverage

The following ledger covers every entry in the supplied 47-integration extensions
queue. “Source” means the AI-specific changed source was inspected and followed
where relevant; “screened” means a bounded change or nonruntime artifact was read;
“handoff” means this report does not claim the other owner's behavioral review.
The machine-readable ledger is
`/private/tmp/proxysql-behavior-review-2026-10/ai-services-coverage.json`.

| Integration | Disposition / depth | AI scope or handoff |
| --- | --- | --- |
| [0524363322](https://github.com/sysown/proxysql/commit/0524363322d4ebdc2e6473d0a9059a5556cc0e73) | reviewed / source-and-consumers | Introduces core GenAI/MCP/RAG/LLM/anomaly services; traced old session dispatch, HTTP handlers, SQL tools, harvesters, vector storage and standalone ingestion. AI-01, AI-03, AI-04, AI-06, AI-09, AI-12, C-04, C-05, C-07, C-09. |
| [8e58ce592f](https://github.com/sysown/proxysql/commit/8e58ce592fa54a7368df29aac9c8b399123b5c33) | screened / artifact-diff | RAG system-prompt prose only; instructions are agent guidance, not an implemented runtime policy or maintainer ratification. |
| [3b578db4bf](https://github.com/sysown/proxysql/commit/3b578db4bf767b29ad25b71c500eeaff200749cd) | reviewed / changed-source | Discovery statement ownership migrates to prepare_v2 RAII; no independent policy choice. C-08. |
| [10ff1322ba](https://github.com/sysown/proxysql/commit/10ff1322ba16401c94a819f355b4a1f35749d9d7) | reviewed / source-and-consumers | Multi-protocol target/auth profiles, direct backend routing, default target and PostgreSQL harvest consumers. AI-05, C-02. |
| [63e46acfa7](https://github.com/sysown/proxysql/commit/63e46acfa7a20eff99a58281608d014745a200f2) | reviewed / changed-source | LLM HTTP error status conversion and dead discovery/harvest statements; no surviving public LLM caller at END. C-04. |
| [d683dd7b8b](https://github.com/sysown/proxysql/commit/d683dd7b8b4ac1fffd723d30ff811e49952909fd) | reviewed / source-and-consumers | Observe replaced by Stats handlers; live Top-K/processlist pages, history stores, error and capability boundaries. AI-07, AI-08, AI-09. |
| [d0625dc243](https://github.com/sysown/proxysql/commit/d0625dc243296b99c199203982aa508078580447) | reviewed / changed-source | Test seams expose parsers/token helper and correct bearer scheme case handling; no new service contract. AI-03. |
| [f713d78e41](https://github.com/sysown/proxysql/commit/f713d78e4136fd36cc85d24ccd1e1c7f1ceb75e9) | handoff / inventory-screen | Address-family socket selection belongs to protocol/network and administration owners; no GenAI implementation file changed. |
| [669ab91494](https://github.com/sysown/proxysql/commit/669ab914948f03b10c1ded21a4361d283cd9652d) | screened / changed-source | Header punctuation/comment/lint adjustments; no executable AI behavior changed. |
| [c678ae40d7](https://github.com/sysown/proxysql/commit/c678ae40d7ddc0a8ecd08f72a7fea18d572a7bfb) | reviewed / changed-source | Removal of sqlite-rembed support; actual surviving RAG embedding consumer is HTTP. C-04, C-07. |
| [824588d198](https://github.com/sysown/proxysql/commit/824588d1983f850a941496683d82838b216d5c4c) | reviewed / changed-source | Unused helpers, logging format, member initialization order; no new policy. C-04. |
| [8c9ed94b53](https://github.com/sysown/proxysql/commit/8c9ed94b5316cdcd6b245983687922c5162711ad) | screened / artifact-diff | Deprecated FastAPI proof-of-concept python-dotenv dependency update; no daemon behavior. |
| [9727871a16](https://github.com/sysown/proxysql/commit/9727871a16875f57319b1b782a5054171bafdada) | screened / artifact-diff | Rich discovery CLI python-dotenv dependency update; no daemon behavior. |
| [849fad9440](https://github.com/sysown/proxysql/commit/849fad94401588623cc58e9e1ca560a7bfdce2fc) | handoff / inventory-screen | Core plugin chassis ABI/lifecycle owned by administration audit; AI service policy examined at carve-out integration. |
| [40ee836fc0](https://github.com/sysown/proxysql/commit/40ee836fc0cebdc2dfc2f71dd29922dcf5d259be) | handoff / inventory-screen | mysqlx stack consolidation belongs to protocol-plugin owner; used as actual pre-carve-out source parent. |
| [65c522e635](https://github.com/sysown/proxysql/commit/65c522e635606c74884828a1c28db7becfda15fa) | reviewed / source-and-consumers | GenAI carve-out removes MySQL prefixes/submission path, moves services and query hook, adds staged plugin state. AI-01, AI-12, C-02, C-04, C-05, C-08. |
| [621ddb786e](https://github.com/sysown/proxysql/commit/621ddb786e66bbe6ae1e278a20eef2189d2cba9a) | handoff / inventory-screen | Core authentication lock-order fix owned by authentication/core administration; no AI implementation delta. |
| [05d0268f78](https://github.com/sysown/proxysql/commit/05d0268f78d76be64e429f8d363c5ce3d999e067) | reviewed / source-and-consumers | Plugin-owned statistics projections and in-memory consumers; feature macro normalization and anomaly teardown ownership. AI-07, C-08. |
| [d16e32c5e1](https://github.com/sysown/proxysql/commit/d16e32c5e12d6a5d14ef35462c0353331062b547) | reviewed / source-and-consumers | Standalone RAG change/deletion reconciliation, vector dimension config, latent LLM cache and provider paths. AI-11, C-04, C-06, C-07. |
| [9719d4ae05](https://github.com/sysown/proxysql/commit/9719d4ae0591d8de905b9456df08c3e95117d220) | reviewed / source-and-consumers | Adds broad Admin SQL tool and real direct RAG source refetch replacing mock rows. AI-02, AI-10. |
| [08cc2dbaa5](https://github.com/sysown/proxysql/commit/08cc2dbaa51a4c457ed7df419ec381f4b1d45f0d) | reviewed / source-and-consumers | Empty-token refusal; single-statement/read-only hardening and backend multi-statement removal. AI-03, C-01. |
| [74a33cac69](https://github.com/sysown/proxysql/commit/74a33cac696a15940c1e73308a6981396610581b) | handoff / inventory-screen | mysqlx fetch-depth CI support belongs to protocol-plugin/delivery owner; no AI runtime change. |
| [e069bfc1ec](https://github.com/sysown/proxysql/commit/e069bfc1ec92a3c60a2f2f44289b05ddb71ae64b) | handoff / inventory-screen | mysqlx cache/soak CI support belongs to protocol-plugin/delivery owner. |
| [693013468a](https://github.com/sysown/proxysql/commit/693013468a2f9c0076e198aeb986e8a2068c7ea5) | handoff / inventory-screen | Generic tarball composition/install policy belongs to delivery and administration owners. |
| [71df1e0e85](https://github.com/sysown/proxysql/commit/71df1e0e853d1d96bed23b78413da97576ce5df5) | handoff / inventory-screen | mysqlx shutdown/soak behavior belongs to protocol-plugin owner. |
| [16b361e46f](https://github.com/sysown/proxysql/commit/16b361e46fa17384b714a17a6b8653f5952dbb08) | reviewed / changed-source | Bounds MCP variable copies, preserves long vector-db paths, tightens catalog/FTS string handling; correctness changes, no new approval choice. C-08. |
| [df292eacc8](https://github.com/sysown/proxysql/commit/df292eacc821d56bbed92fcdb68dc98b852e103b) | reviewed / changed-source | MCP owning handler teardown nulls borrowed ownership fields; no policy change. C-08. |
| [99c37c7c1b](https://github.com/sysown/proxysql/commit/99c37c7c1b668c46364ecb767ad085838a3cbfef) | reviewed / changed-source | LLM request correlation IDs switch from rand to rand_fast; not authentication/session identity. C-04. |
| [749c4710c7](https://github.com/sysown/proxysql/commit/749c4710c7dbd84140166c1a22c925588286c896) | reviewed / source-and-consumers | Seeds real defaults, reloads/rebinds AI/RAG dependencies, serializes lifetime, changes plugin variable adapters. C-03, C-08. |
| [e4b5a76574](https://github.com/sysown/proxysql/commit/e4b5a765740eb1cdcaeb4e8724d96e2c8f539298) | screened / build-diff | GenAI Makefile adds vendored OpenSSL linkage; delivery/auth owners cover dependency rollout; no tool semantics. |
| [e7f1ab368b](https://github.com/sysown/proxysql/commit/e7f1ab368be3fef61f1ab6fe61a2bb20b0eec5ba) | screened / build-diff | GenAI link adds PCRE2 dependency; core regex default behavior owned by traffic/administration; no MCP validator replacement. |
| [80941ae5e2](https://github.com/sysown/proxysql/commit/80941ae5e2cb29963c8bb14c46a7a441ae4f08d2) | handoff / inventory-screen | DuckDB server plugin belongs to protocol-plugin owner; GenAI-named CI package files are delivery changes. |
| [3836762330](https://github.com/sysown/proxysql/commit/383676233067cf96962bd6d659223f3a93a13ae0) | reviewed / source-and-consumers | Restores saved MCP profiles/rules on startup, exposes skip diagnostics, stages disk LOAD without runtime apply, clears empty rules, gates listener on rule load. AI-05, C-08. |
| [1155452da5](https://github.com/sysown/proxysql/commit/1155452da51eadaf5320ee42d9ec0a1c476a6746) | handoff / inventory-screen | DuckDB variable defaults/lifecycle belong to protocol-plugin owner. |
| [f80019ca54](https://github.com/sysown/proxysql/commit/f80019ca54325e7fc02181523caf5f6644d3c271) | handoff / inventory-screen | mysqlx variable-table removal belongs to protocol-plugin owner. |
| [563e47f1a8](https://github.com/sysown/proxysql/commit/563e47f1a819c21e1700136c72b3025ae570ddd0) | handoff / inventory-screen | MySQL Router plugin behavior belongs to protocol-plugin owner; chassis/managed runtime belongs to administration. |
| [9ed59e93bd](https://github.com/sysown/proxysql/commit/9ed59e93bd01e8c10eeb81495a86b9e9fc85c42f) | screened / inventory-screen | Vendor archives/CI delivery update; no AI service implementation delta. |
| [2775bb222e](https://github.com/sysown/proxysql/commit/2775bb222ed67e613332fa8bfdff526ae56baa49) | handoff / inventory-screen | PostgreSQL native backend implementation owned by traffic/backends; no AI implementation file changed. |
| [2e19e2d868](https://github.com/sysown/proxysql/commit/2e19e2d868c5d2c756445bba3b40cef3ee6eb6d2) | handoff / inventory-screen | Core plugin listener restart requirements owned by administration; no GenAI-specific listener delta. |
| [37d627b974](https://github.com/sysown/proxysql/commit/37d627b9743f7d51d6b783b039f994e0b18474f0) | reviewed / changed-source | AI listener drain lock order, destructor ownership and runtime-view lifetime corrections embedded in broad IAM integration. C-08. |
| [6f438aa1f0](https://github.com/sysown/proxysql/commit/6f438aa1f0e9ed38ecdb107d0bc829d27f9a8408) | handoff / inventory-screen | Core low-risk security/resultset changes belong to core protocol, administration and observability owners. |
| [58c0e289d7](https://github.com/sysown/proxysql/commit/58c0e289d7ec0ad22f3092929579a055d1799d26) | reviewed / changed-source | Removes invalid manual free of RAII-owned RAG embedding buffers; deprecated POC script change is not daemon behavior. C-07, C-08. |
| [e100071e2b](https://github.com/sysown/proxysql/commit/e100071e2b660c51743d9b52fcd0e7bb515632a0) | reviewed / changed-source | Server-owned HTTP resource lifetime/handler cleanup and shared runtime lock on MCP rule statistics; no new policy. C-08. |
| [c528870031](https://github.com/sysown/proxysql/commit/c5288700311d324df38b8095953d379861bcf81d) | handoff / inventory-screen | Core parsing/routing/plugin-server cleanup owned by traffic/backends/administration; no AI implementation delta. |
| [4d7dea573f](https://github.com/sysown/proxysql/commit/4d7dea573f7868d46ec5adf00e0bf93dbe34bab2) | reviewed / changed-source | MCP Config/Stats use core reentrant Admin SQL guard; preserves refresh/lock bookkeeping and replies. C-08. |
| [f8ada91171](https://github.com/sysown/proxysql/commit/f8ada9117166db4b8e2f83e5ed5909b183bb8a5d) | handoff / inventory-screen | Router readiness state fix belongs to protocol-plugin owner. |
| [d7ce280a3b](https://github.com/sysown/proxysql/commit/d7ce280a3bea04f495d608bbfc8e6f98ce29aaa5) | screened / build-diff | GenAI dynamic-library platform flags only; ClickHouse/macOS and DuckDB archive policies belong to protocol-plugin/delivery owner. |

## Verification record and limits

Only read-only Git history/source commands and documentation writes were used.
END sources were obtained with `git show END:path`; no checkout was advanced.
No build, installation, test execution, production edit, commit, push or GitHub
message was performed. The source scan includes both protocol sessions, query
processing/prefix references and plugin query hooks; the remaining LLM worker-loop
reference was traced back to the removed submission transport. Static reasoning
about an ignored control or destructive branch is not a claim of a reproduced
runtime failure. mysqlx/mysql_router/DuckDB/ClickHouse behavior is owned by the
protocol-plugin audit; core chassis/Cluster lifecycle by administration, and
statistics producers/retention by observability.
