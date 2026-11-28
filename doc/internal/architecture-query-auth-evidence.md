# Query processing and authentication: architecture evidence

Investigation date: 2026-10-18. This is an implementation inventory, not a ratified
architecture contract. References identify both policy producers and consumers.
Build-tier and protocol differences must survive any architectural summary.

## Query processing is a major traffic subsystem

The Query Processor is the policy evaluation and query-analysis subsystem. Routing
is only one of its outputs. Its responsibilities include query characterization,
programmable rule evaluation, rewriting, admission decisions, execution policy,
and query statistics. It does not itself execute the selected database operation.

The shared implementation is the templated
[Query_Processor](../../lib/Query_Processor.cpp), specialized by
[MySQL_Query_Processor](../../lib/MySQL_Query_Processor.cpp) and
[PgSQL_Query_Processor](../../lib/PgSQL_Query_Processor.cpp).
The protocol Session is the execution coordinator and consumes the resulting
policy object. The database protocol, session state, transaction affinity,
connection pool, cache, and logger impose further conditions on those outputs.

### Query analysis and accounting

- Produce normalized digest text and digest identities, extract the first query
  comment, and classify SQL command types. This is query characterization, not
  a complete SQL semantic analyzer or database execution engine.
- Maintain per-command counts and timing distributions and per-digest statistics,
  including dimensions derived from the session and selected hostgroup.
- Own digest aggregation, retrieval/reset, purge, memory accounting, and top-K
  retrieval mechanisms. These feed the administrative statistics surfaces.
- Session `Query_Info` / `PgSQL_Query_Info` invokes classification and completion
  accounting; the Query Processor is not an independent request-processing loop.

Evidence: `query_parser_init()`, `query_parser_update_counters()`,
`update_query_digest()`, `get_query_digests*()`, `purge_query_digests*()` in
[shared implementation](../../lib/Query_Processor.cpp);
`query_parser_command_type()` and `get_stats_commands_counters()` in the protocol
specializations; `Query_Info` and `PgSQL_Query_Info` in
[MySQL Session](../../lib/MySQL_Session.cpp) and
[PostgreSQL Session](../../lib/PgSQL_Session.cpp).

### Programmable policy evaluation

- Match user, schema, frontend/listener address and port, digest, normalized query
  pattern, and raw or previously rewritten query pattern.
- Execute ordered rules with input/output flags, bounded reiteration, terminating
  `apply`, next-query flags, and weighted flag selection from rule attributes.
- Rewrite query text, with supported regular-expression engines and modifiers.
- Support fast routing indexed by user, schema, and flag, alongside general rules.
- Interpret supported first-comment annotations, with configuration controlling
  whether annotation processing precedes or follows normal rule evaluation.
- Publish rule versions and refresh worker-local rule representations; gather
  rule-hit statistics. The policy configuration and worker execution copies are
  distinct representations.

Evidence: `rule_matches_query()`, `process_query()`, `commit()`,
`search_rules_fast_routing_dest_hg()`, and `query_parser_first_comment()` in
[shared implementation](../../lib/Query_Processor.cpp).

### Outputs and execution consumers

| Policy capability | Responsibility after rule evaluation |
| --- | --- |
| Destination hostgroup | Session applies routing alongside transaction persistence and session affinity; pool selects an eligible backend. |
| Rewrite | Session rebuilds the protocol request; prepared/extended operations have their own paths. |
| Local error or OK response | Session emits the protocol response without executing the query against a backend. |
| Cache lifetime and empty-result policy | Session performs cache lookup/insertion subject to operation and session eligibility; Query Cache owns stored results. |
| Delay, timeout, retry budget | Session schedules/delimits execution and checks retry eligibility. A rule does not override transaction/progress safety checks merely by providing a number. |
| Multiplex and connection policy | Session and pool apply connection eligibility, pinning, and synchronization rules. Output fields alone do not prove every protocol implements every option. |
| Mirror hostgroup/flags | MySQL Session creates mirror work. PostgreSQL currently warns and ignores mirror outputs. |
| Logging | Session request completion selects event logging, with rule output qualifying default logging policy. |
| Maximum lag / freshness annotations | Session passes constraints into backend selection; pool/monitor-derived state determines eligibility. |
| MySQL GTID consistency | MySQL specialization supplies `min_gtid` / `gtid_from_hostgroup`; Session and pool enforce the resulting selection/fallback behavior. |
| Fast-forward transition | MySQL specialization can request a supported switch to fast-forward; Session handles the transition. |

Evidence: `Query_Processor_Output` in
[query_processor.h](../../include/query_processor.h), actual `qpo` consumers in
[MySQL Session](../../lib/MySQL_Session.cpp) and
[PostgreSQL Session](../../lib/PgSQL_Session.cpp), and MySQL extensions in
[MySQL_Query_Processor.h](../../include/MySQL_Query_Processor.h).
In particular, PostgreSQL's simple-query consumer explicitly reports mirroring
as unsupported. Shared output structures are not evidence of protocol parity.

### Query admission and firewall

The Query Processor owns configured whitelist users, allowed query digests, and
SQL-injection fingerprint exemptions. It evaluates digest admission in detecting
or protecting modes and can produce an error policy. Session integrates automatic
SQL-injection detection using libinjection and consults the fingerprint whitelist.
This spans policy evaluation and protocol execution; it is not merely routing.

Evidence: `load_firewall()`, `find_firewall_whitelist_user()`,
`find_firewall_whitelist_rule()`, and the end of `process_query()` in the shared
processor; `libinjection_is_sqli()` consumers in both Session implementations.

## Authentication, identity, and session access policy

Authentication is a subsystem with several distinct responsibilities, not a
single credential lookup. Frontend authentication and backend authentication
are separate exchanges, although ordinary configurations reuse an identity.

### Runtime account stores and access policy

[MySQL_Authentication](../../lib/MySQL_Authentication.cpp) and
[PgSQL_Authentication](../../lib/PgSQL_Authentication.cpp) own applied account
records, credential lookup, account connection accounting, checksums, and runtime
user snapshots. Frontend/backend credential scopes are explicit. Account records
also supply session policy: TLS requirement, default hostgroup, transaction
persistence, fast-forward, connection limits, and attributes; MySQL additionally
includes default schema and schema locking.

[ProxySQL_Admin](../../lib/ProxySQL_Admin.cpp) populates these stores from configured
users (`add()` consumers around user loading; atomic MySQL replacement on the
applicable tier). Protocol authentication reads the stores; successful login
installs policy into Session and enforces connection/TLS constraints. The store
is neither the wire handshake engine nor the database authorization engine.
Database permissions remain enforced by the database server.

Admin and stats-interface credentials also use runtime authentication facilities.
On PROXYSQL31 builds, a separate admin scope prevents collisions with application
users; stable-tier scope behavior differs. See `creds_for()` and
`cred_scope_for_session()` consumers rather than assuming one universal namespace.

### Frontend protocol authentication

[mysql_protocol.cpp](../../lib/MySQL_Protocol.cpp) implements MySQL login and
reauthentication negotiation and verification, including native password,
clear-password, and caching-SHA2 flows with their transport/secret constraints.
[pgsql_protocol.cpp](../../lib/PgSQL_Protocol.cpp) implements PostgreSQL startup
and authentication, including MD5 and SCRAM and configured method-floor behavior.
Protocol modules consume account policy; Session handles continuation and access
failure/success. PostgreSQL support must not be inferred from MySQL mechanisms.

### External identity and backend credentials

- MySQL LDAP is an actual optional authentication integration, not an unused hook:
  `mysql_protocol.cpp` invokes `GloMyLdapAuth->lookup()` and can resolve a mapped
  backend username from the backend credential store. Its provider is loaded
  through the process/plugin infrastructure; the provider implementation is not
  fully represented by the public interface declaration.
- MySQL passthrough authentication is implemented across protocol login, Session
  backend-probe continuation, and
  [MySQL_Passthrough_Auth_Cache](../../include/MySQL_Passthrough_Auth_Cache.h).
  It verifies eligible credentials against a backend and maintains a separate
  verified credential cache and failure controls. It is not ordinary account
  store authentication with a different lookup flag.
- MySQL backend authentication policy includes password and, under PROXYSQL40,
  AWS IAM. [MySQL_Backend_Auth](../../lib/MySQL_Backend_Auth.cpp) resolves policy;
  Session obtains tokens through the installed token-source integration and
  selects backend connection behavior. Tier guards are part of the architecture.
- PostgreSQL backend connection establishment lives in
  [PgSQL_Connection](../../lib/PgSQL_Connection.cpp): connection credentials feed
  native/libpq connection paths. Frontend SCRAM verification and backend login
  are separate responsibilities, with different secret-material requirements.

## Implications for the high-level architecture

Query processing and identity/access deserve explicit traffic-runtime branches.
They interact with routing, session execution, pooling, cache, statistics, and
logging, but cannot be reduced to any one of those responsibilities. Statistics
also has subsystem-wide scope beyond the Query Processor's query accounting.
Peer configuration synchronization can transfer their configuration without
owning their runtime semantics or participating in query execution decisions.
