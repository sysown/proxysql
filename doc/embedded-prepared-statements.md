# Embedded prepared execution

The core C++17 framework is integrated with the SQLite3, Admin and STATS MySQL listeners and read-only Admin/STATS PostgreSQL execution. Trusted plugins can register through the [V1 public execution contract](embedded-execution-plugin-contract.md), exposed by PluginServices ABI 17. The complete #6298 acceptance scope remains unfinished. One adapter instance is bound to one engine connection and must outlive its session. The session is neither copyable nor thread-safe. Destroy it before the adapter or connection. It owns statement IDs and finalizes each acquired handle on close or destruction, including a handle supplied with a failed prepare or metadata description. Failed prepare does not consume statement capacity. IDs are never reused during a session. Metadata and values are owned copies; bind must not retain references. Rows returned by fetch are owned by the caller.

The endpoint policy is mandatory and must use the actual endpoint's authorization rules. It is called before native prepare and before every execute and fetch. The caller must arrange any required lock or guard across native operations and the complete lifetime of a live result; these callbacks do not supply one. The adapter and policy must enforce single-statement admission and reject unsupported SQL. Embedded NUL is rejected by the registry. Describing metadata must never execute SQL. Unknown and dynamic metadata are explicit; no wire type mapping is implied.

The session defaults to 128 statements and passes a 64 MiB row-payload budget to the adapter. The adapter must fail before returning a row with payload exceeding that budget; this counts value payloads, not vector capacity or allocator overhead. NULL has zero payload, text, bytes and decimal count their length, and numeric values count eight bytes and Boolean values count one byte. The registry checks the same budget after fetch; this does not bound engine internal materialization or process RSS. Fetch is not streaming-memory protection (#6287). Core Session handles, retained SQL and metadata share process-wide quotas; the MySQL and PostgreSQL frontends also charge retained copies, long-data/bind buffers and private response/portal storage to that pool. MySQL conservatively reserves its configured private response limit before execution. Ordinary network output queues, native engine allocations, temporary scratch and allocator capacity are excluded. The read-only PostgreSQL controller buffers portals as described below; MySQL cursor capabilities remain unimplemented. The MySQL controller supplies bounded long data, parameter type reuse and the protocol limits described below. Cursor requests are explicitly rejected.

Null, Boolean, signed and unsigned integers, floating point, text, bytes and exact decimal are distinct. Text and bytes carry explicit lengths, including empty values and embedded NUL. Temporal values are unsupported until their units and timezone semantics are defined. Adapters must reject unsupported values and overflow instead of coercing or truncating them. Decimal syntax and precision validation remain adapter/integration responsibilities.

Each explicit execute validates arity and obtains policy authorization, then resets the native statement before binding and executing. A reset error stops the operation and is returned unchanged. Native reset must release prior results and bindings without replaying SQL or committing or rolling back. Reset clears execution state and asks the adapter to release results and bindings; it does not end a transaction. Failed execute is never automatically replayed and cannot be fetched. Transaction and autocommit ownership remain with the endpoint; adapters do not implicitly commit or roll back. Structured errors retain native information. The MySQL controller validates SQLSTATE and maps ErrorKind into MySQL error codes instead of exposing engine-native codes as protocol codes; detailed vendor-specific mappings remain pending. The PostgreSQL frontend preserves structured SQLSTATE values and maps unclassified engine errors by ErrorKind. Exceptions propagate to the caller; acquired statement handles remain owned and are finalized during unwinding. Integration must establish where exceptions are translated to protocol errors.

The public callback tables use versioned C-shaped POD layouts and are copied during registration; opaque contexts remain borrowed until successful owner-thread unregister. Core session teardown unregisters before releasing the provider. PluginServices ABI 17 appends the service getter without changing older supported prefixes; Phase B returns no descriptor. The core library and unit targets are wired into the standard Makefiles. Dedicated real-client tests cover the integrated listeners.

The SQLite proxy seam now also exposes native parameter counts, declared column
metadata, binary column access and `stmt_readonly`. The wrapper regression target
covers embedded NUL bytes, empty BLOB versus NULL, and read-only classification
without executing the prepared INSERT. This is groundwork for the SQLite adapter,
not a prepared-protocol endpoint. Independent integrated validation passed 86
lifecycle checks and 87 SQLite wrapper checks on 2026-11-16.

The MySQL bind decoder is now shared through
`MySQL_Protocol::decode_stmt_execute`, taking explicit parameter count, long-data
storage and cached types. The proxy path calls the same implementation. A cache
with a different parameter count and a first execution without types are rejected
before array access. Packet and temporal-buffer ownership remain the existing
protocol contract; embedded consumers must copy values and release those resources
before native execution. This extraction supplies no endpoint dispatch or new
protocol parser. Independent validation passed 13 direct decoder checks and the
existing 9 short-packet and 8 long-data type checks.

The internal `SQLiteAdapter` now implements native preparation, dynamic metadata,
binding, single-row fetch, reset and finalization on a borrowed connection. It
supports NULL, signed integers, lossless unsigned integers through INT64_MAX,
non-NaN doubles, text and binary bytes. It explicitly refuses Decimal binding and
write statements returning columns. Result metadata remains dynamic; this does
not establish a MySQL/PostgreSQL wire type policy. `last_insert_id` is currently 0.

Native preparation consumes one statement. Only whitespace may follow its native
prepare tail: comments after a terminating semicolon are explicitly unsupported
in this initial slice. No second statement is compiled to inspect its shape and
no private SQL/comment lexer is used. Endpoint policy must still authorize the
whole input before native preparation, since SQLite PRAGMAs can act at prepare
time. The adapter has no endpoint authorization or transaction-control policy.

Independent standard-Makefile validation passed all 359 adapter checks, including
constraint-error recovery, schema changes, metadata without execution, rollback
ownership, empty/BLOB/NULL differences, payload limits and cleanup. A separate
ASan/UBSan build passed the same 359 checks with leak detection enabled. The
project sources were instrumented; the supplied SQLite and crypto objects were
not rebuilt with sanitizers.

The prepare-response encoder also accepts explicit metadata through a shared
`generate_STMT_PREPARE_RESPONSE` overload. It uses the existing field and EOF
encoders and checks descriptor pointers before queuing any output. Callers supply
transaction status and keep all NUL-terminated field strings alive through the
synchronous call. The proxy wrapper still holds its metadata lock and uses the
same existing status calculation. All 18 direct metadata-packet checks pass.
Prepared commands are enabled on the SQLite3 MySQL listener. Admin and STATS MySQL listeners are also integrated within the restrictions below. Admin/STATS PostgreSQL listeners now support the read-only subset described below. The native DuckDB MySQL and PostgreSQL listeners also register the shared ABI 17 service for the read-only subset described below.


The SQLite3 listener now registers one shared MySQL prepared controller per
connection. It supports PREPARE, EXECUTE, CLOSE, RESET and bounded SEND_LONG_DATA.
Statements bind native values without SQL interpolation. Cursor execution and
FETCH are rejected with error 1235 before execution. STMT_RESET clears results,
long data and errors while retaining client parameter types. Session reset closes
all statements; wire IDs are not reused. Disconnect finalizes handles before
closing the borrowed SQLite connection. Existing SQLite text-protocol transaction
and disconnect behavior is preserved.

`SQLitePolicy` admits a conservative fully parsed ParserSQL SELECT/DML subset
and a documented function allowlist. It refuses utility statements, transaction
commands, PRAGMAs, ATTACH, user variables, unrecognized functions and unsupported
AST constructs before native preparation. The connection provider must preserve
standard built-ins and ensure that views/triggers cannot reach unsafe native
functions. This endpoint disables extension loading on its own connection. This
policy is not the Admin authorization policy; Admin shared connections and their
extensions require a separate policy and operation-wide locking.

SQLite result columns advertise binary VAR_STRING because SQLite types are
dynamic. Numeric values use exact round-trippable text; text and blobs preserve
lengths, NUL bytes, and empty-versus-NULL values. Typed engines use the same row
codec with fixed numeric types. SQLite Decimal parameters, temporal values,
DML RETURNING and automatic reprepare with changed output names/counts are
explicitly unsupported. SQLite last_insert_id remains zero in this slice.

Default per-session controller limits are 128 statements; 1 MiB SQL per statement
and 16 MiB SQL total; 16 MiB long data per statement and session; 1,024 long-data
parameter entries per statement; 4,096 parameters and result columns per
statement; 8 MiB metadata; and 64 MiB response payload including packet framing.
Metadata/row response errors discard privately buffered packets before sending
ERR. A conservative maximum OK-packet size is reserved before executing DML.
These are transport payload limits, not bounds on engine RSS. Error packets are
sent even when the configured success-response budget cannot fit them. The public versioned registration ABI and shared frontend accounting are integrated; core global quotas are described below.

Validation on 2026-11-16: the real MariaDB C API acceptance client passed 39
checks against the rebuilt isolated SQLite3 listener, including repeated types,
exact binary values, duplicate-key recovery, unsigned overflow without effects,
long data, reset, unsupported SQL/cursors and transaction rollback/status.
Run `test/tap/tests/test_embedded_prepared_mysql-t` with TAP_HOST,
TAP_SQLITE_PORT, TAP_USERNAME and TAP_PASSWORD for a dedicated SQLite3 test
listener. It creates and drops a uniquely named test table. This live test is
currently manual; its unit components are registered in unit-tests-g1.

A native DuckDB SELECT-only adapter is implemented and registered on both native listeners.
It borrows one connection, describes native types without execution, binds exact
integer/Boolean/text/blob/decimal values and checks metadata before exposing rows. Native
DuckDB decimal precision is limited to 38 digits. Unknown, temporal and nested result types are refused. HUGEINT and UHUGEINT use
exact Decimal values with precision 39 and scale 0; native DECIMAL remains limited
to 38 digits. Non-SELECT statements are
refused before execution; prepared writes, transaction commands and cancellation
remain unsupported. The endpoint policy authorizes SELECT function effects.


Shared connections can now supply an optional operation-guard factory. Core holds
the returned RAII guard through native preparation, execution, all row fetching
and response buffering, and through reset/close/finalization. The factory receives
an operation kind and, for a known execute, a synchronously borrowed original SQL
pointer. It runs outside the registry mutex. Factory failures or exceptions become
operation errors; failed executes consume their pending long data while retaining
client type bindings. Disconnect cleanup must acquire its guard successfully;
violating that provider contract terminates rather than leaving callback/native
handles attached to a destroyed borrowed connection. Existing SQLite listener
registration uses no guard. The Admin provider must still supply its actual lock,
startup policy and authorization lease; this hook alone enables no Admin queries.
Independent controller validation now passes 63 checks, including guard lifetime,
throwing factories, rejected-execute stale-data cleanup and malformed execution.


Admin/STATS prepared execution now borrows the correct role's shared database
and holds the existing startup gate and re-entrant Admin SQL lock through each
native operation and all response materialization. It rechecks runtime read-only
state on execution. SELECT is supported on the role's `main` database; prepared
DML is limited to `mysql_servers`, `mysql_users` and `mysql_query_rules`. Utility
commands, transaction control, cross-schema references, CTEs and statistics reset
projections are explicitly unsupported. Text Admin command handling is unchanged.

The scoped native authorizer enforces function, relation, schema and write rules
through views/triggers and automatic reprepare. A direct trusted `PRAGMA
function_list` inspection rejects overrides of allowlisted built-ins. The provider
owns the authorizer slot; native cleanup occurs before releasing the Admin lock.
The optional `sqlite3_set_authorizer` capability is required for Admin prepared
execution, without becoming a new mandatory custom SQLite-plugin startup symbol.
Custom SQLite plugin loading remains disabled by the existing production guard.

Statistics refresh requests come exclusively from ParserSQL relation nodes and
an exact standard-table allowlist, never from original SQL text. String literals,
comments and column aliases cannot request a destructive reset. Uppercase table
references receive the same refresh. Hidden dynamic view dependencies without an
established refresh are refused; the standard PostgreSQL activity view dependency
is handled explicitly. Statistics reset tables are denied through native view
expansion as well as source admission. Unknown dynamic plugin views remain a
future capability rather than a freshness guarantee.

Session-lifetime wire-ID allocation survives provider replacement and connection
reset; retired IDs cannot execute newly prepared statements. The final Session
destructor releases the allocator. Valid transport types survive operation-guard
rejection. Failed replacement metadata invalidates the previous type cache, so a
retry cannot silently use stale signedness; clients must resend types after such
protocol errors. Statement reset still retains valid parameter bindings.

Admin/STATS real-client validation passes 23 checks, including native binary/NULL
values, prepare metadata, repeated execution/reset, runtime `PROXYSQL READONLY`
changes and uppercase statistics-query freshness across a backend configuration
load. The existing SQLite client remains at 39 passing checks. The Admin test
uses TAP_HOST, TAP_ADMINPORT, TAP_ADMINUSERNAME, TAP_ADMINPASSWORD,
TAP_STATSUSERNAME and TAP_STATSPASSWORD against a dedicated fixture initially in
read-write mode. It creates a unique temporary server configuration and restores
it without SAVE commands. Pure statistics-admission tests pass 12 checks; native
Admin policy tests pass 43. The complete controller suite passes 79 checks after final integration validation.

A separate MySQL 8.0.46 oracle probe confirmed long-data/NULL precedence, empty
chunks, reset and cached-type error recovery against the SQLite listener. SQLite
continues to advertise its documented binary VAR_STRING dynamic metadata; engine
error codes and the client call at which a buffered-result error appears need not
match MySQL's streaming behavior.


## PostgreSQL codec prerequisites

The internal PostgreSQL datum and result codecs are implemented separately from
packet framing. The extended-query controller and Admin/STATS registration use these helpers;
codec support does not imply that an endpoint admits every corresponding SQL type.

Parameters support BOOL, INT2/INT4/INT8, FLOAT4/FLOAT8, UTF-8 TEXT/VARCHAR/BPCHAR and BYTEA
in text and binary formats. Finite fixed-point NUMERIC is accepted in text format
as an exact Decimal. Other NUMERIC forms, binary NUMERIC, temporals and
other OIDs return `0A000`. Invalid UTF-8 and embedded text NUL are refused;
BYTEA preserves arbitrary bytes, empty values and NULL distinctly. Integer text
includes PostgreSQL's base prefixes and digit separators. Floating-point parsing
uses locale-independent conversion. Each datum has an explicit payload budget.

Result metadata maps Boolean values to BOOL, signed integers to INT8, doubles to FLOAT8, text and dynamic
values to TEXT, bytes to BYTEA, and exact decimal/unsigned values to NUMERIC.
Binary NUMERIC is explicitly refused during format negotiation. A dynamic TEXT
column cannot represent arbitrary BLOB bytes and refuses them. Field encoders
produce payloads only; the frontend must enforce signed 32-bit framing lengths
and aggregate response limits.

Native parameter-position metadata maps each engine bind slot to an original
positive `$n` position without rewriting SQL. SQLite uses native slot encounter
order; DuckDB reports its native numeric identities. Unknown identities remain
zero and must be refused by the PostgreSQL frontend. The optional SQLite symbol
is not required for existing MySQL prepared execution.

Independent validation on 2026-11-16 passed 308 parameter-codec assertions, 47
result-codec assertions, 31 SQLite position assertions and 65 native DuckDB
adapter assertions. Both PostgreSQL codecs also passed ASan/UBSan. These are
component checks; the endpoint acceptance results are recorded below.


## PostgreSQL read-only controller components

The internal controller implements named and unnamed statements, independent
bound portals, metadata-only Parse/Describe/Bind, one native execution per portal,
and buffered row pagination. An exact row-limit boundary suspends the portal;
a subsequent Execute observes exhaustion. CommandComplete counts rows from that
Execute, following PostgreSQL's PortalRunSelect behavior. Unknown Close names
succeed. Sync clears failed-cycle state and closes implicit-cycle portals;
a simple query also drops the unnamed statement while retaining named ones.
Admin/STATS registration has passed the real-client acceptance below.

This controller requires a policy that admits only read-only SQL. It supports
implicit cycles; explicit transaction ownership is pending. One operation guard
covers execution and complete native fetch, then releases before the next client
packet. Encoded rows are transferred to the caller without copying their field
payloads. Failures discard partial output, poison the cycle and prevent replay.

Limits default to 128 statements and 128 portals, 4,096 parameters and columns,
1 KiB names, 1 MiB SQL per statement, 16 MiB aggregate owned SQL and bind payload,
8 MiB metadata and 64 MiB encoded results. Injected limits can lower these caps.
Accounting includes conservative container and framing charges, but excludes
native/adapter/Session allocations before metadata reaches the controller and
engine internal memory. Callers release each transferred response before asking
for another to retain the stated response bound. Frontend bind/result buffers also participate in shared global accounting.

SQLite now has an opt-in `strict_declared` result profile. Exact native declared
names BLOB/TEXT/INTEGER/INT/BIGINT/REAL/DOUBLE/FLOAT provide fixed descriptors;
other declarations and expressions stay dynamic. Runtime storage classes must
match, with no coercion. This enables BYTEA for declared BLOB columns and rejects
mixed storage before exposing a row under an incompatible descriptor. The default
MySQL profile remains dynamic. Source policies and statistics relation discovery
can select ParserSQL's PostgreSQL dialect; MySQL remains their default.

Independent component validation passed 66 controller assertions, 157 strict
profile assertions, 46 SQLite policy assertions, 46 Admin policy assertions and
16 statistics assertions on 2026-11-16. These component checks alone do not complete the prepared-statement framework.


## Admin/STATS PostgreSQL listener support

Admin and STATS now use the shared frontend for Parse, Bind, Describe, Execute,
Close, Flush and Sync. The initial capability is read-only SELECT with the same
native authorizer and AST-derived statistics refresh protections as the MySQL
provider. It selects ParserSQL's PostgreSQL dialect and the strict SQLite result
profile. Named statements survive Sync; implicit-cycle portals do not. All rows
are read during the portal's first Execute, then paged from its owned buffer.
This does not provide a transaction-wide snapshot across independent portals.

Explicit transaction commands are refused on the Admin/STATS simple-query path,
as well as in prepared SQL. The earlier simple-query acknowledgement did not
start a native transaction. Transaction ownership and writable PostgreSQL prepared
execution remain separate unfinished work. PostgreSQL prepared execution requires
UTF8 client encoding; other startup encodings are refused before native access.
The existing MySQL prepared endpoints retain their current write/transaction
policy. Native DuckDB PostgreSQL sessions now register the shared service explicitly.

Independent live libpq and packet-client validation on 2026-11-16 passed 53 checks
across Admin and STATS, including NULL/empty/binary/Unicode values, exact-limit
portal suspension, Flush without premature ReadyForQuery, multiple portals,
Sync recovery, explicit transaction refusal and non-UTF8 rejection. The existing
#6345 error/Sync regression also passes 15 real-client assertions. Packet-level
checks pass 39 assertions and ASan/UBSan (new sources instrumented, existing core
uninstrumented; global leak checking disabled). Preserved MySQL live clients pass
39 SQLite and 23 Admin/STATS checks. These results do not complete K5's writable
or explicit-transaction acceptance.

MySQL exception hardening now owns decoded bind metadata and temporary prepared
handles, resets active native results before an exception releases its guard, and
publishes prepare success only after statement registration. Its focused tests
pass 81 assertions. The legacy metadata wrapper uses the signed no-transaction
sentinel; the response test passes 26 assertions, including active hostgroup zero.
The SELECT-only native DuckDB adapter passes 65 assertions, including exact zero
binding to fractional-only DECIMAL and native temporary-handle cleanup.


## Boolean values and core global quotas

Boolean values now have an explicit shared tag. MySQL fixed descriptors use TINY
and one-byte 0/1 binary values; PostgreSQL uses BOOL with `t`/`f` text or a binary
byte. PostgreSQL input follows its documented prefixes and treats any nonzero
binary byte as true. SQLite binds Boolean parameters as INTEGER 0/1 without
inventing fixed Boolean metadata for dynamic expressions. The DuckDB adapter uses
native Boolean bindings and result vectors. Temporal values remain unsupported.

Core Sessions share limits of 4,096 native prepared handles, 64 MiB retained SQL
and 64 MiB owned metadata. Handle/SQL reservations precede native prepare;
metadata refusal finalizes the new native handle and releases all reservations.
Reset retains reservations; close and destruction release them. Tests can inject
a smaller shared pool. The shared pool also accounts for 256 MiB bind and 512 MiB result
categories used by frontend accounting. These limits count
logical retained state and exclude allocator overhead, engine memory and transient
adapter allocations; they do not bound process RSS or output network queues.

Independent checks pass 13 quota assertions, 95 lifecycle assertions, 308
PostgreSQL parameter assertions, 47 PostgreSQL field assertions, 65 MySQL field
assertions, 364 native SQLite assertions, 66 portal controller assertions and 65
native DuckDB assertions. The quota helper also passes ASan/UBSan. All three real
client suites retain their 53/39/23 passing checks after enabling Boolean binds.


## Native DuckDB listeners

The MySQL and PostgreSQL listeners use the shared ABI 17 prepared execution
core for native read-only SELECT in implicit autocommit cycles. Explicit client
transactions, prepared DML/RETURNING, temporal and nested values,
cursors and cancellation are unsupported. MySQL requires a UTF-8 handshake or
`SET NAMES utf8`, `utf8mb3`, or `utf8mb4`; PostgreSQL requires UTF8.
On the MySQL listener, `SET autocommit=0` is refused (MySQL 1235 / SQLSTATE `0A000`); setting it to
1 when already enabled is accepted. Explicit text transaction commands remain
available for text queries.

Native output metadata must resolve at prepare time. Untyped expressions such as
`SELECT ? + 0` and `length(?)` may be refused; PostgreSQL
`CAST($1 AS BIGINT)` with an explicit OID and typed table columns are usable.
Opaque PostgreSQL `DECIMAL(p,s)` cast names and MySQL `CAST(? AS INTEGER)` or
`COUNT(DISTINCT ...)` are refused by the current policy/parser. Typed table
results support boolean, decimal and blob, alongside signed/unsigned integer,
floating point, text and NULL within supported mappings. SQL is native DuckDB;
there is no MySQL translation.

A private native read-only transaction guards each prepared operation against
hidden database writes. Engine external access remains disabled by default;
neither control is an OS sandbox. See the [DuckDB protocol guide](duckdb/protocol-compatibility.md#prepared-queries).


Native listener acceptance passed 47 MySQL and 29 PostgreSQL checks on the rebuilt
ABI 17 core and plugin. MySQL connection reset finalizes old handles before
replacing the connection; pending writes roll back, temporary tables disappear,
and the shared provider remains registered. Statement reset retains transaction
ownership. The native provider's 41 assertions and public bridge's 126 pass
ASan/UBSan with the supplied DuckDB/ParserSQL libraries uninstrumented. ParserSQL
admission passes 47 checks, session-setting recognition 11, and existing DuckDB
text/session tests retain 116 passing assertions. These do not complete the D1–D3
or K5–K6 roadmap gates.


HUGEINT and UHUGEINT bind and fetch as exact decimal integers with precision 39,
scale 0. This covers the full signed and unsigned 128-bit ranges and integer SUM
results. Fractional or out-of-range Decimal binds fail without truncation; a valid
rebind recovers. The adapter passes 81 checks, including ASan/UBSan. Additional
real-driver suites pass 32 schema/disconnect checks across MySQL SQLite, Admin and
DuckDB, and 18 native PostgreSQL extended checks for binary formats, portals,
suspension, Sync recovery and schema changes. Ordinary proxy routes pass 9 MySQL
and 14 PostgreSQL prepared regression checks against local MySQL 8.0.46 and
PostgreSQL 16.15 backends, independently rerun against their direct endpoints.
The isolated live targets require explicitly configured TAP listener credentials;
they create and remove uniquely named test objects.
