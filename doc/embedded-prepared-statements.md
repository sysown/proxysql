# Embedded prepared execution: internal foundation

This is an unintegrated C++17 interface, not a plugin ABI or a complete K1/#6298 implementation. One adapter instance is bound to one engine connection and must outlive its session. The session is neither copyable nor thread-safe. Destroy it before the adapter or connection. It owns statement IDs and finalizes each acquired handle on close or destruction, including a handle supplied with a failed prepare or metadata description. Failed prepare does not consume statement capacity. IDs are never reused during a session. Metadata and values are owned copies; bind must not retain references. Rows returned by fetch are owned by the caller.

The endpoint policy is mandatory and must use the actual endpoint's authorization rules. It is called before native prepare and before every execute and fetch. The caller must arrange any required lock or guard across native operations and the complete lifetime of a live result; these callbacks do not supply one. The adapter and policy must enforce single-statement admission and reject unsupported SQL. Embedded NUL is rejected by the registry. Describing metadata must never execute SQL. Unknown and dynamic metadata are explicit; no wire type mapping is implied.

The session defaults to 128 statements and passes a 64 MiB row-payload budget to the adapter. The adapter must fail before returning a row with payload exceeding that budget; this counts value payloads, not vector capacity or allocator overhead. NULL has zero payload, text, bytes and decimal count their length, and numeric values count eight bytes. The registry checks the same budget after fetch; this does not bound engine internal materialization or process RSS. Fetch is not streaming-memory protection (#6287). Global accounting is not implemented. Portals, long-data buffering (future defaults: 128 portals and 16 MiB per session, with per-statement and aggregate enforcement), cursor capabilities, type reuse, and protocol limits are not implemented. No cursor request may be routed here until an explicit capability and protocol policy exist.

Null, signed and unsigned integers, floating point, text, bytes and exact decimal are distinct. Text and bytes carry explicit lengths, including empty values and embedded NUL. Temporal values are unsupported until their units and timezone semantics are defined. Adapters must reject unsupported values and overflow instead of coercing or truncating them. Decimal syntax and precision validation remain adapter/integration responsibilities.

Each explicit execute validates arity and obtains policy authorization, then resets the native statement before binding and executing. A reset error stops the operation and is returned unchanged. Native reset must release prior results and bindings without replaying SQL or committing or rolling back. Reset clears execution state and asks the adapter to release results and bindings; it does not end a transaction. Failed execute is never automatically replayed and cannot be fetched. Transaction and autocommit ownership remain with the endpoint; adapters do not implicitly commit or roll back. Structured errors retain native information; protocol SQLSTATE validation/mapping is pending. Exceptions propagate to the caller; acquired statement handles remain owned and are finalized during unwinding. Integration must establish where exceptions are translated to protocol errors.

A future plugin registration must use a separately reviewed, versioned C ABI and bump the relevant plugin ABI version. No frontend, plugin registration, global limits or live wire tests are supplied by this foundation. The core library and `embedded_prepared_unit-t` target are wired into the standard Makefiles; the test requires no live server.

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
Prepared commands are not yet enabled on SQLite, Admin or DuckDB endpoints.
