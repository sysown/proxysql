# DuckDB typed MySQL results

Date: 2026-11-05
Base: 782baf59b
Scope: the user selected typed MySQL results first, then prepared statements. This change implements typed text-protocol results as the foundation; prepared-statement protocol follows separately.

## Behavior

MySQL clients receive column types, unsigned flags, decimal scale, character set and lengths matching returned scalar values. Map signed/unsigned 8/16/32/64-bit integers to corresponding MySQL integer types; BOOLEAN to TINY with 1/0 values; HUGEINT/UHUGEINT to exact DECIMAL(39,0); DECIMAL to NEWDECIMAL with its precision/scale; FLOAT/DOUBLE to native numeric types; DATE/TIME/TIMESTAMP to their MySQL temporal counterparts. VARCHAR remains UTF-8 text; BLOB is binary with length-aware bytes. SQL NULL remains NULL, independently of column type.

Unknown/composite types and temporal variants outside the supported subset use exact VARCHAR output. Columns containing nonfinite floating-point values, infinite dates/timestamps or years outside 1..9999 fall back to text for that whole column. Do not advertise a MySQL numeric/date type with text its decoder cannot represent. Native floating-point output must round-trip its value. Text/blob lengths describe the largest returned byte length, clamped to the wire field, since DuckDB does not retain declared VARCHAR lengths. Nullable/key/origin metadata unavailable from the C API remains conservative; no invented NOT_NULL/primary-key attributes.

Typed results apply to the MySQL listener in native and compatibility modes. Native MySQL BOOLEAN now returns 1/0 consistently with its numeric type. PostgreSQL retains its current text metadata, boolean values and fallback behavior. No new configuration switch and no changes to query routing or replica apply.

## Implementation choices

Keep the SQLite3_result length-aware value container, with a separate vector of MySQL descriptors in the execution outcome. Capture DuckDB logical types before chunk access and before destroying the materialized result. Emit MySQL field packets with existing core protocol generators; keep plugin-specific mapping/serialization in the plugin rather than extending all SQLite result consumers.

For MySQL queries with unsupported columns, prepare a positional subquery wrapper that casts only those columns. Unique positional aliases preserve order and duplicate output names. Execute once. PostgreSQL keeps its existing wrapper. Scalar DML RETURNING retains transactional conversion and executes once. MySQL DML RETURNING with unsupported output types is rejected before mutation when it cannot be wrapped; PostgreSQL retains its existing fallback.

## Verification

Live driver checks against the isolated child through direct DuckDB and ordinary same-instance hostgroup routing: scalar types/flags/scale, signed boundaries, decimals beyond 64 bits, binary/NUL/empty/NULL, zero rows, duplicate labels, mixed nested/scalar projections, nonfinite/out-of-range temporal fallback, floating precision, DML RETURNING, transaction status, large multi-packet rows and capability variants through existing MySQL listener tests. Add focused converter/session unit coverage. Run affected DuckDB units and existing live compatibility/replica/listener regressions; preserve the documented PostgreSQL baseline failures.

## Validation (2026-11-05)

- Direct/routed typed-result TAP: 31 assertions, including compatibility mode, 16 MiB packet splitting, 300-column sequence wrapping, binary NULs and UTF-8.
- Nine DuckDB units: 379 assertions (result44, session101).
- Existing compatibility39, replica31, Admin22 and MySQL listener17 pass, including MySQL 8 deprecate-EOF capability handling.
- PostgreSQL retains exactly the six previously reproduced baseline failures at assertions19..24.
- Independent review found no Critical/Important issues; C API allocated names are freed and stale comments corrected.

Prepared-statement protocol is the following feature; this change delivers typed COM_QUERY results.
