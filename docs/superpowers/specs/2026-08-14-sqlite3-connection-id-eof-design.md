# SQLite3 `CONNECTION_ID()` CLIENT_DEPRECATE_EOF compatibility

## Goal

Make `SELECT CONNECTION_ID()` on the SQLite3 listener return a valid, nonzero
frontend session ID for both ordinary clients and clients that negotiate
`CLIENT_DEPRECATE_EOF`.

## Root cause

The SQLite3-server interception currently rewrites `SELECT CONNECTION_ID()`
into a SQLite query and relies on the generic SQLite-result conversion path.
The four-mode TAP matrix shows that this response is valid without
`CLIENT_DEPRECATE_EOF`, but result retrieval fails in both configurations that
negotiate it. The failure was present before the test began comparing the
returned value with `mysql_thread_id()`, so it is a response-framing defect,
not an overly strict assertion.

The main MySQL session already implements `SELECT CONNECTION_ID()` as a
native, one-column protocol response. It selects the EOF or OK terminator
according to the negotiated client capability and uses numeric field metadata.

## Design

Replace the SQLite query rewrite with the corresponding native response in
`SQLite3_Server_session_handler()`:

1. Format `sess->thread_session_id` as the one returned value.
2. Emit a one-column `CONNECTION_ID()` result with `MYSQL_TYPE_LONGLONG`
   metadata.
3. Emit an intermediate EOF only when `CLIENT_DEPRECATE_EOF` is not active.
4. Terminate rows with an OK packet when it is active, otherwise an EOF
   packet.
5. Set `run_query` to false and return through the existing SQLite3-server
   handler cleanup path, as its direct OK responses do.

No general resultset code, handshake logic, or connection-ID allocation will
change.

## Regression coverage

The existing `test_sqlite3_special_queries.cpp` already runs the relevant
matrix: `CLIENT_DEPRECATE_EOF` disabled/enabled crossed with the two
multi-statement settings. It asserts that `CONNECTION_ID()` parses as a
nonzero integer and equals `mysql_thread_id(proxy)`. The pre-fix CI run is the
red state: test cases 28 and 40 fail, while cases 4 and 16 pass.

## Verification

Compile the focused TAP binary and run it against a matching daemon. Then run
the full CI matrix for the PR; the two g9 jobs must pass, and Codecov must be
rechecked because the currently failing test produced a patch-coverage status
failure.
