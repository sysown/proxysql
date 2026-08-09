# Task 3 report: authentication packet/error-message hardening

## Scope attempted

- `include/MySQL_Protocol.h`: proposed `bool` results for
  `generate_auth_more_data`, `generate_one_byte_pkt`, and
  `PPHR_passthrough_init`.
- `lib/MySQL_Protocol.cpp`: proposed atomic AuthMoreData allocation handling
  and result propagation through `PPHR_1`, `PPHR_5passwordFalse_0`,
  `PPHR_sha2full`, `PPHR_passthrough_init`/`PPHR_verify_password`, and the
  cleartext cache-hit fast-auth marker.
- `lib/MySQL_Session.cpp`: proposed replacement of both access-denied
  `sprintf` branches with exactly sized `string_format` into `std::string`.
- `test/tap/tests/unit/protocol_unit-t.cpp`: added a positive return-value
  assertion while retaining all four pre-existing wire-format assertions.

## RED evidence

Before production changes, the focused regression was compiled with:

```
make -C test/tap/tests/unit protocol_unit-t
```

The command exited 2. The relevant expected API failures were:

```
protocol_unit-t.cpp:240:44: error: invalid use of void expression
protocol_unit-t.cpp:290:57: error: void value not ignored as it ought to be
```

These are the new observable contract assertions: successful construction
must return true, and forced allocation failure must return false without
queueing or advancing the sequence.

## RLIMIT_AS attempt and revised test decision

The full unit Makefile automatically adds `-DDEBUG` based on an unconditional
library symbol even when `libproxysql.a` was compiled without `-DDEBUG`. That
ABI mismatch shifts `MySQL_Data_Stream` fields and makes the pre-existing
AuthMoreData unit setup crash in `PtrSizeArray::add`. A no-debug test-only
rebuild was used to remove that unrelated mismatch:

```
make -C test/tap/tests/unit -W protocol_unit-t.cpp PSQLDEBUG= protocol_unit-t
./test/tap/tests/unit/protocol_unit-t
```

The executable reached the child regression. Its successful packet checks all
passed (TAP 19--23), but the forced allocation printed:

```
<jemalloc>: Error in malloc(): out of memory
not ok 24 - AuthMoreData reports allocation failure
not ok 26 - AuthMoreData allocation failure does not advance the packet sequence
# Failed 2 tests!
```

The test helper defines jemalloc as `xmalloc:true`, so the child aborts on
allocation failure rather than returning `nullptr`. It cannot call the
builder's false-return path or write the POD result. This is an allocator
policy of the test executable, not a ProxySQL builder failure. The task rules
prohibit allocator hooks/interposition, so the infeasible RLIMIT_AS regression
was removed. The null-return branch is intentionally not dynamically covered
by this harness.

## GREEN evidence

The final focused unit build and run used `PSQLDEBUG=` because the unit
Makefile's automatic DEBUG-symbol detection otherwise compiles the test with a
different `MySQL_Data_Stream` layout than the non-DEBUG library:

```
make -C test/tap/tests/unit PSQLDEBUG= protocol_unit-t
./test/tap/tests/unit/protocol_unit-t
```

Both commands exited 0. The unit output is TAP `1..55`, including the five
AuthMoreData checks at TAP 19--23: true result, one queued packet, exact header
and sequence, `0x01` marker, and exact non-NUL-terminated PEM bytes.

The issue-5988 E2E binary was rebuilt successfully with:

```
make -B -C test/tap/tests reg_test_5988-caching_sha2_rsa-t
```

This command exited 0. It only builds the binary; it does not start the
ProxySQL/MySQL integration environment, so the E2E executable was not run.

`git diff --check` also exited 0.

## Self-review

- Successful AuthMoreData bytes, marker, packet-id calculation, and existing
  post-send sequence increments were left unchanged by the proposed code.
- The proposed failure paths return before enqueue/state changes and do not
  reuse `CACHING_SHA2_RSA_UNAVAILABLE` for OOM.
- The special RSA-unavailable text, logging, error code, SQLSTATE, and counter
  suppression remain unchanged in the proposed `string_format` conversion.
- Active call sites named in the design were searched and covered: RSA public
  key, monitor fast-auth, full-auth, pass-through init/caller, and cache-hit
  fast-auth. The only remaining textual `generate_one_byte_pkt` occurrence is
  in the commented-out template.

## Concerns

The malloc-null failure path has static/ordering review rather than dynamic
coverage: `generate_auth_more_data` returns immediately after a null result,
before writing, enqueueing, or assigning `pkt_sid`; each propagated caller
returns before its later stage/sequence writes. This is the maximum coverage
available without violating the allocator-hook/interposition constraint.
