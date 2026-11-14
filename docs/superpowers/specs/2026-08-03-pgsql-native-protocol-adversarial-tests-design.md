# PostgreSQL Native Backend Protocol — Adversarial Test Coverage

**Date:** 2026-08-03
**Status:** Approved design, pending implementation plan
**Update (2026-08-19):** D3 was subsequently fixed in this same PR (#6112) and
`pgsql-native_framer_retention-t` now passes; the statements below that D3 is
unfixed and out of scope (§4.1, §5, §6) record the original design intent. The
separate recv+feed read-loop accumulation is unrelated to D3 and remains open.
**Scope:** Close the test gaps in the native PostgreSQL backend protocol
(`feature/pgsql-native-backend-protocol`) and prove three defects found by code
audit and direct measurement.
**Related:** `2026-06-11-pgsql-native-protocol-design.md` (the implementation this
tests), `2026-06-14-pgsql-native-scram-plus-design.md`,
`2026-07-07-pgsql-native-extq-stmt-pipeline-design.md`

---

## 1. Motivation

The native backend protocol replaces libpq on the ProxySQL → PostgreSQL data
path. It ships with eleven TAP tests and five unit tests, all of which compare
the native path against libpq as an oracle **using a healthy, well-behaved
PostgreSQL backend over plaintext**.

That shape leaves three classes of behaviour untested:

1. **Everything a cooperative backend never does.** Malformed framing, truncated
   messages, forged authentication, unexpected message types, and mid-stream
   disconnects are all handled by code in `PgSQL_Connection.cpp` and
   `PgSQL_Backend_Protocol.cpp` that no test can reach, because a real
   PostgreSQL will not emit those bytes.
2. **Backend TLS.** `use_ssl` appears in none of the native tests, yet the
   infra's PostgreSQL runs with `ssl = on`. The `SSL_read`/BIO branch of
   `native_recv_into_framer()` and the whole SCRAM-SHA-256-PLUS channel-binding
   path have never executed end to end.
3. **Pool lifecycle.** The differential tests exercise queries on a connection.
   They do not exercise what happens to a native connection when it is *returned
   to the pool* and *reset for a different client*.

A code audit of those three areas found three defects, each confirmed with
evidence. This document specifies the tests that prove them, plus the harness
work needed to reach the untestable surface.

A fourth candidate — a no-op `async_ping()` in native mode — was investigated
and **rejected**; it keeps its identifier D2, marked withdrawn, so the analysis
is not repeated and mis-filed later. D1/D3/D4 keep the identifiers they were
first reported under.

---

## 2. Confirmed Defects

These are stated as findings, not hypotheses. Each names the code and the
evidence.

### D1 — `async_reset_session()` does nothing in native mode

`lib/PgSQL_Connection.cpp:3322`

```c
if (native_mode) {
    async_state_machine = ASYNC_RESET_SESSION_SUCCESSFUL;
    return 0;
}
```

The libpq path (`reset_session_start()`, `lib/PgSQL_Connection.cpp:4206`) sends
`DISCARD ALL`, or `ROLLBACK` when the connection is inside a transaction. The
native branch sends nothing and reports success. `PgSQL_Session.cpp:1169` then
calls `myconn->reset()`, clearing ProxySQL's own record of the connection's
session state.

The result is that ProxySQL marks the connection clean while the backend still
holds the previous client's `SET`s, temp tables, `LISTEN` registrations, open
cursors, and session-level prepared statements.

Reachability is not theoretical: `handler_again___verify_backend_user_db()`
(`lib/PgSQL_Session.cpp:1343`) routes to `RESETTING_CONNECTION_V2` whenever
`requires_RESETTING_CONNECTION()` finds the pooled backend connection carrying
tracked variables the incoming client did not ask for.

**Severity:** session state crosses between clients. Under a shared application
user this is a correctness bug; where distinct end users share a ProxySQL user
it is a confidentiality bug.

### D2 — WITHDRAWN — "`async_ping()` does nothing in native mode"

Originally reported as a native-mode divergence on the strength of the early
return at `lib/PgSQL_Connection.cpp:3410`:

```c
if (native_mode) {
    async_state_machine = ASYNC_PING_SUCCESSFUL;
    return 0;
}
```

**This is not a defect, and not a divergence.** The libpq path does not ping
either:

```c
case ASYNC_IDLE:
    async_state_machine = ASYNC_PING_START;
default:
    //handler(event);                            // lib/PgSQL_Connection.cpp:3430
    async_state_machine = ASYNC_PING_SUCCESSFUL;
```

`handler(event)` is commented out, and the `default:` branch unconditionally
reports success. There is no `ping_start()` or `ping_cont()` anywhere in the
PgSQL sources — unlike `reset_session_start()`, which D1 relies on. Whatever
`native_mode` is, `async_ping()` returns 0 without touching the socket.

The native early return is therefore **redundant, not defective**. It was
reported because it is textually near-identical to the `async_reset_session()`
early return in D1, where the libpq path *is* live. The two functions look
alike and behave differently; only reading both to the end distinguishes them.

**Why this matters for the test plan.** A `pgsql-native_pool_ping-t`
differential would have compared a no-op against a no-op, passed, and been
recorded as evidence that idle-connection health checking works. A green
differential is only meaningful when the oracle actually does the thing.

**The real observation underneath**, recorded here and deliberately left out of
scope: ProxySQL never health-checks idle pooled PostgreSQL connections at all,
where the MySQL path does. A backend connection killed server-side stays in the
pool advertised as healthy in **both** modes. That is a pre-existing gap in the
PostgreSQL implementation, not a regression from this branch, and by
construction it cannot be demonstrated by a libpq-vs-native differential. It
belongs in its own issue against the PgSQL connection pool, with a test that
asserts absolute behaviour rather than parity.

### D3 — The message framer never reclaims consumed bytes

`lib/PgSQL_Backend_Protocol.cpp:40`

```c
pos += total;
if (pos == len) { pos = 0; len = 0; }   // fully drained -> cheap reset
```

`feed()` appends at `buf + len`. The consumed prefix `[0, pos)` is reclaimed
only when a drain happens to land exactly on a message boundary. Retention
therefore grows until `k × chunk ≡ 0 (mod msglen)`, bounding peak retention at
`chunk × msglen / gcd(msglen, chunk)` bytes.

Measured against the real framer compiled standalone, feeding through the same
16384-byte reads `native_recv_into_framer()` uses:

| message size | bytes fed | peak retained |
|---|---|---|
| 105 B | 64 MiB | 1.9 MiB |
| **8197 B** | 256 MiB | **130.0 MiB** |
| 65536 B | 512 MiB | 0 MiB |
| 1 MiB | 512 MiB | 0.9 MiB |

Powers of two share a large GCD with the read size and reset often; **any odd
message length is coprime with 16384 and never resets until the stream ends**.

Stated precisely, peak retention is

```
min( result_set_size,  chunk × msglen / gcd(msglen, chunk) )
```

so the pathological bound is only reached by a result set large enough to get
there: ~130 MiB of retention needs ~130 MiB of 8197-byte rows, and the ~1.6 GiB
implied by a 100 KB odd-length row needs a ~1.6 GiB result set. The
amplification is roughly *one extra full copy of the result set* for coprime
message sizes, on top of the `PgSQL_Query_Result` copy the design's whole point
was to make the *only* copy.

`chunk` is 16384 on the plaintext path (`tmp[16384]`,
`lib/PgSQL_Connection.cpp:2191`) but **8192** on the TLS path (`MY_SSL_BUFFER`,
`include/PgSQL_Data_Stream.h:17`), which halves the bound there without changing
the shape of the problem.

Note that the framer *does* reset between queries: `ReadyForQuery` is normally
the last message in the buffer, so `next()` sees `pos == len` and rewinds. The
growth is confined to a single result set — which is exactly what the
measurement above models.

**Severity:** a normal `SELECT` over a wide text column is a memory-amplification
vector. This directly contradicts design §5's "a backend row's bytes are copied
exactly once".

### D4 — Plaintext reads discard a complete result on EOF

`lib/PgSQL_Connection.cpp:2201`

```c
if (n == 0) {
    return -1; // peer closed
}
```

`got` is ignored. The TLS branch of the same function gets this right
(`lib/PgSQL_Connection.cpp:2181`: `return got ? 1 : -1`).

The plaintext loop only exits early when `recv()` returns a short read. If a
`recv()` fills the 16384-byte buffer exactly and the peer has already sent FIN,
the next iteration returns 0 and the function returns `-1`, discarding a
complete, already-framed result whose terminating `ReadyForQuery` is sitting in
the buffer. The caller reports "backend closed during result fetch".

Triggered when a backend response is an exact multiple of 16384 bytes and the
backend closes immediately after — a self-terminating backend, an admin
shutdown, an `idle_session_timeout` race.

**Triggering it from a black-box test is not deterministic, and the test design
must not pretend otherwise.** The condition is that the *final* `recv()` returns
exactly `sizeof(tmp)`, which requires at least 16384 bytes pending at that
instant. A test cannot arrange that over TCP:

- ProxySQL wakes on the first readable segment, which over a Docker bridge
  (MTU 1500) is ~1448 bytes, not 16384.
- The read loop exits on the first short read, so any short read mid-stream
  destroys the alignment and the remaining tail is delivered normally — the
  query then completes and the FIN is never observed.
- Whether the writer outruns the reader by exactly a 16384 multiple at the end
  is a scheduling artefact, not something the test controls.

The defect is nonetheless established by inspection, and the TLS branch is the
proof that the plaintext branch is wrong rather than deliberately different:
the two paths of the same function disagree about whether buffered data
survives an EOF.

**Severity:** a successfully-completed query is reported to the client as a
connection failure.

---

## 3. Coverage Gaps

Distinct from the defects above: surface with no test at all.

- **No hostile backend exists.** Every `FRAME_ERROR` branch, every "unexpected
  message during auth", "short Authentication message", "short MD5 salt",
  "malformed backend message during result fetch", and every capability-gap
  fallback is unreachable from a cooperative PostgreSQL.
- **Server authentication is unverified.** `pg_scram_verify_server_final()`
  (`include/PgSQL_Backend_Protocol.h:121`) is the sole defence against a
  malicious or spoofed backend impersonating the real server. Its rejection
  branch has no test.
- **Backend TLS has never run.** `native_recv_into_framer()`'s BIO/`SSL_read`
  loop, certificate verification, and the SCRAM-SHA-256-PLUS
  `tls-server-end-point` channel binding are covered only by crypto-level unit
  tests of the helper functions.
- **The framer unit test is seven assertions** (`unit/pgsql_backend_framing-t.cpp`).
  It omits `msglen` 0–3, `msglen == 4`, the exact 1 GiB cap boundary, sticky
  failure semantics, `reset()` recovery, byte-at-a-time feeding, and retention.

---

## 4. Design

Four test groups. Groups 1 and 2 add new capability; groups 3 and 4 extend the
existing libpq-oracle differential pattern to untested axes.

### 4.1 Group 1 — `test/tap/tests/unit/pgsql_backend_framing-t.cpp` (extended)

Pure unit test, no infrastructure. Grows from 7 assertions to roughly 25.

| Case | Assertion |
|---|---|
| `msglen` = 0, 1, 2, 3 | `FRAME_ERROR` for each (length field includes itself, so < 4 is malformed) |
| `msglen` = 4 | `FRAME_OK`, `payload_len == 0` |
| `msglen` = `PGSQL_MAX_BACKEND_MSG_LEN` | `FRAME_NEED_MORE` — at the cap is legal, only the header has been fed |
| `msglen` = cap + 1 | `FRAME_ERROR` |
| after `FRAME_ERROR` | `feed()` is ignored; `next()` stays `FRAME_ERROR` |
| after `reset()` | failure cleared; framing resumes correctly |
| 3 messages, 1 byte per `feed()` | all framed in order, payloads intact |
| N messages in one `feed()` | all framed in order, types and payloads intact |
| **retention (D3)** | 256 MiB of 8197-byte messages in 16384-byte chunks; `VmRSS` delta must stay under 8 MiB |

The retention case reads `VmRSS` from `/proc/self/status` before the loop and
tracks the peak during it. A coarse instrument is adequate for a 130 MiB signal
against an 8 MiB bar. The test skips (rather than fails) if `/proc` is
unavailable, so it stays portable.

**Expected result: the retention case fails.** Everything else passes.

### 4.2 Group 2 — mock backend harness + `pgsql-native_hostile_backend-t`

New reusable helper `test/tap/tests/pgsql_mock_backend.{h,cpp}`, plus the test
that drives it.

**Harness.** A listener thread inside the test process speaks enough of the
PostgreSQL wire protocol to complete a scripted handshake, then emits a
per-case script of attacker-chosen bytes. It supports: reading the client
startup packet; answering with any `Authentication*` subtype including a real
SCRAM server-first with correct nonce extension; emitting arbitrary framed or
deliberately malformed messages; controlling delivery granularity down to one
byte per `write()`; and closing at any chosen point.

**Wiring.** The test-runner container shares the Docker network with ProxySQL
(`run-tests-isolated.bash:276` and `start-proxysql-isolated.bash:228` both use
`${NETWORK_NAME}`). The test discovers its own container IP at runtime and
registers `ip:port` in `pgsql_servers` under a hostgroup dedicated to this test,
with a `pgsql_users` entry routed there. Runtime IP discovery is used rather
than Docker DNS so the test does not depend on how the runner container's name
or hostname is registered.

**Preconditions — without these, most cases fail for reasons unrelated to what
they test.** A backend that deliberately breaks handshakes trips two independent
mechanisms that remove it from rotation:

1. **Monitor shunning.** `PgSQL_Monitor::shunn_non_resp_srv()`
   (`lib/PgSQL_Monitor.cpp:1729`) calls `PgHGM->shun_and_killall()` for a server
   that misses heartbeats. The monitor probes with libpq, which every hostile
   handshake defeats. The test sets `pgsql-monitor_enabled = false` for its
   duration.
2. **Error-counter shunning.** `pgsql-shun_on_failures` defaults to **5** with
   `pgsql-shun_recovery_time_sec` at **10** (`lib/PgSQL_Thread.cpp:1042`). The
   case list below is roughly twenty failures; the mock backend would be shunned
   part-way through and the remaining cases would never reach it. The test
   raises `shun_on_failures` well above the case count for its duration.

Both are restored in memory at the end, including on the `BAIL_OUT` path, and
neither is written to disk. The test asserts the mock backend is `ONLINE` in
`runtime_pgsql_servers` before each case, so that a case failing because the
server was shunned is reported as such rather than as a protocol finding.

**Auth cases.**

| Case | Expectation |
|---|---|
| `ErrorResponse` in place of `R` | error surfaced from the backend's fields; connection torn down |
| unknown message type during auth | "unexpected message during auth"; torn down |
| `R` with `payload_len < 4` | "short Authentication message" |
| `R` type 5 with fewer than 4 salt bytes | "short MD5 salt" |
| `R` type 7 / 9 (GSSAPI / SSPI) | capability gap: single warning, libpq fallback attempted |
| `R` with an unrecognised type code | no hang; deterministic teardown |
| SASL with an empty mechanism list | capability gap |
| **SASL final with a forged server signature** | **rejected — auth must fail** |
| SASL server-first whose nonce does not extend the client nonce | rejected |
| FIN immediately after the startup packet | clean connect failure |
| FIN after `AuthenticationOk`, before `ReadyForQuery` | clean connect failure |
| entire handshake delivered one byte per write | succeeds; partial-message handling holds |

**Result-phase cases** (after a successful cleartext handshake).

| Case | Expectation |
|---|---|
| complete result of exactly *N*×16384 bytes, then FIN, repeated in a bounded loop | **result delivered (D4 — probabilistic prober, see below)** |
| same at *N*×16384 + 1 bytes, then FIN | result delivered (control; must pass) |
| truncated `DataRow`, then FIN | clean error; connection destroyed |
| declared length 900 MB, 100 bytes sent, then silence | no OOM; times out and tears down |
| unrecognised message type mid-result | no crash; deterministic client-visible outcome |
| a second `Z` after `Z`, then a query on the same pooled connection | the next query is not corrupted by the stray message |
| `E` whose final field value has no NUL terminator | parsed within bounds; no over-read |
| `S` whose value has no NUL terminator | parsed within bounds |
| whole result delivered one byte per write | framed correctly |
| `NotificationResponse` delivered while the connection idles in the pool | defined behaviour for the next client on that connection |

**Invariants asserted after every case**: ProxySQL is alive, the admin interface
answers, and the process fd count has not grown. A crash, a hang, or an fd leak
fails the case regardless of the protocol-level outcome.

**The D4 case is a prober, not a proof.** Per §2 D4, the trigger condition is
not controllable over TCP. The case writes a large exact-multiple response and
closes, repeated a bounded number of times (target: 50 iterations, capped by
wall-clock so it cannot dominate the group's runtime). A "backend closed during
result fetch" on a response the mock fully delivered is a **failure and a
confirmed hit**. Completing all iterations without a hit is reported as
`# D4 not observed in N iterations` — explicitly **not** as evidence the defect
is absent, since the same run against known-defective code can legitimately
miss it. The case must never be read as a regression guard.

**Expected result for the rest of the group: exploratory.** Predictions exist
for the framing and bounds cases; the response to a forged SCRAM signature, a
stray second `ReadyForQuery`, and an idle-pool `NotificationResponse` is not
known in advance. Any failure there is a new finding, reported as such and never
normalised away.

### 4.3 Group 3 — pool lifecycle differential

One test — `pgsql-native_pool_reset-t` — following the established libpq-oracle
pattern: run the identical scenario with `pgsql-use_native_backend_protocol`
false then true, and require the client-visible outcomes to match.

A second test for idle-connection health checking was specified in an earlier
draft and **removed**: per §2 D2, both modes share the same no-op `async_ping()`,
so the differential would have passed while proving nothing.

**`pgsql-native_pool_reset-t` (D1).** Client A sets a tracked dynamic variable —
`bytea_output`, in the `PGSQL_NAME_LAST_LOW_WM`..`PGSQL_NAME_LAST_HIGH_WM` block
that `requires_RESETTING_CONNECTION()` compares — and records
`pg_backend_pid()`. A disconnects. Client B connects as the same user, confirms
via `pg_backend_pid()` that it inherited the same backend connection, and reads
the variable back with `current_setting()`. The libpq run is the oracle; the
native run must match it. A test-local hostgroup with `max_connections = 1`
forces reuse, and the case retries a bounded number of times if the PID does not
match rather than asserting on a coincidence.

The test also covers the transaction variant: a connection returned while inside
a transaction, where libpq issues `ROLLBACK`.

Backend variable tracking is protocol-agnostic — `PgSQL_Variables` writes
`session->mybe->server_myds->myconn->var_hash[idx]` with no `native_mode`
branch — so `requires_RESETTING_CONNECTION()` fires identically in both modes
and the reset path is genuinely reached in the native run. This was verified
before specifying the test; had the native path not recorded backend variables,
the reset would never have been requested and the scenario would have needed a
different trigger.

The test restores every runtime variable it changes, in memory only — no
`SAVE ... TO DISK`.

### 4.4 Group 4 — `pgsql-native_tls-t`

Sets `use_ssl = 1` on the backend row and runs the standard two-phase
differential.

The infra supports this without new fixtures: `postgresql.conf:15` sets
`ssl = 'on'`, and `pg_hba.conf:35` (`host all all all scram-sha-256`) matches
before the `hostssl ... cert` rule at line 46, so TLS connections authenticate
with SCRAM and no client certificate is required.

Corpus: the broad query set from `pgsql-native_query_differential-t` plus a
10,000-row result. The large result is the point — it is what forces TLS record
boundaries to fall across protocol message boundaries, exercising the
`SSL_read`/BIO branch of `native_recv_into_framer()` that plaintext testing
cannot reach.

**Channel binding is asserted implicitly but strictly.** PostgreSQL 16 offers
both `SCRAM-SHA-256` and `SCRAM-SHA-256-PLUS`; over TLS the mechanism selection
at `lib/PgSQL_Connection.cpp:2345` takes `-PLUS`. A wrong `tls-server-end-point`
digest produces a SCRAM proof the server rejects, so a successful TLS connect
proves `pg_tls_server_end_point()` and
`pg_scram_build_cbind_input_tls_server_end_point()` are correct end to end.
There is no log line naming the chosen mechanism, so the test additionally
asserts TLS is genuinely in use for the backend connection by joining the
observed backend PID against `pg_stat_ssl` on a direct connection — otherwise a
silent plaintext connect would masquerade as a passing TLS test.

A log tripwire asserts no capability-gap or libpq-fallback warning appeared.

**Expected result: passes.** If it does not, that is a new finding in the TLS or
channel-binding path.

---

## 5. Placement and Reporting

The three TAP tests register in the **same five groups** the existing
`pgsql-native_*` tests use — `legacy-g1`,
`mysql-auto_increment_delay_multiplex=0-g1`, `mysql-multiplexing=false-g1`,
`mysql-query_digests=0-g1`, `mysql-query_digests_keep_comment=1-g1` — matching
the pattern at `test/tap/groups/groups.json:166-175`. Entries must be inserted
in sorted order or `CI-lint-groups-json` fails. The unit test is registered the
way `unit/` tests already are. No new TAP group and no new CI workflow wiring.

Per the decision recorded for this work, **defect-proving assertions land red**.
Each test header states explicitly which assertions are expected to fail, cites
the file and line of the implementation defect, and quotes the measured
evidence. The word "flaky" appears nowhere: a failing assertion here is a
reproducible defect with a known cause, and the header says so, so that a
reader encountering a red run reaches for the fix rather than the mute button.

Two assertions carry a weaker guarantee and their headers must say so plainly:
the D4 prober (§4.2), which cannot prove absence, and the Group 2 exploratory
cases, whose expected outcome is not known in advance.

D1, D3 and D4 are not fixed as part of this work.

---

## 6. Out of Scope

- Fixing D1, D3, D4.
- Idle-connection health checking for PostgreSQL (the real observation under the
  withdrawn D2, §2.2). Pre-existing, not native-specific, needs its own issue and
  an absolute-behaviour test rather than a differential.
- Extended-query pipelining (multiple Parse/Bind/Execute cycles before a single
  Sync). Worth a separate investigation; not part of this suite.
- Statement and portal name truncation at PostgreSQL's 63-byte `NAMEDATALEN`
  limit. ProxySQL keys its registries on the untruncated client name; the same
  collision occurs against a direct PostgreSQL, so it is a shared-semantics
  question rather than a proxy divergence.
- Monitor and genai paths, which the native design deliberately leaves on libpq.
- TLS support in the mock backend harness. The harness is plaintext; Group 4
  covers TLS against the real backend.
