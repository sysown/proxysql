# PostgreSQL Native Backend Protocol — Design

**Date:** 2026-06-11
**Status:** Approved design, pending implementation plan
**Author:** René Cannaò (with Claude)
**Scope:** Replace libpq on the ProxySQL → PostgreSQL backend **data path** with a
native wire-protocol implementation (Option A: full native replacement), behind a
runtime flag with libpq fallback.

---

## 1. Motivation

ProxySQL's PostgreSQL backend currently uses libpq's async API for the entire data
path:

- **Connect:** `PQconnectStart` / `PQconnectPoll` (`PgSQL_Connection.cpp`)
- **Send:** `PQsendQuery` / `PQsendQueryPrepared` / pipeline mode
- **Receive:** `PQconsumeInput` → `PQisBusy` → `PQgetResult` → `PGresult`

Every backend row is materialized by libpq into a `PGresult`, then **re-encoded** back
to client wire format by `PgSQL_Query_Result::add_row(const PGresult*)`. That round-trip
— wire → PGresult → ProxySQL buffer → wire — is a **double read and double write** on
the hottest path. Proxies that forward bytes without this round-trip (pgbouncer,
Odyssey) frequently outperform ProxySQL on PostgreSQL as a result.

Two concrete goals:

1. **Eliminate the double read/write** on result streaming and query send.
2. **Gain capabilities libpq does not expose**, chiefly **named portals** (the wire
   protocol supports them; libpq's API does not).

### Why this is tractable

ProxySQL already implements the **client-facing** half of the PostgreSQL wire protocol
natively. `PgSQL_Protocol` / `PG_pkt` already *encode* every message type
(`RowDescription`, `DataRow`, `CommandComplete`, `ReadyForQuery`, `ErrorResponse`,
`ParseComplete`, `BindComplete`, `CopyData`, auth requests…) and already *parse* the
client startup/handshake/password packets. `libscram` is already vendored. What is
missing is the **backend-direction decoder** and the **backend-side auth/connect state
machine** — roughly the mirror image of code that already exists.

pgbouncer is small (a few thousand lines) because it mostly *tracks* the protocol —
framing by the 5-byte header and parsing payloads only for auth, `ReadyForQuery`
transaction state, and `ParameterStatus` — and forwards everything else opaquely.
ProxySQL must do more (cache, rewrite, firewall, stats interpret results), so the
decoder cannot be quite that thin, but the byte-forwarding fast path for result
streaming can be.

---

## 2. Key Decisions

| Decision | Choice |
|----------|--------|
| Migration strategy | **Runtime flag + libpq fallback.** `pgsql-use_native_backend_protocol`, global with per-hostgroup override. libpq path stays compiled in as fallback and as the differential-test oracle. |
| Scope of paths | **Data path only.** Monitor (`PgSQL_Monitor.cpp`) and the genai plugin keep using libpq indefinitely; libpq stays vendored, off the data plane. |
| Auth methods (v1) | **SCRAM-SHA-256, md5, cleartext/trust.** SCRAM-SHA-256-PLUS (channel binding) **deferred** — the vendored `libscram` (pgbouncer-derived) hardcodes `c=biws` and has no client channel-binding support; adding it means patching vendored code or a custom cbind layer, so it moves to a focused follow-up. GSSAPI/SSPI also deferred. A server that *requires* channel binding (offers only `SCRAM-SHA-256-PLUS`) triggers the capability-gap libpq fallback. |
| TLS | **Reuse ProxySQL's existing OpenSSL backend-TLS stack** (same as MySQL backend / client side). `SSLRequest` + handshake on the fd we own. |
| Result handling | **Hybrid: stream-through by default, materialize-on-feature.** memcpy raw backend messages into the outbound `PgSQL_Query_Result`; additionally parse rows only when cache/rewrite/firewall/stats need them for that query. |
| Extended protocol / named portals | **Phase 3**, after simple-protocol parity. |
| Correctness bar | **Differential vs libpq, byte-level.** Same queries through native and libpq paths; compare client-delivered wire bytes, normalizing only legitimately-variable fields. A divergence is a hard failure. |
| Structural integration | **Approach A:** native engine on a backend `PgSQL_Data_Stream`, dispatched inside a single `PgSQL_Connection` class. |

---

## 3. Components & Ownership

### New

1. **`PgSQL_Backend_Protocol`** — decoder + auth driver; the inverse of the client-facing
   `PgSQL_Protocol`. Consumes backend message types off an inbound buffer and exposes
   parsed events to the connection state machine. Owns the auth sub-state-machine
   (SASL/SCRAM via `libscram`, md5, cleartext/trust). One job: *bytes → protocol events*.

2. **Backend `PgSQL_Data_Stream`** — the connection's fd, inbound buffer, outbound
   buffer. The **same class** the client side already uses, instantiated for the backend
   direction instead of letting libpq own the socket. Non-blocking I/O integrated with
   the existing libev loop and the buffering the data path already trusts.

3. **`PgSQL_Scram_State`** (may be folded into the protocol object) — holds the SASL
   exchange state across the multi-round handshake, including channel-binding material
   pulled from the TLS session.

### Reused as-is

4. **`PgSQL_Protocol` encoder** (`PG_pkt`, `write_StartupMessage`,
   `write_PasswordMessage`, `write_*` Bind/Execute/Query) — already complete for the
   outbound direction. We send to the backend with machinery that today only talks to
   clients.

5. **`PgSQL_Query_Result`** — already stores client-wire-format bytes. The stream-through
   path memcpy's backend `DataRow`/`RowDescription`/`CommandComplete` straight in. A new
   sibling fill method `append_raw_message(buf, len)` is added next to the existing
   `add_row(const PGresult*)`; both fill the same container, one per mode.

### Dispatch

`PgSQL_Connection` stays **one class**. Each async handler (`connect_cont`,
`query_cont`, `fetch_result_cont`, `stmt_*_cont`) gets an `if (native_mode)` branch. The
libpq branch is untouched and remains the fallback and the differential-test oracle. A
connection picks its mode at creation and never switches mid-life. A native connect/auth
failure that indicates a capability gap tears down the connection, retries once via
libpq, and logs once per backend.

---

## 4. Connect & Auth Data Flow (native mode)

Driven non-blocking by `connect_cont` on libev readiness:

1. **TCP connect** — `PgSQL_Connection` opens the socket itself (non-blocking
   `connect()`), wraps it in the backend `PgSQL_Data_Stream`. No `PQconnectStart`.
2. **TLS negotiation** (if enabled) — send `SSLRequest` (code `0x04d2162f`), read the
   single-byte `S`/`N` reply. On `S`, run the OpenSSL handshake via ProxySQL's existing
   backend-TLS machinery. On `N` with `sslmode=require`, fail per config.
3. **Startup** — `write_StartupMessage(user, params)`: `user`, `database`,
   `application_name`, plus protocol params ProxySQL needs. Read the `R` auth challenge.
4. **Auth sub-state-machine**, branching on the `R` subtype:
   - `AuthenticationOk (0)` → done.
   - `AuthenticationCleartextPassword (3)` → `PasswordMessage`.
   - `AuthenticationMD5Password (5)` → md5 hash with 4-byte salt → `PasswordMessage`.
   - `AuthenticationSASL (10)` → SCRAM-SHA-256 via `libscram`: send `SASLInitialResponse`
     selecting the `SCRAM-SHA-256` mechanism (gs2 cbind flag `n`), process
     `AuthenticationSASLContinue (11)`, send `SASLResponse`, verify
     `AuthenticationSASLFinal (12)`. **Mechanism selection:** if the server's mechanism
     list offers both `SCRAM-SHA-256` and `SCRAM-SHA-256-PLUS`, choose plain
     `SCRAM-SHA-256` (channel binding is deferred — see §2). If the server offers **only**
     `SCRAM-SHA-256-PLUS`, treat it as a capability gap → tear down, fall back to libpq,
     log once.
   - `7/8` (GSSAPI), `9` (SSPI) → unsupported in v1 → tear down, fall back to libpq,
     log once.
   - SCRAM-SHA-256-PLUS / channel binding is a deferred follow-up (libscram has no client
     channel-binding support; `tls-server-end-point` digest + cbind construction land then).
5. **Post-auth steady state** — consume `ParameterStatus (S)` (cache `server_version`,
   `client_encoding`, `standard_conforming_strings`, … — values today read via
   `PQparameterStatus`), `BackendKeyData (K)` (store pid/secret for cancellation —
   replaces `PQgetCancel`), until `ReadyForQuery (Z)` with the transaction-state byte.
   Connection enters the pool.

**Cancellation** (`PQcancel` today): native mode opens a fresh connection and sends a
`CancelRequest` with the stored key.

Per-connection state that previously lived in `PGconn`: SCRAM exchange buffers, the
cached `ParameterStatus` map, and `BackendKeyData`.

---

## 5. Query & Result Hot Path (the perf win)

**Send (simple protocol, v1):** `query_cont` writes a `Query ('Q')` message into the
backend data stream's outbound buffer via the existing encoder and flushes. No
`PQsendQuery`, no libpq-side copy.

**Receive — hybrid decoder in `fetch_result_cont`:** as bytes arrive, the decoder frames
messages by the 5-byte header (type + length), waiting for full messages
(partial-message handling reuses the data stream's existing logic). For each framed
message, one routing decision:

- **Stream-through (default).** `RowDescription ('T')`, `DataRow ('D')`,
  `CommandComplete ('C')`, `EmptyQueryResponse ('I')`, `CopyData ('d')` → memcpy the raw
  message bytes from the inbound buffer into the outbound `PgSQL_Query_Result`. These are
  already valid client-wire messages: **zero decode, zero re-encode.**
- **Always parse (cheap, low-volume).** `ReadyForQuery ('Z')` → transaction state
  (replaces `PQtransactionStatus`). `ErrorResponse ('E')` / `NoticeResponse ('N')` →
  parsed via the existing `PgSQL_Error_Helper` field walker (replaces the
  `PQresultErrorField` calls). `CommandComplete` tag → affected-rows (replaces
  `PQcmdTuples`); raw bytes still forwarded.
- **Materialize-on-feature.** When the session has query cache, result rewrite,
  firewall, or row-level stats active for this query, the decoder *additionally* parses
  `RowDescription`/`DataRow` payloads into a lightweight native row view (column count,
  per-field offsets/lengths into the buffer — not a full PGresult copy) and hands that to
  the feature. Bytes still stream through; materialization is an overlay. The decision is
  made once per result set from session flags, so the hot loop has no per-row branching
  when no feature is active.

**Net effect:** in the common case a backend row's bytes are copied exactly once
(inbound buffer → outbound buffer) versus today's wire → PGresult → re-encode → wire.

---

## 6. Edge Cases & Failure Handling

- **COPY (both directions).** `CopyOutResponse ('H')` → stream-through subsequent
  `CopyData ('d')` / `CopyDone ('c')` (replaces `PQgetCopyData`). `CopyInResponse ('G')`
  → forward client `CopyData`/`CopyDone`/`CopyFail` to backend. Simpler and faster than
  libpq's buffered `PQgetCopyData`/`PQputCopyData`.
- **Async / out-of-band.** `NotificationResponse ('A')` (LISTEN/NOTIFY) and
  `NoticeResponse ('N')` can arrive any time, including idle in the pool — the decoder
  handles them outside query state. `ParameterStatus ('S')` can arrive mid-session
  (e.g. `SET client_encoding`) — update the cached map and forward.
- **Multi-statement simple query.** Multiple result sets before one `ReadyForQuery`; the
  state machine loops on result-set boundaries until `Z`, mirroring the libpq loop on
  `PQgetResult`.
- **Protocol desync / parse failure.** Framing violation, unknown message type, or
  unreconcilable short read → mark the connection broken; **do not** fall back mid-query.
  Close it as a libpq protocol error would today. Flag-level fallback applies only at
  *connect* time, never mid-result.
- **Capability-gap fallback.** Decided at connect: GSSAPI/SSPI challenge or an
  unimplemented auth/TLS combination → tear down the half-open connection, retry once via
  libpq, log once per backend (visible, not silent).
- **Error field parity.** `ErrorResponse` parsing reproduces what
  `PQresultErrorField`/`PQresultErrorMessage` gave the rest of ProxySQL (severity,
  SQLSTATE `C`, message `M`, detail, hint, position…) so downstream error handling and
  logging are byte-identical. Prime differential-test target.

---

## 7. Differential Test Harness

- **Dual-run comparator.** A TAP test issues a corpus of queries through two ProxySQL
  configs — native vs libpq backend — against the same Postgres backend, and compares
  the **client-delivered wire bytes** message-by-message. Normalize only legitimately
  variable fields: `BackendKeyData` pid/secret, timestamps/PIDs in notices,
  server-version-dependent strings.
- **Corpus.** Scalar/row/empty/error results; every data type in text and binary format;
  multi-statement queries; COPY in/out; `NOTIFY`; multi-round SCRAM (with and without
  channel binding), md5, cleartext; TLS on/off; large result sets (multi-buffer
  framing); mid-session `SET client_encoding`. Error cases compare parsed `ErrorResponse`
  fields.
- **Integration.** New TAP group(s) under the existing `pgsql*` infra in `groups.json`,
  run via `run-tests-isolated.bash`, reusing existing Postgres backend containers. Per
  the project testing standard, a native/libpq divergence is a hard failure with the diff
  quoted — never normalized away as "close enough."

---

## 8. Phasing

- **Phase 0 — Scaffolding.** Backend `PgSQL_Data_Stream` instantiation, the flag, the
  `if (native_mode)` dispatch skeleton in the `*_cont` handlers (native branch returns
  "not implemented" → falls back). Lands inert.
- **Phase 1 — Connect + auth + TLS.** §4: TCP, SSLRequest/TLS via existing
  OpenSSL stack, startup, md5/cleartext/SCRAM-SHA-256 (plain; channel binding deferred),
  ParameterStatus/BackendKeyData/ReadyForQuery. **Milestone:** native connections reach
  the pool, idle correctly, and pass auth differential tests.
- **Phase 1b (deferred follow-up) — SCRAM-SHA-256-PLUS / channel binding.** Add
  `tls-server-end-point` digest + cbind client-final construction (libscram lacks client
  channel binding, so either patch vendored libscram or add a custom cbind layer). Until
  then, `-PLUS`-only servers use the libpq fallback.
- **Phase 2 — Simple query + result decoder + hybrid.** §5 and §6 (minus extended
  protocol): `Query`, stream-through fast path, parse-on-feature overlay,
  error/notice/COPY/NOTIFY, `ReadyForQuery` loop. **Milestone:** full simple-protocol
  parity, byte-level differential green, perf benchmark vs libpq. **The double-copy dies
  here.**
- **Phase 3 — Extended protocol + named portals.** `Parse`/`Bind`/`Describe`/`Execute`/
  `Close`/`Sync`, prepared-statement passthrough, and **named portals**. Reuses the
  Phase 2 decoder; adds per-statement/per-portal state.
- **Phase 4 (optional, later).** Revisit GSSAPI/SSPI to shrink the fallback surface;
  consider Monitor migration only if profiling justifies it.

Each phase is independently shippable behind the flag and ends on a green differential
run.
