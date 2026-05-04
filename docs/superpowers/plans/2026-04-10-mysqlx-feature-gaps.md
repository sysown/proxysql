# X Protocol Feature Gaps Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close all 10 feature gaps identified in the MySQL Router X Protocol parity comparison.

**Architecture:** Add TLS support following ProxySQL's existing BIO-based pattern (global SSL_CTX, per-session SSL objects, memory BIO pairs). Add per-message response state machines, backend connect timeout, notice awareness, and proper error codes. Each feature is independently testable and committable.

**Tech Stack:** C++17, OpenSSL (BIO-based TLS), protobuf, poll()

---

## File Structure

### Modified Files

| File | Changes |
|------|---------|
| `plugins/mysqlx/include/mysqlx_data_stream.h` | Add SSL members (ssl_, rbio_ssl_, wbio_ssl_, ssl_write_buf_), sslstatus enum, SSL methods |
| `plugins/mysqlx/src/mysqlx_data_stream.cpp` | Implement SSL read/write paths, do_ssl_handshake(), encrypted I/O |
| `plugins/mysqlx/include/mysqlx_session.h` | Add TLS negotiation states, backend TLS state, backend connect timeout |
| `plugins/mysqlx/src/mysqlx_session.cpp` | Implement CapabilitiesSet TLS handling, backend TLS handshake, per-message response states, notice handling |
| `plugins/mysqlx/include/mysqlx_connection.h` | Add backend TLS members, connect timeout |
| `plugins/mysqlx/src/mysqlx_connection.cpp` | Implement backend TLS, CapabilitiesSet TLS to backend, connect timeout |
| `plugins/mysqlx/src/mysqlx_thread.cpp` | Add SSL context initialization, poll integration for SSL pending writes |
| `test/tap/tests/unit/Makefile` | Add new test targets |

### New Files

| File | Purpose |
|------|---------|
| `test/tap/tests/unit/mysqlx_tls_unit-t.cpp` | TLS handshake, encrypted read/write, error cases |
| `test/tap/tests/unit/mysqlx_response_states_unit-t.cpp` | Per-message response state machine tests |

---

### Task 1: TLS Infrastructure in MysqlxDataStream

**Files:**
- Modify: `plugins/mysqlx/include/mysqlx_data_stream.h`
- Modify: `plugins/mysqlx/src/mysqlx_data_stream.cpp`
- Test: `test/tap/tests/unit/mysqlx_tls_unit-t.cpp`

This task adds all SSL members, the sslstatus enum, and the core SSL I/O methods to MysqlxDataStream. TLS is not wired into the session yet — just the data stream layer.

- [ ] **Step 1: Add SSL members and methods to MysqlxDataStream header**

Add to `mysqlx_data_stream.h`:

```cpp
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

enum mysqlx_ssl_status {
	MYSQLX_SSL_OK = 0,
	MYSQLX_SSL_WANT_IO,
	MYSQLX_SSL_FAIL
};
```

Add to private members of MysqlxDataStream:
```cpp
SSL *ssl_;
BIO *rbio_ssl_;
BIO *wbio_ssl_;
std::vector<uint8_t> ssl_write_buf_;
size_t ssl_write_offset_;
bool ssl_handshake_done_;
```

Add public methods:
```cpp
void init_ssl(SSL_CTX* ctx);
bool do_ssl_handshake();
mysqlx_ssl_status get_ssl_status(SSL* ssl, int n);
bool ssl_init_done() const { return ssl_ != nullptr; }
bool ssl_handshake_complete() const { return ssl_handshake_done_; }
bool has_ssl_pending_write() const;
ssize_t flush_ssl_write_buf();
```

- [ ] **Step 2: Initialize SSL members in constructor, cleanup in destructor**

Constructor: set `ssl_ = nullptr; rbio_ssl_ = nullptr; wbio_ssl_ = nullptr; ssl_handshake_done_ = false; ssl_write_offset_ = 0;`

Destructor: if `ssl_` is non-null, call `SSL_set_quiet_shutdown(ssl_, 1); SSL_shutdown(ssl_); SSL_free(ssl_);`. BIOs are freed by `SSL_free` when set via `SSL_set_bio`.

- [ ] **Step 3: Implement init_ssl()**

```cpp
void MysqlxDataStream::init_ssl(SSL_CTX* ctx) {
	if (!ctx) return;
	ssl_ = SSL_new(ctx);
	rbio_ssl_ = BIO_new(BIO_s_mem());
	wbio_ssl_ = BIO_new(BIO_s_mem());
	SSL_set_bio(ssl_, rbio_ssl_, wbio_ssl_);
	SSL_set_accept_state(ssl_);
	ssl_handshake_done_ = false;
	encrypted_ = false;
}
```

- [ ] **Step 4: Implement get_ssl_status() helper**

```cpp
mysqlx_ssl_status MysqlxDataStream::get_ssl_status(SSL* ssl, int n) {
	int err = SSL_get_error(ssl, n);
	ERR_clear_error();
	switch (err) {
		case SSL_ERROR_NONE:
			return MYSQLX_SSL_OK;
		case SSL_ERROR_WANT_WRITE:
		case SSL_ERROR_WANT_READ:
			return MYSQLX_SSL_WANT_IO;
		default:
			return MYSQLX_SSL_FAIL;
	}
}
```

- [ ] **Step 5: Implement do_ssl_handshake()**

```cpp
bool MysqlxDataStream::do_ssl_handshake() {
	if (!ssl_) return false;
	if (ssl_handshake_done_) return true;
	int n = SSL_do_handshake(ssl_);
	if (n == 1) {
		ssl_handshake_done_ = true;
		encrypted_ = true;
		queue_encrypted_output();
		return true;
	}
	mysqlx_ssl_status status = get_ssl_status(ssl_, n);
	if (status == MYSQLX_SSL_WANT_IO) {
		queue_encrypted_output();
		return false;
	}
	return false;
}
```

- [ ] **Step 6: Implement queue_encrypted_output() and flush_ssl_write_buf()**

Private helper:
```cpp
void MysqlxDataStream::queue_encrypted_output() {
	char buf[16384];
	int n;
	while ((n = BIO_read(wbio_ssl_, buf, sizeof(buf))) > 0) {
		ssl_write_buf_.insert(ssl_write_buf_.end(), buf, buf + n);
	}
}
```

```cpp
ssize_t MysqlxDataStream::flush_ssl_write_buf() {
	if (ssl_write_buf_.empty() || fd_ < 0) return 0;
	size_t avail = ssl_write_buf_.size() - ssl_write_offset_;
	ssize_t r;
	do {
		r = send(fd_, ssl_write_buf_.data() + ssl_write_offset_, avail, MSG_NOSIGNAL);
	} while (r < 0 && errno == EINTR);
	if (r > 0) {
		ssl_write_offset_ += static_cast<size_t>(r);
		if (ssl_write_offset_ >= ssl_write_buf_.size()) {
			ssl_write_buf_.clear();
			ssl_write_offset_ = 0;
		}
	}
	return r;
}

bool MysqlxDataStream::has_ssl_pending_write() const {
	return !ssl_write_buf_.empty() || 
		(wbio_ssl_ && BIO_number_written(wbio_ssl_) > BIO_number_read(wbio_ssl_));
}
```

- [ ] **Step 7: Modify read_from_net() for TLS**

When `ssl_ && !ssl_handshake_done_`: recv raw bytes into temp buffer, feed to BIO_write(rbio_ssl_), call do_ssl_handshake(), return.

When `encrypted_`: recv raw bytes, feed to BIO_write(rbio_ssl_), then SSL_read(ssl_) in a loop to get plaintext, feed plaintext to feed_bytes().

When neither: existing non-TLS path unchanged.

- [ ] **Step 8: Modify write_to_net() for TLS**

When `encrypted_`: SSL_write(ssl_, write_buf_ data), then drain wbio_ssl_ into ssl_write_buf_, then send ssl_write_buf_ to network.

When `ssl_ && !ssl_handshake_done_`: just flush ssl_write_buf_ (handshake data).

Otherwise: existing non-TLS path unchanged.

- [ ] **Step 9: Write unit tests for TLS infrastructure**

Create `test/tap/tests/unit/mysqlx_tls_unit-t.cpp`:
- Test init_ssl with null ctx (no crash)
- Test SSL read/write with a socketpair + self-signed cert context
- Test has_ssl_pending_write before/after handshake data
- Test flush_ssl_write_buf with partial write
- Test that non-TLS read/write still works when ssl_ is null

- [ ] **Step 10: Build and run tests**

Run: `cd test/tap/tests/unit && make mysqlx_tls_unit-t && ./mysqlx_tls_unit-t`
Expected: All assertions pass

- [ ] **Step 11: Commit**

```
feat(mysqlx): add TLS infrastructure to MysqlxDataStream

Adds SSL support following ProxySQL's BIO-based pattern:
- sslstatus enum (OK/WANT_IO/FAIL) mapping OpenSSL errors
- init_ssl() creates per-session SSL object from shared SSL_CTX
- Memory BIO pairs (rbio_ssl/wbio_ssl) for encrypted I/O
- do_ssl_handshake() with WANT_IO handling
- TLS-aware read_from_net(): recv→BIO_write→SSL_read→feed_bytes
- TLS-aware write_to_net(): SSL_write→BIO_read→send
- ssl_write_buf for pending encrypted output
- has_ssl_pending_write() for poll integration
- Non-TLS paths unchanged when ssl_ is null

Tests: init with null ctx, encrypted read/write with self-signed cert,
pending write tracking, non-TLS passthrough
```

---

### Task 2: Client-Side TLS Negotiation (CapabilitiesSet)

**Files:**
- Modify: `plugins/mysqlx/src/mysqlx_session.cpp`
- Modify: `plugins/mysqlx/src/mysqlx_thread.cpp`

This task wires TLS into the session state machine. When a client sends `CapabilitiesSet(tls=true)`, the session initiates SSL_accept on the client data stream.

- [ ] **Step 1: Add TLS enablement to handler_capabilities_set()**

In `handler_capabilities_set()`, after popping the frame, parse the CapabilitiesSet protobuf. If it contains `tls=true`, init SSL on the client data stream, send Ok, set status to `X_TLS_ACCEPT_INIT`. Otherwise, existing behavior (send Ok, return to CONNECTING_CLIENT).

- [ ] **Step 2: Implement handler_tls_accept_init() properly**

Replace the stub with real logic:
```cpp
void MysqlxSession::handler_tls_accept_init() {
	if (!client_ds_.ssl_init_done()) {
		SSL_CTX* ctx = nullptr;
		Mysqlx_Thread* thread = static_cast<Mysqlx_Thread*>(thread_ptr_);
		if (thread) ctx = thread->get_ssl_ctx();
		if (!ctx) {
			send_error(3150, "TLS is not configured on server");
			healthy = false;
			return;
		}
		client_ds_.init_ssl(ctx);
	}
	if (!client_ds_.do_ssl_handshake()) {
		return;
	}
	status_ = CONNECTING_CLIENT;
	to_process = true;
}
```

- [ ] **Step 3: Add get_ssl_ctx() to Mysqlx_Thread**

Add `SSL_CTX* get_ssl_ctx() const;` to header. Implementation returns `GloVars.get_SSL_ctx()` (include `proxysql_glovars.hpp`).

- [ ] **Step 4: Update handler() to check ssl handshake in TLS states**

When status is `X_TLS_ACCEPT_INIT` or `X_TLS_ACCEPT_CONT`, call handler_tls_accept_init(). Also check for pending SSL writes after the handler loop.

- [ ] **Step 5: Update process_all_sessions to handle TLS handshake timeout**

Add `X_TLS_ACCEPT_INIT` and `X_TLS_ACCEPT_CONT` to the handshake timeout check.

- [ ] **Step 6: Add tests for CapabilitiesSet TLS negotiation**

Test that CapabilitiesSet with tls=true triggers init_ssl, that missing SSL_CTX generates error, that handshake timeout works.

- [ ] **Step 7: Build and run all tests**

- [ ] **Step 8: Commit**

```
feat(mysqlx): implement client-side TLS negotiation via CapabilitiesSet

When client sends CapabilitiesSet with tls=true, the session:
1. Gets SSL_CTX from Mysqlx_Thread (via GloVars.get_SSL_ctx())
2. Calls client_ds_.init_ssl(ctx) to create per-session SSL object
3. Sets status to X_TLS_ACCEPT_INIT
4. do_ssl_handshake() is called on each handler() invocation
5. When handshake completes, encrypted_ flag is set and session
   returns to CONNECTING_CLIENT state

If SSL_CTX is not configured, sends error 3150 and closes session.
Handshake timeout (10s) applies during TLS negotiation.

Tests: CapabilitiesSet TLS trigger, missing SSL_CTX error, timeout
```

---

### Task 3: Backend TLS

**Files:**
- Modify: `plugins/mysqlx/include/mysqlx_connection.h`
- Modify: `plugins/mysqlx/src/mysqlx_connection.cpp`
- Modify: `plugins/mysqlx/src/mysqlx_session.cpp`

This task adds TLS to backend connections. During backend auth, after CapSet, the connection sends CapabilitiesSet(tls=true) to the backend and initiates SSL_connect.

- [ ] **Step 1: Add SSL members to MysqlxConnection**

Add `MysqlxDataStream backend_tls_ds_` (for TLS handshake I/O), `bool backend_tls_required_`, and `BackendAuthState::BACKEND_AUTH_TLS_SENT` / `BACKEND_AUTH_TLS_DONE` states.

- [ ] **Step 2: Implement backend TLS in step_auth()**

After BACKEND_AUTH_CAPABILITIES_SET_SENT (received Ok from CapSet):
- Send CapabilitiesSet with tls capability
- Transition to BACKEND_AUTH_TLS_SENT
- On next step_auth call, do SSL_connect via BIO pair
- When TLS done, transition to BACKEND_AUTH_AUTHENTICATE_START_SENT

- [ ] **Step 3: Wire backend TLS into session's handler_connecting_server()**

Check backend TLS requirement before auth. If backend_tls_required_ and not yet TLS'd, do TLS first.

- [ ] **Step 4: Add tests for backend TLS state machine**

Test the BACKEND_AUTH_TLS_SENT/DONE states with mock backend socketpair.

- [ ] **Step 5: Build and run all tests**

- [ ] **Step 6: Commit**

```
feat(mysqlx): implement backend TLS via CapabilitiesSet

Adds TLS to backend X Protocol connections:
- New BACKEND_AUTH_TLS_SENT/DONE states in step_auth()
- After CapSet Ok, sends CapabilitiesSet(tls=true) to backend
- Creates SSL object with SSL_set_connect_state for client role
- Performs TLS handshake via BIO pair before authentication
- Backend connection reuses ProxySQL's global SSL_CTX

Tests: backend TLS state transitions, handshake with mock backend
```

---

### Task 4: TLS Passthrough Mode

**Files:**
- Modify: `plugins/mysqlx/src/mysqlx_session.cpp`

When TLS passthrough is configured, raw TLS records are forwarded between client and backend without termination.

- [ ] **Step 1: Add passthrough detection**

In session init or config, check a `tls_mode` setting. If PASSTHROUGH, skip TLS init and forward raw bytes.

- [ ] **Step 2: Implement raw frame forwarding for TLS**

When passthrough is active, read_from_net() and write_to_net() operate on raw bytes without SSL processing. The X Protocol frames are still parsed since X Protocol runs inside TLS.

- [ ] **Step 3: Commit**

```
feat(mysqlx): add TLS passthrough mode

When tls_mode is PASSTHROUGH, raw encrypted bytes are forwarded
between client and backend without TLS termination. X Protocol
frame parsing operates on the decrypted stream visible to each side.

This mode is useful when TLS is terminated elsewhere (e.g., load
balancer) or when ProxySQL should not have access to certificates.
```

---

### Task 5: Per-Message Response State Machines

**Files:**
- Modify: `plugins/mysqlx/include/mysqlx_session.h`
- Modify: `plugins/mysqlx/src/mysqlx_session.cpp`
- Test: `test/tap/tests/unit/mysqlx_response_states_unit-t.cpp`

Replace the single `is_terminal_server_frame()` with per-message-type response tracking.

- [ ] **Step 1: Define response state enum**

```cpp
enum MysqlxResponseState {
	RESP_IDLE = 0,
	RESP_WAITING_STMT_EXECUTE,
	RESP_WAITING_CRUD,
	RESP_WAITING_PREPARE,
	RESP_WAITING_CURSOR,
	RESP_WAITING_EXPECT
};
```

- [ ] **Step 2: Add response_state_ member to MysqlxSession**

- [ ] **Step 3: Set response state in dispatch_client_message()**

Map each client message type to its response state.

- [ ] **Step 4: Implement per-state terminal detection in handler_waiting_server_msg()**

Each response state has its own terminal frame set:
- STMT_EXECUTE: SQL_STMT_EXECUTE_OK, ERROR, FETCH_DONE
- CRUD: OK, ERROR, FETCH_DONE, FETCH_SUSPENDED
- PREPARE: OK, ERROR
- CURSOR: FETCH_DONE, FETCH_SUSPENDED, ERROR
- EXPECT: OK, ERROR

- [ ] **Step 5: Write tests**

Test that each message type correctly identifies terminal frames for its response type. Test that non-terminal frames keep the session in WAITING_SERVER_XMSG.

- [ ] **Step 6: Build and run all tests**

- [ ] **Step 7: Commit**

```
feat(mysqlx): per-message response state machines

Replace single is_terminal_server_frame() with per-message-type
response tracking. Each client message type (StmtExecute, CRUD,
Prepare, Cursor, Expect) now has its own terminal frame set:

- StmtExecute: SQL_STMT_EXECUTE_OK, ERROR, FETCH_DONE
- CRUD: OK, ERROR, FETCH_DONE, FETCH_SUSPENDED
- Prepare: OK, ERROR
- Cursor: FETCH_DONE, FETCH_SUSPENDED, ERROR
- Expect: OK, ERROR

This is more robust than the single catch-all list and matches
MySQL Router's per-type state machine approach.

Tests: all response states with terminal/non-terminal frame combos
```

---

### Task 6: Backend Connect Timeout

**Files:**
- Modify: `plugins/mysqlx/include/mysqlx_connection.h`
- Modify: `plugins/mysqlx/src/mysqlx_connection.cpp`
- Modify: `plugins/mysqlx/src/mysqlx_session.cpp`

- [ ] **Step 1: Add connect_timeout_ and connect_start_time_ to MysqlxConnection**

Default 10 seconds.

- [ ] **Step 2: Check timeout in check_connect()**

If more than connect_timeout_ ms have elapsed since start_connect(), return -1 with appropriate error.

- [ ] **Step 3: Add set_connect_timeout() accessor**

- [ ] **Step 4: Wire into session's handler_connecting_server()**

Set connect timeout from configuration before calling start_connect().

- [ ] **Step 5: Add tests for connect timeout**

Test that check_connect() returns -1 after timeout elapses.

- [ ] **Step 6: Commit**

```
feat(mysqlx): add backend connect timeout

Adds configurable connect timeout (default 10s) for backend
connections. If TCP connection does not complete within the
timeout, the connection attempt fails with error 2003
(Can't connect to backend).

set_connect_timeout() allows runtime configuration.
check_connect() now measures elapsed time since start_connect()
and returns -1 if timeout exceeded.

Tests: timeout detection with mock clock
```

---

### Task 7: Notice Forwarding Awareness

**Files:**
- Modify: `plugins/mysqlx/src/mysqlx_session.cpp`

- [ ] **Step 1: Add NOTICE to the list of always-forwarded non-terminal frames**

In handler_waiting_server_msg(), explicitly check for NOTICE frames and forward them without affecting the terminal state detection. Notices should be forwarded regardless of the current response state.

- [ ] **Step 2: Add NOTICE type check in the frame forwarding loop**

```cpp
if (msg_type == Mysqlx::ServerMessages_Type_NOTICE) {
	// Forward immediately, don't affect terminal detection
	client_ds_.enqueue_frame(msg_type, frame.data() + 5, frame.size() - 5);
	server_ds_.pop_frame();
	continue;
}
```

- [ ] **Step 3: Commit**

```
feat(mysqlx): explicit NOTICE frame forwarding awareness

Server NOTICE frames are now explicitly handled in the response
forwarding loop. Notices are forwarded immediately to the client
without affecting terminal frame detection or response state.

This ensures warnings, session state changes, and other server-side
notifications are always delivered to the client regardless of the
current query response state.
```

---

### Task 8: Proper Compression Error Code

**Files:**
- Modify: `plugins/mysqlx/src/mysqlx_session.cpp`

- [ ] **Step 1: Replace generic compression error with MySQL X Protocol error code**

Change from:
```cpp
send_error(5001, "Compression is not supported");
```
To:
```cpp
send_error(ER_X_CAPABILITY_COMPRESSION_INVALID_ALGORITHM,
           "Compression is not supported");
```

Where `ER_X_CAPABILITY_COMPRESSION_INVALID_ALGORITHM = 5008` (matching MySQL's error code).

- [ ] **Step 2: Commit**

```
fix(mysqlx): use correct X Protocol error code for compression rejection

Replace generic error code 5001 with the standard MySQL X Protocol
error code ER_X_CAPABILITY_COMPRESSION_INVALID_ALGORITHM (5008)
when rejecting compression capability requests.
```

---

### Task 9: Session Reset Passthrough

**Files:**
- Modify: `plugins/mysqlx/src/mysqlx_session.cpp`

- [ ] **Step 1: Handle SESS_RESET in dispatch_client_message()**

When receiving SESS_RESET, forward to backend, wait for Ok response, then reset session state and return backend to pool.

- [ ] **Step 2: Add handler for reset response**

New mini-state: when waiting for SESS_RESET response, expect Ok from backend. On Ok: clear prepared statement tracking, reset backend connection state, return to WAITING_CLIENT_XMSG.

- [ ] **Step 3: Commit**

```
feat(mysqlx): implement Session Reset passthrough with response tracking

SESS_RESET is now forwarded to the backend with response tracking:
1. Forward SESS_RESET frame to backend
2. Wait for Ok response from backend
3. Clear prepared statement tracking
4. Reset backend connection state
5. Return backend to pool (invalidate cached connection)
6. Resume WAITING_CLIENT_XMSG state

This properly resets the session state on both sides.
```

---

### Task 10: TLS Error Messages

**Files:**
- Modify: `plugins/mysqlx/src/mysqlx_session.cpp`
- Modify: `plugins/mysqlx/src/mysqlx_connection.cpp`

- [ ] **Step 1: Add meaningful TLS error messages**

When SSL handshake fails on client:
```cpp
char err_buf[256];
ERR_error_string_n(ERR_get_error(), err_buf, sizeof(err_buf));
send_error(3151, "TLS handshake failed");
```

When backend TLS fails:
```cpp
send_error(3152, "Backend TLS handshake failed");
```

Include specific OpenSSL error details in proxy logs.

- [ ] **Step 2: Commit**

```
feat(mysqlx): add descriptive TLS error messages

Client TLS failures report error 3151 with OpenSSL error details.
Backend TLS failures report error 3152. Both include the specific
OpenSSL error string in proxy log output for diagnostics.
```

---

## Dependency Order

```
Task 1 (DataStream TLS) → Task 2 (Client TLS) → Task 3 (Backend TLS) → Task 4 (Passthrough)
Task 1 → Task 10 (TLS errors)
Task 5 (Response states) — independent
Task 6 (Connect timeout) — independent  
Task 7 (Notice awareness) — independent
Task 8 (Compression error) — independent
Task 9 (Session reset) — independent
```

Tasks 5-9 can be done in any order. Tasks 1-4 and 10 must be sequential.
