#ifndef PROXYSQL_PGSQL_CONNECTION_NATIVE_H
#define PROXYSQL_PGSQL_CONNECTION_NATIVE_H
#include "PgSQL_Connection.h"

// Native (ProxySQL-implemented) wire-protocol backend connection. Has no libpq
// handle (pgsql_conn stays NULL); all transport state lives in the native_*
// members. Selected when pgsql_use_native_backend_protocol = true.
class PgSQL_Connection_Native final : public PgSQL_Connection {
public:
	PgSQL_Connection_Native();
	~PgSQL_Connection_Native() override;

	// --- Fast-forward TLS borrow (Step 5a-i) ---
	bool tls_borrow(SSL* ssl, BIO*& r, BIO*& w, bool& displaced) override;
	bool tls_still_borrowed() const override;
	bool tls_return(SSL* ssl) override;

	// --- handler() hooks (Step 4) ---
	HandlerStep on_connect_end() override;
	void on_connect_successful() override;
	void on_connect_failed() override;
	bool defer_first_result_read() override;
	HandlerStep fetch_result_dispatch(short event, uint64_t* processed_bytes) override;
	void on_command_end() override;
	bool resync_already_synced() override;
	bool resync_send_failed() override;
	HandlerStep reset_session_cont_dispatch() override;
	void on_reset_session_end() override;
	const char* transport_name() const override;
	bool set_single_row_mode() override;

	// --- Transport-dependent overrides (Step 3) ---
	// State machine and health dispatchers moved off the base; each leaf owns
	// the arm it had behind the base's native_mode branch.
	void connect_start() override;
	void connect_cont(short event) override;
	void query_start() override;
	void query_cont(short event) override;
	void fetch_result_cont(short event) override;
	void stmt_prepare_start() override;
	void stmt_prepare_cont(short event) override;
	void stmt_describe_start() override;
	void stmt_describe_cont(short event) override;
	void stmt_execute_start() override;
	void stmt_execute_cont(short event) override;
	void reset_session_start() override;
	void reset_session_cont(short event) override;
	void resync_start() override;
	void resync_cont(short event) override;
	int async_ping(short event) override;
	bool IsKnownActiveTransaction() override;

	// Transport-dependent accessors.
	int get_pg_server_version() override;
	int get_pg_protocol_version() override;
	const char* get_pg_host() override;
	const char* get_pg_hostaddr() override;
	const char* get_pg_port() override;
	const char* get_pg_dbname() override;
	const char* get_pg_user() override;
	const char* get_pg_password() override;
	const char* get_pg_options() override;
	int get_pg_socket_fd() override;
	int get_pg_backend_pid() override;
	int get_pg_client_encoding() override;
	int get_pg_ssl_in_use() override;
	ConnStatusType get_pg_connection_status() const override;
	char last_ready_for_query_status() const override;
	bool needs_pollout() const override;
	int get_pg_is_nonblocking() override;
	const char* get_pg_error_message() override;
	SSL* get_pg_ssl_object() override;
	const char* get_pg_parameter_status(const char* param) override;
	PGTransactionStatusType transport_transaction_status() const override;
	int get_backend_pid() override;
	bool is_pipeline_active() override;
	const char* get_pg_backend_state() const override;
	bool transport_blocks_reuse() const override;
	bool last_execute_suspended() const override;
	bool result_had_notification() const override;
	int relay_async_messages(PtrSizeArray* out) override;

	// PgSQL_Query_Result::add_native_backend_message() writes native_params and parses
	// 'E' into native error state, so it needs the leaf's privates rather than the
	// base's. It is reached only from native_fetch_result_cont() below.
	friend class PgSQL_Query_Result;

	// --- State writes the base hands to whichever transport owns them (Step 5a-ii) ---
	// These two are the whole reason the ReadyForQuery letter and the kill-path
	// backend identity could stay off the base: the base keeps the judgement
	// (is this letter legal, is this connection reusable) and asks the transport for
	// the storage. Only this transport has any.
	void note_ready_for_query(char st) override;
	void native_backend_key(int& pid, int& secret) const override;

	// --- Native transport state (Step 5a-ii) ---
	// Moved here from the base, and deliberately still `public` because that is the
	// access it had there: this step relocates the state, it does not re-architect
	// it. No production code outside this class reads or writes any of it, and
	// nothing on the libpq or client transport has an equivalent -- but the six
	// test/tap/tests/unit/pgsql-native_*_unit-t.cpp tests drive this state machine
	// directly (parking a connection mid-handshake, draining the framer, arming a
	// SCRAM exchange), and they reach it by member rather than through a public API
	// because no such API exists. Tightening this to `private` is therefore real
	// deferred work, not a one-line edit: it means giving the state machine the
	// entry points the tests would use instead. It is tracked as a follow-up.
	// Two of the base's members stayed behind on purpose -- `native_mode` (the
	// const transport selector shared code reads) and `native_connected` (read by
	// backend_is_live(), which the base destructor reaches); both carry the reason
	// at their declaration in PgSQL_Connection.h.
	// --- Native backend connect/auth handshake state (Task 1.6a, plaintext only) ---
	// Every member below is only meaningful on this transport. The base's
	// `native_mode` is const and true for this leaf and no other, so no shared code
	// may read these -- and no production code outside this class does.
	enum class PG_Native_Conn_St {
		TCP_CONNECTING,   // non-blocking connect() in flight, waiting for writable
		SSL_READ_REPLY,   // waiting for the single-byte 'S'/'N' SSLRequest reply
		SSL_HANDSHAKE,    // driving the OpenSSL client handshake over the raw fd
		SEND_STARTUP,     // socket connected, StartupMessage (and pending bytes) to flush
		AUTH,             // exchanging Authentication* / Password / SASL messages
		STARTUP_TAIL,     // consuming ParameterStatus/BackendKeyData until ReadyForQuery
		DONE,             // ReadyForQuery received; connection usable
		FAILED            // unrecoverable error during the native handshake
	};
	PG_Native_Conn_St native_st = PG_Native_Conn_St::TCP_CONNECTING;
	// When an outbound message is only partially sent, native_st is set to
	// SEND_STARTUP to flush the remainder; this records the state to resume in
	// once the buffer drains (AUTH after a password/SASL message, etc.).
	PG_Native_Conn_St native_st_after_send = PG_Native_Conn_St::AUTH;
	PgSQL_Backend_Msg_Framer native_framer;          // frames inbound backend bytes
	// Which direction OpenSSL is blocked on, when that is not the direction the protocol wants:
	// SSL_write can need to READ before it will accept more plaintext (a TLS 1.3 KeyUpdate or a
	// renegotiation arrives mid-stream), and SSL_read can need to WRITE. 0 means no such need.
	// Set by the two TLS helpers and cleared at the top of each, so it always describes the most
	// recent TLS call rather than a stale one.
	short native_ssl_block_dir = 0;
	// True while the backend still owes us a ReadyForQuery: we have sent extended-query messages it
	// has not concluded. Until that arrives the backend holds an implicit transaction and the locks
	// the statements took, so the connection must not be handed to anyone else. Cleared only by an
	// actual ReadyForQuery, because that is the only thing that ends the batch.
	bool native_unsynced_work = false;
	PgSQL_Scram_State* native_scram = nullptr;       // owned; freed in destructor / teardown
	// How far the backend SCRAM exchange has got. The message type alone does not say whether a
	// step is legal: a backend can repeat one, or skip one. Each step below feeds state that
	// libscram expects to be touched once and in order, so every SASL case checks this first, and
	// AuthenticationOk is refused while an exchange is still unverified -- otherwise a backend
	// ends the handshake early and never proves it knows the password.
	enum class PG_Native_Scram_Step : uint8_t {
		NONE,              // no exchange started
		CLIENT_FIRST_SENT, // SASLInitialResponse sent, waiting for server-first
		CLIENT_FINAL_SENT, // SASLResponse sent, waiting for server-final
		SERVER_VERIFIED    // server signature checked; AuthenticationOk may now be accepted
	};
	PG_Native_Scram_Step native_scram_step = PG_Native_Scram_Step::NONE;
	std::string native_outbuf;                       // pending outbound bytes (partial send buffer)
	std::map<std::string, std::string> native_params; // ParameterStatus name->value
	std::string native_host;                         // backend host (parent->address, captured at connect)
	std::string native_options;                      // the `options` value sent in the StartupMessage
	std::string native_hostaddr;                     // resolved numeric IP, or "" — mirrors when the libpq path passes hostaddr=
	std::string native_port;                         // backend port as a decimal string, matching PQport()'s shape
	int native_backend_pid = 0;                      // BackendKeyData PID
	int native_backend_secret = 0;                   // BackendKeyData secret key

	// --- Native simple-query / simple-command execution (Task 1.6c / Phase 2 core) ---
	// Set true once a ReadyForQuery ('Z') has been consumed for the in-flight query,
	// signalling the result stream is complete. Reset at query_start().
	bool native_result_complete = false;
	// Set true once a CopyInResponse ('G') or CopyBothResponse ('W') has been
	// answered with a CopyFail by the native_fetch_result_cont() safety net
	// (see there). Reset at query_start() alongside native_result_complete.
	bool native_copy_intercepted = false;

	// --- Native extended-query (prepared-statement) drive (Task C) ---
	// Which extended-query wire step the native drive is currently executing. Set by
	// stmt_prepare_start / stmt_describe_start / stmt_execute_start, consumed by
	// native_fetch_result_cont() to apply the per-step terminator + ack-filtering
	// rules. Reset to NONE alongside native_result_complete at each stmt start.
	// APPEND-ONLY (values are compared by the drain/ack-filter; a mid-list insert
	// would silently reclassify steps in any translation unit not recompiled). CLOSE_P
	// (Task P2) drives a real backend Close('P', name) round-trip whose CloseComplete
	// '3' is forwarded to the client. RESYNC is a bare Sync sent to conclude a batch the
	// client already believes finished; it matches none of the per-step branches, so it
	// skips NONE's bare-ReadyForQuery protocol-violation check that a resync would trip.
	enum class PG_Native_Stmt_Step { NONE, PARSE, DESCRIBE_S, DESCRIBE_P, EXECUTE, BIND, CLOSE_P, RESYNC };
	PG_Native_Stmt_Step native_stmt_step = PG_Native_Stmt_Step::NONE;
	// Set by the drain when a native EXECUTE step's terminator was 's' (PortalSuspended
	// — max_rows cut the result short); cleared when it was 'C'/'I' (the portal ran to
	// completion). Read once by the session epilogue to mark/clear a NAMED portal's
	// entry.suspended for resume. Reset at each native stmt start. Task P2.
	bool native_last_execute_suspended = false;
	// True when the step was terminated on the wire with Sync (so it completes on the
	// backend's ReadyForQuery 'Z'); false when terminated with Flush (completes on the
	// step's own terminator: '1' for PARSE, 'T'|'n' for DESCRIBE, 'C'|'I'|'s' for
	// EXECUTE — the backend sends no 'Z' until a later Sync).
	bool native_stmt_sync_terminated = false;
	// True for an implicit Parse (IMPLICIT_PREPARE detour): the client never issued a
	// Parse, so the backend's ParseComplete '1' must be suppressed (never forwarded).
	bool native_suppress_parse_complete = false;
	// True when the result just streamed to the client carried a NotificationResponse.
	// The query cache stores the client-wire bytes verbatim, so such a result must not be
	// admitted: the notification would be replayed to every later client that hits the
	// entry. Set while forwarding, cleared at the start of each query.
	bool native_result_had_notification = false;
	// Set true once native_fetch_result_cont() has injected a Sync to recover from an
	// ErrorResponse mid-frame on a Flush-terminated step. After 'E' the backend is in
	// the aborted-until-Sync state and emits no 'Z' on its own; the injected Sync
	// brings it back to ReadyForQuery so the drain can complete and the session's
	// error path can run. Guards against injecting a second Sync while draining to 'Z'.
	bool native_stmt_error_resync = false;
	// True once the injected-Sync recovery proxy_warning has been emitted on this
	// connection. Deliberately NOT reset in native_stmt_reset_step() — the warning
	// fires at most once per backend-connection lifetime, so a client habitually
	// sending Parse-time-invalid SQL (PQexecParams in a loop) cannot flood the
	// production log at WARNING level (the libpq oracle path logs nothing for the
	// same event). The recovery itself (native_stmt_error_resync) still runs on
	// every errored step; only the log line is deduplicated.
	bool native_stmt_resync_logged = false;
	// Reset all per-step native stmt drive state. Called at each native stmt start.
	// (native_stmt_resync_logged is intentionally absent: per-connection, not per-step.)
	inline void native_stmt_reset_step() {
		native_result_complete = false;
		native_copy_intercepted = false;
		native_stmt_step = PG_Native_Stmt_Step::NONE;
		native_last_execute_suspended = false;
		native_stmt_sync_terminated = false;
		native_suppress_parse_complete = false;
		native_stmt_error_resync = false;
		// See query_start(): resetting while a partially received asynchronous message is
		// buffered would truncate it and desynchronise the stream.
		if (native_framer.empty()) native_framer.reset();
		native_outbuf.clear();
	}
	// Drive the native result fetch: recv backend bytes, frame them, and stream each
	// raw message into query_result via add_native_backend_message(). Non-blocking:
	// EAGAIN/incomplete frame → async_exit_status = PG_EVENT_READ and return; a fatal
	// recv/frame error sets error_info and marks the fetch done. Sets
	// native_result_complete when ReadyForQuery is reached.
	// Adds up the bytes it hands to query_result in *processed_bytes, so the
	// caller can apply the same fetch-pause rule the libpq loop uses.
	void native_fetch_result_cont(short event, uint64_t* processed_bytes = nullptr);
	// Finish sending a reset command and consume its reply up to ReadyForQuery.
	// The reply is discarded; a connection being reset has no client to send it to.
	void native_reset_session_cont();
	// Record a ParameterStatus message into native_params.
	void native_track_parameter_status(const unsigned char* payload, uint32_t len);
	// Flush the just-built extended-query step in native_outbuf and set
	// async_exit_status the way the stmt_*_start callers expect: PG_EVENT_WRITE while
	// bytes remain buffered (caller waits for POLLOUT), PG_EVENT_NONE once fully sent
	// (caller proceeds straight to the result fetch). Sets error_info on a fatal send.
	void native_stmt_send_or_wait();
	// Finish flushing a partially-sent extended-query step on a POLLOUT re-entry.
	void native_stmt_flush_cont();

	// --- Native backend TLS (Task 1.6b) ---
	// native_ssl_requested is set in native_connect_start() when SSL is wanted for
	// this backend (parent->use_ssl). When true the handshake takes the
	// SSLRequest -> SSL_READ_REPLY -> SSL_HANDSHAKE path before SEND_STARTUP,
	// and all subsequent native I/O is funneled through SSL_read/SSL_write against
	// myds->ssl (BIO-mem model, pumped to/from `fd` by native_send_or_buffer /
	// native_recv_into_framer). When false the plaintext 1.6a path is used verbatim.
	bool native_ssl_requested = false;
	// SSL verification mode derived from the backend config. Mirrors the libpq
	// sslmode semantics so native TLS honors the same policy as the libpq path.
	enum class PG_Native_SSL_Mode {
		DISABLE,      // no SSL at all (native_ssl_requested == false)
		REQUIRE,      // encrypt, do NOT verify (matches libpq sslmode=require)
		VERIFY_CA,    // encrypt + verify chain to CA, no hostname check
		VERIFY_FULL   // encrypt + verify chain + hostname (X509 host check)
	};
	PG_Native_SSL_Mode native_ssl_mode = PG_Native_SSL_Mode::DISABLE;
	// Pending raw ciphertext awaiting send() to the fd (connect phase only). When
	// SSL_write/SSL_do_handshake produces bytes into wbio_ssl faster than the socket
	// drains, the remainder parks here so the next writable event flushes it. Kept
	// distinct from native_outbuf (which holds *plaintext* protocol bytes).
	std::string native_ssl_outbuf;
	// Owned per-connection client SSL_CTX (TLS_client_method()). Freed in
	// native_teardown() and the destructor. nullptr in plaintext mode.
	SSL_CTX* native_ssl_ctx = nullptr;

	// Native handshake helpers (implemented in PgSQL_Connection_Native.cpp). They drive the
	// sub-state machine above and never block: every recv()/send() handles EAGAIN by
	// setting async_exit_status and returning to the event loop.
	void native_connect_start();
	void native_connect_cont(short event);
	void native_drive_auth(short event);             // AUTH sub-state: Authentication* exchange
	void native_drive_startup_tail(short event);     // post-auth: ParamStatus/KeyData/ReadyForQuery
	bool native_flush_outbuf();                      // returns false on fatal send error
	// Queue an outbound message and try to flush it. If it can't all go out now,
	// parks in SEND_STARTUP and resumes in `resume_st` once drained. Returns false
	// on fatal send error (caller should teardown + return).
	bool native_send_or_buffer(PG_Native_Conn_St resume_st);
	// Non-blocking recv() into the framer. Returns: 1 = got bytes (or already had
	// buffered), 0 = EAGAIN (caller should wait for READ), -1 = EOF/fatal.
	int native_recv_into_framer();
	// Drain messages that arrived on an IDLE connection pinned by LISTEN. There is no
	// query in flight and so no query_result to stream into; a NotificationResponse is
	// rebuilt onto `out` as client-wire bytes and everything else an idle backend may
	// legally send is absorbed. Returns the number of notifications relayed, or -1 when
	// the connection is gone and the caller should destroy it.
	int native_relay_async_messages(PtrSizeArray* out);
	void native_teardown();                          // close fd, free scram (capability gap / failure)
	// Fatal error during the RESULT phase: records the error AND tears the socket
	// down, so the connection is classified non-reusable instead of being pooled.
	// See the definition in PgSQL_Connection_Native.cpp for why the teardown is required.
	void native_result_fatal(const char* code, const char* message);
	// End the result cycle on a protocol violation ProxySQL itself detected, telling the CLIENT
	// why. Unlike native_result_fatal() this leaves the socket open so the session takes the
	// branch that reports an error rather than the one for a connection that merely died, and it
	// finishes the result first -- the client-facing path aborts the proxy on a half-built one.
	// The connection is marked so it is destroyed afterwards rather than pooled.
	void native_result_protocol_violation(const char* message);
	// Parse an ErrorResponse ('E') payload into error_info.
	void native_fill_error_from_E(const unsigned char* payload, uint32_t len);

	// --- Native backend TLS helpers (Task 1.6b). All non-blocking. ---
	// Drive the SSL_HANDSHAKE sub-state: pump bytes between the mem BIOs and the raw
	// fd, calling SSL_do_handshake(). Returns: 1 = handshake complete, 0 = need more
	// I/O (async_exit_status already set, caller returns), -1 = fatal (error_info set,
	// teardown done). On success the connection moves on to SEND_STARTUP over TLS.
	int native_drive_ssl_handshake();
	// Build/obtain a TLS_client_method() SSL_CTX configured from the backend SSL
	// params for this server (CA, client cert/key, CRL, min proto version, verify
	// mode). Returns a per-connection SSL_CTX the caller owns, or nullptr on error.
	SSL_CTX* native_create_client_ssl_ctx();
	// Pump any plaintext bytes SSL has buffered in wbio_ssl out to the raw fd.
	// Returns true on success (all flushed, or EAGAIN with bytes still buffered),
	// false on a fatal write error. Used by the encrypted native_flush_outbuf path.
	bool native_ssl_pump_wbio_to_fd(bool& would_block);
	// Build + queue the StartupMessage and advance toward AUTH. Works for both the
	// plaintext path and the post-handshake TLS path (native_send_or_buffer routes
	// through SSL_write when myds->encrypted). On a fatal error it sets error_info
	// and returns false (caller does the teardown). Returns true otherwise.
	bool native_send_startup();
	// Native backend TLS. Owned by the connection so it shares the lifetime of
	// `fd`, which the native path also owns; the data stream is per-session and
	// would take the TLS session with it when the connection is pooled.
	//
	// SSL_set_bio() transfers both BIOs to the SSL, so SSL_free() releases all
	// three -- done only in native_teardown(), which ~PgSQL_Connection_Native()
	// runs, never on a
	// pool return. myds->ssl stays NULL in native mode.
	// Set when a result fetch stopped early because it had already moved enough
	// bytes for this event. The next entry drains what is still framed instead
	// of asking the socket for more, which may never come.
	bool native_fetch_paused = false;
	SSL* native_ssl  = nullptr;
	BIO* native_rbio = nullptr;
	BIO* native_wbio = nullptr;

	// This is the one member of the relocated block that was NOT public in the base,
	// so it is the one that stays private here.
private:
	// Kept private on purpose. It is stale whenever the connection is broken, so
	// read it through one of the two accessors, which say which question you are
	// asking.
	char native_txn_status = 'I';                    // ReadyForQuery status byte ('I'/'T'/'E')

};

#endif // PROXYSQL_PGSQL_CONNECTION_NATIVE_H
