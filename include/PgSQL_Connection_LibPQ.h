#ifndef PROXYSQL_PGSQL_CONNECTION_LIBPQ_H
#define PROXYSQL_PGSQL_CONNECTION_LIBPQ_H
#include "PgSQL_Connection.h"

// libpq-backed backend connection. Speaks the wire protocol through libpq's
// PGconn handle (pgsql_conn). This is the default transport
// (pgsql_use_native_backend_protocol = false).
class PgSQL_Connection_LibPQ final : public PgSQL_Connection {
public:
	PgSQL_Connection_LibPQ();
	~PgSQL_Connection_LibPQ() override;

	// --- The libpq transport state (Step 5b) ---
	// Private, and deliberately so: nothing outside this class and PgSQL_Query_Result
	// (a friend) reads any of it any more. The three external readers that existed in
	// step 5a-ii went through get_pg_connection() / native_mode instead, so there is no
	// white-box test or consumer left that needs these in the open. The native leaf's
	// state is still public because six unit tests drive its state machine by member.
private:
	PGconn* pgsql_conn;
	PGresult* pgsql_result;
	PSresult  ps_result;
	uint8_t result_type;
	bool is_copy_out;
	// libpq's own transport, held while a fast forward relay has displaced it with
	// memory buffers. Belongs to the connection, not to the stream that borrowed it.
	BIO* saved_backend_rbio = nullptr;
	BIO* saved_backend_wbio = nullptr;
	bool exit_pipeline_mode; // true if it is safe to exit pipeline mode

	// --- Methods that exist only for the libpq transport (Step 5b) ---
	// Each of these sat on the base only because the base held the state above. None of
	// them became a virtual: every caller was already inside this file, which is the
	// whole test for "libpq-only" -- not that the name or the body looks like libpq.
	// flush() 13 callers, set_error_from_PQerrorMessage() 25, get_result() 2,
	// handle_copy_out() / next_multi_statement_result() / set_error_from_result() 1 each,
	// and the two statics only ever reach PQsetNoticeReceiver() here.
	void flush(bool is_resync = false);
	bool handle_copy_out(const PGresult* result, uint64_t* processed_bytes);
	void set_error_from_PQerrorMessage();
	void set_error_from_result(const PGresult* result, uint16_t ext_fields = 0);
	PGresult* get_result();
	void next_multi_statement_result(PGresult* result);
	static void notice_handler_cb(void* arg, const PGresult* result);
	static void unhandled_notice_cb(void* arg, const PGresult* result);

public:
	// --- Shared code asking the transport for its own state (Step 5b) ---
	// get_pg_connection() and backend_is_live() were the two places the base answered
	// "is there a libpq, and is it usable" by reading pgsql_conn and branching on
	// native_mode. Both are that question asked of the object that knows the answer.
	const PGconn* get_pg_connection() const override;
	bool backend_is_live() const override;
	void compute_unknown_transaction_status() override;
	// The PQclear() of pgsql_result, which is the only libpq-owned step inside the
	// shared async_free_result() body.
	void free_transport_result() override;
	void reset_fetch_result_state() override;
	void reset_transport_state() override;
	bool handle_ready_past_connect_start() const override;

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
	// Step 5a-ii: the base keeps the ReadyForQuery validation and the kill-path
	// routing, and asks the transport for the storage behind both. libpq has neither
	// -- it reads the letter from PQtransactionStatus() and takes the backend key
	// from its PGconn -- so both of these do nothing.
	void note_ready_for_query(char st) override;
	void native_backend_key(int& pid, int& secret) const override;
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
};

#endif // PROXYSQL_PGSQL_CONNECTION_LIBPQ_H