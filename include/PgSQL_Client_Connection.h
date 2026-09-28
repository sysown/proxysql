#ifndef PROXYSQL_PGSQL_CLIENT_CONNECTION_H
#define PROXYSQL_PGSQL_CLIENT_CONNECTION_H
#include "PgSQL_Connection.h"

// Connection representing the client side of an accepted session. Distinct from
// the two backend leaves so the transport (and later, the wire protocol
// parser) choice for backend connections cannot accidentally apply to it.
class PgSQL_Client_Connection final : public PgSQL_Connection {
public:
	PgSQL_Client_Connection();

	// --- Fast-forward TLS borrow (Step 5a-i) ---
	// A client connection has no backend transport to lend. The guard in
	// PgSQL_Data_Stream::adopt_backend_tls() (is_connected() and
	// get_pg_ssl_in_use() are both 0 here) means none of these is ever called;
	// assert(0) matches the 17 pre-existing dispatchers below.
	bool tls_borrow(SSL* ssl, BIO*& r, BIO*& w, bool& displaced) override;
	bool tls_still_borrowed() const override;
	bool tls_return(SSL* ssl) override;

	// --- handler() hooks (Step 4) ---
	// Unreachable, like every state-machine dispatcher above: handler() is the
	// backend drive and a client connection has nothing to drive.
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
	// A client-side connection has no transport. The state-machine dispatchers
	// are unreachable here (they would today trip assert(pgsql_conn) or
	// dereference a null parent), so each asserts. The accessors answer the
	// fixed values a never-connected libpq connection would report.
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
	// Step 5a-ii: base-owned state hooks this transport cannot be asked for. A
	// ReadyForQuery is backend-to-frontend and a client stream has no backend; the
	// kill path only reaches for the backend key under `if (native_mode)`, which is
	// false here. Both are therefore unreachable, and say so.
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

#endif // PROXYSQL_PGSQL_CLIENT_CONNECTION_H