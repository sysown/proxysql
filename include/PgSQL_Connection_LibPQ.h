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

	// --- handler() hooks (Step 4) ---
	HandlerStep on_connect_end() override;
	void on_connect_successful() override;
	void on_connect_failed() override;
	bool defer_first_result_read() override;
	HandlerStep fetch_result_dispatch(short event, uint64_t* processed_bytes) override;
	bool stmt_start_flushed_at_once() const override;
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
};

#endif // PROXYSQL_PGSQL_CONNECTION_LIBPQ_H