#include "PgSQL_Client_Connection.h"

// A client-side connection has no transport: it never dials a backend and holds a
// permanently NULL pgsql_conn. That makes two very different groups of overrides
// necessary here.
//
// The state-machine dispatchers are unreachable on a client connection. On the
// unified class they would run the libpq arm, which asserts on the NULL handle or
// dereferences the NULL `parent`; they are the backend drive, and a client
// connection has nothing to drive. They assert so a future caller that reaches one
// fails at the call site instead of reading through a null pointer.
//
// The accessors ARE reachable: the session, the thread poll loop and the monitor all
// ask every connection for these facts. Each answers the value the same accessor
// would have produced on a libpq connection that had never connected -- the libpq
// calls with a NULL PGconn*, or the fixed initial value of a field the libpq
// transport never writes. That is exactly what the unified class answered for a
// client connection, so this leaf is behaviour-preserving; the unit test asserts
// the two leaves side by side to keep it that way.

PgSQL_Client_Connection::PgSQL_Client_Connection() : PgSQL_Connection(true, false) {}

// --- State-machine dispatchers (unreachable) ---

// --- handler() hooks (Step 4) ---
// Unreachable, like every state-machine dispatcher above: handler() is the
// backend drive and a client connection has nothing to drive.

PgSQL_Connection::HandlerStep PgSQL_Client_Connection::on_connect_end() {
	assert(0); // backend drive, not reachable on a client connection
	return HandlerStep::CONTINUE;
}

void PgSQL_Client_Connection::on_connect_successful() {
	assert(0); // backend drive, not reachable on a client connection
}

void PgSQL_Client_Connection::on_connect_failed() {
	assert(0); // backend drive, not reachable on a client connection
}

bool PgSQL_Client_Connection::defer_first_result_read() {
	assert(0); // backend drive, not reachable on a client connection
	return false;
}

PgSQL_Connection::HandlerStep PgSQL_Client_Connection::fetch_result_dispatch(short event, uint64_t* processed_bytes) {
	(void)event;
	(void)processed_bytes;
	assert(0); // backend drive, not reachable on a client connection
	return HandlerStep::CONTINUE;
}

void PgSQL_Client_Connection::on_command_end() {
	assert(0); // backend drive, not reachable on a client connection
}

bool PgSQL_Client_Connection::resync_already_synced() {
	assert(0); // backend drive, not reachable on a client connection
	return false;
}

bool PgSQL_Client_Connection::resync_send_failed() {
	assert(0); // backend drive, not reachable on a client connection
	return false;
}

PgSQL_Connection::HandlerStep PgSQL_Client_Connection::reset_session_cont_dispatch() {
	assert(0); // backend drive, not reachable on a client connection
	return HandlerStep::CONTINUE;
}

void PgSQL_Client_Connection::on_reset_session_end() {
	assert(0); // backend drive, not reachable on a client connection
}

bool PgSQL_Client_Connection::stmt_start_flushed_at_once() const {
	assert(0); // backend drive, not reachable on a client connection
	return false;
}

const char* PgSQL_Client_Connection::transport_name() const {
	return "client";
}

bool PgSQL_Client_Connection::set_single_row_mode() {
	assert(0); // backend drive, not reachable on a client connection
	return false;
}

void PgSQL_Client_Connection::connect_start() {
	assert(0); // backend drive, not reachable on a client connection
}

void PgSQL_Client_Connection::connect_cont(short event) {
	(void)event;
	assert(0); // backend drive, not reachable on a client connection
}

void PgSQL_Client_Connection::query_start() {
	assert(0); // backend drive, not reachable on a client connection
}

void PgSQL_Client_Connection::query_cont(short event) {
	(void)event;
	assert(0); // backend drive, not reachable on a client connection
}

void PgSQL_Client_Connection::fetch_result_cont(short event) {
	(void)event;
	assert(0); // backend drive, not reachable on a client connection
}

void PgSQL_Client_Connection::stmt_prepare_start() {
	assert(0); // backend drive, not reachable on a client connection
}

void PgSQL_Client_Connection::stmt_prepare_cont(short event) {
	(void)event;
	assert(0); // backend drive, not reachable on a client connection
}

void PgSQL_Client_Connection::stmt_describe_start() {
	assert(0); // backend drive, not reachable on a client connection
}

void PgSQL_Client_Connection::stmt_describe_cont(short event) {
	(void)event;
	assert(0); // backend drive, not reachable on a client connection
}

void PgSQL_Client_Connection::stmt_execute_start() {
	assert(0); // backend drive, not reachable on a client connection
}

void PgSQL_Client_Connection::stmt_execute_cont(short event) {
	(void)event;
	assert(0); // backend drive, not reachable on a client connection
}

void PgSQL_Client_Connection::reset_session_start() {
	assert(0); // backend drive, not reachable on a client connection
}

void PgSQL_Client_Connection::reset_session_cont(short event) {
	(void)event;
	assert(0); // backend drive, not reachable on a client connection
}

void PgSQL_Client_Connection::resync_start() {
	assert(0); // backend drive, not reachable on a client connection
}

void PgSQL_Client_Connection::resync_cont(short event) {
	(void)event;
	assert(0); // backend drive, not reachable on a client connection
}

int PgSQL_Client_Connection::async_ping(short event) {
	(void)event;
	assert(0); // backend drive, not reachable on a client connection
	return 0;
}

bool PgSQL_Client_Connection::IsKnownActiveTransaction() {
	// The libpq arm asked PQtransactionStatus() about a backend that does not
	// exist, which reads as "no transaction in progress" -- and a client
	// connection is not talking to a backend at all.
	return false;
}

// --- Accessors (the never-connected libpq answers) ---

// get_pg_connection() is not here: the base keeps it a plain inline returning
// pgsql_conn, which is nullptr on a client connection, so it needs no override.

int PgSQL_Client_Connection::get_pg_server_version() {
	return 0;
}

int PgSQL_Client_Connection::get_pg_protocol_version() {
	return 0;
}

const char* PgSQL_Client_Connection::get_pg_host() {
	return nullptr;
}

const char* PgSQL_Client_Connection::get_pg_hostaddr() {
	return nullptr;
}

const char* PgSQL_Client_Connection::get_pg_port() {
	return nullptr;
}

const char* PgSQL_Client_Connection::get_pg_dbname() {
	return nullptr;
}

const char* PgSQL_Client_Connection::get_pg_user() {
	return nullptr;
}

const char* PgSQL_Client_Connection::get_pg_password() {
	return nullptr;
}

const char* PgSQL_Client_Connection::get_pg_options() {
	return nullptr;
}

int PgSQL_Client_Connection::get_pg_socket_fd() {
	return -1;
}

int PgSQL_Client_Connection::get_pg_backend_pid() {
	return 0;
}

int PgSQL_Client_Connection::get_pg_client_encoding() {
	return -1;
}

int PgSQL_Client_Connection::get_pg_ssl_in_use() {
	return 0;
}

SSL* PgSQL_Client_Connection::get_pg_ssl_object() {
	return nullptr;
}

const char* PgSQL_Client_Connection::get_pg_parameter_status(const char* param) {
	(void)param;
	return nullptr;
}

ConnStatusType PgSQL_Client_Connection::get_pg_connection_status() const {
	return CONNECTION_BAD;
}

char PgSQL_Client_Connection::last_ready_for_query_status() const {
	// 'I' -- the initial value of the field, and the value the libpq leaf reports
	// for the same reason: no backend ever sent a ReadyForQuery to be remembered.
	return 'I';
}

bool PgSQL_Client_Connection::needs_pollout() const {
	// Only a backend stream asks this; a client stream is readable, never writable
	// on the client's behalf. The initial async_exit_status reads as PG_EVENT_NONE.
	return (async_exit_status & PG_EVENT_WRITE) != 0;
}

int PgSQL_Client_Connection::get_pg_is_nonblocking() {
	return 0;
}

const char* PgSQL_Client_Connection::get_pg_error_message() {
	// Not "": libpq answers a NULL handle with a static string of its own, and the
	// callers of this accessor append whatever it returns to an error message.
	return PQerrorMessage(nullptr);
}

PGTransactionStatusType PgSQL_Client_Connection::transport_transaction_status() const {
	// The base's get_pg_transaction_status() never gets here: it reports
	// PQTRANS_UNKNOWN first because backend_is_live() is false. Answered the way
	// PQtransactionStatus(NULL) would, in case that check is ever relaxed.
	return PQTRANS_UNKNOWN;
}

int PgSQL_Client_Connection::get_backend_pid() {
	return -1;
}

bool PgSQL_Client_Connection::is_pipeline_active() {
	return false;
}

const char* PgSQL_Client_Connection::get_pg_backend_state() const {
	// What PQstatus(NULL) != CONNECTION_OK made the shared body report.
	return "disconnected";
}

bool PgSQL_Client_Connection::transport_blocks_reuse() const {
	return false;
}

bool PgSQL_Client_Connection::last_execute_suspended() const {
	return false;
}

bool PgSQL_Client_Connection::result_had_notification() const {
	return false;
}

int PgSQL_Client_Connection::relay_async_messages(PtrSizeArray* out) {
	// There is no backend to relay from. The caller only acts on a non-negative
	// return, and the shared body returned 0 whenever it relayed nothing.
	(void)out;
	return 0;
}

