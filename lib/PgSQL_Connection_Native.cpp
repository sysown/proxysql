#include "PgSQL_Connection_Native.h"
#include <fcntl.h>
#include <string_view>
#include <sstream>
#include <atomic>
#include <memory>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>

#include "openssl/x509v3.h" // X509_VERIFY_PARAM_set1_host / set_hostflags (native backend TLS)
#include "openssl/evp.h"     // EVP_MAX_MD_SIZE for cbind digest buffer (SCRAM-PLUS)
#include "PgSQL_Backend_Protocol.h"  // pg_tls_server_end_point / pg_scram_build_cbind_input_* / pg_scram_set_cbind (SCRAM-PLUS)
#include "openssl/crypto.h"   // OPENSSL_cleanse — non-elidable wipe of harvested SCRAM key material

#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON
#include "c_tokenizer.h"
#include "PgSQL_HostGroups_Manager.h"
#include "PgSQL_Monitor.hpp"
#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_PreparedStatement.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Query_Processor.h"
#include "PgSQL_Variables.h"
#include "PgSQL_Extended_Query_Message.h"
#include "PgSQL_Connection_LibPQ.h"
#include "PgSQL_Connection_Native.h"

#include "proxysql_find_charset.h"

// Defined in PgSQL_Connection.cpp; the native simple-query drive is a caller.
void pg_append_typed_msg(std::string& out, char type, const unsigned char* body, size_t bodylen);

PgSQL_Connection_Native::PgSQL_Connection_Native()
	: PgSQL_Connection(false, true)
{
}

PgSQL_Connection_Native::~PgSQL_Connection_Native() {
	// native_teardown() rather than a second copy of the native cleanup the base
	// destructor used to inline, so the pool-return path and the destruction path
	// release the same resources in the same order. It also subtracts from
	// server_connections_connected when this connection was counted and clears the
	// flag, so the base destructor's own decrement finds it already false and the
	// count still moves exactly once. native_teardown() sets fd = -1, so a
	// teardown earlier in the connection's life is not repeated here -- which also
	// covers the safety net the old inline block carried for a connection
	// destroyed before native_teardown() had ever run.
	native_teardown();
}

bool PgSQL_Connection_Native::tls_borrow(SSL* ssl, BIO*& r, BIO*& w, bool& displaced) {
	// The native path built this SSL with two memory BIOs and keeps reading and
	// writing through those same pointers. Share them rather than installing a
	// pair for the relay: SSL_set_bio() would free the ones still in use, and the
	// next query on the connection would touch freed memory. Nothing is displaced,
	// so there is nothing for tls_return() to put back.
	(void)ssl;
	assert(native_rbio != NULL && native_wbio != NULL);
	r = native_rbio;
	w = native_wbio;
	displaced = false;
	return true;
}

bool PgSQL_Connection_Native::tls_still_borrowed() const {
	return false;
}

bool PgSQL_Connection_Native::tls_return(SSL* ssl) {
	(void)ssl;
	return true;
}

bool PgSQL_Connection_Native::set_single_row_mode() {
	// There is no PQsetSingleRowMode() here: the native transport streams raw
	// DataRow messages one at a time, which is what single-row mode exists to
	// arrange. The call site used to guard this with `!native_mode &&`, so
	// "succeeded" is exactly what it answered before.
	return true;
}

PgSQL_Connection::HandlerStep PgSQL_Connection_Native::on_connect_end() {
	// Nothing to do: native_connect_start() created the socket O_NONBLOCK, so
	// there is no PQsetnonblocking() handshake.
	return HandlerStep::CONTINUE;
}

void PgSQL_Connection_Native::on_connect_successful() {
	// Nothing to seed: native_connect_start() resolved the address through the
	// monitor's DNS cache, so that cache is already warm for the next connect.
}

void PgSQL_Connection_Native::on_connect_failed() {
	// Release the native socket/SCRAM state promptly. Some failure sub-paths
	// already teardown, but a generic failure may reach here with the fd still
	// open; native_teardown() sets fd=-1 so this is double-close safe.
	if (fd >= 0) {
		native_teardown();
	}
}

bool PgSQL_Connection_Native::defer_first_result_read() {
	return true;
}

PgSQL_Connection::HandlerStep PgSQL_Connection_Native::fetch_result_dispatch(short event, uint64_t* processed_bytes) {
	// --- Native simple-query / simple-command result fetch (Task 1.6c) ---
	// Stream raw backend messages directly into query_result. This fully
	// handles the native path and must NOT fall through to any libpq
	// PGresult dispatch.
	native_fetch_result_cont(event, processed_bytes);
	if (async_exit_status) {
		// Need more bytes from the socket -> wait for READ.
		next_event(ASYNC_USE_RESULT_CONT);
		return HandlerStep::YIELD;
	}
	if (native_result_complete || is_error_present()) {
		// ReadyForQuery consumed (result complete) or a fatal recv/frame
		// error: hand off to the end state (ASYNC_QUERY_END for queries,
		// or the configured fetch_result_end_st).
		return go(fetch_result_end_st);
	}
	// Enough bytes moved in this event: pause and let the client drain,
	// exactly as the libpq loop does, so pgsql-threshold_resultset_size
	// behaves the same on both paths.
	if (suspend_resultset_fetch(*processed_bytes)) {
		next_event(ASYNC_USE_RESULT_CONT); // we temporarily pause
		return HandlerStep::YIELD;
	}
	// Neither complete nor error nor waiting: loop to drain/recv more.
	return go(ASYNC_USE_RESULT_CONT);
}

void PgSQL_Connection_Native::on_command_end() {
	// Nothing: pgsql_conn is permanently NULL here, so there is no notice receiver
	// to install, and the native transport never enters libpq's pipeline mode.
}

bool PgSQL_Connection_Native::resync_already_synced() {
	// Always false, and it has to be. PQpipelineStatus(NULL) answers
	// PQ_PIPELINE_OFF, so asking here would let a connection that is still
	// mid-batch take the shortcut and be pooled.
	return false;
}

bool PgSQL_Connection_Native::resync_send_failed() {
	// A native send failure sets an error record, which is what the shared form
	// checks. (libpq reports the same thing with resync_failed and no record,
	// which is why the shared form is `resync_send_failed() || resync_failed`.)
	return is_error_present();
}

PgSQL_Connection::HandlerStep PgSQL_Connection_Native::reset_session_cont_dispatch() {
	// native_reset_session_cont() has already read and discarded the reply, and
	// nothing here ever enters pipeline mode, so libpq's PGresult and
	// reset_session_in_pipeline arms have no counterpart here -- get_result() has
	// nothing to return either, with pgsql_conn permanently NULL. The two arms
	// that remain are not libpq's: an open transaction still needs another pass to
	// roll it back, and otherwise the reset is finished. Both were in the shared
	// body and both have to keep advancing the state machine, so they are repeated
	// here rather than left to fall out of the case.
	if (reset_session_in_txn) {
		reset_session_in_txn = false;
		return go(ASYNC_RESET_SESSION_START);
	}
	return go(ASYNC_RESET_SESSION_END);
}

void PgSQL_Connection_Native::on_reset_session_end() {
	// No notice receiver to reinstall.
}

const char* PgSQL_Connection_Native::transport_name() const {
	return "native";
}

void PgSQL_Connection_Native::connect_start() {
	PROXY_TRACE();
	assert(pgsql_conn == NULL); // already there is a connection
	reset_error();
	async_exit_status = PG_EVENT_NONE;

		native_connect_start();
		return;
	}

void PgSQL_Connection_Native::connect_cont(short event) {
	PROXY_TRACE();
		// Native (non-libpq) backend connect + auth driver. Drives the
		// native_st sub-state machine and returns to the event loop; it never
		// falls through to the libpq path below.
		native_connect_cont(event);
		return;
	}

void PgSQL_Connection_Native::query_start() {
	PROXY_TRACE();
	reset_error();
	processing_multi_statement = false;
	async_exit_status = PG_EVENT_NONE;

		// Native simple-query path (Task 1.6c). Build a 'Q' (Query) message and
		// flush it non-blocking. The Query body is the SQL string INCLUDING a
		// trailing NUL terminator. The libpq path relies on query.ptr being
		// NUL-terminated (PQsendQuery reads to NUL); we build the body
		// defensively from query.length bytes + an explicit NUL so we never
		// depend on / read past the caller's terminator.
		native_result_complete = false;
		native_copy_intercepted = false;
		// A simple query is not an extended-query step: clear any stmt-step state left
		// on a pooled connection by a prior Parse/Describe/Execute so the native result
		// drain takes the plain 'Z'-terminated path, not the per-step path.
		native_stmt_step = PG_Native_Stmt_Step::NONE;
		native_stmt_sync_terminated = false;
		native_suppress_parse_complete = false;
		native_stmt_error_resync = false;
		native_result_had_notification = false;
		// A connection pinned by LISTEN can be holding the front of an asynchronous
		// message that arrived between queries; resetting here would drop those bytes and
		// the rest would then be read as a new message header. Empty is the normal case
		// for every other connection, so this still clears a stale framer.
		if (native_framer.empty()) native_framer.reset();
		native_outbuf.clear();
		// Body for the 'Q' (Query) message is the SQL text followed by EXACTLY ONE
		// NUL terminator, matching PQsendQuery() semantics. Callers are inconsistent
		// about whether query.length includes the terminator: the extended/simple
		// client-query path (async_query with pgsql_real_query.QuerySize) passes a
		// length that INCLUDES the trailing NUL, while async_send_simple_command
		// (e.g. init_connect via strlen()) does NOT. Emitting query.length bytes and
		// then appending a NUL therefore produces a malformed double-NUL body for
		// client queries, which the backend rejects with 08P01 "invalid message
		// format". Normalize by taking the SQL up to the first NUL (bounded by
		// query.length) and appending a single terminator.
		size_t sql_len = 0;
		if (query.ptr) { while (sql_len < query.length && query.ptr[sql_len] != '\0') sql_len++; }
		std::string qbody;
		if (sql_len) qbody.assign(query.ptr, sql_len);
		qbody.push_back('\0');
		pg_append_typed_msg(native_outbuf, 'Q', (const unsigned char*)qbody.data(), qbody.size());
		if (!native_send_or_buffer(PG_Native_Conn_St::DONE)) {
			// native_send_or_buffer drives native_st for the connect handshake; in
			// the query path we only care about the flush result. A false return
			// means a fatal send error.
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send(Query) failed", false);
			async_exit_status = PG_EVENT_NONE;
			return;
		}
		// If bytes remain buffered (plaintext native_outbuf or pending ciphertext),
		// we must wait for the socket to become writable before fetching the result.
		if (!native_outbuf.empty() || !native_ssl_outbuf.empty()) {
			async_exit_status = PG_EVENT_WRITE;
		} else {
			async_exit_status = PG_EVENT_NONE;
		}
		return;
	}

void PgSQL_Connection_Native::query_cont(short event) {
	PROXY_TRACE();
		// Native simple-query path (Task 1.6c): finish flushing the Query message.
		async_exit_status = PG_EVENT_NONE;
		if (!native_flush_outbuf()) {
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send(Query) failed", false);
			return;
		}
		if (!native_outbuf.empty() || !native_ssl_outbuf.empty()) {
			// Still bytes pending → keep waiting for writable.
			async_exit_status = PG_EVENT_WRITE;
		} else {
			// Fully sent → proceed to fetch the result (handler advances to
			// ASYNC_USE_RESULT_START with async_exit_status == PG_EVENT_NONE).
			async_exit_status = PG_EVENT_NONE;
		}
		return;
	}

void PgSQL_Connection_Native::fetch_result_cont(short event) {
	PROXY_TRACE();
		// Native result fetch is handled directly in the handler()
		// ASYNC_USE_RESULT_CONT case (via native_fetch_result_cont), which never
		// falls through to this libpq routine. Route here defensively so no
		// PQ*/PGresult code ever runs in native mode.
		native_fetch_result_cont(event);
		return;
	}


// Returns:
// 0 when the ping is completed successfully
// -1 when the ping is completed not successfully
// 1 when the ping is not completed
// -2 on timeout
// the calling function should check pgsql error in pgsql struct
int PgSQL_Connection_Native::async_ping(short event) {
	PROXY_TRACE();
	// In native_mode pgsql_conn is permanently NULL; the libpq ping path is
	// not applicable. Pretend the ping succeeded; the native path keeps its
	// own liveness state via the socket readiness callback.
		async_state_machine = ASYNC_PING_SUCCESSFUL;
		return 0;
	}

bool PgSQL_Connection_Native::IsKnownActiveTransaction() {
	// Callers use this to decide whether a failed statement can safely be run
	// again on a different connection. A connection that died in the middle of a
	// transaction must still say it has one, otherwise the statement would be
	// re-run on its own, outside that transaction. Do not add a liveness check
	// here -- the answer has to survive the connection dying.
		return native_txn_status == 'T' || native_txn_status == 'E';
	}

void PgSQL_Connection_Native::stmt_prepare_start() {
	PROXY_TRACE();
	reset_error();
	processing_multi_statement = false;
	async_exit_status = PG_EVENT_NONE;

		// Native Parse drive (Task C). Emit a 'P' (Parse) message with the same
		// backend statement name and parameter OIDs the libpq PQsendPrepare call
		// below uses, terminated by Flush or Sync per the EXACT flag logic the libpq
		// branch applies to PQsendFlushRequest vs PQsendPipelineSync.
		native_stmt_reset_step();
		const PgSQL_Extended_Query_Info* extended_query_info = query.extended_query_info;
		const Parse_Param_Types& parse_param_types = extended_query_info->parse_param_types;
		native_stmt_step = PG_Native_Stmt_Step::PARSE;
		// Implicit prepares carry no client Parse, so their ParseComplete '1' is
		// suppressed; real client Parses (cache-miss) forward their '1'.
		native_suppress_parse_complete =
			(extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_IMPLICIT_PREPARE) != 0;

		pg_build_parse(native_outbuf, query.backend_stmt_name, query.ptr,
			parse_param_types.data(),
			static_cast<uint16_t>(parse_param_types.size()));

		// Flush if this is not the last extended query message in the frame (or an
		// implicit prepare); otherwise Sync. Mirrors the libpq branch exactly.
		const bool use_flush =
			(extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_IMPLICIT_PREPARE) != 0 ||
			(extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_SYNC) == 0;
		if (use_flush) {
			pg_build_flush(native_outbuf);
		} else {
			pg_build_sync(native_outbuf);
		}
		native_stmt_sync_terminated = !use_flush;
		native_stmt_send_or_wait();
		return;
	}

void PgSQL_Connection_Native::stmt_prepare_cont(short event) {
	PROXY_TRACE();
		native_stmt_flush_cont();
		return;
	}

void PgSQL_Connection_Native::stmt_describe_start() {
	PROXY_TRACE();
	reset_error();
	processing_multi_statement = false;
	async_exit_status = PG_EVENT_NONE;

		// Native Describe drive (Task C). 'D' with kind 'S' (statement) or 'P'
		// (portal), matching the same statement-vs-portal branch libpq takes below.
		native_stmt_reset_step();
		const PgSQL_Extended_Query_Info* extended_query_info = query.extended_query_info;
		switch (extended_query_info->stmt_type) {
		case 'P': // Portal
			pg_build_describe(native_outbuf, 'P', extended_query_info->stmt_client_portal_name);
			native_stmt_step = PG_Native_Stmt_Step::DESCRIBE_P;
			break;
		case 'S': // Prepared statement
			pg_build_describe(native_outbuf, 'S', query.backend_stmt_name);
			native_stmt_step = PG_Native_Stmt_Step::DESCRIBE_S;
			break;
		default:
			set_error(PGSQL_ERROR_CODES::ERRCODE_INVALID_PARAMETER_VALUE, "Invalid statement type for describe", false);
			proxy_error("Failed to build describe message. %s\n", get_error_code_with_message().c_str());
			return;
		}
		const bool use_flush =
			(extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_SYNC) == 0;
		if (use_flush) {
			pg_build_flush(native_outbuf);
		} else {
			pg_build_sync(native_outbuf);
		}
		native_stmt_sync_terminated = !use_flush;
		native_stmt_send_or_wait();
		return;
	}

void PgSQL_Connection_Native::stmt_describe_cont(short event) {
	PROXY_TRACE();
		native_stmt_flush_cont();
		return;
	}

void PgSQL_Connection_Native::resync_start() {
	PROXY_TRACE();
	async_exit_status = PG_EVENT_NONE;

		// The client was already told this frame succeeded (a trailing message was
		// answered locally), so the batch is still open on the backend. Sending the
		// Sync concludes it -- the 'Z' clears native_unsynced_work.
		native_stmt_reset_step();
		native_stmt_step = PG_Native_Stmt_Step::RESYNC;
		native_stmt_sync_terminated = true;
		pg_build_sync(native_outbuf);
		native_stmt_send_or_wait();
		return;
	}

void PgSQL_Connection_Native::resync_cont(short event) {
	PROXY_TRACE();
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "event=%d\n", event);
		native_stmt_flush_cont();
		return;
	}

void PgSQL_Connection_Native::stmt_execute_cont(short event) {
	PROXY_TRACE();
		native_stmt_flush_cont();
		return;
	}

void PgSQL_Connection_Native::reset_session_start() {
	PROXY_TRACE();
		// Two commands, and the order is forced: the backend refuses DISCARD ALL while
		// a transaction is open, so an open one is rolled back first and DISCARD ALL
		// goes out on the next pass.
		reset_session_in_pipeline = false; // nothing here ever runs in pipeline mode
		reset_session_in_txn = IsKnownActiveTransaction();
		const char* cmd = (reset_session_in_txn == false ? "DISCARD ALL" : "ROLLBACK");
		set_query(cmd, strlen(cmd));
		query_start();
		if (async_exit_status == PG_EVENT_NONE && is_error_present() == false) {
			// Reached only when the whole command actually went out: query_start() asks
			// for writability instead if any of it is still buffered, and leaves an error
			// set if the send failed outright. Nothing is left to send, so what we wait
			// for is the reply. Say so, or the cycle finishes here without ever entering
			// ASYNC_RESET_SESSION_CONT -- taking the reset timeout, which lives in that
			// state, with it.
			async_exit_status = PG_EVENT_READ;
		}
		return;
	}

void PgSQL_Connection_Native::reset_session_cont(short event) {
	PROXY_TRACE();
		native_reset_session_cont();
		return;
	}

void PgSQL_Connection_Native::stmt_execute_start() {
	PROXY_TRACE();
	reset_error();
	processing_multi_statement = false;
	async_exit_status = PG_EVENT_NONE;

	if (bind_only) {
		// Native named-portal Bind drive (Task P1): emit ONLY a Bind on the CLIENT'S
		// named portal, terminated by Flush or Sync per the frame's SYNC flag. No
		// Execute and no Describe are folded in — Execute/Describe of a named portal
		// are separate client messages (routed by Task P2). The backend's real
		// BindComplete '2' is forwarded to the client (the session did NOT synthesize
		// one for named portals — see the BIND drain step). Params are decoded from the
		// registry-owned Bind message exactly as the unnamed Execute path below reads
		// them, preserving the client's per-param/per-result formats verbatim.
		native_stmt_reset_step();
		const PgSQL_Extended_Query_Info* extended_query_info = query.extended_query_info;
		const PgSQL_Bind_Message* bind_msg = extended_query_info->bind_msg;
		assert(bind_msg); // registry entry always carries the bind message
		const PgSQL_Bind_Data& bind_data = bind_msg->data();

		std::vector<const char*> param_values;
		std::vector<int32_t> param_lengths;
		std::vector<uint16_t> param_formats;
		std::vector<uint16_t> result_formats;

		if (bind_data.num_param_values > 0) {
			auto param_value_reader = bind_msg->get_param_value_reader();
			param_values.resize(bind_data.num_param_values);
			param_lengths.resize(bind_data.num_param_values);
			for (uint16_t i = 0; i < bind_data.num_param_values; ++i) {
				PgSQL_Param_Value param_val;
				if (!param_value_reader.next(&param_val)) {
					proxy_error("Failed to read param value at index %u\n", i);
					set_error(PGSQL_ERROR_CODES::ERRCODE_INVALID_PARAMETER_VALUE,
						"Failed to read param value", false);
					return;
				}
				param_values[i] = (param_val.len == -1) ? nullptr : reinterpret_cast<const char*>(param_val.value);
				param_lengths[i] = param_val.len;
			}
		}

		if (bind_data.num_param_formats > 0) {
			auto param_fmt_reader = bind_msg->get_param_format_reader();
			param_formats.resize(bind_data.num_param_formats);
			for (uint16_t i = 0; i < bind_data.num_param_formats; ++i) {
				uint16_t format;
				if (!param_fmt_reader.next(&format)) {
					proxy_error("Failed to read param format at index %u\n", i);
					set_error(PGSQL_ERROR_CODES::ERRCODE_INVALID_PARAMETER_VALUE,
						"Failed to read param format", false);
					return;
				}
				param_formats[i] = format; // 0 = text, 1 = binary
			}
		}

		if (bind_data.num_result_formats > 0) {
			auto result_fmt_reader = bind_msg->get_result_format_reader();
			result_formats.resize(bind_data.num_result_formats);
			for (uint16_t i = 0; i < bind_data.num_result_formats; ++i) {
				uint16_t format;
				if (!result_fmt_reader.next(&format)) {
					proxy_error("Failed to read result format at index %u\n", i);
					set_error(PGSQL_ERROR_CODES::ERRCODE_INVALID_PARAMETER_VALUE,
						"Failed to read result format", false);
					return;
				}
				result_formats[i] = format;
			}
		}

		pg_build_bind(native_outbuf, extended_query_info->stmt_client_portal_name, query.backend_stmt_name,
			param_formats.empty() ? nullptr : param_formats.data(),
			static_cast<uint16_t>(param_formats.size()),
			param_values.empty() ? nullptr : param_values.data(),
			param_lengths.empty() ? nullptr : param_lengths.data(),
			static_cast<uint16_t>(param_values.size()),
			result_formats.empty() ? nullptr : result_formats.data(),
			static_cast<uint16_t>(result_formats.size()));

		const bool use_flush =
			(extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_SYNC) == 0;
		if (use_flush) {
			pg_build_flush(native_outbuf);
		} else {
			pg_build_sync(native_outbuf);
		}
		native_stmt_sync_terminated = !use_flush;
		native_stmt_step = PG_Native_Stmt_Step::BIND;
		native_stmt_send_or_wait();
		return;
	}

	if (close_only) {
		// Native named-portal Close drive (Task P2): emit ONLY a Close('P', portal) on
		// the client's named portal, terminated by Flush or Sync per the frame's SYNC
		// flag. No Bind/Execute. The backend's real CloseComplete '3' is forwarded to
		// the client (unnamed Close is synthesized locally in the session; only named
		// Close round-trips). PostgreSQL emits CloseComplete even when the portal does
		// not exist (Close is idempotent), so the session evicts unconditionally on rc0.
		native_stmt_reset_step();
		const PgSQL_Extended_Query_Info* eqi = query.extended_query_info;
		pg_build_close(native_outbuf, 'P', eqi->stmt_client_portal_name);
		const bool use_flush =
			(eqi->flags & PGSQL_EXTENDED_QUERY_FLAG_SYNC) == 0;
		if (use_flush) {
			pg_build_flush(native_outbuf);
		} else {
			pg_build_sync(native_outbuf);
		}
		native_stmt_sync_terminated = !use_flush;
		native_stmt_step = PG_Native_Stmt_Step::CLOSE_P;
		native_stmt_send_or_wait();
		return;
	}

	if (
		(query.extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_PORTAL_ALREADY_BOUND) != 0) {
		// Native named-portal Execute / resume drive (Task P2): the portal is ALREADY
		// bound on the backend (a prior named Bind registered it), so emit ONLY
		// Execute(portal, max_rows) — NO Bind. A Describe('P', portal) is folded in
		// first exactly when the client asked for the portal's RowDescription
		// (PGSQL_EXTENDED_QUERY_FLAG_DESCRIBE_PORTAL, set by the Describe->Execute peek).
		// max_rows is honored on the wire for NAMED portals only (the unnamed path below
		// always emits 0 — invariant 2). A resume Execute after PortalSuspended is just
		// another Execute on the same portal and takes this same path.
		native_stmt_reset_step();
		const PgSQL_Extended_Query_Info* eqi = query.extended_query_info;
		if ((eqi->flags & PGSQL_EXTENDED_QUERY_FLAG_DESCRIBE_PORTAL) != 0) {
			pg_build_describe(native_outbuf, 'P', eqi->stmt_client_portal_name);
		}
		pg_build_execute(native_outbuf, eqi->stmt_client_portal_name, eqi->max_rows);
		const bool use_flush =
			(eqi->flags & PGSQL_EXTENDED_QUERY_FLAG_SYNC) == 0;
		if (use_flush) {
			pg_build_flush(native_outbuf);
		} else {
			pg_build_sync(native_outbuf);
		}
		native_stmt_sync_terminated = !use_flush;
		native_stmt_step = PG_Native_Stmt_Step::EXECUTE;
		native_stmt_send_or_wait();
		return;
	}

		// Native Execute drive (Task C): Bind [+ Describe('P')] + Execute + Flush/Sync
		// on the unnamed portal. Decodes the client's Bind params from the SAME parsed
		// PgSQL_Bind_Message the libpq PQsendQueryPrepared branch below reads, but hands
		// them to pg_build_bind preserving the client's per-param/per-result formats
		// verbatim (protocol-native). Unlike the libpq branch, we do NOT expand a single
		// param format across all params, and we forward ALL result formats faithfully
		// (libpq mode collapses result formats to result_formats[0]; corpus clients use
		// uniform formats, so the differential is unaffected).
		native_stmt_reset_step();
		const PgSQL_Extended_Query_Info* extended_query_info = query.extended_query_info;
		const PgSQL_Bind_Message* bind_msg = extended_query_info->bind_msg;
		assert(bind_msg); // should never be null
		const PgSQL_Bind_Data& bind_data = bind_msg->data();

		std::vector<const char*> param_values;
		std::vector<int32_t> param_lengths;
		std::vector<uint16_t> param_formats;
		std::vector<uint16_t> result_formats;

		if (bind_data.num_param_values > 0) {
			auto param_value_reader = bind_msg->get_param_value_reader();
			param_values.resize(bind_data.num_param_values);
			param_lengths.resize(bind_data.num_param_values);
			for (uint16_t i = 0; i < bind_data.num_param_values; ++i) {
				PgSQL_Param_Value param_val;
				if (!param_value_reader.next(&param_val)) {
					proxy_error("Failed to read param value at index %u\n", i);
					set_error(PGSQL_ERROR_CODES::ERRCODE_INVALID_PARAMETER_VALUE,
						"Failed to read param value", false);
					return;
				}
				// NULL => value pointer nullptr + length -1 (pg_build_bind emits length
				// -1 with no bytes); empty/non-empty => real pointer + byte length.
				param_values[i] = (param_val.len == -1) ? nullptr : reinterpret_cast<const char*>(param_val.value);
				param_lengths[i] = param_val.len;
			}
		}

		if (bind_data.num_param_formats > 0) {
			auto param_fmt_reader = bind_msg->get_param_format_reader();
			param_formats.resize(bind_data.num_param_formats);
			for (uint16_t i = 0; i < bind_data.num_param_formats; ++i) {
				uint16_t format;
				if (!param_fmt_reader.next(&format)) {
					proxy_error("Failed to read param format at index %u\n", i);
					set_error(PGSQL_ERROR_CODES::ERRCODE_INVALID_PARAMETER_VALUE,
						"Failed to read param format", false);
					return;
				}
				param_formats[i] = format; // 0 = text, 1 = binary
			}
		}

		if (bind_data.num_result_formats > 0) {
			auto result_fmt_reader = bind_msg->get_result_format_reader();
			result_formats.resize(bind_data.num_result_formats);
			for (uint16_t i = 0; i < bind_data.num_result_formats; ++i) {
				uint16_t format;
				if (!result_fmt_reader.next(&format)) {
					proxy_error("Failed to read result format at index %u\n", i);
					set_error(PGSQL_ERROR_CODES::ERRCODE_INVALID_PARAMETER_VALUE,
						"Failed to read result format", false);
					return;
				}
				result_formats[i] = format;
			}
		}

		pg_build_bind(native_outbuf, "", query.backend_stmt_name,
			param_formats.empty() ? nullptr : param_formats.data(),
			static_cast<uint16_t>(param_formats.size()),
			param_values.empty() ? nullptr : param_values.data(),
			param_lengths.empty() ? nullptr : param_lengths.data(),
			static_cast<uint16_t>(param_values.size()),
			result_formats.empty() ? nullptr : result_formats.data(),
			static_cast<uint16_t>(result_formats.size()));

		// Fold in a Describe('P') on the unnamed portal exactly when the libpq path
		// would forward the portal's RowDescription — i.e. when the client asked for
		// it (recorded as PGSQL_EXTENDED_QUERY_FLAG_DESCRIBE_PORTAL). When it did not,
		// no Describe is sent, the backend emits no 'T'/'n', and the client sees only
		// '2'(suppressed)/'D'*/'C' — byte-identical to the libpq path, which sends the
		// Describe but does not forward the RowDescription.
		if ((extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_DESCRIBE_PORTAL) != 0) {
			pg_build_describe(native_outbuf, 'P', "");
		}

		pg_build_execute(native_outbuf, "", 0); // unnamed portal, max_rows 0 (parity phase)

		const bool use_flush =
			(extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_SYNC) == 0;
		if (use_flush) {
			pg_build_flush(native_outbuf);
		} else {
			pg_build_sync(native_outbuf);
		}
		native_stmt_sync_terminated = !use_flush;
		native_stmt_step = PG_Native_Stmt_Step::EXECUTE;
		native_stmt_send_or_wait();
		return;
	}

const char* PgSQL_Connection_Native::get_pg_backend_state() const {
	// A native snapshot is a follow-up (see the split plan); the shared
	// body asked libpq with a NULL pgsql_conn and answered "disconnected".
	return "disconnected";
}

int PgSQL_Connection_Native::get_pg_ssl_in_use() {
	return (native_ssl != nullptr) ? 1 : 0;
}

SSL* PgSQL_Connection_Native::get_pg_ssl_object() {
	return native_ssl;
}

int PgSQL_Connection_Native::get_pg_server_version() {
	auto it = native_params.find("server_version");
	if (it == native_params.end()) return 0;
	// PostgreSQL changed the numeric version encoding at 10: major*10000 + minor
	// from 10 onwards, major*10000 + minor*100 + revision before it.
	int vmaj = 0, vmin = 0, vrev = 0;
	const int cnt = sscanf(it->second.c_str(), "%d.%d.%d", &vmaj, &vmin, &vrev);
	// The backend controls this string; the multiplies below overflow int for
	// absurd values, so anything implausible is reported as unknown.
	if (vmaj < 0 || vmaj > 9999 || vmin < 0 || vmin > 9999 || vrev < 0 || vrev > 9999) return 0;
	if (cnt == 3) return (100 * vmaj + vmin) * 100 + vrev;
	if (cnt == 2) return (vmaj >= 10) ? (100 * 100 * vmaj + vmin) : ((100 * vmaj + vmin) * 100);
	if (cnt == 1) return 100 * 100 * vmaj;
	return 0;
}

int PgSQL_Connection_Native::get_pg_protocol_version() {
	return 3;
}

const char* PgSQL_Connection_Native::get_pg_host() {
	return native_host.c_str();
}

const char* PgSQL_Connection_Native::get_pg_hostaddr() {
	return native_hostaddr.c_str();
}

const char* PgSQL_Connection_Native::get_pg_port() {
	return native_port.c_str();
}

const char* PgSQL_Connection_Native::get_pg_dbname() {
	return (userinfo ? userinfo->dbname : "");
}

const char* PgSQL_Connection_Native::get_pg_user() {
	return (userinfo ? userinfo->username : "");
}

const char* PgSQL_Connection_Native::get_pg_password() {
	return (userinfo && userinfo->password ? userinfo->password : "");
}

const char* PgSQL_Connection_Native::get_pg_options() {
	return native_options.c_str();
}

int PgSQL_Connection_Native::get_pg_socket_fd() {
	return fd;
}

int PgSQL_Connection_Native::get_pg_backend_pid() {
	return native_backend_pid;
}

int PgSQL_Connection_Native::get_pg_client_encoding() {
	constexpr int SQL_ASCII = 0;   // PG_SQL_ASCII; mb/pg_wchar.h is not included here
	auto it = native_params.find("client_encoding");
	if (it == native_params.end()) return SQL_ASCII;
	const int enc = char_to_encoding(it->second.c_str());
	return (enc < 0) ? SQL_ASCII : enc;
}

ConnStatusType PgSQL_Connection_Native::get_pg_connection_status() const {
	return backend_is_live() ? CONNECTION_OK : CONNECTION_BAD;
}

char PgSQL_Connection_Native::last_ready_for_query_status() const {
	return native_txn_status;
}

bool PgSQL_Connection_Native::needs_pollout() const {
	if (native_ssl_block_dir) return native_ssl_block_dir == PG_EVENT_WRITE;
	return (async_exit_status & PG_EVENT_WRITE) != 0;
}

int PgSQL_Connection_Native::get_pg_is_nonblocking() {
	return 1;
}

const char* PgSQL_Connection_Native::get_pg_error_message() {
	return (error_info.message.empty() ? "" : error_info.message.c_str());
}

const char* PgSQL_Connection_Native::get_pg_parameter_status(const char* param) {
	if (param == nullptr) return nullptr;
	auto it = native_params.find(param);
	return it == native_params.end() ? nullptr : it->second.c_str();
}

PGTransactionStatusType PgSQL_Connection_Native::transport_transaction_status() const {
	switch (native_txn_status) {
		case 'I': return PQTRANS_IDLE;
		case 'T': return PQTRANS_INTRANS;
		case 'E': return PQTRANS_INERROR;
		default:  return PQTRANS_UNKNOWN;
	}
}

int PgSQL_Connection_Native::get_backend_pid() {
	return native_backend_pid;
}

bool PgSQL_Connection_Native::is_pipeline_active() {
	return native_unsynced_work;
}

bool PgSQL_Connection_Native::transport_blocks_reuse() const {
	// Not-connected and mid-batch answers are native-only: libpq reports both
	// through PQstatus()/the transaction status, which the shared tail reads.
	return !backend_is_live() || native_unsynced_work;
}

bool PgSQL_Connection_Native::last_execute_suspended() const {
	return native_last_execute_suspended;
}

bool PgSQL_Connection_Native::result_had_notification() const {
	return native_result_had_notification;
}

int PgSQL_Connection_Native::relay_async_messages(PtrSizeArray* out) {
	return native_relay_async_messages(out);
}
