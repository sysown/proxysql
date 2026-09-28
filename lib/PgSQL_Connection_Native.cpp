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
	// Was `assert(pgsql_conn == NULL); // already there is a connection`. Step 5b moved
	// the handle into PgSQL_Connection_LibPQ and made get_pg_connection() a pure virtual
	// that answers nullptr here, so the same fact is now true by construction rather
	// than by an assertion: there is no member on this object for a handle to live in.
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

void PgSQL_Connection_Native::note_ready_for_query(char st) {
	// The two writes that were inline in the base's set_ready_for_query_status().
	// The base validates the byte around this call and keeps the judgement; only the
	// storage is ours. native_unsynced_work clears here and nowhere else, because a
	// ReadyForQuery is the only thing that ends a batch the backend still owes us on.
	native_txn_status = st;
	native_unsynced_work = false;
}

void PgSQL_Connection_Native::native_backend_key(int& pid, int& secret) const {
	// Captured from BackendKeyData during the startup tail. The kill path reaches
	// this only under `if (native_mode)`, and a native connection is always this
	// class, so the cast is an identity cast.
	pid = native_backend_pid;
	secret = native_backend_secret;
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


// --- File-local helpers the moved bodies below need -----------------
// These were static helpers at the top of PgSQL_Connection.cpp. Nothing in the
// base uses either of them -- the two big-endian reads serve the auth and
// startup-tail state machines, and the legality check guards the result
// drain -- so they came along with the code rather than staying behind.

static inline uint32_t pg_read_be32(const unsigned char* p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

// The message types a query reply is allowed to carry:
//   1 ParseComplete  2 BindComplete  3 CloseComplete  n NoData  s PortalSuspended
//   t ParameterDescription  T RowDescription  D DataRow  C CommandComplete
//   I EmptyQueryResponse  E ErrorResponse  N NoticeResponse  S ParameterStatus
//   H CopyOutResponse  d CopyData  c CopyDone  Z ReadyForQuery  A NotificationResponse
// Everything else belongs to the startup phase or to no phase at all. The native
// path copies backend bytes to the client verbatim, so without this check a
// backend could put an AuthenticationRequest ('R') in the middle of a result set
// and the client would prompt its user for a password -- and the whole byte
// stream, injected message included, is eligible for the query cache and would be
// replayed to later clients. 'G'/'W' are deliberately absent: the CopyInResponse
// safety net answers those earlier, so one arriving here means the stream is out
// of step and the connection should go.
// 'A' stays legal here because a NotificationResponse is a real message, not a sign of a
// hostile backend. The drain loop discards it a few lines further on, so a connection
// that carries one is kept instead of being thrown away as a protocol violation.
static inline bool pg_native_type_legal_in_result(char t) {
	switch (t) {
		case '1': case '2': case '3': case 'n': case 's': case 't':
		case 'T': case 'D': case 'C': case 'I': case 'E': case 'N':
		case 'S': case 'H': case 'd': case 'c': case 'Z': case 'A':
			return true;
		default:
			return false;
	}
}

// ============================================================
// Native handshake, auth, TLS and result-drive implementations
// (moved from PgSQL_Connection.cpp in step 5a-ii)
//
// These bodies are private to this leaf. Nothing in the base calls any of
// them, so they needed no virtual hook to move -- which is the property that
// made this half of the split a relocation rather than a rewrite.
// ============================================================
// ---- native_ssl_pump_wbio_to_fd ----

// Flush native_outbuf via non-blocking send(). Consumes the bytes that were
// written; on EAGAIN leaves the remainder buffered and returns true (caller must
// keep waiting for writable). Returns false on a fatal socket error.
// Drain native_ssl_outbuf (pending raw ciphertext) to the fd. On EAGAIN leaves the
// remainder buffered and sets would_block=true. Returns false only on a fatal error.
bool PgSQL_Connection_Native::native_ssl_pump_wbio_to_fd(bool& would_block) {
	would_block = false;
	// First, pull any freshly produced ciphertext out of wbio into native_ssl_outbuf.
	char buf[MY_SSL_BUFFER];
	for (;;) {
		int n = BIO_read(native_wbio, buf, sizeof(buf));
		if (n > 0) {
			native_ssl_outbuf.append(buf, (size_t)n);
			continue;
		}
		// No more bytes pending; BIO_should_retry distinguishes empty from error.
		if (!BIO_should_retry(native_wbio)) {
			// For a mem BIO an "empty" read also returns !should_retry; that is normal.
		}
		break;
	}
	// Now flush native_ssl_outbuf to the socket.
	while (!native_ssl_outbuf.empty()) {
		ssize_t n = ::send(fd, native_ssl_outbuf.data(), native_ssl_outbuf.size(), 0);
		if (n > 0) {
			native_ssl_outbuf.erase(0, (size_t)n);
			continue;
		}
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			would_block = true;
			return true; // partial: keep the rest buffered, wait for writable
		}
		if (n < 0 && errno == EINTR) {
			continue;
		}
		return false; // fatal
	}
	return true;
}

// ---- native_flush_outbuf ----

bool PgSQL_Connection_Native::native_flush_outbuf() {
	native_ssl_block_dir = 0;
	// Encrypted path: native_outbuf holds *plaintext* protocol bytes. Feed them to
	// SSL_write, which produces ciphertext into wbio_ssl, then drain wbio to the fd.
	if (native_ssl != nullptr) {
		// If there is leftover ciphertext from a previous partial socket write, flush
		// it first before producing more (preserves ordering).
		if (!native_ssl_outbuf.empty()) {
			bool wb = false;
			if (!native_ssl_pump_wbio_to_fd(wb)) return false;
			if (wb) return true; // still can't drain; wait for writable
		}
		while (!native_outbuf.empty()) {
			ERR_clear_error();
			int w = SSL_write(native_ssl, native_outbuf.data(), (int)native_outbuf.size());
			if (w > 0) {
				native_outbuf.erase(0, (size_t)w);
				bool wb = false;
				if (!native_ssl_pump_wbio_to_fd(wb)) return false;
				if (wb) return true; // socket full; remaining plaintext stays buffered
				continue;
			}
			int err = SSL_get_error(native_ssl, w);
			if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
				// SSL needs to do I/O before it can accept more plaintext. Drain
				// whatever ciphertext it produced and wait for the socket.
				// WANT_READ means the socket being writable is not what we are waiting for --
				// it already is, so asking to be woken on that alone spins the thread.
				native_ssl_block_dir = (err == SSL_ERROR_WANT_READ) ? PG_EVENT_READ : PG_EVENT_WRITE;
				bool wb = false;
				if (!native_ssl_pump_wbio_to_fd(wb)) return false;
				return true; // not fatal; resume on next event
			}
			// SSL_ERROR_SYSCALL / SSL / ZERO_RETURN -> fatal
			while (ERR_get_error()) { /* drain */ }
			return false;
		}
		// All plaintext consumed; make sure any trailing ciphertext is flushed.
		bool wb = false;
		if (!native_ssl_pump_wbio_to_fd(wb)) return false;
		return true;
	}

	// Plaintext path (1.6a): native_outbuf holds raw bytes for the socket.
	while (!native_outbuf.empty()) {
		ssize_t n = ::send(fd, native_outbuf.data(), native_outbuf.size(), 0);
		if (n > 0) {
			native_outbuf.erase(0, (size_t)n);
			continue;
		}
		if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			return true; // partial send: keep the rest buffered, wait for writable
		}
		if (n < 0 && errno == EINTR) {
			continue;
		}
		// fatal
		return false;
	}
	return true;
}

// ---- native_result_fatal ----

// A fatal error during the RESULT phase kills the CONNECTION, not just the query,
// so the socket must be torn down and not merely flagged.
//
// Two kinds of exit reach here and both are unrecoverable for the connection:
//   * CONNECTION_FAILURE -- the peer closed, or a send()/recv() failed outright.
//   * PROTOCOL_VIOLATION -- the byte stream is desynchronised. We no longer know
//     where the next message begins, so nothing can ever be read from it safely
//     again, even though the socket is still technically open.
//
// Closing the socket here is what marks the connection as unusable, so it gets
// thrown away instead of going back into the pool.
//
// The auth and startup phases already do this -- their "backend closed during
// auth" / "during startup" exits call native_teardown() -- the result phase simply
// never did, on any of its exits.
void PgSQL_Connection_Native::native_result_fatal(const char* code, const char* message) {
	set_error(code, message, false);
	native_teardown();
}

// ---- native_result_protocol_violation ----

void PgSQL_Connection_Native::native_result_protocol_violation(const char* message) {
	set_error(PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION, message, false);
	reusable = false;
	healthy = false;
	if (myds && myds->sess) {
		myds->sess->set_unhealthy();
	}
	// Finish the result before handing it back. Rows already framed are flushed first so the
	// error lands behind them rather than in front, and the ReadyForQuery closes the cycle.
	// Report a failed transaction block if the client had one open, because the batch it was
	// in is over.
	if (query_result) {
		query_result->buffer_to_PSarrayOut();
		query_result->add_error(NULL);
		query_result->add_ready_status(
			(native_txn_status == 'T' || native_txn_status == 'E')
				? PQTRANS_INERROR : PQTRANS_IDLE);
	}
	// The backend owes us nothing further: the cycle is over as far as this connection goes.
	native_unsynced_work = false;
}

// ---- native_teardown ----

void PgSQL_Connection_Native::native_teardown() {
	if (native_scram) {
		pg_scram_free(native_scram);
		native_scram = nullptr;
	}
	// Not cleared here. The backend never sent the ReadyForQuery that ends the batch, so its
	// outcome is unknown; clearing it would let the retry check replay work already committed.
	if (fd >= 0) {
		::close(fd);
		fd = -1;
	}
	// Drop this connection from the count of connected backends. The check makes
	// sure we only subtract if we added in the first place, so a teardown followed
	// by the destructor still subtracts exactly once.
	if (counted_in_connections_connected) {
		__sync_fetch_and_sub(&PgHGM->status.server_connections_connected, 1);
		counted_in_connections_connected = false;
	}
	native_connected = false;
	native_framer.reset();
	native_outbuf.clear();
	native_ssl_outbuf.clear();
	// The TLS session belongs to this connection (see PgSQL_Connection.h), so we
	// free it here. SSL_set_bio() transferred both BIOs to the SSL, so SSL_free()
	// releases all three; freeing the BIOs separately would be a double free. It
	// uses mem BIOs, so SSL_free()'s shutdown writes harmlessly into a mem buffer
	// even though the fd is already closed.
	//
	// This runs only on REAL teardown. A pool return must never reach here -- that
	// was precisely finding A7, where the TLS context was destroyed while the
	// socket stayed open and pooled.
	if (native_ssl) {
		SSL_free(native_ssl);
		native_ssl  = nullptr;
		native_rbio = nullptr;
		native_wbio = nullptr;
	}
	if (native_ssl_ctx) {
		SSL_CTX_free(native_ssl_ctx);
		native_ssl_ctx = nullptr;
	}
	// The connect handshake must not resume: its steps read what was just freed, and the TLS
	// step dereferences the BIOs that went with the SSL. connect_cont() does get called again
	// on a connection the session is still holding, when the connect timeout expires.
	native_st = PG_Native_Conn_St::FAILED;
}

// ---- native_connect_start ----

void PgSQL_Connection_Native::native_connect_start() {
	// Resolve the backend address. Prefer the DNS cache (non-blocking); fall back
	// to the literal parent->address (which may itself be an IP literal).
	std::string ip = connect_start_DNS_lookup();
	const char* host = (!ip.empty()) ? ip.c_str() : parent->address;

	// getaddrinfo on a numeric host with AI_NUMERICHOST does not block. The DNS
	// cache returns numeric IPs; if it missed and parent->address is a hostname,
	// fall back to a (potentially blocking) resolve — acceptable as the pool
	// connect path already tolerates this and 1.8 validates against real backends.
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if (!ip.empty()) {
		hints.ai_flags = AI_NUMERICHOST;
	}
	char portstr[16];
	snprintf(portstr, sizeof(portstr), "%u", (unsigned)parent->port);

	struct addrinfo* res = nullptr;
	int gai = getaddrinfo(host, portstr, &hints, &res);
	if (gai != 0 || res == nullptr) {
		set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE),
			gai_strerror(gai), false);
		proxy_error("Native connect: getaddrinfo(%s:%s) failed: %s\n", host, portstr, gai_strerror(gai));
		if (res) freeaddrinfo(res);
		async_exit_status = PG_EVENT_NONE; // error present -> handler moves to FAILED
		return;
	}

	int sock = -1;
	for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
		sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0) continue;
		// non-blocking
		int fl = fcntl(sock, F_GETFL, 0);
		if (fl < 0 || fcntl(sock, F_SETFL, fl | O_NONBLOCK) < 0) {
			::close(sock); sock = -1; continue;
		}
		{ int one = 1; setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)); }
		int rc = ::connect(sock, ai->ai_addr, ai->ai_addrlen);
		if (rc == 0 || errno == EINPROGRESS || errno == EWOULDBLOCK || errno == EINTR) {
			break; // connect in progress (or immediately done)
		}
		::close(sock); sock = -1;
	}
	freeaddrinfo(res);

	if (sock < 0) {
		set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE),
			"native connect() failed", false);
		proxy_error("Native connect: socket/connect to %s:%s failed: %s\n", host, portstr, strerror(errno));
		async_exit_status = PG_EVENT_NONE;
		return;
	}

	this->fd = sock;
	native_host = parent->address ? parent->address : "";
	// Mirror the libpq path's rule for `hostaddr` (connect_start(): passed only when
	// the DNS cache resolved something DIFFERENT from parent->address) so that both
	// paths report the same value for the same server configuration.
	native_hostaddr = (!ip.empty() && parent->address && ip != std::string(parent->address)) ? ip : "";
	native_port = portstr;
	native_st = PG_Native_Conn_St::TCP_CONNECTING;
	native_framer.reset();
	native_outbuf.clear();
	native_ssl_outbuf.clear();
	native_connected = false;
	// Cleared here rather than in teardown, so a reconnect on this object starts clean.
	native_unsynced_work = false;

	// Decide whether this backend wants TLS, and with which verification policy.
	// The SSL param source is the SAME as the libpq path (get_Server_SSL_Params /
	// the pgsql_thread___ssl_p2s_* fallbacks). There is currently no per-server
	// `sslmode` column: the libpq path uses sslmode='require' whenever use_ssl is
	// set (encryption WITHOUT certificate verification), so to MATCH libpq exactly
	// the native default is REQUIRE (SSL_VERIFY_NONE). VERIFY_CA / VERIFY_FULL are
	// implemented and wired through native_create_client_ssl_ctx(); they are not
	// selectable until a config knob is added (flagged for Task 1.8). We never
	// default to a *weaker* policy than the config asks for.
	native_ssl_requested = (parent->use_ssl != 0);
	native_ssl_mode = native_ssl_requested
		? PG_Native_SSL_Mode::REQUIRE
		: PG_Native_SSL_Mode::DISABLE;

	// wait for writable = TCP connect completion
	async_exit_status = PG_EVENT_WRITE;
}

// ---- native_connect_cont ----

void PgSQL_Connection_Native::native_connect_cont(short event) {
	reset_error();
	async_exit_status = PG_EVENT_NONE;

	switch (native_st) {
	case PG_Native_Conn_St::TCP_CONNECTING: {
		// Verify the non-blocking connect() completed successfully.
		int soerr = 0;
		socklen_t slen = sizeof(soerr);
		if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0 || soerr != 0) {
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE),
				soerr ? strerror(soerr) : "connect failed", false);
			proxy_error("Native connect: TCP connect to %s:%d failed: %s\n",
				parent->address, parent->port, strerror(soerr));
			native_teardown();
			return; // error present -> handler -> ASYNC_CONNECT_FAILED
		}
		if (native_ssl_requested) {
			// TLS path: negotiate SSLRequest BEFORE the StartupMessage. Send the
			// 8-byte SSLRequest, then read the single-byte 'S'/'N' reply.
			unsigned char req[8];
			pg_build_ssl_request(req);
			native_outbuf.assign((const char*)req, sizeof(req));
			if (!native_send_or_buffer(PG_Native_Conn_St::SSL_READ_REPLY)) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send(SSLRequest) failed", false);
				native_teardown();
				return;
			}
			// native_send_or_buffer set native_st (SSL_READ_REPLY or SEND_STARTUP
			// to flush the rest) and async_exit_status. Note: the SSLRequest is sent
			// in the clear; encryption begins only after the handshake completes.
			return;
		}
		// Plaintext path (1.6a): send the StartupMessage immediately.
		if (!native_send_startup()) {
			native_teardown();
			return;
		}
		return;
	}

	case PG_Native_Conn_St::SSL_READ_REPLY: {
		// The SSLRequest reply is exactly one byte, sent in the clear: 'S' = server
		// accepts SSL, 'N' = server refuses. Read it raw from the fd.
		unsigned char reply = 0;
		ssize_t n = ::recv(fd, &reply, 1, 0);
		if (n == 0) {
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "backend closed during SSLRequest", false);
			native_teardown();
			return;
		}
		if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				async_exit_status = PG_EVENT_READ;
				return;
			}
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "recv(SSLRequest reply) failed", false);
			native_teardown();
			return;
		}
		if (reply == 'S') {
			// Server accepts SSL: set up the client SSL object and begin the handshake.
			if (!native_create_client_ssl_ctx()) {
				// error_info already set; ctx creation failure is a real error.
				native_teardown();
				return;
			}
			native_ssl = SSL_new(native_ssl_ctx);
			if (native_ssl == nullptr) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "SSL_new() failed", false);
				native_teardown();
				return;
			}
			// The SSL holds a reference to the ctx now; drop our ctx reference so we
			// never leak it (teardown's SSL_CTX_free becomes a no-op after this).
			SSL_CTX_free(native_ssl_ctx);
			native_ssl_ctx = nullptr;

			SSL_set_connect_state(native_ssl); // client role
			// verify-full: enforce hostname verification at the TLS layer.
			if (native_ssl_mode == PG_Native_SSL_Mode::VERIFY_FULL) {
				const char* host = (parent->address && parent->address[0]) ? parent->address : native_host.c_str();
				X509_VERIFY_PARAM* vp = SSL_get0_param(native_ssl);
				X509_VERIFY_PARAM_set_hostflags(vp, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
				if (X509_VERIFY_PARAM_set1_host(vp, host, 0) != 1) {
					set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "failed to set TLS verify host", false);
					native_teardown();
					return;
				}
			}
			// SNI: present the backend hostname (best-effort; ignored for IP literals).
			if (parent->address && parent->address[0]) {
				SSL_set_tlsext_host_name(native_ssl, parent->address);
			}
			native_rbio = BIO_new(BIO_s_mem());
			native_wbio = BIO_new(BIO_s_mem());
			if (native_rbio == nullptr || native_wbio == nullptr) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_OUT_OF_MEMORY), "BIO_new() failed", false);
				// Free them HERE, not via native_teardown(). Ownership passes to the
				// SSL only at SSL_set_bio() below, which has not run yet -- so
				// teardown's SSL_free(native_ssl) would not release them and the one
				// that DID allocate would leak. Teardown nulls the pointers, so it
				// cannot clean up after us either.
				if (native_rbio) { BIO_free(native_rbio); native_rbio = nullptr; }
				if (native_wbio) { BIO_free(native_wbio); native_wbio = nullptr; }
				native_teardown();
				return;
			}
			SSL_set_bio(native_ssl, native_rbio, native_wbio);
			native_st = PG_Native_Conn_St::SSL_HANDSHAKE;
			// Kick the handshake immediately (it will emit ClientHello into wbio).
			native_connect_cont(event);
			return;
		}
		if (reply == 'N') {
			// Server refuses SSL. Honor the configured policy:
			//  - REQUIRE / VERIFY_CA / VERIFY_FULL: SSL is mandatory -> hard error.
			//    (We never silently downgrade to plaintext when SSL was required.)
			//  - (allow/prefer would fall back to plaintext here, but those modes are
			//    not currently selectable; use_ssl=1 always maps to REQUIRE.)
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE),
				"server does not support SSL, but SSL was required", false);
			proxy_error("Native connect: backend %s:%d refused SSL (SSLRequest -> 'N'); SSL is required\n",
				parent->address, parent->port);
			native_teardown();
			return;
		}
		// Any other byte is a protocol violation (or a pre-auth ErrorResponse 'E',
		// which a server emits e.g. when it cannot fork a backend). Treat as fatal.
		set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_PROTOCOL_VIOLATION),
			"unexpected SSLRequest reply byte", false);
		proxy_error("Native connect: backend %s:%d returned unexpected SSLRequest reply 0x%02x\n",
			parent->address, parent->port, reply);
		native_teardown();
		return;
	}

	case PG_Native_Conn_St::SSL_HANDSHAKE: {
		int hs = native_drive_ssl_handshake();
		if (hs < 0) {
			// error_info + teardown already done inside the helper.
			return;
		}
		if (hs == 0) {
			// async_exit_status already set (WANT_READ/WANT_WRITE). Wait.
			return;
		}
		// Handshake complete -> send the StartupMessage, now over TLS.
		if (!native_send_startup()) {
			native_teardown();
			return;
		}
		return;
	}

	case PG_Native_Conn_St::SEND_STARTUP: {
		// Flushing a previously partial outbound buffer (startup or a password msg).
		if (!native_flush_outbuf()) {
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send() failed", false);
			native_teardown();
			return;
		}
		if (!native_outbuf.empty() || !native_ssl_outbuf.empty()) { async_exit_status = PG_EVENT_WRITE; return; }
		// Drained: resume where the partial send left off (always a READ wait).
		native_st = native_st_after_send;
		async_exit_status = PG_EVENT_READ;
		return;
	}

	case PG_Native_Conn_St::AUTH:
		native_drive_auth(event);
		return;

	case PG_Native_Conn_St::STARTUP_TAIL:
		native_drive_startup_tail(event);
		return;

	case PG_Native_Conn_St::DONE:
		native_connected = true;
		async_exit_status = PG_EVENT_NONE;
		return;

	case PG_Native_Conn_St::FAILED:
	default:
		if (!is_error_present()) {
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "native handshake failed", false);
		}
		async_exit_status = PG_EVENT_NONE;
		return;
	}
}

// ---- native_send_startup ----

bool PgSQL_Connection_Native::native_send_startup() {
	size_t slen2 = 0;
	const char* user = userinfo->username ? userinfo->username : "";
	const char* db = (userinfo->dbname && userinfo->dbname[0]) ? userinfo->dbname : user;

	// Carry the session settings the libpq path sends in its conninfo. Without these a
	// client's connection options are silently dropped, and every new backend connection
	// pays a SET round-trip because requires_RESETTING_CONNECTION() sees a mismatch.
	std::string startup_encoding, startup_options;
	const bool have_params = build_and_record_startup_session_params(startup_encoding, startup_options,
	                                                                 StartupParamEscape::Wire);

	// The untracked half of the options string is client-controlled, so size the buffer
	// from the content rather than assuming a fixed ceiling.
	std::vector<unsigned char> startup(512 + strlen(user) + strlen(db) +
	                                   startup_encoding.size() + startup_options.size());
	if (!pg_build_startup(startup.data(), &slen2, startup.size(), user, db,
	                      have_params ? startup_encoding.c_str() : nullptr,
	                      have_params ? startup_options.c_str()  : nullptr,
	                      "proxysql")) {
		set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE),
			"startup message too large", false);
		return false;
	}
	// Keep the options value for reporting (PROXYSQL INTERNAL SESSION / stats), matching
	// what PQoptions() returns on the libpq path.
	native_options = have_params ? startup_options : std::string();
	native_outbuf.assign((const char*)startup.data(), slen2);
	// After the StartupMessage flushes, wait for the AuthenticationRequest. On the
	// TLS path native_send_or_buffer routes the plaintext through SSL_write.
	if (!native_send_or_buffer(PG_Native_Conn_St::AUTH)) {
		set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send(startup) failed", false);
		return false;
	}
	return true;
}

// ---- native_create_client_ssl_ctx ----

// Create a per-connection client SSL_CTX (TLS_client_method()) configured from the
// SAME backend SSL param source as the libpq conninfo path: per-server params from
// PgHGM->get_Server_SSL_Params(), with the pgsql_thread___ssl_p2s_* globals as the
// fallback. Sets the verify mode from native_ssl_mode. Stores the ctx in
// native_ssl_ctx and returns it; returns nullptr (with error_info set) on failure.
//
// SECURITY NOTE: ProxySQL's global GloVars.global.ssl_ctx is a TLS_server_method()
// context (src/main.cpp) and MUST NOT be used for the backend client handshake.
SSL_CTX* PgSQL_Connection_Native::native_create_client_ssl_ctx() {
	SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == nullptr) {
		set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_OUT_OF_MEMORY), "SSL_CTX_new(client) failed", false);
		return nullptr;
	}
	// TLS 1.2 floor (match-or-exceed the server ctx; never negotiate legacy TLS).
	if (!SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION)) {
		SSL_CTX_free(ctx);
		set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "SSL_CTX_set_min_proto_version failed", false);
		return nullptr;
	}

	// Resolve backend SSL params (same source/order as the libpq path ~990-1024).
	std::string ca, cert, key, crl, crldir;
	std::unique_ptr<PgSQLServers_SslParams> ssl_params {
		PgHGM->get_Server_SSL_Params(parent->address, parent->port, userinfo->username)
	};
	if (ssl_params != nullptr) {
		ca     = ssl_params->ssl_ca;
		cert   = ssl_params->ssl_cert;
		key    = ssl_params->ssl_key;
		crl    = ssl_params->ssl_crl;
		crldir = ssl_params->ssl_crlpath;
	} else {
		if (pgsql_thread___ssl_p2s_ca)      ca     = pgsql_thread___ssl_p2s_ca;
		if (pgsql_thread___ssl_p2s_cert)    cert   = pgsql_thread___ssl_p2s_cert;
		if (pgsql_thread___ssl_p2s_key)     key    = pgsql_thread___ssl_p2s_key;
		if (pgsql_thread___ssl_p2s_crl)     crl    = pgsql_thread___ssl_p2s_crl;
		if (pgsql_thread___ssl_p2s_crlpath) crldir = pgsql_thread___ssl_p2s_crlpath;
	}

	// Trust store (CA): needed for VERIFY_CA / VERIFY_FULL. Loaded whenever present
	// so a future mode switch does not require reconnect logic changes.
	if (!ca.empty()) {
		if (SSL_CTX_load_verify_locations(ctx, ca.c_str(), nullptr) != 1) {
			SSL_CTX_free(ctx);
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "failed to load sslrootcert (CA)", false);
			proxy_error("Native TLS: SSL_CTX_load_verify_locations(%s) failed for %s:%d\n",
				ca.c_str(), parent->address, parent->port);
			return nullptr;
		}
	} else if (native_ssl_mode == PG_Native_SSL_Mode::VERIFY_CA ||
	           native_ssl_mode == PG_Native_SSL_Mode::VERIFY_FULL) {
		// Verification requested but no CA available: fail closed rather than
		// silently downgrading to no verification.
		SSL_CTX_free(ctx);
		set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE),
			"sslmode requires verification but no CA (sslrootcert) configured", false);
		return nullptr;
	}

	// Client certificate + key (mutual TLS), if configured.
	if (!cert.empty()) {
		if (SSL_CTX_use_certificate_chain_file(ctx, cert.c_str()) != 1) {
			SSL_CTX_free(ctx);
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "failed to load sslcert (client cert)", false);
			proxy_error("Native TLS: failed to load client certificate %s for %s:%d\n",
				cert.c_str(), parent->address, parent->port);
			return nullptr;
		}
	}
	if (!key.empty()) {
		if (SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM) != 1) {
			SSL_CTX_free(ctx);
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "failed to load sslkey (client key)", false);
			proxy_error("Native TLS: failed to load client private key %s for %s:%d\n",
				key.c_str(), parent->address, parent->port);
			return nullptr;
		}
		if (SSL_CTX_check_private_key(ctx) != 1) {
			SSL_CTX_free(ctx);
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "client cert/key mismatch", false);
			return nullptr;
		}
	}

	// CRL (revocation), if configured. Enable CRL checking on the store.
	if (!crl.empty() || !crldir.empty()) {
		X509_STORE* store = SSL_CTX_get_cert_store(ctx);
		if (store) {
			if (X509_STORE_load_locations(store,
					crl.empty() ? nullptr : crl.c_str(),
					crldir.empty() ? nullptr : crldir.c_str()) != 1) {
				SSL_CTX_free(ctx);
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "failed to load sslcrl", false);
				proxy_error("Native TLS: failed to load CRL for %s:%d\n", parent->address, parent->port);
				return nullptr;
			}
			X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
		}
	}

	// Verification mode -> SSL_VERIFY_*. We mirror libpq sslmode semantics:
	//   REQUIRE      -> SSL_VERIFY_NONE (encrypt, do NOT verify)  [current default]
	//   VERIFY_CA    -> SSL_VERIFY_PEER (verify chain to CA)
	//   VERIFY_FULL  -> SSL_VERIFY_PEER (+ hostname, set on the SSL object)
	// Note: SSL_VERIFY_NONE on a client still completes the handshake; the cert is
	// received but not checked. This matches libpq's `require`. Hostname enforcement
	// for VERIFY_FULL is applied via X509_VERIFY_PARAM_set1_host on the SSL object.
	switch (native_ssl_mode) {
		case PG_Native_SSL_Mode::VERIFY_CA:
		case PG_Native_SSL_Mode::VERIFY_FULL:
			SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
			break;
		case PG_Native_SSL_Mode::REQUIRE:
		case PG_Native_SSL_Mode::DISABLE:
		default:
			SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
			break;
	}

	native_ssl_ctx = ctx;
	return ctx;
}

// ---- native_drive_ssl_handshake ----

// Drive the TLS client handshake over the raw fd using the mem-BIO model. Returns
// 1 = complete, 0 = need more I/O (async_exit_status set, caller returns), -1 = fatal
// (error_info set + teardown done). Non-blocking: WANT_READ/WANT_WRITE map to
// PG_EVENT_READ / PG_EVENT_WRITE. We own the raw recv()/send() here (the data
// stream's read_from_net/write_to_net assume the steady state, not connect).
int PgSQL_Connection_Native::native_drive_ssl_handshake() {
	// 1) Flush any ciphertext we already produced (e.g. ClientHello) to the socket.
	{
		bool wb = false;
		if (!native_ssl_pump_wbio_to_fd(wb)) {
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send() during TLS handshake failed", false);
			native_teardown();
			return -1;
		}
		if (wb) { async_exit_status = PG_EVENT_WRITE; return 0; }
	}

	for (;;) {
		ERR_clear_error();
		int ret = SSL_do_handshake(native_ssl);
		if (ret == 1) {
			// Handshake complete. For VERIFY_CA / VERIFY_FULL, confirm the result.
			// (For VERIFY_FULL the hostname check is folded into SSL_get_verify_result
			// because we set the verify host on the SSL object before the handshake.)
			if (native_ssl_mode == PG_Native_SSL_Mode::VERIFY_CA ||
			    native_ssl_mode == PG_Native_SSL_Mode::VERIFY_FULL) {
				X509* peer = SSL_get_peer_certificate(native_ssl);
				if (peer == nullptr) {
					set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE),
						"TLS verification required but server presented no certificate", false);
					native_teardown();
					return -1;
				}
				X509_free(peer);
				long vr = SSL_get_verify_result(native_ssl);
				if (vr != X509_V_OK) {
					char msg[256];
					snprintf(msg, sizeof(msg), "TLS certificate verification failed: %s",
						X509_verify_cert_error_string(vr));
					set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), msg, false);
					proxy_error("Native TLS: %s for %s:%d\n", msg, parent->address, parent->port);
					native_teardown();
					return -1;
				}
			}
			// Drain any final handshake bytes to the socket.
			bool wb = false;
			if (!native_ssl_pump_wbio_to_fd(wb)) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send() finishing TLS handshake failed", false);
				native_teardown();
				return -1;
			}
			if (wb) { async_exit_status = PG_EVENT_WRITE; return 0; }
			return 1;
		}

		int err = SSL_get_error(native_ssl, ret);
		if (err == SSL_ERROR_WANT_WRITE) {
			bool wb = false;
			if (!native_ssl_pump_wbio_to_fd(wb)) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send() during TLS handshake failed", false);
				native_teardown();
				return -1;
			}
			async_exit_status = PG_EVENT_WRITE;
			return 0;
		}
		if (err == SSL_ERROR_WANT_READ) {
			// First, push out whatever we produced, then read more ciphertext from fd.
			bool wb = false;
			if (!native_ssl_pump_wbio_to_fd(wb)) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send() during TLS handshake failed", false);
				native_teardown();
				return -1;
			}
			if (wb) { async_exit_status = PG_EVENT_WRITE; return 0; }
			unsigned char cipher[MY_SSL_BUFFER];
			ssize_t n = ::recv(fd, cipher, sizeof(cipher), 0);
			if (n == 0) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "backend closed during TLS handshake", false);
				native_teardown();
				return -1;
			}
			if (n < 0) {
				if (errno == EAGAIN || errno == EWOULDBLOCK) { async_exit_status = PG_EVENT_READ; return 0; }
				if (errno == EINTR) { async_exit_status = PG_EVENT_READ; return 0; }
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "recv() during TLS handshake failed", false);
				native_teardown();
				return -1;
			}
			unsigned char* src = cipher;
			int len = (int)n;
			while (len > 0) {
				int w = BIO_write(native_rbio, src, len);
				if (w <= 0) {
					if (!BIO_should_retry(native_rbio)) {
						set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "BIO_write during TLS handshake failed", false);
						native_teardown();
						return -1;
					}
					continue;
				}
				src += w;
				len -= w;
			}
			// Loop and retry SSL_do_handshake with the new ciphertext.
			continue;
		}
		// SSL_ERROR_SSL / SSL_ERROR_SYSCALL / ZERO_RETURN -> fatal handshake error.
		{
			unsigned long e = ERR_peek_last_error();
			char ebuf[256] = {0};
			if (e) ERR_error_string_n(e, ebuf, sizeof(ebuf));
			char msg[320];
			snprintf(msg, sizeof(msg), "TLS handshake failed%s%s", e ? ": " : "", e ? ebuf : "");
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), msg, false);
			proxy_error("Native TLS: handshake to %s:%d failed (SSL_get_error=%d): %s\n",
				parent->address, parent->port, err, ebuf[0] ? ebuf : "(no detail)");
			while (ERR_get_error()) { /* drain */ }
			native_teardown();
			return -1;
		}
	}
}

// ---- native_send_or_buffer ----

bool PgSQL_Connection_Native::native_send_or_buffer(PG_Native_Conn_St resume_st) {
	if (!native_flush_outbuf()) {
		return false;
	}
	// "Not fully sent" means either plaintext protocol bytes remain (native_outbuf)
	// or, on the encrypted path, ciphertext is still pending the socket (native_ssl_outbuf).
	if (!native_outbuf.empty() || !native_ssl_outbuf.empty()) {
		// Couldn't flush it all: park in SEND_STARTUP, resume in resume_st later.
		native_st_after_send = resume_st;
		native_st = PG_Native_Conn_St::SEND_STARTUP;
		async_exit_status = PG_EVENT_WRITE;
		return true;
	}
	// Fully sent: move straight to the resume state and wait for the reply.
	native_st = resume_st;
	async_exit_status = PG_EVENT_READ;
	return true;
}

// ---- native_recv_into_framer ----

int PgSQL_Connection_Native::native_recv_into_framer() {
	native_ssl_block_dir = 0;
	// Encrypted path: read ciphertext from fd into rbio, then SSL_read plaintext
	// protocol bytes out and feed them to the framer. Mirrors the BIO-mem decrypt
	// loop of PgSQL_Data_Stream::read_from_net(), but drives the raw fd directly.
	if (native_ssl != nullptr) {
		bool got = false;
		unsigned char cipher[MY_SSL_BUFFER];
		// Pull whatever ciphertext is available from the socket into rbio. A single
		// recv() per call is sufficient: SSL_read below decrypts everything buffered,
		// and the caller re-enters on the next READ event for more.
		ssize_t n = ::recv(fd, cipher, sizeof(cipher), 0);
		bool peer_closed = false;
		if (n == 0) {
			// The peer closed, but the record layer may still hold plaintext we already
			// received. Reporting the close now would throw away a reply that is complete,
			// and the client would see a connection error instead of its result.
			peer_closed = true;
		} else if (n < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				// Nothing new from the socket. There may still be buffered plaintext
				// inside the SSL record layer; fall through to drain it.
			} else if (errno == EINTR) {
				return 0; // retry on next event
			} else {
				return -1; // fatal
			}
		} else {
			// Feed all received ciphertext into rbio (BIO_write of a mem BIO accepts
			// the whole buffer, but loop defensively in case of a short write).
			unsigned char* src = cipher;
			int len = (int)n;
			while (len > 0) {
				int w = BIO_write(native_rbio, src, len);
				if (w <= 0) {
					if (!BIO_should_retry(native_rbio)) return -1;
					continue;
				}
				src += w;
				len -= w;
			}
		}
		// Decrypt as much as is available into the framer.
		for (;;) {
			unsigned char plain[MY_SSL_BUFFER];
			ERR_clear_error();
			int r = SSL_read(native_ssl, plain, sizeof(plain));
			if (r > 0) {
				native_framer.feed(plain, (size_t)r);
				got = true;
				continue;
			}
			int err = SSL_get_error(native_ssl, r);
			if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
				if (err == SSL_ERROR_WANT_WRITE) {
					// SSL owes the peer a record (a KeyUpdate response, a renegotiation step)
					// before it will decrypt anything more. Send it, and wait on writable:
					// the backend is holding its own reply until it arrives, so waiting to be
					// read would wait forever.
					native_ssl_block_dir = PG_EVENT_WRITE;
					bool wb = false;
					if (!native_ssl_pump_wbio_to_fd(wb)) return -1;
				}
				break; // need more ciphertext from the socket; wait for next event
			}
			if (err == SSL_ERROR_ZERO_RETURN) {
				// Clean TLS close. If we got nothing this call it's an EOF; otherwise
				// surface the data we did read and let the next call see the close.
				while (ERR_get_error()) { /* drain */ }
				return got ? 1 : -1;
			}
			// SSL_ERROR_SYSCALL / SSL -> fatal
			while (ERR_get_error()) { /* drain */ }
			return -1;
		}
		if (peer_closed) return got ? 1 : -1;
		return got ? 1 : 0;
	}

	// Plaintext path (1.6a).
	unsigned char tmp[16384];
	// Cap one pass so a backend that keeps the socket full cannot push a whole
	// result set into the framer buffer, which doubles, never shrinks, and lives
	// as long as the pooled connection does.
	const size_t burst_max = 16 * sizeof(tmp);
	size_t fed = 0;
	bool got = false;
	for (;;) {
		ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
		if (n > 0) {
			native_framer.feed(tmp, (size_t)n);
			got = true;
			fed += (size_t)n;
			if ((size_t)n < sizeof(tmp)) break; // likely drained the socket buffer
			if (fed >= burst_max) break;        // let the caller frame these; poll() reports the rest
			continue;
		}
		if (n == 0) {
			// Keep what this pass already framed. A result whose tail lands in the same read
			// as the close is complete; discarding it turns it into a connection error.
			return got ? 1 : -1;
		}
		// n < 0
		if (errno == EAGAIN || errno == EWOULDBLOCK) break;
		if (errno == EINTR) continue;
		return -1; // fatal
	}
	return got ? 1 : 0;
}

// ---- native_relay_async_messages ----

int PgSQL_Connection_Native::native_relay_async_messages(PtrSizeArray* out) {
	int r = native_recv_into_framer();
	if (r < 0) return -1;   // EOF or fatal: the backend really is gone
	if (r == 0) return 0;   // readable but nothing arrived yet
	int relayed = 0;
	for (;;) {
		PgSQL_Backend_Msg msg;
		PgSQL_Frame_Result fr = native_framer.next(msg);
		if (fr == FRAME_NEED_MORE) break;   // partial tail stays buffered for the next read
		if (fr == FRAME_ERROR) {
			proxy_error("native: malformed message on idle backend %s:%d\n",
				parent ? parent->address : "?", parent ? parent->port : 0);
			return -1;
		}
		switch (msg.type) {
			case 'A': {
				// Rebuilt rather than reinterpreted: ProxySQL has no business parsing the
				// channel and payload, it only has to hand the same bytes to the client.
				const unsigned int size = 5 + msg.payload_len;
				unsigned char* p = (unsigned char*)l_alloc(size);
				const uint32_t wire_len = msg.payload_len + 4;
				p[0] = 'A';
				p[1] = (wire_len >> 24) & 0xff;
				p[2] = (wire_len >> 16) & 0xff;
				p[3] = (wire_len >> 8) & 0xff;
				p[4] = wire_len & 0xff;
				if (msg.payload_len) memcpy(p + 5, msg.payload, msg.payload_len);
				out->add(p, size);
				relayed++;
				break;
			}
			case 'S':
				// A reported setting changed under us, e.g. after a server config reload.
				native_track_parameter_status(msg.payload, msg.payload_len);
				break;
			case 'N':
				// The libpq path logs notices and does not forward them; match that rather
				// than pushing one at a client sitting at ReadyForQuery.
				proxy_info("native: notice on idle backend %s:%d, dropped\n",
					parent ? parent->address : "?", parent ? parent->port : 0);
				break;
			case 'E':
				// FATAL: idle_session_timeout, pg_terminate_backend, server shutdown.
				// Record it so the log says why, then let the caller tear the session down.
				native_fill_error_from_E(msg.payload, msg.payload_len);
				return -1;
			default:
				proxy_error("native: unexpected message type '0x%02X' on idle backend %s:%d\n",
					(unsigned char)msg.type, parent ? parent->address : "?", parent ? parent->port : 0);
				return -1;
		}
	}
	return relayed;
}

// ---- native_fill_error_from_E ----

void PgSQL_Connection_Native::native_fill_error_from_E(const unsigned char* payload, uint32_t len) {
	// ErrorResponse: series of (field-type-byte, NUL-terminated value), terminated
	// by a zero field-type byte. Extract Severity('S'), SQLSTATE('C'), Message('M').
	std::string severity = "ERROR";
	std::string sqlstate = "08000"; // connection_exception default
	std::string message  = "native handshake error";
	uint32_t i = 0;
	while (i < len && payload[i] != 0) {
		char ftype = (char)payload[i++];
		const unsigned char* vstart = payload + i;
		while (i < len && payload[i] != 0) i++;
		std::string val((const char*)vstart, (const char*)(payload + i));
		if (i < len) i++; // skip the NUL
		switch (ftype) {
			case 'S': // Severity (localized)
			case 'V': // Severity (non-localized) — prefer if present
				if (ftype == 'V' || severity == "ERROR") severity = val;
				break;
			case 'C': sqlstate = val; break;
			case 'M': message = val; break;
			default: break;
		}
	}
	PgSQL_Error_Helper::fill_error_info(error_info, sqlstate.c_str(), message.c_str(), severity.c_str());
}

// ---- native_drive_auth ----

void PgSQL_Connection_Native::native_drive_auth(short /*event*/) {
	int r = native_recv_into_framer();
	if (r == 0) { async_exit_status = PG_EVENT_READ; return; }       // EAGAIN, wait
	if (r < 0) {
		set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "backend closed during auth", false);
		native_teardown();
		return;
	}

	for (;;) {
		PgSQL_Backend_Msg msg;
		PgSQL_Frame_Result fr = native_framer.next(msg);
		if (fr == FRAME_NEED_MORE) {
			async_exit_status = PG_EVENT_READ;
			return;
		}
		if (fr == FRAME_ERROR) {
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_PROTOCOL_VIOLATION), "malformed backend message during auth", false);
			native_teardown();
			return;
		}
		// FRAME_OK: msg.payload points INTO the framer buffer and is valid only
		// until the next feed(). We do not feed() again inside this loop, so it
		// stays valid; anything retained past a recv() is copied first.
		if (msg.type == 'E') {
			native_fill_error_from_E(msg.payload, msg.payload_len);
			proxy_error("Native auth: backend ErrorResponse: %s\n", get_error_code_with_message().c_str());
			native_teardown();
			return;
		}
		if (msg.type == 'N') {
			continue; // NoticeResponse: ignore during auth
		}
		if (msg.type != 'R') {
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_PROTOCOL_VIOLATION), "unexpected message during auth", false);
			native_teardown();
			return;
		}
		if (msg.payload_len < 4) {
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_PROTOCOL_VIOLATION), "short Authentication message", false);
			native_teardown();
			return;
		}
		uint32_t auth_type = pg_read_be32(msg.payload);
		const unsigned char* rest = msg.payload + 4;
		uint32_t rest_len = msg.payload_len - 4;

		switch (auth_type) {
		case 0: // AuthenticationOk
			// SCRAM proves both sides. A backend that answers our client-final with a plain
			// AuthenticationOk has skipped its half, so it never showed it knows the password --
			// accepting it would hand the session to whoever is on the other end of the socket.
			if (native_scram != nullptr && native_scram_step != PG_Native_Scram_Step::SERVER_VERIFIED) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_PROTOCOL_VIOLATION),
					"backend completed authentication without finishing the SCRAM exchange", false);
				native_teardown();
				return;
			}
			native_st = PG_Native_Conn_St::STARTUP_TAIL;
			// Fall through to consuming any already-buffered tail messages.
			native_drive_startup_tail(0);
			return;

		case 3: { // AuthenticationCleartextPassword
			const char* pw = userinfo->password ? userinfo->password : "";
			// Only a plaintext secret can answer this challenge: the backend wants the password
			// itself, and a stored md5 hash or SCRAM verifier is a one-way derivation we cannot
			// invert. libpq fails the same combination on its shared "no password supplied"
			// guard in pg_fe_sendauth(), so refusing here keeps the two paths identical.
			if (get_password_type(pw) != PASSWORD_TYPE_PLAINTEXT) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_INVALID_PASSWORD),
					"backend requested a cleartext password but the stored credential is not a plaintext password", false);
				native_teardown();
				return;
			}
			size_t pwlen = strlen(pw);
			native_outbuf.clear();
			pg_append_typed_msg(native_outbuf, 'p', (const unsigned char*)pw, pwlen + 1); // include NUL
			if (!native_send_or_buffer(PG_Native_Conn_St::AUTH)) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send(cleartext pw) failed", false);
				native_teardown();
			}
			return;
		}

		case 5: { // AuthenticationMD5Password (4 salt bytes follow)
			if (rest_len < 4) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_PROTOCOL_VIOLATION), "short MD5 salt", false);
				native_teardown();
				return;
			}
			unsigned char salt[4];
			memcpy(salt, rest, 4);
			char md5buf[36];
			const char* user = userinfo->username ? userinfo->username : "";
			const char* pw = userinfo->password ? userinfo->password : "";
			// An md5-stored secret IS hex(md5(password+user)) -- the inner hash this response is
			// built from. Running pg_build_md5() over it hashes it a SECOND time and the backend
			// rejects the login -- the md5 divergence from libpq, which reuses the stored hash
			// via the patched md5_secret conninfo parameter.
			switch (get_password_type(pw)) {
			case PASSWORD_TYPE_MD5:
				// get_password_type() applies the same test (length 35, "md5", 32 lowercase hex),
				// so this branch is unreachable from here; it is the postcondition that keeps a
				// half-built response off the wire if the two ever diverge. Covered directly by
				// pgsql_backend_auth-t rather than end to end.
				if (!pg_build_md5_from_secret(md5buf, pw, salt)) {
					set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_INVALID_PASSWORD),
						"stored md5 credential is malformed; expected \"md5\" followed by 32 lowercase hex digits", false);
					native_teardown();
					return;
				}
				break;
			case PASSWORD_TYPE_PLAINTEXT:
				pg_build_md5(md5buf, user, pw, salt); // "md5"+32hex+NUL (35 chars + NUL)
				break;
			default:
				// A SCRAM verifier cannot answer an md5 challenge at all: the two derivations
				// share nothing. libpq reaches its no-password guard here and fails likewise.
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_INVALID_PASSWORD),
					"backend requested md5 authentication but the stored credential is a SCRAM verifier", false);
				native_teardown();
				return;
			}
			native_outbuf.clear();
			pg_append_typed_msg(native_outbuf, 'p', (const unsigned char*)md5buf, strlen(md5buf) + 1);
			if (!native_send_or_buffer(PG_Native_Conn_St::AUTH)) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send(md5 pw) failed", false);
				native_teardown();
			}
			return;
		}

		case 10: { // AuthenticationSASL: list of NUL-terminated mechanism names
			bool has_scram = false, has_scram_plus = false;
			uint32_t i = 0;
			while (i < rest_len && rest[i] != 0) {
				const char* mech = (const char*)(rest + i);
				size_t mlen = strnlen(mech, rest_len - i);
				if (mlen == strlen("SCRAM-SHA-256") && memcmp(mech, "SCRAM-SHA-256", mlen) == 0) has_scram = true;
				else if (mlen == strlen("SCRAM-SHA-256-PLUS") && memcmp(mech, "SCRAM-SHA-256-PLUS", mlen) == 0) has_scram_plus = true;
				i += mlen + 1;
			}

			// Mechanism selection (mirror of design §4):
			//   plain-only     -> plain
			//   plus-only, TLS -> PLUS  (set cbind below)
			//   plus-only, !TLS-> fail (cbind makes no sense over plaintext)
			//   both,    TLS   -> PLUS  (set cbind below)   <-- the upgrade
			//   both,    !TLS  -> plain
			//   neither        -> fail
			const bool tls_in_use = (native_ssl != nullptr);
			bool use_scram_plus = false;
			if (has_scram_plus && tls_in_use) {
				use_scram_plus = true;
			} else if (has_scram_plus && !tls_in_use && !has_scram) {
				// Channel binding hashes the server certificate, and a plaintext connection has
				// none to hash. Retrying through libpq cannot help: both paths read the same
				// use_ssl column, so libpq would connect in the clear as well and fail here too.
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
					"backend requires SCRAM-SHA-256-PLUS channel binding, which needs an encrypted connection to this server; set use_ssl=1 on its pgsql_servers row", false);
				native_teardown();
				return;
			} else if (!has_scram && !has_scram_plus) {
				// The libpq we bundle recognises these same two mechanism names and nothing else,
				// so handing the connection to it would repeat this failure one connect later.
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_FEATURE_NOT_SUPPORTED),
					"backend offers no SASL mechanism ProxySQL supports; only SCRAM-SHA-256 and SCRAM-SHA-256-PLUS are implemented", false);
				native_teardown();
				return;
			}
			// Remaining cases (has_scram && !use_scram_plus) -> plain.

			if (native_scram) { pg_scram_free(native_scram); native_scram = nullptr; }
			native_scram = pg_scram_new();
			if (native_scram == nullptr) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_OUT_OF_MEMORY), "scram state alloc failed", false);
				native_teardown();
				return;
			}

			// Verifier pass-through. A verifier-stored user has no plaintext to
			// derive from, so the exchange runs off the ClientKey harvested during that user's
			// FRONTEND SCRAM login plus the verifier's ServerKey -- PgSQL_Protocol.cpp records
			// both on the userinfo. Installed before client-first so client-final has them.
			{
				const char* stored = userinfo->password ? userinfo->password : "";
				if (userinfo->has_scram_keys) {
					if (!pg_scram_set_keys(native_scram, userinfo->scram_client_key,
							userinfo->scram_server_key)) {
						set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_INVALID_PASSWORD),
							"could not install the harvested SCRAM keys for the backend handshake", false);
						native_teardown();
						return;
					}
				} else switch (get_password_type(stored)) {
				case PASSWORD_TYPE_PLAINTEXT:
					break;   // libscram derives the keys ad-hoc from the plaintext
				case PASSWORD_TYPE_SCRAM_SHA_256:
					// A verifier with no harvested ClientKey: a proof derived from the verifier
					// TEXT is always rejected. libpq refuses to build the conninfo at all here
					// (pgsql_append_conninfo_credentials); fail for the same reason.
					set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_INVALID_PASSWORD),
						"SCRAM verifier stored but no harvested ClientKey; cannot authenticate to the backend without a frontend SCRAM login", false);
					native_teardown();
					return;
				default:
					// An md5 secret shares no derivation with SCRAM, so there is nothing to reuse.
					// A role's FRONTEND auth-method floor and its backend pg_hba method are chosen
					// independently, so an md5-stored user meeting a scram-sha-256 backend is
					// reachable -- and without this the md5 hash TEXT would go through PBKDF2 and
					// fail as an opaque "password authentication failed". libpq stops on its
					// no-password guard here (only md5_secret was set, never password).
					set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_INVALID_PASSWORD),
						"backend requested SCRAM authentication but the stored credential is an md5 hash", false);
					native_teardown();
					return;
				}
			}

			// If using -PLUS, set the cbind input BEFORE building client-first
			// so the gs2 header in client-first is "p=tls-server-end-point,,".
			if (use_scram_plus) {
				unsigned char digest[EVP_MAX_MD_SIZE];
				size_t digest_len = 0;
				if (pg_tls_server_end_point(native_ssl, digest, &digest_len) < 0) {
					// Digest failed: degrade to plain if the backend also offered it.
					if (has_scram) {
						use_scram_plus = false;
					} else {
						// pg_tls_server_end_point() mirrors libpq's own fingerprint code step for
						// step, so a certificate ours cannot digest defeats libpq's as well.
						set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
							"could not compute this backend certificate's fingerprint for SCRAM-SHA-256-PLUS channel binding, and the backend offered no other mechanism", false);
						native_teardown();
						return;
					}
				} else {
					// 24-byte header + max 64-byte digest = 88 bytes.
					unsigned char cbind_input[88];
					int cbind_len = pg_scram_build_cbind_input_tls_server_end_point(
						digest, digest_len, cbind_input, sizeof(cbind_input));
					if (cbind_len < 0) {
						// Buffer math error — by construction impossible.
						assert(0);
						native_teardown();
						return;
					}
					pg_scram_set_cbind(native_scram, (const char*)cbind_input, cbind_len);
				}
			}

			const char* client_first = pg_scram_client_first(native_scram, /*channel_binding=*/use_scram_plus);
			if (client_first == nullptr) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "SCRAM client-first failed", false);
				native_teardown();
				return;
			}
			// SASLInitialResponse body: mechname\0 + int32(initial-resp-len) + initial-resp
			const char* mechname = use_scram_plus ? "SCRAM-SHA-256-PLUS" : "SCRAM-SHA-256";
			uint32_t cflen = (uint32_t)strlen(client_first);
			std::string body;
			body.append(mechname, strlen(mechname) + 1); // include NUL
			unsigned char lenbe[4] = {
				(unsigned char)((cflen >> 24) & 0xff), (unsigned char)((cflen >> 16) & 0xff),
				(unsigned char)((cflen >> 8) & 0xff),  (unsigned char)(cflen & 0xff) };
			body.append((const char*)lenbe, 4);
			body.append(client_first, cflen);
			native_outbuf.clear();
			pg_append_typed_msg(native_outbuf, 'p', (const unsigned char*)body.data(), body.size());
			if (!native_send_or_buffer(PG_Native_Conn_St::AUTH)) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send(SASLInitialResponse) failed", false);
				native_teardown();
				return;
			}
			native_scram_step = PG_Native_Scram_Step::CLIENT_FIRST_SENT;
			return;
		}

		case 11: { // AuthenticationSASLContinue: server-first message
			// Exactly one is expected, and only after client-first. A second one would run the
			// proof calculation over state libscram has already consumed, which trips an assert
			// inside it and takes the process down; it would also emit a fresh proof over a salt
			// the backend chose, which is an offline-crackable artifact it can ask for repeatedly.
			if (native_scram == nullptr || native_scram_step != PG_Native_Scram_Step::CLIENT_FIRST_SENT) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_PROTOCOL_VIOLATION), "unexpected SASLContinue", false);
				native_teardown();
				return;
			}
			// Copy server-first BEFORE building (client_final reads it; no further feed here,
			// but copying keeps us robust against the dangling-pointer rule).
			std::string server_first((const char*)rest, rest_len);
			// With keys injected there is no password to send.
			const char* pw = userinfo->has_scram_keys
				? nullptr
				: (userinfo->password ? userinfo->password : "");
			const char* client_final = pg_scram_client_final(native_scram, pw, server_first.data(), server_first.size());
			if (client_final == nullptr) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "SCRAM client-final failed", false);
				native_teardown();
				return;
			}
			native_outbuf.clear();
			pg_append_typed_msg(native_outbuf, 'p', (const unsigned char*)client_final, strlen(client_final));
			if (!native_send_or_buffer(PG_Native_Conn_St::AUTH)) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send(SASLResponse) failed", false);
				native_teardown();
				return;
			}
			native_scram_step = PG_Native_Scram_Step::CLIENT_FINAL_SENT;
			return;
		}

		case 12: { // AuthenticationSASLFinal: server-final message
			// Only after our client-final. Arriving earlier means the messages libscram compares
			// the signature against were never built, and it reads them as strings -- a backend
			// that skips straight to this message would crash the proxy.
			if (native_scram == nullptr || native_scram_step != PG_Native_Scram_Step::CLIENT_FINAL_SENT) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_PROTOCOL_VIOLATION), "unexpected SASLFinal", false);
				native_teardown();
				return;
			}
			std::string server_final((const char*)rest, rest_len);
			if (!pg_scram_verify_server_final(native_scram, server_final.data(), server_final.size())) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_INVALID_PASSWORD), "SCRAM server signature verification failed", false);
				native_teardown();
				return;
			}
			native_scram_step = PG_Native_Scram_Step::SERVER_VERIFIED;
			// Server verified; an AuthenticationOk ('R',0) normally follows. Keep
			// looping to consume it (it may already be framed).
			break;
		}

		case 2:  // GSSAPI continue
		case 7:  // GSSAPI
		case 8:  // GSSAPI continue
		case 9:  // SSPI
			// Not supported. The libpq we bundle is built without GSSAPI (pg_config.h leaves
			// ENABLE_GSS undefined), so handing the connection over would fail too, one
			// connect attempt later and with a vaguer message.
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_FEATURE_NOT_SUPPORTED),
				"backend requested GSSAPI/SSPI authentication, which ProxySQL does not support", false);
			proxy_error("Native connect: backend %s:%d requested GSSAPI/SSPI authentication, which is not supported\n",
				parent->address, parent->port);
			native_teardown();
			return;

		default:
			// We implement the same authentication types as the libpq we bundle (trust, cleartext,
			// md5, SCRAM), so anything else fails on both paths alike. The type number only fits
			// in the log, which is why the client message stays generic.
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_FEATURE_NOT_SUPPORTED),
				"backend requested an authentication method ProxySQL does not support", false);
			proxy_error("Native connect: backend %s:%d requested unsupported AuthenticationRequest %u\n",
				parent->address, parent->port, auth_type);
			native_teardown();
			return;
		}
		// Loop to process further already-buffered messages (e.g. AuthenticationOk
		// after SASLFinal). msg.payload references stay valid until next feed().
	}
}

// ---- native_track_parameter_status ----

// Record a ParameterStatus ('S'): two NUL-separated strings, name then value. The
// backend sends one whenever a reported setting changes, and DISCARD ALL changes
// every one of them back to its default. Dropping these would leave native_params
// describing settings the connection no longer has.
void PgSQL_Connection_Native::native_track_parameter_status(const unsigned char* payload, uint32_t len) {
	if (payload == nullptr || len == 0) return;
	uint32_t i = 0;
	const char* name = (const char*)payload;
	while (i < len && payload[i] != 0) i++;
	if (i >= len) return; // malformed; ignore
	std::string nm(name, (const char*)(payload + i));
	i++; // skip the NUL between the two strings
	const char* val = (const char*)(payload + i);
	while (i < len && payload[i] != 0) i++;
	native_params[nm] = std::string(val, (const char*)(payload + i));
}

// ---- native_drive_startup_tail ----

void PgSQL_Connection_Native::native_drive_startup_tail(short /*event*/) {
	// Consume ParameterStatus(S)/BackendKeyData(K)/NoticeResponse(N) until
	// ReadyForQuery(Z). This may be called immediately after AuthenticationOk
	// (tail messages possibly already buffered) or on a fresh READ event.
	for (;;) {
		PgSQL_Backend_Msg msg;
		PgSQL_Frame_Result fr = native_framer.next(msg);
		if (fr == FRAME_NEED_MORE) {
			int r = native_recv_into_framer();
			if (r == 0) { async_exit_status = PG_EVENT_READ; return; } // EAGAIN
			if (r < 0) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "backend closed during startup", false);
				native_teardown();
				return;
			}
			continue; // got bytes, retry next()
		}
		if (fr == FRAME_ERROR) {
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_PROTOCOL_VIOLATION), "malformed backend message during startup", false);
			native_teardown();
			return;
		}
		// FRAME_OK. Copy any payload we retain before a subsequent recv()/feed().
		switch (msg.type) {
		case 'S': // ParameterStatus
			native_track_parameter_status(msg.payload, msg.payload_len);
			break;
		case 'K': { // BackendKeyData: int32 pid, int32 secret
			if (msg.payload_len >= 8) {
				native_backend_pid = (int)pg_read_be32(msg.payload);
				native_backend_secret = (int)pg_read_be32(msg.payload + 4);
			}
			break;
		}
		case 'N': // NoticeResponse: ignore
			break;
		case 'E': // ErrorResponse mid-startup
			native_fill_error_from_E(msg.payload, msg.payload_len);
			proxy_error("Native startup: backend ErrorResponse: %s\n", get_error_code_with_message().c_str());
			native_teardown();
			return;
		case 'Z': { // ReadyForQuery: 1 status byte
			if (msg.payload_len >= 1) set_ready_for_query_status((char)msg.payload[0]);
			native_connected = true;
			native_st = PG_Native_Conn_St::DONE;
			async_exit_status = PG_EVENT_NONE; // connect/auth phase COMPLETE
			return;
		}
		default:
			// Other messages (e.g. 'R' AuthenticationOk that arrived here) are
			// benign at this stage; skip them.
			break;
		}
	}
}

// ---- native_stmt_send_or_wait ----

void PgSQL_Connection_Native::native_stmt_send_or_wait() {
	// Flush the extended-query step just built into native_outbuf. Mirrors the tail
	// of query_start()'s native branch: on a fatal send set error_info; otherwise
	// leave async_exit_status = PG_EVENT_WRITE while bytes remain buffered (the
	// caller's START case then waits for POLLOUT via *_CONT) or PG_EVENT_NONE once
	// fully sent (the START case proceeds straight to the result fetch).
	if (!native_send_or_buffer(PG_Native_Conn_St::DONE)) {
		// native_send_or_buffer drives native_st only for the connect handshake; here
		// (post-connect) only the flush result matters. false == fatal send error.
		set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send(extended-query) failed", false);
		async_exit_status = PG_EVENT_NONE;
		return;
	}
	// From here until a ReadyForQuery comes back, the backend is mid-batch. Recorded on the way out
	// rather than at each of the six call sites so no future step can forget to.
	native_unsynced_work = true;
	if (!native_outbuf.empty() || !native_ssl_outbuf.empty()) {
		async_exit_status = PG_EVENT_WRITE;
	} else {
		async_exit_status = PG_EVENT_NONE;
	}
}

// ---- native_stmt_flush_cont ----

void PgSQL_Connection_Native::native_stmt_flush_cont() {
	// Finish flushing a partially-sent extended-query step (mirrors query_cont()'s
	// native branch). PG_EVENT_WRITE keeps the caller waiting for POLLOUT; PG_EVENT_NONE
	// once fully drained lets the caller's *_CONT case advance to the result fetch.
	async_exit_status = PG_EVENT_NONE;
	if (!native_flush_outbuf()) {
		set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send(extended-query) failed", false);
		return;
	}
	if (!native_outbuf.empty() || !native_ssl_outbuf.empty()) {
		async_exit_status = PG_EVENT_WRITE;
	}
}

// ---- native_fetch_result_cont ----

void PgSQL_Connection_Native::native_fetch_result_cont(short /*event*/, uint64_t* processed_bytes) {
	// Every byte handed to query_result counts towards this event's total, which
	// the caller compares against pgsql-threshold_resultset_size to decide when
	// to pause the fetch.
	auto count_bytes = [&](unsigned int n) { if (processed_bytes) *processed_bytes += n; };
	// Native result fetch (Task 1.6c / Phase 2). Pull backend bytes into the
	// framer, then drain every complete message into query_result as raw
	// client-wire bytes. Non-blocking throughout.
	async_exit_status = PG_EVENT_NONE;

	// query_result must have been allocated in ASYNC_USE_RESULT_START via
	// init_query_result(). Guard defensively so we never deref a null result.
	if (query_result == nullptr) {
		native_result_fatal(PGSQL_GET_ERROR_CODE_STR(ERRCODE_INTERNAL_ERROR), "native result fetch with no query_result");
		return;
	}

	// Self-heal any pending outbound bytes before reading more frames. The only
	// writer during the fetch phase is the 'G'/'W' CopyFail interception below:
	// if its send was partial we returned with PG_EVENT_WRITE, and this re-entry
	// (on POLLOUT) must finish flushing the CopyFail or the backend — which is
	// blocked mid-COPY waiting for it — will never produce the ErrorResponse +
	// ReadyForQuery that complete the cycle. Mirrors query_cont()'s native branch.
	if (!native_outbuf.empty() || !native_ssl_outbuf.empty()) {
		if (!native_flush_outbuf()) {
			native_result_fatal(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send failed during result fetch");
			return;
		}
		if (!native_outbuf.empty() || !native_ssl_outbuf.empty()) {
			// Still bytes pending → keep waiting for writable.
			async_exit_status = PG_EVENT_WRITE;
			return;
		}
	}

	if (native_fetch_paused) {
		// Resuming a fetch that stopped on the byte threshold: the messages are
		// already framed, and the backend may have nothing left to send.
		native_fetch_paused = false;
	} else {
		int r = native_recv_into_framer();
		if (r < 0) {
			native_result_fatal(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "backend closed during result fetch");
			return;
		}
		if (r == 0) {
			// EAGAIN: no bytes available yet → wait for the socket to become readable.
			async_exit_status = PG_EVENT_READ;
			return;
		}
	}

	// Drain all complete messages. msg.payload points INTO the framer buffer and
	// is invalidated by the next feed(); we copy each message out (into the result
	// buffer) before looping, and we never feed() again inside this loop, so the
	// dangling-pointer rule is respected.
	for (;;) {
		// Enough bytes for this event: stop before taking another message and let
		// the client drain, the same rule the libpq fetch loop applies per row.
		if (processed_bytes && suspend_resultset_fetch(*processed_bytes)) {
			native_fetch_paused = true;
			return;
		}
		PgSQL_Backend_Msg msg;
		PgSQL_Frame_Result fr = native_framer.next(msg);
		if (fr == FRAME_OK) {
			if (msg.type == 'G' || msg.type == 'W') {
				// CopyInResponse / CopyBothResponse: the native drive cannot supply
				// client CopyData (COPY ... FROM STDIN is routed to the session
				// fast_forward path before it reaches us — see copy_cmd_matcher).
				// If one slips through, abort the COPY cleanly: suppress the
				// message (the client must not enter COPY mode) and send
				// CopyFail; the backend responds with ErrorResponse +
				// ReadyForQuery, which complete the cycle via the existing 'Z'
				// handling below.
				if (!native_copy_intercepted) {
					native_copy_intercepted = true;
					proxy_warning("native backend protocol: unexpected CopyInResponse/CopyBothResponse ('%c'); sending CopyFail\n", msg.type);
					pg_native_build_copyfail(native_outbuf, "ProxySQL native backend protocol cannot drive COPY FROM STDIN on this path");
					// native_send_or_buffer's native_st side effect only matters
					// during the connect handshake; it is dead here (post-connect,
					// mid-fetch) — only the flush result and async_exit_status count.
					if (!native_send_or_buffer(PG_Native_Conn_St::DONE)) {
						native_result_fatal(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send(CopyFail) failed");
						return;
					}
					if (async_exit_status == PG_EVENT_WRITE || !native_outbuf.empty() || !native_ssl_outbuf.empty()) {
						// Partial send: return so the poll loop arms POLLOUT and
						// re-enters us; the preamble above finishes the flush.
						// Continuing the loop here would let the FRAME_NEED_MORE
						// branch overwrite async_exit_status with PG_EVENT_READ,
						// leaving the CopyFail forever unflushed while the backend
						// waits for it — a mutual-wait hang.
						return;
					}
				}
				continue;   // do NOT forward 'G'/'W' to the client
			}

			// Check the type before any of it is copied towards the client. Every
			// add_native_backend_message() call below is reached through here, so this
			// is the one place that has to hold. Nothing is forwarded and the
			// connection is dropped, because a backend sending a type that cannot
			// appear in a result stream is either hostile or desynchronized, and in
			// both cases its remaining bytes are worthless.
			if (!pg_native_type_legal_in_result(msg.type)) {
				proxy_error("native backend protocol: illegal message type '0x%02X' in result stream on fd=%d; discarding connection\n",
					(unsigned char)msg.type, fd);
				// Record the reason and stop reading, but leave the socket open for now.
				// Closing it here would make the session treat this as a connection that
				// merely died, and the client would be told only that -- never what
				// ProxySQL refused. Ending the cycle instead lets the session report the
				// error, while the flags below make sure the connection is destroyed
				// rather than returned to the pool.
				native_result_protocol_violation("illegal backend message type in result stream");
				return;
			}

			// A NotificationResponse answers a LISTEN, which belongs to the connection and
			// not necessarily to the client currently holding it. PostgreSQL flushes pending
			// notifications just before ReadyForQuery, so one legitimately arrives mid-reply;
			// the question is who it is for. When this connection carries the subscription it
			// is this client's, and forwarding it is the whole point -- a driver reading
			// notifications synchronously gets them out of the query reply. Otherwise it
			// belongs to nobody reachable, and handing it over would leak a channel and
			// payload to an unrelated client, so it goes the way libpq sends it: nowhere.
			if (msg.type == 'A') {
				if (!get_status(STATUS_PGSQL_CONNECTION_LISTEN)) {
					proxy_debug(PROXY_DEBUG_MYSQL_COM, 5,
						"Discarded asynchronous NotificationResponse in result stream on fd=%d\n", fd);
					continue;
				}
				native_result_had_notification = true;
			}

			// --- Extended-query (prepared-statement) drain (Task C) ---
			// When driving a Parse/Describe/Execute step, apply the per-step
			// ack-filtering + terminator rules. native_stmt_step == NONE means a plain
			// simple query, which keeps the original 'Z'-only completion below.
			if (native_stmt_step != PG_Native_Stmt_Step::NONE) {
				const char t = msg.type;

				// BindComplete: for the unnamed portal the session synthesized it at
				// Bind intake, so suppress the backend copy. For a named-portal Bind
				// (BIND step) NO synthesis happened — forward the REAL BindComplete.
				// A Flush-terminated BIND step completes here; a Sync-terminated one
				// waits for its 'Z' below.
				if (t == '2') {
					if (native_stmt_step == PG_Native_Stmt_Step::BIND) {
						count_bytes(query_result->add_native_backend_message(t, msg.payload, msg.payload_len));
						if (!native_stmt_sync_terminated) {
							native_result_complete = true;
							return;
						}
						continue;
					}
					continue;
				}

				// CloseComplete: forwarded during a named-portal Close (CLOSE_P step).
				// PostgreSQL emits '3' even when the portal did not exist (Close is
				// idempotent), so the session evicts the registry entry unconditionally
				// on success. A Flush-terminated CLOSE_P completes here; a Sync-
				// terminated one waits for its 'Z' below. Outside a CLOSE_P step '3' is
				// unexpected in native extq (unnamed Close is synthesized) - forward it
				// defensively rather than drop it.
				if (t == '3') {
					count_bytes(query_result->add_native_backend_message(t, msg.payload, msg.payload_len));
					if (native_stmt_step == PG_Native_Stmt_Step::CLOSE_P &&
						!native_stmt_sync_terminated) {
						native_result_complete = true;
						return;
					}
					continue;
				}

				// ParseComplete: suppress for implicit prepares (client issued no
				// Parse), forward for a real client Parse (cache miss). A Flush-
				// terminated PARSE step completes here; a Sync-terminated one waits
				// for its 'Z'.
				if (t == '1') {
					if (!native_suppress_parse_complete) {
						count_bytes(query_result->add_native_backend_message(t, msg.payload, msg.payload_len));
					}
					if (native_stmt_step == PG_Native_Stmt_Step::PARSE && !native_stmt_sync_terminated) {
						native_result_complete = true;
						return;
					}
					continue;
				}

				// ErrorResponse: forward it (its side effect fills error_info, so the
				// session sees rc -1), then get the backend back to ReadyForQuery.
				if (t == 'E') {
					count_bytes(query_result->add_native_backend_message(t, msg.payload, msg.payload_len));
					if (native_stmt_sync_terminated) {
						// A Sync already reached the backend, so it WILL emit 'Z' after
						// the error; keep draining until we consume it.
						continue;
					}
					// Flush-terminated: after 'E' the backend is in the aborted-until-
					// Sync state and sends NO 'Z' until it receives a Sync. Inject one
					// so the drain can reach ReadyForQuery and end this cycle on a
					// cleanly-synchronized connection (mirrors the observable effect of
					// the libpq pipeline path routing to ASYNC_RESYNC_START on error).
					if (!native_stmt_error_resync) {
						native_stmt_error_resync = true;
						// Not gated behind a runtime debug level so this flagship recovery
						// path stays observable in production logs and in tests grepping
						// proxysql.log — but logged AT MOST ONCE PER CONNECTION
						// (native_stmt_resync_logged, never reset per-step): a client
						// habitually sending Parse-time-invalid SQL would otherwise flood
						// the log at WARNING on every errored query, while the libpq
						// oracle path (resync via ASYNC_RESYNC_START) logs nothing for
						// the same event. The recovery itself still runs every time.
						if (!native_stmt_resync_logged) {
							native_stmt_resync_logged = true;
							proxy_warning("native extq: mid-frame stmt-step error ('E') on fd=%d (step=%d); "
								"injecting Sync to resynchronize backend for ReadyForQuery\n",
								fd, (int)native_stmt_step);
						}
						pg_build_sync(native_outbuf);
						if (!native_send_or_buffer(PG_Native_Conn_St::DONE)) {
							native_result_fatal(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send(Sync) failed");
							return;
						}
						if (async_exit_status == PG_EVENT_WRITE || !native_outbuf.empty() || !native_ssl_outbuf.empty()) {
							// Partial send: return so the poll loop arms POLLOUT and the
							// flush-preamble at the top finishes the Sync before we read
							// 'Z' — continuing here would let FRAME_NEED_MORE overwrite
							// async_exit_status with PG_EVENT_READ, deadlocking on a 'Z'
							// the backend cannot send until the Sync arrives.
							return;
						}
					}
					continue; // drain to the 'Z' the injected Sync produces
				}

				// ReadyForQuery: completes any Sync-terminated step (and the injected-
				// Sync error recovery above).
				if (t == 'Z') {
					count_bytes(query_result->add_native_backend_message(t, msg.payload, msg.payload_len));
					native_result_complete = true;
					return;
				}

				// Everything else (ParameterDescription 't', RowDescription 'T', NoData
				// 'n', DataRow 'D', CommandComplete 'C', EmptyQueryResponse 'I',
				// ParameterStatus 'S', NoticeResponse 'N', etc.) streams through.
				count_bytes(query_result->add_native_backend_message(t, msg.payload, msg.payload_len));

				// Named-portal suspend/resume bookkeeping (Task P2): record whether the
				// EXECUTE step's terminator was 's' (PortalSuspended — max_rows cut the
				// result short, the portal stays open for a resume Execute) or 'C'/'I'
				// (the portal ran to completion). Recorded on BOTH flush- and sync-
				// terminated EXECUTE steps: the terminator byte streams through this
				// generic section before either completion path (flush completes just
				// below on 's'/'C'/'I'; sync completes later on 'Z'). Read once by the
				// session epilogue to mark/clear a NAMED portal's entry.suspended.
				if (native_stmt_step == PG_Native_Stmt_Step::EXECUTE) {
					if (t == 's') {
						native_last_execute_suspended = true;
					} else if (t == 'C' || t == 'I') {
						native_last_execute_suspended = false;
					}
				}

				// Flush-terminated per-step terminators (no 'Z' until a later Sync):
				if (!native_stmt_sync_terminated) {
					if ((native_stmt_step == PG_Native_Stmt_Step::DESCRIBE_S ||
						 native_stmt_step == PG_Native_Stmt_Step::DESCRIBE_P) &&
						(t == 'T' || t == 'n')) {
						// DESCRIBE('S'): 't' precedes, then 'T'|'n' terminates.
						// DESCRIBE('P'): 'T'|'n' terminates.
						native_result_complete = true;
						return;
					}
					if (native_stmt_step == PG_Native_Stmt_Step::EXECUTE &&
						(t == 'C' || t == 'I' || t == 's')) {
						// EXECUTE: CommandComplete / EmptyQueryResponse / PortalSuspended.
						native_result_complete = true;
						return;
					}
				}
				continue;
			}

			// The same refusal, before the ReadyForQuery joins the result.
			if (msg.type == 'Z') {
				reject_result_without_outcome();
			}
			count_bytes(query_result->add_native_backend_message(msg.type, msg.payload, msg.payload_len));
			if (msg.type == 'Z') {
				// ReadyForQuery: the result stream for this query is complete.
				native_result_complete = true;
				return;
			}
			continue;
		}
		if (fr == FRAME_NEED_MORE) {
			// Incomplete trailing message → need more bytes from the socket.
			async_exit_status = PG_EVENT_READ;
			return;
		}
		// FRAME_ERROR: malformed backend message length.
		// Same class as the illegal-type guard above: ProxySQL decided this stream is not
		// the protocol, so the client is told why rather than being left to infer it from a
		// dropped connection.
		native_result_protocol_violation("malformed backend message during result fetch");
		return;
	}
}

// ---- native_reset_session_cont ----

// Finish sending a reset command and read its reply, which is thrown away: a
// connection being reset has no client waiting for it. Reading stops at
// ReadyForQuery. Two things in the reply are kept -- the transaction status, which
// decides whether a second command is still owed, and an error, because a reset that
// failed must not be reported as done or a dirty connection goes back in the pool.
void PgSQL_Connection_Native::native_reset_session_cont() {
	async_exit_status = PG_EVENT_NONE;

	// A command that did not fit in one write has to be finished before its reply
	// can arrive.
	if (!native_outbuf.empty() || !native_ssl_outbuf.empty()) {
		if (!native_flush_outbuf()) {
			native_result_fatal(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "send failed during reset");
			return;
		}
		if (!native_outbuf.empty() || !native_ssl_outbuf.empty()) {
			async_exit_status = PG_EVENT_WRITE;
			return;
		}
	}

	for (;;) {
		PgSQL_Backend_Msg msg;
		PgSQL_Frame_Result fr = native_framer.next(msg);
		if (fr == FRAME_NEED_MORE) {
			int r = native_recv_into_framer();
			if (r == 0) { // EAGAIN
				async_exit_status = PG_EVENT_READ;
				return;
			}
			if (r < 0) {
				native_result_fatal(PGSQL_GET_ERROR_CODE_STR(ERRCODE_CONNECTION_FAILURE), "backend closed during reset");
				return;
			}
			continue;
		}
		if (fr == FRAME_ERROR) {
			native_result_fatal(PGSQL_GET_ERROR_CODE_STR(ERRCODE_PROTOCOL_VIOLATION), "malformed backend message during reset");
			return;
		}
		switch (msg.type) {
		case 'E': // the backend refused the command; ReadyForQuery still follows it
			native_fill_error_from_E(msg.payload, msg.payload_len);
			break;
		case 'S': // ParameterStatus: DISCARD ALL reverts reported settings and says so
			native_track_parameter_status(msg.payload, msg.payload_len);
			break;
		case 'Z': // ReadyForQuery: the reply is complete
			if (msg.payload_len >= 1) set_ready_for_query_status((char)msg.payload[0]);
			return;
		default:
			// CommandComplete and NoticeResponse: nothing to keep.
			break;
		}
	}
}


// --- Step 5b: the base asking the transport for its own state ---
// backend_is_live() is the only one of the six with a real answer. It was the base's
// `if (native_mode) { return fd >= 0 && native_connected; }` arm, and it became pure in
// step 5b, so the body came here with native_connected. The comment is the one the base
// carried, kept because the reasoning is still load-bearing: do not substitute
// native_st, which moves back to a sending state whenever a large query cannot be
// written in one go, which would make a healthy connection look dead.
bool PgSQL_Connection_Native::backend_is_live() const {
	return fd >= 0 && native_connected;
}

// The other five were `if (pgsql_conn)` guards or libpq-only member reads in base
// functions, and pgsql_conn is permanently NULL on this transport, so none of them ever
// did anything here either. Saying so in the bodies keeps the next reader from looking
// for the transport work that is missing.

const PGconn* PgSQL_Connection_Native::get_pg_connection() const {
	// plan:236-237. nullptr is load-bearing, not incidental: the native query
	// differential test uses the NULL address as its native oracle.
	return nullptr;
}

void PgSQL_Connection_Native::compute_unknown_transaction_status() {
	// Was the base's `if (pgsql_conn) { ... }` guard around the PQtransactionStatus()
	// switch. This transport tracks its own native_txn_status and never asked libpq,
	// so there is nothing to compute here.
}

void PgSQL_Connection_Native::free_transport_result() {
	// The PQclear() of a PGresult. The native fetch path streams bytes into
	// PgSQL_Query_Result directly and never builds one.
}

void PgSQL_Connection_Native::reset_fetch_result_state() {
	// result_type and ps_result are the libpq result shape. The native framer keeps
	// its own per-message state and resets it where a fetch cycle starts.
}

bool PgSQL_Connection_Native::handle_ready_past_connect_start() const {
	// This transport has no PGconn at any point in its life, so "the handle is present"
	// has nothing to answer and the invariant cannot be violated. The native
	// equivalent -- the socket is open and login finished -- is a different question
	// with a different answer for a connection mid-handshake, and that is
	// backend_is_live()'s to answer.
	return true;
}

void PgSQL_Connection_Native::reset_transport_state() {
	// exit_pipeline_mode and PQpipelineStatus() are libpq's; a native connection is
	// never in pipeline mode.
}
