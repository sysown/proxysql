#include "PgSQL_Connection_LibPQ.h"
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

// Defined in PgSQL_Connection.cpp; the libpq connect path is their only caller.
void append_conninfo_param(std::ostringstream& conninfo, const char* key, char* val);
bool pgsql_append_conninfo_credentials(std::ostringstream& conninfo, const char* username,
	char* password, bool has_scram_keys, const uint8_t* scram_client_key,
	const uint8_t* scram_server_key, const char* conn_ctx);

PgSQL_Connection_LibPQ::PgSQL_Connection_LibPQ()
	: PgSQL_Connection(false, false)
{
}

PgSQL_Connection_LibPQ::~PgSQL_Connection_LibPQ() {
	// The libpq transport's own resources. A leaf destructor runs before the base
	// body, so these three happen ahead of the shared cleanup instead of in the
	// middle of it. Nothing that runs later needs them: PQclear() takes only a
	// PGresult, the BIOs are this connection's own, and async_free_result() reads
	// userinfo, local_stmts and query_result -- all still alive, because the base
	// body is what deletes those.
	if (pgsql_result) {
		PQclear(pgsql_result);
		pgsql_result = NULL;
	}
	// Still held here means a relay went away without releasing it. Drop it so it
	// cannot outlive the connection.
	// BIO_free, not BIO_free_all: this is the reference adopt_backend_tls() took
	// with BIO_up_ref, and the chain behind it belongs to libpq.
	if (saved_backend_wbio && saved_backend_wbio != saved_backend_rbio) {
		BIO_free(saved_backend_wbio);
	}
	if (saved_backend_rbio) {
		BIO_free(saved_backend_rbio);
	}
	saved_backend_rbio = NULL;
	saved_backend_wbio = NULL;
	if (pgsql_conn) {
		// async_free_result() first, and while pgsql_conn is still a live handle:
		// it calls compute_unknown_transaction_status(), which asks PQstatus() and
		// PQtransactionStatus() about it. PQfinish() has to come after, as it did.
		async_free_result();
		PQfinish(pgsql_conn);
		pgsql_conn = NULL;
	}
}

bool PgSQL_Connection_LibPQ::set_single_row_mode() {
	assert(pgsql_conn);
	if (PQsetSingleRowMode(pgsql_conn) == 0) {
		set_error_from_PQerrorMessage();
		proxy_error("Failed to set single row mode. %s\n", get_error_code_with_message().c_str());
		return false;
	}
	return true;
}

PgSQL_Connection::HandlerStep PgSQL_Connection_LibPQ::on_connect_end() {
	// libpq hands back a blocking socket, and this is where it stops blocking.
	if (PQisnonblocking(pgsql_conn) == false) {
		// Set non-blocking mode
		if (PQsetnonblocking(pgsql_conn, 1) != 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to set non-blocking mode: %s\n", get_error_code_with_message().c_str());
			return go(ASYNC_CONNECT_FAILED);
		}
	}
	return HandlerStep::CONTINUE;
}

void PgSQL_Connection_LibPQ::on_connect_successful() {
	// Seed the PgSQL DNS cache from the just-established connection so the next
	// connect for this hostname can skip getaddrinfo even if the background
	// resolver loop hasn't visited it yet.
	PgSQL_Monitor::update_dns_cache_from_pgsql_conn(pgsql_conn);
}

void PgSQL_Connection_LibPQ::on_connect_failed() {
	// Nothing: the PGConn is left for the destructor to PQfinish(). A connect that
	// failed is never pooled, so there is nothing to release early either.
}

bool PgSQL_Connection_LibPQ::defer_first_result_read() {
	// false: the request really is on the wire and readable now, because
	// ASYNC_QUERY_CONT only hands over once the flush reported it was.
	return false;
}

PgSQL_Connection::HandlerStep PgSQL_Connection_LibPQ::fetch_result_dispatch(short event, uint64_t* processed_bytes) {
	fetch_result_cont(event);
	if (async_exit_status) {
		next_event(ASYNC_USE_RESULT_CONT);
		return HandlerStep::YIELD;
	}

	// Issue #6109: the fetch produced nothing to dispatch. fetch_result_cont()
	// returns from its PQconsumeInput() failure without assigning result_type, so
	// the dispatch below would act on the previous iteration's value; its other
	// empty returns set async_exit_status and were handled above. The transport may
	// also be gone with a result already taken (result_type 1 or 2 and a NULL
	// pgsql_result), which libpq reports as CONNECTION_BAD.
	//
	// End the cycle either way, so async_query() returns -1 and the session
	// destroys the connection and unplugs the dead fd. Not is_error_present():
	// that is also true for an ordinary backend ERROR, which must keep flowing
	// through the PGRES_FATAL_ERROR arm below. pgsql_result == NULL keeps a pending
	// multi-statement result dispatching first. is_copy_out is cleared because a
	// backend dying mid-COPY would otherwise reach the end state with it still set.
	if (result_type == 0 || (pgsql_result == NULL && PQstatus(pgsql_conn) == CONNECTION_BAD)) {
		is_copy_out = false;
		if (!is_error_present()) {
			set_error(PGSQL_ERROR_CODES::ERRCODE_CONNECTION_FAILURE,
				"backend connection lost mid-result", false);
		}
		return go(fetch_result_end_st);
	}

	if (result_type == 1) {
		std::unique_ptr<PGresult, decltype(&PQclear)> result(get_result(), PQclear);

		if (result) {

			const ExecStatusType exec_status_type = PQresultStatus(result.get());

			// Multi-statements are supported only in simple queries
			if (fetch_result_end_st == ASYNC_QUERY_END &&
				(query_result->get_result_packet_type() & (PGSQL_QUERY_RESULT_COMMAND | PGSQL_QUERY_RESULT_EMPTY | PGSQL_QUERY_RESULT_ERROR))) {
				next_multi_statement_result(result.release());
				next_event(ASYNC_USE_RESULT_START);
				return HandlerStep::YIELD;
			}

			switch (exec_status_type) {
			case PGRES_COMMAND_OK:
				{
					unsigned int bytes_recv = 0;
					switch (fetch_result_end_st)
					{
					case ASYNC_STMT_PREPARE_END:
						bytes_recv = query_result->add_parse_completion();
						break;
					case ASYNC_STMT_DESCRIBE_END:
						bytes_recv = query_result->add_describe_completion(result.get(), query.extended_query_info->stmt_type);
						break;
					case ASYNC_STMT_EXECUTE_END:
						// PQsendQueryPrepared sends the sequence BIND -> DESCRIBE(PORTAL) -> EXECUTE -> SYNC
						// Since libpq does not indicate whether the DESCRIBE PORTAL step produced a
						// NoData packet for commands such as INSERT, DELETE, or UPDATE.
						// In these cases, libpq returns PGRES_COMMAND_OK (whereas SELECT statements
						// yield PGRES_SINGLE_TUPLE or PGRES_TUPLES_OK). Therefore, it is safe to
						// explicitly append a NoData packet to the result.
						if ((query.extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_DESCRIBE_PORTAL) != 0) {
							bytes_recv = query_result->add_no_data();
						}
						// fallthrough
					default:
						bytes_recv += query_result->add_command_completion(result.get());
						break;
					}
					update_bytes_recv(bytes_recv);
				}
				return go(ASYNC_USE_RESULT_CONT);
			case PGRES_EMPTY_QUERY:
				{
					unsigned int bytes_recv = 0;

					if (fetch_result_end_st == ASYNC_STMT_EXECUTE_END) {
						if ((query.extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_DESCRIBE_PORTAL) != 0) {
							bytes_recv = query_result->add_no_data();
						}
					}
					bytes_recv += query_result->add_empty_query_response(result.get());
					update_bytes_recv(bytes_recv);
				}
				return go(ASYNC_USE_RESULT_CONT);
			case PGRES_TUPLES_OK:
			case PGRES_SINGLE_TUPLE:
				break;
			case PGRES_COPY_OUT:
				if (handle_copy_out(result.get(), processed_bytes) == false) {
					next_event(ASYNC_USE_RESULT_CONT);
					return HandlerStep::YIELD; // Threashold for result size reached. Pause temporarily
				}
				return go(ASYNC_USE_RESULT_CONT);
			case PGRES_COPY_IN:
			case PGRES_COPY_BOTH:
				// disconnect client session (and backend connection) if COPY (STDIN) command bypasses the initial checks.
				// This scenario should be handled in fast-forward mode and should never occur at this point.
				if (myds && myds->sess) {
					proxy_warning("Unable to process the '%s' command from client %s:%d. Please report a bug for future enhancements.\n",
						myds->sess->CurrentQuery.QueryParserArgs.digest_text ? myds->sess->CurrentQuery.QueryParserArgs.digest_text : "COPY",
						myds->sess->client_myds->addr.addr, myds->sess->client_myds->addr.port);
				} else {
					proxy_warning("Unable to process the 'COPY' command. Please report a bug for future enhancements.\n");
				}
				set_error(PGSQL_ERROR_CODES::ERRCODE_RAISE_EXCEPTION, "Unable to process 'COPY' command", true);
				return go(fetch_result_end_st);
			case PGRES_PIPELINE_SYNC:
				// backend connection is in Ready for Query state, we can now safely exit pipeline mode
				exit_pipeline_mode = true;
				return go(ASYNC_USE_RESULT_CONT);
			case PGRES_PIPELINE_ABORTED:
				// received an extended query immediately after an error was triggered by a previous query (before sync).
				// In ProxySQL this should never happen, since the extended query frame is reset after an error.
				// However, it may rarely occur if an error is raised during the "describe portal" phase (while executing).
				// In that case, we continue until PGRES_PIPELINE_SYNC (Ready for Query state) is received, then safely exit pipeline mode.
				return go(ASYNC_USE_RESULT_CONT);
			case PGRES_BAD_RESPONSE:
			case PGRES_NONFATAL_ERROR:
			case PGRES_FATAL_ERROR:
			default:
				// if on previous call we encountered a FATAL error, we will not process the result, as it will contain residual protocol messages
				// from the broken connection
				if (is_error_present() == true && get_error_severity() == PGSQL_ERROR_SEVERITY::ERRSEVERITY_FATAL) {
					return go(ASYNC_USE_RESULT_CONT);
				}

				// we don't have a command completion, empty query responseor error packet in the result. This check is here to
				// handle internal cleanup of libpq that might return residual protocol messages from the broken connection and
				// may add multiple final packets.
				//if ((query_result->get_result_packet_type() & (PGSQL_QUERY_RESULT_COMMAND | PGSQL_QUERY_RESULT_EMPTY | PGSQL_QUERY_RESULT_ERROR)) == 0) {
				set_error_from_result(result.get(), PGSQL_ERROR_FIELD_ALL);
				assert(is_error_present());

				// we will not send FATAL error messages to the client
				const PGSQL_ERROR_SEVERITY severity = get_error_severity();
				if (severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_ERROR ||
					severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_WARNING ||
					severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_NOTICE) {

					const unsigned int bytes_recv = query_result->add_error(result.get());
					update_bytes_recv(bytes_recv);
				}

				const PGSQL_ERROR_CATEGORY error_category = get_error_category();
				if (error_category != PGSQL_ERROR_CATEGORY::ERRCATEGORY_SYNTAX_ERROR &&
					error_category != PGSQL_ERROR_CATEGORY::ERRCATEGORY_STATUS &&
					error_category != PGSQL_ERROR_CATEGORY::ERRCATEGORY_DATA_ERROR) {
					proxy_error("Error: %s, Multi-Statement: %d\n", get_error_code_with_message().c_str(), processing_multi_statement);
				}
				return go(ASYNC_USE_RESULT_CONT);
			}

			if (new_result == true) {
				bool should_add_row_description = true;

				// In extended query mode, we should add RowDescription only if the DESCRIBE PORTAL message was sent
				// before the EXECUTE message.
				if (fetch_result_end_st == ASYNC_STMT_EXECUTE_END) {
					should_add_row_description =
						(query.extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_DESCRIBE_PORTAL) != 0;
				}

				if (should_add_row_description) {
					const auto bytes_recv = query_result->add_row_description(result.get());
					update_bytes_recv(bytes_recv);
				} else {
					query_result->num_fields = PQnfields(result.get());
				}

				new_result = false;
			}

			if (PQntuples(result.get()) > 0) {
				const unsigned int bytes_recv = query_result->add_row(result.get());
				update_bytes_recv(bytes_recv);
				*processed_bytes += bytes_recv;	// issue #527 : bytes processed during this event, added to the caller's counter

				if (suspend_resultset_fetch(*processed_bytes)) {
					next_event(ASYNC_USE_RESULT_CONT); // we temporarily pause
					return HandlerStep::YIELD;
				} else {
					return go(ASYNC_USE_RESULT_CONT); // we continue looping
				}
			} else {
				const unsigned int bytes_recv=query_result->add_command_completion(result.get(), false);
				update_bytes_recv(bytes_recv);
				return go(ASYNC_USE_RESULT_CONT);
			}
		}
	} else if (result_type == 2) {
		if (ps_result.id == 'D') {
			unsigned int bytes_recv=query_result->add_row(&ps_result);
			update_bytes_recv(bytes_recv);
			*processed_bytes += bytes_recv;	// issue #527 : bytes processed during this event, added to the caller's counter

			if (suspend_resultset_fetch(*processed_bytes)) {
				next_event(ASYNC_USE_RESULT_CONT); // we temporarily pause
				return HandlerStep::YIELD;
			} else {
				return go(ASYNC_USE_RESULT_CONT); // we continue looping
			}
		} else {
			assert(0);
		}
	} else {
		assert(0);
	}

	// if we arrive here via async_perform_resync, the connection is in "Ready for Query" state,
	// but query_result will be empty. In this case, we check exit_pipeline_mode; if it is true,
	// it indicates a non-error scenario and we skip this check.
	// exit_pipeline_mode means an async_perform_resync left the result empty on purpose.
	if (exit_pipeline_mode == false) {
		reject_result_without_outcome();
	}

	if (fetch_result_end_st != ASYNC_QUERY_END) {
		bool has_error = (query_result->get_result_packet_type() & PGSQL_QUERY_RESULT_ERROR) != 0;

		// Normally, ReadyForQuery is not sent immediately if we are in extended query mode
		// and there are pending messages in the queue, as it will be sent once the entire
		// extended query frame has been processed.
		//
		// Edge case: if a message fails with an error while the queue still contains pending
		// messages, the queue will be cleared later in the session. In this situation,
		// ReadyForQuery would never be sent because the pending messages are discarded.
		//
		// Fix: if the result indicates an error, explicitly send ReadyForQuery immediately.
		// The extended query frame will still be reset later in the session.
		if (!myds->sess->is_extended_query_ready_for_query() && !has_error) {
			// Skip sending ReadyForQuery if there are still extended query messages pending in the queue
			return go(fetch_result_end_st);
		}

		// An error has occurred while executing extended query sequence,
		// and connection is not in 'Ready for Query' state, i.e., unsynchronized.
		// To recover, we must resync by sending a SYNC to the backend connection.
		if (!exit_pipeline_mode && has_error) {
			return go(ASYNC_RESYNC_START);
		}
	}

	// finally add ready for query packet
	query_result->add_ready_status(PQtransactionStatus(pgsql_conn));
	update_bytes_recv(6);
	//processing_multi_statement = false;
	return go(fetch_result_end_st);
}

void PgSQL_Connection_LibPQ::on_command_end() {
	PQsetNoticeReceiver(pgsql_conn, &PgSQL_Connection::unhandled_notice_cb, this);

	// we check exit_pipeline_mode to ensure it is safe to exit pipeline mode
	if (exit_pipeline_mode &&
		PQpipelineStatus(pgsql_conn) == PQ_PIPELINE_ON) {
		if (PQexitPipelineMode(pgsql_conn) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to exit pipeline mode. %s\n", get_error_code_with_message().c_str());
		}
		exit_pipeline_mode = false;
	}
}

bool PgSQL_Connection_LibPQ::resync_already_synced() {
	// Only askable here: PQpipelineStatus() answers PQ_PIPELINE_OFF for a NULL
	// handle, so the native transport must not make this test at all.
	if (PQpipelineStatus(pgsql_conn) == PQ_PIPELINE_OFF) {
		proxy_warning("Resync not required - connection already synchronized.\n");
		return true;
	}
	return false;
}

bool PgSQL_Connection_LibPQ::resync_send_failed() {
	// A failed Sync is reported with resync_failed and no error record:
	// resync_start() sets it when PQsendPipelineSync() returns 0, and flush(true)
	// sets it instead of setting an error. In ASYNC_RESYNC_START, arriving at the
	// "everything was sent" arm at all implies it, which is what lets the shared
	// form stand in for the old libpq arm.
	return resync_failed;
}

PgSQL_Connection::HandlerStep PgSQL_Connection_LibPQ::reset_session_cont_dispatch() {
	PGresult* result = get_result();
	if (result) {
		if (PQresultStatus(result) != PGRES_COMMAND_OK &&
			PQresultStatus(result) != PGRES_PIPELINE_SYNC) {
			set_error_from_result(result, PGSQL_ERROR_FIELD_ALL);
			assert(is_error_present());
		}
		PQclear(result);
		return go(ASYNC_RESET_SESSION_CONT);
	}
	if (reset_session_in_pipeline) {
		if (PQexitPipelineMode(pgsql_conn) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to exit pipeline mode. %s\n", get_error_code_with_message().c_str());
			return go(ASYNC_RESET_SESSION_END);
		}
		reset_session_in_pipeline = false;
		return go(ASYNC_RESET_SESSION_START);
	}
	if (reset_session_in_txn) {
		reset_session_in_txn = false;
		return go(ASYNC_RESET_SESSION_START);
	}
	return go(ASYNC_RESET_SESSION_END);
}

void PgSQL_Connection_LibPQ::on_reset_session_end() {
	PQsetNoticeReceiver(pgsql_conn, &PgSQL_Connection::unhandled_notice_cb, this);
}

const char* PgSQL_Connection_LibPQ::transport_name() const {
	return "libpq";
}

void PgSQL_Connection_LibPQ::connect_start() {
	PROXY_TRACE();
	assert(pgsql_conn == NULL); // already there is a connection
	reset_error();
	async_exit_status = PG_EVENT_NONE;

	std::ostringstream conninfo;
	append_conninfo_param(conninfo, "user", userinfo->username); // username
	if (pgsql_append_conninfo_credentials(conninfo, userinfo->username, userinfo->password,
		userinfo->has_scram_keys, userinfo->scram_client_key, userinfo->scram_server_key, "connect") == false) {
		// Fail closed. Leaving pgsql_conn NULL and async_exit_status at PG_EVENT_NONE routes
		// handler() to ASYNC_CONNECT_END -> ASYNC_CONNECT_FAILED, the same path a PQconnectStart()
		// failure below already takes, so the client gets a clean error instead of a wrong login.
		set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_INVALID_AUTHORIZATION_SPECIFICATION),
			"no usable backend credential for this user", false);
		return;
	}
	append_conninfo_param(conninfo, "dbname", userinfo->dbname); // dbname
	append_conninfo_param(conninfo, "host", parent->address); // backend address
	// If the DNS cache has resolved this hostname already, also pass
	// hostaddr=<ip>.  libpq documents this combo specifically to skip name
	// resolution while keeping the hostname for TLS verification and error
	// messages.  Empty IP -> cache miss / IP literal / disabled, leave as-is.
	{
		const std::string ip = connect_start_DNS_lookup();
		if (!ip.empty() && ip != std::string(parent->address)) {
		append_conninfo_param(conninfo, "hostaddr", const_cast<char*>(ip.c_str()));
		}
	}
	// port=0 means hostname is a Unix-domain socket path; libpq rejects
	// "port=0" with "invalid port number: \"0\"".
	if (parent->port != 0) {
		conninfo << "port=" << parent->port << " ";
	}
	conninfo << "application_name=proxysql "; // application name
	//conninfo << "require_auth=" << AUTHENTICATION_METHOD_STR[pgsql_thread___authentication_method]; // authentication method
	if (parent->use_ssl) {
		conninfo << "sslmode='require' "; // SSL required
		std::unique_ptr<PgSQLServers_SslParams> ssl_params {
			PgHGM->get_Server_SSL_Params(parent->address, parent->port, userinfo->username)
		};
		if (ssl_params != nullptr) {
			// Use per-server SSL params
			if (ssl_params->ssl_key.length() > 0)
				append_conninfo_param(conninfo, "sslkey", (char*)ssl_params->ssl_key.c_str());
			if (ssl_params->ssl_cert.length() > 0)
				append_conninfo_param(conninfo, "sslcert", (char*)ssl_params->ssl_cert.c_str());
			if (ssl_params->ssl_ca.length() > 0)
				append_conninfo_param(conninfo, "sslrootcert", (char*)ssl_params->ssl_ca.c_str());
			if (ssl_params->ssl_crl.length() > 0)
				append_conninfo_param(conninfo, "sslcrl", (char*)ssl_params->ssl_crl.c_str());
			if (ssl_params->ssl_crlpath.length() > 0)
				append_conninfo_param(conninfo, "sslcrldir", (char*)ssl_params->ssl_crlpath.c_str());
			// ssl_protocol_version_range was pre-parsed at PgSQLServers_SslParams
			// construction time (see parse_tls_version()). Empty min/max means
			// either unset or malformed — in both cases libpq defaults apply.
			if (ssl_params->ssl_min_protocol_version.length() > 0)
				append_conninfo_param(conninfo, "ssl_min_protocol_version", (char*)ssl_params->ssl_min_protocol_version.c_str());
			if (ssl_params->ssl_max_protocol_version.length() > 0)
				append_conninfo_param(conninfo, "ssl_max_protocol_version", (char*)ssl_params->ssl_max_protocol_version.c_str());
		} else {
			// Fall back to global SSL settings
			append_conninfo_param(conninfo, "sslkey", pgsql_thread___ssl_p2s_key);
			append_conninfo_param(conninfo, "sslcert", pgsql_thread___ssl_p2s_cert);
			append_conninfo_param(conninfo, "sslrootcert", pgsql_thread___ssl_p2s_ca);
			append_conninfo_param(conninfo, "sslcrl", pgsql_thread___ssl_p2s_crl);
			append_conninfo_param(conninfo, "sslcrldir", pgsql_thread___ssl_p2s_crlpath);
		}
	} else {
		conninfo << "sslmode='disable' "; // not supporting SSL
	}

	{
		std::string startup_encoding, startup_options;
		if (build_and_record_startup_session_params(startup_encoding, startup_options,
		                                           StartupParamEscape::Conninfo)) {
			conninfo << "client_encoding='" << startup_encoding << "' ";
			// Join the "-c key=value" tokens with a leading separator so the options value
			// has no trailing space before the closing quote. PgBouncer rejects a startup
			// packet whose options value ends in whitespace (#5801).
			conninfo << "options='" << startup_options << "'";
		}
	}

	/*conninfo << "postgres://";
	 conninfo << userinfo->username << ":" << userinfo->password; // username and password
	 conninfo << "@";
	 conninfo << parent->address << ":" << parent->port; // backend address and port
	 conninfo << "/";
	 conninfo << userinfo->schemaname; // currently schemaname consists of datasename (have to improve this in future). In PostgreSQL database and schema are NOT the same.
	 conninfo << "?";
	 //conninfo << "require_auth=" << AUTHENTICATION_METHOD_STR[pgsql_thread___authentication_method]; // authentication method
	 conninfo << "application_name=proxysql";
	*/

	const std::string& conninfo_str = conninfo.str();
	pgsql_conn = PQconnectStart(conninfo_str.c_str());

	// introduced a new, formatted error verbosity type.
	PQsetErrorVerbosity(pgsql_conn, PSERRORS_FORMATTED_DEFAULT);
	//PQsetErrorContextVisibility(pgsql_conn, PQSHOW_CONTEXT_ERRORS);

	if (pgsql_conn == NULL || PQstatus(pgsql_conn) == CONNECTION_BAD) {
		if (pgsql_conn) {
			set_error_from_PQerrorMessage();
		} else {
			set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_OUT_OF_MEMORY), "Out of memory", false);
		}
		proxy_error("Connect failed. %s\n", get_error_code_with_message().c_str());
		return;
	}
	if (PQsetnonblocking(pgsql_conn, 1) != 0) {
		set_error_from_PQerrorMessage();
		proxy_error("Failed to set non-blocking mode: %s\n", get_error_code_with_message().c_str());
		return;
	}
	fd = PQsocket(pgsql_conn);
	async_exit_status = PG_EVENT_WRITE;
}

void PgSQL_Connection_LibPQ::connect_cont(short event) {
	PROXY_TRACE();
	assert(pgsql_conn);
	reset_error();
	async_exit_status = PG_EVENT_NONE;

// For troubleshooting connection issue
#if 0
	const char* message = nullptr;
	switch (PQstatus(pgsql_conn))
	{
	case CONNECTION_STARTED:
		message = "Connecting...";
		break;

	case CONNECTION_MADE:
		message = "Connected to server (waiting to send) ...";
		break;

	case CONNECTION_AWAITING_RESPONSE:
		message = "Waiting for a response from the server...";
		break;

	case CONNECTION_AUTH_OK:
		message = "Received authentication; waiting for backend start - up to finish...";
		break;

	case CONNECTION_SSL_STARTUP:
		message = "Negotiating SSL encryption...";
		break;
	
	case CONNECTION_SETENV:
		message = "Negotiating environment-driven parameter settings...";
		break;

	default:
		message = "Connecting...";
	}

	proxy_info("Connection status: %d %s\n", PQsocket(pgsql_conn), message);
#endif

	PostgresPollingStatusType poll_res = PQconnectPoll(pgsql_conn);
	switch (poll_res) {
	case PGRES_POLLING_WRITING:
		async_exit_status = PG_EVENT_WRITE;
		break;
	case PGRES_POLLING_ACTIVE: // Not used
	case PGRES_POLLING_READING:
		async_exit_status = PG_EVENT_READ;
		break;
	case PGRES_POLLING_OK:
		async_exit_status = PG_EVENT_NONE;
		break;
	//case PGRES_POLLING_FAILED:
	default:
		set_error_from_PQerrorMessage();
		proxy_error("Connect failed. %s\n", get_error_code_with_message().c_str());
	}
	int current_fd = PQsocket(pgsql_conn);
	if (current_fd != fd) {
		proxy_warning("PgSQL Connection FD has been changed by PQconnectPoll(). oldFD:%d newFD:%d\n", fd, current_fd);
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "PgSQL Connection FD has been changed by PQconnectPoll()"
			"Session=%p, Conn=%p, myds=%p, oldFD=%d, newFD=%d\n", myds->sess, this, myds, fd, current_fd);
		fd = current_fd;
	}
}

void PgSQL_Connection_LibPQ::query_start() {
	PROXY_TRACE();
	reset_error();
	processing_multi_statement = false;
	async_exit_status = PG_EVENT_NONE;

	PQsetNoticeReceiver(pgsql_conn, &PgSQL_Connection::notice_handler_cb, this);

	if (PQsendQuery(pgsql_conn, query.ptr) == 0) {
		set_error_from_PQerrorMessage();
		proxy_error("Failed to send query. %s\n", get_error_code_with_message().c_str());
		return;
	}
	flush();
}

void PgSQL_Connection_LibPQ::query_cont(short event) {
	PROXY_TRACE();
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "event=%d\n", event);
	async_exit_status = PG_EVENT_NONE;
	if (event & POLLOUT) {
		flush();
	}
}

void PgSQL_Connection_LibPQ::fetch_result_cont(short event) {
	PROXY_TRACE();
	async_exit_status = PG_EVENT_NONE;

	// Avoid fetching a new result if one is already available.
	// This situation can happen when a multi-statement query has been executed.
	// result_type must be set: fetch_result_start() zeroed it for this cycle, so
	// without this the caller would dispatch on 0 instead of the pending result.
	if (pgsql_result) {
		result_type = 1;
		return;
	}

	if (is_copy_out == false) {
		switch (PShandleRowData(pgsql_conn, new_result, &ps_result)) {
		case 0:
			result_type = 2;
			return;
		case 1:
			// we already have data available in buffer
			if (PQisBusy(pgsql_conn) == 0) {
				result_type = 1;
				pgsql_result = PQgetResult(pgsql_conn);

				if (!pgsql_result &&
					query.extended_query_info &&
					(query.extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_SYNC) != 0) {
					pgsql_result = PQgetResult(pgsql_conn);
				}
				return;
			}
			break;
		}
	}

	if (PQconsumeInput(pgsql_conn) == 0) {
		/* We will only set the error if we didn't capture error in last call. If is_error_present is true,
		 * it indicates that an error was already captured during a previous PQconsumeInput call,
		 * and we do not want to overwrite that information.
		 */
		if (is_error_present() == false) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to consume input. %s\n", get_error_code_with_message().c_str());
		}
		return;
	}

	switch (PShandleRowData(pgsql_conn, new_result, &ps_result)) {
	case 0:
		result_type = 2;
		return;
	case 1:
		if (PQisBusy(pgsql_conn)) {
			async_exit_status = PG_EVENT_READ;
			return;
		}
		break;
	default:
		async_exit_status = PG_EVENT_READ;
		return;
	}
	result_type = 1;
	pgsql_result = PQgetResult(pgsql_conn);

	if (!pgsql_result &&
		query.extended_query_info &&
		(query.extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_SYNC) != 0) {
		pgsql_result = PQgetResult(pgsql_conn);
	}
}

// Returns:
// 0 when the ping is completed successfully
// -1 when the ping is completed not successfully
// 1 when the ping is not completed
// -2 on timeout
// the calling function should check pgsql error in pgsql struct
int PgSQL_Connection_LibPQ::async_ping(short event) {
	PROXY_TRACE();
	// In native_mode pgsql_conn is permanently NULL; the libpq ping path is
	// not applicable. Pretend the ping succeeded; the native path keeps its
	// own liveness state via the socket readiness callback.
	assert(pgsql_conn);
	switch (async_state_machine) {
	case ASYNC_PING_SUCCESSFUL:
		unknown_transaction_status = false;
		async_state_machine = ASYNC_IDLE;
		return 0;
		break;
	case ASYNC_PING_FAILED:
		return -1;
		break;
	case ASYNC_PING_TIMEOUT:
		return -2;
		break;
	case ASYNC_IDLE:
		async_state_machine = ASYNC_PING_START;
	default:
		//handler(event);
		async_state_machine = ASYNC_PING_SUCCESSFUL;
		break;
	}

	// check again
	switch (async_state_machine) {
	case ASYNC_PING_SUCCESSFUL:
		unknown_transaction_status = false;
		async_state_machine = ASYNC_IDLE;
		return 0;
		break;
	case ASYNC_PING_FAILED:
		return -1;
		break;
	case ASYNC_PING_TIMEOUT:
		return -2;
		break;
	default:
		return 1;
		break;
	}
	return 1;
}

bool PgSQL_Connection_LibPQ::IsKnownActiveTransaction() {
	// Callers use this to decide whether a failed statement can safely be run
	// again on a different connection. A connection that died in the middle of a
	// transaction must still say it has one, otherwise the statement would be
	// re-run on its own, outside that transaction. Do not add a liveness check
	// here -- the answer has to survive the connection dying.
	if (!pgsql_conn) return false;

	PGTransactionStatusType status = PQtransactionStatus(pgsql_conn);
	if (status == PQTRANS_INTRANS || status == PQTRANS_INERROR) {
		return true;
	}

	// In pipeline mode, libpq status may be stale because ReadyForQuery hasn't been processed yet
	// Use the session's transaction state manager which tracks BEGIN/COMMIT/ROLLBACK via SQL parsing
	if (PQpipelineStatus(pgsql_conn) == PQ_PIPELINE_ON && myds && myds->sess) {
		return myds->sess->is_in_transaction();
	}

	return false;
}

void PgSQL_Connection_LibPQ::stmt_prepare_start() {
	PROXY_TRACE();
	reset_error();
	processing_multi_statement = false;
	async_exit_status = PG_EVENT_NONE;

	if (PQpipelineStatus(pgsql_conn) == PQ_PIPELINE_OFF) {
		if (PQenterPipelineMode(pgsql_conn) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to enter pipeline mode. %s\n", get_error_code_with_message().c_str());
			return;
		}
	}
	
	PQsetNoticeReceiver(pgsql_conn, &PgSQL_Connection::notice_handler_cb, this);

	const PgSQL_Extended_Query_Info* extended_query_info = query.extended_query_info;
	const Parse_Param_Types& parse_param_types = extended_query_info->parse_param_types;

	if (PQsendPrepare(pgsql_conn, query.backend_stmt_name, query.ptr, parse_param_types.size(), parse_param_types.data()) == 0) {
		set_error_from_PQerrorMessage();
		proxy_error("Failed to send prepare. %s\n", get_error_code_with_message().c_str());
		return;
	}

	// Send a Flush if this is not the last extended query message in the sequence/frame (or is an implicit prepared);  
	// otherwise, send a SYNC.
	if ((extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_IMPLICIT_PREPARE) != 0 ||
		(extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_SYNC) == 0) {
		if (PQsendFlushRequest(pgsql_conn) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to send flush request. %s\n", get_error_code_with_message().c_str());
			return;
		}
	} else {
		if (PQsendPipelineSync(pgsql_conn) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to send pipeline sync. %s\n", get_error_code_with_message().c_str());
			return;
		}
	}
	flush();
}

void PgSQL_Connection_LibPQ::stmt_prepare_cont(short event) {
	PROXY_TRACE();
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "event=%d\n", event);
	async_exit_status = PG_EVENT_NONE;
	if (event & POLLOUT) {
		flush();
	}
}

void PgSQL_Connection_LibPQ::stmt_describe_start() {
	PROXY_TRACE();
	reset_error();
	processing_multi_statement = false;
	async_exit_status = PG_EVENT_NONE;

	if (PQpipelineStatus(pgsql_conn) == PQ_PIPELINE_OFF) {
		if (PQenterPipelineMode(pgsql_conn) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to enter pipeline mode. %s\n", get_error_code_with_message().c_str());
			return;
		}
	}

	PQsetNoticeReceiver(pgsql_conn, &PgSQL_Connection::notice_handler_cb, this);

	const PgSQL_Extended_Query_Info* extended_query_info = query.extended_query_info;

	switch (extended_query_info->stmt_type) {
	case 'P': // Portal
		if (PQsendDescribePortal(pgsql_conn, extended_query_info->stmt_client_portal_name) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to send describe portal message. %s\n", get_error_code_with_message().c_str());
			return;
		}
		break;
	case 'S': // Prepared Statement
		if (PQsendDescribePrepared(pgsql_conn, query.backend_stmt_name) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to send describe prepared statement. %s\n", get_error_code_with_message().c_str());
			return;
		}
		break;
	default:
		set_error(PGSQL_ERROR_CODES::ERRCODE_INVALID_PARAMETER_VALUE, "Invalid statement type for describe", false);
		proxy_error("Failed to send describe message. %s\n", get_error_code_with_message().c_str());
		return;
	}

	// Send a Flush if this is not the last extended query message in the sequence/frame;  
	// otherwise, send a SYNC.
	if ((extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_SYNC) == 0) {
		if (PQsendFlushRequest(pgsql_conn) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to send flush request. %s\n", get_error_code_with_message().c_str());
			return;
		}
	} else {
		if (PQsendPipelineSync(pgsql_conn) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to send pipeline sync. %s\n", get_error_code_with_message().c_str());
			return;
		}
	}
	flush();
}

void PgSQL_Connection_LibPQ::stmt_describe_cont(short event) {
	PROXY_TRACE();
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "event=%d\n", event);
	async_exit_status = PG_EVENT_NONE;
	if (event & POLLOUT) {
		flush();
	}
}

void PgSQL_Connection_LibPQ::resync_start() {
	PROXY_TRACE();
	async_exit_status = PG_EVENT_NONE;

	PQsetNoticeReceiver(pgsql_conn, &PgSQL_Connection::notice_handler_cb, this);

	if (PQsendPipelineSync(pgsql_conn) == 0) {
		proxy_error("Failed to send pipeline sync.\n");
		resync_failed = true;
		return;
	}
	flush(true);
}

void PgSQL_Connection_LibPQ::resync_cont(short event) {
	PROXY_TRACE();
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "event=%d\n", event);
	async_exit_status = PG_EVENT_NONE;
	if (event & POLLOUT) {
		flush(true);
	}
}

void PgSQL_Connection_LibPQ::stmt_execute_cont(short event) {
	PROXY_TRACE();
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "event=%d\n", event);
	async_exit_status = PG_EVENT_NONE;
	if (event & POLLOUT) {
		flush();
	}
}

void PgSQL_Connection_LibPQ::reset_session_start() {
	PROXY_TRACE();
	assert(pgsql_conn);
	reset_error();
	async_exit_status = PG_EVENT_NONE;
	PQsetNoticeReceiver(pgsql_conn, &PgSQL_Connection::notice_handler_cb, this);

	reset_session_in_pipeline = is_pipeline_active();
	if (reset_session_in_pipeline) {
		if (PQsendPipelineSync(pgsql_conn) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to send pipeline sync. %s\n", get_error_code_with_message().c_str());
			return;
		}
	} else {
		reset_session_in_txn = IsKnownActiveTransaction();
		if (PQsendQuery(pgsql_conn, (reset_session_in_txn == false ? "DISCARD ALL" : "ROLLBACK")) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to send query. %s\n", get_error_code_with_message().c_str());
			return;
		}
	}
	flush();
}

void PgSQL_Connection_LibPQ::reset_session_cont(short event) {
	PROXY_TRACE();
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "event=%d\n", event);
	async_exit_status = PG_EVENT_NONE;
	if (event & POLLOUT) {
		flush();
		return;
	}

	if (PQconsumeInput(pgsql_conn) == 0) {
		/* We will only set the error if we didn't capture error in last call. If is_error_present is true,
		 * it indicates that an error was already captured during a previous PQconsumeInput call,
		 * and we do not want to overwrite that information.
		 */
		if (is_error_present() == false) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to consume input. %s\n", get_error_code_with_message().c_str());
		}
		return;
	}

	if (PQisBusy(pgsql_conn)) {
		async_exit_status = PG_EVENT_READ;
		return;
	}

	pgsql_result = PQgetResult(pgsql_conn);
}

void PgSQL_Connection_LibPQ::stmt_execute_start() {
	PROXY_TRACE();
	reset_error();
	processing_multi_statement = false;
	async_exit_status = PG_EVENT_NONE;

	// Named-portal Bind is a native-mode-only capability. The session gate keys on the
	// thread flag, but the backend connection assigned by find_or_create_backend may
	// have been established earlier in libpq mode (the flag was flipped with a warm
	// pool) — native_mode is fixed per-connection at creation. The libpq drive cannot
	// express named portals, so surface a clean FEATURE_NOT_SUPPORTED rather than
	// aborting. In a stable native-only deployment every backend conn is native and
	// this branch is never taken; it is a reachable operational edge, NOT a programming
	// error, so it must NOT assert.
	// A named Execute / resume (PORTAL_ALREADY_BOUND) is likewise native-only: the
	// native drive branch for it lives in PgSQL_Connection_Native and is unreachable
	// on this transport, so on a libpq-mode backend connection (flag flipped with a
	// warm pool) it would otherwise fall through to
	// the libpq Bind+Execute path below and silently re-Bind the unnamed portal with
	// the registry's stashed params — wrong semantics. Reject symmetrically with the
	// Bind/Close paths (defensive; unreachable in a stable native-only deployment).
	const bool named_execute_only =
		query.extended_query_info != nullptr &&
		(query.extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_PORTAL_ALREADY_BOUND) != 0;
	if (bind_only || close_only || named_execute_only) {
		set_error(PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED,
			"named portals require the native backend protocol", false);
		proxy_warning("native named-portal %s dispatched onto a libpq-mode backend connection "
			"(use_native_backend_protocol flipped with a warm pool); rejecting on fd=%d\n",
			close_only ? "Close" : (named_execute_only ? "Execute" : "Bind"), fd);
		return;
	}

	if (PQpipelineStatus(pgsql_conn) == PQ_PIPELINE_OFF) {
		if (PQenterPipelineMode(pgsql_conn) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to enter pipeline mode. %s\n", get_error_code_with_message().c_str());
			return;
		}
	}

	PQsetNoticeReceiver(pgsql_conn, &PgSQL_Connection::notice_handler_cb, this);

	const PgSQL_Extended_Query_Info* extended_query_info = query.extended_query_info;
	const PgSQL_Bind_Message* bind_msg = extended_query_info->bind_msg;
	assert(bind_msg); // should never be null
	const PgSQL_Bind_Data& bind_data = bind_msg->data(); // will always have valid data

	std::vector<const char*> param_values;
	std::vector<int> param_lengths;
	std::vector<int> param_formats;
	std::vector<int> result_formats;

	if (bind_data.num_param_values > 0) {
		auto param_value_reader = bind_msg->get_param_value_reader();

		param_values.resize(bind_data.num_param_values);
		param_lengths.resize(bind_data.num_param_values);

		for (int i = 0; i < bind_data.num_param_values; ++i) {
			PgSQL_Param_Value param_val;
			if (!param_value_reader.next(&param_val)) {
				proxy_error("Failed to read param value at index %u\n", i);
				set_error(PGSQL_ERROR_CODES::ERRCODE_INVALID_PARAMETER_VALUE,
					"Failed to read param value", false);
				return;
			}

			param_values[i] = (reinterpret_cast<const char*>(param_val.value));
			param_lengths[i] = param_val.len;
		}
	}

	if (bind_data.num_param_formats > 0) {
		auto param_fmt_reader = bind_msg->get_param_format_reader();

		param_formats.resize(bind_data.num_param_formats);

		for (int i = 0; i < bind_data.num_param_formats; ++i) {
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

	// Normalize param formats for libpq:
	// According to the PostgreSQL Bind message specification:
	// https://www.postgresql.org/docs/current/protocol-message-formats.html#PROTOCOL-MESSAGE-FORMATS-BIND
	//  - num_param_formats = 0 -> all parameters are TEXT
	//  - num_param_formats = 1 -> the single format applies to all parameters (even 0 of them)
	//  - num_param_formats = num_param_values -> formats are applied per-parameter in order
	// Any other number of parameter formats is a protocol error.
	if (!param_formats.empty()) {
		if (param_formats.size() == 1 && param_values.size() != 1) {
			// PostgreSQL protocol allows 1 format for all params, libpq DOES NOT,
			// so expand it (resize to 0 correctly clears it when there are no params, issue #5899)
			int fmt = param_formats[0];
			param_formats.resize(param_values.size(), fmt);
		} else if (param_formats.size() != param_values.size()) {
			// Mirror PostgreSQL's exec_bind_message() wording and SQLSTATE
			// (08P01, protocol_violation) so clients see the same diagnostic.
			char errmsg[128];
			snprintf(errmsg, sizeof(errmsg),
				"bind message has %zu parameter formats but %zu parameters",
				param_formats.size(), param_values.size());
			proxy_error("%s\n", errmsg);
			set_error(PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION, errmsg, false);
			return;
		}
	}

	if (bind_data.num_result_formats > 0) {
		auto result_fmt_reader = bind_msg->get_result_format_reader();
		result_formats.resize(bind_data.num_result_formats);
		for (int i = 0; i < bind_data.num_result_formats; ++i) {
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

	// Issue #5866 defense-in-depth: PQsendQueryPrepared() below can express only ONE
	// result-column format code, so a heterogeneous array would be silently collapsed
	// to result_formats[0], corrupting every other column. The session-level gate in
	// handle_post_sync_bind_message rejects this for libpq-mode sessions, but is
	// skipped when pgsql-use_native_backend_protocol is on (the native drive forwards
	// the array verbatim) — and such a session can still land here on a warm POOLED
	// libpq connection after a flag flip. Error out rather than collapse.
	for (size_t i = 1; i < result_formats.size(); ++i) {
		if (result_formats[i] != result_formats[0]) {
			set_error(PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED,
				"per-column result formats are not supported: all result columns must request the same format code",
				false);
			return;
		}
	}

	// If the client did not send any parameter formats (num_param_formats = 0),
	// PostgreSQL protocol defines this as "all parameters are TEXT".
	// libpq represents this case by passing paramFormats = nullptr.
	const int* param_formats_data = (param_formats.empty() == false ? param_formats.data() : nullptr);

	if (PQsendQueryPrepared(pgsql_conn, query.backend_stmt_name, param_values.size(),
		param_values.data(), param_lengths.data(), param_formats_data,
		(result_formats.size() > 0) ? result_formats[0] : 0) == 0) {
		set_error_from_PQerrorMessage();
		proxy_error("Failed to send execute prepared statement. %s\n", get_error_code_with_message().c_str());
		return;
	}

	// Send a Flush if this is not the last extended query message in the sequence/frame;  
	// otherwise, send a SYNC.
	if ((extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_SYNC) == 0) {
		if (PQsendFlushRequest(pgsql_conn) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to send flush request. %s\n", get_error_code_with_message().c_str());
			return;
		}
	} else {
		if (PQsendPipelineSync(pgsql_conn) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to send pipeline sync. %s\n", get_error_code_with_message().c_str());
			return;
		}
	}
	flush();
}

const char* PgSQL_Connection_LibPQ::get_pg_backend_state() const {
	if (PQstatus(pgsql_conn) != CONNECTION_OK)
		return "disconnected";

	switch (PQtransactionStatus(pgsql_conn)) {
	case PQTRANS_IDLE:
		return "idle";
	case PQTRANS_ACTIVE:
		return "active";
	case PQTRANS_INTRANS:
		return "idle in transaction";
	case PQTRANS_INERROR:
		return "idle in transaction (aborted)";
	case PQTRANS_UNKNOWN:
	default:
		return "unknown";
	}
}

int PgSQL_Connection_LibPQ::get_pg_ssl_in_use() {
	return PQsslInUse(pgsql_conn);
}

SSL* PgSQL_Connection_LibPQ::get_pg_ssl_object() {
	return (SSL*)PQsslStruct(pgsql_conn, "OpenSSL");
}

int PgSQL_Connection_LibPQ::get_pg_server_version() {
	return PQserverVersion(pgsql_conn);
}

int PgSQL_Connection_LibPQ::get_pg_protocol_version() {
	return PQprotocolVersion(pgsql_conn);
}

const char* PgSQL_Connection_LibPQ::get_pg_host() {
	return PQhost(pgsql_conn);
}

const char* PgSQL_Connection_LibPQ::get_pg_hostaddr() {
	return PQhostaddr(pgsql_conn);
}

const char* PgSQL_Connection_LibPQ::get_pg_port() {
	return PQport(pgsql_conn);
}

const char* PgSQL_Connection_LibPQ::get_pg_dbname() {
	return PQdb(pgsql_conn);
}

const char* PgSQL_Connection_LibPQ::get_pg_user() {
	return PQuser(pgsql_conn);
}

const char* PgSQL_Connection_LibPQ::get_pg_password() {
	return PQpass(pgsql_conn);
}

const char* PgSQL_Connection_LibPQ::get_pg_options() {
	return PQoptions(pgsql_conn);
}

int PgSQL_Connection_LibPQ::get_pg_socket_fd() {
	return PQsocket(pgsql_conn);
}

int PgSQL_Connection_LibPQ::get_pg_backend_pid() {
	return PQbackendPID(pgsql_conn);
}

int PgSQL_Connection_LibPQ::get_pg_client_encoding() {
	return PQclientEncoding(pgsql_conn);
}

ConnStatusType PgSQL_Connection_LibPQ::get_pg_connection_status() const {
	return PQstatus(pgsql_conn);
}

char PgSQL_Connection_LibPQ::last_ready_for_query_status() const {
	return 'I';
}

bool PgSQL_Connection_LibPQ::needs_pollout() const {
	return (async_exit_status & PG_EVENT_WRITE) != 0;
}

int PgSQL_Connection_LibPQ::get_pg_is_nonblocking() {
	return PQisnonblocking(pgsql_conn);
}

const char* PgSQL_Connection_LibPQ::get_pg_error_message() {
	return PQerrorMessage(pgsql_conn);
}

const char* PgSQL_Connection_LibPQ::get_pg_parameter_status(const char* param) {
	return PQparameterStatus(pgsql_conn, param);
}

PGTransactionStatusType PgSQL_Connection_LibPQ::transport_transaction_status() const {
	return PQtransactionStatus(pgsql_conn);
}

int PgSQL_Connection_LibPQ::get_backend_pid() {
	// A NULL handle is the never-connected state the same accessor answered
	// before the split; -1 is the "no backend process" answer.
	return (pgsql_conn) ? get_pg_backend_pid() : -1;
}

bool PgSQL_Connection_LibPQ::is_pipeline_active() {
	return (PQpipelineStatus(pgsql_conn) != PQ_PIPELINE_OFF);
}

bool PgSQL_Connection_LibPQ::transport_blocks_reuse() const {
	return false;
}

bool PgSQL_Connection_LibPQ::last_execute_suspended() const {
	return false;
}

bool PgSQL_Connection_LibPQ::result_had_notification() const {
	return false;
}

int PgSQL_Connection_LibPQ::relay_async_messages(PtrSizeArray* out) {
	(void)out;
	return 0;
}
