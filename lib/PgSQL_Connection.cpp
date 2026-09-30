
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

void PgSQL_Variable::fill_server_internal_session(json &j, int conn_num, int idx) {
	j[conn_num]["conn"][pgsql_tracked_variables[idx].set_variable_name] = std::string(value?value:"");
}

void PgSQL_Variable::fill_client_internal_session(json &j, int idx) {
	j["conn"][pgsql_tracked_variables[idx].set_variable_name] = value?value:"";
}

PgSQL_Connection_userinfo::PgSQL_Connection_userinfo() {
	username=NULL;
	password=NULL;
	sha1_pass=NULL;
	dbname=NULL;
	fe_username=NULL;
	hash=0;
	has_scram_keys=false;
	memset(scram_client_key, 0, sizeof(scram_client_key));
	memset(scram_server_key, 0, sizeof(scram_server_key));
}

PgSQL_Connection_userinfo::~PgSQL_Connection_userinfo() {
	if (username) free(username);
	if (fe_username) free(fe_username);
	if (password) free(password);
	if (sha1_pass) free(sha1_pass);
	if (dbname) free(dbname);
	// Scrub the harvested SCRAM key material (the ClientKey is password-equivalent) on destruction,
	// with a non-elidable wipe (OPENSSL_cleanse) so the compiler can't optimize the clear away.
	OPENSSL_cleanse(scram_client_key, sizeof(scram_client_key));
	OPENSSL_cleanse(scram_server_key, sizeof(scram_server_key));
}

uint64_t PgSQL_Connection_userinfo::compute_hash() {
	size_t username_len = username ? std::string_view(username).size() : 0;
	size_t password_len = password ? std::string_view(password).size() : 0;
	size_t dbname_len = dbname ? std::string_view(dbname).size() : 0;
	size_t l = username_len + password_len + dbname_len;
// two random seperator
	constexpr char delimiter1[] = "-ujhtgf76y576574fhYTRDF345wdt-";
	constexpr char delimiter2[] = "-8k7jrhtrgJHRgrefgreyhtRFewg6-";
	size_t delimiter1_len = sizeof(delimiter1) - 1;
	size_t delimiter2_len = sizeof(delimiter2) - 1;
	l += delimiter1_len + delimiter2_len;

	std::string hash_input;
	hash_input.reserve(l);
	if (username) {
		hash_input.append(username, username_len);
	}
	hash_input.append(delimiter1);
	if (password) {
		hash_input.append(password, password_len);
	}
	if (dbname) {
		hash_input.append(dbname, dbname_len);
	}
	hash_input.append(delimiter2);
	hash = SpookyHash::Hash64(hash_input.data(), hash_input.size(), 0);
	return hash;
}

void PgSQL_Connection_userinfo::set(char *user, char *pass, char *db, char *sh1) {
	if (user) {
		if (username) {
			if (strcmp(user,username)) {
				free(username);
				username=strdup(user);
			}
		} else {
			username=strdup(user);
		}
	}
	if (pass) {
		if (password) {
			if (strcmp(pass,password)) {
				free(password);
				password=strdup(pass);
			}
		} else {
			password=strdup(pass);
		}
	}
	if (db) {
		if (dbname) { 
			if (strcmp(db,dbname)) {
				free(dbname);
				dbname=strdup(db);
			}
		} else {
			dbname=strdup(db);
		}
	}
	if (sh1) {
		if (sha1_pass) {
			free(sha1_pass);
		}
		sha1_pass=strdup(sh1);
	}
	compute_hash();
}

void PgSQL_Connection_userinfo::set(PgSQL_Connection_userinfo *ui) {
	set(ui->username, ui->password, ui->dbname, ui->sha1_pass);
	// Carry the harvested SCRAM keys frontend->backend (not part of the hash).
	memcpy(scram_client_key, ui->scram_client_key, sizeof(scram_client_key));
	memcpy(scram_server_key, ui->scram_server_key, sizeof(scram_server_key));
	has_scram_keys = ui->has_scram_keys;
}

bool PgSQL_Connection_userinfo::set_dbname(const char* db) {
	assert(db);
	const int new_db_len = db ? strlen(db) : 0;
	const int old_db_len = dbname ? strlen(dbname) : 0;

	if (old_db_len == 0 || old_db_len != new_db_len || strcmp(db, dbname)) {
		if (dbname) {
			free(dbname);
		}
		dbname = (char*)malloc(new_db_len + 1);
		// Copy string including null terminator
		memcpy(dbname, db, new_db_len + 1);
		compute_hash();
		return true;
	}
	return false;
}

#define NEXT_IMMEDIATE(new_st) do { async_state_machine = new_st; goto handler_again; } while (0)

PgSQL_Connection* PgSQL_Connection::create_backend() {
	if (pgsql_thread___use_native_backend_protocol) {
		return new PgSQL_Connection_Native();
	}
	return new PgSQL_Connection_LibPQ();
}

PgSQL_Connection::PgSQL_Connection(bool is_client_conn, bool native) : native_mode(native) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Creating new PgSQL_Connection %p\n", this);
	async_exit_status = PG_EVENT_NONE;
	is_client_connection = is_client_conn;
	query_result = NULL;
	query_result_reuse = NULL;
	//stmt_metadata_result = NULL;
	myds = NULL;
	parent = NULL;
	fd = -1;
	status_flags = 0;
	largest_query_length = 0;
	bytes_info.bytes_recv = 0;
	bytes_info.bytes_sent = 0;
	statuses.questions = 0;
	statuses.pgconnpoll_get = 0;
	statuses.pgconnpoll_put = 0;
	unknown_transaction_status = false;
	send_quit = true;
	reusable = false;
	healthy = true;
	multiplex_delayed = false;
	processing_multi_statement = false;
	async_state_machine = ASYNC_CONNECT_START;
	last_time_used = 0;
	creation_time = 0;
	auto_increment_delay_token = 0;
	query.ptr = NULL;
	query.length = 0;
	options.init_connect = NULL;
	options.init_connect_sent = false;
	userinfo = new PgSQL_Connection_userinfo();
	local_stmts = new PgSQL_STMT_Local(false); // false by default, it is a backend

	//for (int i = 0; i < PGSQL_NAME_LAST_HIGH_WM; i++) {
	//	variables[i].value = NULL;
	//	var_hash[i] = 0;
	//}

	new_result = true;
	resync_failed = false;
	reset_error();
}

PgSQL_Connection::~PgSQL_Connection() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Destroying PgSQL_Connection %p\n", this);
	if (userinfo) {
		delete userinfo;
		userinfo = NULL;
	}
	if (local_stmts) {
		delete local_stmts;
		local_stmts = NULL;
	}
	// Subtract once for every connection that was added, libpq and native alike. The
	// flag says whether this one was ever counted; asking is_connected() instead never
	// subtracted a backend that had died, so the count only climbed. Clearing it keeps
	// anyone from subtracting the same connection twice.
	//
	// A leaf destructor runs before this body, so the native leaf has already called
	// native_teardown() by now -- and that is what subtracts for a native connection,
	// clearing the same flag. So this still fires exactly once per connection, on
	// either transport. The libpq leaf has no counter of its own and leaves the flag
	// for this line.
	if (counted_in_connections_connected) {
		__sync_fetch_and_sub(&PgHGM->status.server_connections_connected, 1);
		counted_in_connections_connected = false;
	}
	if (query_result) {
		delete query_result;
		query_result = NULL;
	}
	if (query_result_reuse) {
		delete query_result_reuse;
		query_result_reuse = NULL;
	}

	/*if (stmt_metadata_result) {
		delete stmt_metadata_result;
		stmt_metadata_result = NULL;
	}*/

	if (options.init_connect) free(options.init_connect);

	for (int i = 0; i < PGSQL_NAME_LAST_HIGH_WM; ++i) {
		if (variables[i].value) {
			free(variables[i].value);
			variables[i].value = NULL;
			var_hash[i] = 0;
		}
	}

	for (int i = 0; i < PGSQL_NAME_LAST_HIGH_WM; ++i) {
		if (startup_parameters[i]) {
			free(startup_parameters[i]);
			startup_parameters[i] = nullptr;
			startup_parameters_hash[i] = 0;
		}
	}
	reset_error_info(error_info, true);
}

void PgSQL_Connection::next_event(PG_ASYNC_ST new_st) {
#ifdef DEBUG
	int fd;
#endif /* DEBUG */
	wait_events = 0;

	if (async_exit_status & PG_EVENT_READ)
		wait_events |= POLLIN;
	if (async_exit_status & PG_EVENT_WRITE)
		wait_events |= POLLOUT;
	if (wait_events)
#ifdef DEBUG
		// The value is for this log line only and is discarded in a release build, so
		// it goes through the accessor rather than through a libpq call the base can no
		// longer make. One difference worth naming: for a native connection this now
		// logs the real fd where it used to log PQsocket(NULL), i.e. -1.
		fd = get_pg_socket_fd();
#else
		get_pg_socket_fd();
#endif /* DEBUG */
	else
#ifdef DEBUG
		fd = -1;
#endif /* DEBUG */

	proxy_debug(PROXY_DEBUG_NET, 8, "fd=%d, wait_events=%d , old_ST=%d, new_ST=%d\n", fd, wait_events, async_state_machine, new_st);
	async_state_machine = new_st;
};


PG_ASYNC_ST PgSQL_Connection::handler(short event) {
#if ENABLE_TIMER
	Timer timer(myds->sess->thread->Timers.Connections_Handlers);
#endif // ENABLE_TIMER
	uint64_t processed_bytes = 0;	// issue #527 : this variable will store the amount of bytes processed during this event
	if (handler_first_call) {
		// it is the first time handler() is being called.
		// Use an explicit one-shot flag rather than (pgsql_conn == NULL): in
		// native_mode pgsql_conn stays NULL for the whole connect/auth cycle,
		// so the old condition would re-run this init (and re-open the socket)
		// on every event. The flag works identically for both paths.
		handler_first_call = false;
		async_state_machine = ASYNC_CONNECT_START;
		myds->wait_until = myds->sess->thread->curtime + pgsql_thread___connect_timeout_server * 1000;
		if (myds->max_connect_time) {
			if (myds->wait_until > myds->max_connect_time) {
				myds->wait_until = myds->max_connect_time;
			}
		}
	}
handler_again:
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "async_state_machine=%d\n", async_state_machine);
	switch (async_state_machine) {
	case ASYNC_CONNECT_START:
		connect_start();
		if (async_exit_status) {
			next_event(ASYNC_CONNECT_CONT);
		}
		else {
			NEXT_IMMEDIATE(ASYNC_CONNECT_END);
		}
		break;
	case ASYNC_CONNECT_CONT:
		if (event) {
			connect_cont(event);
		}
		if (async_exit_status) {
			if (myds->sess->thread->curtime >= myds->wait_until) {
				NEXT_IMMEDIATE(ASYNC_CONNECT_TIMEOUT);
			}
			next_event(ASYNC_CONNECT_CONT);
		} else {
			NEXT_IMMEDIATE(ASYNC_CONNECT_END);
		}
		break;
	case ASYNC_CONNECT_END:
		if (myds) {
			if (myds->sess) {
				if (myds->sess->thread) {
					unsigned long long curtime = monotonic_time();
					myds->sess->thread->atomic_curtime = curtime;
				}
			}
		}
		if (is_error_present()) {
			// always increase the counter
			proxy_error("Failed to PQconnectStart() on %u:%s:%d , FD (Conn:%d , MyDS:%d) , %s.\n", parent->myhgc->hid, parent->address, parent->port, get_pg_socket_fd(), myds->fd, get_error_code_with_message().c_str());
			NEXT_IMMEDIATE(ASYNC_CONNECT_FAILED);
		} else {
			// Native sockets are created O_NONBLOCK already; only the libpq path
			// needs the PQsetnonblocking() handshake (pgsql_conn is NULL in native mode).
			if (on_connect_end() == HandlerStep::AGAIN) {
				goto handler_again;
			}
			NEXT_IMMEDIATE(ASYNC_CONNECT_SUCCESSFUL);
		}
		break;
	case ASYNC_CONNECT_SUCCESSFUL:
		if (!is_connected()) 
			assert(0); // shouldn't ever reach here, we have messed up the state machine
		
		if (get_pg_ssl_in_use()) {
			if (myds && myds->sess && myds->sess->session_fast_forward) {
				// Native connections come through here too. adopt_backend_tls() shares this
				// connection's own memory BIOs with the stream instead of installing a new
				// pair, so nothing the connection still uses gets freed underneath it.
				assert(myds->ssl == NULL);
				if (myds->adopt_backend_tls() == false) {
					// This connection would relay in the clear, so fail the connect
					// rather than hand it to the session. It never reaches the count
					// below, which is right because a failed connect is always deleted
					// and never pooled.
					NEXT_IMMEDIATE(ASYNC_CONNECT_FAILED);
				}
			}
		}
		__sync_fetch_and_add(&PgHGM->status.server_connections_connected, 1);
		counted_in_connections_connected = true;
		__sync_fetch_and_add(&parent->connect_OK, 1);
		on_connect_successful();
		break;
	case ASYNC_CONNECT_FAILED:
		//PQfinish(pgsql_conn);//release connection even on error
		//pgsql_conn = NULL;
		on_connect_failed();
		PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::pgsql, parent->myhgc->hid, parent->address, parent->port, 9999 /* TODO: fix this mysql_errno(pgsql) */);
		parent->connect_error(9999 /* TODO: fix this mysql_errno(pgsql)*/);
		break;
	case ASYNC_CONNECT_TIMEOUT:
		// to fix
		//PQfinish(pgsql_conn);//release connection
		//pgsql_conn = NULL;
		on_connect_failed();
		proxy_error("Connect timeout on %s:%d : exceeded by %lluus\n", parent->address, parent->port, myds->sess->thread->curtime - myds->wait_until);
		PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::pgsql, parent->myhgc->hid, parent->address, parent->port, 9999/* TODO: fix this mysql_errno(pgsql)*/);
		parent->connect_error(9999 /* TODO: fix this mysql_errno(pgsql)*/);
		break;
	case ASYNC_QUERY_START:
		query_start();
		__sync_fetch_and_add(&parent->queries_sent, 1);
		update_bytes_sent(query.length + 5);
		statuses.questions++;
		if (async_exit_status) {
			next_event(ASYNC_QUERY_CONT);
		} else {
			if (is_error_present()) {
				NEXT_IMMEDIATE(ASYNC_QUERY_END);
			}
			// Record where this query should go once its reply has been read.
			//
			// Two functions reach this case. async_query() runs ordinary client queries,
			// and async_send_simple_command() is what ProxySQL uses internally to configure
			// a backend connection, for example the "SET client_encoding" it sends when a
			// pooled connection is given to a client that asked for a different encoding.
			// Both send a single 'Q' message and both finish in ASYNC_QUERY_END, so that is
			// the value stored here.
			//
			// ASYNC_QUERY_CONT below stores the same value, but it cannot be relied on to
			// do it. query_start() will often write the whole 'Q' in one syscall, which is
			// the normal outcome in native mode for something as short as a SET. When that
			// happens there is nothing left to wait for, so we go straight to the result
			// drain and never pass through ASYNC_QUERY_CONT at all.
			//
			// Nothing else ever clears this field. Without the line below it would still
			// hold whatever an earlier extended-query step left on this connection, such as
			// ASYNC_STMT_EXECUTE_END, and the result dispatch would jump there when the
			// reply arrived. async_query() copes with that, because it accepts any *_END
			// state as success. async_send_simple_command() does not: it accepts only
			// ASYNC_QUERY_END, so anything else makes it answer "not finished yet" every
			// time it is called, and the session then waits in SETTING_VARIABLE forever
			// because nothing times it out.
			//
			// Only the native path can get into that state. libpq's flush never reports
			// that it sent everything in one go, so a libpq connection always goes through
			// ASYNC_QUERY_CONT and picks up the assignment there.
			set_fetch_result_end_state(ASYNC_QUERY_END);
			NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
		}
		break;
	case ASYNC_QUERY_CONT:
		if (event) {
			query_cont(event);
		}
		if (async_exit_status) {
			next_event(ASYNC_QUERY_CONT);
		} else {
			if (is_error_present() || !set_single_row_mode()) {
				NEXT_IMMEDIATE(ASYNC_QUERY_END);
			}
			set_fetch_result_end_state(ASYNC_QUERY_END);
			NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
		}
		break;
	case ASYNC_USE_RESULT_START:
		fetch_result_start();
		if (async_exit_status == PG_EVENT_NONE) {
			if (is_error_present()) {
				NEXT_IMMEDIATE(fetch_result_end_st);
			}
			init_query_result();
			if (defer_first_result_read()) {
				async_exit_status = PG_EVENT_READ;
				next_event(ASYNC_USE_RESULT_CONT);
				break;
			}
			NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
		} else {
			assert(0); // shouldn't ever reach here
		}
		break;
	case ASYNC_USE_RESULT_CONT:
	{
		if (myds->sess && myds->sess->client_myds && myds->sess->mirror == false) { // see issue#4072
			const unsigned int buffered_data = myds->sess->client_myds->PSarrayOUT->len * PGSQL_RESULTSET_BUFLEN;
			if (buffered_data > overflow_safe_multiply<8,unsigned int>(pgsql_thread___threshold_resultset_size)) {
				next_event(ASYNC_USE_RESULT_CONT); // we temporarily pause . See #1232
				break;
			}
		}

		// The per-transport result drain, including the libpq PGresult dispatch.
		// Everything above the threshold check is shared; everything below it belongs
		// to the transport, so it reports which way it left through HandlerStep.
		switch (fetch_result_dispatch(event, &processed_bytes)) {
		case HandlerStep::AGAIN:
			goto handler_again;
		case HandlerStep::YIELD:
			return async_state_machine;
		case HandlerStep::CONTINUE:
			// Nothing shared is left after the switch, so this falls out of the case
			// exactly like YIELD. Neither transport returns it from
			// fetch_result_dispatch(): each one either had to wait (YIELD) or had
			// already picked the next state (AGAIN). The case is kept so the switch
			// stays exhaustive over HandlerStep.
			break;
		}
	}
	break;

	case ASYNC_STMT_PREPARE_START:
		stmt_prepare_start();
		__sync_fetch_and_add(&parent->queries_sent, 1);
		update_bytes_sent(query.length + 5);
		statuses.questions++;
		if (async_exit_status) {
			next_event(ASYNC_STMT_PREPARE_CONT);
		} else {
			// Nothing is left to send, so either the whole frame went out and
			// the reply is what we wait for, or the send failed outright and the
			// path that failed left an error set. The two are told apart by that
			// error, not by the transport: every PG_EVENT_NONE exit of the three
			// stmt_*_start() bodies runs set_error()/set_error_from_PQerrorMessage()
			// first, on libpq as well as native.
			if (is_error_present()) {
				NEXT_IMMEDIATE(ASYNC_STMT_PREPARE_END);
			}
			set_fetch_result_end_state(ASYNC_STMT_PREPARE_END);
			NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
		}
		break;
	case ASYNC_STMT_PREPARE_CONT:
		if (event) {
			stmt_prepare_cont(event);
		}
		if (async_exit_status) {
			next_event(ASYNC_STMT_PREPARE_CONT);
		} else {
			if (is_error_present()) {
				NEXT_IMMEDIATE(ASYNC_STMT_PREPARE_END);
			}
			set_fetch_result_end_state(ASYNC_STMT_PREPARE_END);
			NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
		}
		break;

	case ASYNC_STMT_DESCRIBE_START:
	{
		stmt_describe_start();
		__sync_fetch_and_add(&parent->queries_sent, 1);
		size_t bytes_sent = 7 + 5; // 7 for DESCRIBE header, 5 for SYNC/FLUSH
		if (query.extended_query_info->stmt_type == 'P') {
			bytes_sent += query.extended_query_info->stmt_client_portal_name ? (strlen(query.extended_query_info->stmt_client_portal_name) + 1) : 0;
		} else {
			bytes_sent += query.backend_stmt_name ? (strlen(query.backend_stmt_name) + 1) : 0;
		}
		update_bytes_sent(bytes_sent);
		statuses.questions++;
		if (async_exit_status) {
			next_event(ASYNC_STMT_DESCRIBE_CONT);
		} else {
			// Same shape as ASYNC_STMT_PREPARE_START; see the comment there.
			if (is_error_present()) {
				NEXT_IMMEDIATE(ASYNC_STMT_DESCRIBE_END);
			}
			set_fetch_result_end_state(ASYNC_STMT_DESCRIBE_END);
			NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
		}
	}
	break;
	case ASYNC_STMT_DESCRIBE_CONT:
		if (event) {
			stmt_describe_cont(event);
		}
		if (async_exit_status) {
			next_event(ASYNC_STMT_DESCRIBE_CONT);
		} else {
			if (is_error_present()) {
				NEXT_IMMEDIATE(ASYNC_STMT_DESCRIBE_END);
			}
			set_fetch_result_end_state(ASYNC_STMT_DESCRIBE_END);
			NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
		}
		break;

	case ASYNC_STMT_EXECUTE_START:
		stmt_execute_start();
		__sync_fetch_and_add(&parent->queries_sent, 1);
		// bind_msg is NULL for a named-portal Close (close_only) — it carries no
		// Bind bytes — so guard the bytes-sent accounting (Task P2). EXECUTE and BIND
		// always carry a bind_msg.
		if (query.extended_query_info->bind_msg) {
			update_bytes_sent(query.extended_query_info->bind_msg->get_raw_pkt().size + 5);
		}
		statuses.questions++;
		if (async_exit_status) {
			next_event(ASYNC_STMT_EXECUTE_CONT);
		} else {
			// Same shape as ASYNC_STMT_PREPARE_START; see the comment there.
			if (is_error_present()) {
				NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_END);
			}
			set_fetch_result_end_state(ASYNC_STMT_EXECUTE_END);
			NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
		}
		break;
	case ASYNC_STMT_EXECUTE_CONT:
		if (event) {
			stmt_execute_cont(event);
		}
		if (async_exit_status) {
			next_event(ASYNC_STMT_EXECUTE_CONT);
		} else {
			if (is_error_present() || !set_single_row_mode()) {
				NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_END);
			}
			set_fetch_result_end_state(ASYNC_STMT_EXECUTE_END);
			NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
		}
		break;

	case ASYNC_RESYNC_END:
		// if we reach here, it means that the connection is now synchronized
		if (resync_failed) {
			// if resync failed
			set_error(PGSQL_ERROR_CODES::ERRCODE_RAISE_EXCEPTION, "Failed to synchronize connection", false);
		}
		// fall through
	case ASYNC_QUERY_END:
	case ASYNC_STMT_PREPARE_END:
	case ASYNC_STMT_DESCRIBE_END:
	case ASYNC_STMT_EXECUTE_END:
		PROXY_TRACE2();

		if (is_error_present()) {
			compute_unknown_transaction_status();
		} else {
			unknown_transaction_status = false;
		}

		// The finalization is the leaf's: the notice receiver, the pipeline-mode exit
		// and the two "should be NULL" checks all describe libpq state, which
		// PgSQL_Connection_LibPQ::on_command_end() now owns (plan:202).
		on_command_end();
		break;

	case ASYNC_RESYNC_START:
		// PQpipelineStatus(NULL) returns PQ_PIPELINE_OFF, so without this guard native
		// would take the shortcut below and pool a connection still mid-batch.
		if (resync_already_synced()) {
			NEXT_IMMEDIATE(ASYNC_RESYNC_END);
		}
		resync_start();
		update_bytes_sent(5); // SYNC message
		if (async_exit_status) {
			next_event(ASYNC_RESYNC_CONT);
		} else {
			// The Sync went out in full (non-blocking, same as
			// ASYNC_STMT_PREPARE_START): go straight to the drain. A failed send
			// also lands here, so route that to END instead of an empty drain.
			if (resync_send_failed()) {
				NEXT_IMMEDIATE(ASYNC_RESYNC_END);
			}
			set_fetch_result_end_state(ASYNC_RESYNC_END);
			NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
		}
		break;
	case ASYNC_RESYNC_CONT:
		if (event) {
			resync_cont(event);
		}
		if (async_exit_status) {
			if (myds->wait_until != 0 && myds->sess->thread->curtime >= myds->wait_until) {
				proxy_error("Timeout waiting for pipeline sync to complete.\n");
				resync_failed = true;
				NEXT_IMMEDIATE(ASYNC_RESYNC_END);
			}
			next_event(ASYNC_RESYNC_CONT);
			break;
		} else {
			// A failed send lands here the same way as in ASYNC_RESYNC_START. The
			// second term is redundant on libpq (resync_send_failed() answers
			// resync_failed there) and on native (which never sets resync_failed),
			// but the timeout path above sets it for both, so it is kept.
			if (resync_send_failed() || resync_failed) {
				NEXT_IMMEDIATE(ASYNC_RESYNC_END);
			}
			if (query_result && query_result->result_packet_type != PGSQL_QUERY_RESULT_NO_DATA) {
				// we have already have some result set, so we just continue
				NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
			} else {
				set_fetch_result_end_state(ASYNC_RESYNC_END);
				NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
			}
		}
		break;

	case ASYNC_RESET_SESSION_START:
		reset_session_start();
		if (reset_session_in_pipeline) {
			update_bytes_sent(5);
		}
		else {
			update_bytes_sent((reset_session_in_txn == false ? (sizeof("DISCARD ALL") + 5) : (sizeof("ROLLBACK") + 5)));
		}
		if (async_exit_status) {
			next_event(ASYNC_RESET_SESSION_CONT);
		}
		else {
			if (is_error_present()) {
				NEXT_IMMEDIATE(ASYNC_RESET_SESSION_END);
			}
			NEXT_IMMEDIATE(ASYNC_RESET_SESSION_CONT);
		}
		break;
	case ASYNC_RESET_SESSION_CONT:
	{
		if (event) {
			reset_session_cont(event);
		}
		if (async_exit_status) {
			if (myds->wait_until != 0 && myds->sess->thread->curtime >= myds->wait_until) {
				NEXT_IMMEDIATE(ASYNC_RESET_SESSION_TIMEOUT);
			}
			next_event(ASYNC_RESET_SESSION_CONT);
			break;
		}
		if (is_error_present()) {
			NEXT_IMMEDIATE(ASYNC_RESET_SESSION_END);
		}
		switch (reset_session_cont_dispatch()) {
		case HandlerStep::AGAIN:
			goto handler_again;
		case HandlerStep::YIELD:
			return async_state_machine;
		case HandlerStep::CONTINUE:
			break;
		}
	}
	break;
	case ASYNC_RESET_SESSION_END:
		on_reset_session_end();
		if (is_error_present()) {
			NEXT_IMMEDIATE(ASYNC_RESET_SESSION_FAILED);
		}
		NEXT_IMMEDIATE(ASYNC_RESET_SESSION_SUCCESSFUL);
		break;
	case ASYNC_RESET_SESSION_FAILED:
	case ASYNC_RESET_SESSION_SUCCESSFUL:
	case ASYNC_RESET_SESSION_TIMEOUT:
		break;

	default:
		// The connection is in a state nothing here knows how to handle. Log which
		// state it was, so the abort below is not a bare assert with no clue, then stop.
		proxy_error("Unhandled state %d in PgSQL_Connection::handler() for backend %s:%d (transport=%s, fd=%d). Aborting.\n",
			(int)async_state_machine,
			(parent && parent->address) ? parent->address : "(unknown)",
			parent ? parent->port : -1,
			transport_name(), fd);
		assert(0);
	}
	return async_state_machine;
}

// libpq/pgcommon base64 (linked via libpgcommon.a) — used to encode the 32-byte SCRAM
// keys into the conninfo string. Does not NUL-terminate; returns the encoded length.
extern "C" int pg_b64_encode(const char *src, int len, char *dst, int dstlen);

void append_conninfo_param(std::ostringstream& conninfo, const char* key, char* val) {
	if (!val) return;
	char* escaped_str = escape_string_single_quotes_and_backslashes(val, false);
	conninfo << key << "='" << escaped_str << "' ";
	if (escaped_str != val) {
		free(escaped_str);
	}
}

// Appends the credential params for a backend libpq connection, picking the mechanism that matches
// the stored secret: harvested SCRAM keys (pass-through), an md5 hash, or a plaintext password.
//
// EVERY backend connection must build its credentials here — the pooled one (connect_start()) and
// the auxiliary kill/terminate one alike. libpq applies no prefix detection to 'password': handing
// it a verifier or an md5 hash makes it run SASLprep+PBKDF2 over that literal text, and the backend
// rejects the login. 'conn_ctx' names the caller for the diagnostics below.
//
// Returns true only when a credential parameter was actually emitted; on false the caller must
// abandon the connection. A conninfo carrying no credential is not inert — libpq falls back to
// PGPASSWORD and then ~/.pgpass from the ProxySQL process environment, authenticating the backend
// as whoever owns the host rather than as the configured user. Refusing to connect prevents that.
// (password='' is not a fix: libpq still reads ~/.pgpass when the password is empty.)
//
// Not static so pgsql_conninfo_credentials_unit-t can pin that postcondition — the failing branches
// are unreachable end to end, so a unit test is the only way to cover them. Same arrangement as
// pgsql_reconcile_auth_method() in PgSQL_Protocol.cpp.
bool pgsql_append_conninfo_credentials(std::ostringstream& conninfo, const char* username,
	char* password, bool has_scram_keys, const uint8_t* scram_client_key,
	const uint8_t* scram_server_key, const char* conn_ctx)
{
	// libpq reads PGUSER, then the OS account name, whenever 'user' is missing or empty. Emitting a
	// real password under that identity is the same fail-open the checks below refuse, so no
	// username means no connection.
	if (!username || *username == '\0') {
		proxy_error("PgSQL backend %s: no username; refusing to connect rather than let libpq fall back to PGUSER or the OS user\n",
			conn_ctx);
		return false;
	}

	if (has_scram_keys) {
		// Hand libpq the harvested ClientKey + the verifier's ServerKey (base64) and send NO
		// password — the stored secret is a verifier, which libpq would otherwise wrongly run
		// PBKDF2 over.
		char ck_b64[64] = { 0 };
		char sk_b64[64] = { 0 };
		int n1 = pg_b64_encode((const char*)scram_client_key, PGSQL_SCRAM_KEY_LEN,
			ck_b64, (int)sizeof(ck_b64) - 1);
		int n2 = pg_b64_encode((const char*)scram_server_key, PGSQL_SCRAM_KEY_LEN,
			sk_b64, (int)sizeof(sk_b64) - 1);
		const bool encoded = (n1 > 0 && n2 > 0);
		if (encoded) {
			ck_b64[n1] = '\0';
			sk_b64[n2] = '\0';
			append_conninfo_param(conninfo, "scram_client_key", ck_b64);
			append_conninfo_param(conninfo, "scram_server_key", sk_b64);
		} else {
			// Cannot happen at these sizes (32 bytes -> 44 chars into a 63-byte buffer), but
			// handled so the postcondition holds on every branch: emitting the zero-initialised
			// buffers would send scram_client_key='', which libpq treats as absent, putting us
			// back on the fallback above.
			proxy_error("PgSQL backend %s for user '%s': failed to base64-encode the harvested SCRAM keys (n1=%d, n2=%d); refusing to connect\n",
				conn_ctx, username ? username : "(null)", n1, n2);
		}
		// Scrub the base64 key material from the stack buffers once handed to libpq (non-elidable).
		// Both paths: the buffers hold password-equivalent material either way.
		OPENSSL_cleanse(ck_b64, sizeof(ck_b64));
		OPENSSL_cleanse(sk_b64, sizeof(sk_b64));
		return encoded;
	} else if (password && get_password_type(password) == PASSWORD_TYPE_MD5) {
		// md5-stored user: reuse the stored "md5…" hash directly; no plaintext.
		append_conninfo_param(conninfo, "md5_secret", password);
		return true;
	} else if (password && get_password_type(password) == PASSWORD_TYPE_SCRAM_SHA_256) {
		// A SCRAM verifier reached a backend connect with no harvested keys (has_scram_keys==false).
		// Do NOT ship it as a plaintext password — libpq would run PBKDF2 over the verifier text and
		// fail. Not reachable from a normal frontend SCRAM login (which always harvests the ClientKey);
		// reaching here means an internal/monitor connection or a logic error.
		proxy_error("PgSQL backend %s for user '%s': SCRAM verifier stored but no harvested ClientKey; cannot authenticate to backend without a frontend SCRAM login\n",
			conn_ctx, username ? username : "(null)");
		return false;
	} else if (password) {
		append_conninfo_param(conninfo, "password", password); // password (may legitimately be "")
		return true;
	}
	// No stored secret at all: omitting the parameter would hand the decision to PGPASSWORD / ~/.pgpass.
	proxy_error("PgSQL backend %s for user '%s': no stored credential; refusing to connect rather than let libpq fall back to PGPASSWORD or ~/.pgpass\n",
		conn_ctx, username ? username : "(null)");
	return false;
}

std::string PgSQL_Connection::connect_start_DNS_lookup() {
	// PgSQL_Monitor::dns_lookup() returns an IP on cache hit, or empty
	// on miss / when 'parent->address' is itself an IP / when the cache is
	// disabled.  Empty result means "don't pass hostaddr to libpq" so the
	// existing behavior (libpq does getaddrinfo) is preserved.
	const std::string ip = PgSQL_Monitor::dns_lookup(parent->address,
		/*return_hostname_if_lookup_fails=*/false);
	return ip;
}

// Raises a wire-form value to the level a libpq conninfo needs. libpq parses the conninfo
// and strips one level of backslash escaping before the value reaches the wire, so doubling
// every backslash of the wire form is what makes the backend see that exact wire form.
// The spaces separating the "-c key=value" tokens need nothing: both values are single-quoted
// in the conninfo, so they pass through untouched. The apostrophe does need it, for a different
// reason: an unescaped ' ends the quoted value, and everything after it is parsed by libpq as
// further conninfo KEYWORDS (host=, sslmode=, ...). Escaping it here keeps a client-supplied
// option value a literal instead of a way to redirect the backend connection.
static std::string pg_conninfo_escape_level(const std::string& wire) {
	std::string out;
	// Worst case is every character needing an escape, so reserve once rather than
	// regrowing part-way through.
	out.reserve(wire.size() * 2);
	for (char c : wire) {
		if (c == '\\' || c == '\'') out += '\\';
		out += c;
	}
	return out;
}

bool PgSQL_Connection::build_and_record_startup_session_params(std::string& client_encoding_out,
                                                   std::string& options_out,
                                                   StartupParamEscape escape_mode) {
	if (!(myds && myds->sess && myds->sess->client_myds)) return false;

	// Client encoding is always set; it travels as its own startup key, not inside options.
	const char* client_charset = pgsql_variables.client_get_value(myds->sess, PGSQL_CLIENT_ENCODING);
	assert(client_charset);
	const uint32_t client_charset_hash = pgsql_variables.client_get_hash(myds->sess, PGSQL_CLIENT_ENCODING);
	assert(client_charset_hash);
	// A startup key's value is a plain NUL-terminated string, so the wire form is the raw
	// value; the conninfo form is derived from it at the end of this function.
	client_encoding_out.assign(client_charset);
	// charset validation is already done
	pgsql_variables.server_set_hash_and_value(myds->sess, PGSQL_CLIENT_ENCODING, client_charset, client_charset_hash);

	// The tracked variables, as "-c name=value" tokens, escaped for the wire.
	std::string opts;
	const char* separator = "";
	for (int idx = 1; idx < PGSQL_NAME_LAST_LOW_WM; idx++) {
		const char* value = pgsql_variables.client_get_value(myds->sess, idx);
		opts += separator;
		opts += "-c ";
		opts += pgsql_tracked_variables[idx].set_variable_name;
		opts += "=";
		pg_append_escaped_option_value(opts, value);
		separator = " ";
		const uint32_t hash = pgsql_variables.client_get_hash(myds->sess, idx);
		pgsql_variables.server_set_hash_and_value(myds->sess, idx, value, hash);
	}
	// The client's own connection options, which it supplied as options='-c ...'.
	if (myds->sess->untracked_option_parameters.empty() == false) {
		opts += separator;
		opts += myds->sess->untracked_option_parameters;
	}
	options_out = std::move(opts);

	// Snapshot variables[] into startup_parameters[] so requires_RESETTING_CONNECTION()
	// knows these are already applied. server_set_hash_and_value() above wrote into
	// sess->mybe->server_myds->myconn, and this copy is intra-object (variables[] ->
	// startup_parameters[] on whichever connection it is called on), so it has to run on
	// that same connection -- hence the same expression rather than `this`.
	myds->sess->mybe->server_myds->myconn->copy_pgsql_variables_to_startup_parameters(true);

	// Everything above is the wire form, which is what untracked_option_parameters is
	// stored in too. The libpq path needs one level more, since libpq strips one while
	// parsing the conninfo.
	if (escape_mode == StartupParamEscape::Conninfo) {
		client_encoding_out = pg_conninfo_escape_level(client_encoding_out);
		options_out = pg_conninfo_escape_level(options_out);
	}
	return true;
}

// Build a one-byte-typed frontend message ('p' PasswordMessage / SASL response)
// into out: type byte, int32 big-endian length (= 4 + bodylen), body.
//
// The only caller is the native transport, which frames its PasswordMessage and
// SASL responses this way; the libpq transport gets the same bytes from
// PQputPasswords/PQsendPasswordGSS, so it needs no builder. The connect and
// authentication state machine this used to sit above now lives in
// PgSQL_Connection_Native, where its SSLRequest -> SSL_READ_REPLY ->
// SSL_HANDSHAKE path is handled in full.
void pg_append_typed_msg(std::string& out, char type, const unsigned char* body, size_t bodylen) {
	uint32_t len = (uint32_t)(4 + bodylen);
	unsigned char hdr[5];
	hdr[0] = (unsigned char)type;
	hdr[1] = (len >> 24) & 0xff;
	hdr[2] = (len >> 16) & 0xff;
	hdr[3] = (len >> 8) & 0xff;
	hdr[4] = len & 0xff;
	out.append((const char*)hdr, 5);
	if (bodylen) out.append((const char*)body, bodylen);
}

void PgSQL_Connection::fetch_result_start() {
	PROXY_TRACE();
	reset_error();
	async_exit_status = PG_EVENT_NONE;
	// result_type and ps_result are per-fetch outputs that have connection lifetime.
	// Left over from a previous fetch they are indistinguishable from a value this one
	// produced, so they are reset where the cycle starts -- and they are libpq's, so
	// the leaf does it. A no-op on the transports that never had them.
	reset_fetch_result_state();
}

int PgSQL_Connection::async_connect(short event) {
	PROXY_TRACE();
	// Past ASYNC_CONNECT_START, a transport's handle is in the state its own state
	// machine guarantees. This used to read `!native_mode && pgsql_conn == NULL` -- the
	// flag deciding which transport to ask, and the handle read out of the base. Step 6
	// hands the whole question to the leaf: handle_ready_past_connect_start() is true for
	// libpq only when pgsql_conn exists, and unconditionally true for the two transports
	// that have no PGconn by design. That was the last read of native_mode inside the
	// hierarchy; the constructor's initialiser and the reads in PgSQL_Session.cpp /
	// PgSQL_HostGroups_Manager.cpp are outside it and are what the flag is for.
	// LCOV_EXCL_START
	if (async_state_machine != ASYNC_CONNECT_START && !handle_ready_past_connect_start()) {
		assert(0);
	}
	// LCOV_EXCL_STOP
	if (async_state_machine == ASYNC_IDLE) {
		myds->wait_until = 0;
		return 0;
	}
	if (async_state_machine == ASYNC_CONNECT_SUCCESSFUL) {
		compute_unknown_transaction_status();
		async_state_machine = ASYNC_IDLE;
		myds->wait_until = 0;
		creation_time = monotonic_time();
		return 0;
	}
	handler(event);
	switch (async_state_machine) {
	case ASYNC_CONNECT_SUCCESSFUL:
		compute_unknown_transaction_status();
		async_state_machine = ASYNC_IDLE;
		myds->wait_until = 0;
		return 0;
	case ASYNC_CONNECT_FAILED:
		return -1;
	case ASYNC_CONNECT_TIMEOUT:
		return -2;
	default:
		break;
	}
	return 1;
}

bool PgSQL_Connection::is_connected() const {
	return backend_is_live();
}

void PgSQL_Connection::async_free_result() {
	PROXY_TRACE();
	//assert(pgsql_conn);

	if (query.ptr) {
		query.ptr = NULL;
		query.length = 0;
	}
	if (userinfo) {
		// if userinfo is NULL , the connection is being destroyed
		// because it is reset on destructor ( ~PgSQL_Connection() )
		// therefore this section is skipped completely
		// this should prevent bug #1046
		//if (query.stmt) {
		//	if (query.stmt->mysql) {
		//		if (query.stmt->mysql == pgsql) { // extra check
		//			mysql_stmt_free_result(query.stmt);
		//		}
		//	}
		//	// If we reached here from 'ASYNC_STMT_PREPARE_FAILED', the
		//	// prepared statement was never added to 'local_stmts', thus
		//	// it will never be freed when 'local_stmts' are purged. If
		//	// initialized, it must be freed. For more context see #3525.
		//	if (this->async_state_machine == ASYNC_STMT_PREPARE_FAILED) {
		//		if (query.stmt != NULL) {
		//			proxy_mysql_stmt_close(query.stmt);
		//		}
		//	}
		//	query.stmt = NULL;
		//}
	}
	// The one libpq-owned step in this shared body: the LibPQ leaf holds the PGresult
	// and frees it. The native and client leaves have never had one to free.
	free_transport_result();
	compute_unknown_transaction_status();
	async_state_machine = ASYNC_IDLE;
	if (query_result) {
		if (query_result_reuse) {
			delete (query_result_reuse);
		}
		query_result_reuse = query_result;
		query_result = NULL;
	}
	new_result = false;
}

// Returns:
// 0 when the query is completed
// 1 when the query is not completed
// the calling function should check pgsql error in pgsql struct
int PgSQL_Connection::async_query(short event, const char* stmt, unsigned long length, const char* backend_stmt_name,
	PgSQL_Extended_Query_Type type, const PgSQL_Extended_Query_Info* extended_query_info) {
	PROXY_TRACE();
	PROXY_TRACE2();
	// In native_mode pgsql_conn is permanently NULL; both simple queries and the
	// extended-query cycle (Parse/Bind/Describe/Execute/Sync) are driven by the native
	// state machine. The native stmt_prepare_start/stmt_describe_start/
	// stmt_execute_start drives swap only the wire layer — ProxySQL's entire
	// prepared-statement pipeline (GloPgStmt cache, local_stmts, backend-id reuse,
	// ack synthesis) is shared with the libpq path. See
	// docs/superpowers/specs/2026-07-07-pgsql-native-extq-stmt-pipeline-design.md.

	server_status = parent->status; // we copy it here to avoid race condition. The caller will see this
	if (IsServerOffline())
		return -1;

	if (myds) {
		if (myds->DSS != STATE_MARIADB_QUERY) {
			myds->DSS = STATE_MARIADB_QUERY;
		}
	}
	switch (async_state_machine) {
	case ASYNC_STMT_EXECUTE_END:
	case ASYNC_QUERY_END:
		processing_multi_statement = false;	// no matter if we are processing a multi statement or not, we reached the end
		return 0;
		break;
	case ASYNC_IDLE:
		if (myds && myds->sess) {
			if (myds->sess->active_transactions == 0) {
				// every time we start a query (no matter if COM_QUERY, STMT_PREPARE or otherwise)
				// also a transaction starts, even if in autocommit mode
				myds->sess->active_transactions = 1;
				myds->sess->transaction_started_at = myds->sess->thread->curtime;
			}
		}
		if (!extended_query_info) {
			async_state_machine = ASYNC_QUERY_START;
		} else {
			bind_only = false;
			close_only = false;
			if (type == PGSQL_EXTENDED_QUERY_TYPE_PARSE) {
				async_state_machine = ASYNC_STMT_PREPARE_START;
			} else if (type == PGSQL_EXTENDED_QUERY_TYPE_DESCRIBE) {
				async_state_machine = ASYNC_STMT_DESCRIBE_START;
			} else if (type == PGSQL_EXTENDED_QUERY_TYPE_EXECUTE) {
				async_state_machine = ASYNC_STMT_EXECUTE_START;
			} else if (type == PGSQL_EXTENDED_QUERY_TYPE_BIND) {
				// Named-portal Bind reuses the EXECUTE state chain (CONT/END/return
				// path all handle it unchanged); bind_only + native_stmt_step
				// BIND distinguish the wire drive and the drain terminator. Task P1.
				async_state_machine = ASYNC_STMT_EXECUTE_START;
				bind_only = true;
			} else if (type == PGSQL_EXTENDED_QUERY_TYPE_CLOSE) {
				// Named-portal Close reuses the EXECUTE state chain the same way BIND
				// does; close_only + native_stmt_step CLOSE_P distinguish the
				// wire drive (Close('P', portal) only) and the drain terminator '3'
				// (CloseComplete). Task P2.
				async_state_machine = ASYNC_STMT_EXECUTE_START;
				close_only = true;
			} else {
				assert(0); // should never reach here
			}
		}
		set_query(stmt, length, backend_stmt_name, extended_query_info);
	default:
		handler(event);
		break;
	}

	if (async_state_machine == ASYNC_QUERY_END ||
		async_state_machine == ASYNC_STMT_EXECUTE_END ||
		async_state_machine == ASYNC_STMT_DESCRIBE_END ||
		async_state_machine == ASYNC_STMT_PREPARE_END ||
		async_state_machine == ASYNC_RESYNC_END) {
		PROXY_TRACE2();
		compute_unknown_transaction_status();
		if (is_error_present()) {
			return -1;
		} else {
			return 0;
		}
	}

	if (async_state_machine == ASYNC_USE_RESULT_START) {
		// if we reached this point it measn we are processing a multi-statement
		// and we need to exit to give control to PgSQL_Session
		processing_multi_statement = true;
		return 2;
	}
	if (processing_multi_statement == true) {
		// we are in the middle of processing a multi-statement
		return 3;
	}
	return 1;
}

// Returns:
// 0 when the query is completed
// 1 when the query is not completed
// the calling function should check pgsql error in pgsql struct
int PgSQL_Connection::async_reset_session(short event) {
	PROXY_TRACE();
	PROXY_TRACE2();
	// A native connection has no pgsql_conn and never will; only the libpq branches
	// below dereference it. Everything else in this function -- the timeout, the error
	// mapping, returning the connection to ASYNC_IDLE once the backend has acknowledged
	// the reset -- serves both kinds of connection.

	server_status = parent->status; // we copy it here to avoid race condition. The caller will see this
	if (IsServerOffline())
		return -1;

	/*if (myds) {
		if (myds->DSS != STATE_MARIADB_QUERY) {
			myds->DSS = STATE_MARIADB_QUERY;
		}
	}*/

	switch (async_state_machine) {
	case ASYNC_RESET_SESSION_SUCCESSFUL:
		unknown_transaction_status = false;
		async_state_machine = ASYNC_IDLE;
		return 0;
		break;
	case ASYNC_RESET_SESSION_FAILED:
		return -1;
		break;
	case ASYNC_RESET_SESSION_TIMEOUT:
		return -2;
		break;
	case ASYNC_IDLE:
		if (myds && myds->sess) {
			if (myds->sess->active_transactions == 0) {
				myds->sess->active_transactions = 1;
				myds->sess->transaction_started_at = myds->sess->thread->curtime;
			}
		}
		async_state_machine = ASYNC_RESET_SESSION_START;
	default:
		handler(event);
		break;
	}

	switch (async_state_machine) {
	case ASYNC_RESET_SESSION_SUCCESSFUL:
		if (myds && myds->sess) {
			if (myds->sess->active_transactions != 0) {
				myds->sess->active_transactions = 0;
				myds->sess->transaction_started_at = 0;
			}
		}
		unknown_transaction_status = false;
		async_state_machine = ASYNC_IDLE;
		return 0;
		break;
	case ASYNC_RESET_SESSION_FAILED:
		if (myds && myds->sess) {
			if (myds->sess->active_transactions != 0) {
				myds->sess->active_transactions = 0;
				myds->sess->transaction_started_at = 0;
			}
		}
		return -1;
		break;
	case ASYNC_RESET_SESSION_TIMEOUT:
		if (myds && myds->sess) {
			if (myds->sess->active_transactions != 0) {
				myds->sess->active_transactions = 0;
				myds->sess->transaction_started_at = 0;
			}
		}
		return -2;
		break;
	default:
		break;
	}
	return 1;
}

bool PgSQL_Connection::IsActiveTransaction() {
	// First check known state
	if (IsKnownActiveTransaction()) {
		return true;
	}

	// Check unknown transaction status flag
	if (is_error_present() && unknown_transaction_status) {
		return true;
	}

	return false;
}

bool PgSQL_Connection::IsServerOffline() {
	bool ret = false;
	if (parent == NULL)
		return ret;
	server_status = parent->status; // we copy it here to avoid race condition. The caller will see this
	if (
		(server_status == MYSQL_SERVER_STATUS_OFFLINE_HARD) // the server is OFFLINE as specific by the user
		||
		(server_status == MYSQL_SERVER_STATUS_SHUNNED && parent->shunned_automatic == true && parent->shunned_and_kill_all_connections == true) // the server is SHUNNED due to a serious issue
		||
		(server_status == MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) // slave is lagging! see #774
		) {
		ret = true;
	}
	return ret;
}

void PgSQL_Connection::set_is_client() {
	local_stmts->set_is_client(myds->sess);
}

bool PgSQL_Connection::is_connection_in_reusable_state() const {
	// The transport answers first: a native connection that never finished
	// connecting, or that still owes the backend a ReadyForQuery, is mid-batch
	// and unusable with no error recorded against it. libpq answers false here
	// on purpose -- a dead libpq connection with nothing recorded must still
	// trip the shared check below exactly the way it always did.
	if (transport_blocks_reuse()) {
		return false;
	}
	const PGTransactionStatusType txn_status = get_pg_transaction_status();
	const bool conn_usable = !(txn_status == PQTRANS_UNKNOWN || txn_status == PQTRANS_ACTIVE);
	assert(!(conn_usable == false && is_error_present() == false));
	return conn_usable;
}

// A reply that says nothing -- a bare ReadyForQuery, with no CommandComplete, EmptyQueryResponse
// or ErrorResponse (issue #6110). Tell the client and destroy the connection; a reset cannot cure
// a server that answers incorrectly. Call this BEFORE the ReadyForQuery is added: a client told
// the cycle is over discards whatever follows, so an error appended there is never seen.
void PgSQL_Connection::reject_result_without_outcome() {
	if ((query_result->get_result_packet_type() &
	     (PGSQL_QUERY_RESULT_COMMAND | PGSQL_QUERY_RESULT_EMPTY | PGSQL_QUERY_RESULT_ERROR)) != 0) {
		return;
	}
	if (!is_error_present()) {
		proxy_error("Backend %s:%d answered a query with no command outcome (bare ReadyForQuery)\n",
			parent ? parent->address : "?", parent ? parent->port : 0);
		set_error(PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION,
			"backend answered the query with no command outcome", false);
		reusable = false;
		healthy = false;
		if (myds && myds->sess) {
			myds->sess->set_unhealthy();
		}
	}
	// Flush any rows still in the inline buffer, so the error lands behind them, not in front.
	query_result->buffer_to_PSarrayOut();
	query_result->add_error(NULL);
}

bool PgSQL_Connection::requires_RESETTING_CONNECTION(const PgSQL_Connection* client_conn) {
	for (auto i = 0; i < PGSQL_NAME_LAST_LOW_WM; i++) {
		if (client_conn->var_hash[i] == 0) {
			if (var_hash[i]) {
				// this connection has a variable set that the
				// client connection doesn't have.
				// Since connection cannot be unset , this connection
				// needs to be reset 
				return true;
			}
		}
	}
	if (client_conn->dynamic_variables_idx.size() < dynamic_variables_idx.size()) {
		// the server connection has more variables set than the client
		return true;
	}
	std::vector<uint32_t>::const_iterator it_c = client_conn->dynamic_variables_idx.begin(); // client connection iterator
	std::vector<uint32_t>::const_iterator it_s = dynamic_variables_idx.begin();              // server connection iterator
	for (; it_s != dynamic_variables_idx.end(); it_s++) {
		while (it_c != client_conn->dynamic_variables_idx.end() && (*it_c < *it_s)) {
			it_c++;
		}
		if (it_c != client_conn->dynamic_variables_idx.end() && *it_c == *it_s) {
			// the backend variable idx matches the frontend variable idx
		}
		else {
			// we are processing a backend variable but there are
			// no more frontend variables
			return true;
		}
	}
	return false;
}

bool PgSQL_Connection::has_same_connection_options(const PgSQL_Connection* client_conn) {
	if (userinfo->hash != client_conn->userinfo->hash) {
		if (strcmp(userinfo->username, client_conn->userinfo->username)) {
			return false;
		}
		if (strcmp(userinfo->dbname, client_conn->userinfo->dbname)) {
			return false;
		}
	}
	return true;
}

unsigned int PgSQL_Connection::get_memory_usage() const {
	// TODO: need to create new function in libpq
	unsigned int memory_bytes = (16 * 1024) * 2; //PSgetMemoryUsage(pgsql_conn);
	return /*sizeof(PGconn) +*/ memory_bytes;
}

bool PgSQL_Connection::suspend_resultset_fetch(uint64_t processed_bytes) const {
	bool suspend = (processed_bytes > overflow_safe_multiply<8,unsigned int>(pgsql_thread___threshold_resultset_size));
	// A cacheable query is allowed to buffer up to the whole query cache instead,
	// otherwise it would be paused before it could ever be stored.
	if (suspend == true && myds->sess && myds->sess->qpo && myds->sess->qpo->cache_ttl > 0) {
		suspend = (processed_bytes > ((uint64_t)pgsql_thread___query_cache_size_MB) * 1024ULL * 1024ULL);
	}
	if (suspend == true) return true;
	return (pgsql_thread___throttle_ratio_server_to_client && pgsql_thread___throttle_max_bytes_per_second_to_client
		&& (processed_bytes > (unsigned long long)pgsql_thread___throttle_max_bytes_per_second_to_client / 10 * (unsigned long long)pgsql_thread___throttle_ratio_server_to_client));
}

void PgSQL_Connection::update_bytes_recv(uint64_t bytes_recv) {
	__sync_fetch_and_add(&parent->bytes_recv, bytes_recv);
	myds->sess->thread->status_variables.stvar[st_var_queries_backends_bytes_recv] += bytes_recv;
	myds->bytes_info.bytes_recv += bytes_recv;
	bytes_info.bytes_recv += bytes_recv;
}

void PgSQL_Connection::update_bytes_sent(uint64_t bytes_sent) {
	__sync_fetch_and_add(&parent->bytes_sent, bytes_sent);
	myds->sess->thread->status_variables.stvar[st_var_queries_backends_bytes_sent] += bytes_sent;
	myds->bytes_info.bytes_sent += bytes_sent;
	bytes_info.bytes_sent += bytes_sent;
}

const char* PgSQL_Connection::get_pg_server_version_str(char* buff, int buff_size) {
	const int postgresql_version = get_pg_server_version();
	snprintf(buff, buff_size, "%d.%d.%d", postgresql_version / 10000, (postgresql_version / 100) % 100, postgresql_version % 100);
	return buff;
}

const char* PgSQL_Connection::get_pg_connection_status_str() {
	switch (get_pg_connection_status()) {
	case CONNECTION_OK:
		return "OK";
	case CONNECTION_BAD:
		return "BAD";
	case CONNECTION_STARTED:
		return "STARTED";
	case CONNECTION_MADE:
		return "MADE";
	case CONNECTION_AWAITING_RESPONSE:
		return "AWAITING_RESPONSE";
	case CONNECTION_AUTH_OK:
		return "AUTH_OK";
	case CONNECTION_SETENV:
		return "SETENV";
	case CONNECTION_SSL_STARTUP:
		return "SSL_STARTUP";
	case CONNECTION_NEEDED:
		return "NEEDED";
	case CONNECTION_CHECK_WRITABLE:
		return "CHECK_WRITABLE";
	case CONNECTION_CONSUME:
		return "CONSUME";
	case CONNECTION_GSS_STARTUP:
		return "GSS_STARTUP";
	case CONNECTION_CHECK_TARGET:
		return "CHECK_TARGET";
	case CONNECTION_CHECK_STANDBY:
		return "CHECK_STANDBY";
	}
	return "UNKNOWN";
}

const char* PgSQL_Connection::get_pg_transaction_status_str() {
	switch (get_pg_transaction_status()) {
	case PQTRANS_IDLE:
		return "IDLE";
	case PQTRANS_ACTIVE:
		return "ACTIVE";
	case PQTRANS_INTRANS:
		return "IN-TRANSACTION";
	case PQTRANS_INERROR:
		return "IN-ERROR-TRANSACTION";
	case PQTRANS_UNKNOWN:
		return "UNKNOWN";
	}
	return "INVALID";
}

void PgSQL_Connection::ProcessQueryAndSetStatusFlags(const char* query_digest_text, int savepoint_count) {
	if (query_digest_text == NULL) return;
	// unknown what to do with multiplex
	int mul = -1;
	if (myds) {
		if (myds->sess) {
			if (myds->sess->qpo) {
				mul = myds->sess->qpo->multiplex;
				if (mul == 0) {
					set_status(true, STATUS_PGSQL_CONNECTION_NO_MULTIPLEX);
				} else {
					if (mul == 1) {
						set_status(false, STATUS_PGSQL_CONNECTION_NO_MULTIPLEX);
					}
				}
			}
		}
	}

	if (get_status(STATUS_PGSQL_CONNECTION_USER_VARIABLE) == false) { // we search for variables only if not already set
		if (strncasecmp(query_digest_text, "SET ", 4) == 0) {
			// For issue #555 , multiplexing is disabled if --safe-updates is used (see session_vars definition)
			int sqloh = pgsql_thread___set_query_lock_on_hostgroup;
			switch (sqloh) {
			case 0: // old algorithm
				if (mul != 2) {
					if (index(query_digest_text, '.')) { // mul = 2 has a special meaning : do not disable multiplex for variables in THIS QUERY ONLY
						if (!IsKeepMultiplexEnabledVariables(query_digest_text)) {
							set_status(true, STATUS_PGSQL_CONNECTION_USER_VARIABLE);
						}
					}
				}
				break;
			case 1: // new algorithm
				if (myds->sess->locked_on_hostgroup > -1) {
					// locked_on_hostgroup was set, so some variable wasn't parsed
					set_status(true, STATUS_PGSQL_CONNECTION_USER_VARIABLE);
				}
				break;
			default:
				break;
			}
		} else {
			if (mul != 2 && index(query_digest_text, '.')) { // mul = 2 has a special meaning : do not disable multiplex for variables in THIS QUERY ONLY
				if (!IsKeepMultiplexEnabledVariables(query_digest_text)) {
					set_status(true, STATUS_PGSQL_CONNECTION_USER_VARIABLE);
				}
			}
		}
	}
	if (get_status(STATUS_PGSQL_CONNECTION_PREPARED_STATEMENT) == false) { // we search if prepared was already executed
		if (!strncasecmp(query_digest_text, "PREPARE ", strlen("PREPARE "))) {
			set_status(true, STATUS_PGSQL_CONNECTION_PREPARED_STATEMENT);
		}
	}

	// CREATE TEMP TABLE creates a session-scoped temporary table.
	// It exists only for the duration of the session and is automatically dropped when the session ends.
	// Since we are not tracking individual temp tables, the status will be reset only on DISCARD TEMP.
	if (get_status(STATUS_PGSQL_CONNECTION_TEMPORARY_TABLE) == false) { // we search for temporary if not already set
		if (!strncasecmp(query_digest_text, "CREATE TEMPORARY TABLE ", strlen("CREATE TEMPORARY TABLE ")) || 
			!strncasecmp(query_digest_text, "CREATE TEMP TABLE ", strlen("CREATE TEMP TABLE "))) {
			set_status(true, STATUS_PGSQL_CONNECTION_TEMPORARY_TABLE);
		}
	} else { // we search for temporary if not already set
		if (!strncasecmp(query_digest_text, "DISCARD TEMP", strlen("DISCARD TEMP"))) {
			set_status(false, STATUS_PGSQL_CONNECTION_TEMPORARY_TABLE);
		}
	}

	// LOCK TABLE is transaction-scoped:
	// The lock is released automatically when the transaction ends
	// (either COMMIT or ROLLBACK). It cannot persist beyond the transaction.
	if (get_status(STATUS_PGSQL_CONNECTION_LOCK_TABLES) == false) { // we search for lock tables only if not already set
		if (IsKnownActiveTransaction() == true && 
			!strncasecmp(query_digest_text, "LOCK TABLE", strlen("LOCK TABLE"))) {
			set_status(true, STATUS_PGSQL_CONNECTION_LOCK_TABLES);
		}
	} else {
		if (IsKnownActiveTransaction() == false) {
			set_status(false, STATUS_PGSQL_CONNECTION_LOCK_TABLES);
		}
	}

	// pg_advisory_xact_lock is transaction-scoped:
	// The advisory lock is automatically released at the end of the current transaction
	// (either COMMIT or ROLLBACK). It does not persist beyond the transaction.
	if (get_status(STATUS_PGSQL_CONNECTION_ADVISORY_XACT_LOCK) == false) {
		if (IsKnownActiveTransaction() == true && 
			!strncasecmp(query_digest_text, "SELECT pg_advisory_xact_lock", sizeof("SELECT pg_advisory_xact_lock") - 1)) {
			set_status(true, STATUS_PGSQL_CONNECTION_ADVISORY_XACT_LOCK);
		}
	} else {
		if (IsKnownActiveTransaction() == false) {
			set_status(false, STATUS_PGSQL_CONNECTION_ADVISORY_XACT_LOCK);
		}
	}

	// pg_advisory_lock is session-level:
	// In ProxySQL, as we are not tracking individual Advisory Locks, we will reset the status only 
	// when we see pg_advisory_unlock_all, which releases all session-level advisory locks.
	if (get_status(STATUS_PGSQL_CONNECTION_ADVISORY_LOCK) == false) { // we search for pg_advisory_lock* if not already set
		if (!strncasecmp(query_digest_text, "SELECT pg_advisory_lock", sizeof("SELECT pg_advisory_lock")-1)) {
			set_status(true, STATUS_PGSQL_CONNECTION_ADVISORY_LOCK);
		}
	} else {
		if (!strncasecmp(query_digest_text, "SELECT pg_advisory_unlock_all", sizeof("SELECT pg_advisory_unlock_all") - 1)) {
			set_status(false, STATUS_PGSQL_CONNECTION_ADVISORY_LOCK);
		}
	}

	// LISTEN registers a subscription on the backend connection, so the connection must
	// stay with this session: notifications can only be delivered to the client that asked
	// for them, and a pooled connection would hand them to whoever holds it next. This flag
	// is also what stops such a connection returning to the pool still subscribed.
	// Individual channels are not tracked, so only UNLISTEN * clears it -- after
	// UNLISTEN <channel> ProxySQL cannot know whether any subscription remains, and
	// unpinning while one does sends the next notification to the wrong client.
	// DISCARD ALL is the other way out, and it clears every flag through reset().
	// A subscription lives on this connection, so the connection has to stay with the
	// session that made it: pooled, it would hand notifications to whoever holds it next.
	// Only UNLISTEN * clears the flag, since individual channels are not tracked and
	// unpinning while one remains sends the next notification to the wrong client.
	// DISCARD ALL is the other way out, through reset().
	if (get_status(STATUS_PGSQL_CONNECTION_LISTEN) == false) {
		if (pgsql_stmt_first_keyword_is(query_digest_text, "LISTEN")) {
			set_status(true, STATUS_PGSQL_CONNECTION_LISTEN);
		}
	} else {
		// The star may abut the keyword: UNLISTEN* is valid and the digest keeps it joined,
		// so a compare against "UNLISTEN " would leave the connection pinned for good.
		if (pgsql_stmt_first_keyword_is(query_digest_text, "UNLISTEN")) {
			const char* p = query_digest_text + sizeof("UNLISTEN") - 1;
			while (*p == ' ') p++;
			if (*p == '*') set_status(false, STATUS_PGSQL_CONNECTION_LISTEN);
		}
	}

	// CREATE SEQUENCE vs CREATE TEMP SEQUENCE:
	/// - CREATE SEQUENCE: Persistent; survives across sessions until explicitly dropped.
	// - CREATE TEMP SEQUENCE: Session-scoped; automatically dropped when the session ends.
	// Since we are not tracking individual sequences, the status will not be reset on DROP SEQUENCE.
	// Instead, it will be reset on DISCARD SEQUENCES, which removes all session-scoped sequences.
	if (get_status(STATUS_PGSQL_CONNECTION_HAS_SEQUENCES) == false) { // we search for sequences only if not already set
		if (!strncasecmp(query_digest_text, "CREATE ", sizeof("CREATE ") - 1) &&
			(!strncasecmp(query_digest_text + sizeof("CREATE ") - 1, "SEQUENCE", sizeof("SEQUENCE") - 1) ||
				!strncasecmp(query_digest_text + sizeof("CREATE ") - 1, "TEMP SEQUENCE", sizeof("TEMP SEQUENCE") - 1) ||
				!strncasecmp(query_digest_text + sizeof("CREATE ") - 1, "TEMPORARY SEQUENCE", sizeof("TEMPORARY SEQUENCE") - 1))) {
			set_status(true, STATUS_PGSQL_CONNECTION_HAS_SEQUENCES);
		}
	} else { // we search for sequences only if not already set
		if (!strncasecmp(query_digest_text, "DISCARD SEQUENCES", sizeof("DISCARD SEQUENCES")-1)) {
			set_status(false, STATUS_PGSQL_CONNECTION_HAS_SEQUENCES);
		}
	}

	// SAVEPOINT is transaction-scoped:
	// The savepoint is automatically released at the end of the current transaction
	// (either COMMIT or ROLLBACK). It does not persist beyond the transaction.
	// If the savepoint count is -1, it means we are not sure if we are in a transaction or not.
	// If the savepoint count is > 0, it means we are in a transaction and have savepoints.
	// If the savepoint count is 0, it means we are not in a transaction and have no savepoints.
	if (get_status(STATUS_PGSQL_CONNECTION_HAS_SAVEPOINT) == false) {
		if (savepoint_count > 0) {
			set_status(true, STATUS_PGSQL_CONNECTION_HAS_SAVEPOINT);
		} else if (savepoint_count == -1) {
			if (IsKnownActiveTransaction() == true && 
				!strncasecmp(query_digest_text, "SAVEPOINT ", sizeof("SAVEPOINT ")-1)) {
					set_status(true, STATUS_PGSQL_CONNECTION_HAS_SAVEPOINT);
			}
		}
	} else {
		if (savepoint_count == 0) {
			set_status(false, STATUS_PGSQL_CONNECTION_HAS_SAVEPOINT);
		} else if (savepoint_count == -1) {
			if ((IsKnownActiveTransaction() == false) /* ||
				(strncasecmp(query_digest_text, "COMMIT", strlen("COMMIT")) == 0) ||
				(strncasecmp(query_digest_text, "ROLLBACK", strlen("ROLLBACK")) == 0) ||
				(strncasecmp(query_digest_text, "ABORT", strlen("ABORT")) == 0)*/) {
				set_status(false, STATUS_PGSQL_CONNECTION_HAS_SAVEPOINT);
			}
		} 
	}
}

// this function is identical to async_query() , with the only exception that query_result should never contain PGSQL_QUERY_RESULT_TUPLE
int PgSQL_Connection::async_send_simple_command(short event, char* stmt, unsigned long length) {
	PROXY_TRACE();
	PROXY_TRACE2();
	// In native_mode pgsql_conn is permanently NULL; the native query state
	// machine drives the same QUERY_START → USE_RESULT_CONT → QUERY_END flow.

	server_status = parent->status; // we copy it here to avoid race condition. The caller will see this
	if (IsServerOffline())
		return -1;

	switch (async_state_machine) {
	case ASYNC_QUERY_END:
		processing_multi_statement = false;	// no matter if we are processing a multi statement or not, we reached the end
		//return 0; <= bug. Do not return here, because we need to reach the if (async_state_machine==ASYNC_QUERY_END) few lines below
		break;
	case ASYNC_IDLE:
		set_query(stmt, length);
		async_state_machine = ASYNC_QUERY_START;
	default:
		handler(event);
		break;
	}
	if (query_result && (query_result->get_result_packet_type() & PGSQL_QUERY_RESULT_TUPLE)) {
		// this is a severe mistake, we shouldn't have reach here
		// for now we do not assert but report the error
		// PMC-10003: Retrieved a resultset while running a simple command using async_send_simple_command() .
		// async_send_simple_command() is used by ProxySQL to configure the connection, thus it
		// shouldn't retrieve any resultset.
		// A common issue for triggering this error is to have configure pgsql-init_connect to
		// run a statement that returns a resultset.
		proxy_error("Retrieved a resultset while running a simple command '%s'\n", stmt);
		return -2;
	}
	if (async_state_machine == ASYNC_QUERY_END) {
		// We just needed to know if the query was successful, not. 
		// We discard the result.
		if (query_result) {
			assert(!query_result_reuse);
			query_result->clear();
			query_result_reuse = query_result;
			query_result = NULL;
		}
		compute_unknown_transaction_status();
		if (is_error_present()) {
			return -1;
		} else {
			async_state_machine = ASYNC_IDLE;
			return 0;
		}
	}

	if (async_state_machine == ASYNC_USE_RESULT_START) {
		// if we reached this point it measn we are processing a multi-statement
		// and we need to exit to give control to MySQL_Session
		processing_multi_statement = true;
		return 2;
	}
	if (processing_multi_statement == true) {
		// we are in the middle of processing a multi-statement
		return 3;
	}

	return 1;
}

int PgSQL_Connection::async_perform_resync(short event) {
	PROXY_TRACE();
	PROXY_TRACE2();
	// pgsql_conn is permanently NULL in native_mode; resync_start()/resync_cont() drive
	// their own native branch instead of the PQsendPipelineSync() calls below.

	server_status = parent->status; // we copy it here to avoid race condition. The caller will see this
	if (IsServerOffline())
		return -1;

	switch (async_state_machine) {
	case ASYNC_RESYNC_END:
		processing_multi_statement = false;
		break;
	case ASYNC_IDLE:
		if (myds && myds->sess) {
			if (myds->sess->active_transactions == 0) {
				myds->sess->active_transactions = 1;
				myds->sess->transaction_started_at = myds->sess->thread->curtime;
			}
		}
		async_state_machine = ASYNC_RESYNC_START;
	default:
		handler(event);
		break;
	}
	if (async_state_machine == ASYNC_RESYNC_END) {
		if (myds && myds->sess) {
			if (myds->sess->active_transactions != 0) {
				myds->sess->active_transactions = 0;
				myds->sess->transaction_started_at = 0;
			}
		}
		// We just needed to know if the query was successful, not. 
		// We discard the result.
		if (query_result) {
			assert(!query_result_reuse);
			query_result->clear();
			query_result_reuse = query_result;
			query_result = NULL;
		}
		compute_unknown_transaction_status();
		// resync_failed only covers the two libpq send-phase paths that don't call
		// set_error() (PQsendPipelineSync/PQflush failures) -- it was never a full signal.
		// is_error_present() catches native's failures and a drain-phase libpq failure
		// (PQconsumeInput in fetch_result_cont()) that resync_failed has always missed too;
		// fetch_result_start() resets error state before this drain runs for both modes,
		// so it can't be a stale leftover here.
		if (resync_failed || is_error_present()) {
			return -1;
		} else {
			async_state_machine = ASYNC_IDLE;
			return 0;
		}
	}
	return 1;
}

unsigned int PgSQL_Connection::reorder_dynamic_variables_idx() {
	dynamic_variables_idx.clear();
	// note that we are inserting the index already ordered
	for (auto i = PGSQL_NAME_LAST_LOW_WM + 1; i < PGSQL_NAME_LAST_HIGH_WM; i++) {
		if (var_hash[i] != 0) {
			dynamic_variables_idx.push_back(i);
		}
	}
	unsigned int r = dynamic_variables_idx.size();
	return r;
}

unsigned int PgSQL_Connection::number_of_matching_session_variables(const PgSQL_Connection* client_conn, unsigned int& not_matching) {
	unsigned int ret = 0;
	for (auto i = 0; i < PGSQL_NAME_LAST_LOW_WM; i++) {
		if (client_conn->var_hash[i]) { // client has a variable set
			if (var_hash[i] == client_conn->var_hash[i]) { // server conection has the variable set to the same value
				ret++;
			}
			else {
				not_matching++;
			}
		}
	}
	// increse not_matching y the sum of client and server variables
	// when a match is found the counter will be reduced by 2
	not_matching += client_conn->dynamic_variables_idx.size();
	not_matching += dynamic_variables_idx.size();
	std::vector<uint32_t>::const_iterator it_c = client_conn->dynamic_variables_idx.begin(); // client connection iterator
	std::vector<uint32_t>::const_iterator it_s = dynamic_variables_idx.begin();              // server connection iterator
	for (; it_c != client_conn->dynamic_variables_idx.end() && it_s != dynamic_variables_idx.end(); it_c++) {
		while (it_s != dynamic_variables_idx.end() && *it_s < *it_c) {
			it_s++;
		}
		if (it_s != dynamic_variables_idx.end()) {
			if (*it_s == *it_c) {
				if (var_hash[*it_s] == client_conn->var_hash[*it_c]) { // server conection has the variable set to the same value
					// when a match is found the counter is reduced by 2
					not_matching -= 2;
					ret++;
				}
			}
		}
	}
	return ret;
}

void PgSQL_Connection::reset() {
	bool old_no_multiplex_hg = get_status(STATUS_PGSQL_CONNECTION_NO_MULTIPLEX_HG);
	bool old_compress = get_status(STATUS_PGSQL_CONNECTION_COMPRESSION);
	status_flags = 0;
	// reconfigure STATUS_PGSQL_CONNECTION_NO_MULTIPLEX_HG
	set_status(old_no_multiplex_hg, STATUS_PGSQL_CONNECTION_NO_MULTIPLEX_HG);
	// reconfigure STATUS_PGSQL_CONNECTION_COMPRESSION
	set_status(old_compress, STATUS_PGSQL_CONNECTION_COMPRESSION);
	reusable = true;
	creation_time = monotonic_time();
	delete local_stmts;
	local_stmts = new PgSQL_STMT_Local(false);

	// reset all variables
	for (int i = 0; i < PGSQL_NAME_LAST_HIGH_WM; i++) {
		var_hash[i] = 0;
		if (variables[i].value) {
			free(variables[i].value);
			variables[i].value = NULL;
		}
	}
	dynamic_variables_idx.clear();

	// We need to copy the startup parameters:
	// For client connections, we copy all startup parameters
	// For server connections, we copy only copy critical parameters
	copy_startup_parameters_to_pgsql_variables(/*copy_only_critical_param=*/!is_client_connection);

	if (options.init_connect) {
		free(options.init_connect);
		options.init_connect = NULL;
		options.init_connect_sent = false;
	}
	auto_increment_delay_token = 0;	
	resync_failed = false;
	// exit_pipeline_mode, and the DEBUG assertion that libpq's pipeline really is off,
	// are the transport's; resync_failed above is shared and stays inline (plan:350-352).
	reset_transport_state();
}

void PgSQL_Connection::set_status(bool set, uint32_t status_flag) {
	if (set) {
		this->status_flags |= status_flag;
	} else {
		this->status_flags &= ~status_flag;
	}
}

bool PgSQL_Connection::get_status(uint32_t status_flag) {
	return this->status_flags & status_flag;
}

bool PgSQL_Connection::MultiplexDisabled(bool check_delay_token) {
	// status_flags stores information about the status of the connection
	// can be used to determine if multiplexing can be enabled or not
	bool ret = false;
	if (status_flags & (STATUS_PGSQL_CONNECTION_USER_VARIABLE | STATUS_PGSQL_CONNECTION_PREPARED_STATEMENT |
		STATUS_PGSQL_CONNECTION_LOCK_TABLES | STATUS_PGSQL_CONNECTION_TEMPORARY_TABLE | STATUS_PGSQL_CONNECTION_ADVISORY_LOCK | 
		STATUS_PGSQL_CONNECTION_NO_MULTIPLEX | STATUS_PGSQL_CONNECTION_HAS_SEQUENCES | STATUS_PGSQL_CONNECTION_ADVISORY_XACT_LOCK | 
		STATUS_PGSQL_CONNECTION_NO_MULTIPLEX_HG | STATUS_PGSQL_CONNECTION_HAS_SAVEPOINT |
		STATUS_PGSQL_CONNECTION_LISTEN )) {
		ret = true;
	}
	if (check_delay_token && auto_increment_delay_token) return true;
	return ret;
}

void PgSQL_Connection::set_query(const char* stmt, unsigned long length, const char* _backend_stmt_name, const PgSQL_Extended_Query_Info* extended_query_info) {
	query.length = length;
	query.ptr = stmt;
	if (length > largest_query_length) {
		largest_query_length = length;
	}
	query.backend_stmt_name = _backend_stmt_name;
	query.extended_query_info = extended_query_info;
}

bool PgSQL_Connection::IsKeepMultiplexEnabledVariables(const char* query_digest_text) {

	return true;
	/* TODO: fix this
	if (query_digest_text == NULL) return true;

	char* query_digest_text_filter_select = NULL;
	unsigned long query_digest_text_len = strlen(query_digest_text);
	if (strncasecmp(query_digest_text, "SELECT ", strlen("SELECT ")) == 0) {
		query_digest_text_filter_select = (char*)malloc(query_digest_text_len - 7 + 1);
		memcpy(query_digest_text_filter_select, &query_digest_text[7], query_digest_text_len - 7);
		query_digest_text_filter_select[query_digest_text_len - 7] = '\0';
	}
	else {
		return false;
	}
	//filter @@session., @@local. and @@
	char* match = NULL;
	char* last_pos = NULL;
	const int at_session_offset = strlen("@@session.");
	const int at_local_offset = strlen("@@local."); // Alias of session
	const int double_at_offset = strlen("@@");
	while (query_digest_text_filter_select && (match = strcasestr(query_digest_text_filter_select, "@@session."))) {
		memmove(match, match + at_session_offset, strlen(match) - at_session_offset);
		last_pos = match + strlen(match) - at_session_offset;
		*last_pos = '\0';
	}
	while (query_digest_text_filter_select && (match = strcasestr(query_digest_text_filter_select, "@@local."))) {
		memmove(match, match + at_local_offset, strlen(match) - at_local_offset);
		last_pos = match + strlen(match) - at_local_offset;
		*last_pos = '\0';
	}
	while (query_digest_text_filter_select && (match = strcasestr(query_digest_text_filter_select, "@@"))) {
		memmove(match, match + double_at_offset, strlen(match) - double_at_offset);
		last_pos = match + strlen(match) - double_at_offset;
		*last_pos = '\0';
	}

	std::vector<char*>query_digest_text_filter_select_v;
	char* query_digest_text_filter_select_tok = NULL;
	char* save_query_digest_text_ptr = NULL;
	if (query_digest_text_filter_select) {
		query_digest_text_filter_select_tok = strtok_r(query_digest_text_filter_select, ",", &save_query_digest_text_ptr);
	}
	while (query_digest_text_filter_select_tok) {
		//filter "as"/space/alias,such as select @@version as a, @@version b
		while (1) {
			char c = *query_digest_text_filter_select_tok;
			if (!isspace(c)) {
				break;
			}
			query_digest_text_filter_select_tok++;
		}
		char* match_as;
		match_as = strcasestr(query_digest_text_filter_select_tok, " ");
		if (match_as) {
			query_digest_text_filter_select_tok[match_as - query_digest_text_filter_select_tok] = '\0';
			query_digest_text_filter_select_v.push_back(query_digest_text_filter_select_tok);
		}
		else {
			query_digest_text_filter_select_v.push_back(query_digest_text_filter_select_tok);
		}
		query_digest_text_filter_select_tok = strtok_r(NULL, ",", &save_query_digest_text_ptr);
	}

	std::vector<char*>keep_multiplexing_variables_v;
	char* keep_multiplexing_variables_tmp;
	char* save_keep_multiplexing_variables_ptr = NULL;
	unsigned long keep_multiplexing_variables_len = strlen(pgsql_thread___keep_multiplexing_variables);
	keep_multiplexing_variables_tmp = (char*)malloc(keep_multiplexing_variables_len + 1);
	memcpy(keep_multiplexing_variables_tmp, pgsql_thread___keep_multiplexing_variables, keep_multiplexing_variables_len);
	keep_multiplexing_variables_tmp[keep_multiplexing_variables_len] = '\0';
	char* keep_multiplexing_variables_tok = strtok_r(keep_multiplexing_variables_tmp, " ,", &save_keep_multiplexing_variables_ptr);
	while (keep_multiplexing_variables_tok) {
		keep_multiplexing_variables_v.push_back(keep_multiplexing_variables_tok);
		keep_multiplexing_variables_tok = strtok_r(NULL, " ,", &save_keep_multiplexing_variables_ptr);
	}

	for (std::vector<char*>::iterator it = query_digest_text_filter_select_v.begin(); it != query_digest_text_filter_select_v.end(); it++) {
		bool is_match = false;
		for (std::vector<char*>::iterator it1 = keep_multiplexing_variables_v.begin(); it1 != keep_multiplexing_variables_v.end(); it1++) {
			//printf("%s,%s\n",*it,*it1);
			if (strncasecmp(*it, *it1, strlen(*it1)) == 0) {
				is_match = true;
				break;
			}
		}
		if (is_match) {
			is_match = false;
			continue;
		}
		else {
			free(query_digest_text_filter_select);
			free(keep_multiplexing_variables_tmp);
			return false;
		}
	}
	free(query_digest_text_filter_select);
	free(keep_multiplexing_variables_tmp);
	return true;
	*/
}

bool PgSQL_Connection::is_valid_formatted_pq_error_header(const std::string& s, size_t pos) {
	if (pos >= s.size() || !std::isupper(s[pos])) return false;
	size_t prefix_end = pos;
	while (prefix_end < s.size() && std::isupper(s[prefix_end])) prefix_end++;
	if (prefix_end >= s.size() || s[prefix_end] != ':') return false;
	size_t size_start = prefix_end + 1;
	if (size_start >= s.size()) return false;

	// Check valid size format
	size_t size_end = size_start;
	if (size_end >= s.size() || !std::isdigit(s[size_end])) return false;
	while (size_end < s.size() && std::isdigit(s[size_end])) size_end++;
	return (size_end < s.size() && s[size_end] == ':');
}

std::map<std::string, std::vector<std::string>> PgSQL_Connection::parse_pq_error_message(const std::string& error_str) {
	std::map<std::string, std::vector<std::string>> components;
	size_t pos = 0;

	while (pos < error_str.size()) {
		if (is_valid_formatted_pq_error_header(error_str, pos)) {
			std::string prefix;
			int size = 0;
			std::string value;

			// Extract prefix
			size_t prefix_end = pos;
			while (prefix_end < error_str.size() && std::isupper(error_str[prefix_end]))
				prefix_end++;
			prefix = error_str.substr(pos, prefix_end - pos);
			pos = prefix_end + 1;

			// Parse size
			size_t size_start = pos;
			while (pos < error_str.size() && std::isdigit(error_str[pos])) pos++;
			std::string size_str = error_str.substr(size_start, pos - size_start);
			bool valid_size = true;

			if (size_str.empty()) {
				valid_size = false;
			} else {
				size = 0;
				for (char c : size_str) {
					if (!std::isdigit(c)) {
						valid_size = false;
						break;
					}
					int digit = c - '0';
					if (size > (INT_MAX - digit) / 10) {
						valid_size = false;
						break;
					}
					size = size * 10 + digit;
				}
			}
			if (!valid_size || size < 0) {
				pos = size_start;
				continue;
			}
			pos++;
			// Extract value
			size_t value_start = pos;
			size_t value_end;
			value_end = value_start + size;
			if (value_end > error_str.size()) {
				pos = value_start;
				continue;
			}

			value = trim(error_str.substr(value_start, value_end - value_start));
			components[prefix].push_back(value);
			pos = value_end;
		}
		else {
			size_t le_start = pos;
			while (pos < error_str.size() && !is_valid_formatted_pq_error_header(error_str, pos))
				pos++;
			std::string le_value = error_str.substr(le_start, pos - le_start);
			le_value = trim(le_value);
			if (!le_value.empty()) {
				components["LE"].push_back(le_value);
			}
		}
	}

	return components;
}

std::pair<const char*, uint32_t> PgSQL_Connection::get_startup_parameter_and_hash(enum pgsql_variable_name idx) {
	// within valid range?
	assert(idx >= 0 && idx < PGSQL_NAME_LAST_HIGH_WM);

	// Attempt to retrieve value from default startup parameters
	if (startup_parameters_hash[idx] != 0) {
		assert(startup_parameters[idx]);
		return { startup_parameters[idx], startup_parameters_hash[idx] };
	}
	assert(!(idx < PGSQL_NAME_LAST_LOW_WM));
	return { "", 0};
}

void PgSQL_Connection::copy_pgsql_variables_to_startup_parameters(bool copy_only_critical_param) {

	//memcpy(startup_parameters_hash, var_hash, sizeof(uint32_t) * PGSQL_NAME_LAST_LOW_WM);
	for (int i = 0; i < PGSQL_NAME_LAST_LOW_WM; ++i) {
		assert(var_hash[i]);
		assert(variables[i].value);
		startup_parameters_hash[i] = var_hash[i];
		free(startup_parameters[i]);
		startup_parameters[i] = strdup(variables[i].value);
	}

	if (copy_only_critical_param) return;

	for (int i = PGSQL_NAME_LAST_LOW_WM + 1; i < PGSQL_NAME_LAST_HIGH_WM; i++) {
		if (var_hash[i] != 0) {
			startup_parameters_hash[i] = var_hash[i];
			free(startup_parameters[i]);
			startup_parameters[i] = strdup(variables[i].value);
		} else {
			startup_parameters_hash[i] = 0;
			free(startup_parameters[i]);
			startup_parameters[i] = nullptr;
		}
	}
}

void PgSQL_Connection::copy_startup_parameters_to_pgsql_variables(bool copy_only_critical_param) {

	//memcpy(var_hash, startup_parameters_hash, sizeof(uint32_t) * PGSQL_NAME_LAST_LOW_WM);
	for (int i = 0; i < PGSQL_NAME_LAST_LOW_WM; i++) {
		assert(startup_parameters_hash[i]);
		assert(startup_parameters[i]);
		var_hash[i] = startup_parameters_hash[i];
		free(variables[i].value);
		variables[i].value = strdup(startup_parameters[i]);
	}

	if (copy_only_critical_param) return;

	for (int i = PGSQL_NAME_LAST_LOW_WM + 1; i < PGSQL_NAME_LAST_HIGH_WM; i++) {
		if (startup_parameters_hash[i]) {
			var_hash[i] = startup_parameters_hash[i];
			free(variables[i].value);
			variables[i].value = strdup(startup_parameters[i]);
		} else {
			var_hash[i] = 0;
			free(variables[i].value);
			variables[i].value = nullptr;
		}
	}
}

void PgSQL_Connection::init_query_result() {
	if (!query_result_reuse) {
		if (query_result) {
#ifdef DEBUG
			assert(!query_result);
#endif
			delete query_result;
			query_result = nullptr;
		}
		query_result = new PgSQL_Query_Result();
	} else {
		query_result = query_result_reuse;
		query_result_reuse = nullptr;
	}

	if (myds->sess->mirror == false) {
		query_result->init(&myds->sess->client_myds->myprot, myds, this);
	}
	else {
		query_result->init(NULL, myds, this);
	}
	new_result = true;
}

PgSQL_Backend_Kill_Args::PgSQL_Backend_Kill_Args(PGconn* conn, const PgSQL_Connection_userinfo* ui, const char* host,
	unsigned int p, unsigned int hid, bool ssl, TYPE typ, PgSQL_Thread* thd) {

	if (typ == TYPE::CANCEL_QUERY)
		cancel_conn = PQgetCancel(conn);
	else {
		cancel_conn = nullptr;
	}
	username = strdup(ui->username);
	// A user with no stored secret is the one case worth carrying instead of crashing here:
	// pgsql_append_conninfo_credentials() refuses to build a conninfo without a credential, so
	// the terminate is skipped rather than run as whoever owns the ProxySQL process.
	password = ui->password ? strdup(ui->password) : nullptr;
	hostname = strdup(host);
	dbname = strdup(ui->dbname);
	// Carry the harvested SCRAM keys, so TERMINATE_CONNECTION can authenticate a verifier-stored
	// user the same way connect_start() does.
	memcpy(scram_client_key, ui->scram_client_key, sizeof(scram_client_key));
	memcpy(scram_server_key, ui->scram_server_key, sizeof(scram_server_key));
	has_scram_keys = ui->has_scram_keys;
	port = p;
	hostgroup_id = hid;
	type = typ;
	pgsql_thd = thd;
	backend_pid = PQbackendPID(conn);
	ssl_config.use_ssl = ssl;
	if (ssl) {
		std::unique_ptr<PgSQLServers_SslParams> params {
			PgHGM->get_Server_SSL_Params(hostname, port, username)
		};
		if (params != nullptr) {
			ssl_config.sslkey = params->ssl_key.length() > 0 ? strdup(params->ssl_key.c_str()) : nullptr;
			ssl_config.sslcert = params->ssl_cert.length() > 0 ? strdup(params->ssl_cert.c_str()) : nullptr;
			ssl_config.sslrootcert = params->ssl_ca.length() > 0 ? strdup(params->ssl_ca.c_str()) : nullptr;
			ssl_config.sslcrl = params->ssl_crl.length() > 0 ? strdup(params->ssl_crl.c_str()) : nullptr;
			ssl_config.sslcrldir = params->ssl_crlpath.length() > 0 ? strdup(params->ssl_crlpath.c_str()) : nullptr;
			ssl_config.ssl_min_protocol_version = params->ssl_min_protocol_version.length() > 0 ? strdup(params->ssl_min_protocol_version.c_str()) : nullptr;
			ssl_config.ssl_max_protocol_version = params->ssl_max_protocol_version.length() > 0 ? strdup(params->ssl_max_protocol_version.c_str()) : nullptr;
		} else {
			ssl_config.sslkey = pgsql_thread___ssl_p2s_key ? strdup(pgsql_thread___ssl_p2s_key) : nullptr;
			ssl_config.sslcert = pgsql_thread___ssl_p2s_cert ? strdup(pgsql_thread___ssl_p2s_cert) : nullptr;
			ssl_config.sslrootcert = pgsql_thread___ssl_p2s_ca ? strdup(pgsql_thread___ssl_p2s_ca) : nullptr;
			ssl_config.sslcrl = pgsql_thread___ssl_p2s_crl ? strdup(pgsql_thread___ssl_p2s_crl) : nullptr;
			ssl_config.sslcrldir = pgsql_thread___ssl_p2s_crlpath ? strdup(pgsql_thread___ssl_p2s_crlpath) : nullptr;
			ssl_config.ssl_min_protocol_version = nullptr;
			ssl_config.ssl_max_protocol_version = nullptr;
		}
	} else {
		ssl_config.sslkey = nullptr;
		ssl_config.sslcert = nullptr;
		ssl_config.sslrootcert = nullptr;
		ssl_config.sslcrl = nullptr;
		ssl_config.sslcrldir = nullptr;
		ssl_config.ssl_min_protocol_version = nullptr;
		ssl_config.ssl_max_protocol_version = nullptr;
	}
}

PgSQL_Backend_Kill_Args::~PgSQL_Backend_Kill_Args() {
	free(username);
	free(password);
	free(hostname);
	free(dbname);
	// Scrub the copied SCRAM key material (the ClientKey is password-equivalent) with a non-elidable
	// wipe, as PgSQL_Connection_userinfo does.
	OPENSSL_cleanse(scram_client_key, sizeof(scram_client_key));
	OPENSSL_cleanse(scram_server_key, sizeof(scram_server_key));
	free(ssl_config.sslkey);
	free(ssl_config.sslcert);
	free(ssl_config.sslrootcert);
	free(ssl_config.sslcrl);
	free(ssl_config.sslcrldir);
	free(ssl_config.ssl_min_protocol_version);
	free(ssl_config.ssl_max_protocol_version);
	if (cancel_conn)
		PQfreeCancel(cancel_conn);
}

// Native-mode query cancellation primitive. Opens a fresh TCP connection to
// host:port with a BOUNDED connect (non-blocking connect + poll, 5s) and sends
// the 16-byte CancelRequest carrying (pid, secret) with a bounded blocking send
// (SO_SNDTIMEO). This runs inside the detached kill thread, which tolerates
// blocking (PQcancel blocks too), but the bound keeps a black-holed backend
// from parking the thread for the kernel's full connect timeout (~2min).
// Per the protocol the server sends no reply — it acts on the request and
// closes — so we only need a successful send.
//
// NOTE on TLS: the CancelRequest is sent over a PLAIN connection. This is what
// the protocol prescribes — PostgreSQL processes CancelRequest at the
// startup-packet layer, BEFORE SSL negotiation and pg_hba rule matching, so a
// plaintext cancel commonly succeeds even against hostssl-only backends. If a
// backend or middlebox nonetheless refuses the plaintext connection, the
// failure is reported gracefully (proxy_error + error counter) and the query
// simply runs to completion, mirroring a lost PQcancel.
static bool pg_native_send_cancel_request(const char* host, unsigned int port,
	int pid, int secret, char* errbuf, size_t errlen) {
	const int CONNECT_TIMEOUT_MS = 5000;
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	char portstr[16];
	snprintf(portstr, sizeof(portstr), "%u", port);

	struct addrinfo* res = nullptr;
	int gai = getaddrinfo(host, portstr, &hints, &res);
	if (gai != 0 || res == nullptr) {
		snprintf(errbuf, errlen, "getaddrinfo(%s:%s) failed: %s", host, portstr, gai_strerror(gai));
		if (res) freeaddrinfo(res);
		return false;
	}

	int sock = -1;
	for (struct addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
		sock = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (sock < 0) continue;
		// Bounded connect: non-blocking connect + poll(POLLOUT) with timeout,
		// then verify SO_ERROR. Falls through to the next addrinfo on failure.
		int fl = fcntl(sock, F_GETFL, 0);
		if (fl < 0 || fcntl(sock, F_SETFL, fl | O_NONBLOCK) < 0) {
			::close(sock); sock = -1; continue;
		}
		int rc = ::connect(sock, ai->ai_addr, ai->ai_addrlen);
		if (rc != 0 && errno != EINPROGRESS) {
			::close(sock); sock = -1; continue;
		}
		if (rc != 0) { // in progress: wait bounded for writability
			struct pollfd pfd;
			pfd.fd = sock;
			pfd.events = POLLOUT;
			pfd.revents = 0;
			int prc;
			do {
				prc = ::poll(&pfd, 1, CONNECT_TIMEOUT_MS);
			} while (prc < 0 && errno == EINTR);
			if (prc <= 0) { // timeout or poll error
				::close(sock); sock = -1; continue;
			}
			int soerr = 0;
			socklen_t slen = sizeof(soerr);
			if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &soerr, &slen) < 0 || soerr != 0) {
				::close(sock); sock = -1; continue;
			}
		}
		// Connected: restore blocking mode and bound the send with SO_SNDTIMEO.
		if (fcntl(sock, F_SETFL, fl) < 0) {
			::close(sock); sock = -1; continue;
		}
		struct timeval tv;
		tv.tv_sec = CONNECT_TIMEOUT_MS / 1000;
		tv.tv_usec = (CONNECT_TIMEOUT_MS % 1000) * 1000;
		setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)); // best-effort
		break;
	}
	freeaddrinfo(res);
	if (sock < 0) {
		snprintf(errbuf, errlen, "connect(%s:%s) failed or timed out (%dms): %s",
			host, portstr, CONNECT_TIMEOUT_MS, strerror(errno));
		return false;
	}

	unsigned char pkt[16];
	pg_build_cancel_request(pkt, pid, secret);
	size_t off = 0;
	bool ok = true;
	while (off < sizeof(pkt)) {
		ssize_t n = ::send(sock, pkt + off, sizeof(pkt) - off, MSG_NOSIGNAL);
		if (n > 0) { off += (size_t)n; continue; }
		if (n < 0 && (errno == EINTR)) continue;
		snprintf(errbuf, errlen, "send(CancelRequest) failed: %s", strerror(errno));
		ok = false;
		break;
	}
	::close(sock);
	return ok;
}

void* PgSQL_backend_kill_thread(void* arg) {
	assert(arg);
	PgSQL_Backend_Kill_Args* backend_kill_args = static_cast<PgSQL_Backend_Kill_Args*>(arg);

	if (backend_kill_args->type == PgSQL_Backend_Kill_Args::TYPE::CANCEL_QUERY) {
		// Native connections have no libpq handle (cancel_conn == NULL). Serve
		// the cancel with a raw CancelRequest over a fresh TCP connection using
		// the pid/secret captured from the backend's BackendKeyData.
		if (backend_kill_args->native_mode) {
			if (backend_kill_args->pgsql_thd) backend_kill_args->pgsql_thd->status_variables.stvar[st_var_killed_queries]++;
			char nerrbuf[256];
			if (!pg_native_send_cancel_request(backend_kill_args->hostname, backend_kill_args->port,
				backend_kill_args->backend_pid, backend_kill_args->native_secret_key, nerrbuf, sizeof(nerrbuf))) {
				proxy_error("Failed to cancel query (native) on %s:%d with backend PID %d: %s\n",
					backend_kill_args->hostname, backend_kill_args->port, backend_kill_args->backend_pid, nerrbuf);
				PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::pgsql, backend_kill_args->hostgroup_id,
					backend_kill_args->hostname, backend_kill_args->port, 999);
			} else {
				proxy_warning("Canceled query (native) on %s:%d with backend PID %d successfully\n",
					backend_kill_args->hostname, backend_kill_args->port, backend_kill_args->backend_pid);
			}
			goto __exit;
		}
		if (!backend_kill_args->cancel_conn) {
			proxy_error("Failed to cancel query on %s:%d with backend PID %d\n", backend_kill_args->hostname,
				backend_kill_args->port, backend_kill_args->backend_pid);
			PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::pgsql, backend_kill_args->hostgroup_id,
				backend_kill_args->hostname, backend_kill_args->port, 999);
			goto __exit;
		}

		if (backend_kill_args->pgsql_thd) backend_kill_args->pgsql_thd->status_variables.stvar[st_var_killed_queries]++;

		char errbuf[256];
		if (!PQcancel(backend_kill_args->cancel_conn, errbuf, sizeof(errbuf))) {
			proxy_error("Failed to cancel query on %s:%d with backend PID %d: %s\n", backend_kill_args->hostname, 
				backend_kill_args->port, backend_kill_args->backend_pid, errbuf);
			PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::pgsql, backend_kill_args->hostgroup_id, 
				backend_kill_args->hostname, backend_kill_args->port, 999);
		} else {
			proxy_warning("Canceled query on %s:%d with backend PID %d successfully\n", backend_kill_args->hostname,
				backend_kill_args->port, backend_kill_args->backend_pid);
		}
	} else if (backend_kill_args->type == PgSQL_Backend_Kill_Args::TYPE::TERMINATE_CONNECTION) {

		std::ostringstream conninfo;
		append_conninfo_param(conninfo, "user", backend_kill_args->username); // username
		if (pgsql_append_conninfo_credentials(conninfo, backend_kill_args->username, backend_kill_args->password,
			backend_kill_args->has_scram_keys, backend_kill_args->scram_client_key,
			backend_kill_args->scram_server_key, "kill connection") == false) {
			// Fail closed. The terminate is best-effort, so skipping it is correct; connecting on
			// an ambient PGPASSWORD / ~/.pgpass credential is not. The helper logged the reason.
			goto __exit;
		}
		append_conninfo_param(conninfo, "dbname", backend_kill_args->dbname); // dbname
		append_conninfo_param(conninfo, "host", backend_kill_args->hostname); // backend address
		// port=0 means hostname is a Unix-domain socket path; libpq rejects
		// "port=0" with "invalid port number: \"0\"".
		if (backend_kill_args->port != 0) {
			conninfo << "port=" << backend_kill_args->port << " ";
		}
		conninfo << "application_name=proxysql "; // application name
		
		if (backend_kill_args->ssl_config.use_ssl) {
			conninfo << "sslmode='require' "; // SSL required
			append_conninfo_param(conninfo, "sslkey", backend_kill_args->ssl_config.sslkey);
			append_conninfo_param(conninfo, "sslcert", backend_kill_args->ssl_config.sslcert);
			append_conninfo_param(conninfo, "sslrootcert", backend_kill_args->ssl_config.sslrootcert);
			append_conninfo_param(conninfo, "sslcrl", backend_kill_args->ssl_config.sslcrl);
			append_conninfo_param(conninfo, "sslcrldir", backend_kill_args->ssl_config.sslcrldir);
			// Per-server TLS protocol pinning was pre-parsed from
			// ssl_protocol_version_range when the Kill_Args struct was built.
			append_conninfo_param(conninfo, "ssl_min_protocol_version", backend_kill_args->ssl_config.ssl_min_protocol_version);
			append_conninfo_param(conninfo, "ssl_max_protocol_version", backend_kill_args->ssl_config.ssl_max_protocol_version);
		} else {
			conninfo << "sslmode='disable' "; // not supporting SSL
		}

		const std::string& conninfo_str = conninfo.str();
		PGconn* kill_conn = PQconnectdb(conninfo_str.c_str());

		if (PQstatus(kill_conn) != CONNECTION_OK) {
			proxy_error("Connection failed: %s\n", PQerrorMessage(kill_conn));
			PQfinish(kill_conn);
			goto __exit;
		}

		if (backend_kill_args->pgsql_thd) backend_kill_args->pgsql_thd->status_variables.stvar[st_var_killed_connections]++;

		char query[128];
		snprintf(query, sizeof(query), "SELECT pg_terminate_backend(%d)", backend_kill_args->backend_pid);

		PGresult* res = PQexec(kill_conn, query);
		if (PQresultStatus(res) != PGRES_TUPLES_OK) {
			proxy_error("Terminate failed: %s\n", PQerrorMessage(kill_conn));
		}
		PQclear(res);
		// release the connection used to run the terminate
		PQfinish(kill_conn);


		//proxy_warning("Terminating connection on %s:%d with backend PID %d\n", ka->hostname, ka->port, ka->backend_pid);
	}
__exit:
	delete backend_kill_args;
	return NULL;
}
