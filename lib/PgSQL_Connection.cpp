
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
#include "PgSQL_HostGroups_Manager.h"
#include "PgSQL_Monitor.hpp"
#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_PreparedStatement.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Query_Processor.h"
#include "PgSQL_Variables.h"
#include "PgSQL_Extended_Query_Message.h"

extern char * binary_sha1;

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

void print_backtrace(void);

#define NEXT_IMMEDIATE(new_st) do { async_state_machine = new_st; goto handler_again; } while (0)

PgSQL_Connection::PgSQL_Connection(bool is_client_conn) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Creating new PgSQL_Connection %p\n", this);
	is_client_connection = is_client_conn;
	pgsql_conn = NULL;
	result_type = 0;
	pgsql_result = NULL;
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
	is_copy_out = false;
	exit_pipeline_mode = false;
	resync_failed = false;
	reset_error();
	memset(&connected_host_details, 0, sizeof(connected_host_details));
}

PgSQL_Connection::~PgSQL_Connection() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Destroying PgSQL_Connection %p\n", this);
	if (userinfo) {
		delete userinfo;
		userinfo = NULL;
	}
	if (pgsql_result) {
		PQclear(pgsql_result);
		pgsql_result = NULL;
	}
	if (local_stmts) {
		delete local_stmts;
		local_stmts = NULL;
	}
	if (pgsql_conn) {
		if (is_connected())
			__sync_fetch_and_sub(&PgHGM->status.server_connections_connected, 1);
		async_free_result();
		PQfinish(pgsql_conn);
		pgsql_conn = NULL;
	}
	// Native (non-libpq) connection cleanup. In native mode pgsql_conn stays NULL,
	// so the block above is skipped: mirror its connected-counter decrement and
	// free the native socket + SCRAM state here.
	if (native_mode) {
		if (native_connected) {
			__sync_fetch_and_sub(&PgHGM->status.server_connections_connected, 1);
		}
		if (native_scram) {
			pg_scram_free(native_scram);
			native_scram = nullptr;
		}
		if (fd >= 0) {
			::close(fd);
			fd = -1;
		}
		// The TLS session is owned by this connection (see PgSQL_Connection.h), so it
		// must be released here as well as in native_teardown(): a pooled connection
		// evicted by destroy_MyConn_from_pool() is `delete`d WITHOUT going through
		// teardown, and would otherwise leak the SSL and both its BIOs. SSL_free()
		// releases the BIOs too (SSL_set_bio transferred them).
		if (native_ssl) {
			SSL_free(native_ssl);
			native_ssl  = nullptr;
			native_rbio = nullptr;
			native_wbio = nullptr;
		}
		// native_ssl_ctx is normally freed at SSL_new() time (the SSL holds a ref) or
		// in native_teardown(); free here as a safety net if a connection is destroyed
		// before either ran. The SSL* itself lives on myds and is freed by ~PgSQL_Data_Stream().
		if (native_ssl_ctx) {
			SSL_CTX_free(native_ssl_ctx);
			native_ssl_ctx = nullptr;
		}
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

	if (connected_host_details.hostname) {
		free(connected_host_details.hostname);
		connected_host_details.hostname = NULL;
	}
	if (connected_host_details.ip) {
		free(connected_host_details.ip);
		connected_host_details.hostname = NULL;
	}

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
		fd = PQsocket(pgsql_conn);
#else
		PQsocket(pgsql_conn);
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
		native_mode = pgsql_thread___use_native_backend_protocol;
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
			proxy_error("Failed to PQconnectStart() on %u:%s:%d , FD (Conn:%d , MyDS:%d) , %s.\n", parent->myhgc->hid, parent->address, parent->port, (native_mode ? fd : PQsocket(pgsql_conn)), myds->fd, get_error_code_with_message().c_str());
			NEXT_IMMEDIATE(ASYNC_CONNECT_FAILED);
		} else {
			// Native sockets are created O_NONBLOCK already; only the libpq path
			// needs the PQsetnonblocking() handshake (pgsql_conn is NULL in native mode).
			if (!native_mode && PQisnonblocking(pgsql_conn) == false) {
				// Set non-blocking mode
				if (PQsetnonblocking(pgsql_conn, 1) != 0) {
					set_error_from_PQerrorMessage();
					proxy_error("Failed to set non-blocking mode: %s\n", get_error_code_with_message().c_str());
					NEXT_IMMEDIATE(ASYNC_CONNECT_FAILED);
				}
			}
			NEXT_IMMEDIATE(ASYNC_CONNECT_SUCCESSFUL);
		}
		break;
	case ASYNC_CONNECT_SUCCESSFUL:
		if (!is_connected()) 
			assert(0); // shouldn't ever reach here, we have messed up the state machine
		
		if (get_pg_ssl_in_use()) {
			if (native_mode && myds && myds->sess && myds->sess->session_fast_forward) {
				// fast_forward relays raw bytes and wants the backend SSL on the data
				// stream. Handing it ours is not fatal -- detach_connection() nulls
				// myds->ssl for fast_forward without freeing it (a deliberate
				// borrowed-pointer design), so there is no double free -- but the
				// block below calls SSL_set_bio(), which REPLACES and frees the BIOs
				// this connection still holds pointers to, leaving native_rbio /
				// native_wbio dangling.
				//
				// MEASURED: with this guard disabled, 10 native fast_forward TLS
				// sessions produced no crash, no assert and no double free; the
				// queries failed either way. fast_forward + backend TLS is broken for
				// BOTH the native and libpq paths (verified: libpq fails identically),
				// so this guard changes no user-visible outcome. It is kept only so
				// the connection is never left holding freed BIO pointers; the
				// fallback also routes the session to libpq, which is the path that
				// owns this combination.
				native_capability_gap("fast_forward with native TLS");
				return async_state_machine;
			}
			if (myds && myds->sess && myds->sess->session_fast_forward) {
				assert(myds->ssl == NULL);
				SSL* ssl_obj = get_pg_ssl_object();
				if (ssl_obj != NULL) {
					myds->encrypted = true;
					myds->ssl = ssl_obj;
					myds->rbio_ssl = BIO_new(BIO_s_mem());
					myds->wbio_ssl = BIO_new(BIO_s_mem());
					SSL_set_bio(myds->ssl, myds->rbio_ssl, myds->wbio_ssl);
				}
				else {
					// it means that ProxySQL tried to use SSL to connect to the backend
					// but the backend didn't support SSL				
				}
			}
		}
		__sync_fetch_and_add(&PgHGM->status.server_connections_connected, 1);
		__sync_fetch_and_add(&parent->connect_OK, 1);
		// Seed the PgSQL DNS cache from the just-established connection so
		// the next connect for this hostname can skip getaddrinfo even if
		// the background resolver loop hasn't visited it yet. libpq-only:
		// the native path resolves via the DNS cache itself in native_connect_start().
		if (!native_mode) {
			PgSQL_Monitor::update_dns_cache_from_pgsql_conn(pgsql_conn);
		}
		break;
	case ASYNC_CONNECT_FAILED:
		//PQfinish(pgsql_conn);//release connection even on error
		//pgsql_conn = NULL;
		// Native mode: release the native socket/SCRAM state promptly. Some failure
		// sub-paths already teardown, but generic failures may reach here with the
		// fd still open; native_teardown() sets fd=-1 so this is double-close safe.
		if (native_mode && fd >= 0) {
			native_teardown();
		}
		PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::pgsql, parent->myhgc->hid, parent->address, parent->port, 9999 /* TODO: fix this mysql_errno(pgsql) */);
		parent->connect_error(9999 /* TODO: fix this mysql_errno(pgsql)*/);
		break;
	case ASYNC_CONNECT_TIMEOUT:
		// to fix
		//PQfinish(pgsql_conn);//release connection
		//pgsql_conn = NULL;
		// Native mode: a connect timeout leaves the native socket open; release it
		// now instead of waiting for the destructor. native_teardown() sets fd=-1,
		// so the destructor's fd>=0 guard prevents any double-close.
		if (native_mode && fd >= 0) {
			native_teardown();
		}
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
			// set_single_row_mode() is a libpq concept (PQsetSingleRowMode) and
			// asserts pgsql_conn; the native path streams raw DataRow messages
			// individually, so skip it entirely in native mode.
			if (is_error_present() ||
				(!native_mode && !set_single_row_mode())) {
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

		// --- Native simple-query / simple-command result fetch (Task 1.6c) ---
		// Stream raw backend messages directly into query_result. This fully
		// handles the native path and must NOT fall through to any libpq
		// PGresult dispatch below.
		if (native_mode) {
			native_fetch_result_cont(event);
			if (async_exit_status) {
				// Need more bytes from the socket → wait for READ.
				next_event(ASYNC_USE_RESULT_CONT);
				break;
			}
			if (native_result_complete || is_error_present()) {
				// ReadyForQuery consumed (result complete) or a fatal recv/frame
				// error: hand off to the end state (ASYNC_QUERY_END for queries,
				// or the configured fetch_result_end_st).
				NEXT_IMMEDIATE(fetch_result_end_st);
			}
			// Neither complete nor error nor waiting: loop to drain/recv more.
			NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
		}

		fetch_result_cont(event);
		if (async_exit_status) {
			next_event(ASYNC_USE_RESULT_CONT);
			break;
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
			NEXT_IMMEDIATE(fetch_result_end_st);
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
					break;
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
							// Pass the global stmt_info so a statement-level Describe ('S')
							// populates the set-once metadata cache (libpq-mode capture).
							bytes_recv = query_result->add_describe_completion(result.get(), query.extended_query_info->stmt_type,
								query.extended_query_info->stmt_info);
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
					NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
					break;
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
					NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
					break;
				case PGRES_TUPLES_OK:
				case PGRES_SINGLE_TUPLE:
					break;
				case PGRES_COPY_OUT:
					if (handle_copy_out(result.get(), &processed_bytes) == false) {
						next_event(ASYNC_USE_RESULT_CONT);
						return async_state_machine; // Threashold for result size reached. Pause temporarily
					}
					NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
					break;
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
					NEXT_IMMEDIATE(fetch_result_end_st);
					break;
				case PGRES_PIPELINE_SYNC:
					// backend connection is in Ready for Query state, we can now safely exit pipeline mode
					exit_pipeline_mode = true;
					NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
					break;
				case PGRES_PIPELINE_ABORTED:
					// received an extended query immediately after an error was triggered by a previous query (before sync).
					// In ProxySQL this should never happen, since the extended query frame is reset after an error.
					// However, it may rarely occur if an error is raised during the "describe portal" phase (while executing).
					// In that case, we continue until PGRES_PIPELINE_SYNC (Ready for Query state) is received, then safely exit pipeline mode.
					NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
					break;
				case PGRES_BAD_RESPONSE:
				case PGRES_NONFATAL_ERROR:
				case PGRES_FATAL_ERROR:
				default:
					// if on previous call we encountered a FATAL error, we will not process the result, as it will contain residual protocol messages
					// from the broken connection
					if (is_error_present() == true && get_error_severity() == PGSQL_ERROR_SEVERITY::ERRSEVERITY_FATAL) {
						NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
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
					NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
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
					processed_bytes += bytes_recv;	// issue #527 : this variable will store the amount of bytes processed during this event
					
					bool suspend_resultset_fetch = (processed_bytes > overflow_safe_multiply<8,unsigned int>(pgsql_thread___threshold_resultset_size));
					 
					if (suspend_resultset_fetch == true && myds->sess && myds->sess->qpo && myds->sess->qpo->cache_ttl > 0) {
						suspend_resultset_fetch = (processed_bytes > ((uint64_t)pgsql_thread___query_cache_size_MB) * 1024ULL * 1024ULL);
					}
					
					if (
						suspend_resultset_fetch
						||
						(pgsql_thread___throttle_ratio_server_to_client && pgsql_thread___throttle_max_bytes_per_second_to_client && (processed_bytes > (unsigned long long)pgsql_thread___throttle_max_bytes_per_second_to_client / 10 * (unsigned long long)pgsql_thread___throttle_ratio_server_to_client))
						) {
						next_event(ASYNC_USE_RESULT_CONT); // we temporarily pause
						break;
					} else {
						NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT); // we continue looping 
					}
				} else {
					const unsigned int bytes_recv=query_result->add_command_completion(result.get(), false);
					update_bytes_recv(bytes_recv);
					NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
				}
			}
		} else if (result_type == 2) {
			if (ps_result.id == 'D') {
				unsigned int bytes_recv=query_result->add_row(&ps_result);
				update_bytes_recv(bytes_recv);
				processed_bytes += bytes_recv;	// issue #527 : this variable will store the amount of bytes processed during this event

				bool suspend_resultset_fetch = (processed_bytes > overflow_safe_multiply<8,unsigned int>(pgsql_thread___threshold_resultset_size));

				if (suspend_resultset_fetch == true && myds->sess && myds->sess->qpo && myds->sess->qpo->cache_ttl > 0) {
					suspend_resultset_fetch = (processed_bytes > ((uint64_t)pgsql_thread___query_cache_size_MB) * 1024ULL * 1024ULL);
				}

				if (
					suspend_resultset_fetch
					||
					(pgsql_thread___throttle_ratio_server_to_client && pgsql_thread___throttle_max_bytes_per_second_to_client && (processed_bytes > (unsigned long long)pgsql_thread___throttle_max_bytes_per_second_to_client / 10 * (unsigned long long)pgsql_thread___throttle_ratio_server_to_client))
					) {
					next_event(ASYNC_USE_RESULT_CONT); // we temporarily pause
					break;
				} else {
					NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT); // we continue looping
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
		if (exit_pipeline_mode == false &&
			(query_result->get_result_packet_type() & (PGSQL_QUERY_RESULT_COMMAND | PGSQL_QUERY_RESULT_EMPTY | PGSQL_QUERY_RESULT_ERROR)) == 0) {
			// Issue #6110: normally error_info was set on a previous call. It is not always: a
			// backend can answer a query with NO command outcome at all - a bare
			// ReadyForQuery, without CommandComplete, EmptyQueryResponse or
			// ErrorResponse. That is the backend violating the protocol, not an
			// invariant of ours, so report it to the client rather than aborting the
			// process. Setting error_info here also feeds add_error(NULL) below, which
			// otherwise asserts for the same reason.
			//
			// Two independent consequences follow, one per object:
			//   - the CONNECTION is unhealthy and not reusable, so it is destroyed
			//     rather than pooled or reset. A reset cannot cure a server that
			//     answers incorrectly, and another client must not inherit it.
			//   - the SESSION is closed, because a reply we cannot interpret leaves
			//     us unable to vouch for its protocol state.
			// They are set separately on purpose: neither implies the other.
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

			query_result->add_error(NULL);
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
				NEXT_IMMEDIATE(fetch_result_end_st);
			}

			// An error has occurred while executing extended query sequence,  
			// and connection is not in 'Ready for Query' state, i.e., unsynchronized.  
			// To recover, we must resync by sending a SYNC to the backend connection.
			if (!exit_pipeline_mode && has_error) {
				NEXT_IMMEDIATE(ASYNC_RESYNC_START);
			}
		}

		// finally add ready for query packet
		query_result->add_ready_status(PQtransactionStatus(pgsql_conn));
		update_bytes_recv(6);
		//processing_multi_statement = false;
		NEXT_IMMEDIATE(fetch_result_end_st);
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
			if (native_mode) {
				// Fully flushed synchronously: proceed straight to the native result
				// drain (mirrors ASYNC_QUERY_START). On a fatal send, native_mode leaves
				// error_info set, and ASYNC_STMT_PREPARE_END handles it. The libpq path
				// never lands here (its flush() always leaves READ/WRITE).
				if (is_error_present()) {
					NEXT_IMMEDIATE(ASYNC_STMT_PREPARE_END);
				}
				set_fetch_result_end_state(ASYNC_STMT_PREPARE_END);
				NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
			}
			NEXT_IMMEDIATE(ASYNC_STMT_PREPARE_END);
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
			if (native_mode) {
				if (is_error_present()) {
					NEXT_IMMEDIATE(ASYNC_STMT_DESCRIBE_END);
				}
				set_fetch_result_end_state(ASYNC_STMT_DESCRIBE_END);
				NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
			}
			NEXT_IMMEDIATE(ASYNC_STMT_DESCRIBE_END);
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
		// bind_msg is NULL for a named-portal Close (native_close_only) — it carries no
		// Bind bytes — so guard the bytes-sent accounting (Task P2). EXECUTE and BIND
		// always carry a bind_msg.
		if (query.extended_query_info->bind_msg) {
			update_bytes_sent(query.extended_query_info->bind_msg->get_raw_pkt().size + 5);
		}
		statuses.questions++;
		if (async_exit_status) {
			next_event(ASYNC_STMT_EXECUTE_CONT);
		} else {
			if (native_mode) {
				if (is_error_present()) {
					NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_END);
				}
				set_fetch_result_end_state(ASYNC_STMT_EXECUTE_END);
				NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
			}
			NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_END);
		}
		break;
	case ASYNC_STMT_EXECUTE_CONT:
		if (event) {
			stmt_execute_cont(event);
		}
		if (async_exit_status) {
			next_event(ASYNC_STMT_EXECUTE_CONT);
		} else {
			// set_single_row_mode() is a libpq concept (PQsetSingleRowMode) and asserts
			// pgsql_conn; the native path streams raw DataRow messages, so skip it.
			if (is_error_present() ||
				(!native_mode && !set_single_row_mode())) {
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

		// Native mode keeps pgsql_conn permanently NULL and never uses libpq's
		// notice receiver or pipeline mode, so skip all of the libpq finalization.
		if (!native_mode) {
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
		// should be NULL
		assert(!pgsql_result);
		assert(!is_copy_out);
		break;

	case ASYNC_RESYNC_START:
		if (PQpipelineStatus(pgsql_conn) == PQ_PIPELINE_OFF) {
			proxy_warning("Resync not required - connection already synchronized.\n");
			NEXT_IMMEDIATE(ASYNC_RESYNC_END);
		}
		resync_start();
		update_bytes_sent(5); // SYNC message
		if (async_exit_status) {
			next_event(ASYNC_RESYNC_CONT);
		} else {
			NEXT_IMMEDIATE(ASYNC_RESYNC_END);
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
			if (resync_failed == true) {
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
		PGresult* result = get_result();
		if (result) {
			if (PQresultStatus(result) != PGRES_COMMAND_OK &&
				PQresultStatus(result) != PGRES_PIPELINE_SYNC) {
				set_error_from_result(result, PGSQL_ERROR_FIELD_ALL);
				assert(is_error_present());
			}
			PQclear(result);
			NEXT_IMMEDIATE(ASYNC_RESET_SESSION_CONT);
		}
		if (reset_session_in_pipeline) {
			if (PQexitPipelineMode(pgsql_conn) == 0) {
				set_error_from_PQerrorMessage();
				proxy_error("Failed to exit pipeline mode. %s\n", get_error_code_with_message().c_str());
				NEXT_IMMEDIATE(ASYNC_RESET_SESSION_END);
			}
			reset_session_in_pipeline = false;
			NEXT_IMMEDIATE(ASYNC_RESET_SESSION_START);
		}
		if (reset_session_in_txn) {
			reset_session_in_txn = false;
			NEXT_IMMEDIATE(ASYNC_RESET_SESSION_START);
		}
		NEXT_IMMEDIATE(ASYNC_RESET_SESSION_END);
	}
	break;
	case ASYNC_RESET_SESSION_END:
		PQsetNoticeReceiver(pgsql_conn, &PgSQL_Connection::unhandled_notice_cb, this);
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
		// not implemented yet
		assert(0); 
	}
	return async_state_machine;
}

// libpq/pgcommon base64 (linked via libpgcommon.a) — used to encode the 32-byte SCRAM
// keys into the conninfo string. Does not NUL-terminate; returns the encoded length.
extern "C" int pg_b64_encode(const char *src, int len, char *dst, int dstlen);

static void append_conninfo_param(std::ostringstream& conninfo, const char* key, char* val) {
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

void PgSQL_Connection::connect_start() {
	PROXY_TRACE();
	assert(pgsql_conn == NULL); // already there is a connection
	reset_error();
	async_exit_status = PG_EVENT_NONE;

	if (native_mode) {
		native_connect_start();
		return;
	}

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

void PgSQL_Connection::connect_cont(short event) {
	PROXY_TRACE();
	if (native_mode) {
		// Native (non-libpq) backend connect + auth driver. Drives the
		// native_st sub-state machine and returns to the event loop; it never
		// falls through to the libpq path below (unless a capability gap forces
		// a libpq restart, which is handled inside native_connect_cont()).
		native_connect_cont(event);
		return;
	}
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

// ===========================================================================
// Native (non-libpq) backend connect + authentication (Task 1.6a, PLAINTEXT)
// ===========================================================================
//
// These routines drive a small sub-state machine (native_st) that performs the
// PostgreSQL frontend handshake by hand: a non-blocking TCP connect, a
// StartupMessage, the AuthenticationRequest exchange (trust / cleartext / md5 /
// SCRAM-SHA-256), and then consumes the post-auth messages (ParameterStatus,
// BackendKeyData, ReadyForQuery) so the connection becomes usable in the pool.
//
// Event-loop contract (see handler()/next_event()):
//   - async_exit_status = PG_EVENT_WRITE -> we have bytes to send / want writable
//   - async_exit_status = PG_EVENT_READ  -> waiting for backend bytes
//   - async_exit_status = PG_EVENT_NONE  -> the connect/auth phase is COMPLETE
//
// TLS is NOT handled here (sub-task 1.6b). Backends requiring SSL are assumed
// non-SSL for now; a backend that rejects plaintext will surface as an error.

// Build a one-byte-typed frontend message ('p' PasswordMessage / SASL response)
// into native_outbuf: type byte, int32 big-endian length (= 4 + bodylen), body.
static void pg_append_typed_msg(std::string& out, char type, const unsigned char* body, size_t bodylen) {
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

static inline uint32_t pg_read_be32(const unsigned char* p) {
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

// Flush native_outbuf via non-blocking send(). Consumes the bytes that were
// written; on EAGAIN leaves the remainder buffered and returns true (caller must
// keep waiting for writable). Returns false on a fatal socket error.
// Drain native_ssl_outbuf (pending raw ciphertext) to the fd. On EAGAIN leaves the
// remainder buffered and sets would_block=true. Returns false only on a fatal error.
bool PgSQL_Connection::native_ssl_pump_wbio_to_fd(bool& would_block) {
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

bool PgSQL_Connection::native_flush_outbuf() {
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

// A fatal error during the RESULT phase kills the CONNECTION, not just the query,
// so the socket must be torn down and not merely flagged.
//
// Two kinds of exit reach here and both are unrecoverable for the connection:
//   * CONNECTION_FAILURE -- the peer closed, or a send()/recv() failed outright.
//   * PROTOCOL_VIOLATION -- the byte stream is desynchronised. We no longer know
//     where the next message begins, so nothing can ever be read from it safely
//     again, even though the socket is still technically open.
//
// Without the teardown the object still looks HEALTHY to
// is_connection_in_reusable_state(): `fd` is >= 0, and `native_connected` is still
// true because that flag is only cleared when a NEW connect starts
// (native_connect_start()) and never on breakage -- it means "completed a
// handshake once", not "is alive now". Both halves of that gate's
// `fd == -1 || native_connected == false` test therefore answer "reusable", and
// destroy_MySQL_Connection_From_Pool() re-pools a connection whose peer is gone or
// whose stream is out of sync. The next session to draw it inherits the mess.
//
// The auth and startup phases already do this -- their "backend closed during
// auth" / "during startup" exits call native_teardown() -- the result phase simply
// never did, on any of its exits.
void PgSQL_Connection::native_result_fatal(const char* code, const char* message) {
	set_error(code, message, false);
	native_teardown();
}

void PgSQL_Connection::native_teardown() {
	if (native_scram) {
		pg_scram_free(native_scram);
		native_scram = nullptr;
	}
	if (fd >= 0) {
		::close(fd);
		fd = -1;
	}
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
}

// Defined out-of-line (not in the header) because PgSQL_Data_Stream is an incomplete
// type at the header's accessor declarations. Native TLS reports SSL-in-use once the
// handshake handed the SSL* to myds; the libpq path defers to PQsslInUse().
int PgSQL_Connection::get_pg_ssl_in_use() {
	if (native_mode) return (native_ssl != nullptr) ? 1 : 0;
	return PQsslInUse(pgsql_conn);
}

SSL* PgSQL_Connection::get_pg_ssl_object() {
	if (native_mode) return native_ssl;
	return (SSL*)PQsslStruct(pgsql_conn, "OpenSSL");
}

// Capability gap (GSSAPI/SSPI/SCRAM-SHA-256-PLUS-only/unhandled auth): we cannot
// complete this handshake natively. Tear down the native socket, disable
// native_mode, log once per backend, and restart the connect via libpq by
// re-entering connect_start() (now that native_mode==false it takes the libpq
// branch and builds a fresh pgsql_conn). We then advance the connect/auth state
// machine as if libpq's connect_start() had just run.
void PgSQL_Connection::native_capability_gap(const char* mechanism) {
	static thread_local bool warned = false;
	if (!warned) {
		proxy_warning("native backend auth capability gap (%s) for hg %u %s:%d; falling back to libpq\n",
			mechanism ? mechanism : "unknown", parent->myhgc->hid, parent->address, parent->port);
		warned = true;
	}
	native_teardown();
	native_mode = false;
	// Re-initiate the libpq connect. connect_start() asserts pgsql_conn==NULL,
	// which still holds (native mode never created one). It sets async_exit_status
	// for the libpq path; we mirror handler()'s ASYNC_CONNECT_START dispatch so
	// the next event continues the libpq handshake.
	connect_start();
	if (async_exit_status) {
		async_state_machine = ASYNC_CONNECT_CONT;
	} else {
		async_state_machine = ASYNC_CONNECT_END;
	}
}

void PgSQL_Connection::native_connect_start() {
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

void PgSQL_Connection::native_connect_cont(short event) {
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

bool PgSQL_Connection::native_send_startup() {
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

// Create a per-connection client SSL_CTX (TLS_client_method()) configured from the
// SAME backend SSL param source as the libpq conninfo path: per-server params from
// PgHGM->get_Server_SSL_Params(), with the pgsql_thread___ssl_p2s_* globals as the
// fallback. Sets the verify mode from native_ssl_mode. Stores the ctx in
// native_ssl_ctx and returns it; returns nullptr (with error_info set) on failure.
//
// SECURITY NOTE: ProxySQL's global GloVars.global.ssl_ctx is a TLS_server_method()
// context (src/main.cpp) and MUST NOT be used for the backend client handshake.
SSL_CTX* PgSQL_Connection::native_create_client_ssl_ctx() {
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

// Drive the TLS client handshake over the raw fd using the mem-BIO model. Returns
// 1 = complete, 0 = need more I/O (async_exit_status set, caller returns), -1 = fatal
// (error_info set + teardown done). Non-blocking: WANT_READ/WANT_WRITE map to
// PG_EVENT_READ / PG_EVENT_WRITE. We own the raw recv()/send() here (the data
// stream's read_from_net/write_to_net assume the steady state, not connect).
int PgSQL_Connection::native_drive_ssl_handshake() {
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

bool PgSQL_Connection::native_send_or_buffer(PG_Native_Conn_St resume_st) {
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

int PgSQL_Connection::native_recv_into_framer() {
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
		if (n == 0) {
			return -1; // peer closed
		}
		if (n < 0) {
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
		return got ? 1 : 0;
	}

	// Plaintext path (1.6a).
	unsigned char tmp[16384];
	bool got = false;
	for (;;) {
		ssize_t n = ::recv(fd, tmp, sizeof(tmp), 0);
		if (n > 0) {
			native_framer.feed(tmp, (size_t)n);
			got = true;
			if ((size_t)n < sizeof(tmp)) break; // likely drained the socket buffer
			continue;
		}
		if (n == 0) {
			return -1; // peer closed
		}
		// n < 0
		if (errno == EAGAIN || errno == EWOULDBLOCK) break;
		if (errno == EINTR) continue;
		return -1; // fatal
	}
	return got ? 1 : 0;
}

void PgSQL_Connection::native_fill_error_from_E(const unsigned char* payload, uint32_t len) {
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

void PgSQL_Connection::native_drive_auth(short /*event*/) {
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
			native_st = PG_Native_Conn_St::STARTUP_TAIL;
			// Fall through to consuming any already-buffered tail messages.
			native_drive_startup_tail(0);
			return;

		case 3: { // AuthenticationCleartextPassword
			const char* pw = userinfo->password ? userinfo->password : "";
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
			pg_build_md5(md5buf, user, pw, salt); // "md5"+32hex+NUL (35 chars + NUL)
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
			//   plus-only, !TLS-> capability gap (cbind makes no sense over plaintext)
			//   both,    TLS   -> PLUS  (set cbind below)   <-- the upgrade
			//   both,    !TLS  -> plain
			//   neither        -> capability gap
			const bool tls_in_use = (native_ssl != nullptr);
			bool use_scram_plus = false;
			if (has_scram_plus && tls_in_use) {
				use_scram_plus = true;
			} else if (has_scram_plus && !tls_in_use && !has_scram) {
				native_capability_gap("SCRAM-SHA-256-PLUS only, no TLS");
				return;
			} else if (!has_scram && !has_scram_plus) {
				native_capability_gap("no supported SASL mechanism");
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

			// If using -PLUS, set the cbind input BEFORE building client-first
			// so the gs2 header in client-first is "p=tls-server-end-point,,".
			if (use_scram_plus) {
				unsigned char digest[EVP_MAX_MD_SIZE];
				size_t digest_len = 0;
				if (pg_tls_server_end_point(native_ssl, digest, &digest_len) < 0) {
					// Digest failed: degrade to plain if also offered, else
					// capability gap. Log once via the capability-gap path.
					if (has_scram) {
						use_scram_plus = false;
					} else {
						native_capability_gap("SCRAM-SHA-256-PLUS cert digest failed");
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
			}
			return;
		}

		case 11: { // AuthenticationSASLContinue: server-first message
			if (native_scram == nullptr) {
				set_error(PGSQL_GET_ERROR_CODE_STR(ERRCODE_PROTOCOL_VIOLATION), "unexpected SASLContinue", false);
				native_teardown();
				return;
			}
			// Copy server-first BEFORE building (client_final reads it; no further feed here,
			// but copying keeps us robust against the dangling-pointer rule).
			std::string server_first((const char*)rest, rest_len);
			const char* pw = userinfo->password ? userinfo->password : "";
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
			}
			return;
		}

		case 12: { // AuthenticationSASLFinal: server-final message
			if (native_scram == nullptr) {
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
			// Server verified; an AuthenticationOk ('R',0) normally follows. Keep
			// looping to consume it (it may already be framed).
			break;
		}

		case 2:  // GSSAPI continue
		case 7:  // GSSAPI
		case 8:  // GSSAPI continue
		case 9:  // SSPI
			native_capability_gap("GSSAPI/SSPI");
			return;

		default:
			native_capability_gap("unhandled AuthenticationRequest");
			return;
		}
		// Loop to process further already-buffered messages (e.g. AuthenticationOk
		// after SASLFinal). msg.payload references stay valid until next feed().
	}
}

void PgSQL_Connection::native_drive_startup_tail(short /*event*/) {
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
		case 'S': { // ParameterStatus: two C-strings name, value
			const unsigned char* p = msg.payload;
			uint32_t len = msg.payload_len;
			uint32_t i = 0;
			const char* name = (const char*)p;
			while (i < len && p[i] != 0) i++;
			if (i >= len) break; // malformed; ignore
			std::string nm(name, (const char*)(p + i));
			i++; // skip NUL
			const char* val = (const char*)(p + i);
			uint32_t vstart = i;
			while (i < len && p[i] != 0) i++;
			std::string vl(val, (const char*)(p + i));
			(void)vstart;
			native_params[nm] = vl;
			break;
		}
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
			if (msg.payload_len >= 1) native_txn_status = (char)msg.payload[0];
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

void PgSQL_Connection::query_start() {
	PROXY_TRACE();
	reset_error();
	processing_multi_statement = false;
	async_exit_status = PG_EVENT_NONE;

	if (native_mode) {
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
		// Reset the framer so any stray connect-phase bytes (there should be none
		// after a clean ReadyForQuery) cannot leak into this query's result parse.
		native_framer.reset();
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

	PQsetNoticeReceiver(pgsql_conn, &PgSQL_Connection::notice_handler_cb, this);

	if (PQsendQuery(pgsql_conn, query.ptr) == 0) {
		set_error_from_PQerrorMessage();
		proxy_error("Failed to send query. %s\n", get_error_code_with_message().c_str());
		return;
	}
	flush();
}

void PgSQL_Connection::query_cont(short event) {
	PROXY_TRACE();
	if (native_mode) {
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
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "event=%d\n", event);
	async_exit_status = PG_EVENT_NONE;
	if (event & POLLOUT) {
		flush();
	}
}

void PgSQL_Connection::fetch_result_start() {
	PROXY_TRACE();
	reset_error();
	async_exit_status = PG_EVENT_NONE;
	// result_type and ps_result are per-fetch outputs but have connection lifetime.
	// Left over from a previous fetch they are indistinguishable from a value this
	// one produced, so reset them where the cycle starts.
	result_type = 0;
	ps_result.id = 0;
	ps_result.len = 0;
	ps_result.data = NULL;
}

void PgSQL_Connection::fetch_result_cont(short event) {
	PROXY_TRACE();
	if (native_mode) {
		// Native result fetch is handled directly in the handler()
		// ASYNC_USE_RESULT_CONT case (via native_fetch_result_cont), which never
		// falls through to this libpq routine. Route here defensively so no
		// PQ*/PGresult code ever runs in native mode.
		native_fetch_result_cont(event);
		return;
	}
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

void PgSQL_Connection::native_stmt_send_or_wait() {
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
	if (!native_outbuf.empty() || !native_ssl_outbuf.empty()) {
		async_exit_status = PG_EVENT_WRITE;
	} else {
		async_exit_status = PG_EVENT_NONE;
	}
}

void PgSQL_Connection::native_stmt_flush_cont() {
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

void PgSQL_Connection::native_publish_describe_cache() {
	// Publish the statement-level Describe metadata captured during this DESCRIBE_S
	// step to the global statement's set-once cache. Guards:
	//  - a global stmt_info must be attached to the current query;
	//  - a ParameterDescription 't' must have been seen (empty param → the step
	//    errored before metadata, or this isn't a real statement Describe) AND a
	//    RowDescription/NoData must have terminated it;
	//  - skip the allocation entirely if the cache is already populated.
	// Ownership: publish_describe_cache() frees the candidate if it loses the race.
	const PgSQL_Extended_Query_Info* eqi = query.extended_query_info;
	if (eqi == nullptr || eqi->stmt_info == nullptr) return;
	if (native_describe_param_payload.empty() || !native_describe_have_row) return;
	if (eqi->stmt_info->get_describe_cache() != nullptr) return;

	auto* cand = new PgSQL_Describe_Cache();
	cand->param_desc_payload = native_describe_param_payload;
	cand->no_data = native_describe_no_data;
	if (!native_describe_no_data) {
		cand->row_desc_payload = native_describe_row_payload;
	}
	eqi->stmt_info->publish_describe_cache(cand);
}

void PgSQL_Connection::native_fetch_result_cont(short /*event*/) {
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

	// Drain all complete messages. msg.payload points INTO the framer buffer and
	// is invalidated by the next feed(); we copy each message out (into the result
	// buffer) before looping, and we never feed() again inside this loop, so the
	// dangling-pointer rule is respected.
	for (;;) {
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
						query_result->add_native_backend_message(t, msg.payload, msg.payload_len);
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
					query_result->add_native_backend_message(t, msg.payload, msg.payload_len);
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
						query_result->add_native_backend_message(t, msg.payload, msg.payload_len);
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
					query_result->add_native_backend_message(t, msg.payload, msg.payload_len);
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
					query_result->add_native_backend_message(t, msg.payload, msg.payload_len);
					// A Sync-terminated statement-level Describe streamed its 't'+'T'|'n'
					// through the generic case below and completes here — publish the
					// captured metadata now (no-op if nothing valid was captured).
					if (native_stmt_step == PG_Native_Stmt_Step::DESCRIBE_S) {
						native_publish_describe_cache();
					}
					native_result_complete = true;
					return;
				}

				// Everything else (ParameterDescription 't', RowDescription 'T', NoData
				// 'n', DataRow 'D', CommandComplete 'C', EmptyQueryResponse 'I',
				// ParameterStatus 'S', NoticeResponse 'N', etc.) streams through.
				query_result->add_native_backend_message(t, msg.payload, msg.payload_len);

				// Statement-level Describe metadata capture (set-once cache): copy the
				// backend's raw 't' body and 'T'/'n' state as they stream past, for
				// publication on step completion. Portal Describes ('P') are never cached.
				if (native_stmt_step == PG_Native_Stmt_Step::DESCRIBE_S) {
					if (t == 't') {
						native_describe_param_payload.assign((const char*)msg.payload, msg.payload_len);
					} else if (t == 'T') {
						native_describe_row_payload.assign((const char*)msg.payload, msg.payload_len);
						native_describe_have_row = true;
						native_describe_no_data = false;
					} else if (t == 'n') {
						native_describe_row_payload.clear();
						native_describe_have_row = true;
						native_describe_no_data = true;
					}
				}

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
						if (native_stmt_step == PG_Native_Stmt_Step::DESCRIBE_S) {
							native_publish_describe_cache();
						}
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

			query_result->add_native_backend_message(msg.type, msg.payload, msg.payload_len);
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
		native_result_fatal(PGSQL_GET_ERROR_CODE_STR(ERRCODE_PROTOCOL_VIOLATION), "malformed backend message during result fetch");
		return;
	}
}

void PgSQL_Connection::flush(bool is_resync) {
	int res = PQflush(pgsql_conn);

	if (res > 0) {
		async_exit_status = PG_EVENT_WRITE;
	}
	else if (res == 0) {
		async_exit_status = PG_EVENT_READ;
	}
	else {
		if (!is_resync) {
			set_error_from_PQerrorMessage();
		} else {
			resync_failed = true;
		}
		proxy_error("Failed to flush data to backend. %s\n", get_error_code_with_message().c_str());
		async_exit_status = PG_EVENT_NONE;
	}
}

int PgSQL_Connection::async_connect(short event) {
	PROXY_TRACE();
	if (!native_mode && pgsql_conn == NULL && async_state_machine != ASYNC_CONNECT_START) {
		// In native_mode pgsql_conn is permanently NULL (the native sub-state
		// machine uses its own fd), so this libpq-only invariant must be skipped.
		// LCOV_EXCL_START
		assert(0);
		// LCOV_EXCL_STOP
	}
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
	if (native_mode) {
		// Native handshake completed (ReadyForQuery received) => usable in the pool.
		return native_connected;
	}
	if (pgsql_conn == nullptr || PQstatus(pgsql_conn) != CONNECTION_OK) {
		return false;
	}
	return true;
}

void PgSQL_Connection::compute_unknown_transaction_status() {
	
	if (pgsql_conn) {
		// make sure we have not missed even a single error
		if (is_error_present() == false) {
			unknown_transaction_status = false;
			return;
		}

		// On a broken backend, PQtransactionStatus() returns PQTRANS_UNKNOWN
		// even if a transaction was active — libpq has no cached INTRANS bit
		// equivalent to MySQL's server_status & SERVER_STATUS_IN_TRANS. Force
		// unknown_transaction_status=true so IsActiveTransaction() still
		// reports true and the retry path does not replay inside-tx statements
		// on a fresh connection (which would run them as autocommit).
		if (is_connected() == false) {
			unknown_transaction_status = true;
			return;
		}

		switch (PQtransactionStatus(pgsql_conn)) {
		case PQTRANS_INTRANS:
		case PQTRANS_INERROR:
		case PQTRANS_ACTIVE:
			unknown_transaction_status = true;
			break;
		case PQTRANS_UNKNOWN:
		default:
			//unknown_transaction_status = false;
			break;
		}
	}
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
	if (pgsql_result) {
		PQclear(pgsql_result);
		pgsql_result = NULL;
	}
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
	assert(native_mode || pgsql_conn);

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
			native_bind_only = false;
			native_close_only = false;
			if (type == PGSQL_EXTENDED_QUERY_TYPE_PARSE) {
				async_state_machine = ASYNC_STMT_PREPARE_START;
			} else if (type == PGSQL_EXTENDED_QUERY_TYPE_DESCRIBE) {
				async_state_machine = ASYNC_STMT_DESCRIBE_START;
			} else if (type == PGSQL_EXTENDED_QUERY_TYPE_EXECUTE) {
				async_state_machine = ASYNC_STMT_EXECUTE_START;
			} else if (type == PGSQL_EXTENDED_QUERY_TYPE_BIND) {
				// Named-portal Bind reuses the EXECUTE state chain (CONT/END/return
				// path all handle it unchanged); native_bind_only + native_stmt_step
				// BIND distinguish the wire drive and the drain terminator. Task P1.
				async_state_machine = ASYNC_STMT_EXECUTE_START;
				native_bind_only = true;
			} else if (type == PGSQL_EXTENDED_QUERY_TYPE_CLOSE) {
				// Named-portal Close reuses the EXECUTE state chain the same way BIND
				// does; native_close_only + native_stmt_step CLOSE_P distinguish the
				// wire drive (Close('P', portal) only) and the drain terminator '3'
				// (CloseComplete). Task P2.
				async_state_machine = ASYNC_STMT_EXECUTE_START;
				native_close_only = true;
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
	// In native_mode pgsql_conn is permanently NULL (the native state machine
	// owns the socket and is reset on a different code path). The libpq-only
	// invariant asserted below does not hold for native connections; bail out
	// early with a successful reset rather than crashing the process.
	if (native_mode) {
		async_state_machine = ASYNC_RESET_SESSION_SUCCESSFUL;
		return 0;
	}
	assert(pgsql_conn);

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

// Returns:
// 0 when the ping is completed successfully
// -1 when the ping is completed not successfully
// 1 when the ping is not completed
// -2 on timeout
// the calling function should check pgsql error in pgsql struct
int PgSQL_Connection::async_ping(short event) {
	PROXY_TRACE();
	// In native_mode pgsql_conn is permanently NULL; the libpq ping path is
	// not applicable. Pretend the ping succeeded; the native path keeps its
	// own liveness state via the socket readiness callback.
	if (native_mode) {
		async_state_machine = ASYNC_PING_SUCCESSFUL;
		return 0;
	}
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

bool PgSQL_Connection::IsKnownActiveTransaction() {
	if (native_mode) {
		// Native state machine tracks txn status in `native_txn_status` ('I'/'T'/'E'),
		// the same byte the backend emits in ReadyForQuery. pgsql_conn is null for
		// native connections, so the libpq path below does not apply.
		return native_txn_status == 'T' || native_txn_status == 'E';
	}
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
	// In native mode pgsql_conn is NULL, so PQtransactionStatus() would return
	// PQTRANS_UNKNOWN and wrongly classify a normal query error (backend sent
	// ErrorResponse then ReadyForQuery — connection still idle and reusable) as a
	// broken connection. Derive the transaction status from the last ReadyForQuery
	// byte tracked natively.
	PGTransactionStatusType txn_status;
	if (native_mode) {
		// A connection whose socket is already gone, or that never completed its
		// handshake, can never be reused -- whatever native_txn_status still says.
		//
		// native_teardown() closes the fd and sets it to -1 on every failure path
		// but does not touch native_txn_status, so a connection that died during
		// authentication still reports its initial 'I' here. That mapped to
		// PQTRANS_IDLE and made this function answer "reusable", so
		// destroy_MySQL_Connection_From_Pool() took its reset-and-re-pool branch
		// instead of destroying. The dead object (fd == -1) went back into the
		// pool, and the next session to pick it up aborted the whole process on
		// the `default: assert(0)` in PgSQL_Connection::handler().
		if (fd == -1 || native_connected == false) {
			return false;
		}
		switch (native_txn_status) {
			case 'I': txn_status = PQTRANS_IDLE; break;
			case 'T': txn_status = PQTRANS_INTRANS; break;
			case 'E': txn_status = PQTRANS_INERROR; break;
			default:  txn_status = PQTRANS_UNKNOWN; break;
		}
	} else {
		txn_status = PQtransactionStatus(pgsql_conn);
	}
	bool conn_usable = !(txn_status == PQTRANS_UNKNOWN || txn_status == PQTRANS_ACTIVE);
	assert(!(conn_usable == false && is_error_present() == false));
	return conn_usable;
}

PGresult* PgSQL_Connection::get_result() {
	PGresult* result_tmp = pgsql_result;
	pgsql_result = nullptr;
	return result_tmp;
}

bool PgSQL_Connection::set_single_row_mode() {
	assert(pgsql_conn);
	if (PQsetSingleRowMode(pgsql_conn) == 0) {
		set_error_from_PQerrorMessage();
		proxy_error("Failed to set single row mode. %s\n", get_error_code_with_message().c_str());
		return false;
	}
	return true;
}

void PgSQL_Connection::next_multi_statement_result(PGresult* result) {
	// set unprocessed result to pgsql_result
	pgsql_result = result;
	// copy buffer to PSarrayOut
	query_result->buffer_to_PSarrayOut();
}

void PgSQL_Connection::stmt_prepare_start() {
	PROXY_TRACE();
	reset_error();
	processing_multi_statement = false;
	async_exit_status = PG_EVENT_NONE;

	if (native_mode) {
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

void PgSQL_Connection::stmt_prepare_cont(short event) {
	PROXY_TRACE();
	if (native_mode) {
		native_stmt_flush_cont();
		return;
	}
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "event=%d\n", event);
	async_exit_status = PG_EVENT_NONE;
	if (event & POLLOUT) {
		flush();
	}
}

void PgSQL_Connection::stmt_describe_start() {
	PROXY_TRACE();
	reset_error();
	processing_multi_statement = false;
	async_exit_status = PG_EVENT_NONE;

	if (native_mode) {
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

void PgSQL_Connection::stmt_describe_cont(short event) {
	PROXY_TRACE();
	if (native_mode) {
		native_stmt_flush_cont();
		return;
	}
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "event=%d\n", event);
	async_exit_status = PG_EVENT_NONE;
	if (event & POLLOUT) {
		flush();
	}
}

void PgSQL_Connection::resync_start() {
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

void PgSQL_Connection::resync_cont(short event) {
	PROXY_TRACE();
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "event=%d\n", event);
	async_exit_status = PG_EVENT_NONE;
	if (event & POLLOUT) {
		flush(true);
	}
}

void PgSQL_Connection::stmt_execute_start() {
	PROXY_TRACE();
	reset_error();
	processing_multi_statement = false;
	async_exit_status = PG_EVENT_NONE;

	if (native_mode && native_bind_only) {
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

	if (native_mode && native_close_only) {
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

	if (native_mode &&
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

	if (native_mode) {
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

	// Named-portal Bind is a native-mode-only capability. The session gate keys on the
	// thread flag, but the backend connection assigned by find_or_create_backend may
	// have been established earlier in libpq mode (the flag was flipped with a warm
	// pool) — native_mode is fixed per-connection at creation. The libpq drive cannot
	// express named portals, so surface a clean FEATURE_NOT_SUPPORTED rather than
	// aborting. In a stable native-only deployment every backend conn is native and
	// this branch is never taken; it is a reachable operational edge, NOT a programming
	// error, so it must NOT assert.
	// A named Execute / resume (PORTAL_ALREADY_BOUND) is likewise native-only: its
	// native drive branch above is gated on native_mode, so on a libpq-mode backend
	// connection (flag flipped with a warm pool) it would otherwise fall through to
	// the libpq Bind+Execute path below and silently re-Bind the unnamed portal with
	// the registry's stashed params — wrong semantics. Reject symmetrically with the
	// Bind/Close paths (defensive; unreachable in a stable native-only deployment).
	const bool named_execute_only =
		query.extended_query_info != nullptr &&
		(query.extended_query_info->flags & PGSQL_EXTENDED_QUERY_FLAG_PORTAL_ALREADY_BOUND) != 0;
	if (native_bind_only || native_close_only || named_execute_only) {
		set_error(PGSQL_ERROR_CODES::ERRCODE_FEATURE_NOT_SUPPORTED,
			"named portals require the native backend protocol", false);
		proxy_warning("native named-portal %s dispatched onto a libpq-mode backend connection "
			"(use_native_backend_protocol flipped with a warm pool); rejecting on fd=%d\n",
			native_close_only ? "Close" : (named_execute_only ? "Execute" : "Bind"), fd);
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

void PgSQL_Connection::stmt_execute_cont(short event) {
	PROXY_TRACE();
	if (native_mode) {
		native_stmt_flush_cont();
		return;
	}
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "event=%d\n", event);
	async_exit_status = PG_EVENT_NONE;
	if (event & POLLOUT) {
		flush();
	}
}

void PgSQL_Connection::reset_session_start() {
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

void PgSQL_Connection::reset_session_cont(short event) {
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

char PgSQL_Connection::get_transaction_status_char() {
	char txn_status;
	switch (get_pg_transaction_status()) {
	case PQTRANS_IDLE:
		txn_status = 'I';
		break;
	case PQTRANS_ACTIVE:
	case PQTRANS_INTRANS:
		txn_status = 'T';
		break;
	case PQTRANS_INERROR:
		txn_status = 'E';
		break;
	case PQTRANS_UNKNOWN:
	default:
		txn_status = 'U';
	}
	return txn_status;
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

const char* PgSQL_Connection::get_pg_backend_state() const {
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

bool PgSQL_Connection::handle_copy_out(const PGresult* result, uint64_t* processed_bytes) {

	if (new_result == true) {
		const unsigned int bytes_recv = query_result->add_copy_out_response_start(result);
		update_bytes_recv(bytes_recv);
		new_result = false;
		is_copy_out = true;
	}

	char* buffer = NULL;
	int copy_data_len = 0;

	while ((copy_data_len = PQgetCopyData(pgsql_conn, &buffer, 1)) > 0) {
		const unsigned int bytes_recv = query_result->add_copy_out_row(buffer, copy_data_len);
		update_bytes_recv(bytes_recv);
		PQfreemem(buffer);
		buffer = NULL;
		*processed_bytes += bytes_recv;	// issue #527 : this variable will store the amount of bytes processed during this event
		if (
			(*processed_bytes > (unsigned int)pgsql_thread___threshold_resultset_size * 8)
			||
			(pgsql_thread___throttle_ratio_server_to_client && pgsql_thread___throttle_max_bytes_per_second_to_client && (*processed_bytes > (uint64_t)pgsql_thread___throttle_max_bytes_per_second_to_client / 10 * (uint64_t)pgsql_thread___throttle_ratio_server_to_client))
			) 
		{
			return false;
		}
	}

	if (copy_data_len == -1) {
		const unsigned int bytes_recv = query_result->add_copy_out_response_end();
		update_bytes_recv(bytes_recv);
		is_copy_out = false;
	} else if (copy_data_len < 0) {
		if (is_error_present() == false) {
			set_error_from_PQerrorMessage();
			proxy_error("PQgetCopyData failed. %s\n", get_error_code_with_message().c_str());
		}
		is_copy_out = false;
	}

	return true;
}

void PgSQL_Connection::notice_handler_cb(void* arg, const PGresult* result) {
	assert(arg);
	PgSQL_Connection* conn = (PgSQL_Connection*)arg;
	if (conn->query_result == nullptr) {
		// Notice received without active query_result. This can happen when:
		// - RESET SESSION is in progress (DISCARD ALL or ROLLBACK)
		proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Notice received without active query_result [State: %d, FD: %d]: %s\n",
			(int)conn->async_state_machine,
			conn->get_pg_socket_fd(),
			(result ? PQresultErrorMessage(result) : "unknown notice"));
		return;
	}
	const unsigned int bytes_recv = conn->query_result->add_notice(result);
	conn->update_bytes_recv(bytes_recv);
}

void PgSQL_Connection::unhandled_notice_cb(void* arg, const PGresult* result) {
	assert(arg);
	PgSQL_Connection* conn = (PgSQL_Connection*)arg;
	proxy_error("Unhandled notice: '%s' received from backend [PID: %d] (Host: %s, Port: %d, User: %s, FD: %d, State: %d). Please report this issue for further investigation and enhancements.\n",
		PQresultErrorMessage(result), conn->get_pg_backend_pid(), conn->get_pg_host(), atoi(conn->get_pg_port()), conn->get_pg_user(), conn->get_pg_socket_fd(), (int)conn->async_state_machine);
#ifdef DEBUG
	assert(0);
#endif
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
	assert(native_mode || pgsql_conn);

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
	assert(pgsql_conn);

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
		if (resync_failed) {
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
	exit_pipeline_mode = false;
	resync_failed = false;
#ifdef DEBUG
	if (pgsql_conn)
		assert(PQpipelineStatus(pgsql_conn) == PQ_PIPELINE_OFF);
#endif
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
		STATUS_PGSQL_CONNECTION_NO_MULTIPLEX_HG | STATUS_PGSQL_CONNECTION_HAS_SAVEPOINT 
		/*| STATUS_PGSQL_CONNECTION_HAS_WARNINGS*/ )) {
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

void PgSQL_Connection::set_error_from_PQerrorMessage() {
	const char* raw_msg = PQerrorMessage(pgsql_conn);
	if (raw_msg == nullptr) {
		PgSQL_Error_Helper::fill_error_info(error_info, PGSQL_ERROR_CODES::ERRCODE_INTERNAL_ERROR, "Unknown error",
			PGSQL_ERROR_SEVERITY::ERRSEVERITY_FATAL);
		return;
	}

	std::string org_msg(raw_msg);

	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,
		"Session=%p, Conn=%p, myds=%p. Error message: '%s' received from backend (Host: %s, Port: %d, User: %s, FD: %d)\n",
		myds->sess, this, myds, org_msg.c_str(), parent->address, parent->port, userinfo->username, get_pg_socket_fd());

	const auto error_field_map = parse_pq_error_message(org_msg);

	auto lookup = [&error_field_map](const char* key, std::string_view fallback) -> std::string_view {
		auto it = error_field_map.find(key);
		if (it != error_field_map.end() && !it->second.empty())
			return it->second.back();
		return fallback;
	};

	std::string_view severity = lookup("S", PgSQL_Error_Helper::get_severity(PGSQL_ERROR_SEVERITY::ERRSEVERITY_FATAL));
	std::string_view sqlstate = lookup("C", PgSQL_Error_Helper::get_error_code(PGSQL_ERROR_CODES::ERRCODE_RAISE_EXCEPTION));
	std::string_view primary_msg = lookup("M", "");
	std::string_view lib_errmsg = lookup("LE", "");

	// we are currently distinguishing between server errors and library-generated errors. 
	// A library-generated error is only set when a server error is not available.
	const std::string_view& full_msg = !primary_msg.empty() ? primary_msg : lib_errmsg;
	PgSQL_Error_Helper::fill_error_info(error_info, sqlstate.data(), full_msg.data(), severity.data());
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
	// In native_mode the libpq-allocated startup_parameters / hash arrays are
	// not populated (native state machine keeps the ParameterStatus values
	// directly in native_params). The libpq-only invariant asserted below
	// does not hold; skip the copy.
	if (native_mode) return;

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
	password = strdup(ui->password);
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
