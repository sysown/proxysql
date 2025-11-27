
#include <fcntl.h>
#include <sstream>
#include <atomic>

#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON
#include "PgSQL_HostGroups_Manager.h"
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
}

PgSQL_Connection_userinfo::~PgSQL_Connection_userinfo() {
	if (username) free(username);
	if (fe_username) free(fe_username);
	if (password) free(password);
	if (sha1_pass) free(sha1_pass);
	if (dbname) free(dbname);
}

uint64_t PgSQL_Connection_userinfo::compute_hash() {
	int l=0;
	if (username)
		l+=strlen(username);
	if (password)
		l+=strlen(password);
	if (dbname)
		l+=strlen(dbname);
// two random seperator
#define _COMPUTE_HASH_DEL1_	"-ujhtgf76y576574fhYTRDF345wdt-"
#define _COMPUTE_HASH_DEL2_	"-8k7jrhtrgJHRgrefgreyhtRFewg6-"
	l+=strlen(_COMPUTE_HASH_DEL1_);
	l+=strlen(_COMPUTE_HASH_DEL2_);
	char *buf=(char *)malloc(l+1);
	l=0;
	if (username) {
		strcpy(buf+l,username);
		l+=strlen(username);
	}
	strcpy(buf+l,_COMPUTE_HASH_DEL1_);
	l+=strlen(_COMPUTE_HASH_DEL1_);
	if (password) {
		strcpy(buf+l,password);
		l+=strlen(password);
	}
	if (dbname) {
		strcpy(buf+l, dbname);
		l+=strlen(dbname);
	}
	strcpy(buf+l,_COMPUTE_HASH_DEL2_);
	l+=strlen(_COMPUTE_HASH_DEL2_);
	hash=SpookyHash::Hash64(buf,l,0);
	free(buf);
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
	local_stmts = new PgSQL_STMTs_local_v14(false); // false by default, it is a backend

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
	if (pgsql_conn == NULL) {
		// it is the first time handler() is being called
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
			proxy_error("Failed to PQconnectStart() on %u:%s:%d , FD (Conn:%d , MyDS:%d) , %s.\n", parent->myhgc->hid, parent->address, parent->port, PQsocket(pgsql_conn), myds->fd, get_error_code_with_message().c_str());
			NEXT_IMMEDIATE(ASYNC_CONNECT_FAILED);
		} else {
			if (PQisnonblocking(pgsql_conn) == false) {
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
		//MySQL_Monitor::update_dns_cache_from_mysql_conn(pgsql);
		break;
	case ASYNC_CONNECT_FAILED:
		//PQfinish(pgsql_conn);//release connection even on error
		//pgsql_conn = NULL;
		PgHGM->p_update_pgsql_error_counter(p_pgsql_error_type::pgsql, parent->myhgc->hid, parent->address, parent->port, 9999 /* TODO: fix this mysql_errno(pgsql) */);
		parent->connect_error(9999 /* TODO: fix this mysql_errno(pgsql)*/);
		break;
	case ASYNC_CONNECT_TIMEOUT:
		// to fix
		//PQfinish(pgsql_conn);//release connection
		//pgsql_conn = NULL;
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
			if (is_error_present() || 
				!set_single_row_mode()) {
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

		fetch_result_cont(event);
		if (async_exit_status) {
			next_event(ASYNC_USE_RESULT_CONT);
			break;
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
			// if we reach here we assume that error_info is already set in previous call
			if (!is_error_present())
				assert(0); // we might have missed setting error_info in previous call

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
		stmt_describe_start();
		if (async_exit_status) {
			next_event(ASYNC_STMT_DESCRIBE_CONT);
		} else {
			NEXT_IMMEDIATE(ASYNC_STMT_DESCRIBE_END);
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
		if (async_exit_status) {
			next_event(ASYNC_STMT_EXECUTE_CONT);
		} else {
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
			if (is_error_present() ||
				!set_single_row_mode()) {
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
		// should be NULL
		assert(!pgsql_result);
		assert(!is_copy_out);
		break;

	case ASYNC_RESYNC_START:
		if (PQpipelineStatus(pgsql_conn) == PQ_PIPELINE_OFF) {
			proxy_warning("Resync not required — connection already synchronized.\n");
			NEXT_IMMEDIATE(ASYNC_RESYNC_END);
		}
		resync_start();
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

static void append_conninfo_param(std::ostringstream& conninfo, const char* key, char* val) {
	if (!val) return;
	char* escaped_str = escape_string_single_quotes_and_backslashes(val, false);
	conninfo << key << "='" << escaped_str << "' ";
	if (escaped_str != val) {
		free(escaped_str);
	}
}

void PgSQL_Connection::connect_start() {
	PROXY_TRACE();
	assert(pgsql_conn == NULL); // already there is a connection
	reset_error();
	async_exit_status = PG_EVENT_NONE;

	std::ostringstream conninfo;
	append_conninfo_param(conninfo, "user", userinfo->username); // username
	append_conninfo_param(conninfo, "password", userinfo->password); // password
	append_conninfo_param(conninfo, "dbname", userinfo->dbname); // dbname
	append_conninfo_param(conninfo, "host", parent->address); // backend address
	conninfo << "port=" << parent->port << " "; // backend port
	conninfo << "application_name=proxysql "; // application name
	//conninfo << "require_auth=" << AUTHENTICATION_METHOD_STR[pgsql_thread___authentication_method]; // authentication method
	if (parent->use_ssl) {
		conninfo << "sslmode='require' "; // SSL required
		append_conninfo_param(conninfo, "sslkey", pgsql_thread___ssl_p2s_key);
		append_conninfo_param(conninfo, "sslcert", pgsql_thread___ssl_p2s_cert);
		append_conninfo_param(conninfo, "sslrootcert", pgsql_thread___ssl_p2s_ca);
		append_conninfo_param(conninfo, "sslcrl", pgsql_thread___ssl_p2s_crl);
		append_conninfo_param(conninfo, "sslcrldir", pgsql_thread___ssl_p2s_crlpath);
		// Only supported in PostgreSQL Server
		// if (pgsql_thread___ssl_p2s_cipher)
		//	  conninfo << "sslcipher=" << pgsql_thread___ssl_p2s_cipher << " ";
	} else {
		conninfo << "sslmode='disable' "; // not supporting SSL
	}

	if (myds && myds->sess && myds->sess->client_myds) {
		// Client Encoding should be always set
		const char* client_charset = pgsql_variables.client_get_value(myds->sess, PGSQL_CLIENT_ENCODING);
		assert(client_charset);
		uint32_t client_charset_hash = pgsql_variables.client_get_hash(myds->sess, PGSQL_CLIENT_ENCODING);
		assert(client_charset_hash);
		const char* escaped_str = escape_string_backslash_spaces(client_charset);
		conninfo << "client_encoding='" << escaped_str << "' ";
		if (escaped_str != client_charset)
			free((char*)escaped_str);

		// charset validation is already done 
		pgsql_variables.server_set_hash_and_value(myds->sess, PGSQL_CLIENT_ENCODING, client_charset, client_charset_hash);

		// optimized way to set client parameters on backend connection when creating a new connection
		conninfo << "options='";
		// excluding client_encoding, which is already set above
		for (int idx = 1; idx < PGSQL_NAME_LAST_LOW_WM; idx++) {
			const char* value = pgsql_variables.client_get_value(myds->sess, idx);
			const char* escaped_str = escape_string_backslash_spaces(value);
			conninfo << "-c " << pgsql_tracked_variables[idx].set_variable_name << "=" << escaped_str << " ";
			if (escaped_str != value)
				free((char*)escaped_str);

			const uint32_t hash = pgsql_variables.client_get_hash(myds->sess, idx);
			pgsql_variables.server_set_hash_and_value(myds->sess, idx, value, hash);
		}

		myds->sess->mybe->server_myds->myconn->copy_pgsql_variables_to_startup_parameters(true);

		// if there are untracked parameters, the session should lock on the host group
		if (myds->sess->untracked_option_parameters.empty() == false) {
			conninfo << myds->sess->untracked_option_parameters;
		}
		conninfo << "'";
		
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

void PgSQL_Connection::query_start() {
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

void PgSQL_Connection::query_cont(short event) {
	PROXY_TRACE();
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
}

void PgSQL_Connection::fetch_result_cont(short event) {
	PROXY_TRACE();
	async_exit_status = PG_EVENT_NONE;

	// Avoid fetching a new result if one is already available. 
	// This situation can happen when a multi-statement query has been executed.
	if (pgsql_result)
		return;
	
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

void PgSQL_Connection::flush() {
	int res = PQflush(pgsql_conn);

	if (res > 0) {
		async_exit_status = PG_EVENT_WRITE;
	}
	else if (res == 0) {
		async_exit_status = PG_EVENT_READ;
	}
	else {
		set_error_from_PQerrorMessage();
		proxy_error("Failed to flush data to backend. %s\n", get_error_code_with_message().c_str());
		async_exit_status = PG_EVENT_NONE;
	}
}

int PgSQL_Connection::async_connect(short event) {
	PROXY_TRACE();
	if (pgsql_conn == NULL && async_state_machine != ASYNC_CONNECT_START) {
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

		/*if (is_connected() == false) {
			unknown_transaction_status = true;
			return;
		}*/

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
	assert(pgsql_conn);

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
			if (type == PGSQL_EXTENDED_QUERY_TYPE_PARSE) {
				async_state_machine = ASYNC_STMT_PREPARE_START;
			} else if (type == PGSQL_EXTENDED_QUERY_TYPE_DESCRIBE) {
				async_state_machine = ASYNC_STMT_DESCRIBE_START;
			} else if (type == PGSQL_EXTENDED_QUERY_TYPE_EXECUTE) {
				async_state_machine = ASYNC_STMT_EXECUTE_START;
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
	bool in_txn = false;
	if (pgsql_conn) {
		// Get the transaction status
		PGTransactionStatusType status = PQtransactionStatus(pgsql_conn);
		if (status == PQTRANS_INTRANS || status == PQTRANS_INERROR) {
			in_txn = true;
		}
	}
	return in_txn;
}

bool PgSQL_Connection::IsActiveTransaction() {
	bool in_txn = false;
	if (pgsql_conn) {

		// Get the transaction status
		PGTransactionStatusType status = PQtransactionStatus(pgsql_conn);

		switch (status) {
		case PQTRANS_INTRANS:
		case PQTRANS_INERROR:
			in_txn = true;
			break;
		case PQTRANS_UNKNOWN:
		case PQTRANS_IDLE:
		case PQTRANS_ACTIVE:
		default:
			in_txn = false;
		}

		if (in_txn == false && is_error_present() && unknown_transaction_status == true) {
			in_txn = true;
		} 
	}
	return in_txn;
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
	PGTransactionStatusType txn_status = PQtransactionStatus(pgsql_conn);
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
		// FIXME: Switch to PQsendPipelineSync once libpq is updated to version 17 or higher
		if (PQpipelineSync(pgsql_conn) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to send pipeline sync. %s\n", get_error_code_with_message().c_str());
			return;
		}
	}
	flush();
}

void PgSQL_Connection::stmt_prepare_cont(short event) {
	PROXY_TRACE();
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
		// FIXME: Switch to PQsendPipelineSync once libpq is updated to version 17 or higher
		if (PQpipelineSync(pgsql_conn) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to send pipeline sync. %s\n", get_error_code_with_message().c_str());
			return;
		}
	}
	flush();
}

void PgSQL_Connection::stmt_describe_cont(short event) {
	PROXY_TRACE();
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

	// FIXME: Switch to PQsendPipelineSync once libpq is updated to version 17 or higher
	if (PQpipelineSync(pgsql_conn) == 0) {
		proxy_error("Failed to send pipeline sync.\n");
		resync_failed = true;
		return;
	}
	async_exit_status = PG_EVENT_WRITE;
}

void PgSQL_Connection::resync_cont(short event) {
	PROXY_TRACE();
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6, "event=%d\n", event);
	async_exit_status = PG_EVENT_NONE;
	if (event & POLLOUT) {
		int res = PQflush(pgsql_conn);

		if (res > 0) {
			async_exit_status = PG_EVENT_WRITE;
		} else if (res == 0) {
			async_exit_status = PG_EVENT_READ;
		} else {
			proxy_error("Failed to flush data to backend.\n");
			async_exit_status = PG_EVENT_NONE;
			resync_failed = true;
		}
	}
}

void PgSQL_Connection::stmt_execute_start() {
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
			param_formats[i] = format;
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

	if (PQsendQueryPrepared(pgsql_conn, query.backend_stmt_name, param_values.size(),
		param_values.data(), param_lengths.data(), param_formats.data(),
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
		// FIXME: Switch to PQsendPipelineSync once libpq is updated to version 17 or higher
		if (PQpipelineSync(pgsql_conn) == 0) {
			set_error_from_PQerrorMessage();
			proxy_error("Failed to send pipeline sync. %s\n", get_error_code_with_message().c_str());
			return;
		}
	}
	flush();
}

void PgSQL_Connection::stmt_execute_cont(short event) {
	PROXY_TRACE();
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

	reset_session_in_pipeline = is_pipeline_active();
	if (reset_session_in_pipeline) {
		// FIXME: Switch to PQsendPipelineSync once libpq is updated to version 17 or higher
		if (PQpipelineSync(pgsql_conn) == 0) {
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
	assert(pgsql_conn);

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
	local_stmts = new PgSQL_STMTs_local_v14(false);

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

PgSQL_Backend_Kill_Args::PgSQL_Backend_Kill_Args(PGconn* conn, const char* user, const char* pass, const char* db, const char* host,
	unsigned int p, unsigned int hid, bool ssl, TYPE typ, PgSQL_Thread* thd) {

	if (typ == TYPE::CANCEL_QUERY)
		cancel_conn = PQgetCancel(conn);
	else {
		cancel_conn = nullptr;
	}
	username = strdup(user);
	password = strdup(pass);
	hostname = strdup(host);
	dbname = strdup(db);
	port = p;
	hostgroup_id = hid;
	type = typ;
	pgsql_thd = thd;
	backend_pid = PQbackendPID(conn);
	ssl_config.use_ssl = ssl;
	if (ssl) {
		ssl_config.sslkey = pgsql_thread___ssl_p2s_key ? strdup(pgsql_thread___ssl_p2s_key) : nullptr;
		ssl_config.sslcert = pgsql_thread___ssl_p2s_cert ? strdup(pgsql_thread___ssl_p2s_cert) : nullptr;
		ssl_config.sslrootcert = pgsql_thread___ssl_p2s_ca ? strdup(pgsql_thread___ssl_p2s_ca) : nullptr;
		ssl_config.sslcrl = pgsql_thread___ssl_p2s_crl ? strdup(pgsql_thread___ssl_p2s_crl) : nullptr;
		ssl_config.sslcrldir = pgsql_thread___ssl_p2s_crlpath ? strdup(pgsql_thread___ssl_p2s_crlpath) : nullptr;
	} else {
		ssl_config.sslkey = nullptr;
		ssl_config.sslcert = nullptr;
		ssl_config.sslrootcert = nullptr;
		ssl_config.sslcrl = nullptr;
		ssl_config.sslcrldir = nullptr;
	}
}

PgSQL_Backend_Kill_Args::~PgSQL_Backend_Kill_Args() {
	free(username);
	free(password);
	free(hostname);
	free(dbname);
	free(ssl_config.sslkey);
	free(ssl_config.sslcert);
	free(ssl_config.sslrootcert);
	free(ssl_config.sslcrl);
	free(ssl_config.sslcrldir);
	if (cancel_conn) 
		PQfreeCancel(cancel_conn);
}

void* PgSQL_backend_kill_thread(void* arg) {
	assert(arg);
	PgSQL_Backend_Kill_Args* backend_kill_args = static_cast<PgSQL_Backend_Kill_Args*>(arg);

	if (backend_kill_args->type == PgSQL_Backend_Kill_Args::TYPE::CANCEL_QUERY) {
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
		append_conninfo_param(conninfo, "password", backend_kill_args->password); // password
		append_conninfo_param(conninfo, "dbname", backend_kill_args->dbname); // dbname
		append_conninfo_param(conninfo, "host", backend_kill_args->hostname); // backend address
		conninfo << "port=" << backend_kill_args->port << " "; // backend port
		conninfo << "application_name=proxysql "; // application name
		
		if (backend_kill_args->ssl_config.use_ssl) {
			conninfo << "sslmode='require' "; // SSL required
			append_conninfo_param(conninfo, "sslkey", backend_kill_args->ssl_config.sslkey);
			append_conninfo_param(conninfo, "sslcert", backend_kill_args->ssl_config.sslcert);
			append_conninfo_param(conninfo, "sslrootcert", backend_kill_args->ssl_config.sslrootcert);
			append_conninfo_param(conninfo, "sslcrl", backend_kill_args->ssl_config.sslcrl);
			append_conninfo_param(conninfo, "sslcrldir", backend_kill_args->ssl_config.sslcrldir);
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


		//proxy_warning("Terminating connection on %s:%d with backend PID %d\n", ka->hostname, ka->port, ka->backend_pid);
	}
__exit:
	delete backend_kill_args;
	return NULL;
}
