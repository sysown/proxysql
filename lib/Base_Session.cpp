#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "Base_Session.h"

#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"
#include "PgSQL_Data_Stream.h"

#define SELECT_DB_USER "select DATABASE(), USER() limit 1"
#define SELECT_DB_USER_LEN 33
#define SELECT_CHARSET_STATUS "select @@character_set_client, @@character_set_connection, @@character_set_server, @@character_set_database limit 1"
#define SELECT_CHARSET_STATUS_LEN 115

using json = nlohmann::json;

// Explicitly instantiate the required template class and member functions
template void Base_Session<MySQL_Session,MySQL_Data_Stream,MySQL_Backend,MySQL_Thread>::init();
template void Base_Session<PgSQL_Session,PgSQL_Data_Stream,PgSQL_Backend,PgSQL_Thread>::init();

template Base_Session<MySQL_Session,MySQL_Data_Stream,MySQL_Backend,MySQL_Thread>::Base_Session();
template Base_Session<PgSQL_Session,PgSQL_Data_Stream,PgSQL_Backend,PgSQL_Thread>::Base_Session();
template Base_Session<MySQL_Session,MySQL_Data_Stream,MySQL_Backend,MySQL_Thread>::~Base_Session();
template Base_Session<PgSQL_Session,PgSQL_Data_Stream,PgSQL_Backend,PgSQL_Thread>::~Base_Session();

template MySQL_Backend * Base_Session<MySQL_Session,MySQL_Data_Stream,MySQL_Backend,MySQL_Thread>::find_backend(int);
template PgSQL_Backend * Base_Session<PgSQL_Session,PgSQL_Data_Stream,PgSQL_Backend,PgSQL_Thread>::find_backend(int);

template MySQL_Backend * Base_Session<MySQL_Session,MySQL_Data_Stream,MySQL_Backend,MySQL_Thread>::find_or_create_backend(int, MySQL_Data_Stream *);
template PgSQL_Backend * Base_Session<PgSQL_Session,PgSQL_Data_Stream,PgSQL_Backend,PgSQL_Thread>::find_or_create_backend(int, PgSQL_Data_Stream *);

template void Base_Session<MySQL_Session,MySQL_Data_Stream,MySQL_Backend,MySQL_Thread>::writeout();
template void Base_Session<PgSQL_Session,PgSQL_Data_Stream,PgSQL_Backend,PgSQL_Thread>::writeout();

template void Base_Session<MySQL_Session, MySQL_Data_Stream, MySQL_Backend, MySQL_Thread>::return_proxysql_internal(_PtrSize_t*);
template void Base_Session<PgSQL_Session, PgSQL_Data_Stream, PgSQL_Backend, PgSQL_Thread>::return_proxysql_internal(_PtrSize_t*);

template bool Base_Session<MySQL_Session, MySQL_Data_Stream, MySQL_Backend, MySQL_Thread>::has_any_backend();
template bool Base_Session<PgSQL_Session, PgSQL_Data_Stream, PgSQL_Backend, PgSQL_Thread>::has_any_backend();

template void Base_Session<MySQL_Session, MySQL_Data_Stream, MySQL_Backend, MySQL_Thread>::reset_all_backends();
template void Base_Session<PgSQL_Session, PgSQL_Data_Stream, PgSQL_Backend, PgSQL_Thread>::reset_all_backends();

template bool Base_Session<MySQL_Session, MySQL_Data_Stream, MySQL_Backend, MySQL_Thread>::handler_special_queries_STATUS(_PtrSize_t*);
template bool Base_Session<PgSQL_Session, PgSQL_Data_Stream, PgSQL_Backend, PgSQL_Thread>::handler_special_queries_STATUS(_PtrSize_t*);

template void Base_Session<MySQL_Session, MySQL_Data_Stream, MySQL_Backend, MySQL_Thread>::housekeeping_before_pkts();
template void Base_Session<PgSQL_Session, PgSQL_Data_Stream, PgSQL_Backend, PgSQL_Thread>::housekeeping_before_pkts();


template void Base_Session<MySQL_Session, MySQL_Data_Stream, MySQL_Backend, MySQL_Thread>::update_expired_conns(std::vector<std::function<bool (MySQL_Connection*)>, std::allocator<std::function<bool (MySQL_Connection*)> > > const&);
template void Base_Session<PgSQL_Session, PgSQL_Data_Stream, PgSQL_Backend, PgSQL_Thread>::update_expired_conns(std::vector<std::function<bool (PgSQL_Connection*)>, std::allocator<std::function<bool (PgSQL_Connection*)> > > const&);

template unsigned int Base_Session<MySQL_Session, MySQL_Data_Stream, MySQL_Backend, MySQL_Thread>::NumActiveTransactions(bool);
template unsigned int Base_Session<PgSQL_Session, PgSQL_Data_Stream, PgSQL_Backend, PgSQL_Thread>::NumActiveTransactions(bool);

template void Base_Session<MySQL_Session, MySQL_Data_Stream, MySQL_Backend, MySQL_Thread>::set_unhealthy();
template void Base_Session<PgSQL_Session, PgSQL_Data_Stream, PgSQL_Backend, PgSQL_Thread>::set_unhealthy();

template int Base_Session<MySQL_Session, MySQL_Data_Stream, MySQL_Backend, MySQL_Thread>::FindOneActiveTransaction(bool);
template int Base_Session<PgSQL_Session, PgSQL_Data_Stream, PgSQL_Backend, PgSQL_Thread>::FindOneActiveTransaction(bool);

template bool Base_Session<MySQL_Session, MySQL_Data_Stream, MySQL_Backend, MySQL_Thread>::HasOfflineBackends();
template bool Base_Session<PgSQL_Session, PgSQL_Data_Stream, PgSQL_Backend, PgSQL_Thread>::HasOfflineBackends();

template bool Base_Session<MySQL_Session, MySQL_Data_Stream, MySQL_Backend, MySQL_Thread>::SetEventInOfflineBackends();
template bool Base_Session<PgSQL_Session, PgSQL_Data_Stream, PgSQL_Backend, PgSQL_Thread>::SetEventInOfflineBackends();

template<typename S, typename DS, typename B, typename T>
Base_Session<S,DS,B,T>::Base_Session() {
};

template<typename S, typename DS, typename B, typename T>
Base_Session<S,DS,B,T>::~Base_Session() {
};

template<typename S, typename DS, typename B, typename T>
void Base_Session<S,DS,B,T>::init() {
	transaction_persistent_hostgroup = -1;
	transaction_persistent = false;
	mybes = new PtrArray(4);
	// Conditional initialization based on derived class
	if constexpr (std::is_same_v<S, MySQL_Session>) {
		sess_STMTs_meta = new MySQL_STMTs_meta();
		SLDH = new StmtLongDataHandler();
	} else if constexpr (std::is_same_v<S, PgSQL_Session>) {
		sess_STMTs_meta = NULL;
		SLDH = NULL;
	} else {
		assert(0);
	}
};


template<typename S, typename DS, typename B, typename T>
B * Base_Session<S,DS,B,T>::find_backend(int hostgroup_id) {
	B *_mybe;
	unsigned int i;
	for (i=0; i < mybes->len; i++) {
		_mybe=(B *)mybes->index(i);
		if (_mybe->hostgroup_id==hostgroup_id) {
			return _mybe;
		}
	}
	return NULL; // NULL = backend not found
};

/**
 * @brief Create a new MySQL backend associated with the specified hostgroup ID and data stream.
 * 
 * This function creates a new MySQL backend object and associates it with the provided hostgroup ID
 * and data stream. If the data stream is not provided (_myds is nullptr), a new MySQL_Data_Stream
 * object is created and initialized.
 * 
 * @param hostgroup_id The ID of the hostgroup to which the backend belongs.
 * @param _myds The MySQL data stream associated with the backend.
 * @return A pointer to the newly created MySQL_Backend object.
 */
template<typename S, typename DS, typename B, typename T>
B * Base_Session<S,DS,B,T>::create_backend(int hostgroup_id, DS *_myds) {
	B *_mybe = new B();
	proxy_debug(PROXY_DEBUG_NET,4,"HID=%d, _myds=%p, _mybe=%p\n" , hostgroup_id, _myds, _mybe);
	_mybe->hostgroup_id=hostgroup_id;
	if (_myds) {
		_mybe->server_myds=_myds;
	} else {
		_mybe->server_myds = new DS();
		_mybe->server_myds->DSS=STATE_NOT_INITIALIZED;
		_mybe->server_myds->init(MYDS_BACKEND_NOT_CONNECTED, static_cast<S*>(this), 0);
	}
	// the newly created backend is added to the session's list of backends (mybes) and a pointer to it is returned.
	mybes->add(_mybe);
	return _mybe;
};

/**
 * @brief Find or create a MySQL backend associated with the specified hostgroup ID and data stream.
 * 
 * This function first attempts to find an existing MySQL backend associated with the provided
 * hostgroup ID. If a backend is found, its pointer is returned. Otherwise, a new MySQL backend
 * is created and associated with the hostgroup ID and data stream. If the data stream is not provided
 * (_myds is nullptr), a new MySQL_Data_Stream object is created and initialized for the new backend.
 * 
 * @param hostgroup_id The ID of the hostgroup to which the backend belongs.
 * @param _myds The MySQL data stream associated with the backend.
 * @return A pointer to the MySQL_Backend object found or created.
 */
template<typename S, typename DS, typename B, typename T>
B * Base_Session<S,DS,B,T>::find_or_create_backend(int hostgroup_id, DS *_myds) {
	B * _mybe = find_backend(hostgroup_id);
	proxy_debug(PROXY_DEBUG_NET,4,"HID=%d, _myds=%p, _mybe=%p\n" , hostgroup_id, _myds, _mybe);
	// The pointer to the found or newly created backend is returned.
	return ( _mybe ? _mybe : create_backend(hostgroup_id, _myds) );
};

/**
 * @brief Writes data from the session to the network with optional throttling and flow control.
 *
 * The writeout() function in the MySQL_Session class is responsible for writing data from the session to the network.
 * It supports throttling, which limits the rate at which data is sent to the client. Throttling is controlled by the
 * mysql_thread___throttle_max_bytes_per_second_to_client configuration parameter. If throttling is disabled (the parameter
 * is set to 0), the function bypasses throttling.
 *
 * This function first ensures that any pending data in the session's data stream (client_myds) is written to the network.
 * This ensures that the network buffers are emptied, allowing new data to be sent.
 *
 * After writing data to the network, the function checks if flow control is necessary. If the total amount of data written
 * exceeds the maximum allowed per call (mwpl), or if the data is sent too quickly, the function pauses writing for a brief
 * period to control the flow of data.
 *
 * If throttling is enabled, the function adjusts the throttle based on the amount of data written and the configured maximum
 * bytes per second. If the current throughput exceeds the configured limit, the function increases the pause duration to
 * regulate the flow of data.
 *
 * Finally, if the session has a backend associated with it (mybe), and the backend has a server data stream (server_myds),
 * the function also writes data from the server data stream to the network.
 *
 * @note This function assumes that necessary session and network structures are properly initialized.
 *
 * @see mysql_thread___throttle_max_bytes_per_second_to_client
 * @see MySQL_Session::client_myds
 * @see MySQL_Session::mybe
 * @see MySQL_Backend::server_myds
 */

template<typename S, typename DS, typename B, typename T>
void Base_Session<S,DS,B,T>::writeout() {
	int tps = 10; // throttling per second , by default every 100ms
	int total_written = 0;
	unsigned long long last_sent_=0;
	int tmbpstc = 0; // throttle_max_bytes_per_second_to_client
	enum proxysql_session_type _tmp_session_type_cmp1;
	if constexpr (std::is_same_v<S, MySQL_Session>) {
		tmbpstc = mysql_thread___throttle_max_bytes_per_second_to_client;
		_tmp_session_type_cmp1 = PROXYSQL_SESSION_MYSQL;
	} else if constexpr (std::is_same_v<S, PgSQL_Session>) {
		tmbpstc = pgsql_thread___throttle_max_bytes_per_second_to_client;
		_tmp_session_type_cmp1 = PROXYSQL_SESSION_PGSQL;
	} else {
		assert(0);
	}
	bool disable_throttle = tmbpstc == 0;
	int mwpl = tmbpstc; // max writes per call
	mwpl = mwpl/tps;
	// logic to disable throttling

	if (session_type != _tmp_session_type_cmp1) {
		disable_throttle = true;
	}

	if (client_myds) client_myds->array2buffer_full();
	if (mybe && mybe->server_myds && mybe->server_myds->myds_type == MYDS_BACKEND) {
		if (session_type == _tmp_session_type_cmp1) {
			if (mybe->server_myds->net_failure == false) {
				if (mybe->server_myds->poll_fds_idx > -1) { // NOTE: attempt to force writes
					mybe->server_myds->array2buffer_full();
				}
			}
		}
		else {
			mybe->server_myds->array2buffer_full();
		}
	}

	if (client_myds && thread->curtime >= client_myds->pause_until) {
		if (mirror==false) {
			bool runloop=false;
			if (client_myds->mypolls) {
				last_sent_ = client_myds->mypolls->last_sent[client_myds->poll_fds_idx];
			}
			int retbytes=client_myds->write_to_net_poll();
			total_written+=retbytes;
			if (retbytes==QUEUE_T_DEFAULT_SIZE) { // optimization to solve memory bloat
				runloop=true;
			}
			while (runloop && (disable_throttle || total_written < mwpl)) {
				runloop=false; // the default
				client_myds->array2buffer_full();
				struct pollfd fds;
				fds.fd=client_myds->fd;
				fds.events=POLLOUT;
				fds.revents=0;
				int retpoll=poll(&fds, 1, 0);
				if (retpoll>0) {
					if (fds.revents==POLLOUT) {
						retbytes=client_myds->write_to_net_poll();
						total_written+=retbytes;
						if (retbytes==QUEUE_T_DEFAULT_SIZE) { // optimization to solve memory bloat
							runloop=true;
						}
					}
				}
			}
		}
	}

	// flow control
	if (!disable_throttle && total_written > 0) {
		if (total_written > mwpl) {
			unsigned long long add_ = 1000000 / tps + 1000000 / tps * ((unsigned long long)total_written - (unsigned long long)mwpl) / mwpl;
			pause_until = thread->curtime + add_;
			client_myds->remove_pollout();
			client_myds->pause_until = thread->curtime + add_;
		}
		else {
			if (total_written >= QUEUE_T_DEFAULT_SIZE) {
				unsigned long long time_diff = thread->curtime - last_sent_;
				if (time_diff == 0) { // sending data really too fast!
					unsigned long long add_ = 1000000 / tps + 1000000 / tps * ((unsigned long long)total_written - (unsigned long long)mwpl) / mwpl;
					pause_until = thread->curtime + add_;
					client_myds->remove_pollout();
					client_myds->pause_until = thread->curtime + add_;
				}
				else {
					float current_Bps = (float)total_written * 1000 * 1000 / time_diff;
					if (current_Bps > tmbpstc) {
						unsigned long long add_ = 1000000 / tps;
						pause_until = thread->curtime + add_;
						assert(pause_until > thread->curtime);
						client_myds->remove_pollout();
						client_myds->pause_until = thread->curtime + add_;
					}
				}
			}
		}
	}
	if (mybe) {
		if (mybe->server_myds) mybe->server_myds->write_to_net_poll();
	}
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Writeout Session %p\n" , this->thread, this, this); 
}

template<typename S, typename DS, typename B, typename T>
void Base_Session<S, DS, B, T>::return_proxysql_internal(PtrSize_t* pkt) {
	unsigned int l = 0;
	l = strlen((char*)"PROXYSQL INTERNAL SESSION");
	if constexpr (std::is_same_v<S, MySQL_Session>) {
		if (pkt->size == (5 + l) && strncasecmp((char*)"PROXYSQL INTERNAL SESSION", (char*)pkt->ptr + 5, l) == 0) {
			json j;
			generate_proxysql_internal_session_json(j);
			std::string s = j.dump(4, ' ', false, json::error_handler_t::replace);
			SQLite3_result* resultset = new SQLite3_result(1);
			resultset->add_column_definition(SQLITE_TEXT, "session_info");
			char* pta[1];
			pta[0] = (char*)s.c_str();
			resultset->add_row(pta);
			bool deprecate_eof_active = client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
			SQLite3_to_MySQL(resultset, NULL, 0, &client_myds->myprot, false, deprecate_eof_active);
			delete resultset;
			l_free(pkt->size, pkt->ptr);
			return;
		}
		// default
		client_myds->DSS = STATE_QUERY_SENT_NET;
		client_myds->myprot.generate_pkt_ERR(true, NULL, NULL, 1, 1064, (char*)"42000", (char*)"Unknown PROXYSQL INTERNAL command", true);
	}
	else if constexpr (std::is_same_v<S, PgSQL_Session>) {
		if (pkt->size >= (5 + 1 + l) && strncasecmp((char*)"PROXYSQL INTERNAL SESSION", (char*)pkt->ptr + 5, l) == 0) {
			json j;
			generate_proxysql_internal_session_json(j);
			std::string s = j.dump(4, ' ', false, json::error_handler_t::replace);
			SQLite3_result* resultset = new SQLite3_result(1);
			resultset->add_column_definition(SQLITE_TEXT, "session_info");
			char* pta[1];
			pta[0] = (char*)s.c_str();
			resultset->add_row(pta);
			SQLite3_to_Postgres(client_myds->PSarrayOUT, resultset, nullptr, 0, (const char*)pkt->ptr + 5);
			delete resultset;
			l_free(pkt->size, pkt->ptr);
			return;
		}
		client_myds->DSS = STATE_QUERY_SENT_NET;
		client_myds->myprot.generate_error_packet(true, true, "Unknown PROXYSQL INTERNAL command", PGSQL_ERROR_CODES::ERRCODE_SYNTAX_ERROR, false, true);
	}
	else {
		assert(0);
	}
	if (mirror == false) {
		RequestEnd(NULL);
	}
	else {
		client_myds->DSS = STATE_SLEEP;
		status = WAITING_CLIENT_DATA;
	}
	l_free(pkt->size, pkt->ptr);
}

/**
 * @brief Check if any backend has an active MySQL connection.
 *
 * This function iterates through all backends associated with the session and checks if any backend has an
 * active MySQL connection. If any backend has an active connection, it returns true; otherwise, it returns false.
 *
 * @return true if any backend has an active MySQL connection, otherwise false.
 */
template<typename S, typename DS, typename B, typename T>
bool Base_Session<S,DS,B,T>::has_any_backend() {
	for (unsigned int j=0;j < mybes->len;j++) {
		B * tmp_mybe=(B *)mybes->index(j);
		DS *__myds=tmp_mybe->server_myds;
		if (__myds->myconn) {
			return true;
		}
	}
	return false;
}




/**
 * @brief Reset all MySQL backends associated with this session.
 * 
 * This function resets all MySQL backends associated with the current session.
 * It iterates over all backends stored in the session, resets each backend, and then deletes it.
 * 
 */
template<typename S, typename DS, typename B, typename T>
void Base_Session<S,DS,B,T>::reset_all_backends() {
	B *mybe;
	while(mybes->len) {
		mybe=(B *)mybes->remove_index_fast(0);
		mybe->reset();
		delete mybe;
	}
};



/**
 * @brief Handles special queries executed by the STATUS command in mysql cli .
 *   Specifically:
 *   "select DATABASE(), USER() limit 1"
 *   "select @@character_set_client, @@character_set_connection, @@character_set_server, @@character_set_database limit 1"
 *   See Github issues 4396 and 4426
 *
 * @param PtrSize_t The packet from the client
 *
 * @return True if the queries are handled
 *
 * @note even if this function uses templates, perhaps is relevant only for MySQL client and not PostgreSQL
 */
template<typename S, typename DS, typename B, typename T>
bool Base_Session<S,DS,B,T>::handler_special_queries_STATUS(PtrSize_t* pkt) {
	if (pkt->size == (SELECT_DB_USER_LEN + 5)) {
		if (strncasecmp(SELECT_DB_USER, (char*)pkt->ptr + 5, SELECT_DB_USER_LEN) == 0) {
			SQLite3_result* resultset = new SQLite3_result(2);
			resultset->add_column_definition(SQLITE_TEXT, "DATABASE()");
			resultset->add_column_definition(SQLITE_TEXT, "USER()");
			char* pta[2];
			pta[0] = client_myds->myconn->userinfo->username;
			pta[1] = client_myds->myconn->userinfo->schemaname;
			resultset->add_row(pta);
			bool deprecate_eof_active = client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
			SQLite3_to_MySQL(resultset, NULL, 0, &client_myds->myprot, false, deprecate_eof_active);
			delete resultset;
			l_free(pkt->size, pkt->ptr);
			return true;
		}
	}

	if (pkt->size == (SELECT_CHARSET_STATUS_LEN + 5)) {
		if (strncasecmp(SELECT_CHARSET_STATUS, (char*)pkt->ptr + 5, SELECT_CHARSET_STATUS_LEN) == 0) {
			SQLite3_result* resultset = new SQLite3_result(4);
			resultset->add_column_definition(SQLITE_TEXT, "@@character_set_client");
			resultset->add_column_definition(SQLITE_TEXT, "@@character_set_connection");
			resultset->add_column_definition(SQLITE_TEXT, "@@character_set_server");
			resultset->add_column_definition(SQLITE_TEXT, "@@character_set_database");

			// here we do a bit back and forth to and from JSON to reuse existing code instead of writing new code.
			// This is not great for performance, but this query is rarely executed.
			string vals[4];
			json j = {};
			json& jc = j["conn"];
			if constexpr (std::is_same_v<S, MySQL_Session>) {
				MySQL_Connection * conn = client_myds->myconn;
				conn->variables[SQL_CHARACTER_SET_CLIENT].fill_client_internal_session(jc, SQL_CHARACTER_SET_CLIENT);
				conn->variables[SQL_CHARACTER_SET_CONNECTION].fill_client_internal_session(jc, SQL_CHARACTER_SET_CONNECTION);
				conn->variables[SQL_CHARACTER_SET_DATABASE].fill_client_internal_session(jc, SQL_CHARACTER_SET_DATABASE);
			} else if constexpr (std::is_same_v<S, PgSQL_Session>) {
				PgSQL_Connection * conn = client_myds->myconn;
				conn->variables[SQL_CHARACTER_SET_CLIENT].fill_client_internal_session(jc, SQL_CHARACTER_SET_CLIENT);
				conn->variables[SQL_CHARACTER_SET_CONNECTION].fill_client_internal_session(jc, SQL_CHARACTER_SET_CONNECTION);
				conn->variables[SQL_CHARACTER_SET_DATABASE].fill_client_internal_session(jc, SQL_CHARACTER_SET_DATABASE);
			} else {
				assert(0);
			}

			// @@character_set_client
			vals[0] = jc[mysql_tracked_variables[SQL_CHARACTER_SET_CLIENT].internal_variable_name];
			// @@character_set_connection
			vals[1] = jc[mysql_tracked_variables[SQL_CHARACTER_SET_CONNECTION].internal_variable_name];
			// @@character_set_server
			if constexpr (std::is_same_v<S, MySQL_Session>) {
				vals[2] = string(mysql_thread___default_variables[SQL_CHARACTER_SET]);
			} else if constexpr (std::is_same_v<S, PgSQL_Session>) {
				vals[2] = string(mysql_thread___default_variables[SQL_CHARACTER_SET]);
			} else {
				assert(0);
			}
			// @@character_set_database
			vals[3] = jc[mysql_tracked_variables[SQL_CHARACTER_SET_DATABASE].internal_variable_name];

			const char* pta[4];
			for (int i = 0; i < 4; i++) {
				pta[i] = vals[i].c_str();
			}
			resultset->add_row(pta);
			bool deprecate_eof_active = client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
			SQLite3_to_MySQL(resultset, NULL, 0, &client_myds->myprot, false, deprecate_eof_active);
			delete resultset;
			l_free(pkt->size, pkt->ptr);
			return true;
		}
	}
	return false;
}



/**
 * @brief Perform housekeeping tasks before processing packets.
 *
 * This function is responsible for performing necessary housekeeping tasks
 * before processing packets. These tasks include handling expired connections
 * for multiplexing scenarios. If multiplexing is enabled, it iterates over
 * the list of expired backend connections and either returns them to the connection pool
 * or destroys them based on certain conditions.
 *
 * @note This function assumes that the `hgs_expired_conns` vector contains the IDs
 *       of the backend connections that have expired.
 *
 * @return None.
 */
template<typename S, typename DS, typename B, typename T>
void Base_Session<S,DS,B,T>::housekeeping_before_pkts() {
	bool thread___multiplexing = true;
	if constexpr (std::is_same_v<S, MySQL_Session>) {
		thread___multiplexing = mysql_thread___multiplexing;
	} else if constexpr (std::is_same_v<S, PgSQL_Session>) {
		thread___multiplexing = pgsql_thread___multiplexing;
	} else {
		assert(0);
	}
	if (thread___multiplexing) {
		for (const int hg_id : hgs_expired_conns) {
			B * mybe = find_backend(hg_id);

			if (mybe != nullptr) {
				DS * myds = mybe->server_myds;
				// FIXME: NOTE: the logic for autocommit is relevant only for MYSQL
				if (mysql_thread___autocommit_false_not_reusable && myds->myconn->IsAutoCommit()==false) {
					if constexpr (std::is_same_v<S, MySQL_Session>) {
						if (mysql_thread___reset_connection_algorithm == 2) {
							create_new_session_and_reset_connection(myds);
						} else {
							myds->destroy_MySQL_Connection_From_Pool(true);
						}
					} else if constexpr (std::is_same_v<S, PgSQL_Session>) {
						create_new_session_and_reset_connection(myds);
					} else {
						assert(0);
					}
				} else {
					myds->return_MySQL_Connection_To_Pool();
				}
			}
		}
		// We are required to perform a cleanup after consuming the elements, thus preventing any subsequent
		// 'handler' call to perform recomputing of the already processed elements.
		if (hgs_expired_conns.empty() == false) {
			hgs_expired_conns.clear();
		}
	}
}

/**
 * @brief Update expired connections based on specified checks.
 * 
 * This function iterates through the list of backends and their connections
 * to determine if any connections have expired based on the provided checks.
 * If a connection is found to be expired, its hostgroup ID is added to the
 * list of expired connections for further processing.
 * 
 * @param checks A vector of function objects representing checks to determine if a connection has expired.
 */
template<typename S, typename DS, typename B, typename T>
using TypeConn = typename std::conditional<
	std::is_same_v<S, MySQL_Session>, MySQL_Connection, PgSQL_Connection
>::type;

template<typename S, typename DS, typename B, typename T>
void Base_Session<S,DS,B,T>::update_expired_conns(const vector<function<bool(TypeConn *)>>& checks) {
	for (uint32_t i = 0; i < mybes->len; i++) { // iterate through the list of backends 
		B * mybe = static_cast<B *>(mybes->index(i));
		DS * myds = mybe != nullptr ? mybe->server_myds : nullptr;


		TypeConn * myconn = myds != nullptr ? myds->myconn : nullptr;

		//!  it performs a series of checks to determine if it has expired
		if (myconn != nullptr) {
			const bool is_active_transaction = myconn->IsActiveTransaction();
			const bool multiplex_disabled = myconn->MultiplexDisabled(false);
			const bool is_idle = myconn->async_state_machine == ASYNC_IDLE;

			// Make sure the connection is reusable before performing any check
			if (myconn->reusable == true && is_active_transaction == false && multiplex_disabled == false && is_idle) {
				for (const function<bool(TypeConn*)>& check : checks) {
					if (check(myconn)) {
						// If a connection is found to be expired based on the provided checks,
						// its hostgroup ID is added to the list of expired connections (hgs_expired_conns)
						// for further processing.
						this->hgs_expired_conns.push_back(mybe->hostgroup_id);
						break;
					}
				}
			}
		}
	}
}


template<typename S, typename DS, typename B, typename T>
void Base_Session<S,DS,B,T>::set_unhealthy() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess:%p\n", this);
	healthy=0;
}


template<typename S, typename DS, typename B, typename T>
unsigned int Base_Session<S,DS,B,T>::NumActiveTransactions(bool check_savepoint) {
	unsigned int ret=0;
	if (mybes==0) return ret;
	B *_mybe;
	unsigned int i;
	for (i=0; i < mybes->len; i++) {
		_mybe=(B *)mybes->index(i);
		if (_mybe->server_myds) {
			if (_mybe->server_myds->myconn) {
				if (_mybe->server_myds->myconn->IsActiveTransaction()) {
					ret++;
				} else {
					// we use check_savepoint to check if we shouldn't ignore COMMIT or ROLLBACK due
					// to MySQL bug https://bugs.mysql.com/bug.php?id=107875 related to
					// SAVEPOINT and autocommit=0
					if (check_savepoint) {
						if (_mybe->server_myds->myconn->AutocommitFalse_AndSavepoint() == true) {
							ret++;
						}
					}
				}
			}
		}
	}
	return ret;
}

template<typename S, typename DS, typename B, typename T>
bool Base_Session<S,DS,B,T>::HasOfflineBackends() {
	bool ret=false;
	if (mybes==0) return ret;
	B * _mybe;
	unsigned int i;
	for (i=0; i < mybes->len; i++) {
		_mybe=(B *)mybes->index(i);
		if (_mybe->server_myds)
			if (_mybe->server_myds->myconn)
				if (_mybe->server_myds->myconn->IsServerOffline()) {
					ret=true;
					return ret;
				}
	}
	return ret;
}

template<typename S, typename DS, typename B, typename T>
bool Base_Session<S,DS,B,T>::SetEventInOfflineBackends() {
	bool ret=false;
	if (mybes==0) return ret;
	B * _mybe;
	unsigned int i;
	for (i = 0; i < mybes->len; i++) {
		_mybe = (B *) mybes->index(i);
		if (_mybe->server_myds)
			if (_mybe->server_myds->myconn)
				if (_mybe->server_myds->myconn->IsServerOffline()) {
					_mybe->server_myds->revents |= POLLIN;
					ret = true;
				}
	}
	return ret;
}


template<typename S, typename DS, typename B, typename T>
int Base_Session<S,DS,B,T>::FindOneActiveTransaction(bool check_savepoint) {
	int ret=-1;
	if (mybes==0) return ret;
	B * _mybe;
	unsigned int i;
	for (i=0; i < mybes->len; i++) {
		_mybe = (B *) mybes->index(i);
		if (_mybe->server_myds) {
			if (_mybe->server_myds->myconn) {
				if (_mybe->server_myds->myconn->IsKnownActiveTransaction()) {
					return (int)_mybe->server_myds->myconn->parent->myhgc->hid;
				}
				else if (_mybe->server_myds->myconn->IsActiveTransaction()) {
					ret = (int)_mybe->server_myds->myconn->parent->myhgc->hid;
				}
				else {
					// we use check_savepoint to check if we shouldn't ignore COMMIT or ROLLBACK due
					// to MySQL bug https://bugs.mysql.com/bug.php?id=107875 related to
					// SAVEPOINT and autocommit=0
					if (check_savepoint) {
						if (_mybe->server_myds->myconn->AutocommitFalse_AndSavepoint() == true) {
							return (int)_mybe->server_myds->myconn->parent->myhgc->hid;
						}
					}
				}
			}
		}
	}
	return ret;
}
