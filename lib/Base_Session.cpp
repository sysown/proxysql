#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "Base_Session.h"

#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"
#include "PgSQL_Data_Stream.h"

using json = nlohmann::json;

// Explicitly instantiate the required template class and member functions
template void Base_Session<MySQL_Session,MySQL_Data_Stream,MySQL_Backend,MySQL_Thread>::init();
template void Base_Session<PgSQL_Session,PgSQL_Data_Stream,PgSQL_Backend,PgSQL_Thread>::init();

template Base_Session<MySQL_Session,MySQL_Data_Stream,MySQL_Backend,MySQL_Thread>::Base_Session();
template Base_Session<PgSQL_Session,PgSQL_Data_Stream,PgSQL_Backend,PgSQL_Thread>::Base_Session();
template Base_Session<MySQL_Session,MySQL_Data_Stream,MySQL_Backend,MySQL_Thread>::~Base_Session();
template Base_Session<PgSQL_Session,PgSQL_Data_Stream,PgSQL_Backend,PgSQL_Thread>::~Base_Session();

//template Base_Session<MySQL_Session,MySQL_Data_Stream>::Base_Session();
//emplate Base_Session<PgSQL_Session,PgSQL_Data_Stream>::Base_Session();

//template void Base_Session::init<MySQL_Session>();
//template void Base_Session::init<PgSQL_Session>();

template MySQL_Backend * Base_Session<MySQL_Session,MySQL_Data_Stream,MySQL_Backend,MySQL_Thread>::find_backend(int);
template PgSQL_Backend * Base_Session<PgSQL_Session,PgSQL_Data_Stream,PgSQL_Backend,PgSQL_Thread>::find_backend(int);
/*
template MySQL_Backend * Base_Session::find_backend<MySQL_Backend,MySQL_Session>(int);
template PgSQL_Backend * Base_Session::find_backend<PgSQL_Backend,PgSQL_Session>(int);

template MySQL_Backend * Base_Session::create_backend<MySQL_Backend,MySQL_Session,MySQL_Data_Stream>(int, MySQL_Data_Stream *);
template PgSQL_Backend * Base_Session::create_backend<PgSQL_Backend,PgSQL_Session,PgSQL_Data_Stream>(int, PgSQL_Data_Stream *);
template MySQL_Backend * Base_Session::find_or_create_backend<MySQL_Backend,MySQL_Session,MySQL_Data_Stream>(int, MySQL_Data_Stream *);
template PgSQL_Backend * Base_Session::find_or_create_backend<PgSQL_Backend,PgSQL_Session,PgSQL_Data_Stream>(int, PgSQL_Data_Stream *);
*/
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
	if constexpr (std::is_same<S, MySQL_Session>::value) {
		tmbpstc = mysql_thread___throttle_max_bytes_per_second_to_client;
	} else if constexpr (std::is_same<S, PgSQL_Session>::value) {
		tmbpstc = pgsql_thread___throttle_max_bytes_per_second_to_client;
	} else {
		assert(0);
	}
	bool disable_throttle = tmbpstc == 0;
	int mwpl = tmbpstc; // max writes per call
	mwpl = mwpl/tps;
	// logic to disable throttling
	if constexpr (std::is_same<S, MySQL_Session>::value) {
		if (session_type!=PROXYSQL_SESSION_MYSQL) {
			disable_throttle = true;
		}
	}
	if constexpr (std::is_same<S, PgSQL_Session>::value) {
		if (session_type != PROXYSQL_SESSION_PGSQL) {
			disable_throttle = true;
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

#if 0
void MySQL_Session::writeout() {
	if (client_myds) client_myds->array2buffer_full();
	if (mybe && mybe->server_myds && mybe->server_myds->myds_type==MYDS_BACKEND) {
		if (session_type==PROXYSQL_SESSION_MYSQL) {
			if (mybe->server_myds->net_failure==false) {
				if (mybe->server_myds->poll_fds_idx>-1) { // NOTE: attempt to force writes
					mybe->server_myds->array2buffer_full();
				}
			}
		} else {
			mybe->server_myds->array2buffer_full();
		}
	}


void PgSQL_Session::writeout() {
	if (client_myds) client_myds->array2buffer_full();
	if (mybe && mybe->server_myds && mybe->server_myds->myds_type == MYDS_BACKEND) {
		if (session_type == PROXYSQL_SESSION_PGSQL) {
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
#endif // 0


template<typename S, typename DS, typename B, typename T>
void Base_Session<S,DS,B,T>::return_proxysql_internal(PtrSize_t* pkt) {
	unsigned int l = 0;
	l = strlen((char*)"PROXYSQL INTERNAL SESSION");
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
	if constexpr (std::is_same_v<S, MySQL_Session>) {
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1064,(char *)"42000",(char *)"Unknown PROXYSQL INTERNAL command",true);
	} else if constexpr (std::is_same_v<S, PgSQL_Session>) {
		client_myds->myprot.generate_error_packet(true, true, "Unknown PROXYSQL INTERNAL command", PGSQL_ERROR_CODES::ERRCODE_SYNTAX_ERROR, false, true);
	} else {
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
