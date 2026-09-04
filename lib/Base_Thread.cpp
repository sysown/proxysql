#include "Base_Thread.h"

#include "cpp.h"

#include <unistd.h>
#include <fcntl.h>
#include "PgSQL_Data_Stream.h"
#include "MySQL_Data_Stream.h"


// Explicitly instantiate the required template class and member functions
template MySQL_Session* Base_Thread::create_new_session_and_client_data_stream<MySQL_Thread, MySQL_Session*>(int);
template PgSQL_Session* Base_Thread::create_new_session_and_client_data_stream<PgSQL_Thread, PgSQL_Session*>(int);
template void Base_Thread::ProcessAllSessions_Partition<MySQL_Session>();
template void Base_Thread::ProcessAllSessions_Partition<PgSQL_Session>();
template void Base_Thread::ProcessAllMyDS_AfterPoll<MySQL_Thread>();
template void Base_Thread::ProcessAllMyDS_AfterPoll<PgSQL_Thread>();
template void Base_Thread::ProcessAllMyDS_BeforePoll<MySQL_Thread>();
template void Base_Thread::ProcessAllMyDS_BeforePoll<PgSQL_Thread>();
template void Base_Thread::register_session(MySQL_Thread*, MySQL_Session*, bool);
template void Base_Thread::register_session(PgSQL_Thread*, PgSQL_Session*, bool);
template void Base_Thread::run_SetAllSession_ToProcess0<MySQL_Thread, MySQL_Session>();
template void Base_Thread::run_SetAllSession_ToProcess0<PgSQL_Thread, PgSQL_Session>();

Base_Thread::Base_Thread() :
	curtime(0),
	last_move_to_idle_thread_time(0),
	epoll_thread(false),
	shutdown(0),
	mysql_sessions(nullptr)
{
};

Base_Thread::~Base_Thread() {
};

bool Base_Thread::update_partition_gate() {
	// 64-bit so the multiplications below cannot overflow unsigned int.
	const uint64_t attempts = partition_pool_attempts;
	const uint64_t nulls    = partition_pool_nulls;
	partition_pool_attempts = 0;
	partition_pool_nulls    = 0;

	// Low-volume ticks carry no signal; leave gate and streak unchanged.
	if (attempts < PARTITION_GATE_MIN_ATTEMPTS) {
		return partition_active;
	}

	const bool stressed = (nulls * PARTITION_GATE_NULL_RATIO_DEN
	                       >= attempts * PARTITION_GATE_NULL_RATIO_NUM);
	if (stressed == partition_active) {
		partition_streak = 0;
	} else if (++partition_streak >= PARTITION_GATE_STREAK) {
		partition_active = stressed;
		partition_streak = 0;
	}
	return partition_active;
}

template<typename T, typename S>
void Base_Thread::register_session(T thr, S _sess, bool up_start) {
	if (mysql_sessions==NULL) {
		mysql_sessions = new PtrArray();
	}
	mysql_sessions->add(_sess);

	_sess->thread = thr;
//	if (T a = dynamic_cast<T>(thr)) {
//		_sess->thread = a;
//	} else {
//		assert(0);
//	}
	_sess->match_regexes=match_regexes;
	if constexpr (std::is_same_v<T, PgSQL_Thread*>) {
		_sess->copy_cmd_matcher = (static_cast<PgSQL_Thread*>(this))->copy_cmd_matcher;
	}

	if (up_start)
		_sess->start_time=curtime;
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Registered new session\n", _sess->thread, _sess);
}


template<typename T, typename S>
S Base_Thread::create_new_session_and_client_data_stream(int _fd) {
	int arg_on = 1;
	S sess = NULL;
	bool use_tcp_keepalive = false;
	int tcp_keepalive_time = 0;
	if constexpr (std::is_same_v<T, PgSQL_Thread>) {
		sess = new PgSQL_Session();
		use_tcp_keepalive = pgsql_thread___use_tcp_keepalive;
		tcp_keepalive_time = pgsql_thread___tcp_keepalive_time;
	} else if constexpr (std::is_same_v<T, MySQL_Thread>) {
		sess = new MySQL_Session();
		use_tcp_keepalive = mysql_thread___use_tcp_keepalive;
		tcp_keepalive_time = mysql_thread___tcp_keepalive_time;
	} else {
		assert(0);
	}
	register_session(static_cast<T*>(this), sess);
	if constexpr (std::is_same_v<T, PgSQL_Thread>) {
		sess->client_myds = new PgSQL_Data_Stream();
	} else if constexpr (std::is_same_v<T, MySQL_Thread>) {
		sess->client_myds = new MySQL_Data_Stream();
	} else {
		assert(0);
	}
	sess->client_myds->fd = _fd;

	// set not blocking for client connections too!
	{
		// PMC-10004
		// While implementing SSL and fast_forward it was noticed that all frontend connections
		// are in blocking, although this was never a problem because we call poll() before reading.
		// Although it became a problem with fast_forward, SSL and large packets because SSL handled
		// data in chunks of 16KB and there may be data inside SSL even when there is no data
		// received from the network.
		// The only modules that seems to be affected by this issue are Admin, SQLite3 Server
		// and Clickhouse Server
		int prevflags = fcntl(_fd, F_GETFL, 0);
		if (prevflags == -1) {
			proxy_error("For FD %d fcntl() returned -1 errno %d\n", _fd, errno);
			if (
				(shutdown == 0)
				&&
				(glovars.shutdown == 0) // this is specific for modules that do not refresh `shutdown`
			) {
				assert(prevflags != -1);
			}
		}
		int nb = fcntl(_fd, F_SETFL, prevflags | O_NONBLOCK);
		if (nb == -1) {
			proxy_error("For FD %d fcntl() returned -1 , previous flags %d , errno %d\n", _fd, prevflags, errno);
			// previously we were asserting here. But it is possible that this->shutdown is still 0 during the
			// shutdown itself:
			// - the current thread is processing connections
			// - the signal handler thread is still setting shutdown = 0
			//if (shutdown == 0)
			//	assert (nb != -1);
		}
	}
	setsockopt(sess->client_myds->fd, IPPROTO_TCP, TCP_NODELAY, (char*)&arg_on, sizeof(arg_on));

	if (use_tcp_keepalive) {
		setsockopt(sess->client_myds->fd, SOL_SOCKET, SO_KEEPALIVE, (char*)&arg_on, sizeof(arg_on));
#ifdef TCP_KEEPIDLE
		if (tcp_keepalive_time > 0) {
			int keepalive_time = tcp_keepalive_time;
			setsockopt(sess->client_myds->fd, IPPROTO_TCP, TCP_KEEPIDLE, (char*)&keepalive_time, sizeof(keepalive_time));
		}
#endif
	}

#ifdef __APPLE__
	setsockopt(sess->client_myds->fd, SOL_SOCKET, SO_NOSIGPIPE, (char*)&arg_on, sizeof(int));
#endif
	sess->client_myds->init(MYDS_FRONTEND, sess, sess->client_myds->fd);
	proxy_debug(PROXY_DEBUG_NET, 1, "Thread=%p, Session=%p, DataStream=%p -- Created new client Data Stream\n", sess->thread, sess, sess->client_myds);
#ifdef DEBUG
	sess->client_myds->myprot.dump_pkt = true;
#endif
	if constexpr (std::is_same_v<T, PgSQL_Thread>) {
		PgSQL_Connection* myconn = new PgSQL_Connection(true);
		sess->client_myds->attach_connection(myconn);
		sess->client_myds->myconn->set_is_client(); // this is used for prepared statements
	} else if constexpr (std::is_same_v<T, MySQL_Thread>) {
		MySQL_Connection* myconn = new MySQL_Connection();
		sess->client_myds->attach_connection(myconn);
		sess->client_myds->myconn->set_is_client(); // this is used for prepared statements
	} else {
		assert(0);
	}
	sess->client_myds->myconn->last_time_used = curtime;
	sess->client_myds->myconn->myds = sess->client_myds; // 20141011
	sess->client_myds->myconn->fd = sess->client_myds->fd; // 20141011

	sess->client_myds->myprot.init(&sess->client_myds, sess->client_myds->myconn->userinfo, sess);

	if constexpr (std::is_same_v<T, MySQL_Thread>) {	
		uint32_t session_track_gtids_int = SpookyHash::Hash32(mysql_thread___default_session_track_gtids, strlen(mysql_thread___default_session_track_gtids), 10);
		sess->client_myds->myconn->options.session_track_gtids_int = session_track_gtids_int;
		if (sess->client_myds->myconn->options.session_track_gtids) {
			free(sess->client_myds->myconn->options.session_track_gtids);
		}
		sess->client_myds->myconn->options.session_track_gtids = strdup(mysql_thread___default_session_track_gtids);
	}
	return sess;
}


/**
 * @brief Checks for timing out session and marks them for processing.
 * 
 * This function checks for timing out sessions and marks them for processing. Although the logic for managing connection timeout
 * was removed due to the addition of the MariaDB client library, this function remains as a placeholder. It checks if the session
 * has reached its wait_until or pause_until time, and if so, marks the session for processing.
 * 
 * @param n The index of the session in the MySQL_Data_Stream array.
 */
template<typename T>
void Base_Thread::check_timing_out_session(unsigned int n) {
	// FIXME: this logic was removed completely because we added mariadb client library. Yet, we need to implement a way to manage connection timeout
	// check for timeout
	// no events. This section is copied from process_data_on_data_stream()
	T* thr = static_cast<T*>(this);
	auto* _myds = thr->mypolls.myds[n];
	if (!_myds) return;

	auto* _sess = _myds->sess;
	if (!_sess) return;

	// Generic timeout checks (wait_until or pause_until)
	if ((_myds->wait_until && curtime > _myds->wait_until) ||
		(_sess->pause_until && curtime > _sess->pause_until)) {
		_sess->to_process = 1;
	}

	// PostgreSQL-specific cancel query handling
	if constexpr (std::is_same_v<T, PgSQL_Thread>) {
		// If a cancel query is requested and the data stream is a backend, mark the session for processing
		if (_myds->cancel_query && _myds->myds_type == MYDS_BACKEND) {
			_sess->to_process = 1;
		}
	}
}


/**
 * @brief Checks for an invalid file descriptor (FD) and raises an error if found.
 * 
 * This function checks if the file descriptor (FD) at the specified index in the `mypolls.fds` array is invalid (`POLLNVAL`).
 * If an invalid FD is found, it raises an error and asserts to ensure that the program does not proceed with an invalid FD.
 * 
 * @param n The index of the file descriptor in the `mypolls.fds` array.
 */
template<typename T>
void Base_Thread::check_for_invalid_fd(unsigned int n) {
	// check if the FD is valid
	T* thr = static_cast<T*>(this);
	if (thr->mypolls.fds[n].revents==POLLNVAL) {
		// debugging output before assert
		auto *_myds=thr->mypolls.myds[n];
		if (_myds) {
			if (_myds->myconn) {
				proxy_error("revents==POLLNVAL for FD=%d, events=%d, MyDSFD=%d, MyConnFD=%d\n", thr->mypolls.fds[n].fd, thr->mypolls.fds[n].events, _myds->fd, _myds->myconn->fd);
				assert(thr->mypolls.fds[n].revents!=POLLNVAL);
			}
		}
		// if we reached her, we didn't assert() yet
		proxy_error("revents==POLLNVAL for FD=%d, events=%d, MyDSFD=%d\n", thr->mypolls.fds[n].fd, thr->mypolls.fds[n].events, _myds->fd);
		assert(thr->mypolls.fds[n].revents!=POLLNVAL);
	}
}


/**
 * @brief Partition all sessions into three blocks by backend state.
 *
 * Block layout produced in mysql_sessions->pdata:
 *   [0, running_end)         block A - running a query against the backend
 *                            (myconn != NULL, mct == 0, status != WAITING_CLIENT_DATA)
 *   [running_end, idle_begin) block B - acquiring/awaiting a backend
 *                            (mct != 0)
 *   [idle_begin, len)        block C - idle, or holds-conn-but-WAITING_CLIENT_DATA
 *
 * Block A drives the backend and may release its conn at end-of-query, giving
 * block B sessions a fairness chance to acquire it. Sessions parked in
 * WAITING_CLIENT_DATA (idle in a transaction after BEGIN) hold the conn but
 * cannot release it until the client sends the next packet, so they live in C.
 *
 * Classification tests max_connect_time first: it must win over A even when
 * myconn != NULL, to catch CHANGING_USER_SERVER on pooled connections and the
 * post-error retry path where the old conn hasn't been destroyed yet.
 *
 * Single O(n) pass, in place. idx walks up, idle_begin walks down, they meet
 * and terminate. A previous Lomuto-style sort of the B band by max_connect_time
 * was removed: measurement showed it hurt throughput by ~12% at 500 clients /
 * 50-conn pool under SSL, without a corresponding tail-latency benefit. If
 * reintroduced, it should be gated on an explicit starvation-age signal rather
 * than run unconditionally on every iteration.
 */
template<typename S>
void Base_Thread::ProcessAllSessions_Partition() {
	size_t running_end = 0;
	size_t idle_begin = mysql_sessions->len;
	size_t idx = 0;
	size_t oldest_idx = SIZE_MAX;
	unsigned long long oldest_mct = UINT64_MAX;

	while (idx < idle_begin) {
		S* s = static_cast<S*>(mysql_sessions->index(idx));

		const bool has_be = (s->mybe && s->mybe->server_myds);
		const unsigned long long mct = has_be ? s->mybe->server_myds->max_connect_time : 0ULL;
		const bool is_B = (mct != 0);
		const bool is_A = !is_B && has_be && (s->mybe->server_myds->myconn != nullptr) && (s->status != WAITING_CLIENT_DATA);

		if (is_A) {
			if (idx != running_end) {
				// Keep the tracked oldest valid: the B session at running_end is
				// about to be swapped to idx.
				if (oldest_idx == running_end) oldest_idx = idx;
				void* p = mysql_sessions->pdata[idx];
				mysql_sessions->pdata[idx] = mysql_sessions->pdata[running_end];
				mysql_sessions->pdata[running_end] = p;
			}
			++running_end;
			++idx;
		} else if (is_B) {
			// Key on max_connect_time: it was already loaded for the is_B test
			// above, so this is a register compare with no extra memory access.
			// Smallest max_connect_time == earliest connect start == the session
			// closest to the connect_timeout_server_max abort.
			if (mct < oldest_mct) {
				oldest_mct = mct;
				oldest_idx = idx;
			}
			++idx;
		} else {
			--idle_begin;
			if (idx != idle_begin) {
				void* p = mysql_sessions->pdata[idx];
				mysql_sessions->pdata[idx] = mysql_sessions->pdata[idle_begin];
				mysql_sessions->pdata[idle_begin] = p;
			}
			// do NOT advance idx - re-examine the swapped-in element test
		}
	}

	// Promote the longest-waiting B session (smallest max_connect_time) to
	// running_end so the CONNECTING_SERVER pass serves it first. Gated by a
	// minimum B-band size to avoid churn on tiny bands.
	if (idle_begin > running_end + PARTITION_FAIRNESS_MIN_B
	    && oldest_idx != SIZE_MAX && oldest_idx != running_end) {
		void* p = mysql_sessions->pdata[running_end];
		mysql_sessions->pdata[running_end] = mysql_sessions->pdata[oldest_idx];
		mysql_sessions->pdata[oldest_idx] = p;
	}
}

// this function was inline in MySQL_Thread::run()
/**
 * @brief Processes all MySQL Data Streams after polling.
 * 
 * This function iterates through all MySQL polls and processes the associated data streams.
 * For each poll, it prints debug information about the file descriptor and its events.
 * If a MySQL Data Stream is associated with the poll, it checks for events on the file descriptor.
 * If there are no events and a poll timeout is enabled, it checks for sessions timing out.
 * If there are events, it checks for invalid file descriptors and handles new connections 
 * for listener type data streams. For other types of data streams, it processes data and 
 * handles any potential errors.
 */
template<typename T>
void Base_Thread::ProcessAllMyDS_AfterPoll() {
	T* thr = static_cast<T*>(this);
	for (unsigned int n = 0; n < thr->mypolls.len; n++) {
		proxy_debug(PROXY_DEBUG_NET,3, "poll for fd %d events %d revents %d\n", thr->mypolls.fds[n].fd , thr->mypolls.fds[n].events, thr->mypolls.fds[n].revents);

		auto * myds = thr->mypolls.myds[n];
		if (myds==NULL) {
			read_one_byte_from_pipe<T>(n);
			continue;
		}
		if (thr->mypolls.fds[n].revents==0) {
			if (thr->poll_timeout_bool) {
				check_timing_out_session<T>(n);
			}
		} else {
			check_for_invalid_fd<T>(n); // this is designed to assert in case of failure
			switch(myds->myds_type) {
				// Note: this logic that was here was removed completely because we added mariadb client library.
				case MYDS_LISTENER:
					// we got a new connection!
					thr->listener_handle_new_connection(myds,n);
					continue;
					break;
				default:
					break;
			}
			// data on exiting connection
			bool rc = thr->process_data_on_data_stream(myds, n);
			if (rc==false) {
				n--;
			}
		}
	}
}


template<typename T>
void Base_Thread::read_one_byte_from_pipe(unsigned int n) {
	T* thr = static_cast<T*>(this);
	if (thr->mypolls.fds[n].revents) {
		unsigned char c;
		if (read(thr->mypolls.fds[n].fd, &c, 1)==-1) {// read just one byte
			proxy_error("Error during read from signal_all_threads()\n");
		}
		proxy_debug(PROXY_DEBUG_GENERIC,3, "Got signal from admin , done nothing\n");
		//fprintf(stderr,"Got signal from admin , done nothing\n"); // FIXME: this is just the skeleton for issue #253
		if (c) {
			// we are being signaled to sleep for some ms. Before going to sleep we also release the mutex
			pthread_mutex_unlock(&thr->thread_mutex);
			usleep(c*1000);
			pthread_mutex_lock(&thr->thread_mutex);
			// we enter in maintenance loop only if c is set
			// when threads are signaling each other, there is no need to set maintenance_loop
			maintenance_loop=true;
		}
	}
}

template<typename T, typename DS>
void Base_Thread::tune_timeout_for_myds_needs_pause(DS * myds) {
	T* thr = static_cast<T*>(this);
	if (myds->wait_until > curtime) {
		if (thr->mypolls.poll_timeout==0 || (myds->wait_until - curtime < thr->mypolls.poll_timeout) ) {
			thr->mypolls.poll_timeout= myds->wait_until - curtime;
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Session=%p , poll_timeout=%u , wait_until=%llu , curtime=%llu\n", myds->sess, thr->mypolls.poll_timeout, myds->wait_until, curtime);
		}
	}
}

template<typename T, typename DS>
void Base_Thread::tune_timeout_for_session_needs_pause(DS * myds) {
	T* thr = static_cast<T*>(this);

	// Only adjust poll_timeout if the pause is still in the future. If pause_until
	// is stale (already <= curtime), computing (pause_until - curtime) as unsigned
	// would underflow to ~1.8e19 and corrupt poll_timeout, making poll() fall back
	// to the default timeout (~2s) and stalling the worker thread. The stale-pause
	// case is handled by check_timing_out_session (AfterPoll) and the handler-entry
	// pause checks, so doing nothing here is correct.
	if (myds->sess->pause_until > curtime) {
		if (thr->mypolls.poll_timeout == 0 || (myds->sess->pause_until - curtime < thr->mypolls.poll_timeout)) {
			thr->mypolls.poll_timeout = myds->sess->pause_until - curtime;
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Session=%p , poll_timeout=%u , pause_until=%llu , curtime=%llu\n", myds->sess, thr->mypolls.poll_timeout,
				myds->sess->pause_until, curtime);
		}
	}
}

template<typename T, typename DS>
void Base_Thread::configure_pollout(DS * myds, unsigned int n) {
	T* thr = static_cast<T*>(this);
	if (myds->myds_type==MYDS_FRONTEND && myds->DSS==STATE_SLEEP && myds->sess && myds->sess->status==WAITING_CLIENT_DATA) {
		myds->set_pollout();
	} else {
		if (myds->DSS > STATE_MARIADB_BEGIN && myds->DSS < STATE_MARIADB_END) {
			thr->mypolls.fds[n].events = POLLIN;
			if constexpr (std::is_same_v<T, PgSQL_Thread>) {
				if (thr->mypolls.myds[n]->myconn->async_exit_status & PG_EVENT_WRITE)
					thr->mypolls.fds[n].events |= POLLOUT;
			} else if constexpr (std::is_same_v<T, MySQL_Thread>) {
				if (thr->mypolls.myds[n]->myconn->async_exit_status & MYSQL_WAIT_WRITE)
					thr->mypolls.fds[n].events |= POLLOUT;
			}
		} else {
			myds->set_pollout();
		}
	}
	if (unlikely(myds->sess->pause_until > curtime)) {
		if (myds->myds_type==MYDS_FRONTEND) {
			myds->remove_pollout();
		}
		if (myds->myds_type==MYDS_BACKEND) {
			if constexpr (std::is_same_v<T, PgSQL_Thread>) {
				if (pgsql_thread___throttle_ratio_server_to_client) {
					thr->mypolls.fds[n].events = 0;
				}
			} else if constexpr (std::is_same_v<T, MySQL_Thread>) {
				if (mysql_thread___throttle_ratio_server_to_client) {
					thr->mypolls.fds[n].events = 0;
				}
			} else {
				assert(0);
			}
		}
	}
	if (myds->myds_type==MYDS_BACKEND) {
		set_backend_to_be_skipped_if_frontend_is_slow<T>(myds, n);
	}
}

template<typename T, typename DS>
bool Base_Thread::set_backend_to_be_skipped_if_frontend_is_slow(DS * myds, unsigned int n) {
	T* thr = static_cast<T*>(this);
	if (myds->sess && myds->sess->client_myds && myds->sess->mirror==false) {
		// we pause receiving from backend at mysql_thread___threshold_resultset_size * 8
		// but assuming that client isn't completely blocked, we will stop checking for data
		// only at mysql_thread___threshold_resultset_size * 4
		if constexpr (std::is_same_v<T, PgSQL_Thread>) {
			const unsigned int buffered_data = myds->sess->client_myds->PSarrayOUT->len * PGSQL_RESULTSET_BUFLEN;
			if (buffered_data > overflow_safe_multiply<4,unsigned int>(pgsql_thread___threshold_resultset_size)) {
				thr->mypolls.fds[n].events = 0;
				return true;
			}
		} else if constexpr (std::is_same_v<T, MySQL_Thread>) {
			unsigned int buffered_data = 0;
			buffered_data = myds->sess->client_myds->PSarrayOUT->len * RESULTSET_BUFLEN;
			buffered_data += myds->sess->client_myds->resultset->len * RESULTSET_BUFLEN;
			if (buffered_data > overflow_safe_multiply<4,unsigned int>(mysql_thread___threshold_resultset_size)) {
				thr->mypolls.fds[n].events = 0;
				return true;
			}
		}
		else {
			assert(0);
		}
		
	}
	return false;
}

#ifdef IDLE_THREADS
/**
 * @brief Moves a session to the idle session array if it meets the idle criteria.
 * 
 * This function checks if a session should be moved to the idle session array based on its idle time
 * and other conditions. If the session meets the idle criteria, it is moved to the idle session array.
 * 
 * @param myds Pointer to the MySQL data stream associated with the session.
 * @param n The index of the session in the poll array.
 * @return True if the session is moved to the idle session array, false otherwise.
 */
template<typename T, typename DS>
bool Base_Thread::move_session_to_idle_mysql_sessions(DS * myds, unsigned int n) {
	T* thr = static_cast<T*>(this);
	unsigned long long _tmp_idle = thr->mypolls.last_recv[n] > thr->mypolls.last_sent[n] ? thr->mypolls.last_recv[n] : thr->mypolls.last_sent[n] ;

	int session_idle_ms = 0;

	if constexpr (std::is_same_v<T, PgSQL_Thread>) {
		session_idle_ms = pgsql_thread___session_idle_ms;
	} else if constexpr (std::is_same_v<T, MySQL_Thread>) {
		session_idle_ms = mysql_thread___session_idle_ms;
	} else {
		assert(0);
	}

	if (_tmp_idle < ( (curtime > (unsigned int)session_idle_ms * 1000) ? (curtime - session_idle_ms * 1000) : 0)) {
		// make sure data stream has no pending data out and session is not throttled (#1939)
		// because epoll thread does not handle data stream with data out
		if (myds->sess->client_myds == myds && !myds->available_data_out() && myds->sess->pause_until <= curtime) {
			//unsigned int j;
			bool has_backends = myds->sess->has_any_backend();
			if (has_backends==false) {
				unsigned long long idle_since = curtime - myds->sess->IdleTime();
				thr->mypolls.remove_index_fast(n);
				myds->mypolls=NULL;
				unsigned int i = find_session_idx_in_mysql_sessions<T>(myds->sess);
				myds->sess->thread=NULL;
				thr->unregister_session(i);
				myds->sess->idle_since = idle_since;
				thr->idle_mysql_sessions->add(myds->sess);
				return true;
			}
		}
	}
	return false;
}
#endif // IDLE_THREADS

template<typename T, typename S>
unsigned int Base_Thread::find_session_idx_in_mysql_sessions(S * sess) {
	T* thr = static_cast<T*>(this);
	unsigned int i=0;
	for (i=0;i<mysql_sessions->len;i++) {
		S *mysess=(S *)thr->mysql_sessions->index(i);
		if (mysess==sess) {
			return i;
		}
	}
	return i;
}

template<typename T>
void Base_Thread::ProcessAllMyDS_BeforePoll() {
	T* thr = static_cast<T*>(this);
	bool check_if_move_to_idle_thread = false;
#ifdef IDLE_THREADS
	if (GloVars.global.idle_threads) {

		int session_idle_ms = 0;

		if constexpr (std::is_same_v<T, PgSQL_Thread>) {
			session_idle_ms = pgsql_thread___session_idle_ms;
		} else if constexpr (std::is_same_v<T, MySQL_Thread>) {
			session_idle_ms = mysql_thread___session_idle_ms;
		} else {
			assert(0);
		}

		if (curtime > last_move_to_idle_thread_time + (unsigned long long)session_idle_ms * 1000) {
			last_move_to_idle_thread_time=curtime;
			check_if_move_to_idle_thread=true;
		}
	}
#endif
	for (unsigned int n = 0; n < thr->mypolls.len; n++) {
		auto * myds=thr->mypolls.myds[n];
		thr->mypolls.fds[n].revents=0;
		if (myds) {
#ifdef IDLE_THREADS
			if (check_if_move_to_idle_thread == true) {
				// here we try to move it to the maintenance thread
				if (myds->myds_type==MYDS_FRONTEND && myds->sess) {
					if (myds->DSS==STATE_SLEEP && myds->sess->status==WAITING_CLIENT_DATA) {
						if (move_session_to_idle_mysql_sessions<T>(myds, n)) {
							n--;  // compensate mypolls.remove_index_fast(n) and n++ of loop
							continue;
						}
					}
				}
			}
#endif // IDLE_THREADS
			if (unlikely(myds->wait_until)) {
				tune_timeout_for_myds_needs_pause<T>(myds);
			}
			if (myds->sess) {
				if (unlikely(myds->sess->pause_until > 0)) {
					tune_timeout_for_session_needs_pause<T>(myds);
				}
			}
			if constexpr (std::is_same_v<T, PgSQL_Thread>) {
				// If there is a pending cancel_query request, we want poll() to return 
				// immediatly and process the cancel request. For long-running queries (e.g., pg_sleep), 
				// no data is sent to ProxySQL until the query completes, so poll() would only return 
				// after the timeout expires. To avoid this delay, we set poll_timeout to 1ms (later this will be set to 0)
				// so poll() wakes up promptly and the cancel request can be processed immediately. 
				if (myds->cancel_query && myds->myds_type == MYDS_BACKEND) {
					thr->mypolls.poll_timeout = 1; // we want to wake up immediately
				}
			}
			myds->revents=0;
			if (myds->myds_type!=MYDS_LISTENER) {
				configure_pollout<T>(myds, n);
			}
		}
		proxy_debug(PROXY_DEBUG_NET,1,"Poll for DataStream=%p will be called with FD=%d and events=%d\n", thr->mypolls.myds[n], thr->mypolls.fds[n].fd, thr->mypolls.fds[n].events);
	}
}

template<typename T, typename S>
void Base_Thread::run_SetAllSession_ToProcess0() {
	T* __attribute__((unused)) thr = static_cast<T*>(this);
	unsigned int n;
#ifdef IDLE_THREADS
	// @note: in MySQL_Thread::run we have:  bool idle_maintenance_thread=epoll_thread;
	// Thus idle_maintenance_thread and epoll_thread are equivalent.
	if (epoll_thread==false) {
#endif // IDLE_THREADS
		for (n=0; n<mysql_sessions->len; n++) {
			S *_sess=(S *)mysql_sessions->index(n);
			_sess->to_process=0;
		}
#ifdef IDLE_THREADS
	}
#endif // IDLE_THREADS
}
