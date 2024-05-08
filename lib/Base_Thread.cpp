#include "Base_Thread.h"

#include "cpp.h"

#include <unistd.h>
#include <fcntl.h>
#include "PgSQL_Data_Stream.h"
#include "MySQL_Data_Stream.h"


// Explicitly instantiate the required template class and member functions
template MySQL_Session* Base_Thread::create_new_session_and_client_data_stream<MySQL_Thread, MySQL_Session*>(int);
template PgSQL_Session* Base_Thread::create_new_session_and_client_data_stream<PgSQL_Thread, PgSQL_Session*>(int);
template void Base_Thread::check_timing_out_session<MySQL_Thread>(unsigned int);
template void Base_Thread::check_timing_out_session<PgSQL_Thread>(unsigned int);
template void Base_Thread::check_for_invalid_fd<MySQL_Thread>(unsigned int);
template void Base_Thread::check_for_invalid_fd<PgSQL_Thread>(unsigned int);
template void Base_Thread::ProcessAllSessions_SortingSessions<MySQL_Session>();
template void Base_Thread::ProcessAllSessions_SortingSessions<PgSQL_Session>();
template void Base_Thread::ProcessAllMyDS_AfterPoll<MySQL_Thread>();
template void Base_Thread::ProcessAllMyDS_AfterPoll<PgSQL_Thread>();
template void Base_Thread::read_one_byte_from_pipe<MySQL_Thread>(unsigned int n);
template void Base_Thread::read_one_byte_from_pipe<PgSQL_Thread>(unsigned int n);
template void Base_Thread::tune_timeout_for_myds_needs_pause<MySQL_Thread>(MySQL_Data_Stream *);
template void Base_Thread::tune_timeout_for_myds_needs_pause<PgSQL_Thread>(PgSQL_Data_Stream *);
template void Base_Thread::tune_timeout_for_session_needs_pause<MySQL_Thread>(MySQL_Data_Stream *);
template void Base_Thread::tune_timeout_for_session_needs_pause<PgSQL_Thread>(PgSQL_Data_Stream *);
template void Base_Thread::configure_pollout<MySQL_Thread>(MySQL_Data_Stream *, unsigned int);
template void Base_Thread::configure_pollout<PgSQL_Thread>(PgSQL_Data_Stream *, unsigned int);


Base_Thread::Base_Thread() {
};

Base_Thread::~Base_Thread() {
};

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
	if (up_start)
		_sess->start_time=curtime;
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Registered new session\n", _sess->thread, _sess);
}


template<typename T, typename S>
S Base_Thread::create_new_session_and_client_data_stream(int _fd) {
	int arg_on = 1;
	S sess = NULL;
	if constexpr (std::is_same<T, PgSQL_Thread>::value) {
		sess = new PgSQL_Session();
	} else if constexpr (std::is_same<T, MySQL_Thread>::value) {
		sess = new MySQL_Session();
	} else {
		assert(0);
	}
	register_session(static_cast<T*>(this), sess);
	if constexpr (std::is_same<T, PgSQL_Thread>::value) {
		sess->client_myds = new PgSQL_Data_Stream();
	} else if constexpr (std::is_same<T, MySQL_Thread>::value) {
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
			if (shutdown == 0)
				assert(prevflags != -1);
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

	if (mysql_thread___use_tcp_keepalive) {
		setsockopt(sess->client_myds->fd, SOL_SOCKET, SO_KEEPALIVE, (char*)&arg_on, sizeof(arg_on));
#ifdef TCP_KEEPIDLE
		if (mysql_thread___tcp_keepalive_time > 0) {
			int keepalive_time = mysql_thread___tcp_keepalive_time;
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
	if constexpr (std::is_same<T, PgSQL_Thread>::value) {
		PgSQL_Connection* myconn = new PgSQL_Connection();
		sess->client_myds->attach_connection(myconn);
	} else if constexpr (std::is_same<T, MySQL_Thread>::value) {
		MySQL_Connection* myconn = new MySQL_Connection();
		sess->client_myds->attach_connection(myconn);
	} else {
		assert(0);
	}
	sess->client_myds->myconn->set_is_client(); // this is used for prepared statements
	sess->client_myds->myconn->last_time_used = curtime;
	sess->client_myds->myconn->myds = sess->client_myds; // 20141011
	sess->client_myds->myconn->fd = sess->client_myds->fd; // 20141011

	sess->client_myds->myprot.init(&sess->client_myds, sess->client_myds->myconn->userinfo, sess);

	if constexpr (std::is_same<T, MySQL_Thread>::value) {	
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
	auto * _myds = thr->mypolls.myds[n];
	if (_myds && _myds->sess) {
		if (_myds->wait_until && curtime > _myds->wait_until) {
			// timeout
			_myds->sess->to_process=1;
		} else {
			if (_myds->sess->pause_until && curtime > _myds->sess->pause_until) {
				// timeout
				_myds->sess->to_process=1;
			}
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

// this function was inline in  MySQL_Thread::process_all_sessions()
/**
 * @brief Sort all sessions based on maximum connection time.
 * 
 * This function iterates through all MySQL sessions and sorts them based on their maximum connection time.
 * Sessions with a valid maximum connection time are compared, and if one session has a greater maximum connection
 * time than another, their positions in the session list are swapped. The sorting is performed in-place.
 * 
 * @note This function assumes that MySQL sessions and their associated data structures have been initialized
 * and are accessible within the MySQL Thread.
 */
template<typename S>
void Base_Thread::ProcessAllSessions_SortingSessions() {
	unsigned int a=0;
	for (unsigned int n=0; n<mysql_sessions->len; n++) {
		S *sess=(S *)mysql_sessions->index(n);
		if (sess->mybe && sess->mybe->server_myds) {
			if (sess->mybe->server_myds->max_connect_time) {
				S *sess2=(S *)mysql_sessions->index(a);
				if (sess2->mybe && sess2->mybe->server_myds && sess2->mybe->server_myds->max_connect_time && sess2->mybe->server_myds->max_connect_time <= sess->mybe->server_myds->max_connect_time) {
					// do nothing
				} else {
					void *p=mysql_sessions->pdata[a];
					mysql_sessions->pdata[a]=mysql_sessions->pdata[n];
					mysql_sessions->pdata[n]=p;
					a++;
				}
			}
		}
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
	if (thr->mypolls.poll_timeout==0 || (myds->sess->pause_until - curtime < thr->mypolls.poll_timeout) ) {
		thr->mypolls.poll_timeout= myds->sess->pause_until - curtime;
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Session=%p , poll_timeout=%u , pause_until=%llu , curtime=%llu\n", myds->sess, thr->mypolls.poll_timeout, myds->sess->pause_until, curtime);
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
			if (thr->mypolls.myds[n]->myconn->async_exit_status & MYSQL_WAIT_WRITE)
				thr->mypolls.fds[n].events |= POLLOUT;
		} else {
			myds->set_pollout();
		}
	}
	if (unlikely(myds->sess->pause_until > curtime)) {
		if (myds->myds_type==MYDS_FRONTEND) {
			myds->remove_pollout();
		}
		if (myds->myds_type==MYDS_BACKEND) {
			if (mysql_thread___throttle_ratio_server_to_client) {
				thr->mypolls.fds[n].events = 0;
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
		unsigned int buffered_data=0;
		buffered_data = myds->sess->client_myds->PSarrayOUT->len * RESULTSET_BUFLEN;
		buffered_data += myds->sess->client_myds->resultset->len * RESULTSET_BUFLEN;
		// we pause receiving from backend at mysql_thread___threshold_resultset_size * 8
		// but assuming that client isn't completely blocked, we will stop checking for data
		// only at mysql_thread___threshold_resultset_size * 4
		if (buffered_data > (unsigned int)mysql_thread___threshold_resultset_size*4) {
			thr->mypolls.fds[n].events = 0;
			return true;
		}
	}
	return false;
}

