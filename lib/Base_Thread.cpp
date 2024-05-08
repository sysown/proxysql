#include "Base_Thread.h"

#include "cpp.h"

#include <unistd.h>
#include <fcntl.h>
#include "PgSQL_Data_Stream.h"
#include "MySQL_Data_Stream.h"


// Explicitly instantiate the required template class and member functions
template MySQL_Session* Base_Thread::create_new_session_and_client_data_stream<MySQL_Thread, MySQL_Session*>(int);
template PgSQL_Session* Base_Thread::create_new_session_and_client_data_stream<PgSQL_Thread, PgSQL_Session*>(int);

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
