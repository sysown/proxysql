#define __CLASS_STANDARD_MYSQL_THREAD_H
#define MYSQL_THREAD_IMPLEMENTATION
#include "proxysql.h"
#include "cpp.h"

extern Query_Processor *GloQPro;
extern Standard_MySQL_Threads_Handler *GloMTH;

//class Standard_MySQL_Thread;


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
//void mypoll_add(proxy_poll_t *, uint32_t, int, MySQL_Data_Stream *);
//void __mypoll_add(proxy_poll_t *, struct pollfd *, MySQL_Data_Stream *); 
//int mypoll_del(proxy_poll_t *_myp, int i);
#ifdef __cplusplus
}
#endif /* __cplusplus */


#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define MYSQL_THREAD_VERSION "0.1.1114" DEB


#define DEFAULT_NUM_THREADS	4
#define DEFAULT_STACK_SIZE	1024*1024

#define SESSIONS_FOR_CONNECTIONS_HANDLER	64


/*
#define MIN_POLL_LEN 8
#define MIN_POLL_DELETE_RATIO  8



static unsigned int near_pow_2 (unsigned int n) {
  unsigned int i = 1;
  while (i < n) i <<= 1;
  return i ? i : n;
}
*/

// this structure tries to emulate epoll()
/*
class ProxySQL_Poll {

	private:
	void shrink() {
		unsigned int new_size=near_pow_2(len+1);
		fds=(struct pollfd *)realloc(fds,new_size*sizeof(struct pollfd));
		myds=(MySQL_Data_Stream **)realloc(myds,new_size*sizeof(MySQL_Data_Stream *));
//		status=(unsigned char *)realloc(status,new_size*sizeof(unsigned char));
		size=new_size;
	};
	void expand(unsigned int more) {
		if ( (len+more) > size ) {
			unsigned int new_size=near_pow_2(len+more);
			fds=(struct pollfd *)realloc(fds,new_size*sizeof(struct pollfd));
			myds=(MySQL_Data_Stream **)realloc(myds,new_size*sizeof(MySQL_Data_Stream *));
//			status=(unsigned char *)realloc(status,new_size*sizeof(unsigned char));
			size=new_size;
		}
	};

	public:
	unsigned int len=0;
	unsigned int size=0;
	struct pollfd *fds=NULL;
	MySQL_Data_Stream **myds=NULL;
//	unsigned char *status=NULL;   // this should be moved within the Data Stream
	ProxySQL_Poll() {
		size=MIN_POLL_LEN;
		// preallocate MIN_POLL_LEN slots
		fds=(struct pollfd *)malloc(size*sizeof(struct pollfd));
		myds=(MySQL_Data_Stream **)malloc(size*sizeof(MySQL_Data_Stream *));
		//status=(unsigned char *)malloc(size*sizeof(unsigned char));
	};

	~ProxySQL_Poll() {
		unsigned int i;
		for (i=0;i<len;i++) {
			if (myds[i]->myds_type==MYDS_LISTENER) {
				delete myds[i];
			}
		}
		free(myds);
		free(fds);
	};



	void add(uint32_t _events, int _fd, MySQL_Data_Stream *_myds) {
		if (len==size) {
			expand(1);
		}
		myds[len]=_myds;
		fds[len].fd=_fd;
		fds[len].events=_events;
		fds[len].revents=0;
		len++;
	};

	void remove_index_fast(unsigned int i) {
		if (i != (len-1)) {
			myds[i]=myds[len-1];
			fds[i].fd=fds[len-1].fd;
			fds[i].events=fds[len-1].events;
			fds[i].revents=fds[len-1].revents;
			//status[i]=status[len-1];
		}
		len--;
		if ( ( len>MIN_POLL_LEN ) && ( size > len*MIN_POLL_DELETE_RATIO ) ) {
			shrink();
		}
	};	
};

*/


/*
void mypoll_add(proxy_poll_t *_myp, uint32_t _events, int _fd, MySQL_Data_Stream *_myds) {
	struct pollfd _pollfd;
	_pollfd.revents=0;
	_pollfd.events=_events;
	_pollfd.fd=_fd;
	__mypoll_add(_myp, &_pollfd, _myds);
}

void __mypoll_add(proxy_poll_t *_myp, struct pollfd *_fd, MySQL_Data_Stream *_myds) {
	proxy_debug(PROXY_DEBUG_NET,1,"Session=%p, DataStream=%p -- Adding MySQL Data Stream %p for FD %d\n", _myds->sess, _myds, _myds, _fd->fd);
	if (_myp->nfds==_myp->max_nfds) {  // no space left, expand
		_myp->max_nfds+=MIN_POLL_FDS_PER_THREAD;
		struct pollfd *fds_tmp=(struct pollfd *)malloc(sizeof(struct pollfd)*_myp->max_nfds);
		assert(fds_tmp);
		MySQL_Data_Stream **myds_tmp=(MySQL_Data_Stream **)malloc(sizeof(MySQL_Data_Stream *)*_myp->max_nfds);
		assert(myds_tmp);
		memcpy(fds_tmp,_myp->fds,sizeof(struct pollfd)*_myp->nfds);
		memcpy(myds_tmp,_myp->myds,sizeof(MySQL_Data_Stream *)*_myp->nfds);
		free(_myp->fds);
		free(_myp->myds);
		_myp->fds=fds_tmp;
		_myp->myds=myds_tmp;
	}

//	memcpy(&(_myp->fds[_myp->nfds]),&_fd,sizeof(struct pollfd));
	_myp->fds[_myp->nfds].events=_fd->events;
	_myp->fds[_myp->nfds].revents=_fd->revents;
	_myp->fds[_myp->nfds].fd=_fd->fd;

	_myp->myds[_myp->nfds]=_myds;
	_myds->poll_fds_idx=_myp->nfds;	// pointer back
	_myp->nfds+=1;
}

// return if data was moved or not
int mypoll_del(proxy_poll_t *_myp, int i) {
	if (i >= _myp->nfds) return 0;
	if (i < _myp->nfds-1) {
		_myp->nfds--;
		memcpy(&_myp->fds[i],&_myp->fds[_myp->nfds],sizeof(struct pollfd));
		_myp->myds[i]=_myp->myds[_myp->nfds];
		_myp->myds[i]->poll_fds_idx=i;
		return 1;
	}
	_myp->nfds--;
	return 0;
}
*/

__thread MySQL_Connection_Pool *MyConnPool;


__thread unsigned int __thread_MySQL_Thread_Variables_version;

volatile static unsigned int __global_MySQL_Thread_Variables_version;



static char * mysql_thread_variables_names[]= {
	(char *)"connect_timeout_server",
	(char *)"connect_timeout_server_error",
	(char *)"default_schema",
	(char *)"poll_timeout",
	(char *)"server_capabilities",
	(char *)"server_version",
	(char *)"servers_stats",
	(char *)"session_debug",
	(char *)"stacksize",
	(char *)"threads",
	NULL
};


/*
class Standard_MySQL_Threads_Handler: public MySQL_Threads_Handler
{
	private:
	size_t stacksize;
	pthread_attr_t attr;
	rwlock_t rwlock;
	struct {
		char *default_schema;
		char *server_version;
		bool servers_stats;
#ifdef DEBUG
		bool session_debug;
#endif
		uint16_t server_capabilities;
		int poll_timeout;
	} variables;
	public:
	Standard_MySQL_Threads_Handler();
	virtual ~Standard_MySQL_Threads_Handler();
	virtual SQLite3_result * SQL3_Threads_status(MySQL_Session *);
	
	virtual void wrlock();
	virtual void wrunlock();
	virtual void commit();

	char *get_variable_string(char *name);
	uint16_t get_variable_uint16(char *name);
	int get_variable_int(char *name);
	virtual char * get_variable(char *name); // this is the public function, accessible from admin
	virtual bool set_variable(char *name, char *value);// this is the public function, accessible from admin
	virtual char **get_variables_list();
	virtual void print_version();
	virtual void init(unsigned int num, size_t stack);
	virtual proxysql_mysql_thread_t *create_thread(unsigned int tn, void *(*start_routine) (void *));
	virtual void shutdown_threads();
};
*/

//__thread l_sfp *__thr_sfp=NULL;

static void * connection_manager_thread_callback(void *args) {
	//Standard_MySQL_Threads_Handler *MTH=(Standard_MySQL_Threads_Handler *)GloMTH;
	__thr_sfp=l_mem_init();
	GloMTH->connection_manager_thread();
	l_mem_destroy(__thr_sfp);
	return NULL;
}



Standard_MySQL_Threads_Handler::Standard_MySQL_Threads_Handler() {
#ifdef DEBUG
	if (glovars.has_debug==false) {
#else
	if (glovars.has_debug==true) {
#endif /* DEBUG */
		perror("Incompatible debagging version");
		exit(EXIT_FAILURE);
	}
	num_threads=0;
	mysql_threads=NULL;
	stacksize=0;
	shutdown=0;
	spinlock_rwlock_init(&rwlock);
	pthread_attr_init(&attr);
	variables.connect_timeout_server=10000;
	variables.connect_timeout_server_error=strdup((char *)"#2003:Can't connect to MySQL server");
	variables.default_schema=strdup((char *)"information_schema");
	variables.server_version=strdup((char *)"5.1.30");
	variables.server_capabilities=CLIENT_FOUND_ROWS | CLIENT_PROTOCOL_41 | CLIENT_IGNORE_SIGPIPE | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB | CLIENT_SSL;
	variables.poll_timeout=2000;
	variables.servers_stats=true;
#ifdef DEBUG
	variables.session_debug=true;
#endif /*debug */
	__global_MySQL_Thread_Variables_version=1;
}

void Standard_MySQL_Threads_Handler::wrlock() {
	spin_wrlock(&rwlock);
}

void Standard_MySQL_Threads_Handler::wrunlock() {
	spin_wrunlock(&rwlock);
}

void Standard_MySQL_Threads_Handler::commit() {
	__sync_add_and_fetch(&__global_MySQL_Thread_Variables_version,1);
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 1, "Increasing version number to %d - all threads will notice this and refresh their variables\n", __global_MySQL_Thread_Variables_version);
}

char * Standard_MySQL_Threads_Handler::get_variable_string(char *name) {
	if (!strcasecmp(name,"connect_timeout_server_error")) return strdup(variables.connect_timeout_server_error);
	if (!strcmp(name,"server_version")) return strdup(variables.server_version);
	if (!strcmp(name,"default_schema")) return strdup(variables.default_schema);
	proxy_error("Not existing variable: %s\n", name); assert(0);
	return NULL;
}

uint16_t Standard_MySQL_Threads_Handler::get_variable_uint16(char *name) {
	if (!strcmp(name,"server_capabilities")) return variables.server_capabilities;
	proxy_error("Not existing variable: %s\n", name); assert(0);
	return 0;
}

int Standard_MySQL_Threads_Handler::get_variable_int(char *name) {
#ifdef DEBUG
	if (!strcmp(name,"session_debug")) return (int)variables.session_debug;
#endif /* DEBUG */
	if (!strcasecmp(name,"connect_timeout_server")) return (int)variables.connect_timeout_server;
	if (!strcmp(name,"servers_stats")) return (int)variables.servers_stats;
	if (!strcmp(name,"poll_timeout")) return variables.poll_timeout;
	if (!strcmp(name,"stacksize")) return ( stacksize ? stacksize : DEFAULT_STACK_SIZE);
	proxy_error("Not existing variable: %s\n", name); assert(0);
	return 0;
}

char * Standard_MySQL_Threads_Handler::get_variable(char *name) {	// this is the public function, accessible from admin
#define INTBUFSIZE	4096
	char intbuf[INTBUFSIZE];
	if (!strcasecmp(name,"connect_timeout_server_error")) return strdup(variables.connect_timeout_server_error);
	if (!strcmp(name,"server_version")) return strdup(variables.server_version);
	if (!strcmp(name,"default_schema")) return strdup(variables.default_schema);
	if (!strcmp(name,"server_capabilities")) {
		// FIXME : make it human readable
		sprintf(intbuf,"%d",variables.server_capabilities);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"connect_timeout_server")) {
		sprintf(intbuf,"%d",variables.connect_timeout_server);
		return strdup(intbuf);
	}
	if (!strcmp(name,"poll_timeout")) {
		sprintf(intbuf,"%d",variables.poll_timeout);
		return strdup(intbuf);
	}
	if (!strcmp(name,"threads")) {
		sprintf(intbuf,"%d", (num_threads ? num_threads : DEFAULT_NUM_THREADS));
		return strdup(intbuf);
	}
	if (!strcmp(name,"stacksize")) {
		sprintf(intbuf,"%d", (int)(stacksize ? stacksize : DEFAULT_STACK_SIZE));
		return strdup(intbuf);
	}
#ifdef DEBUG
	if (!strcmp(name,"session_debug")) {
		return strdup((variables.session_debug ? "true" : "false"));
	}
#endif /* DEBUG */
	if (!strcmp(name,"servers_stats")) {
		return strdup((variables.servers_stats ? "true" : "false"));
	}
	return NULL;
}	



bool Standard_MySQL_Threads_Handler::set_variable(char *name, char *value) {	// this is the public function, accessible from admin
	// IN:
	// name: variable name
	// value: variable value
	//
	// OUT:
	// false: unable to change the variable value, either because doesn't exist, or because out of range, or read only
	// true: variable value changed
	// 
	size_t vallen=strlen(value);

	if (!strcasecmp(name,"connect_timeout_server")) {
		int intv=atoi(value);
		if (intv > 10 && intv < 600000) {
			variables.connect_timeout_server=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"connect_timeout_server_error")) {
		if (vallen) {
			free(variables.connect_timeout_server_error);
			variables.connect_timeout_server_error=strdup(value);
			return true;
		} else {
			return false;
		}
	}
	if (!strcmp(name,"default_schema")) {
		if (vallen) {
			free(variables.default_schema);
			variables.default_schema=strdup(value);
			return true;
		} else {
			return false;
		}
	}
	if (!strcmp(name,"server_version")) {
		if (vallen) {
			free(variables.server_version);
			variables.server_version=strdup(value);
			return true;
		} else {
			return false;
		}
	}
	if (!strcmp(name,"poll_timeout")) {
		int intv=atoi(value);
		if (intv > 10 && intv < 20000) {
			variables.poll_timeout=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcmp(name,"server_capabilities")) {
		int intv=atoi(value);
		if (intv > 0) {
			variables.server_capabilities=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcmp(name,"stacksize")) {
		int intv=atoi(value);
		if (intv >= 256*1024 && intv <= 4*1024*1024) {
			stacksize=intv;
			return true;
		} else {
			return false;
		}
	}
	if (!strcmp(name,"threads")) {
		unsigned int intv=atoi(value);
		if ((num_threads==0 || num_threads==intv) && intv > 0 && intv < 128) {
			num_threads=intv;
			return true;
		} else {
			return false;
		}
	}
#ifdef DEBUG
	if (!strcmp(name,"session_debug")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.session_debug=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.session_debug=false;
			return true;
		}
		return false;
	}
#endif /* DEBUG */
	if (!strcmp(name,"servers_stats")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.servers_stats=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.servers_stats=false;
			return true;
		}
		return false;
	}
	return false;
}

char ** Standard_MySQL_Threads_Handler::get_variables_list() {
	size_t l=sizeof(mysql_thread_variables_names)/sizeof(char *);
	unsigned int i;
	char **ret=(char **)malloc(sizeof(char *)*l);
	for (i=0;i<l;i++) {
		ret[i]=(i==l-1 ? NULL : strdup(mysql_thread_variables_names[i]));
	}
	return ret;
}

void Standard_MySQL_Threads_Handler::print_version() {
	fprintf(stderr,"Standard MySQL Threads Handler rev. %s -- %s -- %s\n", MYSQL_THREAD_VERSION, __FILE__, __TIMESTAMP__);
}

void Standard_MySQL_Threads_Handler::init(unsigned int num, size_t stack) {
	if (stack) {
		stacksize=stack;
	} else {
		if (stacksize==0) stacksize=DEFAULT_STACK_SIZE;
	}
	if (num) {
		num_threads=num;
	} else {
		if (num_threads==0) num_threads=DEFAULT_NUM_THREADS; //default
	}
	int rc=pthread_attr_setstacksize(&attr, stacksize);
	assert(rc==0);
	mysql_threads=(proxysql_mysql_thread_t *)malloc(sizeof(proxysql_mysql_thread_t)*num_threads);
}

proxysql_mysql_thread_t * Standard_MySQL_Threads_Handler::create_thread(unsigned int tn, void *(*start_routine) (void *)) {
	if (tn==0) {
		pthread_create(&connection_manager_thread_id, &attr, connection_manager_thread_callback, NULL);
	}
	pthread_create(&mysql_threads[tn].thread_id, &attr, start_routine , &mysql_threads[tn]);
	return NULL;
}

void Standard_MySQL_Threads_Handler::shutdown_threads() {
	unsigned int i;
	shutdown=1;
	for (i=0; i<num_threads; i++) {
		mysql_threads[i].worker->shutdown=1;
	}
	for (i=0; i<num_threads; i++) {
		pthread_join(mysql_threads[i].thread_id,NULL);
	}
	pthread_join(connection_manager_thread_id,NULL);
}




Standard_MySQL_Threads_Handler::~Standard_MySQL_Threads_Handler() {
	if (variables.connect_timeout_server_error) free(variables.connect_timeout_server_error);
	if (variables.default_schema) free(variables.default_schema);
	if (variables.server_version) free(variables.server_version);
	free(mysql_threads);
}

//extern Standard_MySQL_Threads_Handler *GloMTH;


class Standard_MySQL_Thread: public MySQL_Thread {

private:
	MySQL_Connection **my_idle_conns;
	bool processing_idles;
	unsigned long long last_processing_idles;
	PtrArray *mysql_sessions_connections_handler;
public:
//ProxySQL_Poll mypolls;
rwlock_t thread_mutex;
Standard_MySQL_Thread() {
	spinlock_rwlock_init(&thread_mutex);
	mypolls.len=0;
	mypolls.size=0;
	mypolls.fds=NULL;
	mypolls.myds=NULL;
	my_idle_conns=NULL;
	processing_idles=false;
	last_processing_idles=0;
	__thread_MySQL_Thread_Variables_version=0;
	mysql_thread___connect_timeout_server_error=NULL;
	mysql_thread___server_version=NULL;
//	GloQPro->init_thread();
//	MyConnPool=new MySQL_Connection_Pool();
	//events=NULL;
//	mypolls.fds=NULL;
//	mypolls.myds=NULL;
//	mysql_sessions=NULL;
};

void refresh_variables() {
	GloMTH->wrlock();
	__thread_MySQL_Thread_Variables_version=__global_MySQL_Thread_Variables_version;
	mysql_thread___connect_timeout_server=GloMTH->get_variable_int((char *)"connect_timeout_server");
	if (mysql_thread___connect_timeout_server_error) free(mysql_thread___connect_timeout_server_error);
	mysql_thread___connect_timeout_server_error=GloMTH->get_variable_string((char *)"connect_timeout_server_error");
	if (mysql_thread___server_version) free(mysql_thread___server_version);
	mysql_thread___server_version=GloMTH->get_variable_string((char *)"server_version");
	if (mysql_thread___default_schema) free(mysql_thread___default_schema);
	mysql_thread___default_schema=GloMTH->get_variable_string((char *)"default_schema");
	mysql_thread___server_capabilities=GloMTH->get_variable_uint16((char *)"server_capabilities");
	mysql_thread___poll_timeout=GloMTH->get_variable_int((char *)"poll_timeout");
	mysql_thread___servers_stats=(bool)GloMTH->get_variable_int((char *)"servers_stats");
#ifdef DEBUG
	mysql_thread___session_debug=(bool)GloMTH->get_variable_int((char *)"session_debug");
#endif /* DEBUG */
	GloMTH->wrunlock();
}

virtual ~Standard_MySQL_Thread() {
//	if (mypolls.fds)
//		free(mypolls.fds);
//	if (mypolls.myds)
//		free(mypolls.myds);
//	destroy_all_sessions(mysql_sessions);

	if (mysql_sessions) {
		while(mysql_sessions->len) {
			MySQL_Session *sess=(MySQL_Session *)mysql_sessions->remove_index_fast(0);
				delete sess;
			}
		delete mysql_sessions;
	}
	if (mysql_sessions_connections_handler) {
		while(mysql_sessions_connections_handler->len) {
			MySQL_Session *sess=(MySQL_Session *)mysql_sessions_connections_handler->remove_index_fast(0);
				delete sess;
			}
		delete mysql_sessions_connections_handler;
	}
	unsigned int i;
	for (i=0;i<mypolls.len;i++) {
		if (mypolls.myds[i]->myds_type==MYDS_LISTENER) {
			delete mypolls.myds[i];
		}
	}

	if (my_idle_conns)
		free(my_idle_conns);
	GloQPro->end_thread();
	delete MyConnPool;

	if (mysql_thread___default_schema) { free(mysql_thread___default_schema); mysql_thread___default_schema=NULL; }
	if (mysql_thread___server_version) { free(mysql_thread___server_version); mysql_thread___server_version=NULL; }

};

virtual bool init() {
	int i;
	mysql_sessions = new PtrArray();
	assert(mysql_sessions);
	mysql_sessions_connections_handler = new PtrArray();
	assert(mysql_sessions_connections_handler);
	for (i=0; i<SESSIONS_FOR_CONNECTIONS_HANDLER;i++) {
		MySQL_Session *sess=new MySQL_Session();
		register_session_connection_handler(sess);
	}
	shutdown=0;
	my_idle_conns=(MySQL_Connection **)malloc(sizeof(MySQL_Connection *)*SESSIONS_FOR_CONNECTIONS_HANDLER);
	GloQPro->init_thread();
	MyConnPool=new MySQL_Connection_Pool();
	return true;
};

/*
void MySQL_Thread::init_poll() {
//	mypolls.max_nfds = MIN_POLL_FDS_PER_THREAD;
//	mypolls.fds=(struct pollfd *)malloc(sizeof(struct pollfd)*mypolls.max_nfds);
//	assert(mypolls.fds);
//	mypolls.myds=(MySQL_Data_Stream **)malloc(sizeof(MySQL_Data_Stream *)*mypolls.max_nfds);
//	assert(mypolls.myds);
//	mypolls.nfds=0;
}
*/

//virtual void print_version() {
//	fprintf(stderr,"Standard MySQL Thread rev. %s -- %s -- %s\n", MYSQL_THREAD_VERSION, __FILE__, __TIMESTAMP__);
//};

inline virtual struct pollfd * get_pollfd(unsigned int i) {
	return &mypolls.fds[i];
};

virtual void poll_listener_add(int sock) {
	MySQL_Data_Stream *listener_DS = new MySQL_Data_Stream;	
	listener_DS->myds_type=MYDS_LISTENER;
	listener_DS->fd=sock;

	proxy_debug(PROXY_DEBUG_NET,1,"Created listener %p for socket %d\n", listener_DS, sock);
	//mypoll_add(&mypolls, POLLIN, sock, listener_DS);	
	mypolls.add(POLLIN, sock, listener_DS, monotonic_time());	
};


virtual void register_session(MySQL_Session *_sess) {
	if (mysql_sessions==NULL) return;
	mysql_sessions->add(_sess);
	_sess->thread=this;
	_sess->MyConnPool=MyConnPool;
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Registered new session\n", _sess->thread, _sess);
};

virtual void unregister_session(int idx) {
	if (mysql_sessions==NULL) return;
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Unregistered session\n", this, mysql_sessions->index(idx));
	mysql_sessions->remove_index_fast(idx);
};


virtual MySQL_Session * create_new_session_and_client_data_stream(int _fd) {
	int arg_on=1;
	MySQL_Session *sess=new MySQL_Session;
	register_session(sess); // register session
	//sess->client_fd=_fd;
	sess->client_myds = new MySQL_Data_Stream();
	sess->client_myds->fd=_fd;
	setsockopt(sess->client_myds->fd, IPPROTO_TCP, TCP_NODELAY, (char *) &arg_on, sizeof(int));
	sess->client_myds->init(MYDS_FRONTEND, sess, sess->client_myds->fd);
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p, DataStream=%p -- Created new client Data Stream\n", sess->thread, sess, sess->client_myds);
	//sess->prot.generate_server_handshake(sess->client_myds);
#ifdef DEBUG
	//sess->myprot_client.dump_pkt=true;
	sess->client_myds->myprot.dump_pkt=true;
#endif
	sess->client_myds->myconn=new MySQL_Connection();  // 20141011
	sess->client_myds->myconn->last_time_used=curtime;
	sess->client_myds->myconn->myds=sess->client_myds; // 20141011
	sess->client_myds->myconn->fd=sess->client_myds->fd; // 20141011

	// FIXME: initializing both, later we will drop one
	//sess->myprot_client.init(&sess->client_myds, sess->client_myds->myconn->userinfo, sess);
	sess->client_myds->myprot.init(&sess->client_myds, sess->client_myds->myconn->userinfo, sess);
	return sess;
};

// main loop
virtual void run() {
	unsigned int n;
	int rc;
	//int arg_on=1;


	unsigned long long oldtime=monotonic_time();

	curtime=monotonic_time();

	spin_wrlock(&thread_mutex);

	while (shutdown==0) {

	if (processing_idles==false &&  (last_processing_idles < curtime-5*1000000) ) {
		int num_idles, i;
		num_idles=MyHGM->get_multiple_idle_connections(-1, curtime-5*1000000, my_idle_conns, SESSIONS_FOR_CONNECTIONS_HANDLER);
		for (i=0; i<num_idles; i++) {
			MySQL_Data_Stream *myds;
			myds=new MySQL_Data_Stream();
			MySQL_Connection *mc=my_idle_conns[i];
			myds->myconn=mc;
			myds->assign_fd_from_mysql_conn();
			myds->myds_type=MYDS_BACKEND;
			MySQL_Session *sess=(MySQL_Session *)mysql_sessions_connections_handler->index(i);
			myds->sess=sess;
			myds->init();
			sess->mybe=sess->find_or_create_backend(mc->parent->myhgc->hid);
			sess->mybe->server_myds=myds;
			sess->to_process=1;
			sess->status=WAITING_SERVER_DATA;
			myds->mypolls=&mypolls;
			mc->last_time_used=curtime;
			myds->myprot.init(&myds, myds->myconn->userinfo, NULL);
			myds->myprot.generate_COM_PING(true,NULL,NULL);
			myds->array2buffer_full();
			myds->DSS=STATE_QUERY_SENT_DS;
			mypolls.add(POLLIN|POLLOUT, myds->fd, myds, curtime);


		}
	}
	


		for (n = 0; n < mypolls.len; n++) {
			mypolls.fds[n].revents=0;
			if (mypolls.myds[n]->myds_type!=MYDS_LISTENER && mypolls.myds[n]->myds_type!=MYDS_BACKEND_PAUSE_CONNECT) {
				mypolls.myds[n]->set_pollout();
			}
		}

	
		spin_wrunlock(&thread_mutex);
		//this is the only portion of code not protected by a global mutex
		proxy_debug(PROXY_DEBUG_NET,5,"Calling poll with timeout %d\n", ( mypolls.poll_timeout ? mypolls.poll_timeout : mysql_thread___poll_timeout )  );
		// poll is called with a timeout of mypolls.poll_timeout if set , or mysql_thread___poll_timeout
		rc=poll(mypolls.fds,mypolls.len, ( mypolls.poll_timeout ? mypolls.poll_timeout : mysql_thread___poll_timeout ) );
		proxy_debug(PROXY_DEBUG_NET,5,"%s\n", "Returning poll");
		spin_wrlock(&thread_mutex);

		mypolls.poll_timeout=0; // always reset this to 0 . If a session needs a specific timeout, it will set this one
		
		curtime=monotonic_time();

		// update polls statistics
		mypolls.loops++;
		mypolls.loop_counters->incr(curtime/1000000);

		if (curtime>(oldtime+(mysql_thread___poll_timeout*1000))) {
			oldtime=curtime;
			GloQPro->update_query_processor_stats();
		}

			if (rc == -1 && errno == EINTR)
				// poll() timeout, try again
				continue;
			if (rc == -1) {
				// error , exit
				perror("poll()");
				exit(EXIT_FAILURE);
			}


		if (__sync_add_and_fetch(&__global_MySQL_Thread_Variables_version,0) > __thread_MySQL_Thread_Variables_version) {
			refresh_variables();
		}


		for (n = 0; n < mypolls.len; n++) {
			proxy_debug(PROXY_DEBUG_NET,3, "poll for fd %d events %d revents %d\n", mypolls.fds[n].fd , mypolls.fds[n].events, mypolls.fds[n].revents);




			MySQL_Data_Stream *myds=mypolls.myds[n];
			if (mypolls.fds[n].revents==0) {

				switch(myds->myds_type) {
					case MYDS_BACKEND_NOT_CONNECTED:
						myds_backend_set_failed_connect(myds,n);
						break;
					case MYDS_BACKEND_PAUSE_CONNECT:
						myds_backend_set_failed_connect(myds,n);
						break;
					default:
						//if (mypolls.fds[n].revents==0 && ( mypolls.myds[n]->myds_type!=MYDS_BACKEND_NOT_CONNECTED && mypolls.myds[n]->myds_type!=MYDS_BACKEND_PAUSE_CONNECT ) ) continue;
						continue;
						break;
				}

			} else {

				switch(myds->myds_type) {
					case MYDS_BACKEND_NOT_CONNECTED:
//			if (myds->myds_type==MYDS_BACKEND_NOT_CONNECTED && mypolls.fds[n].revents) {
						if ( (mypolls.fds[n].revents & POLLERR) || (mypolls.fds[n].revents & POLLHUP) ) {
							// error on connect
							myds_backend_pause_connect(myds);
							continue;
						}
						if (mypolls.fds[n].revents & POLLOUT) {
							// first data on connect from a not blocking socket
							myds_backend_first_packet_after_connect(myds, n);
						}
						break;
					case MYDS_LISTENER:
						// we got a new connection!
						listener_handle_new_connection(myds,n);
						continue;
						break;
					case MYDS_FRONTEND:
						// detected an error on backend
						if ( (mypolls.fds[n].revents & POLLERR) || (mypolls.fds[n].revents & POLLHUP) ) {
							// FIXME: try to handle it in a more graceful way
							myds->sess->healthy=0;
						}
						break;
					default:
						break;
				}
				// data on exiting connection
				process_data_on_data_stream(myds, n);
		}
		}
		// iterate through all sessions and process the session logic
		process_all_sessions();
		process_all_sessions_connections_handler();
	}
};

void process_data_on_data_stream(MySQL_Data_Stream *myds, unsigned int n) {
				mypolls.last_recv[n]=curtime;
				myds->revents=mypolls.fds[n].revents;
				myds->read_from_net();
				myds->read_pkts();

				if ( (mypolls.fds[n].events & POLLOUT) 
						&&
						( (mypolls.fds[n].revents & POLLERR) || (mypolls.fds[n].revents & POLLHUP) )
				) {
					myds->net_failure=true;
				}

				myds->check_data_flow();
				myds->sess->to_process=1;


	      if (myds->active==FALSE) {
					if (myds->sess->client_myds==myds) {
						proxy_debug(PROXY_DEBUG_NET,1, "Session=%p, DataStream=%p -- Deleting FD %d\n", myds->sess, myds, myds->fd);
						myds->sess->healthy=0;
					}
				}

/*
	      if (myds->active==FALSE) {
					mypolls.remove_index_fast(n);
					proxy_debug(PROXY_DEBUG_NET,1, "Session=%p, DataStream=%p -- Deleting FD %d\n", myds->sess, myds, myds->fd);
					//myds->shut_hard();
					MySQL_Session *sess=myds->sess;
					if (
						(sess->server_myds==myds)
						&&
						(myds->myds_type==MYDS_BACKEND)
						&&
						(myds->DSS==STATE_READY)
					) {
						if (sess->mybe->myconn) {
							MyHGM->destroy_MyConn_from_pool(sess->mybe->myconn);
							sess->mybe->myconn=NULL;
						}
						// This is a failed backend, let's try to save the session
						return;
					}

					sess->healthy=0;
					if (sess->client_myds==myds) {
						sess->client_myds=NULL;
						delete myds;
					}
					if (sess->server_myds==myds) {
						sess->server_myds=NULL;
					}
					//delete myds;
					//myds=NULL; // useless?
// FIXME
//  	   		if (sess->client_myds==NULL && sess->server_myds==NULL) {
//						mysql_sessions->remove_fast(sess);
//						delete sess;
//						continue;
//					}
				}
*/
}

void process_all_sessions() {
	unsigned int n;
	int rc;
	for (n=0; n<mysql_sessions->len; n++) {
		MySQL_Session *sess=(MySQL_Session *)mysql_sessions->index(n);
		if (sess->healthy==0) {
			unregister_session(n);
			n--;
			delete sess;
		} else {
			if (sess->to_process==1 || sess->pause<=curtime ) {
				if (sess->pause <= curtime ) sess->pause=0;
				if (sess->pause_until <= curtime) {
					rc=sess->handler();
					if (rc==-1) {
						unregister_session(n);
						n--;
						delete sess;
					}
				}
			}
		}
	}
}


	void process_all_sessions_connections_handler();
	void register_session_connection_handler(MySQL_Session *_sess);
	void myds_backend_set_failed_connect(MySQL_Data_Stream *myds, unsigned int n);
	void myds_backend_pause_connect(MySQL_Data_Stream *myds);
	void myds_backend_first_packet_after_connect(MySQL_Data_Stream *myds, unsigned int n);
	void listener_handle_new_connection(MySQL_Data_Stream *myds, unsigned int n);
	SQLite3_result * SQL3_Thread_status(MySQL_Session *sess);
};   // end class Standard_MySQL_Thread


void Standard_MySQL_Thread::process_all_sessions_connections_handler() {
	unsigned int n;
	int rc;
	for (n=0; n<mysql_sessions_connections_handler->len; n++) {
		MySQL_Session *sess=(MySQL_Session *)mysql_sessions_connections_handler->index(n);
		if (sess->to_process==1) {
			sess->handler();
			sess->to_process=0;
		}
	}
}

void Standard_MySQL_Thread::register_session_connection_handler(MySQL_Session *_sess) {
	if (mysql_sessions_connections_handler==NULL) return;
	mysql_sessions_connections_handler->add(_sess);
	_sess->thread=this;
	_sess->connections_handler=true;
	_sess->MyConnPool=MyConnPool;
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Registered new session for connection handler\n", _sess->thread, _sess);
};


void Standard_MySQL_Thread::myds_backend_set_failed_connect(MySQL_Data_Stream *myds, unsigned int n) {
	if (curtime>mypolls.last_recv[n]+10000000) {
		proxy_error("connect() timeout . curtime: %llu , last_recv: %llu , failed after %lluus . fd: %d , myds_type: %s\n", curtime, mypolls.last_recv[n] , (curtime-mypolls.last_recv[n]) , myds->fd, (myds->myds_type==MYDS_BACKEND_PAUSE_CONNECT ? "MYDS_BACKEND_PAUSE_CONNECT" : "MYDS_BACKEND_NOT_CONNECTED" ) );
		myds->myds_type=MYDS_BACKEND_FAILED_CONNECT;
		myds->sess->pause=curtime+10000000;
		myds->sess->to_process=1;
	}
}

void Standard_MySQL_Thread::myds_backend_pause_connect(MySQL_Data_Stream *myds) {
	proxy_error("connect() error on fd %d . Pausing ...\n", myds->fd);
	myds->myds_type=MYDS_BACKEND_PAUSE_CONNECT;
	myds->sess->pause=curtime+10000000;
	myds->sess->to_process=1;
}

void Standard_MySQL_Thread::myds_backend_first_packet_after_connect(MySQL_Data_Stream *myds, unsigned int n) {
	int optval;
	socklen_t optlen=sizeof(optval);
	getsockopt(myds->fd, SOL_SOCKET, SO_ERROR, &optval, &optlen);
	if (optval==0) {
		mypolls.last_recv[n]=curtime;
		myds->myds_type=MYDS_BACKEND;
		myds->sess->pause=0;
	} else {
		fprintf(stderr,"Connect() error\n");
		myds->myds_type=MYDS_BACKEND_PAUSE_CONNECT;
		myds->sess->pause=curtime+10000000;
	}
}

void Standard_MySQL_Thread::listener_handle_new_connection(MySQL_Data_Stream *myds, unsigned int n) {
	int c;
	c=accept(myds->fd, NULL, NULL);
	if (c>-1) { // accept() succeeded
		// create a new client connection
		mypolls.fds[n].revents=0;
		MySQL_Session *sess=create_new_session_and_client_data_stream(c);
		//sess->myprot_client.generate_pkt_initial_handshake(sess->client_myds,true,NULL,NULL);
		//sess->myprot_client.generate_pkt_initial_handshake(true,NULL,NULL);
		sess->client_myds->myprot.generate_pkt_initial_handshake(true,NULL,NULL);
		ioctl_FIONBIO(sess->client_myds->fd, 1);
		mypolls.add(POLLIN|POLLOUT, sess->client_myds->fd, sess->client_myds, curtime);
		proxy_debug(PROXY_DEBUG_NET,1,"Session=%p -- Adding client FD %d\n", sess, sess->client_myds->fd);
	} else {
		// if we arrive here, accept() failed
		// because multiple threads try to handle the same incoming connection, this is OK
	}
}

SQLite3_result * Standard_MySQL_Thread::SQL3_Thread_status(MySQL_Session *sess) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Dumping MySQL Session status\n");
  SQLite3_result *result=new SQLite3_result(4);
	result->add_column_definition(SQLITE_TEXT,"ThreadID");
	result->add_column_definition(SQLITE_TEXT,"Thread_ptr");
	result->add_column_definition(SQLITE_TEXT,"Session_ptr");
	result->add_column_definition(SQLITE_TEXT,"Status");

	char buf[1024];
	char buf2[1024];

	char **pta=(char **)malloc(sizeof(char *)*4);
	long long int thread_id=syscall(SYS_gettid);
	itostr(pta[0],thread_id);
	pta[1]=(char *)malloc(32);
	sprintf(pta[1],"%p",this);
	pta[2]=(char *)malloc(32);
	sprintf(pta[2],"%p",sess);
	
	std::string status_str;
	status_str.reserve(10000);
	status_str = "\n";
	status_str+= "============\n";
	status_str+= "MySQL Thread\n";
	status_str+= "============\n";
	status_str+= "ThreadID: ";
	status_str.append(pta[0]);
	status_str+= "\n";

	status_str+="\ndefault_schema : "; status_str.append(mysql_thread___default_schema);
	status_str+="\nserver_version : "; status_str.append(mysql_thread___server_version);
	sprintf(buf,"\ncapabilities   : %d\npoll_timeout   : %d\n", mysql_thread___server_capabilities, mysql_thread___poll_timeout);
	status_str.append(buf);
	status_str+= "\n";

	int _c=curtime/1000000;
	sprintf(buf, "Proxy_Polls: %p , len: %d , loops: %lu  { %d , %d , %d , %d , %d }\n", &mypolls, mypolls.len, mypolls.loops, mypolls.loop_counters->sum(_c,1) , mypolls.loop_counters->sum(_c-1,1) , mypolls.loop_counters->sum(_c-2,1) , mypolls.loop_counters->sum(_c-3,1) , mypolls.loop_counters->sum(_c-4,1) );
	status_str.append(buf);
	for (unsigned int i=0; i < mypolls.len; i++) {
		MySQL_Data_Stream *_myds=mypolls.myds[i];
		if (_myds->myconn && _myds->myconn->parent) {
			sprintf(buf2," = { HG=%d , addr=%s , port=%d }", _myds->myconn->parent->myhgc->hid , _myds->myconn->parent->address , _myds->myconn->parent->port );
		}
		sprintf(buf, "myds[%d]: %p = { fd=%d , events=%d , revents=%d } , type=%d , dss=%d , sess=%p , trx=%d , conn=%p%s\n", i, _myds , mypolls.fds[i].fd , mypolls.fds[i].events , mypolls.fds[i].revents , _myds->myds_type , _myds->DSS , _myds->sess , _myds->active_transaction , _myds->myconn, ( (_myds->myconn && _myds->myconn->parent ) ? buf2 : "" ) );
		status_str.append(buf);
	}
	status_str+= "\n";

	sprintf(buf, "MySQL Sessions: %p, len: %d\n", mysql_sessions, mysql_sessions->len);
	status_str.append(buf);
	for (unsigned int i=0; i < mysql_sessions->len; i++) {
		MySQL_Session *s=(MySQL_Session *)mysql_sessions->pdata[i];
		MySQL_Connection_userinfo *ui=s->client_myds->myconn->userinfo;
		sprintf(buf, "session[%d] = %p : COM counters { %d , %d , %d , %d , %d , %d , %d , %d , %d , %d }\n\tuserinfo={%s,%s} , status=%d , myds={%p,%p} , HG={d:%d,c:%d}\n\tLast query= ", i, s, s->command_counters->sum(_c-0,1), s->command_counters->sum(_c-1,1), s->command_counters->sum(_c-2,1), s->command_counters->sum(_c-3,1), s->command_counters->sum(_c-4,1), s->command_counters->sum(_c-5,1), s->command_counters->sum(_c-6,1), s->command_counters->sum(_c-7,1), s->command_counters->sum(_c-8,1), s->command_counters->sum(_c-9,1), ui->username, ui->schemaname, s->status, s->client_myds, ( s->mybe ? s->mybe->server_myds : NULL ) , s->default_hostgroup, s->current_hostgroup);
		status_str.append(buf);
		if (s->CurrentQuery.QueryLength && s->CurrentQuery.MyComQueryCmd!=MYSQL_COM_QUERY___NONE) {
			status_str.append((char *)s->CurrentQuery.QueryPointer);
		}
		status_str+= "\n";
	}

	pta[3]=(char *)status_str.c_str();
	result->add_row(pta);
	for (int i=0; i<3; i++)
		free(pta[i]);
	free(pta);
	return result;
}

SQLite3_result * Standard_MySQL_Threads_Handler::SQL3_Threads_status(MySQL_Session *sess) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Dumping MySQL Threads Handler status\n");
  SQLite3_result *result=new SQLite3_result(1);
	result->add_column_definition(SQLITE_TEXT,"Status");
	//char buf[1024];
	unsigned int i;
	for (i=0;i<num_threads;i++) {
		Standard_MySQL_Thread *thr=(Standard_MySQL_Thread *)mysql_threads[i].worker;
		if (thr!=sess->thread) spin_wrlock(&thr->thread_mutex);
	}
	//sleep(1);
	for (i=0;i<num_threads;i++) {
		Standard_MySQL_Thread *thr=(Standard_MySQL_Thread *)mysql_threads[i].worker;
		if(thr!=sess->thread) spin_wrunlock(&thr->thread_mutex);
	}

	char **pta=(char **)malloc(sizeof(char *)*1);
	std::string status_str;
	status_str.reserve(10000);
	status_str = "\n";
	status_str+= "=====================\n";
	status_str+= "MySQL Threads Handler\n";
	status_str+= "=====================\n";
	pta[0]=(char *)status_str.c_str();
	result->add_row(pta);
	free(pta);
	return result;
}

void Standard_MySQL_Threads_Handler::connection_manager_thread() {
	MySQL_Thread *mythr=new MySQL_Thread();
	MySQL_Session *sess=new MySQL_Session();
	sess->admin=false;
	sess->thread=mythr;
	ProxySQL_Poll mypolls;
	MySQL_Connection **myconns;
	//MySQL_Data_Stream **mydses;
	int max_idle_connections=200;	// randomly hardcoded for now
	int rc,i;
	myconns=(MySQL_Connection **)malloc(sizeof(MySQL_Connection *)*max_idle_connections);
	//mydses=(MySQL_Data_Stream **)malloc(sizeof(MySQL_Data_Stream *)*max_idle_connections);
	while (shutdown==0) {
		sleep(1);
		continue; // FIXME
		bool more_poll=false;
		MySQL_Data_Stream *myds=NULL;
		mythr->curtime=monotonic_time();
		unsigned long long exp=mythr->curtime-10*1000000;
		rc=MyHGM->get_multiple_idle_connections(-1, exp, myconns, max_idle_connections);
		fprintf(stderr,"Idle connections: %d\n", rc);
		for (i=0;i<rc;i++) {
			myds=new MySQL_Data_Stream();
			MySQL_Connection *mc=myconns[i];
			myds->myconn=mc;
			myds->assign_fd_from_mysql_conn();
			myds->myds_type=MYDS_BACKEND;
			myds->init();
			myds->mypolls=&mypolls;
			//myds->DSS=STATE_READY;
			mc->last_time_used=mythr->curtime;
			myds->myprot.init(&myds, myds->myconn->userinfo, NULL);
			myds->myprot.generate_COM_PING(true,NULL,NULL);
			myds->array2buffer_full();
			myds->DSS=STATE_QUERY_SENT_DS;
			mypolls.add(POLLIN|POLLOUT, myds->fd, myds, mythr->curtime);
//			mydses[i]=myds;
/*
			// destroy
			myds=mydses[i];
			mc=myds->myconn;
			//MyHGM->destroy_MyConn_from_pool(mc);
			MyHGM->push_MyConn_to_pool(mc);
			myds->myconn=NULL;
			delete myds;
*/
		}
		if (rc) more_poll=true;
		while (more_poll) {
			unsigned int n;
			for (n = 0; n < mypolls.len; n++) {
				mypolls.fds[n].revents=0;
				mypolls.myds[n]->set_pollout();
      }

			proxy_debug(PROXY_DEBUG_NET,5,"Calling poll with timeout %d\n", ( mypolls.poll_timeout ? mypolls.poll_timeout : mysql_thread___poll_timeout )  );
			rc=poll(mypolls.fds,mypolls.len, 2000);
			proxy_debug(PROXY_DEBUG_NET,5,"%s\n", "Returning poll");			

			unsigned long long curtime2=monotonic_time();
			for (n = 0; n < mypolls.len; n++) {
				proxy_debug(PROXY_DEBUG_NET,3, "poll for fd %d events %d revents %d\n", mypolls.fds[n].fd , mypolls.fds[n].events, mypolls.fds[n].revents);
				if (mypolls.fds[n].revents==0) {
					continue;
				} else {
					myds=mypolls.myds[n];
					myds->sess=sess;
					mypolls.last_recv[n]=mythr->curtime;
					myds->revents=mypolls.fds[n].revents;
					myds->read_from_net();
					if ((myds->revents & POLLOUT) == POLLOUT) {
						myds->write_to_net_poll();
						myds->DSS=STATE_QUERY_SENT_NET;
					}
					if (((myds->revents & POLLIN) == POLLIN) && (myds->DSS==STATE_QUERY_SENT_NET) ) {
					if (myds->PSarrayIN->len==1) {
						PtrSize_t pkt;
						myds->PSarrayIN->remove_index(0,&pkt);
						if (myds->myprot.process_pkt_OK((unsigned char *)pkt.ptr,pkt.size)==true) {
							mypolls.remove_index_fast(n);
							MyHGM->push_MyConn_to_pool(myds->myconn);
							myds->myconn=NULL;
							l_free(pkt.size,pkt.ptr);
							delete myds;
							continue;
						} else {
							myds->active=FALSE;
							l_free(pkt.size,pkt.ptr);
						}
					} else {
						myds->active=FALSE;
					}
					}
					if (myds->active==FALSE) {
						mypolls.remove_index_fast(n);
						MyHGM->destroy_MyConn_from_pool(myds->myconn);
						myds->myconn=NULL;
						delete myds;
						continue;
					}	
				}
			}
			if (curtime2 > mythr->curtime+10000000) {
				while(mypolls.len) {
					mypolls.remove_index_fast(0);
					myds=mypolls.myds[0];
					MyHGM->destroy_MyConn_from_pool(myds->myconn);
					delete myds;
				}
			}
			if (mypolls.len==0) more_poll=false;
		}
	}
	free(myconns);
	delete sess;
//	free(mydses);
}

extern "C" MySQL_Threads_Handler * create_MySQL_Threads_Handler_func() {
    return new Standard_MySQL_Threads_Handler();
}

extern "C" void destroy_MySQL_Threads_Handler_func(MySQL_Threads_Handler * ms) {
    delete ms;
}

extern "C" MySQL_Thread * create_MySQL_Thread_func() {
    return new Standard_MySQL_Thread();
}

extern "C" void destroy_MySQL_Thread_func(MySQL_Thread * ms) {
    delete ms;
}

//typedef MySQL_Thread * create_MySQL_Thread_t();
//typedef void destroy_QC_t(Query_Cache*);
