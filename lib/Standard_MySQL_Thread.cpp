#define __CLASS_STANDARD_MYSQL_THREAD_H
#define MYSQL_THREAD_IMPLEMENTATION
#include "proxysql.h"
#include "cpp.h"

extern Query_Processor *GloQPro;

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
//void mypoll_add(proxy_poll_t *, uint32_t, int, MySQL_Data_Stream *);
//void __mypoll_add(proxy_poll_t *, struct pollfd *, MySQL_Data_Stream *); 
//int mypoll_del(proxy_poll_t *_myp, int i);
#ifdef __cplusplus
}
#endif /* __cplusplus */


#define MYSQL_THREAD_VERSION "0.1.1114"


#define DEFAULT_NUM_THREADS	4
#define DEFAULT_STACK_SIZE	1024*1024

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
	(char *)"default_schema",
	(char *)"poll_timeout",
	(char *)"server_capabilities",
	(char *)"server_version",
	(char *)"servers_stats",
	(char *)"stacksize",
	(char *)"threads",
	NULL
};



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
		uint16_t server_capabilities;
		int poll_timeout;
	} variables;
	public:
	Standard_MySQL_Threads_Handler() {
		num_threads=0;
		mysql_threads=NULL;
		stacksize=0;
		spinlock_rwlock_init(&rwlock);
		pthread_attr_init(&attr);
		variables.default_schema=strdup((char *)"information_schema");
		variables.server_version=strdup((char *)"5.1.30");
		variables.server_capabilities=CLIENT_FOUND_ROWS | CLIENT_PROTOCOL_41 | CLIENT_IGNORE_SIGPIPE | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION | CLIENT_CONNECT_WITH_DB | CLIENT_SSL;
		variables.poll_timeout=2000;
		variables.servers_stats=true;
		__global_MySQL_Thread_Variables_version=1;
	}
	virtual ~Standard_MySQL_Threads_Handler() {
		if (variables.default_schema) free(variables.default_schema);
		if (variables.server_version) free(variables.server_version);
		free(mysql_threads);
	}
	virtual void wrlock() {
		spin_wrlock(&rwlock);                                                                                                                                
	}
	virtual void wrunlock() {                                                                                                           
		spin_wrunlock(&rwlock);                                                                                                                              
	}

	virtual void commit() {
	__sync_add_and_fetch(&__global_MySQL_Thread_Variables_version,1);
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 1, "Increasing version number to %d - all threads will notice this and refresh their variables\n", __global_MySQL_Thread_Variables_version);
	};

	char *get_variable_string(char *name) {
		if (!strcmp(name,"server_version")) return strdup(variables.server_version);
		if (!strcmp(name,"default_schema")) return strdup(variables.default_schema);
		proxy_error("Not existing variable: %s\n", name); assert(0);
		return NULL;
	}
	uint16_t get_variable_uint16(char *name) {
		if (!strcmp(name,"server_capabilities")) return variables.server_capabilities;
		proxy_error("Not existing variable: %s\n", name); assert(0);
		return 0;
	}
	int get_variable_int(char *name) {
		if (!strcmp(name,"servers_stats")) return (int)variables.servers_stats;
		if (!strcmp(name,"poll_timeout")) return variables.poll_timeout;
		if (!strcmp(name,"stacksize")) return ( stacksize ? stacksize : DEFAULT_STACK_SIZE);
		proxy_error("Not existing variable: %s\n", name); assert(0);
		return 0;
	}

	virtual char *get_variable(char *name) {	// this is the public function, accessible from admin
#define INTBUFSIZE	4096
		char intbuf[INTBUFSIZE];
		if (!strcmp(name,"server_version")) return strdup(variables.server_version);
		if (!strcmp(name,"default_schema")) return strdup(variables.default_schema);
		if (!strcmp(name,"server_capabilities")) {
			// FIXME : make it human readable
			sprintf(intbuf,"%d",variables.server_capabilities);
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
		if (!strcmp(name,"servers_stats")) {
			return strdup((variables.servers_stats ? "true" : "false"));
		}
		return NULL;
	}	




	virtual bool set_variable(char *name, char *value) {	// this is the public function, accessible from admin
		// IN:
		// name: variable name
		// value: variable value
		//
		// OUT:
		// false: unable to change the variable value, either because doesn't exist, or because out of range, or read only
		// true: variable value changed
		// 
		size_t vallen=strlen(value);

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
			int intv=atoi(value);
			if ((num_threads==0 || num_threads==intv) && intv > 0 && intv < 128) {
				num_threads=intv;
				return true;
			} else {
				return false;
			}
		}
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


	virtual char **get_variables_list() {
		size_t l=sizeof(mysql_thread_variables_names)/sizeof(char *);
		unsigned int i;
		char **ret=(char **)malloc(sizeof(char *)*l);
		for (i=0;i<l;i++) {
			ret[i]=(i==l-1 ? NULL : strdup(mysql_thread_variables_names[i]));
		}
		return ret;
	}


	virtual void print_version() {
		fprintf(stderr,"Standard MySQL Threads Handler rev. %s -- %s -- %s\n", MYSQL_THREAD_VERSION, __FILE__, __TIMESTAMP__);
	}
	virtual void init(unsigned int num, size_t stack) {
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
	virtual proxysql_mysql_thread_t *create_thread(unsigned int tn, void *(*start_routine) (void *)) {
		pthread_create(&mysql_threads[tn].thread_id, &attr, start_routine , &mysql_threads[tn]);
		return NULL;
	}
	virtual void shutdown_threads() {
		unsigned int i;
		for (i=0; i<num_threads; i++) {
			mysql_threads[i].worker->shutdown=1;
		}
		for (i=0; i<num_threads; i++) {
			pthread_join(mysql_threads[i].thread_id,NULL);
		}
	}
};


extern Standard_MySQL_Threads_Handler *GloMTH;


class Standard_MySQL_Thread: public MySQL_Thread {

private:

public:
//ProxySQL_Poll mypolls;
Standard_MySQL_Thread() {
	mypolls.len=0;
	mypolls.size=0;
	mypolls.fds=NULL;
	mypolls.myds=NULL;
	__thread_MySQL_Thread_Variables_version=0;
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
	if (mysql_thread___server_version) free(mysql_thread___server_version);
	mysql_thread___server_version=GloMTH->get_variable_string((char *)"server_version");
	if (mysql_thread___default_schema) free(mysql_thread___default_schema);
	mysql_thread___default_schema=GloMTH->get_variable_string((char *)"default_schema");
	mysql_thread___server_capabilities=GloMTH->get_variable_uint16((char *)"server_capabilities");
	mysql_thread___poll_timeout=GloMTH->get_variable_int((char *)"poll_timeout");
	mysql_thread___servers_stats=(bool)GloMTH->get_variable_int((char *)"servers_stats");
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
	unsigned int i;
	for (i=0;i<mypolls.len;i++) {
		if (mypolls.myds[i]->myds_type==MYDS_LISTENER) {
			delete mypolls.myds[i];
		}
	}

	GloQPro->end_thread();
	delete MyConnPool;

	if (mysql_thread___default_schema) { free(mysql_thread___default_schema); mysql_thread___default_schema=NULL; }
	if (mysql_thread___server_version) { free(mysql_thread___server_version); mysql_thread___server_version=NULL; }

};

virtual bool init() {
	mysql_sessions = new PtrArray();
	assert(mysql_sessions);
	shutdown=0;
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
	sess->client_fd=_fd;
	setsockopt(sess->client_fd, IPPROTO_TCP, TCP_NODELAY, (char *) &arg_on, sizeof(int));
	sess->client_myds = new MySQL_Data_Stream();
	sess->client_myds->init(MYDS_FRONTEND, sess, sess->client_fd);
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p, DataStream=%p -- Created new client Data Stream\n", sess->thread, sess, sess->client_myds);
	//sess->prot.generate_server_handshake(sess->client_myds);
#ifdef DEBUG
	sess->myprot_client.dump_pkt=true;
#endif
	sess->client_myds->myconn=new MySQL_Connection();  // 20141011
	sess->client_myds->myconn->myds=sess->client_myds; // 20141011
	sess->client_myds->myconn->fd=sess->client_myds->fd; // 20141011
	sess->myprot_client.init(&sess->client_myds, sess->client_myds->myconn->userinfo, sess);
	return sess;
};

// main loop
virtual void run() {
	unsigned int n;
	int rc;
	//int arg_on=1;

	int loops=0;	// FIXME: debug


	unsigned long long oldtime=monotonic_time();
//	unsigned long curtime=monotonic_time();

	while (shutdown==0) {

		for (n = 0; n < mypolls.len; n++) {
			mypolls.fds[n].revents=0;
			if (mypolls.myds[n]->myds_type!=MYDS_LISTENER && mypolls.myds[n]->myds_type!=MYDS_BACKEND_PAUSE_CONNECT) {
				mypolls.myds[n]->set_pollout();
			}
		}

		loops++;
		if (loops>100) {
			loops-=10;
		}	


	
		proxy_debug(PROXY_DEBUG_NET,5,"%s\n", "Calling poll");
		rc=poll(mypolls.fds,mypolls.len,mysql_thread___poll_timeout);
		proxy_debug(PROXY_DEBUG_NET,5,"%s\n", "Returning poll");

		curtime=monotonic_time();
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


		//unsigned long long curtime=monotonic_time();

		if (__sync_add_and_fetch(&__global_MySQL_Thread_Variables_version,0) > __thread_MySQL_Thread_Variables_version) {
			refresh_variables();
		}


		for (n = 0; n < mypolls.len; n++) {
			proxy_debug(PROXY_DEBUG_NET,3, "poll for fd %d events %d revents %d\n", mypolls.fds[n].fd , mypolls.fds[n].events, mypolls.fds[n].revents);



			MySQL_Data_Stream *myds=mypolls.myds[n];
			if (mypolls.fds[n].revents==0) {

				switch(mypolls.myds[n]->myds_type) {
			//MySQL_Data_Stream *myds=(MySQL_Data_Stream *)events[n].data.ptr;
					case MYDS_BACKEND_NOT_CONNECTED:
//			if (mypolls.fds[n].revents==0 && myds->myds_type==MYDS_BACKEND_NOT_CONNECTED) {
						if (curtime>mypolls.last_recv[n]+10000000) {
							fprintf(stderr, "connect() timeout %d curtime: %llu last_recv: %llu\n", __LINE__, curtime, mypolls.last_recv[n]);
							myds->myds_type=MYDS_BACKEND_FAILED_CONNECT;
							myds->sess->pause=curtime+10000000;
							myds->sess->to_process=1;
						}
						break;
//			if (mypolls.fds[n].revents==0 && myds->myds_type==MYDS_BACKEND_PAUSE_CONNECT) {
						case MYDS_BACKEND_PAUSE_CONNECT:
							if (curtime>mypolls.last_recv[n]+10000000) {
								fprintf(stderr, "connect() timeout %d\n", __LINE__);
								myds->myds_type=MYDS_BACKEND_FAILED_CONNECT;
								myds->sess->pause=curtime+10000000;
								myds->sess->to_process=1;
							}
							break;
						default:
							//if (mypolls.fds[n].revents==0 && ( mypolls.myds[n]->myds_type!=MYDS_BACKEND_NOT_CONNECTED && mypolls.myds[n]->myds_type!=MYDS_BACKEND_PAUSE_CONNECT ) ) continue;
							continue;
							break;
				}
			} else {
				int c;
				switch(mypolls.myds[n]->myds_type) {
					case MYDS_BACKEND_NOT_CONNECTED:
//			if (myds->myds_type==MYDS_BACKEND_NOT_CONNECTED && mypolls.fds[n].revents) {
						if ( (mypolls.fds[n].revents & POLLERR) || (mypolls.fds[n].revents & POLLHUP) ) {
							fprintf(stderr, "connect() timeout %d\n", __LINE__);
							myds->myds_type=MYDS_BACKEND_PAUSE_CONNECT;
							myds->sess->pause=curtime+10000000;
							myds->sess->to_process=1;
							continue;
						}
						if (mypolls.fds[n].revents & POLLOUT) {
							// connect from a not blocking socket
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
						break;
					case MYDS_LISTENER:
//			if (myds->myds_type==MYDS_LISTENER && mypolls.fds[n].revents) {
						// we got a new connection!
						c=accept(myds->fd, NULL, NULL);
						if (c>-1) { // accept() succeeded
							// create a new client connection
							mypolls.fds[n].revents=0;
							MySQL_Session *sess=create_new_session_and_client_data_stream(c);
							//sess->myprot_client.generate_pkt_initial_handshake(sess->client_myds,true,NULL,NULL);
							sess->myprot_client.generate_pkt_initial_handshake(true,NULL,NULL);
							ioctl_FIONBIO(sess->client_fd, 1);
							mypolls.add(POLLIN|POLLOUT, sess->client_fd, sess->client_myds, curtime);
							proxy_debug(PROXY_DEBUG_NET,1,"Session=%p -- Adding client FD %d\n", sess, sess->client_fd);
						}
			// if we arrive here, accept() failed
						continue;
						break;
					case MYDS_FRONTEND:
//			if (myds->myds_type==MYDS_FRONTEND && mypolls.fds[n].revents) {
						if ( (mypolls.fds[n].revents & POLLERR) || (mypolls.fds[n].revents & POLLHUP) ) {
							myds->sess->healthy=0;
						}
						break;
					default:
						break;
				}
				// data on exiting connection
				mypolls.last_recv[n]=curtime;
				myds->revents=mypolls.fds[n].revents;
				myds->read_from_net();
				myds->read_pkts();
				myds->check_data_flow();
				myds->sess->to_process=1;
	      if (myds->active==FALSE) {
					mypolls.remove_index_fast(n);
					proxy_debug(PROXY_DEBUG_NET,1, "Session=%p, DataStream=%p -- Deleting FD %d\n", myds->sess, myds, myds->fd);
					myds->shut_hard();
					MySQL_Session *sess=myds->sess;
					sess->healthy=0;
					if (sess->client_myds==myds) sess->client_myds=NULL;
					if (sess->server_myds==myds) sess->server_myds=NULL;
					delete myds;
					myds=NULL;
// FIXME
//  	   		if (sess->client_myds==NULL && sess->server_myds==NULL) {
//						mysql_sessions->remove_fast(sess);
//						delete sess;
//						continue;
//					}
			}
	      // always move pkts from queue to evbuffer
			//	sess->writeout();
			//if (myds) myds->write_to_net_poll();
		}
		}
		// iterate through all sessions and process the session logic
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
};
};


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
