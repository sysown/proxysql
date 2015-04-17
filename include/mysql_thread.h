#ifndef __CLASS_MYSQL_THREAD_H
#define __CLASS_MYSQL_THREAD_H
#include "proxysql.h"
#include "cpp.h"

/*
#define MYSQL_THREAD_EPOLL_MAXEVENTS 1000
#define MIN_POLL_FDS_PER_THREAD 1024
*/


#define MIN_POLL_LEN 8
#define MIN_POLL_DELETE_RATIO  8


#define ADMIN_HOSTGROUP	-2
#define STATS_HOSTGROUP	-3


static unsigned int near_pow_2 (unsigned int n) {
  unsigned int i = 1;
  while (i < n) i <<= 1;
  return i ? i : n;
}

class ProxySQL_Poll {

  private:
  void shrink() {
    unsigned int new_size=near_pow_2(len+1);
    fds=(struct pollfd *)realloc(fds,new_size*sizeof(struct pollfd));
    myds=(MySQL_Data_Stream **)realloc(myds,new_size*sizeof(MySQL_Data_Stream *));
//    status=(unsigned char *)realloc(status,new_size*sizeof(unsigned char));
		last_recv=(unsigned long long *)realloc(last_recv,new_size*sizeof(unsigned long long));
		last_sent=(unsigned long long *)realloc(last_sent,new_size*sizeof(unsigned long long));
    size=new_size;
  };
  void expand(unsigned int more) {
    if ( (len+more) > size ) {
      unsigned int new_size=near_pow_2(len+more);
      fds=(struct pollfd *)realloc(fds,new_size*sizeof(struct pollfd));
      myds=(MySQL_Data_Stream **)realloc(myds,new_size*sizeof(MySQL_Data_Stream *));
//      status=(unsigned char *)realloc(status,new_size*sizeof(unsigned char));
			last_recv=(unsigned long long *)realloc(last_recv,new_size*sizeof(unsigned long long));
			last_sent=(unsigned long long *)realloc(last_sent,new_size*sizeof(unsigned long long));
      size=new_size;
    }
  };

  public:
	int poll_timeout;
	unsigned long loops;
	StatCounters *loop_counters;
  unsigned int len;
  unsigned int size;
  struct pollfd *fds;
  MySQL_Data_Stream **myds;
	unsigned long long *last_recv;
	unsigned long long *last_sent;
	volatile int pending_listener_add;
	volatile int pending_listener_del;
//  unsigned char *status=NULL;   // this should be moved within the Data Stream
  ProxySQL_Poll() {
		loop_counters=new StatCounters(15,10,false);
		poll_timeout=0;
		loops=0;
		len=0;
		pending_listener_add=0;
		pending_listener_del=0;
    size=MIN_POLL_LEN;
    // preallocate MIN_POLL_LEN slots
    fds=(struct pollfd *)malloc(size*sizeof(struct pollfd));
    myds=(MySQL_Data_Stream **)malloc(size*sizeof(MySQL_Data_Stream *));
    //status=(unsigned char *)malloc(size*sizeof(unsigned char));
		last_recv=(unsigned long long *)malloc(size*sizeof(unsigned long long));
		last_sent=(unsigned long long *)malloc(size*sizeof(unsigned long long));
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
		free(last_recv);
		free(last_sent);
		delete loop_counters;
  };



  void add(uint32_t _events, int _fd, MySQL_Data_Stream *_myds, unsigned long long sent_time) {
		//fprintf(stderr,"ProxySQL_Poll: Adding fd %d\n",_fd);
    if (len==size) {
      expand(1);
    }
		_myds->mypolls=this;
    myds[len]=_myds;
    fds[len].fd=_fd;
    fds[len].events=_events;
    fds[len].revents=0;
		_myds->poll_fds_idx=len;  // fix a serious bug
    last_recv[len]=monotonic_time();
    last_sent[len]=sent_time;
    len++;
  };

  void remove_index_fast(unsigned int i) {
		//fprintf(stderr,"ProxySQL_Poll: Removing fd %d\n",fds[i].fd);
		if ((int)i==-1) return;
		myds[i]->poll_fds_idx=-1; // this prevents further delete
    if (i != (len-1)) {
      myds[i]=myds[len-1];
      fds[i].fd=fds[len-1].fd;
      fds[i].events=fds[len-1].events;
      fds[i].revents=fds[len-1].revents;
			myds[i]->poll_fds_idx=i;  // fix a serious bug
      //status[i]=status[len-1];
    	last_recv[i]=last_recv[len-1];
    	last_sent[i]=last_sent[len-1];
    }
    len--;
    if ( ( len>MIN_POLL_LEN ) && ( size > len*MIN_POLL_DELETE_RATIO ) ) {
      shrink();
    }
  };  

	int find_index(int fd) {
		unsigned int i;
		for (i=0; i<len; i++) {
			if (fds[i].fd==fd) {
				return i;
			}
		}
		return -1;
	}

};


class MySQL_Thread
{
	protected:
	int nfds;

//	ProxySQL_Poll mypolls;
	
	public:

	unsigned long long curtime;

	ProxySQL_Poll mypolls;
	pthread_t thread_id;
	int shutdown;
	PtrArray *mysql_sessions;
	
	MySQL_Thread() {};
	virtual ~MySQL_Thread() {};
	virtual bool init() {return false;};
	virtual void poll_listener_add(int fd) {};
	virtual void poll_listener_del(int fd) {};
	virtual void run() {};

	virtual SQLite3_result * SQL3_Thread_status(MySQL_Session *) {return NULL;};

	virtual void register_session(MySQL_Session *) {};
	virtual void unregister_session(int) {};
	virtual MySQL_Session * create_new_session_and_client_data_stream(int) {return NULL;};

	virtual struct pollfd * get_pollfd(unsigned int) {return NULL;};
};

typedef MySQL_Thread * create_MySQL_Thread_t();
typedef void destroy_MySQL_Thread_t(MySQL_Thread *);



class iface_info {
	public:
	char *iface;
	char *address;
	int port;
	int fd;
	iface_info(char *_i, char *_a, int p, int f) {
		iface=strdup(_i);
		address=strdup(_a);
		port=p;
		fd=f;
	}
	~iface_info() {
		free(iface);
		free(address);
	}
};



class MySQL_Listeners_Manager {
	private:
	PtrArray *ifaces;
	public:
  MySQL_Listeners_Manager();
	~MySQL_Listeners_Manager();
	int add(const char *iface);
	int add(const char *address, int port);
	int find_idx(const char *iface);
	int find_idx(const char *address, int port);
	int get_fd(unsigned int idx);
	void del(unsigned int idx);
};



class MySQL_Threads_Handler
{
	public:
	unsigned int num_threads;
	proxysql_mysql_thread_t *mysql_threads;
	MySQL_Threads_Handler() {};
	virtual ~MySQL_Threads_Handler() {};
	virtual const char *version() {return NULL;};
	virtual void print_version() {};
	virtual void init(unsigned int num=0, size_t stack=0) {};
	virtual proxysql_mysql_thread_t *create_thread(unsigned int tn, void *(*start_routine) (void *)) {return NULL;};
	virtual void shutdown_threads() {};
	virtual void wrlock() {};
  virtual void wrunlock() {};
	virtual void commit() {};
	virtual char *get_variable(char *name) {return NULL;};
	virtual bool set_variable(char *name, char *value) {return false;};
	virtual char **get_variables_list() {return NULL;}
	virtual SQLite3_result * SQL3_Threads_status(MySQL_Session *) {return NULL;}
	virtual int listener_add(const char *iface) {return -1;}
	virtual int listener_add(const char *address, int port) {return -1;}
	virtual int listener_del(const char *iface) {return -1;}
	virtual int listener_del(const char *address, int port) {return -1;}
	virtual void start_listeners() {};
};

class Standard_MySQL_Threads_Handler: public MySQL_Threads_Handler
{
	private:
	int shutdown_;
	size_t stacksize;
	pthread_attr_t attr;
	rwlock_t rwlock;
	struct {
		int ping_interval_server;
		int ping_timeout_server;
		int connect_timeout_server;
		char *connect_timeout_server_error;
		char *default_schema;
		char *interfaces;
		char *server_version;
		uint8_t default_charset;
		bool servers_stats;
		bool have_compress;
#ifdef DEBUG
		bool session_debug;
#endif /* DEBUG */
		uint16_t server_capabilities;
		int poll_timeout;
	} variables;
	PtrArray *bind_fds;
	MySQL_Listeners_Manager *MLM;
	public:
	Standard_MySQL_Threads_Handler();
	virtual ~Standard_MySQL_Threads_Handler();
	virtual SQLite3_result * SQL3_Threads_status(MySQL_Session *);
	
	virtual void wrlock();
	virtual void wrunlock();
	virtual void commit();

	char *get_variable_string(char *name);
	uint8_t get_variable_uint8(char *name);
	uint16_t get_variable_uint16(char *name);
	int get_variable_int(char *name);
	virtual char * get_variable(char *name); // this is the public function, accessible from admin
	virtual bool set_variable(char *name, char *value);// this is the public function, accessible from admin
	virtual char **get_variables_list();
	virtual void print_version();
	virtual void init(unsigned int num, size_t stack);
	virtual proxysql_mysql_thread_t *create_thread(unsigned int tn, void *(*start_routine) (void *));
	virtual void shutdown_threads();
	virtual int listener_add(const char *iface);
	virtual int listener_add(const char *address, int port);
	virtual int listener_del(const char *iface);
	virtual void start_listeners();
//	virtual int listener_del(const char *address, int port);
//	pthread_t connection_manager_thread_id;
//	void connection_manager_thread();
};


typedef MySQL_Threads_Handler * create_MySQL_Threads_Handler_t();
typedef void destroy_MySQL_Threads_Handler_t(MySQL_Threads_Handler *);


/*
#ifndef MYSQL_THREAD_IMPLEMENTATION
#define __EXTERN extern
#else
#define __EXTERN
#endif */ /* MYSQL_THREAD_IMPLEMENTATION */
/*
__EXTERN __thread char *mysql_thread___default_schema;
__EXTERN __thread char *mysql_thread___server_version;
__EXTERN __thread int mysql_thread___ping_interval_server;
__EXTERN __thread int mysql_thread___ping_timeout_server;
__EXTERN __thread int mysql_thread___connect_timeout_server;
__EXTERN __thread char *mysql_thread___connect_timeout_server_error;
__EXTERN __thread uint16_t mysql_thread___server_capabilities;
__EXTERN __thread int mysql_thread___poll_timeout;
__EXTERN __thread bool mysql_thread___servers_stats;
#ifdef DEBUG
__EXTERN __thread bool mysql_thread___session_debug;
#endif */ /* DEBUG */

#endif /* __CLASS_MYSQL_THREAD_H */
