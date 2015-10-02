#ifndef __CLASS_MYSQL_THREAD_H
#define __CLASS_MYSQL_THREAD_H
#define ____CLASS_STANDARD_MYSQL_THREAD_H
#include "proxysql.h"
#include "cpp.h"


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
		last_recv=(unsigned long long *)realloc(last_recv,new_size*sizeof(unsigned long long));
		last_sent=(unsigned long long *)realloc(last_sent,new_size*sizeof(unsigned long long));
    size=new_size;
  };
  void expand(unsigned int more) {
    if ( (len+more) > size ) {
      unsigned int new_size=near_pow_2(len+more);
      fds=(struct pollfd *)realloc(fds,new_size*sizeof(struct pollfd));
      myds=(MySQL_Data_Stream **)realloc(myds,new_size*sizeof(MySQL_Data_Stream *));
			last_recv=(unsigned long long *)realloc(last_recv,new_size*sizeof(unsigned long long));
			last_sent=(unsigned long long *)realloc(last_sent,new_size*sizeof(unsigned long long));
      size=new_size;
    }
  };

  public:
	unsigned int poll_timeout;
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

  ProxySQL_Poll() {
		loop_counters=new StatCounters(15,10,false);
		poll_timeout=0;
		loops=0;
		len=0;
		pending_listener_add=0;
		pending_listener_del=0;
    size=MIN_POLL_LEN;
    fds=(struct pollfd *)malloc(size*sizeof(struct pollfd));
    myds=(MySQL_Data_Stream **)malloc(size*sizeof(MySQL_Data_Stream *));
		last_recv=(unsigned long long *)malloc(size*sizeof(unsigned long long));
		last_sent=(unsigned long long *)malloc(size*sizeof(unsigned long long));
  };

  ~ProxySQL_Poll() {
    unsigned int i;
    for (i=0;i<len;i++) {
      if (
				myds[i] && // fix bug #278 . This should be caused by not initialized datastreams used to ping the backend
				myds[i]->myds_type==MYDS_LISTENER) {
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
    if (len==size) {
      expand(1);
    }
    myds[len]=_myds;
    fds[len].fd=_fd;
    fds[len].events=_events;
    fds[len].revents=0;
		if (_myds) {
			_myds->mypolls=this;
			_myds->poll_fds_idx=len;  // fix a serious bug
		}
    last_recv[len]=monotonic_time();
    last_sent[len]=sent_time;
    len++;
  };

  void remove_index_fast(unsigned int i) {
		if ((int)i==-1) return;
		myds[i]->poll_fds_idx=-1; // this prevents further delete
    if (i != (len-1)) {
      myds[i]=myds[len-1];
      fds[i].fd=fds[len-1].fd;
      fds[i].events=fds[len-1].events;
      fds[i].revents=fds[len-1].revents;
			myds[i]->poll_fds_idx=i;  // fix a serious bug
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

	private:
  MySQL_Connection **my_idle_conns;
  //MySQL_Data_Stream **my_idle_myds;
  bool processing_idles;
  unsigned long long last_processing_idles;
  PtrArray *mysql_sessions_connections_handler;


	protected:
	int nfds;

	public:

	int pipefd[2];
	unsigned long long curtime;

	ProxySQL_Poll mypolls;
	pthread_t thread_id;
	int shutdown;
	PtrArray *mysql_sessions;

	// status variables are per thread only
	// in this way, there is no need for atomic operation and there is no cache miss
	// when it is needed a total, all threads are checked
	struct {
		unsigned long long queries;
		unsigned long long queries_slow;
		unsigned long long queries_backends_bytes_sent;
		unsigned long long queries_backends_bytes_recv;
	} status_variables;


  rwlock_t thread_mutex;
  MySQL_Thread();
  ~MySQL_Thread();
  MySQL_Session * create_new_session_and_client_data_stream(int _fd);
  bool init();
  void run();
  void poll_listener_add(int sock);
  void poll_listener_del(int sock);
  void register_session(MySQL_Session*);
  void unregister_session(int);
  struct pollfd * get_pollfd(unsigned int i);
  void process_data_on_data_stream(MySQL_Data_Stream *myds, unsigned int n);
  void process_all_sessions();
  void refresh_variables();
  void process_all_sessions_connections_handler();
  void register_session_connection_handler(MySQL_Session *_sess, bool _new=false);
  void unregister_session_connection_handler(int idx, bool _new=false);
  //void myds_backend_set_failed_connect(MySQL_Data_Stream *myds, unsigned int n);
  //void myds_backend_pause_connect(MySQL_Data_Stream *myds);
  //void myds_backend_first_packet_after_connect(MySQL_Data_Stream *myds, unsigned int n);
  void listener_handle_new_connection(MySQL_Data_Stream *myds, unsigned int n);
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
		close(fd);
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
	private:
	int shutdown_;
	size_t stacksize;
	pthread_attr_t attr;
	rwlock_t rwlock;
	struct {
		int monitor_history;
		int monitor_connect_interval;
		int monitor_connect_timeout;
		int monitor_ping_interval;
		int monitor_ping_timeout;
		int monitor_read_only_interval;
		int monitor_read_only_timeout;
		int monitor_replication_lag_interval;
		int monitor_replication_lag_timeout;
		int monitor_query_interval;
		int monitor_query_timeout;
		char * monitor_query_variables;
		char * monitor_query_status;
		char *monitor_username;
		char *monitor_password;
		bool monitor_timer_cached;
		int ping_interval_server;
		int ping_timeout_server;
		int shun_on_failures;
		int shun_recovery_time;
		int connect_retries_on_failure;
		int connect_retries_delay;
		int connect_timeout_server;
		int connect_timeout_server_max;
		int free_connections_pct;
		bool sessions_sort;
		char *default_schema;
		char *interfaces;
		char *server_version;
		uint8_t default_charset;
		bool servers_stats;
		bool commands_stats;
		bool query_digests;
		bool default_reconnect;
		bool have_compress;
		int max_transaction_time;
		int threshold_query_length;
		int threshold_resultset_size;
		int wait_timeout;
		int max_connections;
		int default_query_delay;
		int default_query_timeout;
		int long_query_time;
#ifdef DEBUG
		bool session_debug;
#endif /* DEBUG */
		uint16_t server_capabilities;
		int poll_timeout;
		int poll_timeout_on_failure;
	} variables;
	PtrArray *bind_fds;
	MySQL_Listeners_Manager *MLM;
	public:
	unsigned int num_threads;
	proxysql_mysql_thread_t *mysql_threads;
	//virtual const char *version() {return NULL;};
	unsigned int get_global_version();
	void wrlock();
 	void wrunlock();
	void commit();
	char *get_variable(char *name);
	bool set_variable(char *name, char *value);
	char **get_variables_list();

	MySQL_Threads_Handler();
	~MySQL_Threads_Handler();
	
	char *get_variable_string(char *name);
	uint8_t get_variable_uint8(char *name);
	uint16_t get_variable_uint16(char *name);
	int get_variable_int(char *name);
	void print_version();
	void init(unsigned int num=0, size_t stack=0);
	proxysql_mysql_thread_t *create_thread(unsigned int tn, void *(*start_routine) (void *));
	void shutdown_threads();
	int listener_add(const char *iface);
	int listener_add(const char *address, int port);
	int listener_del(const char *iface);
	int listener_del(const char *address, int port);
	void start_listeners();
	void stop_listeners();
	void signal_all_threads(unsigned char _c=0);
	SQLite3_result * SQL3_Processlist();
	SQLite3_result * SQL3_GlobalStatus();
	bool kill_session(uint32_t _thread_session_id);
	unsigned long long get_total_queries();
	unsigned long long get_slow_queries();
	unsigned long long get_queries_backends_bytes_recv();
	unsigned long long get_queries_backends_bytes_sent();
};


#endif /* __CLASS_MYSQL_THREAD_H */
