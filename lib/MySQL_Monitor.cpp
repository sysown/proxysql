/*
	RECENT CHANGELOG
	1.2.0723
		* almost completely rewritten
		* use of blocking call for new connections
    * use of Thread Pool instead of a thread per check type
	0.2.0902
		* original implementation
*/

#include <map>
#include <list>
#include <thread>
#include "proxysql.h"
#include "cpp.h"

#include "thread.h"
#include "wqueue.h"

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define MYSQL_MONITOR_VERSION "1.2.0723" DEB

extern ProxySQL_Admin *GloAdmin;
extern MySQL_Threads_Handler *GloMTH;


static MySQL_Monitor *GloMyMon;

#define SAFE_SQLITE3_STEP(_stmt) do {\
	do {\
		rc=sqlite3_step(_stmt);\
		if (rc!=SQLITE_DONE) {\
			assert(rc==SQLITE_LOCKED);\
			usleep(100);\
		}\
	} while (rc!=SQLITE_DONE);\
} while (0)


class ConsumerThread : public Thread {
	//wqueue<MySQL_Monitor_State_Data*>& m_queue;
	wqueue<WorkItem*>& m_queue;
	//void *(*routine) (void *);
	int thrn;
	public:
	//ConsumerThreadPing(wqueue<MySQL_Monitor_State_Data*>& queue, void *(*start_routine) (void *), int _n) : m_queue(queue) {
	ConsumerThread(wqueue<WorkItem*>& queue, int _n) : m_queue(queue) {
		//routine=start_routine;
		thrn=_n;
	}
	void* run() {
		// Remove 1 item at a time and process it. Blocks if no items are 
		// available to process.
		for (int i = 0; ( thrn ? i < thrn : 1) ; i++) {
			WorkItem* item = (WorkItem*)m_queue.remove();
			if (item==NULL) {
				if (thrn) {
					// we took a NULL item that wasn't meant to reach here! Add it again
					WorkItem *item=NULL;
					GloMyMon->queue.add(item);
				}
				// this is intentional to EXIT immediately
				return NULL;
			}
			if (item->routine) { // NULL is allowed, do nothing for it
				if (GloMyMon->monitor_enabled==true) {
					item->routine((void *)item->mmsd);
				}
			}
			//routine((void *)mmsd);
			delete item->mmsd;
			delete item;
		}
		return NULL;
	}
};


static int wait_for_mysql(MYSQL *mysql, int status) {
	struct pollfd pfd;
	int timeout, res;

	pfd.fd = mysql_get_socket(mysql);
	pfd.events =
		(status & MYSQL_WAIT_READ ? POLLIN : 0) |
		(status & MYSQL_WAIT_WRITE ? POLLOUT : 0) |
		(status & MYSQL_WAIT_EXCEPT ? POLLPRI : 0);
	timeout = 10;
	res = poll(&pfd, 1, timeout);
	if (res == 0)
		return MYSQL_WAIT_TIMEOUT | status;
	else if (res < 0)
		return MYSQL_WAIT_TIMEOUT;
	else {
		int status = 0;
		if (pfd.revents & POLLIN) status |= MYSQL_WAIT_READ;
		if (pfd.revents & POLLOUT) status |= MYSQL_WAIT_WRITE;
		if (pfd.revents & POLLPRI) status |= MYSQL_WAIT_EXCEPT;
		return status;
	}
}

static void close_mysql(MYSQL *my) {
	if (my->net.vio) {
		char buff[5];
		mysql_hdr myhdr;
		myhdr.pkt_id=0;
		myhdr.pkt_length=1;
		memcpy(buff, &myhdr, sizeof(mysql_hdr));
		buff[4]=0x01;
		int fd=my->net.fd;
		int wb=send(fd, buff, 5, MSG_NOSIGNAL);
		fd+=wb; // dummy, to make compiler happy
		fd-=wb; // dummy, to make compiler happy
	}
	mysql_close_no_command(my);
}



struct cmp_str {
	bool operator()(char const *a, char const *b) const
	{
		return strcmp(a, b) < 0;
	}
};

class MySQL_Monitor_Connection_Pool {
	private:
	pthread_mutex_t mutex;
	int size;
	std::map<char *, std::list<MYSQL *>* , cmp_str> my_connections;
	public:
	MySQL_Monitor_Connection_Pool();
	~MySQL_Monitor_Connection_Pool();
	MYSQL * get_connection(char *hostname, int port);
	void put_connection(char *hostname, int port, MYSQL *my);
	void purge_idle_connections();
};

MySQL_Monitor_Connection_Pool::MySQL_Monitor_Connection_Pool() {
	size=0;
	pthread_mutex_init(&mutex,NULL);
}

MySQL_Monitor_Connection_Pool::~MySQL_Monitor_Connection_Pool() {
}

void MySQL_Monitor_Connection_Pool::purge_idle_connections() {
	unsigned long long now=monotonic_time();
	pthread_mutex_lock(&mutex);
	//fprintf(stderr,"conn pool size: %d\n",my_connections.size());
	unsigned int totconn = 0;
	for(auto& it : my_connections)
		totconn+=it.second->size();
	//fprintf(stderr,"tot conn in pool: %d\n",totconn);
	for(auto it = my_connections.begin(); it != my_connections.end();) {
		std::list<MYSQL *> *lst=it->second;
		if (!lst->empty()) {
			for(auto it3 = lst->begin(); it3 != lst->end();) {
				//it3=lst->begin();
				MYSQL *my=*it3;
				unsigned long long then=0;
				memcpy(&then,my->net.buff,sizeof(unsigned long long));
				if (now > (then + mysql_thread___monitor_ping_interval*1000 * 3)) {
					MySQL_Monitor_State_Data *mmsd= new MySQL_Monitor_State_Data((char *)"",0,NULL,false);
					mmsd->mysql=my;
					WorkItem *item;
					item=new WorkItem(mmsd,NULL);
					GloMyMon->queue.add(item);
					it3 = lst->erase(it3);
				} else
					++it3;
			}
			++it;
		} else {
			free(it->first);
			free(it->second);
			it = my_connections.erase(it);
		}
	}
	pthread_mutex_unlock(&mutex);
}


MYSQL * MySQL_Monitor_Connection_Pool::get_connection(char *hostname, int port) {
	std::map<char *, std::list<MYSQL *>* , cmp_str >::iterator it;
	//it = my_connections.find(std::make_pair(hostname,port));
	char *buf=(char *)malloc(16+strlen(hostname));
	sprintf(buf,"%s:%d",hostname,port);
	pthread_mutex_lock(&mutex);
	it = my_connections.find(buf);
	free(buf);
	if (it != my_connections.end()) {
		std::list<MYSQL *> *lst=it->second;
		if (!lst->empty()) {
			MYSQL *ret=lst->front();
			lst->pop_front();
			size--;
			pthread_mutex_unlock(&mutex);
			memset(ret->net.buff,0,sizeof(unsigned long long)); // reset what was polluted
			return ret;
		}
	}
	pthread_mutex_unlock(&mutex);
	return NULL;
}

void MySQL_Monitor_Connection_Pool::put_connection(char *hostname, int port, MYSQL *my) {
	size++;
	std::map<char *, std::list<MYSQL *>* , cmp_str >::iterator it;
	char * buf=(char *)malloc(16+strlen(hostname));
	sprintf(buf,"%s:%d",hostname,port);
	unsigned long long now=monotonic_time();
	memcpy(my->net.buff,&now,sizeof(unsigned long long));	//mark insert time
	pthread_mutex_lock(&mutex);
	it = my_connections.find(buf);
	std::list<MYSQL *> *lst=NULL;
	if (it==my_connections.end()) {
		lst=new std::list<MYSQL *>;
		my_connections.insert(my_connections.begin(), std::pair<char *,std::list<MYSQL *>*>(buf,lst));
	} else {
		free(buf);
		lst=it->second;
	}
	lst->push_back(my);
	pthread_mutex_unlock(&mutex);
}

MySQL_Monitor_State_Data::MySQL_Monitor_State_Data(char *h, int p, struct event_base *b, bool _use_ssl, int g) {
		task_id=MON_CONNECT;
		mysql=NULL;
		result=NULL;
		ret=NULL;
		row=NULL;
		mysql_error_msg=NULL;
		hostname=strdup(h);
		port=p;
		//base=b;
		use_ssl=_use_ssl;
		ST=0;
		//ev_mysql=NULL;
		hostgroup_id=g;
	};

MySQL_Monitor_State_Data::~MySQL_Monitor_State_Data() {
	if (hostname) {
		free(hostname);
	}
	//assert(mysql==NULL); // if mysql is not NULL, there is a bug
	if (mysql) {
		close_mysql(mysql);
		mysql=NULL;
	}
	if (mysql_error_msg) {
		free(mysql_error_msg);
	}
}

void * monitor_connect_pthread(void *arg) {
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
	GloMyMon->monitor_connect();
	return NULL;
}

void * monitor_ping_pthread(void *arg) {
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
	GloMyMon->monitor_ping();
	return NULL;
}

void * monitor_read_only_pthread(void *arg) {
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
	GloMyMon->monitor_read_only();
	return NULL;
}

void * monitor_replication_lag_pthread(void *arg) {
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
	GloMyMon->monitor_replication_lag();
	return NULL;
}

MySQL_Monitor::MySQL_Monitor() {

	GloMyMon = this;

	My_Conn_Pool=new MySQL_Monitor_Connection_Pool();

	shutdown=false;
	monitor_enabled=true;	// default
	// create new SQLite datatabase
	monitordb = new SQLite3DB();
	monitordb->open((char *)"file:mem_monitordb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);

	admindb=new SQLite3DB();
	admindb->open((char *)"file:mem_admindb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	admindb->execute("ATTACH DATABASE 'file:mem_monitordb?mode=memory&cache=shared' AS 'monitor'");
	// define monitoring tables
	tables_defs_monitor=new std::vector<table_def_t *>;
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_connect", MONITOR_SQLITE_TABLE_MYSQL_SERVER_CONNECT);	
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_connect_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_CONNECT_LOG);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_ping", MONITOR_SQLITE_TABLE_MYSQL_SERVER_PING);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_ping_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_PING_LOG);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_read_only_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_READ_ONLY_LOG);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_replication_lag_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_REPLICATION_LAG_LOG);
	// create monitoring tables
	check_and_build_standard_tables(monitordb, tables_defs_monitor);
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_connect_log_time_start ON mysql_server_connect_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_ping_log_time_start ON mysql_server_ping_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_read_only_log_time_start ON mysql_server_read_only_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_replication_lag_log_time_start ON mysql_server_replication_lag_log (time_start_us)");

	num_threads=8;
	if (GloMTH) {
		if (GloMTH->num_threads) {
			num_threads=GloMTH->num_threads*2;
		}
	}
	if (num_threads>16) {
		num_threads=16;	// limit to 16
	}
};

MySQL_Monitor::~MySQL_Monitor() {
	drop_tables_defs(tables_defs_monitor);
	delete tables_defs_monitor;
	delete monitordb;
	delete admindb;
	delete My_Conn_Pool;
};


void MySQL_Monitor::print_version() {
	fprintf(stderr,"Standard MySQL Monitor (StdMyMon) rev. %s -- %s -- %s\n", MYSQL_MONITOR_VERSION, __FILE__, __TIMESTAMP__);
};

// This function is copied from ProxySQL_Admin
void MySQL_Monitor::insert_into_tables_defs(std::vector<table_def_t *> *tables_defs, const char *table_name, const char *table_def) {
	table_def_t *td = new table_def_t;
	td->table_name=strdup(table_name);
	td->table_def=strdup(table_def);
	tables_defs->push_back(td);
};

// This function is copied from ProxySQL_Admin
void MySQL_Monitor::drop_tables_defs(std::vector<table_def_t *> *tables_defs) {
	table_def_t *td;
	while (!tables_defs->empty()) {
		td=tables_defs->back();
		free(td->table_name);
		td->table_name=NULL;
		free(td->table_def);
		td->table_def=NULL;
		tables_defs->pop_back();
		delete td;
	}
};

// This function is copied from ProxySQL_Admin
void MySQL_Monitor::check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs) {
	table_def_t *td;
	db->execute("PRAGMA foreign_keys = OFF");
	for (std::vector<table_def_t *>::iterator it=tables_defs->begin(); it!=tables_defs->end(); ++it) {
		td=*it;
		db->check_and_build_table(td->table_name, td->table_def);
	}
	db->execute("PRAGMA foreign_keys = ON");
};

void * monitor_connect_thread(void *arg) {
	MySQL_Monitor_State_Data *mmsd=(MySQL_Monitor_State_Data *)arg;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	mysql_thr->refresh_variables();
	if (!GloMTH) return NULL;	// quick exit during shutdown/restart

	mmsd->create_new_connection();

	unsigned long long start_time=mysql_thr->curtime;
	mmsd->t1=start_time;
	mmsd->t2=monotonic_time();

	sqlite3_stmt *statement=NULL;
	sqlite3 *mondb=mmsd->mondb->get_db();
	int rc;
	char *query=NULL;
	query=(char *)"INSERT OR REPLACE INTO mysql_server_connect_log VALUES (?1 , ?2 , ?3 , ?4 , ?5)";
	rc=sqlite3_prepare_v2(mondb, query, -1, &statement, 0);
	assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int(statement, 2, mmsd->port); assert(rc==SQLITE_OK);
	unsigned long long time_now=realtime_time();
	time_now=time_now-(mmsd->t2 - start_time);
	rc=sqlite3_bind_int64(statement, 3, time_now); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_int64(statement, 4, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1)); assert(rc==SQLITE_OK);
	rc=sqlite3_bind_text(statement, 5, mmsd->mysql_error_msg, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
	SAFE_SQLITE3_STEP(statement);
	rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
	rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
	sqlite3_finalize(statement);
	if (mmsd->mysql_error_msg) {
		if (strncmp(mmsd->mysql_error_msg,"Access denied for user",strlen("Access denied for user"))==0) {
			proxy_error("Server %s:%d is returning \"Access denied\" for monitoring user\n", mmsd->hostname, mmsd->port);
		}
	}
	mysql_close(mmsd->mysql);
	mmsd->mysql=NULL;
	delete mysql_thr;
	return NULL;
}

void * monitor_ping_thread(void *arg) {
	MySQL_Monitor_State_Data *mmsd=(MySQL_Monitor_State_Data *)arg;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	mysql_thr->refresh_variables();
	if (!GloMTH) return NULL;	// quick exit during shutdown/restart

	mmsd->mysql=GloMyMon->My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port);
	unsigned long long start_time=mysql_thr->curtime;

	mmsd->t1=start_time;
	bool crc=false;
	if (mmsd->mysql==NULL) { // we don't have a connection, let's create it
		bool rc;
		rc=mmsd->create_new_connection();
		crc=true;
		if (rc==false) {
			goto __exit_monitor_ping_thread;
		}
	}

	mmsd->t1=monotonic_time();
	//async_exit_status=mysql_change_user_start(&ret_bool, mysql,"msandbox2","msandbox2","information_schema");
	mmsd->async_exit_status=mysql_ping_start(&mmsd->interr,mmsd->mysql);
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > mmsd->t1 + mysql_thread___monitor_ping_timeout * 1000) {
			mmsd->mysql_error_msg=strdup("timeout during ping");
			goto __exit_monitor_ping_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_ping_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_ping_cont(&mmsd->interr, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) { // ping failed
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
	} else {
		if (crc==false) {
			GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname,mmsd->port,mmsd->mysql);
			mmsd->mysql=NULL;
		}
	}

__exit_monitor_ping_thread:
	mmsd->t2=monotonic_time();
	{
		sqlite3_stmt *statement=NULL;
		sqlite3 *mondb=mmsd->mondb->get_db();
		int rc;
		char *query=NULL;
		query=(char *)"INSERT OR REPLACE INTO mysql_server_ping_log VALUES (?1 , ?2 , ?3 , ?4 , ?5)";
		rc=sqlite3_prepare_v2(mondb, query, -1, &statement, 0);
		assert(rc==SQLITE_OK);
		rc=sqlite3_bind_text(statement, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int(statement, 2, mmsd->port); assert(rc==SQLITE_OK);
		unsigned long long time_now=realtime_time();
		time_now=time_now-(mmsd->t2 - start_time);
		rc=sqlite3_bind_int64(statement, 3, time_now); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement, 4, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1)); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_text(statement, 5, mmsd->mysql_error_msg, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
		SAFE_SQLITE3_STEP(statement);
		rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
		rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
		sqlite3_finalize(statement);
	}
__fast_exit_monitor_ping_thread:
	if (mmsd->mysql) {
		// if we reached here we didn't put the connection back
		if (mmsd->mysql_error_msg) {
			mysql_close(mmsd->mysql); // if we reached here we should destroy it
			mmsd->mysql=NULL;
		} else {
			if (crc) {
				bool rc=mmsd->set_wait_timeout();
				if (rc) {
					GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname,mmsd->port,mmsd->mysql);
				} else {
					mysql_close(mmsd->mysql); // set_wait_timeout failed
				}
				mmsd->mysql=NULL;
			} else { // really not sure how we reached here, drop it
				mysql_close(mmsd->mysql);
				mmsd->mysql=NULL;
			}
		}
	}
	delete mysql_thr;
	return NULL;
}

bool MySQL_Monitor_State_Data::set_wait_timeout() {
	bool ret=false;
	char *query=NULL;
	char *qt=(char *)"SET wait_timeout=%d";
	int wait_timeout=mysql_thread___monitor_ping_interval*10/1000;	// convert to second and multiply by 10
	query=(char *)malloc(strlen(qt)+32);
	sprintf(query,qt,wait_timeout);
	t1=monotonic_time();
	async_exit_status=mysql_query_start(&interr,mysql,query);
	while (async_exit_status) {
		async_exit_status=wait_for_mysql(mysql, async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > t1 + mysql_thread___monitor_ping_timeout * 1000) {
			mysql_error_msg=strdup("timeout");
			goto __exit_set_wait_timeout;
		}
		if (GloMyMon->shutdown==true) {
			goto __exit_set_wait_timeout;	// exit immediately
		}
		if ((async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			async_exit_status=mysql_query_cont(&interr, mysql, async_exit_status);
		}
	}
	if (interr) { // SET failed
		ret=false;
	} else {
		ret=true;
	}
__exit_set_wait_timeout:
	free(query);
	return ret;
}

bool MySQL_Monitor_State_Data::create_new_connection() {
		mysql=mysql_init(NULL);
		assert(mysql);
		if (use_ssl) {
			mysql_ssl_set(mysql, mysql_thread___ssl_p2s_key, mysql_thread___ssl_p2s_cert, mysql_thread___ssl_p2s_ca, NULL, mysql_thread___ssl_p2s_cipher);
		}
		unsigned int timeout=mysql_thread___monitor_connect_timeout/1000;
		if (timeout==0) timeout=1;
		mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
//		mysql_options(mysql, MYSQL_OPT_READ_TIMEOUT, &timeout);
//		mysql_options(mysql, MYSQL_OPT_WRITE_TIMEOUT, &timeout);
		mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "program_name", "proxysql_monitor");
		MYSQL *myrc=NULL;
		if (port) {
			myrc=mysql_real_connect(mysql, hostname, mysql_thread___monitor_username, mysql_thread___monitor_password, NULL, port, NULL, 0);
		} else {
			myrc=mysql_real_connect(mysql, "localhost", mysql_thread___monitor_username, mysql_thread___monitor_password, NULL, 0, hostname, 0);
		}
		if (myrc==NULL) {
			mysql_error_msg=strdup(mysql_error(mysql));
			return false;
		} else {
			// mariadb client library disables NONBLOCK for SSL connections ... re-enable it!
			mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
			int f=fcntl(mysql->net.fd, F_GETFL);
#ifdef FD_CLOEXEC
			// asynchronously set also FD_CLOEXEC , this to prevent then when a fork happens the FD are duplicated to new process
			fcntl(mysql->net.fd, F_SETFL, f|O_NONBLOCK|FD_CLOEXEC);
#else
			fcntl(mysql->net.fd, F_SETFL, f|O_NONBLOCK);
#endif /* FD_CLOEXEC */
	}
	return true;
}

void * monitor_read_only_thread(void *arg) {
	MySQL_Monitor_State_Data *mmsd=(MySQL_Monitor_State_Data *)arg;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	mysql_thr->refresh_variables();
	if (!GloMTH) return NULL;	// quick exit during shutdown/restart

	mmsd->mysql=GloMyMon->My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port);
	unsigned long long start_time=mysql_thr->curtime;


	mmsd->t1=start_time;

	bool crc=false;
	if (mmsd->mysql==NULL) { // we don't have a connection, let's create it
		bool rc;
		rc=mmsd->create_new_connection();
		crc=true;
		if (rc==false) {
			goto __fast_exit_monitor_read_only_thread;
		}
	}

	mmsd->t1=monotonic_time();
	//async_exit_status=mysql_change_user_start(&ret_bool, mysql,"msandbox2","msandbox2","information_schema");
	//mmsd->async_exit_status=mysql_ping_start(&mmsd->interr,mmsd->mysql);
	mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,"SHOW GLOBAL VARIABLES LIKE 'read_only'");
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > mmsd->t1 + mysql_thread___monitor_read_only_timeout * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			proxy_error("Timeout on read_only check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_read_only_timeout. Assuming read_only=1\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
			goto __exit_monitor_read_only_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_read_only_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_query_cont(&mmsd->interr, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	mmsd->async_exit_status=mysql_store_result_start(&mmsd->result,mmsd->mysql);
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > mmsd->t1 + mysql_thread___monitor_read_only_timeout * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			proxy_error("Timeout on read_only check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_read_only_timeout. Assuming read_only=1\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
			goto __exit_monitor_read_only_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_read_only_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_store_result_cont(&mmsd->result, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) { // ping failed
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
	}

__exit_monitor_read_only_thread:
	mmsd->t2=monotonic_time();
	{
		sqlite3_stmt *statement=NULL;
		sqlite3 *mondb=mmsd->mondb->get_db();
		int rc;
		char *query=NULL;
		query=(char *)"INSERT OR REPLACE INTO mysql_server_read_only_log VALUES (?1 , ?2 , ?3 , ?4 , ?5 , ?6)";
		rc=sqlite3_prepare_v2(mondb, query, -1, &statement, 0);
		assert(rc==SQLITE_OK);
		int read_only=1; // as a safety mechanism , read_only=1 is the default
		rc=sqlite3_bind_text(statement, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int(statement, 2, mmsd->port); assert(rc==SQLITE_OK);
		unsigned long long time_now=realtime_time();
		time_now=time_now-(mmsd->t2 - start_time);
		rc=sqlite3_bind_int64(statement, 3, time_now); assert(rc==SQLITE_OK);
		rc=sqlite3_bind_int64(statement, 4, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1)); assert(rc==SQLITE_OK);
		if (mmsd->result) {
			int num_fields=0;
			int k=0;
			MYSQL_FIELD *fields=NULL;
			int j=-1;
			num_fields = mysql_num_fields(mmsd->result);
			fields = mysql_fetch_fields(mmsd->result);
			for(k = 0; k < num_fields; k++) {
				//if (strcmp("VARIABLE_NAME", fields[k].name)==0) {
				if (strcmp((char *)"Value", (char *)fields[k].name)==0) {
					j=k;
				}
			}
			if (j>-1) {
				MYSQL_ROW row=mysql_fetch_row(mmsd->result);
				if (row) {
					if (row[j]) {
						if (!strcmp(row[j],"0") || !strcasecmp(row[j],"OFF"))
							read_only=0;
					}
				}
			}
//					if (repl_lag>=0) {
			rc=sqlite3_bind_int64(statement, 5, read_only); assert(rc==SQLITE_OK);
//					} else {
//						rc=sqlite3_bind_null(statement, 5); assert(rc==SQLITE_OK);
//					}
			mysql_free_result(mmsd->result);
			mmsd->result=NULL;
		} else {
			rc=sqlite3_bind_null(statement, 5); assert(rc==SQLITE_OK);
		}
		rc=sqlite3_bind_text(statement, 6, mmsd->mysql_error_msg, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
		SAFE_SQLITE3_STEP(statement);
		rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
		rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);

		MyHGM->read_only_action(mmsd->hostname, mmsd->port, read_only);

		sqlite3_finalize(statement);
	}
	if (mmsd->interr) { // check failed
	} else {
		if (crc==false) {
			if (mmsd->mysql) {
				GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname,mmsd->port,mmsd->mysql);
				mmsd->mysql=NULL;
			}
		}
	}
__fast_exit_monitor_read_only_thread:
	if (mmsd->mysql) {
		// if we reached here we didn't put the connection back
		if (mmsd->mysql_error_msg) {
			mysql_close(mmsd->mysql); // if we reached here we should destroy it
			mmsd->mysql=NULL;
		} else {
			if (crc) {
				bool rc=mmsd->set_wait_timeout();
				if (rc) {
					GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname,mmsd->port,mmsd->mysql);
				} else {
					mysql_close(mmsd->mysql); // set_wait_timeout failed
				}
				mmsd->mysql=NULL;
			} else { // really not sure how we reached here, drop it
				mysql_close(mmsd->mysql);
				mmsd->mysql=NULL;
			}
		}
	}
	delete mysql_thr;
	return NULL;
}

void * monitor_replication_lag_thread(void *arg) {
	MySQL_Monitor_State_Data *mmsd=(MySQL_Monitor_State_Data *)arg;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	mysql_thr->refresh_variables();
	if (!GloMTH) return NULL;	// quick exit during shutdown/restart

	mmsd->mysql=GloMyMon->My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port);
	unsigned long long start_time=mysql_thr->curtime;


	mmsd->t1=start_time;

	bool crc=false;
	if (mmsd->mysql==NULL) { // we don't have a connection, let's create it
		bool rc;
		rc=mmsd->create_new_connection();
		crc=true;
		if (rc==false) {
			goto __fast_exit_monitor_replication_lag_thread;
		}
	}

	mmsd->t1=monotonic_time();
	//async_exit_status=mysql_change_user_start(&ret_bool, mysql,"msandbox2","msandbox2","information_schema");
	//mmsd->async_exit_status=mysql_ping_start(&mmsd->interr,mmsd->mysql);
	mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,"SHOW SLAVE STATUS");
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > mmsd->t1 + mysql_thread___monitor_replication_lag_timeout * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			goto __exit_monitor_replication_lag_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_replication_lag_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_query_cont(&mmsd->interr, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	mmsd->async_exit_status=mysql_store_result_start(&mmsd->result,mmsd->mysql);
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > mmsd->t1 + mysql_thread___monitor_replication_lag_timeout * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			goto __exit_monitor_replication_lag_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_replication_lag_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_store_result_cont(&mmsd->result, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) { // replication lag check failed
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
	} else {
		if (crc==false) {
			GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname,mmsd->port,mmsd->mysql);
			mmsd->mysql=NULL;
		}
	}

__exit_monitor_replication_lag_thread:
	mmsd->t2=monotonic_time();
	{
		sqlite3_stmt *statement=NULL;
		sqlite3 *mondb=mmsd->mondb->get_db();
		int rc;
		char *query=NULL;

			query=(char *)"INSERT OR REPLACE INTO mysql_server_replication_lag_log VALUES (?1 , ?2 , ?3 , ?4 , ?5 , ?6)";
			rc=sqlite3_prepare_v2(mondb, query, -1, &statement, 0);
			assert(rc==SQLITE_OK);
//			while (i>0) {
//				i--;
				int repl_lag=-2;
				//MySQL_Monitor_State_Data *mmsd=sds[i];
				rc=sqlite3_bind_text(statement, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int(statement, 2, mmsd->port); assert(rc==SQLITE_OK);
				unsigned long long time_now=realtime_time();
				time_now=time_now-(mmsd->t2 - start_time);
				rc=sqlite3_bind_int64(statement, 3, time_now); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement, 4, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1)); assert(rc==SQLITE_OK);
				if (mmsd->result) {
					int num_fields=0;
					int k=0;
					MYSQL_FIELD * fields=NULL;
					int j=-1;
					num_fields = mysql_num_fields(mmsd->result);
					fields = mysql_fetch_fields(mmsd->result);
					for(k = 0; k < num_fields; k++) {
						if (strcmp("Seconds_Behind_Master", fields[k].name)==0) {
							j=k;
						}
					}
					if (j>-1) {
						MYSQL_ROW row=mysql_fetch_row(mmsd->result);
						if (row) {
							repl_lag=-1; // this is old behavior
							repl_lag=mysql_thread___monitor_slave_lag_when_null; // new behavior, see 669
							if (row[j]) { // if Seconds_Behind_Master is not NULL
								repl_lag=atoi(row[j]);
							}
						}
					}
					if (repl_lag>=0) {
						rc=sqlite3_bind_int64(statement, 5, repl_lag); assert(rc==SQLITE_OK);
					} else {
						rc=sqlite3_bind_null(statement, 5); assert(rc==SQLITE_OK);
					}
					mysql_free_result(mmsd->result);
					mmsd->result=NULL;
				} else {
					rc=sqlite3_bind_null(statement, 5); assert(rc==SQLITE_OK);
				}
				rc=sqlite3_bind_text(statement, 6, mmsd->mysql_error_msg, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				SAFE_SQLITE3_STEP(statement);
				rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
				rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
				//MyHGM->replication_lag_action(mmsd->hostgroup_id, mmsd->hostname, mmsd->port, (repl_lag==-1 ? 0 : repl_lag));
				MyHGM->replication_lag_action(mmsd->hostgroup_id, mmsd->hostname, mmsd->port, repl_lag);
//				delete mmsd;
//			}
			sqlite3_finalize(statement);

	}
	if (mmsd->interr) { // check failed
	} else {
		if (mmsd->mysql) {
			GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname,mmsd->port,mmsd->mysql);
			mmsd->mysql=NULL;
		}
	}
__fast_exit_monitor_replication_lag_thread:
	if (mmsd->mysql) {
		// if we reached here we didn't put the connection back
		if (mmsd->mysql_error_msg) {
			mysql_close(mmsd->mysql); // if we reached here we should destroy it
			mmsd->mysql=NULL;
		} else {
			if (crc) {
				bool rc=mmsd->set_wait_timeout();
				if (rc) {
					GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname,mmsd->port,mmsd->mysql);
				} else {
					mysql_close(mmsd->mysql); // set_wait_timeout failed
				}
				mmsd->mysql=NULL;
			} else { // really not sure how we reached here, drop it
				mysql_close(mmsd->mysql);
				mmsd->mysql=NULL;
			}
		}
	}
	delete mysql_thr;
	return NULL;
}


void * MySQL_Monitor::monitor_connect() {
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	//struct event_base *libevent_base;
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();
	if (!GloMTH) return NULL;	// quick exit during shutdown/restart


	unsigned long long t1;
	unsigned long long t2;
	unsigned long long next_loop_at=0;
	while (GloMyMon->shutdown==false && mysql_thread___monitor_enabled==true) {

		char *error=NULL;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		// add support for SSL
		char *query=(char *)"SELECT hostname, port, MAX(use_ssl) use_ssl FROM mysql_servers GROUP BY hostname, port";
		unsigned int glover;
		t1=monotonic_time();

		if (!GloMTH) return NULL;	// quick exit during shutdown/restart
		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			next_loop_at=0;
		}

		if (t1 < next_loop_at) {
			goto __sleep_monitor_connect_loop;
		}
		next_loop_at=t1+1000*mysql_thread___monitor_connect_interval;

		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		if (error) {
			proxy_error("Error on %s : %s\n", query, error);
			goto __end_monitor_connect_loop;
		} else {
			if (resultset->rows_count==0) {
				goto __end_monitor_connect_loop;
			}
			int us=100;
			if (resultset->rows_count) {
				us=mysql_thread___monitor_connect_interval/2/resultset->rows_count;
			}
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				MySQL_Monitor_State_Data *mmsd=new MySQL_Monitor_State_Data(r->fields[0],atoi(r->fields[1]), NULL, atoi(r->fields[2]));
				mmsd->mondb=monitordb;
				WorkItem* item;
				item=new WorkItem(mmsd,monitor_connect_thread);
				GloMyMon->queue.add(item);
				usleep(us);
				if (GloMyMon->shutdown) return NULL;
			}
		}


__end_monitor_connect_loop:
		if (mysql_thread___monitor_enabled==true) {
			sqlite3_stmt *statement=NULL;
			sqlite3 *mondb=monitordb->get_db();
			int rc;
			char *query=NULL;
			query=(char *)"DELETE FROM mysql_server_connect_log WHERE time_start_us < ?1";
			rc=sqlite3_prepare_v2(mondb, query, -1, &statement, 0);
			assert(rc==SQLITE_OK);
			if (mysql_thread___monitor_history < mysql_thread___monitor_ping_interval * (mysql_thread___monitor_ping_max_failures + 1 )) { // issue #626
				if (mysql_thread___monitor_ping_interval < 3600000)
					mysql_thread___monitor_history = mysql_thread___monitor_ping_interval * (mysql_thread___monitor_ping_max_failures + 1 );
			}
			unsigned long long time_now=realtime_time();
			rc=sqlite3_bind_int64(statement, 1, time_now-(unsigned long long)mysql_thread___monitor_history*1000); assert(rc==SQLITE_OK);
			SAFE_SQLITE3_STEP(statement);
			rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
			rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
			sqlite3_finalize(statement);
		}
		if (resultset)
			delete resultset;

__sleep_monitor_connect_loop:
		t2=monotonic_time();
		if (t2<next_loop_at) {
			unsigned long long st=0;
			st=next_loop_at-t2;
			if (st > 500000) {
				st = 500000;
			}
			usleep(st);
		}
	}
	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr=NULL;
	}
	for (unsigned int i=0;i<num_threads; i++) {
		WorkItem *item=NULL;
		GloMyMon->queue.add(item);
	}
	return NULL;
}


void * MySQL_Monitor::monitor_ping() {
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
//	struct event_base *libevent_base;
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();
	if (!GloMTH) return NULL;	// quick exit during shutdown/restart

	unsigned long long t1;
	unsigned long long t2;
	unsigned long long next_loop_at=0;

	while (GloMyMon->shutdown==false && mysql_thread___monitor_enabled==true) {

		unsigned int glover;
		char *error=NULL;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		char *query=(char *)"SELECT hostname, port, MAX(use_ssl) use_ssl FROM mysql_servers WHERE status NOT LIKE 'OFFLINE\%' GROUP BY hostname, port";
		t1=monotonic_time();

		if (!GloMTH) return NULL;	// quick exit during shutdown/restart
		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			next_loop_at=0;
		}

		if (t1 < next_loop_at) {
			goto __sleep_monitor_ping_loop;
		}
		next_loop_at=t1+1000*mysql_thread___monitor_ping_interval;

		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		if (error) {
			proxy_error("Error on %s : %s\n", query, error);
			goto __end_monitor_ping_loop;
		} else {
			if (resultset->rows_count==0) {
				goto __end_monitor_ping_loop;
			}
			int us=100;
			if (resultset->rows_count) {
				us=mysql_thread___monitor_ping_interval/2/resultset->rows_count;
			}
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				MySQL_Monitor_State_Data *mmsd = new MySQL_Monitor_State_Data(r->fields[0],atoi(r->fields[1]), NULL, atoi(r->fields[2]));
				mmsd->mondb=monitordb;
				WorkItem* item;
				item=new WorkItem(mmsd,monitor_ping_thread);
				GloMyMon->queue.add(item);
				usleep(us);
				if (GloMyMon->shutdown) return NULL;
			}
		}

__end_monitor_ping_loop:
		if (mysql_thread___monitor_enabled==true) {
			sqlite3_stmt *statement=NULL;
			sqlite3 *mondb=monitordb->get_db();
			int rc;
			char *query=NULL;
			query=(char *)"DELETE FROM mysql_server_ping_log WHERE time_start_us < ?1";
			rc=sqlite3_prepare_v2(mondb, query, -1, &statement, 0);
			assert(rc==SQLITE_OK);
			if (mysql_thread___monitor_history < mysql_thread___monitor_ping_interval * (mysql_thread___monitor_ping_max_failures + 1 )) { // issue #626
				if (mysql_thread___monitor_ping_interval < 3600000)
					mysql_thread___monitor_history = mysql_thread___monitor_ping_interval * (mysql_thread___monitor_ping_max_failures + 1 );
			}
			unsigned long long time_now=realtime_time();
			rc=sqlite3_bind_int64(statement, 1, time_now-(unsigned long long)mysql_thread___monitor_history*1000); assert(rc==SQLITE_OK);
			SAFE_SQLITE3_STEP(statement);
			rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
			rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
			sqlite3_finalize(statement);
		}

		if (resultset) {
			delete resultset;
			resultset=NULL;
		}

		// now it is time to shun all problematic hosts
		query=(char *)"SELECT DISTINCT a.hostname, a.port FROM mysql_servers a JOIN monitor.mysql_server_ping_log b ON a.hostname=b.hostname WHERE status NOT LIKE 'OFFLINE\%' AND b.ping_error IS NOT NULL AND b.ping_error NOT LIKE 'Access denied for user\%'";
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		if (error) {
			proxy_error("Error on %s : %s\n", query, error);
		} else {
			// get all addresses and ports
			int i=0;
			int j=0;
			char **addresses=(char **)malloc(resultset->rows_count * sizeof(char *));
			char **ports=(char **)malloc(resultset->rows_count * sizeof(char *));
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				addresses[i]=strdup(r->fields[0]);
				ports[i]=strdup(r->fields[1]);
				i++;
			}
			if (resultset) {
				delete resultset;
				resultset=NULL;
			}
			char *new_query=NULL;
			new_query=(char *)"SELECT 1 FROM (SELECT hostname,port,ping_error FROM mysql_server_ping_log WHERE hostname='%s' AND port='%s' ORDER BY time_start_us DESC LIMIT %d) a WHERE ping_error IS NOT NULL AND ping_error NOT LIKE 'Access denied for user%%' GROUP BY hostname,port HAVING COUNT(*)=%d";
			for (j=0;j<i;j++) {
				char *buff=(char *)malloc(strlen(new_query)+strlen(addresses[j])+strlen(ports[j])+16);
				int max_failures=mysql_thread___monitor_ping_max_failures;
				sprintf(buff,new_query,addresses[j],ports[j],max_failures,max_failures);
				monitordb->execute_statement(buff, &error , &cols , &affected_rows , &resultset);
				if (!error) {
					if (resultset) {
						if (resultset->rows_count) {
							// disable host
							proxy_error("Server %s:%s missed %d heartbeats, shunning it and killing all the connections\n", addresses[j], ports[j], max_failures);
							MyHGM->shun_and_killall(addresses[j],atoi(ports[j]));
						}
						delete resultset;
						resultset=NULL;
					}
				} else {
					proxy_error("Error on %s : %s\n", query, error);
				}
				free(buff);
			}

			while (i) { // now free all the addresses/ports
				i--;
				free(addresses[i]);
				free(ports[i]);
			}
			free(addresses);
			free(ports);
		}


		// now it is time to update current_lantency_ms
		query=(char *)"SELECT DISTINCT a.hostname, a.port FROM mysql_servers a JOIN monitor.mysql_server_ping_log b ON a.hostname=b.hostname WHERE status NOT LIKE 'OFFLINE\%' AND b.ping_error IS NULL";
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		if (error) {
			proxy_error("Error on %s : %s\n", query, error);
		} else {
			// get all addresses and ports
			int i=0;
			int j=0;
			char **addresses=(char **)malloc(resultset->rows_count * sizeof(char *));
			char **ports=(char **)malloc(resultset->rows_count * sizeof(char *));
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				addresses[i]=strdup(r->fields[0]);
				ports[i]=strdup(r->fields[1]);
				i++;
			}
			if (resultset) {
				delete resultset;
				resultset=NULL;
			}
			char *new_query=NULL;

			new_query=(char *)"SELECT hostname,port,COALESCE(CAST(AVG(ping_success_time_us) AS INTEGER),10000) FROM (SELECT hostname,port,ping_success_time_us,ping_error FROM mysql_server_ping_log WHERE hostname='%s' AND port='%s' ORDER BY time_start_us DESC LIMIT 3) a WHERE ping_error IS NULL GROUP BY hostname,port";
			for (j=0;j<i;j++) {
				char *buff=(char *)malloc(strlen(new_query)+strlen(addresses[j])+strlen(ports[j])+16);
				sprintf(buff,new_query,addresses[j],ports[j]);
				monitordb->execute_statement(buff, &error , &cols , &affected_rows , &resultset);
				if (!error) {
					if (resultset) {
						if (resultset->rows_count) {
							for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
								SQLite3_row *r=*it; // this should be called just once, but we create a generic for loop
								// update current_latency_ms
								MyHGM->set_server_current_latency_us(addresses[j],atoi(ports[j]), atoi(r->fields[2]));
							}
						}
						delete resultset;
						resultset=NULL;
					}
				} else {
					proxy_error("Error on %s : %s\n", query, error);
				}
				free(buff);
			}
			while (i) { // now free all the addresses/ports
				i--;
				free(addresses[i]);
				free(ports[i]);
			}
			free(addresses);
			free(ports);
		}

__sleep_monitor_ping_loop:
		t2=monotonic_time();
		if (t2<next_loop_at) {
			unsigned long long st=0;
			st=next_loop_at-t2;
			if (st > 500000) {
				st = 500000;
			}
			usleep(st);
		}
	}
	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr=NULL;
	}
	for (unsigned int i=0;i<num_threads; i++) {
		WorkItem *item=NULL;
		GloMyMon->queue.add(item);
	}
	return NULL;
}

void * MySQL_Monitor::monitor_read_only() {
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
//	struct event_base *libevent_base;
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();
	if (!GloMTH) return NULL;	// quick exit during shutdown/restart

	unsigned long long t1;
	unsigned long long t2;
	unsigned long long next_loop_at=0;

	while (GloMyMon->shutdown==false && mysql_thread___monitor_enabled==true) {

		unsigned int glover;
		char *error=NULL;
		SQLite3_result *resultset=NULL;
		//char *query=(char *)"SELECT DISTINCT hostname, port FROM mysql_servers JOIN mysql_replication_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE status!='OFFLINE_HARD'";
		// add support for SSL
		char *query=(char *)"SELECT hostname, port, MAX(use_ssl) use_ssl FROM mysql_servers JOIN mysql_replication_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE status NOT LIKE 'OFFLINE\%' GROUP BY hostname, port";
		t1=monotonic_time();

		if (!GloMTH) return NULL;	// quick exit during shutdown/restart
		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			next_loop_at=0;
		}

		if (t1 < next_loop_at) {
			goto __sleep_monitor_read_only;
		}
		next_loop_at=t1+1000*mysql_thread___monitor_read_only_interval;
		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
//		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		resultset = MyHGM->execute_query(query, &error);
		assert(resultset);
		if (error) {
			proxy_error("Error on %s : %s\n", query, error);
			goto __end_monitor_read_only_loop;
		} else {
			if (resultset->rows_count==0) {
				goto __end_monitor_read_only_loop;
			}
			int us=100;
			if (resultset->rows_count) {
				us=mysql_thread___monitor_read_only_interval/2/resultset->rows_count;
			}
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				MySQL_Monitor_State_Data *mmsd=new MySQL_Monitor_State_Data(r->fields[0],atoi(r->fields[1]), NULL, atoi(r->fields[2]));
				mmsd->mondb=monitordb;
				//pthread_t thr_;
				//if ( pthread_create(&thr_, &attr, monitor_read_only_thread, (void *)mmsd) != 0 ) {
				//	perror("Thread creation monitor_read_only_thread");
				//}
				WorkItem* item;
				item=new WorkItem(mmsd,monitor_read_only_thread);
				GloMyMon->queue.add(item);
				usleep(us);
				if (GloMyMon->shutdown) return NULL;
			}
		}

__end_monitor_read_only_loop:
		if (mysql_thread___monitor_enabled==true) {
			sqlite3_stmt *statement=NULL;
			sqlite3 *mondb=monitordb->get_db();
			int rc;
			char *query=NULL;
			query=(char *)"DELETE FROM mysql_server_read_only_log WHERE time_start_us < ?1";
			rc=sqlite3_prepare_v2(mondb, query, -1, &statement, 0);
			assert(rc==SQLITE_OK);
			if (mysql_thread___monitor_history < mysql_thread___monitor_ping_interval * (mysql_thread___monitor_ping_max_failures + 1 )) { // issue #626
				if (mysql_thread___monitor_ping_interval < 3600000)
					mysql_thread___monitor_history = mysql_thread___monitor_ping_interval * (mysql_thread___monitor_ping_max_failures + 1 );
			}
			unsigned long long time_now=realtime_time();
			rc=sqlite3_bind_int64(statement, 1, time_now-(unsigned long long)mysql_thread___monitor_history*1000); assert(rc==SQLITE_OK);
			SAFE_SQLITE3_STEP(statement);
			rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
			rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
			sqlite3_finalize(statement);
		}


		if (resultset)
			delete resultset;



__sleep_monitor_read_only:
		t2=monotonic_time();
		if (t2<next_loop_at) {
			unsigned long long st=0;
			st=next_loop_at-t2;
			if (st > 500000) {
				st = 500000;
			}
			usleep(st);
		}
	}
	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr=NULL;
	}
	for (unsigned int i=0;i<num_threads; i++) {
		WorkItem *item=NULL;
		GloMyMon->queue.add(item);
	}
	return NULL;
}

void * MySQL_Monitor::monitor_replication_lag() {
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	//struct event_base *libevent_base;
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();
	if (!GloMTH) return NULL;	// quick exit during shutdown/restart

	unsigned long long t1;
	unsigned long long t2;
	unsigned long long next_loop_at=0;

	while (GloMyMon->shutdown==false && mysql_thread___monitor_enabled==true) {

		unsigned int glover;
		char *error=NULL;
		SQLite3_result *resultset=NULL;
		//char *query=(char *)"SELECT hostgroup_id, hostname, port, max_replication_lag FROM mysql_servers WHERE max_replication_lag > 0 AND status NOT LIKE 'OFFLINE%'";
		// add support for SSL
		char *query=(char *)"SELECT hostgroup_id, hostname, port, max_replication_lag, use_ssl FROM mysql_servers WHERE max_replication_lag > 0 AND status NOT IN (2,3)";
		t1=monotonic_time();

		if (!GloMTH) return NULL;	// quick exit during shutdown/restart
		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			next_loop_at=0;
		}

		if (t1 < next_loop_at) {
			goto __sleep_monitor_replication_lag;
		}
		next_loop_at=t1+1000*mysql_thread___monitor_replication_lag_interval;

		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
//		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		resultset = MyHGM->execute_query(query, &error);
		assert(resultset);
		if (error) {
			proxy_error("Error on %s : %s\n", query, error);
			goto __end_monitor_replication_lag_loop;
		} else {
			if (resultset->rows_count==0) {
				goto __end_monitor_replication_lag_loop;
			}
//			sds=(MySQL_Monitor_State_Data **)malloc(resultset->rows_count * sizeof(MySQL_Monitor_State_Data *));
			int us=100;
			if (resultset->rows_count) {
				us=mysql_thread___monitor_replication_lag_interval/2/resultset->rows_count;
			}
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				MySQL_Monitor_State_Data *mmsd = new MySQL_Monitor_State_Data(r->fields[1], atoi(r->fields[2]), NULL, atoi(r->fields[4]), atoi(r->fields[0]));
				mmsd->mondb=monitordb;
				WorkItem* item;
				item=new WorkItem(mmsd,monitor_replication_lag_thread);
				GloMyMon->queue.add(item);
				usleep(us);
				if (GloMyMon->shutdown) return NULL;
			}
		}

__end_monitor_replication_lag_loop:
		if (mysql_thread___monitor_enabled==true) {
			sqlite3_stmt *statement=NULL;
			sqlite3 *mondb=monitordb->get_db();
			int rc;
			char *query=NULL;
			query=(char *)"DELETE FROM mysql_server_replication_lag_log WHERE time_start_us < ?1";
			rc=sqlite3_prepare_v2(mondb, query, -1, &statement, 0);
			assert(rc==SQLITE_OK);
			if (mysql_thread___monitor_history < mysql_thread___monitor_ping_interval * (mysql_thread___monitor_ping_max_failures + 1 )) { // issue #626
				if (mysql_thread___monitor_ping_interval < 3600000)
					mysql_thread___monitor_history = mysql_thread___monitor_ping_interval * (mysql_thread___monitor_ping_max_failures + 1 );
			}
			unsigned long long time_now=realtime_time();
			rc=sqlite3_bind_int64(statement, 1, time_now-(unsigned long long)mysql_thread___monitor_history*1000); assert(rc==SQLITE_OK);
			SAFE_SQLITE3_STEP(statement);
			rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
			rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
			sqlite3_finalize(statement);
		}

		if (resultset)
			delete resultset;

__sleep_monitor_replication_lag:
		t2=monotonic_time();
		if (t2<next_loop_at) {
			unsigned long long st=0;
			st=next_loop_at-t2;
			if (st > 500000) {
				st = 500000;
			}
			usleep(st);
		}
	}
	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr=NULL;
	}
	for (unsigned int i=0;i<num_threads; i++) {
		WorkItem *item=NULL;
		GloMyMon->queue.add(item);
	}
	return NULL;
}


void * MySQL_Monitor::run() {
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();
	if (!GloMTH) return NULL;	// quick exit during shutdown/restart
	//wqueue<WorkItem*>  queue;
__monitor_run:
	while (queue.size()) { // this is a clean up in case Monitor was restarted
		WorkItem* item = (WorkItem*)queue.remove();
		if (item) {
			if (item->mmsd) {
				delete item->mmsd;
			}
			delete item;
		}
	}
	ConsumerThread **threads= (ConsumerThread **)malloc(sizeof(ConsumerThread *)*num_threads);
	for (unsigned int i=0;i<num_threads; i++) {
		threads[i] = new ConsumerThread(queue, 0);
		threads[i]->start(false);
	}
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize (&attr, 64*1024);
	pthread_t monitor_connect_thread;
	pthread_create(&monitor_connect_thread, &attr, &monitor_connect_pthread,NULL);
	pthread_t monitor_ping_thread;
	pthread_create(&monitor_ping_thread, &attr, &monitor_ping_pthread,NULL);
	pthread_t monitor_read_only_thread;
	pthread_create(&monitor_read_only_thread, &attr, &monitor_read_only_pthread,NULL);
	pthread_t monitor_replication_lag_thread;
	pthread_create(&monitor_replication_lag_thread, &attr, &monitor_replication_lag_pthread,NULL);
	while (shutdown==false && mysql_thread___monitor_enabled==true) {
		unsigned int glover;
		if (GloMTH) {
			glover=GloMTH->get_global_version();
			if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
				MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
				mysql_thr->refresh_variables();
			}
		}
		monitor_enabled=mysql_thread___monitor_enabled;
		if ( rand()%5 == 0) { // purge once in a while
			My_Conn_Pool->purge_idle_connections();
		}
		usleep(500000);
		int qsize=queue.size();
		if (qsize>500) {
			proxy_error("Monitor queue too big, try to reduce frequency of checks: %d\n", qsize);
			qsize=qsize/250;
			proxy_error("Monitor is starting %d helper threads\n", qsize);
			ConsumerThread **threads_aux= (ConsumerThread **)malloc(sizeof(ConsumerThread *)*qsize);
			for (int i=0; i<qsize; i++) {
				threads_aux[i] = new ConsumerThread(queue, 245);
				threads_aux[i]->start();
			}
			for (int i=0; i<qsize; i++) {
				threads_aux[i]->join();
			}
			free(threads_aux);
		}
	}
	for (unsigned int i=0;i<num_threads; i++) {
		WorkItem *item=NULL;
		GloMyMon->queue.add(item);
	}
	for (unsigned int i=0;i<num_threads; i++) {
		threads[i]->join();
	}
	free(threads);
	pthread_join(monitor_connect_thread,NULL);
	pthread_join(monitor_ping_thread,NULL);
	pthread_join(monitor_read_only_thread,NULL);
	pthread_join(monitor_replication_lag_thread,NULL);
	while (shutdown==false) {
		unsigned int glover;
		if (GloMTH) {
			glover=GloMTH->get_global_version();
			if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
				MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
				mysql_thr->refresh_variables();
			}
		}
		monitor_enabled=mysql_thread___monitor_enabled;
		if (mysql_thread___monitor_enabled==true) {
			goto __monitor_run;
		}
		usleep(200000);
	}
	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr=NULL;
	}
	return NULL;
};
