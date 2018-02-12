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
#include <mutex>
#include <thread>
#include "proxysql.h"
#include "cpp.h"

#include "thread.h"
#include "wqueue.h"

#include <fcntl.h>

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

#define SAFE_SQLITE3_STEP2(_stmt) do {\
        do {\
                rc=sqlite3_step(_stmt);\
                if (rc==SQLITE_LOCKED || rc==SQLITE_BUSY) {\
                        usleep(100);\
                }\
        } while (rc==SQLITE_LOCKED || rc==SQLITE_BUSY);\
} while (0)

class ConsumerThread : public Thread {
	wqueue<WorkItem*>& m_queue;
	int thrn;
	public:
	ConsumerThread(wqueue<WorkItem*>& queue, int _n) : m_queue(queue) {
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
	if (my->net.pvio) {
		char buff[5];
		mysql_hdr myhdr;
		myhdr.pkt_id=0;
		myhdr.pkt_length=1;
		memcpy(buff, &myhdr, sizeof(mysql_hdr));
		buff[4]=0x01;
		int fd=my->net.fd;
#ifdef __APPLE__
		int arg_on=1;
		setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (char *) &arg_on, sizeof(int));
		int wb=send(fd, buff, 5, 0);
#else
		int wb=send(fd, buff, 5, MSG_NOSIGNAL);
#endif
		fd+=wb; // dummy, to make compiler happy
		fd-=wb; // dummy, to make compiler happy
	}
	mysql_close_no_command(my);
}


class MySQL_Monitor_Connection_Pool {
private:
	std::mutex mutex;
	std::map<std::pair<std::string, int>, std::vector<MYSQL*> > my_connections;
public:
	MYSQL * get_connection(char *hostname, int port);
	void put_connection(char *hostname, int port, MYSQL *my);
	void purge_idle_connections();
};

void MySQL_Monitor_Connection_Pool::purge_idle_connections() {
	unsigned long long now = monotonic_time();
	std::lock_guard<std::mutex> lock(mutex);
	for(auto it = my_connections.begin(); it != my_connections.end();) {
		auto& lst = it->second;
		for(auto it3 = lst.begin(); it3 != lst.end();) {
			MYSQL *my = *it3;
			unsigned long long then = *(unsigned long long*)my->net.buff;
			if (now > (then + mysql_thread___monitor_ping_interval*1000 * 3)) {
				MySQL_Monitor_State_Data *mmsd= new MySQL_Monitor_State_Data((char *)"",0,NULL,false);
				mmsd->mysql=my;
				GloMyMon->queue.add(new WorkItem(mmsd,NULL));
				std::swap(*it3, lst.back());
				if(it3 == lst.end() - 1)
					it3 = lst.erase(it3);
				else
					lst.pop_back();
			} else
				++it3;
		}
		if (lst.size()) {
			++it;
		} else {
			it = my_connections.erase(it);
		}
	}
}


MYSQL * MySQL_Monitor_Connection_Pool::get_connection(char *hostname, int port) {
	std::lock_guard<std::mutex> lock(mutex);
	auto it = my_connections.find(std::make_pair(hostname, port));
	if (it == my_connections.end() || !it->second.size())
		return NULL;
	MYSQL *my = it->second.back();
	it->second.pop_back();
	*(unsigned long long*)my->net.buff = 0;
	return my;
}

void MySQL_Monitor_Connection_Pool::put_connection(char *hostname, int port, MYSQL *my) {
	unsigned long long now = monotonic_time();
	std::lock_guard<std::mutex> lock(mutex);
	*(unsigned long long*)my->net.buff = now;
	//this doesn't work on old compilers
//	auto it = my_connections.emplace(std::piecewise_construct,
//		std::forward_as_tuple(hostname, port), std::forward_as_tuple()).first;
//	it->second.push_back(my);
	// code for old compilers (gcc 4.7 in debian7)
	auto it = my_connections.find(std::make_pair(hostname, port));
	if (it != my_connections.end()) {
		it->second.push_back(my);
	} else {
		my_connections[std::make_pair(hostname,port)].push_back(my);
	}
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
		use_ssl=_use_ssl;
		ST=0;
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
#ifndef NOJEM
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	GloMyMon->monitor_connect();
	return NULL;
}

void * monitor_ping_pthread(void *arg) {
#ifndef NOJEM
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	GloMyMon->monitor_ping();
	return NULL;
}

void * monitor_read_only_pthread(void *arg) {
#ifndef NOJEM
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	GloMyMon->monitor_read_only();
	return NULL;
}

void * monitor_group_replication_pthread(void *arg) {
#ifndef NOJEM
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	GloMyMon->monitor_group_replication();
	return NULL;
}

void * monitor_replication_lag_pthread(void *arg) {
#ifndef NOJEM
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	GloMyMon->monitor_replication_lag();
	return NULL;
}

MySQL_Monitor::MySQL_Monitor() {

	GloMyMon = this;

	My_Conn_Pool=new MySQL_Monitor_Connection_Pool();

	pthread_mutex_init(&group_replication_mutex,NULL);
	Group_Replication_Hosts_resultset=NULL;

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
	//insert_into_tables_defs(tables_defs_monitor,"mysql_server_connect", MONITOR_SQLITE_TABLE_MYSQL_SERVER_CONNECT);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_connect_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_CONNECT_LOG);
	//insert_into_tables_defs(tables_defs_monitor,"mysql_server_ping", MONITOR_SQLITE_TABLE_MYSQL_SERVER_PING);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_ping_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_PING_LOG);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_read_only_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_READ_ONLY_LOG);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_replication_lag_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_REPLICATION_LAG_LOG);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_group_replication_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_GROUP_REPLICATION_LOG);
	// create monitoring tables
	check_and_build_standard_tables(monitordb, tables_defs_monitor);
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_connect_log_time_start ON mysql_server_connect_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_ping_log_time_start ON mysql_server_ping_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_read_only_log_time_start ON mysql_server_read_only_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_replication_lag_log_time_start ON mysql_server_replication_lag_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_group_replication_log_time_start ON mysql_server_group_replication_log (time_start_us)");

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
	if (Group_Replication_Hosts_resultset) {
		delete Group_Replication_Hosts_resultset;
		Group_Replication_Hosts_resultset=NULL;
	}
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
	SAFE_SQLITE3_STEP2(statement);
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
		SAFE_SQLITE3_STEP2(statement);
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
	if (mysql_thread___monitor_wait_timeout==false) {
		return true;
	}
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
	if (mmsd->task_id == MON_INNODB_READ_ONLY) {
		mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,"SHOW GLOBAL VARIABLES LIKE 'innodb_read_only'");
	} else {
		if (mmsd->task_id == MON_SUPER_READ_ONLY) {
			mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,"SHOW GLOBAL VARIABLES LIKE 'super_read_only'");
		} else {
			mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,"SHOW GLOBAL VARIABLES LIKE 'read_only'");
		}
	}
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
		SAFE_SQLITE3_STEP2(statement);
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

void * monitor_group_replication_thread(void *arg) {
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
			goto __fast_exit_monitor_group_replication_thread;
		}
	}

	mmsd->t1=monotonic_time();
	//async_exit_status=mysql_change_user_start(&ret_bool, mysql,"msandbox2","msandbox2","information_schema");
	//mmsd->async_exit_status=mysql_ping_start(&mmsd->interr,mmsd->mysql);
	mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,"SELECT viable_candidate,read_only,transactions_behind FROM sys.gr_member_routing_candidate_status");
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > mmsd->t1 + mysql_thread___monitor_groupreplication_healthcheck_timeout * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			proxy_error("Timeout on group replication health check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_groupreplication_healthcheck_timeout. Assuming viable_candidate=nO and read_only=YES\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
			goto __exit_monitor_group_replication_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_group_replication_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_query_cont(&mmsd->interr, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	mmsd->async_exit_status=mysql_store_result_start(&mmsd->result,mmsd->mysql);
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > mmsd->t1 + mysql_thread___monitor_groupreplication_healthcheck_timeout * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			proxy_error("Timeout on group replication health check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_groupreplication_healthcheck_timeout. Assuming viable_candidate=nO and read_only=YES\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
			goto __exit_monitor_group_replication_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_group_replication_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_store_result_cont(&mmsd->result, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) { // ping failed
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
	}

__exit_monitor_group_replication_thread:
	mmsd->t2=monotonic_time();
	{
		// TODO : complete this
		char buf[128];
		char *s=NULL;
		int l=strlen(mmsd->hostname);
		if (l<110) {
			s=buf;
		}	else {
			s=(char *)malloc(l+16);
		}
		sprintf(s,"%s:%d",mmsd->hostname,mmsd->port);
		bool viable_candidate=false;
		bool read_only=true;
		long long transactions_behind=-1;
		if (mmsd->result) {
			int num_fields=0;
			int num_rows=0;
			num_fields = mysql_num_fields(mmsd->result);
			if (num_fields!=3) {
				proxy_error("Incorrect number of fields, please report a bug\n");
				goto __end_process_group_replication_result;
			}
			num_rows = mysql_num_rows(mmsd->result);
			if (num_rows!=1) {
				proxy_error("Incorrect number of rows, please report a bug\n");
				goto __end_process_group_replication_result;
			}
			MYSQL_ROW row=mysql_fetch_row(mmsd->result);
			if (!strcasecmp(row[0],"YES")) {
				viable_candidate=true;
			}
			if (!strcasecmp(row[1],"NO")) {
				read_only=false;
			}
			transactions_behind=atol(row[2]);
			mysql_free_result(mmsd->result);
			mmsd->result=NULL;
		}
__end_process_group_replication_result:
		//proxy_info("GR: %s:%d , viable=%s , ro=%s, trx=%ld, err=%s\n", mmsd->hostname, mmsd->port, (viable_candidate ? "YES": "NO") , (read_only ? "YES": "NO") , transactions_behind, ( mmsd->mysql_error_msg ? mmsd->mysql_error_msg : "") );
		if (mmsd->mysql_error_msg) {
			//proxy_warning("GR: %s:%d , viable=%s , ro=%s, trx=%ld, err=%s\n", mmsd->hostname, mmsd->port, (viable_candidate ? "YES": "NO") , (read_only ? "YES": "NO") , transactions_behind, ( mmsd->mysql_error_msg ? mmsd->mysql_error_msg : "") );
		}
		unsigned long long time_now=realtime_time();
		time_now=time_now-(mmsd->t2 - start_time);
		pthread_mutex_lock(&GloMyMon->group_replication_mutex);
		//auto it = 
		// TODO : complete this
		std::map<std::string, MyGR_monitor_node *>::iterator it2;
		it2 = GloMyMon->Group_Replication_Hosts_Map.find(s);
		MyGR_monitor_node *node=NULL;
		if (it2!=GloMyMon->Group_Replication_Hosts_Map.end()) {
			node=it2->second;
			node->add_entry(time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1) , transactions_behind,viable_candidate,read_only,mmsd->mysql_error_msg);
		} else {
			node = new MyGR_monitor_node(mmsd->hostname,mmsd->port,mmsd->writer_hostgroup);
			node->add_entry(time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1) , transactions_behind,viable_candidate,read_only,mmsd->mysql_error_msg);
			GloMyMon->Group_Replication_Hosts_Map.insert(std::make_pair(s,node));
		}
		pthread_mutex_unlock(&GloMyMon->group_replication_mutex);

		// NOTE: we update MyHGM outside the mutex group_replication_mutex
		if (mmsd->mysql_error_msg) { // there was an error checking the status of the server, surely we need to reconfigure GR
			MyHGM->update_group_replication_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, mmsd->mysql_error_msg);
		} else {
			if (viable_candidate==false) {
				MyHGM->update_group_replication_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"viable_candidate=NO");
			} else {
				if (read_only==true) {
					if (transactions_behind > mmsd->max_transactions_behind) {
						MyHGM->update_group_replication_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"slave is lagging");
					} else {
						MyHGM->update_group_replication_set_read_only(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"read_only=YES");
					}
				} else {
					// the node is a writer
					// TODO: for now we don't care about the number of writers
					MyHGM->update_group_replication_set_writer(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup);
				}
			}
		}

		// clean up
		if (l<110) {
		} else {
			free(s);
		}
/*
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
		SAFE_SQLITE3_STEP2(statement);
		rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
		rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);

		MyHGM->read_only_action(mmsd->hostname, mmsd->port, read_only);

		sqlite3_finalize(statement);
*/

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
__fast_exit_monitor_group_replication_thread:
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

	bool use_percona_heartbeat = false;
	char * percona_heartbeat_table = mysql_thread___monitor_replication_lag_use_percona_heartbeat;

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
	if (percona_heartbeat_table) {
		int l = strlen(percona_heartbeat_table);
		if (l) {
			use_percona_heartbeat = true;
			char *base_query = (char *)"SELECT MIN(ROUND(TIMESTAMPDIFF(MICROSECOND, ts, SYSDATE(6))/1000000)) AS Seconds_Behind_Master FROM %s";
			char *replication_query = (char *)malloc(strlen(base_query)+l);
			sprintf(replication_query,base_query,percona_heartbeat_table);
			mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,replication_query);
			free(replication_query);
		}
	}
	if (use_percona_heartbeat == false) {
		mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,"SHOW SLAVE STATUS");
	}
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
				int repl_lag=-2;
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
				SAFE_SQLITE3_STEP2(statement);
				rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
				rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
				MyHGM->replication_lag_action(mmsd->hostgroup_id, mmsd->hostname, mmsd->port, repl_lag);
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
			SAFE_SQLITE3_STEP2(statement);
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
			SAFE_SQLITE3_STEP2(statement);
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
		// add support for SSL
		char *query=(char *)"SELECT hostname, port, MAX(use_ssl) use_ssl, check_type FROM mysql_servers JOIN mysql_replication_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE status NOT IN (2,3) GROUP BY hostname, port";
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
				mmsd->task_id = MON_READ_ONLY; // default
				if (r->fields[3]) {
					if (strcasecmp(r->fields[3],(char *)"innodb_read_only")==0) {
						mmsd->task_id = MON_INNODB_READ_ONLY;
					} else {
						if (strcasecmp(r->fields[3],(char *)"super_read_only")==0) {
							mmsd->task_id = MON_SUPER_READ_ONLY;
						}
					}
				}
				mmsd->mondb=monitordb;
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
			SAFE_SQLITE3_STEP2(statement);
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

void * MySQL_Monitor::monitor_group_replication() {
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
//	struct event_base *libevent_base;
	unsigned int latest_table_servers_version=0;
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
//		char *error=NULL;
//		SQLite3_result *resultset=NULL;
		// add support for SSL
//		char *query=(char *)"SELECT hostname, port, MAX(use_ssl) use_ssl FROM mysql_servers JOIN mysql_group_replication_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=writer_hostgroup hostgroup_id=reader_hostgroup WHERE status NOT LIKE 'OFFLINE\%' GROUP BY hostname, port";
		t1=monotonic_time();

		if (!GloMTH) return NULL;	// quick exit during shutdown/restart
		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			next_loop_at=0;
		}

		if (t1 < next_loop_at) {
			goto __sleep_monitor_group_replication;
		}
		next_loop_at=t1+1000*mysql_thread___monitor_groupreplication_healthcheck_interval;
		pthread_mutex_lock(&group_replication_mutex);
//		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
//		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
//		resultset = MyHGM->execute_query(query, &error);
//		assert(resultset);
		if (Group_Replication_Hosts_resultset==NULL) {
				goto __end_monitor_group_replication_loop;
//		}
//		if (error) {
//			proxy_error("Error on %s : %s\n", query, error);
//			goto __end_monitor_read_only_loop;
		} else {
			if (Group_Replication_Hosts_resultset->rows_count==0) {
				goto __end_monitor_group_replication_loop;
			}
			int us=100;
			if (Group_Replication_Hosts_resultset->rows_count) {
				us=mysql_thread___monitor_read_only_interval/2/Group_Replication_Hosts_resultset->rows_count;
			}
			for (std::vector<SQLite3_row *>::iterator it = Group_Replication_Hosts_resultset->rows.begin() ; it != Group_Replication_Hosts_resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				MySQL_Monitor_State_Data *mmsd=new MySQL_Monitor_State_Data(r->fields[1],atoi(r->fields[2]), NULL, atoi(r->fields[3]));
				mmsd->writer_hostgroup=atoi(r->fields[0]);
				mmsd->writer_is_also_reader=atoi(r->fields[4]);
				mmsd->max_transactions_behind=atoi(r->fields[5]);
				mmsd->mondb=monitordb;
				//pthread_t thr_;
				//if ( pthread_create(&thr_, &attr, monitor_read_only_thread, (void *)mmsd) != 0 ) {
				//	perror("Thread creation monitor_read_only_thread");
				//}
				WorkItem* item;
				item=new WorkItem(mmsd,monitor_group_replication_thread);
				GloMyMon->queue.add(item);
				usleep(us);
				if (GloMyMon->shutdown) {
					pthread_mutex_unlock(&group_replication_mutex);
					return NULL;
				}
			}
		}

__end_monitor_group_replication_loop:
		pthread_mutex_unlock(&group_replication_mutex);
		if (mysql_thread___monitor_enabled==true) {
/*
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
			SAFE_SQLITE3_STEP2(statement);
			rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
			rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
			sqlite3_finalize(statement);
*/
		}


//		if (resultset)
//			delete resultset;



__sleep_monitor_group_replication:
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
		resultset = MyHGM->execute_query(query, &error);
		assert(resultset);
		if (error) {
			proxy_error("Error on %s : %s\n", query, error);
			goto __end_monitor_replication_lag_loop;
		} else {
			if (resultset->rows_count==0) {
				goto __end_monitor_replication_lag_loop;
			}
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
			SAFE_SQLITE3_STEP2(statement);
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
		threads[i]->start(64,false);
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
	pthread_t monitor_group_replication_thread;
	pthread_create(&monitor_group_replication_thread, &attr, &monitor_group_replication_pthread,NULL);
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
				threads_aux[i]->start(64,false);
			}
			for (int i=0; i<qsize; i++) {
				threads_aux[i]->join();
				delete threads_aux[i];
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
		delete threads[i];
	}
	free(threads);
	pthread_join(monitor_connect_thread,NULL);
	pthread_join(monitor_ping_thread,NULL);
	pthread_join(monitor_read_only_thread,NULL);
	pthread_join(monitor_group_replication_thread,NULL);
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


MyGR_monitor_node::MyGR_monitor_node(char *_a, int _p, int _whg) {
	addr=NULL;
	if (_a) {
		addr=strdup(_a);
	}
	port=_p;
	idx_last_entry=-1;
	writer_hostgroup=_whg;
	int i;
	for (i=0;i<MyGR_Nentries;i++) {
		last_entries[i].error=NULL;
		last_entries[i].start_time=0;
	}
}

MyGR_monitor_node::~MyGR_monitor_node() {
	if (addr) {
		free(addr);
	}
}

// return true if status changed
bool MyGR_monitor_node::add_entry(unsigned long long _st, unsigned long long _ct, long long _tb, bool _pp, bool _ro, char *_error) {
	bool ret=false;
	if (idx_last_entry==-1) ret=true;
	int prev_last_entry=idx_last_entry;
	idx_last_entry++;
	if (idx_last_entry>=MyGR_Nentries) {
		idx_last_entry=0;
	}
	last_entries[idx_last_entry].start_time=_st;
	last_entries[idx_last_entry].check_time=_ct;
	last_entries[idx_last_entry].transactions_behind=_tb;
	last_entries[idx_last_entry].primary_partition=_pp;
	last_entries[idx_last_entry].read_only=_ro;
	if (last_entries[idx_last_entry].error) {
		free(last_entries[idx_last_entry].error);
		last_entries[idx_last_entry].error=NULL;
	}
	if (_error) {
		last_entries[idx_last_entry].error=strdup(_error);	// we always copy
	}
	if (ret==false) {
		if (last_entries[idx_last_entry].primary_partition != last_entries[prev_last_entry].primary_partition) {
			ret=true;
		}
		if (last_entries[idx_last_entry].read_only != last_entries[prev_last_entry].read_only) {
			ret=true;
		}
		if (
			(last_entries[idx_last_entry].error && last_entries[prev_last_entry].error==NULL)
			||
			(last_entries[idx_last_entry].error==NULL && last_entries[prev_last_entry].error)
			||
			(last_entries[idx_last_entry].error && last_entries[prev_last_entry].error && strcmp(last_entries[idx_last_entry].error,last_entries[prev_last_entry].error))
		) {
			ret=true;
		}
	}
	return ret;
}

void MySQL_Monitor::populate_monitor_mysql_server_group_replication_log() {
	sqlite3 *mondb=monitordb->get_db();
	int rc;
	//char *query=NULL;
	char *query1=NULL;
	query1=(char *)"INSERT INTO mysql_server_group_replication_log VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)";
	sqlite3_stmt *statement1=NULL;
	pthread_mutex_lock(&GloMyMon->group_replication_mutex);
	rc=sqlite3_prepare_v2(mondb, query1, -1, &statement1, 0);
	assert(rc==SQLITE_OK);
	monitordb->execute((char *)"DELETE FROM mysql_server_group_replication_log");
	std::map<std::string, MyGR_monitor_node *>::iterator it2;
	MyGR_monitor_node *node=NULL;
	for (it2=GloMyMon->Group_Replication_Hosts_Map.begin(); it2!=GloMyMon->Group_Replication_Hosts_Map.end(); ++it2) {
		std::string s=it2->first;
		node=it2->second;
		std::size_t found=s.find_last_of(":");
		std::string host=s.substr(0,found);
		std::string port=s.substr(found+1);
		int i;
		for (i=0; i<MyGR_Nentries; i++) {
			if (node->last_entries[i].start_time) {
				rc=sqlite3_bind_text(statement1, 1, host.c_str(), -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 2, atoi(port.c_str())); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 3, node->last_entries[i].start_time ); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 4, node->last_entries[i].check_time ); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 5, ( node->last_entries[i].primary_partition ? (char *)"YES" : (char *)"NO" ) , -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 6, ( node->last_entries[i].read_only ? (char *)"YES" : (char *)"NO" ) , -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 7, node->last_entries[i].transactions_behind ); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 8, node->last_entries[i].error , -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				SAFE_SQLITE3_STEP2(statement1);
				rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
				rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);
			}
		}
	}
	pthread_mutex_unlock(&GloMyMon->group_replication_mutex);
}
