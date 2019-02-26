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
#define MYSQL_MONITOR_VERSION "2.0.1226" DEB

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
VALGRIND_DISABLE_ERROR_REPORTING;
			WorkItem* item = (WorkItem*)m_queue.remove();
VALGRIND_ENABLE_ERROR_REPORTING;
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
	while (GloMTH==NULL) {
		usleep(50000);
	}
	usleep(100000);
	GloMyMon->monitor_connect();
	return NULL;
}

void * monitor_ping_pthread(void *arg) {
#ifndef NOJEM
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	while (GloMTH==NULL) {
		usleep(50000);
	}
	usleep(100000);
	GloMyMon->monitor_ping();
	return NULL;
}

void * monitor_read_only_pthread(void *arg) {
#ifndef NOJEM
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	while (GloMTH==NULL) {
		usleep(50000);
	}
	usleep(100000);
	GloMyMon->monitor_read_only();
	return NULL;
}

void * monitor_group_replication_pthread(void *arg) {
#ifndef NOJEM
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	while (GloMTH==NULL) {
		usleep(50000);
	}
	usleep(100000);
	GloMyMon->monitor_group_replication();
	return NULL;
}

void * monitor_galera_pthread(void *arg) {
#ifndef NOJEM
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	while (GloMTH==NULL) {
		usleep(50000);
	}
	usleep(100000);
	GloMyMon->monitor_galera();
	return NULL;
}

void * monitor_aws_aurora_pthread(void *arg) {
//#ifndef NOJEM
//	bool cache=false;
//	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
//#endif
	while (GloMTH==NULL) {
		usleep(50000);
	}
	usleep(100000);
	GloMyMon->monitor_aws_aurora();
	return NULL;
}

void * monitor_replication_lag_pthread(void *arg) {
#ifndef NOJEM
	bool cache=false;
	mallctl("thread.tcache.enabled", NULL, NULL, &cache, sizeof(bool));
#endif
	while (GloMTH==NULL) {
		usleep(50000);
	}
	usleep(100000);
	GloMyMon->monitor_replication_lag();
	return NULL;
}

MySQL_Monitor::MySQL_Monitor() {

	GloMyMon = this;

	My_Conn_Pool=new MySQL_Monitor_Connection_Pool();

	pthread_mutex_init(&group_replication_mutex,NULL);
	Group_Replication_Hosts_resultset=NULL;

	pthread_mutex_init(&galera_mutex,NULL);
	Galera_Hosts_resultset=NULL;

	pthread_mutex_init(&aws_aurora_mutex,NULL);
	AWS_Aurora_Hosts_resultset=NULL;
	AWS_Aurora_Hosts_resultset_checksum = 0;
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
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_galera_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_GALERA_LOG);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_aws_aurora_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_LOG);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_aws_aurora_check_status", MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_CHECK_STATUS);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_aws_aurora_failovers", MONITOR_SQLITE_TABLE_MYSQL_SERVER_AWS_AURORA_FAILOVERS);
	// create monitoring tables
	check_and_build_standard_tables(monitordb, tables_defs_monitor);
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_connect_log_time_start ON mysql_server_connect_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_ping_log_time_start ON mysql_server_ping_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_read_only_log_time_start ON mysql_server_read_only_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_replication_lag_log_time_start ON mysql_server_replication_lag_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_group_replication_log_time_start ON mysql_server_group_replication_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_galera_log_time_start ON mysql_server_galera_log (time_start_us)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_aws_aurora_log_time_start ON mysql_server_aws_aurora_log (time_start_us)");

	num_threads=2;
	aux_threads=0;
	started_threads=0;

	connect_check_OK = 0;
	connect_check_ERR = 0;
	ping_check_OK = 0;
	ping_check_ERR = 0;
	read_only_check_OK = 0;
	read_only_check_ERR = 0;
	replication_lag_check_OK = 0;
	replication_lag_check_ERR = 0;



/*
	if (GloMTH) {
		if (GloMTH->num_threads) {
			num_threads=GloMTH->num_threads*2;
		}
	}
	if (num_threads>16) {
		num_threads=16;	// limit to 16
	}
*/
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
	if (Galera_Hosts_resultset) {
		delete Galera_Hosts_resultset;
		Galera_Hosts_resultset=NULL;
	}
	if (AWS_Aurora_Hosts_resultset) {
		delete AWS_Aurora_Hosts_resultset;
		AWS_Aurora_Hosts_resultset=NULL;
	}
	std::map<std::string, AWS_Aurora_monitor_node *>::iterator it2;
	AWS_Aurora_monitor_node *node=NULL;
	for (it2 = AWS_Aurora_Hosts_Map.begin(); it2 != AWS_Aurora_Hosts_Map.end(); ++it2) {
		node = it2->second;
		delete node;
	}
	AWS_Aurora_Hosts_Map.clear();
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
	if (!GloMTH) return NULL;	// quick exit during shutdown/restart
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	mysql_thr->refresh_variables();

	bool connect_success = false;
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
		if (
			(strncmp(mmsd->mysql_error_msg,"Access denied for user",strlen("Access denied for user"))==0)
			||
			(strncmp(mmsd->mysql_error_msg,"ProxySQL Error: Access denied for user",strlen("ProxySQL Error: Access denied for user"))==0)
		) {
			proxy_error("Server %s:%d is returning \"Access denied\" for monitoring user\n", mmsd->hostname, mmsd->port);
		}
	} else {
		connect_success = true;
	}
	mysql_close(mmsd->mysql);
	mmsd->mysql=NULL;
	if (connect_success) {
		__sync_fetch_and_add(&GloMyMon->connect_check_OK,1);
	} else {
		__sync_fetch_and_add(&GloMyMon->connect_check_ERR,1);
	}
	delete mysql_thr;
	return NULL;
}

void * monitor_ping_thread(void *arg) {
	MySQL_Monitor_State_Data *mmsd=(MySQL_Monitor_State_Data *)arg;
	if (!GloMTH) return NULL;	// quick exit during shutdown/restart
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	mysql_thr->refresh_variables();

	bool ping_success = false;
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
	mmsd->interr=0; // reset the value
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
#ifdef TEST_AURORA
//		if ((rand() % 10) ==0) {
#endif // TEST_AURORA
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
		if (mmsd->mysql_error_msg == NULL) {
			ping_success = true;
		}
#ifdef TEST_AURORA
//		}
#endif // TEST_AURORA
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
	if (ping_success) {
		__sync_fetch_and_add(&GloMyMon->ping_check_OK,1);
	} else {
		__sync_fetch_and_add(&GloMyMon->ping_check_ERR,1);
	}
	delete mysql_thr;
	return NULL;
}

bool MySQL_Monitor_State_Data::set_wait_timeout() {
	if (mysql_thread___monitor_wait_timeout==false) {
		return true;
	}
#ifdef TEST_AURORA
	return true;
#endif // TEST_AURORA
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
	bool timeout_reached = false;
	MySQL_Monitor_State_Data *mmsd=(MySQL_Monitor_State_Data *)arg;
	if (!GloMTH) return NULL;	// quick exit during shutdown/restart
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	mysql_thr->refresh_variables();

	mmsd->mysql=GloMyMon->My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port);
	unsigned long long start_time=mysql_thr->curtime;

	bool read_only_success = false;
	mmsd->t1=start_time;

	bool crc=false;
	if (mmsd->mysql==NULL) { // we don't have a connection, let's create it
		bool rc;
		rc=mmsd->create_new_connection();
		crc=true;
		if (rc==false) {
			unsigned long long now=monotonic_time();
			char * new_error = (char *)malloc(50+strlen(mmsd->mysql_error_msg));
			sprintf(new_error,"timeout on creating new connection: %s",mmsd->mysql_error_msg);
			free(mmsd->mysql_error_msg);
			mmsd->mysql_error_msg = new_error;
			proxy_error("Timeout on read_only check for %s:%d after %lldms. Unable to create a connection. If the server is overload, increase mysql-monitor_connect_timeout. Error: %s.\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000, new_error);
			timeout_reached = true;
			goto __exit_monitor_read_only_thread;
			//goto __fast_exit_monitor_read_only_thread;
		}
	}

	mmsd->t1=monotonic_time();
	mmsd->interr=0; // reset the value
	if (mmsd->task_id == MON_INNODB_READ_ONLY) {
		mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,"SELECT @@global.innodb_read_only");
	} else {
		if (mmsd->task_id == MON_SUPER_READ_ONLY) {
			mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,"SELECT @@global.super_read_only");
		} else {
			mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,"SELECT @@global.read_only");
		}
	}
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > mmsd->t1 + mysql_thread___monitor_read_only_timeout * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			proxy_error("Timeout on read_only check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_read_only_timeout.\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
			timeout_reached = true;
			goto __exit_monitor_read_only_thread;
		}
		if (mmsd->interr) {
			// error during query
			mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
			goto __exit_monitor_read_only_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_read_only_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_query_cont(&mmsd->interr, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) {
		// error during query
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
		goto __exit_monitor_read_only_thread;
	}
	mmsd->async_exit_status=mysql_store_result_start(&mmsd->result,mmsd->mysql);
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > mmsd->t1 + mysql_thread___monitor_read_only_timeout * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			proxy_error("Timeout on read_only check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_read_only_timeout.\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
			timeout_reached = true;
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
		if (mmsd->interr == 0 && mmsd->result) {
			int num_fields=0;
			int k=0;
			MYSQL_FIELD *fields=NULL;
			int j=-1;
			num_fields = mysql_num_fields(mmsd->result);
			fields = mysql_fetch_fields(mmsd->result);
			for(k = 0; k < num_fields; k++) {
 				if (strcmp((char *)"@@global.innodb_read_only", (char *)fields[k].name)==0 || strcmp((char *)"@@global.super_read_only", (char *)fields[k].name)==0 || strcmp((char *)"@@global.read_only", (char *)fields[k].name)==0) {
					j=k;
				}
			}
			if (j>-1) {
				MYSQL_ROW row=mysql_fetch_row(mmsd->result);
				if (row) {
VALGRIND_DISABLE_ERROR_REPORTING;
					if (row[j]) {
						if (!strcmp(row[j],"0") || !strcasecmp(row[j],"OFF"))
							read_only=0;
					}
VALGRIND_ENABLE_ERROR_REPORTING;
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
		if (mmsd->result) {
			// make sure it is clear
			mysql_free_result(mmsd->result);
			mmsd->result=NULL;
		}
		rc=sqlite3_bind_text(statement, 6, mmsd->mysql_error_msg, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
		SAFE_SQLITE3_STEP2(statement);
		rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
		rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
		sqlite3_finalize(statement);

		if (mmsd->mysql_error_msg == NULL) {
			read_only_success = true;
		}

		if (timeout_reached == false && mmsd->interr == 0) {
			MyHGM->read_only_action(mmsd->hostname, mmsd->port, read_only); // default behavior
		} else {
			char *error=NULL;
			int cols=0;
			int affected_rows=0;
			SQLite3_result *resultset=NULL;
			char *new_query=NULL;
			SQLite3DB *mondb=mmsd->mondb;
			new_query=(char *)"SELECT 1 FROM (SELECT hostname,port,read_only,error FROM mysql_server_read_only_log WHERE hostname='%s' AND port='%d' ORDER BY time_start_us DESC LIMIT %d) a WHERE read_only IS NULL AND SUBSTR(error,1,7) = 'timeout' GROUP BY hostname,port HAVING COUNT(*)=%d";
			char *buff=(char *)malloc(strlen(new_query)+strlen(mmsd->hostname)+32);
			int max_failures=mysql_thread___monitor_read_only_max_timeout_count;
			sprintf(buff,new_query, mmsd->hostname, mmsd->port, max_failures, max_failures);
			mondb->execute_statement(buff, &error , &cols , &affected_rows , &resultset);
			if (!error) {
				if (resultset) {
					if (resultset->rows_count) {
						// disable host
						proxy_error("Server %s:%d missed %d read_only checks. Assuming read_only=1\n", mmsd->hostname, mmsd->port, max_failures);
						MyHGM->read_only_action(mmsd->hostname, mmsd->port, read_only); // N timeouts reached
					}
					delete resultset;
					resultset=NULL;
				}
			} else {
				proxy_error("Error on %s : %s\n", buff, error);
			}
			free(buff);
		}
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
	if (read_only_success) {
		__sync_fetch_and_add(&GloMyMon->read_only_check_OK,1);
	} else {
		__sync_fetch_and_add(&GloMyMon->read_only_check_ERR,1);
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
	mmsd->interr=0; // reset the value
	mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,"SELECT viable_candidate,read_only,transactions_behind FROM sys.gr_member_routing_candidate_status");
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > mmsd->t1 + mysql_thread___monitor_groupreplication_healthcheck_timeout * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			proxy_error("Timeout on group replication health check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_groupreplication_healthcheck_timeout. Assuming viable_candidate=nO and read_only=YES\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
			goto __exit_monitor_group_replication_thread;
		}
		if (mmsd->interr) {
			// error during query
			mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
			goto __exit_monitor_group_replication_thread;
		}

		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_group_replication_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_query_cont(&mmsd->interr, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) {
		// error during query
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
		goto __exit_monitor_group_replication_thread;
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
		if (mmsd->interr == 0 && mmsd->result) {
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
		if (mmsd->result) {
			// make sure it is clear
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

void * monitor_galera_thread(void *arg) {
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
			unsigned long long now=monotonic_time();
			char * new_error = (char *)malloc(50+strlen(mmsd->mysql_error_msg));
			sprintf(new_error,"timeout or error in creating new connection: %s",mmsd->mysql_error_msg);
			free(mmsd->mysql_error_msg);
			mmsd->mysql_error_msg = new_error;
			proxy_error("Error on Galera check for %s:%d after %lldms. Unable to create a connection. If the server is overload, increase mysql-monitor_connect_timeout. Error: %s.\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000, new_error);
			goto __exit_monitor_galera_thread;
		}
	}

	mmsd->t1=monotonic_time();
	mmsd->interr=0; // reset the value
	{
		char *sv = mmsd->mysql->server_version;
		if (strncmp(sv,(char *)"5.7",3)==0 || strncmp(sv,(char *)"8",1)==0) {
			// the backend is either MySQL 5.7 or MySQL 8 : INFORMATION_SCHEMA.GLOBAL_STATUS is deprecated
	mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,"SELECT (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='WSREP_LOCAL_STATE') wsrep_local_state, @@read_only read_only, (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='WSREP_LOCAL_RECV_QUEUE') wsrep_local_recv_queue , @@wsrep_desync wsrep_desync, @@wsrep_reject_queries wsrep_reject_queries, @@wsrep_sst_donor_rejects_queries wsrep_sst_donor_rejects_queries, (SELECT VARIABLE_VALUE FROM performance_schema.global_status WHERE VARIABLE_NAME='WSREP_CLUSTER_STATUS') wsrep_cluster_status");
		} else {
			// any other version
			mmsd->async_exit_status=mysql_query_start(&mmsd->interr,mmsd->mysql,"SELECT (SELECT VARIABLE_VALUE FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME='WSREP_LOCAL_STATE') wsrep_local_state, @@read_only read_only, (SELECT VARIABLE_VALUE FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME='WSREP_LOCAL_RECV_QUEUE') wsrep_local_recv_queue , @@wsrep_desync wsrep_desync, @@wsrep_reject_queries wsrep_reject_queries, @@wsrep_sst_donor_rejects_queries wsrep_sst_donor_rejects_queries, (SELECT VARIABLE_VALUE FROM INFORMATION_SCHEMA.GLOBAL_STATUS WHERE VARIABLE_NAME='WSREP_CLUSTER_STATUS') wsrep_cluster_status");
		}
	}
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > mmsd->t1 + mysql_thread___monitor_galera_healthcheck_timeout * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			proxy_error("Timeout on Galera health check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_galera_healthcheck_timeout. Assuming wsrep_cluster_status	 is NOT Primary\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
			goto __exit_monitor_galera_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_galera_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_query_cont(&mmsd->interr, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	mmsd->async_exit_status=mysql_store_result_start(&mmsd->result,mmsd->mysql);
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > mmsd->t1 + mysql_thread___monitor_galera_healthcheck_timeout * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			proxy_error("Timeout on Galera health check for %s:%d after %lldms. If the server is overload, increase mysql-monitor_galera_healthcheck_timeout. Assuming wsrep_local_state is NOT 4 and read_only=YES\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
			goto __exit_monitor_galera_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_galera_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_store_result_cont(&mmsd->result, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) { // ping failed
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
	}

__exit_monitor_galera_thread:
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
		bool primary_partition = false;
		bool read_only=true;
		bool wsrep_desync = true;
		int wsrep_local_state = 0;
		bool wsrep_reject_queries = true;
		bool wsrep_sst_donor_rejects_queries = true;
		long long wsrep_local_recv_queue=0;
		if (mmsd->interr == 0 && mmsd->result) {
			int num_fields=0;
			int num_rows=0;
			num_fields = mysql_num_fields(mmsd->result);
			if (num_fields!=7) {
				proxy_error("Incorrect number of fields, please report a bug\n");
				goto __end_process_galera_result;
			}
			num_rows = mysql_num_rows(mmsd->result);
			if (num_rows!=1) {
				proxy_error("Incorrect number of rows, please report a bug\n");
				goto __end_process_galera_result;
			}
			MYSQL_ROW row=mysql_fetch_row(mmsd->result);
			if (row[0]) {
				wsrep_local_state = atoi(row[0]);
			}
			if (row[1]) {
				if (!strcasecmp(row[1],"NO") || !strcasecmp(row[1],"OFF") || !strcasecmp(row[1],"0")) {
					read_only=false;
				}
			}
			if (row[2]) {
				wsrep_local_recv_queue = atoll(row[2]);
			}
			if (row[3]) {
				if (!strcasecmp(row[3],"NO") || !strcasecmp(row[3],"OFF") || !strcasecmp(row[3],"0")) {
					wsrep_desync = false;
				}
			}
			if (row[4]) {
				if (!strcasecmp(row[4],"NONE")) {
					wsrep_reject_queries = false;
				}
			}
			if (row[5]) {
				if (!strcasecmp(row[5],"NO") || !strcasecmp(row[5],"OFF") || !strcasecmp(row[5],"0")) {
					wsrep_sst_donor_rejects_queries = false;
				}
			}
			if (row[6]) {
				if (!strcasecmp(row[6],"Primary")) {
					primary_partition = true;
				}
			}
			mysql_free_result(mmsd->result);
			mmsd->result=NULL;
		}
__end_process_galera_result:
		if (mmsd->mysql_error_msg) {
		}
		unsigned long long time_now=realtime_time();
		time_now=time_now-(mmsd->t2 - start_time);
		pthread_mutex_lock(&GloMyMon->galera_mutex);
		//auto it = 
		// TODO : complete this
		std::map<std::string, Galera_monitor_node *>::iterator it2;
		it2 = GloMyMon->Galera_Hosts_Map.find(s);
		Galera_monitor_node *node=NULL;
		if (it2!=GloMyMon->Galera_Hosts_Map.end()) {
			node=it2->second;
			//node->add_entry(time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1) , transactions_behind,viable_candidate,read_only,mmsd->mysql_error_msg);
			node->add_entry(time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1) , wsrep_local_recv_queue, primary_partition, read_only, wsrep_local_state, wsrep_desync, wsrep_reject_queries, wsrep_sst_donor_rejects_queries, mmsd->mysql_error_msg);
		} else {
			node = new Galera_monitor_node(mmsd->hostname,mmsd->port,mmsd->writer_hostgroup);
			//node->add_entry(time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1) , transactions_behind,viable_candidate,read_only,mmsd->mysql_error_msg);
			node->add_entry(time_now, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1) , wsrep_local_recv_queue, primary_partition, read_only, wsrep_local_state, wsrep_desync, wsrep_reject_queries, wsrep_sst_donor_rejects_queries, mmsd->mysql_error_msg);
			GloMyMon->Galera_Hosts_Map.insert(std::make_pair(s,node));
		}
		pthread_mutex_unlock(&GloMyMon->galera_mutex);

		// NOTE: we update MyHGM outside the mutex galera_mutex
		if (mmsd->mysql_error_msg) { // there was an error checking the status of the server, surely we need to reconfigure GR
			MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, mmsd->mysql_error_msg);
		} else {
			if (primary_partition == false || wsrep_desync == true || wsrep_local_state!=4) {
				if (primary_partition == false) {
					MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"primary_partition=NO");
				} else {
					if (wsrep_desync == true) {
						MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"wsrep_desync=YES");
					} else {
						char msg[80];
						sprintf(msg,"wsrep_local_state=%d",wsrep_local_state);
						MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, msg);
					}
				}
			} else {
				//if (wsrep_sst_donor_rejects_queries || wsrep_reject_queries) {
					if (wsrep_reject_queries) {
						MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"wsrep_reject_queries=true");
				//	} else {
				//		// wsrep_sst_donor_rejects_queries
				//		MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"wsrep_sst_donor_rejects_queries=true");
				//	}
				} else {
					if (read_only==true) {
						if (wsrep_local_recv_queue > mmsd->max_transactions_behind) {
							MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"slave is lagging");
						} else {
							MyHGM->update_galera_set_read_only(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"read_only=YES");
						}
					} else {
						// the node is a writer
						// TODO: for now we don't care about the number of writers
						MyHGM->update_galera_set_writer(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup);
					}
				}
			}
		}

		// clean up
		if (l<110) {
		} else {
			free(s);
		}
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
__fast_exit_monitor_galera_thread:
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
	if (!GloMTH) return NULL;	// quick exit during shutdown/restart
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	mysql_thr->refresh_variables();

	mmsd->mysql=GloMyMon->My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port);
	unsigned long long start_time=mysql_thr->curtime;

	bool replication_lag_success = false;

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
	mmsd->interr=0; // reset the value
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
			if (mmsd->mysql_error_msg == NULL) {
				replication_lag_success = true;
			}

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
	if (replication_lag_success) {
		__sync_fetch_and_add(&GloMyMon->replication_lag_check_OK,1);
	} else {
		__sync_fetch_and_add(&GloMyMon->replication_lag_check_ERR,1);
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
		char *query=(char *)"SELECT hostname, port, MAX(use_ssl) use_ssl FROM mysql_servers GROUP BY hostname, port ORDER BY RANDOM()";
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
				us*=40;
				if (us > 1000000) {
					us = 10000;
				}
				us = us + rand()%us;
				if (resultset->rows_count==1) {
					// only 1 server, sleep also before creating the job
					usleep(us);
				}
			}
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				bool rc_ping = true;
				rc_ping = server_responds_to_ping(r->fields[0],atoi(r->fields[1]));
				if (rc_ping) { // only if server is responding to pings
					MySQL_Monitor_State_Data *mmsd=new MySQL_Monitor_State_Data(r->fields[0],atoi(r->fields[1]), NULL, atoi(r->fields[2]));
					mmsd->mondb=monitordb;
					WorkItem* item;
					item=new WorkItem(mmsd,monitor_connect_thread);
					GloMyMon->queue.add(item);
					usleep(us);
				}
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
		char *query=(char *)"SELECT hostname, port, MAX(use_ssl) use_ssl FROM mysql_servers WHERE status NOT LIKE 'OFFLINE\%' GROUP BY hostname, port ORDER BY RANDOM()";
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
				us*=40;
				if (us > 1000000) {
					us = 10000;
				}
				us = us + rand()%us;
				if (resultset->rows_count==1) {
					// only 1 server, sleep also before creating the job
					usleep(us);
				}
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
			new_query=(char *)"SELECT 1 FROM (SELECT hostname,port,ping_error FROM mysql_server_ping_log WHERE hostname='%s' AND port='%s' ORDER BY time_start_us DESC LIMIT %d) a WHERE ping_error IS NOT NULL AND ping_error NOT LIKE 'Access denied for user%%' AND ping_error NOT LIKE 'ProxySQL Error: Access denied for user%%' GROUP BY hostname,port HAVING COUNT(*)=%d";
			for (j=0;j<i;j++) {
				char *buff=(char *)malloc(strlen(new_query)+strlen(addresses[j])+strlen(ports[j])+16);
				int max_failures=mysql_thread___monitor_ping_max_failures;
				sprintf(buff,new_query,addresses[j],ports[j],max_failures,max_failures);
				monitordb->execute_statement(buff, &error , &cols , &affected_rows , &resultset);
				if (!error) {
					if (resultset) {
						if (resultset->rows_count) {
							// disable host
							bool rc_shun = false;
							rc_shun = MyHGM->shun_and_killall(addresses[j],atoi(ports[j]));
							if (rc_shun) {
								proxy_error("Server %s:%s missed %d heartbeats, shunning it and killing all the connections. Disabling other checks until the node comes back online.\n", addresses[j], ports[j], max_failures);
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



bool MySQL_Monitor::server_responds_to_ping(char *address, int port) {
	bool ret = true; // default
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *new_query=NULL;
	new_query=(char *)"SELECT 1 FROM (SELECT hostname,port,ping_error FROM mysql_server_ping_log WHERE hostname='%s' AND port=%d ORDER BY time_start_us DESC LIMIT %d) a WHERE ping_error IS NOT NULL AND ping_error NOT LIKE 'Access denied for user%%' GROUP BY hostname,port HAVING COUNT(*)=%d";
	char *buff=(char *)malloc(strlen(new_query)+strlen(address)+32);
	int max_failures = mysql_thread___monitor_ping_max_failures;
	sprintf(buff,new_query,address,port,max_failures,max_failures);
	monitordb->execute_statement(buff, &error , &cols , &affected_rows , &resultset);
	if (!error) {
		if (resultset) {
			if (resultset->rows_count) {
				ret = false;
			}
			delete resultset;
			resultset=NULL;
		}
	} else {
		proxy_error("Error on %s : %s\n", buff, error);
	}
	if (resultset) {
		delete resultset;
		resultset=NULL;
	}
	free(buff);
	return ret;
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
		char *query=(char *)"SELECT hostname, port, MAX(use_ssl) use_ssl, check_type FROM mysql_servers JOIN mysql_replication_hostgroups ON hostgroup_id=writer_hostgroup OR hostgroup_id=reader_hostgroup WHERE status NOT IN (2,3) GROUP BY hostname, port ORDER BY RANDOM()";
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
				us*=40;
				if (us > 1000000) {
					us = 10000;
				}
				us = us + rand()%us;
				if (resultset->rows_count==1) {
					// only 1 server, sleep also before creating the job
					usleep(us);
				}
			}
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				bool rc_ping = true;
				rc_ping = server_responds_to_ping(r->fields[0],atoi(r->fields[1]));
				if (rc_ping) { // only if server is responding to pings
					MySQL_Monitor_State_Data *mmsd=new MySQL_Monitor_State_Data(r->fields[0],atoi(r->fields[1]), NULL, atoi(r->fields[2]));
					mmsd->task_id = MON_READ_ONLY; // default
					if (r->fields[3]) {
						if (strcasecmp(r->fields[3],(char *)"innodb_read_only")==0) {
							mmsd->task_id = MON_INNODB_READ_ONLY;
						} else if (strcasecmp(r->fields[3],(char *)"super_read_only")==0) {
							mmsd->task_id = MON_SUPER_READ_ONLY;
						}
					}
					mmsd->mondb=monitordb;
					WorkItem* item;
					item=new WorkItem(mmsd,monitor_read_only_thread);
					GloMyMon->queue.add(item);
					usleep(us);
				}
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
			if (mysql_thread___monitor_history < mysql_thread___monitor_read_only_interval * (mysql_thread___monitor_read_only_max_timeout_count + 1 )) { // issue #626
				if (mysql_thread___monitor_read_only_interval < 3600000)
					mysql_thread___monitor_history = mysql_thread___monitor_read_only_interval * (mysql_thread___monitor_read_only_max_timeout_count + 1 );
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
				bool rc_ping = true;
				rc_ping = server_responds_to_ping(r->fields[1],atoi(r->fields[2]));
				if (rc_ping) { // only if server is responding to pings
					MySQL_Monitor_State_Data *mmsd=new MySQL_Monitor_State_Data(r->fields[1],atoi(r->fields[2]), NULL, atoi(r->fields[3]));
					mmsd->writer_hostgroup=atoi(r->fields[0]);
					mmsd->writer_is_also_reader=atoi(r->fields[4]);
					mmsd->max_transactions_behind=atoi(r->fields[5]);
					mmsd->mondb=monitordb;
					WorkItem* item;
					item=new WorkItem(mmsd,monitor_group_replication_thread);
					GloMyMon->queue.add(item);
					usleep(us);
				}
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
void * MySQL_Monitor::monitor_galera() {
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
		t1=monotonic_time();

		if (!GloMTH) return NULL;	// quick exit during shutdown/restart
		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			next_loop_at=0;
		}

		if (t1 < next_loop_at) {
			goto __sleep_monitor_galera;
		}
		next_loop_at=t1+1000*mysql_thread___monitor_galera_healthcheck_interval;
		pthread_mutex_lock(&galera_mutex);
		if (Galera_Hosts_resultset==NULL) {
				goto __end_monitor_galera_loop;
		} else {
			if (Galera_Hosts_resultset->rows_count==0) {
				goto __end_monitor_galera_loop;
			}
			int us=100;
			if (Galera_Hosts_resultset->rows_count) {
				us=mysql_thread___monitor_read_only_interval/2/Galera_Hosts_resultset->rows_count;
			}
			for (std::vector<SQLite3_row *>::iterator it = Galera_Hosts_resultset->rows.begin() ; it != Galera_Hosts_resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				bool rc_ping = true;
				rc_ping = server_responds_to_ping(r->fields[1],atoi(r->fields[2]));
				if (rc_ping) { // only if server is responding to pings
					MySQL_Monitor_State_Data *mmsd=new MySQL_Monitor_State_Data(r->fields[1],atoi(r->fields[2]), NULL, atoi(r->fields[3]));
					mmsd->writer_hostgroup=atoi(r->fields[0]);
					mmsd->writer_is_also_reader=atoi(r->fields[4]);
					mmsd->max_transactions_behind=atoi(r->fields[5]);
					mmsd->mondb=monitordb;
					WorkItem* item;
					item=new WorkItem(mmsd,monitor_galera_thread);
					GloMyMon->queue.add(item);
					usleep(us);
				}
				if (GloMyMon->shutdown) {
					pthread_mutex_unlock(&galera_mutex);
					return NULL;
				}
			}
		}

__end_monitor_galera_loop:
		pthread_mutex_unlock(&galera_mutex);
		if (mysql_thread___monitor_enabled==true) {
		}


__sleep_monitor_galera:
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
				bool rc_ping = true;
				rc_ping = server_responds_to_ping(r->fields[1],atoi(r->fields[2]));
				if (rc_ping) { // only if server is responding to pings
					MySQL_Monitor_State_Data *mmsd = new MySQL_Monitor_State_Data(r->fields[1], atoi(r->fields[2]), NULL, atoi(r->fields[4]), atoi(r->fields[0]));
					mmsd->mondb=monitordb;
					WorkItem* item;
					item=new WorkItem(mmsd,monitor_replication_lag_thread);
					GloMyMon->queue.add(item);
					usleep(us);
				}
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
	while (GloMTH==NULL) {
		usleep(50000);
	}
	usleep(100000);
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();
	//if (!GloMTH) return NULL;	// quick exit during shutdown/restart
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
		threads[i]->start(128,false);
	}
	started_threads += num_threads;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize (&attr, 128*1024);
	pthread_t monitor_connect_thread;
	if (pthread_create(&monitor_connect_thread, &attr, &monitor_connect_pthread,NULL) != 0) {
		proxy_error("Thread creation\n");
		assert(0);
	}
	pthread_t monitor_ping_thread;
	if (pthread_create(&monitor_ping_thread, &attr, &monitor_ping_pthread,NULL) != 0) {
		proxy_error("Thread creation\n");
		assert(0);
	}
	pthread_t monitor_read_only_thread;
	if (pthread_create(&monitor_read_only_thread, &attr, &monitor_read_only_pthread,NULL) != 0) {
		proxy_error("Thread creation\n");
		assert(0);
	}
	pthread_t monitor_group_replication_thread;
	if (pthread_create(&monitor_group_replication_thread, &attr, &monitor_group_replication_pthread,NULL) != 0) {
		proxy_error("Thread creation\n");
		assert(0);
	}
	pthread_t monitor_galera_thread;
	if (pthread_create(&monitor_galera_thread, &attr, &monitor_galera_pthread,NULL) != 0) {
		proxy_error("Thread creation\n");
		assert(0);
	}
	pthread_t monitor_aws_aurora_thread;
	if (pthread_create(&monitor_aws_aurora_thread, &attr, &monitor_aws_aurora_pthread,NULL) != 0) {
		proxy_error("Thread creation\n");
		assert(0);
	}
	pthread_t monitor_replication_lag_thread;
	if (pthread_create(&monitor_replication_lag_thread, &attr, &monitor_replication_lag_pthread,NULL) != 0) {
		proxy_error("Thread creation\n");
		assert(0);
	}
	while (shutdown==false && mysql_thread___monitor_enabled==true) {
		unsigned int glover;
		if (GloMTH) {
			glover=GloMTH->get_global_version();
			if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
				MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
				mysql_thr->refresh_variables();
				unsigned int old_num_threads = num_threads;
				unsigned int threads_min = (unsigned int)mysql_thread___monitor_threads_min;
				if (old_num_threads < threads_min) {
					num_threads = threads_min;
					threads= (ConsumerThread **)realloc(threads, sizeof(ConsumerThread *)*num_threads);
					started_threads += (num_threads - old_num_threads);
					for (unsigned int i = old_num_threads ; i < num_threads ; i++) {
						threads[i] = new ConsumerThread(queue, 0);
						threads[i]->start(128,false);
					}
				}
			}
		}
		monitor_enabled=mysql_thread___monitor_enabled;
		if ( rand()%5 == 0) { // purge once in a while
			My_Conn_Pool->purge_idle_connections();
		}
		usleep(200000);
		int qsize=queue.size();
		if (qsize > mysql_thread___monitor_threads_queue_maxsize/4) {
			proxy_warning("Monitor queue too big: %d\n", qsize);
			unsigned int threads_max = (unsigned int)mysql_thread___monitor_threads_max;
			if (threads_max > num_threads) {
				unsigned int new_threads = threads_max - num_threads;
				if ((qsize / 4) < new_threads) {
					new_threads = qsize/4; // try to not burst threads
				}
				if (new_threads) {
					unsigned int old_num_threads = num_threads;
					num_threads += new_threads;
					threads= (ConsumerThread **)realloc(threads, sizeof(ConsumerThread *)*num_threads);
					started_threads += new_threads;
					for (unsigned int i = old_num_threads ; i < num_threads ; i++) {
						threads[i] = new ConsumerThread(queue, 0);
						threads[i]->start(128,false);
					}
				}
			}
			// check again. Do we need also aux threads?
			usleep(50000);
			qsize=queue.size();
			if (qsize > mysql_thread___monitor_threads_queue_maxsize) {
				qsize=qsize/50;
				unsigned int threads_max = (unsigned int)mysql_thread___monitor_threads_max;
				if ((qsize + num_threads) > (threads_max * 2)) { // allow a small bursts
					qsize = threads_max * 2 - num_threads;
				}
				if (qsize > 0) {
					proxy_info("Monitor is starting %d helper threads\n", qsize);
					ConsumerThread **threads_aux= (ConsumerThread **)malloc(sizeof(ConsumerThread *)*qsize);
					aux_threads = qsize;
					started_threads += aux_threads;
					for (int i=0; i<qsize; i++) {
						threads_aux[i] = new ConsumerThread(queue, 245);
						threads_aux[i]->start(128,false);
					}
					for (int i=0; i<qsize; i++) {
						threads_aux[i]->join();
						delete threads_aux[i];
					}
					free(threads_aux);
					aux_threads = 0;
				}
			}
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
	pthread_join(monitor_galera_thread,NULL);
	pthread_join(monitor_aws_aurora_thread,NULL);
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


AWS_Aurora_replica_host_status_entry::AWS_Aurora_replica_host_status_entry(char *serid, char *sessid, char *lut, float rlm, float _c) {
	server_id = strdup(serid);
	session_id = strdup(sessid);
	last_update_timestamp = strdup(lut);
	replica_lag_ms = rlm;
	cpu = _c;
}

AWS_Aurora_replica_host_status_entry::AWS_Aurora_replica_host_status_entry(char *serid, char *sessid, char *lut, char *rlm, char *_c) {
	server_id = strdup(serid);
	session_id = strdup(sessid);
	last_update_timestamp = strdup(lut);
	replica_lag_ms = strtof(rlm, NULL);
	cpu = strtof(_c, NULL);
}

AWS_Aurora_replica_host_status_entry::~AWS_Aurora_replica_host_status_entry() {
	free(server_id);
	free(session_id);
	free(last_update_timestamp);
}

AWS_Aurora_status_entry::AWS_Aurora_status_entry(unsigned long long st, unsigned long long ct, char *e) {
	start_time = st;
	check_time = ct;
	error = NULL;
	if (e) {
		error = strdup(e);
	}
	host_statuses = new std::vector<AWS_Aurora_replica_host_status_entry *>;
}

AWS_Aurora_status_entry::~AWS_Aurora_status_entry() {
	if (error) {
		free(error);
	}
	AWS_Aurora_replica_host_status_entry *entry;
	for (std::vector<AWS_Aurora_replica_host_status_entry *>::iterator it = host_statuses->begin(); it != host_statuses->end(); ++it) {
		entry=*it;
		delete entry;
	}
	host_statuses->clear();
	delete host_statuses;
}

void AWS_Aurora_status_entry::add_host_status(AWS_Aurora_replica_host_status_entry *hs) {
	host_statuses->push_back(hs);
}

Galera_monitor_node::Galera_monitor_node(char *_a, int _p, int _whg) {
	addr=NULL;
	if (_a) {
		addr=strdup(_a);
	}
	port=_p;
	idx_last_entry=-1;
	writer_hostgroup=_whg;
	int i;
	for (i=0;i<Galera_Nentries;i++) {
		last_entries[i].error=NULL;
		last_entries[i].start_time=0;
	}
}

Galera_monitor_node::~Galera_monitor_node() {
	if (addr) {
		free(addr);
	}
}

// return true if status changed
bool Galera_monitor_node::add_entry(unsigned long long _st, unsigned long long _ct, long long _tb, bool _pp, bool _ro, int _local_state, bool _desync, bool _reject, bool _sst_donor_reject, char *_error) {
	bool ret=false;
	if (idx_last_entry==-1) ret=true;
	int prev_last_entry=idx_last_entry;
	idx_last_entry++;
	if (idx_last_entry>=Galera_Nentries) {
		idx_last_entry=0;
	}
	last_entries[idx_last_entry].start_time=_st;
	last_entries[idx_last_entry].check_time=_ct;
	last_entries[idx_last_entry].wsrep_local_recv_queue=_tb;
	last_entries[idx_last_entry].primary_partition=_pp;
	last_entries[idx_last_entry].read_only=_ro;
	last_entries[idx_last_entry].wsrep_local_state = _local_state;
	last_entries[idx_last_entry].wsrep_desync = _desync;
	last_entries[idx_last_entry].wsrep_reject_queries = _reject;
	last_entries[idx_last_entry].wsrep_sst_donor_rejects_queries = _sst_donor_reject;
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
	sqlite3_finalize(statement1);
	pthread_mutex_unlock(&GloMyMon->group_replication_mutex);
}

void MySQL_Monitor::populate_monitor_mysql_server_galera_log() {
	sqlite3 *mondb=monitordb->get_db();
	int rc;
	//char *query=NULL;
	char *query1=NULL;
	query1=(char *)"INSERT INTO mysql_server_galera_log VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
	sqlite3_stmt *statement1=NULL;
	pthread_mutex_lock(&GloMyMon->galera_mutex);
	rc=sqlite3_prepare_v2(mondb, query1, -1, &statement1, 0);
	assert(rc==SQLITE_OK);
	monitordb->execute((char *)"DELETE FROM mysql_server_galera_log");
	std::map<std::string, Galera_monitor_node *>::iterator it2;
	Galera_monitor_node *node=NULL;
	for (it2=GloMyMon->Galera_Hosts_Map.begin(); it2!=GloMyMon->Galera_Hosts_Map.end(); ++it2) {
		std::string s=it2->first;
		node=it2->second;
		std::size_t found=s.find_last_of(":");
		std::string host=s.substr(0,found);
		std::string port=s.substr(found+1);
		int i;
		for (i=0; i<Galera_Nentries; i++) {
			if (node->last_entries[i].start_time) {
				rc=sqlite3_bind_text(statement1, 1, host.c_str(), -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 2, atoi(port.c_str())); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 3, node->last_entries[i].start_time ); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 4, node->last_entries[i].check_time ); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 5, ( node->last_entries[i].primary_partition ? (char *)"YES" : (char *)"NO" ) , -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 6, ( node->last_entries[i].read_only ? (char *)"YES" : (char *)"NO" ) , -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 7, node->last_entries[i].wsrep_local_recv_queue ); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement1, 8, node->last_entries[i].wsrep_local_state ); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 9, ( node->last_entries[i].wsrep_desync ? (char *)"YES" : (char *)"NO" ) , -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 10, ( node->last_entries[i].wsrep_reject_queries ? (char *)"YES" : (char *)"NO" ) , -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 11, ( node->last_entries[i].wsrep_sst_donor_rejects_queries ? (char *)"YES" : (char *)"NO" ) , -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement1, 12, node->last_entries[i].error , -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				SAFE_SQLITE3_STEP2(statement1);
				rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
				rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);
			}
		}
	}
	sqlite3_finalize(statement1);
	pthread_mutex_unlock(&GloMyMon->galera_mutex);
}

char * MySQL_Monitor::galera_find_last_node(int writer_hostgroup) {
/*
	sqlite3 *mondb=monitordb->get_db();
	int rc;
	//char *query=NULL;
	char *query1=NULL;
	query1=(char *)"INSERT INTO mysql_server_galera_log VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)";
	sqlite3_stmt *statement1=NULL;
*/
	char *str = NULL;
	pthread_mutex_lock(&GloMyMon->galera_mutex);
/*
	rc=sqlite3_prepare_v2(mondb, query1, -1, &statement1, 0);
	assert(rc==SQLITE_OK);
	monitordb->execute((char *)"DELETE FROM mysql_server_galera_log");
*/
	std::map<std::string, Galera_monitor_node *>::iterator it2;
	Galera_monitor_node *node=NULL;
	Galera_monitor_node *writer_node=NULL;
	unsigned int writer_nodes = 0;
	unsigned long long curtime = monotonic_time();
	unsigned long long ti = mysql_thread___monitor_galera_healthcheck_interval;
	ti *= 2;
	std::string s = "";
	for (it2=GloMyMon->Galera_Hosts_Map.begin(); it2!=GloMyMon->Galera_Hosts_Map.end(); ++it2) {
		node=it2->second;
		if (node->writer_hostgroup == writer_hostgroup) {
			Galera_status_entry_t * st = node->last_entry();
			if (st) {
				if (st->start_time >= curtime - ti) { // only consider recent checks
					if (st->error == NULL) { // no check error
						if (st->read_only == false) { // the server is writable (this check is arguable)
							if (st->wsrep_sst_donor_rejects_queries == false) {
								if (writer_nodes == 0) {
									s=it2->first;
									writer_node = node;
								}
								writer_nodes++;
							}
						}
					}
				}
			}
		}
	}
	if (writer_node && writer_nodes == 1) {
		// we have only one node let
		// we don't care if status
		str = strdup(s.c_str());
/*
		std::size_t found=s.find_last_of(":");
		std::string host=s.substr(0,found);
		std::string port=s.substr(found+1);
*/
	}
	pthread_mutex_unlock(&GloMyMon->galera_mutex);
	return str;
}

std::vector<string> * MySQL_Monitor::galera_find_possible_last_nodes(int writer_hostgroup) {
	std::vector<string> * result = new std::vector<string>();
	pthread_mutex_lock(&GloMyMon->galera_mutex);
	std::map<std::string, Galera_monitor_node *>::iterator it2;
	Galera_monitor_node *node=NULL;
	unsigned long long curtime = monotonic_time();
	unsigned long long ti = mysql_thread___monitor_galera_healthcheck_interval;
	ti *= 2;
	for (it2=GloMyMon->Galera_Hosts_Map.begin(); it2!=GloMyMon->Galera_Hosts_Map.end(); ++it2) {
		node=it2->second;
		if (node->writer_hostgroup == writer_hostgroup) {
			Galera_status_entry_t * st = node->last_entry();
			if (st) {
				if (st->start_time >= curtime - ti) { // only consider recent checks
					if (st->error == NULL) { // no check error
						if (st->wsrep_reject_queries == false) {
							if (st->read_only == false) { // the server is writable (this check is arguable)
								if (st->wsrep_sst_donor_rejects_queries == false) {
									string s = it2->first;
									result->push_back(s);
								}
							}
						}
					}
				}
			}
		}
	}
	pthread_mutex_unlock(&GloMyMon->galera_mutex);
	return result;
}

void MySQL_Monitor::populate_monitor_mysql_server_aws_aurora_log() {
	sqlite3 *mondb=monitordb->get_db();
	int rc;
	//char *query=NULL;
	char *query1=NULL;
	query1=(char *)"INSERT OR IGNORE INTO mysql_server_aws_aurora_log VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
	sqlite3_stmt *statement1=NULL;
	char *query2=NULL;
	query2=(char *)"INSERT OR IGNORE INTO mysql_server_aws_aurora_log (hostname, port, time_start_us, success_time_us, error) VALUES (?1, ?2, ?3, ?4, ?5)";
	sqlite3_stmt *statement2=NULL;
	rc=sqlite3_prepare_v2(mondb, query1, -1, &statement1, 0);
	assert(rc==SQLITE_OK);
	rc=sqlite3_prepare_v2(mondb, query2, -1, &statement2, 0);
	assert(rc==SQLITE_OK);
	pthread_mutex_lock(&GloMyMon->aws_aurora_mutex);
	monitordb->execute((char *)"DELETE FROM mysql_server_aws_aurora_log");
	std::map<std::string, AWS_Aurora_monitor_node *>::iterator it2;
	AWS_Aurora_monitor_node *node=NULL;
	for (it2=GloMyMon->AWS_Aurora_Hosts_Map.begin(); it2!=GloMyMon->AWS_Aurora_Hosts_Map.end(); ++it2) {
		std::string s=it2->first;
		node=it2->second;
		std::size_t found=s.find_last_of(":");
		std::string host=s.substr(0,found);
		std::string port=s.substr(found+1);
		int i;
		for (i=0; i<AWS_Aurora_Nentries; i++) {
			AWS_Aurora_status_entry * aase = node->last_entries[i];
			if (aase && aase->start_time) {
				if ( aase->host_statuses->size() ) {
					for (std::vector<AWS_Aurora_replica_host_status_entry *>::iterator it3 = aase->host_statuses->begin(); it3!=aase->host_statuses->end(); ++it3) {
						AWS_Aurora_replica_host_status_entry *hse = *it3;
						if (hse) {
							rc=sqlite3_bind_text(statement1, 1, host.c_str(), -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
							rc=sqlite3_bind_int64(statement1, 2, atoi(port.c_str())); assert(rc==SQLITE_OK);
							rc=sqlite3_bind_int64(statement1, 3, aase->start_time ); assert(rc==SQLITE_OK);
							rc=sqlite3_bind_int64(statement1, 4, aase->check_time ); assert(rc==SQLITE_OK);
							rc=sqlite3_bind_text(statement1, 5, aase->error , -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
							rc=sqlite3_bind_text(statement1, 6, hse->server_id , -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
							rc=sqlite3_bind_text(statement1, 7, hse->session_id , -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
							rc=sqlite3_bind_text(statement1, 8, hse->last_update_timestamp , -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
							rc=sqlite3_bind_double(statement1, 9, hse->replica_lag_ms ); assert(rc==SQLITE_OK);
							rc=sqlite3_bind_double(statement1, 10, hse->cpu ); assert(rc==SQLITE_OK);
							SAFE_SQLITE3_STEP2(statement1);
							rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
							rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);
						}
					}
				} else {
					rc=sqlite3_bind_text(statement2, 1, host.c_str(), -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement2, 2, atoi(port.c_str())); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement2, 3, aase->start_time ); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement2, 4, aase->check_time ); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_text(statement2, 5, aase->error , -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
					SAFE_SQLITE3_STEP2(statement2);
					rc=sqlite3_clear_bindings(statement2); assert(rc==SQLITE_OK);
					rc=sqlite3_reset(statement2); assert(rc==SQLITE_OK);
				}
			}
		}
	}
	sqlite3_finalize(statement1);
	sqlite3_finalize(statement2);
	pthread_mutex_unlock(&GloMyMon->aws_aurora_mutex);
}

void MySQL_Monitor::populate_monitor_mysql_server_aws_aurora_check_status() {
	sqlite3 *mondb=monitordb->get_db();
	int rc;
	//char *query=NULL;
	char *query1=NULL;
	query1=(char *)"INSERT OR IGNORE INTO mysql_server_aws_aurora_check_status VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)";
	sqlite3_stmt *statement1=NULL;
	rc=sqlite3_prepare_v2(mondb, query1, -1, &statement1, 0);
	assert(rc==SQLITE_OK);
	pthread_mutex_lock(&GloMyMon->aws_aurora_mutex);
	monitordb->execute((char *)"DELETE FROM mysql_server_aws_aurora_check_status");
	std::map<std::string, AWS_Aurora_monitor_node *>::iterator it2;
	AWS_Aurora_monitor_node *node=NULL;
	for (it2=GloMyMon->AWS_Aurora_Hosts_Map.begin(); it2!=GloMyMon->AWS_Aurora_Hosts_Map.end(); ++it2) {
		std::string s=it2->first;
		node=it2->second;
		std::size_t found=s.find_last_of(":");
		std::string host=s.substr(0,found);
		std::string port=s.substr(found+1);
		AWS_Aurora_status_entry * aase = node->last_entry();
		char *error_msg = NULL;
		if (aase && aase->start_time) {
			if (aase->error) {
				error_msg = aase->error;
			}
		}
		char lut[30];
		struct tm __tm_info;
		localtime_r(&node->last_checked_at, &__tm_info);
		strftime(lut, 25, "%Y-%m-%d %H:%M:%S", &__tm_info);

/*
		int i;
		for (i=0; i<AWS_Aurora_Nentries; i++) {
			AWS_Aurora_status_entry * aase = node->last_entries[i];
			if (aase && aase->start_time) {
				if ( aase->host_statuses->size() ) {
					for (std::vector<AWS_Aurora_replica_host_status_entry *>::iterator it3 = aase->host_statuses->begin(); it3!=aase->host_statuses->end(); ++it3) {
						AWS_Aurora_replica_host_status_entry *hse = *it3;
						if (hse) {
*/
							rc=sqlite3_bind_int64(statement1, 1, node->writer_hostgroup); assert(rc==SQLITE_OK);
							rc=sqlite3_bind_text(statement1, 2, host.c_str(), -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
							rc=sqlite3_bind_int64(statement1, 3, atoi(port.c_str())); assert(rc==SQLITE_OK);
							rc=sqlite3_bind_text(statement1, 4, lut, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
							rc=sqlite3_bind_int64(statement1, 5, node->num_checks_tot ); assert(rc==SQLITE_OK);
							rc=sqlite3_bind_int64(statement1, 6, node->num_checks_ok ); assert(rc==SQLITE_OK);
							rc=sqlite3_bind_text(statement1, 7, error_msg , -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
							SAFE_SQLITE3_STEP2(statement1);
							rc=sqlite3_clear_bindings(statement1); assert(rc==SQLITE_OK);
							rc=sqlite3_reset(statement1); assert(rc==SQLITE_OK);
/*
						}
					}
				} else {
					rc=sqlite3_bind_text(statement2, 1, host.c_str(), -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement2, 2, atoi(port.c_str())); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement2, 3, aase->start_time ); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_int64(statement2, 4, aase->check_time ); assert(rc==SQLITE_OK);
					rc=sqlite3_bind_text(statement2, 5, aase->error , -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
					SAFE_SQLITE3_STEP2(statement2);
					rc=sqlite3_clear_bindings(statement2); assert(rc==SQLITE_OK);
					rc=sqlite3_reset(statement2); assert(rc==SQLITE_OK);
				}
			}
		}
*/
	}
	sqlite3_finalize(statement1);
	pthread_mutex_unlock(&GloMyMon->aws_aurora_mutex);
}

/*
void MySQL_Monitor::gdb_dump___monitor_mysql_server_aws_aurora_log(char *hostname) {
	fprintf(stderr,"gdb_dump___monitor_mysql_server_aws_aurora_log\n");
	std::map<std::string, AWS_Aurora_monitor_node *>::iterator it2;
	AWS_Aurora_monitor_node *node=NULL;
	for (it2=GloMyMon->AWS_Aurora_Hosts_Map.begin(); it2!=GloMyMon->AWS_Aurora_Hosts_Map.end(); ++it2) {
		std::string s=it2->first;
		node=it2->second;
		std::size_t found=s.find_last_of(":");
		std::string host=s.substr(0,found);
		std::string port=s.substr(found+1);
		int i;
		for (i=0; i<AWS_Aurora_Nentries; i++) {
			AWS_Aurora_status_entry * aase = node->last_entries[i];
			if (aase && aase->start_time) {
				if ( aase->host_statuses->size() ) {
					for (std::vector<AWS_Aurora_replica_host_status_entry *>::iterator it3 = aase->host_statuses->begin(); it3!=aase->host_statuses->end(); ++it3) {
						AWS_Aurora_replica_host_status_entry *hse = *it3;
						if (hse) {
							if (hostname == NULL || (hostname && ( (strcmp(hostname,host.c_str())==0) || (strcmp(hostname,hse->server_id)==0)) )) {
								fprintf(stderr,"%s:%d %llu %llu %s %s %s %s %f %f\n", host.c_str(), atoi(port.c_str()), aase->start_time, aase->check_time, aase->error, hse->server_id,hse->session_id, hse->last_update_timestamp, hse->replica_lag_ms , hse->cpu);
							}
						}
					}
				} else {
					if (hostname == NULL || (hostname && strcmp(hostname,host.c_str())==0) ) {
						fprintf(stderr,"%s:%d %llu %llu %s\n", host.c_str(), atoi(port.c_str()), aase->start_time, aase->check_time, aase->error);
					}
				}
			}
		}
	}
}
*/

AWS_Aurora_monitor_node::AWS_Aurora_monitor_node(char *_a, int _p, int _whg) {
	addr=NULL;
	if (_a) {
		addr=strdup(_a);
	}
	port=_p;
	idx_last_entry=-1;
	writer_hostgroup=_whg;
	int i;
	for (i=0;i<AWS_Aurora_Nentries;i++) {
		last_entries[i] = NULL;
		//last_entries[i]->start_time=0;
		//last_entries[i]->check_time=0;
	}
	num_checks_tot = 0;
	num_checks_ok = 0;
	last_checked_at = 0;
}

AWS_Aurora_monitor_node::~AWS_Aurora_monitor_node() {
	if (addr) {
		free(addr);
	}
}

bool AWS_Aurora_monitor_node::add_entry(AWS_Aurora_status_entry *ase) {
	bool ret=false;
	if (idx_last_entry==-1) ret=true;
	int prev_last_entry=idx_last_entry;
	idx_last_entry++;
	if (idx_last_entry>=AWS_Aurora_Nentries) {
		idx_last_entry=0;
	}
	if (last_entries[idx_last_entry]) {
		AWS_Aurora_status_entry *old = last_entries[idx_last_entry];
		delete old;
	}
	last_entries[idx_last_entry] = ase;
	num_checks_tot++;
	if (ase->error == NULL) {
		num_checks_ok++;
	}
	last_checked_at = time(NULL);
	return ret; // for now ignored
}

void * monitor_AWS_Aurora_thread(void *arg);


typedef struct _host_def_t {
	char *host;
	int port;
	int use_ssl;
} host_def_t;

static void shuffle_hosts(host_def_t *array, size_t n) {
	char tmp[sizeof(host_def_t)];
	char *arr = (char *)array;
	size_t stride = sizeof(host_def_t) * sizeof(char);

	if (n > 1) {
		size_t i;
		for (i = 0; i < n - 1 ; ++i) {
			size_t rnd = (size_t) fastrand();
			size_t j = i + rnd / (0x7FFF / (n - i) + 1);
			memcpy(tmp, arr + j * stride, sizeof(host_def_t));
			memcpy(arr + j * stride, arr + i * stride, sizeof(host_def_t));
			memcpy(arr + i * stride, tmp, sizeof(host_def_t));
		}
	}
}

void * monitor_AWS_Aurora_thread_HG(void *arg) {
	unsigned int wHG = *(unsigned int *)arg;
	unsigned int rHG = 0;
	unsigned int num_hosts = 0;
	unsigned int cur_host_idx = 0;
	unsigned int max_lag_ms = 0;
	unsigned int check_interval_ms = 0;
	unsigned int check_timeout_ms = 0;
	//unsigned int i = 0;
	proxy_info("Started Monitor thread for AWS Aurora writer HG %u\n", wHG);

	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();
	if (!GloMTH) return NULL;	// quick exit during shutdown/restart

	uint64_t initial_raw_checksum = 0;

	// this is a static array of the latest reads
	unsigned int ase_idx = 0;
	AWS_Aurora_status_entry *lasts_ase[N_L_ASE];
	for (unsigned int i=0; i<N_L_ASE; i++) {
		lasts_ase[i] = NULL;
	}

	// initial data load
	pthread_mutex_lock(&GloMyMon->aws_aurora_mutex);
	initial_raw_checksum = GloMyMon->AWS_Aurora_Hosts_resultset_checksum;
	// count the number of hosts
	for (std::vector<SQLite3_row *>::iterator it = GloMyMon->AWS_Aurora_Hosts_resultset->rows.begin() ; it != GloMyMon->AWS_Aurora_Hosts_resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		if (atoi(r->fields[0]) == wHG) {
			num_hosts++;
			if (max_lag_ms == 0) {
				max_lag_ms = atoi(r->fields[5]);
			}
			if (check_interval_ms == 0) {
				check_interval_ms = atoi(r->fields[5]);
			}
			if (check_timeout_ms == 0) {
				check_timeout_ms = atoi(r->fields[7]);
			}
			if (rHG == 0) {
				rHG = atoi(r->fields[1]);
			}
		}
	}
	host_def_t *hpa = (host_def_t *)malloc(sizeof(host_def_t)*num_hosts);
	for (std::vector<SQLite3_row *>::iterator it = GloMyMon->AWS_Aurora_Hosts_resultset->rows.begin() ; it != GloMyMon->AWS_Aurora_Hosts_resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		if (atoi(r->fields[0]) == wHG) {
			hpa[cur_host_idx].host = strdup(r->fields[2]);
			hpa[cur_host_idx].port = atoi(r->fields[3]);
			hpa[cur_host_idx].use_ssl = atoi(r->fields[4]);
			cur_host_idx++;
		}
	}
	pthread_mutex_unlock(&GloMyMon->aws_aurora_mutex);

	bool exit_now = false;
	unsigned long long t1 = 0;
	//unsigned long long t2 = 0;
	unsigned long long next_loop_at = 0;

	bool crc = false;

	uint64_t current_raw_checksum = 0;
	size_t rnd;
	bool found_pingable_host = false;
	bool rc_ping = false;
	MySQL_Monitor_State_Data *mmsd = NULL;

	t1 = monotonic_time();
	unsigned long long start_time=t1;

	while (GloMyMon->shutdown==false && mysql_thread___monitor_enabled==true && exit_now==false) {

		unsigned int glover;
		t1=monotonic_time();
		
		//proxy_info("Looping Monitor thread for AWS Aurora writer HG %u\n", wHG);

		if (!GloMTH) {
			//proxy_info("Stopping Monitor thread for AWS Aurora writer HG %u\n", wHG);
			goto __exit_monitor_AWS_Aurora_thread_HG_now;
			return NULL;	// quick exit during shutdown/restart
		}

		// if variables has changed, triggers new checks
		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			next_loop_at=0;
		}

		pthread_mutex_lock(&GloMyMon->aws_aurora_mutex);
		current_raw_checksum = GloMyMon->AWS_Aurora_Hosts_resultset_checksum;
		pthread_mutex_unlock(&GloMyMon->aws_aurora_mutex);

		if (current_raw_checksum != initial_raw_checksum) {
			// the content of AWS_Aurora_Hosts_resultset has changed. Exit
			exit_now=true;
			break;
		}
		//fprintf(stderr,"%u : %llu %llu\n", wHG, t1, next_loop_at);
		if (t1 < next_loop_at) {
			unsigned long long st=0;
			st=next_loop_at-t1;
			if (st > 50000) {
				st = 50000;
			}
			usleep(st);
			//proxy_info("Looping Monitor thread for AWS Aurora writer HG %u\n", wHG);
			continue;
		}
		//proxy_info("Running check AWS Aurora writer HG %u\n", wHG);
		found_pingable_host = false;

		rc_ping = false;
		// pick a random host
		rnd = (size_t) rand();
		rnd %= num_hosts;
		rc_ping = GloMyMon->server_responds_to_ping(hpa[rnd].host, hpa[rnd].port);
		//proxy_info("Looping Monitor thread for AWS Aurora writer HG %u\n", wHG);
#ifdef TEST_AURORA
		if (rand() % 100 < 30) {
			// we randomly fail 30% of the requests
			rc_ping = false;
		}
#endif // TEST_AURORA
		if (rc_ping) {
			found_pingable_host = true;
			cur_host_idx = rnd;
		} else {
			// the randomly picked host didn't work work
			shuffle_hosts(hpa,num_hosts);
			for (unsigned int i=0; (found_pingable_host == false && i<num_hosts ) ; i++) {
				rc_ping = GloMyMon->server_responds_to_ping(hpa[i].host, hpa[i].port);
				if (rc_ping) {
					found_pingable_host = true;
					cur_host_idx = i;
				}
			}
		}
			
#ifdef TEST_AURORA
		if (rand() % 200 == 0) {
			// we randomly fail 0.5% of the requests
			found_pingable_host = false;
		}
#endif // TEST_AURORA

		if (found_pingable_host == false) {
			proxy_error("No node is pingable for AWS Aurora cluster with writer HG %u\n", wHG);
			next_loop_at = t1 + check_interval_ms * 1000;
			continue;
		}
		if (rand() % 1000 == 0) { // suppress 99.9% of the output, too verbose
			proxy_info("Running check for AWS Aurora writer HG %u on %s:%d\n", wHG , hpa[cur_host_idx].host, hpa[cur_host_idx].port);
		}
		mmsd = NULL;
		mmsd = new MySQL_Monitor_State_Data(hpa[cur_host_idx].host, hpa[cur_host_idx].port, NULL, hpa[cur_host_idx].use_ssl);
		mmsd->writer_hostgroup = wHG;
		mmsd->aws_aurora_check_timeout_ms = check_timeout_ms;
		mmsd->mysql=GloMyMon->My_Conn_Pool->get_connection(mmsd->hostname, mmsd->port);
		//unsigned long long start_time=mysql_thr->curtime;
		start_time=t1;


		mmsd->t1=start_time;

		crc=false;
		if (mmsd->mysql==NULL) { // we don't have a connection, let's create it
			bool rc;
			rc=mmsd->create_new_connection();
			crc=true;
			if (rc==false) {
				unsigned long long now=monotonic_time();
				char * new_error = (char *)malloc(50+strlen(mmsd->mysql_error_msg));
				sprintf(new_error,"timeout or error in creating new connection: %s",mmsd->mysql_error_msg);
				free(mmsd->mysql_error_msg);
				mmsd->mysql_error_msg = new_error;
				proxy_error("Error on AWS Aurora check for %s:%d after %lldms. Unable to create a connection. If the server is overload, increase mysql-monitor_connect_timeout. Error: %s.\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000, new_error);
				goto __exit_monitor_aws_aurora_HG_thread;
			}
		}

	mmsd->t1=monotonic_time();
	mmsd->interr=0; // reset the value
#ifdef TEST_AURORA
	mmsd->async_exit_status = mysql_query_start(&mmsd->interr, mmsd->mysql, "SELECT SERVER_ID, SESSION_ID, LAST_UPDATE_TIMESTAMP, REPLICA_LAG_IN_MILLISECONDS, CPU FROM REPLICA_HOST_STATUS ORDER BY SERVER_ID");
#else
	mmsd->async_exit_status = mysql_query_start(&mmsd->interr, mmsd->mysql, "SELECT SERVER_ID, SESSION_ID, LAST_UPDATE_TIMESTAMP, REPLICA_LAG_IN_MILLISECONDS, CPU FROM INFORMATION_SCHEMA.REPLICA_HOST_STATUS ORDER BY SERVER_ID");
#endif // TEST_AURORA
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > mmsd->t1 + mmsd->aws_aurora_check_timeout_ms * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			proxy_error("Timeout on AWS Aurora health check for %s:%d after %lldms. If the server is overload, increase mysql_aws_aurora_hostgroups.check_timeout_ms\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
			goto __exit_monitor_aws_aurora_HG_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_aws_aurora_HG_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_query_cont(&mmsd->interr, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	mmsd->async_exit_status=mysql_store_result_start(&mmsd->result,mmsd->mysql);
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > mmsd->t1 + mmsd->aws_aurora_check_timeout_ms * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			proxy_error("Timeout on AWS Aurora health check for %s:%d after %lldms. If the server is overload, increase mysql_aws_aurora_hostgroups.check_timeout_ms\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
			goto __exit_monitor_aws_aurora_HG_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_aws_aurora_HG_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_store_result_cont(&mmsd->result, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) { // check failed
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
	}

__exit_monitor_aws_aurora_HG_thread:
		mmsd->t2=monotonic_time();
		next_loop_at = t1 + (check_interval_ms * 1000);
		if (mmsd->t2 > t1) {
			next_loop_at -= (mmsd->t2 - t1);
		}
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
			AWS_Aurora_status_entry *ase = new AWS_Aurora_status_entry(mmsd->t1, mmsd->t2-mmsd->t1, mmsd->mysql_error_msg);
			AWS_Aurora_status_entry *ase_l = new AWS_Aurora_status_entry(mmsd->t1, mmsd->t2-mmsd->t1, mmsd->mysql_error_msg);
			if (mmsd->interr == 0 && mmsd->result) {
				int num_fields=0;
				int num_rows=0;
				num_fields = mysql_num_fields(mmsd->result);
				if (num_fields!=5) {
					proxy_error("Incorrect number of fields, please report a bug\n");
				} else {
					MYSQL_ROW row;
					while ((row = mysql_fetch_row(mmsd->result))) {
						AWS_Aurora_replica_host_status_entry *arhse = new AWS_Aurora_replica_host_status_entry(row[0], row[1], row[2], row[3], row[4]);
						ase->add_host_status(arhse);
						AWS_Aurora_replica_host_status_entry *arhse_l = new AWS_Aurora_replica_host_status_entry(row[0], row[1], row[2], row[3], row[4]);
						ase_l->add_host_status(arhse_l);
					}
				}
				mysql_free_result(mmsd->result);
				mmsd->result=NULL;
			}
//__end_process_aws_aurora_result:
			if (mmsd->mysql_error_msg) {
			}
			unsigned long long time_now=realtime_time();
			time_now=time_now-(mmsd->t2 - start_time);
			pthread_mutex_lock(&GloMyMon->aws_aurora_mutex);
			//auto it = 
			// TODO : complete this
			std::map<std::string, AWS_Aurora_monitor_node *>::iterator it2;
			it2 = GloMyMon->AWS_Aurora_Hosts_Map.find(s);
			AWS_Aurora_monitor_node *node=NULL;
			if (it2!=GloMyMon->AWS_Aurora_Hosts_Map.end()) {
				node=it2->second;
				node->add_entry(ase);
			} else {
				node = new AWS_Aurora_monitor_node(mmsd->hostname,mmsd->port,mmsd->writer_hostgroup);
				node->add_entry(ase);
				GloMyMon->AWS_Aurora_Hosts_Map.insert(std::make_pair(s,node));
			}
			// clean up
			if (l<110) {
			} else {
				free(s);
			}
			pthread_mutex_unlock(&GloMyMon->aws_aurora_mutex);
			if (lasts_ase[ase_idx]) {
				AWS_Aurora_status_entry * l_ase = lasts_ase[ase_idx];
				delete l_ase;
			}
			lasts_ase[ase_idx] = ase_l;
			GloMyMon->evaluate_aws_aurora_results(wHG, rHG, &lasts_ase[0], ase_idx, max_lag_ms);
			// remember that we call evaluate_aws_aurora_results()
			// *before* shifting ase_idx
			ase_idx++;
			if (ase_idx == N_L_ASE) {
				ase_idx = 0;
			}
		}
		if (mmsd->interr || mmsd->async_exit_status) { // check failed
		} else {
			if (crc==false) {
				if (mmsd->mysql) {
					GloMyMon->My_Conn_Pool->put_connection(mmsd->hostname,mmsd->port,mmsd->mysql);
					mmsd->mysql=NULL;
				}
			}
		}
__fast_exit_monitor_aws_aurora_HG_thread:
	if (mmsd->mysql) {
		// if we reached here we didn't put the connection back
		if (mmsd->mysql_error_msg || mmsd->async_exit_status) {
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
__exit_monitor_AWS_Aurora_thread_HG_now:
	if (mmsd) {
		delete (mmsd);
		mmsd = NULL;
	for (unsigned int i=0; i<N_L_ASE; i++) {
		if (lasts_ase[i]) {
			delete lasts_ase[i];
			lasts_ase[i] = NULL;
		}
	}
	}
/*
		mmsd->writer_hostgroup=atoi(r->fields[0]);
		mmsd->writer_is_also_reader=atoi(r->fields[4]);
					mmsd->max_transactions_behind=atoi(r->fields[5]);
					mmsd->mondb=monitordb;
					WorkItem* item;
					item=new WorkItem(mmsd,monitor_AWS_Aurora_thread);
					GloMyMon->queue.add(item);
					usleep(us);
*/
//				}
		
/*
		for
		for (std::vector<SQLite3_row *>::iterator it = Galera_Hosts_resultset->rows.begin() ; it != Galera_Hosts_resultset->rows.end(); ++it) {

		}
				SQLite3_row *r=*it;
				bool rc_ping = true;
				rc_ping = server_responds_to_ping(r->fields[1],atoi(r->fields[2]));
				if (rc_ping) { // only if server is responding to pings
					MySQL_Monitor_State_Data *mmsd=new MySQL_Monitor_State_Data(r->fields[1],atoi(r->fields[2]), NULL, atoi(r->fields[3]));
					mmsd->writer_hostgroup=atoi(r->fields[0]);
					mmsd->writer_is_also_reader=atoi(r->fields[4]);
					mmsd->max_transactions_behind=atoi(r->fields[5]);
					mmsd->mondb=monitordb;
		
*/
	}

	free(hpa);
	if (mysql_thr) {
		delete mysql_thr;
		mysql_thr=NULL;
	}
	for (unsigned int i=0; i<N_L_ASE; i++) {
		if (lasts_ase[i]) {
			AWS_Aurora_status_entry * ase = lasts_ase[i];
			delete ase;
		}
	}
	proxy_info("Stopping Monitor thread for AWS Aurora writer HG %u\n", wHG);
	return NULL;
} 


void * MySQL_Monitor::monitor_aws_aurora() {
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
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

	uint64_t last_raw_checksum = 0;

	// ADD here an unordered map , Writer HG => next time at
	// when empty, a new map is populated
	// when next_loop_at = 0 , the tables is emptied so to be populated again

	unsigned int *hgs_array = NULL;
	pthread_t *pthreads_array = NULL;
	unsigned int hgs_num = 0;

	while (GloMyMon->shutdown==false && mysql_thread___monitor_enabled==true) {

		unsigned int glover;
		t1=monotonic_time();

		if (!GloMTH) return NULL;	// quick exit during shutdown/restart

		// if variables has changed, triggers new checks
		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			next_loop_at=0;
		}

		// if list of servers or HG or options has changed, triggers new checks
		pthread_mutex_lock(&aws_aurora_mutex);
		uint64_t new_raw_checksum = AWS_Aurora_Hosts_resultset->raw_checksum();
		pthread_mutex_unlock(&aws_aurora_mutex);
		if (new_raw_checksum != last_raw_checksum) {
			proxy_info("Detected new/changed definition for AWS Aurora monitoring\n");
			next_loop_at = 0;
			last_raw_checksum = new_raw_checksum;
			if (pthreads_array) {
				// wait all threads to terminate
				for (unsigned int i=0; i < hgs_num; i++) {
					pthread_join(pthreads_array[i], NULL);
					proxy_info("Stopped Monitor thread for AWS Aurora writer HG %u\n", hgs_array[i]);
				}
				free(pthreads_array);
				free(hgs_array);
			}
			hgs_num = 0;
			pthread_mutex_lock(&aws_aurora_mutex);
			// scan all the writer HGs
			unsigned int num_rows = AWS_Aurora_Hosts_resultset->rows_count;
			if (num_rows) {
				unsigned int *tmp_hgs_array = (unsigned int *)malloc(sizeof(unsigned int)*num_rows);
				for (std::vector<SQLite3_row *>::iterator it = AWS_Aurora_Hosts_resultset->rows.begin() ; it != AWS_Aurora_Hosts_resultset->rows.end(); ++it) {
					SQLite3_row *r=*it;
					int wHG = atoi(r->fields[0]);
					bool found = false;
					// very simple search. Far from optimal, but assuming very few HGs it is fast enough
					for (unsigned int i=0; i < hgs_num; i++) {
						if (tmp_hgs_array[i] == wHG) {
							found = true;
						}
					}
					if (found == false) {
						// new wHG found
						tmp_hgs_array[hgs_num]=wHG;
						hgs_num++;
					}
				}
				proxy_info("Activating Monitoring of %u AWS Aurora clusters\n", hgs_num);
				hgs_array = (unsigned int *)malloc(sizeof(unsigned int)*hgs_num);
				pthreads_array = (pthread_t *)malloc(sizeof(pthread_t)*hgs_num);
				for (unsigned int i=0; i < hgs_num; i++) {
					hgs_array[i] = tmp_hgs_array[i];
					proxy_info("Starting Monitor thread for AWS Aurora writer HG %u\n", hgs_array[i]);
					if (pthread_create(&pthreads_array[i], NULL, monitor_AWS_Aurora_thread_HG, &hgs_array[i]) != 0) {
						proxy_error("Thread creation\n");
						assert(0);
					}
				}
				free(tmp_hgs_array);
			}
			pthread_mutex_unlock(&aws_aurora_mutex);
		}

/*
		if (t1 < next_loop_at) {
			goto __sleep_monitor_aws_aurora;
		}

		if (next_loop_at == 0) {
			// free the queue
			
		}

		next_loop_at=t1+1000*mysql_thread___monitor_galera_healthcheck_interval;
		pthread_mutex_lock(&aws_aurora_mutex);
		if (AWS_Aurora_Hosts_resultset==NULL) {
				goto __end_monitor_aws_aurora_loop;
		} else {
			if (AWS_Aurora_Hosts_resultset->rows_count==0) {
				goto __end_monitor_aws_aurora_loop;
			}
			int us=100;
			if (AWS_Aurora_Hosts_resultset->rows_count) {
				us=mysql_thread___monitor_read_only_interval/2/Galera_Hosts_resultset->rows_count;
			}
			for (std::vector<SQLite3_row *>::iterator it = Galera_Hosts_resultset->rows.begin() ; it != Galera_Hosts_resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				bool rc_ping = true;
				rc_ping = server_responds_to_ping(r->fields[1],atoi(r->fields[2]));
				if (rc_ping) { // only if server is responding to pings
					MySQL_Monitor_State_Data *mmsd=new MySQL_Monitor_State_Data(r->fields[1],atoi(r->fields[2]), NULL, atoi(r->fields[3]));
					mmsd->writer_hostgroup=atoi(r->fields[0]);
					mmsd->writer_is_also_reader=atoi(r->fields[4]);
					mmsd->max_transactions_behind=atoi(r->fields[5]);
					mmsd->mondb=monitordb;
					WorkItem* item;
					item=new WorkItem(mmsd,monitor_AWS_Aurora_thread);
					GloMyMon->queue.add(item);
					usleep(us);
				}
				if (GloMyMon->shutdown) {
					pthread_mutex_unlock(&galera_mutex);
					return NULL;
				}
			}
		}

__end_monitor_aws_aurora_loop:
		pthread_mutex_unlock(&aws_aurora_mutex);
		if (mysql_thread___monitor_enabled==true) {
		}

__sleep_monitor_aws_aurora:
		t2=monotonic_time();
		if (t2<next_loop_at) {
			unsigned long long st=0;
			st=next_loop_at-t2;
			if (st > 200000) {
				st = 200000;
			}
			usleep(st);
		}
*/
		usleep(10000);
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

void * monitor_AWS_Aurora_thread(void *arg) {
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
			unsigned long long now=monotonic_time();
			char * new_error = (char *)malloc(50+strlen(mmsd->mysql_error_msg));
			sprintf(new_error,"timeout or error in creating new connection: %s",mmsd->mysql_error_msg);
			free(mmsd->mysql_error_msg);
			mmsd->mysql_error_msg = new_error;
			proxy_error("Error on AWS Aurora check for %s:%d after %lldms. Unable to create a connection. If the server is overload, increase mysql-monitor_connect_timeout. Error: %s.\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000, new_error);
			goto __exit_monitor_aws_aurora_thread;
		}
	}

	mmsd->t1=monotonic_time();
	mmsd->interr=0; // reset the value
#ifdef TEST_AURORA
	mmsd->async_exit_status = mysql_query_start(&mmsd->interr, mmsd->mysql, "SELECT SERVER_ID, SESSION_ID, LAST_UPDATE_TIMESTAMP, REPLICA_LAG_IN_MILLISECONDS, CPU FROM REPLICA_HOST_STATUS ORDER BY SERVER_ID");
#else
	mmsd->async_exit_status = mysql_query_start(&mmsd->interr, mmsd->mysql, "SELECT SERVER_ID, SESSION_ID, LAST_UPDATE_TIMESTAMP, REPLICA_LAG_IN_MILLISECONDS, CPU FROM INFORMATION_SCHEMA.REPLICA_HOST_STATUS ORDER BY SERVER_ID");
#endif // TEST_AURORA
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > mmsd->t1 + mmsd->aws_aurora_check_timeout_ms * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			proxy_error("Timeout on AWS Aurora health check for %s:%d after %lldms. If the server is overload, increase mysql_aws_aurora_hostgroups.check_timeout_ms\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
			goto __exit_monitor_aws_aurora_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_aws_aurora_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_query_cont(&mmsd->interr, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	mmsd->async_exit_status=mysql_store_result_start(&mmsd->result,mmsd->mysql);
	while (mmsd->async_exit_status) {
		mmsd->async_exit_status=wait_for_mysql(mmsd->mysql, mmsd->async_exit_status);
		unsigned long long now=monotonic_time();
		if (now > mmsd->t1 + mmsd->aws_aurora_check_timeout_ms * 1000) {
			mmsd->mysql_error_msg=strdup("timeout check");
			proxy_error("Timeout on AWS Aurora health check for %s:%d after %lldms. If the server is overload, increase mysql_aws_aurora_hostgroups.check_timeout_ms\n", mmsd->hostname, mmsd->port, (now-mmsd->t1)/1000);
			goto __exit_monitor_aws_aurora_thread;
		}
		if (GloMyMon->shutdown==true) {
			goto __fast_exit_monitor_aws_aurora_thread;	// exit immediately
		}
		if ((mmsd->async_exit_status & MYSQL_WAIT_TIMEOUT) == 0) {
			mmsd->async_exit_status=mysql_store_result_cont(&mmsd->result, mmsd->mysql, mmsd->async_exit_status);
		}
	}
	if (mmsd->interr) { // check failed
		mmsd->mysql_error_msg=strdup(mysql_error(mmsd->mysql));
	}

__exit_monitor_aws_aurora_thread:
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
		AWS_Aurora_status_entry *ase = new AWS_Aurora_status_entry(mmsd->t1, mmsd->t2-mmsd->t1, mmsd->mysql_error_msg);
		if (mmsd->interr == 0 && mmsd->result) {
			int num_fields=0;
			int num_rows=0;
			num_fields = mysql_num_fields(mmsd->result);
			if (num_fields!=5) {
				proxy_error("Incorrect number of fields, please report a bug\n");
			} else {
				MYSQL_ROW row;
				while ((row = mysql_fetch_row(mmsd->result))) {
					AWS_Aurora_replica_host_status_entry *arhse = new AWS_Aurora_replica_host_status_entry(row[0], row[1], row[2], row[3], row[4]);
					ase->add_host_status(arhse);
				}
			}
			mysql_free_result(mmsd->result);
			mmsd->result=NULL;
		}
//__end_process_aws_aurora_result:
		if (mmsd->mysql_error_msg) {
		}
		unsigned long long time_now=realtime_time();
		time_now=time_now-(mmsd->t2 - start_time);
		pthread_mutex_lock(&GloMyMon->aws_aurora_mutex);
		//auto it = 
		// TODO : complete this
		std::map<std::string, AWS_Aurora_monitor_node *>::iterator it2;
		it2 = GloMyMon->AWS_Aurora_Hosts_Map.find(s);
		AWS_Aurora_monitor_node *node=NULL;
		if (it2!=GloMyMon->AWS_Aurora_Hosts_Map.end()) {
			node=it2->second;
			node->add_entry(ase);
		} else {
			node = new AWS_Aurora_monitor_node(mmsd->hostname,mmsd->port,mmsd->writer_hostgroup);
			node->add_entry(ase);
			GloMyMon->AWS_Aurora_Hosts_Map.insert(std::make_pair(s,node));
		}
		pthread_mutex_unlock(&GloMyMon->aws_aurora_mutex);
/*
		// NOTE: we update MyHGM outside the mutex aws_aurora_mutex
		if (mmsd->mysql_error_msg) { // there was an error checking the status of the server, surely we need to reconfigure GR
			MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, mmsd->mysql_error_msg);
		} else {
			if (primary_partition == false || wsrep_desync == true || wsrep_local_state!=4) {
				if (primary_partition == false) {
					MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"primary_partition=NO");
				} else {
					if (wsrep_desync == true) {
						MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"wsrep_desync=YES");
					} else {
						char msg[80];
						sprintf(msg,"wsrep_local_state=%d",wsrep_local_state);
						MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, msg);
					}
				}
			} else {
				//if (wsrep_sst_donor_rejects_queries || wsrep_reject_queries) {
					if (wsrep_reject_queries) {
						MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"wsrep_reject_queries=true");
				//	} else {
				//		// wsrep_sst_donor_rejects_queries
				//		MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"wsrep_sst_donor_rejects_queries=true");
				//	}
				} else {
					if (read_only==true) {
						if (wsrep_local_recv_queue > mmsd->max_transactions_behind) {
							MyHGM->update_galera_set_offline(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"slave is lagging");
						} else {
							MyHGM->update_galera_set_read_only(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup, (char *)"read_only=YES");
						}
					} else {
						// the node is a writer
						// TODO: for now we don't care about the number of writers
						MyHGM->update_galera_set_writer(mmsd->hostname, mmsd->port, mmsd->writer_hostgroup);
					}
				}
			}
		}
*/
		// clean up
		if (l<110) {
		} else {
			free(s);
		}
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
__fast_exit_monitor_aws_aurora_thread:
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

void MySQL_Monitor::evaluate_aws_aurora_results(unsigned int wHG, unsigned int rHG, AWS_Aurora_status_entry **lasts_ase, unsigned int ase_idx, unsigned int max_latency_ms) {
	unsigned int i = 0;
#ifdef TEST_AURORA
	bool verbose = false;
	unsigned int action_yes = 0;
	unsigned int action_no = 0;
	unsigned int enabling = 0;
	unsigned int disabling = 0;
	if (rand() % 500 == 0) {
		verbose = true;
		bool ev = false;
		if (rand() % 1000 == 0) {
			ev = true;
		}
		for (i=0; i < N_L_ASE; i++) {
			AWS_Aurora_status_entry *aase = lasts_ase[i];
			if (ev == true || i == ase_idx) {
				if (aase && aase->start_time) {
					if ( aase->host_statuses->size() ) {
						for (std::vector<AWS_Aurora_replica_host_status_entry *>::iterator it3 = aase->host_statuses->begin(); it3!=aase->host_statuses->end(); ++it3) {
							AWS_Aurora_replica_host_status_entry *hse = *it3;
							if (hse) {
								fprintf(stderr,"%s %s %s %f %f\n", hse->server_id, hse->session_id, hse->last_update_timestamp, hse->replica_lag_ms , hse->cpu);
							}
						}
					}
				}
			}
		}
	}
#endif // TEST_AURORA
	unsigned int prev_ase_idx = ase_idx;
	if (prev_ase_idx == 0) prev_ase_idx = N_L_ASE;
	prev_ase_idx--;
	AWS_Aurora_status_entry *aase = lasts_ase[ase_idx];
	AWS_Aurora_status_entry *prev_aase = lasts_ase[prev_ase_idx];
	if (aase && aase->start_time) {
		if ( aase->host_statuses->size() ) {
			for (std::vector<AWS_Aurora_replica_host_status_entry *>::iterator it3 = aase->host_statuses->begin(); it3!=aase->host_statuses->end(); ++it3) {
				AWS_Aurora_replica_host_status_entry *hse = *it3;
				bool run_action = true;
				bool enable = true;
				bool is_writer = false;
				bool rla_rc = true;
				if (hse->replica_lag_ms > max_latency_ms) {
					enable = false;
				}
				if (strcmp(hse->session_id,"MASTER_SESSION_ID")==0) {
					is_writer = true;
				}
				// we also try to determine if a change needs to be made
				if (prev_aase && prev_aase->start_time) {
					if ( prev_aase->host_statuses->size() ) {
						for (std::vector<AWS_Aurora_replica_host_status_entry *>::iterator it4 = prev_aase->host_statuses->begin(); it4!=prev_aase->host_statuses->end(); ++it4) {
							AWS_Aurora_replica_host_status_entry *prev_hse = *it4;
							if (strcmp(prev_hse->server_id,hse->server_id)==0) {
								bool prev_enabled = true;
								if (prev_hse->replica_lag_ms > max_latency_ms) {
									prev_enabled = false;
								}
								if (prev_enabled == enable) {
									// the previous status should be the same
									// do not run any action
									run_action = false;
								}
							}
						}
					}
				}
				if (run_action) {
#ifdef TEST_AURORA
					action_yes++;
					(enable ? enabling++ : disabling++);
					rla_rc = MyHGM->aws_aurora_replication_lag_action(wHG, rHG, hse->server_id, 3306, hse->replica_lag_ms, enable, is_writer, verbose);
#else
					rla_rc = MyHGM->aws_aurora_replication_lag_action(wHG, rHG, hse->server_id, 3306, hse->replica_lag_ms, enable, is_writer);
#endif // TEST_AURORA
#ifdef TEST_AURORA
				} else {
					action_no++;
#endif // TEST_AURORA
					rla_rc = MyHGM->aws_aurora_replication_lag_action(wHG, rHG, hse->server_id, 3306, hse->replica_lag_ms, enable, is_writer);
				}
				//if (is_writer == true && rla_rc == false) {
				if (rla_rc == false) {
				if (is_writer == true) {
					// the server is not configured as a writer
#ifdef TEST_AURORA
					proxy_info("Calling update_aws_aurora_set_writer for %s\n", hse->server_id);
#endif // TEST_AURORA
					MyHGM->update_aws_aurora_set_writer(wHG, rHG, hse->server_id, 3306);
					time_t __timer;
					char lut[30];
					struct tm __tm_info;
					time(&__timer);
					localtime_r(&__timer, &__tm_info);
					strftime(lut, 25, "%Y-%m-%d %H:%M:%S", &__tm_info);
					char *q1 = (char *)"INSERT INTO mysql_server_aws_aurora_failovers VALUES (%d, '%s', '%s')";
					char *q2 = (char *)malloc(strlen(q1)+strlen(lut)+strlen(hse->server_id));
					sprintf(q2, q1, wHG, hse->server_id, lut);
					monitordb->execute(q2);
					free(q2);
				} else {
#ifdef TEST_AURORA
					proxy_info("Calling update_aws_aurora_set_reader for %s\n", hse->server_id);
#endif // TEST_AURORA
					MyHGM->update_aws_aurora_set_reader(wHG, rHG, hse->server_id, 3306);
				}
				}
			}
		}
	}
#ifdef TEST_AURORA
	if (verbose) {
		proxy_info("replication_lag_actions: YES=%u , NO=%u , enabling=%u , disabling=%u\n", action_yes, action_no, enabling, disabling);
	}
#endif // TEST_AURORA
}
