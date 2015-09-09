#include <map>
#include <list>
#include <thread>
#include "proxysql.h"
#include "cpp.h"


#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define MYSQL_MONITOR_VERSION "0.2.0902" DEB


#include <event2/event.h>

extern ProxySQL_Admin *GloAdmin;
extern MySQL_Threads_Handler *GloMTH;


static MySQL_Monitor *GloMyMon;

#define NEXT_IMMEDIATE(new_st) do { ST= new_st; goto again; } while (0)

#define SAFE_SQLITE3_STEP(_stmt) do {\
	do {\
		rc=sqlite3_step(_stmt);\
		if (rc!=SQLITE_DONE) {\
			assert(rc==SQLITE_LOCKED);\
			usleep(100);\
		}\
	} while (rc!=SQLITE_DONE);\
} while (0)

static void state_machine_handler(int fd, short event, void *arg);


/*
struct state_data {
	int ST;
	char *hostname;
	int port;
	struct event ev_mysql;
	MYSQL mysql;
	MYSQL_RES *result;
	MYSQL *ret;
	int err;
	MYSQL_ROW row;
	struct query_entry *query_element;
	int index;
};
*/

static int connect__num_active_connections;
static int total_connect__num_active_connections=0;
static int ping__num_active_connections;
static int total_ping__num_active_connections=0;
static int replication_lag__num_active_connections;
static int total_replication_lag__num_active_connections=0;


struct cmp_str {
	bool operator()(char const *a, char const *b)
	{
		return strcmp(a, b) < 0;
	}
};

class MySQL_Monitor_Connection_Pool {
	private:
	int size;
	//std::map<std::pair<char *, std::list<MYSQL *>* > my_connections;
	std::map<char *, std::list<MYSQL *>* , cmp_str> my_connections;
	public:
	MySQL_Monitor_Connection_Pool();
	~MySQL_Monitor_Connection_Pool();
	MYSQL * get_connection(char *hostname, int port);
	void put_connection(char *hostname, int port, MYSQL *my);
};

MySQL_Monitor_Connection_Pool::MySQL_Monitor_Connection_Pool() {
	size=0;
}

MySQL_Monitor_Connection_Pool::~MySQL_Monitor_Connection_Pool() {
}

MYSQL * MySQL_Monitor_Connection_Pool::get_connection(char *hostname, int port) {
	std::map<char *, std::list<MYSQL *>* >::iterator it;
	//it = my_connections.find(std::make_pair(hostname,port));
	char *buf=(char *)malloc(16+strlen(hostname));
	sprintf(buf,"%s:%d",hostname,port);
	it = my_connections.find(buf);
	free(buf);
	if (it != my_connections.end()) {
		std::list<MYSQL *> *lst=it->second;
		if (!lst->empty()) {
			MYSQL *ret=lst->front();
			lst->pop_front();
			size--;
			return ret;
		}
	}
	return NULL;
}

void MySQL_Monitor_Connection_Pool::put_connection(char *hostname, int port, MYSQL *my) {
	size++;
	std::map<char *, std::list<MYSQL *>* >::iterator it;
	char * buf=(char *)malloc(16+strlen(hostname));
	sprintf(buf,"%s:%d",hostname,port);
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
}

enum MySQL_Monitor_State_Data_Task_Type {
	MON_CONNECT,
	MON_PING,
	MON_REPLICATION_LAG
};

class MySQL_Monitor_State_Data {
	public:
	MySQL_Monitor_State_Data_Task_Type task_id;
	struct timeval tv_out;
	unsigned long long t1;
	unsigned long long t2;
	int ST;
	char *hostname;
	int port;
	struct event *ev_mysql;
	MYSQL *mysql;
	struct event_base *base;
	MYSQL_RES *result;
	MYSQL *ret;
	int interr;
	char * mysql_error_msg;
	MYSQL_ROW *row;
	unsigned int repl_lag;
	unsigned int hostgroup_id;
	MySQL_Monitor_State_Data(char *h, int p, struct event_base *b) {
		task_id=MON_CONNECT;
		mysql=NULL;
		result=NULL;
		ret=NULL;
		row=NULL;
		mysql_error_msg=NULL;
		hostname=strdup(h);
		port=p;
		base=b;
		ST=0;
		ev_mysql=NULL;
	}
	~MySQL_Monitor_State_Data() {
		if (hostname) {
			free(hostname);
		}
		assert(mysql==NULL); // if mysql is not NULL, there is a bug
		if (mysql_error_msg) {
			free(mysql_error_msg);
		}
	}
	void unregister() {
		if (ev_mysql) {
			event_del(ev_mysql);
			event_free(ev_mysql);
		}
	}
	int handler(int fd, short event) {
		int status;
again:
		switch (ST) {
			case 0:
				mysql=mysql_init(NULL);
				assert(mysql);
				mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
				if (mysql_thread___monitor_timer_cached==true) {
					event_base_gettimeofday_cached(base, &tv_out);
				} else {
					evutil_gettimeofday(&tv_out, NULL);
				}
				t1=(((unsigned long long) tv_out.tv_sec) * 1000000) + (tv_out.tv_usec);
				if (port) {
					status= mysql_real_connect_start(&ret, mysql, hostname, mysql_thread___monitor_username, mysql_thread___monitor_password, NULL, port, NULL, 0);
				} else {
					status= mysql_real_connect_start(&ret, mysql, "localhost", mysql_thread___monitor_username, mysql_thread___monitor_password, NULL, 0, hostname, 0);
				}
        if (status)
					/* Wait for connect to complete. */
					next_event(1, status);
				else
					NEXT_IMMEDIATE(3);
				break;
			case 1:
				status= mysql_real_connect_cont(&ret, mysql, mysql_status(event));
				if (status)
					next_event(1, status);
				else
					//NEXT_IMMEDIATE(40);
					NEXT_IMMEDIATE(3);
		break;

			case 3:
				if (!ret) {
					mysql_error_msg=strdup(mysql_error(mysql));
					mysql_close(mysql);
					mysql=NULL;
					NEXT_IMMEDIATE(50);
				}
				switch(task_id) {
					case MON_CONNECT:
						NEXT_IMMEDIATE(40);
						break;
					case MON_PING:
						NEXT_IMMEDIATE(7);
						break;
					case MON_REPLICATION_LAG:
						NEXT_IMMEDIATE(10);
						break;
					default:
						assert(0);
						break;
				}
				break;

			case 7:
				if (mysql_thread___monitor_timer_cached==true) {
					event_base_gettimeofday_cached(base, &tv_out);
				} else {
					evutil_gettimeofday(&tv_out, NULL);
				}
				t1=(((unsigned long long) tv_out.tv_sec) * 1000000) + (tv_out.tv_usec);
				status=mysql_ping_start(&interr,mysql);
				if (status)
					next_event(8,status);
				else
					NEXT_IMMEDIATE(9);
				break;

			case 8:
				status=mysql_ping_cont(&interr,mysql, mysql_status(event));
				if (status)
					next_event(8,status);
				else 
					NEXT_IMMEDIATE(9);
				break;

			case 9:
				if (interr) {
					mysql_error_msg=strdup(mysql_error(mysql));
					mysql_close(mysql);
					mysql=NULL;
					NEXT_IMMEDIATE(50);
				}
				switch(task_id) {
					case MON_PING:
					case MON_REPLICATION_LAG:
						NEXT_IMMEDIATE(39);
						break;
					default:
						assert(0);
						break;
				}
				break;

			case 10:
				if (mysql_thread___monitor_timer_cached==true) {
					event_base_gettimeofday_cached(base, &tv_out);
				} else {
					evutil_gettimeofday(&tv_out, NULL);
				}
				t1=(((unsigned long long) tv_out.tv_sec) * 1000000) + (tv_out.tv_usec);
				status=mysql_query_start(&interr,mysql,"SHOW SLAVE STATUS");
				if (status)
					next_event(11,status);
				else
					NEXT_IMMEDIATE(12);
				break;

			case 11:
				status=mysql_query_cont(&interr,mysql, mysql_status(event));
				if (status)
					next_event(11,status);
				else
					NEXT_IMMEDIATE(12);
				break;

			case 12:
				if (interr) {
					mysql_error_msg=strdup(mysql_error(mysql));
					mysql_close(mysql);
					mysql=NULL;
					NEXT_IMMEDIATE(50);
				} else {
					status=mysql_store_result_start(&result, mysql);
					if (status)
						next_event(13,status);
					else
						NEXT_IMMEDIATE(14);
				}
				break;

			case 13:
				status=mysql_store_result_cont(&result, mysql, mysql_status(event));
				if (status)
					next_event(13,status);
				else
					NEXT_IMMEDIATE(14);
				break;

			case 14:
				if (result) {
					if (mysql_thread___monitor_timer_cached==true) {
						event_base_gettimeofday_cached(base, &tv_out);
					} else {
						evutil_gettimeofday(&tv_out, NULL);
					}
					t2=(((unsigned long long) tv_out.tv_sec) * 1000000) + (tv_out.tv_usec);
					GloMyMon->My_Conn_Pool->put_connection(hostname,port,mysql);
					mysql=NULL;
					return -1;
				}	else {
					// no resultset, consider it an error
					mysql_error_msg=strdup(mysql_error(mysql));
					mysql_close(mysql);
					mysql=NULL;
					NEXT_IMMEDIATE(50);
				}
				break;

			case 39:
				if (mysql_thread___monitor_timer_cached==true) {
					event_base_gettimeofday_cached(base, &tv_out);
				} else {
					evutil_gettimeofday(&tv_out, NULL);
				}
				t2=(((unsigned long long) tv_out.tv_sec) * 1000000) + (tv_out.tv_usec);
				GloMyMon->My_Conn_Pool->put_connection(hostname,port,mysql);
				mysql=NULL;
				return -1;
				break;

			case 40:
				if (mysql_thread___monitor_timer_cached==true) {
					event_base_gettimeofday_cached(base, &tv_out);
				} else {
					evutil_gettimeofday(&tv_out, NULL);
				}
				t2=(((unsigned long long) tv_out.tv_sec) * 1000000) + (tv_out.tv_usec);
				NEXT_IMMEDIATE(50); // TEMP
				status= mysql_close_start(mysql);
				if (status)
					next_event(41, status);
				else
					NEXT_IMMEDIATE(50);
				break;

			case 41:
				status= mysql_close_cont(mysql, mysql_status(event));
				if (status)
					next_event(41, status);
				else
					NEXT_IMMEDIATE(50);
				break;

			case 50:
				/* We are done! */
				if (mysql) {
					mysql_close(mysql);
					mysql=NULL;
				}
				return -1;
				break;

			default:
				assert(0);
				break;

		}
		return 0;
	}
	void next_event(int new_st, int status) {
		short wait_event= 0;
		struct timeval tv, *ptv;
		int fd;

		if (status & MYSQL_WAIT_READ)
			wait_event|= EV_READ;
		if (status & MYSQL_WAIT_WRITE)
			wait_event|= EV_WRITE;
		if (wait_event)
			fd= mysql_get_socket(mysql);
		else
			fd= -1;
		if (status & MYSQL_WAIT_TIMEOUT) {
			tv.tv_sec= 0;
			tv.tv_usec= 10000;
			ptv= &tv;
		} else {
			ptv= NULL;
		}
		//event_set(ev_mysql, fd, wait_event, state_machine_handler, this);
		if (ev_mysql==NULL) {
			ev_mysql=event_new(base, fd, wait_event, state_machine_handler, this);
			//event_add(ev_mysql, ptv);
		}
		//event_del(ev_mysql);
		event_assign(ev_mysql, base, fd, wait_event, state_machine_handler, this);
		event_add(ev_mysql, ptv);
		ST= new_st;
	}
};


static void
state_machine_handler(int fd __attribute__((unused)), short event, void *arg) {
	MySQL_Monitor_State_Data *msd=(MySQL_Monitor_State_Data *)arg;
	struct event_base *base=msd->base;
	int rc=msd->handler(fd, event);
	if (rc==-1) {
		//delete msd;
		msd->unregister();
		switch (msd->task_id) {
			case MON_CONNECT:
				connect__num_active_connections--;
				if (connect__num_active_connections == 0)
					event_base_loopbreak(base);
				break;
			case MON_PING:
				ping__num_active_connections--;
				if (ping__num_active_connections == 0)
					event_base_loopbreak(base);
				break;
			case MON_REPLICATION_LAG:
				replication_lag__num_active_connections--;
				if (replication_lag__num_active_connections == 0)
					event_base_loopbreak(base);
				break;
			default:
				assert(0);
				break;
		}
	}
}

MySQL_Monitor::MySQL_Monitor() {

	GloMyMon = this;

	My_Conn_Pool=new MySQL_Monitor_Connection_Pool();

	shutdown=false;
	// create new SQLite datatabase
	monitordb = new SQLite3DB();
	monitordb->open((char *)"file:mem_monitordb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);

	admindb=new SQLite3DB();
  admindb->open((char *)"file:mem_admindb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);

	// define monitoring tables
	tables_defs_monitor=new std::vector<table_def_t *>;
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_connect", MONITOR_SQLITE_TABLE_MYSQL_SERVER_CONNECT);	
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_connect_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_CONNECT_LOG);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_ping", MONITOR_SQLITE_TABLE_MYSQL_SERVER_PING);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_ping_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_PING_LOG);
	insert_into_tables_defs(tables_defs_monitor,"mysql_server_replication_lag_log", MONITOR_SQLITE_TABLE_MYSQL_SERVER_REPLICATION_LAG_LOG);
	// create monitoring tables
	check_and_build_standard_tables(monitordb, tables_defs_monitor);
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_connect_log_time_start ON mysql_server_connect_log (time_start)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_ping_log_time_start ON mysql_server_ping_log (time_start)");
	monitordb->execute("CREATE INDEX IF NOT EXISTS idx_replication_lag_log_time_start ON mysql_server_replication_lag_log (time_start)");


};

MySQL_Monitor::~MySQL_Monitor() {
	drop_tables_defs(tables_defs_monitor);
	delete tables_defs_monitor;
	delete monitordb;
	delete admindb;
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


void * MySQL_Monitor::monitor_connect() {
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	struct event_base *libevent_base;
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();
	unsigned long long t1;
	unsigned long long t2;
	unsigned long long next_loop_at=0;
	unsigned long long start_time;
	while (shutdown==false) {

		char *error=NULL;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		int i=0;
		MySQL_Monitor_State_Data **sds=NULL;
		char *query=(char *)"SELECT DISTINCT hostname, port FROM mysql_servers";
		unsigned int glover;
		t1=monotonic_time();

		if (t1 < next_loop_at) {
			goto __sleep_monitor_connect_loop;
		}
		next_loop_at=t1+1000*mysql_thread___monitor_connect_interval;

		struct timeval tv_out;
		evutil_gettimeofday(&tv_out, NULL);
		start_time=(((unsigned long long) tv_out.tv_sec) * 1000000) + (tv_out.tv_usec);

		connect__num_active_connections=0;
		// create libevent base
		libevent_base= event_base_new();

		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			//proxy_error("%s\n", "MySQL_Monitor - CONNECT - refreshing variables");
		}

		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		if (error) {
			proxy_error("Error on %s : %s\n", query, error);
			goto __end_monitor_connect_loop;
		} else {
			if (resultset->rows_count==0) {
				goto __end_monitor_connect_loop;
			}
			sds=(MySQL_Monitor_State_Data **)malloc(resultset->rows_count * sizeof(MySQL_Monitor_State_Data *));
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				sds[i] = new MySQL_Monitor_State_Data(r->fields[0],atoi(r->fields[1]),libevent_base);
				sds[i]->task_id=MON_CONNECT;
				connect__num_active_connections++;
				total_connect__num_active_connections++;
				state_machine_handler(-1,-1,sds[i]);
				i++;
			}
		}

		// start libevent loop
		event_base_dispatch(libevent_base);


__end_monitor_connect_loop:
		if (sds) {
			sqlite3_stmt *statement;
			sqlite3 *mondb=monitordb->get_db();
			int rc;
			char *query=NULL;
			query=(char *)"DELETE FROM mysql_server_connect_log WHERE time_start < ?1";
			rc=sqlite3_prepare_v2(mondb, query, -1, &statement, 0);
			assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement, 1, start_time-mysql_thread___monitor_history*1000); assert(rc==SQLITE_OK);
			SAFE_SQLITE3_STEP(statement);
			rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
			rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
			sqlite3_finalize(statement);

			query=(char *)"INSERT OR REPLACE INTO mysql_server_connect_log VALUES (?1 , ?2 , ?3 , ?4 , ?5)";
			rc=sqlite3_prepare_v2(mondb, query, -1, &statement, 0);
			assert(rc==SQLITE_OK);
			while (i>0) {
				i--;
				MySQL_Monitor_State_Data *mmsd=sds[i];
				rc=sqlite3_bind_text(statement, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int(statement, 2, mmsd->port); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement, 3, start_time); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement, 4, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1)); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement, 5, mmsd->mysql_error_msg, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				SAFE_SQLITE3_STEP(statement);
				rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
				rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
				delete mmsd;
			}
			sqlite3_finalize(statement);
			free(sds);
		}
		if (resultset)
			delete resultset;

		event_base_free(libevent_base);

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
	return NULL;
}

void * MySQL_Monitor::monitor_ping() {
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	struct event_base *libevent_base;
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();

	unsigned long long t1;
	unsigned long long t2;
	unsigned long long start_time;
	unsigned long long next_loop_at=0;
	//unsigned int t1;
	//unsigned int t2;
	//t1=monotonic_time();

	while (shutdown==false) {

		unsigned int glover;
		char *error=NULL;
		int cols=0;
		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		MySQL_Monitor_State_Data **sds=NULL;
		int i=0;
		char *query=(char *)"SELECT DISTINCT hostname, port FROM mysql_servers";
		t1=monotonic_time();

		if (t1 < next_loop_at) {
			goto __sleep_monitor_ping_loop;
		}
		next_loop_at=t1+1000*mysql_thread___monitor_ping_interval;

		struct timeval tv_out;
		evutil_gettimeofday(&tv_out, NULL);
		start_time=(((unsigned long long) tv_out.tv_sec) * 1000000) + (tv_out.tv_usec);

		ping__num_active_connections=0;
		// create libevent base
		libevent_base= event_base_new();

		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			//proxy_error("%s\n","MySQL_Monitor - PING - refreshing variables");
		}

		proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
		admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		if (error) {
			proxy_error("Error on %s : %s\n", query, error);
			goto __end_monitor_ping_loop;
		} else {
			if (resultset->rows_count==0) {
				goto __end_monitor_ping_loop;
			}
			sds=(MySQL_Monitor_State_Data **)malloc(resultset->rows_count * sizeof(MySQL_Monitor_State_Data *));
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				sds[i] = new MySQL_Monitor_State_Data(r->fields[0],atoi(r->fields[1]),libevent_base);
				sds[i]->task_id=MON_PING;
				ping__num_active_connections++;
				total_ping__num_active_connections++;
				MySQL_Monitor_State_Data *_mmsd=sds[i];
				_mmsd->mysql=GloMyMon->My_Conn_Pool->get_connection(_mmsd->hostname, _mmsd->port);
				if (_mmsd->mysql==NULL) {
					state_machine_handler(-1,-1,_mmsd);
				} else {
					int fd=mysql_get_socket(_mmsd->mysql);
					_mmsd->ST=7;
					state_machine_handler(fd,-1,_mmsd);
				}
				i++;
			}
		}

		// start libevent loop
		event_base_dispatch(libevent_base);

__end_monitor_ping_loop:
		if (sds) {
			sqlite3_stmt *statement;
			sqlite3 *mondb=monitordb->get_db();
			int rc;
			char *query=NULL;
			query=(char *)"DELETE FROM mysql_server_ping_log WHERE time_start < ?1";
			rc=sqlite3_prepare_v2(mondb, query, -1, &statement, 0);
			assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement, 1, start_time-mysql_thread___monitor_history*1000); assert(rc==SQLITE_OK);
			SAFE_SQLITE3_STEP(statement);
			rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
			rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
			sqlite3_finalize(statement);

			query=(char *)"INSERT OR REPLACE INTO mysql_server_ping_log VALUES (?1 , ?2 , ?3 , ?4 , ?5)";
			rc=sqlite3_prepare_v2(mondb, query, -1, &statement, 0);
			assert(rc==SQLITE_OK);
			while (i>0) {
				i--;
				MySQL_Monitor_State_Data *mmsd=sds[i];
				rc=sqlite3_bind_text(statement, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int(statement, 2, mmsd->port); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement, 3, start_time); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement, 4, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1)); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_text(statement, 5, mmsd->mysql_error_msg, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				SAFE_SQLITE3_STEP(statement);
				rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
				rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
				delete mmsd;
			}
			sqlite3_finalize(statement);
			free(sds);
		}

		if (resultset)
			delete resultset;

		event_base_free(libevent_base);


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
	return NULL;
}
void * MySQL_Monitor::monitor_replication_lag() {
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	struct event_base *libevent_base;
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();

	unsigned long long t1;
	unsigned long long t2;
	unsigned long long start_time;
	unsigned long long next_loop_at=0;

	while (shutdown==false) {

		unsigned int glover;
		char *error=NULL;
//		int cols=0;
//		int affected_rows=0;
		SQLite3_result *resultset=NULL;
		MySQL_Monitor_State_Data **sds=NULL;
		int i=0;
		char *query=(char *)"SELECT hostgroup_id, hostname, port, max_replication_lag FROM mysql_servers WHERE max_replication_lag > 0 AND status NOT LIKE 'OFFLINE%'";
		t1=monotonic_time();

		if (t1 < next_loop_at) {
			goto __sleep_monitor_replication_lag;
		}
		next_loop_at=t1+1000*mysql_thread___monitor_replication_lag_interval;

		struct timeval tv_out;
		evutil_gettimeofday(&tv_out, NULL);
		start_time=(((unsigned long long) tv_out.tv_sec) * 1000000) + (tv_out.tv_usec);

		replication_lag__num_active_connections=0;
		// create libevent base
		libevent_base= event_base_new();

		glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			//proxy_error("%s\n","MySQL_Monitor - PING - refreshing variables");
		}

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
			sds=(MySQL_Monitor_State_Data **)malloc(resultset->rows_count * sizeof(MySQL_Monitor_State_Data *));
			for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
				SQLite3_row *r=*it;
				sds[i] = new MySQL_Monitor_State_Data(r->fields[1],atoi(r->fields[2]),libevent_base);
				sds[i]->task_id=MON_REPLICATION_LAG;
				sds[i]->hostgroup_id=atoi(r->fields[0]);
				sds[i]->repl_lag=atoi(r->fields[3]);
				replication_lag__num_active_connections++;
				total_replication_lag__num_active_connections++;
				MySQL_Monitor_State_Data *_mmsd=sds[i];
				_mmsd->mysql=GloMyMon->My_Conn_Pool->get_connection(_mmsd->hostname, _mmsd->port);
				if (_mmsd->mysql==NULL) {
					state_machine_handler(-1,-1,_mmsd);
				} else {
					int fd=mysql_get_socket(_mmsd->mysql);
					_mmsd->ST=10;
					state_machine_handler(fd,-1,_mmsd);
				}
				i++;
			}
		}

		// start libevent loop
		event_base_dispatch(libevent_base);

__end_monitor_replication_lag_loop:
		if (sds) {
			sqlite3_stmt *statement;
			sqlite3 *mondb=monitordb->get_db();
			int rc;
			char *query=NULL;
			query=(char *)"DELETE FROM mysql_server_replication_lag_log WHERE time_start < ?1";
			rc=sqlite3_prepare_v2(mondb, query, -1, &statement, 0);
			assert(rc==SQLITE_OK);
			rc=sqlite3_bind_int64(statement, 1, start_time-mysql_thread___monitor_history*1000); assert(rc==SQLITE_OK);
			SAFE_SQLITE3_STEP(statement);
			rc=sqlite3_clear_bindings(statement); assert(rc==SQLITE_OK);
			rc=sqlite3_reset(statement); assert(rc==SQLITE_OK);
			sqlite3_finalize(statement);

			query=(char *)"INSERT OR REPLACE INTO mysql_server_replication_lag_log VALUES (?1 , ?2 , ?3 , ?4 , ?5 , ?6)";
			rc=sqlite3_prepare_v2(mondb, query, -1, &statement, 0);
			assert(rc==SQLITE_OK);
			while (i>0) {
				i--;
				int repl_lag=-1;
				MySQL_Monitor_State_Data *mmsd=sds[i];
				rc=sqlite3_bind_text(statement, 1, mmsd->hostname, -1, SQLITE_TRANSIENT); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int(statement, 2, mmsd->port); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement, 3, start_time); assert(rc==SQLITE_OK);
				rc=sqlite3_bind_int64(statement, 4, (mmsd->mysql_error_msg ? 0 : mmsd->t2-mmsd->t1)); assert(rc==SQLITE_OK);
				if (mmsd->result) {
					unsigned int num_fields;
					unsigned int k;
					int j=-1;
					MYSQL_FIELD *fields;

					num_fields = mysql_num_fields(mmsd->result);
					fields = mysql_fetch_fields(mmsd->result);
					for(k = 0; k < num_fields; k++) {
						if (strcmp("Seconds_Behind_Master", fields[k].name)==0) {
							j=k;
						}
					}
					if (j>-1) {
						MYSQL_ROW row=mysql_fetch_row(mmsd->result);
						if (row[j]) {
							repl_lag=atoi(row[j]);
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
				MyHGM->replication_lag_action(mmsd->hostgroup_id, mmsd->hostname, mmsd->port, repl_lag);
				delete mmsd;
			}
			sqlite3_finalize(statement);
			free(sds);
		}

		if (resultset)
			delete resultset;

		event_base_free(libevent_base);


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
	return NULL;
}

void * MySQL_Monitor::run() {
	// initialize the MySQL Thread (note: this is not a real thread, just the structures associated with it)
	unsigned int MySQL_Monitor__thread_MySQL_Thread_Variables_version;
	MySQL_Thread * mysql_thr = new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();
	MySQL_Monitor__thread_MySQL_Thread_Variables_version=GloMTH->get_global_version();
	mysql_thr->refresh_variables();
	std::thread * monitor_connect_thread = new std::thread(&MySQL_Monitor::monitor_connect,this);
	std::thread * monitor_ping_thread = new std::thread(&MySQL_Monitor::monitor_ping,this);
	std::thread * monitor_replication_lag_thread = new std::thread(&MySQL_Monitor::monitor_replication_lag,this);
	while (shutdown==false) {
		unsigned int glover=GloMTH->get_global_version();
		if (MySQL_Monitor__thread_MySQL_Thread_Variables_version < glover ) {
			MySQL_Monitor__thread_MySQL_Thread_Variables_version=glover;
			mysql_thr->refresh_variables();
			//proxy_error("%s\n","MySQL_Monitor refreshing variables");
		}
		usleep(500000);
	}
	monitor_connect_thread->join();
	monitor_ping_thread->join();
	monitor_replication_lag_thread->join();
	return NULL;
};
