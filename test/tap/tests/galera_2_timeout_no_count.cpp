#include <iostream>     // std::cout
#include <algorithm>    // std::sort
#include <vector>       // std::vector
#include "re2/re2.h"
#include "re2/regexp.h"
#include "proxysql.h"
#include "cpp.h"

#include "MySQL_Logger.hpp"
#include "MySQL_Data_Stream.h"
#include "query_processor.h"
#include "SQLite3_Server.h"

#include <search.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/socket.h>
#include <resolv.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <fcntl.h>
#include <sys/utsname.h>

#include "tap.h"

#define SELECT_VERSION_COMMENT "select @@version_comment limit 1"
#define SELECT_VERSION_COMMENT_LEN 32
#define SELECT_DB_USER "select DATABASE(), USER() limit 1"
#define SELECT_DB_USER_LEN 33
#define SELECT_CHARSET_VARIOUS "select @@character_set_client, @@character_set_connection, @@character_set_server, @@character_set_database limit 1"
#define SELECT_CHARSET_VARIOUS_LEN 115

#define READ_ONLY_OFF "\x01\x00\x00\x01\x02\x23\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x1b\x00\x00\x03\x03\x64\x65\x66\x00\x00\x00\x05\x56\x61\x6c\x75\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x05\x00\x00\x04\xfe\x00\x00\x02\x00\x0e\x00\x00\x05\x09\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x03\x4f\x46\x46\x05\x00\x00\x06\xfe\x00\x00\x02\x00"
#define READ_ONLY_ON "\x01\x00\x00\x01\x02\x23\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x1b\x00\x00\x03\x03\x64\x65\x66\x00\x00\x00\x05\x56\x61\x6c\x75\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x05\x00\x00\x04\xfe\x00\x00\x02\x00\x0d\x00\x00\x05\x09\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x02\x4f\x4e\x05\x00\x00\x06\xfe\x00\x00\x02\x00"

extern SQLite3_Server *GloSQLite3Server;
extern MySQL_Authentication *GloMyAuth;
extern ProxySQL_Admin *GloAdmin;
extern MySQL_Threads_Handler *GloMTH;
extern MySQL_Logger *GloMyLogger;
extern MySQL_Monitor *GloMyMon;
extern SQLite3_Server *GloSQLite3Server;
extern MySQL_HostGroups_Manager *MyHGM;

static bool init_tap=false;
static std::vector<int> timeouts;

void SQLite3_Server::init_galera_ifaces_string(std::string& s) {
	if(!s.empty())
		s += ";";
	pthread_mutex_init(&galera_mutex,NULL);
	unsigned int ngs = time(NULL);
	ngs = ngs % 3; // range
	ngs += 5; // min
	max_num_galera_servers = 1; // hypothetical maximum number of nodes
	for (unsigned int j=1; j<4; j++) {
		//cur_aurora_writer[j-1] = 0;
		num_galera_servers[j-1] = ngs;
		for (unsigned int i=11; i<max_num_galera_servers+11 ; i++) {
			s += "127.1." + std::to_string(j) + "." + std::to_string(i) + ":3306";
			if ( j!=3 || (j==3 && i<max_num_galera_servers+11-1) ) {
				s += ";";
			}
		}
	}
}

void SQLite3_Server::populate_galera_table(MySQL_Session *sess) {
	// this function needs to be called with lock on mutex galera_mutex already acquired
	sessdb->execute("BEGIN TRANSACTION");
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
    SQLite3_result *resultset=NULL;
    //sqlite3 *mydb3=sessdb->get_db();
	string myip = string(sess->client_myds->proxy_addr.addr);
	string clu_id_s = myip.substr(6,1);
	unsigned int cluster_id = atoi(clu_id_s.c_str());
	cluster_id--;
	int hg_id = 2270+(cluster_id*10)+1;
	char buf[1024];
	sprintf(buf, (char *)"SELECT * FROM HOST_STATUS_GALERA WHERE hostgroup_id = %d LIMIT 1", hg_id);
	sessdb->execute_statement(buf, &error , &cols , &affected_rows , &resultset);
	if (resultset->rows_count==0) {
		//sessdb->execute("DELETE FROM HOST_STATUS_GALERA");
		sqlite3_stmt *statement=NULL;
		int rc;
		char *query=(char *)"INSERT INTO HOST_STATUS_GALERA VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)";
		//rc=sqlite3_prepare_v2(mydb3, query, -1, &statement, 0);
		rc = sessdb->prepare_v2(query, &statement);
		ASSERT_SQLITE_OK(rc, sessdb);
		for (unsigned int i=0; i<num_galera_servers[cluster_id]; i++) {
			string serverid = "";
			serverid = "127.1." + std::to_string(cluster_id+1) + "." + std::to_string(i+11);

			rc=sqlite3_bind_int64(statement, 1, hg_id); ASSERT_SQLITE_OK(rc, sessdb);
			rc=sqlite3_bind_text(statement, 2, serverid.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sessdb);
			rc=sqlite3_bind_int64(statement, 3, 3306); ASSERT_SQLITE_OK(rc, sessdb);
			rc=sqlite3_bind_int64(statement, 4, 4); ASSERT_SQLITE_OK(rc, sessdb);
			rc=sqlite3_bind_int64(statement, 5, 0); ASSERT_SQLITE_OK(rc, sessdb);
			rc=sqlite3_bind_int64(statement, 6, 0); ASSERT_SQLITE_OK(rc, sessdb);
			rc=sqlite3_bind_int64(statement, 7, 0); ASSERT_SQLITE_OK(rc, sessdb);
			rc=sqlite3_bind_text(statement, 8, (char *)"NONE", -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sessdb);
			rc=sqlite3_bind_int64(statement, 9, 0); ASSERT_SQLITE_OK(rc, sessdb);
			rc=sqlite3_bind_text(statement, 10, (char *)"Primary", -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sessdb);

			SAFE_SQLITE3_STEP2(statement);
			rc=sqlite3_clear_bindings(statement); ASSERT_SQLITE_OK(rc, sessdb);
			rc=sqlite3_reset(statement); ASSERT_SQLITE_OK(rc, sessdb);
		}
		sqlite3_finalize(statement);
	}
	sessdb->execute("COMMIT");
}

void SQLite3_Server_session_handler(MySQL_Session *sess, void *_pa, PtrSize_t *pkt) {

	char *error=NULL;
	int cols;
	int affected_rows;
	bool run_query=true;
	SQLite3_result *resultset=NULL;
	char *strA=NULL;
	char *strB=NULL;
	int strAl, strBl;
	char *query=NULL;
	unsigned int query_length=pkt->size-sizeof(mysql_hdr);
	static int num_timeouts=0;
	static int iteration=0;
	auto max_timeouts = mysql_thread___monitor_galera_healthcheck_max_timeout_count;

	if (sess->client_myds->proxy_addr.addr == NULL) {
		struct sockaddr addr;
		socklen_t addr_len=sizeof(struct sockaddr);
		memset(&addr,0,addr_len);
		int rc;
		rc=getsockname(sess->client_myds->fd, &addr, &addr_len);
		if (rc==0) {
			char buf[512];
			switch (addr.sa_family) {
				case AF_INET: {
						struct sockaddr_in *ipv4 = (struct sockaddr_in *)&addr;
						inet_ntop(addr.sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
						sess->client_myds->proxy_addr.addr = strdup(buf);
					}
					break;
				case AF_INET6: {
						struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&addr;
						inet_ntop(addr.sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
						sess->client_myds->proxy_addr.addr = strdup(buf);
					}
					break;
				default:
					sess->client_myds->proxy_addr.addr = strdup("unknown");
					break;
			}
		} else {
			sess->client_myds->proxy_addr.addr = strdup("unknown");
		}
	}

	if (strncmp("127.1.", sess->client_myds->proxy_addr.addr, 6)) return;

	if (!init_tap) {
		plan(13);
		diag("Testing GALERA timeout offline");
		init_tap=true;

		for (auto i=0; i<max_timeouts-1; i++)
			timeouts.push_back(1);
		timeouts.push_back(0);
		for (auto i=0; i<max_timeouts-1; i++)
			timeouts.push_back(1);
		timeouts.push_back(0);
	}

	query=(char *)l_alloc(query_length);
	memcpy(query,(char *)pkt->ptr+sizeof(mysql_hdr)+1,query_length-1);
	query[query_length-1]=0;

	char *query_no_space=(char *)l_alloc(query_length);
	memcpy(query_no_space,query,query_length);

	unsigned int query_no_space_length=remove_spaces(query_no_space);

	// fix bug #925
	while (query_no_space[query_no_space_length-1]==';' || query_no_space[query_no_space_length-1]==' ') {
		query_no_space_length--;
		query_no_space[query_no_space_length]=0;
	}

	if (run_query) {
		if (strncasecmp("SELECT",query_no_space,6)==0) {
			if (strstr(query_no_space,(char *)"HOST_STATUS_GALERA")) {
				pthread_mutex_lock(&GloSQLite3Server->galera_mutex);
				GloSQLite3Server->populate_galera_table(sess);
			}
			if (strstr(query_no_space,(char *)"Seconds_Behind_Master")) {
				free(query);
				char *a = (char *)"SELECT %d as Seconds_Behind_Master";
				query = (char *)malloc(strlen(a)+4);
				sprintf(query,a,rand()%30+10);
			}
		}
		SQLite3_Session *sqlite_sess = (SQLite3_Session *)sess->thread->gen_args;
		sqlite_sess->sessdb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		if (strncasecmp("SELECT",query_no_space,6)==0) {
			if (strstr(query_no_space,(char *)"HOST_STATUS_GALERA")) {
				pthread_mutex_unlock(&GloSQLite3Server->galera_mutex);
				if (resultset->rows_count == 0) {
					PROXY_TRACE();
				}
			}

			if (!strcmp(sess->client_myds->proxy_addr.addr, "127.1.1.11")) {
				if (timeouts[iteration]) {
					sleep(2);
					num_timeouts++;
				}
				iteration++;

				GloMyMon->populate_monitor_mysql_server_galera_log();
				char *error=NULL;
				int cols=0;
				int affected_rows=0;
				SQLite3_result *rs1=NULL;

				GloMyMon->monitordb->execute_statement("SELECT * FROM mysql_server_galera_log WHERE hostname = '127.1.1.11'", &error, &cols, &affected_rows, &rs1);
				rs1->dump_to_stderr();
				int actual_timeouts=0;
				for (auto r : rs1->rows) {
					if (r->fields[11] && !strcmp(r->fields[11],"timeout check") ) {
						actual_timeouts++;
					}
					else {
						actual_timeouts=0;
					}
				}
				delete rs1;

				std::unique_ptr<SQLite3_result> rs = std::unique_ptr<SQLite3_result>(MyHGM->dump_table_mysql("mysql_servers"));
				for (auto r : rs->rows) {
					if (r->fields[0] && r->fields[1] && !strcmp(r->fields[1], "127.1.1.11") && strcmp(r->fields[0],"2274")) {
						ok(true, "Host stays online. Max timeouts count [%d], number of timeouts in a row [%d], generated timeouts [%d]", max_timeouts, actual_timeouts, num_timeouts);
						if (iteration == timeouts.size()) {
							exit_status();
							exit(0);
						}
					}
				}
				ok(iteration < timeouts.size(), "Continue iteration. Still have data in timeouts vector.");
				if (iteration >= timeouts.size()) {
					exit_status();
					exit(3);
				}
			}
		}
		sqlite3 *db = sqlite_sess->sessdb->get_db();
		bool in_trans = false;
		if (sqlite3_get_autocommit(db)==0) {
			in_trans = true;
		}
		sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot, in_trans);
		delete resultset;
	}
	l_free(pkt->size-sizeof(mysql_hdr),query_no_space); // it is always freed here
	l_free(query_length,query);
}

