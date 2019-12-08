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
#include "SpookyV2.h"

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
		char *query=(char *)"INSERT INTO HOST_STATUS_GALERA VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)";
		//rc=sqlite3_prepare_v2(mydb3, query, -1, &statement, 0);
		rc = sessdb->prepare_v2(query, &statement);
		ASSERT_SQLITE_OK(rc, sessdb);
		for (unsigned int i=0; i<num_galera_servers[cluster_id]; i++) {
			string serverid = "";
			serverid = "127.1." + std::to_string(cluster_id+1) + "." + std::to_string(i+11);
//			fprintf(stderr,"%d , %s:3306 \n", hg_id , serverid.c_str());

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

			char *pxt_maint_mode = rand()%2==0?(char*)"ENABLED":(char*)"DISABLED";
			rc=sqlite3_bind_text(statement, 11, pxt_maint_mode, -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sessdb);

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
	query=(char *)l_alloc(query_length);
	memcpy(query,(char *)pkt->ptr+sizeof(mysql_hdr)+1,query_length-1);
	query[query_length-1]=0;

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

	char *query_no_space=(char *)l_alloc(query_length);
	memcpy(query_no_space,query,query_length);

	unsigned int query_no_space_length=remove_spaces(query_no_space);

	// fix bug #925
	while (query_no_space[query_no_space_length-1]==';' || query_no_space[query_no_space_length-1]==' ') {
		query_no_space_length--;
		query_no_space[query_no_space_length]=0;
	}

	// fix bug #1047
	if (
/*
		(!strncasecmp("BEGIN", query_no_space, strlen("BEGIN")))
		||
		(!strncasecmp("START TRANSACTION", query_no_space, strlen("START TRANSACTION")))
		||
		(!strncasecmp("COMMIT", query_no_space, strlen("COMMIT")))
		||
		(!strncasecmp("ROLLBACK", query_no_space, strlen("ROLLBACK")))
		||
*/
		(!strncasecmp("SET character_set_results", query_no_space, strlen("SET character_set_results")))
		||
		(!strncasecmp("SET SQL_AUTO_IS_NULL", query_no_space, strlen("SET SQL_AUTO_IS_NULL")))
		||
		(!strncasecmp("SET NAMES", query_no_space, strlen("SET NAMES")))
		||
		(!strncasecmp("SET AUTOCOMMIT", query_no_space, strlen("SET AUTOCOMMIT")))
		||
		(!strncasecmp("/*!40100 SET @@SQL_MODE='' */", query_no_space, strlen("/*!40100 SET @@SQL_MODE='' */")))
		||
		(!strncasecmp("/*!40103 SET TIME_ZONE=", query_no_space, strlen("/*!40103 SET TIME_ZONE=")))
		||
		(!strncasecmp("/*!80000 SET SESSION", query_no_space, strlen("/*!80000 SET SESSION")))
		||
		(!strncasecmp("SET SESSION", query_no_space, strlen("SET SESSION")))
		||
		(!strncasecmp("SET wait_timeout", query_no_space, strlen("SET wait_timeout")))
	) {
		SQLite3_Session *sqlite_sess = (SQLite3_Session *)sess->thread->gen_args;
		sqlite3 *db = sqlite_sess->sessdb->get_db();
		uint16_t status=2; // autocommit
		if (sqlite3_get_autocommit(db)==0) {
			status = 3; // autocommit + transaction
		}
		GloSQLite3Server->send_MySQL_OK(&sess->client_myds->myprot, NULL, 0, status);
		run_query=false;
		goto __run_query;
	}

	if (query_no_space_length==17) {
		if (!strncasecmp((char *)"START TRANSACTION", query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			query = l_strdup((char *)"BEGIN IMMEDIATE");
			query_length=strlen(query)+1;
			goto __run_query;
		}
	}

	if (query_no_space_length==5) {
		if (!strncasecmp((char *)"BEGIN", query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			query = l_strdup((char *)"BEGIN IMMEDIATE");
			query_length=strlen(query)+1;
			goto __run_query;
		}
	}

	if (query_no_space_length==SELECT_VERSION_COMMENT_LEN) {
		if (!strncasecmp(SELECT_VERSION_COMMENT, query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			char *a = (char *)"SELECT '(ProxySQL Automated Test Server) - %s'";
			query = (char *)malloc(strlen(a)+strlen(sess->client_myds->proxy_addr.addr));
			sprintf(query,a,sess->client_myds->proxy_addr.addr);
			query_length=strlen(query)+1;
			goto __run_query;
		}
	}

	if (query_no_space_length==SELECT_DB_USER_LEN) {
		if (!strncasecmp(SELECT_DB_USER, query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			char *query1=(char *)"SELECT \"admin\" AS 'DATABASE()', \"%s\" AS 'USER()'";
			char *query2=(char *)malloc(strlen(query1)+strlen(sess->client_myds->myconn->userinfo->username)+10);
			sprintf(query2,query1,sess->client_myds->myconn->userinfo->username);
			query=l_strdup(query2);
			query_length=strlen(query2)+1;
			free(query2);
			goto __run_query;
		}
	}

	if (query_no_space_length==SELECT_CHARSET_VARIOUS_LEN) {
		if (!strncasecmp(SELECT_CHARSET_VARIOUS, query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			char *query1=(char *)"select 'utf8' as '@@character_set_client', 'utf8' as '@@character_set_connection', 'utf8' as '@@character_set_server', 'utf8' as '@@character_set_database' limit 1";
			query=l_strdup(query1);
			query_length=strlen(query1)+1;
			goto __run_query;
		}
	}

	if (!strncasecmp("SELECT @@version", query_no_space, strlen("SELECT @@version"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT '%s' AS '@@version'";
		query_length=strlen(q)+20;
		query=(char *)l_alloc(query_length);
		sprintf(query,q,PROXYSQL_VERSION);
		goto __run_query;
	}

	if (!strncasecmp("SELECT version()", query_no_space, strlen("SELECT version()"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT '%s' AS 'version()'";
		query_length=strlen(q)+20;
		query=(char *)l_alloc(query_length);
		sprintf(query,q,PROXYSQL_VERSION);
		goto __run_query;
	}

	if (strncasecmp("SHOW ", query_no_space, 5)) {
		goto __end_show_commands; // in the next block there are only SHOW commands
	}

	if (query_no_space_length==strlen("SHOW TABLES") && !strncasecmp("SHOW TABLES",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT name AS tables FROM sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence') ORDER BY name");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if ((query_no_space_length>17) && (!strncasecmp("SHOW TABLES FROM ", query_no_space, 17))) {
		strA=query_no_space+17;
		strAl=strlen(strA);
		strB=(char *)"SELECT name AS tables FROM %s.sqlite_master WHERE type='table' AND name NOT IN ('sqlite_sequence') ORDER BY name";
		strBl=strlen(strB);
		int l=strBl+strAl-2;
		char *b=(char *)l_alloc(l+1);
		snprintf(b,l+1,strB,strA);
		b[l]=0;
		l_free(query_length,query);
		query=b;
		query_length=l+1;
		goto __run_query;
	}

	if ((query_no_space_length>17) && (!strncasecmp("SHOW TABLES LIKE ", query_no_space, 17))) {
		strA=query_no_space+17;
		strAl=strlen(strA);
		strB=(char *)"SELECT name AS tables FROM sqlite_master WHERE type='table' AND name LIKE '%s'";
		strBl=strlen(strB);
		char *tn=NULL; // tablename
		tn=(char *)malloc(strlen(strA));
		unsigned int i=0, j=0;
		while (i<strlen(strA)) {
			if (strA[i]!='\\' && strA[i]!='`' && strA[i]!='\'') {
				tn[j]=strA[i];
				j++;
			}
			i++;
		}
		tn[j]=0;
		int l=strBl+strlen(tn)-2;
		char *b=(char *)l_alloc(l+1);
		snprintf(b,l+1,strB,tn);
		b[l]=0;
		free(tn);
		l_free(query_length,query);
		query=b;
		query_length=l+1;
		goto __run_query;
	}

	strA=(char *)"SHOW CREATE TABLE ";
	strB=(char *)"SELECT name AS 'table' , REPLACE(REPLACE(sql,' , ', X'2C0A20202020'),'CREATE TABLE %s (','CREATE TABLE %s ('||X'0A20202020') AS 'Create Table' FROM %s.sqlite_master WHERE type='table' AND name='%s'";
	strAl=strlen(strA);
  if (strncasecmp("SHOW CREATE TABLE ", query_no_space, strAl)==0) {
		strBl=strlen(strB);
		char *dbh=NULL;
		char *tbh=NULL;
		c_split_2(query_no_space+strAl,".",&dbh,&tbh);

		if (strlen(tbh)==0) {
			free(tbh);
			tbh=dbh;
			dbh=strdup("main");
		}
		if (strlen(tbh)>=3 && tbh[0]=='`' && tbh[strlen(tbh)-1]=='`') { // tablename is quoted
			char *tbh_tmp=(char *)malloc(strlen(tbh)-1);
			strncpy(tbh_tmp,tbh+1,strlen(tbh)-2);
			tbh_tmp[strlen(tbh)-2]=0;
			free(tbh);
			tbh=tbh_tmp;
		}
		int l=strBl+strlen(tbh)*3+strlen(dbh)-8;
		char *buff=(char *)l_alloc(l+1);
		snprintf(buff,l+1,strB,tbh,tbh,dbh,tbh);
		buff[l]=0;
		free(tbh);
		free(dbh);
		l_free(query_length,query);
		query=buff;
		query_length=l+1;
		goto __run_query;
	}

	if (
		(query_no_space_length==strlen("SHOW DATABASES") && !strncasecmp("SHOW DATABASES",query_no_space, query_no_space_length))
		||
		(query_no_space_length==strlen("SHOW SCHEMAS") && !strncasecmp("SHOW SCHEMAS",query_no_space, query_no_space_length))
	) {
		l_free(query_length,query);
		query=l_strdup("PRAGMA DATABASE_LIST");
		query_length=strlen(query)+1;
		goto __run_query;
	}

__end_show_commands:

	if (query_no_space_length==strlen("SELECT DATABASE()") && !strncasecmp("SELECT DATABASE()",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT \"main\" AS 'DATABASE()'");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	// see issue #1022
	if (query_no_space_length==strlen("SELECT DATABASE() AS name") && !strncasecmp("SELECT DATABASE() AS name",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT \"main\" AS 'DATABASE()'");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if (sess->session_type == PROXYSQL_SESSION_SQLITE) { // no admin
		if (
			(strncasecmp("PRAGMA",query_no_space,6)==0)
			||
			(strncasecmp("ATTACH",query_no_space,6)==0)
		) {
			proxy_error("[WARNING]: Commands executed from stats interface in Admin Module: \"%s\"\n", query_no_space);
			GloSQLite3Server->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Command not allowed");
			run_query=false;
		}
	}

__run_query:
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
				if (rand() % 20 == 0) {
					// randomly add some latency on 5% of the traffic
					sleep(2);
				}
			}
			if (strstr(query_no_space,(char *)"Seconds_Behind_Master")) {
				if (rand() % 10 == 0) {
					// randomly add some latency on 10% of the traffic
					sleep(2);
				}
			}
			ok(true, "Success");
			exit(0);
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

