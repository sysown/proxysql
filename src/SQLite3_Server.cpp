#include <iostream>     // std::cout
#include <algorithm>    // std::sort
#include <vector>       // std::vector
#include "re2/re2.h"
#include "re2/regexp.h"
#include "proxysql.h"
#include "cpp.h"

#include "MySQL_Logger.hpp"
#include "MySQL_Data_Stream.h"
#include "proxysql_utils.h"
#include "MySQL_Query_Processor.h"
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
#include <pthread.h>
#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

#include <fcntl.h>
#include <sys/utsname.h>

using std::string;

#define SELECT_VERSION_COMMENT "select @@version_comment limit 1"
#define SELECT_VERSION_COMMENT_LEN 32
#define SELECT_DB_USER "select DATABASE(), USER() limit 1"
#define SELECT_DB_USER_LEN 33
#define SELECT_CHARSET_VARIOUS "select @@character_set_client, @@character_set_connection, @@character_set_server, @@character_set_database limit 1"
#define SELECT_CHARSET_VARIOUS_LEN 115

#define READ_ONLY_OFF "\x01\x00\x00\x01\x02\x23\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x1b\x00\x00\x03\x03\x64\x65\x66\x00\x00\x00\x05\x56\x61\x6c\x75\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x05\x00\x00\x04\xfe\x00\x00\x02\x00\x0e\x00\x00\x05\x09\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x03\x4f\x46\x46\x05\x00\x00\x06\xfe\x00\x00\x02\x00"
#define READ_ONLY_ON "\x01\x00\x00\x01\x02\x23\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x0d\x56\x61\x72\x69\x61\x62\x6c\x65\x5f\x6e\x61\x6d\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x1b\x00\x00\x03\x03\x64\x65\x66\x00\x00\x00\x05\x56\x61\x6c\x75\x65\x00\x0c\x21\x00\x0f\x00\x00\x00\xfd\x01\x00\x1f\x00\x00\x05\x00\x00\x04\xfe\x00\x00\x02\x00\x0d\x00\x00\x05\x09\x72\x65\x61\x64\x5f\x6f\x6e\x6c\x79\x02\x4f\x4e\x05\x00\x00\x06\xfe\x00\x00\x02\x00"


#ifdef __APPLE__
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif // MSG_NOSIGNAL
#endif // __APPLE__

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

/*
struct cpu_timer
{
	cpu_timer() {
		begin = monotonic_time();
	}
	~cpu_timer()
	{
		unsigned long long end = monotonic_time();
#ifdef DEBUG
		std::cerr << double( end - begin ) / 1000000 << " secs.\n" ;
#endif
		begin=end-begin; // make the compiler happy
	};
	unsigned long long begin;
};
*/

static char *s_strdup(char *s) {
	char *ret=NULL;
	if (s) {
		ret=strdup(s);
	}
	return ret;
}

static int __SQLite3_Server_refresh_interval=1000;

extern MySQL_Query_Cache *GloMyQC;
extern MySQL_Authentication *GloMyAuth;
extern ProxySQL_Admin *GloAdmin;
extern MySQL_Query_Processor* GloMyQPro;
extern MySQL_Threads_Handler *GloMTH;
extern MySQL_Logger *GloMyLogger;
extern MySQL_Monitor *GloMyMon;
extern SQLite3_Server *GloSQLite3Server;

#define PANIC(msg)  { perror(msg); exit(EXIT_FAILURE); }


static pthread_mutex_t sock_mutex = PTHREAD_MUTEX_INITIALIZER;

static char * SQLite3_Server_variables_names[] = {
	(char *)"mysql_ifaces",
	(char *)"read_only",
  NULL
};

static void * (*child_func[1]) (void *arg);

typedef struct _main_args {
	int nfds;
	struct pollfd *fds;
	int *callback_func;
	volatile int *shutdown;
} main_args;

typedef struct _ifaces_desc_t {
		char **mysql_ifaces;
} ifaces_desc_t;

#define MAX_IFACES	128
#define MAX_SQLITE3SERVER_LISTENERS 128

class ifaces_desc {
	public:
	PtrArray *ifaces;
	ifaces_desc() {
		ifaces=new PtrArray();
	}
	bool add(const char *iface) {
		for (unsigned int i=0; i<ifaces->len; i++) {
			if (strcmp((const char *)ifaces->index(i),iface)==0) {
				return false;
			}
		}
		ifaces->add(strdup(iface));
		return true;
	}
	~ifaces_desc() {
		while(ifaces->len) {
			char *d=(char *)ifaces->remove_index_fast(0);
			free(d);
		}
		delete ifaces;
	}
};

class sqlite3server_main_loop_listeners {
	private:
	int version;
	pthread_rwlock_t rwlock;

	char ** reset_ifaces(char **ifaces) {
		int i;
		if (ifaces) {
			for (i=0; i<MAX_IFACES; i++) {
				if (ifaces[i]) free(ifaces[i]);
			}
		} else {
			ifaces=(char **)malloc(sizeof(char *)*MAX_IFACES);
		}
		for (i=0; i<MAX_IFACES; i++) {
			ifaces[i]=NULL;
		}
		return ifaces;
	}


	public:
	int nfds;
	struct pollfd *fds;
	int *callback_func;
	int get_version() { return version; }
	void wrlock() {
		pthread_rwlock_wrlock(&rwlock);
	}
	void wrunlock() {
		pthread_rwlock_unlock(&rwlock);
	}
	ifaces_desc *ifaces_mysql;
	ifaces_desc_t descriptor_new;
	sqlite3server_main_loop_listeners() {
		pthread_rwlock_init(&rwlock, NULL);
		ifaces_mysql=new ifaces_desc();
		version=0;
		descriptor_new.mysql_ifaces=NULL;
	}


	void update_ifaces(char *list, ifaces_desc **ifd) {
		wrlock();
		delete *ifd;
		*ifd=new ifaces_desc();
		int i=0;
		tokenizer_t tok;
		tokenizer( &tok, list, ";", TOKENIZER_NO_EMPTIES );
		const char* token;
		for ( token = tokenize( &tok ) ; token && i < MAX_IFACES ; token = tokenize( &tok ) ) {
			(*ifd)->add(token);
			i++;
		}
		free_tokenizer( &tok );
		version++;
		wrunlock();
	}


	bool update_ifaces(char *list, char ***_ifaces) {
		wrlock();
		int i;
		char **ifaces=*_ifaces;
		tokenizer_t tok;
		tokenizer( &tok, list, ";", TOKENIZER_NO_EMPTIES );
		const char* token;
		ifaces=reset_ifaces(ifaces);
		i=0;
		for ( token = tokenize( &tok ) ; token && i < MAX_IFACES ; token = tokenize( &tok ) ) {
			ifaces[i]=(char *)malloc(strlen(token)+1);
			strcpy(ifaces[i],token);
			i++;
		}
		free_tokenizer( &tok );
		version++;
		wrunlock();
		return true;
	}
};

static sqlite3server_main_loop_listeners S_amll;

#ifdef TEST_GROUPREP
/**
 * @brief Helper function that checks if the supplied string
 *   is a number.
 * @param s The string to check.
 * @return True if the supplied string is just composed of
 *   digits, false otherwise.
 */
bool is_number(const std::string& s) {
	if (s.empty()) { return false; }

	for (const auto& d : s) {
		if (std::isdigit(d) == false) {
			return false;
		}
	}

	return true;
}

/**
 * @brief Checks if the query matches an specified 'monitor_query' of the
 *   following format:
 *
 *   "$MONITOR_QUERY" + " hostname:port"
 *
 *   If the query matches, 'true' is returned, false otherwise.
 *
 * @param monitor_query Query that should be matched against the current
 *   supplied 'query'.
 * @param query Current query, to be matched against the supplied
 *   'monitor_query'.
 * @return 'true' if the query matches, false otherwise.
 */
bool match_monitor_query(const std::string& monitor_query, const std::string& query) {
	if (query.rfind(monitor_query, 0) != 0) {
		return false;
	}

	std::string srv_address {
		query.substr(monitor_query.size())
	};

	// Check that what is beyond this point, is just the servers address,
	// written as an identifier 'n.n.n.n:n'.
	std::size_t cur_mark_pos = 0;
	for (int i = 0; i < 3; i++) {
		std::size_t next_mark_pos = srv_address.find('.', cur_mark_pos);
		if (next_mark_pos == std::string::npos) {
			return false;
		} else {
			std::string number {
				srv_address.substr(cur_mark_pos, next_mark_pos - cur_mark_pos)
			};

			if (is_number(number)) {
				cur_mark_pos = next_mark_pos + 1;
			} else {
				return false;
			}
		}
	}

	// Check last part is also a valid number
	cur_mark_pos = srv_address.find(':', cur_mark_pos);
	if (cur_mark_pos == std::string::npos) {
		return false;
	} else {
		std::string number {
			srv_address.substr(cur_mark_pos + 1)
		};

		return is_number(number);
	}
}
#endif // TEST_GROUPREP

#ifdef TEST_AURORA

using std::vector;

using aurora_hg_info_t = std::tuple<uint32_t,uint32_t,string>;
enum AURORA_HG_INFO {
	WRITER_HG,
	READER_HG,
	DOMAIN_NAME
};

vector<aurora_hg_info_t> get_hgs_info(SQLite3DB* db) {
	vector<aurora_hg_info_t> whgs {};

	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
    SQLite3_result* resultset = NULL;

	GloAdmin->admindb->execute_statement(
		"SELECT writer_hostgroup,reader_hostgroup,domain_name FROM mysql_aws_aurora_hostgroups",
		&error, &cols, &affected_rows, &resultset
	);

	for (const SQLite3_row* r : resultset->rows) {
		uint32_t writer_hg = atoi(r->fields[0]);
		uint32_t reader_hg = atoi(r->fields[1]);
		string domain_name { r->fields[2] };

		whgs.push_back({writer_hg, reader_hg, domain_name});
	}

	return whgs;
}


#endif

void SQLite3_Server_session_handler(MySQL_Session* sess, void *_pa, PtrSize_t *pkt) {

	char *error=NULL;
	int cols;
	int affected_rows;
	bool run_query=true;
	SQLite3_result *resultset=NULL;
	char *strA=NULL;
	char *strB=NULL;
	size_t strAl, strBl;
	char *query=NULL;
	unsigned int query_length=pkt->size-sizeof(mysql_hdr);
	query=(char *)l_alloc(query_length);
	memcpy(query,(char *)pkt->ptr+sizeof(mysql_hdr)+1,query_length-1);
	query[query_length-1]=0;

#if defined(TEST_AURORA) || defined(TEST_GALERA) || defined(TEST_GROUPREP) || defined(TEST_READONLY) || defined(TEST_REPLICATIONLAG)
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
#endif // TEST_AURORA || TEST_GALERA || TEST_GROUPREP || TEST_READONLY || TEST_REPLICATIONLAG

	char *query_no_space=(char *)l_alloc(query_length);
	memcpy(query_no_space,query,query_length);

	unsigned int query_no_space_length=remove_spaces(query_no_space);

	// fix bug #925
	while (query_no_space[query_no_space_length-1]==';' || query_no_space[query_no_space_length-1]==' ') {
		query_no_space_length--;
		query_no_space[query_no_space_length]=0;
	}

	proxy_debug(PROXY_DEBUG_SQLITE, 4, "Received query on Session %p , thread_session_id %u : %s\n", sess, sess->thread_session_id, query_no_space);

	{
		SQLite3_Session *sqlite_sess = (SQLite3_Session *)sess->thread->gen_args;
		sqlite3 *db = sqlite_sess->sessdb->get_db();
		char c=((char *)pkt->ptr)[5];
		bool ret=false;
		if (c=='c' || c=='C') {
			if (strncasecmp((char *)"commit",(char *)pkt->ptr+5,6)==0) {
				if ((*proxy_sqlite3_get_autocommit)(db)==1) {
					ret=true;
				}
			}
		} else {
			if (c=='r' || c=='R') {
				if ( strncasecmp((char *)"rollback",(char *)pkt->ptr+5,8)==0 ) {
					if ((*proxy_sqlite3_get_autocommit)(db)==1) {
						ret=true;
					}
				}
			}
		}
		// if there is no transactions we filter both commit and rollback
		if (ret == true) {
			uint16_t status=0;
			if (sess->autocommit) status |= SERVER_STATUS_AUTOCOMMIT;
			if ((*proxy_sqlite3_get_autocommit)(db)==0) {
				status |= SERVER_STATUS_IN_TRANS;
			}
			GloSQLite3Server->send_MySQL_OK(&sess->client_myds->myprot, NULL, 0, status);
			run_query=false;
			goto __run_query;
		}
	}



	{
		SQLite3_Session *sqlite_sess = (SQLite3_Session *)sess->thread->gen_args;
		sqlite3 *db = sqlite_sess->sessdb->get_db();
		bool prev_autocommit = sess->autocommit;
		bool autocommit_to_skip = sess->handler_SetAutocommit(pkt);
		if (prev_autocommit == sess->autocommit) {
			if (autocommit_to_skip==true) {
				uint16_t status=0;
				if (sess->autocommit) status |= SERVER_STATUS_AUTOCOMMIT;
				if ((*proxy_sqlite3_get_autocommit)(db)==0) {
					status |= SERVER_STATUS_IN_TRANS;
				}
				GloSQLite3Server->send_MySQL_OK(&sess->client_myds->myprot, NULL, 0, status);
				run_query=false;
				goto __run_query;
			}
		} else {
			// autocommit changed
			if (sess->autocommit == false) {
				// we simply reply ok. We will create a transaction at the next query
				// we defer the creation of the transaction to simulate how MySQL works
				uint16_t status=0;
				if (sess->autocommit) status |= SERVER_STATUS_AUTOCOMMIT;
				if ((*proxy_sqlite3_get_autocommit)(db)==0) {
					status |= SERVER_STATUS_IN_TRANS;
				}
				GloSQLite3Server->send_MySQL_OK(&sess->client_myds->myprot, NULL, 0, status);
				run_query=false;
				goto __run_query;
/*
				l_free(query_length,query);
				query = l_strdup((char *)"BEGIN IMMEDIATE");
				query_length=strlen(query)+1;
				goto __run_query;
*/
			} else {
				// setting autocommit=1
				if ((*proxy_sqlite3_get_autocommit)(db)==1) {
					// there is no transaction
					uint16_t status=0;
					if (sess->autocommit) status |= SERVER_STATUS_AUTOCOMMIT;
					if ((*proxy_sqlite3_get_autocommit)(db)==0) {
						status |= SERVER_STATUS_IN_TRANS;
					}
					GloSQLite3Server->send_MySQL_OK(&sess->client_myds->myprot, NULL, 0, status);
					run_query=false;
					goto __run_query;
				} else {
					// there is a transaction, we run COMMIT
					l_free(query_length,query);
					query = l_strdup((char *)"COMMIT");
					query_length=strlen(query)+1;
					goto __run_query;
				}
			}
		}
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
		//(!strncasecmp("SET AUTOCOMMIT", query_no_space, strlen("SET AUTOCOMMIT")))
		//||
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
		uint16_t status=0;
		if (sess->autocommit) status |= SERVER_STATUS_AUTOCOMMIT;
		if ((*proxy_sqlite3_get_autocommit)(db)==0) {
			status |= SERVER_STATUS_IN_TRANS;
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
#if defined(TEST_AURORA) || defined(TEST_GALERA) || defined(TEST_GROUPREP) || defined(TEST_READONLY) || defined(TEST_REPLICATIONLAG)
			char *a = (char *)"SELECT '(ProxySQL Automated Test Server) - %s'";
			query = (char *)malloc(strlen(a)+strlen(sess->client_myds->proxy_addr.addr));
			sprintf(query,a,sess->client_myds->proxy_addr.addr);
#else
			query=l_strdup("SELECT '(ProxySQL SQLite3 Server)'");
#endif // TEST_AURORA || TEST_GALERA || TEST_GROUPREP || TEST_READONLY || TEST_REPLICATIONLAG
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
		query_length=strlen(q)+strlen(PROXYSQL_VERSION)+20;
		query=(char *)l_alloc(query_length);
		sprintf(query,q,PROXYSQL_VERSION);
		goto __run_query;
	}

	if (!strncasecmp("SELECT version()", query_no_space, strlen("SELECT version()"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT '%s' AS 'version()'";
		query_length=strlen(q)+strlen(PROXYSQL_VERSION)+20;
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
		tn=(char *)malloc(strAl+1);
		unsigned int i=0, j=0;
		while (i<strAl) {
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

	if (query_length>20 && strncasecmp(query,"SELECT",6)==0) {
		if (strncasecmp(query+query_length-12," FOR UPDATE",11)==0) {
			char * query_new = strndup(query,query_length-12);
			l_free(query_length,query);
			query_length-=11;
			query = query_new;
		} else if (strncasecmp(query+query_length-20," LOCK IN SHARE MODE",19)==0) {
			char * query_new = strndup(query,query_length-20);
			l_free(query_length,query);
			query_length-=11;
			query = query_new;
		}
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
#if defined(TEST_AURORA) || defined(TEST_GALERA) || defined(TEST_GROUPREP) || defined(TEST_READONLY) || defined(TEST_REPLICATIONLAG)
		if (strncasecmp("SELECT",query_no_space,6)==0) {
#ifdef TEST_AURORA
			if (strstr(query_no_space,(char *)"REPLICA_HOST_STATUS")) {
				pthread_mutex_lock(&GloSQLite3Server->aurora_mutex);

				if (strcasestr(query_no_space, TEST_AURORA_MONITOR_BASE_QUERY)) {
					string s_whg { query_no_space + strlen(TEST_AURORA_MONITOR_BASE_QUERY) };
					uint32_t whg = atoi(s_whg.c_str());

					GloSQLite3Server->populate_aws_aurora_table(sess, whg);
					vector<aurora_hg_info_t> hgs_info { get_hgs_info(GloAdmin->admindb) };

					const auto match_writer = [&whg](const aurora_hg_info_t& hg_info) {
						return std::get<AURORA_HG_INFO::WRITER_HG>(hg_info) == whg;
					};
					const auto hg_info_it = std::find_if(hgs_info.begin(), hgs_info.end(), match_writer);
					string select_query {
						"SELECT SERVER_ID,SESSION_ID,LAST_UPDATE_TIMESTAMP,REPLICA_LAG_IN_MILLISECONDS,CPU"
							" FROM REPLICA_HOST_STATUS "
					};

					if (hg_info_it == hgs_info.end()) {
						select_query += " LIMIT 0";
					} else {
						const string& domain_name { std::get<AURORA_HG_INFO::DOMAIN_NAME>(*hg_info_it) };
						select_query += " WHERE DOMAIN_NAME='" + domain_name + "' ORDER BY SERVER_ID";
					}

					free(query);
					query = static_cast<char*>(malloc(select_query.length() + 1));
					strcpy(query, select_query.c_str());
				}
			}
#endif // TEST_AURORA
#ifdef TEST_GALERA
			if (strstr(query_no_space,(char *)"HOST_STATUS_GALERA")) {
				pthread_mutex_lock(&GloSQLite3Server->galera_mutex);
				GloSQLite3Server->populate_galera_table(sess);
			}
#endif // TEST_GALERA
#ifdef TEST_GROUPREP
			if (strstr(query_no_space,(char *)"GR_MEMBER_ROUTING_CANDIDATE_STATUS")) {
				pthread_mutex_lock(&GloSQLite3Server->grouprep_mutex);
				GloSQLite3Server->populate_grouprep_table(sess, 0);
				// NOTE: This query should be in one place that can be reused by
				// 'ProxySQL_Monitor' module.
				const std::string grouprep_monitor_test_query_start {
					"SELECT viable_candidate,read_only,transactions_behind,members "
						"FROM GR_MEMBER_ROUTING_CANDIDATE_STATUS "
				};

				// If the query matches 'grouprep_monitor_test_query_start', it
				// means that the query has been issued by `ProxySQL_Monitor` and
				// we need to fetch for the proper values and replace the query
				// with one holding the values from `grouprep_map`.
				if (match_monitor_query(grouprep_monitor_test_query_start, query_no_space)) {
					std::string srv_addr {
						query_no_space + grouprep_monitor_test_query_start.size()
					};

					const group_rep_status& gr_srv_status =
						GloSQLite3Server->grouprep_test_value(srv_addr);
					free(query);

					std::string t_select_as_query {
						"SELECT '%s' AS viable_candidate, '%s' AS read_only, %d AS transactions_behind, '%s' AS members"
					};
					std::string select_as_query {};
					string_format(
						t_select_as_query, select_as_query,
						std::get<0>(gr_srv_status) ? "YES" : "NO",
						std::get<1>(gr_srv_status) ? "YES" : "NO",
						std::get<2>(gr_srv_status),
						std::get<3>(gr_srv_status).c_str()
					);

					query = static_cast<char*>(malloc(select_as_query.length() + 1));
					strcpy(query, select_as_query.c_str());
				}
			}
#endif // TEST_GROUPREP
#ifdef TEST_READONLY
			if (strncasecmp("SELECT @@global.read_only read_only ",query_no_space, strlen("SELECT @@global.read_only read_only "))==0) {
				if (strlen(query_no_space) > strlen("SELECT @@global.read_only read_only ")+5) {
					pthread_mutex_lock(&GloSQLite3Server->test_readonly_mutex);
					// the current test doesn't try to simulate failures, therefore it will return immediately
					if (GloSQLite3Server->readonly_map_size() == 0) {
						// probably never initialized
						GloSQLite3Server->load_readonly_table(sess);
					}
					int rc = GloSQLite3Server->readonly_test_value(query_no_space+strlen("SELECT @@global.read_only read_only "));
					free(query);
					char *a = (char *)"SELECT %d as read_only";
					query = (char *)malloc(strlen(a)+2);
					sprintf(query,a,rc);
					pthread_mutex_unlock(&GloSQLite3Server->test_readonly_mutex);
				}
			}
#endif // TEST_READONLY
#ifdef TEST_REPLICATIONLAG
			if (strncasecmp("SELECT SLAVE STATUS ", query_no_space, strlen("SELECT SLAVE STATUS ")) == 0) {
				if (strlen(query_no_space) > strlen("SELECT SLAVE STATUS ") + 5) {
					pthread_mutex_lock(&GloSQLite3Server->test_replicationlag_mutex);
					// the current test doesn't try to simulate failures, therefore it will return immediately
					if (GloSQLite3Server->replicationlag_map_size() == 0) {
						// probably never initialized
						GloSQLite3Server->load_replicationlag_table(sess);
					}
					const int* rc = GloSQLite3Server->replicationlag_test_value(query_no_space + strlen("SELECT SLAVE STATUS "));
					free(query);
					if (rc == nullptr) {
						const char* a = (char*)"SELECT null as Seconds_Behind_Master";
						query = (char*)malloc(strlen(a) + 2);
						sprintf(query, a);
					} else {
						const char* a = (char*)"SELECT %d as Seconds_Behind_Master";
						query = (char*)malloc(strlen(a) + 2);
						sprintf(query, a, *rc);
					}
					pthread_mutex_unlock(&GloSQLite3Server->test_replicationlag_mutex);
				}
			}
#endif // TEST_REPLICATIONLAG
			if (strstr(query_no_space,(char *)"Seconds_Behind_Master")) {
				free(query);
				char *a = (char *)"SELECT %d as Seconds_Behind_Master";
				query = (char *)malloc(strlen(a)+4);
				sprintf(query,a,rand()%30+10);
			}
		}
#endif // TEST_AURORA || TEST_GALERA || TEST_GROUPREP || TEST_READONLY || TEST_REPLICATIONLAG
		SQLite3_Session *sqlite_sess = (SQLite3_Session *)sess->thread->gen_args;
		if (sess->autocommit==false) {
			sqlite3 *db = sqlite_sess->sessdb->get_db();
			if ((*proxy_sqlite3_get_autocommit)(db)==1) {
				// we defer the creation of the transaction to simulate how MySQL works
				sqlite_sess->sessdb->execute("BEGIN IMMEDIATE");
			}
		}
		sqlite_sess->sessdb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
#if defined(TEST_AURORA) || defined(TEST_GALERA) || defined(TEST_GROUPREP)
		if (strncasecmp("SELECT",query_no_space,6)==0) {
#ifdef TEST_AURORA
			if (strstr(query_no_space,(char *)"REPLICA_HOST_STATUS")) {
				pthread_mutex_unlock(&GloSQLite3Server->aurora_mutex);
#ifdef TEST_AURORA_RANDOM
				if (rand() % 100 == 0) {
					// randomly add some latency on 1% of the traffic
					sleep(2);
				}
#endif
			}
#endif // TEST_AURORA
#ifdef TEST_GALERA
			if (strstr(query_no_space,(char *)"HOST_STATUS_GALERA")) {
				pthread_mutex_unlock(&GloSQLite3Server->galera_mutex);
				if (resultset->rows_count == 0) {
					PROXY_TRACE();
				}
#ifdef TEST_GALERA_RANDOM
				if (rand() % 20 == 0) {
					// randomly add some latency on 5% of the traffic
					sleep(2);
				}
#endif
			}
#endif // TEST_GALERA
#ifdef TEST_GROUPREP
			if (strstr(query_no_space,(char *)"GR_MEMBER_ROUTING_CANDIDATE_STATUS")) {
				pthread_mutex_unlock(&GloSQLite3Server->grouprep_mutex);

				// NOTE: Enable this just in case of manual testing
				// if (rand() % 100 == 0) {
				// 	// randomly add some latency on 1% of the traffic
				// 	sleep(2);
				// }
			}
#endif // TEST_GROUPREP
			if (strstr(query_no_space,(char *)"Seconds_Behind_Master")) {
				if (rand() % 10 == 0) {
					// randomly add some latency on 10% of the traffic
					sleep(2);
				}
			}
		}
#endif // TEST_AURORA || TEST_GALERA || TEST_GROUPREP
		sqlite3 *db = sqlite_sess->sessdb->get_db();
		bool in_trans = false;
		if ((*proxy_sqlite3_get_autocommit)(db)==0) {
			in_trans = true;
		}
		sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot, in_trans);
		delete resultset;
#ifdef TEST_READONLY
		if (strncasecmp("SELECT",query_no_space,6)) {
			if (strstr(query_no_space,(char *)"READONLY_STATUS")) {
				// the table is writable
				pthread_mutex_lock(&GloSQLite3Server->test_readonly_mutex);
				GloSQLite3Server->load_readonly_table(sess);
				pthread_mutex_unlock(&GloSQLite3Server->test_readonly_mutex);
			}
		}
#endif // TEST_READONLY
#ifdef TEST_REPLICATIONLAG
		if (strncasecmp("SELECT", query_no_space, 6)) {
			if (strstr(query_no_space, (char*)"REPLICATIONLAG_HOST_STATUS")) {
				// the table is writable
				pthread_mutex_lock(&GloSQLite3Server->test_replicationlag_mutex);
				GloSQLite3Server->load_replicationlag_table(sess);
				pthread_mutex_unlock(&GloSQLite3Server->test_replicationlag_mutex);
			}
		}
#endif // TEST_REPLICATIONLAG
	}
	l_free(pkt->size-sizeof(mysql_hdr),query_no_space); // it is always freed here
	l_free(query_length,query);
}

#ifdef TEST_GROUPREP
group_rep_status SQLite3_Server::grouprep_test_value(const std::string& srv_addr) {
	group_rep_status cur_srv_st { "YES", "YES", 0, "" };

	auto it = grouprep_map.find(srv_addr);
	if (it != grouprep_map.end()) {
		cur_srv_st = it->second;
	}

	return cur_srv_st;
}
#endif

SQLite3_Session::SQLite3_Session() {
	sessdb=new SQLite3DB();
    sessdb->open(GloVars.sqlite3serverdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	sessdb->execute((char *)"PRAGMA journal_mode=WAL");
	sessdb->execute((char *)"PRAGMA journal_size_limit=67108864");
	sessdb->execute((char *)"PRAGMA synchronous=0");
}

SQLite3_Session::~SQLite3_Session() {
	sqlite3 *db = sessdb->get_db();
	if ((*proxy_sqlite3_get_autocommit)(db)==0) {
		sessdb->execute((char *)"COMMIT");
	}
	delete sessdb;
	sessdb = NULL;
}

static void *child_mysql(void *arg) {

	int client = *(int *)arg;

	set_thread_name("SQLiteChldMySQL");
	GloMTH->wrlock();
	{
		char *s=GloMTH->get_variable((char *)"server_capabilities");
		mysql_thread___server_capabilities=atoi(s);
		free(s);
	}
	GloMTH->wrunlock();

	struct pollfd fds[1];
	nfds_t nfds=1;
	int rc;
	pthread_mutex_unlock(&sock_mutex);
	MySQL_Thread *mysql_thr=new MySQL_Thread();
	mysql_thr->curtime=monotonic_time();

	SQLite3_Session *sqlite_sess = new SQLite3_Session();
	mysql_thr->gen_args = (void *)sqlite_sess;

	GloMyQPro->init_thread();
	mysql_thr->refresh_variables();
	MySQL_Session *sess=mysql_thr->create_new_session_and_client_data_stream<MySQL_Thread, MySQL_Session*>(client);
	sess->thread=mysql_thr;
	sess->session_type = PROXYSQL_SESSION_SQLITE;
	sess->handler_function=SQLite3_Server_session_handler;
	MySQL_Data_Stream *myds=sess->client_myds;

	fds[0].fd=client;
	fds[0].revents=0;
	fds[0].events=POLLIN|POLLOUT;
	free(arg);
	sess->client_myds->myprot.generate_pkt_initial_handshake(true,NULL,NULL, &sess->thread_session_id, false);

	while (__sync_fetch_and_add(&glovars.shutdown,0)==0) {
		if (myds->available_data_out()) {
			fds[0].events=POLLIN|POLLOUT;
		} else {
			fds[0].events=POLLIN;
		}
		fds[0].revents=0;
		rc=poll(fds,nfds,__sync_fetch_and_add(&__SQLite3_Server_refresh_interval,0));
		if (rc == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				goto __exit_child_mysql;
			}
		}
		myds->revents=fds[0].revents;
		// FIXME: CI test test_sqlite3_server-t or test_sqlite3_server_and_fast_routing-t
		// seems to result in fds->fd = -1
		// it needs investigation
		int rb = 0;
		rb = myds->read_from_net();
		if (myds->net_failure) goto __exit_child_mysql;
		myds->read_pkts();
		if (myds->encrypted == true) {
			// PMC-10004
			// we probably should use SSL_pending() and/or SSL_has_pending() to determine
			// if there is more data to be read, but it doesn't seem to be working.
			// Therefore we try to call read_from_net() again as long as there is data.
			// Previously we hardcoded 16KB but it seems that it can return in smaller
			// chunks of 4KB.
			// We finally removed the chunk size as it seems that any size is possible.
			while (rb > 0) {
				rb = myds->read_from_net();
				if (myds->net_failure) goto __exit_child_mysql;
				myds->read_pkts();
			}
		}
		sess->to_process=1;
		if (sess->client_myds->client_addr == NULL) {
			// Get and set the client address before the sesion is processed.
			union {
				struct sockaddr_in in;
				struct sockaddr_in6 in6;
			} custom_sockaddr;
			struct sockaddr *addr=(struct sockaddr *)malloc(sizeof(custom_sockaddr));
			socklen_t addrlen=sizeof(custom_sockaddr);
			memset(addr, 0, sizeof(custom_sockaddr));
			sess->client_myds->client_addrlen=addrlen;
			sess->client_myds->client_addr=addr;
			int g_rc = getpeername(sess->client_myds->fd, addr, &addrlen);
			if (g_rc == -1) {
				proxy_error("'getpeername' failed with error: %d\n", g_rc);
			}
		}
		int rc=sess->handler();
		if (rc==-1) goto __exit_child_mysql;
	}

__exit_child_mysql:
	delete sqlite_sess;
	mysql_thr->gen_args = NULL;
	delete mysql_thr;
	return NULL;
}


static void * sqlite3server_main_loop(void *arg)
{
	int i;
	int version=0;
	struct sockaddr_in addr;
	struct pollfd *fds=((struct _main_args *)arg)->fds;
	int nfds=((struct _main_args *)arg)->nfds;
	int *callback_func=((struct _main_args *)arg)->callback_func;
	volatile int *shutdown=((struct _main_args *)arg)->shutdown;
	char *socket_names[MAX_SQLITE3SERVER_LISTENERS];
	for (i=0;i<MAX_SQLITE3SERVER_LISTENERS;i++) { socket_names[i]=NULL; }
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	set_thread_name("SQLite3_Main");
	while (glovars.shutdown==0 && *shutdown==0)
	{
		int *client;
		int client_t;
		socklen_t addr_size = sizeof(addr);
		pthread_t child;
		size_t stacks;
		unsigned long long curtime=monotonic_time();
		unsigned long long next_run=GloAdmin->scheduler_run_once();
		unsigned long long poll_wait=500000;
		if (next_run < curtime + 500000) {
			poll_wait=next_run-curtime;
		}
		if (poll_wait > 500000) {
			poll_wait=500000;
		}
		poll_wait=poll_wait/1000;	// conversion to millisecond
		int rc;
		rc=poll(fds,nfds,poll_wait);
		if ((rc == -1 && errno == EINTR) || rc==0) {
        // poll() timeout, try again
			goto __end_while_pool;
		}
		for (i=1;i<nfds;i++) {
			if (fds[i].revents==POLLIN) {
				client_t = accept(fds[i].fd, (struct sockaddr*)&addr, &addr_size);
				if (client_t > 0) { // minor error handling
					pthread_attr_getstacksize (&attr, &stacks);
					pthread_mutex_lock (&sock_mutex);
					client=(int *)malloc(sizeof(int));
					*client= client_t;
					if ( pthread_create(&child, &attr, child_func[callback_func[i]], client) != 0 )
						perror("Thread creation");
				} else {
					proxy_error("accept() error: %s\n", strerror(errno));
				}
			}
			fds[i].revents=0;
		}
		// NOTE: In case the address imposed by 'sqliteserver-mysql_ifaces' isn't avaible,
		// a infinite loop could take place if 'POLLNVAL' is not checked here.
		// This means that trying to set a 'mysql_ifaces' to an address that is
		// already taken will result into an 'assert' in ProxySQL side.
		if (nfds == 1 && fds[0].revents == POLLNVAL) {
			proxy_error("revents==POLLNVAL for FD=%d, events=%d\n", fds[i].fd, fds[i].events);
			if (glovars.shutdown==0 && *shutdown==0) {
				assert(fds[0].revents != POLLNVAL);
			}
		}
__end_while_pool:
		if (S_amll.get_version()!=version) {
			S_amll.wrlock();
			version=S_amll.get_version();
			for (i=1; i<nfds; i++) {
				char *add=NULL; char *port=NULL;
				close(fds[i].fd);
				if (socket_names[i] != NULL) { // this should skip socket_names[0] , because it is a pipe
					c_split_2(socket_names[i], ":" , &add, &port);
					if (atoi(port)==0) { unlink(socket_names[i]); }
				}
			}
			nfds=0;
			fds[nfds].fd=GloAdmin->pipefd[0];
			fds[nfds].events=POLLIN;
			fds[nfds].revents=0;
			nfds++;
			unsigned int j;
			i=0; j=0;
			for (j=0; j<S_amll.ifaces_mysql->ifaces->len; j++) {
				char *add=NULL; char *port=NULL; char *sn=(char *)S_amll.ifaces_mysql->ifaces->index(j);

                                char *h = NULL;
                                if (*sn == '[') {
                                        char *p = strchr(sn, ']');
                                        if (p == NULL)
                                                proxy_error("Invalid IPv6 address: %s\n", sn);

                                        h = ++sn; // remove first '['
                                        *p = '\0';
                                        sn = p++; // remove last ']'
                                        add = h;
                                        port = ++p; // remove ':'
                                } else {
                                        c_split_2(sn, ":" , &add, &port);
                                }

#ifdef SO_REUSEPORT
				int s = ( atoi(port) ? listen_on_port(add, atoi(port), 128, true) : listen_on_unix(add, 128));
#else
				int s = ( atoi(port) ? listen_on_port(add, atoi(port), 128) : listen_on_unix(add, 128));
#endif // SO_REUSEPORT
				if (s>0) { fds[nfds].fd=s; fds[nfds].events=POLLIN; fds[nfds].revents=0; callback_func[nfds]=0; socket_names[nfds]=strdup(sn); nfds++; }
				if (add) free(add);
				if (port) free(port);
			}
			S_amll.wrunlock();
		}

	}
	//if (__sync_add_and_fetch(shutdown,0)==0) __sync_add_and_fetch(shutdown,1);
	for (i=0; i<nfds; i++) {
		char *add=NULL; char *port=NULL;
		close(fds[i].fd);
		c_split_2(socket_names[i], ":" , &add, &port);
		if (atoi(port)==0) {
			if (socket_names[i]) {
				unlink(socket_names[i]);
			}
		}
		if (socket_names[i]) free(socket_names[i]);
		if (add) free(add);
		if (port) free(port);
	}
	free(arg);
	return NULL;
}

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_SQLITE3_SERVER_VERSION "1.9.0218" DEB

SQLite3_Server::~SQLite3_Server() {
	delete sessdb;
	sessdb = NULL;

#ifdef TEST_GALERA
	drop_tables_defs(tables_defs_galera);
	delete tables_defs_galera;
#endif // TEST_GALERA

#ifdef TEST_AURORA
	drop_tables_defs(tables_defs_aurora);
	delete tables_defs_aurora;
#endif // TEST_AURORA

#ifdef TEST_GROUPREP
	drop_tables_defs(tables_defs_grouprep);
	delete tables_defs_grouprep;
#endif // TEST_GROUPREP
};

#ifdef TEST_AURORA
void SQLite3_Server::init_aurora_ifaces_string(std::string& s) {
	if(!s.empty())
		s += ";";
	pthread_mutex_init(&aurora_mutex,NULL);
	unsigned int nas = time(NULL);
	nas = nas % 3; // range
	nas += 4; // min
	max_num_aurora_servers = 10; // hypothetical maximum number of nodes
	for (unsigned int j=1; j<4; j++) {
		cur_aurora_writer[j-1] = 0;
		num_aurora_servers[j-1] = nas;
		for (unsigned int i=11; i<max_num_aurora_servers+11 ; i++) {
			s += "127.0." + std::to_string(j) + "." + std::to_string(i) + ":3306";
			if ( j!=3 || (j==3 && i<max_num_aurora_servers+11-1) ) {
				s += ";";
			}
		}
	}
}
#endif

#ifdef TEST_GALERA
void SQLite3_Server::init_galera_ifaces_string(std::string& s) {
	if(!s.empty())
		s += ";";
	pthread_mutex_init(&galera_mutex,NULL);
	unsigned int ngs = time(NULL);
	ngs = ngs % 3; // range
	ngs += 5; // min
	max_num_galera_servers = 10; // hypothetical maximum number of nodes
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
#endif // TEST_GALERA

#ifdef TEST_GROUPREP
void SQLite3_Server::init_grouprep_ifaces_string(std::string& s) {
	pthread_mutex_init(&grouprep_mutex,NULL);
	if (!s.empty())
		s += ";";

	// Maximum number of servers to simulate.
	max_num_grouprep_servers = 50;
	for (unsigned int i=0; i < max_num_grouprep_servers; i++) {
		s += "127.2.1." + std::to_string(i) + ":3306";

		if (i != max_num_grouprep_servers) {
			s += ";";
		}
	}
}
#endif // TEST_GROUPREP

SQLite3_Server::SQLite3_Server() {
#ifdef DEBUG
		if (glovars.has_debug==false) {
#else
		if (glovars.has_debug==true) {
#endif /* DEBUG */
			perror("Incompatible debugging version");
			exit(EXIT_FAILURE);
		}

//	SPA=this;

	//Initialize locker
	pthread_rwlock_init(&rwlock,NULL);

	sessdb=new SQLite3DB();
	sessdb->open(GloVars.sqlite3serverdb, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	sessdb->execute((char *)"PRAGMA journal_mode=WAL");
	sessdb->execute((char *)"PRAGMA journal_size_limit=67108864");
	sessdb->execute((char *)"PRAGMA synchronous=0");

	variables.read_only=false;

#if defined(TEST_AURORA) || defined(TEST_GALERA) || defined(TEST_GROUPREP) || defined(TEST_READONLY) || defined(TEST_REPLICATIONLAG) 
	string s = "";

#ifdef TEST_AURORA
	init_aurora_ifaces_string(s);
#endif // TEST_AURORA

#ifdef TEST_GALERA
	init_galera_ifaces_string(s);
#endif // TEST_GALERA

#ifdef TEST_GROUPREP
	init_grouprep_ifaces_string(s);
#endif // TEST_GROUPREP
#ifdef TEST_READONLY
	// for readonly test we listen on all IPs because we simulate a lot of clusters
	if (!s.empty())
		s += ";";
	s += "0.0.0.0:3306";
	pthread_mutex_init(&test_readonly_mutex, NULL);
#endif //TEST_READONLY
#ifdef TEST_REPLICATIONLAG
	// for replication test we listen on all IPs
	if (!s.empty())
		s += ";";
	s += "0.0.0.0:3306";
	pthread_mutex_init(&test_replicationlag_mutex, NULL);
#endif //TEST_REPLICATIONLAG

	variables.mysql_ifaces=strdup(s.c_str());

#else
	variables.mysql_ifaces=strdup("127.0.0.1:6030");
#endif // TEST_AURORA || TEST_GALERA || TEST_GROUPREP || TEST_READONLY || TEST_REPLICATIONLAG
};



#ifdef TEST_GALERA
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

			rc=sqlite3_bind_text(statement, 11, (char *)"DISABLED", -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, sessdb);

			SAFE_SQLITE3_STEP2(statement);
			rc=sqlite3_clear_bindings(statement); ASSERT_SQLITE_OK(rc, sessdb);
			rc=sqlite3_reset(statement); ASSERT_SQLITE_OK(rc, sessdb);
		}
		sqlite3_finalize(statement);
	}
	sessdb->execute("COMMIT");
}
#endif // TEST_GALERA

#ifdef TEST_AURORA

float get_rand_cpu() {
	int cpu_i = rand() % 10000;
	float cpu = static_cast<float>(cpu_i) / 100;

	return cpu;
}

string get_curtime_str() {
	time_t __timer;
	char lut[30];
	struct tm __tm_info;
	time(&__timer);
	localtime_r(&__timer, &__tm_info);
	strftime(lut, 25, "%Y-%m-%d %H:%M:%S", &__tm_info);
	string s = string(lut);
	return s;
}

void bind_query_params(
	SQLite3DB* db,
	sqlite3_stmt* stmt,
	const string& server_id,
	const string& domain,
	const string& session_id,
	float cpu,
	const string& lut,
	int32_t lag_ms
) {
	int rc = 0;

	rc=sqlite3_bind_text(stmt, 1, server_id.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
	rc=sqlite3_bind_text(stmt, 2, domain.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
	rc=sqlite3_bind_text(stmt, 3, session_id.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
	rc=sqlite3_bind_double(stmt, 4, cpu); ASSERT_SQLITE_OK(rc, db);
	rc=sqlite3_bind_text(stmt, 5, lut.c_str(), -1, SQLITE_TRANSIENT); ASSERT_SQLITE_OK(rc, db);
	rc=sqlite3_bind_double(stmt, 6, lag_ms); ASSERT_SQLITE_OK(rc, db);
	SAFE_SQLITE3_STEP2(stmt);
	rc=sqlite3_clear_bindings(stmt); ASSERT_SQLITE_OK(rc, db);
	rc=sqlite3_reset(stmt); ASSERT_SQLITE_OK(rc, db);
}

/**
 * @brief Extracts SERVER_ID from the supplied hostname using DOMAIN_NAME.
 * @param hostname The server hostname (SERVER_ID + DOMAIN_NAME)).
 * @param domain_name The server DOMAIN_NAME as in 'mysql_aws_aurora_hostgroups'
 * @return Either the SERVER_ID in the supplied hostname or empty if DOMAIN_NAME failed to match.
 */
string get_server_id(const string& hostname, const string& domain_name) {
	string::size_type pos = hostname.find(domain_name);

	if (pos == string::npos) {
		return {};
	} else {
		return hostname.substr(0, pos);
	}
}

void SQLite3_Server::populate_aws_aurora_table(MySQL_Session *sess, uint32_t whg) {
	int rc = 0;
	sqlite3_stmt* stmt = NULL;
    const char query[] { "INSERT INTO REPLICA_HOST_STATUS VALUES (?1, ?2, ?3, ?4, ?5, ?6)" };

	rc = sessdb->prepare_v2(query, &stmt);
	ASSERT_SQLITE_OK(rc, sessdb);

#ifndef TEST_AURORA_RANDOM
    SQLite3_result* host_status = NULL;

	{
		char* error = NULL;
		int cols = 0;
		int affected_rows = 0;

		string query {
			"SELECT SERVER_ID,DOMAIN_NAME,SESSION_ID,LAST_UPDATE_TIMESTAMP,REPLICA_LAG_IN_MILLISECONDS"
				" FROM REPLICA_HOST_STATUS"
		};
		sessdb->execute_statement(query.c_str(), &error, &cols, &affected_rows, &host_status);
	}

	// If empty, we fill the map with sensible defaults for performing manual testing.
	if (host_status->rows.empty()) {
		vector<aurora_hg_info_t> hgs_info { get_hgs_info(GloAdmin->admindb) };
		SQLite3_result* resultset = nullptr;

		{
			char* error = nullptr;
			int cols = 0;
			int affected_rows = 0;

			GloAdmin->admindb->execute_statement(
				"SELECT hostname, hostgroup_id FROM mysql_servers WHERE hostgroup_id BETWEEN 1270 AND 1300"
					" GROUP BY HOSTNAME",
				&error, &cols, &affected_rows, &resultset
			);
		}

		sessdb->execute("DELETE FROM REPLICA_HOST_STATUS");
		vector<string> proc_srvs {};

		for (const aurora_hg_info_t& hg_info : hgs_info) {
			const auto match_writer = [&hg_info](const SQLite3_row* row) {
				return atoi(row->fields[1]) == std::get<AURORA_HG_INFO::WRITER_HG>(hg_info);
			};
			const auto mysrv_it = std::find_if(resultset->rows.begin(), resultset->rows.end(), match_writer);
			bool writer_set = false;

			for (const SQLite3_row* r : resultset->rows) {
				const string srv_hostname { r->fields[0] };
				const uint32_t srv_hg_id = atoi(r->fields[1]);
				const string& aurora_domain { std::get<AURORA_HG_INFO::DOMAIN_NAME>(hg_info) };

				if (
					srv_hostname.find(aurora_domain) == string::npos ||
					std::find(proc_srvs.begin(), proc_srvs.end(), srv_hostname) != proc_srvs.end()
				) {
					continue;
				}

				const string server_id {
					get_server_id(srv_hostname, std::get<AURORA_HG_INFO::DOMAIN_NAME>(hg_info))
				};

				string session_id {};

				if (
					(mysrv_it == resultset->rows.end() && writer_set == false) ||
					(srv_hg_id == std::get<AURORA_HG_INFO::WRITER_HG>(hg_info) && writer_set == false)
				) {
					session_id = "MASTER_SESSION_ID";
					writer_set = true;
				} else {
					session_id = "TESTID-" + server_id + aurora_domain + "-R";
				}

				const float cpu = get_rand_cpu();
				const string lut { get_curtime_str() };
				const int lag_ms = 0;

				bind_query_params(sessdb, stmt, server_id, aurora_domain, session_id, cpu, lut, lag_ms);
				proc_srvs.push_back(srv_hostname);
			}
		}

		sqlite3_finalize(stmt);
		delete resultset;
	} else {
		// We just re-generate deterministic 'SESSION_IDS', preserving 'MASTER_SESSION_ID' values:
		// 'SESSION_IDS' are preserved, 'MASTER_SESSION_ID' or others.
		for (SQLite3_row* row : host_status->rows) {
			const char* server_id = row->fields[0];
			const char* domain_name = row->fields[1];

			const char update_query_t[] {
				"UPDATE REPLICA_HOST_STATUS SET SESSION_ID='%s',CPU=%f,LAST_UPDATE_TIMESTAMP='%s'"
				" WHERE SERVER_ID='%s' AND DOMAIN_NAME='%s' AND SESSION_ID!='MASTER_SESSION_ID'"
			};

			const string session_id { "TESTID-" + string { server_id } + domain_name + "-R" };
			const float cpu = get_rand_cpu();
			const string lut { get_curtime_str() };

			const string update_query {
				cstr_format(update_query_t, session_id.c_str(), cpu, lut.c_str(), server_id, domain_name).str
			};

			sessdb->execute(update_query.c_str());
		}
	}

	delete host_status;
#else
	sessdb->execute("DELETE FROM REPLICA_HOST_STATUS");

	string lut { get_curtime_str() };
	string myip = string(sess->client_myds->proxy_addr.addr);
	string clu_id_s = myip.substr(6,1);
	unsigned int cluster_id = atoi(clu_id_s.c_str());
	cluster_id--;

	if (rand() % 20000 == 0) {
		// simulate a failover
		cur_aurora_writer[cluster_id] = rand() % num_aurora_servers[cluster_id];
		proxy_info("Simulating a failover for AWS Aurora cluster %d , HGs (%d:%d)\n", cluster_id, 1270 + cluster_id*2+1 , 1270 + cluster_id*2+2);
	}
	if (rand() % 1000 == 0) {
		if (num_aurora_servers[cluster_id] < max_num_aurora_servers) {
			num_aurora_servers[cluster_id]++;
			proxy_info("Simulating the add of a new server for AWS Aurora Cluster %d , HGs (%d:%d). Now adding server num %d\n", cluster_id, 1270 + cluster_id*2+1 , 1270 + cluster_id*2+2, num_aurora_servers[cluster_id]);
		}
	}
	if (rand() % 1000 == 0) {
		if (num_aurora_servers[cluster_id] > 1) {
			if (cur_aurora_writer[cluster_id] != (num_aurora_servers[cluster_id] - 1) ) {
				num_aurora_servers[cluster_id]--;
				proxy_info("Simulating the deletion of a server from AWS Aurora Cluster %d , HGs (%d:%d). Removing server num %d\n", cluster_id, 1270 + cluster_id*2+1 , 1270 + cluster_id*2+2, num_aurora_servers[cluster_id]+1);
			}
		}
	}
	for (unsigned int i=0; i<num_aurora_servers[cluster_id]; i++) {
		// we simulate that clusters 1 and 3 have the same servers
		string serverid = "host." + std::to_string( ( cluster_id == 2 ? 0 : cluster_id )  +1) + "." + std::to_string(i+11);
		string sessionid= "";
		string aurora_domain {
			(cluster_id == 0 || cluster_id == 3) ? ".aws-test.com" : ".cluster2.aws.test"
		};
		float lag_ms = 0;
		if (i==cur_aurora_writer[cluster_id]) {
			sessionid = "MASTER_SESSION_ID";
		} else {
			sessionid = "b80ef4b4-" + serverid + "-aa01";
			int lag_ms_i = rand();
			lag_ms_i %= 2000;
			lag_ms = lag_ms_i;
			lag_ms /= 100;
			lag_ms += 10;
		}
		float cpu = get_rand_cpu();
		bind_query_params(sessdb, stmt, serverid, aurora_domain, sessionid, cpu, lut, lag_ms);
	}
	sqlite3_finalize(stmt);
#endif // TEST_AURORA_RANDOM
}
#endif // TEST_AURORA

#ifdef TEST_GROUPREP
/**
 * @brief Populates the 'grouprep' table if it's found empty with the default
 *   values for the three testing servers.
 *
 *   NOTE: This function needs to be called with lock on grouprep_mutex already acquired
 *
 * @param sess The current session performing a query.
 * @param txs_behind Unused parameter.
 */
void SQLite3_Server::populate_grouprep_table(MySQL_Session *sess, int txs_behind) {
	GloAdmin->mysql_servers_wrlock();
	// We are going to repopulate the map
	this->grouprep_map.clear();

	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;

	string query { "SELECT * FROM GR_MEMBER_ROUTING_CANDIDATE_STATUS" };
	sessdb->execute_statement(query.c_str(), &error, &cols, &affected_rows, &resultset);
	if (resultset) {
		for (const SQLite3_row* r : resultset->rows) {
			std::string srv_addr { std::string(r->fields[0]) + ":" + std::string(r->fields[1]) };
			const group_rep_status srv_status {
				std::string { r->fields[2] } == "YES" ? true : false,
				std::string { r->fields[3] } == "YES" ? true : false,
				atoi(r->fields[4]),
				std::string { r->fields[5] }
			};

			this->grouprep_map[srv_addr] = srv_status;
		}
	}
	delete resultset;

	// Insert some default servers for manual testing.
	//
	// NOTE: This logic can be improved in the future, for now it only populates
	// the 'monitoring' data for the default severs. If more servers are placed
	// as the default ones, more servers will be placed in their appropiated
	// hostgroups with the same pattern as first ones.
	if (this->grouprep_map.size() == 0) {
		GloAdmin->admindb->execute_statement(
			(char*)"SELECT DISTINCT hostname, port, hostgroup_id FROM mysql_servers"
			" WHERE hostgroup_id BETWEEN 2700 AND 4200",
			&error, &cols , &affected_rows , &resultset
		);

		for (const SQLite3_row* r : resultset->rows) {
			std::string hostname { r->fields[0] };
			int port = atoi(r->fields[1]);
			int hostgroup_id = atoi(r->fields[2]);
			const std::string t_insert_query {
				"INSERT INTO GR_MEMBER_ROUTING_CANDIDATE_STATUS"
					" (hostname, port, viable_candidate, read_only, transactions_behind, members) VALUES"
					" ('%s', %d, '%s', '%s', 0, '%s')"
			};
			std::string insert_query {};

			if (hostgroup_id % 4 == 0) {
				string_format(t_insert_query, insert_query, hostname.c_str(), port, "YES", "NO", "");
				sessdb->execute(insert_query.c_str());
			} else {
				string_format(t_insert_query, insert_query, hostname.c_str(), port, "YES", "YES", "");
				sessdb->execute(insert_query.c_str());
			}
		}
		delete resultset;
	}

	GloAdmin->mysql_servers_wrunlock();
}
#endif // TEST_GALERA


#if defined(TEST_AURORA) || defined(TEST_GALERA) || defined(TEST_GROUPREP) || defined(TEST_READONLY) || defined(TEST_REPLICATIONLAG)
void SQLite3_Server::insert_into_tables_defs(std::vector<table_def_t *> *tables_defs, const char *table_name, const char *table_def) {
	table_def_t *td = new table_def_t;
	td->table_name=strdup(table_name);
	td->table_def=strdup(table_def);
	tables_defs->push_back(td);
};

void SQLite3_Server::check_and_build_standard_tables(SQLite3DB *db, std::vector<table_def_t *> *tables_defs) {
	table_def_t *td;
	db->execute("PRAGMA foreign_keys = OFF");
	for (std::vector<table_def_t *>::iterator it=tables_defs->begin(); it!=tables_defs->end(); ++it) {
		td=*it;
		db->check_and_build_table(td->table_name, td->table_def);
	}
	db->execute("PRAGMA foreign_keys = ON");
};

void SQLite3_Server::drop_tables_defs(std::vector<table_def_t *> *tables_defs) {
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
#endif // TEST_AURORA || TEST_GALERA || TEST_GROUPREP || TEST_READONLY || TEST_REPLICATIONLAG

void SQLite3_Server::wrlock() {
	pthread_rwlock_wrlock(&rwlock);
};

void SQLite3_Server::wrunlock() {
	pthread_rwlock_unlock(&rwlock);
};


void SQLite3_Server::print_version() {
  fprintf(stderr,"Standard ProxySQL SQLite3 Server rev. %s -- %s -- %s\n", PROXYSQL_SQLITE3_SERVER_VERSION, __FILE__, __TIMESTAMP__);
};

bool SQLite3_Server::init() {
	//cpu_timer cpt;

#ifdef TEST_AURORA
	tables_defs_aurora = new std::vector<table_def_t *>;
	insert_into_tables_defs(tables_defs_aurora,
		(const char *)"REPLICA_HOST_STATUS",
		"CREATE TABLE REPLICA_HOST_STATUS ("
			" SERVER_ID VARCHAR NOT NULL , DOMAIN_NAME VARCHAR NOT NULL , SESSION_ID VARCHAR NOT NULL ,"
			" CPU REAL NOT NULL , LAST_UPDATE_TIMESTAMP VARCHAR NOT NULL , REPLICA_LAG_IN_MILLISECONDS REAL NOT NULL ,"
			" PRIMARY KEY (SERVER_ID, DOMAIN_NAME)"
		")"
	);
	check_and_build_standard_tables(sessdb, tables_defs_aurora);
	GloAdmin->enable_aurora_testing();
#endif // TEST_AURORA
#ifdef TEST_GALERA
	tables_defs_galera = new std::vector<table_def_t *>;
	insert_into_tables_defs(tables_defs_galera,
		(const char *)"HOST_STATUS_GALERA",
		(const char *)"CREATE TABLE HOST_STATUS_GALERA (hostgroup_id INT NOT NULL , hostname VARCHAR NOT NULL , port INT NOT NULL , wsrep_local_state VARCHAR , read_only VARCHAR , wsrep_local_recv_queue VARCHAR , wsrep_desync VARCHAR , wsrep_reject_queries VARCHAR , wsrep_sst_donor_rejects_queries VARCHAR , wsrep_cluster_status VARCHAR , pxc_maint_mode VARCHAR NOT NULL CHECK (pxc_maint_mode IN ('DISABLED', 'SHUTDOWN', 'MAINTENANCE')) DEFAULT 'DISABLED' , PRIMARY KEY (hostgroup_id, hostname, port))");
	check_and_build_standard_tables(sessdb, tables_defs_galera);
	GloAdmin->enable_galera_testing();
#endif // TEST_GALERA
#ifdef TEST_GROUPREP
	tables_defs_grouprep = new std::vector<table_def_t *>;
	insert_into_tables_defs(tables_defs_grouprep,
		(const char *)"GR_MEMBER_ROUTING_CANDIDATE_STATUS",
		(const char*)"CREATE TABLE GR_MEMBER_ROUTING_CANDIDATE_STATUS ("
			"hostname VARCHAR NOT NULL, port INT NOT NULL, viable_candidate varchar not null, read_only varchar not null, transactions_behind int not null, members VARCHAR NOT NULL, PRIMARY KEY (hostname, port)"
		")"
	);

	check_and_build_standard_tables(sessdb, tables_defs_grouprep);
	GloAdmin->enable_grouprep_testing();
#endif // TEST_GALERA
#ifdef TEST_READONLY
	tables_defs_readonly = new std::vector<table_def_t *>;
	insert_into_tables_defs(tables_defs_readonly,
		(const char *)"READONLY_STATUS",
		(const char*)"CREATE TABLE READONLY_STATUS (hostname VARCHAR NOT NULL , port INT NOT NULL , read_only INT NOT NULL CHECK (read_only IN (0, 1)) DEFAULT 1 , PRIMARY KEY (hostname, port))");
	check_and_build_standard_tables(sessdb, tables_defs_readonly);
	GloAdmin->enable_readonly_testing();
#endif // TEST_READONLY
#ifdef TEST_REPLICATIONLAG
	tables_defs_replicationlag = new std::vector<table_def_t*>;
	insert_into_tables_defs(tables_defs_replicationlag,
		(const char*)"REPLICATIONLAG_HOST_STATUS",
		(const char*)"CREATE TABLE REPLICATIONLAG_HOST_STATUS ("
		"hostname VARCHAR NOT NULL, port INT NOT NULL, seconds_behind_master INT DEFAULT NULL, PRIMARY KEY (hostname, port)"
		")"
	);

	check_and_build_standard_tables(sessdb, tables_defs_replicationlag);
	GloAdmin->enable_replicationlag_testing();
#endif // TEST_REPLICATIONLAG
	child_func[0]=child_mysql;
	main_shutdown=0;
	main_poll_nfds=0;
	main_poll_fds=NULL;
	main_callback_func=NULL;

	main_callback_func=(int *)malloc(sizeof(int)*MAX_SQLITE3SERVER_LISTENERS);
	main_poll_fds=(struct pollfd *)malloc(sizeof(struct pollfd)*MAX_SQLITE3SERVER_LISTENERS);
	main_poll_nfds=0;

	S_amll.update_ifaces(variables.mysql_ifaces, &S_amll.ifaces_mysql);

	pthread_t SQLite3_Server_thr;
	struct _main_args *arg=(struct _main_args *)malloc(sizeof(struct _main_args));
	arg->nfds=main_poll_nfds;
	arg->fds=main_poll_fds;
	arg->shutdown=&main_shutdown;
	arg->callback_func=main_callback_func;
	if (pthread_create(&SQLite3_Server_thr, NULL, sqlite3server_main_loop, (void *)arg) !=0 ) {
		perror("Thread creation");
		exit(EXIT_FAILURE);
	}
#ifdef DEBUG
	std::cerr << "SQLite3 Server initialized in ";
#endif
	return true;
};

char **SQLite3_Server::get_variables_list() {
	size_t l=sizeof(SQLite3_Server_variables_names)/sizeof(char *);
	unsigned int i;
	char **ret=(char **)malloc(sizeof(char *)*l);
	for (i=0;i<l;i++) {
		ret[i]=(i==l-1 ? NULL : strdup(SQLite3_Server_variables_names[i]));
	}
	return ret;
}


// Returns true if the given name is the name of an existing admin variable
bool SQLite3_Server::has_variable(const char *name) {
	size_t no_vars = sizeof(SQLite3_Server_variables_names) / sizeof(char *);
	for (unsigned int i = 0; i < no_vars-1 ; ++i) {
		size_t var_len = strlen(SQLite3_Server_variables_names[i]);
		if (strlen(name) == var_len && !strncmp(name, SQLite3_Server_variables_names[i], var_len)) {
			return true;
		}
	}
	return false;
}

char * SQLite3_Server::get_variable(char *name) {
	if (!strcasecmp(name,"mysql_ifaces")) return s_strdup(variables.mysql_ifaces);
	if (!strcasecmp(name,"read_only")) {
		return strdup((variables.read_only ? "true" : "false"));
	}
	return NULL;
}

bool SQLite3_Server::set_variable(char *name, char *value) {  // this is the public function, accessible from admin
	size_t vallen=strlen(value);

	if (!strcasecmp(name,"mysql_ifaces")) {
		if (vallen) {
			bool update_creds=false;
			if ((variables.mysql_ifaces==NULL) || strcasecmp(variables.mysql_ifaces,value) ) update_creds=true;
			if (variables.mysql_ifaces) {
				free(variables.mysql_ifaces);
				variables.mysql_ifaces=strdup(value);
				if (update_creds && variables.mysql_ifaces) {
					S_amll.update_ifaces(variables.mysql_ifaces, &S_amll.ifaces_mysql);
				}
			}
			return true;
		} else {
			return false;
		}
	}
	if (!strcasecmp(name,"read_only")) {
		if (strcasecmp(value,"true")==0 || strcasecmp(value,"1")==0) {
			variables.read_only=true;
			return true;
		}
		if (strcasecmp(value,"false")==0 || strcasecmp(value,"0")==0) {
			variables.read_only=false;
			return true;
		}
		return false;
	}
	return false;
}

void SQLite3_Server::send_MySQL_OK(MySQL_Protocol *myprot, char *msg, int rows, uint16_t status) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	myprot->generate_pkt_OK(true,NULL,NULL,1,rows,0,status,0,msg,false);
	myds->DSS=STATE_SLEEP;
}

void SQLite3_Server::send_MySQL_ERR(MySQL_Protocol *myprot, char *msg) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	myprot->generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"28000",msg);
	myds->DSS=STATE_SLEEP;
}

#ifdef TEST_READONLY
void SQLite3_Server::load_readonly_table(MySQL_Session *sess) {
	// this function needs to be called with lock on mutex readonly_mutex already acquired
	GloAdmin->mysql_servers_wrlock();
	readonly_map.clear();
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
    SQLite3_result *resultset=NULL;
	sessdb->execute_statement((char *)"SELECT * FROM READONLY_STATUS", &error , &cols , &affected_rows , &resultset);
	if (resultset) {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			std::string s = std::string(r->fields[0])+":"+std::string(r->fields[1]);
			int ro = atoi(r->fields[2]);
			bool b = ( ro ? true : false );
			readonly_map[s]=b;
		}
	}
	delete resultset;
	if (readonly_map.size()==0) {
		GloAdmin->admindb->execute_statement((char *)"SELECT DISTINCT hostname, port FROM mysql_servers WHERE hostgroup_id BETWEEN 4202 AND 4700", &error , &cols , &affected_rows , &resultset);
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			std::string s = "INSERT INTO READONLY_STATUS VALUES ('" + std::string(r->fields[0]) + "'," + std::string(r->fields[1]) + ",1)";
			sessdb->execute(s.c_str());
		}
		delete resultset;
	}
	GloAdmin->mysql_servers_wrunlock();
}

int SQLite3_Server::readonly_test_value(char *p) {
	int rc = 1; // default read_only
	std::string s = std::string(p);
	std::unordered_map<std::string, bool>::iterator it = readonly_map.find(s);
	if (it != readonly_map.end()) {
		rc = it->second;
	}
	return rc;
}
#endif // TEST_READONLY

#ifdef TEST_REPLICATIONLAG
void SQLite3_Server::load_replicationlag_table(MySQL_Session* sess) {
	GloAdmin->mysql_servers_wrlock();
	replicationlag_map.clear();
	char* error = NULL;
	int cols = 0;
	int affected_rows = 0;
	SQLite3_result* resultset = NULL;
	sessdb->execute_statement((char*)"SELECT * FROM REPLICATIONLAG_HOST_STATUS", &error, &cols, &affected_rows, &resultset);
	if (resultset) {
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r = *it;
			const std::string& s = std::string(r->fields[0]) + ":" + std::string(r->fields[1]);

			if (r->fields[2] == nullptr) {
				replicationlag_map[s] = nullptr;
			} else {
				replicationlag_map[s] = std::make_unique<int>(atoi(r->fields[2]));
			}
		}
	}
	delete resultset;
	if (replicationlag_map.size() == 0) {
		GloAdmin->admindb->execute_statement((char*)"SELECT DISTINCT hostname, port FROM mysql_servers WHERE hostgroup_id BETWEEN 5202 AND 5700", &error, &cols, &affected_rows, &resultset);
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin(); it != resultset->rows.end(); ++it) {
			SQLite3_row* r = *it;
			const std::string& s = "INSERT INTO REPLICATIONLAG_HOST_STATUS VALUES ('" + std::string(r->fields[0]) + "'," + std::string(r->fields[1]) + ",null)";
			sessdb->execute(s.c_str());
		}
		delete resultset;
	}
	GloAdmin->mysql_servers_wrunlock();
}

int* SQLite3_Server::replicationlag_test_value(const char* p) {
	int* rc = 0; // default
	std::unordered_map<std::string, std::unique_ptr<int>>::iterator it = replicationlag_map.find(std::string(p));
	if (it != replicationlag_map.end()) {
		rc = it->second.get();
	}
	return rc;
}
#endif // TEST_REPLICATIONLAG
