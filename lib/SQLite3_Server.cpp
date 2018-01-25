#include <iostream>     // std::cout
#include <algorithm>    // std::sort
#include <vector>       // std::vector
#include "re2/re2.h"
#include "re2/regexp.h"
#include "proxysql.h"
#include "cpp.h"

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

<<<<<<< HEAD
=======
#define SAFE_SQLITE3_STEP2(_stmt) do {\
        do {\
                rc=sqlite3_step(_stmt);\
                if (rc==SQLITE_LOCKED || rc==SQLITE_BUSY) {\
                        usleep(100);\
                }\
        } while (rc==SQLITE_LOCKED || rc==SQLITE_BUSY);\
} while (0)

/*
static void StringToHex(unsigned char *string, unsigned char *hexstring, size_t l) {
	unsigned char ch;
	size_t i, j;

	for (i=0, j=0; i<l; i++, j+=2) {
		ch=string[i];
		ch = ch >> 4;
		if (ch <= 9) {
			hexstring[j]= '0' + ch;
		} else {
			hexstring[j]= 'A' + ch - 10;
		}
		ch = string[i];
		ch = ch & 0x0F;
		if (ch <= 9) {
			hexstring[j+1]= '0' + ch;
		} else {
			hexstring[j+1]= 'A' + ch - 10;
		}
	}
}
*/
>>>>>>> 9b3fffd... Removing SQLLite lock assertion

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

static char *s_strdup(char *s) {
	char *ret=NULL;
	if (s) {
		ret=strdup(s);
	}
	return ret;
}

static int __SQLite3_Server_refresh_interval=1000;

extern Query_Cache *GloQC;
extern MySQL_Authentication *GloMyAuth;
extern ProxySQL_Admin *GloAdmin;
extern Query_Processor *GloQPro;
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

#define MAX_IFACES	8
#define MAX_SQLITE3SERVER_LISTENERS 16

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

	char *query_no_space=(char *)l_alloc(query_length);
	memcpy(query_no_space,query,query_length);

	unsigned int query_no_space_length=remove_spaces(query_no_space);

	// fix bug #925
	while (query_no_space[query_no_space_length-1]==';' || query_no_space[query_no_space_length-1]==' ') {
		query_no_space_length--;
		query_no_space[query_no_space_length]=0;
	}

	if (query_no_space_length==SELECT_VERSION_COMMENT_LEN) {
		if (!strncasecmp(SELECT_VERSION_COMMENT, query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			query=l_strdup("SELECT '(ProxySQL Admin Module)'");
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
		SQLite3_Session *sqlite_sess = (SQLite3_Session *)sess->thread->gen_args;
		sqlite_sess->sessdb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot);
		delete resultset;
	}
	l_free(pkt->size-sizeof(mysql_hdr),query_no_space); // it is always freed here
	l_free(query_length,query);
}


SQLite3_Session::SQLite3_Session() {
	sessdb = new SQLite3DB();
    sessdb->open((char *)"file:mem_sqlitedb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);	
}

SQLite3_Session::~SQLite3_Session() {
	delete sessdb;
	sessdb = NULL;
}

static void *child_mysql(void *arg) {

	int client = *(int *)arg;

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

	GloQPro->init_thread();
	mysql_thr->refresh_variables();
	MySQL_Session *sess=mysql_thr->create_new_session_and_client_data_stream(client);
	sess->thread=mysql_thr;
	sess->session_type = PROXYSQL_SESSION_SQLITE;
	sess->handler_function=SQLite3_Server_session_handler;
	MySQL_Data_Stream *myds=sess->client_myds;

	fds[0].fd=client;
	fds[0].revents=0;
	fds[0].events=POLLIN|POLLOUT;
	free(arg);
	sess->client_myds->myprot.generate_pkt_initial_handshake(true,NULL,NULL, &sess->thread_session_id);

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
		myds->read_from_net();
		if (myds->net_failure) goto __exit_child_mysql;
		myds->read_pkts();
		sess->to_process=1;
		int rc=sess->handler();
		if (rc==-1) goto __exit_child_mysql;
	}

__exit_child_mysql:
	delete sqlite_sess;
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
				pthread_attr_getstacksize (&attr, &stacks);
				pthread_mutex_lock (&sock_mutex);
				client=(int *)malloc(sizeof(int));
				*client= client_t;
				if ( pthread_create(&child, &attr, child_func[callback_func[i]], client) != 0 )
					perror("Thread creation");
			}
			fds[i].revents=0;
		}
__end_while_pool:
		if (S_amll.get_version()!=version) {
			S_amll.wrlock();
			version=S_amll.get_version();
			for (i=0; i<nfds; i++) {
				char *add=NULL; char *port=NULL;
				close(fds[i].fd);
				c_split_2(socket_names[i], ":" , &add, &port);
				if (atoi(port)==0) { unlink(socket_names[i]); }
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

				int s = ( atoi(port) ? listen_on_port(add, atoi(port), 128) : listen_on_unix(add, 128));
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
#define PROXYSQL_SQLITE3_SERVER_VERSION "0.7.0625" DEB

SQLite3_Server::~SQLite3_Server() {
	delete sessdb;
	sessdb = NULL;
};

SQLite3_Server::SQLite3_Server() {
#ifdef DEBUG
		if (glovars.has_debug==false) {
#else
		if (glovars.has_debug==true) {
#endif /* DEBUG */
			perror("Incompatible debagging version");
			exit(EXIT_FAILURE);
		}

//	SPA=this;

	//Initialize locker
	pthread_rwlock_init(&rwlock,NULL);

	sessdb = new SQLite3DB();
    sessdb->open((char *)"file:mem_sqlitedb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);	

	variables.mysql_ifaces=strdup("127.0.0.1:6030");
	variables.read_only=false;
};

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
	cpu_timer cpt;

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
			if (variables.mysql_ifaces)
				free(variables.mysql_ifaces);
				variables.mysql_ifaces=strdup(value);
				if (update_creds && variables.mysql_ifaces) {
					S_amll.update_ifaces(variables.mysql_ifaces, &S_amll.ifaces_mysql);
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

void SQLite3_Server::send_MySQL_OK(MySQL_Protocol *myprot, char *msg, int rows) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	myprot->generate_pkt_OK(true,NULL,NULL,1,rows,0,2,0,msg);
	myds->DSS=STATE_SLEEP;
}

void SQLite3_Server::send_MySQL_ERR(MySQL_Protocol *myprot, char *msg) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	myprot->generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"28000",msg);
	myds->DSS=STATE_SLEEP;
}
