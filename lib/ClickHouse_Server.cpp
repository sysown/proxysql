#ifdef PROXYSQLCLICKHOUSE
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
#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

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
    rc=(*proxy_sqlite3_step)(_stmt);\
    if (rc!=SQLITE_DONE) {\
      assert(rc==SQLITE_LOCKED);\
      usleep(100);\
    }\
  } while (rc!=SQLITE_DONE);\
} while (0)

#define SAFE_SQLITE3_STEP2(_stmt) do {\
	do {\
	rc=(*proxy_sqlite3_step)(_stmt);\
		if (rc==SQLITE_LOCKED || rc==SQLITE_BUSY) {\
			usleep(100);\
		}\
	} while (rc==SQLITE_LOCKED || rc==SQLITE_BUSY);\
} while (0)

#include "clickhouse/client.h"

using namespace clickhouse;

__thread MySQL_Session * clickhouse_thread___mysql_sess;

inline void ClickHouse_to_MySQL(const Block& block) {
	MySQL_Session *sess = clickhouse_thread___mysql_sess;
	MySQL_Protocol *myprot=NULL;
	myprot=&sess->client_myds->myprot;

	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	int columns=block.GetColumnCount();
	ClickHouse_Session *clickhouse_sess = (ClickHouse_Session *)sess->thread->gen_args;
	int sid=clickhouse_sess->sid;
	if (clickhouse_sess->transfer_started==false) {
		clickhouse_sess->transfer_started=true;
		sid=1;
		columns=block.GetColumnCount();
		//int rows=block.GetRowCount();
		myprot->generate_pkt_column_count(true,NULL,NULL,sid,block.GetColumnCount()); sid++;
		// Return proper types for:
		// - Int8/Int16/Int32/Int64/Float/Double/NULL/DATE/Datetime
		for (Block::Iterator bi(block); bi.IsValid(); bi.Next()) {
			clickhouse::Type::Code cc = bi.Type()->GetCode();

			uint8_t is_null = 1;

			if (cc != clickhouse::Type::Code::Nullable) {
				is_null = 0;
			} else {
				auto s_t = bi.Column()->As<ColumnNullable>();
#ifdef CXX17
				cc = s_t->Nested()->GetType().GetCode();
#else
				cc = s_t->Type()->GetNestedType()->GetCode();
#endif // CXX17
			}

			if (cc >= clickhouse::Type::Code::Int8 && cc <= clickhouse::Type::Code::Float64) {
				bool _unsigned = false;
				uint16_t flags = is_null | 128;

				// NOTE: Both 'size' and 'decimals' are just used for representation purposes.
				// For this reason, the values we specify here are always the 'MAX' length of these
				// fields without any computation specific to the current value. See note:
				//   - https://dev.mysql.com/doc/internals/en/com-query-response.html#column-definition
				uint32_t size = 0;
				uint8_t decimals = 0;

				enum_field_types type = MYSQL_TYPE_LONG;

				switch(cc) {
					case clickhouse::Type::Code::UInt8:
						_unsigned = true;
					case clickhouse::Type::Code::Int8:
						type = MYSQL_TYPE_TINY;
						flags |= (_unsigned ? 32 : 0);
						size = 4;
						break;
					case clickhouse::Type::Code::UInt16:
						_unsigned = true;
					case clickhouse::Type::Code::Int16:
						type = MYSQL_TYPE_SHORT;
						flags |= (_unsigned ? 32 : 0);
						size = 6;
						break;
					case clickhouse::Type::Code::UInt32:
						_unsigned = true;
					case clickhouse::Type::Code::Int32:
						type = MYSQL_TYPE_LONG;
						flags |= (_unsigned ? 32 : 0);
						size = 11;
						break;
					case clickhouse::Type::Code::UInt64:
						_unsigned = true;
					case clickhouse::Type::Code::Int64:
						type = MYSQL_TYPE_LONGLONG;
						flags |= (_unsigned ? 32 : 0);
						size = 20;
						break;
					case clickhouse::Type::Code::Float32:
						type = MYSQL_TYPE_FLOAT;
						size = 12;
						decimals = 31;
						break;
					case clickhouse::Type::Code::Float64:
						type = MYSQL_TYPE_DOUBLE;
						size = 22;
						decimals = 31;
						break;
					default:
						_unsigned = false;
						flags = 128;
						size = 22;
				}

				myprot->generate_pkt_field(
					true, NULL, NULL, sid, (char*)"", (char*)"", (char*)"", (char*)bi.Name().c_str(),
					(char*)"", 63, size, type, flags, decimals, false, 0, NULL
				);
			} else if (cc == clickhouse::Type::Code::Date || cc == clickhouse::Type::Code::DateTime) {
				if (cc == clickhouse::Type::Code::Date) {
					const uint32_t size = strlen("YYYY-MM-DD") + 1;
					myprot->generate_pkt_field(
						true, NULL, NULL, sid, (char*)"", (char*)"", (char*)"", (char*)bi.Name().c_str(),
						(char*)"", 33, size, MYSQL_TYPE_DATE, 0, 0x0, false, 0, NULL
					);
				} else {
					const uint32_t size = strlen("YYYY-MM-DD hh:mm:ss") + 1;
					myprot->generate_pkt_field(
						true, NULL, NULL, sid, (char*)"", (char*)"", (char*)"", (char*)bi.Name().c_str(),
						(char*)"", 33, size, MYSQL_TYPE_DATETIME, 0, 0x0, false, 0, NULL
					);
				}
			} else {
				myprot->generate_pkt_field(
					true, NULL, NULL, sid, (char *)"", (char *)"", (char *)"", (char *)bi.Name().c_str(),
					(char *)"", 33, 15, MYSQL_TYPE_VAR_STRING, 0, 0x1f, false, 0, NULL
				);
			}

			sid++;
		}
/*
	for (size_t i = 0; i < block.GetColumnCount(); ++i) {
		std::cout << block[i]->Type()->GetCode() << "\n";
	}
*/
		myds->DSS=STATE_COLUMN_DEFINITION;
		unsigned int nTrx=0;
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		//if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
		bool deprecate_eof_active = sess->client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
		if (!deprecate_eof_active) {
			myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
		}
	}
	char **p=(char **)malloc(sizeof(char*)*columns);
	unsigned long *l=(unsigned long *)malloc(sizeof(unsigned long *)*columns);
	int rows=block.GetRowCount();
	for (int r=0; r<rows; r++) {
		for (int i=0; i<columns; i++) {
			clickhouse::Type::Code cc = block[i]->Type()->GetCode();
			bool is_null = false;
			string s;
			switch (cc) {
				case clickhouse::Type::Code::Int8:
					s=std::to_string(block[i]->As<ColumnInt8>()->At(r));
					break;
				case clickhouse::Type::Code::UInt8:
					s=std::to_string(block[i]->As<ColumnUInt8>()->At(r));
					break;
				case clickhouse::Type::Code::Int16:
					s=std::to_string(block[i]->As<ColumnInt16>()->At(r));
					break;
				case clickhouse::Type::Code::UInt16:
					s=std::to_string(block[i]->As<ColumnUInt16>()->At(r));
					break;
				case clickhouse::Type::Code::Int32:
					s=std::to_string(block[i]->As<ColumnInt32>()->At(r));
					break;
				case clickhouse::Type::Code::UInt32:
					s=std::to_string(block[i]->As<ColumnUInt32>()->At(r));
					break;
				case clickhouse::Type::Code::Int64:
					s=std::to_string(block[i]->As<ColumnInt64>()->At(r));
					break;
				case clickhouse::Type::Code::UInt64:
					s=std::to_string(block[i]->As<ColumnUInt64>()->At(r));
					break;
				case clickhouse::Type::Code::Float32:
					s=std::to_string(block[i]->As<ColumnFloat32>()->At(r));
					break;
				case clickhouse::Type::Code::Float64:
					s=std::to_string(block[i]->As<ColumnFloat64>()->At(r));
					break;
				case clickhouse::Type::Code::Enum8:
					s=block[i]->As<ColumnEnum8>()->NameAt(r);;
					break;
				case clickhouse::Type::Code::Enum16:
					s=block[i]->As<ColumnEnum16>()->NameAt(r);;
					break;
				case clickhouse::Type::Code::String:
					s=block[i]->As<ColumnString>()->At(r);
					break;
				case clickhouse::Type::Code::FixedString:
					s=block[i]->As<ColumnFixedString>()->At(r);
					break;
				case clickhouse::Type::Code::Date:
					{
						std::time_t t=block[i]->As<ColumnDate>()->At(r);
						struct tm *tm = localtime(&t);
						char date[20];
						memset(date,0,sizeof(date));
						strftime(date, sizeof(date), "%Y-%m-%d", tm);
						s=date;
					}
					break;
				case clickhouse::Type::Code::DateTime:
					{
						std::time_t t=block[i]->As<ColumnDateTime>()->At(r);
						struct tm *tm = localtime(&t);
						char date[20];
						memset(date,0,sizeof(date));
						strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", tm);
						s=date;
					}
					break;
				case clickhouse::Type::Code::Nullable:
					{
						auto s_t = block[i]->As<ColumnNullable>();
						if (s_t->IsNull(r)) {
							is_null = true;
						} else {
							clickhouse::Type::Code cnc = s_t->Nested()->Type()->GetCode();
							switch (cnc) {
								case clickhouse::Type::Code::Int8:
									s=std::to_string(s_t->Nested()->As<ColumnInt8>()->At(r));
									break;
								case clickhouse::Type::Code::UInt8:
									s=std::to_string(s_t->Nested()->As<ColumnUInt8>()->At(r));
									break;
								case clickhouse::Type::Code::Int16:
									s=std::to_string(s_t->Nested()->As<ColumnInt16>()->At(r));
									break;
								case clickhouse::Type::Code::UInt16:
									s=std::to_string(s_t->Nested()->As<ColumnUInt16>()->At(r));
									break;
								case clickhouse::Type::Code::Int32:
									s=std::to_string(s_t->Nested()->As<ColumnInt32>()->At(r));
									break;
								case clickhouse::Type::Code::UInt32:
									s=std::to_string(s_t->Nested()->As<ColumnUInt32>()->At(r));
									break;
								case clickhouse::Type::Code::Int64:
									s=std::to_string(s_t->Nested()->As<ColumnInt64>()->At(r));
									break;
								case clickhouse::Type::Code::UInt64:
									s=std::to_string(s_t->Nested()->As<ColumnUInt64>()->At(r));
									break;
								case clickhouse::Type::Code::Float32:
									s=std::to_string(s_t->Nested()->As<ColumnFloat32>()->At(r));
									break;
								case clickhouse::Type::Code::Float64:
									s=std::to_string(s_t->Nested()->As<ColumnFloat64>()->At(r));
									break;
								case clickhouse::Type::Code::String:
									s=s_t->Nested()->As<ColumnString>()->At(r);
									break;
								case clickhouse::Type::Code::FixedString:
									s=s_t->Nested()->As<ColumnFixedString>()->At(r);
									break;
								case clickhouse::Type::Code::Date:
									{
										std::time_t t=block[i]->As<ColumnDate>()->At(r);
										struct tm *tm = localtime(&t);
										char date[20];
										memset(date,0,sizeof(date));
										strftime(date, sizeof(date), "%Y-%m-%d", tm);
										s=date;
									}
									break;
								case clickhouse::Type::Code::DateTime:
									{
										std::time_t t=block[i]->As<ColumnDateTime>()->At(r);
										struct tm *tm = localtime(&t);
										char date[20];
										memset(date,0,sizeof(date));
										strftime(date, sizeof(date), "%Y-%m-%d %H:%M:%S", tm);
										s=date;
									}
									break;
								default:
									break;
							}
						}
					}
					break;
				default:
					break;
			}
			if (is_null == false) {
				l[i]=s.length();
				p[i]=strdup((char *)s.c_str());
			} else {
				p[i]=NULL;
			}
    }
    myprot->generate_pkt_row(true,NULL,NULL,sid,columns,l,p); sid++;
		for (int i=0; i<columns; i++) {
			free(p[i]);
		}
    }
    myds->DSS=STATE_ROW;
		clickhouse_sess->sid=sid;
    //myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, 2 | setStatus ); sid++;
    //myds->DSS=STATE_SLEEP;
    free(l);
    free(p);
}

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


static int __ClickHouse_Server_refresh_interval=1000;
extern Query_Cache *GloQC;
extern ClickHouse_Authentication *GloClickHouseAuth;
extern ProxySQL_Admin *GloAdmin;
extern Query_Processor *GloQPro;
extern MySQL_Threads_Handler *GloMTH;
extern MySQL_Logger *GloMyLogger;
extern MySQL_Monitor *GloMyMon;
extern ClickHouse_Server *GloClickHouseServer;

#define PANIC(msg)  { perror(msg); exit(EXIT_FAILURE); }

static pthread_mutex_t sock_mutex = PTHREAD_MUTEX_INITIALIZER;


static char * ClickHouse_Server_variables_names[] = {
	(char *)"hostname",
	(char *)"mysql_ifaces",
	(char *)"read_only",
	(char *)"port",
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

void ClickHouse_Server_session_handler(MySQL_Session *sess, void *_pa, PtrSize_t *pkt) {
	char *error=NULL;
	int cols;
	int affected_rows;
	bool run_query=true;
	bool run_query_sqlite=false;
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

	proxy_debug(PROXY_DEBUG_SQLITE, 4, "Received query on Session %p , thread_session_id %u : %s\n", sess, sess->thread_session_id, query_no_space);


	if (sess->session_type == PROXYSQL_SESSION_CLICKHOUSE) {
		if (!strncasecmp("SET ", query_no_space, 4)) {
			if (
				!strncasecmp("SET AUTOCOMMIT", query_no_space, 14) ||
				!strncasecmp("SET NAMES ", query_no_space, 10) ||
				!strncasecmp("SET FOREIGN_KEY_CHECKS",query_no_space,22) ||
				!strncasecmp("SET CHARACTER", query_no_space, 13) ||
				!strncasecmp("SET COLLATION", query_no_space, 13) ||
				!strncasecmp("SET SQL_AUTO_", query_no_space, 13) ||
				!strncasecmp("SET SQL_SAFE_", query_no_space, 13) ||
				!strncasecmp("SET SESSION TRANSACTION", query_no_space, 23) ||
				!strncasecmp("SET WAIT_TIMEOUT", query_no_space, 16)
			) {
				GloClickHouseServer->send_MySQL_OK(&sess->client_myds->myprot, NULL);
				run_query=false;
				goto __run_query;
			}
		}	
		if (!strncasecmp("SHOW ", query_no_space, 5)) {
			if (
				!strncasecmp("SHOW COLUMNS FROM ", query_no_space, 18)
			) {
				l_free(query_length,query);
				char *q=(char *)malloc(query_length+256);
				sprintf(q,"DESC %s",query_no_space+18);
				//fprintf(stderr,"%s\n",q);
				query=l_strdup(q);
				query_length=strlen(query)+1;
				free(q);
            	run_query = true;
				goto __run_query;
			}
			if (
				!strncasecmp("SHOW SESSION STATUS LIKE ", query_no_space, 25)
				||
				!strncasecmp("SHOW SESSION VARIABLES LIKE ", query_no_space, 28)
				||
				!strncasecmp("SHOW VARIABLES LIKE ", query_no_space, 20)
			) {
				bool found = false;
				int offset = 0;
				if (found == false && !strncasecmp("SHOW SESSION STATUS LIKE ", query_no_space, 25)) {
					offset = 25;
					found = true;
				}
				if (found == false && !strncasecmp("SHOW SESSION VARIABLES LIKE ", query_no_space, 28)) {
					offset = 28;
					found = true;
				}
				if (found == false && !strncasecmp("SHOW VARIABLES LIKE ", query_no_space, 20)) {
					offset = 20;
					found = true;
				}
				l_free(query_length,query);
				char *q=(char *)malloc(query_length+256);
				sprintf(q,"SELECT variable_name Variable_name, Variable_value Value FROM global_variables WHERE Variable_name LIKE %s",query_no_space+offset);
				//fprintf(stderr,"%s\n",q);
				query=l_strdup(q);
				query_length=strlen(query)+1;
				free(q);
            	run_query_sqlite = true;
            	goto __run_query_sqlite;
			}
			if (
				(query_no_space_length==strlen("SHOW GLOBAL VARIABLES") && !strncasecmp("SHOW GLOBAL VARIABLES",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("SHOW ALL VARIABLES") && !strncasecmp("SHOW ALL VARIABLES",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("SHOW GLOBAL STATUS") && !strncasecmp("SHOW GLOBAL STATUS",query_no_space, query_no_space_length))
				||
				(query_no_space_length==strlen("SHOW VARIABLES") && !strncasecmp("SHOW VARIABLES",query_no_space, query_no_space_length))
			) {
				l_free(query_length,query);
				query=l_strdup("SELECT variable_name AS Variable_name, variable_value AS Value FROM global_variables ORDER BY variable_name");
				query_length=strlen(query)+1;
            	run_query_sqlite = true;
            	goto __run_query_sqlite;
			}
			if (
				(query_no_space_length==strlen("SHOW ENGINES") && !strncasecmp("SHOW ENGINES",query_no_space, query_no_space_length))
			) {
				l_free(query_length,query);
				query=l_strdup("SELECT * FROM show_engines");
				query_length=strlen(query)+1;
            	run_query_sqlite = true;
            	goto __run_query_sqlite;
			}
			if (
				(pkt->size==(strlen("show charset")+5) && strncasecmp((char *)"show charset",(char *)pkt->ptr+5,pkt->size-5)==0)
			) {
				l_free(query_length,query);
				query=l_strdup("SELECT Charset, Collation AS 'Default collation' FROM mysql_collations WHERE `Default`='Yes'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
			}
			if (
				(pkt->size==(strlen("show collation")+5) && strncasecmp((char *)"show collation",(char *)pkt->ptr+5,pkt->size-5)==0)
			) {
				l_free(query_length,query);
				query=l_strdup("SELECT * FROM mysql_collations");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
			}
			if (
				(pkt->size==(strlen("SHOW FULL TABLES FROM `default`")+5) && strncasecmp((char *)"SHOW FULL TABLES FROM `default`",(char *)pkt->ptr+5,pkt->size-5)==0)
			) {
				l_free(query_length,query);
				query=l_strdup("SELECT name, 'BASE TABLE' AS Table_type FROM system.tables WHERE database = 'default'");
				query_length=strlen(query)+1;
				run_query = true;
				goto __run_query;
			}
		}
		if (
			(pkt->size==(strlen("SELECT * FROM INFORMATION_SCHEMA.CHARACTER_SETS")+5) && strncasecmp((char *)"SELECT * FROM INFORMATION_SCHEMA.CHARACTER_SETS",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT Charset AS CHARACTER_SET_NAME , Collation AS DEFAULT_COLLATE_NAME, 'UTF-8 Unicode' AS DESCRIPTION , 3 AS LEN FROM mysql_collations WHERE `Default`='Yes'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}

		if (
			(pkt->size==(strlen("SELECT @@character_set_results")+5) && strncasecmp((char *)"SELECT @@character_set_results",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT 'utf8' AS '@@character_set_results'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}
		if (
			(pkt->size==(strlen("SELECT @@collation_server")+5) && strncasecmp((char *)"SELECT @@collation_server",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT 'utf8_general_ci' AS '@@collation_server'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}
		if (
			(pkt->size==(strlen("SELECT @@have_profiling")+5) && strncasecmp((char *)"SELECT @@have_profiling",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT 'NO' AS '@@have_profiling'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}
		if (
			(pkt->size==(strlen("SELECT @@lower_case_table_names")+5) && strncasecmp((char *)"SELECT @@lower_case_table_names",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT '0' AS '@@lower_case_table_names'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}
		if (
			(pkt->size==(strlen("SELECT @@version, @@version_comment")+5) && strncasecmp((char *)"SELECT @@version, @@version_comment",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT '5.7.19-ProxySQL-ClickHouse' AS '@@version', '(ProxySQL-ClickHouse)' AS '@@version_comment'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}
		if (
			(pkt->size==(strlen("SELECT @@storage_engine")+5) && strncasecmp((char *)"SELECT @@storage_engine",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT 'MergeTree' AS '@@storage_engine'");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}

		if (query_no_space_length==strlen((char *)"SELECT CURRENT_USER()")) {
			if (!strncasecmp((char *)"SELECT CURRENT_USER()", query_no_space, query_no_space_length)) {
				l_free(query_length,query);
				char *query1=(char *)"SELECT \"%s\" AS 'CURRENT_USER()'";
				char *query2=(char *)malloc(strlen(query1)+strlen(sess->client_myds->myconn->userinfo->username)+10);
				sprintf(query2,query1,sess->client_myds->myconn->userinfo->username);
				query=l_strdup(query2);
				query_length=strlen(query2)+1;
				free(query2);
				run_query_sqlite = true;
				goto __run_query_sqlite;
			}
		}
		if (query_no_space_length==strlen((char *)"SELECT USER()")) {
			if (!strncasecmp((char *)"SELECT USER()", query_no_space, query_no_space_length)) {
				l_free(query_length,query);
				char *query1=(char *)"SELECT \"%s\" AS 'USER()'";
				char *query2=(char *)malloc(strlen(query1)+strlen(sess->client_myds->myconn->userinfo->username)+10);
				sprintf(query2,query1,sess->client_myds->myconn->userinfo->username);
				query=l_strdup(query2);
				query_length=strlen(query2)+1;
				free(query2);
				run_query_sqlite = true;
				goto __run_query_sqlite;
			}
		}

		if (
			(pkt->size==(strlen("SELECT * FROM INFORMATION_SCHEMA.COLLATIONS")+5) && strncasecmp((char *)"SELECT * FROM INFORMATION_SCHEMA.COLLATIONS",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
				l_free(query_length,query);
				query=l_strdup("SELECT Collation AS COLLATION_NAME, Charset AS CHARACTER_SET_NAME, Id AS ID, 'Default' AS IS_DEFAULT, 'Yes' AS IS_COMPILED, '3' AS SORTLEN FROM mysql_collations");
				query_length=strlen(query)+1;
				run_query_sqlite = true;
				goto __run_query_sqlite;
		}
		if (
			!strncasecmp("/*!40101 SET ", query_no_space, 13)
		) {
			GloClickHouseServer->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			run_query=false;
			goto __run_query;
		}

		if (
			(
				(query_no_space_length > 40) &&
				strncasecmp("SELECT DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SC",query_no_space,strlen("SELECT DEFAULT_COLLATION_NAME FROM information_schema.SCHEMATA WHERE SC") == 0))
		) {
			l_free(query_length,query);
			query=l_strdup("SELECT 'utf8_general_ci' AS DEFAULT_COLLATION_NAME");
			query_length=strlen(query)+1;
            run_query_sqlite = true;
            goto __run_query_sqlite;
		}
		if (
			(
				(query_no_space_length > 50) &&
				//(strncasecmp("SELECT \*,\n       ",query_no_space,strlen("SELECT \*,\n       ") == 0)) &&
				(strstr(query_no_space,"CAST(BIN_NAME AS CHAR CHARACTER SET utf8) AS SCHEMA_NAME")) &&
				(strstr(query_no_space,"BINARY s.SCHEMA_NAME AS BIN_NAME,")) &&
				(strstr(query_no_space,"s.DEFAULT_COLLATION_NAME")) &&
				(strstr(query_no_space,"FROM `information_schema`.SCHEMATA s")) &&
				(strstr(query_no_space,"GROUP BY BINARY s.SCHEMA_NAME, s.DEFAULT_COLLATION_NAME"))
			)
		) {
			l_free(query_length,query);
			query=l_strdup("SELECT name AS BIN_NAME, 'utf8_general_ci' AS DEFAULT_COLLATION_NAME, name AS SCHEMA_NAME FROM system.databases");
			query_length=strlen(query)+1;
			goto __run_query;
		}

		if (
			(pkt->size==(strlen("SELECT `SCHEMA_NAME` FROM `INFORMATION_SCHEMA`.`SCHEMATA`")+5) && strncasecmp((char *)"SELECT `SCHEMA_NAME` FROM `INFORMATION_SCHEMA`.`SCHEMATA`",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
			l_free(query_length,query);
			query=l_strdup("SELECT name AS SCHEMA_NAME FROM system.databases");
			query_length=strlen(query)+1;
			goto __run_query;
		}

		if (
			(pkt->size==(strlen("SELECT version()")+5) && strncasecmp((char *)"SELECT version()",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
			l_free(query_length,query);
			char *q=(char *)malloc(query_length+256);
			sprintf(q,"SELECT Variable_value 'version' FROM global_variables WHERE Variable_name = 'version'");
			query=l_strdup(q);
			query_length=strlen(query)+1;
			free(q);
            run_query_sqlite = true;
            goto __run_query_sqlite;	
		}
		if (
			(pkt->size==(strlen("select name, type FROM mysql.proc where db='default'")+5) && strncasecmp((char *)"select name, type FROM mysql.proc where db='default'",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
			l_free(query_length,query);
			char *q=(char *)malloc(query_length+256);
			sprintf(q,"SELECT * FROM global_variables WHERE 1=0");
			query=l_strdup(q);
			query_length=strlen(query)+1;
			free(q);
            run_query_sqlite = true;
            goto __run_query_sqlite;	
		}
		if (
			(pkt->size==(strlen((char *)"SELECT logfile_group_name FROM information_schema.FILES")+5) && strncasecmp((char *)"SELECT logfile_group_name FROM information_schema.FILES",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
			l_free(query_length,query);
			char *q=(char *)"SELECT ' ' AS logfile_group_name FROM global_variables WHERE 1=0";
			query=l_strdup(q);
			query_length=strlen(query)+1;
            run_query_sqlite = true;
            goto __run_query_sqlite;
		}
		if (
			(pkt->size==(strlen((char *)"SELECT tablespace_name FROM information_schema.FILES")+5) && strncasecmp((char *)"SELECT tablespace_name FROM information_schema.FILES",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
			l_free(query_length,query);
			char *q=(char *)"SELECT ' ' AS tablespace_name FROM global_variables WHERE 1=0";
			query=l_strdup(q);
			query_length=strlen(query)+1;
            run_query_sqlite = true;
            goto __run_query_sqlite;
		}
		if (
			(pkt->size==(strlen("SELECT CONNECTION_ID()")+5) && strncasecmp((char *)"SELECT CONNECTION_ID()",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
			char buf[16];
			sprintf(buf,"%u",sess->thread_session_id);
			//unsigned int nTrx=NumActiveTransactions();
			unsigned int nTrx= 0;
			uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
			//if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
			setStatus += SERVER_STATUS_AUTOCOMMIT;
			MySQL_Data_Stream *myds=sess->client_myds;
			MySQL_Protocol *myprot=&sess->client_myds->myprot;
			myds->DSS=STATE_QUERY_SENT_DS;
			int sid=1;
			myprot->generate_pkt_column_count(true,NULL,NULL,sid,1); sid++;
			myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",(char *)"CONNECTION_ID()",(char *)"",63,31,MYSQL_TYPE_LONGLONG,161,0,false,0,NULL); sid++;
			myds->DSS=STATE_COLUMN_DEFINITION;
			bool deprecate_eof_active = sess->client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
			if (!deprecate_eof_active) {
				myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
			}
			char **p=(char **)malloc(sizeof(char*)*1);
			unsigned long *l=(unsigned long *)malloc(sizeof(unsigned long *)*1);
			l[0]=strlen(buf);;
			p[0]=buf;
			myprot->generate_pkt_row(true,NULL,NULL,sid,1,l,p); sid++;
			myds->DSS=STATE_ROW;
			if (!deprecate_eof_active) {
				myprot->generate_pkt_EOF(true, NULL, NULL, sid, 0, setStatus);
				sid++;
			} else {
				myprot->generate_pkt_OK(true, NULL, NULL, sid, 0, 0, setStatus, 0, NULL, true);
				sid++;
			}
			myds->DSS=STATE_SLEEP;
			run_query=false;
			goto __run_query;
		}
/*
		if (
			(pkt->size==(strlen("SELECT current_user()")+5) && strncasecmp((char *)"SELECT current_user()",(char *)pkt->ptr+5,pkt->size-5)==0)
		) {
			char buf[32];
			sprintf(buf,"%s",sess->client_myds->myconn->userinfo->username);
			//unsigned int nTrx=NumActiveTransactions();
			unsigned int nTrx= 0;
			uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
			//if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
			setStatus += SERVER_STATUS_AUTOCOMMIT;
			MySQL_Data_Stream *myds=sess->client_myds;
			MySQL_Protocol *myprot=&sess->client_myds->myprot;
			myds->DSS=STATE_QUERY_SENT_DS;
			int sid=1;
			myprot->generate_pkt_column_count(true,NULL,NULL,sid,1); sid++;
			myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",(char *)"current_user()",(char *)"",33,15,MYSQL_TYPE_VAR_STRING,1,0x1f,false,0,NULL); sid++;
			myds->DSS=STATE_COLUMN_DEFINITION;
			myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
			char **p=(char **)malloc(sizeof(char*)*1);
			unsigned long *l=(unsigned long *)malloc(sizeof(unsigned long *)*1);
			l[0]=strlen(buf);
			p[0]=buf;
			myprot->generate_pkt_row(true,NULL,NULL,sid,1,l,p); sid++;
			myds->DSS=STATE_ROW;
			myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
			myds->DSS=STATE_SLEEP;
			run_query=false;
			goto __run_query;
		}
*/
	}

	if (query_no_space_length==SELECT_VERSION_COMMENT_LEN) {
		if (!strncasecmp(SELECT_VERSION_COMMENT, query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			query=l_strdup("SELECT '(ProxySQL ClickHouse Module)'");
			query_length=strlen(query)+1;
			goto __run_query;
		}
	}

	if (query_no_space_length==SELECT_DB_USER_LEN) {
		if (!strncasecmp(SELECT_DB_USER, query_no_space, query_no_space_length)) {
			l_free(query_length,query);
			char *query1=(char *)"SELECT 'admin' AS \"DATABASE()\", '%s' AS \"USER()\"";
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
			char *query1=(char *)"select 'utf8' as \"@@character_set_client\", 'utf8' as \"@@character_set_connection\", 'utf8' as \"@@character_set_server\", 'utf8' as \"@@character_set_database\" limit 1";
			query=l_strdup(query1);
			query_length=strlen(query1)+1;
			goto __run_query;
		}
	}

	if (!strncasecmp("SELECT version()", query_no_space, strlen("SELECT version()"))) {
		l_free(query_length,query);
		char *q=(char *)"SELECT '%s' AS \"version()\"";
		query_length=strlen(q)+20;
		query=(char *)l_alloc(query_length);
		sprintf(query,q,PROXYSQL_VERSION);
		goto __run_query;
	}
	if (strncasecmp("SHOW ", query_no_space, 5)) {
		goto __end_show_commands; // in the next block there are only SHOW commands
	}

	if (
		(query_no_space_length==strlen("SHOW DATABASES") && !strncasecmp("SHOW DATABASES",query_no_space, query_no_space_length))
		||
		(query_no_space_length==strlen("SHOW SCHEMAS") && !strncasecmp("SHOW SCHEMAS",query_no_space, query_no_space_length))
		||
		(query_no_space_length==strlen("SHOW DATABASES LIKE '%'") && !strncasecmp("SHOW DATABASES LIKE '%'",query_no_space, query_no_space_length))
	) {
		l_free(query_length,query);
		query=l_strdup("SELECT name FROM system.databases");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	if ((query_no_space_length>24) && (!strncasecmp("SHOW TABLE STATUS FROM `", query_no_space, 24))) {
		strA=query_no_space+24;
		strAl=strlen(strA);
		strB=(char *)"SELECT name AS Name, engine AS Engine, '10' AS Version, 'Dynamic' AS Row_format, 0 AS Rows, 0 AS Avg_row_length, 0 AS Data_length, 0 AS Max_data_length, 0 AS Index_length, 0 AS Data_free, 'NULL' AS Auto_increment, metadata_modification_time AS Create_time, metadata_modification_time AS Update_time, metadata_modification_time AS Check_time, 'utf8_bin' AS Collation, 'NULL' AS Checksum, '' AS Create_options, '' AS Comment FROM system.tables WHERE database='%s";
		strBl=strlen(strB);
		int l=strBl+strAl-2;
		char *b=(char *)l_alloc(l+1);
		snprintf(b,l+1,strB,strA);
		b[l-1]='\'';
		b[l]=0;
		l_free(query_length,query);
		query=b;
		printf("%s\n",query);
		query_length=l+1;
		goto __run_query;
	}

__end_show_commands:

	if ((query_no_space_length>50) && (!strncasecmp("SELECT TABLE_NAME ", query_no_space, 18))) {
		if (
			(strstr(query_no_space,"information_schema.VIEWS"))
		) {
			l_free(query_length,query);
			char *q=(char *)"SELECT name AS TABLE_NAME FROM system.tables WHERE 1=0";
			//fprintf(stderr,"%s\n",q);
			query=l_strdup(q);
			query_length=strlen(query)+1;
            goto __run_query;
		}
	}


	if (query_no_space_length==strlen("SELECT DATABASE()") && !strncasecmp("SELECT DATABASE()",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT 'main' AS DATABASE");
		query_length=strlen(query)+1;
		goto __run_query;
	}

	// see issue #1022
	if (query_no_space_length==strlen("SELECT DATABASE() AS name") && !strncasecmp("SELECT DATABASE() AS name",query_no_space, query_no_space_length)) {
		l_free(query_length,query);
		query=l_strdup("SELECT 'main' AS \"DATABASE()\"");
		query_length=strlen(query)+1;
		goto __run_query;
	}

/*
	if (sess->session_type == PROXYSQL_SESSION_SQLITE) { // no admin
		if (
			(strncasecmp("PRAGMA",query_no_space,6)==0)
			||
			(strncasecmp("ATTACH",query_no_space,6)==0)
		) {
			proxy_error("[WARNING]: Commands executed from stats interface in Admin Module: \"%s\"\n", query_no_space);
			GloClickHouseServer->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Command not allowed");
			run_query=false;
			goto __run_query;
		}
	}
*/
	if (sess->session_type == PROXYSQL_SESSION_CLICKHOUSE) { // no admin
/*
		if (
			(strncasecmp("SHOW SESSION VARIABLES",query_no_space,22)==0)
			||
			(strncasecmp("SHOW VARIABLES",query_no_space,14)==0)
		) {
			l_free(query_length,query);
			char *q=(char *)malloc(query_length+256);
			sprintf(q,"SELECT variable_name Variable_name, Variable_value Value FROM global_variables");
			//fprintf(stderr,"%s\n",q);
			query=l_strdup(q);
			query_length=strlen(query)+1;
			free(q);
            run_query_sqlite = true;
            goto __run_query_sqlite;
		}
*/
		if (
			(strncasecmp("SET NAMES",query_no_space,9)==0)
			||
			(strncasecmp("SET FOREIGN_KEY_CHECKS",query_no_space,22)==0)
			||
			(strncasecmp("SET AUTOCOMMIT",query_no_space,14)==0)
			||
			(strncasecmp("SET SESSION TRANSACTION ISOLATION LEVEL",query_no_space,39)==0)
		) {
			GloClickHouseServer->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			run_query=false;
			goto __run_query;
		}
		if (
			(strncasecmp("SHOW MASTER STATUS",query_no_space,18)==0)
			||
			(strncasecmp("SHOW SLAVE STATUS",query_no_space,17)==0)
			||
			(strncasecmp("SHOW MASTER LOGS",query_no_space,16)==0)
		) {
			GloClickHouseServer->send_MySQL_ERR(&sess->client_myds->myprot, (char *)"Access Denied");
			run_query=false;
			goto __run_query;
		}
		if (
			(strncasecmp("LOCK TABLE",query_no_space,10)==0)
			||
			(strncasecmp("UNLOCK TABLE",query_no_space,12)==0)
		) {
			GloClickHouseServer->send_MySQL_OK(&sess->client_myds->myprot, NULL);
			run_query=false;
			goto __run_query;
		}
	}
	
__run_query:
	if (run_query) {
		ClickHouse_Session *clickhouse_sess = (ClickHouse_Session *)sess->thread->gen_args;
		bool supported_command = false;
		bool expected_resultset = true;
		if (supported_command == false && strncasecmp("SELECT ",query_no_space,7) == 0) {
			supported_command = true;
			expected_resultset = true;
		}

		if (supported_command == false && strncasecmp("INSERT ",query_no_space,7) == 0) {
			if (strcasestr(query_no_space,"VALUES")==NULL) {
				if (strcasestr(query_no_space,"SELECT")) {
					supported_command = true;
					expected_resultset = false;
				}
			}
		}

		if (supported_command == false && strncasecmp("SET ",query_no_space,4) == 0) {
			supported_command = true;
			expected_resultset = false;
		}
		if (supported_command == false && strncasecmp("USE ",query_no_space,4) == 0) {
			supported_command = true;
			expected_resultset = false;
		}
		if (supported_command == false) {
			if (
				(strncasecmp("CREATE ",query_no_space,7) == 0)
				|| (strncasecmp("ALTER ",query_no_space,6) == 0)
				|| (strncasecmp("DROP ",query_no_space,5) == 0)
				|| (strncasecmp("RENAME ",query_no_space,7) == 0)
			) {
				supported_command = true;
				expected_resultset = false;
			}
		}
		if (supported_command == false) {
			if (
				(strncasecmp("SHOW ",query_no_space,5) == 0)
				|| (strncasecmp("DESC ",query_no_space,5) == 0)
				|| (strncasecmp("DESCRIBE ",query_no_space,9) == 0)
			) {
				supported_command = true;
				expected_resultset = true;
			}
		}

		if (supported_command == false) {
  			MySQL_Protocol *myprot=NULL;
  			myprot=&sess->client_myds->myprot;
			assert(myprot);
			MySQL_Data_Stream *myds=myprot->get_myds();
			myds->DSS=STATE_QUERY_SENT_DS;
			myprot->generate_pkt_ERR(true,NULL,NULL,1,1148,(char *)"42000",(char *)"Command not supported");
			myds->DSS=STATE_SLEEP;
		} else {
		
			try {
				clickhouse_thread___mysql_sess = sess;
				if (clickhouse_sess->connected == true) {
					if (clickhouse_sess->schema_initialized == false) {
						if (sess && sess->client_myds) {
							MySQL_Data_Stream *ds = sess->client_myds;
							if (ds->myconn && ds->myconn->userinfo && ds->myconn->userinfo->schemaname) {
								char *sn = ds->myconn->userinfo->schemaname;
								char *use_query = NULL;
								use_query = (char *)malloc(strlen(sn)+8);
								sprintf(use_query,"USE %s", sn);
								clickhouse::Query myq(use_query);
								clickhouse_sess->client->Execute(myq);
								free(use_query);
							}
						}
						clickhouse_sess->schema_initialized = true;
					}

					if (expected_resultset) {
						clickhouse_sess->client->Select(query, [](const Block& block) { ClickHouse_to_MySQL(block); } );

  						MySQL_Protocol *myprot=NULL;
	  					myprot=&sess->client_myds->myprot; assert(myprot);
  						MySQL_Data_Stream *myds=myprot->get_myds();

						if (clickhouse_sess->transfer_started) {
							myds->DSS=STATE_ROW;
							bool deprecate_eof_active = sess->client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
							if (deprecate_eof_active) {
								myprot->generate_pkt_OK(true, NULL, NULL, clickhouse_sess->sid, 0, 0, 2, 0, NULL, true);
								clickhouse_sess->sid++;
							} else {
								myprot->generate_pkt_EOF(true, NULL, NULL, clickhouse_sess->sid, 0, 2);
								clickhouse_sess->sid++;
							}
						} else {
							myprot->generate_pkt_OK(true,NULL,NULL,1,0,0,2,0,(char *)"");
						}
	  					myds->DSS=STATE_SLEEP;
						clickhouse_sess->transfer_started=false;
					} else {
						clickhouse::Query myq(query);
						clickhouse_sess->client->Execute(myq);
  						MySQL_Protocol *myprot=NULL;
	  					myprot=&sess->client_myds->myprot; assert(myprot);
  						MySQL_Data_Stream *myds=myprot->get_myds();
						myds->DSS=STATE_QUERY_SENT_DS;
						myprot->generate_pkt_OK(true,NULL,NULL,1,0,0,2,0,(char *)"");
  						myds->DSS=STATE_SLEEP;
						clickhouse_sess->transfer_started=false;
					}
				} else {
  					MySQL_Protocol *myprot=NULL;
	  				myprot=&sess->client_myds->myprot; assert(myprot);
  					MySQL_Data_Stream *myds=myprot->get_myds();
					myds->DSS=STATE_QUERY_SENT_DS;
					myprot->generate_pkt_ERR(true,NULL,NULL,1,1148,(char *)"42000",(char *)"Backend not connected");
					myds->DSS=STATE_SLEEP;
				}
			} catch (const std::exception& e) {
  				MySQL_Protocol *myprot=NULL;
  				myprot=&sess->client_myds->myprot;
				assert(myprot);
				MySQL_Data_Stream *myds=myprot->get_myds();
				myds->DSS=STATE_QUERY_SENT_DS;
				std::stringstream buffer;
				buffer << e.what();
    			myprot->generate_pkt_ERR(true,NULL,NULL,1,1148,(char *)"42000",(char *)buffer.str().c_str());
				myds->DSS=STATE_SLEEP;
				std::cerr << "Exception in query for ClickHouse: " << e.what() << std::endl;
				sess->set_unhealthy();
			}
		}
		l_free(pkt->size-sizeof(mysql_hdr),query_no_space); // it is always freed here
		l_free(query_length,query);
	}
	return;

__run_query_sqlite: // we are introducing this new section to send some query to internal sqlite to simplify the execution of dummy queries

	if (run_query_sqlite) {
		ClickHouse_Session *sqlite_sess = (ClickHouse_Session *)sess->thread->gen_args;
		sqlite_sess->sessdb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
		bool deprecate_eof_active = sess->client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
		sess->SQLite3_to_MySQL(resultset, error, affected_rows, &sess->client_myds->myprot, false, deprecate_eof_active);
		delete resultset;
		l_free(pkt->size-sizeof(mysql_hdr),query_no_space); // it is always freed here
		l_free(query_length,query);
	}
}


ClickHouse_Session::ClickHouse_Session() {
	sessdb = new SQLite3DB();
    sessdb->open((char *)"file:mem_sqlitedb_clickhouse?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);	
	transfer_started = false;
	schema_initialized = false;
}

bool ClickHouse_Session::init() {
	bool ret=false;
	char *hostname = NULL;
	char *port = NULL;
	hostname = GloClickHouseServer->get_variable((char *)"hostname");
	port = GloClickHouseServer->get_variable((char *)"port");
	try {
		co.SetHost(hostname);
		co.SetPort(atoi(port));
		co.SetCompressionMethod(CompressionMethod::None);
		client = NULL;
		client = new clickhouse::Client(co);
		ret=true;
	} catch (const std::exception& e) {
		std::cerr << "Connection to ClickHouse failed: " << e.what() << std::endl;	
		ret=false;
	}
	connected = ret;
	if (hostname) {
		free(hostname);
	}
	if (port) {
		free(port);
	}
	return ret;
}

ClickHouse_Session::~ClickHouse_Session() {
	delete sessdb;
	sessdb = NULL;
	delete client;
	client = NULL;
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

	MySQL_Session *sess = NULL;
	MySQL_Data_Stream *myds = NULL;

	ClickHouse_Session *sqlite_sess = new ClickHouse_Session();
	sqlite_sess->init();
	mysql_thr->gen_args = (void *)sqlite_sess;

	GloQPro->init_thread();
	mysql_thr->refresh_variables();
	sess=mysql_thr->create_new_session_and_client_data_stream(client);
	sess->thread=mysql_thr;
	sess->session_type = PROXYSQL_SESSION_CLICKHOUSE;
	sess->handler_function=ClickHouse_Server_session_handler;
	myds=sess->client_myds;

	fds[0].fd=client;
	fds[0].revents=0;
	fds[0].events=POLLIN|POLLOUT;
	free(arg);
	sess->client_myds->myprot.generate_pkt_initial_handshake(true,NULL,NULL, &sess->thread_session_id, true);

	while (__sync_fetch_and_add(&glovars.shutdown,0)==0) {
		if (myds->available_data_out()) {
			fds[0].events=POLLIN|POLLOUT;
		} else {
			fds[0].events=POLLIN;
		}
		fds[0].revents=0;
		rc=poll(fds,nfds,__sync_fetch_and_add(&__ClickHouse_Server_refresh_interval,0));
		if (rc == -1) {
			if (errno == EINTR) {
				continue;
			} else {
				goto __exit_child_mysql;
			}
		}
		myds->revents=fds[0].revents;
		int rb = 0;
		rb - myds->read_from_net();
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
	int rc;
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
			for (i=1; i<nfds; i++) {
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
#define PROXYSQL_CLICKHOUSE_SERVER_VERSION "0.1.0702" DEB

ClickHouse_Server::~ClickHouse_Server() {
	delete SQLite_General_DB;
	SQLite_General_DB = NULL;
};

ClickHouse_Server::ClickHouse_Server() {
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

	SQLite_General_DB = new SQLite3DB();
    SQLite_General_DB->open((char *)"file:mem_sqlitedb_clickhouse?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);	
	SQLite_General_DB->execute((char *)"CREATE TABLE global_variables (variable_name VARCHAR NOT NULL PRIMARY KEY , variable_value VARCHAR NOT NULL)");
	SQLite_General_DB->execute((char *)"INSERT INTO global_variables VALUES ('lower_case_table_names','0')");
	SQLite_General_DB->execute((char *)"INSERT INTO global_variables VALUES ('sql_mode','')");
	SQLite_General_DB->execute((char *)"INSERT INTO global_variables VALUES ('version','5.5.30-clickhouse')");
	SQLite_General_DB->execute((char *)"INSERT INTO global_variables VALUES ('version_comment','(ProxySQL ClickHouse Module)')");
	SQLite_General_DB->execute((char *)"INSERT INTO global_variables VALUES ('wait_timeout','3600')");
	SQLite_General_DB->execute((char *)"INSERT INTO global_variables VALUES ('interactive_wait_timeout','3600')");

	SQLite_General_DB->execute((char *)"CREATE TABLE mysql_collations (Id INTEGER NOT NULL PRIMARY KEY , Collation VARCHAR NOT NULL , Charset VARCHAR NOT NULL , `Default` VARCHAR NOT NULL)");
	dump_mysql_collations();
	SQLite_General_DB->execute((char *)"CREATE TABLE show_engines (Engine VARCHAR , Support VARCHAR , Comment VARCHAR , Transactions VARCHAR , XA VARCHAR , Savepoints)");
	SQLite_General_DB->execute((char *)"INSERT INTO show_engines VALUES ('ClickHouse','DEFAULT','ProxySQL frontend to ClickHouse','YES','NO','NO')");


	variables.mysql_ifaces=strdup("0.0.0.0:6090");
	variables.hostname = strdup("127.0.0.1");
	variables.port = 9000;
	variables.read_only=false;
};

void ClickHouse_Server::wrlock() {
	pthread_rwlock_wrlock(&rwlock);
};

void ClickHouse_Server::wrunlock() {
	pthread_rwlock_unlock(&rwlock);
};


void ClickHouse_Server::print_version() {
  fprintf(stderr,"Standard ProxySQL ClickHouse Server rev. %s -- %s -- %s\n", PROXYSQL_CLICKHOUSE_SERVER_VERSION, __FILE__, __TIMESTAMP__);
};

bool ClickHouse_Server::init() {
//	cpu_timer cpt;

	child_func[0]=child_mysql;
	main_shutdown=0;
	main_poll_nfds=0;
	main_poll_fds=NULL;
	main_callback_func=NULL;

	main_callback_func=(int *)malloc(sizeof(int)*MAX_SQLITE3SERVER_LISTENERS);
	main_poll_fds=(struct pollfd *)malloc(sizeof(struct pollfd)*MAX_SQLITE3SERVER_LISTENERS);
	main_poll_nfds=0;

	S_amll.update_ifaces(variables.mysql_ifaces, &S_amll.ifaces_mysql);



	pthread_t ClickHouse_Server_thr;
	struct _main_args *arg=(struct _main_args *)malloc(sizeof(struct _main_args));
	arg->nfds=main_poll_nfds;
	arg->fds=main_poll_fds;
	arg->shutdown=&main_shutdown;
	arg->callback_func=main_callback_func;
	if (pthread_create(&ClickHouse_Server_thr, NULL, sqlite3server_main_loop, (void *)arg) !=0 ) {
		perror("Thread creation");
		exit(EXIT_FAILURE);
	}
/*
#ifdef DEBUG
	std::cerr << "SQLite3 Server initialized in ";
#endif
*/
	return true;
};

// This function is used only used to export what collations are available
// it is mostly informative

void ClickHouse_Server::dump_mysql_collations() {
	const MARIADB_CHARSET_INFO * c = mariadb_compiled_charsets;
	char buf[1024];
	char *query=(char *)"INSERT INTO mysql_collations VALUES (%d, \"%s\", \"%s\", \"\")";
	SQLite_General_DB->execute("DELETE FROM mysql_collations");
	do {
		sprintf(buf,query,c->nr, c->name, c->csname);
		SQLite_General_DB->execute(buf);
		++c;
	} while (c[0].nr != 0);
	SQLite_General_DB->execute("INSERT OR REPLACE INTO mysql_collations SELECT Id, Collation, Charset, 'Yes' FROM mysql_collations JOIN (SELECT MIN(Id) minid FROM mysql_collations GROUP BY Charset) t ON t.minid=mysql_collations.Id");
}

char **ClickHouse_Server::get_variables_list() {
	size_t l=sizeof(ClickHouse_Server_variables_names)/sizeof(char *);
	unsigned int i;
	char **ret=(char **)malloc(sizeof(char *)*l);
	for (i=0;i<l;i++) {
		ret[i]=(i==l-1 ? NULL : strdup(ClickHouse_Server_variables_names[i]));
	}
	return ret;
}


// Returns true if the given name is the name of an existing clickhouse variable
bool ClickHouse_Server::has_variable(const char *name) {
	size_t no_vars = sizeof(ClickHouse_Server_variables_names) / sizeof(char *);
	for (unsigned int i = 0; i < no_vars-1 ; ++i) {
		size_t var_len = strlen(ClickHouse_Server_variables_names[i]);
		if (strlen(name) == var_len && !strncmp(name, ClickHouse_Server_variables_names[i], var_len)) {
			return true;
		}
	}
	return false;
}

char * ClickHouse_Server::get_variable(char *name) {
#define INTBUFSIZE  4096
	char intbuf[INTBUFSIZE];
	if (!strcasecmp(name,"hostname")) return s_strdup(variables.hostname);
	if (!strcasecmp(name,"mysql_ifaces")) return s_strdup(variables.mysql_ifaces);
	if (!strcasecmp(name,"port")) {
		sprintf(intbuf,"%d",variables.port);
		return strdup(intbuf);
	}
	if (!strcasecmp(name,"read_only")) {
		return strdup((variables.read_only ? "true" : "false"));
	}
	return NULL;
}

bool ClickHouse_Server::set_variable(char *name, char *value) {  // this is the public function, accessible from admin
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
	if (!strcasecmp(name,"hostname")) {
		if (vallen) {
			free(variables.hostname);
			variables.hostname=strdup(value);
			return true;
		} else {
			return true;
		}
	}
	if (!strcasecmp(name,"port")) {
		int intv=atoi(value);
		if (intv > 0 && intv < 65536) {
			variables.port=intv;
			return true;
		} else {
			return false;
		}
	}

	return false;
}


void ClickHouse_Server::send_MySQL_OK(MySQL_Protocol *myprot, char *msg, int rows) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	myprot->generate_pkt_OK(true,NULL,NULL,1,rows,0,2,0,msg);
	myds->DSS=STATE_SLEEP;
}

void ClickHouse_Server::send_MySQL_ERR(MySQL_Protocol *myprot, char *msg) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	myprot->generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"28000",msg);
	myds->DSS=STATE_SLEEP;
}

#endif /* PROXYSQLCLICKHOUSE */
