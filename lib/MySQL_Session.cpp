#include "MySQL_HostGroups_Manager.h"
#include "MySQL_Thread.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_utils.h"
#include "re2/re2.h"
#include "re2/regexp.h"
#include "mysqld_error.h"

#include "MySQL_Data_Stream.h"
#include "query_processor.h"
#include "MySQL_PreparedStatement.h"
#include "MySQL_Logger.hpp"
#include "StatCounters.h"
#include "MySQL_Authentication.hpp"
#include "MySQL_LDAP_Authentication.hpp"
#include "MySQL_Protocol.h"
#include "SQLite3_Server.h"
#include "MySQL_Variables.h"
#include "ProxySQL_Cluster.hpp"


#include "libinjection.h"
#include "libinjection_sqli.h"

#define SELECT_VERSION_COMMENT "select @@version_comment limit 1"
#define SELECT_VERSION_COMMENT_LEN 32
#define SELECT_DB_USER "select DATABASE(), USER() limit 1"
#define SELECT_DB_USER_LEN 33
#define SELECT_CHARSET_STATUS "select @@character_set_client, @@character_set_connection, @@character_set_server, @@character_set_database limit 1"
#define SELECT_CHARSET_STATUS_LEN 115
#define PROXYSQL_VERSION_COMMENT "\x01\x00\x00\x01\x01\x27\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x11\x40\x40\x76\x65\x72\x73\x69\x6f\x6e\x5f\x63\x6f\x6d\x6d\x65\x6e\x74\x00\x0c\x21\x00\x18\x00\x00\x00\xfd\x00\x00\x1f\x00\x00\x05\x00\x00\x03\xfe\x00\x00\x02\x00\x0b\x00\x00\x04\x0a(ProxySQL)\x05\x00\x00\x05\xfe\x00\x00\x02\x00"
#define PROXYSQL_VERSION_COMMENT_LEN 81

// PROXYSQL_VERSION_COMMENT_WITH_OK is sent instead of PROXYSQL_VERSION_COMMENT
// if Client supports CLIENT_DEPRECATE_EOF
#define PROXYSQL_VERSION_COMMENT_WITH_OK "\x01\x00\x00\x01\x01" \
"\x27\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x11\x40\x40\x76\x65\x72\x73\x69\x6f\x6e\x5f\x63\x6f\x6d\x6d\x65\x6e\x74\x00\x0c\x21\x00\x18\x00\x00\x00\xfd\x00\x00\x1f\x00\x00" \
"\x0b\x00\x00\x03\x0a(ProxySQL)" \
"\x07\x00\x00\x04\xfe\x00\x00\x02\x00\x00\x00"
#define PROXYSQL_VERSION_COMMENT_WITH_OK_LEN 74

#define SELECT_CONNECTION_ID "SELECT CONNECTION_ID()"
#define SELECT_CONNECTION_ID_LEN 22
#define SELECT_LAST_INSERT_ID "SELECT LAST_INSERT_ID()"
#define SELECT_LAST_INSERT_ID_LEN 23
#define SELECT_LAST_INSERT_ID_FROM_DUAL "SELECT LAST_INSERT_ID() FROM DUAL"
#define SELECT_LAST_INSERT_ID_FROM_DUAL_LEN 33
#define SELECT_LAST_INSERT_ID_LIMIT1 "SELECT LAST_INSERT_ID() LIMIT 1"
#define SELECT_LAST_INSERT_ID_LIMIT1_LEN 31
#define SELECT_VARIABLE_IDENTITY "SELECT @@IDENTITY"
#define SELECT_VARIABLE_IDENTITY_LEN 17
#define SELECT_VARIABLE_IDENTITY_LIMIT1 "SELECT @@IDENTITY LIMIT 1"
#define SELECT_VARIABLE_IDENTITY_LIMIT1_LEN 25

#define EXPMARIA

using std::function;
using std::vector;

static inline char is_digit(char c) {
	if(c >= '0' && c <= '9')
		return 1;
	return 0;
}
static inline char is_normal_char(char c) {
	if(c >= 'a' && c <= 'z')
		return 1;
	if(c >= 'A' && c <= 'Z')
		return 1;
	if(c >= '0' && c <= '9')
		return 1;
	if(c == '$' || c == '_')
		return 1;
	return 0;
}

static const std::set<std::string> mysql_variables_boolean = {
	"aurora_read_replica_read_committed",
	"foreign_key_checks",
	"innodb_strict_mode",
	"innodb_table_locks",
	"sql_auto_is_null",
	"sql_big_selects",
	"sql_generate_invisible_primary_key",
	"sql_log_bin",
	"sql_quote_show_create",
	"sql_require_primary_key",
	"sql_safe_updates",
	"unique_checks",
};

static const std::set<std::string> mysql_variables_numeric = {
	"auto_increment_increment",
	"auto_increment_offset",
	"group_concat_max_len",
	"innodb_lock_wait_timeout",
	"join_buffer_size",
	"lock_wait_timeout",
	"long_query_time",
	"max_execution_time",
	"max_heap_table_size",
	"max_join_size",
	"max_sort_length",
	"max_statement_time",
	"optimizer_prune_level",
	"optimizer_search_depth",
	"optimizer_use_condition_selectivity",
	"query_cache_type",
	"sort_buffer_size",
	"sql_select_limit",
	"timestamp",
	"tmp_table_size",
	"wsrep_sync_wait"
};
static const std::set<std::string> mysql_variables_strings = {
	"default_storage_engine",
	"default_tmp_storage_engine",
	"group_replication_consistency",
	"lc_messages",
	"lc_time_names",
	"log_slow_filter",
	"optimizer_switch",
	"wsrep_osu_method",
};

#include "proxysql_find_charset.h"

extern MySQL_Authentication *GloMyAuth;
extern MySQL_LDAP_Authentication *GloMyLdapAuth;
extern ProxySQL_Admin *GloAdmin;
extern MySQL_Logger *GloMyLogger;
extern MySQL_STMT_Manager_v14 *GloMyStmt;

extern SQLite3_Server *GloSQLite3Server;

#ifdef PROXYSQLCLICKHOUSE
extern ClickHouse_Authentication *GloClickHouseAuth;
extern ClickHouse_Server *GloClickHouseServer;
#endif /* PROXYSQLCLICKHOUSE */


/**
 * @brief Converts session type to a human-readable string.
 * @param session_type The session type to convert.
 * @return A string representing the session type.
 */
std::string proxysql_session_type_str(enum proxysql_session_type session_type) {
	if (session_type == PROXYSQL_SESSION_MYSQL) {
		return "PROXYSQL_SESSION_MYSQL";
	} else if (session_type == PROXYSQL_SESSION_ADMIN) {
		return "PROXYSQL_SESSION_ADMIN";
	} else if (session_type == PROXYSQL_SESSION_STATS) {
		return "PROXYSQL_SESSION_STATS";
	} else if (session_type == PROXYSQL_SESSION_SQLITE) {
		return "PROXYSQL_SESSION_SQLITE";
	} else if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
		return "PROXYSQL_SESSION_CLICKHOUSE";
	} else if (session_type == PROXYSQL_SESSION_MYSQL_EMU) {
		return "PROXYSQL_SESSION_MYSQL_EMU";
	} else {
		return "PROXYSQL_SESSION_NONE";
	}
};

/**
 * @brief Constructs a Session_Regex object with the specified pattern.
 * 
 * This constructor initializes a Session_Regex object with the provided pattern.
 * It sets up the regular expression engine with case insensitivity.
 * 
 * @param[in] p The regular expression pattern.
 */
Session_Regex::Session_Regex(char *p) {
	s=strdup(p);
	re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
	opt2->set_case_sensitive(false);
	opt=(void *)opt2;
	re=(RE2 *)new RE2(s, *opt2);
}


/**
 * @brief Destroys the Session_Regex object.
 * 
 * This destructor releases the memory allocated for the regular expression pattern,
 * the regular expression object, and its associated options.
 */
Session_Regex::~Session_Regex() {
	free(s);
	delete (RE2 *)re;
	delete (re2::RE2::Options *)opt;
}

/**
 * @brief Matches the given input against the regular expression pattern.
 * 
 * This function attempts to match the input string against the regular expression pattern.
 * 
 * @param[in] m The input string to match.
 * @return true if the input matches the pattern, false otherwise.
 */
bool Session_Regex::match(char *m) {
	bool rc=false;
	rc=RE2::PartialMatch(m,*(RE2 *)re);
	return rc;
}

KillArgs::KillArgs(char* u, char* p, char* h, unsigned int P, unsigned int _hid, unsigned long i, int kt, int _use_ssl, MySQL_Thread* _mt) :
	KillArgs(u, p, h, P, _hid, i, kt, _use_ssl, _mt, NULL) {
	// resolving DNS if available in Cache
	resolve_hostname();
}

KillArgs::KillArgs(char* u, char* p, char* h, unsigned int P, unsigned int _hid, unsigned long i, int kt, int _use_ssl, MySQL_Thread *_mt, char *ip) {
	username=strdup(u);
	password=strdup(p);
	hostname=strdup(h);
	ip_addr = NULL;
	if (ip)
		ip_addr = strdup(ip);
	port=P;
	hid=_hid;
	id=i;
	kill_type=kt;
	use_ssl=_use_ssl;
	mt=_mt;
}

KillArgs::~KillArgs() {
	free(username);
	free(password);
	free(hostname);
	if (ip_addr)
		free(ip_addr);
}

const char* KillArgs::get_host_address() const {
	const char* host_address = hostname;

	if (ip_addr)
		host_address = ip_addr;

	return host_address;
}

void KillArgs::resolve_hostname() {
	if (ip_addr) {
		free(ip_addr);
		ip_addr = NULL;
	}
	if (hostname && port) {
		const std::string& ip = MySQL_Monitor::dns_lookup(hostname, false);

		if (ip.empty() == false) {
			ip_addr = strdup(ip.c_str());
		}
	}
}

void KillArgs::remove_dns_record() {
	if (hostname && port) {
		MySQL_Monitor::remove_dns_record_from_dns_cache(hostname);
	}
}

/**
 * @brief Thread function to kill a query or connection on a MySQL server.
 * 
 * This function is executed in a separate thread to kill a query or connection on a MySQL server.
 * It establishes a connection to the MySQL server and sends a kill command to terminate the specified query or connection.
 * 
 * @param[in] arg A pointer to a KillArgs structure containing the necessary parameters for killing the query or connection.
 * @return nullptr.
 */
void* kill_query_thread(void *arg) {
	KillArgs *ka=(KillArgs *)arg;
	//! It initializes a new MySQL_Thread object to handle MySQL-related operations.
	std::unique_ptr<MySQL_Thread> mysql_thr(new MySQL_Thread());
	set_thread_name("KillQuery");
	//! Retrieves the current time and refreshes thread variables.
	mysql_thr->curtime=monotonic_time();
	mysql_thr->refresh_variables();

	//! Initializes ssl_params to NULL, which holds SSL parameters for the MySQL connection.
	MySQLServers_SslParams * ssl_params = NULL;

	//! Initializes a new MySQL connection using mysql_init(NULL).
	MYSQL *mysql=mysql_init(NULL);
	if (!mysql) {
		goto __exit_kill_query_thread;
	}

	//! Sets specific connection attributes such as program_name and _server_host using mysql_options4().
	mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "program_name", "proxysql_killer");
	mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "_server_host", ka->hostname);


	//! If SSL is enabled and port information is available, it retrieves SSL parameters for the server from MyHGM and configures the MySQL connection accordingly.
	if (ka->use_ssl && ka->port) {
		ssl_params = MyHGM->get_Server_SSL_Params(ka->hostname, ka->port, ka->username);
		MySQL_Connection::set_ssl_params(mysql,ssl_params);
		mysql_options(mysql, MARIADB_OPT_SSL_KEYLOG_CALLBACK, (void*)proxysql_keylog_write_line_callback);
	}

	MYSQL *ret;

	//! Depending on the type of operation (kill_type), constructs a KILL command string (buf) to terminate the specified query or connection.
	if (ka->port) {
		switch (ka->kill_type) {
			case KILL_QUERY:
				proxy_warning("KILL QUERY %lu on %s:%d\n", ka->id, ka->hostname, ka->port);
				if (ka->mt) {
					ka->mt->status_variables.stvar[st_var_killed_queries]++;
				}
				break;
			case KILL_CONNECTION:
				proxy_warning("KILL CONNECTION %lu on %s:%d\n", ka->id, ka->hostname, ka->port);
				if (ka->mt) {
					ka->mt->status_variables.stvar[st_var_killed_connections]++;
				}
				break;
			default:
				break;
		}
		ret=mysql_real_connect(mysql, ka->get_host_address(), ka->username, ka->password, NULL, ka->port, NULL, 0);
	} else {
		switch (ka->kill_type) {
			case KILL_QUERY:
				proxy_warning("KILL QUERY %lu on localhost\n", ka->id);
				break;
			case KILL_CONNECTION:
				proxy_warning("KILL CONNECTION %lu on localhost\n", ka->id);
				break;
			default:
				break;
		}
		ret=mysql_real_connect(mysql,"localhost",ka->username,ka->password,NULL,0,ka->hostname,0);
	}
	if (!ret) {
		ka->remove_dns_record();
		//ka->resolve_hostname();
		int myerr = mysql_errno(mysql);
		if (ssl_params != NULL && myerr == 2026) {
			proxy_error("Failed to connect to server %s:%d to run KILL %s %lu.  SSL Params: %s , %s , %s , %s , %s , %s , %s , %s\n",
				ka->hostname, ka->port, ( ka->kill_type==KILL_QUERY ? "QUERY" : "CONNECTION" ) , ka->id,
				ssl_params->ssl_ca.c_str() , ssl_params->ssl_cert.c_str() , ssl_params->ssl_key.c_str() , ssl_params->ssl_capath.c_str() ,
				ssl_params->ssl_crl.c_str() , ssl_params->ssl_crlpath.c_str() , ssl_params->ssl_cipher.c_str() , ssl_params->tls_version.c_str()
			);
		} else {
			proxy_error("Failed to connect to server %s:%d to run KILL %s %lu: Error: %s\n" , ka->hostname, ka->port, ( ka->kill_type==KILL_QUERY ? "QUERY" : "CONNECTION" ) , ka->id, mysql_error(mysql));
		}
		MyHGM->p_update_mysql_error_counter(p_mysql_error_type::mysql, ka->hid, ka->hostname, ka->port, mysql_errno(mysql));
		goto __exit_kill_query_thread;
	}

	MySQL_Monitor::update_dns_cache_from_mysql_conn(mysql);

	char buf[100];
	switch (ka->kill_type) {
		case KILL_QUERY:
			sprintf(buf,"KILL QUERY %lu", ka->id);
			break;
		case KILL_CONNECTION:
			sprintf(buf,"KILL CONNECTION %lu", ka->id);
			break;
		default:
			sprintf(buf,"KILL %lu", ka->id);
			break;
	}
	//! Executes the KILL command using mysql_query() on the established MySQL connection. Note that this call is blocking.
	// FIXME: these 2 calls are blocking, fortunately on their own thread
	mysql_query(mysql,buf);
__exit_kill_query_thread:
	//! clean-up
	if (mysql)
		mysql_close(mysql);
	delete ka;
	if (ssl_params != NULL) {
		delete ssl_params;
		ssl_params = NULL;
	}
	// De-initializes per-thread structures. Required in all auxiliary threads using MySQL and SSL.
	mysql_thread_end();
	return NULL;
}

extern Query_Processor *GloQPro;
extern Query_Cache *GloQC;
extern ProxySQL_Admin *GloAdmin;
extern MySQL_Threads_Handler *GloMTH;


/**
 * @brief Default constructor.
 * Initializes all member variables to their default values.
 */
Query_Info::Query_Info() {
	MyComQueryCmd=MYSQL_COM_QUERY___NONE;
	QueryPointer=NULL;
	QueryLength=0;
	QueryParserArgs.digest_text=NULL;
	QueryParserArgs.first_comment=NULL;
	stmt_info=NULL;
	bool_is_select_NOT_for_update=false;
	bool_is_select_NOT_for_update_computed=false;
	have_affected_rows=false; // if affected rows is set, last_insert_id is set too
	waiting_since = 0;
	affected_rows=0;
	last_insert_id = 0;
	rows_sent=0;
	start_time=0;
	end_time=0;
	stmt_client_id=0;
}

/**
 * @brief Destructor.
 * Frees resources associated with QueryParserArgs and stmt_info.
 */
Query_Info::~Query_Info() {
	GloQPro->query_parser_free(&QueryParserArgs);
	if (stmt_info) {
		stmt_info=NULL;
	}
}

/**
 * @brief Initializes query information.
 * @param _p Pointer to the query data.
 * @param len Length of the query data.
 * @param mysql_header Flag indicating whether MySQL header is present.
 */
void Query_Info::begin(unsigned char *_p, int len, bool mysql_header) {
	MyComQueryCmd=MYSQL_COM_QUERY___NONE;
	QueryPointer=NULL;
	QueryLength=0;
	mysql_stmt=NULL;
	stmt_meta=NULL;
	QueryParserArgs.digest_text=NULL;
	QueryParserArgs.first_comment=NULL;
	start_time=sess->thread->curtime;
	init(_p, len, mysql_header);
	if (mysql_thread___commands_stats || mysql_thread___query_digests) {
		query_parser_init();
		if (mysql_thread___commands_stats)
			query_parser_command_type();
	}
	bool_is_select_NOT_for_update=false;
	bool_is_select_NOT_for_update_computed=false;
	have_affected_rows=false; // if affected rows is set, last_insert_id is set too
	waiting_since = 0;
	affected_rows=0;
	last_insert_id = 0;
	rows_sent=0;
	sess->gtid_hid=-1;
	stmt_client_id=0;
}


/**
 * @brief Finalizes query information.
 * Updates query counters and performs clean-up.
 */
void Query_Info::end() {
	query_parser_update_counters();
	query_parser_free();
	if ((end_time-start_time) > (unsigned int)mysql_thread___long_query_time*1000) {
		__sync_add_and_fetch(&sess->thread->status_variables.stvar[st_var_queries_slow],1);
	}
	if (sess->with_gtid) {
		__sync_add_and_fetch(&sess->thread->status_variables.stvar[st_var_queries_gtid],1);
	}
	assert(mysql_stmt==NULL);
	if (stmt_info) {
		stmt_info=NULL;
	}
	if (stmt_meta) { // fix bug #796: memory is not freed in case of error during STMT_EXECUTE
		if (stmt_meta->pkt) {
			uint32_t stmt_global_id=0;
			memcpy(&stmt_global_id,(char *)(stmt_meta->pkt)+5,sizeof(uint32_t));
			sess->SLDH->reset(stmt_global_id);
			free(stmt_meta->pkt);
			stmt_meta->pkt=NULL;
		}
		stmt_meta = NULL;
	}
}

/**
 * @brief Initializes query information with the given parameters.
 * @param _p Pointer to the query data.
 * @param len Length of the query data.
 * @param mysql_header Flag indicating whether MySQL header is present.
 */
void Query_Info::init(unsigned char *_p, int len, bool mysql_header) {
	QueryLength=(mysql_header ? len-5 : len);
	QueryPointer=(mysql_header ? _p+5 : _p);
	MyComQueryCmd = MYSQL_COM_QUERY__UNINITIALIZED;
	bool_is_select_NOT_for_update=false;
	bool_is_select_NOT_for_update_computed=false;
	have_affected_rows=false; // if affected rows is set, last_insert_id is set too
	waiting_since = 0;
	affected_rows=0;
	last_insert_id = 0;
	rows_sent=0;
}

/**
 * @brief Initializes the query parser.
 */
void Query_Info::query_parser_init() {
	GloQPro->query_parser_init(&QueryParserArgs,(char *)QueryPointer,QueryLength,0);
}

/**
 * @brief Retrieves the command type of the query from the query parser.
 * @return The command type of the query.
 */
enum MYSQL_COM_QUERY_command Query_Info::query_parser_command_type() {
	MyComQueryCmd=GloQPro->query_parser_command_type(&QueryParserArgs);
	return MyComQueryCmd;
}

/**
 * @brief Frees resources associated with the query parser.
 */
void Query_Info::query_parser_free() {
	GloQPro->query_parser_free(&QueryParserArgs);
}

/**
 * @brief Updates query counters and resets member variables.
 * @return The number of rows affected by the query.
 */
unsigned long long Query_Info::query_parser_update_counters() {
	if (stmt_info) {
		MyComQueryCmd=stmt_info->MyComQueryCmd;
	}
	if (MyComQueryCmd==MYSQL_COM_QUERY___NONE) return 0; // this means that it was never initialized
	if (MyComQueryCmd == MYSQL_COM_QUERY__UNINITIALIZED) return 0; // this means that it was never initialized
	unsigned long long ret=GloQPro->query_parser_update_counters(sess, MyComQueryCmd, &QueryParserArgs, end_time-start_time);
	MyComQueryCmd=MYSQL_COM_QUERY___NONE;
	QueryPointer=NULL;
	QueryLength=0;
	return ret;
}

/**
 * @brief Retrieves the digest text of the query from the query parser.
 * @return The digest text of the query.
 */
char * Query_Info::get_digest_text() {
	return GloQPro->get_digest_text(&QueryParserArgs);
}

/**
 * @brief Checks if the query is a SELECT statement with the NOT FOR UPDATE clause.
 * @return True if the query is a SELECT statement with the NOT FOR UPDATE clause, false otherwise.
 */
bool Query_Info::is_select_NOT_for_update() {
	if (stmt_info) { // we are processing a prepared statement. We already have the information
		return stmt_info->is_select_NOT_for_update;
	}
	if (QueryPointer==NULL) {
		return false;
	}
	if (bool_is_select_NOT_for_update_computed) {
		return bool_is_select_NOT_for_update;
	}
	bool_is_select_NOT_for_update_computed=true;
	if (QueryLength<7) {
		return false;
	}
	char *QP = (char *)QueryPointer;
	size_t ql = QueryLength;
	// we try to use the digest, if avaiable
	if (QueryParserArgs.digest_text) {
		QP = QueryParserArgs.digest_text;
		ql = strlen(QP);
	}
	if (strncasecmp(QP,(char *)"SELECT ",7)) {
		return false;
	}
	// if we arrive till here, it is a SELECT
	if (ql>=17) {
		char *p=QP;
		p+=ql-11;
		if (strncasecmp(p," FOR UPDATE",11)==0) {
			__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
			return false;
		}
		p=QP;
		p+=ql-10;
		if (strncasecmp(p," FOR SHARE",10)==0) {
			__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
			return false;
		}
		if (ql>=25) {
			char *p=QP;
			p+=ql-19;
			if (strncasecmp(p," LOCK IN SHARE MODE",19)==0) {
				__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
				return false;
			}
			p=QP;
			p+=ql-7;
			if (strncasecmp(p," NOWAIT",7)==0) {
				// let simplify. If NOWAIT is used, we assume FOR UPDATE|SHARE is used
				__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
				return false;
/*
				if (strcasestr(QP," FOR UPDATE ")==NULL) {
					__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
					return false;
				}
				if (strcasestr(QP," FOR SHARE ")==NULL) {
					__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
					return false;
				}
*/
			}
			p=QP;
			p+=ql-12;
			if (strncasecmp(p," SKIP LOCKED",12)==0) {
				// let simplify. If SKIP LOCKED is used, we assume FOR UPDATE|SHARE is used
				__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
				return false;
/*
				if (strcasestr(QP," FOR UPDATE ")) {
					__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
					return false;
				}
				if (strcasestr(QP," FOR SHARE ")) {
					__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
					return false;
				}
*/
			}
			p=QP;
			char buf[129];
			if (ql>=128) { // for long query, just check the last 128 bytes
				p+=ql-128;
				memcpy(buf,p,128);
				buf[128]=0;
			} else {
				memcpy(buf,p,ql);
				buf[ql]=0;
			}
			if (strcasestr(buf," FOR ")) {
				if (strcasestr(buf," FOR UPDATE ")) {
					__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
					return false;
				}
				if (strcasestr(buf," FOR SHARE ")) {
					__sync_fetch_and_add(&MyHGM->status.select_for_update_or_equivalent, 1);
					return false;
				}
			}
		}
	}
	bool_is_select_NOT_for_update=true;
	return true;
}

void * MySQL_Session::operator new(size_t size) {
	return l_alloc(size);
}

void MySQL_Session::operator delete(void *ptr) {
	l_free(sizeof(MySQL_Session),ptr);
}


void MySQL_Session::set_status(enum session_status e) {
	if (e==session_status___NONE) {
		if (mybe) {
			if (mybe->server_myds) {
				assert(mybe->server_myds->myconn==0);
				if (mybe->server_myds->myconn) {
					assert(mybe->server_myds->myconn->async_state_machine==ASYNC_IDLE);
				}
			}
		}
	}
	status=e;
}

/**
 * @brief Constructs a new MySQL session object.
 */
MySQL_Session::MySQL_Session() {
	thread_session_id=0;
	//handler_ret = 0;
	pause_until=0;
	qpo=new Query_Processor_Output();
	start_time=0;
	command_counters=new StatCounters(15,10);
	healthy=1;
	autocommit=true;
	autocommit_handled=false;
	sending_set_autocommit=false;
	autocommit_on_hostgroup=-1;
	killed=false;
	session_type=PROXYSQL_SESSION_MYSQL;
	//admin=false;
	connections_handler=false;
	max_connections_reached=false;
	//stats=false;
	client_authenticated=false;
	default_schema=NULL;
	user_attributes=NULL;
	schema_locked=false;
	session_fast_forward=false;
	started_sending_data_to_client=false;
	handler_function=NULL;
	client_myds=NULL;
	to_process=0;
	mybe=NULL;
	mirror=false;
	mirrorPkt.ptr=NULL;
	mirrorPkt.size=0;
	set_status(session_status___NONE);
	warning_in_hg = -1;

	idle_since = 0;
	transaction_started_at = 0;

	CurrentQuery.sess=this;
	CurrentQuery.mysql_stmt=NULL;
	CurrentQuery.stmt_meta=NULL;
	CurrentQuery.stmt_global_id=0;
	CurrentQuery.stmt_client_id=0;
	CurrentQuery.stmt_info=NULL;

	current_hostgroup=-1;
	default_hostgroup=-1;
	locked_on_hostgroup=-1;
	locked_on_hostgroup_and_all_variables_set=false;
	next_query_flagIN=-1;
	mirror_hostgroup=-1;
	mirror_flagOUT=-1;
	active_transactions=0;

	with_gtid = false;
	use_ssl = false;
	change_user_auth_switch = false;

	//gtid_trxid = 0;
	gtid_hid = -1;
	memset(gtid_buf,0,sizeof(gtid_buf));

	match_regexes=NULL;

	init(); // we moved this out to allow CHANGE_USER

	last_insert_id=0; // #1093

	last_HG_affected_rows = -1; // #1421 : advanced support for LAST_INSERT_ID()
	proxysql_node_address = NULL;
	use_ldap_auth = false;
}

/**
 * @brief Initializes the MySQL session.
 */
void MySQL_Session::init() {
	transaction_persistent_hostgroup=-1;
	transaction_persistent=false;
	mybes= new PtrArray(4);
	sess_STMTs_meta=new MySQL_STMTs_meta();
	SLDH=new StmtLongDataHandler();
}

/**
 * @brief Resets the MySQL session to its initial state.
 */
void MySQL_Session::reset() {
	autocommit=true;
	autocommit_handled=false;
	sending_set_autocommit=false;
	autocommit_on_hostgroup=-1;
	warning_in_hg = -1;
	current_hostgroup=-1;
	default_hostgroup=-1;
	locked_on_hostgroup=-1;
	locked_on_hostgroup_and_all_variables_set=false;
	if (sess_STMTs_meta) {
		delete sess_STMTs_meta;
		sess_STMTs_meta=NULL;
	}
	if (SLDH) {
		delete SLDH;
		SLDH=NULL;
	}
	if (mybes) {
		reset_all_backends();
		delete mybes;
		mybes=NULL;
	}
	mybe=NULL;

	with_gtid = false;

	//gtid_trxid = 0;
	gtid_hid = -1;
	memset(gtid_buf,0,sizeof(gtid_buf));
	if (session_type == PROXYSQL_SESSION_SQLITE) {
		SQLite3_Session *sqlite_sess = (SQLite3_Session *)thread->gen_args;
		if (sqlite_sess && sqlite_sess->sessdb) {
			sqlite3 *db = sqlite_sess->sessdb->get_db();
			if ((*proxy_sqlite3_get_autocommit)(db)==0) {
				sqlite_sess->sessdb->execute((char *)"COMMIT");
			}
		}
	}
	if (client_myds) {
		if (client_myds->myconn) {
			client_myds->myconn->reset();
		}
	}
}

/**
 * @brief Destructor for the MySQL session.
 */
MySQL_Session::~MySQL_Session() {

	reset(); // we moved this out to allow CHANGE_USER

	if (locked_on_hostgroup >= 0) {
		thread->status_variables.stvar[st_var_hostgroup_locked]--;
	}

	if (client_myds) {
		if (client_authenticated) {
			switch (session_type) {
#ifdef PROXYSQLCLICKHOUSE
				case PROXYSQL_SESSION_CLICKHOUSE:
					GloClickHouseAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->username);
					break;
#endif /* PROXYSQLCLICKHOUSE */
				default:
					if (use_ldap_auth == false) {
						GloMyAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->username);
					} else {
						GloMyLdapAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->fe_username);
					}
					break;
			}
		}
		delete client_myds;
	}
	if (default_schema) {
		free(default_schema);
	}
	if (user_attributes) {
		free(user_attributes);
		user_attributes = NULL;
	}
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Shutdown Session %p\n" , this->thread, this, this);
	delete command_counters;
	if (session_type==PROXYSQL_SESSION_MYSQL && connections_handler==false && mirror==false) {
		__sync_fetch_and_sub(&MyHGM->status.client_connections,1);
	}
	assert(qpo);
	delete qpo;
	match_regexes=NULL;
	if (mirror) {
		__sync_sub_and_fetch(&GloMTH->status_variables.mirror_sessions_current,1);
		GloMTH->status_variables.p_gauge_array[p_th_gauge::mirror_concurrency]->Decrement();
	}
	if (proxysql_node_address) {
		delete proxysql_node_address;
		proxysql_node_address = NULL;
	}
}


/**
 * @brief Find a backend associated with the specified hostgroup ID.
 * 
 * @param hostgroup_id The ID of the hostgroup to search for.
 * @return A pointer to the MySQL backend associated with the specified hostgroup ID, or nullptr if not found.
 */
MySQL_Backend * MySQL_Session::find_backend(int hostgroup_id) {
	MySQL_Backend *_mybe;
	unsigned int i;
	for (i=0; i < mybes->len; i++) {
		_mybe=(MySQL_Backend *)mybes->index(i);
		if (_mybe->hostgroup_id==hostgroup_id) {
			return _mybe;
		}
	}
	return NULL; // NULL = backend not found
};

/**
 * @brief Update expired connections based on specified checks.
 * 
 * This function iterates through the list of backends and their connections
 * to determine if any connections have expired based on the provided checks.
 * If a connection is found to be expired, its hostgroup ID is added to the
 * list of expired connections for further processing.
 * 
 * @param checks A vector of function objects representing checks to determine if a connection has expired.
 */
void MySQL_Session::update_expired_conns(const vector<function<bool(MySQL_Connection*)>>& checks) {
	for (uint32_t i = 0; i < mybes->len; i++) { // iterate through the list of backends 
		MySQL_Backend* mybe = static_cast<MySQL_Backend*>(mybes->index(i));
		MySQL_Data_Stream* myds = mybe != nullptr ? mybe->server_myds : nullptr;
		MySQL_Connection* myconn = myds != nullptr ? myds->myconn : nullptr;

		//!  it performs a series of checks to determine if it has expired
		if (myconn != nullptr) {
			const bool is_active_transaction = myconn->IsActiveTransaction();
			const bool multiplex_disabled = myconn->MultiplexDisabled(false);
			const bool is_idle = myconn->async_state_machine == ASYNC_IDLE;

			// Make sure the connection is reusable before performing any check
			if (myconn->reusable==true && is_active_transaction==false && multiplex_disabled==false && is_idle) {
				for (const function<bool(MySQL_Connection*)>& check : checks) {
					if (check(myconn)) {
						// If a connection is found to be expired based on the provided checks,
						// its hostgroup ID is added to the list of expired connections (hgs_expired_conns)
						// for further processing.
						this->hgs_expired_conns.push_back(mybe->hostgroup_id);
						break;
					}
				}
			}
		}
	}
}

/**
 * @brief Create a new MySQL backend associated with the specified hostgroup ID and data stream.
 * 
 * This function creates a new MySQL backend object and associates it with the provided hostgroup ID
 * and data stream. If the data stream is not provided (_myds is nullptr), a new MySQL_Data_Stream
 * object is created and initialized.
 * 
 * @param hostgroup_id The ID of the hostgroup to which the backend belongs.
 * @param _myds The MySQL data stream associated with the backend.
 * @return A pointer to the newly created MySQL_Backend object.
 */
MySQL_Backend * MySQL_Session::create_backend(int hostgroup_id, MySQL_Data_Stream *_myds) {
	MySQL_Backend *_mybe=new MySQL_Backend();
	proxy_debug(PROXY_DEBUG_NET,4,"HID=%d, _myds=%p, _mybe=%p\n" , hostgroup_id, _myds, _mybe);
	_mybe->hostgroup_id=hostgroup_id;
	if (_myds) {
		_mybe->server_myds=_myds;
	} else {
		_mybe->server_myds = new MySQL_Data_Stream();
		_mybe->server_myds->DSS=STATE_NOT_INITIALIZED;
		_mybe->server_myds->init(MYDS_BACKEND_NOT_CONNECTED, this, 0);
	}
	// the newly created backend is added to the session's list of backends (mybes) and a pointer to it is returned.
	mybes->add(_mybe);
	return _mybe;
};

/**
 * @brief Find or create a MySQL backend associated with the specified hostgroup ID and data stream.
 * 
 * This function first attempts to find an existing MySQL backend associated with the provided
 * hostgroup ID. If a backend is found, its pointer is returned. Otherwise, a new MySQL backend
 * is created and associated with the hostgroup ID and data stream. If the data stream is not provided
 * (_myds is nullptr), a new MySQL_Data_Stream object is created and initialized for the new backend.
 * 
 * @param hostgroup_id The ID of the hostgroup to which the backend belongs.
 * @param _myds The MySQL data stream associated with the backend.
 * @return A pointer to the MySQL_Backend object found or created.
 */
MySQL_Backend * MySQL_Session::find_or_create_backend(int hostgroup_id, MySQL_Data_Stream *_myds) {
	MySQL_Backend *_mybe=find_backend(hostgroup_id);
	proxy_debug(PROXY_DEBUG_NET,4,"HID=%d, _myds=%p, _mybe=%p\n" , hostgroup_id, _myds, _mybe);
	// The pointer to the found or newly created backend is returned.
	return ( _mybe ? _mybe : create_backend(hostgroup_id, _myds) );
};

/**
 * @brief Reset all MySQL backends associated with this session.
 * 
 * This function resets all MySQL backends associated with the current session.
 * It iterates over all backends stored in the session, resets each backend, and then deletes it.
 * 
 */
void MySQL_Session::reset_all_backends() {
	MySQL_Backend *mybe;
	while(mybes->len) {
		mybe=(MySQL_Backend *)mybes->remove_index_fast(0);
		mybe->reset();
		delete mybe;
	}
};

/**
 * @brief Writes data from the session to the network with optional throttling and flow control.
 *
 * The writeout() function in the MySQL_Session class is responsible for writing data from the session to the network.
 * It supports throttling, which limits the rate at which data is sent to the client. Throttling is controlled by the
 * mysql_thread___throttle_max_bytes_per_second_to_client configuration parameter. If throttling is disabled (the parameter
 * is set to 0), the function bypasses throttling.
 *
 * This function first ensures that any pending data in the session's data stream (client_myds) is written to the network.
 * This ensures that the network buffers are emptied, allowing new data to be sent.
 *
 * After writing data to the network, the function checks if flow control is necessary. If the total amount of data written
 * exceeds the maximum allowed per call (mwpl), or if the data is sent too quickly, the function pauses writing for a brief
 * period to control the flow of data.
 *
 * If throttling is enabled, the function adjusts the throttle based on the amount of data written and the configured maximum
 * bytes per second. If the current throughput exceeds the configured limit, the function increases the pause duration to
 * regulate the flow of data.
 *
 * Finally, if the session has a backend associated with it (mybe), and the backend has a server data stream (server_myds),
 * the function also writes data from the server data stream to the network.
 *
 * @note This function assumes that necessary session and network structures are properly initialized.
 *
 * @see mysql_thread___throttle_max_bytes_per_second_to_client
 * @see MySQL_Session::client_myds
 * @see MySQL_Session::mybe
 * @see MySQL_Backend::server_myds
 */
void MySQL_Session::writeout() {
	int tps = 10; // throttling per second , by default every 100ms
	int total_written = 0;
	unsigned long long last_sent_=0;
	bool disable_throttle = mysql_thread___throttle_max_bytes_per_second_to_client == 0;
	int mwpl = mysql_thread___throttle_max_bytes_per_second_to_client; // max writes per call
	mwpl = mwpl/tps;
	if (session_type!=PROXYSQL_SESSION_MYSQL) {
		disable_throttle = true;
	}
	if (client_myds) client_myds->array2buffer_full();
	if (mybe && mybe->server_myds && mybe->server_myds->myds_type==MYDS_BACKEND) {
		if (session_type==PROXYSQL_SESSION_MYSQL) {
			if (mybe->server_myds->net_failure==false) {
				if (mybe->server_myds->poll_fds_idx>-1) { // NOTE: attempt to force writes
					mybe->server_myds->array2buffer_full();
				}
			}
		} else {
			mybe->server_myds->array2buffer_full();
		}
	}
	if (client_myds && thread->curtime >= client_myds->pause_until) {
		if (mirror==false) {
			bool runloop=false;
			if (client_myds->mypolls) {
				last_sent_ = client_myds->mypolls->last_sent[client_myds->poll_fds_idx];
			}
			int retbytes=client_myds->write_to_net_poll();
			total_written+=retbytes;
			if (retbytes==QUEUE_T_DEFAULT_SIZE) { // optimization to solve memory bloat
				runloop=true;
			}
			while (runloop && (disable_throttle || total_written < mwpl)) {
				runloop=false; // the default
				client_myds->array2buffer_full();
				struct pollfd fds;
				fds.fd=client_myds->fd;
				fds.events=POLLOUT;
				fds.revents=0;
				int retpoll=poll(&fds, 1, 0);
				if (retpoll>0) {
					if (fds.revents==POLLOUT) {
						retbytes=client_myds->write_to_net_poll();
						total_written+=retbytes;
						if (retbytes==QUEUE_T_DEFAULT_SIZE) { // optimization to solve memory bloat
							runloop=true;
						}
					}
				}
			}
		}
	}

	// flow control
	if (!disable_throttle && total_written > 0) {
	   if (total_written > mwpl) {
			unsigned long long add_ = 1000000/tps + 1000000/tps*((unsigned long long)total_written - (unsigned long long)mwpl)/mwpl;
			pause_until = thread->curtime + add_;
			client_myds->remove_pollout();
			client_myds->pause_until = thread->curtime + add_;
		} else {
			if (total_written >= QUEUE_T_DEFAULT_SIZE) {
				unsigned long long time_diff = thread->curtime - last_sent_;
				if (time_diff == 0) { // sending data really too fast!
					unsigned long long add_ = 1000000/tps + 1000000/tps*((unsigned long long)total_written - (unsigned long long)mwpl)/mwpl;
					pause_until = thread->curtime + add_;
					client_myds->remove_pollout();
					client_myds->pause_until = thread->curtime + add_;
				} else {
					float current_Bps = (float)total_written*1000*1000/time_diff;
					if (current_Bps > mysql_thread___throttle_max_bytes_per_second_to_client) {
						unsigned long long add_ = 1000000/tps;
						pause_until = thread->curtime + add_;
						assert(pause_until > thread->curtime);
						client_myds->remove_pollout();
						client_myds->pause_until = thread->curtime + add_;
					}
				}
			}
		}
	}

	if (mybe) {
		if (mybe->server_myds) mybe->server_myds->write_to_net_poll();
	}
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Writeout Session %p\n" , this->thread, this, this);
}

/**
 * @brief Handles COMMIT or ROLLBACK commands received from the client.
 *
 * The handler_CommitRollback() function processes COMMIT or ROLLBACK commands received from the client. It checks
 * the command type and verifies if the command matches the expected syntax for COMMIT or ROLLBACK. If the command
 * matches, it updates the respective commit or rollback count in the global monitor's status. Additionally, it
 * checks for the presence of an active transaction to determine whether to forward the command or reply with an OK
 * status.
 *
 * If there is an active transaction, the function sets the current hostgroup to the hostgroup of the active transaction
 * and returns false, indicating that the command should be forwarded. If there are no active transactions, the function
 * replies with an OK status and updates the client data stream accordingly.
 *
 * @param pkt Pointer to the packet containing the COMMIT or ROLLBACK command.
 * @return True if the command is successfully handled and replied to, false otherwise.
 *
 * @see MySQL_Session::FindOneActiveTransaction()
 * @see MySQL_Session::current_hostgroup
 * @see MySQL_Session::autocommit
 * @see MySQL_Session::client_myds
 * @see MySQL_Data_Stream::DSS
 * @see MySQL_Protocol::generate_pkt_OK()
 * @see MySQL_Session::RequestEnd()
 */
bool MySQL_Session::handler_CommitRollback(PtrSize_t *pkt) {
	if (pkt->size <= 5) { return false; }
	char c=((char *)pkt->ptr)[5];
	bool ret=false;
	if (c=='c' || c=='C') {
		if (pkt->size==strlen("commit")+5) {
			if (strncasecmp((char *)"commit",(char *)pkt->ptr+5,6)==0) {
				__sync_fetch_and_add(&MyHGM->status.commit_cnt, 1);
				ret=true;
			}
		}
	} else {
		if (c=='r' || c=='R') {
			if (pkt->size==strlen("rollback")+5) {
				if ( strncasecmp((char *)"rollback",(char *)pkt->ptr+5,8)==0 ) {
					__sync_fetch_and_add(&MyHGM->status.rollback_cnt, 1);
					ret=true;
				}
			}
		}
	}

	if (ret==false) {
		return false;	// quick exit
	}
	// in this part of the code (as at release 2.4.3) where we call
	// NumActiveTransactions() with the check_savepoint flag .
	// This to try to handle MySQL bug https://bugs.mysql.com/bug.php?id=107875
	//
	// Since we are limited to forwarding just one 'COMMIT|ROLLBACK', we work under the assumption that we
	// only have one active transaction. Under this premise, we should execute this command under that
	// specific connection, for that, we update 'current_hostgroup' with the first active transaction we are
	// able to find. If more transactions are simultaneously open for the session, more 'COMMIT|ROLLBACK'
	// commands are required to be issued by the client to continue ending transactions.
	int hg = FindOneActiveTransaction(true);
	if (hg != -1) {
		// there is an active transaction, we must forward the request
		current_hostgroup = hg;
		return false;
	} else {
		// there is no active transaction, we will just reply OK
		client_myds->DSS=STATE_QUERY_SENT_NET;
		uint16_t setStatus = 0;
		if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
		if (mirror==false) {
			RequestEnd(NULL);
		} else {
			client_myds->DSS=STATE_SLEEP;
			status=WAITING_CLIENT_DATA;
		}
		l_free(pkt->size,pkt->ptr);
		if (c=='c' || c=='C') {
			__sync_fetch_and_add(&MyHGM->status.commit_cnt_filtered, 1);
		} else {
			__sync_fetch_and_add(&MyHGM->status.rollback_cnt_filtered, 1);
		}
		return true;
	}
	return false;
}

/**
 * @brief Handles the SET AUTOCOMMIT command received from the client.
 *
 * The handler_SetAutocommit() function processes the SET AUTOCOMMIT command received from the client.
 * It parses the command to determine the new autocommit value and updates the autocommit status accordingly.
 * Additionally, it checks for the presence of active transactions and handles the forwarding of the command if needed.
 * The function also replies with an OK status to the client after processing the command.
 *
 * @param pkt Pointer to the packet containing the SET AUTOCOMMIT command.
 * @return True if the command is successfully handled and replied to, false otherwise.
 *
 * @see MySQL_Session::autocommit_handled
 * @see MySQL_Session::sending_set_autocommit
 * @see MySQL_Session::current_hostgroup
 * @see MySQL_Session::autocommit
 * @see MySQL_Session::client_myds
 * @see MySQL_Session::NumActiveTransactions()
 * @see MySQL_Data_Stream::DSS
 * @see MySQL_Protocol::generate_pkt_OK()
 * @see MySQL_Session::RequestEnd()
 */
bool MySQL_Session::handler_SetAutocommit(PtrSize_t *pkt) {
	autocommit_handled=false;
	sending_set_autocommit=false;
	size_t sal=strlen("set autocommit");
	char * _ptr = (char *)pkt->ptr;
#ifdef DEBUG
	string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Parsing SET command = %s\n", nqn.c_str());
#endif
	if ( pkt->size >= 7+sal) {
		if (strncasecmp((char *)"SET @@session.autocommit",(char *)pkt->ptr+5,strlen((char *)"SET @@session.autocommit"))==0) {
			memmove(_ptr+9, _ptr+19, pkt->size - 19);
			memset(_ptr+pkt->size-10,' ',10);
		}
		if (strncasecmp((char *)"set autocommit",(char *)pkt->ptr+5,sal)==0) {
			void *p = NULL;
			// make a copy
			PtrSize_t _new_pkt;
			_new_pkt.size = pkt->size;
			_new_pkt.ptr = malloc(_new_pkt.size);
			memcpy(_new_pkt.ptr, pkt->ptr, _new_pkt.size);
			_ptr = (char *)_new_pkt.ptr;
			for (int i=5+sal; i < (int)_new_pkt.size; i++) {
				*((char *)_new_pkt.ptr+i) = tolower(*((char *)_new_pkt.ptr+i));
			}
			p = memmem(_ptr+5+sal, pkt->size-5-sal, (void *)"false", 5);
			if (p) {
				memcpy(p,(void *)"0    ",5);
			}
			p = memmem(_ptr+5+sal, pkt->size-5-sal, (void *)"true", 4);
			if (p) {
				memcpy(p,(void *)"1   ",4);
			}
			p = memmem(_ptr+5+sal, pkt->size-5-sal, (void *)"off", 3);
			if (p) {
				memcpy(p,(void *)"0  ",3);
			}
			p = memmem(_ptr+5+sal, pkt->size-5-sal, (void *)"on", 2);
			if (p) {
				memcpy(p,(void *)"1 ",2);
			}
			unsigned int i;
			bool eq=false;
			int fd=-1; // first digit
			for (i=5+sal;i<_new_pkt.size;i++) {
				char c=((char *)_new_pkt.ptr)[i];
				if (c!='0' && c!='1' && c!=' ' && c!='=' && c!='/') {
					free(_new_pkt.ptr);
					return false; // found a not valid char
				}
				if (eq==false) {
					if (c!=' ' && c!='=') {
						free(_new_pkt.ptr);
						return false; // found a not valid char
					}
					if (c=='=') eq=true;
				} else {
					if (c!='0' && c!='1' && c!=' ' && c!='/') {
						free(_new_pkt.ptr);
						return false; // found a not valid char
					}
					if (fd==-1) {
						if (c=='0' || c=='1') { // found first digit
							if (c=='0')
								fd=0;
							else
								fd=1;
						}
					} else {
						if (c=='0' || c=='1') { // found second digit
							free(_new_pkt.ptr);
							return false;
						} else {
							if (c=='/' || c==' ') {
								break;
							}
						}
					}
				}
			}
			if (fd >= 0) { // we can set autocommit
				autocommit_handled=true;
#ifdef DEBUG
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Setting autocommit to = %d\n", fd);
#endif
				__sync_fetch_and_add(&MyHGM->status.autocommit_cnt, 1);
				// we immediately process the number of transactions
				unsigned int nTrx=NumActiveTransactions();
				if (fd==1 && autocommit==true) {
					// nothing to do, return OK
					goto __ret_autocommit_OK;
				}
				if (fd==1 && autocommit==false) {
					// in this part of the code (as at release 2.4.3) where we call
					// NumActiveTransactions() with the check_savepoint flag .
					// This to try to handle MySQL bug https://bugs.mysql.com/bug.php?id=107875
					unsigned int nTrx_SP=NumActiveTransactions(true); // check savepoint
					if (nTrx_SP) { // previously we were checking nTrx . Now nTrx_SP
						// there is an active transaction, we need to forward it
						// because this can potentially close the transaction
						autocommit=true;
						client_myds->myconn->set_autocommit(autocommit);
						autocommit_on_hostgroup=FindOneActiveTransaction(true);
						free(_new_pkt.ptr);
						sending_set_autocommit=true;
						return false;
					} else {
						// as there is no active transaction, we do no need to forward it
						// just change internal state
						autocommit=true;
						client_myds->myconn->set_autocommit(autocommit);
						goto __ret_autocommit_OK;
					}
				}

				if (fd==0) {
					autocommit=false;	// we set it, no matter if already set or not
					client_myds->myconn->set_autocommit(autocommit);
					// it turned out I was wrong
					// set autocommit=0 has no effect if there is an acrive transaction
					// therefore, we never forward set autocommit = 0
					goto __ret_autocommit_OK;
				}
__ret_autocommit_OK:
				if (session_type == PROXYSQL_SESSION_MYSQL) { // do not run this if PROXYSQL_SESSION_SQLITE
					client_myds->DSS=STATE_QUERY_SENT_NET;
					uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
					if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
					client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
					if (mirror==false) {
						RequestEnd(NULL);
					} else {
						client_myds->DSS=STATE_SLEEP;
						status=WAITING_CLIENT_DATA;
					}
					__sync_fetch_and_add(&MyHGM->status.autocommit_cnt_filtered, 1);
				}
				if (session_type == PROXYSQL_SESSION_MYSQL) {
					// free() only if session_type == PROXYSQL_SESSION_MYSQL
					// because the packet will be freed in
					// handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___not_mysql()
					// for all session type other than PROXYSQL_SESSION_MYSQL
					l_free(pkt->size,pkt->ptr);
				}
				free(_new_pkt.ptr);
				return true;
			}
			free(_new_pkt.ptr);
		}
	}
	return false;
}

void MySQL_Session::generate_proxysql_internal_session_json(json &j) {
	char buff[32];
	sprintf(buff,"%p",this);
	j["address"] = buff;
	if (thread) {
		sprintf(buff,"%p",thread);
		j["thread"] = buff;
	}
	uint64_t age_ms = (thread->curtime - start_time)/1000;
	j["age_ms"] = age_ms;
	j["status"] = status;
	j["autocommit"] = autocommit;
	j["thread_session_id"] = thread_session_id;
	j["current_hostgroup"] = current_hostgroup;
	j["default_hostgroup"] = default_hostgroup;
	j["locked_on_hostgroup"] = locked_on_hostgroup;
	j["autocommit_on_hostgroup"] = autocommit_on_hostgroup;
	j["last_insert_id"] = last_insert_id;
	j["last_HG_affected_rows"] = last_HG_affected_rows;
	j["active_transactions"] = active_transactions;
	j["transaction_time_ms"] = thread->curtime - transaction_started_at;
	j["warning_in_hg"] = warning_in_hg;
	j["gtid"]["hid"] = gtid_hid;
	j["gtid"]["last"] = ( strlen(gtid_buf) ? gtid_buf : "" );
	json& jqpo = j["qpo"];
	qpo->get_info_json(jqpo);
	j["default_schema"] = ( default_schema ? default_schema : "" );
	j["user_attributes"] = ( user_attributes ? user_attributes : "" );
	j["transaction_persistent"] = transaction_persistent;
	if (client_myds != NULL) { // only if client_myds is defined
		client_myds->get_client_myds_info_json(j);
	}
	for (unsigned int i=0; i<mybes->len; i++) {
		MySQL_Backend *_mybe = NULL;
		_mybe=(MySQL_Backend *)mybes->index(i);
		//unsigned int i = _mybe->hostgroup_id;
		j["backends"][i] = {};
		j["backends"][i]["hostgroup_id"] = _mybe->hostgroup_id;
		j["backends"][i]["gtid"] = ( strlen(_mybe->gtid_uuid) ? _mybe->gtid_uuid : "" );
		if (_mybe->server_myds) {
			MySQL_Data_Stream *_myds=_mybe->server_myds;
			sprintf(buff,"%p",_myds);
			j["backends"][i]["stream"]["address"] = buff;
			j["backends"][i]["stream"]["questions"] = _myds->statuses.questions;
			j["backends"][i]["stream"]["myconnpoll_get"] = _myds->statuses.myconnpoll_get;
			j["backends"][i]["stream"]["myconnpoll_put"] = _myds->statuses.myconnpoll_put;
			/* when fast_forward is not used, these metrics are always 0. Explicitly disabled
			j["backend"][i]["stream"]["pkts_recv"] = _myds->pkts_recv;
			j["backend"][i]["stream"]["pkts_sent"] = _myds->pkts_sent;
			*/
			j["backends"][i]["stream"]["bytes_recv"] = _myds->bytes_info.bytes_recv;
			j["backends"][i]["stream"]["bytes_sent"] = _myds->bytes_info.bytes_sent;
			j["backends"][i]["stream"]["DSS"] = _myds->DSS;
			if (_myds->myconn) {
				json& jc = j["backends"][i]["conn"];
				_myds->myconn->get_backend_conn_info_json(jc);
			}
		}
	}
}

void MySQL_Session::return_proxysql_internal(PtrSize_t *pkt) {
	unsigned int l = 0;
	l = strlen((char *)"PROXYSQL INTERNAL SESSION");
	if (pkt->size==(5+l) && strncasecmp((char *)"PROXYSQL INTERNAL SESSION", (char *)pkt->ptr+5, l)==0) {
		json j;
		generate_proxysql_internal_session_json(j);
		std::string s = j.dump(4, ' ', false, json::error_handler_t::replace);
		SQLite3_result *resultset = new SQLite3_result(1);
		resultset->add_column_definition(SQLITE_TEXT,"session_info");
		char *pta[1];
		pta[0] = (char *)s.c_str();
		resultset->add_row(pta);
		bool deprecate_eof_active = client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
		SQLite3_to_MySQL(resultset, NULL, 0, &client_myds->myprot, false, deprecate_eof_active);
		delete resultset;
		l_free(pkt->size,pkt->ptr);
		return;
	}
	// default
	client_myds->DSS=STATE_QUERY_SENT_NET;
	string errmsg = "Unknown PROXYSQL INTERNAL command";
	client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1047,(char *)"08S01", errmsg.c_str() ,true);
	if (mirror==false) {
		MyHGM->add_mysql_errors(current_hostgroup, (char *)"", 0, client_myds->myconn->userinfo->username, (client_myds->addr.addr ? client_myds->addr.addr : (char *)"unknown" ), client_myds->myconn->userinfo->schemaname, 1047, (char *)errmsg.c_str());
		RequestEnd(NULL, 1047, errmsg.c_str());
	} else {
		client_myds->DSS=STATE_SLEEP;
		status=WAITING_CLIENT_DATA;
	}
	l_free(pkt->size,pkt->ptr);
}

/**
 * @brief Handles special queries executed by the STATUS command in mysql cli .
 *   Specifically:
 *   "select DATABASE(), USER() limit 1"
 *   "select @@character_set_client, @@character_set_connection, @@character_set_server, @@character_set_database limit 1"
 *   See Github issues 4396 and 4426
 *
 * @param PtrSize_t The packet from the client
 *
 * @return True if the queries are handled
 */
bool MySQL_Session::handler_special_queries_STATUS(PtrSize_t *pkt) {
	if (pkt->size == (SELECT_DB_USER_LEN+5)) {
		if (strncasecmp(SELECT_DB_USER,(char *)pkt->ptr+5, SELECT_DB_USER_LEN)==0) {
			SQLite3_result *resultset = new SQLite3_result(2);
			resultset->add_column_definition(SQLITE_TEXT,"DATABASE()");
			resultset->add_column_definition(SQLITE_TEXT,"USER()");
			char *pta[2];
			pta[0] = client_myds->myconn->userinfo->username;
			pta[1] = client_myds->myconn->userinfo->schemaname;
			resultset->add_row(pta);
			bool deprecate_eof_active = client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
			SQLite3_to_MySQL(resultset, NULL, 0, &client_myds->myprot, false, deprecate_eof_active);
			delete resultset;
			l_free(pkt->size,pkt->ptr);
			return true;
		}
	}
	if (pkt->size == (SELECT_CHARSET_STATUS_LEN+5)) {
		if (strncasecmp(SELECT_CHARSET_STATUS,(char *)pkt->ptr+5, SELECT_CHARSET_STATUS_LEN)==0) {
			SQLite3_result *resultset = new SQLite3_result(4);
			resultset->add_column_definition(SQLITE_TEXT,"@@character_set_client");
			resultset->add_column_definition(SQLITE_TEXT,"@@character_set_connection");
			resultset->add_column_definition(SQLITE_TEXT,"@@character_set_server");
			resultset->add_column_definition(SQLITE_TEXT,"@@character_set_database");

			string vals[4];
			json j = {};
			json& jc = j["conn"];
			MySQL_Connection *conn = client_myds->myconn;
			// here we do a bit back and forth to and from JSON to reuse existing code instead of writing new code.
			// This is not great for performance, but this query is rarely executed.
			conn->variables[SQL_CHARACTER_SET_CLIENT].fill_client_internal_session(jc, SQL_CHARACTER_SET_CLIENT);
			conn->variables[SQL_CHARACTER_SET_CONNECTION].fill_client_internal_session(jc, SQL_CHARACTER_SET_CONNECTION);
			conn->variables[SQL_CHARACTER_SET_DATABASE].fill_client_internal_session(jc, SQL_CHARACTER_SET_DATABASE);

			vals[0] = jc[mysql_tracked_variables[SQL_CHARACTER_SET_CLIENT].internal_variable_name];
			vals[1] = jc[mysql_tracked_variables[SQL_CHARACTER_SET_CONNECTION].internal_variable_name];
			vals[2] = string(mysql_thread___default_variables[SQL_CHARACTER_SET]);
			vals[3] = jc[mysql_tracked_variables[SQL_CHARACTER_SET_DATABASE].internal_variable_name];

			const char *pta[4];
			for (int i=0; i<4; i++) {
				pta[i] = vals[i].c_str();
			}
			resultset->add_row(pta);
			bool deprecate_eof_active = client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
			SQLite3_to_MySQL(resultset, NULL, 0, &client_myds->myprot, false, deprecate_eof_active);
			delete resultset;
			l_free(pkt->size,pkt->ptr);
			return true;
		}
	}
	return false;
}

bool MySQL_Session::handler_special_queries(PtrSize_t *pkt) {
	bool deprecate_eof_active = client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;

	if (
		(pkt->size == (SELECT_DB_USER_LEN+5))
		||
		(pkt->size == (SELECT_CHARSET_STATUS_LEN+5))
	) {
		if (handler_special_queries_STATUS(pkt) == true) {
			return true;
		}
	}
	if (pkt->size>(5+18) && strncasecmp((char *)"PROXYSQL INTERNAL ",(char *)pkt->ptr+5,18)==0) {
		return_proxysql_internal(pkt);
		return true;
	}
	if (locked_on_hostgroup == -1) {
		if (handler_SetAutocommit(pkt) == true) {
			return true;
		}
		if (handler_CommitRollback(pkt) == true) {
			return true;
		}
	}

	//handle 2564
	if (pkt->size==SELECT_VERSION_COMMENT_LEN+5 && *((char *)(pkt->ptr)+4)==(char)0x03 && strncmp((char *)SELECT_VERSION_COMMENT,(char *)pkt->ptr+5,pkt->size-5)==0) {
		// FIXME: this doesn't return AUTOCOMMIT or IN_TRANS
		PtrSize_t pkt_2;
		if (deprecate_eof_active) {
			pkt_2.size=PROXYSQL_VERSION_COMMENT_WITH_OK_LEN;
			pkt_2.ptr=l_alloc(pkt_2.size);
			memcpy(pkt_2.ptr,PROXYSQL_VERSION_COMMENT_WITH_OK,pkt_2.size);
		} else {
			pkt_2.size=PROXYSQL_VERSION_COMMENT_LEN;
			pkt_2.ptr=l_alloc(pkt_2.size);
			memcpy(pkt_2.ptr,PROXYSQL_VERSION_COMMENT,pkt_2.size);
		}
		status=WAITING_CLIENT_DATA;
		client_myds->DSS=STATE_SLEEP;
		client_myds->PSarrayOUT->add(pkt_2.ptr,pkt_2.size);
		if (mirror==false) {
			RequestEnd(NULL);
		}
		l_free(pkt->size,pkt->ptr);
		return true;
	}
	if (pkt->size==strlen((char *)"select USER()")+5 && strncmp((char *)"select USER()",(char *)pkt->ptr+5,pkt->size-5)==0) {
		// FIXME: this doesn't return AUTOCOMMIT or IN_TRANS
		char *query1=(char *)"SELECT \"%s\" AS 'USER()'";
		char *query2=(char *)malloc(strlen(query1)+strlen(client_myds->myconn->userinfo->username)+10);
		sprintf(query2,query1,client_myds->myconn->userinfo->username);
		char *error;
		int cols;
		int affected_rows;
		SQLite3_result *resultset;
		GloAdmin->admindb->execute_statement(query2, &error , &cols , &affected_rows , &resultset);
		SQLite3_to_MySQL(resultset, error, affected_rows, &client_myds->myprot, false, deprecate_eof_active);
		delete resultset;
		free(query2);
		if (mirror==false) {
			RequestEnd(NULL);
		}
		l_free(pkt->size,pkt->ptr);
		return true;
	}
	// MySQL client check command for dollars quote support, starting at version '8.1.0'. See #4300.
	if ((pkt->size == strlen("SELECT $$") + 5) && strncasecmp("SELECT $$", (char*)pkt->ptr + 5, pkt->size - 5) == 0) {
		pair<int,const char*> err_info { get_dollar_quote_error(mysql_thread___server_version) };

		client_myds->DSS=STATE_QUERY_SENT_NET;
		client_myds->myprot.generate_pkt_ERR(true, NULL, NULL, 1, err_info.first, (char *)"HY000", err_info.second, true);
		client_myds->DSS=STATE_SLEEP;
		status=WAITING_CLIENT_DATA;

		if (mirror==false) {
			RequestEnd(NULL, err_info.first, err_info.second);
		}
		l_free(pkt->size,pkt->ptr);

		return true;
	}
	if (locked_on_hostgroup >= 0 && (strncasecmp((char *)"SET ",(char *)pkt->ptr+5,4)==0)) {
		// this is a circuit breaker, we will send everything to the backend
		//
		// also note that in the current implementation we stop tracking variables:
		// this becomes a problem if mysql-set_query_lock_on_hostgroup is
		// disabled while a session is already locked
		return false;
	}
	if ((pkt->size < 60) && (pkt->size > 38) && (strncasecmp((char *)"SET SESSION character_set_server",(char *)pkt->ptr+5,32)==0) ) { // issue #601
		char *idx=NULL;
		char *p=(char *)pkt->ptr+37;
		idx=(char *)memchr(p,'=',pkt->size-37);
		if (idx) { // we found =
			PtrSize_t pkt_2;
			pkt_2.size=5+strlen((char *)"SET NAMES ")+pkt->size-1-(idx-(char *)pkt->ptr);
			pkt_2.ptr=l_alloc(pkt_2.size);
			mysql_hdr Hdr;
			memcpy(&Hdr,pkt->ptr,sizeof(mysql_hdr));
			Hdr.pkt_length=pkt_2.size-5;
			memcpy((char *)pkt_2.ptr+4,(char *)pkt->ptr+4,1);
			memcpy(pkt_2.ptr,&Hdr,sizeof(mysql_hdr));
			strcpy((char *)pkt_2.ptr+5,(char *)"SET NAMES ");
			memcpy((char *)pkt_2.ptr+15,idx+1,pkt->size-1-(idx-(char *)pkt->ptr));
			l_free(pkt->size,pkt->ptr);
			pkt->size=pkt_2.size;
			pkt->ptr=pkt_2.ptr;
			// Fix 'use-after-free': To change the pointer of the 'PtrSize_t' being processed by
			// 'MySQL_Session::handler' we are forced to update 'MySQL_Session::CurrentQuery'.
			CurrentQuery.QueryPointer = static_cast<unsigned char*>(pkt_2.ptr);
			CurrentQuery.QueryLength = pkt_2.size;
		}
	}
	if ((pkt->size < 60) && (pkt->size > 39) && (strncasecmp((char *)"SET SESSION character_set_results",(char *)pkt->ptr+5,33)==0) ) { // like the above
		char *idx=NULL;
		char *p=(char *)pkt->ptr+38;
		idx=(char *)memchr(p,'=',pkt->size-38);
		if (idx) { // we found =
			PtrSize_t pkt_2;
			pkt_2.size=5+strlen((char *)"SET NAMES ")+pkt->size-1-(idx-(char *)pkt->ptr);
			pkt_2.ptr=l_alloc(pkt_2.size);
			mysql_hdr Hdr;
			memcpy(&Hdr,pkt->ptr,sizeof(mysql_hdr));
			Hdr.pkt_length=pkt_2.size-5;
			memcpy((char *)pkt_2.ptr+4,(char *)pkt->ptr+4,1);
			memcpy(pkt_2.ptr,&Hdr,sizeof(mysql_hdr));
			strcpy((char *)pkt_2.ptr+5,(char *)"SET NAMES ");
			memcpy((char *)pkt_2.ptr+15,idx+1,pkt->size-1-(idx-(char *)pkt->ptr));
			l_free(pkt->size,pkt->ptr);
			pkt->size=pkt_2.size;
			pkt->ptr=pkt_2.ptr;
			// Fix 'use-after-free': To change the pointer of the 'PtrSize_t' being processed by
			// 'MySQL_Session::handler' we are forced to update 'MySQL_Session::CurrentQuery'.
			CurrentQuery.QueryPointer = static_cast<unsigned char*>(pkt_2.ptr);
			CurrentQuery.QueryLength = pkt_2.size;
		}
	}
	if (
		(pkt->size < 100) && (pkt->size > 15) && (strncasecmp((char *)"SET NAMES ",(char *)pkt->ptr+5,10)==0)
		&&
		(memchr((const void *)((char *)pkt->ptr+5),',',pkt->size-15)==NULL) // there is no comma
	) {
		char *unstripped=strndup((char *)pkt->ptr+15,pkt->size-15);
		char *csname=trim_spaces_and_quotes_in_place(unstripped);
		//unsigned int charsetnr = 0;
		const MARIADB_CHARSET_INFO * c;
		char * collation_name_unstripped = NULL;
		char * collation_name = NULL;
		if (strcasestr(csname," COLLATE ")) {
			collation_name_unstripped = strcasestr(csname," COLLATE ") + strlen(" COLLATE ");
			collation_name = trim_spaces_and_quotes_in_place(collation_name_unstripped);
			char *_s1=index(csname,' ');
			char *_s2=index(csname,'\'');
			char *_s3=index(csname,'"');
			char *_s = NULL;
			if (_s1) {
				_s = _s1;
			}
			if (_s2) {
				if (_s) {
					if (_s2 < _s) {
						_s = _s2;
					}
				} else {
					_s = _s2;
				}
			}
			if (_s3) {
				if (_s) {
					if (_s3 < _s) {
						_s = _s3;
					}
				} else {
					_s = _s3;
				}
			}
			if (_s) {
				*_s = '\0';
			}

			_s1 = index(collation_name,' ');
			_s2 = index(collation_name,'\'');
			_s3 = index(collation_name,'"');
			_s = NULL;
			if (_s1) {
				_s = _s1;
			}
			if (_s2) {
				if (_s) {
					if (_s2 < _s) {
						_s = _s2;
					}
				} else {
					_s = _s2;
				}
			}
			if (_s3) {
				if (_s) {
					if (_s3 < _s) {
						_s = _s3;
					}
				} else {
					_s = _s3;
				}
			}
			if (_s) {
				*_s = '\0';
			}

			c = proxysql_find_charset_collate_names(csname,collation_name);
		} else {
			c = proxysql_find_charset_name(csname);
		}
		free(unstripped);
		if (c) {
			client_myds->DSS=STATE_QUERY_SENT_NET;
			client_myds->myconn->set_charset(c->nr, NAMES);
			unsigned int nTrx=NumActiveTransactions();
			uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
			if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
			if (mirror==false) {
				RequestEnd(NULL);
			} else {
				client_myds->DSS=STATE_SLEEP;
				status=WAITING_CLIENT_DATA;
			}
			l_free(pkt->size,pkt->ptr);
			__sync_fetch_and_add(&MyHGM->status.frontend_set_names, 1);
			return true;
		}
	}
	// if query digest is disabled, warnings in ProxySQL are also deactivated, 
	// resulting in an empty response being sent to the client.
	if ((pkt->size == 18) && (strncasecmp((char*)"SHOW WARNINGS", (char*)pkt->ptr + 5, 13) == 0) &&
		CurrentQuery.QueryParserArgs.digest_text == nullptr) {
		SQLite3_result* resultset = new SQLite3_result(3);
		resultset->add_column_definition(SQLITE_TEXT, "Level");
		resultset->add_column_definition(SQLITE_TEXT, "Code");
		resultset->add_column_definition(SQLITE_TEXT, "Message");
		SQLite3_to_MySQL(resultset, NULL, 0, &client_myds->myprot, false, deprecate_eof_active);
		delete resultset;
		if (mirror == false) {
			RequestEnd(NULL);
		} else {
			client_myds->DSS=STATE_SLEEP;
			status=WAITING_CLIENT_DATA;
		}
		l_free(pkt->size, pkt->ptr);
		return true;
	}
	// if query digest is disabled, warnings in ProxySQL are also deactivated, 
	// resulting in zero warning count sent to the client.
	if ((pkt->size == 27) && (strncasecmp((char*)"SHOW COUNT(*) WARNINGS", (char*)pkt->ptr + 5, 22) == 0) &&
		CurrentQuery.QueryParserArgs.digest_text == nullptr) {
		SQLite3_result* resultset = new SQLite3_result(1);
		resultset->add_column_definition(SQLITE_TEXT, "@@session.warning_count");
		char* pta[1];
		pta[0] = (char*)"0";
		resultset->add_row(pta);
		SQLite3_to_MySQL(resultset, NULL, 0, &client_myds->myprot, false, deprecate_eof_active);
		delete resultset;
		client_myds->DSS = STATE_SLEEP;
		status = WAITING_CLIENT_DATA;
		if (mirror == false) {
			RequestEnd(NULL);
		}
		l_free(pkt->size, pkt->ptr);
		return true;
	}
	// 'LOAD DATA LOCAL INFILE' is unsupported. We report an specific error to inform clients about this fact. For more context see #833.
	if ( (pkt->size >= 22 + 5) && (strncasecmp((char *)"LOAD DATA LOCAL INFILE",(char *)pkt->ptr+5, 22)==0) ) {
		if (mysql_thread___enable_load_data_local_infile == false) {
			client_myds->DSS=STATE_QUERY_SENT_NET;
			string errmsg = "Unsupported 'LOAD DATA LOCAL INFILE' command";
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1047,(char *)"08S01", errmsg.c_str(), true);
			if (mirror==false) {
				MyHGM->add_mysql_errors(current_hostgroup, (char *)"", 0, client_myds->myconn->userinfo->username, (client_myds->addr.addr ? client_myds->addr.addr : (char *)"unknown" ), client_myds->myconn->userinfo->schemaname, 1047, (char *)errmsg.c_str());
				RequestEnd(NULL, 1047, errmsg.c_str());
			} else {
				client_myds->DSS=STATE_SLEEP;
				status=WAITING_CLIENT_DATA;
			}
			l_free(pkt->size,pkt->ptr);
			return true;
		} else {
			if (mysql_thread___verbose_query_error) {
				proxy_warning(
					"Command '%.*s' refers to file in ProxySQL instance, NOT on client side!\n",
					static_cast<int>(pkt->size - sizeof(mysql_hdr) - 1),
					static_cast<char*>(pkt->ptr) + 5
				);
			} else {
				proxy_warning(
					"Command 'LOAD DATA LOCAL INFILE' refers to file in ProxySQL instance, NOT on client side!\n"
				);
			}
		}
	}

	return false;
}

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___create_mirror_session() {
	if (pkt.size < 15*1024*1024 && (qpo->mirror_hostgroup >= 0 || qpo->mirror_flagOUT >= 0)) {
		// check if there are too many mirror sessions in queue
		if (thread->mirror_queue_mysql_sessions->len >= (unsigned int)mysql_thread___mirror_max_queue_length) {
			return;
		}
		// at this point, we will create the new session
		// we will later decide if queue it or sent it immediately

//		int i=0;
//		for (i=0;i<100;i++) {
		MySQL_Session *newsess=NULL;
		if (thread->mirror_queue_mysql_sessions_cache->len==0) {
			newsess=new MySQL_Session();
			newsess->client_myds = new MySQL_Data_Stream();
			newsess->client_myds->DSS=STATE_SLEEP;
			newsess->client_myds->sess=newsess;
			newsess->client_myds->fd=0;
			newsess->client_myds->myds_type=MYDS_FRONTEND;
			newsess->client_myds->PSarrayOUT= new PtrSizeArray();
			newsess->thread_session_id=__sync_fetch_and_add(&glovars.thread_id,1);
			if (newsess->thread_session_id==0) {
				newsess->thread_session_id=__sync_fetch_and_add(&glovars.thread_id,1);
			}
			newsess->status=WAITING_CLIENT_DATA;
			MySQL_Connection *myconn=new MySQL_Connection;
			newsess->client_myds->attach_connection(myconn);
			newsess->client_myds->myprot.init(&newsess->client_myds, newsess->client_myds->myconn->userinfo, newsess);
			newsess->mirror=true;
			newsess->client_myds->destroy_queues();
		} else {
			newsess=(MySQL_Session *)thread->mirror_queue_mysql_sessions_cache->remove_index_fast(0);
		}
		newsess->client_myds->myconn->userinfo->set(client_myds->myconn->userinfo);
		newsess->to_process=1;
		newsess->default_hostgroup=default_hostgroup;
		if (qpo->mirror_hostgroup>= 0) {
			newsess->mirror_hostgroup=qpo->mirror_hostgroup; // in the new session we copy the mirror hostgroup
		} else {
			newsess->mirror_hostgroup=default_hostgroup; // copy the default
		}
		newsess->mirror_flagOUT=qpo->mirror_flagOUT; // in the new session we copy the mirror flagOUT
		if (newsess->default_schema==NULL) {
			newsess->default_schema=strdup(default_schema);
		} else {
			if (strcmp(newsess->default_schema,default_schema)) {
				free(newsess->default_schema);
				newsess->default_schema=strdup(default_schema);
			}
		}
		newsess->mirrorPkt.size=pkt.size;
		newsess->mirrorPkt.ptr=l_alloc(newsess->mirrorPkt.size);
		memcpy(newsess->mirrorPkt.ptr,pkt.ptr,pkt.size);

		if (thread->mirror_queue_mysql_sessions->len==0) {
			// there are no sessions in the queue, we try to execute immediately
			// Only mysql_thread___mirror_max_concurrency mirror session can run in parallel
			if (__sync_add_and_fetch(&GloMTH->status_variables.mirror_sessions_current,1) > (unsigned int)mysql_thread___mirror_max_concurrency ) {
				// if the limit is reached, we queue it instead
				__sync_sub_and_fetch(&GloMTH->status_variables.mirror_sessions_current,1);
				thread->mirror_queue_mysql_sessions->add(newsess);
			}	else {
				GloMTH->status_variables.p_gauge_array[p_th_gauge::mirror_concurrency]->Increment();
				thread->register_session(newsess);
				newsess->handler(); // execute immediately
				//newsess->to_process=0;
				if (newsess->status==WAITING_CLIENT_DATA) { // the mirror session has completed
					thread->unregister_session(thread->mysql_sessions->len-1);
					unsigned int l = (unsigned int)mysql_thread___mirror_max_concurrency;
					if (thread->mirror_queue_mysql_sessions->len*0.3 > l) l=thread->mirror_queue_mysql_sessions->len*0.3;
					if (thread->mirror_queue_mysql_sessions_cache->len <= l) {
						bool to_cache=true;
						if (newsess->mybe) {
							if (newsess->mybe->server_myds) {
								to_cache=false;
							}
						}
						if (to_cache) {
							__sync_sub_and_fetch(&GloMTH->status_variables.mirror_sessions_current,1);
							GloMTH->status_variables.p_gauge_array[p_th_gauge::mirror_concurrency]->Decrement();
							thread->mirror_queue_mysql_sessions_cache->add(newsess);
						} else {
							delete newsess;
						}
					} else {
						delete newsess;
					}
				}
			}
		} else {
			thread->mirror_queue_mysql_sessions->add(newsess);
		}
	}
}

/**
 * @brief Handles the process of pinging the server again in the PINGING_SERVER status.
 *
 * The handler_again___status_PINGING_SERVER() function is responsible for managing the re-pinging process
 * when the session status is set to PINGING_SERVER. It asserts the existence of the server connection's data stream
 * and connection. It then performs an asynchronous ping operation on the server connection and processes the result.
 * Depending on the ping result, it either returns -1 to indicate a termination or continues with further actions.
 *
 * @return -1 if the session should be terminated, 0 otherwise.
 *
 * @see MySQL_Session::mybe
 * @see MySQL_Backend::server_myds
 * @see MySQL_Data_Stream
 * @see MySQL_Connection
 * @see MySQL_Connection::async_ping()
 * @see MySQL_Connection::compute_unknown_transaction_status()
 * @see MySQL_Data_Stream::return_MySQL_Connection_To_Pool()
 * @see MySQL_Data_Stream::destroy_MySQL_Connection_From_Pool()
 * @see MySQL_Session::set_status()
 * @see ProxySQL_MySQL_Error_Counter::p_update_mysql_error_counter()
 */
int MySQL_Session::handler_again___status_PINGING_SERVER() {
	assert(mybe->server_myds->myconn);
	MySQL_Data_Stream *myds=mybe->server_myds;
	MySQL_Connection *myconn=myds->myconn;
	int rc=myconn->async_ping(myds->revents);
	if (rc==0) {
		myconn->async_state_machine=ASYNC_IDLE;
		myconn->compute_unknown_transaction_status();
		//if (mysql_thread___multiplexing && (myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
		// due to issue #2096 we disable the global check on mysql_thread___multiplexing
		if ((myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
			myds->return_MySQL_Connection_To_Pool();
		} else {
			myds->destroy_MySQL_Connection_From_Pool(true);
		}
		delete mybe->server_myds;
		mybe->server_myds=NULL;
		set_status(session_status___NONE);
			return -1;
	} else {
		if (rc==-1 || rc==-2) {
			if (rc==-2) {
				unsigned long long us = mysql_thread___ping_timeout_server*1000;
				us += thread->curtime;
				us -= myds->wait_until;
				proxy_error("Ping timeout during ping on %s:%d after %lluus (timeout %dms)\n", myconn->parent->address, myconn->parent->port, us, mysql_thread___ping_timeout_server);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, ER_PROXYSQL_PING_TIMEOUT);
			} else { // rc==-1
				int myerr=mysql_errno(myconn->mysql);
				detected_broken_connection(__FILE__ , __LINE__ , __func__ , "during ping", myconn, myerr, mysql_error(myconn->mysql) , true);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::mysql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myerr);
			}
			myds->destroy_MySQL_Connection_From_Pool(false);
			myds->fd=0;
			delete mybe->server_myds;
			mybe->server_myds=NULL;
			return -1;
		} else {
			// rc==1 , nothing to do for now
			if (myds->mypolls==NULL) {
				thread->mypolls.add(POLLIN|POLLOUT, myds->fd, myds, thread->curtime);
			}
		}
	}
	return 0;
}

/**
 * @brief Handles the process of resetting the connection in the RESETTING_CONNECTION status.
 *
 * The handler_again___status_RESETTING_CONNECTION() function manages the resetting of the connection when
 * the session status is set to RESETTING_CONNECTION. It asserts the existence of the server connection's data stream
 * and connection. It then performs an asynchronous change user operation on the server connection and processes the result.
 * Depending on the result of the change user operation, it either returns -1 to indicate termination or continues with further actions.
 *
 * @return -1 if the session should be terminated, 0 otherwise.
 *
 * @see MySQL_Session::mybe
 * @see MySQL_Backend::server_myds
 * @see MySQL_Data_Stream
 * @see MySQL_Connection
 * @see MySQL_Connection::async_change_user()
 * @see MySQL_Data_Stream::return_MySQL_Connection_To_Pool()
 * @see MySQL_Session::set_status()
 * @see ProxySQL_MySQL_Error_Counter::p_update_mysql_error_counter()
 */
int MySQL_Session::handler_again___status_RESETTING_CONNECTION() {
	assert(mybe->server_myds->myconn);
	MySQL_Data_Stream *myds=mybe->server_myds;
	MySQL_Connection *myconn=myds->myconn;
	if (myds->mypolls==NULL) {
		thread->mypolls.add(POLLIN|POLLOUT, myds->fd, myds, thread->curtime);
	}
	myds->DSS=STATE_MARIADB_QUERY;
	// we recreate local_stmts : see issue #752
	delete myconn->local_stmts;
	myconn->local_stmts=new MySQL_STMTs_local_v14(false); // false by default, it is a backend
	int rc=myconn->async_change_user(myds->revents);
	if (rc==0) {
		__sync_fetch_and_add(&MyHGM->status.backend_change_user, 1);
		//myds->myconn->userinfo->set(client_myds->myconn->userinfo);
		myds->myconn->reset();
		myds->DSS = STATE_MARIADB_GENERIC;
		myconn->async_state_machine=ASYNC_IDLE;
//		if (mysql_thread___multiplexing && (myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
			myds->return_MySQL_Connection_To_Pool();
//		} else {
//			myds->destroy_MySQL_Connection_From_Pool(true);
//		}
		delete mybe->server_myds;
		mybe->server_myds=NULL;
		set_status(session_status___NONE);
		return -1;
	} else {
		if (rc==-1 || rc==-2) {
			if (rc==-2) {
				proxy_error("Change user timeout during COM_CHANGE_USER on %s , %d\n", myconn->parent->address, myconn->parent->port);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::mysql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, ER_PROXYSQL_CHANGE_USER_TIMEOUT);
			} else { // rc==-1
				int myerr=mysql_errno(myconn->mysql);
				MyHGM->p_update_mysql_error_counter(
					p_mysql_error_type::mysql,
					myconn->parent->myhgc->hid,
					myconn->parent->address,
					myconn->parent->port,
					( myerr ? myerr : ER_PROXYSQL_OFFLINE_SRV )
				);
				if (myerr != 0) {
					proxy_warning("Detected an error during COM_CHANGE_USER on (%d,%s,%d) , FD (Conn:%d , MyDS:%d) : %d, %s\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myds->fd, myds->myconn->fd, myerr, mysql_error(myconn->mysql));
				} else {
					proxy_warning(
						"Detected an error during COM_CHANGE_USER on (%d,%s,%d) , FD (Conn:%d , MyDS:%d) : %d, %s\n",
						myconn->parent->myhgc->hid,
						myconn->parent->address,
						myconn->parent->port,
						myds->fd,
						myds->myconn->fd,
						ER_PROXYSQL_OFFLINE_SRV,
						"Detected offline server prior to statement execution"
					);
				}
			}
			myds->destroy_MySQL_Connection_From_Pool(false);
			myds->fd=0;
			//delete mybe->server_myds;
			//mybe->server_myds=NULL;
			RequestEnd(myds); //fix bug #682
			return -1;
		} else {
			// rc==1 , nothing to do for now
			if (myds->mypolls==NULL) {
				thread->mypolls.add(POLLIN|POLLOUT, myds->fd, myds, thread->curtime);
			}
		}
	}
	return 0;
}

/**
 * @brief Initiates a new thread to kill the connection associated with the session.
 *
 * The handler_again___new_thread_to_kill_connection() function creates a new thread to execute the query
 * needed to kill the connection associated with the session. It first retrieves the data stream of the server connection.
 * If the connection exists and is associated with a MySQL instance, and if it has not been marked for killing before,
 * the function prepares the necessary information for the kill operation and spawns a new thread to execute it.
 * The kill operation is performed asynchronously in the new thread.
 *
 * @note This function is used to handle the situation where the session is in the process of resetting the connection,
 * and the connection needs to be forcibly terminated.
 *
 * @see MySQL_Session::mybe
 * @see MySQL_Backend::server_myds
 * @see MySQL_Data_Stream
 * @see MySQL_Connection
 * @see MySQL_Connection_userinfo
 * @see KillArgs
 * @see kill_query_thread
 */
void MySQL_Session::handler_again___new_thread_to_kill_connection() {
	MySQL_Data_Stream *myds=mybe->server_myds;
	if (myds->myconn && myds->myconn->mysql) {
		if (myds->killed_at==0) {
			myds->wait_until=0;
			myds->killed_at=thread->curtime;
			//fprintf(stderr,"Expired: %llu, %llu\n", mybe->server_myds->wait_until, thread->curtime);
			MySQL_Connection_userinfo *ui=client_myds->myconn->userinfo;
			char *auth_password=NULL;
			if (ui->password) {
				if (ui->password[0]=='*') { // we don't have the real password, let's pass sha1
					auth_password=ui->sha1_pass;
				} else {
					auth_password=ui->password;
				}
			}

			KillArgs *ka = new KillArgs(ui->username, auth_password, myds->myconn->parent->address, myds->myconn->parent->port, myds->myconn->parent->myhgc->hid, myds->myconn->mysql->thread_id, KILL_QUERY, myds->myconn->parent->use_ssl, thread, myds->myconn->connected_host_details.ip);
			pthread_attr_t attr;
			pthread_attr_init(&attr);
			pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
			pthread_attr_setstacksize (&attr, 256*1024);
			pthread_t pt;
			if (pthread_create(&pt, &attr, &kill_query_thread, ka) != 0) {
				// LCOV_EXCL_START
				proxy_error("Thread creation\n");
				assert(0);
				// LCOV_EXCL_STOP
			}
		}
	}
}

// NEXT_IMMEDIATE is a legacy macro used inside handler() to immediately jump
// to handler_again
#define NEXT_IMMEDIATE(new_st) do { set_status(new_st); goto handler_again; } while (0)
// NEXT_IMMEDIATE_NEW is a new macro to use *outside* handler().
// handler() should check the return code of the function it calls, and if
// true should jump to handler_again
#define NEXT_IMMEDIATE_NEW(new_st) do { set_status(new_st); return true; } while (0)

/**
 * @brief Verifies and synchronizes the multi-statement capability between client and server connections.
 *
 * The handler_again___verify_backend_multi_statement() function verifies whether the multi-statement capability
 * of the client connection matches that of the server connection. If there is a mismatch, it synchronizes the
 * capability by updating the server connection's options accordingly.
 *
 * @return Always returns false.
 *
 * @see MySQL_Session::client_myds
 * @see MySQL_Session::mybe
 * @see MySQL_Data_Stream
 * @see MySQL_Connection
 */
bool MySQL_Session::handler_again___verify_backend_multi_statement() {
	if ((client_myds->myconn->options.client_flag & CLIENT_MULTI_STATEMENTS) != (mybe->server_myds->myconn->options.client_flag & CLIENT_MULTI_STATEMENTS)) {

		if (client_myds->myconn->options.client_flag & CLIENT_MULTI_STATEMENTS)
			mybe->server_myds->myconn->options.client_flag |= CLIENT_MULTI_STATEMENTS;
		else
			mybe->server_myds->myconn->options.client_flag &= ~CLIENT_MULTI_STATEMENTS;

		// Sets the previous status of the MySQL session according to the current status.
		set_previous_status_mode3();
		NEXT_IMMEDIATE_NEW(SETTING_MULTI_STMT);
	}
	return false;
}

/**
 * @brief Sets the previous status of the MySQL session according to the current status, with an option to allow EXECUTE statements.
 *
 * This method updates the previous status of the MySQL session based on its current status. It employs a switch statement
 * to determine the current status and then pushes the corresponding status value onto the `previous_status` stack. If the
 * `allow_execute` parameter is set to true and the current status is `PROCESSING_STMT_EXECUTE`, the method pushes this status
 * onto the stack; otherwise, it skips pushing the status for EXECUTE statements. If the current status does not match any known
 * status value (which should not occur under normal circumstances), the method asserts to indicate a programming error.
 * It currently works with only 3 possible status:
 * - PROCESSING_QUERY
 * - PROCESSING_STMT_PREPARE
 * - PROCESSING_STMT_EXECUTE
 *
 * @param allow_execute A boolean value indicating whether to allow the status of EXECUTE statements to be pushed onto the
 * `previous_status` stack. If set to true, the method will include EXECUTE statements in the session's status history.
 *
 * @return void.
 * @note This method assumes that the `status` member variable has been properly initialized with one of the predefined
 * status values.
 * @note This method is primarily used to maintain a history of the session's previous states for later reference or
 * recovery purposes.
 * @note The LCOV_EXCL_START and LCOV_EXCL_STOP directives are used to exclude the assert statement from code coverage
 * analysis because the condition should not occur during normal execution and is included as a safeguard against
 * programming errors.
 */
void MySQL_Session::set_previous_status_mode3(bool allow_execute) {
	switch(status) {
		case PROCESSING_QUERY:
			previous_status.push(PROCESSING_QUERY);
			break;
		case PROCESSING_STMT_PREPARE:
			previous_status.push(PROCESSING_STMT_PREPARE);
			break;
		case PROCESSING_STMT_EXECUTE:
			if (allow_execute == true) {
				previous_status.push(PROCESSING_STMT_EXECUTE);
				break;
			}
		default:
			// LCOV_EXCL_START
			assert(0); // Assert to indicate an unexpected status value
			break;
			// LCOV_EXCL_STOP
	}
}

/**
 * @brief Verifies and sets the init_connect option for the server connection.
 *
 * The handler_again___verify_init_connect() function checks if the init_connect option has been sent
 * to the server connection. If not, it sets the option to true and sets the init_connect queries
 * based on the attributes defined for the hostgroup. It then updates the status for handling the
 * init_connect setting.
 *
 * @return Always returns false.
 *
 * @see MySQL_Session::mybe
 * @see MySQL_Data_Stream
 * @see MySQL_Connection
 */
bool MySQL_Session::handler_again___verify_init_connect() {
	if (mybe->server_myds->myconn->options.init_connect_sent==false) {
		// we needs to set it to true
		mybe->server_myds->myconn->options.init_connect_sent=true;
		char * tmp_init_connect = mysql_thread___init_connect;
		char * init_connect_hg = mybe->server_myds->myconn->parent->myhgc->attributes.init_connect;
		if (init_connect_hg != NULL && strlen(init_connect_hg) != 0) {
			// mysql_hostgroup_attributes takes priority
			tmp_init_connect = init_connect_hg;
		}
		if (tmp_init_connect) {
			// we send init connect queries only if set
			mybe->server_myds->myconn->options.init_connect=strdup(tmp_init_connect);
			// Sets the previous status of the MySQL session according to the current status.
			set_previous_status_mode3();
			NEXT_IMMEDIATE_NEW(SETTING_INIT_CONNECT);
		}
	}
	return false;
}

/**
 * @brief Verifies and sets the session_track_gtids option for the backend connection.
 *
 * The handler_again___verify_backend_session_track_gtids() function verifies whether the backend
 * connection supports session_track_gtids and sets the option accordingly based on the client's
 * request. If the backend does not support session_track_gtids, the function returns false.
 * If the backend supports session_track_gtids, it sets the option to OWN_GTID if the client
 * requests GTIDs or if the option is not configured yet. Otherwise, it sets the option to OFF.
 * The function then updates the backend's session_track_gtids setting and switches the status
 * to handle the session_track_gtids setting.
 *
 * @return True if the session_track_gtids option is set for the backend connection, false otherwise.
 *
 * @see MySQL_Session::mybe
 * @see MySQL_Data_Stream
 * @see MySQL_Connection
 */
bool MySQL_Session::handler_again___verify_backend_session_track_gtids() {
	bool ret = false;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , client: %s , backend: %s\n", this, client_myds->myconn->options.session_track_gtids, mybe->server_myds->myconn->options.session_track_gtids);
	// we first verify that the backend supports it
	// if backend is old (or if it is not mysql) ignore this setting
	if ((mybe->server_myds->myconn->mysql->server_capabilities & CLIENT_SESSION_TRACKING) == 0) {
		// the backend doesn't support CLIENT_SESSION_TRACKING
		return ret; // exit immediately
	}
	uint32_t b_int = mybe->server_myds->myconn->options.session_track_gtids_int;
	uint32_t f_int = client_myds->myconn->options.session_track_gtids_int;

	// we need to precompute and hardcode the values for OFF and OWN_GTID
	// for performance reason we hardcoded the values
	// OFF = 114160514
	if (
		(b_int == 114160514) // OFF
		||
		(b_int == 0) // not configured yet
	) {
		if (strcmp(mysql_thread___default_session_track_gtids, (char *)"OWN_GTID")==0) {
			// backend connection doesn't have session_track_gtids enabled
			ret = true;
		} else {
			if (f_int != 0 && f_int != 114160514) {
				// client wants GTID
				ret = true;
			}
		}
	}

	if (ret) {
		// we deprecated handler_again___verify_backend__generic_variable
		// and moved the logic here
		if (mybe->server_myds->myconn->options.session_track_gtids) { // reset current value
			free(mybe->server_myds->myconn->options.session_track_gtids);
			mybe->server_myds->myconn->options.session_track_gtids = NULL;
		}
		// because the only two possible values are OWN_GTID and OFF
		// and because we don't mind receiving GTIDs , if we reach here
		// it means we are setting it to OWN_GTID, either because the client
		// wants it, or because it is the default
		// therefore we hardcode "OWN_GTID"
		mybe->server_myds->myconn->options.session_track_gtids = strdup((char *)"OWN_GTID");
		mybe->server_myds->myconn->options.session_track_gtids_int =
			SpookyHash::Hash32((char *)"OWN_GTID", strlen((char *)"OWN_GTID"), 10);
		// we now switch status to set session_track_gtids
		// Sets the previous status of the MySQL session according to the current status.
		set_previous_status_mode3();
		NEXT_IMMEDIATE_NEW(SETTING_SESSION_TRACK_GTIDS);
	}
	return ret;
}


bool MySQL_Session::handler_again___verify_multiple_variables(MySQL_Connection* myconn) {
	for (auto i = 0; i < SQL_NAME_LAST_LOW_WM; i++) {
		auto client_hash = client_myds->myconn->var_hash[i];
#ifdef DEBUG
		if (GloVars.global.gdbg) {
			switch (i) {
				case SQL_CHARACTER_SET:
				case SQL_SET_NAMES:
				case SQL_CHARACTER_SET_RESULTS:
				case SQL_CHARACTER_SET_CONNECTION:
				case SQL_CHARACTER_SET_CLIENT:
				case SQL_COLLATION_CONNECTION:
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Session %p , variable %s has value %s\n" , this, mysql_tracked_variables[i].set_variable_name , client_myds->myconn->variables[i].value);
				default:
					break;
			}
		}
#endif // DEBUG
		if (client_hash) {
			auto server_hash = myconn->var_hash[i];
			if (client_hash != server_hash) {
				if(!myconn->var_absent[i] && mysql_variables.verify_variable(this, i)) {
					return true;
				}
			}
		}
	}
	MySQL_Connection *c_con = client_myds->myconn;
	vector<uint32_t>::const_iterator it_c = c_con->dynamic_variables_idx.begin();  // client connection iterator
	for ( ; it_c != c_con->dynamic_variables_idx.end() ; it_c++) {
		auto i = *it_c;
		auto client_hash = c_con->var_hash[i];
		auto server_hash = myconn->var_hash[i];
		if (client_hash != server_hash) {
			if(
				!myconn->var_absent[i]
				&&
				mysql_variables.verify_variable(this, i)
			) {
				return true;
			}
		}
	}
	return false;
}


/**
 * @brief Verifies and sets the ldap_user_variable option for the backend connection.
 *
 * The handler_again___verify_ldap_user_variable() function verifies whether the ldap_user_variable
 * option needs to be set for the backend connection. If the ldap_user_variable_sent flag is false
 * or if ldap_user_variable_value is NULL, the function sets the option to true. If the backend
 * connection already has ldap_user_variable_sent set to true and the ldap_user_variable_value
 * differs from the client's frontend username, the function resets the ldap_user_variable settings
 * and sets the option to true. Finally, if the option needs to be set, the function updates the
 * backend's ldap_user_variable settings and switches the status to handle the ldap_user_variable setting.
 *
 * @return Always returns false.
 *
 * @see MySQL_Session::mybe
 * @see MySQL_Data_Stream
 * @see MySQL_Connection
 */
bool MySQL_Session::handler_again___verify_ldap_user_variable() {
	bool ret = false;
	if (mybe->server_myds->myconn->options.ldap_user_variable_sent==false) {
		ret = true;
	}
	if (mybe->server_myds->myconn->options.ldap_user_variable_value == NULL) {
		ret = true;
	}
	if (ret==false) {
		if (mybe->server_myds->myconn->options.ldap_user_variable_sent) {
			if (client_myds && client_myds->myconn) {
				if (client_myds->myconn->userinfo) {
					if (client_myds->myconn->userinfo->fe_username) {
		 				if (strcmp(mybe->server_myds->myconn->options.ldap_user_variable_value,client_myds->myconn->userinfo->fe_username)) {
							ret = true;
							free(mybe->server_myds->myconn->options.ldap_user_variable);
							mybe->server_myds->myconn->options.ldap_user_variable = NULL;
							free(mybe->server_myds->myconn->options.ldap_user_variable_value);
							mybe->server_myds->myconn->options.ldap_user_variable_value = NULL;
							mybe->server_myds->myconn->options.ldap_user_variable_sent = false;
						}
					}
				}
			}
		}
	}
	if (ret) {
		// we needs to set it to true
		mybe->server_myds->myconn->options.ldap_user_variable_sent=true;
		if (mysql_thread___ldap_user_variable) {
			// we send ldap user variable  query only if set
			mybe->server_myds->myconn->options.ldap_user_variable=strdup(mysql_thread___ldap_user_variable);
			// Sets the previous status of the MySQL session according to the current status.
			set_previous_status_mode3();
			NEXT_IMMEDIATE_NEW(SETTING_LDAP_USER_VARIABLE);
		}
	}
	return false;
}

bool MySQL_Session::handler_again___verify_backend_autocommit() {
	if (sending_set_autocommit) {
		// if sending_set_autocommit==true, the next query proxysql is going
		// to run defines autocommit, for example:
		// * SET autocommit=1 , or
		// * SET sql_mode='', autocommit=1
		// for this reason, matching autocommit beforehand is not required
		// and we return
		//
		// Nonetheless, we need to set autocommit in backend's MySQL_Connection
		MySQL_Connection *mc = mybe->server_myds->myconn;
		mc->set_autocommit(autocommit);
		mc->options.last_set_autocommit = ( mc->options.autocommit ? 1 : 0 );
		if (autocommit==1) {
			// due to  MySQL bug https://bugs.mysql.com/bug.php?id=107875 related to
			// SAVEPOINT and autocommit=0 , if we send autocommit=1 we need to drop
			// the flag related to savepoint
			mc->set_status(false, STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT);
		}
		return false;
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , client: %d , backend: %d\n", this, client_myds->myconn->options.autocommit, mybe->server_myds->myconn->options.autocommit);
	if (autocommit != mybe->server_myds->myconn->IsAutoCommit()) {
		// see case #485
		if (mysql_thread___enforce_autocommit_on_reads == false && autocommit == false) {
			// enforce_autocommit_on_reads is disabled
			// we need to check if it is a SELECT not FOR UPDATE
			if (CurrentQuery.is_select_NOT_for_update()==false) {
				// Sets the previous status of the MySQL session according to the current status.
				set_previous_status_mode3();
				NEXT_IMMEDIATE_NEW(CHANGING_AUTOCOMMIT);
			}
		} else {
			// in every other cases, enforce autocommit
			// Sets the previous status of the MySQL session according to the current status.
			set_previous_status_mode3();
			NEXT_IMMEDIATE_NEW(CHANGING_AUTOCOMMIT);
		}
	} else {
		if (autocommit == false) { // also IsAutoCommit==false
			if (mysql_thread___enforce_autocommit_on_reads == false) {
				if (
					mybe->server_myds->myconn->IsActiveTransaction() == false
					&&
					// another edge case related to MySQL bug https://bugs.mysql.com/bug.php?id=107875
					// about autocommit=0 and SAVEPOINT
					mybe->server_myds->myconn->AutocommitFalse_AndSavepoint() == false
				) {
					if (CurrentQuery.is_select_NOT_for_update()==true) {
						// client wants autocommit=0
						// enforce_autocommit_on_reads=false
						// there is no transaction
						// this seems to be the first query, and a SELECT not FOR UPDATE
						// we will switch back to autcommit=1
						if (status == PROCESSING_QUERY) {
							previous_status.push(PROCESSING_QUERY);
							NEXT_IMMEDIATE_NEW(CHANGING_AUTOCOMMIT);
						}
					}
				}
			} else { // mysql_thread___enforce_autocommit_on_reads == true
				// this code seems wrong. Removed
/*
				if (mybe->server_myds->myconn->IsActiveTransaction() == false) {
					if (status == PROCESSING_QUERY) {
						previous_status.push(PROCESSING_QUERY);
						NEXT_IMMEDIATE_NEW(CHANGING_AUTOCOMMIT);
					}
				}
*/
			}
		}
	}
	return false;
}

bool MySQL_Session::handler_again___verify_backend_user_schema() {
	MySQL_Data_Stream *myds=mybe->server_myds;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , client: %s , backend: %s\n", this, client_myds->myconn->userinfo->username, mybe->server_myds->myconn->userinfo->username);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , client: %s , backend: %s\n", this, client_myds->myconn->userinfo->schemaname, mybe->server_myds->myconn->userinfo->schemaname);
	if (client_myds->myconn->userinfo->hash!=mybe->server_myds->myconn->userinfo->hash) {
		if (strcmp(client_myds->myconn->userinfo->username,myds->myconn->userinfo->username)) {
			// Sets the previous status of the MySQL session according to the current status.
			set_previous_status_mode3();
			mybe->server_myds->wait_until = thread->curtime + mysql_thread___connect_timeout_server*1000;   // max_timeout
			NEXT_IMMEDIATE_NEW(CHANGING_USER_SERVER);
		}
		if (strcmp(client_myds->myconn->userinfo->schemaname,myds->myconn->userinfo->schemaname)) {
			// Sets the previous status of the MySQL session according to the current status.
			set_previous_status_mode3();
			NEXT_IMMEDIATE_NEW(CHANGING_SCHEMA);
		}
	}
	// if we reach here, the username is the same
	if (myds->myconn->requires_CHANGE_USER(client_myds->myconn)) {
		// if we reach here, even if the username is the same,
		// the backend connection has some session variable set
		// that the client never asked for
		// because we can't unset variables, we will reset the connection

		// Sets the previous status of the MySQL session according to the current status.
		set_previous_status_mode3();
		mybe->server_myds->wait_until = thread->curtime + mysql_thread___connect_timeout_server*1000;   // max_timeout
		NEXT_IMMEDIATE_NEW(CHANGING_USER_SERVER);
	}
	return false;
}

bool MySQL_Session::handler_again___status_SETTING_INIT_CONNECT(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	MySQL_Data_Stream *myds=mybe->server_myds;
	MySQL_Connection *myconn=myds->myconn;
	myds->DSS=STATE_MARIADB_QUERY;
	enum session_status st=status;
	if (myds->mypolls==NULL) {
		thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
	}
	int rc=myconn->async_send_simple_command(myds->revents,myconn->options.init_connect,strlen(myconn->options.init_connect));
	if (rc==0) {
		myds->revents|=POLLOUT;	// we also set again POLLOUT to send a query immediately!
		//myds->free_mysql_real_query();
		myds->DSS = STATE_MARIADB_GENERIC;
		st=previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1 || rc==-2) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			MyHGM->p_update_mysql_error_counter(
				p_mysql_error_type::mysql,
				myconn->parent->myhgc->hid,
				myconn->parent->address,
				myconn->parent->port,
				( myerr ? myerr : ER_PROXYSQL_OFFLINE_SRV )
			);
			if (myerr >= 2000 || myerr == 0) {
				bool retry_conn=false;
				// client error, serious
				detected_broken_connection(__FILE__ , __LINE__ , __func__ , "while setting INIT CONNECT", myconn, myerr, mysql_error(myconn->mysql));
							//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
							if (rc != -2) { // see PMC-10003
								if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
									retry_conn=true;
							}
				}
				myds->destroy_MySQL_Connection_From_Pool(false);
				myds->fd=0;
				if (rc==-2) {
					// Here we handle PMC-10003
					// and we terminate the session
					retry_conn=false;
				}
				if (retry_conn) {
					myds->DSS=STATE_NOT_INITIALIZED;
					//previous_status.push(PROCESSING_QUERY);
					NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
				}
				*_rc=-1;	// an error happened, we should destroy the Session
				return ret;
			} else {
				proxy_warning("Error while setting INIT CONNECT on %s:%d hg %d : %d, %s\n", myconn->parent->address, myconn->parent->port, current_hostgroup, myerr, mysql_error(myconn->mysql));
					// we won't go back to PROCESSING_QUERY
				st=previous_status.top();
				previous_status.pop();
				char sqlstate[10];
				sprintf(sqlstate,"%s",mysql_sqlstate(myconn->mysql));
				client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql));
					myds->destroy_MySQL_Connection_From_Pool(true);
					myds->fd=0;
				status=WAITING_CLIENT_DATA;
				client_myds->DSS=STATE_SLEEP;
			}
		} else {
			// rc==1 , nothing to do for now
		}
	}
	return ret;
}

bool MySQL_Session::handler_again___status_SETTING_LDAP_USER_VARIABLE(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	MySQL_Data_Stream *myds=mybe->server_myds;
	MySQL_Connection *myconn=myds->myconn;
	myds->DSS=STATE_MARIADB_QUERY;
	enum session_status st=status;

	if (
		(GloMyLdapAuth==NULL) || (use_ldap_auth==false)
		||
		(client_myds==NULL || client_myds->myconn==NULL || client_myds->myconn->userinfo==NULL)
	) { // nothing to do
		myds->revents|=POLLOUT;	// we also set again POLLOUT to send a query immediately!
		//myds->free_mysql_real_query();
		myds->DSS = STATE_MARIADB_GENERIC;
		st=previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	}

	if (myds->mypolls==NULL) {
		thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
	}
	int rc;
	if (myconn->async_state_machine == ASYNC_IDLE) {
		char *fe=client_myds->myconn->userinfo->fe_username;
		char *a = (char *)"SET @%s:='%s'";
		if (fe == NULL) {
			fe = (char *)"unknown";
		}
		if (myconn->options.ldap_user_variable_value) {
			free(myconn->options.ldap_user_variable_value);
		}
		myconn->options.ldap_user_variable_value = strdup(fe);
		char *buf = (char *)malloc(strlen(fe)+strlen(a)+strlen(myconn->options.ldap_user_variable));
		sprintf(buf,a,myconn->options.ldap_user_variable,fe);
		rc = myconn->async_send_simple_command(myds->revents,buf,strlen(buf));
		free(buf);
	} else { // if async_state_machine is not ASYNC_IDLE , arguments are ignored
		rc = myconn->async_send_simple_command(myds->revents,(char *)"", 0);
	}
	if (rc==0) {
		myds->revents|=POLLOUT;	// we also set again POLLOUT to send a query immediately!
		//myds->free_mysql_real_query();
		myds->DSS = STATE_MARIADB_GENERIC;
		st=previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			MyHGM->p_update_mysql_error_counter(
				p_mysql_error_type::mysql,
				myconn->parent->myhgc->hid,
				myconn->parent->address,
				myconn->parent->port,
				( myerr ? myerr : ER_PROXYSQL_OFFLINE_SRV )
			);
			if (myerr >= 2000 || myerr == 0) {
				bool retry_conn=false;
				// client error, serious
				detected_broken_connection(__FILE__ , __LINE__ , __func__ , "while setting LDAP USER VARIABLE", myconn, myerr, mysql_error(myconn->mysql));
				if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
					retry_conn=true;
				}
				myds->destroy_MySQL_Connection_From_Pool(false);
				myds->fd=0;
				if (retry_conn) {
					myds->DSS=STATE_NOT_INITIALIZED;
					NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
				}
				*_rc=-1;	// an error happened, we should destroy the Session
				return ret;
			} else {
				proxy_warning("Error while setting LDAP USER VARIABLE: %s:%d hg %d : %d, %s\n", myconn->parent->address, myconn->parent->port, current_hostgroup, myerr, mysql_error(myconn->mysql));
				// we won't go back to PROCESSING_QUERY
				st=previous_status.top();
				previous_status.pop();
				char sqlstate[10];
				sprintf(sqlstate,"%s",mysql_sqlstate(myconn->mysql));
				client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql));
				myds->destroy_MySQL_Connection_From_Pool(true);
				myds->fd=0;
				status=WAITING_CLIENT_DATA;
				client_myds->DSS=STATE_SLEEP;
			}
		} else {
			// rc==1 , nothing to do for now
		}
	}
	return ret;
}

bool MySQL_Session::handler_again___status_SETTING_SQL_LOG_BIN(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	MySQL_Data_Stream *myds=mybe->server_myds;
	MySQL_Connection *myconn=myds->myconn;
	myds->DSS=STATE_MARIADB_QUERY;
	enum session_status st=status;
	if (myds->mypolls==NULL) {
		thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
	}
	char *query=NULL;
	unsigned long query_length=0;
	if (myconn->async_state_machine==ASYNC_IDLE) {
		char *q=(char *)"SET SQL_LOG_BIN=%s";
		query=(char *)malloc(strlen(q)+8);
		sprintf(query,q,mysql_variables.client_get_value(this, SQL_SQL_LOG_BIN));
		query_length=strlen(query);
	}
	int rc=myconn->async_send_simple_command(myds->revents,query,query_length);
	if (query) {
		free(query);
		query=NULL;
	}
	if (rc==0) {
		if (!strcmp("0", mysql_variables.client_get_value(this, SQL_SQL_LOG_BIN)) || !strcasecmp("OFF",  mysql_variables.client_get_value(this, SQL_SQL_LOG_BIN))) {
			// Pay attention here. STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0 sets sql_log_bin to ZERO:
			//   - sql_log_bin=0 => true
			//   - sql_log_bin=1 => false
			myconn->set_status(true, STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0);
		} else if (!strcmp("1", mysql_variables.client_get_value(this, SQL_SQL_LOG_BIN)) || !strcasecmp("ON",  mysql_variables.client_get_value(this, SQL_SQL_LOG_BIN))) {
			myconn->set_status(false, STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0);
		}
		myds->revents|=POLLOUT; // we also set again POLLOUT to send a query immediately!
		myds->DSS = STATE_MARIADB_GENERIC;
		st=previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			MyHGM->p_update_mysql_error_counter(
				p_mysql_error_type::mysql,
				myconn->parent->myhgc->hid,
				myconn->parent->address,
				myconn->parent->port,
				( myerr ? myerr : ER_PROXYSQL_OFFLINE_SRV )
			);
			if (myerr >= 2000 || myerr == 0) {
				bool retry_conn=false;
				// client error, serious
				detected_broken_connection(__FILE__ , __LINE__ , __func__ , "while setting SQL_LOG_BIN", myconn, myerr, mysql_error(myconn->mysql));
				if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
					retry_conn=true;
				}
				myds->destroy_MySQL_Connection_From_Pool(false);
				myds->fd=0;
				if (retry_conn) {
					myds->DSS=STATE_NOT_INITIALIZED;
					NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
				}
				*_rc=-1;        // an error happened, we should destroy the Session
				return ret;
			} else {
				proxy_warning("Error while setting SQL_LOG_BIN: %s:%d hg %d : %d, %s\n", myconn->parent->address, myconn->parent->port, current_hostgroup, myerr, mysql_error(myconn->mysql));
				// we won't go back to PROCESSING_QUERY
				st=previous_status.top();
				previous_status.pop();
				char sqlstate[10];
				sprintf(sqlstate,"%s",mysql_sqlstate(myconn->mysql));
				client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql));
				myds->destroy_MySQL_Connection_From_Pool(true);
				myds->fd=0;
				RequestEnd(myds);
			}
		} else {
			// rc==1 , nothing to do for now
		}
	}
	return ret;
}

bool MySQL_Session::handler_again___status_CHANGING_CHARSET(int *_rc) {
	assert(mybe->server_myds->myconn);
	MySQL_Data_Stream *myds=mybe->server_myds;
	MySQL_Connection *myconn=myds->myconn;

	/* Validate that server can support client's charset */
	if (!validate_charset(this, SQL_CHARACTER_SET_CLIENT, *_rc)) {
		return false;
	}

	myds->DSS=STATE_MARIADB_QUERY;
	enum session_status st=status;
	if (myds->mypolls==NULL) {
		thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
	}

	mysql_variables.client_set_value(this, SQL_CHARACTER_SET, mysql_variables.client_get_value(this, SQL_CHARACTER_SET_CLIENT));
	int charset = atoi(mysql_variables.client_get_value(this, SQL_CHARACTER_SET_CLIENT));
	int rc=myconn->async_set_names(myds->revents, charset);

	if (rc==0) {
		__sync_fetch_and_add(&MyHGM->status.backend_set_names, 1);
		myds->DSS = STATE_MARIADB_GENERIC;
		st=previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			MyHGM->p_update_mysql_error_counter(
				p_mysql_error_type::mysql,
				myconn->parent->myhgc->hid,
				myconn->parent->address,
				myconn->parent->port,
				( myerr ? myerr : ER_PROXYSQL_OFFLINE_SRV )
			);
			if (myerr >= 2000 || myerr == 0) {
				if (myerr == 2019) {
					proxy_error(
						"Client trying to set a charset/collation (%u) not supported by backend (%s:%d). Changing it to %s\n",
						charset, myconn->parent->address, myconn->parent->port, mysql_tracked_variables[SQL_CHARACTER_SET].default_value
					);
				}
				bool retry_conn=false;
				// client error, serious
				detected_broken_connection(__FILE__ , __LINE__ , __func__ , "during SET NAMES", myconn, myerr, mysql_error(myconn->mysql));
				if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
					retry_conn=true;
				}
				myds->destroy_MySQL_Connection_From_Pool(false);
				myds->fd=0;
				if (retry_conn) {
					myds->DSS=STATE_NOT_INITIALIZED;
					//previous_status.push(PROCESSING_QUERY);
					NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
				}
				*_rc=-1;
				return false;
			} else {
				proxy_warning("Error during SET NAMES: %d, %s\n", myerr, mysql_error(myconn->mysql));
				// we won't go back to PROCESSING_QUERY
				st=previous_status.top();
				previous_status.pop();
				char sqlstate[10];
				sprintf(sqlstate,"%s",mysql_sqlstate(myconn->mysql));
				client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql));
				myds->destroy_MySQL_Connection_From_Pool(true);
				myds->fd=0;
				RequestEnd(myds);
			}
		} else {
			// rc==1 , nothing to do for now
		}
	}
	return false;
}

bool MySQL_Session::handler_again___status_SETTING_GENERIC_VARIABLE(int *_rc, const char *var_name, const char *var_value, bool no_quote, bool set_transaction) {
	bool ret = false;
	assert(mybe->server_myds->myconn);
	MySQL_Data_Stream *myds=mybe->server_myds;
	MySQL_Connection *myconn=myds->myconn;
	myds->DSS=STATE_MARIADB_QUERY;
	enum session_status st=status;
	if (myds->mypolls==NULL) {
		thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
	}
	char *query=NULL;
	unsigned long query_length=0;
	if (myconn->async_state_machine==ASYNC_IDLE) {
		char *q = NULL;
		if (set_transaction==false) {
			if (no_quote) {
				q=(char *)"SET %s=%s";
			} else {
				q=(char *)"SET %s='%s'"; // default
				if (var_value[0] && var_value[0]=='@') {
					q=(char *)"SET %s=%s";}
				if (strncasecmp(var_value,(char *)"CONCAT",6)==0)
					q=(char *)"SET %s=%s";
				if (strncasecmp(var_value,(char *)"IFNULL",6)==0)
					q=(char *)"SET %s=%s";
				if (strncasecmp(var_value,(char *)"REPLACE",7)==0)
					q=(char *)"SET %s=%s";
				if (var_value[0] && var_value[0]=='(') { // the value is a subquery
					q=(char *)"SET %s=%s";
				}
			}
		} else {
			// NOTE: for now, only SET SESSION is supported
			// the calling function is already passing "SESSION TRANSACTION"
			q=(char *)"SET %s %s";
		}
		query=(char *)malloc(strlen(q)+strlen(var_name)+strlen(var_value));
		if (strncasecmp("tx_isolation", var_name, 12) == 0) {
			char *sv = mybe->server_myds->myconn->mysql->server_version;
			if (strncmp(sv,(char *)"8",1)==0) {
				sprintf(query,q,"transaction_isolation", var_value);
			} else {
				sprintf(query,q,"tx_isolation", var_value);
			}
		} else if (strncasecmp("tx_read_only", var_name, 12) == 0) {
			char* sv = mybe->server_myds->myconn->mysql->server_version;
			if (strncmp(sv, (char *)"8", 1) == 0) {
				sprintf(query,q,"transaction_read_only", var_value);
			} else {
				sprintf(query,q,"tx_read_only", var_value);
			}
		} else if (strncasecmp("aurora_read_replica_read_committed", var_name, 34) == 0) {
			// If aurora_read_replica_read_committed is set, isolation level is
			// internally reset so that it will be set again.
			// This solves the weird behavior in AWS Aurora related to isolation level
			// as described in
			// https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/AuroraMySQL.Reference.html#AuroraMySQL.Reference.IsolationLevels
			// Basically, to change isolation level you must first set
			// aurora_read_replica_read_committed , and then isolation level
			mysql_variables.server_reset_value(this, SQL_ISOLATION_LEVEL);
			sprintf(query,q,var_name, var_value);
		} else {
			sprintf(query,q,var_name, var_value);
		}
		query_length=strlen(query);
	}
	int rc=myconn->async_send_simple_command(myds->revents,query,query_length);
	if (query) {
		free(query);
		query=NULL;
	}
	if (rc==0) {
		myds->revents|=POLLOUT;	// we also set again POLLOUT to send a query immediately!
		myds->DSS = STATE_MARIADB_GENERIC;
		st=previous_status.top();
		previous_status.pop();

		if (strcasecmp("transaction isolation level", var_name) == 0) {
			mysql_variables.server_reset_value(this, SQL_NEXT_ISOLATION_LEVEL);
			mysql_variables.client_reset_value(this, SQL_NEXT_ISOLATION_LEVEL);
		} else if (strcasecmp("transaction read", var_name) == 0) {
			mysql_variables.server_reset_value(this, SQL_NEXT_TRANSACTION_READ);
			mysql_variables.client_reset_value(this, SQL_NEXT_TRANSACTION_READ);
		}

		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			MyHGM->p_update_mysql_error_counter(
				p_mysql_error_type::mysql,
				myconn->parent->myhgc->hid,
				myconn->parent->address,
				myconn->parent->port,
				( myerr ? myerr : ER_PROXYSQL_OFFLINE_SRV )
			);
			if (myerr >= 2000 || myerr == 0) {
				bool retry_conn=false;
				// client error, serious
				std::string action = "while setting ";
				action += var_name;
				detected_broken_connection(__FILE__ , __LINE__ , __func__ , action.c_str(), myconn, myerr, mysql_error(myconn->mysql));
				//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
				if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
					retry_conn=true;
				}
				myds->destroy_MySQL_Connection_From_Pool(false);
				myds->fd=0;
				if (retry_conn) {
					myds->DSS=STATE_NOT_INITIALIZED;
					NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
				}
				*_rc=-1;	// an error happened, we should destroy the Session
				return ret;
			} else {
				proxy_warning("Error while setting %s to \"%s\" on %s:%d hg %d :  %d, %s\n", var_name, var_value, myconn->parent->address, myconn->parent->port, current_hostgroup, myerr, mysql_error(myconn->mysql));
				if (
					(myerr == 1064) // You have an error in your SQL syntax
					||
					(myerr == 1193) // variable is not found
					||
					(myerr == 1651) // Query cache is disabled
					||
					(is_perm_track_err(myerr, var_name)) // Special permitted tracking errors (~= '1193')
				) {
					int idx = SQL_NAME_LAST_HIGH_WM;
					for (int i=0; i<SQL_NAME_LAST_HIGH_WM; i++) {
						if (strcasecmp(mysql_tracked_variables[i].set_variable_name, var_name) == 0) {
							idx = i;
							break;
						}
					}
					if (idx != SQL_NAME_LAST_LOW_WM) {
						myconn->var_absent[idx] = true;

						myds->myconn->async_free_result();
						myconn->compute_unknown_transaction_status();

						myds->revents|=POLLOUT;	// we also set again POLLOUT to send a query immediately!
						myds->DSS = STATE_MARIADB_GENERIC;
						st=previous_status.top();
						previous_status.pop();
						NEXT_IMMEDIATE_NEW(st);
					}
				}

				// we won't go back to PROCESSING_QUERY
				st=previous_status.top();
				previous_status.pop();
				char sqlstate[10];
				sprintf(sqlstate,"%s",mysql_sqlstate(myconn->mysql));
				client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql));
				int myerr=mysql_errno(myconn->mysql);
				switch (myerr) {
					case 1231:
/*
						too complicated code?
						if (mysql_thread___multiplexing && (myconn->reusable==true) && myconn->IsActiveTransaction()==false && myconn->MultiplexDisabled()==false) {
							myds->DSS=STATE_NOT_INITIALIZED;
							if (mysql_thread___autocommit_false_not_reusable && myconn->IsAutoCommit()==false) {
								if (mysql_thread___reset_connection_algorithm == 2) {
									create_new_session_and_reset_connection(myds);
								} else {
									myds->destroy_MySQL_Connection_From_Pool(true);
								}
							} else {
								myds->return_MySQL_Connection_To_Pool();
							}
						} else {
							myconn->async_state_machine=ASYNC_IDLE;
							myds->DSS=STATE_MARIADB_GENERIC;
						}
						break;
*/
					default:
						myds->destroy_MySQL_Connection_From_Pool(true);
						break;
				}
				myds->fd=0;
				RequestEnd(myds);
				ret=true;
			}
		} else {
			// rc==1 , nothing to do for now
		}
	}
	return ret;
}

bool MySQL_Session::handler_again___status_SETTING_MULTI_STMT(int *_rc) {
	assert(mybe->server_myds->myconn);
	MySQL_Data_Stream *myds=mybe->server_myds;
	MySQL_Connection *myconn=myds->myconn;
	enum session_status st=status;
	bool ret = false;

	if (myds->mypolls==NULL) {
		thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
	}
	int rc=myconn->async_set_option(myds->revents, myconn->options.client_flag & CLIENT_MULTI_STATEMENTS);
	if (rc==0) {
		myds->DSS = STATE_MARIADB_GENERIC;
		st=previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			MyHGM->p_update_mysql_error_counter(
				p_mysql_error_type::mysql,
				myconn->parent->myhgc->hid,
				myconn->parent->address,
				myconn->parent->port,
				( myerr ? myerr : ER_PROXYSQL_OFFLINE_SRV )
			);
			if (myerr >= 2000 || myerr == 0) {
				bool retry_conn=false;
				// client error, serious
				detected_broken_connection(__FILE__ , __LINE__ , __func__ , "while setting MYSQL_OPTION_MULTI_STATEMENTS", myconn, myerr, mysql_error(myconn->mysql));
				//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
				if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
					retry_conn=true;
				}
				myds->destroy_MySQL_Connection_From_Pool(false);
				myds->fd=0;
				if (retry_conn) {
					myds->DSS=STATE_NOT_INITIALIZED;
					NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
				}
				*_rc=-1; // an error happened, we should destroy the Session
				return ret;
			} else {
				proxy_warning("Error during MYSQL_OPTION_MULTI_STATEMENTS : %d, %s\n", myerr, mysql_error(myconn->mysql));
				// we won't go back to PROCESSING_QUERY
				st=previous_status.top();
				previous_status.pop();
				char sqlstate[10];
				sprintf(sqlstate,"%s",mysql_sqlstate(myconn->mysql));
				client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql));
				myds->destroy_MySQL_Connection_From_Pool(true);
				myds->fd=0;
				RequestEnd(myds);
			}
		} else {
			// rc==1 , nothing to do for now
		}
	}
	return ret;
}

bool MySQL_Session::handler_again___status_SETTING_SESSION_TRACK_GTIDS(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	ret = handler_again___status_SETTING_GENERIC_VARIABLE(_rc, (char *)"SESSION_TRACK_GTIDS", mybe->server_myds->myconn->options.session_track_gtids, true);
	return ret;
}

bool MySQL_Session::handler_again___status_CHANGING_SCHEMA(int *_rc) {
	bool ret=false;
	//fprintf(stderr,"CHANGING_SCHEMA\n");
	assert(mybe->server_myds->myconn);
	MySQL_Data_Stream *myds=mybe->server_myds;
	MySQL_Connection *myconn=myds->myconn;
	myds->DSS=STATE_MARIADB_QUERY;
	enum session_status st=status;
	if (myds->mypolls==NULL) {
		thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
	}
	int rc=myconn->async_select_db(myds->revents);
	if (rc==0) {
		__sync_fetch_and_add(&MyHGM->status.backend_init_db, 1);
		myds->myconn->userinfo->set(client_myds->myconn->userinfo);
		myds->DSS = STATE_MARIADB_GENERIC;
		st=previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			MyHGM->p_update_mysql_error_counter(
				p_mysql_error_type::mysql,
				myconn->parent->myhgc->hid,
				myconn->parent->address,
				myconn->parent->port,
				( myerr ? myerr : ER_PROXYSQL_OFFLINE_SRV )
			);
			if (myerr >= 2000 || myerr == 0) {
				bool retry_conn=false;
				// client error, serious
				detected_broken_connection(__FILE__ , __LINE__ , __func__ , "during INIT_DB", myconn, myerr, mysql_error(myconn->mysql));
				//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
				if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
					retry_conn=true;
				}
				myds->destroy_MySQL_Connection_From_Pool(false);
				myds->fd=0;
				if (retry_conn) {
					myds->DSS=STATE_NOT_INITIALIZED;
					NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
				}
				*_rc=-1; // an error happened, we should destroy the Session
				return ret;
			} else {
				proxy_warning("Error during INIT_DB: %d, %s\n", myerr, mysql_error(myconn->mysql));
				// we won't go back to PROCESSING_QUERY
				st=previous_status.top();
				previous_status.pop();
				char sqlstate[10];
				sprintf(sqlstate,"%s",mysql_sqlstate(myconn->mysql));
				client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql));
				myds->destroy_MySQL_Connection_From_Pool(true);
				myds->fd=0;
				RequestEnd(myds);
			}
		} else {
			// rc==1 , nothing to do for now
		}
	}
	return false;
}


bool MySQL_Session::handler_again___status_CONNECTING_SERVER(int *_rc) {
	//fprintf(stderr,"CONNECTING_SERVER\n");
	unsigned long long curtime=monotonic_time();
	thread->atomic_curtime=curtime;
	if (mirror) {
		mybe->server_myds->connect_retries_on_failure=0; // no try for mirror
		mybe->server_myds->wait_until=thread->curtime+mysql_thread___connect_timeout_server*1000;
		pause_until=0;
	}
	if (mybe->server_myds->max_connect_time) {
		if (thread->curtime >= mybe->server_myds->max_connect_time) {
			if (mirror) {
				PROXY_TRACE();
			}

			string errmsg {};
			const string session_info { session_fast_forward ? "for 'fast_forward' session " : "" };
			const uint64_t query_time = (thread->curtime - CurrentQuery.start_time)/1000;

			string_format(
				"Max connect timeout reached while reaching hostgroup %d %safter %llums",
				errmsg, current_hostgroup, session_info.c_str(), query_time
			);

			if (thread) {
				thread->status_variables.stvar[st_var_max_connect_timeout_err]++;
			}
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,9001,(char *)"HY000", errmsg.c_str(), true);
			MyHGM->add_mysql_errors(current_hostgroup, (char *)"", 0, client_myds->myconn->userinfo->username, (client_myds->addr.addr ? client_myds->addr.addr : (char *)"unknown" ), client_myds->myconn->userinfo->schemaname, 9001, (char *)errmsg.c_str());
			RequestEnd(mybe->server_myds, 9001, errmsg.c_str());

			string hg_status {};
			generate_status_one_hostgroup(current_hostgroup, hg_status);
			proxy_error("%s . HG status: %s\n", errmsg.c_str(), hg_status.c_str());

			while (previous_status.size()) {
				previous_status.pop();
			}
			if (mybe->server_myds->myconn) {
				// NOTE-3404: Created connection never reached 'connect_cont' phase, due to that internal
				// structures of 'mysql->net' are not fully initialized.  This induces a leak of the 'fd'
				// associated with the socket opened by the library. To prevent this, we need to call
				// `mysql_real_connect_cont` through `connect_cont`. This way we ensure a proper cleanup of
				// all the resources when 'mysql_close' is later called. For more context see issue #3404.
				mybe->server_myds->myconn->connect_cont(MYSQL_WAIT_TIMEOUT);
				mybe->server_myds->destroy_MySQL_Connection_From_Pool(false);
				if (mirror) {
					PROXY_TRACE();
					NEXT_IMMEDIATE_NEW(WAITING_CLIENT_DATA);
				}
			}
			mybe->server_myds->max_connect_time=0;
			NEXT_IMMEDIATE_NEW(WAITING_CLIENT_DATA);
		}
	}
	if (mybe->server_myds->myconn==NULL) {
		handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection();
	}
	if (mybe->server_myds->myconn==NULL) {
		if (mirror) {
			PROXY_TRACE();
			NEXT_IMMEDIATE_NEW(WAITING_CLIENT_DATA);
		}
	}

	// NOTE-connect_retries_delay: This check alone is not enough for imposing
	// 'mysql_thread___connect_retries_delay'. In case of 'async_connect' failing, 'pause_until' should also
	// be set to 'mysql_thread___connect_retries_delay'. Complementary NOTE below.
	if (mybe->server_myds->myconn==NULL) {
		pause_until=thread->curtime+mysql_thread___connect_retries_delay*1000;
		*_rc=1;
		return false;
	} else {
		MySQL_Data_Stream *myds=mybe->server_myds;
		MySQL_Connection *myconn=myds->myconn;
		int rc;
		if (default_hostgroup<0) {
			// we are connected to a Admin module backend
			// we pretend to set a user variable to disable multiplexing
			myconn->set_status(true, STATUS_MYSQL_CONNECTION_USER_VARIABLE);
		}
		enum session_status st=status;
		if (mybe->server_myds->myconn->async_state_machine==ASYNC_IDLE) {
			st=previous_status.top();
			previous_status.pop();
			NEXT_IMMEDIATE_NEW(st);
		}
		assert(st==status);
		unsigned long long curtime=monotonic_time();

		assert(myconn->async_state_machine!=ASYNC_IDLE);
		if (mirror) {
			PROXY_TRACE();
		}
		rc=myconn->async_connect(myds->revents);
		if (myds->mypolls==NULL) {
			// connection yet not in mypolls
			myds->assign_fd_from_mysql_conn();
			thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, curtime);
			if (mirror) {
				PROXY_TRACE();
			}
		}
		switch (rc) {
			case 0:
				myds->myds_type=MYDS_BACKEND;
				myds->DSS=STATE_MARIADB_GENERIC;
				status=WAITING_CLIENT_DATA;
				st=previous_status.top();
				previous_status.pop();
				myds->wait_until=0;
				if (session_fast_forward==true) {
					// we have a successful connection and session_fast_forward enabled
					// set DSS=STATE_SLEEP or it will believe it have to use MARIADB client library
					myds->DSS=STATE_SLEEP;
					myds->myconn->send_quit = false;
					myds->myconn->reusable = false;
					// In a 'fast_forward' session after we disable compression for the fronted connection
					// after we have adquired a backend connection, this is, the 'FAST_FORWARD' session status
					// is reached, and the 1-1 connection relationship is established. We can safely do this
					// due two main reasons:
					//   1. The client and backend have to agree on compression, i.e. if the client connected without
					//   compression using fast-forward to a backend connections expected to have compression, it results
					//   in a fallback to a connection without compression, as it's expected by protocol. In this case we do
					//   not require to compress the data received from the backend.
					//   2. The client and backend have agreed in using compression, in this case, the data received from
					//   the backend is already compressed, so we are only required to forward the data to the client.
					// In both cases, we do not require to perform any specials actions for the received data,
					// so we completely disable the compression flag for the client connection.
					client_myds->myconn->set_status(false, STATUS_MYSQL_CONNECTION_COMPRESSION);
				}
				NEXT_IMMEDIATE_NEW(st);
				break;
			case -1:
			case -2:
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::mysql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, mysql_errno(myconn->mysql));
				if (myds->connect_retries_on_failure >0 ) {
					myds->connect_retries_on_failure--;
					int myerr=mysql_errno(myconn->mysql);
					switch (myerr) {
						case 1226: // ER_USER_LIMIT_REACHED , User '%s' has exceeded the '%s' resource (current value: %ld)
							goto __exit_handler_again___status_CONNECTING_SERVER_with_err;
							break;
						default:
							break;
					}
					if (mirror) {
						PROXY_TRACE();
					}
					myds->destroy_MySQL_Connection_From_Pool(false);
					// NOTE-connect_retries_delay: In case of failure to connect, if
					// 'mysql_thread___connect_retries_delay' is set, we impose a delay in the session
					// processing via 'pause_until'. Complementary NOTE above.
					if (mysql_thread___connect_retries_delay) {
						pause_until=thread->curtime+mysql_thread___connect_retries_delay*1000;
						set_status(CONNECTING_SERVER);
						return false;
					}
					NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
				} else {
__exit_handler_again___status_CONNECTING_SERVER_with_err:
					int myerr=mysql_errno(myconn->mysql);
					string errmsg = "";
					if (myerr) {
						char sqlstate[10];
						errmsg = string(mysql_error(myconn->mysql));
						sprintf(sqlstate,"%s",mysql_sqlstate(myconn->mysql));
						client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate, errmsg.c_str(), true);
					} else {
						errmsg = "Max connect failure while reaching hostgroup " + to_string(current_hostgroup);
						client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,9002,(char *)"HY000", errmsg.c_str(), true);
						if (thread) {
							thread->status_variables.stvar[st_var_max_connect_timeout_err]++;
						}
					}
					if (session_fast_forward==false) {
						// see bug #979
						MyHGM->add_mysql_errors(current_hostgroup, (char *)"", 0, client_myds->myconn->userinfo->username, (client_myds->addr.addr ? client_myds->addr.addr : (char *)"unknown" ), client_myds->myconn->userinfo->schemaname, 9002, (char *)errmsg.c_str());
						RequestEnd(myds, 9002, errmsg.c_str());
					}
					while (previous_status.size()) {
						st=previous_status.top();
						previous_status.pop();
					}
					if (mirror) {
						PROXY_TRACE();
					}
					myds->destroy_MySQL_Connection_From_Pool( myerr ? true : false );
					myds->max_connect_time=0;
					NEXT_IMMEDIATE_NEW(WAITING_CLIENT_DATA);
				}
				break;
			case 1: // continue on next loop
			default:
				break;
		}
	}
	return false;
}
bool MySQL_Session::handler_again___status_CHANGING_USER_SERVER(int *_rc) {
	assert(mybe->server_myds->myconn);
	MySQL_Data_Stream *myds=mybe->server_myds;
	MySQL_Connection *myconn=myds->myconn;
	myds->DSS=STATE_MARIADB_QUERY;
	enum session_status st=status;
	if (myds->mypolls==NULL) {
		thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
	}
	// we recreate local_stmts : see issue #752
	delete myconn->local_stmts;
	myconn->local_stmts=new MySQL_STMTs_local_v14(false); // false by default, it is a backend
	if (mysql_thread___connect_timeout_server_max) {
		if (mybe->server_myds->max_connect_time==0) {
			mybe->server_myds->max_connect_time=thread->curtime+mysql_thread___connect_timeout_server_max*1000;
		}
	}
	int rc=myconn->async_change_user(myds->revents);
	if (rc==0) {
		__sync_fetch_and_add(&MyHGM->status.backend_change_user, 1);
		myds->myconn->userinfo->set(client_myds->myconn->userinfo);
		myds->myconn->reset();
		myds->DSS = STATE_MARIADB_GENERIC;
		st = previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			MyHGM->p_update_mysql_error_counter(
				p_mysql_error_type::mysql,
				myconn->parent->myhgc->hid,
				myconn->parent->address,
				myconn->parent->port,
				( myerr ? myerr : ER_PROXYSQL_OFFLINE_SRV )
			);
			if (myerr >= 2000 || myerr == 0) {
				bool retry_conn=false;
				// client error, serious
				detected_broken_connection(__FILE__ , __LINE__ , __func__ , "during CHANGE_USER", myconn, myerr, mysql_error(myconn->mysql));
				if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
					retry_conn=true;
				}
				myds->destroy_MySQL_Connection_From_Pool(false);
				myds->fd=0;
				if (retry_conn) {
					myds->DSS=STATE_NOT_INITIALIZED;
					NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
				}
				*_rc=-1;
				return false;
			} else {
				proxy_warning("Error during change user: %d, %s\n", myerr, mysql_error(myconn->mysql));
					// we won't go back to PROCESSING_QUERY
				st=previous_status.top();
				previous_status.pop();
				char sqlstate[10];
				sprintf(sqlstate,"%s",mysql_sqlstate(myconn->mysql));
				client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql));
				myds->destroy_MySQL_Connection_From_Pool(true);
				myds->fd=0;
				RequestEnd(myds); //fix bug #682
			}
		} else {
			if (rc==-2) {
				bool retry_conn=false;
				proxy_error("Change user timeout during COM_CHANGE_USER on %s , %d\n", myconn->parent->address, myconn->parent->port);
				MyHGM->p_update_mysql_error_counter(p_mysql_error_type::mysql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, ER_PROXYSQL_CHANGE_USER_TIMEOUT);
				if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
					retry_conn=true;
				}
				myds->destroy_MySQL_Connection_From_Pool(false);
				myds->fd=0;
				if (retry_conn) {
					myds->DSS=STATE_NOT_INITIALIZED;
					NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
				}
				*_rc=-1;
				return false;
			} else {
				// rc==1 , nothing to do for now
			}
		}
	}
	return false;
}

bool MySQL_Session::handler_again___status_CHANGING_AUTOCOMMIT(int *_rc) {
	//fprintf(stderr,"CHANGING_AUTOCOMMIT\n");
	assert(mybe->server_myds->myconn);
	MySQL_Data_Stream *myds=mybe->server_myds;
	MySQL_Connection *myconn=myds->myconn;
	myds->DSS=STATE_MARIADB_QUERY;
	enum session_status st=status;
	if (myds->mypolls==NULL) {
		thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
	}
	bool ac = autocommit;
	if (autocommit == false) { // also IsAutoCommit==false
		if (mysql_thread___enforce_autocommit_on_reads == false) {
			if (mybe->server_myds->myconn->IsAutoCommit() == false) {
				if (mybe->server_myds->myconn->IsActiveTransaction() == false) {
					if (CurrentQuery.is_select_NOT_for_update()==true) {
						// client wants autocommit=0
						// enforce_autocommit_on_reads=false
						// there is no transaction
						// this seems to be the first query, and a SELECT not FOR UPDATE
						// we will switch back to autcommit=1
						ac = true;
					}
				} else {
					st=previous_status.top();
					previous_status.pop();
					myds->DSS = STATE_MARIADB_GENERIC;
					NEXT_IMMEDIATE_NEW(st);
				}
			}
		}
	}
	int rc=myconn->async_set_autocommit(myds->revents, ac);
	if (rc==0) {
		st=previous_status.top();
		previous_status.pop();
		myds->DSS = STATE_MARIADB_GENERIC;
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			MyHGM->p_update_mysql_error_counter(
				p_mysql_error_type::mysql,
				myconn->parent->myhgc->hid,
				myconn->parent->address,
				myconn->parent->port,
				( myerr ? myerr : ER_PROXYSQL_OFFLINE_SRV )
			);
			if (myerr >= 2000 || myerr == 0) {
				bool retry_conn=false;
				// client error, serious
				detected_broken_connection(__FILE__ , __LINE__ , __func__ , "during SET AUTOCOMMIT", myconn, myerr, mysql_error(myconn->mysql));
				if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
					retry_conn=true;
				}
				myds->destroy_MySQL_Connection_From_Pool(false);
				myds->fd=0;
				if (retry_conn) {
					myds->DSS=STATE_NOT_INITIALIZED;
					NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
				}
				*_rc=-1;
				return false;
			} else {
				proxy_warning("Error during SET AUTOCOMMIT: %d, %s\n", myerr, mysql_error(myconn->mysql));
					// we won't go back to PROCESSING_QUERY
				st=previous_status.top();
				previous_status.pop();
				char sqlstate[10];
				sprintf(sqlstate,"%s",mysql_sqlstate(myconn->mysql));
				client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql));
					myds->destroy_MySQL_Connection_From_Pool(true);
					myds->fd=0;
				RequestEnd(myds);
				status=WAITING_CLIENT_DATA;
				client_myds->DSS=STATE_SLEEP;
			}
		} else {
			// rc==1 , nothing to do for now
		}
	}
	return false;
}

// this function was inline inside MySQL_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP
// enum_mysql_command = _MYSQL_COM_STMT_PREPARE
//
// all break were replaced with a return
void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_PREPARE(PtrSize_t& pkt) {
	if (session_type != PROXYSQL_SESSION_MYSQL) { // only MySQL module supports prepared statement!!
		l_free(pkt.size,pkt.ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"28000",(char *)"Command not supported");
		client_myds->DSS=STATE_SLEEP;
		status=WAITING_CLIENT_DATA;
		return;
	} else {
		thread->status_variables.stvar[st_var_frontend_stmt_prepare]++;
		thread->status_variables.stvar[st_var_queries]++;
		// if we reach here, we are not on MySQL module
		bool rc_break=false;
		bool lock_hostgroup = false;

		// Note: CurrentQuery sees the query as sent by the client.
		// shortly after, the packets it used to contain the query will be deallocated
		// Note2 : we call the next function as if it was _MYSQL_COM_QUERY
		// because the offset will be identical
		CurrentQuery.begin((unsigned char *)pkt.ptr,pkt.size,true);

		timespec begint;
		timespec endt;
		if (thread->variables.stats_time_query_processor) {
			clock_gettime(CLOCK_THREAD_CPUTIME_ID,&begint);
		}
		qpo=GloQPro->process_mysql_query(this,pkt.ptr,pkt.size,&CurrentQuery);
		if (thread->variables.stats_time_query_processor) {
			clock_gettime(CLOCK_THREAD_CPUTIME_ID,&endt);
			thread->status_variables.stvar[st_var_query_processor_time] = thread->status_variables.stvar[st_var_query_processor_time] +
				(endt.tv_sec*1000000000+endt.tv_nsec) -
				(begint.tv_sec*1000000000+begint.tv_nsec);
		}
		assert(qpo);	// GloQPro->process_mysql_query() should always return a qpo
		// setting 'prepared' to prevent fetching results from the cache if the digest matches
		rc_break=handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(&pkt, &lock_hostgroup, ps_type_prepare_stmt);
		if (rc_break==true) {
			return;
		}
		if (mysql_thread___set_query_lock_on_hostgroup == 1) { // algorithm introduced in 2.0.6
			if (locked_on_hostgroup < 0) {
				if (lock_hostgroup) {
					// we are locking on hostgroup now
					locked_on_hostgroup = current_hostgroup;
				}
			}
			if (locked_on_hostgroup >= 0) {
				if (current_hostgroup != locked_on_hostgroup) {
					client_myds->DSS=STATE_QUERY_SENT_NET;
					int l = CurrentQuery.QueryLength;
					char *end = (char *)"";
					if (l>256) {
						l=253;
						end = (char *)"...";
					}
					string nqn = string((char *)CurrentQuery.QueryPointer,l);
					char *err_msg = (char *)"Session trying to reach HG %d while locked on HG %d . Rejecting query: %s";
					char *buf = (char *)malloc(strlen(err_msg)+strlen(nqn.c_str())+strlen(end)+64);
					sprintf(buf, err_msg, current_hostgroup, locked_on_hostgroup, nqn.c_str(), end);
					client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,9005,(char *)"HY000",buf, true);
					thread->status_variables.stvar[st_var_hostgroup_locked_queries]++;
					RequestEnd(NULL, 9005, buf);
					free(buf);
					l_free(pkt.size,pkt.ptr);
					return;
				}
			}
		}
		mybe=find_or_create_backend(current_hostgroup);
		if (client_myds->myconn->local_stmts==NULL) {
			client_myds->myconn->local_stmts=new MySQL_STMTs_local_v14(true);
		}
		uint64_t hash=client_myds->myconn->local_stmts->compute_hash(
			(char *)client_myds->myconn->userinfo->username,
			(char *)client_myds->myconn->userinfo->schemaname,
			(char *)CurrentQuery.QueryPointer,
			CurrentQuery.QueryLength
		);
		MySQL_STMT_Global_info *stmt_info=NULL;
		// we first lock GloStmt
		GloMyStmt->wrlock();
		stmt_info=GloMyStmt->find_prepared_statement_by_hash(hash);
		if (stmt_info) {
			// the prepared statement exists in GloMyStmt
			// for this reason, we do not need to prepare it again, and we can already reply to the client
			// we will now generate a unique stmt and send it to the client
			uint32_t new_stmt_id=client_myds->myconn->local_stmts->generate_new_client_stmt_id(stmt_info->statement_id);
			CurrentQuery.stmt_client_id=new_stmt_id;
			client_myds->setDSS_STATE_QUERY_SENT_NET();
			client_myds->myprot.generate_STMT_PREPARE_RESPONSE(client_myds->pkt_sid+1,stmt_info,new_stmt_id);
			LogQuery(NULL);
			l_free(pkt.size,pkt.ptr);
			client_myds->DSS=STATE_SLEEP;
			status=WAITING_CLIENT_DATA;
			CurrentQuery.end_time=thread->curtime;
			CurrentQuery.end();
		} else {
			mybe=find_or_create_backend(current_hostgroup);
			status=PROCESSING_STMT_PREPARE;
			mybe->server_myds->connect_retries_on_failure=mysql_thread___connect_retries_on_failure;
			mybe->server_myds->wait_until=0;
			pause_until=0;
			mybe->server_myds->killed_at=0;
			mybe->server_myds->kill_type=0;
			mybe->server_myds->mysql_real_query.init(&pkt); // fix memory leak for PREPARE in prepared statements #796
			mybe->server_myds->statuses.questions++;
			client_myds->setDSS_STATE_QUERY_SENT_NET();
		}
		GloMyStmt->unlock();
		return; // make sure to not return before unlocking GloMyStmt
	}
}

// this function was inline inside MySQL_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP
// enum_mysql_command = _MYSQL_COM_STMT_EXECUTE
//
// all break were replaced with a return
void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_EXECUTE(PtrSize_t& pkt) {
	if (session_type != PROXYSQL_SESSION_MYSQL) { // only MySQL module supports prepared statement!!
		l_free(pkt.size,pkt.ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"28000",(char *)"Command not supported");
		client_myds->DSS=STATE_SLEEP;
		status=WAITING_CLIENT_DATA;
		return;
	} else {
		// if we reach here, we are on MySQL module
		bool rc_break=false;
		bool lock_hostgroup = false;
		thread->status_variables.stvar[st_var_frontend_stmt_execute]++;
		thread->status_variables.stvar[st_var_queries]++;
		uint32_t client_stmt_id=0;
		uint64_t stmt_global_id=0;
		memcpy(&client_stmt_id,(char *)pkt.ptr+5,sizeof(uint32_t));
		CurrentQuery.stmt_client_id=client_stmt_id;
		stmt_global_id=client_myds->myconn->local_stmts->find_global_stmt_id_from_client(client_stmt_id);
		if (stmt_global_id == 0) {
			l_free(pkt.size,pkt.ptr);
			client_myds->setDSS_STATE_QUERY_SENT_NET();
			string err_msg = "Unknown prepared statement handler (" + to_string(client_stmt_id) + ") given to mysql_stmt_precheck";
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1243,(char *)"HY000", err_msg.c_str());
			client_myds->DSS=STATE_SLEEP;
			status=WAITING_CLIENT_DATA;
			return;
		}
		CurrentQuery.stmt_global_id=stmt_global_id;
		// now we get the statement information
		MySQL_STMT_Global_info *stmt_info=NULL;
		stmt_info=GloMyStmt->find_prepared_statement_by_stmt_id(stmt_global_id);
		if (stmt_info==NULL) {
			// we couldn't find it
			l_free(pkt.size,pkt.ptr);
			client_myds->setDSS_STATE_QUERY_SENT_NET();
			string err_msg = "Unknown prepared statement handler (" + to_string(client_stmt_id) + ") given to mysql_stmt_precheck";
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1243,(char *)"HY000", err_msg.c_str());
			client_myds->DSS=STATE_SLEEP;
			status=WAITING_CLIENT_DATA;
			return;
		}
		CurrentQuery.stmt_info=stmt_info;
		CurrentQuery.start_time=thread->curtime;

		timespec begint;
		timespec endt;
		if (thread->variables.stats_time_query_processor) {
			clock_gettime(CLOCK_THREAD_CPUTIME_ID,&begint);
		}
		qpo=GloQPro->process_mysql_query(this,NULL,0,&CurrentQuery);
		if (qpo->max_lag_ms >= 0) {
			thread->status_variables.stvar[st_var_queries_with_max_lag_ms]++;
		}
		if (thread->variables.stats_time_query_processor) {
			clock_gettime(CLOCK_THREAD_CPUTIME_ID,&endt);
			thread->status_variables.stvar[st_var_query_processor_time] = thread->status_variables.stvar[st_var_query_processor_time] +
				(endt.tv_sec*1000000000+endt.tv_nsec) -
				(begint.tv_sec*1000000000+begint.tv_nsec);
		}
		assert(qpo);	// GloQPro->process_mysql_query() should always return a qpo
		// we now take the metadata associated with STMT_EXECUTE from MySQL_STMTs_meta
		bool stmt_meta_found=true; // let's be optimistic and we assume we will found it
		stmt_execute_metadata_t *stmt_meta=sess_STMTs_meta->find(stmt_global_id);
		if (stmt_meta==NULL) { // we couldn't find any metadata
			stmt_meta_found=false;
		}
		stmt_meta=client_myds->myprot.get_binds_from_pkt(pkt.ptr,pkt.size,stmt_info, &stmt_meta);
		if (stmt_meta==NULL) {
			l_free(pkt.size,pkt.ptr);
			client_myds->setDSS_STATE_QUERY_SENT_NET();
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"28000",(char *)"Error in prepared statement execution", true);
			client_myds->DSS=STATE_SLEEP;
			status=WAITING_CLIENT_DATA;
			//__sync_fetch_and_sub(&stmt_info->ref_count,1); // decrease reference count
			stmt_info=NULL;
			return;
		}
		if (stmt_meta_found==false) {
			// previously we didn't find any metadata
			// but as we reached here, stmt_meta is not null and we save the metadata
			sess_STMTs_meta->insert(stmt_global_id,stmt_meta);
		}
		// else

		CurrentQuery.stmt_meta=stmt_meta;
		//current_hostgroup=qpo->destination_hostgroup;
		rc_break=handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(&pkt, &lock_hostgroup, ps_type_execute_stmt);
		if (rc_break==true) {
			return;
		}
		if (mysql_thread___set_query_lock_on_hostgroup == 1) { // algorithm introduced in 2.0.6
			if (locked_on_hostgroup < 0) {
				if (lock_hostgroup) {
					// we are locking on hostgroup now
					locked_on_hostgroup = current_hostgroup;
				}
			}
			if (locked_on_hostgroup >= 0) {
				if (current_hostgroup != locked_on_hostgroup) {
					client_myds->DSS=STATE_QUERY_SENT_NET;
					//int l = CurrentQuery.QueryLength;
					int l = CurrentQuery.stmt_info->query_length;
					char *end = (char *)"";
					if (l>256) {
						l=253;
						end = (char *)"...";
					}
					string nqn = string((char *)CurrentQuery.stmt_info->query,l);
					char *err_msg = (char *)"Session trying to reach HG %d while locked on HG %d . Rejecting query: %s";
					char *buf = (char *)malloc(strlen(err_msg)+strlen(nqn.c_str())+strlen(end)+64);
					sprintf(buf, err_msg, current_hostgroup, locked_on_hostgroup, nqn.c_str(), end);
					client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,9005,(char *)"HY000",buf, true);
					thread->status_variables.stvar[st_var_hostgroup_locked_queries]++;
					RequestEnd(NULL, 9005, buf);
					free(buf);
					l_free(pkt.size,pkt.ptr);
					return;
				}
			}
		}
		mybe=find_or_create_backend(current_hostgroup);
		status=PROCESSING_STMT_EXECUTE;
		mybe->server_myds->connect_retries_on_failure=mysql_thread___connect_retries_on_failure;
		mybe->server_myds->wait_until=0;
		mybe->server_myds->killed_at=0;
		mybe->server_myds->kill_type=0;
		client_myds->setDSS_STATE_QUERY_SENT_NET();
	}
}

// this function was inline inside MySQL_Session::get_pkts_from_client
// ClickHouse doesn't support COM_INIT_DB , so we replace it
// with a COM_QUERY running USE
void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB_replace_CLICKHOUSE(PtrSize_t& pkt) {
	PtrSize_t _new_pkt;
	_new_pkt.ptr=malloc(pkt.size+4); // USE + space
	memcpy(_new_pkt.ptr , pkt.ptr, 4);
	unsigned char *_c=(unsigned char *)_new_pkt.ptr;
	_c+=4; *_c=0x03;
	_c+=1; *_c='U';
	_c+=1; *_c='S';
	_c+=1; *_c='E';
	_c+=1; *_c=' ';
	memcpy((char *)_new_pkt.ptr+9 , (char *)pkt.ptr+5, pkt.size-5);
	l_free(pkt.size,pkt.ptr);
	pkt.size+=4;
	pkt.ptr = _new_pkt.ptr;
}

// this function was inline inside MySQL_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP
// enum_mysql_command = _MYSQL_COM_QUERY
// it processes the session not MYSQL_SESSION
// Make sure that handler_function() doesn't free the packet
void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___not_mysql(PtrSize_t& pkt) {
	switch (session_type) {
		case PROXYSQL_SESSION_ADMIN:
		case PROXYSQL_SESSION_STATS:
		// this is processed by the admin module
			handler_function(this, (void *)GloAdmin, &pkt);
			l_free(pkt.size,pkt.ptr);
			break;
		case PROXYSQL_SESSION_SQLITE:
			handler_function(this, (void *)GloSQLite3Server, &pkt);
			l_free(pkt.size,pkt.ptr);
			break;
#ifdef PROXYSQLCLICKHOUSE
		case PROXYSQL_SESSION_CLICKHOUSE:
			handler_function(this, (void *)GloClickHouseServer, &pkt);
			l_free(pkt.size,pkt.ptr);
			break;
#endif /* PROXYSQLCLICKHOUSE */
		default:
			// LCOV_EXCL_START
			assert(0);
			// LCOV_EXCL_STOP
	}
}


// this function was inline inside MySQL_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP
// enum_mysql_command = _MYSQL_COM_QUERY
// it searches for SQL injection
// it returns true if it detected an SQL injection
bool MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_detect_SQLi() {
	if (client_myds->com_field_list == false) {
		if (qpo->firewall_whitelist_mode != WUS_OFF) {
			struct libinjection_sqli_state state;
			int issqli;
			const char * input = (char *)CurrentQuery.QueryPointer;
			size_t slen = CurrentQuery.QueryLength;
			libinjection_sqli_init(&state, input, slen, FLAG_SQL_MYSQL);
			issqli = libinjection_is_sqli(&state);
			if (issqli) {
				bool allow_sqli = false;
				allow_sqli = GloQPro->whitelisted_sqli_fingerprint(state.fingerprint);
				if (allow_sqli) {
					thread->status_variables.stvar[st_var_whitelisted_sqli_fingerprint]++;
				} else {
					thread->status_variables.stvar[st_var_automatic_detected_sqli]++;
					char * username = client_myds->myconn->userinfo->username;
					char * client_address = client_myds->addr.addr;
					proxy_error("SQLinjection detected with fingerprint of '%s' from client %s@%s . Query listed below:\n", state.fingerprint, username, client_address);
					fwrite(CurrentQuery.QueryPointer, CurrentQuery.QueryLength, 1, stderr);
					fprintf(stderr,"\n");
					RequestEnd(NULL);
					return true;
				}
			}
		}
	}
	return false;
}

// this function was inline inside MySQL_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP_MULTI_PACKET
//
// replacing the single goto with return true
bool MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP_MULTI_PACKET(PtrSize_t& pkt) {
	if (client_myds->multi_pkt.ptr==NULL) {
		// not initialized yet
		client_myds->multi_pkt.ptr=pkt.ptr;
		client_myds->multi_pkt.size=pkt.size;
	} else {
		PtrSize_t tmp_pkt;
		tmp_pkt.ptr=client_myds->multi_pkt.ptr;
		tmp_pkt.size=client_myds->multi_pkt.size;
		client_myds->multi_pkt.size = pkt.size + tmp_pkt.size-sizeof(mysql_hdr);
		client_myds->multi_pkt.ptr = l_alloc(client_myds->multi_pkt.size);
		memcpy(client_myds->multi_pkt.ptr, tmp_pkt.ptr, tmp_pkt.size);
		memcpy((char *)client_myds->multi_pkt.ptr + tmp_pkt.size , (char *)pkt.ptr+sizeof(mysql_hdr) , pkt.size-sizeof(mysql_hdr)); // the header is not copied
		l_free(tmp_pkt.size , tmp_pkt.ptr);
		l_free(pkt.size , pkt.ptr);
	}
	if (pkt.size==(0xFFFFFF+sizeof(mysql_hdr))) { // there are more packets
		//goto __get_pkts_from_client;
		return true;
	} else {
		// no more packets, move everything back to pkt and proceed
		pkt.ptr=client_myds->multi_pkt.ptr;
		pkt.size=client_myds->multi_pkt.size;
		client_myds->multi_pkt.size=0;
		client_myds->multi_pkt.ptr=NULL;
		client_myds->DSS=STATE_SLEEP;
	}
	return false;
}


// this function was inline inside MySQL_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP
// enum_mysql_command in a large list of possible values
// the most common values for enum_mysql_command are handled from the calling function
// here we only process the not so common ones
// we return false if the enum_mysql_command is not found
bool MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM__various(PtrSize_t* pkt, bool* wrong_pass) {
	unsigned char c;
	c=*((unsigned char *)pkt->ptr+sizeof(mysql_hdr));
	switch ((enum_mysql_command)c) {
		case _MYSQL_COM_CHANGE_USER:
			handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_CHANGE_USER(pkt, wrong_pass);
			break;
		case _MYSQL_COM_PING:
			handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PING(pkt);
			break;
		case _MYSQL_COM_SET_OPTION:
			handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_SET_OPTION(pkt);
			break;
		case _MYSQL_COM_STATISTICS:
			handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STATISTICS(pkt);
			break;
		case _MYSQL_COM_INIT_DB:
			handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB(pkt);
			break;
		case _MYSQL_COM_FIELD_LIST:
			handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_FIELD_LIST(pkt);
			break;
		case _MYSQL_COM_PROCESS_KILL:
			handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PROCESS_KILL(pkt);
			break;
		case _MYSQL_COM_RESET_CONNECTION:
			handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_RESET_CONNECTION(pkt);
			break;
		default:
			return false;
			break;
	}
	return true;
}


// this function was inline inside MySQL_Session::get_pkts_from_client
// where:
// status = NONE or default
//
// this is triggered when proxysql receives a packet when doesn't expect any
// for example while it is supposed to be sending resultset to client
void MySQL_Session::handler___status_NONE_or_default(PtrSize_t& pkt) {
	char buf[INET6_ADDRSTRLEN];
	switch (client_myds->client_addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)client_myds->client_addr;
			inet_ntop(client_myds->client_addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)client_myds->client_addr;
			inet_ntop(client_myds->client_addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
			break;
		}
		default:
			sprintf(buf, "localhost");
			break;
		}
	if (pkt.size == 5) {
		unsigned char c=*((unsigned char *)pkt.ptr+sizeof(mysql_hdr));
		if (c==_MYSQL_COM_QUIT) {
			proxy_error("Unexpected COM_QUIT from client %s . Session_status: %d , client_status: %d Disconnecting it\n", buf, status, client_myds->status);
			if (GloMyLogger) { GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_QUIT, this, NULL); }
			proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_QUIT packet\n");
			l_free(pkt.size,pkt.ptr);
			if (thread) {
				thread->status_variables.stvar[st_var_unexpected_com_quit]++;
			}
			return;
		}
	}
	proxy_error2(10001, "Unexpected packet from client %s . Session_status: %d , client_status: %d Disconnecting it\n", buf, status, client_myds->status);
	if (thread) {
		thread->status_variables.stvar[st_var_unexpected_packet]++;
	}
	return;
}

// this function was inline inside MySQL_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
void MySQL_Session::handler___status_WAITING_CLIENT_DATA___default() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: WAITING_CLIENT_DATA - STATE_UNKNOWN\n");
	if (mirror==false) {
		char buf[INET6_ADDRSTRLEN];
		switch (client_myds->client_addr->sa_family) {
			case AF_INET: {
				struct sockaddr_in *ipv4 = (struct sockaddr_in *)client_myds->client_addr;
				inet_ntop(client_myds->client_addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
				break;
			}
			case AF_INET6: {
				struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)client_myds->client_addr;
				inet_ntop(client_myds->client_addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
				break;
			}
			default:
				sprintf(buf, "localhost");
				break;
		}
		// PMC-10001: A unexpected packet has been received from client. This error has two potential causes:
		//  * Bug: ProxySQL state machine wasn't in the correct state when a legitimate client packet was received.
		//  * Client error: The client incorrectly sent a packet breaking MySQL protocol.
		proxy_error2(10001, "Unexpected packet from client %s . Session_status: %d , client_status: %d Disconnecting it\n", buf, status, client_myds->status);
	}
}

int MySQL_Session::GPFC_Statuses2(bool& wrong_pass, PtrSize_t& pkt) {
	int handler_ret = 0;
	switch (status) {
		case WAITING_CLIENT_DATA:
			// this case should handled directly into get_pkts_from_client()
			assert(0);
			break;
		case CONNECTING_CLIENT:
			switch (client_myds->DSS) {
				case STATE_SERVER_HANDSHAKE:
					handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(&pkt, &wrong_pass);
					break;
				case STATE_SSL_INIT:
					handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(&pkt, &wrong_pass);
					break;
				default:
					proxy_error("Detected not valid state client state: %d\n", client_myds->DSS);
					handler_ret = -1; //close connection
					return handler_ret;
					break;
			}
			break;
		case FAST_FORWARD:
			mybe->server_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
			break;
		// This state is required because it covers the following situation:
		//  1. A new connection is created by a client and the 'FAST_FORWARD' mode is enabled.
		//  2. The first packet received for this connection isn't a whole packet, i.e, it's either
		//     split into multiple packets, or it doesn't fit 'queueIN' size (typically
		//     QUEUE_T_DEFAULT_SIZE).
		//  3. Session is still in 'CONNECTING_SERVER' state, BUT further packets remain to be received
		//     from the initial split packet.
		//
		//  Because of this, packets received during 'CONNECTING_SERVER' when the previous state is
		//  'FAST_FORWARD' should be pushed to 'PSarrayOUT'.
		case CONNECTING_SERVER:
			if (previous_status.empty() == false && previous_status.top() == FAST_FORWARD) {
				mybe->server_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
				break;
			}
		case session_status___NONE:
		default:
			handler___status_NONE_or_default(pkt);
			handler_ret = -1;
			return handler_ret;
			break;
	}
	return handler_ret;
}

void MySQL_Session::GPFC_DetectedMultiPacket_SetDDS() {
	// this is handled only for real traffic, not mirror
	switch (client_myds->DSS) { // real traffic only
		case STATE_SLEEP:
			client_myds->DSS=STATE_SLEEP_MULTI_PACKET;
			break;
		case STATE_SLEEP_MULTI_PACKET:
			break;
		default:
			// LCOV_EXCL_START
			assert(0);
			break;
			// LCOV_EXCL_STOP
	}
}

int MySQL_Session::GPFC_WaitingClientData_FastForwardSession(PtrSize_t& pkt) {
	int handler_ret = 0;
	// If this is a 'fast_forward' session that hasn't yet received a backend connection, we don't
	// forward 'COM_QUIT' packets, since this will make the act of obtaining a connection pointless.
	// Instead, we intercept the 'COM_QUIT' packet and end the 'MySQL_Session'.
	unsigned char command = *(static_cast<unsigned char*>(pkt.ptr)+sizeof(mysql_hdr));
	if (command == _MYSQL_COM_QUIT) {
		proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_QUIT packet\n");
		if (GloMyLogger) { GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_QUIT, this, NULL); }
		l_free(pkt.size,pkt.ptr);
		handler_ret = -1;
		return handler_ret;
	}

	mybe=find_or_create_backend(current_hostgroup); // set a backend
	mybe->server_myds->reinit_queues();             // reinitialize the queues in the myds . By default, they are not active
	mybe->server_myds->PSarrayOUT->add(pkt.ptr, pkt.size); // move the first packet
	previous_status.push(FAST_FORWARD); // next status will be FAST_FORWARD . Now we need a connection

	// If this is a 'fast_forward' session, we impose the 'connect_timeout' prior to actually getting the
	// connection from the 'connection_pool'. This is used to ensure that we kill the session if
	// 'CONNECTING_SERVER' isn't completed before this timeout expiring. For example, if 'max_connections'
	// is reached for the target hostgroup.
	if (mybe->server_myds->max_connect_time == 0) {
		uint64_t connect_timeout =
			mysql_thread___connect_timeout_server < mysql_thread___connect_timeout_server_max ?
				mysql_thread___connect_timeout_server_max : mysql_thread___connect_timeout_server;
		mybe->server_myds->max_connect_time = thread->curtime + connect_timeout * 1000;
	}
	// Impose the same connection retrying policy as done for regular connections during
	// 'MYSQL_CON_QUERY'.
	mybe->server_myds->connect_retries_on_failure = mysql_thread___connect_retries_on_failure;
	// 'CurrentQuery' isn't used for 'FAST_FORWARD' but we update it for using it as a session
	// startup time for when a fast_forward session has attempted to obtain a connection.
	CurrentQuery.start_time=thread->curtime;

	//NEXT_IMMEDIATE(CONNECTING_SERVER);  // we create a connection . next status will be FAST_FORWARD
	// we can't use NEXT_IMMEDIATE() inside get_pkts_from_client()
	// instead we set status to CONNECTING_SERVER and return 0
	// when we exit from get_pkts_from_client() we expect the label "handler_again"
	set_status(CONNECTING_SERVER);

	return handler_ret;
}


void MySQL_Session::GPFC_PreparedStatements(PtrSize_t& pkt, unsigned char c) {
	switch ((enum_mysql_command)c) {
		case _MYSQL_COM_STMT_PREPARE:
			if (GloMyLdapAuth) {
				if (session_type==PROXYSQL_SESSION_MYSQL) {
					if (mysql_thread___add_ldap_user_comment && strlen(mysql_thread___add_ldap_user_comment)) {
						add_ldap_comment_to_pkt(&pkt);
					}
				}
			}
			handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_PREPARE(pkt);
			break;
		case _MYSQL_COM_STMT_EXECUTE:
			handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_EXECUTE(pkt);
			break;
		case _MYSQL_COM_STMT_RESET:
			handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_RESET(pkt);
			break;
		case _MYSQL_COM_STMT_CLOSE:
			handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_CLOSE(pkt);
			break;
		case _MYSQL_COM_STMT_SEND_LONG_DATA:
			handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_SEND_LONG_DATA(pkt);
			break;
		default:
			// LCOV_EXCL_START
			assert(0);
			break;
			// LCOV_EXCL_STOP
	}
}

void MySQL_Session::GPFC_Replication_SwitchToFastForward(PtrSize_t& pkt, unsigned char c) {
	// In this switch we handle commands that download binlog events from MySQL
	// servers. For these commands a lot of the features provided by ProxySQL
	// aren't useful, like multiplexing, query parsing, etc. For this reason,
	// ProxySQL enables fast_forward when it receives these commands. 
	{
		// we use a switch to write the command in the info message
		std::string q = "Received command ";
		switch ((enum_mysql_command)c) {
			case _MYSQL_COM_BINLOG_DUMP:
				q += "MYSQL_COM_BINLOG_DUMP";
				break;
			case _MYSQL_COM_BINLOG_DUMP_GTID:
				q += "MYSQL_COM_BINLOG_DUMP_GTID";
				break;
			case _MYSQL_COM_REGISTER_SLAVE:
				q += "MYSQL_COM_REGISTER_SLAVE";
				break;
			default:
				assert(0);
				break;
		};
		// we add the client details in the info message
		if (client_myds && client_myds->addr.addr) {
			q += " from client " + std::string(client_myds->addr.addr) + ":" + std::to_string(client_myds->addr.port);
		}
		q += " . Changing session fast_forward to true";
		proxy_info("%s\n", q.c_str());
	}
	session_fast_forward = true;

	if (client_myds->PSarrayIN->len) {
		proxy_error("UNEXPECTED PACKET FROM CLIENT -- PLEASE REPORT A BUG\n");
		assert(0);
	}
	client_myds->PSarrayIN->add(pkt.ptr, pkt.size);

	// The following code prepares the session as if it was configured with fast
	// forward before receiving the command. This way the state machine will
	// handle the command automatically.
	current_hostgroup = previous_hostgroup;
	mybe = find_or_create_backend(current_hostgroup); // set a backend
	mybe->server_myds->reinit_queues(); // reinitialize the queues in the myds . By default, they are not active
	// We reinitialize the 'wait_until' since this session shouldn't wait for processing as
	// we are now transitioning to 'FAST_FORWARD'.
	mybe->server_myds->wait_until = 0;
	if (mybe->server_myds->DSS==STATE_NOT_INITIALIZED) {
		// NOTE: This section is entirely borrowed from 'STATE_SLEEP' for 'session_fast_forward'.
		// Check comments there for extra information.
		// =============================================================================
		if (mybe->server_myds->max_connect_time == 0) {
			uint64_t connect_timeout =
				mysql_thread___connect_timeout_server < mysql_thread___connect_timeout_server_max ?
					mysql_thread___connect_timeout_server_max : mysql_thread___connect_timeout_server;
			mybe->server_myds->max_connect_time = thread->curtime + connect_timeout * 1000;
		}
		mybe->server_myds->connect_retries_on_failure = mysql_thread___connect_retries_on_failure;
		CurrentQuery.start_time=thread->curtime;
		// =============================================================================

		// we don't have a connection
		previous_status.push(FAST_FORWARD); // next status will be FAST_FORWARD
		set_status(CONNECTING_SERVER); // now we need a connection
	} else {
		// In case of having a connection, we need to make user to reset the state machine
		// for current server 'MySQL_Data_Stream', setting it outside of any state handled
		// by 'mariadb' library. Otherwise 'MySQL_Thread' will threat this
		// 'MySQL_Data_Stream' as library handled.
		mybe->server_myds->DSS = STATE_READY;
		// myds needs to have encrypted value set correctly
		{
			MySQL_Data_Stream * myds = mybe->server_myds;
			MySQL_Connection * myconn = myds->myconn;
			assert(myconn != NULL);
			// PMC-10005
			// if backend connection uses SSL we will set
			// encrypted = true and we will start using the SSL structure
			// directly from P_MARIADB_TLS structure.
			MYSQL *mysql = myconn->mysql;
			if (mysql && myconn->ret_mysql) {
				if (mysql->options.use_ssl == 1) {
					P_MARIADB_TLS * matls = (P_MARIADB_TLS *)mysql->net.pvio->ctls;
					if (matls != NULL) {
						myds->encrypted = true;
						myds->ssl = (SSL *)matls->ssl;
						myds->rbio_ssl = BIO_new(BIO_s_mem());
						myds->wbio_ssl = BIO_new(BIO_s_mem());
						SSL_set_bio(myds->ssl, myds->rbio_ssl, myds->wbio_ssl);
					} else {
						// if mysql->options.use_ssl == 1 but matls == NULL
						// it means that ProxySQL tried to use SSL to connect to the backend
						// but the backend didn't support SSL
					}
				}
			}
		}
		set_status(FAST_FORWARD); // we can set status to FAST_FORWARD
	}	
}

bool MySQL_Session::GPFC_QueryUSE(PtrSize_t& pkt, int& handler_ret) {
	bool need_break = false;
	// This block was moved from 'handler_special_queries' to support
	// handling of 'USE' statements which are preceded by a comment.
	// For more context check issue: #3493.
	if (session_type != PROXYSQL_SESSION_CLICKHOUSE) {
		const char *qd = CurrentQuery.get_digest_text();
		bool use_db_query = false;

		if (qd != NULL) {
			if (
				(strncasecmp((char *)"USE",qd,3)==0)
				&&
				(
					(strncasecmp((char *)"USE ",qd,4)==0)
					||
					(strncasecmp((char *)"USE`",qd,4)==0)
				)
			) {
				use_db_query = true;
			}
		} else {
			if (pkt.size > (5+4) && strncasecmp((char *)"USE ", (char *)pkt.ptr+5, 4) == 0) {
				use_db_query = true;
			}
		}

		if (use_db_query) {
			handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_USE_DB(&pkt);

			if (mirror == false) {
				need_break = true;
				return need_break;
			} else {
				handler_ret = -1;
				return need_break;
			}
		}
	}

	return need_break;
}

int MySQL_Session::get_pkts_from_client(bool& wrong_pass, PtrSize_t& pkt) {
	int handler_ret = 0;
	unsigned char c;

__get_pkts_from_client:

	// implement a more complex logic to run even in case of mirror
	// if client_myds , this is a regular client
	// if client_myds == NULL , it is a mirror
	//     process mirror only status==WAITING_CLIENT_DATA
	for (unsigned int j=0; j< ( client_myds->PSarrayIN ? client_myds->PSarrayIN->len : 0)  || (mirror==true && status==WAITING_CLIENT_DATA) ;) {
		if (mirror==false) {
			client_myds->PSarrayIN->remove_index(0,&pkt);
		}
		switch (status) {
			case WAITING_CLIENT_DATA:
				if (pkt.size==(0xFFFFFF+sizeof(mysql_hdr))) { // we are handling a multi-packet
					GPFC_DetectedMultiPacket_SetDDS();
				}
				switch (client_myds->DSS) {
					case STATE_SLEEP_MULTI_PACKET:
						if (handler___status_WAITING_CLIENT_DATA___STATE_SLEEP_MULTI_PACKET(pkt)) {
							// if handler___status_WAITING_CLIENT_DATA___STATE_SLEEP_MULTI_PACKET
							// returns true it meansa we need to reiterate
							goto __get_pkts_from_client;
						}
						// Note: the above function can change DSS to STATE_SLEEP
						// in that case we don't break from the witch but continue
						if (client_myds->DSS!=STATE_SLEEP) // if DSS==STATE_SLEEP , we continue
							break;
					case STATE_SLEEP:	// only this section can be executed ALSO by mirror
						command_counters->incr(thread->curtime/1000000);
						if (transaction_persistent_hostgroup==-1) {
							if (mysql_thread___set_query_lock_on_hostgroup == 0) { // behavior before 2.0.6
								current_hostgroup=default_hostgroup;
							} else {
								if (locked_on_hostgroup==-1) {
									current_hostgroup = default_hostgroup;
								} else {
									current_hostgroup = locked_on_hostgroup;
								}
							}
						}
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session=%p , client_myds=%p . Statuses: WAITING_CLIENT_DATA - STATE_SLEEP\n", this, client_myds);

						if (session_fast_forward==true) { // if it is fast forward
							handler_ret = GPFC_WaitingClientData_FastForwardSession(pkt);
							return handler_ret;
						}
						c=*((unsigned char *)pkt.ptr+sizeof(mysql_hdr));

						if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
							if ((enum_mysql_command)c == _MYSQL_COM_INIT_DB) {
								handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB_replace_CLICKHOUSE(pkt);
								c=*((unsigned char *)pkt.ptr+sizeof(mysql_hdr));
							}
						}
						client_myds->com_field_list=false; // default
						if (c == _MYSQL_COM_FIELD_LIST) {
							if (session_type == PROXYSQL_SESSION_MYSQL) {
								MySQL_Protocol *myprot=&client_myds->myprot;
								bool rcp = myprot->generate_COM_QUERY_from_COM_FIELD_LIST(&pkt);
								if (rcp) {
									// all went well
									c=*((unsigned char *)pkt.ptr+sizeof(mysql_hdr));
									client_myds->com_field_list=true;
								} else {
									// parsing failed, proxysql will return not suppported command
								}
							}
						}
						switch ((enum_mysql_command)c) {
							case _MYSQL_COM_QUERY:
								__sync_add_and_fetch(&thread->status_variables.stvar[st_var_queries],1);
								if (session_type == PROXYSQL_SESSION_MYSQL) {
									bool rc_break=false;
									bool lock_hostgroup = false;
									if (session_fast_forward==false) {
										// Note: CurrentQuery sees the query as sent by the client.
										// shortly after, the packets it used to contain the query will be deallocated
										CurrentQuery.begin((unsigned char *)pkt.ptr,pkt.size,true);
									}
									rc_break=handler_special_queries(&pkt);
									if (rc_break==true) {
										if (mirror==false) {
											// track also special queries
											//RequestEnd(NULL);
											// we moved this inside handler_special_queries()
											// because a pointer was becoming invalid
											break;
										} else {
											handler_ret = -1;
											return handler_ret;
										}
									}
									timespec begint;
									timespec endt;
									if (thread->variables.stats_time_query_processor) {
										clock_gettime(CLOCK_THREAD_CPUTIME_ID,&begint);
									}
									qpo=GloQPro->process_mysql_query(this,pkt.ptr,pkt.size,&CurrentQuery);
									if (thread->variables.stats_time_query_processor) {
										clock_gettime(CLOCK_THREAD_CPUTIME_ID,&endt);
										thread->status_variables.stvar[st_var_query_processor_time]=thread->status_variables.stvar[st_var_query_processor_time] +
											(endt.tv_sec*1000000000+endt.tv_nsec) -
											(begint.tv_sec*1000000000+begint.tv_nsec);
									}
									assert(qpo);	// GloQPro->process_mysql_query() should always return a qpo

									{
										bool need_break = GPFC_QueryUSE(pkt, handler_ret);
										if (handler_ret == -1) {
											return handler_ret;
										} else if (need_break == true) {
											break;
										}
									}

									if (qpo->max_lag_ms >= 0) {
										thread->status_variables.stvar[st_var_queries_with_max_lag_ms]++;
									}
									rc_break=handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(&pkt, &lock_hostgroup);
									if (mirror==false && rc_break==false) {
										if (mysql_thread___automatic_detect_sqli) {
											if (handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_detect_SQLi()) {
												handler_ret = -1;
												return handler_ret;
											}
										}
									}
									if (rc_break==true) {
										if (mirror==false) {
											break;
										} else {
											handler_ret = -1;
											return handler_ret;
										}
									}
									if (mirror==false) {
										handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___create_mirror_session();
									}

									if (autocommit_on_hostgroup>=0) {
									}
									if (mysql_thread___set_query_lock_on_hostgroup == 1) { // algorithm introduced in 2.0.6
										if (locked_on_hostgroup < 0) {
											if (lock_hostgroup) {
												// we are locking on hostgroup now
												if ( qpo->destination_hostgroup >= 0 ) {
													if (transaction_persistent_hostgroup == -1) {
														current_hostgroup=qpo->destination_hostgroup;
													}
												}
												locked_on_hostgroup = current_hostgroup;
												thread->status_variables.stvar[st_var_hostgroup_locked]++;
												thread->status_variables.stvar[st_var_hostgroup_locked_set_cmds]++;
											}
										}
										if (locked_on_hostgroup >= 0) {
											if (current_hostgroup != locked_on_hostgroup) {
												client_myds->DSS=STATE_QUERY_SENT_NET;
												int l = CurrentQuery.QueryLength;
												char *end = (char *)"";
												if (l>256) {
													l=253;
													end = (char *)"...";
												}
												string nqn = string((char *)CurrentQuery.QueryPointer,l);
												char *err_msg = (char *)"Session trying to reach HG %d while locked on HG %d . Rejecting query: %s";
												char *buf = (char *)malloc(strlen(err_msg)+strlen(nqn.c_str())+strlen(end)+64);
												sprintf(buf, err_msg, current_hostgroup, locked_on_hostgroup, nqn.c_str(), end);
												client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,9005,(char *)"HY000",buf, true);
												thread->status_variables.stvar[st_var_hostgroup_locked_queries]++;
												RequestEnd(NULL, 9005, buf);
												free(buf);
												l_free(pkt.size,pkt.ptr);
												break;
											}
										}
									}
									mybe=find_or_create_backend(current_hostgroup);
									status=PROCESSING_QUERY;
									// set query retries
									mybe->server_myds->query_retries_on_failure=mysql_thread___query_retries_on_failure;
									// if a number of retries is set in mysql_query_rules, that takes priority
									if (qpo) {
										if (qpo->retries >= 0) {
											mybe->server_myds->query_retries_on_failure=qpo->retries;
										}
									}
									mybe->server_myds->connect_retries_on_failure=mysql_thread___connect_retries_on_failure;
									mybe->server_myds->wait_until=0;
									pause_until=0;
									if (mysql_thread___default_query_delay) {
										pause_until=thread->curtime+mysql_thread___default_query_delay*1000;
									}
									if (qpo) {
										if (qpo->delay > 0) {
											if (pause_until==0)
												pause_until=thread->curtime;
											pause_until+=qpo->delay*1000;
										}
									}


									proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Received query to be processed with MariaDB Client library\n");
									mybe->server_myds->killed_at=0;
									mybe->server_myds->kill_type=0;
									if (GloMyLdapAuth) {
										if (session_type==PROXYSQL_SESSION_MYSQL) {
											if (mysql_thread___add_ldap_user_comment && strlen(mysql_thread___add_ldap_user_comment)) {
												add_ldap_comment_to_pkt(&pkt);
											}
										}
									}
									mybe->server_myds->mysql_real_query.init(&pkt);
									mybe->server_myds->statuses.questions++;
									client_myds->setDSS_STATE_QUERY_SENT_NET();
								} else {
									handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___not_mysql(pkt);
								}
								break;
							case _MYSQL_COM_STMT_PREPARE:
							case _MYSQL_COM_STMT_EXECUTE:
							case _MYSQL_COM_STMT_RESET:
							case _MYSQL_COM_STMT_CLOSE:
							case _MYSQL_COM_STMT_SEND_LONG_DATA:
								GPFC_PreparedStatements(pkt, c);
								break;
							case _MYSQL_COM_BINLOG_DUMP:
							case _MYSQL_COM_BINLOG_DUMP_GTID:
							case _MYSQL_COM_REGISTER_SLAVE:
								GPFC_Replication_SwitchToFastForward(pkt, c);
								break;
							case _MYSQL_COM_QUIT:
								proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_QUIT packet\n");
								if (GloMyLogger) { GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_QUIT, this, NULL); }
								l_free(pkt.size,pkt.ptr);
								handler_ret = -1;
								return handler_ret;
								break;
							default:
								// in this switch we only handle the most common commands.
								// The not common commands are handled by "default" , that
								// calls the following function
								// handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM__various
								if (handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM__various(&pkt, &wrong_pass)==false) {
									// If even this cannot find the command, we return an error to the client
									proxy_error("RECEIVED AN UNKNOWN COMMAND: %d -- PLEASE REPORT A BUG\n", c);
									l_free(pkt.size,pkt.ptr);
									handler_ret = -1; // immediately drop the connection
									return handler_ret;
								}
								break;
						}
						break;
					default:
						handler___status_WAITING_CLIENT_DATA___default();
						handler_ret = -1;
						return handler_ret;
						break;
				}
				break;
			default:
				handler_ret = GPFC_Statuses2(wrong_pass, pkt);
				if (handler_ret != 0) {
					return handler_ret;
				}
		}
	}
	return handler_ret;
}
// end of MySQL_Session::get_pkts_from_client()

/**
 * @brief Handler for processing query errors and checking backend connection status.
 *
 * This function handles query errors and checks the status of the backend connection.
 * It evaluates the server status and takes appropriate actions based on specific conditions.
 *
 * @param myds Pointer to the MySQL data stream associated with the session.
 *
 * @return Returns an integer status code indicating the result of the error handling:
 * - 0: No action required, query processing can continue.
 * - 1: Retry required due to backend connection status, query processing needs to be retried.
 * - -1: Error encountered, query processing cannot continue.
 */

int MySQL_Session::handler_ProcessingQueryError_CheckBackendConnectionStatus(MySQL_Data_Stream *myds) {
	MySQL_Connection *myconn = myds->myconn;
	// the query failed
	if (myconn->IsServerOffline()) {
		// Set maximum connect time if connect timeout is configured
		if (mysql_thread___connect_timeout_server_max) {
			myds->max_connect_time=thread->curtime+mysql_thread___connect_timeout_server_max*1000;
		}

		// Variables to track retry and error conditions
		bool retry_conn=false;
		if (myconn->server_status==MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) {
			thread->status_variables.stvar[st_var_backend_lagging_during_query]++;
			proxy_error("Detected a lagging server during query: %s, %d, session_id:%u\n", myconn->parent->address, myconn->parent->port, this->thread_session_id);
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, ER_PROXYSQL_LAGGING_SRV);
		} else if (myconn->server_status == MYSQL_SERVER_STATUS_ONLINE && myconn->parent->myhgc->online_servers_within_threshold() == false) {
			//proxy_error("Number of online servers detected in a hostgroup exceeds the configured maximum online servers. %s, %d, hostgroup:%u, num_online_servers:%u, max_online_servers:%u, session_id:%u\n", 
			//	myconn->parent->address, myconn->parent->port, myconn->parent->myhgc->hid, num_online_servers, myconn->parent->myhgc->attributes.max_num_online_servers, this->thread_session_id);
			myconn->parent->myhgc->log_num_online_server_count_error();
		} else {
			thread->status_variables.stvar[st_var_backend_offline_during_query]++;
			proxy_error("Detected an offline server during query: %s, %d, session_id:%u\n", myconn->parent->address, myconn->parent->port, this->thread_session_id);
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, ER_PROXYSQL_OFFLINE_SRV);
		}

		// Retry the query if retries are allowed and conditions permit
		if (myds->query_retries_on_failure > 0) {
			myds->query_retries_on_failure--;
			if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
				if (myds->myconn->MyRS && myds->myconn->MyRS->transfer_started) {
				// transfer to frontend has started, we cannot retry
				} else {
					retry_conn=true;
					proxy_warning("Retrying query.\n");
				}
			}
		}

		// Destroy MySQL connection from pool and reset file descriptor
		myds->destroy_MySQL_Connection_From_Pool(false);
		myds->fd=0;
		if (retry_conn) {
			myds->DSS=STATE_NOT_INITIALIZED;
			// Sets the previous status of the MySQL session according to the current status.
			set_previous_status_mode3();
			return 1;
		}
		return -1;
	}
	return 0;
}

void MySQL_Session::SetQueryTimeout() {
	mybe->server_myds->wait_until=0;
	if (qpo) {
		if (qpo->timeout > 0) {
			unsigned long long qr_timeout=qpo->timeout;
			mybe->server_myds->wait_until=thread->curtime;
			mybe->server_myds->wait_until+=qr_timeout*1000;
		}
	}
	if (mysql_thread___default_query_timeout) {
		if (mybe->server_myds->wait_until==0) {
			mybe->server_myds->wait_until=thread->curtime;
			unsigned long long def_query_timeout=mysql_thread___default_query_timeout;
			mybe->server_myds->wait_until+=def_query_timeout*1000;
		}
	}
}

// this function used to be inline.
// now it returns:
// true: NEXT_IMMEDIATE(st) needs to be called
// false: continue
bool MySQL_Session::handler_rc0_PROCESSING_STMT_PREPARE(enum session_status& st, MySQL_Data_Stream *myds, bool& prepared_stmt_with_no_params) {
	thread->status_variables.stvar[st_var_backend_stmt_prepare]++;
	GloMyStmt->wrlock();
	uint32_t client_stmtid=0;
	uint64_t global_stmtid;
	//bool is_new;
	MySQL_STMT_Global_info *stmt_info=NULL;
	stmt_info=GloMyStmt->add_prepared_statement(
		(char *)client_myds->myconn->userinfo->username,
		(char *)client_myds->myconn->userinfo->schemaname,
		(char *)CurrentQuery.QueryPointer,
		CurrentQuery.QueryLength,
		CurrentQuery.QueryParserArgs.first_comment,
		CurrentQuery.mysql_stmt,
		false);
	if (CurrentQuery.QueryParserArgs.digest_text) {
		if (stmt_info->digest_text==NULL) {
			stmt_info->digest_text=strdup(CurrentQuery.QueryParserArgs.digest_text);
			stmt_info->digest=CurrentQuery.QueryParserArgs.digest;	// copy digest
			stmt_info->MyComQueryCmd=CurrentQuery.MyComQueryCmd; // copy MyComQueryCmd
			stmt_info->calculate_mem_usage();
		}
	}
	global_stmtid=stmt_info->statement_id;
	myds->myconn->local_stmts->backend_insert(global_stmtid,CurrentQuery.mysql_stmt);
	// We only perform the generation for a new 'client_stmt_id' when there is no previous status, this
	// is, when 'PROCESSING_STMT_PREPARE' is reached directly without transitioning from a previous status
	// like 'PROCESSING_STMT_EXECUTE'. The same condition needs to hold for setting 'stmt_client_id',
	// otherwise we could be resetting it's current value from the previous state.
	if (previous_status.size() == 0) {
		client_stmtid=client_myds->myconn->local_stmts->generate_new_client_stmt_id(global_stmtid);
		CurrentQuery.stmt_client_id=client_stmtid;
	}
	CurrentQuery.mysql_stmt=NULL;
	st=status;
	size_t sts=previous_status.size();
	if (sts) {
		myds->myconn->async_state_machine=ASYNC_IDLE;
		myds->DSS=STATE_MARIADB_GENERIC;
		st=previous_status.top();
		previous_status.pop();
		GloMyStmt->unlock();
		return true;
		//NEXT_IMMEDIATE(st);
	} else {
		client_myds->myprot.generate_STMT_PREPARE_RESPONSE(client_myds->pkt_sid+1,stmt_info,client_stmtid);
		if (stmt_info->num_params == 0) {
			prepared_stmt_with_no_params = true;
		}
		LogQuery(myds);
		GloMyStmt->unlock();
	}
	return false;
}


// this function used to be inline
void MySQL_Session::handler_rc0_PROCESSING_STMT_EXECUTE(MySQL_Data_Stream *myds) {
	thread->status_variables.stvar[st_var_backend_stmt_execute]++;
	PROXY_TRACE2();
	if (CurrentQuery.mysql_stmt) {
		// See issue #1574. Metadata needs to be updated in case of need also
		// during STMT_EXECUTE, so a failure in the prepared statement
		// metadata cache is only hit once. This way we ensure that the next
		// 'PREPARE' will be answered with the properly updated metadata.
		/********************************************************************/
		// Lock the global statement manager
		GloMyStmt->wrlock();
		// Update the global prepared statement metadata
		MySQL_STMT_Global_info *stmt_info = GloMyStmt->find_prepared_statement_by_stmt_id(CurrentQuery.stmt_global_id, false);
		stmt_info->update_metadata(CurrentQuery.mysql_stmt);
		// Unlock the global statement manager
		GloMyStmt->unlock();
		/********************************************************************/
	}
	MySQL_Stmt_Result_to_MySQL_wire(CurrentQuery.mysql_stmt, myds->myconn);
	LogQuery(myds);
	if (CurrentQuery.stmt_meta) {
		if (CurrentQuery.stmt_meta->pkt) {
			uint32_t stmt_global_id=0;
			memcpy(&stmt_global_id,(char *)(CurrentQuery.stmt_meta->pkt)+5,sizeof(uint32_t));
			SLDH->reset(stmt_global_id);
			free(CurrentQuery.stmt_meta->pkt);
			CurrentQuery.stmt_meta->pkt=NULL;
		}

		// free for all the buffer types in which we allocate
		for (int i = 0; i < CurrentQuery.stmt_meta->num_params; i++) {
			enum enum_field_types buffer_type =
				CurrentQuery.stmt_meta->binds[i].buffer_type;

			if (
				(buffer_type == MYSQL_TYPE_TIME) ||
				(buffer_type == MYSQL_TYPE_DATE) ||
				(buffer_type == MYSQL_TYPE_TIMESTAMP) ||
				(buffer_type == MYSQL_TYPE_DATETIME)
			) {
				free(CurrentQuery.stmt_meta->binds[i].buffer);
				// NOTE: This memory should be zeroed during initialization,
				// but we also nullify it here for extra safety. See #3546.
				CurrentQuery.stmt_meta->binds[i].buffer = NULL;
			}
		}
	}
	CurrentQuery.mysql_stmt=NULL;
}

// this function used to be inline.
// now it returns:
// true: NEXT_IMMEDIATE(CONNECTING_SERVER) needs to be called
// false: continue
bool MySQL_Session::handler_minus1_ClientLibraryError(MySQL_Data_Stream *myds, int myerr, char **errmsg) {
	MySQL_Connection *myconn = myds->myconn;
	bool retry_conn=false;
	// client error, serious
	detected_broken_connection(__FILE__ , __LINE__ , __func__ , "running query", myconn, myerr, mysql_error(myconn->mysql) , true);
	if (myds->query_retries_on_failure > 0) {
		myds->query_retries_on_failure--;
		if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
			if (myds->myconn->MyRS && myds->myconn->MyRS->transfer_started) {
			// transfer to frontend has started, we cannot retry
			} else {
				if (myds->myconn->mysql->server_status & SERVER_MORE_RESULTS_EXIST) {
					// transfer to frontend has started, because this is, at least,
					// the second resultset coming from the server
					// we cannot retry
					proxy_warning("Disabling query retry because SERVER_MORE_RESULTS_EXIST is set\n");
				} else {
					retry_conn=true;
					proxy_warning("Retrying query.\n");
				}
			}
		}
	}
	myds->destroy_MySQL_Connection_From_Pool(false);
	myds->fd=0;
	if (retry_conn) {
		myds->DSS=STATE_NOT_INITIALIZED;
		// Sets the previous status of the MySQL session according to the current status.
		set_previous_status_mode3();
		if (*errmsg) {
			free(*errmsg);
			*errmsg = NULL;
		}
		return true;
	}
	if (*errmsg) {
		free(*errmsg);
		*errmsg = NULL;
	}
	return false;
}


// this function was inline
void MySQL_Session::handler_minus1_LogErrorDuringQuery(MySQL_Connection *myconn, int myerr, char *errmsg) {
	if (mysql_thread___verbose_query_error) {
		proxy_warning("Error during query on (%d,%s,%d,%lu) , user \"%s@%s\" , schema \"%s\" , %d, %s . digest_text = \"%s\"\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myconn->get_mysql_thread_id(), client_myds->myconn->userinfo->username, (client_myds->addr.addr ? client_myds->addr.addr : (char *)"unknown" ), client_myds->myconn->userinfo->schemaname, myerr, ( errmsg ? errmsg : mysql_error(myconn->mysql)), CurrentQuery.QueryParserArgs.digest_text );
	} else {
		proxy_warning("Error during query on (%d,%s,%d,%lu): %d, %s\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myconn->get_mysql_thread_id(), myerr, ( errmsg ? errmsg : mysql_error(myconn->mysql)));
	}
	MyHGM->add_mysql_errors(myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, client_myds->myconn->userinfo->username, (client_myds->addr.addr ? client_myds->addr.addr : (char *)"unknown" ), client_myds->myconn->userinfo->schemaname, myerr, (char *)( errmsg ? errmsg : mysql_error(myconn->mysql)));
}


// this function used to be inline.
// now it returns:
// true:
//		if handler_ret == -1 : return
//		if handler_ret == 0 : NEXT_IMMEDIATE(CONNECTING_SERVER) needs to be called
// false: continue
bool MySQL_Session::handler_minus1_HandleErrorCodes(MySQL_Data_Stream *myds, int myerr, char **errmsg, int& handler_ret) {
	bool retry_conn=false;
	MySQL_Connection * myconn = myds->myconn;
	handler_ret = 0; // default
	switch (myerr) {
		case 1317:  // Query execution was interrupted
			if (killed==true) { // this session is being kiled
				handler_ret = -1;
				return true;
			}
			if (myds->killed_at) {
				// we intentionally killed the query
				break;
			}
			break;
		case 1047: // WSREP has not yet prepared node for application use
		case 1053: // Server shutdown in progress
			myconn->parent->connect_error(myerr);
			if (myds->query_retries_on_failure > 0) {
				myds->query_retries_on_failure--;
				if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
					retry_conn=true;
					proxy_warning("Retrying query.\n");
				}
			}
			switch (myerr) {
				case 1047: // WSREP has not yet prepared node for application use
				case 1053: // Server shutdown in progress
					myds->destroy_MySQL_Connection_From_Pool(false);
					break;
				default:
					if (mysql_thread___reset_connection_algorithm == 2) {
						create_new_session_and_reset_connection(myds);
					} else {
						myds->destroy_MySQL_Connection_From_Pool(true);
					}
					break;
			}
			myconn = myds->myconn;
			myds->fd=0;
			if (retry_conn) {
				myds->DSS=STATE_NOT_INITIALIZED;
				// Sets the previous status of the MySQL session according to the current status.
				set_previous_status_mode3(false);
				if (*errmsg) {
					free(*errmsg);
					*errmsg = NULL;
				}
				return true; // it will call NEXT_IMMEDIATE(CONNECTING_SERVER);
				//NEXT_IMMEDIATE(CONNECTING_SERVER);
			}
			//handler_ret = -1;
			//return handler_ret;
			break;
		case 1153: // ER_NET_PACKET_TOO_LARGE
			proxy_warning("Error ER_NET_PACKET_TOO_LARGE during query on (%d,%s,%d,%lu): %d, %s\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myconn->get_mysql_thread_id(), myerr, mysql_error(myconn->mysql));
			break;
		default:
			break; // continue normally
	}
	return false;
}

// this function used to be inline.
void MySQL_Session::handler_minus1_GenerateErrorMessage(MySQL_Data_Stream *myds, MySQL_Connection *myconn, bool& wrong_pass) {
	switch (status) {
		case PROCESSING_QUERY:
			if (myconn) {
				MySQL_Result_to_MySQL_wire(myconn->mysql, myconn->MyRS, myconn->warning_count, myds);
			} else {
				MySQL_Result_to_MySQL_wire(NULL, NULL, 0, myds);
			}
			break;
		case PROCESSING_STMT_PREPARE:
			{
				char sqlstate[10];
				if (myconn && myconn->mysql) {
					sprintf(sqlstate,"%s",mysql_sqlstate(myconn->mysql));
					client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,mysql_errno(myconn->mysql),sqlstate,(char *)mysql_stmt_error(myconn->query.stmt));
					GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_CLOSE, this, NULL);
				} else {
					client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1, 2013, (char *)"HY000" ,(char *)"Lost connection to MySQL server during query");
					GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_CLOSE, this, NULL);
				}
				client_myds->pkt_sid++;
				if (previous_status.size()) {
					// an STMT_PREPARE failed
					// we have a previous status, probably STMT_EXECUTE,
					//    but returning to that status is not safe after STMT_PREPARE failed
					// for this reason we exit immediately
					wrong_pass=true;
				}
			}
			break;
		case PROCESSING_STMT_EXECUTE:
			{
				char sqlstate[10];
				if (myconn && myconn->mysql) {
					if (myconn->MyRS) {
						PROXY_TRACE2();
						myds->sess->handler_rc0_PROCESSING_STMT_EXECUTE(myds);
					} else {
						sprintf(sqlstate,"%s",mysql_sqlstate(myconn->mysql));
						client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,mysql_errno(myconn->mysql),sqlstate,(char *)mysql_stmt_error(myconn->query.stmt));
					}
				} else {
					client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1, 2013, (char *)"HY000" ,(char *)"Lost connection to MySQL server during query");
				}
				client_myds->pkt_sid++;
			}
			break;
		default:
			// LCOV_EXCL_START
			assert(0);
			break;
			// LCOV_EXCL_STOP
	}
}

// this function was inline
void MySQL_Session::handler_minus1_HandleBackendConnection(MySQL_Data_Stream *myds, MySQL_Connection *myconn) {
	if (myds->myconn) {
		myds->myconn->reduce_auto_increment_delay_token();
		if (mysql_thread___multiplexing && (myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
			myds->DSS=STATE_NOT_INITIALIZED;
			if (mysql_thread___autocommit_false_not_reusable && myds->myconn->IsAutoCommit()==false) {
				if (mysql_thread___reset_connection_algorithm == 2) {
					create_new_session_and_reset_connection(myds);
				} else {
					myds->destroy_MySQL_Connection_From_Pool(true);
				}
			} else {
				myds->return_MySQL_Connection_To_Pool();
			}
		} else {
			myconn->async_state_machine=ASYNC_IDLE;
			myds->DSS=STATE_MARIADB_GENERIC;
		}
	}
}

// this function was inline
/**
 * @brief Run a MySQL query on the current session.
 *
 * This function executes a MySQL query on the current session based on its status.
 * The query execution is asynchronous and handled by the specified MySQL connection.
 * It returns the result code of the asynchronous query execution.
 *
 * @param myds Pointer to the MySQL data stream associated with the session.
 * @param myconn Pointer to the MySQL connection used to execute the query.
 *
 * @return Returns an integer status code indicating the result of the query execution,
 * as returned by async_query():
 * - 0: Query execution completed successfully.
 * - -1: Query execution failed.
 * - 1: Query execution in progress.
 * - 2: Processing a multi-statement query, control needs to be transferred to MySQL_Session.
 * - 3: In the middle of processing a multi-statement query.
 */
int MySQL_Session::RunQuery(MySQL_Data_Stream *myds, MySQL_Connection *myconn) {
	PROXY_TRACE2();
	int rc = 0;
	switch (status) {
		case PROCESSING_QUERY:
			rc=myconn->async_query(myds->revents, myds->mysql_real_query.QueryPtr,myds->mysql_real_query.QuerySize);
			break;
		case PROCESSING_STMT_PREPARE:
			rc=myconn->async_query(myds->revents, (char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength,&CurrentQuery.mysql_stmt);
			break;
		case PROCESSING_STMT_EXECUTE:
			PROXY_TRACE2();
			rc=myconn->async_query(myds->revents, (char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength,&CurrentQuery.mysql_stmt, CurrentQuery.stmt_meta);
			break;
		default:
			// LCOV_EXCL_START
			assert(0);
			break;
			// LCOV_EXCL_STOP
	}
	return rc;
}

// this function was inline
void MySQL_Session::handler___status_WAITING_CLIENT_DATA() {
// NOTE: Maintenance of 'multiplex_delayed' has been moved to 'housekeeping_before_pkts'. The previous impl
// is left below as an example of how to perform a more passive maintenance over session connections.
/*
	if (mybes) {
		MySQL_Backend *_mybe;
		unsigned int i;
		for (i=0; i < mybes->len; i++) {
			_mybe=(MySQL_Backend *)mybes->index(i);
			if (_mybe->server_myds) {
				MySQL_Data_Stream *_myds=_mybe->server_myds;
				if (_myds->myconn) {
					if (_myds->myconn->multiplex_delayed) {
						if (_myds->wait_until <= thread->curtime) {
							_myds->wait_until=0;
							_myds->myconn->multiplex_delayed=false;
							_myds->DSS=STATE_NOT_INITIALIZED;
							_myds->return_MySQL_Connection_To_Pool();
						}
					}
				}
			}
		}
	}
*/
}

/**
 * @brief Perform housekeeping tasks before processing packets.
 *
 * This function is responsible for performing necessary housekeeping tasks
 * before processing packets. These tasks include handling expired connections
 * for multiplexing scenarios. If multiplexing is enabled, it iterates over
 * the list of expired backend connections and either returns them to the connection pool
 * or destroys them based on certain conditions.
 *
 * @note This function assumes that the `hgs_expired_conns` vector contains the IDs
 *       of the backend connections that have expired.
 *
 * @return None.
 */
void MySQL_Session::housekeeping_before_pkts() {
	if (mysql_thread___multiplexing) {
		for (const int hg_id : hgs_expired_conns) {
			MySQL_Backend* mybe = find_backend(hg_id);

			if (mybe != nullptr) {
				MySQL_Data_Stream* myds = mybe->server_myds;

				if (mysql_thread___autocommit_false_not_reusable && myds->myconn->IsAutoCommit()==false) {
					if (mysql_thread___reset_connection_algorithm == 2) {
						create_new_session_and_reset_connection(myds);
					} else {
						myds->destroy_MySQL_Connection_From_Pool(true);
					}
				} else {
					myds->return_MySQL_Connection_To_Pool();
				}
			}
		}
		// We are required to perform a cleanup after consuming the elements, thus preventing any subsequent
		// 'handler' call to perform recomputing of the already processed elements.
		if (hgs_expired_conns.empty() == false) {
			hgs_expired_conns.clear();
		}
	}
}

// this function was inline
/**
 * @brief Process the GTID received from the MySQL connection when the handler return code is 0.
 *
 * This function is responsible for processing the GTID (Global Transaction Identifier)
 * received from the MySQL connection when the handler return code is 0. It extracts
 * the GTID and transaction ID from the MySQL connection and performs additional
 * actions if necessary based on the configuration.
 *
 * @param myconn A pointer to the MySQL_Connection object from which to extract the GTID.
 *               This object contains the necessary information about the connection.
 *
 * @return None.
 */
void MySQL_Session::handler_rc0_Process_GTID(MySQL_Connection *myconn) {
	if (myconn->get_gtid(mybe->gtid_uuid,&mybe->gtid_trxid)) {
		if (mysql_thread___client_session_track_gtid) {
			gtid_hid = current_hostgroup;
			memcpy(gtid_buf,mybe->gtid_uuid,sizeof(gtid_buf));
		}
	}
}

void MySQL_Session::handler_KillConnectionIfNeeded() {
	if ( // two conditions
		// If the server connection is in a non-idle state (ASYNC_IDLE), and the current time is greater than or equal to mybe->server_myds->wait_until
		// This indicates that the server is taking too long to respond.
		(mybe->server_myds->myconn && mybe->server_myds->myconn->async_state_machine!=ASYNC_IDLE && mybe->server_myds->wait_until && thread->curtime >= mybe->server_myds->wait_until)
		||
		// If the session has been marked as killed by an admin.
		(killed==true)
	) { // Logging and Action
		// we only log in case on timing out here. Logging for 'killed' is done in the places that hold that contextual information.
		if (mybe->server_myds->myconn && (mybe->server_myds->myconn->async_state_machine != ASYNC_IDLE) && mybe->server_myds->wait_until && (thread->curtime >= mybe->server_myds->wait_until)) {
			std::string query {};

			if (CurrentQuery.stmt_info == NULL) { // text protocol
				query = std::string { mybe->server_myds->myconn->query.ptr, mybe->server_myds->myconn->query.length };
			} else { // prepared statement
				query = std::string { CurrentQuery.stmt_info->query, CurrentQuery.stmt_info->query_length };
			}

			std::string client_addr { "" };
			int client_port = 0;

			if (client_myds) {
				client_addr = client_myds->addr.addr ? client_myds->addr.addr : "";
				client_port = client_myds->addr.port;
			}
			// it logs a warning message indicating the query that caused the timeout, along with client details.
			proxy_warning(
				"Killing connection %s:%d because query '%s' from client '%s':%d timed out.\n",
				mybe->server_myds->myconn->parent->address,
				mybe->server_myds->myconn->parent->port,
				query.c_str(),
				client_addr.c_str(),
				client_port
			);
		}
		// it calls handler_again___new_thread_to_kill_connection() to initiate the killing of the connection associated with the session that timed out.
		handler_again___new_thread_to_kill_connection();
	}
}

void MySQL_Session::handler_rc0_RefreshActiveTransactions(MySQL_Connection* myconn) {
	if ((myconn->mysql->server_status & SERVER_STATUS_IN_TRANS) == 0) { // there is no transaction on the backend connection
		active_transactions = NumActiveTransactions(); // we check all the hostgroups/backends
		if (active_transactions == 0)
			transaction_started_at = 0; // reset it
	}
}

int MySQL_Session::handler() {
	int handler_ret = 0;
	bool prepared_stmt_with_no_params = false;
	bool wrong_pass=false;
	if (to_process==0) return 0; // this should be redundant if the called does the same check
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Processing session %p\n" , this->thread, this, this);
	//unsigned int j;
	//unsigned char c;

//	FIXME: Sessions without frontend are an ugly hack
	if (session_fast_forward==false) {
	if (client_myds==NULL) {
		// if we are here, probably we are trying to ping backends
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Processing session %p without client_myds\n", this);
		assert(mybe);
		assert(mybe->server_myds);
		goto handler_again;
	} else {
		if (mirror==true) {
			if (mirrorPkt.ptr) { // this is the first time we call handler()
				pkt.ptr=mirrorPkt.ptr;
				pkt.size=mirrorPkt.size;
				mirrorPkt.ptr=NULL; // this will prevent the copy to happen again
			} else {
				if (status==WAITING_CLIENT_DATA) {
					// we are being called a second time with WAITING_CLIENT_DATA
					handler_ret = 0;
					return handler_ret;
				}
			}
		}
	}
	}

	// housekeeping_before_pkts() performs tasks only if hgs_expired_conns.size() is not 0
	if (hgs_expired_conns.size() != 0)
		housekeeping_before_pkts();
	// The function get_pkts_from_client() is called to retrieve packets from the client, passing a reference to wrong_pass and the pkt variable.
	handler_ret = get_pkts_from_client(wrong_pass, pkt);
	// If get_pkts_from_client() returns a non-zero value, indicating an error, the function returns that value immediately.
	if (handler_ret != 0) {
		return handler_ret;
	}

handler_again:

	switch (status) {
		case WAITING_CLIENT_DATA:
			// housekeeping
			handler___status_WAITING_CLIENT_DATA();
			break;
		case FAST_FORWARD:
			if (mybe->server_myds->mypolls==NULL) {
				// register the mysql_data_stream
				thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
			}
			client_myds->PSarrayOUT->copy_add(mybe->server_myds->PSarrayIN, 0, mybe->server_myds->PSarrayIN->len);
			while (mybe->server_myds->PSarrayIN->len) mybe->server_myds->PSarrayIN->remove_index(mybe->server_myds->PSarrayIN->len-1,NULL);
			break;
		case CONNECTING_CLIENT:
			//fprintf(stderr,"CONNECTING_CLIENT\n");
			// FIXME: to implement
			break;
		case PINGING_SERVER:
			{
				int rc=handler_again___status_PINGING_SERVER();
				if (rc==-1) { // if the ping fails, we destroy the session
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case RESETTING_CONNECTION:
			{
				int rc = handler_again___status_RESETTING_CONNECTION();
				if (rc==-1) { // we always destroy the session
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case PROCESSING_STMT_PREPARE:
		case PROCESSING_STMT_EXECUTE:
		case PROCESSING_QUERY:
			//fprintf(stderr,"PROCESSING_QUERY\n");
			// Pause Check
			// It checks if pause_until is greater than the current time (thread->curtime).
			// If so, it returns handler_ret immediately, indicating that processing should be paused until a later time.
			if (pause_until > thread->curtime) {
				handler_ret = 0;
				return handler_ret;
			}
			if (mysql_thread___connect_timeout_server_max) {
				if (mybe->server_myds->max_connect_time==0) {
					// set max_connect_time to the current time plus the specified timeout value
					mybe->server_myds->max_connect_time=thread->curtime+(long long)mysql_thread___connect_timeout_server_max*1000;
				}
			} else {
				// set max_connect_time to zero, indicating no timeout
				mybe->server_myds->max_connect_time=0;
			}
			handler_KillConnectionIfNeeded();

			// checks if the backend MySQL server associated with the session has been initialized (STATE_NOT_INITIALIZED)
			if (mybe->server_myds->DSS==STATE_NOT_INITIALIZED) {
				// we don't have a backend yet
				// It saves the current processing status of the session (status) onto the previous_status stack
				// Sets the previous status of the MySQL session according to the current status.
				set_previous_status_mode3();
				// It transitions the session to the CONNECTING_SERVER state immediately.
				NEXT_IMMEDIATE(CONNECTING_SERVER);
			} else {
				MySQL_Data_Stream *myds=mybe->server_myds;
				MySQL_Connection *myconn=myds->myconn;
				mybe->server_myds->max_connect_time=0;
				// we insert it in mypolls only if not already there
				if (myds->mypolls==NULL) {
					thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
				}
				if (default_hostgroup>=0) {
					if (handler_again___verify_backend_user_schema()) {
						goto handler_again;
					}
					if (mirror==false) { // do not care about autocommit and charset if mirror
							proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , default_HG=%d server_myds DSS=%d , locked_on_HG=%d\n", this, default_hostgroup, mybe->server_myds->DSS, locked_on_hostgroup);
						if (mybe->server_myds->DSS == STATE_READY || mybe->server_myds->DSS == STATE_MARIADB_GENERIC) {
							if (handler_again___verify_init_connect()) {
								goto handler_again;
							}
							if (use_ldap_auth) {
								if (handler_again___verify_ldap_user_variable()) {
									goto handler_again;
								}
							}
							if (handler_again___verify_backend_autocommit()) {
								goto handler_again;
							}
							if (locked_on_hostgroup == -1 || locked_on_hostgroup_and_all_variables_set == false ) {

								if (handler_again___verify_backend_multi_statement()) {
									goto handler_again;
								}

								if (handler_again___verify_backend_session_track_gtids()) {
									goto handler_again;
								}

								// Optimize network traffic when we can use 'SET NAMES'
								if (verify_set_names(this)) {
									goto handler_again;
								}

								if (handler_again___verify_multiple_variables(myconn) == true) {
									goto handler_again;
								}

								if (locked_on_hostgroup != -1) {
									locked_on_hostgroup_and_all_variables_set=true;
								}
							}
						}
						if (status==PROCESSING_STMT_EXECUTE) {
							// It attempts to find the backend statement associated with the current global statement ID (stmt_global_id) in the local statement cache of the connection (myconn).
							CurrentQuery.mysql_stmt=myconn->local_stmts->find_backend_stmt_by_global_id(CurrentQuery.stmt_global_id);
							if (CurrentQuery.mysql_stmt==NULL) {
								// the connection does not have the prepared statement metadata
								MySQL_STMT_Global_info *stmt_info=NULL;
								// the connection we too doesn't have the prepared statements prepared
								// we try to create it now
								// In this case, it proceeds to create the prepared statement based on the global statement ID (stmt_global_id).
								// It retrieves the prepared statement information (stmt_info) from a global prepared statement cache (GloMyStmt) using the statement ID.
								stmt_info=GloMyStmt->find_prepared_statement_by_stmt_id(CurrentQuery.stmt_global_id);
								// It updates the CurrentQuery structure with the query information from the prepared statement (stmt_info).
								CurrentQuery.QueryLength=stmt_info->query_length;
								CurrentQuery.QueryPointer=(unsigned char *)stmt_info->query;
								// NOTE: Update 'first_comment' with the 'first_comment' from the retrieved
								// 'stmt_info' from the found prepared statement. 'CurrentQuery' requires its
								// own copy of 'first_comment' because it will later be free by 'QueryInfo::end'.
								if (stmt_info->first_comment) {
									// If the prepared statement contains a first_comment, it updates the first_comment field of CurrentQuery.
									CurrentQuery.QueryParserArgs.first_comment=strdup(stmt_info->first_comment);
								}
								// It pushes the current processing status (PROCESSING_STMT_EXECUTE) onto the previous_status stack to track the previous state transition.
								previous_status.push(PROCESSING_STMT_EXECUTE);
								// It transitions the processing status to PROCESSING_STMT_PREPARE immediately using the NEXT_IMMEDIATE macro.
								NEXT_IMMEDIATE(PROCESSING_STMT_PREPARE);
								//if (CurrentQuery.stmt_global_id!=stmt_info->statement_id) {
								//	PROXY_TRACE();
								//}
							}
						}
					}
				}

				if (myconn->async_state_machine==ASYNC_IDLE) {
					SetQueryTimeout();
				}
				int rc;
				// declares two timespec variables begint and endt to store the start and end times of the query execution.
				timespec begint;
				timespec endt;
				// If the stats_time_backend_query flag in the thread's variables is set,
				// it records the start time of the query execution using clock_gettime with CLOCK_THREAD_CPUTIME_ID.
				if (thread->variables.stats_time_backend_query) {
					clock_gettime(CLOCK_THREAD_CPUTIME_ID,&begint);
				}
				// It calls the RunQuery function to execute the query on the backend.
				rc = RunQuery(myds, myconn);
				// If the stats_time_backend_query flag is set, it records the end time
				// of the query execution using clock_gettime with CLOCK_THREAD_CPUTIME_ID.
				if (thread->variables.stats_time_backend_query) {
					clock_gettime(CLOCK_THREAD_CPUTIME_ID,&endt);
					// It calculates the duration of the query execution by subtracting the start time (begint) from the end time (endt)
					// and adds it to the stvar_backend_query_time status variable in the thread's status variables.
					thread->status_variables.stvar[st_var_backend_query_time] = thread->status_variables.stvar[st_var_backend_query_time] +
						(endt.tv_sec*1000000000+endt.tv_nsec) -
						(begint.tv_sec*1000000000+begint.tv_nsec);
				}
				gtid_hid = -1;
				if (rc==0) {

					if (active_transactions != 0) {  // run this only if currently we think there is a transaction
						handler_rc0_RefreshActiveTransactions(myconn);
					}

					handler_rc0_Process_GTID(myconn);

					// if we are locked on hostgroup, the value of autocommit is copied from the backend connection
					// see bug #3549
					if (locked_on_hostgroup >= 0) {
						assert(myconn != NULL);
						assert(myconn->mysql != NULL);
						autocommit = myconn->mysql->server_status & SERVER_STATUS_AUTOCOMMIT;
					}

					if (mirror == false) {
						// Support for LAST_INSERT_ID()
						if (myconn->mysql->insert_id) {
							last_insert_id=myconn->mysql->insert_id;
						}
						if (myconn->mysql->affected_rows) {
							if (myconn->mysql->affected_rows != ULLONG_MAX) {
								last_HG_affected_rows = current_hostgroup;
								if (mysql_thread___auto_increment_delay_multiplex && myconn->mysql->insert_id) {
									myconn->auto_increment_delay_token = mysql_thread___auto_increment_delay_multiplex + 1;
									__sync_fetch_and_add(&MyHGM->status.auto_increment_delay_multiplex, 1);
								}
							}
						}
					}

					switch (status) {
						case PROCESSING_QUERY:
							MySQL_Result_to_MySQL_wire(myconn->mysql, myconn->MyRS, myconn->warning_count, myconn->myds);
							break;
						case PROCESSING_STMT_PREPARE:
							{
								enum session_status st;
								if (handler_rc0_PROCESSING_STMT_PREPARE(st, myds, prepared_stmt_with_no_params)) {
									NEXT_IMMEDIATE(st);
								}
							}
							break;
						case PROCESSING_STMT_EXECUTE:
							handler_rc0_PROCESSING_STMT_EXECUTE(myds);
							break;
						default:
							// LCOV_EXCL_START
							assert(0);
							break;
							// LCOV_EXCL_STOP
					}

					if (mysql_thread___log_mysql_warnings_enabled) {
						auto warn_no = mysql_warning_count(myconn->mysql);
						if (warn_no > 0) {
							// Backup actual digest causing the warning before it's destroyed by finishing the request
							const char* digest_text = CurrentQuery.get_digest_text();
							CurrentQuery.show_warnings_prev_query_digest = digest_text == NULL ? "" : digest_text;

							RequestEnd(myds);
							writeout();

							myconn->async_state_machine=ASYNC_IDLE;
							myds->DSS=STATE_MARIADB_GENERIC;

							NEXT_IMMEDIATE(SHOW_WARNINGS);
						}
					}

					RequestEnd(myds);
					finishQuery(myds,myconn,prepared_stmt_with_no_params);
				} else {
					if (rc==-1) {
						// the query failed
						int myerr=mysql_errno(myconn->mysql);
						char *errmsg = NULL;
						if (myerr == 0) {
							if (CurrentQuery.mysql_stmt) {
								myerr = mysql_stmt_errno(CurrentQuery.mysql_stmt);
								errmsg = strdup(mysql_stmt_error(CurrentQuery.mysql_stmt));
							}
						}
						MyHGM->p_update_mysql_error_counter(p_mysql_error_type::mysql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myerr);
						CurrentQuery.mysql_stmt=NULL; // immediately reset mysql_stmt
						int rc1 = handler_ProcessingQueryError_CheckBackendConnectionStatus(myds);
						if (rc1 == -1) {
							handler_ret = -1;
							return handler_ret;
						} else {
							if (rc1 == 1)
								NEXT_IMMEDIATE(CONNECTING_SERVER);
						}
						if (myerr >= 2000 && myerr < 3000) {
							if (handler_minus1_ClientLibraryError(myds, myerr, &errmsg)) {
								NEXT_IMMEDIATE(CONNECTING_SERVER);
							} else {
								handler_ret = -1;
								return handler_ret;
							}
						} else {
							handler_minus1_LogErrorDuringQuery(myconn, myerr, errmsg);
							if (handler_minus1_HandleErrorCodes(myds, myerr, &errmsg, handler_ret)) {
								if (handler_ret == 0)
									NEXT_IMMEDIATE(CONNECTING_SERVER);
								return handler_ret;
							}
							handler_minus1_GenerateErrorMessage(myds, myconn, wrong_pass);
							RequestEnd(myds, myerr);
							handler_minus1_HandleBackendConnection(myds, myconn);
						}
					} else {
						switch (rc) {
							// rc==1 , query is still running
							// start sending to frontend if mysql_thread___threshold_resultset_size is reached
							case 1:
								if (myconn->MyRS && myconn->MyRS->result && myconn->MyRS->resultset_size > (unsigned int) mysql_thread___threshold_resultset_size) {
									myconn->MyRS->get_resultset(client_myds->PSarrayOUT);
								}
								break;
							// rc==2 : a multi-resultset (or multi statement) was detected, and the current statement is completed
							case 2:
								MySQL_Result_to_MySQL_wire(myconn->mysql, myconn->MyRS, myconn->warning_count, myconn->myds);
								  if (myconn->MyRS) { // we also need to clear MyRS, so that the next staement will recreate it if needed
										if (myconn->MyRS_reuse) {
											delete myconn->MyRS_reuse;
										}
										//myconn->MyRS->reset_pid = false;
										myconn->MyRS_reuse = myconn->MyRS;
										myconn->MyRS=NULL;
									}
									NEXT_IMMEDIATE(PROCESSING_QUERY);
								break;
							// rc==3 , a multi statement query is still running
							// start sending to frontend if mysql_thread___threshold_resultset_size is reached
							case 3:
								if (myconn->MyRS && myconn->MyRS->result && myconn->MyRS->resultset_size > (unsigned int) mysql_thread___threshold_resultset_size) {
									myconn->MyRS->get_resultset(client_myds->PSarrayOUT);
								}
								break;
							default:
								break;
						}
					}
				}

				//goto __exit_DSS__STATE_NOT_INITIALIZED;


			}
			break;

		case SETTING_ISOLATION_LEVEL:
		case SETTING_TRANSACTION_READ:
		case SETTING_CHARSET:
		case SETTING_VARIABLE:
		case SETTING_NEXT_ISOLATION_LEVEL:
		case SETTING_NEXT_TRANSACTION_READ:
			{
				int rc = 0;
				if (mysql_variables.update_variable(this, status, rc)) {
					goto handler_again;
				}
				if (rc == -1) {
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case SHOW_WARNINGS:
			if (handler_again___status_SHOW_WARNINGS(mybe->server_myds, prepared_stmt_with_no_params) == true) {
				goto handler_again;
			} else {
				handler_ret = 0; return handler_ret;
			}
			break;

		case CONNECTING_SERVER:
			{
				int rc=0;
				if (handler_again___status_CONNECTING_SERVER(&rc))
					goto handler_again;	// we changed status
				//if (rc==1) //handler_again___status_CONNECTING_SERVER returns 1
				//	goto __exit_DSS__STATE_NOT_INITIALIZED;
			}
			break;
		case session_status___NONE:
			fprintf(stderr,"NONE\n");
		default:
			{
				int rc = 0;
				if (handler_again___multiple_statuses(&rc)) // a sort of catch all
					goto handler_again;	// we changed status
				if (rc==-1) { // we have an error we can't handle
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;
	}


//__exit_DSS__STATE_NOT_INITIALIZED:


#ifdef DEBUG
	if (mybe && mybe->server_myds) {
		if (mybe->server_myds->DSS > STATE_MARIADB_BEGIN && mybe->server_myds->DSS < STATE_MARIADB_END) {
			MySQL_Data_Stream *myds=mybe->server_myds;
			MySQL_Connection *myconn=mybe->server_myds->myconn;
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, status=%d, server_myds->DSS==%d , revents==%d , async_state_machine=%d\n", this, status, mybe->server_myds->DSS, myds->revents, myconn->async_state_machine);
		}
	}
#endif /* DEBUG */

	writeout();

	if (wrong_pass==true) {
		client_myds->array2buffer_full();
		client_myds->write_to_net();
		handler_ret = -1;
		return handler_ret;
	}
	handler_ret = 0;
	return handler_ret;
}
// end ::handler()


bool MySQL_Session::handler_again___status_SHOW_WARNINGS(MySQL_Data_Stream* myds, bool prepared_stmt_with_no_params) {
	// Performs a 'SHOW WARNINGS' query over the current backend connection and returns the connection back
	// to the connection pool when finished. Actual logging of received warnings is performed in
	// 'MySQL_Connection' while processing 'ASYNC_USE_RESULT_CONT'.
	MySQL_Connection *myconn=myds->myconn;

	// Setting POLLOUT is required just in case this state has been reached when 'RunQuery' from
	// 'PROCESSING_QUERY' state has immediately return. This is because in case 'mysql_real_query_start'
	// immediately returns with '0' the session is never processed again by 'MySQL_Thread', and 'revents' is
	// never updated with the result of polling through the 'MySQL_Thread::mypolls'.
	myds->revents |= POLLOUT;

	int rc = myconn->async_query(
		myds->revents,(char *)"SHOW WARNINGS", strlen((char *)"SHOW WARNINGS")
	);
	if (rc == 0 || rc == -1) {
		int myerr = 0;
		// Cleanup the connection resulset from 'SHOW WARNINGS' for the next query.
		if (myconn->MyRS != NULL) {
			delete myconn->MyRS;
			myconn->MyRS = NULL;
		}

		if (rc == -1) {
			myerr = mysql_errno(myconn->mysql);
			proxy_error(
				"'SHOW WARNINGS' failed to be executed over backend connection with error: '%d'\n", myerr
			);
		}

		RequestEnd(myds, myerr);
		finishQuery(myds,myconn,prepared_stmt_with_no_params);

		return false;
	} else {
		return true; // goto handler_again
	}
	return false; // default
}

/**
 * @brief Handle multiple session statuses.
 *
 * This function handles multiple session statuses by invoking specific handler
 * functions corresponding to each status. It checks the current session status
 * and delegates the handling to the appropriate handler function.
 *
 * @param[out] rc Pointer to an integer variable where the return code from the handler function will be stored.
 *
 * @return True if the handling was successful and false otherwise.
 */
bool MySQL_Session::handler_again___multiple_statuses(int *rc) {
	bool ret = false;
	switch(status) {
		case CHANGING_USER_SERVER:
			ret = handler_again___status_CHANGING_USER_SERVER(rc);
			break;
		case CHANGING_AUTOCOMMIT:
			ret = handler_again___status_CHANGING_AUTOCOMMIT(rc);
			break;
		case CHANGING_SCHEMA:
			ret = handler_again___status_CHANGING_SCHEMA(rc);
			break;
		case SETTING_LDAP_USER_VARIABLE:
			ret = handler_again___status_SETTING_LDAP_USER_VARIABLE(rc);
			break;
		case SETTING_INIT_CONNECT:
			ret = handler_again___status_SETTING_INIT_CONNECT(rc);
			break;
		case SETTING_MULTI_STMT:
			ret = handler_again___status_SETTING_MULTI_STMT(rc);
			break;
		case SETTING_SESSION_TRACK_GTIDS:
			ret = handler_again___status_SETTING_SESSION_TRACK_GTIDS(rc);
			break;
		case SETTING_SET_NAMES:
			ret = handler_again___status_CHANGING_CHARSET(rc);
			break;
		default:
			break;
	}
	return ret;
}

void MySQL_Session::handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE_WrongCredentials(PtrSize_t *pkt, bool *wrong_pass) {
	l_free(pkt->size,pkt->ptr);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session=%p , DS=%p . Wrong credentials for frontend: disconnecting\n", this, client_myds);
	*wrong_pass=true;
	// FIXME: this should become close connection
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	char *client_addr=NULL;
	if (client_myds->client_addr && client_myds->myconn->userinfo->username) {
		char buf[512];
		switch (client_myds->client_addr->sa_family) {
			case AF_INET: {
				struct sockaddr_in *ipv4 = (struct sockaddr_in *)client_myds->client_addr;
				if (ipv4->sin_port) {
					inet_ntop(client_myds->client_addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
					client_addr = strdup(buf);
				} else {
					client_addr = strdup((char *)"localhost");
				}
				break;
			}
			case AF_INET6: {
				struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)client_myds->client_addr;
				inet_ntop(client_myds->client_addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
				client_addr = strdup(buf);
				break;
			}
			default:
				client_addr = strdup((char *)"localhost");
				break;
		}
	} else {
		client_addr = strdup((char *)"");
	}
	if (client_myds->myconn->userinfo->username) {
		char *_s=(char *)malloc(strlen(client_myds->myconn->userinfo->username)+100+strlen(client_addr));
		//uint8_t _pid = 2;
		//if (client_myds->switching_auth_stage) _pid+=2;
		//if (is_encrypted) _pid++;
		uint8_t _pid = client_myds->pkt_sid; _pid++;
#ifdef DEBUG
	if (client_myds->myconn->userinfo->password) {
		char *tmp_pass=strdup(client_myds->myconn->userinfo->password);
		int lpass = strlen(tmp_pass);
		for (int i=2; i<lpass-1; i++) {
			tmp_pass[i]='*';
		}
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session=%p , DS=%p . Error: Access denied for user '%s'@'%s' , Password='%s'. Disconnecting\n", this, client_myds, client_myds->myconn->userinfo->username, client_addr, tmp_pass);
		free(tmp_pass);
	} else {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session=%p , DS=%p . Error: Access denied for user '%s'@'%s' . No password. Disconnecting\n", this, client_myds, client_myds->myconn->userinfo->username, client_addr);
	}
#endif // DEBUG
		sprintf(_s,"ProxySQL Error: Access denied for user '%s'@'%s' (using password: %s)", client_myds->myconn->userinfo->username, client_addr, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL, _pid, 1045,(char *)"28000", _s, true);
		proxy_error("ProxySQL Error: Access denied for user '%s'@'%s' (using password: %s)\n", client_myds->myconn->userinfo->username, client_addr, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
		free(_s);
		__sync_fetch_and_add(&MyHGM->status.access_denied_wrong_password, 1);
	}
	if (client_addr) {
		free(client_addr);
	}
	GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_ERR, this, NULL);
	__sync_add_and_fetch(&MyHGM->status.client_connections_aborted,1);
	client_myds->DSS=STATE_SLEEP;
}

void MySQL_Session::handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(PtrSize_t *pkt, bool *wrong_pass) {
	bool is_encrypted = client_myds->encrypted;
	bool handshake_response_return = client_myds->myprot.process_pkt_handshake_response((unsigned char *)pkt->ptr,pkt->size);
	bool handshake_err = true;

	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION,8,"Session=%p , DS=%p , handshake_response=%d , switching_auth_stage=%d , is_encrypted=%d , client_encrypted=%d\n", this, client_myds, handshake_response_return, client_myds->switching_auth_stage, is_encrypted, client_myds->encrypted);
	if (handshake_response_return == false) {
		if (client_myds->auth_in_progress != 0) {
			l_free(pkt->size,pkt->ptr);
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION,8,"Session=%p , DS=%p . Returning\n", this, client_myds);
			return;
		}
		if (
			(is_encrypted == false) && // the connection was encrypted
			(client_myds->encrypted == true) // client is asking for encryption
		) {
			// use SSL
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION,8,"Session=%p , DS=%p . SSL_INIT\n", this, client_myds);
			client_myds->DSS=STATE_SSL_INIT;
			client_myds->rbio_ssl = BIO_new(BIO_s_mem());
			client_myds->wbio_ssl = BIO_new(BIO_s_mem());
			client_myds->ssl = GloVars.get_SSL_new();
			SSL_set_fd(client_myds->ssl, client_myds->fd);
			SSL_set_accept_state(client_myds->ssl);
			SSL_set_bio(client_myds->ssl, client_myds->rbio_ssl, client_myds->wbio_ssl);
			l_free(pkt->size,pkt->ptr);
			proxysql_keylog_attach_callback(GloVars.get_SSL_ctx());
			return;
		}
	}

	if (
		//(client_myds->myprot.process_pkt_handshake_response((unsigned char *)pkt->ptr,pkt->size)==true)
		(handshake_response_return == true)
		&&
		(
#if defined(TEST_AURORA) || defined(TEST_GALERA) || defined(TEST_GROUPREP)
			(default_hostgroup<0 && ( session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS || session_type == PROXYSQL_SESSION_SQLITE) )
#else
			(default_hostgroup<0 && ( session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS) )
#endif // TEST_AURORA || TEST_GALERA || TEST_GROUPREP
			||
			(default_hostgroup == 0 && session_type == PROXYSQL_SESSION_CLICKHOUSE)
			||
			//(default_hostgroup>=0 && session_type == PROXYSQL_SESSION_MYSQL)
			(default_hostgroup>=0 && ( session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE ) )
			||
			(
				client_myds->encrypted==false
				&&
				strncmp(client_myds->myconn->userinfo->username,mysql_thread___monitor_username,strlen(mysql_thread___monitor_username))==0
			)
		) // Do not delete this line. See bug #492
	)	{
		if (session_type == PROXYSQL_SESSION_ADMIN) {
			if ( (default_hostgroup<0) || (strncmp(client_myds->myconn->userinfo->username,mysql_thread___monitor_username,strlen(mysql_thread___monitor_username))==0) ) {
				if (default_hostgroup==STATS_HOSTGROUP) {
					session_type = PROXYSQL_SESSION_STATS;
				}
			}
		}
		l_free(pkt->size,pkt->ptr);
		//if (client_myds->encrypted==false) {
			if (client_myds->myconn->userinfo->schemaname==NULL) {
#ifdef PROXYSQLCLICKHOUSE
				if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
					if (strlen(default_schema) == 0) {
						free(default_schema);
						default_schema = strdup((char *)"default");
					}
				}
#endif /* PROXYSQLCLICKHOUSE */
				client_myds->myconn->userinfo->set_schemaname(default_schema,strlen(default_schema));
			}
			int free_users=0;
			int used_users=0;
			if (
				( max_connections_reached == false )
				&&
				( session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_CLICKHOUSE || session_type == PROXYSQL_SESSION_SQLITE)
			) {
			//if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_CLICKHOUSE) {
				client_authenticated=true;
				switch (session_type) {
					case PROXYSQL_SESSION_SQLITE:
//#if defined(TEST_AURORA) || defined(TEST_GALERA) || defined(TEST_GROUPREP)
						free_users=1;
						break;
//#endif // TEST_AURORA || TEST_GALERA || TEST_GROUPREP
					case PROXYSQL_SESSION_MYSQL:
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION,8,"Session=%p , DS=%p , session_type=PROXYSQL_SESSION_MYSQL\n", this, client_myds);
						if (use_ldap_auth == false) {
							free_users = GloMyAuth->increase_frontend_user_connections(client_myds->myconn->userinfo->username, &used_users);
						} else {
							free_users = GloMyLdapAuth->increase_frontend_user_connections(client_myds->myconn->userinfo->fe_username, &used_users);
						}
						break;
#ifdef PROXYSQLCLICKHOUSE
					case PROXYSQL_SESSION_CLICKHOUSE:
						free_users=GloClickHouseAuth->increase_frontend_user_connections(client_myds->myconn->userinfo->username, &used_users);
						break;
#endif /* PROXYSQLCLICKHOUSE */
					default:
						// LCOV_EXCL_START
						assert(0);
						break;
						// LCOV_EXCL_STOP
				}
			} else {
				free_users=1;
			}
			if (max_connections_reached==true || free_users<=0) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION,8,"Session=%p , DS=%p , max_connections_reached=%d , free_users=%d\n", this, client_myds, max_connections_reached, free_users);
				client_authenticated=false;
				*wrong_pass=true;
				client_myds->setDSS_STATE_QUERY_SENT_NET();
				//uint8_t _pid = 2;
				//if (client_myds->switching_auth_stage) _pid+=2;
				uint8_t _pid = client_myds->pkt_sid; _pid++;
				if (max_connections_reached==true) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session=%p , DS=%p , Too many connections\n", this, client_myds);
					client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,_pid,1040,(char *)"08004", (char *)"Too many connections", true);
					proxy_warning("mysql-max_connections reached. Returning 'Too many connections'\n");
					GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_ERR, this, NULL, (char *)"mysql-max_connections reached");
					__sync_fetch_and_add(&MyHGM->status.access_denied_max_connections, 1);
				} else { // see issue #794
					__sync_fetch_and_add(&MyHGM->status.access_denied_max_user_connections, 1);
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session=%p , DS=%p . User '%s' has exceeded the 'max_user_connections' resource (current value: %d)\n", this, client_myds, client_myds->myconn->userinfo->username, used_users);
					char *a=(char *)"User '%s' has exceeded the 'max_user_connections' resource (current value: %d)";
					char *b=(char *)malloc(strlen(a)+strlen(client_myds->myconn->userinfo->username)+16);
					sprintf(b,a,client_myds->myconn->userinfo->username,used_users);
					GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_ERR, this, NULL, b);
					client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,2,1226,(char *)"42000", b, true);
					proxy_warning("User '%s' has exceeded the 'max_user_connections' resource (current value: %d)\n",client_myds->myconn->userinfo->username,used_users);
					free(b);
				}
				__sync_add_and_fetch(&MyHGM->status.client_connections_aborted,1);
				client_myds->DSS=STATE_SLEEP;
			} else {
				if (
					( default_hostgroup==ADMIN_HOSTGROUP && strcmp(client_myds->myconn->userinfo->username,(char *)"admin")==0 )
					||
					( default_hostgroup==STATS_HOSTGROUP && strcmp(client_myds->myconn->userinfo->username,(char *)"stats")==0 )
					||
					( default_hostgroup < 0 && strcmp(client_myds->myconn->userinfo->username,(char *)"monitor")==0 )
				) {
					char *client_addr = NULL;
					union {
						struct sockaddr_in in;
						struct sockaddr_in6 in6;
					} custom_sockaddr;
					struct sockaddr *addr=(struct sockaddr *)malloc(sizeof(custom_sockaddr));
					socklen_t addrlen=sizeof(custom_sockaddr);
					memset(addr, 0, sizeof(custom_sockaddr));
					int rc = 0;
					rc = getpeername(client_myds->fd, addr, &addrlen);
					if (rc == 0) {
						char buf[512];
						switch (addr->sa_family) {
							case AF_INET: {
								struct sockaddr_in *ipv4 = (struct sockaddr_in *)addr;
								inet_ntop(addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
								client_addr = strdup(buf);
								break;
							}
							case AF_INET6: {
								struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)addr;
								inet_ntop(addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
								client_addr = strdup(buf);
								break;
							}
							default:
								client_addr = strdup((char *)"localhost");
								break;
						}
					} else {
						client_addr = strdup((char *)"");
					}
					//uint8_t _pid = 2;
					//if (client_myds->switching_auth_stage) _pid+=2;
					//if (is_encrypted) _pid++;
					uint8_t _pid = client_myds->pkt_sid; _pid++;
					if (
						(strcmp(client_addr,(char *)"127.0.0.1")==0)
						||
						(strcmp(client_addr,(char *)"localhost")==0)
						||
						(strcmp(client_addr,(char *)"::1")==0)
					) {
						// we are good!
						client_myds->myprot.generate_pkt_OK(true, NULL, NULL, _pid, 0, 0, 2, 0, NULL);
						handshake_err = false;
						GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_OK, this, NULL);
						status=WAITING_CLIENT_DATA;
						client_myds->DSS=STATE_CLIENT_AUTH_OK;
					} else {
						char *a=(char *)"User '%s' can only connect locally";
						char *b=(char *)malloc(strlen(a)+strlen(client_myds->myconn->userinfo->username));
						sprintf(b,a,client_myds->myconn->userinfo->username);
						GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_ERR, this, NULL, b);
						client_myds->myprot.generate_pkt_ERR(true,NULL,NULL, _pid, 1040,(char *)"42000", b, true);
						free(b);
					}
					free(addr);
					free(client_addr);
				} else {
					uint8_t _pid = 2;
					//if (client_myds->switching_auth_stage) _pid+=2;
					//if (is_encrypted) _pid++;
					_pid = client_myds->pkt_sid; _pid++;
					// If this condition is met, it means that the
					// 'STATE_SERVER_HANDSHAKE' being performed isn't from the start of a
					// connection, but as a consequence of a 'COM_USER_CHANGE' which
					// requires an 'Auth Switch'. Thus, we impose a 'pid' of '3' for the
					// response 'OK' packet. See #3504 for more context.
					if (change_user_auth_switch) {
						_pid = 3;
						change_user_auth_switch = 0;
					}
					if (use_ssl == true && is_encrypted == false) {
						*wrong_pass=true;
						GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_ERR, this, NULL);

						char *_a=(char *)"ProxySQL Error: Access denied for user '%s' (using password: %s). SSL is required";
						char *_s=(char *)malloc(strlen(_a)+strlen(client_myds->myconn->userinfo->username)+32);
						sprintf(_s, _a, client_myds->myconn->userinfo->username, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
						client_myds->myprot.generate_pkt_ERR(true,NULL,NULL, _pid, 1045,(char *)"28000", _s, true);
						proxy_error("ProxySQL Error: Access denied for user '%s' (using password: %s). SSL is required\n", client_myds->myconn->userinfo->username, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION,8,"Session=%p , DS=%p . Access denied for user '%s' (using password: %s). SSL is required\n", this, client_myds, client_myds->myconn->userinfo->username, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
						__sync_add_and_fetch(&MyHGM->status.client_connections_aborted,1);
						free(_s);
						__sync_fetch_and_add(&MyHGM->status.access_denied_wrong_password, 1);
					} else {
						// we are good!
						//client_myds->myprot.generate_pkt_OK(true,NULL,NULL, (is_encrypted ? 3 : 2), 0,0,0,0,NULL,false);
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION,8,"Session=%p , DS=%p . STATE_CLIENT_AUTH_OK\n", this, client_myds);
						GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_OK, this, NULL);
						client_myds->myprot.generate_pkt_OK(true, NULL, NULL, _pid, 0, 0, 2, 0, NULL);
						handshake_err = false;
						status=WAITING_CLIENT_DATA;
						client_myds->DSS=STATE_CLIENT_AUTH_OK;
					}
				}
			}
	} else {
		handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE_WrongCredentials(pkt, wrong_pass);
	}
	if (mysql_thread___client_host_cache_size) {
		GloMTH->update_client_host_cache(client_myds->client_addr, handshake_err);
	}
}

// Note: as commented in issue #546 and #547 , some clients ignore the status of CLIENT_MULTI_STATEMENTS
// therefore tracking it is not needed, unless in future this should become a security enhancement,
// returning errors to all clients trying to send multi-statements .
// see also #1140
void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_SET_OPTION(PtrSize_t *pkt) {
	gtid_hid=-1;
	char v;
	v=*((char *)pkt->ptr+3);
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_SET_OPTION packet , value %d\n", v);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	unsigned int nTrx=NumActiveTransactions();
	uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
	if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;

	bool deprecate_eof_active = client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
	if (deprecate_eof_active)
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL,true);
	else
		client_myds->myprot.generate_pkt_EOF(true,NULL,NULL,1,0, setStatus );

	if (v==1) { // disabled. MYSQL_OPTION_MULTI_STATEMENTS_OFF == 1
		client_myds->myconn->options.client_flag &= ~CLIENT_MULTI_STATEMENTS;
	} else { // enabled, MYSQL_OPTION_MULTI_STATEMENTS_ON == 0
		client_myds->myconn->options.client_flag |= CLIENT_MULTI_STATEMENTS;
	}
	client_myds->DSS=STATE_SLEEP;
	l_free(pkt->size,pkt->ptr);
}

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PING(PtrSize_t *pkt) {
	gtid_hid=-1;
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_PING packet\n");
	l_free(pkt->size,pkt->ptr);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	unsigned int nTrx=NumActiveTransactions();
	uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
	if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
	client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
	client_myds->DSS=STATE_SLEEP;
}

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_FIELD_LIST(PtrSize_t *pkt) {
	if (session_type == PROXYSQL_SESSION_MYSQL) {
		/* FIXME: temporary */
		l_free(pkt->size,pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"28000",(char *)"Command not supported", true);
		client_myds->DSS=STATE_SLEEP;
	} else {
		l_free(pkt->size,pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"28000",(char *)"Command not supported", true);
		client_myds->DSS=STATE_SLEEP;
	}
}

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PROCESS_KILL(PtrSize_t *pkt) {
	l_free(pkt->size,pkt->ptr);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,9003,(char *)"28000",(char *)"Command not supported");
	client_myds->DSS=STATE_SLEEP;
}

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB(PtrSize_t *pkt) {
	gtid_hid=-1;
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_INIT_DB packet\n");
	if (session_type == PROXYSQL_SESSION_MYSQL) {
		__sync_fetch_and_add(&MyHGM->status.frontend_init_db, 1);
		client_myds->myconn->userinfo->set_schemaname((char *)pkt->ptr+sizeof(mysql_hdr)+1,pkt->size-sizeof(mysql_hdr)-1);
		l_free(pkt->size,pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		unsigned int nTrx=NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
		GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_INITDB, this, NULL);
		client_myds->DSS=STATE_SLEEP;
	} else {
		l_free(pkt->size,pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		unsigned int nTrx=NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
		client_myds->DSS=STATE_SLEEP;
	}
}

// this function was introduced due to isseu #718
// some application (like the one written in Perl) do not use COM_INIT_DB , but COM_QUERY with USE dbname
void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_USE_DB(PtrSize_t *pkt) {
	gtid_hid=-1;
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_QUERY with USE dbname\n");
	if (session_type == PROXYSQL_SESSION_MYSQL) {
		__sync_fetch_and_add(&MyHGM->status.frontend_use_db, 1);
		string nq=string((char *)pkt->ptr+sizeof(mysql_hdr)+1,pkt->size-sizeof(mysql_hdr)-1);
		SetParser parser(nq);
		string errmsg = "";
		string schemaname = parser.parse_USE_query(errmsg);
		if (schemaname != "") {
			client_myds->myconn->userinfo->set_schemaname((char *)schemaname.c_str(),schemaname.length());
			if (mirror==false) {
				RequestEnd(NULL);
			}
			l_free(pkt->size,pkt->ptr);
			client_myds->setDSS_STATE_QUERY_SENT_NET();
			unsigned int nTrx=NumActiveTransactions();
			uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
			if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
			GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_INITDB, this, NULL);
		} else {
			l_free(pkt->size,pkt->ptr);
			client_myds->setDSS_STATE_QUERY_SENT_NET();
			std::string msg = "Unable to parse: " + nq;
			if (errmsg != "") {
				msg = errmsg + ": " + nq;
			}
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,1148,(char *)"42000", msg.c_str());
			RequestEnd(NULL, 1148, msg.c_str());
		}
		client_myds->DSS=STATE_SLEEP;
	} else {
		l_free(pkt->size,pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		unsigned int nTrx=NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
		client_myds->DSS=STATE_SLEEP;
	}
}


// this function as inline in handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo
/**
 * @brief Rewrite the query packet and update the session state accordingly.
 *
 * This function is responsible for rewriting the query packet and updating the session state
 * based on the rewritten query. It frees the old packet, allocates memory for the new packet,
 * copies the header and query information, and updates the session state to reflect the new query.
 *
 * @param[in,out] pkt Pointer to the packet data structure containing the original query packet.
 */
void MySQL_Session::handler_WCD_SS_MCQ_qpo_QueryRewrite(PtrSize_t *pkt) {
	// the query was rewritten
	l_free(pkt->size,pkt->ptr);	// free old pkt
	// allocate new pkt
	timespec begint;
	if (thread->variables.stats_time_query_processor) {
		clock_gettime(CLOCK_THREAD_CPUTIME_ID,&begint);
	}
	pkt->size=sizeof(mysql_hdr)+1+qpo->new_query->length();
	pkt->ptr=l_alloc(pkt->size);
	mysql_hdr hdr;
	hdr.pkt_id=0;
	hdr.pkt_length=pkt->size-sizeof(mysql_hdr);
	memcpy((unsigned char *)pkt->ptr, &hdr, sizeof(mysql_hdr)); // copy header
	unsigned char *c=(unsigned char *)pkt->ptr+sizeof(mysql_hdr);
	*c=(unsigned char)_MYSQL_COM_QUERY; // set command type
	memcpy((unsigned char *)pkt->ptr+sizeof(mysql_hdr)+1,qpo->new_query->data(),qpo->new_query->length()); // copy query
	CurrentQuery.query_parser_free();
	CurrentQuery.begin((unsigned char *)pkt->ptr,pkt->size,true);
	delete qpo->new_query;
	timespec endt;
	if (thread->variables.stats_time_query_processor) {
		clock_gettime(CLOCK_THREAD_CPUTIME_ID,&endt);
		thread->status_variables.stvar[st_var_query_processor_time] = thread->status_variables.stvar[st_var_query_processor_time] +
			(endt.tv_sec*1000000000+endt.tv_nsec) -
			(begint.tv_sec*1000000000+begint.tv_nsec);
	}
}

/**
 * @brief Handle the generation and sending of an OK message packet in response to a successful query execution.
 *
 * This (formely inline) function is responsible for setting up and sending an OK message packet to the client in response
 * to a successful query execution. It updates the session state, generates the OK message packet using the 
 * appropriate protocol functions, and frees the memory occupied by the original packet.
 *
 * @param[in,out] pkt Pointer to the packet data structure containing the original packet.
 */
void MySQL_Session::handler_WCD_SS_MCQ_qpo_OK_msg(PtrSize_t *pkt) {
	gtid_hid = -1;
	client_myds->DSS=STATE_QUERY_SENT_NET;
	unsigned int nTrx=NumActiveTransactions();
	uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
	if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
	client_myds->myprot.generate_pkt_OK(true,NULL,NULL,client_myds->pkt_sid+1,0,0,setStatus,0,qpo->OK_msg);
	RequestEnd(NULL);
	l_free(pkt->size,pkt->ptr);
}

/**
 * @brief Handle the generation and sending of an error message packet in response to a query execution error.
 *
 * This (formely inline) function is responsible for setting up and sending an error message packet to the client in response
 * to a query execution error. It updates the session state, generates the error message packet using the appropriate
 * protocol functions, and frees the memory occupied by the original packet.
 *
 * @param[in,out] pkt Pointer to the packet data structure containing the original packet.
 */
void MySQL_Session::handler_WCD_SS_MCQ_qpo_error_msg(PtrSize_t *pkt) {
	client_myds->DSS=STATE_QUERY_SENT_NET;
	client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,1148,(char *)"42000",qpo->error_msg);
	MyHGM->add_mysql_errors(current_hostgroup, (char *)"", 0, client_myds->myconn->userinfo->username, (client_myds->addr.addr ? client_myds->addr.addr : (char *)"unknown" ), client_myds->myconn->userinfo->schemaname, 1148, (char *)qpo->error_msg);
	RequestEnd(NULL, 1148, qpo->error_msg);
	l_free(pkt->size,pkt->ptr);
}

/**
 * @brief Handle the generation and sending of an error message packet for a large packet size.
 *
 * This (formely inline) function is responsible for setting up and sending an error message packet to the client
 * in response to receiving a packet larger than the 'max_allowed_packet' size. It updates the session state,
 * generates the error message packet using the appropriate protocol functions, and frees the memory
 * occupied by the original packet.
 *
 * @param[in,out] pkt Pointer to the packet data structure containing the original packet.
 */
void MySQL_Session::handler_WCD_SS_MCQ_qpo_LargePacket(PtrSize_t *pkt) {
	// ER_NET_PACKET_TOO_LARGE
	client_myds->DSS=STATE_QUERY_SENT_NET;
	string errmsg = "Got a packet bigger than 'max_allowed_packet' bytes";
	client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,1153,(char *)"08S01", errmsg.c_str(), true);
	MyHGM->add_mysql_errors(current_hostgroup, (char *)"", 0, client_myds->myconn->userinfo->username, (client_myds->addr.addr ? client_myds->addr.addr : (char *)"unknown" ), client_myds->myconn->userinfo->schemaname, 1153, (char *)errmsg.c_str());
	RequestEnd(NULL, 1153, errmsg.c_str());
	l_free(pkt->size,pkt->ptr);
}

/*
// this function as inline in handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo
// returned values:
// 0 : no action
// 1 : return false
// 2 : return true
int MySQL_Session::handler_WCD_SS_MCQ_qpo_Parse_SQL_LOG_BIN(PtrSize_t *pkt, bool *lock_hostgroup, unsigned int nTrx, string& nq) {
	re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
	opt2->set_case_sensitive(false);
	char *pattern=(char *)"(?: *)SET *(?:|SESSION +|@@|@@session.)SQL_LOG_BIN *(?:|:)= *(\\d+) *(?:(|;|-- .*|#.*))$";
	re2::RE2 *re=new RE2(pattern, *opt2);
	int i;
	int rc=RE2::PartialMatch(nq, *re, &i);
	delete re;
	delete opt2;
	if (rc && ( i==0 || i==1) ) {
		//fprintf(stderr,"sql_log_bin=%d\n", i);
		if (i == 1) {
			if (!mysql_variables.client_set_value(this, SQL_SQL_LOG_BIN, "1"))
				return 1;
		}
		else if (i == 0) {
			if (!mysql_variables.client_set_value(this, SQL_SQL_LOG_BIN, "0"))
				return 1;
		}

#ifdef DEBUG
		proxy_info("Setting SQL_LOG_BIN to %d\n", i);
#endif
#ifdef DEBUG
		{
			string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Setting SQL_LOG_BIN to %d for query: %s\n", i, nqn.c_str());
		}
#endif
		// we recompute command_type instead of taking it from the calling function
		unsigned char command_type=*((unsigned char *)pkt->ptr+sizeof(mysql_hdr));
		if (command_type == _MYSQL_COM_QUERY) {
			client_myds->DSS=STATE_QUERY_SENT_NET;
			uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
			if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
			client_myds->DSS=STATE_SLEEP;
			status=WAITING_CLIENT_DATA;
			RequestEnd(NULL);
			l_free(pkt->size,pkt->ptr);
			return 2;
		}
	} else {
		int kq = 0;
		kq = strncmp((const char *)CurrentQuery.QueryPointer, (const char *)"SET @@SESSION.SQL_LOG_BIN = @MYSQLDUMP_TEMP_LOG_BIN;" , CurrentQuery.QueryLength);
#ifdef DEBUG
		{
			string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Setting SQL_LOG_BIN to %d for query: %s\n", i, nqn.c_str());
		}
#endif
		if (kq == 0) {
			client_myds->DSS=STATE_QUERY_SENT_NET;
			uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
			if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
			client_myds->DSS=STATE_SLEEP;
			status=WAITING_CLIENT_DATA;
			RequestEnd(NULL);
			l_free(pkt->size,pkt->ptr);
			return 2;
		} else {
			string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
			proxy_error("Unable to parse query. If correct, report it as a bug: %s\n", nqn.c_str());
			unable_to_parse_set_statement(lock_hostgroup);
			return 1;
		}
	}
	return 0;
}
*/

bool MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(PtrSize_t *pkt, bool *lock_hostgroup, ps_type prepare_stmt_type) {
/*
	lock_hostgroup:
		If this variable is set to true, this session will get lock to a
		specific hostgroup, and also have multiplexing disabled.
		It means that parsing the query wasn't completely possible (mostly
		a SET statement) and proxysql won't be able to set the same variable
		in another connection.
		This algorithm will be become obsolete once we implement session
		tracking for MySQL 5.7+
*/
	bool exit_after_SetParse = true;
	unsigned char command_type=*((unsigned char *)pkt->ptr+sizeof(mysql_hdr));
	if (qpo->new_query) {
		handler_WCD_SS_MCQ_qpo_QueryRewrite(pkt);
	}

	if (pkt->size > (unsigned int) mysql_thread___max_allowed_packet) {
		handler_WCD_SS_MCQ_qpo_LargePacket(pkt);
		reset_warning_hostgroup_flag_and_release_connection();
		return true;
	}

	if (qpo->OK_msg) {
		handler_WCD_SS_MCQ_qpo_OK_msg(pkt);
		reset_warning_hostgroup_flag_and_release_connection();
		return true;
	}

	if (qpo->error_msg) {
		handler_WCD_SS_MCQ_qpo_error_msg(pkt);
		reset_warning_hostgroup_flag_and_release_connection();
		return true;
	}

	if (prepare_stmt_type & ps_type_execute_stmt) {	// for prepared statement execute we exit here
		reset_warning_hostgroup_flag_and_release_connection();
		goto __exit_set_destination_hostgroup;
	}

	// handle warnings
	if (CurrentQuery.QueryParserArgs.digest_text) {
		const char* dig_text = CurrentQuery.QueryParserArgs.digest_text;
		const size_t dig_len = strlen(dig_text);

		if (dig_len > 0) {
			if ((dig_len == 13) && (strncasecmp(dig_text, "SHOW WARNINGS", 13) == 0)) {
				proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Intercepted '%s'\n", dig_text);
				if (warning_in_hg > -1) {
					proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Changing current_hostgroup to '%d'\n", warning_in_hg);
					current_hostgroup = warning_in_hg;
					return false;
				} else {
					proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "No warnings were detected in the previous query. Sending an empty response.\n");
					std::unique_ptr<SQLite3_result> resultset(new SQLite3_result(3));
					resultset->add_column_definition(SQLITE_TEXT, "Level");
					resultset->add_column_definition(SQLITE_TEXT, "Code");
					resultset->add_column_definition(SQLITE_TEXT, "Message");
					SQLite3_to_MySQL(resultset.get(), NULL, 0, &client_myds->myprot, false, (client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF));
					client_myds->DSS = STATE_SLEEP;
					status = WAITING_CLIENT_DATA;
					if (mirror == false) {
						RequestEnd(NULL);
					}
					l_free(pkt->size, pkt->ptr);
					return true;
				}
			}

			if ((dig_len == 22) && (strncasecmp(dig_text, "SHOW COUNT(*) WARNINGS", 22) == 0)) {
				proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Intercepted '%s'\n", dig_text);
				std::string warning_count = "0";
				if (warning_in_hg > -1) {
					proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Changing current_hostgroup to '%d'\n", warning_in_hg);
					current_hostgroup = warning_in_hg;
					assert(mybe && mybe->server_myds && mybe->server_myds->myconn && mybe->server_myds->myconn->mysql);
					warning_count = std::to_string(mybe->server_myds->myconn->warning_count);
				}
				else {
					proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "No warnings were detected in the previous query. Sending an empty response.\n");
				}
				std::unique_ptr<SQLite3_result> resultset(new SQLite3_result(1));
				resultset->add_column_definition(SQLITE_TEXT, "@@session.warning_count");
				char* pta[1];
				pta[0] = (char*)warning_count.c_str();
				resultset->add_row(pta);
				SQLite3_to_MySQL(resultset.get(), NULL, 0, &client_myds->myprot, false, (client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF));
				client_myds->DSS = STATE_SLEEP;
				status = WAITING_CLIENT_DATA;
				if (mirror == false) {
					RequestEnd(NULL);
				}
				l_free(pkt->size, pkt->ptr);
				return true;
			}
		}
	}

	reset_warning_hostgroup_flag_and_release_connection();

	// handle here #509, #815 and #816
	if (CurrentQuery.QueryParserArgs.digest_text) {
		char *dig=CurrentQuery.QueryParserArgs.digest_text;
		unsigned int nTrx=NumActiveTransactions();
		if ((locked_on_hostgroup == -1) && (strncasecmp(dig,(char *)"SET ",4)==0)) {
			// this code is executed only if locked_on_hostgroup is not set yet
			// if locked_on_hostgroup is set, we do not try to parse the SET statement
#ifdef DEBUG
			{
				string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Parsing SET command = %s\n", nqn.c_str());
			}
#endif
			if (index(dig,';') && (index(dig,';') != dig + strlen(dig)-1)) {
				string nqn;
				if (mysql_thread___parse_failure_logs_digest)
					nqn = string(CurrentQuery.get_digest_text());
				else
					nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
				proxy_warning(
					"Unable to parse multi-statements command with SET statement from client"
					" %s:%d: setting lock hostgroup. Command: %s\n", client_myds->addr.addr,
					client_myds->addr.port, nqn.c_str()
				);
				*lock_hostgroup = true;
				return false;
			}
			int rc;
			string nq=string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
			RE2::GlobalReplace(&nq,(char *)"^/\\*!\\d\\d\\d\\d\\d SET(.*)\\*/",(char *)"SET\\1");
			RE2::GlobalReplace(&nq,(char *)"(?U)/\\*.*\\*/",(char *)"");
			// remove trailing space and semicolon if present. See issue#4380
			size_t pos = nq.find_last_not_of(" ;");
			if (pos != nq.npos) {
				nq.erase(pos + 1); // remove trailing spaces and semicolumns
			}
/*
			// we do not threat SET SQL_LOG_BIN as a special case
			if (match_regexes && match_regexes[0]->match(dig)) {
				int rc = handler_WCD_SS_MCQ_qpo_Parse_SQL_LOG_BIN(pkt, lock_hostgroup, nTrx, nq);
				if (rc == 1) return false;
				if (rc == 2) return true;
				// if rc == 0 , continue as normal
			}
*/
			if (
				(
					match_regexes && (match_regexes[1]->match(dig))
				)
				||
				( strncasecmp(dig,(char *)"SET NAMES", strlen((char *)"SET NAMES")) == 0)
				||
				( strcasestr(dig,(char *)"autocommit"))
			) {
				proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Parsing SET command %s\n", nq.c_str());
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Parsing SET command = %s\n", nq.c_str());
				SetParser parser(nq);
				std::map<std::string, std::vector<std::string>> set = {};
				if (mysql_thread___set_parser_algorithm == 1) { // legacy behavior
					set = parser.parse1();
				} else if (mysql_thread___set_parser_algorithm == 2) { // we use a single SetParser per thread
					thread->thr_SetParser->set_query(nq); // replace the query
					set = thread->thr_SetParser->parse1v2(); // use algorithm v2
				} else {
					assert(0);
				}
				// Flag to be set if any variable within the 'SET' statement fails to be tracked,
				// due to being unknown or because it's an user defined variable.
				bool failed_to_parse_var = false;
				for(auto it = std::begin(set); it != std::end(set); ++it) {
					std::string var = it->first;
					proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET variable %s\n", var.c_str());
					if (it->second.size() < 1 || it->second.size() > 2) {
						// error not enough arguments
						string query_str = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
						string digest_str = string(CurrentQuery.get_digest_text());
						string nqn;
						if (mysql_thread___parse_failure_logs_digest)
							nqn = digest_str;
						else
							nqn = query_str;
						// PMC-10002: A query has failed to be parsed. This can be due a incorrect query or
						// due to ProxySQL not being able to properly parse it. In case the query is correct a
						// bug report should be filed including the offending query.
						proxy_error2(10002, "Unable to parse query. If correct, report it as a bug: %s\n", nqn.c_str());
						proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Locking hostgroup for query %s\n",
									query_str.c_str());
						unable_to_parse_set_statement(lock_hostgroup);
						return false;
					}
					auto values = std::begin(it->second);
					if (var == "sql_mode") {
						std::string value1 = *values;
						if (strcasestr(value1.c_str(),"NO_BACKSLASH_ESCAPES") != NULL) {
							// client is setting NO_BACKSLASH_ESCAPES in sql_mode
							// Because we will reply with an OK packet without
							// first setting sql_mode to the backend (this is
							// by design) we need to set no_backslash_escapes
							// in the client connection
							if (client_myds && client_myds->myconn) { // some extra sanity check
								client_myds->myconn->set_no_backslash_escapes(true);
							}
						}
						if (
							( strcasecmp(value1.c_str(),(char *)"CONCAT") == 0 )
							||
							( strcasecmp(value1.c_str(),(char *)"REPLACE") == 0 )
							||
							( strcasecmp(value1.c_str(),(char *)"IFNULL") == 0 )
						) {
							string query_str = string((char *)CurrentQuery.QueryPointer, CurrentQuery.QueryLength);
							string digest_str = string(CurrentQuery.get_digest_text());
							string nqn;
							if (mysql_thread___parse_failure_logs_digest)
								nqn = digest_str;
							else
								nqn = query_str;
							proxy_error2(10002, "Unable to parse query. If correct, report it as a bug: %s\n", nqn.c_str());
							proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5,
										"Locking hostgroup for query %s\n", query_str.c_str());
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
						std::size_t found_at = value1.find("@");
						if (found_at != std::string::npos) {
							char *v1 = strdup(value1.c_str());
							char *v1t = v1;
							proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Found @ in SQL_MODE . v1 = %s\n", v1);
							char *v2 = NULL;
							while (v1 && (v2 = strstr(v1,(const char *)"@"))) {
								// we found a @ . Maybe we need to lock hostgroup
								proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Found @ in SQL_MODE . v2 = %s\n", v2);
								if (strncasecmp(v2,(const char *)"@@sql_mode",strlen((const char *)"@@sql_mode"))) {
									unable_to_parse_set_statement(lock_hostgroup);
									free(v1);
									return false;
								} else {
									v2++;
								}
								if (strlen(v2) > 1) {
									v1 = v2+1;
								}
							}
							free(v1t);
						}
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET SQL Mode value %s\n", value1.c_str());
						uint32_t sql_mode_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
						if (mysql_variables.client_get_hash(this, SQL_SQL_MODE) != sql_mode_int) {
							if (!mysql_variables.client_set_value(this, SQL_SQL_MODE, value1.c_str())) {
								return false;
							}
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection SQL Mode to %s\n", value1.c_str());
						}
					} else if (mysql_variables_strings.find(var) != mysql_variables_strings.end()) {
						std::string value1 = *values;
						std::size_t found_at = value1.find("@");
						if (found_at != std::string::npos) {
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
						int idx = SQL_NAME_LAST_HIGH_WM;
						for (int i = 0 ; i < SQL_NAME_LAST_HIGH_WM ; i++) {
							if (mysql_tracked_variables[i].is_number == false && mysql_tracked_variables[i].is_bool == false) {
								if (!strcasecmp(var.c_str(), mysql_tracked_variables[i].set_variable_name)) {
									idx = mysql_tracked_variables[i].idx;
									break;
								}
							}
						}
						if (idx != SQL_NAME_LAST_HIGH_WM) {
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection %s to %s\n", var.c_str(), value1.c_str());
							uint32_t var_hash_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
							if (mysql_variables.client_get_hash(this, mysql_tracked_variables[idx].idx) != var_hash_int) {
								if (!mysql_variables.client_set_value(this, mysql_tracked_variables[idx].idx, value1.c_str())) {
									return false;
								}
							}
						}
					} else if (mysql_variables_boolean.find(var) != mysql_variables_boolean.end()) {
						int idx = SQL_NAME_LAST_HIGH_WM;
						for (int i = 0 ; i < SQL_NAME_LAST_HIGH_WM ; i++) {
							if (mysql_tracked_variables[i].is_bool) {
								if (!strcasecmp(var.c_str(), mysql_tracked_variables[i].set_variable_name)) {
									idx = mysql_tracked_variables[i].idx;
									break;
								}
							}
						}
						if (idx != SQL_NAME_LAST_HIGH_WM) {
							if (mysql_variables.parse_variable_boolean(this,idx, *values, lock_hostgroup)==false) {
								return false;
							}
						}
					} else if (mysql_variables_numeric.find(var) != mysql_variables_numeric.end()) {
						int idx = SQL_NAME_LAST_HIGH_WM;
						for (int i = 0 ; i < SQL_NAME_LAST_HIGH_WM ; i++) {
							if (mysql_tracked_variables[i].is_number) {
								if (!strcasecmp(var.c_str(), mysql_tracked_variables[i].set_variable_name)) {
									idx = mysql_tracked_variables[i].idx;
									break;
								}
							}
						}
						if (idx != SQL_NAME_LAST_HIGH_WM) {
							if (var == "query_cache_type") {
								// note that query_cache_type variable can act both as boolean AND a number , but also accept "DEMAND"
								// See https://dev.mysql.com/doc/refman/5.7/en/server-system-variables.html#sysvar_query_cache_type
								std::string value1 = *values;
								if (strcasecmp(value1.c_str(),"off")==0 || strcasecmp(value1.c_str(),"false")==0) {
									value1 = "0";
								} else if (strcasecmp(value1.c_str(),"on")==0 || strcasecmp(value1.c_str(),"true")==0) {
									value1 = "1";
								} else if (strcasecmp(value1.c_str(),"demand")==0 || strcasecmp(value1.c_str(),"true")==0) {
									value1 = "2";
								}
								if (mysql_variables.parse_variable_number(this,idx, value1, lock_hostgroup)==false) {
									return false;
								}
							} else {
								if (mysql_variables.parse_variable_number(this,idx, *values, lock_hostgroup)==false) {
									return false;
								}
							}
						}
					} else if (var == "autocommit") {
						std::string value1 = *values;
						std::size_t found_at = value1.find("@");
						if (found_at != std::string::npos) {
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET autocommit value %s\n", value1.c_str());
						int __tmp_autocommit = -1;
						if (
							(strcasecmp(value1.c_str(),(char *)"0")==0) ||
							(strcasecmp(value1.c_str(),(char *)"false")==0) ||
							(strcasecmp(value1.c_str(),(char *)"off")==0)
						) {
							__tmp_autocommit = 0;
						} else {
							if (
								(strcasecmp(value1.c_str(),(char *)"1")==0) ||
								(strcasecmp(value1.c_str(),(char *)"true")==0) ||
								(strcasecmp(value1.c_str(),(char *)"on")==0)
							) {
								__tmp_autocommit = 1;
							}
						}
						if (__tmp_autocommit >= 0 && autocommit_handled==false) {
							int fd = __tmp_autocommit;
							__sync_fetch_and_add(&MyHGM->status.autocommit_cnt, 1);
							// we immediately process the number of transactions
							unsigned int nTrx=NumActiveTransactions();
							if (fd==1 && autocommit==true) {
								// nothing to do, return OK
							}
							if (fd==1 && autocommit==false) {
								if (nTrx) {
									// there is an active transaction, we need to forward it
									// because this can potentially close the transaction
									autocommit=true;
									client_myds->myconn->set_autocommit(autocommit);
									autocommit_on_hostgroup=FindOneActiveTransaction();
									exit_after_SetParse = false;
									sending_set_autocommit=true;
								} else {
									// as there is no active transaction, we do no need to forward it
									// just change internal state
									autocommit=true;
									client_myds->myconn->set_autocommit(autocommit);
								}
							}

							if (fd==0) {
								autocommit=false;	// we set it, no matter if already set or not
								client_myds->myconn->set_autocommit(autocommit);
							}
						} else {
							if (autocommit_handled==true) {
								exit_after_SetParse = false;
							}
						}
					} else if (var == "time_zone") {
						std::string value1 = *values;
						std::size_t found_at = value1.find("@");
						if (found_at != std::string::npos) {
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET Time Zone value %s\n", value1.c_str());
						{
							// reformat +1:23 to +01:23
							if (value1.length() == 5) {
								if (value1[0]=='+' || value1[0]=='-') {
									if (value1[2]==':') {
										std::string s = std::string(value1,0,1);
										s += "0";
										s += std::string(value1,1,4);
										value1 = s;
									}
								}
							}
						}
						uint32_t time_zone_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
						if (mysql_variables.client_get_hash(this, SQL_TIME_ZONE) != time_zone_int) {
							if (!mysql_variables.client_set_value(this, SQL_TIME_ZONE, value1.c_str()))
								return false;
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection Time zone to %s\n", value1.c_str());
						}
					} else if (var == "session_track_gtids") {
						std::string value1 = *values;
						if ((strcasecmp(value1.c_str(),"OWN_GTID")==0) || (strcasecmp(value1.c_str(),"OFF")==0) || (strcasecmp(value1.c_str(),"ALL_GTIDS")==0)) {
							if (strcasecmp(value1.c_str(),"ALL_GTIDS")==0) {
								// we convert session_track_gtids=ALL_GTIDS to session_track_gtids=OWN_GTID
								std::string a = "";
								if (client_myds && client_myds->addr.addr) {
									a = " . Client ";
									a+= client_myds->addr.addr;
									a+= ":" + std::to_string(client_myds->addr.port);
								}
								proxy_warning("SET session_track_gtids=ALL_GTIDS is not allowed. Switching to session_track_gtids=OWN_GTID%s\n", a.c_str());
								value1 = "OWN_GTID";
							}
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 7, "Processing SET session_track_gtids value %s\n", value1.c_str());
							uint32_t session_track_gtids_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
							if (client_myds->myconn->options.session_track_gtids_int != session_track_gtids_int) {
								client_myds->myconn->options.session_track_gtids_int = session_track_gtids_int;
								if (client_myds->myconn->options.session_track_gtids) {
									free(client_myds->myconn->options.session_track_gtids);
								}
								proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Changing connection session_track_gtids to %s\n", value1.c_str());
								client_myds->myconn->options.session_track_gtids=strdup(value1.c_str());
							}
						} else {
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
					} else if ( (var == "character_set_results") || ( var == "collation_connection" )  ||
							(var == "character_set_connection") || (var == "character_set_client") ||
							(var == "character_set_database")) {
						std::string value1 = *values;
						int vl = strlen(value1.c_str());
						const char *v = value1.c_str();
						bool only_normal_chars = true;
						for (int i=0; i<vl && only_normal_chars==true; i++) {
							if (is_normal_char(v[i])==0) {
								only_normal_chars=false;
							}
						}
						if (only_normal_chars) {
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 7, "Processing SET %s value %s\n", var.c_str(), value1.c_str());
							uint32_t var_value_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
							int idx = SQL_NAME_LAST_HIGH_WM;
							for (int i = 0 ; i < SQL_NAME_LAST_HIGH_WM ; i++) {
								if (!strcasecmp(var.c_str(), mysql_tracked_variables[i].set_variable_name)) {
									idx = mysql_tracked_variables[i].idx;
									break;
								}
							}
							if (idx == SQL_NAME_LAST_HIGH_WM) {
								proxy_error("Variable %s not found in mysql_tracked_variables[]\n", var.c_str());
								unable_to_parse_set_statement(lock_hostgroup);
								return false;
							}
							if (mysql_variables.client_get_hash(this, idx) != var_value_int) {
								const MARIADB_CHARSET_INFO *ci = NULL;
								if (var == "character_set_results" || var == "character_set_connection" ||
										var == "character_set_client" || var == "character_set_database") {
									ci = proxysql_find_charset_name(value1.c_str());
								}
								else if (var == "collation_connection")
									ci = proxysql_find_charset_collate(value1.c_str());

								if (!ci) {
									if (var == "character_set_results") {
										if (!strcasecmp("NULL", value1.c_str())) {
											if (!mysql_variables.client_set_value(this, idx, "NULL")) {
												return false;
											}
										} else if (!strcasecmp("binary", value1.c_str())) {
											if (!mysql_variables.client_set_value(this, idx, "binary")) {
												return false;
											}
										} else {
											// LCOV_EXCL_START
											proxy_error("Cannot find charset/collation [%s]\n", value1.c_str());
											assert(0);
											// LCOV_EXCL_STOP
										}
									}
								} else {
									std::stringstream ss;
									ss << ci->nr;
									/* changing collation_connection the character_set_connection will be changed as well
									 * and vice versa
									 */
									if (var == "collation_connection") {
										if (!mysql_variables.client_set_value(this, SQL_CHARACTER_SET_CONNECTION, ss.str().c_str()))
											return false;
									}
									if (var == "character_set_connection") {
											if (!mysql_variables.client_set_value(this, SQL_COLLATION_CONNECTION, ss.str().c_str()))
												return false;
									}

									/* this is explicit statement from client. we do not multiplex, therefor we must
									 * remember client's choice in the client's variable for future use in verifications, multiplexing etc.
									 */
									if (!mysql_variables.client_set_value(this, idx, ss.str().c_str()))
										return false;
									proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Changing connection %s to %s\n", var.c_str(), value1.c_str());
								}
							}
						} else {
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
					} else if (var == "names") {
						std::string value1 = *values++;
						std::size_t found_at = value1.find("@");
						if (found_at != std::string::npos) {
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET NAMES %s\n",  value1.c_str());
						const MARIADB_CHARSET_INFO * c;
						std::string value2;
						if (values != std::end(it->second)) {
							value2 = *values;
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET NAMES With COLLATE %s\n", value2.c_str());
							c = proxysql_find_charset_collate_names(value1.c_str(), value2.c_str());
						} else {
							c = proxysql_find_charset_name(value1.c_str());
						}
						if (!c) {
							char *m = NULL;
							char *errmsg = NULL;
							if (value2.length()) {
								m=(char *)"Unknown character set '%s' or collation '%s'";
								errmsg=(char *)malloc(value1.length() + value2.length() + strlen(m));
								sprintf(errmsg,m,value1.c_str(), value2.c_str());
							} else {
								m=(char *)"Unknown character set: '%s'";
								errmsg=(char *)malloc(value1.length()+strlen(m));
								sprintf(errmsg,m,value1.c_str());
							}
							client_myds->DSS=STATE_QUERY_SENT_NET;
							client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1115,(char *)"42000",errmsg, true);
							client_myds->DSS=STATE_SLEEP;
							status=WAITING_CLIENT_DATA;
							free(errmsg);
							return true;
						} else {
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection charset to %d\n", c->nr);
							client_myds->myconn->set_charset(c->nr, NAMES);
						}
					} else if (var == "tx_isolation") {
						std::string value1 = *values;
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET tx_isolation value %s\n", value1.c_str());
						auto pos = value1.find('-');
						if (pos != std::string::npos)
							value1[pos] = ' ';
						uint32_t isolation_level_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
						if (mysql_variables.client_get_hash(this, SQL_ISOLATION_LEVEL) != isolation_level_int) {
							if (!mysql_variables.client_set_value(this, SQL_ISOLATION_LEVEL, value1.c_str()))
								return false;
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection TX ISOLATION to %s\n", value1.c_str());
						}
					} else if (var == "tx_read_only") {
						std::string value1 = *values;
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET tx_read_only value %s\n", value1.c_str());

						if (
							(value1 == "0") ||
							(strcasecmp(value1.c_str(), "false")==0) ||
							(strcasecmp(value1.c_str(), "off")==0)
						) {
							value1 = "WRITE";
						} else if (
							(value1 == "1") ||
							(strcasecmp(value1.c_str(), "true")==0) ||
							(strcasecmp(value1.c_str(), "on")==0)
						) {
							value1 = "ONLY";
						} else {
							//proxy_warning("Unknown tx_read_only value \"%s\"\n", value1.c_str());
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
						uint32_t read_only_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
						if (mysql_variables.client_get_hash(this, SQL_TRANSACTION_READ) != read_only_int) {
							if (!mysql_variables.client_set_value(this, SQL_TRANSACTION_READ, value1.c_str()))
								return false;
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection TX ACCESS MODE to READ %s\n", value1.c_str());
						}
					} else if (std::find(mysql_variables.ignore_vars.begin(), mysql_variables.ignore_vars.end(), var) != mysql_variables.ignore_vars.end()) {
						// this is a variable we parse but ignore
						// see MySQL_Variables::MySQL_Variables() for a list of ignored variables
#ifdef DEBUG
						std::string value1 = *values;
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET %s value %s\n", var.c_str(), value1.c_str());
#endif // DEBUG
					} else {
						// At this point the variable is unknown to us, or it's a user variable
						// prefixed by '@', in both cases, we should fail to parse. We don't
						// fail inmediately so we can anyway keep track of the other variables
						// supplied within the 'SET' statement being parsed.
						failed_to_parse_var = true;
					}
				}

				if (failed_to_parse_var) {
					unable_to_parse_set_statement(lock_hostgroup);
					return false;
				}
/*
				if (exit_after_SetParse) {
					goto __exit_set_destination_hostgroup;
				}
*/
				// parseSetCommand wasn't able to parse anything...
				if (set.size() == 0) {
					// try case listed in #1373
					// SET  @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO'),  @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 2147483
					// this is not a complete solution. A right solution involves true parsing
					size_t query_no_space_length = nq.length();
					char *query_no_space=(char *)malloc(query_no_space_length+1);
					memcpy(query_no_space,nq.c_str(),query_no_space_length);
					query_no_space[query_no_space_length]='\0';
					query_no_space_length=remove_spaces(query_no_space);

					string nq1 = string(query_no_space);
					free(query_no_space);
					RE2::GlobalReplace(&nq1,(char *)"SESSION.",(char *)"");
					RE2::GlobalReplace(&nq1,(char *)"SESSION ",(char *)"");
					RE2::GlobalReplace(&nq1,(char *)"session.",(char *)"");
					RE2::GlobalReplace(&nq1,(char *)"session ",(char *)"");
					//fprintf(stderr,"%s\n",nq1.c_str());
					re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
					opt2->set_case_sensitive(false);
					char *pattern=(char *)"^SET @@SQL_MODE *(?:|:)= *(?:'||\")(.*)(?:'||\") *, *@@sql_auto_is_null *(?:|:)= *(?:(?:\\w|\\d)*) *, @@wait_timeout *(?:|:)= *(?:\\d*)$";
					re2::RE2 *re=new RE2(pattern, *opt2);
					string s1;
					rc=RE2::FullMatch(nq1, *re, &s1);
					delete re;
					delete opt2;
					if (rc) {
						uint32_t sql_mode_int=SpookyHash::Hash32(s1.c_str(),s1.length(),10);
						if (mysql_variables.client_get_hash(this, SQL_SQL_MODE) != sql_mode_int) {
							if (!mysql_variables.client_set_value(this, SQL_SQL_MODE, s1.c_str()))
								return false;
							std::size_t found_at = s1.find("@");
							if (found_at != std::string::npos) {
								char *v1 = strdup(s1.c_str());
								char *v2 = NULL;
								while (v1 && (v2 = strstr(v1,(const char *)"@"))) {
									// we found a @ . Maybe we need to lock hostgroup
									if (strncasecmp(v2,(const char *)"@@sql_mode",strlen((const char *)"@@sql_mode"))) {
#ifdef DEBUG
										string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
										proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Locking hostgroup for query %s\n", nqn.c_str());
#endif
										*lock_hostgroup = true;
									}
									if (strlen(v2) > 1) {
										v1 = v2+1;
									}
								}
								free(v1);
								if (*lock_hostgroup) {
									unable_to_parse_set_statement(lock_hostgroup);
									return false;
								}
							}
						}
					} else {
						if (memchr((const char *)CurrentQuery.QueryPointer, '@', CurrentQuery.QueryLength)) {
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
						int kq = 0;
						kq = strncmp((const char *)CurrentQuery.QueryPointer, (const char *)"/*!40101 SET SQL_MODE=@OLD_SQL_MODE */" , CurrentQuery.QueryLength);
						if (kq != 0) {
							kq = strncmp((const char *)CurrentQuery.QueryPointer, (const char *)"/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */" , CurrentQuery.QueryLength);
							if (kq != 0) {
								string nqn;
								if (mysql_thread___parse_failure_logs_digest)
									nqn = string(CurrentQuery.get_digest_text());
								else
									nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
								proxy_error2(10002, "Unable to parse query. If correct, report it as a bug: %s\n", nqn.c_str());
								return false;
							}
						}
					}
				}

				if (exit_after_SetParse) {
					if (command_type == _MYSQL_COM_QUERY) {
						client_myds->DSS=STATE_QUERY_SENT_NET;
						uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
						if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
						client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
						RequestEnd(NULL);
						l_free(pkt->size,pkt->ptr);
						return true;
					}
				}
			} else if (match_regexes && match_regexes[2]->match(dig)) {
				SetParser parser(nq);
				std::map<std::string, std::vector<std::string>> set = parser.parse2();

				for(auto it = std::begin(set); it != std::end(set); ++it) {

					const std::vector<std::string>& val = split_string(it->first, ':');

					if (val.size() == 2) {

						const auto values = std::begin(it->second);
						const std::string& var = val[1];

						enum mysql_variable_name isolation_level_val;
						enum mysql_variable_name transaction_read_val;

						if (val[0] == "session") {
							isolation_level_val = SQL_ISOLATION_LEVEL;
							transaction_read_val = SQL_TRANSACTION_READ;
						} else {
							isolation_level_val = SQL_NEXT_ISOLATION_LEVEL;
							transaction_read_val = SQL_NEXT_TRANSACTION_READ;
						}

						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET variable %s\n", var.c_str());
						if (var == "isolation level") {
							const std::string& value1 = *values;
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET %s TRANSACTION ISOLATION LEVEL value %s\n", val[0].c_str(), value1.c_str());
							const uint32_t isolation_level_int = SpookyHash::Hash32(value1.c_str(), value1.length(), 10);
							if (mysql_variables.client_get_hash(this, isolation_level_val) != isolation_level_int) {
								if (!mysql_variables.client_set_value(this, isolation_level_val, value1.c_str()))
									return false;

								proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection TRANSACTION ISOLATION LEVEL to %s\n", value1.c_str());
							}
						} else if (var == "read") {
							const std::string& value1 = *values;
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET %s TRANSACTION READ value %s\n", val[0].c_str(), value1.c_str());
							const uint32_t transaction_read_int = SpookyHash::Hash32(value1.c_str(), value1.length(), 10);
							if (mysql_variables.client_get_hash(this, transaction_read_val) != transaction_read_int) {
								if (!mysql_variables.client_set_value(this, transaction_read_val, value1.c_str()))
									return false;

								proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection TRANSACTION READ to %s\n", value1.c_str());
							}
						} else {
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
					} else {
						unable_to_parse_set_statement(lock_hostgroup);
						return false;
					}
				}
				if (exit_after_SetParse) {
					if (command_type == _MYSQL_COM_QUERY) {
						client_myds->DSS=STATE_QUERY_SENT_NET;
						uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
						if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
						client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
						RequestEnd(NULL);
						l_free(pkt->size,pkt->ptr);
						return true;
					}
				}
			} else if (match_regexes && match_regexes[3]->match(dig)) {
				SetParser parser(nq);
				std::string charset = parser.parse_character_set();
				const MARIADB_CHARSET_INFO * c;
				if (!charset.empty()) {
					proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET CHARACTER SET %s\n", charset.c_str());
					c = proxysql_find_charset_name(charset.c_str());
				} else {
					unable_to_parse_set_statement(lock_hostgroup);
					return false;
				}
				if (!c) {
					char *m = NULL;
					char *errmsg = NULL;
					m=(char *)"Unknown character set: '%s'";
					errmsg=(char *)malloc(charset.length()+strlen(m));
					sprintf(errmsg,m,charset.c_str());
					client_myds->DSS=STATE_QUERY_SENT_NET;
					client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1115,(char *)"42000",errmsg, true);
					client_myds->DSS=STATE_SLEEP;
					status=WAITING_CLIENT_DATA;
					free(errmsg);
					return true;
				} else {
					proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection charset to %d\n", c->nr);
					client_myds->myconn->set_charset(c->nr, CHARSET);
				}
				if (exit_after_SetParse) {
					if (command_type == _MYSQL_COM_QUERY) {
						client_myds->DSS=STATE_QUERY_SENT_NET;
						uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
						if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
						client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
						RequestEnd(NULL);
						l_free(pkt->size,pkt->ptr);
						return true;
					}
				}
			} else {
				unable_to_parse_set_statement(lock_hostgroup);
				return false;
			}
		}
	}

	if (mirror==true) { // for mirror session we exit here
		current_hostgroup=qpo->destination_hostgroup;
		return false;
	}

	// handle case #1797
	// handle case #2564
       if ((pkt->size==SELECT_CONNECTION_ID_LEN+5 && *((char *)(pkt->ptr)+4)==(char)0x03 && strncasecmp((char *)SELECT_CONNECTION_ID,(char *)pkt->ptr+5,pkt->size-5)==0)) {
		char buf[32];
		char buf2[32];
		sprintf(buf,"%u",thread_session_id);
		int l0=strlen("CONNECTION_ID()");
		memcpy(buf2,(char *)pkt->ptr+5+SELECT_CONNECTION_ID_LEN-l0,l0);
		buf2[l0]=0;
		unsigned int nTrx=NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		MySQL_Data_Stream *myds=client_myds;
		MySQL_Protocol *myprot=&client_myds->myprot;
		myds->DSS=STATE_QUERY_SENT_DS;
		int sid=1;
		myprot->generate_pkt_column_count(true,NULL,NULL,sid,1); sid++;
		myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",buf2,(char *)"",63,31,MYSQL_TYPE_LONGLONG,161,0,false,0,NULL); sid++;
		myds->DSS=STATE_COLUMN_DEFINITION;

		bool deprecate_eof_active = myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
		if (!deprecate_eof_active) {
			myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
		}

		char **p=(char **)malloc(sizeof(char*)*1);
		unsigned long *l=(unsigned long *)malloc(sizeof(unsigned long *)*1);
		l[0]=strlen(buf);
		p[0]=buf;
		myprot->generate_pkt_row(true,NULL,NULL,sid,1,l,p); sid++;
		myds->DSS=STATE_ROW;

		if (deprecate_eof_active) {
			myprot->generate_pkt_OK(true,NULL,NULL,sid,0,0,setStatus,0,NULL,true); sid++;
		} else {
			myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
		}
		myds->DSS=STATE_SLEEP;
		RequestEnd(NULL);
		l_free(pkt->size,pkt->ptr);
		free(p);
		free(l);
		return true;
	}

	// handle case #1421 , about LAST_INSERT_ID
	if (CurrentQuery.QueryParserArgs.digest_text) {
		char *dig=CurrentQuery.QueryParserArgs.digest_text;
		if (strcasestr(dig,"LAST_INSERT_ID") || strcasestr(dig,"@@IDENTITY")) {
			// we need to try to execute it where the last write was successful
			if (last_HG_affected_rows >= 0) {
				MySQL_Backend * _mybe = NULL;
				_mybe = find_backend(last_HG_affected_rows);
				if (_mybe) {
					if (_mybe->server_myds) {
						if (_mybe->server_myds->myconn) {
							if (_mybe->server_myds->myconn->mysql) { // we have an established connection
								// this seems to be the right backend
								qpo->destination_hostgroup = last_HG_affected_rows;
								current_hostgroup = qpo->destination_hostgroup;
								return false; // execute it on backend!
							}
						}
					}
				}
			}
			// if we reached here, we don't know the right backend
			// we try to determine if it is a simple "SELECT LAST_INSERT_ID()" or "SELECT @@IDENTITY" and we return mysql->last_insert_id

			//handle 2564
			if (
				(pkt->size==SELECT_LAST_INSERT_ID_LEN+5 && *((char *)(pkt->ptr)+4)==(char)0x03 && strncasecmp((char *)SELECT_LAST_INSERT_ID,(char *)pkt->ptr+5,pkt->size-5)==0)
				||
				(pkt->size==SELECT_LAST_INSERT_ID_FROM_DUAL_LEN+5 && *((char *)(pkt->ptr)+4)==(char)0x03 && strncasecmp((char *)SELECT_LAST_INSERT_ID_FROM_DUAL,(char *)pkt->ptr+5,pkt->size-5)==0)
				||
				(pkt->size==SELECT_LAST_INSERT_ID_LIMIT1_LEN+5 && *((char *)(pkt->ptr)+4)==(char)0x03 && strncasecmp((char *)SELECT_LAST_INSERT_ID_LIMIT1,(char *)pkt->ptr+5,pkt->size-5)==0)
                ||
                (pkt->size==SELECT_VARIABLE_IDENTITY_LEN+5 && *((char *)(pkt->ptr)+4)==(char)0x03 && strncasecmp((char *)SELECT_VARIABLE_IDENTITY,(char *)pkt->ptr+5,pkt->size-5)==0)
                ||
                (pkt->size==SELECT_VARIABLE_IDENTITY_LIMIT1_LEN+5 && *((char *)(pkt->ptr)+4)==(char)0x03 && strncasecmp((char *)SELECT_VARIABLE_IDENTITY_LIMIT1,(char *)pkt->ptr+5,pkt->size-5)==0)
			) {
				char buf[32];
				sprintf(buf,"%llu",last_insert_id);
				char buf2[32];
                int l0=0;
                if (strcasestr(dig,"LAST_INSERT_ID")){
    				l0=strlen("LAST_INSERT_ID()");
                    memcpy(buf2,(char *)pkt->ptr+5+SELECT_LAST_INSERT_ID_LEN-l0,l0);
                }else if(strcasestr(dig,"@@IDENTITY")){
                    l0=strlen("@@IDENTITY");
                    memcpy(buf2,(char *)pkt->ptr+5+SELECT_VARIABLE_IDENTITY_LEN-l0,l0);
                }
				buf2[l0]=0;
				unsigned int nTrx=NumActiveTransactions();
				uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
				if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
				MySQL_Data_Stream *myds=client_myds;
				MySQL_Protocol *myprot=&client_myds->myprot;
				myds->DSS=STATE_QUERY_SENT_DS;
				int sid=1;
				myprot->generate_pkt_column_count(true,NULL,NULL,sid,1); sid++;
				myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",buf2,(char *)"",63,31,MYSQL_TYPE_LONGLONG,161,0,false,0,NULL); sid++;
				myds->DSS=STATE_COLUMN_DEFINITION;

				bool deprecate_eof_active = myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
				if (!deprecate_eof_active) {
					myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
				}
				char **p=(char **)malloc(sizeof(char*)*1);
				unsigned long *l=(unsigned long *)malloc(sizeof(unsigned long *)*1);
				l[0]=strlen(buf);
				p[0]=buf;
				myprot->generate_pkt_row(true,NULL,NULL,sid,1,l,p); sid++;
				myds->DSS=STATE_ROW;
				if (deprecate_eof_active) {
					myprot->generate_pkt_OK(true,NULL,NULL,sid,0,0,setStatus,0,NULL,true); sid++;
				} else {
					myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
				}
				myds->DSS=STATE_SLEEP;
				RequestEnd(NULL);
				l_free(pkt->size,pkt->ptr);
				free(p);
				free(l);
				return true;
			}

			// if we reached here, we don't know the right backend and we cannot answer the query directly
			// We continue the normal way

			// as a precaution, we reset cache_ttl
			qpo->cache_ttl = 0;
		}
	}

	// handle command KILL #860
	//if (prepared == false) {
		if (handle_command_query_kill(pkt)) {
			return true;
		}
	//}
	if (qpo->cache_ttl>0 && ((prepare_stmt_type & ps_type_prepare_stmt) == 0)) {
		bool deprecate_eof_active = client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
		uint32_t resbuf=0;
		unsigned char *aa=GloQC->get(
			client_myds->myconn->userinfo->hash,
			(const unsigned char *)CurrentQuery.QueryPointer ,
			CurrentQuery.QueryLength ,
			&resbuf ,
			thread->curtime/1000 ,
			qpo->cache_ttl,
			deprecate_eof_active
		);
		if (aa) {
			client_myds->buffer2resultset(aa,resbuf);
			free(aa);
			client_myds->PSarrayOUT->copy_add(client_myds->resultset,0,client_myds->resultset->len);
			while (client_myds->resultset->len) client_myds->resultset->remove_index(client_myds->resultset->len-1,NULL);
			if (transaction_persistent_hostgroup == -1) {
				// not active, we can change it
				current_hostgroup=-1;
			}
			RequestEnd(NULL);
			l_free(pkt->size,pkt->ptr);
			return true;
		}
	}

__exit_set_destination_hostgroup:

	if ( qpo->next_query_flagIN >= 0 ) {
		next_query_flagIN=qpo->next_query_flagIN;
	}
	if ( qpo->destination_hostgroup >= 0 ) {
		if (transaction_persistent_hostgroup == -1) {
			current_hostgroup=qpo->destination_hostgroup;
		}
	}

	if (mysql_thread___set_query_lock_on_hostgroup == 1) { // algorithm introduced in 2.0.6
		if (locked_on_hostgroup >= 0) {
			if (current_hostgroup != locked_on_hostgroup) {
				client_myds->DSS=STATE_QUERY_SENT_NET;
				char buf[140];
				sprintf(buf,"ProxySQL Error: connection is locked to hostgroup %d but trying to reach hostgroup %d", locked_on_hostgroup, current_hostgroup);
				client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,9006,(char *)"Y0000",buf);
				thread->status_variables.stvar[st_var_hostgroup_locked_queries]++;
				RequestEnd(NULL, 9006, buf);
				l_free(pkt->size,pkt->ptr);
				return true;
			}
		}
	}
	return false;
}

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STATISTICS(PtrSize_t *pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_STATISTICS packet\n");
	l_free(pkt->size,pkt->ptr);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	client_myds->myprot.generate_statistics_response(true,NULL,NULL);
	client_myds->DSS=STATE_SLEEP;
}

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_CHANGE_USER(PtrSize_t *pkt, bool *wrong_pass) {
	gtid_hid=-1;
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_CHANGE_USER packet\n");
	//if (session_type == PROXYSQL_SESSION_MYSQL) {
	if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE) {
		reset();
		init();
		if (client_authenticated) {
			if (use_ldap_auth == false) {
				GloMyAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->username);
			} else {
				GloMyLdapAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->fe_username);
			}
		}
		client_authenticated=false;
		if (client_myds->myprot.process_pkt_COM_CHANGE_USER((unsigned char *)pkt->ptr, pkt->size)==true) {
			l_free(pkt->size,pkt->ptr);
			client_myds->myprot.generate_pkt_OK(true, NULL, NULL, 1, 0, 0, 2, 0, NULL);
			client_myds->DSS=STATE_SLEEP;
			status=WAITING_CLIENT_DATA;
			*wrong_pass=false;
			client_authenticated=true;
			//int free_users=0;
			int used_users=0;
			/*free_users */GloMyAuth->increase_frontend_user_connections(client_myds->myconn->userinfo->username, &used_users);
			// FIXME: max_connections is not handled for CHANGE_USER
		} else {
			l_free(pkt->size,pkt->ptr);
			// 'COM_CHANGE_USER' didn't supply a password, and an 'Auth Switch Response' is
			// required, going back to 'STATE_SERVER_HANDSHAKE' to perform the regular
			// 'Auth Switch Response' for a connection is required. See #3504 for more context.
			if (change_user_auth_switch) {
				client_myds->DSS = STATE_SERVER_HANDSHAKE;
				status = CONNECTING_CLIENT;
				return;
			}

			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Wrong credentials for frontend: disconnecting\n");
			*wrong_pass=true;
		// FIXME: this should become close connection
			client_myds->setDSS_STATE_QUERY_SENT_NET();
			char *client_addr=NULL;
			if (client_myds->client_addr) {
				char buf[512];
				switch (client_myds->client_addr->sa_family) {
					case AF_INET: {
						struct sockaddr_in *ipv4 = (struct sockaddr_in *)client_myds->client_addr;
						inet_ntop(client_myds->client_addr->sa_family, &ipv4->sin_addr, buf, INET_ADDRSTRLEN);
						client_addr = strdup(buf);
						break;
					}
					case AF_INET6: {
						struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)client_myds->client_addr;
						inet_ntop(client_myds->client_addr->sa_family, &ipv6->sin6_addr, buf, INET6_ADDRSTRLEN);
						client_addr = strdup(buf);
						break;
					}
					default:
						client_addr = strdup((char *)"localhost");
						break;
				}
			} else {
				client_addr = strdup((char *)"");
			}
			char *_s=(char *)malloc(strlen(client_myds->myconn->userinfo->username)+100+strlen(client_addr));
			sprintf(_s,"ProxySQL Error: Access denied for user '%s'@'%s' (using password: %s)", client_myds->myconn->userinfo->username, client_addr, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
			proxy_error("ProxySQL Error: Access denied for user '%s'@'%s' (using password: %s)\n", client_myds->myconn->userinfo->username, client_addr, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,2,1045,(char *)"28000", _s, true);
			free(_s);
			__sync_fetch_and_add(&MyHGM->status.access_denied_wrong_password, 1);
		}
	} else {
		//FIXME: send an error message saying "not supported" or disconnect
		l_free(pkt->size,pkt->ptr);
	}
}

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_RESET_CONNECTION(PtrSize_t *pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got MYSQL_COM_RESET_CONNECTION packet\n");

	if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE) {
		// Backup the current relevant session values
		int default_hostgroup = this->default_hostgroup;
		bool transaction_persistent = this->transaction_persistent;

		// Re-initialize the session
		reset();
		init();

		// Recover the relevant session values
		this->default_hostgroup = default_hostgroup;
		this->transaction_persistent = transaction_persistent;
		client_myds->myconn->set_charset(default_charset, NAMES);

		if (user_attributes != NULL && strlen(user_attributes)) {
			nlohmann::json j_user_attributes = nlohmann::json::parse(user_attributes);
			auto default_transaction_isolation = j_user_attributes.find("default-transaction_isolation");

			if (default_transaction_isolation != j_user_attributes.end()) {
				std::string def_trx_isolation_val =
					j_user_attributes["default-transaction_isolation"].get<std::string>();
				mysql_variables.client_set_value(this, SQL_ISOLATION_LEVEL, def_trx_isolation_val.c_str());
			}
		}

		l_free(pkt->size,pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_pkt_OK(true, NULL, NULL, 1, 0, 0, 2, 0, NULL);
		client_myds->DSS=STATE_SLEEP;
		status=WAITING_CLIENT_DATA;
	} else {
		l_free(pkt->size,pkt->ptr);

		std::string t_sql_error_msg { "Received unsupported 'COM_RESET_CONNECTION' for session type '%s'" };
		std::string sql_error_msg {};
		string_format(t_sql_error_msg, sql_error_msg, proxysql_session_type_str(session_type).c_str());

		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,2,1047,(char *)"28000", sql_error_msg.c_str(), true);
		client_myds->DSS=STATE_SLEEP;
		status=WAITING_CLIENT_DATA;
	}
}

void MySQL_Session::handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection() {
			// Get a MySQL Connection

		MySQL_Connection *mc=NULL;
		MySQL_Backend * _gtid_from_backend = NULL;
		char uuid[64];
		char * gtid_uuid=NULL;
		uint64_t trxid = 0;
		unsigned long long now_us = 0;
		if (qpo->max_lag_ms >= 0) {
			if (qpo->max_lag_ms > 360000) { // this is an absolute time, we convert it to relative
				if (now_us == 0) {
					now_us = realtime_time();
				}
				long long now_ms = now_us/1000;
				qpo->max_lag_ms = now_ms - qpo->max_lag_ms;
				if (qpo->max_lag_ms < 0) {
					qpo->max_lag_ms = -1; // time expired
				}
			}
		}
		if (session_fast_forward == false && qpo->create_new_conn == false) {
			if (qpo->min_gtid) {
				gtid_uuid = qpo->min_gtid;
				with_gtid = true;
			} else if (qpo->gtid_from_hostgroup >= 0) {
				_gtid_from_backend = find_backend(qpo->gtid_from_hostgroup);
				if (_gtid_from_backend) {
					if (_gtid_from_backend->gtid_uuid[0]) {
						gtid_uuid = _gtid_from_backend->gtid_uuid;
						with_gtid = true;
					}
				}
			}

			char *sep_pos = NULL;
			if (gtid_uuid != NULL) {
				sep_pos = index(gtid_uuid,':');
				if (sep_pos == NULL) {
					gtid_uuid = NULL; // gtid is invalid
				}
			}

			if (gtid_uuid != NULL) {
				int l = sep_pos - gtid_uuid;
				trxid = strtoull(sep_pos+1, NULL, 10);
				int m;
				int n=0;
				for (m=0; m<l; m++) {
					if (gtid_uuid[m] != '-') {
						uuid[n]=gtid_uuid[m];
						n++;
					}
				}
				uuid[n]='\0';
#ifndef STRESSTEST_POOL
				mc=thread->get_MyConn_local(mybe->hostgroup_id, this, uuid, trxid, -1);
#endif // STRESSTEST_POOL
			} else {
#ifndef STRESSTEST_POOL
				mc=thread->get_MyConn_local(mybe->hostgroup_id, this, NULL, 0, (int)qpo->max_lag_ms);
#endif // STRESSTEST_POOL
			}
		}
#ifdef STRESSTEST_POOL
		// Check STRESSTEST_POOL in MySQL_HostGroups_Manager.h
		// Note: this works only if session_fast_forward==false and create_new_conn is false too
#define NUM_SLOW_LOOPS 1000
		// if STRESSTESTPOOL_MEASURE is define, time is measured in Query_Processor_time_nsec
		// even if not the right variable
//#define STRESSTESTPOOL_MEASURE
#ifdef STRESSTESTPOOL_MEASURE
		timespec begint;
		timespec endt;
		clock_gettime(CLOCK_MONOTONIC,&begint);
#endif // STRESSTESTPOOL_MEASURE
		for (unsigned int loops=0; loops < NUM_SLOW_LOOPS; loops++) {
#endif // STRESSTEST_POOL

		if (mc==NULL) {
			if (trxid) {
				mc=MyHGM->get_MyConn_from_pool(mybe->hostgroup_id, this, (session_fast_forward || qpo->create_new_conn), uuid, trxid, -1);
			} else {
				mc=MyHGM->get_MyConn_from_pool(mybe->hostgroup_id, this, (session_fast_forward || qpo->create_new_conn), NULL, 0, (int)qpo->max_lag_ms);
			}
#ifdef STRESSTEST_POOL
			if (mc && (loops < NUM_SLOW_LOOPS - 1)) {
				if (mc->mysql) {
					mybe->server_myds->attach_connection(mc);
					mybe->server_myds->DSS=STATE_NOT_INITIALIZED;
					mybe->server_myds->return_MySQL_Connection_To_Pool();
					mc=NULL;
				}
			}
#endif // STRESSTEST_POOL
		} else {
			thread->status_variables.stvar[st_var_ConnPool_get_conn_immediate]++;
		}
#ifdef STRESSTEST_POOL
#ifdef STRESSTESTPOOL_MEASURE
		clock_gettime(CLOCK_MONOTONIC,&endt);
		thread->status_variables.query_processor_time=thread->status_variables.query_processor_time +
			(endt.tv_sec*1000000000+endt.tv_nsec) -
			(begint.tv_sec*1000000000+begint.tv_nsec);
#endif // STRESSTESTPOOL_MEASURE
		}
#endif // STRESSTEST_POOL
		if (mc) {
			mybe->server_myds->attach_connection(mc);
			thread->status_variables.stvar[st_var_ConnPool_get_conn_success]++;
		} else {
			thread->status_variables.stvar[st_var_ConnPool_get_conn_failure]++;
		}
		if (qpo->max_lag_ms >= 0) {
			if (qpo->max_lag_ms <= 360000) { // this is a relative time , we convert it to absolute
				if (mc == NULL) {
					if (CurrentQuery.waiting_since == 0) {
						CurrentQuery.waiting_since = thread->curtime;
						thread->status_variables.stvar[st_var_queries_with_max_lag_ms__delayed]++;
					}
				}
				if (now_us == 0) {
					now_us = realtime_time();
				}
				long long now_ms = now_us/1000;
				qpo->max_lag_ms = now_ms - qpo->max_lag_ms;
			}
		}
		if (mc) {
			if (CurrentQuery.waiting_since) {
				unsigned long long waited = thread->curtime - CurrentQuery.waiting_since;
				thread->status_variables.stvar[st_var_queries_with_max_lag_ms__total_wait_time_us] += waited;
				CurrentQuery.waiting_since = 0;
			}
		}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p -- server_myds=%p -- MySQL_Connection %p\n", this, mybe->server_myds,  mybe->server_myds->myconn);
	if (mybe->server_myds->myconn==NULL) {
		// we couldn't get a connection for whatever reason, ex: no backends, or too busy
		if (thread->mypolls.poll_timeout==0) { // tune poll timeout
				thread->mypolls.poll_timeout = mysql_thread___poll_timeout_on_failure * 1000;
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Session=%p , DS=%p , poll_timeout=%u\n", mybe->server_myds->sess, mybe->server_myds, thread->mypolls.poll_timeout);
		} else {
			if (thread->mypolls.poll_timeout > (unsigned int)mysql_thread___poll_timeout_on_failure * 1000) {
				thread->mypolls.poll_timeout = mysql_thread___poll_timeout_on_failure * 1000;
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Session=%p , DS=%p , poll_timeout=%u\n", mybe->server_myds->sess, mybe->server_myds, thread->mypolls.poll_timeout);
			}
		}
		return;
	}
	if (mybe->server_myds->myconn->fd==-1) {
		// we didn't get a valid connection, we need to create one
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p -- MySQL Connection has no FD\n", this);
		MySQL_Connection *myconn=mybe->server_myds->myconn;
		myconn->userinfo->set(client_myds->myconn->userinfo);

		myconn->handler(0);
		mybe->server_myds->fd=myconn->fd;
		mybe->server_myds->DSS=STATE_MARIADB_CONNECTING;
		status=CONNECTING_SERVER;
		mybe->server_myds->myconn->reusable=true;
	} else {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p -- MySQL Connection found = %p\n", this, mybe->server_myds->myconn);
		mybe->server_myds->assign_fd_from_mysql_conn();
		mybe->server_myds->myds_type=MYDS_BACKEND;
		mybe->server_myds->DSS=STATE_READY;

		if (session_fast_forward==true) {
			status=FAST_FORWARD;
			mybe->server_myds->myconn->reusable=false; // the connection cannot be usable anymore
		}
	}
}

void MySQL_Session::MySQL_Stmt_Result_to_MySQL_wire(MYSQL_STMT *stmt, MySQL_Connection *myconn) {
	MySQL_ResultSet *MyRS = NULL;
	if (myconn) {
		if (myconn->MyRS) {
			MyRS = myconn->MyRS;
		}
	}
/*
	MYSQL_RES *stmt_result=myconn->query.stmt_result;
	if (stmt_result) {
		MySQL_ResultSet *MyRS=new MySQL_ResultSet();
		MyRS->init(&client_myds->myprot, stmt_result, stmt->mysql, stmt);
		MyRS->get_resultset(client_myds->PSarrayOUT);
		CurrentQuery.rows_sent = MyRS->num_rows;
		//removed  bool resultset_completed=MyRS->get_resultset(client_myds->PSarrayOUT);
		delete MyRS;
*/
	if (MyRS) {
		assert(MyRS->result);
		MyRS->init_with_stmt(myconn);
		bool resultset_completed=MyRS->get_resultset(client_myds->PSarrayOUT);
		CurrentQuery.rows_sent = MyRS->num_rows;
		assert(resultset_completed); // the resultset should always be completed if MySQL_Result_to_MySQL_wire is called
	} else {
		MYSQL *mysql=stmt->mysql;
		// no result set
		int myerrno=mysql_stmt_errno(stmt);
		if (myerrno==0) {
			unsigned int num_rows = mysql_affected_rows(stmt->mysql);
			unsigned int nTrx=NumActiveTransactions();
			uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
			if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
			if (mysql->server_status & SERVER_MORE_RESULTS_EXIST)
				setStatus |= SERVER_MORE_RESULTS_EXIST;
			setStatus |= ( mysql->server_status & ~SERVER_STATUS_AUTOCOMMIT ); // get flags from server_status but ignore autocommit
			setStatus = setStatus & ~SERVER_STATUS_CURSOR_EXISTS; // Do not send cursor #1128
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,client_myds->pkt_sid+1,num_rows,mysql->insert_id, setStatus , myconn ? myconn->warning_count : 0,mysql->info);
			client_myds->pkt_sid++;
		} else {
			// error
			char sqlstate[10];
			sprintf(sqlstate,"%s",mysql_sqlstate(mysql));
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,mysql_errno(mysql),sqlstate,mysql_error(mysql));
			client_myds->pkt_sid++;
		}
	}
}

void MySQL_Session::MySQL_Result_to_MySQL_wire(MYSQL *mysql, MySQL_ResultSet *MyRS, unsigned int warning_count, MySQL_Data_Stream *_myds) {
        if (mysql == NULL) {
                // error
                client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1, 2013, (char *)"HY000" ,(char *)"Lost connection to MySQL server during query");
                return;
        }
	if (MyRS) {
		assert(MyRS->result);
		bool transfer_started=MyRS->transfer_started;
		bool resultset_completed=MyRS->get_resultset(client_myds->PSarrayOUT);
		CurrentQuery.rows_sent = MyRS->num_rows;
		bool com_field_list=client_myds->com_field_list;
		assert(resultset_completed); // the resultset should always be completed if MySQL_Result_to_MySQL_wire is called
		if (transfer_started==false) { // we have all the resultset when MySQL_Result_to_MySQL_wire was called
			if (qpo && qpo->cache_ttl>0 && com_field_list==false) { // the resultset should be cached
				if (mysql_errno(mysql)==0 &&
					(mysql_warning_count(mysql)==0 || 
					 mysql_thread___query_cache_handle_warnings==1)) { // no errors
					if (
						(qpo->cache_empty_result==1)
						|| (
							(qpo->cache_empty_result == -1)
							&&
							(thread->variables.query_cache_stores_empty_result || MyRS->num_rows)
						)
					) {
						client_myds->resultset->copy_add(client_myds->PSarrayOUT,0,client_myds->PSarrayOUT->len);
						client_myds->resultset_length=MyRS->resultset_size;
						unsigned char *aa=client_myds->resultset2buffer(false);
						while (client_myds->resultset->len) client_myds->resultset->remove_index(client_myds->resultset->len-1,NULL);
						bool deprecate_eof_active = client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;
						GloQC->set(
							client_myds->myconn->userinfo->hash ,
							(const unsigned char *)CurrentQuery.QueryPointer,
							CurrentQuery.QueryLength,
							aa ,
							client_myds->resultset_length ,
							thread->curtime/1000 ,
							thread->curtime/1000 ,
							thread->curtime/1000 + qpo->cache_ttl,
							deprecate_eof_active
						);
						l_free(client_myds->resultset_length,aa);
						client_myds->resultset_length=0;
					}
				}
			}
		}
	} else { // no result set
		int myerrno=mysql_errno(mysql);
		if (myerrno==0) {
			unsigned int num_rows = mysql_affected_rows(mysql);
			uint16_t setStatus = (active_transactions ? SERVER_STATUS_IN_TRANS : 0);
			if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
			if (mysql->server_status & SERVER_MORE_RESULTS_EXIST)
				setStatus |= SERVER_MORE_RESULTS_EXIST;
			setStatus |= ( mysql->server_status & ~SERVER_STATUS_AUTOCOMMIT ); // get flags from server_status but ignore autocommit
			setStatus = setStatus & ~SERVER_STATUS_CURSOR_EXISTS; // Do not send cursor #1128
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,client_myds->pkt_sid+1,num_rows,mysql->insert_id, setStatus, warning_count, mysql->info);
			//client_myds->pkt_sid++;
		} else {
			// error
			char sqlstate[10];
			sprintf(sqlstate,"%s",mysql_sqlstate(mysql));
			if (_myds && _myds->killed_at) { // see case #750
				if (_myds->kill_type == 0) {
					client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,1907,sqlstate,(char *)"Query execution was interrupted, query_timeout exceeded");
				} else {
					client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,1317,sqlstate,(char *)"Query execution was interrupted");
				}
			} else {
				client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,mysql_errno(mysql),sqlstate,mysql_error(mysql));
			}
			//client_myds->pkt_sid++;
		}
	}
}

void MySQL_Session::SQLite3_to_MySQL(SQLite3_result *result, char *error, int affected_rows, MySQL_Protocol *myprot, bool in_transaction, bool deprecate_eof_active) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	int sid=1;
	if (result) {
		myprot->generate_pkt_column_count(true,NULL,NULL,sid,result->columns); sid++;
		for (int i=0; i<result->columns; i++) {
			myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",result->column_definition[i]->name,(char *)"",33,15,MYSQL_TYPE_VAR_STRING,1,0x1f,false,0,NULL);
			sid++;
		}
		myds->DSS=STATE_COLUMN_DEFINITION;
		unsigned int nTrx = 0;
		uint16_t setStatus = 0;
		if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		if (in_transaction == false) {
			nTrx=NumActiveTransactions();
			setStatus |= (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		} else {
			// this is for SQLite3 Server
			if (session_type == PROXYSQL_SESSION_SQLITE) {
				//if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
			} else {
				// for sessions that are not SQLITE . Admin and Clickhouse .
				// default
				setStatus |= SERVER_STATUS_AUTOCOMMIT;
			}
			setStatus |= SERVER_STATUS_IN_TRANS;
		}
		if (!deprecate_eof_active) {
			myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus ); sid++;
		}

		char **p=(char **)malloc(sizeof(char*)*result->columns);
		unsigned long *l=(unsigned long *)malloc(sizeof(unsigned long *)*result->columns);

		MySQL_ResultSet MyRS {};
		MyRS.buffer_init(myprot);

		for (int r=0; r<result->rows_count; r++) {
		for (int i=0; i<result->columns; i++) {
			l[i]=result->rows[r]->sizes[i];
			p[i]=result->rows[r]->fields[i];
		}
			sid = myprot->generate_pkt_row3(&MyRS, NULL, sid, result->columns, l, p, 0); sid++;
		}

		MyRS.buffer_to_PSarrayOut();
		MyRS.get_resultset(myds->PSarrayOUT);

		myds->DSS=STATE_ROW;

		if (deprecate_eof_active) {
			myprot->generate_pkt_OK(true, NULL, NULL, sid, 0, 0, setStatus, 0, NULL, true); sid++;
		} else {
			myprot->generate_pkt_EOF(true,NULL,NULL, sid, 0, setStatus ); sid++;
		}

		myds->DSS=STATE_SLEEP;
		free(l);
		free(p);

	} else { // no result set
		if (error) {
			// there was an error
			if (strcmp(error,(char *)"database is locked")==0) {
				myprot->generate_pkt_ERR(true,NULL,NULL,sid,1205,(char *)"HY000",error);
			} else {
				myprot->generate_pkt_ERR(true,NULL,NULL,sid,1045,(char *)"28000",error);
			}
		} else {
			// no error, DML succeeded
			unsigned int nTrx = 0;
			uint16_t setStatus = 0;
			if (in_transaction == false) {
				nTrx=NumActiveTransactions();
				setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
				if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
			} else {
				// this is for SQLite3 Server
				if (session_type == PROXYSQL_SESSION_SQLITE) {
					//if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
				} else {
					// for sessions that are not SQLITE . Admin and Clickhouse .
					// default
					setStatus |= SERVER_STATUS_AUTOCOMMIT;
				}
				setStatus |= SERVER_STATUS_IN_TRANS;
			}
			myprot->generate_pkt_OK(true,NULL,NULL,sid,affected_rows,0,setStatus,0,NULL);
		}
		myds->DSS=STATE_SLEEP;
	}
}

void MySQL_Session::set_unhealthy() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess:%p\n", this);
	healthy=0;
}


unsigned int MySQL_Session::NumActiveTransactions(bool check_savepoint) {
	unsigned int ret=0;
	if (mybes==0) return ret;
	MySQL_Backend *_mybe;
	unsigned int i;
	for (i=0; i < mybes->len; i++) {
		_mybe=(MySQL_Backend *)mybes->index(i);
		if (_mybe->server_myds) {
			if (_mybe->server_myds->myconn) {
				if (_mybe->server_myds->myconn->IsActiveTransaction()) {
					ret++;
				} else {
					// we use check_savepoint to check if we shouldn't ignore COMMIT or ROLLBACK due
					// to MySQL bug https://bugs.mysql.com/bug.php?id=107875 related to
					// SAVEPOINT and autocommit=0
					if (check_savepoint) {
						if (_mybe->server_myds->myconn->AutocommitFalse_AndSavepoint() == true) {
							ret++;
						}
					}
				}
			}
		}
	}
	return ret;
}

bool MySQL_Session::HasOfflineBackends() {
	bool ret=false;
	if (mybes==0) return ret;
	MySQL_Backend *_mybe;
	unsigned int i;
	for (i=0; i < mybes->len; i++) {
		_mybe=(MySQL_Backend *)mybes->index(i);
		if (_mybe->server_myds)
			if (_mybe->server_myds->myconn)
				if (_mybe->server_myds->myconn->IsServerOffline()) {
					ret=true;
					return ret;
				}
	}
	return ret;
}

bool MySQL_Session::SetEventInOfflineBackends() {
	bool ret=false;
	if (mybes==0) return ret;
	MySQL_Backend *_mybe;
	unsigned int i;
	for (i=0; i < mybes->len; i++) {
		_mybe=(MySQL_Backend *)mybes->index(i);
		if (_mybe->server_myds)
			if (_mybe->server_myds->myconn)
				if (_mybe->server_myds->myconn->IsServerOffline()) {
					_mybe->server_myds->revents|=POLLIN;
					ret = true;
				}
	}
	return ret;
}

int MySQL_Session::FindOneActiveTransaction(bool check_savepoint) {
	int ret=-1;
	if (mybes==0) return ret;
	MySQL_Backend *_mybe;
	unsigned int i;
	for (i=0; i < mybes->len; i++) {
		_mybe=(MySQL_Backend *)mybes->index(i);
		if (_mybe->server_myds) {
			if (_mybe->server_myds->myconn) {
				if (_mybe->server_myds->myconn->IsKnownActiveTransaction()) {
					return (int)_mybe->server_myds->myconn->parent->myhgc->hid;
				} else if (_mybe->server_myds->myconn->IsActiveTransaction()) {
					ret = (int)_mybe->server_myds->myconn->parent->myhgc->hid;
				} else {
					// we use check_savepoint to check if we shouldn't ignore COMMIT or ROLLBACK due
					// to MySQL bug https://bugs.mysql.com/bug.php?id=107875 related to
					// SAVEPOINT and autocommit=0
					if (check_savepoint) {
						if (_mybe->server_myds->myconn->AutocommitFalse_AndSavepoint() == true) {
							return (int)_mybe->server_myds->myconn->parent->myhgc->hid;
						}
					}
				}
			}
		}
	}
	return ret;
}

unsigned long long MySQL_Session::IdleTime() {
	unsigned long long ret = 0;
	if (client_myds==0) return 0;
	if (status!=WAITING_CLIENT_DATA && status!=CONNECTING_CLIENT) return 0;
	int idx=client_myds->poll_fds_idx;
	unsigned long long last_sent=thread->mypolls.last_sent[idx];
	unsigned long long last_recv=thread->mypolls.last_recv[idx];
	unsigned long long last_time=(last_sent > last_recv ? last_sent : last_recv);
	if (thread->curtime > last_time) {
		ret = thread->curtime - last_time;
	}
	return ret;
}



// this is called either from RequestEnd(), or at the end of executing
// prepared statements
void MySQL_Session::LogQuery(MySQL_Data_Stream *myds, const unsigned int myerrno, const char * errmsg) {
	// we need to access statistics before calling CurrentQuery.end()
	// so we track the time here
	CurrentQuery.end_time=thread->curtime;

	if (qpo) {
		if (qpo->log==1) {
			GloMyLogger->log_request(this, myds, myerrno, errmsg);	// we send for logging only if logging is enabled for this query
		} else {
			if (qpo->log==-1) {
				if (mysql_thread___eventslog_default_log==1) {
					GloMyLogger->log_request(this, myds, myerrno, errmsg);	// we send for logging only if enabled by default
				}
			}
		}
	}
}
void MySQL_Session::RequestEnd(MySQL_Data_Stream *myds, const unsigned int myerrno, const char * errmsg) {
	// check if multiplexing needs to be disabled
	char *qdt = NULL;

	if (status != PROCESSING_STMT_EXECUTE) {
		qdt = CurrentQuery.get_digest_text();
	} else {
		qdt = CurrentQuery.stmt_info->digest_text;
	}

	if (qdt && myds && myds->myconn) {
		myds->myconn->ProcessQueryAndSetStatusFlags(qdt);
	}

	switch (status) {
		case PROCESSING_STMT_EXECUTE:
		case PROCESSING_STMT_PREPARE:
			// if a prepared statement is executed, LogQuery was already called
			break;
		default:
			if (session_fast_forward==false) {
				LogQuery(myds, myerrno, errmsg);
			}
			break;
	}

	GloQPro->delete_QP_out(qpo);
	// if there is an associated myds, clean its status
	if (myds) {
		// if there is a mysql connection, clean its status
		if (myds->myconn) {
			myds->myconn->async_free_result();
			myds->myconn->compute_unknown_transaction_status();
		}
		myds->free_mysql_real_query();
	}
	if (session_fast_forward==false) {
		// reset status of the session
		status=WAITING_CLIENT_DATA;
		if (client_myds) {
			// reset status of client data stream
			client_myds->DSS=STATE_SLEEP;
			// finalize the query
			CurrentQuery.end();
		}
	}
	started_sending_data_to_client=false;
	previous_hostgroup = current_hostgroup;
}


// this function tries to report all the memory statistics related to the sessions
void MySQL_Session::Memory_Stats() {
	if (thread==NULL)
		return;
	unsigned int i;
	unsigned long long backend=0;
	unsigned long long frontend=0;
	unsigned long long internal=0;
	internal+=sizeof(MySQL_Session);
	if (qpo)
		internal+=sizeof(Query_Processor_Output);
	if (client_myds) {
		internal+=sizeof(MySQL_Data_Stream);
		if (client_myds->queueIN.buffer)
			frontend+=QUEUE_T_DEFAULT_SIZE;
		if (client_myds->queueOUT.buffer)
			frontend+=QUEUE_T_DEFAULT_SIZE;
		if (client_myds->myconn) {
			internal+=sizeof(MySQL_Connection);
		}
		if (client_myds->PSarrayIN) {
			internal += client_myds->PSarrayIN->total_size();
		}
		if (client_myds->PSarrayIN) {
			if (session_fast_forward==true) {
				internal += client_myds->PSarrayOUT->total_size();
			} else {
				internal += client_myds->PSarrayOUT->total_size(RESULTSET_BUFLEN);
				internal += client_myds->resultset->total_size(RESULTSET_BUFLEN);
			}
		}
	}
	for (i=0; i < mybes->len; i++) {
		MySQL_Backend *_mybe=(MySQL_Backend *)mybes->index(i);
			internal+=sizeof(MySQL_Backend);
		if (_mybe->server_myds) {
			internal+=sizeof(MySQL_Data_Stream);
			if (_mybe->server_myds->queueIN.buffer)
				backend+=QUEUE_T_DEFAULT_SIZE;
			if (_mybe->server_myds->queueOUT.buffer)
				backend+=QUEUE_T_DEFAULT_SIZE;
			if (_mybe->server_myds->myconn) {
				MySQL_Connection *myconn=_mybe->server_myds->myconn;
				internal+=sizeof(MySQL_Connection);
				if (myconn->mysql) {
					backend+=sizeof(MYSQL);
					backend+=myconn->mysql->net.max_packet;
					backend+=(4096*15); // ASYNC_CONTEXT_DEFAULT_STACK_SIZE
				}
				if (myconn->MyRS) {
					backend+=myconn->MyRS->current_size();
				}
			}
		}
  }
	thread->status_variables.stvar[st_var_mysql_backend_buffers_bytes] += backend;
	thread->status_variables.stvar[st_var_mysql_frontend_buffers_bytes]+= frontend;
	thread->status_variables.stvar[st_var_mysql_session_internal_bytes] += internal;
}


void MySQL_Session::create_new_session_and_reset_connection(MySQL_Data_Stream *_myds) {
	MySQL_Data_Stream *new_myds = NULL;
	MySQL_Connection * mc = _myds->myconn;
	// we remove the connection from the original data stream
	_myds->detach_connection();
	_myds->unplug_backend();

	// we create a brand new session, a new data stream, and attach the connection to it
	MySQL_Session * new_sess = new MySQL_Session();
	new_sess->mybe = new_sess->find_or_create_backend(mc->parent->myhgc->hid);

	new_myds = new_sess->mybe->server_myds;
	new_myds->attach_connection(mc);
	new_myds->assign_fd_from_mysql_conn();
	new_myds->myds_type = MYDS_BACKEND;
	new_sess->to_process = 1;
	new_myds->wait_until = thread->curtime + mysql_thread___connect_timeout_server*1000;   // max_timeout
	mc->last_time_used = thread->curtime;
	new_myds->myprot.init(&new_myds, new_myds->myconn->userinfo, NULL);
	new_sess->status = RESETTING_CONNECTION;
	mc->async_state_machine = ASYNC_IDLE; // may not be true, but is used to correctly perform error handling
	mc->auto_increment_delay_token = 0;
	new_myds->DSS = STATE_MARIADB_QUERY;
	thread->register_session_connection_handler(new_sess,true);
	if (new_myds->mypolls==NULL) {
		thread->mypolls.add(POLLIN|POLLOUT, new_myds->fd, new_myds, thread->curtime);
	}
	int rc = new_sess->handler();
	if (rc==-1) {
		unsigned int sess_idx = thread->mysql_sessions->len-1;
		thread->unregister_session(sess_idx);
		delete new_sess;
	}
}

bool MySQL_Session::handle_command_query_kill(PtrSize_t *pkt) {
	unsigned char command_type=*((unsigned char *)pkt->ptr+sizeof(mysql_hdr));
	if (CurrentQuery.QueryParserArgs.digest_text) {
		if (command_type == _MYSQL_COM_QUERY) {
			if (client_myds && client_myds->myconn) {
				MySQL_Connection *mc = client_myds->myconn;
				if (mc->userinfo && mc->userinfo->username) {
					if (CurrentQuery.MyComQueryCmd == MYSQL_COM_QUERY_KILL) {
						char *qu = mysql_query_strip_comments((char *)pkt->ptr+1+sizeof(mysql_hdr), pkt->size-1-sizeof(mysql_hdr));
						string nq=string(qu,strlen(qu));
						re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
						opt2->set_case_sensitive(false);
						char *pattern=(char *)"^KILL\\s+(CONNECTION |QUERY |)\\s*(\\d+)\\s*$";
						re2::RE2 *re=new RE2(pattern, *opt2);
						int id=0;
						string tk;
						RE2::FullMatch(nq, *re, &tk, &id);
						delete re;
						delete opt2;
						proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 2, "filtered query= \"%s\"\n", qu);
						free(qu);
						if (id) {
							int tki = -1;
							if (tk.c_str()) {
								if ((strlen(tk.c_str())==0) || (strcasecmp(tk.c_str(),"CONNECTION ")==0)) {
									tki = 0;
								} else {
									if (strcasecmp(tk.c_str(),"QUERY ")==0) {
										tki = 1;
									}
								}
							}
							if (tki >= 0) {
								proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 2, "Killing %s %d\n", (tki == 0 ? "CONNECTION" : "QUERY") , id);
								GloMTH->kill_connection_or_query( id, (tki == 0 ? false : true ),  mc->userinfo->username);
								client_myds->DSS=STATE_QUERY_SENT_NET;
								unsigned int nTrx=NumActiveTransactions();
								uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
								if (autocommit) setStatus = SERVER_STATUS_AUTOCOMMIT;
								client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
								RequestEnd(NULL);
								l_free(pkt->size,pkt->ptr);
								return true;
							}
						}
					}
				}
			}
		}
	}
	return false;
}

void MySQL_Session::add_ldap_comment_to_pkt(PtrSize_t *_pkt) {
	if (GloMyLdapAuth==NULL)
		return;
	if (use_ldap_auth == false)
		return;
	if (client_myds==NULL || client_myds->myconn==NULL || client_myds->myconn->userinfo==NULL)
		return;
	if (client_myds->myconn->userinfo->fe_username==NULL)
		return;
	char *fe=client_myds->myconn->userinfo->fe_username;
	char *a = (char *)" /* %s=%s */";
	char *b = (char *)malloc(strlen(a)+strlen(fe)+strlen(mysql_thread___add_ldap_user_comment));
	sprintf(b,a,mysql_thread___add_ldap_user_comment,fe);
	PtrSize_t _new_pkt;
	_new_pkt.ptr = malloc(strlen(b) + _pkt->size);
	memcpy(_new_pkt.ptr , _pkt->ptr, 5);
	unsigned char *_c=(unsigned char *)_new_pkt.ptr;
	_c+=5;
	void *idx = memchr((char *)_pkt->ptr+5, ' ', _pkt->size-5);
	if (idx) {
		size_t first_word_len = (char *)idx - (char *)_pkt->ptr - 5;
		if (((char *)_pkt->ptr+5)[0]=='/' && ((char *)_pkt->ptr+5)[1]=='*') {
			void* comment_endpos = memmem(static_cast<char*>(_pkt->ptr)+7, _pkt->size-7, "*/", strlen("*/"));

			if (comment_endpos == NULL || idx < comment_endpos) {
				b[1]=' ';
				b[2]=' ';
				b[strlen(b)-1] = ' ';
				b[strlen(b)-2] = ' ';
			}
		}
		memcpy(_c, (char *)_pkt->ptr+5, first_word_len);
		_c+= first_word_len;
		memcpy(_c,b,strlen(b));
		_c+= strlen(b);
		memcpy(_c, (char *)idx, _pkt->size - 5 - first_word_len);
	} else {
		memcpy(_c, (char *)_pkt->ptr+5, _pkt->size-5);
		_c+=_pkt->size-5;
		memcpy(_c,b,strlen(b));
	}
	l_free(_pkt->size,_pkt->ptr);
	_pkt->size = _pkt->size + strlen(b);
	_pkt->ptr = _new_pkt.ptr;
	free(b);
	CurrentQuery.QueryLength = _pkt->size - 5;
	CurrentQuery.QueryPointer = (unsigned char *)_pkt->ptr + 5;
}

void MySQL_Session::finishQuery(MySQL_Data_Stream *myds, MySQL_Connection *myconn, bool prepared_stmt_with_no_params) {
					myds->myconn->reduce_auto_increment_delay_token();
					if (locked_on_hostgroup >= 0) {
						if (qpo->multiplex == -1) {
							myds->myconn->set_status(true, STATUS_MYSQL_CONNECTION_NO_MULTIPLEX);
						}
					}

					const bool is_active_transaction = myds->myconn->IsActiveTransaction();
					const bool multiplex_disabled_by_status = myds->myconn->MultiplexDisabled(false);

					const bool multiplex_delayed = myds->myconn->auto_increment_delay_token > 0;
					const bool multiplex_delayed_with_timeout =
						!multiplex_disabled_by_status && multiplex_delayed && mysql_thread___auto_increment_delay_multiplex_timeout_ms > 0;

					const bool multiplex_disabled = !multiplex_disabled_by_status && (!multiplex_delayed || multiplex_delayed_with_timeout);
					const bool conn_is_reusable = myds->myconn->reusable == true && !is_active_transaction && multiplex_disabled;

					if (mysql_thread___multiplexing && conn_is_reusable) {
						if ((mysql_thread___connection_delay_multiplex_ms || multiplex_delayed_with_timeout) && mirror==false) {
							if (multiplex_delayed_with_timeout) {
								uint64_t delay_multiplex_us = mysql_thread___connection_delay_multiplex_ms * 1000;
								uint64_t auto_increment_delay_us = mysql_thread___auto_increment_delay_multiplex_timeout_ms * 1000;
								uint64_t delay_us = delay_multiplex_us > auto_increment_delay_us ? delay_multiplex_us : auto_increment_delay_us;

								myds->wait_until=thread->curtime + delay_us;
							} else {
								myds->wait_until=thread->curtime+mysql_thread___connection_delay_multiplex_ms*1000;
							}

							myconn->async_state_machine=ASYNC_IDLE;
							myconn->multiplex_delayed=true;
							myds->DSS=STATE_MARIADB_GENERIC;
						} else if (prepared_stmt_with_no_params==true) { // see issue #1432
							myconn->async_state_machine=ASYNC_IDLE;
							myds->DSS=STATE_MARIADB_GENERIC;
							myds->wait_until=0;
							myconn->multiplex_delayed=false;
						} else {
							myconn->multiplex_delayed=false;
							myds->wait_until=0;
							myds->DSS=STATE_NOT_INITIALIZED;
							if (mysql_thread___autocommit_false_not_reusable && myds->myconn->IsAutoCommit()==false) {
								if (mysql_thread___reset_connection_algorithm == 2) {
									create_new_session_and_reset_connection(myds);
								} else {
									myds->destroy_MySQL_Connection_From_Pool(true);
								}
							} else {
								myds->return_MySQL_Connection_To_Pool();
							}
						}
						if (transaction_persistent==true) {
							transaction_persistent_hostgroup=-1;
						}
					} else {
						myconn->multiplex_delayed=false;
						myconn->compute_unknown_transaction_status();
						myconn->async_state_machine=ASYNC_IDLE;
						myds->DSS=STATE_MARIADB_GENERIC;
						if (transaction_persistent==true) {
							if (transaction_persistent_hostgroup==-1) { // change only if not set already, do not allow to change it again
								if (myds->myconn->IsActiveTransaction()==true) { // only active transaction is important here. Ignore other criterias
									transaction_persistent_hostgroup=current_hostgroup;
								}
							} else {
								if (myds->myconn->IsActiveTransaction()==false) { // a transaction just completed
									transaction_persistent_hostgroup=-1;
								}
							}
						}
					}
}


bool MySQL_Session::known_query_for_locked_on_hostgroup(uint64_t digest) {
	bool ret = false;
	switch (digest) {
		case 1732998280766099668ULL: // "SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT"
		case 3748394912237323598ULL: // "SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS"
		case 14407184196285870219ULL: // "SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION"
		case 16906282918371515167ULL: // "SET @OLD_TIME_ZONE=@@TIME_ZONE"
		case 15781568104089880179ULL: // "SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0"
		case 5915334213354374281ULL: // "SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0"
		case 7837089204483965579ULL: //  "SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO'"
		case 4312882378746554890ULL: // "SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0"
		case 4379922288366515816ULL: // "SET @rocksdb_get_is_supported = IF (@rocksdb_has_p_s_session_variables, 'SELECT COUNT(*) INTO @rocksdb_is_supported FROM performance_schema.session_variables WHERE VARIABLE_NAME...
		case 12687634401278615449ULL: // "SET @rocksdb_enable_bulk_load = IF (@rocksdb_is_supported, 'SET SESSION rocksdb_bulk_load = 1', 'SET @rocksdb_dummy_bulk_load = 0')"
		case 15991633859978935883ULL: // "SET @MYSQLDUMP_TEMP_LOG_BIN = @@SESSION.SQL_LOG_BIN"
		case 10636751085721966716ULL: // "SET @@GLOBAL.GTID_PURGED=?"
		case 15976043181199829579ULL: // "SET SQL_QUOTE_SHOW_CREATE=?"
		case 12094956190640701942ULL: // "SET SESSION information_schema_stats_expiry=0"
/*
		case ULL: //
		case ULL: //
		case ULL: //
		case ULL: //
		case ULL: //
*/
			ret = true;
			break;
		default:
			break;
	}
	return ret;
}



void MySQL_Session::unable_to_parse_set_statement(bool *lock_hostgroup) {
	// we couldn't parse the query
	string query_str = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
	string digest_str = string(CurrentQuery.get_digest_text());
	string& nqn = ( mysql_thread___parse_failure_logs_digest == true ? digest_str : query_str );
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Locking hostgroup for query %s\n", query_str.c_str());
	if (qpo->multiplex == -1) {
		// we have no rule about this SET statement. We set hostgroup locking
		if (locked_on_hostgroup < 0) {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "SET query to cause setting lock_hostgroup: %s\n", nqn.c_str());
			if (known_query_for_locked_on_hostgroup(CurrentQuery.QueryParserArgs.digest)) {
				proxy_info("Setting lock_hostgroup for SET query: %s\n", nqn.c_str());
			} else {
				if (client_myds && client_myds->addr.addr) {
					proxy_warning("Unable to parse unknown SET query from client %s:%d. Setting lock_hostgroup. Please report a bug for future enhancements:%s\n", client_myds->addr.addr, client_myds->addr.port, nqn.c_str());
				} else {
					proxy_warning("Unable to parse unknown SET query. Setting lock_hostgroup. Please report a bug for future enhancements:%s\n", nqn.c_str());
				}
			}
			*lock_hostgroup = true;
		} else {
			proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "SET query to cause setting lock_hostgroup, but already set: %s\n", nqn.c_str());
			if (known_query_for_locked_on_hostgroup(CurrentQuery.QueryParserArgs.digest)) {
				//proxy_info("Setting lock_hostgroup for SET query: %s\n", nqn.c_str());
			} else {
				if (client_myds && client_myds->addr.addr) {
					proxy_warning("Unable to parse unknown SET query from client %s:%d. Setting lock_hostgroup. Please report a bug for future enhancements:%s\n", client_myds->addr.addr, client_myds->addr.port, nqn.c_str());
				} else {
					proxy_warning("Unable to parse unknown SET query. Setting lock_hostgroup. Please report a bug for future enhancements:%s\n", nqn.c_str());
				}
			}
		}
	} else {
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5,
					"Unable to parse SET query but NOT setting lock_hostgroup %s\n", query_str.c_str());
	}
}

/**
 * @brief Check if any backend has an active MySQL connection.
 *
 * This function iterates through all backends associated with the session and checks if any backend has an
 * active MySQL connection. If any backend has an active connection, it returns true; otherwise, it returns false.
 *
 * @return true if any backend has an active MySQL connection, otherwise false.
 */
bool MySQL_Session::has_any_backend() {
	for (unsigned int j=0;j < mybes->len;j++) {
		MySQL_Backend *tmp_mybe=(MySQL_Backend *)mybes->index(j);
		MySQL_Data_Stream *__myds=tmp_mybe->server_myds;
		if (__myds->myconn) {
			return true;
		}
	}
	return false;
}

/**
 * @brief Handler for MYSQL_COM_STMT_RESET command in WAITING_CLIENT_DATA state with STATE_SLEEP.
 *
 * This function handles the MYSQL_COM_STMT_RESET command when the session is in the WAITING_CLIENT_DATA state
 * and the data stream state is STATE_SLEEP. It resets the statement with the given statement global ID,
 * frees the memory allocated for the packet, generates an OK packet, and sets the session state back to WAITING_CLIENT_DATA.
 *
 * @param pkt Reference to the packet containing the command and associated data.
 */
void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_RESET(PtrSize_t& pkt) {
	uint32_t stmt_global_id=0;
	memcpy(&stmt_global_id,(char *)pkt.ptr+5,sizeof(uint32_t));
	SLDH->reset(stmt_global_id);
	l_free(pkt.size,pkt.ptr);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	unsigned int nTrx=NumActiveTransactions();
	uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
	if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
	client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
	client_myds->DSS=STATE_SLEEP;
	status=WAITING_CLIENT_DATA;
}

/**
 * @brief Handler for MYSQL_COM_STMT_CLOSE command in WAITING_CLIENT_DATA state with STATE_SLEEP.
 *
 * This function handles the MYSQL_COM_STMT_CLOSE command when the session is in the WAITING_CLIENT_DATA state
 * and the data stream state is STATE_SLEEP. It closes the statement with the given client global ID, frees
 * associated resources, updates counters, and sets the session state back to WAITING_CLIENT_DATA.
 *
 * @param pkt Reference to the packet containing the command and associated data.
 */
void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_CLOSE(PtrSize_t& pkt) {
	uint32_t client_global_id=0;
	memcpy(&client_global_id,(char *)pkt.ptr+5,sizeof(uint32_t));
	// FIXME: no input validation
	uint64_t stmt_global_id=0;
	stmt_global_id=client_myds->myconn->local_stmts->find_global_stmt_id_from_client(client_global_id);
	SLDH->reset(client_global_id);
	if (stmt_global_id) {
		sess_STMTs_meta->erase(stmt_global_id);
	}
	client_myds->myconn->local_stmts->client_close(client_global_id);
	l_free(pkt.size,pkt.ptr);
	// FIXME: this is not complete. Counters should be decreased
	thread->status_variables.stvar[st_var_frontend_stmt_close]++;
	thread->status_variables.stvar[st_var_queries]++;
	client_myds->DSS=STATE_SLEEP;
	status=WAITING_CLIENT_DATA;
}


void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_SEND_LONG_DATA(PtrSize_t& pkt) {
	// FIXME: no input validation
	uint32_t stmt_global_id=0;
	memcpy(&stmt_global_id,(char *)pkt.ptr+5,sizeof(uint32_t));
	uint32_t stmt_param_id=0;
	memcpy(&stmt_param_id,(char *)pkt.ptr+9,sizeof(uint16_t));
	SLDH->add(stmt_global_id,stmt_param_id,(char *)pkt.ptr+11,pkt.size-11);
	client_myds->DSS=STATE_SLEEP;
	status=WAITING_CLIENT_DATA;
	l_free(pkt.size,pkt.ptr);
}

void MySQL_Session::detected_broken_connection(const char *file, unsigned int line, const char *func, const char *action, MySQL_Connection *myconn, int myerr, const char *message, bool verbose) {
	char *msg = (char *)message;
	if (msg == NULL) {
		msg = (char *)"Detected offline server prior to statement execution";
	}
	if (myerr == 0) {
		myerr = ER_PROXYSQL_OFFLINE_SRV;
		msg = (char *)"Detected offline server prior to statement execution";
	}
	unsigned long long last_used = thread->curtime - myconn->last_time_used;
	last_used /= 1000;
	if (verbose) {
		proxy_error_inline(file, line, func, "Detected a broken connection while %s on (%d,%s,%d,%lu) , FD (Conn:%d , MyDS:%d) , user %s , last_used %llums ago : %d, %s\n" , action , myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myconn->get_mysql_thread_id() , myconn->myds->fd , myconn->fd , myconn->userinfo->username, last_used, myerr, msg);
	} else {
		proxy_error_inline(file, line, func, "Detected a broken connection while %s on (%d,%s,%d,%lu) , user %s , last_used %llums ago : %d, %s\n", action, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myconn->get_mysql_thread_id(), myconn->userinfo->username, last_used, myerr, msg);
	}
}

void MySQL_Session::generate_status_one_hostgroup(int hid, std::string& s) {
	SQLite3_result *resultset = MyHGM->SQL3_Connection_Pool(false, &hid);
	json j_res;
	if (resultset->rows_count) {
		for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
			SQLite3_row *r=*it;
			json j; // one json for each row
			for (int i=0; i<resultset->columns; i++) {
				// using the format j["name"] == "value"
				j[resultset->column_definition[i]->name] = ( r->fields[i] ? std::string(r->fields[i]) : std::string("(null)") );
			}
			j_res.push_back(j); // the row json is added to the final json
		}
	} else {
		j_res=json::array();
	}
	s = j_res.dump();
	delete resultset;
}

/**
 * @brief Reset the warning hostgroup flag and release the MySQL connection back to the connection pool.
 *
 * This function resets the warning hostgroup flag and releases the MySQL connection back to the connection pool
 * if necessary. If a warning was found in the previous query execution but the current executed query is not
 * 'SHOW WARNINGS' or 'SHOW COUNT(*) FROM WARNINGS', it means that the warning has been handled, and the connection
 * can be safely returned to the connection pool.
 */
void MySQL_Session::reset_warning_hostgroup_flag_and_release_connection() {
	if (warning_in_hg > -1) {
		// if we've reached this point, it means that warning was found in the previous query, but the
		// current executed query is not 'SHOW WARNINGS' or 'SHOW COUNT(*) FROM WARNINGS', so we can safely reset warning_in_hg and 
		// return connection back to the connection pool.
		MySQL_Backend* _mybe = find_backend(warning_in_hg);
		if (_mybe) {
			MySQL_Data_Stream* myds = _mybe->server_myds;
			if (myds && myds->myconn) {
				myds->myconn->warning_count = 0;
				myds->myconn->set_status(false, STATUS_MYSQL_CONNECTION_HAS_WARNINGS);
				if ((myds->myconn->reusable == true) && myds->myconn->IsActiveTransaction() == false && myds->myconn->MultiplexDisabled() == false) {
					myds->return_MySQL_Connection_To_Pool();
				}
			}
		}
		warning_in_hg = -1;
	}
}
