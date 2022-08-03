#include "MySQL_HostGroups_Manager.h"
#include "ProxyWorker_Thread.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_utils.h"
#include "re2/re2.h"
#include "re2/regexp.h"
#include "SpookyV2.h"
#include "mysqld_error.h"
#include "set_parser.h"

#include "ProxySQL_Data_Stream.h"
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


#include "libinjection.h"
#include "libinjection_sqli.h"

#include "MySQL_Session.h"


#define EXPMARIA


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


extern MARIADB_CHARSET_INFO * proxysql_find_charset_name(const char * const name);
extern MARIADB_CHARSET_INFO * proxysql_find_charset_collate_names(const char *csname, const char *collatename);
extern const MARIADB_CHARSET_INFO * proxysql_find_charset_nr(unsigned int nr);
extern MARIADB_CHARSET_INFO * proxysql_find_charset_collate(const char *collatename);

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

Session_Regex::Session_Regex(char *p) {
	s=strdup(p);
	re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
	opt2->set_case_sensitive(false);
	opt=(void *)opt2;
	re=(RE2 *)new RE2(s, *opt2);
}

Session_Regex::~Session_Regex() {
	free(s);
	delete (RE2 *)re;
	delete (re2::RE2::Options *)opt;
}

bool Session_Regex::match(char *m) {
	bool rc=false;
	rc=RE2::PartialMatch(m,*(RE2 *)re);
	return rc;
}


KillArgs::KillArgs(char *u, char *p, char *h, unsigned int P, unsigned int _hid, unsigned long i, int kt, ProxyWorker_Thread *_mt) {
	username=strdup(u);
	password=strdup(p);
	hostname=strdup(h);
	port=P;
	hid=_hid;
	id=i;
	kill_type=kt;
	mt=_mt;
}

KillArgs::~KillArgs() {
	free(username);
	free(password);
	free(hostname);
}



void * kill_query_thread(void *arg) {
	KillArgs *ka=(KillArgs *)arg;
	MYSQL *mysql;
	ProxyWorker_Thread * thread = ka->mt;
	mysql=mysql_init(NULL);
	mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "program_name", "proxysql_killer");
	mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "_server_host", ka->hostname);
	if (!mysql) {
		goto __exit_kill_query_thread;
	}
	MYSQL *ret;
	if (ka->port) {
		switch (ka->kill_type) {
			case KILL_QUERY:
				proxy_warning("KILL QUERY %lu on %s:%d\n", ka->id, ka->hostname, ka->port);
				if (thread) {
					thread->status_variables.stvar[st_var_killed_queries]++;
				}
				break;
			case KILL_CONNECTION:
				proxy_warning("KILL CONNECTION %lu on %s:%d\n", ka->id, ka->hostname, ka->port);
				if (thread) {
					thread->status_variables.stvar[st_var_killed_connections]++;
				}
				break;
			default:
				break;
		}
		ret=mysql_real_connect(mysql,ka->hostname,ka->username,ka->password,NULL,ka->port,NULL,0);
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
		proxy_error("Failed to connect to server %s:%d to run KILL %s %llu: Error: %s\n" , ka->hostname, ka->port, ( ka->kill_type==KILL_QUERY ? "QUERY" : "CONNECTION" ) , ka->id, mysql_error(mysql));
		MyHGM->p_update_mysql_error_counter(p_mysql_error_type::mysql, ka->hid, ka->hostname, ka->port, mysql_errno(mysql));
		goto __exit_kill_query_thread;
	}
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
	// FIXME: these 2 calls are blocking, fortunately on their own thread
	mysql_query(mysql,buf);
__exit_kill_query_thread:
	if (mysql)
		mysql_close(mysql);
	delete ka;
	return NULL;
}

extern Query_Processor *GloQPro;
extern Query_Cache *GloQC;
extern ProxySQL_Admin *GloAdmin;
extern ProxyWorker_Threads_Handler *GloPWTH;

Query_Info::Query_Info() {
	MyComQueryCmd=MYSQL_COM_QUERY___NONE;
	QueryPointer=NULL;
	QueryLength=0;
	QueryParserArgs.digest_text=NULL;
	QueryParserArgs.first_comment=NULL;
	stmt_info=NULL;
	bool_is_select_NOT_for_update=false;
	bool_is_select_NOT_for_update_computed=false;
	have_affected_rows=false;
	waiting_since = 0;
	affected_rows=0;
	rows_sent=0;
	start_time=0;
	end_time=0;
}

Query_Info::~Query_Info() {
	GloQPro->query_parser_free(&QueryParserArgs);
	if (stmt_info) {
		stmt_info=NULL;
	}
}

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
	have_affected_rows=false;
	waiting_since = 0;
	affected_rows=0;
	rows_sent=0;
	sess->gtid_hid=-1;
}

void Query_Info::end() {
	query_parser_update_counters();
	query_parser_free();
	if ((end_time-start_time) > (unsigned int)mysql_thread___long_query_time*1000) {
		__sync_add_and_fetch(&sess->thread->status_variables.stvar[st_var_queries_slow],1);
	}
	if (sess->with_gtid) {
		__sync_add_and_fetch(&sess->thread->status_variables.stvar[st_var_queries_gtid],1);
	}
	if (sess->session_type==PROXYSQL_SESSION_MYSQL) {
	assert(mysql_stmt==NULL);
	if (stmt_info) {
		stmt_info=NULL;
	}
	if (stmt_meta) { // fix bug #796: memory is not freed in case of error during STMT_EXECUTE
		if (stmt_meta->pkt) {
			uint32_t stmt_global_id=0;
			memcpy(&stmt_global_id,(char *)(stmt_meta->pkt)+5,sizeof(uint32_t));
			((MySQL_Session *)sess)->SLDH->reset(stmt_global_id);
			free(stmt_meta->pkt);
			stmt_meta->pkt=NULL;
		}
		stmt_meta = NULL;
	}
	}
}

void Query_Info::init(unsigned char *_p, int len, bool mysql_header) {
	QueryLength=(mysql_header ? len-5 : len);
	QueryPointer=(mysql_header ? _p+5 : _p);
	MyComQueryCmd = MYSQL_COM_QUERY__UNINITIALIZED;
	bool_is_select_NOT_for_update=false;
	bool_is_select_NOT_for_update_computed=false;
	have_affected_rows=false;
	waiting_since = 0;
	affected_rows=0;
	rows_sent=0;
}

void Query_Info::query_parser_init() {
	GloQPro->query_parser_init(&QueryParserArgs,(char *)QueryPointer,QueryLength,0);
}

enum MYSQL_COM_QUERY_command Query_Info::query_parser_command_type() {
	MyComQueryCmd=GloQPro->query_parser_command_type(&QueryParserArgs);
	return MyComQueryCmd;
}

void Query_Info::query_parser_free() {
	GloQPro->query_parser_free(&QueryParserArgs);
}

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

char * Query_Info::get_digest_text() {
	return GloQPro->get_digest_text(&QueryParserArgs);
}

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

void * Client_Session::operator new(size_t size) {
	return l_alloc(size);
}

void Client_Session::operator delete(void *ptr) {
	l_free(sizeof(Client_Session),ptr);
}


void Client_Session::set_status(enum session_status e) {
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


Client_Session::Client_Session() {
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
	session_type=PROXYSQL_SESSION_MYSQL; // default
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
	to_process=0;
	mybe=NULL;
	mirror=false;
	mirrorPkt.ptr=NULL;
	mirrorPkt.size=0;
	set_status(session_status___NONE);

	idle_since = 0;
	transaction_started_at = 0;

	CurrentQuery.sess=this;

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

void Client_Session::init() {
	transaction_persistent_hostgroup=-1;
	transaction_persistent=false;
	mybes= new PtrArray(4);
	if (session_type==PROXYSQL_SESSION_MYSQL) {
		((MySQL_Session *)this)->mysql_session_init();
	}
/*
	sess_STMTs_meta=new MySQL_STMTs_meta();
	SLDH=new StmtLongDataHandler();
*/
}

void Client_Session::reset() {
	autocommit=true;
	autocommit_handled=false;
	sending_set_autocommit=false;
	autocommit_on_hostgroup=-1;
	current_hostgroup=-1;
	default_hostgroup=-1;
	locked_on_hostgroup=-1;
	locked_on_hostgroup_and_all_variables_set=false;
/*
	if (session_type==PROXYSQL_SESSION_MYSQL) {
		((MySQL_Session *)this)->mysql_session_reset();
	}
*/
/*
	if (sess_STMTs_meta) {
		delete sess_STMTs_meta;
		sess_STMTs_meta=NULL;
	}
	if (SLDH) {
		delete SLDH;
		SLDH=NULL;
	}
*/
	if (mybes) {
		reset_all_mysql_backends();
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
}

Client_Session::~Client_Session() {

	reset(); // we moved this out to allow CHANGE_USER

	if (locked_on_hostgroup >= 0) {
		thread->status_variables.stvar[st_var_hostgroup_locked]--;
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
		__sync_sub_and_fetch(&GloPWTH->status_variables.mirror_sessions_current,1);
		GloPWTH->status_variables.p_gauge_array[p_th_gauge::mirror_concurrency]->Decrement();
	}
	if (proxysql_node_address) {
		delete proxysql_node_address;
		proxysql_node_address = NULL;
	}
}


// scan the pointer array of mysql backends (mybes) looking for a backend for the specified hostgroup_id
MySQL_Backend * Client_Session::find_mysql_backend(int hostgroup_id) {
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


MySQL_Backend * Client_Session::create_mysql_backend(int hostgroup_id, ProxySQL_Data_Stream *pds) {
	MySQL_Backend *_mybe=new MySQL_Backend();
	MySQL_Data_Stream *_myds = (MySQL_Data_Stream *)pds;
	proxy_debug(PROXY_DEBUG_NET,4,"HID=%d, _myds=%p, _mybe=%p\n" , hostgroup_id, _myds, _mybe);
	_mybe->hostgroup_id=hostgroup_id;
	if (_myds) {
		_mybe->server_myds=_myds;
	} else {
		_mybe->server_myds = new MySQL_Data_Stream();
		_mybe->server_myds->DSS=STATE_NOT_INITIALIZED;
		_mybe->server_myds->init(MYDS_BACKEND_NOT_CONNECTED, this, 0);
	}
	mybes->add(_mybe);
	return _mybe;
};

MySQL_Backend * Client_Session::find_or_create_mysql_backend(int hostgroup_id, ProxySQL_Data_Stream *_myds) {
	MySQL_Backend *_mybe=find_mysql_backend(hostgroup_id);
	proxy_debug(PROXY_DEBUG_NET,4,"HID=%d, _myds=%p, _mybe=%p\n" , hostgroup_id, _myds, _mybe);
	return ( _mybe ? _mybe : create_mysql_backend(hostgroup_id, _myds) );
};

void Client_Session::reset_all_mysql_backends() {
	MySQL_Backend *mybe;
	while(mybes->len) {
		mybe=(MySQL_Backend *)mybes->remove_index_fast(0);
		mybe->reset();
		delete mybe;
	}
};

void Client_Session::generate_proxysql_internal_session_json(json &j) {
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
	j["gtid"]["hid"] = gtid_hid;
	j["gtid"]["last"] = ( strlen(gtid_buf) ? gtid_buf : "" );
	j["qpo"]["create_new_connection"] = qpo->create_new_conn;
	j["qpo"]["reconnect"] = qpo->reconnect;
	j["qpo"]["sticky_conn"] = qpo->sticky_conn;
	j["qpo"]["cache_timeout"] = qpo->cache_timeout;
	j["qpo"]["cache_ttl"] = qpo->cache_ttl;
	j["qpo"]["delay"] = qpo->delay;
	j["qpo"]["destination_hostgroup"] = qpo->destination_hostgroup;
	j["qpo"]["firewall_whitelist_mode"] = qpo->firewall_whitelist_mode;
	j["qpo"]["multiplex"] = qpo->multiplex;
	j["qpo"]["timeout"] = qpo->timeout;
	j["qpo"]["retries"] = qpo->retries;
	j["qpo"]["max_lag_ms"] = qpo->max_lag_ms;
	j["default_schema"] = ( default_schema ? default_schema : "" );
	j["user_attributes"] = ( user_attributes ? user_attributes : "" );
	j["transaction_persistent"] = transaction_persistent;
	MySQL_Data_Stream *client_myds = NULL;
	if (session_type==PROXYSQL_SESSION_MYSQL) {
		client_myds = ((MySQL_Session *)this)->client_myds;
	}
	if (client_myds != NULL) { // only if client_myds is defined
		j["client"]["stream"]["pkts_recv"] = client_myds->pkts_recv;
		j["client"]["stream"]["pkts_sent"] = client_myds->pkts_sent;
		j["client"]["stream"]["bytes_recv"] = client_myds->bytes_info.bytes_recv;
		j["client"]["stream"]["bytes_sent"] = client_myds->bytes_info.bytes_sent;
		j["client"]["client_addr"]["address"] = ( client_myds->addr.addr ? client_myds->addr.addr : "" );
		j["client"]["client_addr"]["port"] = client_myds->addr.port;
		j["client"]["proxy_addr"]["address"] = ( client_myds->proxy_addr.addr ? client_myds->proxy_addr.addr : "" );
		j["client"]["proxy_addr"]["port"] = client_myds->proxy_addr.port;
		j["client"]["encrypted"] = client_myds->encrypted;
		if (client_myds->encrypted) {
			const SSL_CIPHER *cipher = SSL_get_current_cipher(client_myds->ssl);
			if (cipher) {
				const char * name = SSL_CIPHER_get_name(cipher);
				if (name) {
					j["client"]["ssl_cipher"] = name;
				}
			}
		}
		j["client"]["DSS"] = client_myds->DSS;
		j["client"]["switching_auth_type"] = client_myds->switching_auth_type;
		if (client_myds->myconn != NULL) { // only if myconn is defined
			if (client_myds->myconn->userinfo != NULL) { // only if userinfo is defined
				j["client"]["userinfo"]["username"] = ( client_myds->myconn->userinfo->username ? client_myds->myconn->userinfo->username : "" );
				j["client"]["userinfo"]["schemaname"] = ( client_myds->myconn->userinfo->schemaname ? client_myds->myconn->userinfo->schemaname : "" );
#ifdef DEBUG
				j["client"]["userinfo"]["password"] = ( client_myds->myconn->userinfo->password ? client_myds->myconn->userinfo->password : "" );
#endif
			}
			j["conn"]["session_track_gtids"] = ( client_myds->myconn->options.session_track_gtids ? client_myds->myconn->options.session_track_gtids : "") ;
			for (auto idx = 0; idx < SQL_NAME_LAST_LOW_WM; idx++) {
				client_myds->myconn->variables[idx].fill_client_internal_session(j, idx);
			}
			{
				MySQL_Connection *c = client_myds->myconn;
				for (std::vector<uint32_t>::const_iterator it_c = c->dynamic_variables_idx.begin(); it_c != c->dynamic_variables_idx.end(); it_c++) {
					c->variables[*it_c].fill_client_internal_session(j, *it_c);
				}
			}

			j["conn"]["autocommit"] = ( client_myds->myconn->options.autocommit ? "ON" : "OFF" );
			j["conn"]["client_flag"]["value"] = client_myds->myconn->options.client_flag;
			j["conn"]["client_flag"]["client_found_rows"] = (client_myds->myconn->options.client_flag & CLIENT_FOUND_ROWS ? 1 : 0);
			j["conn"]["client_flag"]["client_multi_statements"] = (client_myds->myconn->options.client_flag & CLIENT_MULTI_STATEMENTS ? 1 : 0);
			j["conn"]["client_flag"]["client_multi_results"] = (client_myds->myconn->options.client_flag & CLIENT_MULTI_RESULTS ? 1 : 0);
			j["conn"]["client_flag"]["client_deprecate_eof"] = (client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF ? 1 : 0);
			j["conn"]["no_backslash_escapes"] = client_myds->myconn->options.no_backslash_escapes;
			j["conn"]["status"]["compression"] = client_myds->myconn->get_status(STATUS_MYSQL_CONNECTION_COMPRESSION);
			j["conn"]["status"]["transaction"] = client_myds->myconn->get_status(STATUS_MYSQL_CONNECTION_TRANSACTION);
			j["conn"]["ps"]["client_stmt_to_global_ids"] = client_myds->myconn->local_stmts->client_stmt_to_global_ids;
		}
	}
	for (unsigned int k=0; k<mybes->len; k++) {
		MySQL_Backend *_mybe = NULL;
		_mybe=(MySQL_Backend *)mybes->index(k);
		unsigned int i = _mybe->hostgroup_id;
		j["backends"][i]["hostgroup_id"] = i;
		j["backends"][i]["gtid"] = ( strlen(_mybe->gtid_uuid) ? _mybe->gtid_uuid : "" );
		if (session_type==PROXYSQL_SESSION_MYSQL && _mybe->server_myds) {
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
				MySQL_Connection * _myconn = _myds->myconn;
				for (auto idx = 0; idx < SQL_NAME_LAST_LOW_WM; idx++) {
					_myconn->variables[idx].fill_server_internal_session(j, i, idx);
				}
				for (std::vector<uint32_t>::const_iterator it_c = _myconn->dynamic_variables_idx.begin(); it_c != _myconn->dynamic_variables_idx.end(); it_c++) {
					_myconn->variables[*it_c].fill_server_internal_session(j, i, *it_c);
				}
				sprintf(buff,"%p",_myconn);
				j["backends"][i]["conn"]["address"] = buff;
				j["backends"][i]["conn"]["auto_increment_delay_token"] = _myconn->auto_increment_delay_token;
				j["backends"][i]["conn"]["bytes_recv"] = _myconn->bytes_info.bytes_recv;
				j["backends"][i]["conn"]["bytes_sent"] = _myconn->bytes_info.bytes_sent;
				j["backends"][i]["conn"]["questions"] = _myconn->statuses.questions;
				j["backends"][i]["conn"]["myconnpoll_get"] = _myconn->statuses.myconnpoll_get;
				j["backends"][i]["conn"]["myconnpoll_put"] = _myconn->statuses.myconnpoll_put;
				//j["backend"][i]["conn"]["charset"] = _myds->myconn->options.charset; // not used for backend
				j["backends"][i]["conn"]["session_track_gtids"] = ( _myconn->options.session_track_gtids ? _myconn->options.session_track_gtids : "") ;
				j["backends"][i]["conn"]["init_connect"] = ( _myconn->options.init_connect ? _myconn->options.init_connect : "");
				j["backends"][i]["conn"]["init_connect_sent"] = _myds->myconn->options.init_connect_sent;
				j["backends"][i]["conn"]["autocommit"] = ( _myds->myconn->options.autocommit ? "ON" : "OFF" );
				j["backends"][i]["conn"]["last_set_autocommit"] = _myds->myconn->options.last_set_autocommit;
				j["backends"][i]["conn"]["no_backslash_escapes"] = _myconn->options.no_backslash_escapes;
				j["backends"][i]["conn"]["status"]["get_lock"] = _myconn->get_status(STATUS_MYSQL_CONNECTION_GET_LOCK);
				j["backends"][i]["conn"]["status"]["lock_tables"] = _myconn->get_status(STATUS_MYSQL_CONNECTION_LOCK_TABLES);
				j["backends"][i]["conn"]["status"]["has_savepoint"] = _myconn->get_status(STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT);
				j["backends"][i]["conn"]["status"]["temporary_table"] = _myconn->get_status(STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE);
				j["backends"][i]["conn"]["status"]["user_variable"] = _myconn->get_status(STATUS_MYSQL_CONNECTION_USER_VARIABLE);
				j["backends"][i]["conn"]["status"]["found_rows"] = _myconn->get_status(STATUS_MYSQL_CONNECTION_FOUND_ROWS);
				j["backends"][i]["conn"]["status"]["no_multiplex"] = _myconn->get_status(STATUS_MYSQL_CONNECTION_NO_MULTIPLEX);
				j["backends"][i]["conn"]["status"]["compression"] = _myconn->get_status(STATUS_MYSQL_CONNECTION_COMPRESSION);
				j["backends"][i]["conn"]["status"]["prepared_statement"] = _myconn->get_status(STATUS_MYSQL_CONNECTION_PREPARED_STATEMENT);
				j["backends"][i]["conn"]["MultiplexDisabled"] = _myconn->MultiplexDisabled();
				j["backends"][i]["conn"]["ps"]["backend_stmt_to_global_ids"] = _myconn->local_stmts->backend_stmt_to_global_ids;
				j["backends"][i]["conn"]["ps"]["global_stmt_to_backend_ids"] = _myconn->local_stmts->global_stmt_to_backend_ids;
				j["backends"][i]["conn"]["client_flag"]["value"] = _myconn->options.client_flag;
				j["backends"][i]["conn"]["client_flag"]["client_found_rows"] = (_myconn->options.client_flag & CLIENT_FOUND_ROWS ? 1 : 0);
				j["backends"][i]["conn"]["client_flag"]["client_multi_statements"] = (_myconn->options.client_flag & CLIENT_MULTI_STATEMENTS ? 1 : 0);
				j["backends"][i]["conn"]["client_flag"]["client_deprecate_eof"] = (_myconn->options.client_flag & CLIENT_DEPRECATE_EOF ? 1 : 0);
				if (_myconn->mysql && _myconn->ret_mysql) {
					MYSQL * _my = _myconn->mysql;
					sprintf(buff,"%p",_my);
					j["backends"][i]["conn"]["mysql"]["address"] = buff;
					j["backends"][i]["conn"]["mysql"]["host"] = ( _my->host ? _my->host : "" );
					j["backends"][i]["conn"]["mysql"]["host_info"] = ( _my->host_info ? _my->host_info : "" );
					j["backends"][i]["conn"]["mysql"]["port"] = _my->port;
					j["backends"][i]["conn"]["mysql"]["server_version"] = ( _my->server_version ? _my->server_version : "" );
					j["backends"][i]["conn"]["mysql"]["user"] = ( _my->user ? _my->user : "" );
					j["backends"][i]["conn"]["mysql"]["unix_socket"] = (_my->unix_socket ? _my->unix_socket : "");
					j["backends"][i]["conn"]["mysql"]["db"] = (_my->db ? _my->db : "");
					j["backends"][i]["conn"]["mysql"]["affected_rows"] = _my->affected_rows;
					j["backends"][i]["conn"]["mysql"]["insert_id"] = _my->insert_id;
					j["backends"][i]["conn"]["mysql"]["thread_id"] = _my->thread_id;
					j["backends"][i]["conn"]["mysql"]["server_status"] = _my->server_status;
					j["backends"][i]["conn"]["mysql"]["charset"] = _my->charset->nr;
					j["backends"][i]["conn"]["mysql"]["charset_name"] = _my->charset->csname;
					//j["backends"][i]["conn"]["mysql"][""] = _my->;
					//j["backends"][i]["conn"]["mysql"][""] = _my->;
					j["backends"][i]["conn"]["mysql"]["options"]["charset_name"] = ( _my->options.charset_name ? _my->options.charset_name : "" );
					j["backends"][i]["conn"]["mysql"]["options"]["use_ssl"] = _my->options.use_ssl;
					j["backends"][i]["conn"]["mysql"]["net"]["last_errno"] = _my->net.last_errno;
					j["backends"][i]["conn"]["mysql"]["net"]["fd"] = _my->net.fd;
					j["backends"][i]["conn"]["mysql"]["net"]["max_packet_size"] = _my->net.max_packet_size;
					j["backends"][i]["conn"]["mysql"]["net"]["sqlstate"] = _my->net.sqlstate;
					//j["backends"][i]["conn"]["mysql"]["net"][""] = _my->net.;
					//j["backends"][i]["conn"]["mysql"]["net"][""] = _my->net.;
				}
			}
		}
	}
}

void Client_Session::return_proxysql_internal(PtrSize_t *pkt) {
	assert(session_type==PROXYSQL_SESSION_MYSQL);
	MySQL_Data_Stream * client_myds = NULL;
	if (session_type==PROXYSQL_SESSION_MYSQL) {
		client_myds = ((MySQL_Session *)this)->client_myds;
	}
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
	assert(client_myds != NULL);
	client_myds->DSS=STATE_QUERY_SENT_NET;
	client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1064,(char *)"42000",(char *)"Unknown PROXYSQL INTERNAL command",true);
	client_myds->DSS=STATE_SLEEP;
	status=WAITING_CLIENT_DATA;
	if (mirror==false) {
		((MySQL_Session *)this)->RequestEnd_mysql(NULL);
	}
	l_free(pkt->size,pkt->ptr);
}


/*
int Client_Session::handler_again___status_RESETTING_CONNECTION() {
	assert(mybe->server_myds->myconn);
	ProxySQL_Data_Stream *myds=mybe->server_myds;
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
					proxy_error("Detected an error during COM_CHANGE_USER on (%d,%s,%d) , FD (Conn:%d , MyDS:%d) : %d, %s\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myds->fd, myds->myconn->fd, myerr, mysql_error(myconn->mysql));
				} else {
					proxy_error(
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
			RequestEnd_mysql(myds); //fix bug #682
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
*/

void Client_Session::handler_again___new_thread_to_kill_connection() {
	MySQL_Data_Stream *myds=mybe->server_myds;
	assert(session_type==PROXYSQL_SESSION_MYSQL);
	if (myds->myconn && myds->myconn->mysql) {
		if (myds->killed_at==0) {
			myds->wait_until=0;
			myds->killed_at=thread->curtime;
			//fprintf(stderr,"Expired: %llu, %llu\n", mybe->server_myds->wait_until, thread->curtime);
			MySQL_Data_Stream *client_myds = NULL;
			if (session_type==PROXYSQL_SESSION_MYSQL) {
				client_myds = ((MySQL_Session *)this)->client_myds;
			}
			MySQL_Connection_userinfo *ui=client_myds->myconn->userinfo;
			char *auth_password=NULL;
			if (ui->password) {
				if (ui->password[0]=='*') { // we don't have the real password, let's pass sha1
					auth_password=ui->sha1_pass;
				} else {
					auth_password=ui->password;
				}
			}
			KillArgs *ka = new KillArgs(ui->username, auth_password, myds->myconn->parent->address, myds->myconn->parent->port, myds->myconn->parent->myhgc->hid, myds->myconn->mysql->thread_id, KILL_QUERY, thread);
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

/*
bool Client_Session::handler_again___verify_backend_multi_statement() {
	if ((client_myds->myconn->options.client_flag & CLIENT_MULTI_STATEMENTS) != (mybe->server_myds->myconn->options.client_flag & CLIENT_MULTI_STATEMENTS)) {

		if (client_myds->myconn->options.client_flag & CLIENT_MULTI_STATEMENTS)
			mybe->server_myds->myconn->options.client_flag |= CLIENT_MULTI_STATEMENTS;
		else
			mybe->server_myds->myconn->options.client_flag &= ~CLIENT_MULTI_STATEMENTS;

		switch(status) { // this switch can be replaced with a simple previous_status.push(status), but it is here for readibility
			case PROCESSING_QUERY:
				previous_status.push(PROCESSING_QUERY);
				break;
				case PROCESSING_STMT_PREPARE:
			previous_status.push(PROCESSING_STMT_PREPARE);
				break;
				case PROCESSING_STMT_EXECUTE:
				previous_status.push(PROCESSING_STMT_EXECUTE);
				break;
			default:
				// LCOV_EXCL_START
				assert(0);
				break;
				// LCOV_EXCL_STOP
		}
		NEXT_IMMEDIATE_NEW(SETTING_MULTI_STMT);
	}
	return false;
}
*/
/*
bool Client_Session::handler_again___verify_init_connect() {
	if (mybe->server_myds->myconn->options.init_connect_sent==false) {
		// we needs to set it to true
		mybe->server_myds->myconn->options.init_connect_sent=true;
		if (mysql_thread___init_connect) {
			// we send init connect queries only if set
			mybe->server_myds->myconn->options.init_connect=strdup(mysql_thread___init_connect);
			switch(status) { // this switch can be replaced with a simple previous_status.push(status), but it is here for readibility
				case PROCESSING_QUERY:
					previous_status.push(PROCESSING_QUERY);
					break;
				case PROCESSING_STMT_PREPARE:
					previous_status.push(PROCESSING_STMT_PREPARE);
					break;
				case PROCESSING_STMT_EXECUTE:
					previous_status.push(PROCESSING_STMT_EXECUTE);
					break;
				default:
					// LCOV_EXCL_START
					assert(0);
					break;
					// LCOV_EXCL_STOP
			}
			NEXT_IMMEDIATE_NEW(SETTING_INIT_CONNECT);
		}
	}
	return false;
}
*/
/*
bool Client_Session::handler_again___verify_backend_session_track_gtids() {
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
		switch(status) {
			case PROCESSING_QUERY:
			case PROCESSING_STMT_PREPARE:
			case PROCESSING_STMT_EXECUTE:
				previous_status.push(status);
				break;
			default:
				// LCOV_EXCL_START
				assert(0);
				break;
				// LCOV_EXCL_STOP
		}
		NEXT_IMMEDIATE_NEW(SETTING_SESSION_TRACK_GTIDS);
	}
	return ret;
}

bool Client_Session::handler_again___verify_backend_autocommit() {
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
		return false;
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , client: %d , backend: %d\n", this, client_myds->myconn->options.autocommit, mybe->server_myds->myconn->options.autocommit);
	if (autocommit != mybe->server_myds->myconn->IsAutoCommit()) {
		// see case #485
		if (mysql_thread___enforce_autocommit_on_reads == false && autocommit == false) {
			// enforce_autocommit_on_reads is disabled
			// we need to check if it is a SELECT not FOR UPDATE
			if (CurrentQuery.is_select_NOT_for_update()==false) {
				//previous_status.push(PROCESSING_QUERY);
				switch(status) { // this switch can be replaced with a simple previous_status.push(status), but it is here for readibility
					case PROCESSING_QUERY:
						previous_status.push(PROCESSING_QUERY);
						break;
					case PROCESSING_STMT_PREPARE:
						previous_status.push(PROCESSING_STMT_PREPARE);
						break;
					case PROCESSING_STMT_EXECUTE:
						previous_status.push(PROCESSING_STMT_EXECUTE);
						break;
					default:
						// LCOV_EXCL_START
						assert(0);
						break;
						// LCOV_EXCL_STOP
				}
				NEXT_IMMEDIATE_NEW(CHANGING_AUTOCOMMIT);
			}
		} else {
			// in every other cases, enforce autocommit
			//previous_status.push(PROCESSING_QUERY);
			switch(status) { // this switch can be replaced with a simple previous_status.push(status), but it is here for readibility
				case PROCESSING_QUERY:
					previous_status.push(PROCESSING_QUERY);
					break;
				case PROCESSING_STMT_PREPARE:
					previous_status.push(PROCESSING_STMT_PREPARE);
					break;
				case PROCESSING_STMT_EXECUTE:
					previous_status.push(PROCESSING_STMT_EXECUTE);
					break;
				default:
					// LCOV_EXCL_START
					assert(0);
					break;
					// LCOV_EXCL_STOP
			}
			NEXT_IMMEDIATE_NEW(CHANGING_AUTOCOMMIT);
		}
	} else {
		if (autocommit == false) { // also IsAutoCommit==false
			if (mysql_thread___enforce_autocommit_on_reads == false) {
				if (mybe->server_myds->myconn->IsActiveTransaction() == false) {
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
			}
		}
	}
	return false;
}

bool Client_Session::handler_again___verify_backend_user_schema() {
	ProxySQL_Data_Stream *myds=mybe->server_myds;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , client: %s , backend: %s\n", this, client_myds->myconn->userinfo->username, mybe->server_myds->myconn->userinfo->username);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , client: %s , backend: %s\n", this, client_myds->myconn->userinfo->schemaname, mybe->server_myds->myconn->userinfo->schemaname);
	if (client_myds->myconn->userinfo->hash!=mybe->server_myds->myconn->userinfo->hash) {
		if (strcmp(client_myds->myconn->userinfo->username,myds->myconn->userinfo->username)) {
			//previous_status.push(PROCESSING_QUERY);
			switch(status) { // this switch can be replaced with a simple previous_status.push(status), but it is here for readibility
				case PROCESSING_QUERY:
					previous_status.push(PROCESSING_QUERY);
					break;
				case PROCESSING_STMT_PREPARE:
					previous_status.push(PROCESSING_STMT_PREPARE);
					break;
				case PROCESSING_STMT_EXECUTE:
					previous_status.push(PROCESSING_STMT_EXECUTE);
					break;
				default:
					// LCOV_EXCL_START
					assert(0);
					break;
					// LCOV_EXCL_STOP
			}
			mybe->server_myds->wait_until = thread->curtime + mysql_thread___connect_timeout_server*1000;   // max_timeout
			NEXT_IMMEDIATE_NEW(CHANGING_USER_SERVER);
		}
		if (strcmp(client_myds->myconn->userinfo->schemaname,myds->myconn->userinfo->schemaname)) {
			//previous_status.push(PROCESSING_QUERY);
			switch(status) { // this switch can be replaced with a simple previous_status.push(status), but it is here for readibility
				case PROCESSING_QUERY:
					previous_status.push(PROCESSING_QUERY);
					break;
				case PROCESSING_STMT_PREPARE:
					previous_status.push(PROCESSING_STMT_PREPARE);
					break;
				case PROCESSING_STMT_EXECUTE:
					previous_status.push(PROCESSING_STMT_EXECUTE);
					break;
				default:
					// LCOV_EXCL_START
					assert(0);
					break;
					// LCOV_EXCL_STOP
			}
			NEXT_IMMEDIATE_NEW(CHANGING_SCHEMA);
		}
	}
	// if we reach here, the username is the same
	if (myds->myconn->requires_CHANGE_USER(client_myds->myconn)) {
		// if we reach here, even if the username is the same,
		// the backend connection has some session variable set
		// that the client never asked for
		// because we can't unset variables, we will reset the connection
		switch(status) {
			case PROCESSING_QUERY:
			case PROCESSING_STMT_PREPARE:
			case PROCESSING_STMT_EXECUTE:
				previous_status.push(status);
				break;
			default:
				// LCOV_EXCL_START
				assert(0);
				break;
				// LCOV_EXCL_STOP
		}
		mybe->server_myds->wait_until = thread->curtime + mysql_thread___connect_timeout_server*1000;   // max_timeout
		NEXT_IMMEDIATE_NEW(CHANGING_USER_SERVER);
	}
	return false;
}

bool Client_Session::handler_again___status_SETTING_INIT_CONNECT(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	ProxySQL_Data_Stream *myds=mybe->server_myds;
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
				detected_broken_connection(__FILE__ , __LINE__ , __func__ , "while setting INIT CONNECT", myconn, myerr, mysql_error(myconn->mysql));
							//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
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

bool Client_Session::handler_again___status_SETTING_LDAP_USER_VARIABLE(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	ProxySQL_Data_Stream *myds=mybe->server_myds;
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

bool Client_Session::handler_again___status_SETTING_SQL_LOG_BIN(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	ProxySQL_Data_Stream *myds=mybe->server_myds;
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
				RequestEnd_mysql(myds);
			}
		} else {
			// rc==1 , nothing to do for now
		}
	}
	return ret;
}

bool Client_Session::handler_again___status_CHANGING_CHARSET(int *_rc) {
	assert(mybe->server_myds->myconn);
	ProxySQL_Data_Stream *myds=mybe->server_myds;
	MySQL_Connection *myconn=myds->myconn;

	// Validate that server can support client's charset
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
					proxy_error("Client trying to set a charset/collation (%u) not supported by backend (%s:%d). Changing it to %u\n", charset, myconn->parent->address, myconn->parent->port, mysql_tracked_variables[SQL_CHARACTER_SET].default_value);
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
				status=WAITING_CLIENT_DATA;
				client_myds->DSS=STATE_SLEEP;
				RequestEnd_mysql(myds);
			}
		} else {
			// rc==1 , nothing to do for now
		}
	}
	return false;
}

bool Client_Session::handler_again___status_SETTING_GENERIC_VARIABLE(int *_rc, const char *var_name, const char *var_value, bool no_quote, bool set_transaction) {
	bool ret = false;
	assert(mybe->server_myds->myconn);
	ProxySQL_Data_Stream *myds=mybe->server_myds;
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
			}
			else {
				sprintf(query,q,"tx_isolation", var_value);
			}
		}
		else {
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
					default:
						myds->destroy_MySQL_Connection_From_Pool(true);
						break;
				}
				myds->fd=0;
				RequestEnd_mysql(myds);
				ret=true;
			}
		} else {
			// rc==1 , nothing to do for now
		}
	}
	return ret;
}

bool Client_Session::handler_again___status_SETTING_MULTI_STMT(int *_rc) {
	assert(mybe->server_myds->myconn);
	ProxySQL_Data_Stream *myds=mybe->server_myds;
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
				RequestEnd_mysql(myds);
			}
		} else {
			// rc==1 , nothing to do for now
		}
	}
	return ret;
}

bool Client_Session::handler_again___status_SETTING_SESSION_TRACK_GTIDS(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	ret = handler_again___status_SETTING_GENERIC_VARIABLE(_rc, (char *)"SESSION_TRACK_GTIDS", mybe->server_myds->myconn->options.session_track_gtids, true);
	return ret;
}

bool Client_Session::handler_again___status_CHANGING_SCHEMA(int *_rc) {
	bool ret=false;
	//fprintf(stderr,"CHANGING_SCHEMA\n");
	assert(mybe->server_myds->myconn);
	ProxySQL_Data_Stream *myds=mybe->server_myds;
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
				RequestEnd_mysql(myds);
			}
		} else {
			// rc==1 , nothing to do for now
		}
	}
	return false;
}
*/

bool Client_Session::handler_again___status_CONNECTING_SERVER(int *_rc) { 
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
			char buf[256];
			sprintf(buf,"Max connect timeout reached while reaching hostgroup %d after %llums", current_hostgroup, (thread->curtime - CurrentQuery.start_time)/1000 );
			if (thread) {
				thread->status_variables.stvar[st_var_max_connect_timeout_err]++;
			}
			assert(session_type==PROXYSQL_SESSION_MYSQL);
			if (session_type==PROXYSQL_SESSION_MYSQL) {
				MySQL_Data_Stream * client_myds = ((MySQL_Session *)this)->client_myds;
				client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,9001,(char *)"HY000",buf, true);
				((MySQL_Session *)this)->RequestEnd_mysql(mybe->server_myds);
			}
			std::string errmsg;
			generate_status_one_hostgroup(current_hostgroup, errmsg);
			proxy_error("%s . HG status: %s\n", buf, errmsg.c_str());
			//enum session_status st;
			while (previous_status.size()) {
				previous_status.top();
				previous_status.pop();
			}
			if (mybe->server_myds->myconn) {
				// Created connection never reached 'connect_cont' phase, due to that
				// internal structures of 'mysql->net' are not fully initialized.
				// This induces a leak of the 'fd' associated with the socket
				// opened by the library. To prevent this, we need to call
				// `mysql_real_connect_cont` through `connect_cont`. This way
				// we ensure a proper cleanup of all the resources when 'mysql_close'
				// is later called. For more context see issue #3404.
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
		handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_mysql_connection();
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
					MySQL_Data_Stream * client_myds = NULL;
					assert(session_type==PROXYSQL_SESSION_MYSQL);
					if (session_type==PROXYSQL_SESSION_MYSQL) {
						client_myds = ((MySQL_Session *)this)->client_myds;
					}
					int myerr=mysql_errno(myconn->mysql);
					if (myerr) {
						char sqlstate[10];
						sprintf(sqlstate,"%s",mysql_sqlstate(myconn->mysql));
						client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql),true);
					} else {
						char buf[256];
						sprintf(buf,"Max connect failure while reaching hostgroup %d", current_hostgroup);
						client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,9002,(char *)"HY000",buf,true);
						if (thread) {
							thread->status_variables.stvar[st_var_max_connect_timeout_err]++;
						}
					}
					if (session_fast_forward==false) {
						// see bug #979
						((MySQL_Session *)this)->RequestEnd_mysql(myds);
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
bool Client_Session::handler_again___status_CHANGING_USER_SERVER(int *_rc) {
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
		assert(session_type==PROXYSQL_SESSION_MYSQL);
		MySQL_Data_Stream *client_myds = NULL;
		if (session_type==PROXYSQL_SESSION_MYSQL) {
			client_myds = ((MySQL_Session *)this)->client_myds;
			__sync_fetch_and_add(&MyHGM->status.backend_change_user, 1);
			myds->myconn->userinfo->set(client_myds->myconn->userinfo);
			myds->myconn->reset();
			myds->DSS = STATE_MARIADB_GENERIC;
		}
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
				MySQL_Data_Stream *client_myds = NULL;
				assert(session_type==PROXYSQL_SESSION_MYSQL);
				if (session_type==PROXYSQL_SESSION_MYSQL) {
					client_myds = ((MySQL_Session *)this)->client_myds;
					client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql));
					myds->destroy_MySQL_Connection_From_Pool(true);
					myds->fd=0;
					((MySQL_Session *)this)->RequestEnd_mysql(myds); //fix bug #682
				}
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


/*
// this function was inline inside Client_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP
// enum_mysql_command = _MYSQL_COM_STMT_PREPARE
//
// all break were replaced with a return
void Client_Session::handler_WCDSS_MYSQL_COM_STMT_PREPARE(PtrSize_t& pkt) {
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
		rc_break=handler_WCDSS_MYSQL_COM_QUERY_qpo(&pkt, &lock_hostgroup);
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
					RequestEnd_mysql(NULL);
					free(buf);
					l_free(pkt.size,pkt.ptr);
					return;
				}
			}
		}
		mybe=find_or_create_mysql_backend(current_hostgroup);
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
			client_myds->setDSS_STATE_QUERY_SENT_NET();
			client_myds->myprot.generate_STMT_PREPARE_RESPONSE(client_myds->pkt_sid+1,stmt_info,new_stmt_id);
			LogQuery(NULL);
			l_free(pkt.size,pkt.ptr);
			client_myds->DSS=STATE_SLEEP;
			status=WAITING_CLIENT_DATA;
			CurrentQuery.end_time=thread->curtime;
			CurrentQuery.end();
		} else {
			mybe=find_or_create_mysql_backend(current_hostgroup);
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

// this function was inline inside Client_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP
// enum_mysql_command = _MYSQL_COM_STMT_EXECUTE
//
// all break were replaced with a return
void Client_Session::handler_WCDSS_MYSQL_COM_STMT_EXECUTE(PtrSize_t& pkt) {
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
		stmt_global_id=client_myds->myconn->local_stmts->find_global_stmt_id_from_client(client_stmt_id);
		if (stmt_global_id == 0) {
			// FIXME: add error handling
			// LCOV_EXCL_START
			assert(0);
			// LCOV_EXCL_STOP
		}
		CurrentQuery.stmt_global_id=stmt_global_id;
		// now we get the statement information
		MySQL_STMT_Global_info *stmt_info=NULL;
		stmt_info=GloMyStmt->find_prepared_statement_by_stmt_id(stmt_global_id);
		if (stmt_info==NULL) {
			// we couldn't find it
			l_free(pkt.size,pkt.ptr);
			client_myds->setDSS_STATE_QUERY_SENT_NET();
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"28000",(char *)"Prepared statement doesn't exist", true);
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
		rc_break=handler_WCDSS_MYSQL_COM_QUERY_qpo(&pkt, &lock_hostgroup, true);
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
					RequestEnd_mysql(NULL);
					free(buf);
					l_free(pkt.size,pkt.ptr);
					return;
				}
			}
		}
		mybe=find_or_create_mysql_backend(current_hostgroup);
		status=PROCESSING_STMT_EXECUTE;
		mybe->server_myds->connect_retries_on_failure=mysql_thread___connect_retries_on_failure;
		mybe->server_myds->wait_until=0;
		mybe->server_myds->killed_at=0;
		mybe->server_myds->kill_type=0;
		client_myds->setDSS_STATE_QUERY_SENT_NET();
	}
}
*/

// this function was inline inside Client_Session::get_pkts_from_client
// ClickHouse doesn't support COM_INIT_DB , so we replace it
// with a COM_QUERY running USE
void Client_Session::handler_WCDSS_MYSQL_COM_INIT_DB_replace_CLICKHOUSE(PtrSize_t& pkt) {
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

// this function was inline inside Client_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP
// enum_mysql_command = _MYSQL_COM_QUERY
// it processes the session not MYSQL_SESSION
void Client_Session::handler_WCDSS_MYSQL_COM_QUERY___not_mysql(PtrSize_t& pkt) {
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




// this function was inline inside Client_Session::get_pkts_from_client
// where:
// status = NONE or default
//
// this is triggered when proxysql receives a packet when doesn't expect any
// for example while it is supposed to be sending resultset to client
void Client_Session::handler___status_NONE_or_default(PtrSize_t& pkt) {
	if (session_type==PROXYSQL_SESSION_MYSQL) {
		((MySQL_Session *)this)->handler___status_NONE_or_default(pkt);
		return;
	}
/*
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
*/
}

int Client_Session::get_pkts_from_client(bool& wrong_pass, PtrSize_t& pkt) {
	int handler_ret = 0;
	unsigned char c;
	MySQL_Data_Stream *client_myds = NULL;
	assert(session_type==PROXYSQL_SESSION_MYSQL || session_type==PROXYSQL_SESSION_ADMIN || session_type==PROXYSQL_SESSION_STATS || session_type==PROXYSQL_SESSION_SQLITE || session_type==PROXYSQL_SESSION_CLICKHOUSE);
	if (session_type==PROXYSQL_SESSION_MYSQL || session_type==PROXYSQL_SESSION_ADMIN || session_type==PROXYSQL_SESSION_STATS || session_type==PROXYSQL_SESSION_SQLITE || session_type==PROXYSQL_SESSION_CLICKHOUSE) {
		client_myds = ((MySQL_Session *)this)->client_myds;
	}

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

			case CONNECTING_CLIENT:
				switch (client_myds->DSS) {
					case STATE_SERVER_HANDSHAKE:
						((MySQL_Session *)this)->handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(&pkt, &wrong_pass);
						break;
					case STATE_SSL_INIT:
						((MySQL_Session *)this)->handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(&pkt, &wrong_pass);
						break;
					default:
						proxy_error("Detected not valid state client state: %d\n", client_myds->DSS);
						handler_ret = -1; //close connection
						return handler_ret;
						break;
				}
				break;

			case WAITING_CLIENT_DATA:
				// this is handled only for real traffic, not mirror
				if (pkt.size==(0xFFFFFF+sizeof(mysql_hdr))) {
					// we are handling a multi-packet
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
				switch (client_myds->DSS) {
					case STATE_SLEEP_MULTI_PACKET:
						assert(session_type==PROXYSQL_SESSION_MYSQL);
						if (session_type==PROXYSQL_SESSION_MYSQL) {
							if (((MySQL_Session *)this)->handler_WCDSS_MULTI_PACKET(pkt)) {
								// if handler_WCDSS_MULTI_PACKET
								// returns true it meansa we need to reiterate
								goto __get_pkts_from_client;
							}
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
							mybe=find_or_create_mysql_backend(current_hostgroup); // set a backend
							mybe->server_myds->reinit_queues();             // reinitialize the queues in the myds . By default, they are not active
							mybe->server_myds->PSarrayOUT->add(pkt.ptr, pkt.size); // move the first packet
							previous_status.push(FAST_FORWARD); // next status will be FAST_FORWARD . Now we need a connection
							{
								//NEXT_IMMEDIATE(CONNECTING_SERVER);  // we create a connection . next status will be FAST_FORWARD
								// we can't use NEXT_IMMEDIATE() inside get_pkts_from_client()
								// instead we set status to CONNECTING_SERVER and return 0
								// when we exit from get_pkts_from_client() we expect the label "handler_again"
								set_status(CONNECTING_SERVER);
								return 0;
							}
						}
						c=*((unsigned char *)pkt.ptr+sizeof(mysql_hdr));
						if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
							if ((enum_mysql_command)c == _MYSQL_COM_INIT_DB) {
								handler_WCDSS_MYSQL_COM_INIT_DB_replace_CLICKHOUSE(pkt);
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
									rc_break=((MySQL_Session *)this)->handler_special_queries(&pkt);
									if (rc_break==true) {
										if (mirror==false) {
											// track also special queries
											//RequestEnd_mysql(NULL);
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
									// This block was moved from 'handler_special_queries' to support
									// handling of 'USE' statements which are preceded by a comment.
									// For more context check issue: #3493.
									// ===================================================
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
											((MySQL_Session *)this)->handler_WCDSS_MYSQL_COM_QUERY_USE_DB(&pkt);

											if (mirror == false) {
												break;
											} else {
												handler_ret = -1;
												return handler_ret;
											}
										}
									}
									// ===================================================
									if (qpo->max_lag_ms >= 0) {
										thread->status_variables.stvar[st_var_queries_with_max_lag_ms]++;
									}
									if (thread->variables.stats_time_query_processor) {
										clock_gettime(CLOCK_THREAD_CPUTIME_ID,&endt);
										thread->status_variables.stvar[st_var_query_processor_time]=thread->status_variables.stvar[st_var_query_processor_time] +
											(endt.tv_sec*1000000000+endt.tv_nsec) -
											(begint.tv_sec*1000000000+begint.tv_nsec);
									}
									assert(qpo);	// GloQPro->process_mysql_query() should always return a qpo
									rc_break=((MySQL_Session *)this)->handler_WCDSS_MYSQL_COM_QUERY_qpo(&pkt, &lock_hostgroup);
									if (session_type==PROXYSQL_SESSION_MYSQL) {
										if (mirror==false && rc_break==false) {
											if (mysql_thread___automatic_detect_sqli) {
												if (((MySQL_Session *)this)->handler_WCDSS_MYSQL_COM_QUERY_detect_SQLi()) {
													handler_ret = -1;
													return handler_ret;
												}
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
										((MySQL_Session *)this)->handler_WCDSS_MYSQL_COM_QUERY___create_mirror_session();
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
												((MySQL_Session *)this)->RequestEnd_mysql(NULL);
												free(buf);
												l_free(pkt.size,pkt.ptr);
												break;
											}
										}
									}
									mybe=find_or_create_mysql_backend(current_hostgroup);
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
												((MySQL_Session *)this)->add_ldap_comment_to_pkt(&pkt);
											}
										}
									}
									mybe->server_myds->mysql_real_query.init(&pkt);
									mybe->server_myds->statuses.questions++;
									client_myds->setDSS_STATE_QUERY_SENT_NET();
								} else {
									handler_WCDSS_MYSQL_COM_QUERY___not_mysql(pkt);
								}
								break;
							case _MYSQL_COM_STMT_PREPARE:
								((MySQL_Session *)this)->handler_WCDSS_MYSQL_COM_STMT_PREPARE(pkt);
								break;
							case _MYSQL_COM_STMT_EXECUTE:
								((MySQL_Session *)this)->handler_WCDSS_MYSQL_COM_STMT_EXECUTE(pkt);
								break;
							case _MYSQL_COM_STMT_RESET:
								((MySQL_Session *)this)->handler_WCDSS_MYSQL_COM_STMT_RESET(pkt);
								break;
							case _MYSQL_COM_STMT_CLOSE:
								((MySQL_Session *)this)->handler_WCDSS_MYSQL_COM_STMT_CLOSE(pkt);
								break;
							case _MYSQL_COM_STMT_SEND_LONG_DATA:
								((MySQL_Session *)this)->handler_WCDSS_MYSQL_COM_STMT_SEND_LONG_DATA(pkt);
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
								// handler_WCDSS_MYSQL_COM__various
								if (session_type==PROXYSQL_SESSION_MYSQL || session_type==PROXYSQL_SESSION_ADMIN || session_type==PROXYSQL_SESSION_STATS || session_type==PROXYSQL_SESSION_SQLITE || session_type==PROXYSQL_SESSION_CLICKHOUSE) {
									if (((MySQL_Session *)this)->handler_WCDSS_MYSQL_COM__various(&pkt, &wrong_pass)==false) {
										// If even this cannot find the command, we return an error to the client
										proxy_error("RECEIVED AN UNKNOWN COMMAND: %d -- PLEASE REPORT A BUG\n", c);
										l_free(pkt.size,pkt.ptr);
										handler_ret = -1; // immediately drop the connection
										return handler_ret;
									}
								}
								break;
						}
						break;
					default:
						if (session_type==PROXYSQL_SESSION_MYSQL) {
							((MySQL_Session *)this)->handler___status_WAITING_CLIENT_DATA___default();
						}
						handler_ret = -1;
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
	}
	return handler_ret;
}
// end of Client_Session::get_pkts_from_client()


// this function returns:
// 0 : no action
// -1 : the calling function will return
// 1 : call to NEXT_IMMEDIATE
int Client_Session::handler_ProcessingQueryError_CheckBackendConnectionStatus(ProxySQL_Data_Stream *pds) {
	assert(pds->sess->session_type==PROXYSQL_SESSION_MYSQL);
	MySQL_Data_Stream *myds = (MySQL_Data_Stream *)pds;
	MySQL_Connection *myconn = myds->myconn;
	// the query failed
	if (
		// due to #774 , we now read myconn->server_status instead of myconn->parent->status
		(myconn->server_status==MYSQL_SERVER_STATUS_OFFLINE_HARD) // the query failed because the server is offline hard
		||
		(myconn->server_status==MYSQL_SERVER_STATUS_SHUNNED && myconn->parent->shunned_automatic==true && myconn->parent->shunned_and_kill_all_connections==true) // the query failed because the server is shunned due to a serious failure
		||
		(myconn->server_status==MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) // slave is lagging! see #774
	) {
		if (mysql_thread___connect_timeout_server_max) {
			myds->max_connect_time=thread->curtime+mysql_thread___connect_timeout_server_max*1000;
		}
		bool retry_conn=false;
		if (myconn->server_status==MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) {
			thread->status_variables.stvar[st_var_backend_lagging_during_query]++;
			proxy_error("Detected a lagging server during query: %s, %d\n", myconn->parent->address, myconn->parent->port);
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, ER_PROXYSQL_LAGGING_SRV);
		} else {
			thread->status_variables.stvar[st_var_backend_offline_during_query]++;
			proxy_error("Detected an offline server during query: %s, %d\n", myconn->parent->address, myconn->parent->port);
			MyHGM->p_update_mysql_error_counter(p_mysql_error_type::proxysql, myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, ER_PROXYSQL_OFFLINE_SRV);
		}
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
		myds->destroy_MySQL_Connection_From_Pool(false);
		myds->fd=0;
		if (retry_conn) {
			myds->DSS=STATE_NOT_INITIALIZED;
			//previous_status.push(PROCESSING_QUERY);
			switch(status) { // this switch can be replaced with a simple previous_status.push(status), but it is here for readibility
				case PROCESSING_QUERY:
					previous_status.push(PROCESSING_QUERY);
					break;
				case PROCESSING_STMT_PREPARE:
					previous_status.push(PROCESSING_STMT_PREPARE);
					break;
				case PROCESSING_STMT_EXECUTE:
					previous_status.push(PROCESSING_STMT_EXECUTE);
					break;
				default:
					// LCOV_EXCL_START
					assert(0);
					break;
					// LCOV_EXCL_STOP
			}
			return 1;
		}
		return -1;
	}
	return 0;
}

void Client_Session::SetQueryTimeout() {
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

/*
// this function used to be inline.
// now it returns:
// true: NEXT_IMMEDIATE(st) needs to be called
// false: continue
bool Client_Session::handler_rc0_PROCESSING_STMT_PREPARE(enum session_status& st, ProxySQL_Data_Stream *myds, bool& prepared_stmt_with_no_params) {
	thread->status_variables.stvar[st_var_backend_stmt_prepare]++;
	GloMyStmt->wrlock();
	uint32_t client_stmtid;
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
		}
	}
	global_stmtid=stmt_info->statement_id;
	myds->myconn->local_stmts->backend_insert(global_stmtid,CurrentQuery.mysql_stmt);
	if (previous_status.size() == 0)
	client_stmtid=client_myds->myconn->local_stmts->generate_new_client_stmt_id(global_stmtid);
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
void Client_Session::handler_rc0_PROCESSING_STMT_EXECUTE(ProxySQL_Data_Stream *myds) {
	thread->status_variables.stvar[st_var_backend_stmt_execute]++;
	PROXY_TRACE2();
	if (CurrentQuery.mysql_stmt) {
		// See issue #1574. Metadata needs to be updated in case of need also
		// during STMT_EXECUTE, so a failure in the prepared statement
		// metadata cache is only hit once. This way we ensure that the next
		// 'PREPARE' will be answered with the properly updated metadata.
		// ********************************************************************
		// Lock the global statement manager
		GloMyStmt->wrlock();
		// Update the global prepared statement metadata
		MySQL_STMT_Global_info *stmt_info = GloMyStmt->find_prepared_statement_by_stmt_id(CurrentQuery.stmt_global_id, false);
		stmt_info->update_metadata(CurrentQuery.mysql_stmt);
		// Unlock the global statement manager
		GloMyStmt->unlock();
		// ********************************************************************
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
*/


// this function was inline
int Client_Session::RunQuery_mysql(ProxySQL_Data_Stream *pds, MySQL_Connection *myconn) {
	PROXY_TRACE2();
	int rc = 0;
	assert(session_type==PROXYSQL_SESSION_MYSQL);
	MySQL_Data_Stream *myds = (MySQL_Data_Stream *)pds;
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

void Client_Session::writeout() {
	switch (session_type) {
		case PROXYSQL_SESSION_MYSQL:
		case PROXYSQL_SESSION_ADMIN:
		case PROXYSQL_SESSION_STATS:
		case PROXYSQL_SESSION_SQLITE:
		case PROXYSQL_SESSION_CLICKHOUSE:
			((MySQL_Session *)this)->writeout();
			break;
		default:
			break;
	}
}

// this function was inline
void Client_Session::handler___status_WAITING_CLIENT_DATA() {
	if (session_type==PROXYSQL_SESSION_MYSQL) {
		((MySQL_Session *)this)->handler___status_WAITING_CLIENT_DATA();
	}
}

// this function was inline
void Client_Session::handler_rc0_Process_GTID(MySQL_Connection *myconn) {
	if (myconn->get_gtid(mybe->gtid_uuid,&mybe->gtid_trxid)) {
		if (mysql_thread___client_session_track_gtid) {
			gtid_hid = current_hostgroup;
			memcpy(gtid_buf,mybe->gtid_uuid,sizeof(gtid_buf));
		}
	}
}

int Client_Session::handler() {
	int handler_ret = 0;
	bool prepared_stmt_with_no_params = false;
	bool wrong_pass=false;
	if (to_process==0) return 0; // this should be redundant if the called does the same check
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Processing session %p\n" , this->thread, this, this);
	PtrSize_t pkt;
	pktH=&pkt;
	//unsigned int j;
	//unsigned char c;

	if (active_transactions == 0) {
		active_transactions=NumActiveTransactions();
		if (active_transactions > 0) {
			transaction_started_at = thread->curtime;
		}
	}
//	FIXME: Sessions without frontend are an ugly hack
	if (session_fast_forward==false) {
	MySQL_Data_Stream * client_myds = NULL;
	assert(session_type==PROXYSQL_SESSION_MYSQL || session_type==PROXYSQL_SESSION_ADMIN || session_type==PROXYSQL_SESSION_STATS || session_type==PROXYSQL_SESSION_SQLITE || session_type==PROXYSQL_SESSION_CLICKHOUSE);
	client_myds = ((MySQL_Session *)this)->client_myds;
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

	handler_ret = get_pkts_from_client(wrong_pass, pkt);
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
			if (session_type==PROXYSQL_SESSION_MYSQL) {
				MySQL_Data_Stream *client_myds = ((MySQL_Session *)this)->client_myds;
				client_myds->PSarrayOUT->copy_add(mybe->server_myds->PSarrayIN, 0, mybe->server_myds->PSarrayIN->len);
			}
			while (mybe->server_myds->PSarrayIN->len) mybe->server_myds->PSarrayIN->remove_index(mybe->server_myds->PSarrayIN->len-1,NULL);
			break;
		case CONNECTING_CLIENT:
			//fprintf(stderr,"CONNECTING_CLIENT\n");
			// FIXME: to implement
			break;
		case PINGING_SERVER:
			assert(session_type==PROXYSQL_SESSION_MYSQL);
			{
				int rc = ((MySQL_Session *)this)->handler_again___status_PINGING_SERVER();
				if (rc==-1) { // if the ping fails, we destroy the session
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case RESETTING_CONNECTION:
			assert(session_type==PROXYSQL_SESSION_MYSQL);
			{
				int rc = ((MySQL_Session *)this)->handler_again___status_RESETTING_CONNECTION();
				if (rc==-1) { // we always destroy the session
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case PROCESSING_STMT_PREPARE:
		case PROCESSING_STMT_EXECUTE:
		case PROCESSING_QUERY:
			assert(session_type==PROXYSQL_SESSION_MYSQL);
			//fprintf(stderr,"PROCESSING_QUERY\n");
			if (pause_until > thread->curtime) {
				handler_ret = 0;
				return handler_ret;
			}
			if (mysql_thread___connect_timeout_server_max) {
				if (mybe->server_myds->max_connect_time==0)
					mybe->server_myds->max_connect_time=thread->curtime+(long long)mysql_thread___connect_timeout_server_max*1000;
			} else {
				mybe->server_myds->max_connect_time=0;
			}
			if (
				(mybe->server_myds->myconn && mybe->server_myds->myconn->async_state_machine!=ASYNC_IDLE && mybe->server_myds->wait_until && thread->curtime >= mybe->server_myds->wait_until)
				// query timed out
				||
				(killed==true) // session was killed by admin
			) {
				((MySQL_Session *)this)->LogKillQueryTimeout(mybe->server_myds, __FILE__, __LINE__);
				handler_again___new_thread_to_kill_connection();
			}
			if (mybe->server_myds->DSS==STATE_NOT_INITIALIZED) {
				// we don't have a backend yet
				switch(status) { // this switch can be replaced with a simple previous_status.push(status), but it is here for readibility
					case PROCESSING_QUERY:
						previous_status.push(PROCESSING_QUERY);
						break;
					case PROCESSING_STMT_PREPARE:
						previous_status.push(PROCESSING_STMT_PREPARE);
						break;
					case PROCESSING_STMT_EXECUTE:
						previous_status.push(PROCESSING_STMT_EXECUTE);
						break;
					default:
						// LCOV_EXCL_START
						assert(0);
						break;
						// LCOV_EXCL_STOP
				}
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
					if (session_type==PROXYSQL_SESSION_MYSQL) {
						if (((MySQL_Session *)this)->handler_again___verify_backend_user_schema()) {
							goto handler_again;
						}
					}
					if (mirror==false) { // do not care about autocommit and charset if mirror
							proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , default_HG=%d server_myds DSS=%d , locked_on_HG=%d\n", this, default_hostgroup, mybe->server_myds->DSS, locked_on_hostgroup);
						if (mybe->server_myds->DSS == STATE_READY || mybe->server_myds->DSS == STATE_MARIADB_GENERIC) {
							if (((MySQL_Session *)this)->ProcessingRequest_MatchEnvironment(myconn)) {
								goto handler_again;
							}
						}
						if (status==PROCESSING_STMT_EXECUTE) {
							CurrentQuery.mysql_stmt=myconn->local_stmts->find_backend_stmt_by_global_id(CurrentQuery.stmt_global_id);
							if (CurrentQuery.mysql_stmt==NULL) {
								MySQL_STMT_Global_info *stmt_info=NULL;
								// the connection we too doesn't have the prepared statements prepared
								// we try to create it now
								stmt_info=GloMyStmt->find_prepared_statement_by_stmt_id(CurrentQuery.stmt_global_id);
								CurrentQuery.QueryLength=stmt_info->query_length;
								CurrentQuery.QueryPointer=(unsigned char *)stmt_info->query;
								// NOTE: Update 'first_comment' with the the from the retrieved
								// 'stmt_info' from the found prepared statement. 'CurrentQuery' requires its
								// own copy of 'first_comment' because it will later be free by 'QueryInfo::end'.
								if (stmt_info->first_comment) {
									CurrentQuery.QueryParserArgs.first_comment=strdup(stmt_info->first_comment);
								}
								previous_status.push(PROCESSING_STMT_EXECUTE);
								NEXT_IMMEDIATE(PROCESSING_STMT_PREPARE);
								if (CurrentQuery.stmt_global_id!=stmt_info->statement_id) {
									PROXY_TRACE();
								}
							}
						}
					}
				}

				if (myconn->async_state_machine==ASYNC_IDLE) {
					SetQueryTimeout();
				}
				int rc;
				timespec begint;
				if (thread->variables.stats_time_backend_query) {
					clock_gettime(CLOCK_THREAD_CPUTIME_ID,&begint);
				}
				rc = RunQuery_mysql(myds, myconn);
				timespec endt;
				if (thread->variables.stats_time_backend_query) {
					clock_gettime(CLOCK_THREAD_CPUTIME_ID,&endt);
					thread->status_variables.stvar[st_var_backend_query_time] = thread->status_variables.stvar[st_var_backend_query_time] +
						(endt.tv_sec*1000000000+endt.tv_nsec) -
						(begint.tv_sec*1000000000+begint.tv_nsec);
				}
				gtid_hid = -1;
				if (rc==0) {
					if (((MySQL_Session *)this)->RunQuery_Success(myconn, prepared_stmt_with_no_params)) {
						goto handler_again;
					}
				} else {
					if (rc==-1) {
						// the query failed
						if (((MySQL_Session *)this)->RunQuery_Failed(myconn, wrong_pass, handler_ret)) {
							goto handler_again;
						} else {
							if (handler_ret == -1) {
								return handler_ret;
							}
						}
					} else {
						if (((MySQL_Session *)this)->RunQuery_Continue(myconn, rc)) {
							goto handler_again;
						}
					}
				}

				goto __exit_DSS__STATE_NOT_INITIALIZED;


			}
			break;

		case SETTING_ISOLATION_LEVEL:
		case SETTING_TRANSACTION_READ:
		case SETTING_CHARSET:
		case SETTING_VARIABLE:
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
			// Performs a 'SHOW WARNINGS' query over the current backend connection and returns the connection back
			// to the connection pool when finished. Actual logging of received warnings is performed in
			// 'MySQL_Connection' while processing 'ASYNC_USE_RESULT_CONT'.
			{
				assert(session_type==PROXYSQL_SESSION_MYSQL);
				MySQL_Data_Stream *myds=mybe->server_myds;
				MySQL_Connection *myconn=myds->myconn;

				// Setting POLLOUT is required just in case this state has been reached when 'RunQuery_mysql' from
				// 'PROCESSING_QUERY' state has immediately return. This is because in case 'mysql_real_query_start'
				// immediately returns with '0' the session is never processed again by 'ProxyWorker_Thread', and 'revents' is
				// never updated with the result of polling through the 'ProxyWorker_Thread::mypolls'.
				myds->revents |= POLLOUT;

				int rc = myconn->async_query(
					mybe->server_myds->revents,(char *)"SHOW WARNINGS", strlen((char *)"SHOW WARNINGS")
				);
				if (rc == 0 || rc == -1) {
					// Cleanup the connection resulset from 'SHOW WARNINGS' for the next query.
					if (myconn->MyRS != NULL) {
						delete myconn->MyRS;
						myconn->MyRS = NULL;
					}

					if (rc == -1) {
						int myerr = mysql_errno(myconn->mysql);
						proxy_error(
							"'SHOW WARNINGS' failed to be executed over backend connection with error: '%d'\n", myerr
						);
					}

					((MySQL_Session *)this)->RequestEnd_mysql(myds);
					finishQuery(myds,myconn,prepared_stmt_with_no_params);

					handler_ret = 0;
					return handler_ret;
				} else {
					goto handler_again;
				}
			}
			break;

		case CONNECTING_SERVER:
			{
				int rc=0;
				if (handler_again___status_CONNECTING_SERVER(&rc))
					goto handler_again;	// we changed status
				if (rc==1) //handler_again___status_CONNECTING_SERVER returns 1
					goto __exit_DSS__STATE_NOT_INITIALIZED;
			}
			break;
		case session_status___NONE:
			fprintf(stderr,"NONE\n");
		default:
			{
				int rc = 0;
				if (session_type==PROXYSQL_SESSION_MYSQL) {
					if (((MySQL_Session *)this)->handler_again___multiple_statuses(&rc)) // a sort of catch all
						goto handler_again;	// we changed status
					if (rc==-1) { // we have an error we can't handle
						handler_ret = -1;
						return handler_ret;
					}
				} else {
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;
	}


__exit_DSS__STATE_NOT_INITIALIZED:
		

	if (mybe && mybe->server_myds) {
	if (mybe->server_myds->DSS > STATE_MARIADB_BEGIN && mybe->server_myds->DSS < STATE_MARIADB_END) {
#ifdef DEBUG
		ProxySQL_Data_Stream *myds=mybe->server_myds;
		MySQL_Connection *myconn=mybe->server_myds->myconn;
#endif /* DEBUG */
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, status=%d, server_myds->DSS==%d , revents==%d , async_state_machine=%d\n", this, status, mybe->server_myds->DSS, myds->revents, myconn->async_state_machine);
	}
	}

	writeout();

	if (wrong_pass==true) {
		MySQL_Data_Stream * client_myds = ((MySQL_Session *)this)->client_myds;
		client_myds->array2buffer_full();
		client_myds->write_to_net();
		handler_ret = -1;
		return handler_ret;
	}
	handler_ret = 0;
	return handler_ret;
}
// end ::handler()



/*
// Note: as commented in issue #546 and #547 , some clients ignore the status of CLIENT_MULTI_STATEMENTS
// therefore tracking it is not needed, unless in future this should become a security enhancement,
// returning errors to all clients trying to send multi-statements .
// see also #1140
void Client_Session::handler_WCDSS_MYSQL_COM_SET_OPTION(PtrSize_t *pkt) {
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

void Client_Session::handler_WCDSS_MYSQL_COM_PING(PtrSize_t *pkt) {
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

void Client_Session::handler_WCDSS_MYSQL_COM_FIELD_LIST(PtrSize_t *pkt) {
	if (session_type == PROXYSQL_SESSION_MYSQL) {
		// FIXME: temporary
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

void Client_Session::handler_WCDSS_MYSQL_COM_PROCESS_KILL(PtrSize_t *pkt) {
	l_free(pkt->size,pkt->ptr);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,9003,(char *)"28000",(char *)"Command not supported");
	client_myds->DSS=STATE_SLEEP;
}
*/


/*
// this function as inline in handler_WCDSS_MYSQL_COM_QUERY_qpo
// returned values:
// 0 : no action
// 1 : return false
// 2 : return true
int Client_Session::handler_WCD_SS_MCQ_qpo_Parse_SQL_LOG_BIN(PtrSize_t *pkt, bool *lock_hostgroup, unsigned int nTrx, string& nq) {
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
			RequestEnd_mysql(NULL);
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
			RequestEnd_mysql(NULL);
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

/*
void Client_Session::handler_WCDSS_MYSQL_COM_CHANGE_USER(PtrSize_t *pkt, bool *wrong_pass) {
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
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,0,0,NULL);
			client_myds->DSS=STATE_SLEEP;
			status=WAITING_CLIENT_DATA;
			*wrong_pass=false;
			client_authenticated=true;
			//int free_users=0;
			int used_users=0;
			// free_users
			GloMyAuth->increase_frontend_user_connections(client_myds->myconn->userinfo->username, &used_users);
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
*/
/*
void Client_Session::handler_WCDSS_MYSQL_COM_RESET_CONNECTION(PtrSize_t *pkt) {
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
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,0,0,NULL);
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
*/
void Client_Session::handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_mysql_connection() {
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
				_gtid_from_backend = find_mysql_backend(qpo->gtid_from_hostgroup);
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
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Session=%p , DS=%p , poll_timeout=%llu\n", mybe->server_myds, thread->mypolls.poll_timeout);
		} else {
			if (thread->mypolls.poll_timeout > (unsigned int)mysql_thread___poll_timeout_on_failure * 1000) {
				thread->mypolls.poll_timeout = mysql_thread___poll_timeout_on_failure * 1000;
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Session=%p , DS=%p , poll_timeout=%llu\n", mybe->server_myds, thread->mypolls.poll_timeout);
			}
		}
		return;
	}
	if (mybe->server_myds->myconn->fd==-1) {
		// we didn't get a valid connection, we need to create one
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p -- MySQL Connection has no FD\n", this);
		MySQL_Connection *myconn=mybe->server_myds->myconn;
		MySQL_Data_Stream *client_myds = NULL;
		if (this->session_type==PROXYSQL_SESSION_MYSQL) {
			client_myds = ((MySQL_Session *)this)->client_myds;
		}
		assert(client_myds != NULL);
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


void Client_Session::SQLite3_to_MySQL(SQLite3_result *result, char *error, int affected_rows, MySQL_Protocol *myprot, bool in_transaction, bool deprecate_eof_active) {
	assert(myprot);
	ProxySQL_Data_Stream *myds=myprot->get_myds();
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
		if (in_transaction == false) {
			nTrx=NumActiveTransactions();
			setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
			if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		} else {
			// this is for SQLite3 Server
			setStatus = SERVER_STATUS_AUTOCOMMIT;
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
			// I think the 2 | setStatus here is a bug. the previous generate_pkt_EOF was changed from 2|setStatus to just
			// setStatus a long time ago in c3e6fda7a47ecb94e97d4e191cdbd0f10fec7924
			// also 2 represents the SERVER_STATUS_IN_TRANS which is already set in setStatus
			myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, 2 | setStatus ); sid++;
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
				setStatus = SERVER_STATUS_AUTOCOMMIT;
				setStatus |= SERVER_STATUS_IN_TRANS;
			}
			myprot->generate_pkt_OK(true,NULL,NULL,sid,affected_rows,0,setStatus,0,NULL);
		}
		myds->DSS=STATE_SLEEP;
	}
}

void Client_Session::set_unhealthy() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess:%p\n", this);
	healthy=0;
}


unsigned int Client_Session::NumActiveTransactions() {
	unsigned int ret=0;
	if (mybes==0) return ret;
	MySQL_Backend *_mybe;
	unsigned int i;
	for (i=0; i < mybes->len; i++) {
		_mybe=(MySQL_Backend *)mybes->index(i);
		if (_mybe->server_myds)
			if (_mybe->server_myds->myconn)
				if (_mybe->server_myds->myconn->IsActiveTransaction())
					ret++;
	}
	return ret;
}

bool Client_Session::HasOfflineBackends() {
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

bool Client_Session::SetEventInOfflineBackends() {
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

int Client_Session::FindOneActiveTransaction() {
	int ret=-1;
	if (mybes==0) return ret;
	MySQL_Backend *_mybe;
	unsigned int i;
	for (i=0; i < mybes->len; i++) {
		_mybe=(MySQL_Backend *)mybes->index(i);
		if (_mybe->server_myds)
			if (_mybe->server_myds->myconn)
				if (_mybe->server_myds->myconn->IsActiveTransaction())
					return (int)_mybe->server_myds->myconn->parent->myhgc->hid;
	}
	return ret;
}

unsigned long long Client_Session::IdleTime() {
	unsigned long long ret = 0;
	MySQL_Data_Stream *client_myds = NULL;
	if (this->session_type==PROXYSQL_SESSION_MYSQL) {
		client_myds = ((MySQL_Session *)this)->client_myds;
	}
	if (client_myds==NULL) return 0;
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



// this is called either from RequestEnd_mysql(), or at the end of executing
// prepared statements 
void Client_Session::LogQuery(ProxySQL_Data_Stream *myds) {
	// we need to access statistics before calling CurrentQuery.end()
	// so we track the time here
	CurrentQuery.end_time=thread->curtime;

	if (qpo) {
		if (qpo->log==1) {
			GloMyLogger->log_request(this, myds);	// we send for logging only if logging is enabled for this query
		} else {
			if (qpo->log==-1) {
				if (mysql_thread___eventslog_default_log==1) {
					GloMyLogger->log_request(this, myds);	// we send for logging only if enabled by default
				}
			}
		}
	}
}

// this function tries to report all the memory statistics related to the sessions
void Client_Session::Memory_Stats() {
	if (thread==NULL)
		return;
	unsigned int i;
	unsigned long long backend=0;
	unsigned long long frontend=0;
	unsigned long long internal=0;
	if (qpo)
		internal+=sizeof(Query_Processor_Output);
	MySQL_Data_Stream *client_myds = NULL;
	if (this->session_type==PROXYSQL_SESSION_MYSQL) {
		client_myds = ((MySQL_Session *)this)->client_myds;
		internal+=sizeof(MySQL_Session);
	} else {
		internal+=sizeof(Client_Session);
	}
	if (client_myds) {
		internal+=sizeof(ProxySQL_Data_Stream);
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
	if (this->session_type==PROXYSQL_SESSION_MYSQL) {
	for (i=0; i < mybes->len; i++) {
		MySQL_Backend *_mybe=(MySQL_Backend *)mybes->index(i);
			internal+=sizeof(MySQL_Backend);
		if (_mybe->server_myds) {
			internal+=sizeof(ProxySQL_Data_Stream);
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
	}
	thread->status_variables.stvar[st_var_mysql_backend_buffers_bytes] += backend;
	thread->status_variables.stvar[st_var_mysql_frontend_buffers_bytes]+= frontend;
	thread->status_variables.stvar[st_var_mysql_session_internal_bytes] += internal;
}


/*
void Client_Session::create_new_session_and_reset_mysql_connection(ProxySQL_Data_Stream *_myds) {
	ProxySQL_Data_Stream *new_myds = NULL;
	MySQL_Connection * mc = _myds->myconn;
	// we remove the connection from the original data stream
	_myds->detach_connection();
	_myds->unplug_backend();

	// we create a brand new session, a new data stream, and attach the connection to it
	Client_Session * new_sess = new Client_Session();
	new_sess->mybe = new_sess->find_or_create_mysql_backend(mc->parent->myhgc->hid);

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
*/

bool Client_Session::handle_command_query_kill(PtrSize_t *pkt) {
	assert(this->session_type==PROXYSQL_SESSION_MYSQL);
	MySQL_Data_Stream *client_myds = ((MySQL_Session *)this)->client_myds;
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
								GloPWTH->kill_connection_or_query( id, (tki == 0 ? false : true ),  mc->userinfo->username);
								client_myds->DSS=STATE_QUERY_SENT_NET;
								unsigned int nTrx=NumActiveTransactions();
								uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
								if (autocommit) setStatus = SERVER_STATUS_AUTOCOMMIT;
								client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
								client_myds->DSS=STATE_SLEEP;
								status=WAITING_CLIENT_DATA;
								((MySQL_Session *)this)->RequestEnd_mysql(NULL);
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

void Client_Session::finishQuery(ProxySQL_Data_Stream *pds, MySQL_Connection *myconn, bool prepared_stmt_with_no_params) {
	assert(this->session_type==PROXYSQL_SESSION_MYSQL);
	MySQL_Data_Stream * myds = (MySQL_Data_Stream *) pds;
					myds->myconn->reduce_auto_increment_delay_token();
					if (locked_on_hostgroup >= 0) {
						if (qpo->multiplex == -1) {
							myds->myconn->set_status(true, STATUS_MYSQL_CONNECTION_NO_MULTIPLEX);
						}
					}
					if (mysql_thread___multiplexing && (myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
						if (mysql_thread___connection_delay_multiplex_ms && mirror==false) {
							myds->wait_until=thread->curtime+mysql_thread___connection_delay_multiplex_ms*1000;
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
									((MySQL_Session *)this)->create_new_session_and_reset_mysql_connection(myds);
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


bool Client_Session::known_query_for_locked_on_hostgroup(uint64_t digest) {
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



void Client_Session::unable_to_parse_set_statement(bool *lock_hostgroup) {
	// we couldn't parse the query
	MySQL_Data_Stream *client_myds = NULL;
	if (this->session_type==PROXYSQL_SESSION_MYSQL) {
		client_myds = ((MySQL_Session *)this)->client_myds;
	}
	assert(client_myds != NULL);
	string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
	proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Locking hostgroup for query %s\n", nqn.c_str());
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
		proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Unable to parse SET query but NOT setting lock_hostgroup %s\n", nqn.c_str());
	}
}

bool Client_Session::has_any_backend() {
	for (unsigned int j=0;j < mybes->len;j++) {
		MySQL_Backend *tmp_mybe=(MySQL_Backend *)mybes->index(j);
		MySQL_Data_Stream *__myds=tmp_mybe->server_myds;
		if (__myds->myconn) {
			return true;
		}
	}
	return false;
}

/*
void Client_Session::handler_WCDSS_MYSQL_COM_STMT_RESET(PtrSize_t& pkt) {
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

void Client_Session::handler_WCDSS_MYSQL_COM_STMT_CLOSE(PtrSize_t& pkt) {
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


void Client_Session::handler_WCDSS_MYSQL_COM_STMT_SEND_LONG_DATA(PtrSize_t& pkt) {
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
*/

void Client_Session::detected_broken_connection(const char *file, unsigned int line, const char *func, const char *action, MySQL_Connection *myconn, int myerr, const char *message, bool verbose) {
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

void Client_Session::generate_status_one_hostgroup(int hid, std::string& s) {
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

