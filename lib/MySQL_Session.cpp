#include "proxysql.h"
#include "cpp.h"
#include "re2/re2.h"
#include "re2/regexp.h"
#include "SpookyV2.h"
#include "set_parser.h"

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

#define SELECT_VERSION_COMMENT "select @@version_comment limit 1"
#define SELECT_VERSION_COMMENT_LEN 32
#define PROXYSQL_VERSION_COMMENT "\x01\x00\x00\x01\x01\x27\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x11\x40\x40\x76\x65\x72\x73\x69\x6f\x6e\x5f\x63\x6f\x6d\x6d\x65\x6e\x74\x00\x0c\x21\x00\x18\x00\x00\x00\xfd\x00\x00\x1f\x00\x00\x05\x00\x00\x03\xfe\x00\x00\x02\x00\x0b\x00\x00\x04\x0a(ProxySQL)\x05\x00\x00\x05\xfe\x00\x00\x02\x00"
#define PROXYSQL_VERSION_COMMENT_LEN 81
#define SELECT_CONNECTION_ID "SELECT CONNECTION_ID()"
#define SELECT_CONNECTION_ID_LEN 22
#define SELECT_LAST_INSERT_ID "SELECT LAST_INSERT_ID()"
#define SELECT_LAST_INSERT_ID_LEN 23
#define SELECT_LAST_INSERT_ID_LIMIT1 "SELECT LAST_INSERT_ID() LIMIT 1"
#define SELECT_LAST_INSERT_ID_LIMIT1_LEN 31
#define SELECT_VARIABLE_IDENTITY "SELECT @@IDENTITY"
#define SELECT_VARIABLE_IDENTITY_LEN 17
#define SELECT_VARIABLE_IDENTITY_LIMIT1 "SELECT @@IDENTITY LIMIT 1"
#define SELECT_VARIABLE_IDENTITY_LIMIT1_LEN 25

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


extern const MARIADB_CHARSET_INFO * proxysql_find_charset_name(const char * const name);
extern MARIADB_CHARSET_INFO * proxysql_find_charset_collate_names(const char *csname, const char *collatename);
extern const MARIADB_CHARSET_INFO * proxysql_find_charset_nr(unsigned int nr);

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


KillArgs::KillArgs(char *u, char *p, char *h, unsigned int P, unsigned long i, int kt, MySQL_Thread *_mt) {
	username=strdup(u);
	password=strdup(p);
	hostname=strdup(h);
	port=P;
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
	MySQL_Thread * thread = ka->mt;
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
					thread->status_variables.killed_queries++;
				}
				break;
			case KILL_CONNECTION:
				proxy_warning("KILL CONNECTION %lu on %s:%d\n", ka->id, ka->hostname, ka->port);
				if (thread) {
					thread->status_variables.killed_connections++;
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
extern MySQL_Threads_Handler *GloMTH;

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
		__sync_add_and_fetch(&sess->thread->status_variables.queries_slow,1);
	}
	if (sess->with_gtid) {
		__sync_add_and_fetch(&sess->thread->status_variables.queries_gtid,1);
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

void * MySQL_Session::operator new(size_t size) {
	return l_alloc(size);
}

void MySQL_Session::operator delete(void *ptr) {
	l_free(sizeof(MySQL_Session),ptr);
}


void MySQL_Session::set_status(enum session_status e) {
	if (e==NONE) {
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


MySQL_Session::MySQL_Session() {
	thread_session_id=0;
	handler_ret = 0;
	pause_until=0;
	qpo=new Query_Processor_Output();
	start_time=0;
	command_counters=new StatCounters(15,10);
	healthy=1;
	autocommit=true;
	autocommit_handled=false;
	autocommit_on_hostgroup=-1;
	killed=false;
	session_type=PROXYSQL_SESSION_MYSQL;
	//admin=false;
	connections_handler=false;
	max_connections_reached=false;
	//stats=false;
	client_authenticated=false;
	default_schema=NULL;
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
	set_status(NONE);

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

	//gtid_trxid = 0;
	gtid_hid = -1;
	memset(gtid_buf,0,sizeof(gtid_buf));

	match_regexes=NULL;
/*
	match_regexes=(Session_Regex **)malloc(sizeof(Session_Regex *)*3);
	match_regexes[0]=new Session_Regex((char *)"^SET (|SESSION |@@|@@session.)SQL_LOG_BIN( *)(:|)=( *)");
	match_regexes[1]=new Session_Regex((char *)"^SET (|SESSION |@@|@@session.)SQL_MODE( *)(:|)=( *)");
	match_regexes[2]=new Session_Regex((char *)"^SET (|SESSION |@@|@@session.)TIME_ZONE( *)(:|)=( *)");
*/
	init(); // we moved this out to allow CHANGE_USER

	last_insert_id=0; // #1093

	last_HG_affected_rows = -1; // #1421 : advanced support for LAST_INSERT_ID()
	ldap_ctx = NULL;
}

void MySQL_Session::init() {
	transaction_persistent_hostgroup=-1;
	transaction_persistent=false;
	mybes= new PtrArray(4);
	sess_STMTs_meta=new MySQL_STMTs_meta();
	SLDH=new StmtLongDataHandler();
	mysql_variables = std::unique_ptr<MySQL_Variables>(new MySQL_Variables(this));
}

void MySQL_Session::reset() {
	autocommit=true;
	autocommit_handled=false;
	autocommit_on_hostgroup=-1;
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
}

MySQL_Session::~MySQL_Session() {

	reset(); // we moved this out to allow CHANGE_USER

	if (locked_on_hostgroup >= 0) {
		thread->status_variables.hostgroup_locked--;
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
					GloMyAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->username);
					break;
			}
		}
		delete client_myds;
	}
	if (default_schema) {
		free(default_schema);
	}
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Shutdown Session %p\n" , this->thread, this, this);
	delete command_counters;
	if (session_type==PROXYSQL_SESSION_MYSQL && connections_handler==false && mirror==false) {
		__sync_fetch_and_sub(&MyHGM->status.client_connections,1);
	}
	assert(qpo);
	delete qpo;
	{
/*
		Session_Regex *sr=NULL;
		sr=match_regexes[0];
		delete sr;
		sr=match_regexes[1];
		delete sr;
		sr=match_regexes[2];
		delete sr;
	free(match_regexes);
*/
	match_regexes=NULL;
	}
	if (mirror) {
		__sync_sub_and_fetch(&GloMTH->status_variables.mirror_sessions_current,1);
	}
	if (ldap_ctx) {
		GloMyLdapAuth->ldap_ctx_free(ldap_ctx);
		ldap_ctx = NULL;
	}
}


// scan the pointer array of mysql backends (mybes) looking for a backend for the specified hostgroup_id
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
	mybes->add(_mybe);
	return _mybe;
};

MySQL_Backend * MySQL_Session::find_or_create_backend(int hostgroup_id, MySQL_Data_Stream *_myds) {
	MySQL_Backend *_mybe=find_backend(hostgroup_id);
	proxy_debug(PROXY_DEBUG_NET,4,"HID=%d, _myds=%p, _mybe=%p\n" , hostgroup_id, _myds, _mybe);
	return ( _mybe ? _mybe : create_backend(hostgroup_id, _myds) );
};

void MySQL_Session::reset_all_backends() {
	MySQL_Backend *mybe;
	while(mybes->len) {
		mybe=(MySQL_Backend *)mybes->remove_index_fast(0);
		mybe->reset();
		delete mybe;
	}
};

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

// FIXME: This function is currently disabled . See #469
bool MySQL_Session::handler_CommitRollback(PtrSize_t *pkt) {
	char c=((char *)pkt->ptr)[5];
	bool ret=false;
	if (c=='c' || c=='C') {
		if (strncasecmp((char *)"commit",(char *)pkt->ptr+5,6)==0) {
				__sync_fetch_and_add(&MyHGM->status.commit_cnt, 1);
				ret=true;
			}
		} else {
			if (c=='r' || c=='R') {
				if ( strncasecmp((char *)"rollback",(char *)pkt->ptr+5,8)==0 ) {
					__sync_fetch_and_add(&MyHGM->status.rollback_cnt, 1);
					ret=true;
				}
			}
		}

	if (ret==false) {
		return false;	// quick exit
	}
	unsigned int nTrx=NumActiveTransactions();
	if (nTrx) {
		// there is an active transaction, we must forward the request
		return false;
	} else {
		// there is no active transaction, we will just reply OK
		client_myds->DSS=STATE_QUERY_SENT_NET;
		uint16_t setStatus = 0;
		if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
		client_myds->DSS=STATE_SLEEP;
		status=WAITING_CLIENT_DATA;
		if (mirror==false) {
			RequestEnd(NULL);
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


bool MySQL_Session::handler_SetAutocommit(PtrSize_t *pkt) {
	autocommit_handled=false;
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
					if (nTrx) {
						// there is an active transaction, we need to forward it
						// because this can potentially close the transaction
						autocommit=true;
						client_myds->myconn->set_autocommit(autocommit);
						autocommit_on_hostgroup=FindOneActiveTransaction();
						free(_new_pkt.ptr);
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
				client_myds->DSS=STATE_QUERY_SENT_NET;
				uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
				if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
				client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
				client_myds->DSS=STATE_SLEEP;
				status=WAITING_CLIENT_DATA;
				if (mirror==false) {
					RequestEnd(NULL);
				}
				l_free(pkt->size,pkt->ptr);
				__sync_fetch_and_add(&MyHGM->status.autocommit_cnt_filtered, 1);
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
	j["gtid"]["hid"] = gtid_hid;
	j["gtid"]["last"] = ( strlen(gtid_buf) ? gtid_buf : "" );
	j["client"]["userinfo"]["username"] = ( client_myds->myconn->userinfo->username ? client_myds->myconn->userinfo->username : "" );
#ifdef DEBUG
	j["client"]["userinfo"]["password"] = ( client_myds->myconn->userinfo->password ? client_myds->myconn->userinfo->password : "" );
#endif
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
	j["default_schema"] = ( default_schema ? default_schema : "" );
	j["transaction_persistent"] = transaction_persistent;
	for (auto idx = 0; idx < SQL_NAME_LAST; idx++) {
		client_myds->myconn->variables[idx].fill_client_internal_session(j, idx);
	}
	j["conn"]["session_track_gtids"] = ( client_myds->myconn->options.session_track_gtids ? client_myds->myconn->options.session_track_gtids : "") ;
	j["conn"]["sql_auto_is_null"] = ( client_myds->myconn->options.sql_auto_is_null ? client_myds->myconn->options.sql_auto_is_null : "") ;
	j["conn"]["collation_connection"] = ( client_myds->myconn->options.collation_connection ? client_myds->myconn->options.collation_connection : "") ;
	j["conn"]["net_write_timeout"] = ( client_myds->myconn->options.net_write_timeout ? client_myds->myconn->options.net_write_timeout : "") ;
	j["conn"]["max_join_size"] = ( client_myds->myconn->options.max_join_size ? client_myds->myconn->options.max_join_size : "") ;
	j["conn"]["charset"] = client_myds->myconn->options.charset;
	j["conn"]["sql_log_bin"] = client_myds->myconn->options.sql_log_bin;
	j["conn"]["autocommit"] = ( client_myds->myconn->options.autocommit ? "ON" : "OFF" );
	j["conn"]["client_flag"]["value"] = client_myds->myconn->options.client_flag;
	j["conn"]["client_flag"]["client_found_rows"] = (client_myds->myconn->options.client_flag & CLIENT_FOUND_ROWS ? 1 : 0);
	j["conn"]["client_flag"]["client_multi_statements"] = (client_myds->myconn->options.client_flag & CLIENT_MULTI_STATEMENTS ? 1 : 0);
	j["conn"]["client_flag"]["client_multi_results"] = (client_myds->myconn->options.client_flag & CLIENT_MULTI_RESULTS ? 1 : 0);
	j["conn"]["no_backslash_escapes"] = client_myds->myconn->options.no_backslash_escapes;
	j["conn"]["status"]["compression"] = client_myds->myconn->get_status_compression();
	j["conn"]["status"]["transaction"] = client_myds->myconn->get_status_transaction();
	j["conn"]["ps"]["client_stmt_to_global_ids"] = client_myds->myconn->local_stmts->client_stmt_to_global_ids;
	for (unsigned int k=0; k<mybes->len; k++) {
		MySQL_Backend *_mybe = NULL;
		_mybe=(MySQL_Backend *)mybes->index(k);
		unsigned int i = _mybe->hostgroup_id;
		j["backends"][i]["hostgroup_id"] = i;
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
				MySQL_Connection * _myconn = _myds->myconn;
				for (auto idx = 0; idx < SQL_NAME_LAST; idx++) {
					_myconn->variables[idx].fill_server_internal_session(j, i, idx);
				}
				sprintf(buff,"%p",_myconn);
				j["backends"][i]["conn"]["address"] = buff;
				j["backends"][i]["conn"]["auto_increment_delay_token"] = _myconn->auto_increment_delay_token;
				j["backends"][i]["conn"]["bytes_recv"] = _myconn->bytes_info.bytes_recv;
				j["backends"][i]["conn"]["bytes_sent"] = _myconn->bytes_info.bytes_sent;
				j["backends"][i]["conn"]["questions"] = _myconn->statuses.questions;
				j["backends"][i]["conn"]["myconnpoll_get"] = _myconn->statuses.myconnpoll_get;
				j["backends"][i]["conn"]["myconnpoll_put"] = _myconn->statuses.myconnpoll_put;
				j["backends"][i]["conn"]["session_track_gtids"] = ( _myconn->options.session_track_gtids ? _myconn->options.session_track_gtids : "") ;
				j["backends"][i]["conn"]["sql_auto_is_null"] = ( _myconn->options.sql_auto_is_null ? _myconn->options.sql_auto_is_null : "") ;
				j["backends"][i]["conn"]["collation_connection"] = ( _myconn->options.collation_connection ? _myconn->options.collation_connection : "") ;
				j["backends"][i]["conn"]["net_write_timeout"] = ( _myconn->options.net_write_timeout ? _myconn->options.net_write_timeout : "") ;
                j["backends"][i]["conn"]["max_join_size"] = ( _myconn->options.max_join_size ? _myconn->options.max_join_size : "") ;
				//j["backend"][i]["conn"]["charset"] = _myds->myconn->options.charset; // not used for backend
				j["backends"][i]["conn"]["sql_log_bin"] = ( _myconn->options.sql_log_bin ? "ON" : "OFF" );
				j["backends"][i]["conn"]["init_connect"] = ( _myconn->options.init_connect ? _myconn->options.init_connect : "");
				j["backends"][i]["conn"]["init_connect_sent"] = _myds->myconn->options.init_connect_sent;
				j["backends"][i]["conn"]["autocommit"] = ( _myds->myconn->options.autocommit ? "ON" : "OFF" );
				j["backends"][i]["conn"]["last_set_autocommit"] = _myds->myconn->options.last_set_autocommit;
				j["backends"][i]["conn"]["no_backslash_escapes"] = _myconn->options.no_backslash_escapes;
				j["backends"][i]["conn"]["status"]["get_lock"] = _myconn->get_status_get_lock();
				j["backends"][i]["conn"]["status"]["lock_tables"] = _myconn->get_status_lock_tables();
				j["backends"][i]["conn"]["status"]["temporary_table"] = _myconn->get_status_temporary_table();
				j["backends"][i]["conn"]["status"]["user_variable"] = _myconn->get_status_user_variable();
				j["backends"][i]["conn"]["status"]["found_rows"] = _myconn->get_status_found_rows();
				j["backends"][i]["conn"]["status"]["no_multiplex"] = _myconn->get_status_no_multiplex();
				j["backends"][i]["conn"]["MultiplexDisabled"] = _myconn->MultiplexDisabled();
				j["backends"][i]["conn"]["ps"]["backend_stmt_to_global_ids"] = _myconn->local_stmts->backend_stmt_to_global_ids;
				j["backends"][i]["conn"]["ps"]["global_stmt_to_backend_ids"] = _myconn->local_stmts->global_stmt_to_backend_ids;
				j["backends"][i]["conn"]["client_flag"]["value"] = _myconn->options.client_flag;
				j["backends"][i]["conn"]["client_flag"]["client_found_rows"] = (_myconn->options.client_flag & CLIENT_FOUND_ROWS ? 1 : 0);
				j["backends"][i]["conn"]["client_flag"]["client_multi_statements"] = (_myconn->options.client_flag & CLIENT_MULTI_STATEMENTS ? 1 : 0);
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
		SQLite3_to_MySQL(resultset, NULL, 0, &client_myds->myprot);
		delete resultset;
		return;
	}
	// default
	client_myds->DSS=STATE_QUERY_SENT_NET;
	client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1064,(char *)"42000",(char *)"Unknown PROXYSQL INTERNAL command",true);
	client_myds->DSS=STATE_SLEEP;
	status=WAITING_CLIENT_DATA;
	if (mirror==false) {
		RequestEnd(NULL);
	}
	l_free(pkt->size,pkt->ptr);
}

bool MySQL_Session::handler_special_queries(PtrSize_t *pkt) {

	if (pkt->size>(5+18) && strncasecmp((char *)"PROXYSQL INTERNAL ",(char *)pkt->ptr+5,18)==0) {
		return_proxysql_internal(pkt);
		return true;
	}
	if (mysql_thread___forward_autocommit == false) {
		if (handler_SetAutocommit(pkt) == true) {
			return true;
		}
		if (handler_CommitRollback(pkt) == true) {
			return true;
		}
	}

	if (session_type != PROXYSQL_SESSION_CLICKHOUSE) {
		if (pkt->size>(5+4) && strncasecmp((char *)"USE ",(char *)pkt->ptr+5,4)==0) {
			handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_USE_DB(pkt);
			return true;
		}
	}
/*
	if (
		(pkt->size==SELECT_LAST_INSERT_ID_LEN+5 && strncasecmp((char *)SELECT_LAST_INSERT_ID,(char *)pkt->ptr+5,pkt->size-5)==0)
		||
		(pkt->size==SELECT_LAST_INSERT_ID_LIMIT1_LEN+5 && strncasecmp((char *)SELECT_LAST_INSERT_ID_LIMIT1,(char *)pkt->ptr+5,pkt->size-5)==0)
	) {
		char buf[32];
		sprintf(buf,"%llu",last_insert_id);
		unsigned int nTrx=NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
		MySQL_Data_Stream *myds=client_myds;
		MySQL_Protocol *myprot=&client_myds->myprot;
		myds->DSS=STATE_QUERY_SENT_DS;
		int sid=1;
		myprot->generate_pkt_column_count(true,NULL,NULL,sid,1); sid++;
		myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",(char *)"LAST_INSERT_ID()",(char *)"",63,31,MYSQL_TYPE_LONGLONG,161,0,false,0,NULL); sid++;
		myds->DSS=STATE_COLUMN_DEFINITION;
		myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
		char **p=(char **)malloc(sizeof(char*)*1);
		unsigned long *l=(unsigned long *)malloc(sizeof(unsigned long *)*1);
		l[0]=strlen(buf);;
		p[0]=buf;
		myprot->generate_pkt_row(true,NULL,NULL,sid,1,l,p); sid++;
		myds->DSS=STATE_ROW;
		myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
		myds->DSS=STATE_SLEEP;
		l_free(pkt->size,pkt->ptr);
		free(p);
		free(l);
		return true;
	}
*/
	if (pkt->size==SELECT_VERSION_COMMENT_LEN+5 && strncmp((char *)SELECT_VERSION_COMMENT,(char *)pkt->ptr+5,pkt->size-5)==0) {
		// FIXME: this doesn't return AUTOCOMMIT or IN_TRANS
		PtrSize_t pkt_2;
		pkt_2.size=PROXYSQL_VERSION_COMMENT_LEN;
		pkt_2.ptr=l_alloc(pkt_2.size);
		memcpy(pkt_2.ptr,PROXYSQL_VERSION_COMMENT,pkt_2.size);
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
		SQLite3_to_MySQL(resultset, error, affected_rows, &client_myds->myprot);
		delete resultset;
		free(query2);
		if (mirror==false) {
			RequestEnd(NULL);
		}
		l_free(pkt->size,pkt->ptr);
		return true;
	}
	if ( (pkt->size < 60) && (pkt->size > 38) && (strncasecmp((char *)"SET SESSION character_set_server",(char *)pkt->ptr+5,32)==0) ) { // issue #601
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
		}
	}
	if ( (pkt->size < 60) && (pkt->size > 39) && (strncasecmp((char *)"SET SESSION character_set_results",(char *)pkt->ptr+5,33)==0) ) { // like the above
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
		}
	}
	if (
		(pkt->size < 100) && (pkt->size > 15) && (strncasecmp((char *)"SET NAMES ",(char *)pkt->ptr+5,10)==0)
		&&
		(memchr((const void *)((char *)pkt->ptr+5),',',pkt->size-15)==NULL) // there is no comma
	) {
		char *unstripped=strndup((char *)pkt->ptr+15,pkt->size-15);
		char *csname=trim_spaces_and_quotes_in_place(unstripped);
		bool collation_specified = false;
		//unsigned int charsetnr = 0;
		const MARIADB_CHARSET_INFO * c;
		char * collation_name_unstripped = NULL;
		char * collation_name = NULL;
		if (strcasestr(csname," COLLATE ")) {
			collation_specified = true;
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
		client_myds->DSS=STATE_QUERY_SENT_NET;
		if (!c) {
			char *m = NULL;
			char *errmsg = NULL;
			if (collation_specified) {
				m=(char *)"Unknown character set '%s' or collation '%s'";
				errmsg=(char *)malloc(strlen(csname)+strlen(collation_name)+strlen(m));
				sprintf(errmsg,m,csname,collation_name);
			} else {
				m=(char *)"Unknown character set: '%s'";
				errmsg=(char *)malloc(strlen(csname)+strlen(m));
				sprintf(errmsg,m,csname);
			}
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1115,(char *)"42000",errmsg,true);
			free(errmsg);
		} else {
			client_myds->myconn->set_charset(c->nr, NAMES);
			unsigned int nTrx=NumActiveTransactions();
			uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
			if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
		}
		client_myds->DSS=STATE_SLEEP;
		status=WAITING_CLIENT_DATA;
		if (mirror==false) {
			RequestEnd(NULL);
		}
		l_free(pkt->size,pkt->ptr);
		free(unstripped);
		__sync_fetch_and_add(&MyHGM->status.frontend_set_names, 1);
		return true;
	}
	if ( (pkt->size == 18) && (strncasecmp((char *)"SHOW WARNINGS",(char *)pkt->ptr+5,13)==0) ) {
		SQLite3_result * resultset=new SQLite3_result(3);
		resultset->add_column_definition(SQLITE_TEXT,"Level");
		resultset->add_column_definition(SQLITE_TEXT,"Code");
		resultset->add_column_definition(SQLITE_TEXT,"Message");
		SQLite3_to_MySQL(resultset, NULL, 0, &client_myds->myprot);
		delete resultset;
		client_myds->DSS=STATE_SLEEP;
		status=WAITING_CLIENT_DATA;
		if (mirror==false) {
			RequestEnd(NULL);
		}
		l_free(pkt->size,pkt->ptr);
		return true;
	}
	return false;
}

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___create_mirror_session() {
	if (pktH->size < 15*1024*1024 && (qpo->mirror_hostgroup >= 0 || qpo->mirror_flagOUT >= 0)) {
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
		newsess->mirrorPkt.size=pktH->size;
		newsess->mirrorPkt.ptr=l_alloc(newsess->mirrorPkt.size);
		memcpy(newsess->mirrorPkt.ptr,pktH->ptr,pktH->size);

		if (thread->mirror_queue_mysql_sessions->len==0) {
			// there are no sessions in the queue, we try to execute immediately
			// Only mysql_thread___mirror_max_concurrency mirror session can run in parallel
			if (__sync_add_and_fetch(&GloMTH->status_variables.mirror_sessions_current,1) > (unsigned int)mysql_thread___mirror_max_concurrency ) {
				// if the limit is reached, we queue it instead
				__sync_sub_and_fetch(&GloMTH->status_variables.mirror_sessions_current,1);
				thread->mirror_queue_mysql_sessions->add(newsess);
			}	else {
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


//		if (i==0) {
//		} else {
//			delete newsess;
//		}
	}
}

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
		set_status(NONE);
			return -1;
	} else {
		if (rc==-1 || rc==-2) {
			if (rc==-2) {
				unsigned long long us = mysql_thread___ping_timeout_server*1000;
				us += thread->curtime;
				us -= myds->wait_until;
				proxy_error("Ping timeout during ping on %s:%d after %lluus (timeout %dms)\n", myconn->parent->address, myconn->parent->port, us, mysql_thread___ping_timeout_server);
			} else { // rc==-1
				int myerr=mysql_errno(myconn->mysql);
				proxy_error("Detected a broken connection during ping on (%d,%s,%d) , FD (Conn:%d , MyDS:%d) : %d, %s\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myds->fd, myds->myconn->fd, myerr, mysql_error(myconn->mysql));
			}
			myds->destroy_MySQL_Connection_From_Pool(false);
			myds->fd=0;
			delete mybe->server_myds;
			mybe->server_myds=NULL;
			return -1;
		} else {
			// rc==1 , nothing to do for now
// tring to fix bug
			if (myds->mypolls==NULL) {
				thread->mypolls.add(POLLIN|POLLOUT, myds->fd, myds, thread->curtime);
			}
// tring to fix bug
		}
	}
	return 0;
}

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
		myconn->async_state_machine=ASYNC_IDLE;
//		if (mysql_thread___multiplexing && (myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
			myds->return_MySQL_Connection_To_Pool();
//		} else {
//			myds->destroy_MySQL_Connection_From_Pool(true);
//		}
		delete mybe->server_myds;
		mybe->server_myds=NULL;
		set_status(NONE);
		return -1;
	} else {
		if (rc==-1 || rc==-2) {
			if (rc==-2) {
				proxy_error("Change user timeout during COM_CHANGE_USER on %s , %d\n", myconn->parent->address, myconn->parent->port);
			} else { // rc==-1
				int myerr=mysql_errno(myconn->mysql);
				proxy_error("Detected an error during COM_CHANGE_USER on (%d,%s,%d) , FD (Conn:%d , MyDS:%d) : %d, %s\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myds->fd, myds->myconn->fd, myerr, mysql_error(myconn->mysql));
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
			KillArgs *ka = new KillArgs(ui->username, auth_password, myds->myconn->parent->address, myds->myconn->parent->port, myds->myconn->mysql->thread_id, KILL_QUERY, thread);
			pthread_attr_t attr;
			pthread_attr_init(&attr);
			pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
			pthread_attr_setstacksize (&attr, 256*1024);
			pthread_t pt;
			if (pthread_create(&pt, &attr, &kill_query_thread, ka) != 0) {
				proxy_error("Thread creation\n");
				assert(0);
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

bool MySQL_Session::handler_again___verify_backend_charset() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , client charset: %u , backend charset: %u\n", this, client_myds->myconn->options.charset, mybe->server_myds->myconn->mysql->charset->nr);
	if (client_myds->myconn->options.charset != mybe->server_myds->myconn->mysql->charset->nr || client_myds->myconn->options.charset_action != mybe->server_myds->myconn->options.charset_action) {
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
				assert(0);
				break;
		}
		if (client_myds->myconn->options.charset_action == NAMES) {
			NEXT_IMMEDIATE_NEW(CHANGING_CHARSET);
		} else if (client_myds->myconn->options.charset_action == CHARSET) {
			NEXT_IMMEDIATE_NEW(SETTING_CHARSET);
		} else {
			assert(0);
		}
	}
	return false;
}

bool MySQL_Session::handler_again___verify_backend_sql_log_bin() {
	if (client_myds->myconn->options.sql_log_bin != mybe->server_myds->myconn->options.sql_log_bin) {
		mybe->server_myds->myconn->options.sql_log_bin = client_myds->myconn->options.sql_log_bin;
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
				assert(0);
				break;
		}
		NEXT_IMMEDIATE_NEW(SETTING_SQL_LOG_BIN);
	}
	return false;
}

bool MySQL_Session::handler_again___verify_backend__generic_variable(uint32_t *be_int, char **be_var, char *def, uint32_t *fe_int, char *fe_var, enum session_status next_sess_status) {
	// be_int = backend int (hash)
	// be_var = backend value
	// def = default
	// fe_int = frontend int (has)
	// fe_var = frontend value
	if (*be_int == 0) {
		// it is the first time we use this backend. Set value to default
		if (*be_var) {
			free(*be_var);
			*be_var = NULL;
		}
		*be_var = strdup(def);
		uint32_t tmp_int = SpookyHash::Hash32(*be_var, strlen(*be_var), 10);
		*be_int = tmp_int;
	}
	if (*fe_int) {
		if (*fe_int != *be_int) {
			{
				*be_int = *fe_int;
				if (*be_var) {
					free(*be_var);
					*be_var = NULL;
				}
				if (fe_var) {
					*be_var = strdup(fe_var);
				}
			}
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
					assert(0);
					break;
			}
			NEXT_IMMEDIATE_NEW(next_sess_status);
		}
	}
	return false;
}

bool MySQL_Session::handler_again___verify_backend_session_track_gtids() {
	bool ret = false;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , client: %s , backend: %s\n", this, client_myds->myconn->options.session_track_gtids, mybe->server_myds->myconn->options.session_track_gtids);
	ret = handler_again___verify_backend__generic_variable(
		&mybe->server_myds->myconn->options.session_track_gtids_int,
		&mybe->server_myds->myconn->options.session_track_gtids,
		mysql_thread___default_session_track_gtids,
		&client_myds->myconn->options.session_track_gtids_int,
		client_myds->myconn->options.session_track_gtids,
		SETTING_SESSION_TRACK_GTIDS
	);
	return ret;
}

bool MySQL_Session::handler_again___verify_backend_sql_auto_is_null() {
	bool ret = false;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , client: %s , backend: %s\n", this, client_myds->myconn->options.sql_auto_is_null, mybe->server_myds->myconn->options.sql_auto_is_null);
	ret = handler_again___verify_backend__generic_variable(
		&mybe->server_myds->myconn->options.sql_auto_is_null_int,
		&mybe->server_myds->myconn->options.sql_auto_is_null,
		mysql_thread___default_sql_auto_is_null,
		&client_myds->myconn->options.sql_auto_is_null_int,
		client_myds->myconn->options.sql_auto_is_null,
		SETTING_SQL_AUTO_IS_NULL
	);
	return ret;
}

bool MySQL_Session::handler_again___verify_backend(int var) {
	bool ret = false;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , client: %s , backend: %s\n", this, mysql_variables->client_get_value(var), mysql_variables->server_get_value(var));
	ret = mysql_variables->verify_variable(var);
	return ret;
}

bool MySQL_Session::handler_again___verify_backend_collation_connection() {
	bool ret = false;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , client: %s , backend: %s\n", this, client_myds->myconn->options.collation_connection, mybe->server_myds->myconn->options.collation_connection);
	ret = handler_again___verify_backend__generic_variable(
		&mybe->server_myds->myconn->options.collation_connection_int,
		&mybe->server_myds->myconn->options.collation_connection,
		mysql_thread___default_collation_connection,
		&client_myds->myconn->options.collation_connection_int,
		client_myds->myconn->options.collation_connection,
		SETTING_COLLATION_CONNECTION
	);
	return ret;
}

bool MySQL_Session::handler_again___verify_backend_net_write_timeout() {
	bool ret = false;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , client: %s , backend: %s\n", this, client_myds->myconn->options.net_write_timeout, mybe->server_myds->myconn->options.net_write_timeout);
	ret = handler_again___verify_backend__generic_variable(
		&mybe->server_myds->myconn->options.net_write_timeout_int,
		&mybe->server_myds->myconn->options.net_write_timeout,
		mysql_thread___default_net_write_timeout,
		&client_myds->myconn->options.net_write_timeout_int,
		client_myds->myconn->options.net_write_timeout,
		SETTING_NET_WRITE_TIMEOUT
	);
	return ret;
}

bool MySQL_Session::handler_again___verify_backend_multi_statement() {
	if (client_myds->myconn->options.client_flag & CLIENT_MULTI_STATEMENTS != mybe->server_myds->myconn->options.client_flag & CLIENT_MULTI_STATEMENTS) {

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
				assert(0);
				break;
		}
		NEXT_IMMEDIATE_NEW(SETTING_MULTI_STMT);
	}
	return false;
}

bool MySQL_Session::handler_again___verify_backend_max_join_size() {
	bool ret = false;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , client: %s , backend: %s\n", this, client_myds->myconn->options.max_join_size, mybe->server_myds->myconn->options.max_join_size);
	ret = handler_again___verify_backend__generic_variable(
		&mybe->server_myds->myconn->options.max_join_size_int,
		&mybe->server_myds->myconn->options.max_join_size,
		mysql_thread___default_max_join_size,
		&client_myds->myconn->options.max_join_size_int,
		client_myds->myconn->options.max_join_size,
		SETTING_MAX_JOIN_SIZE
	);
	return ret;
}

bool MySQL_Session::handler_again___verify_init_connect() {
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
					assert(0);
					break;
			}
			NEXT_IMMEDIATE_NEW(SETTING_INIT_CONNECT);
		}
	}
	return false;
}

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
					assert(0);
					break;
			}
			NEXT_IMMEDIATE_NEW(SETTING_LDAP_USER_VARIABLE);
		}
	}
	return false;
}

bool MySQL_Session::handler_again___verify_backend_autocommit() {
	if (mysql_thread___forward_autocommit == true) {
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
						assert(0);
						break;
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
					assert(0);
					break;
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
					assert(0);
					break;
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
					assert(0);
					break;
			}
			NEXT_IMMEDIATE_NEW(CHANGING_SCHEMA);
		}
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
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			if (myerr >= 2000) {
				bool retry_conn=false;
				// client error, serious
				proxy_error("Detected a broken connection while setting INIT CONNECT on %s:%d hg %d : %d, %s\n", myconn->parent->address, myconn->parent->port, current_hostgroup, myerr, mysql_error(myconn->mysql));
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

bool MySQL_Session::handler_again___status_SETTING_LDAP_USER_VARIABLE(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	MySQL_Data_Stream *myds=mybe->server_myds;
	MySQL_Connection *myconn=myds->myconn;
	myds->DSS=STATE_MARIADB_QUERY;
	enum session_status st=status;

	if (
		(GloMyLdapAuth==NULL) || (ldap_ctx==NULL)
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
			if (myerr >= 2000) {
				bool retry_conn=false;
				// client error, serious
				proxy_error("Detected a broken connection while setting LDAP USER VARIABLE on %s:%d hg %d : %d, %s\n", myconn->parent->address, myconn->parent->port, current_hostgroup, myerr, mysql_error(myconn->mysql));
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
		char *q=(char *)"SET SQL_LOG_BIN=%d";
		query=(char *)malloc(strlen(q)+8);
		sprintf(query,q,myconn->options.sql_log_bin);
		query_length=strlen(query);
	}
	int rc=myconn->async_send_simple_command(myds->revents,query,query_length);
	if (query) {
		free(query);
		query=NULL;
	}
	if (rc==0) {
		if (myconn->options.sql_log_bin==0) {
			// pay attention here. set_status_sql_log_bin0 sets it sql_log_bin is ZERO
			// sql_log_bin=0 => true
			// sql_log_bin=1 => false
			myconn->set_status_sql_log_bin0(true);
		} else {
			myconn->set_status_sql_log_bin0(false);
		}
		myds->revents|=POLLOUT;	// we also set again POLLOUT to send a query immediately!
		myds->DSS = STATE_MARIADB_GENERIC;
		st=previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			if (myerr >= 2000) {
				bool retry_conn=false;
				// client error, serious
				proxy_error("Detected a broken connection while setting SQL_LOG_BIN on %s:%d hg %d : %d, %s\n", myconn->parent->address, myconn->parent->port, current_hostgroup, myerr, mysql_error(myconn->mysql));
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

/* FIXME: this old code hardcoded the handling of issue 1738
// this seems unnecessary/redundant
// leaving the code for further reference, to be removed later
// FIXME
bool MySQL_Session::handler_again___status_SETTING_SQL_MODE(int *_rc) {
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
		char *q=NULL;
		q=(char *)"SET SQL_MODE='%s'";
		if (strlen(myconn->options.sql_mode) > 6) {
			if (strncasecmp(myconn->options.sql_mode,(char *)"CONCAT",6)==0) {
				q=(char *)"SET SQL_MODE=%s";
			}
			if (strncasecmp(myconn->options.sql_mode,(char *)"@",1)==0) {
				q=(char *)"SET SQL_MODE=%s";
			}
		}
		query=(char *)malloc(strlen(q)+strlen(myconn->options.sql_mode));
		sprintf(query,q,myconn->options.sql_mode);
		query_length=strlen(query);
	}
	int rc=myconn->async_send_simple_command(myds->revents,query,query_length);
	if (query) {
		free(query);
		query=NULL;
	}
	if (rc==0) {
		myds->revents|=POLLOUT;	// we also set again POLLOUT to send a query immediately!
		st=previous_status.top();
		previous_status.pop();
		bool nbe = (myconn->mysql->server_status & SERVER_STATUS_NO_BACKSLASH_ESCAPES);
		if (client_myds) {
			client_myds->myconn->set_no_backslash_escapes(nbe);
		}
		if (nbe) {
			myconn->set_status_no_backslash_escapes(nbe);
		}
		if (st == PROCESSING_QUERY) { // only TEXT protocol, no prepared statements
			if (client_myds && mirror==false) {
				if (CurrentQuery.QueryParserArgs.digest_text) {
					// this is not meant to match all the SET SQL_MODE, but just to
					// reduce unnecessary SET SQL_MODE when possible
					if (strncasecmp(CurrentQuery.QueryParserArgs.digest_text,(char *)"set sql_mode",12)==0) {
						unsigned int nTrx=NumActiveTransactions();
						uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
						if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
						client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
						RequestEnd(myds);
						finishQuery(myds,myconn,false);
						return ret;
					}
				}
			}
		}
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			if (myerr >= 2000) {
				bool retry_conn=false;
				// client error, serious
				proxy_error("Detected a broken connection while setting SQL_MODE on %s , %d : %d, %s\n", myconn->parent->address, myconn->parent->port, myerr, mysql_error(myconn->mysql));
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
				proxy_warning("Error while setting SQL_MODE: %d, %s\n", myerr, mysql_error(myconn->mysql));
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
*/

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
			if (myerr >= 2000) {
				bool retry_conn=false;
				// client error, serious
				proxy_error("Detected a broken connection while setting %s on %s:%d hg %d : %d, %s\n", var_name, myconn->parent->address, myconn->parent->port, current_hostgroup, myerr, mysql_error(myconn->mysql));
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
		proxy_error("Error setting multistatemnt on server\n");
	}
	return ret;
}

bool MySQL_Session::handler_again___status_SETTING_CHARSET(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	mybe->server_myds->myconn->set_charset(client_myds->myconn->options.charset, CHARSET);
	const MARIADB_CHARSET_INFO * c = proxysql_find_charset_nr(client_myds->myconn->options.charset);
	ret = handler_again___status_SETTING_GENERIC_VARIABLE(_rc, (char *)"CHARSET", (char*)c->csname, false, true);
	return ret;
}

bool MySQL_Session::handler_again___status_SETTING_SESSION_TRACK_GTIDS(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	ret = handler_again___status_SETTING_GENERIC_VARIABLE(_rc, (char *)"SESSION_TRACK_GTIDS", mybe->server_myds->myconn->options.session_track_gtids, true);
	return ret;
}

bool MySQL_Session::handler_again___status_SETTING_SQL_AUTO_IS_NULL(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	ret = handler_again___status_SETTING_GENERIC_VARIABLE(_rc, (char *)"SQL_AUTO_IS_NULL", mybe->server_myds->myconn->options.sql_auto_is_null, true);
	return ret;
}

bool MySQL_Session::handler_again___status_SETTING_SQL_SELECT_LIMIT(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	ret = handler_again___status_SETTING_GENERIC_VARIABLE(_rc, (char *)"SQL_SELECT_LIMIT", mysql_variables->server_get_value(SQL_SELECT_LIMIT), true);
	return ret;
}

bool MySQL_Session::handler_again___status_SETTING_SQL_SAFE_UPDATES(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	ret = handler_again___status_SETTING_GENERIC_VARIABLE(_rc, (char *)"SQL_SAFE_UPDATES", mysql_variables->server_get_value(SQL_SAFE_UPDATES), true);
	return ret;
}

bool MySQL_Session::handler_again___status_SETTING_COLLATION_CONNECTION(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	ret = handler_again___status_SETTING_GENERIC_VARIABLE(_rc, (char *)"COLLATION_CONNECTION", mybe->server_myds->myconn->options.collation_connection);
	return ret;
}

bool MySQL_Session::handler_again___status_SETTING_NET_WRITE_TIMEOUT(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	ret = handler_again___status_SETTING_GENERIC_VARIABLE(_rc, (char *)"NET_WRITE_TIMEOUT", mybe->server_myds->myconn->options.net_write_timeout, true);
	return ret;
}

bool MySQL_Session::handler_again___status_SETTING_MAX_JOIN_SIZE(int *_rc) {
	bool ret=false;
	assert(mybe->server_myds->myconn);
	ret = handler_again___status_SETTING_GENERIC_VARIABLE(_rc, (char *)"MAX_JOIN_SIZE", mybe->server_myds->myconn->options.max_join_size, true);
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
			if (myerr >= 2000) {
				bool retry_conn=false;
				// client error, serious
				proxy_error("Detected a broken connection during INIT_DB on %s , %d : %d, %s\n", myconn->parent->address, myconn->parent->port, myerr, mysql_error(myconn->mysql));
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
				thread->status_variables.max_connect_timeout_err++;
			}
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,9001,(char *)"HY000",buf, true);
			RequestEnd(mybe->server_myds);
			//enum session_status st;
			while (previous_status.size()) {
				previous_status.top();
				previous_status.pop();
			}
			if (mybe->server_myds->myconn) {
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
			myconn->set_status_user_variable(true);
		}
		enum session_status st=status;
		if (mybe->server_myds->myconn->async_state_machine==ASYNC_IDLE) {
			st=previous_status.top();
			previous_status.pop();
			NEXT_IMMEDIATE_NEW(st);
			assert(0);
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
					NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
				} else {
__exit_handler_again___status_CONNECTING_SERVER_with_err:
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
							thread->status_variables.max_connect_timeout_err++;
						}
					}
					if (session_fast_forward==false) {
						// see bug #979
						RequestEnd(myds);
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
		st=previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			if (myerr >= 2000) {
				bool retry_conn=false;
				// client error, serious
				proxy_error("Detected a broken connection during change user on %s, %d : %d, %s\n", myconn->parent->address, myconn->parent->port, myerr, mysql_error(myconn->mysql));
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

bool MySQL_Session::handler_again___status_CHANGING_CHARSET(int *_rc) {
	assert(mybe->server_myds->myconn);
	MySQL_Data_Stream *myds=mybe->server_myds;
	MySQL_Connection *myconn=myds->myconn;
	char msg[128];
	const MARIADB_CHARSET_INFO *ci = NULL;
	const char* replace_collation = "";
	const char* not_supported_collation = "";

	/* Validate that server can support client's charset */
	if (client_myds->myconn->options.charset >= 255 && myconn->mysql->server_version[0] != '8') {
		switch(mysql_thread___handle_unknown_charset) {
			case HANDLE_UNKNOWN_CHARSET__DISCONNECT_CLIENT:
				snprintf(msg,sizeof(msg),"Can't initialize character set %d",client_myds->myconn->options.charset);
				proxy_error("Can't initialize character set on %s, %d: Error %d (%s). Closing client connection %s:%d.\n",
						myconn->parent->address, myconn->parent->port, 2019, msg, client_myds->addr.addr, client_myds->addr.port);
				myds->destroy_MySQL_Connection_From_Pool(false);
				myds->fd=0;
				*_rc=-1;
				return false;
			case HANDLE_UNKNOWN_CHARSET__REPLACE_WITH_DEFAULT_VERBOSE:
				ci = proxysql_find_charset_nr(client_myds->myconn->options.charset);
				if (ci)	not_supported_collation = ci->name;

				ci = proxysql_find_charset_nr(mysql_thread___default_charset);
				if (ci)	replace_collation = ci->name;

				proxy_warning("Server doesn't support collation (%d) %s. Replacing it with the configured default (%d) %s. Client %s:%d\n",
						client_myds->myconn->options.charset, not_supported_collation, 
						mysql_thread___default_charset, replace_collation, client_myds->addr.addr, client_myds->addr.port);

				client_myds->myconn->options.charset=mysql_thread___default_charset;
				break;
			case HANDLE_UNKNOWN_CHARSET__REPLACE_WITH_DEFAULT:
				client_myds->myconn->options.charset=mysql_thread___default_charset;
				break;
			default:
				proxy_error("Wrong configuration of the handle_unknown_charset\n");
				break;
		}
	}

	myds->DSS=STATE_MARIADB_QUERY;
	enum session_status st=status;
	if (client_myds->myconn->options.charset_action == NAMES) {
		if (myds->mypolls==NULL) {
			thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
		}
		int rc=myconn->async_set_names(myds->revents, client_myds->myconn->options.charset);
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
				if (myerr >= 2000) {
					if (myerr == 2019) {
            			proxy_error("Client trying to set a charset/collation (%u) not supported by backend (%s:%d). Changing it to %u\n", client_myds->myconn->options.charset, myconn->parent->address, myconn->parent->port, mysql_thread___default_charset);
						client_myds->myconn->options.charset = mysql_thread___default_charset;
					}
					bool retry_conn=false;
					// client error, serious
					proxy_error("Detected a broken connection during SET NAMES on %s , %d : %d, %s\n", myconn->parent->address, myconn->parent->port, myerr, mysql_error(myconn->mysql));
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
					RequestEnd(myds);
				}
			} else {
				// rc==1 , nothing to do for now
			}
		}
	} else if (client_myds->myconn->options.charset_action == CHARSET) {
		myds->DSS = STATE_MARIADB_GENERIC;
		st=previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
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
			if (myerr >= 2000) {
				bool retry_conn=false;
				// client error, serious
				proxy_error("Detected a broken connection during SET AUTOCOMMIT on %s , %d : %d, %s\n", myconn->parent->address, myconn->parent->port, myerr, mysql_error(myconn->mysql));
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

int MySQL_Session::handler() {
	handler_ret = 0;
	bool prepared_stmt_with_no_params = false;
	bool wrong_pass=false;
	if (to_process==0) return 0; // this should be redundant if the called does the same check
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Processing session %p\n" , this->thread, this, this);
	PtrSize_t pkt;
	pktH=&pkt;
	unsigned int j;
	unsigned char c;

	if (active_transactions <= 0) {
		active_transactions=NumActiveTransactions();
	}
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

__get_pkts_from_client:

	//for (j=0; j<client_myds->PSarrayIN->len;) {
	// implement a more complex logic to run even in case of mirror
	// if client_myds , this is a regular client
	// if client_myds == NULL , it is a mirror
	//     process mirror only status==WAITING_CLIENT_DATA
	for (j=0; j< ( client_myds->PSarrayIN ? client_myds->PSarrayIN->len : 0)  || (mirror==true && status==WAITING_CLIENT_DATA) ;) {
		if (mirror==false) {
			client_myds->PSarrayIN->remove_index(0,&pkt);
		}
		switch (status) {

			case CONNECTING_CLIENT:
				switch (client_myds->DSS) {
					case STATE_SERVER_HANDSHAKE:
						handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(&pkt, &wrong_pass);
						break;
					case STATE_SSL_INIT:
						handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(&pkt, &wrong_pass);
						//handler___status_CONNECTING_CLIENT___STATE_SSL_INIT(&pkt);
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
							assert(0);
							break;
					}
				}
				switch (client_myds->DSS) {
					case STATE_SLEEP_MULTI_PACKET:
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
							goto __get_pkts_from_client;
						} else {
							// no more packets, move everything back to pkt and proceed
							pkt.ptr=client_myds->multi_pkt.ptr;
							pkt.size=client_myds->multi_pkt.size;
							client_myds->multi_pkt.size=0;
							client_myds->multi_pkt.ptr=NULL;
							client_myds->DSS=STATE_SLEEP;
						}
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
							mybe=find_or_create_backend(current_hostgroup); // set a backend
							mybe->server_myds->reinit_queues();             // reinitialize the queues in the myds . By default, they are not active
							mybe->server_myds->PSarrayOUT->add(pkt.ptr, pkt.size); // move the first packet
							previous_status.push(FAST_FORWARD); // next status will be FAST_FORWARD . Now we need a connection
							NEXT_IMMEDIATE(CONNECTING_SERVER);  // we create a connection . next status will be FAST_FORWARD
						}
						c=*((unsigned char *)pkt.ptr+sizeof(mysql_hdr));
						if (session_type == PROXYSQL_SESSION_CLICKHOUSE) {
							if ((enum_mysql_command)c == _MYSQL_COM_INIT_DB) {
								PtrSize_t _new_pkt;
								_new_pkt.ptr=malloc(pkt.size+4); // USE + space
								memcpy(_new_pkt.ptr , pkt.ptr, 4);
								unsigned char *_c=(unsigned char *)_new_pkt.ptr;
								_c+=4; *_c=0x03;
								_c+=1; *_c='U';
								_c+=1; *_c='S';
								_c+=1; *_c='E';
								_c+=1; *_c=' ';
//								(unsigned char *)_new_pkt.ptr[4]=0x03;
//								(unsigned char *)_new_pkt.ptr[5]='U';
//								(unsigned char *)_new_pkt.ptr[6]='S';
//								(unsigned char *)_new_pkt.ptr[7]='E';
//								(unsigned char *)_new_pkt.ptr[8]=' ';
								memcpy((char *)_new_pkt.ptr+9 , (char *)pkt.ptr+5, pkt.size-5);
								l_free(pkt.size,pkt.ptr);
								pkt.size+=4;
								pkt.ptr = _new_pkt.ptr;
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
								__sync_add_and_fetch(&thread->status_variables.queries,1);
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
									if (qpo->max_lag_ms >= 0) {
										thread->status_variables.queries_with_max_lag_ms++;
									}
									if (thread->variables.stats_time_query_processor) {
										clock_gettime(CLOCK_THREAD_CPUTIME_ID,&endt);
										thread->status_variables.query_processor_time=thread->status_variables.query_processor_time +
											(endt.tv_sec*1000000000+endt.tv_nsec) -
											(begint.tv_sec*1000000000+begint.tv_nsec);
									}
									assert(qpo);	// GloQPro->process_mysql_query() should always return a qpo
									rc_break=handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(&pkt, &lock_hostgroup);
									if (mirror==false) {
										if (mysql_thread___automatic_detect_sqli) {
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
															thread->status_variables.whitelisted_sqli_fingerprint++;
														} else {
															thread->status_variables.automatic_detected_sqli++;
															char * username = client_myds->myconn->userinfo->username;
															char * client_address = client_myds->addr.addr;
															proxy_error("SQLinjection detected with fingerprint of '%s' from client %s@%s . Query listed below:\n", state.fingerprint, username, client_address);
															fwrite(CurrentQuery.QueryPointer, CurrentQuery.QueryLength, 1, stderr);
															fprintf(stderr,"\n");
															handler_ret = -1;
															RequestEnd(NULL);
															return handler_ret;
														}
													}
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
												thread->status_variables.hostgroup_locked++;
												thread->status_variables.hostgroup_locked_set_cmds++;
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
												thread->status_variables.hostgroup_locked_queries++;
												RequestEnd(NULL);
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
											assert(0);
									}
								}
								break;
							case _MYSQL_COM_CHANGE_USER:
								handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_CHANGE_USER(&pkt, &wrong_pass);
								break;
							case _MYSQL_COM_STMT_RESET:
								{
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
								break;
							case _MYSQL_COM_STMT_CLOSE:
								{
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
								}
								l_free(pkt.size,pkt.ptr);
								// FIXME: this is not complete. Counters should be decreased
								thread->status_variables.frontend_stmt_close++;
								thread->status_variables.queries++;
								client_myds->DSS=STATE_SLEEP;
								status=WAITING_CLIENT_DATA;
								break;
							case _MYSQL_COM_STMT_SEND_LONG_DATA:
								{
									// FIXME: no input validation
									uint32_t stmt_global_id=0;
									memcpy(&stmt_global_id,(char *)pkt.ptr+5,sizeof(uint32_t));
									uint32_t stmt_param_id=0;
									memcpy(&stmt_param_id,(char *)pkt.ptr+9,sizeof(uint16_t));
									SLDH->add(stmt_global_id,stmt_param_id,(char *)pkt.ptr+11,pkt.size-11);
								}
								client_myds->DSS=STATE_SLEEP;
								status=WAITING_CLIENT_DATA;
								l_free(pkt.size,pkt.ptr);
								break;
							case _MYSQL_COM_STMT_PREPARE:
								if (session_type != PROXYSQL_SESSION_MYSQL) { // only MySQL module supports prepared statement!!
									l_free(pkt.size,pkt.ptr);
									client_myds->setDSS_STATE_QUERY_SENT_NET();
									client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"28000",(char *)"Command not supported");
									client_myds->DSS=STATE_SLEEP;
									status=WAITING_CLIENT_DATA;
									break;
								} else {
									thread->status_variables.frontend_stmt_prepare++;
									thread->status_variables.queries++;
									// if we reach here, we are not on MySQL module
									bool rc_break=false;
									bool lock_hostgroup = false;

									// Note: CurrentQuery sees the query as sent by the client.
									// shortly after, the packets it used to contain the query will be deallocated
									// Note2 : we call the next function as if it was _MYSQL_COM_QUERY
									// because the offset will be identical
									CurrentQuery.begin((unsigned char *)pkt.ptr,pkt.size,true);

									qpo=GloQPro->process_mysql_query(this,pkt.ptr,pkt.size,&CurrentQuery);
									assert(qpo);	// GloQPro->process_mysql_query() should always return a qpo
									rc_break=handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(&pkt, &lock_hostgroup);
									if (rc_break==true) {
										break;
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
												thread->status_variables.hostgroup_locked_queries++;
												RequestEnd(NULL);
												free(buf);
												l_free(pkt.size,pkt.ptr);
												break;
											}
										}
									}
									mybe=find_or_create_backend(current_hostgroup);
									if (client_myds->myconn->local_stmts==NULL) {
										client_myds->myconn->local_stmts=new MySQL_STMTs_local_v14(true);
									}
									uint64_t hash=client_myds->myconn->local_stmts->compute_hash(current_hostgroup,(char *)client_myds->myconn->userinfo->username,(char *)client_myds->myconn->userinfo->schemaname,(char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
									MySQL_STMT_Global_info *stmt_info=NULL;
									// we first lock GloStmt
									GloMyStmt->wrlock();
									stmt_info=GloMyStmt->find_prepared_statement_by_hash(hash,false);
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
									break; // make sure to not break before unlocking GloMyStmt
								}
								break;
							case _MYSQL_COM_STMT_EXECUTE:
								if (session_type != PROXYSQL_SESSION_MYSQL) { // only MySQL module supports prepared statement!!
									l_free(pkt.size,pkt.ptr);
									client_myds->setDSS_STATE_QUERY_SENT_NET();
									client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"28000",(char *)"Command not supported");
									client_myds->DSS=STATE_SLEEP;
									status=WAITING_CLIENT_DATA;
									break;
								} else {
									// if we reach here, we are on MySQL module
									thread->status_variables.frontend_stmt_execute++;
									thread->status_variables.queries++;
									//bool rc_break=false;

									uint32_t client_stmt_id=0;
									uint64_t stmt_global_id=0;
									memcpy(&client_stmt_id,(char *)pkt.ptr+5,sizeof(uint32_t));
									stmt_global_id=client_myds->myconn->local_stmts->find_global_stmt_id_from_client(client_stmt_id);
									if (stmt_global_id == 0) {
										// FIXME: add error handling
										assert(0);
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
										break;
									}
									CurrentQuery.stmt_info=stmt_info;
									CurrentQuery.start_time=thread->curtime;

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
										break;
									}
									if (stmt_meta_found==false) {
										// previously we didn't find any metadata
										// but as we reached here, stmt_meta is not null and we save the metadata
										sess_STMTs_meta->insert(stmt_global_id,stmt_meta);
									}
									// else

									CurrentQuery.stmt_meta=stmt_meta;
//									assert(qpo);	// GloQPro->process_mysql_query() should always return a qpo
									// NOTE: we do not call YET the follow function for STMT_EXECUTE
									//rc_break=handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(&pkt);
									current_hostgroup=stmt_info->hostgroup_id;
									mybe=find_or_create_backend(current_hostgroup);
									status=PROCESSING_STMT_EXECUTE;
									mybe->server_myds->connect_retries_on_failure=mysql_thread___connect_retries_on_failure;
									mybe->server_myds->wait_until=0;
									mybe->server_myds->killed_at=0;
									mybe->server_myds->kill_type=0;
									client_myds->setDSS_STATE_QUERY_SENT_NET();
								}
								break;
//							case _MYSQL_COM_STMT_PREPARE:
//								handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_PREPARE(&pkt);
//								break;
//							case _MYSQL_COM_STMT_EXECUTE:
//								handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_EXECUTE(&pkt);
//								break;
//							case _MYSQL_COM_STMT_CLOSE:
//								mybe->server_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
//								break;
							case _MYSQL_COM_QUIT:
								proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_QUIT packet\n");
								GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_QUIT, this, NULL);
								l_free(pkt.size,pkt.ptr);
								handler_ret = -1;
								return handler_ret;
								break;
							case _MYSQL_COM_PING:
								handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PING(&pkt);
								break;
							case _MYSQL_COM_SET_OPTION:
								handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_SET_OPTION(&pkt);
								break;
							case _MYSQL_COM_STATISTICS:
								handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STATISTICS(&pkt);
								break;
							case _MYSQL_COM_INIT_DB:
								handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB(&pkt);
								break;
							case _MYSQL_COM_FIELD_LIST:
								handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_FIELD_LIST(&pkt);
								break;
							case _MYSQL_COM_PROCESS_KILL:
								handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PROCESS_KILL(&pkt);
								break;
							default:
								proxy_error("RECEIVED AN UNKNOWN COMMAND: %d -- PLEASE REPORT A BUG\n", c);
								l_free(pkt.size,pkt.ptr);
								handler_ret = -1; // immediately drop the connection
								return handler_ret;
								// assert(0); // see issue #859
								break;
						}
						break;
					default:
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: WAITING_CLIENT_DATA - STATE_UNKNOWN\n");
						{
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
								proxy_error("Unexpected packet from client %s . Session_status: %d , client_status: %d Disconnecting it\n", buf, status, client_myds->status);
							}
						}
						handler_ret = -1;
						return handler_ret;
						break;
			}
				
				break;
			case FAST_FORWARD:
				mybe->server_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
				break;
			case NONE:
			default:
				{
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
						c=*((unsigned char *)pkt.ptr+sizeof(mysql_hdr));
						if (c==_MYSQL_COM_QUIT) {
							proxy_error("Unexpected COM_QUIT from client %s . Session_status: %d , client_status: %d Disconnecting it\n", buf, status, client_myds->status);
							GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_QUIT, this, NULL);
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_QUIT packet\n");
							l_free(pkt.size,pkt.ptr);
							if (thread) {
								thread->status_variables.unexpected_com_quit++;
							}
							handler_ret = -1;
							return handler_ret;
						}
					}
					proxy_error("Unexpected packet from client %s . Session_status: %d , client_status: %d Disconnecting it\n", buf, status, client_myds->status);
					if (thread) {
						thread->status_variables.unexpected_packet++;
					}
					handler_ret = -1;
					return handler_ret;
				}
				break;
		}
	}



handler_again:

	switch (status) {
		case WAITING_CLIENT_DATA:
			// housekeeping
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
			break;
		case FAST_FORWARD:
			if (mybe->server_myds->mypolls==NULL) {
				// register the mysql_data_stream
				thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
			}
			client_myds->PSarrayOUT->copy_add(mybe->server_myds->PSarrayIN, 0, mybe->server_myds->PSarrayIN->len);
			while (mybe->server_myds->PSarrayIN->len) mybe->server_myds->PSarrayIN->remove_index(mybe->server_myds->PSarrayIN->len-1,NULL);
			// copy all packets from backend to frontend
			//for (unsigned int k=0; k < mybe->server_myds->PSarrayIN->len; k++) {
			//	PtrSize_t pkt;
			//	mybe->server_myds->PSarrayIN->remove_index(0,&pkt);
			//	client_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
			//}
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
						assert(0);
						break;
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
					if (handler_again___verify_backend_user_schema()) {
						goto handler_again;
					}
					if (mirror==false) { // do not care about autocommit and charset if mirror
							proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p , default_HG=%d server_myds DSS=%d , locked_on_HG=%d\n", this, default_hostgroup, mybe->server_myds->DSS, locked_on_hostgroup);
						if (mybe->server_myds->DSS == STATE_READY || mybe->server_myds->DSS == STATE_MARIADB_GENERIC) {
							if (handler_again___verify_init_connect()) {
								goto handler_again;
							}
							if (ldap_ctx) {
								if (handler_again___verify_ldap_user_variable()) {
									goto handler_again;
								}
							}
							if (handler_again___verify_backend_autocommit()) {
								goto handler_again;
							}
							if (locked_on_hostgroup == -1 || locked_on_hostgroup_and_all_variables_set == false ) {

								if (handler_again___verify_backend_charset()) {
									goto handler_again;
								}

								for (auto i = 0; i < SQL_NAME_LAST; i++) {
									if(mysql_variables->verify_variable(i))
										goto handler_again;
								}

								if (handler_again___verify_backend_sql_log_bin()) {
									goto handler_again;
								}
								if (handler_again___verify_backend_session_track_gtids()) {
									goto handler_again;
								}
								if (handler_again___verify_backend_sql_auto_is_null()) {
									goto handler_again;
								}
								if (handler_again___verify_backend_collation_connection()) {
									goto handler_again;
								}
								if (handler_again___verify_backend_net_write_timeout()) {
									goto handler_again;
								}
								if (handler_again___verify_backend_max_join_size()) {
									goto handler_again;
								}
								if (handler_again___verify_backend_multi_statement()) {
									goto handler_again;
								}
								if (locked_on_hostgroup != -1) {
									locked_on_hostgroup_and_all_variables_set=true;
								}
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
					mybe->server_myds->wait_until=0;
					if (qpo) {
						if (qpo->timeout > 0) {
							mybe->server_myds->wait_until=thread->curtime+qpo->timeout*1000;
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
				int rc;
				timespec begint;
				if (thread->variables.stats_time_backend_query) {
					clock_gettime(CLOCK_THREAD_CPUTIME_ID,&begint);
				}
				switch (status) {
					case PROCESSING_QUERY:
						rc=myconn->async_query(myds->revents, myds->mysql_real_query.QueryPtr,myds->mysql_real_query.QuerySize);
						break;
					case PROCESSING_STMT_PREPARE:
						rc=myconn->async_query(myds->revents, (char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength,&CurrentQuery.mysql_stmt);
						break;
					case PROCESSING_STMT_EXECUTE:
						// PROCESSING_STMT_EXECUTE FIXME
						{
							rc=myconn->async_query(myds->revents, (char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength,&CurrentQuery.mysql_stmt, CurrentQuery.stmt_meta);
						}
						break;
					default:
						assert(0);
						break;
				}
				timespec endt;
				if (thread->variables.stats_time_backend_query) {
					clock_gettime(CLOCK_THREAD_CPUTIME_ID,&endt);
					thread->status_variables.backend_query_time=thread->status_variables.backend_query_time +
						(endt.tv_sec*1000000000+endt.tv_nsec) -
						(begint.tv_sec*1000000000+begint.tv_nsec);
				}
				gtid_hid = -1;
				if (rc==0) {
					if (myconn->get_gtid(mybe->gtid_uuid,&mybe->gtid_trxid)) {
						if (mysql_thread___client_session_track_gtid) {
							gtid_hid = current_hostgroup;
							memcpy(gtid_buf,mybe->gtid_uuid,sizeof(gtid_buf));
						}
					}

					// check if multiplexing needs to be disabled
					char *qdt=CurrentQuery.get_digest_text();
					if (qdt)
						myconn->ProcessQueryAndSetStatusFlags(qdt);

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
								}
							}
						}
					}

					switch (status) {
						case PROCESSING_QUERY:
							MySQL_Result_to_MySQL_wire(myconn->mysql, myconn->MyRS);
							break;
						case PROCESSING_STMT_PREPARE:
							{
								thread->status_variables.backend_stmt_prepare++;
								GloMyStmt->wrlock();
								uint32_t client_stmtid;
								uint64_t global_stmtid;
								//bool is_new;
								MySQL_STMT_Global_info *stmt_info=NULL;
									stmt_info=GloMyStmt->add_prepared_statement(current_hostgroup,
										(char *)client_myds->myconn->userinfo->username,
										(char *)client_myds->myconn->userinfo->schemaname,
										(char *)CurrentQuery.QueryPointer,
										CurrentQuery.QueryLength,
										CurrentQuery.mysql_stmt,
										qpo->cache_ttl,
										qpo->timeout,
										qpo->delay,
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
								enum session_status st=status;
								size_t sts=previous_status.size();
								if (sts) {
									myconn->async_state_machine=ASYNC_IDLE;
									myds->DSS=STATE_MARIADB_GENERIC;
									st=previous_status.top();
									previous_status.pop();
									GloMyStmt->unlock();
									NEXT_IMMEDIATE(st);
								} else {
									client_myds->myprot.generate_STMT_PREPARE_RESPONSE(client_myds->pkt_sid+1,stmt_info,client_stmtid);
									if (stmt_info->num_params == 0) {
										prepared_stmt_with_no_params = true;
									}
									LogQuery(myds);
									GloMyStmt->unlock();
								}
							}
							break;
						case PROCESSING_STMT_EXECUTE:
							{
								thread->status_variables.backend_stmt_execute++;
								MySQL_Stmt_Result_to_MySQL_wire(CurrentQuery.mysql_stmt, myds->myconn);
								LogQuery(myds);
								if (CurrentQuery.stmt_meta)
									if (CurrentQuery.stmt_meta->pkt) {
										uint32_t stmt_global_id=0;
										memcpy(&stmt_global_id,(char *)(CurrentQuery.stmt_meta->pkt)+5,sizeof(uint32_t));
										SLDH->reset(stmt_global_id);
										free(CurrentQuery.stmt_meta->pkt);
										CurrentQuery.stmt_meta->pkt=NULL;
									}
							}
							CurrentQuery.mysql_stmt=NULL;
							break;
						default:
							assert(0);
							break;
					}
					RequestEnd(myds);
					finishQuery(myds,myconn,prepared_stmt_with_no_params);
				} else {
					if (rc==-1) {
						int myerr=mysql_errno(myconn->mysql);
						char *errmsg = NULL;
						if (myerr == 0) {
							if (CurrentQuery.mysql_stmt) {
								myerr = mysql_stmt_errno(CurrentQuery.mysql_stmt);
								errmsg = strdup(mysql_stmt_error(CurrentQuery.mysql_stmt));
							}
						}
						CurrentQuery.mysql_stmt=NULL; // immediately reset mysql_stmt
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
								thread->status_variables.backend_lagging_during_query++;
								proxy_error("Detected a lagging server during query: %s, %d\n", myconn->parent->address, myconn->parent->port);
							} else {
								thread->status_variables.backend_offline_during_query++;
								proxy_error("Detected an offline server during query: %s, %d\n", myconn->parent->address, myconn->parent->port);
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
										assert(0);
										break;
								}
								NEXT_IMMEDIATE(CONNECTING_SERVER);
							}
							handler_ret = -1;
							return handler_ret;
						}
						if (myerr >= 2000 && myerr < 3000) {
							bool retry_conn=false;
							// client error, serious
							proxy_error("Detected a broken connection during query on (%d,%s,%d) , FD (Conn:%d , MyDS:%d) : %d, %s\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myds->fd, myds->myconn->fd, myerr, ( errmsg ? errmsg : mysql_error(myconn->mysql)));
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
										assert(0);
										break;
								}
								if (errmsg) {
									free(errmsg);
									errmsg = NULL;
								}
								NEXT_IMMEDIATE(CONNECTING_SERVER);
							}
							if (errmsg) {
								free(errmsg);
								errmsg = NULL;
							}
							handler_ret = -1;
							return handler_ret;
						} else {
							if (mysql_thread___verbose_query_error) {
								proxy_warning("Error during query on (%d,%s,%d) , user \"%s@%s\" , schema \"%s\" , %d, %s . digest_text = \"%s\"\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, client_myds->myconn->userinfo->username, (client_myds->addr.addr ? client_myds->addr.addr : (char *)"unknown" ), client_myds->myconn->userinfo->schemaname, myerr, ( errmsg ? errmsg : mysql_error(myconn->mysql)), CurrentQuery.QueryParserArgs.digest_text );
							} else {
								proxy_warning("Error during query on (%d,%s,%d): %d, %s\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myerr, ( errmsg ? errmsg : mysql_error(myconn->mysql)));
							}
							MyHGM->add_mysql_errors(myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, client_myds->myconn->userinfo->username, (client_myds->addr.addr ? client_myds->addr.addr : (char *)"unknown" ), client_myds->myconn->userinfo->schemaname, myerr, (char *)( errmsg ? errmsg : mysql_error(myconn->mysql)));
							bool retry_conn=false;
							switch (myerr) {
								case 1317:  // Query execution was interrupted
									if (killed==true) { // this session is being kiled
										handler_ret = -1;
										return handler_ret;
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
									myconn = myds->myconn; // re-initialize
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
										default:
											assert(0);
											break;
										}
										if (errmsg) {
											free(errmsg);
											errmsg = NULL;
										}
										NEXT_IMMEDIATE(CONNECTING_SERVER);
									}
									//handler_ret = -1;
									//return handler_ret;
									break;
								case 1153: // ER_NET_PACKET_TOO_LARGE
									proxy_warning("Error ER_NET_PACKET_TOO_LARGE during query on (%d,%s,%d): %d, %s\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myerr, mysql_error(myconn->mysql));
									break;
								default:
									break; // continue normally
							}

							switch (status) {
								case PROCESSING_QUERY:
									if (myconn) {
										MySQL_Result_to_MySQL_wire(myconn->mysql, myconn->MyRS, myds);
									} else {
										MySQL_Result_to_MySQL_wire(NULL, NULL, myds);
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
											sprintf(sqlstate,"%s",mysql_sqlstate(myconn->mysql));
											client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,mysql_errno(myconn->mysql),sqlstate,(char *)mysql_stmt_error(myconn->query.stmt));
										} else {
											client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1, 2013, (char *)"HY000" ,(char *)"Lost connection to MySQL server during query");
										}
										client_myds->pkt_sid++;
									}
									break;
								default:
									assert(0);
									break;
							}
							RequestEnd(myds);
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
								MySQL_Result_to_MySQL_wire(myconn->mysql, myconn->MyRS);
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

				goto __exit_DSS__STATE_NOT_INITIALIZED;


			}
			break;

		case CHANGING_USER_SERVER:
			{
				int rc=0;
				if (handler_again___status_CHANGING_USER_SERVER(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) { // we have an error we can't handle
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case CHANGING_AUTOCOMMIT:
			{
				int rc=0;
				if (handler_again___status_CHANGING_AUTOCOMMIT(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) { // we have an error we can't handle
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case CHANGING_CHARSET:
			{
				int rc=0;
				if (handler_again___status_CHANGING_CHARSET(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) { // we have an error we can't handle
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;
		case SETTING_CHARSET:
			{
				int rc=0;
				if (handler_again___status_SETTING_CHARSET(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) { // we have an error we can't handle
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case SETTING_MULTI_STMT:
			{
				int rc=0;
				if (handler_again___status_SETTING_MULTI_STMT(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) { // we have an error we can't handle
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case SETTING_SQL_LOG_BIN:
			{
				int rc=0;
				if (handler_again___status_SETTING_SQL_LOG_BIN(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) { // we have an error we can't handle
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case SETTING_SESSION_TRACK_GTIDS:
			{
				int rc=0;
				if (handler_again___status_SETTING_SESSION_TRACK_GTIDS(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) { // we have an error we can't handle
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case SETTING_SQL_AUTO_IS_NULL:
			{
				int rc=0;
				if (handler_again___status_SETTING_SQL_AUTO_IS_NULL(&rc))
					goto handler_again; // we changed status
				if (rc==-1) { // we have an error we can't handle
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case SETTING_SQL_MODE:
		case SETTING_SQL_SELECT_LIMIT:
		case SETTING_SQL_SAFE_UPDATES:
		case SETTING_TIME_ZONE:
		case SETTING_CHARACTER_SET_RESULTS:
		case SETTING_ISOLATION_LEVEL:
		case SETTING_TRANSACTION_READ:
			for (auto i = 0; i < SQL_NAME_LAST; i++) {
				int rc = 0;
				if (mysql_variables->update_variable(rc)) {
					goto handler_again;
				}
				if (rc == -1) {
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case SETTING_COLLATION_CONNECTION:
			{
				int rc=0;
				if (handler_again___status_SETTING_COLLATION_CONNECTION(&rc))
					goto handler_again; // we changed status
				if (rc==-1) { // we have an error we can't handle
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case SETTING_NET_WRITE_TIMEOUT:
			{
				int rc=0;
				if (handler_again___status_SETTING_NET_WRITE_TIMEOUT(&rc))
					goto handler_again; // we changed status
				if (rc==-1) { // we have an error we can't handle
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case SETTING_MAX_JOIN_SIZE:
			{
				int rc=0;
				if (handler_again___status_SETTING_MAX_JOIN_SIZE(&rc))
					goto handler_again; // we changed status
				if (rc==-1) { // we have an error we can't handle
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case SETTING_INIT_CONNECT:
			{
				int rc=0;
				if (handler_again___status_SETTING_INIT_CONNECT(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) { // we have an error we can't handle
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case SETTING_LDAP_USER_VARIABLE:
			{
				int rc=0;
				if (handler_again___status_SETTING_LDAP_USER_VARIABLE(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) { // we have an error we can't handle
					handler_ret = -1;
					return handler_ret;
				}
			}
			break;

		case CHANGING_SCHEMA:
			{
				int rc=0;
				if (handler_again___status_CHANGING_SCHEMA(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) { // we have an error we can't handle
					handler_ret = -1;
					return handler_ret;
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
		case NONE:
			fprintf(stderr,"NONE\n");
		default:
			break;
	}


__exit_DSS__STATE_NOT_INITIALIZED:
		

	if (mybe && mybe->server_myds) {
	if (mybe->server_myds->DSS > STATE_MARIADB_BEGIN && mybe->server_myds->DSS < STATE_MARIADB_END) {
#ifdef DEBUG
		MySQL_Data_Stream *myds=mybe->server_myds;
		MySQL_Connection *myconn=mybe->server_myds->myconn;
#endif /* DEBUG */
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, status=%d, server_myds->DSS==%d , revents==%d , async_state_machine=%d\n", this, status, mybe->server_myds->DSS, myds->revents, myconn->async_state_machine);
	}
	}

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


void MySQL_Session::handler___status_WAITING_SERVER_DATA___STATE_READING_COM_STMT_PREPARE_RESPONSE(PtrSize_t *pkt) {
	unsigned char c;
	c=*((unsigned char *)pkt->ptr+sizeof(mysql_hdr));

	//fprintf(stderr,"%d %d\n", mybe->server_myds->myprot.current_PreStmt->pending_num_params, mybe->server_myds->myprot.current_PreStmt->pending_num_columns);
	if (c==0xfe && pkt->size < 13) {
		if (mybe->server_myds->myprot.current_PreStmt->pending_num_params+mybe->server_myds->myprot.current_PreStmt->pending_num_columns) {
			mybe->server_myds->DSS=STATE_EOF1;
		} else {
			mybe->server_myds->myconn->processing_prepared_statement_prepare=false;
			client_myds->myconn->processing_prepared_statement_prepare=false;
			mybe->server_myds->DSS=STATE_READY;
			status=WAITING_CLIENT_DATA;
			client_myds->DSS=STATE_SLEEP;
		}
	} else {
		if (mybe->server_myds->myprot.current_PreStmt->pending_num_params) {
			--mybe->server_myds->myprot.current_PreStmt->pending_num_params;
		} else {
			if (mybe->server_myds->myprot.current_PreStmt->pending_num_columns) {
				--mybe->server_myds->myprot.current_PreStmt->pending_num_columns;
			}
		}
	}
	client_myds->PSarrayOUT->add(pkt->ptr, pkt->size);
}


void MySQL_Session::handler___status_CHANGING_USER_CLIENT___STATE_CLIENT_HANDSHAKE(PtrSize_t *pkt, bool *wrong_pass) {
	// FIXME: no support for SSL yet
	if (
		client_myds->myprot.process_pkt_auth_swich_response((unsigned char *)pkt->ptr,pkt->size)==true
	) {
		l_free(pkt->size,pkt->ptr);
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session=%p , DS=%p . Successful connection\n", this, client_myds);
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,2,0,0,0,0,NULL);
		GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_CHANGE_USER_OK, this, NULL);
		status=WAITING_CLIENT_DATA;
		client_myds->DSS=STATE_SLEEP;
	} else {
		l_free(pkt->size,pkt->ptr);
		*wrong_pass=true;
		// FIXME: this should become close connection
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		char *client_addr=NULL;
		if (client_myds->client_addr) {
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
		char *_s=(char *)malloc(strlen(client_myds->myconn->userinfo->username)+100+strlen(client_addr));
		sprintf(_s,"ProxySQL Error: Access denied for user '%s'@'%s' (using password: %s)", client_myds->myconn->userinfo->username, client_addr, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
		proxy_error("ProxySQL Error: Access denied for user '%s'@'%s' (using password: %s)", client_myds->myconn->userinfo->username, client_addr, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,2,1045,(char *)"28000", _s, true);
#ifdef DEBUG
		if (client_myds->myconn->userinfo->password) {
			char *tmp_pass=strdup(client_myds->myconn->userinfo->password);
			int lpass = strlen(tmp_pass);
			for (int i=2; i<lpass-1; i++) {
				tmp_pass[i]='*';
			}
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session=%p , DS=%p . Wrong credentials for frontend: %s:%s . Password=%s . Disconnecting\n", this, client_myds, client_myds->myconn->userinfo->username, client_addr, tmp_pass);
			free(tmp_pass);
		} else {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session=%p , DS=%p . Wrong credentials for frontend: %s:%s . No password. Disconnecting\n", this, client_myds, client_myds->myconn->userinfo->username, client_addr);
		}
#endif //DEBUG
		GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_CHANGE_USER_ERR, this, NULL);
		free(_s);
		__sync_fetch_and_add(&MyHGM->status.access_denied_wrong_password, 1);
	}
}

void MySQL_Session::handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(PtrSize_t *pkt, bool *wrong_pass) {
	bool is_encrypted = client_myds->encrypted;
	bool handshake_response_return = client_myds->myprot.process_pkt_handshake_response((unsigned char *)pkt->ptr,pkt->size);

	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION,8,"Session=%p , DS=%p , handshake_response=%d , switching_auth_stage=%d , is_encrypted=%d , client_encrypted=%d\n", this, client_myds, handshake_response_return, client_myds->switching_auth_stage, is_encrypted, client_myds->encrypted);
	if (
		(handshake_response_return == false) && (client_myds->switching_auth_stage == 1)
	) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION,8,"Session=%p , DS=%p . Returning\n", this, client_myds);
		return;
	}
	
	if (
		(is_encrypted == false) && // the connection was encrypted
		(handshake_response_return == false) && // the authentication didn't complete
		(client_myds->encrypted == true) // client is asking for encryption
	) {
		// use SSL
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION,8,"Session=%p , DS=%p . SSL_INIT\n", this, client_myds);
		client_myds->DSS=STATE_SSL_INIT;
		client_myds->rbio_ssl = BIO_new(BIO_s_mem());
		client_myds->wbio_ssl = BIO_new(BIO_s_mem());
		client_myds->ssl=SSL_new(GloVars.global.ssl_ctx);
		SSL_set_fd(client_myds->ssl, client_myds->fd);
		SSL_set_accept_state(client_myds->ssl); 
		SSL_set_bio(client_myds->ssl, client_myds->rbio_ssl, client_myds->wbio_ssl);
/*
		while (!SSL_is_init_finished(client_myds->ssl)) {
            int ret = SSL_do_handshake(client_myds->ssl);
            int ret2;
            if (ret != 1) {
                //ERR_print_errors_fp(stderr);
                ret2 = SSL_get_error(client_myds->ssl, ret);
                fprintf(stderr,"%d\n",ret2);
            }

		}			
*/
//		if (!SSL_is_init_finished(client_myds->ssl)) {
//			int n = SSL_do_handshake(client_myds->ssl);
//			
//		}
		//ioctl_FIONBIO(client_myds->fd,0);

//		bool connected = false;
//		while (connected) {	
//		if (!SSL_accept(client_myds->ssl)==-1) {
//		if (SSL_do_handshake(client_myds->ssl)==-1) {
//			ERR_print_errors_fp(stderr);
//		} else {
//			connected = true;
//		}
//		}
		//ioctl_FIONBIO(client_myds->fd,1);
		//int my_ssl_error;
		//int n = SSL_accept(client_myds->ssl);
		//my_ssl_error = SSL_get_error(client_mmyds->ssl);
		return;
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
						if (ldap_ctx==NULL) {
							free_users=GloMyAuth->increase_frontend_user_connections(client_myds->myconn->userinfo->username, &used_users);
						} else {
							free_users=GloMyLdapAuth->increase_frontend_user_connections(client_myds->myconn->userinfo->username, &used_users);
						}
						break;
#ifdef PROXYSQLCLICKHOUSE
					case PROXYSQL_SESSION_CLICKHOUSE:
						free_users=GloClickHouseAuth->increase_frontend_user_connections(client_myds->myconn->userinfo->username, &used_users);
						break;
#endif /* PROXYSQLCLICKHOUSE */
					default:
						assert(0);
						break;
				}
			} else {
				free_users=1;
			}
			if (max_connections_reached==true || free_users<=0) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION,8,"Session=%p , DS=%p , max_connections_reached=%d , free_users=%d\n", this, client_myds, max_connections_reached, free_users);
				client_authenticated=false;
				*wrong_pass=true;
				client_myds->setDSS_STATE_QUERY_SENT_NET();
				uint8_t _pid = 2;
				if (client_myds->switching_auth_stage) _pid+=2;
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
					GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_ERR, this, NULL, b);
					sprintf(b,a,client_myds->myconn->userinfo->username,used_users);
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
					uint8_t _pid = 2;
					if (client_myds->switching_auth_stage) _pid+=2;
					if (is_encrypted) _pid++;
					if (
						(strcmp(client_addr,(char *)"127.0.0.1")==0)
						||
						(strcmp(client_addr,(char *)"localhost")==0)
						||
						(strcmp(client_addr,(char *)"::1")==0)
					) {
						// we are good!
						//client_myds->myprot.generate_pkt_OK(true,NULL,NULL, (is_encrypted ? 3 : 2), 0,0,0,0,NULL);
						client_myds->myprot.generate_pkt_OK(true,NULL,NULL, _pid, 0,0,0,0,NULL);
						GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_OK, this, NULL);
						status=WAITING_CLIENT_DATA;
						client_myds->DSS=STATE_CLIENT_AUTH_OK;
					} else {
						char *a=(char *)"User '%s' can only connect locally";
						char *b=(char *)malloc(strlen(a)+strlen(client_myds->myconn->userinfo->username));
						sprintf(b,a,client_myds->myconn->userinfo->username);
						//client_myds->myprot.generate_pkt_ERR(true,NULL,NULL, (is_encrypted ? 3 : 2), 1040,(char *)"42000", b, true);
							GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_ERR, this, NULL, b);
						client_myds->myprot.generate_pkt_ERR(true,NULL,NULL, _pid, 1040,(char *)"42000", b, true);
						free(b);
					}
					free(addr);
					free(client_addr);
				} else {
					uint8_t _pid = 2;
					if (client_myds->switching_auth_stage) _pid+=2;
					if (is_encrypted) _pid++;
					if (use_ssl == true && is_encrypted == false) {
						*wrong_pass=true;
						GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_ERR, this, NULL);
						
						char *_a=(char *)"ProxySQL Error: Access denied for user '%s' (using password: %s). SSL is required";
						char *_s=(char *)malloc(strlen(_a)+strlen(client_myds->myconn->userinfo->username)+32);
						sprintf(_s, _a, client_myds->myconn->userinfo->username, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
						client_myds->myprot.generate_pkt_ERR(true,NULL,NULL, _pid, 1045,(char *)"28000", _s, true);
						proxy_error("ProxySQL Error: Access denied for user '%s' (using password: %s). SSL is required", client_myds->myconn->userinfo->username, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION,8,"Session=%p , DS=%p . Access denied for user '%s' (using password: %s). SSL is required\n", this, client_myds, client_myds->myconn->userinfo->username, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
						__sync_add_and_fetch(&MyHGM->status.client_connections_aborted,1);
						free(_s);
						__sync_fetch_and_add(&MyHGM->status.access_denied_wrong_password, 1);
					} else {
						// we are good!
						//client_myds->myprot.generate_pkt_OK(true,NULL,NULL, (is_encrypted ? 3 : 2), 0,0,0,0,NULL);
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION,8,"Session=%p , DS=%p . STATE_CLIENT_AUTH_OK\n", this, client_myds);
						GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_OK, this, NULL);
						client_myds->myprot.generate_pkt_OK(true,NULL,NULL, _pid, 0,0,0,0,NULL);
						status=WAITING_CLIENT_DATA;
						client_myds->DSS=STATE_CLIENT_AUTH_OK;
					}
				}
			}
//		} else {
/*
			// use SSL
			client_myds->DSS=STATE_SSL_INIT;
			client_myds->ssl=SSL_new(GloVars.global.ssl_ctx);
			SSL_set_fd(client_myds->ssl, client_myds->fd);
			ioctl_FIONBIO(client_myds->fd,0);
			if (SSL_accept(client_myds->ssl)==-1) {
				ERR_print_errors_fp(stderr);
			}
			ioctl_FIONBIO(client_myds->fd,1);
*/
//		}
	} else {
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
			uint8_t _pid = 2;
			if (client_myds->switching_auth_stage) _pid+=2;
			if (is_encrypted) _pid++;
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
		GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_ERR, this, NULL);
		__sync_add_and_fetch(&MyHGM->status.client_connections_aborted,1);
		client_myds->DSS=STATE_SLEEP;
	}
}

void MySQL_Session::handler___status_CONNECTING_CLIENT___STATE_SSL_INIT(PtrSize_t *pkt) {
/*
	if (client_myds->myprot.process_pkt_handshake_response((unsigned char *)pkt->ptr,pkt->size)==true) {
		l_free(pkt->size,pkt->ptr);
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,3,0,0,0,0,NULL);
		mybe->server_myds->myconn->userinfo->set(client_myds->myconn->userinfo);
		status=WAITING_CLIENT_DATA;
		client_myds->DSS=STATE_SLEEP;
	} else {
		l_free(pkt->size,pkt->ptr);
		// FIXME: this should become close connection
		perror("Hitting a not implemented feature: https://github.com/sysown/proxysql-0.2/issues/124");
		assert(0);
	}	
*/
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
	if (v==1) { // disabled. MYSQL_OPTION_MULTI_STATEMENTS_OFF == 1
		client_myds->myprot.generate_pkt_EOF(true,NULL,NULL,1,0, setStatus );
		client_myds->myconn->options.client_flag &= ~CLIENT_MULTI_STATEMENTS;
	} else { // enabled, MYSQL_OPTION_MULTI_STATEMENTS_ON == 0
		client_myds->myprot.generate_pkt_EOF(true,NULL,NULL,1,0, setStatus );
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

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_PREPARE(PtrSize_t *pkt) {
	if (session_type == PROXYSQL_SESSION_MYSQL) {
		client_myds->myconn->has_prepared_statement=true;
		client_myds->myconn->processing_prepared_statement_prepare=true;
		mybe=find_or_create_backend(default_hostgroup);
		mybe->server_myds->PSarrayOUT->add(pkt->ptr, pkt->size);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
	} else {
		l_free(pkt->size,pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"28000",(char *)"Command not supported");
		client_myds->DSS=STATE_SLEEP;
	}
}

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_STMT_EXECUTE(PtrSize_t *pkt) {
	if (session_type == PROXYSQL_SESSION_MYSQL) {
		client_myds->myconn->processing_prepared_statement_execute=true;
		mybe=find_or_create_backend(default_hostgroup);
		mybe->server_myds->PSarrayOUT->add(pkt->ptr, pkt->size);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
	} else {
		l_free(pkt->size,pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"28000",(char *)"Command not supported");
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
		char *schemaname=strndup((char *)pkt->ptr+sizeof(mysql_hdr)+5,pkt->size-sizeof(mysql_hdr)-5);
		char *schemanameptr=trim_spaces_and_quotes_in_place(schemaname);
/*
		//remove leading spaces
		while(isspace((unsigned char)*schemanameptr)) schemanameptr++;
		// remove trailing semicolon , issue #915
		if (schemanameptr[strlen(schemanameptr)-1]==';') {
			schemanameptr[strlen(schemanameptr)-1]='\0';
		}
*/
		// handle cases like "USE `schemaname`
		if(schemanameptr[0]=='`' && schemanameptr[strlen(schemanameptr)-1]=='`') {
			schemanameptr[strlen(schemanameptr)-1]='\0';
			schemanameptr++;
		}
		client_myds->myconn->userinfo->set_schemaname(schemanameptr,strlen(schemanameptr));
		free(schemaname);
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

bool MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(PtrSize_t *pkt, bool *lock_hostgroup, bool prepared) {
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
	bool ret = false;
	bool exit_after_SetParse = false;
	unsigned char command_type=*((unsigned char *)pkt->ptr+sizeof(mysql_hdr));
	if (qpo->new_query) {
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
			thread->status_variables.query_processor_time=thread->status_variables.query_processor_time +
				(endt.tv_sec*1000000000+endt.tv_nsec) -
				(begint.tv_sec*1000000000+begint.tv_nsec);
		}
	}

	if (pkt->size > (unsigned int) mysql_thread___max_allowed_packet) {
		// ER_NET_PACKET_TOO_LARGE
		client_myds->DSS=STATE_QUERY_SENT_NET;
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,1153,(char *)"08S01",(char *)"Got a packet bigger than 'max_allowed_packet' bytes", true);
		RequestEnd(NULL);
		l_free(pkt->size,pkt->ptr);
		return true;
	}

	if (qpo->OK_msg) {
		gtid_hid = -1;
		client_myds->DSS=STATE_QUERY_SENT_NET;
		unsigned int nTrx=NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,client_myds->pkt_sid+1,0,0,setStatus,0,qpo->OK_msg);
		RequestEnd(NULL);
		l_free(pkt->size,pkt->ptr);
		return true;
	}

	if (qpo->error_msg) {
		client_myds->DSS=STATE_QUERY_SENT_NET;
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,1148,(char *)"42000",qpo->error_msg);
		RequestEnd(NULL);
		l_free(pkt->size,pkt->ptr);
		return true;
	}

	if (prepared) {	// for prepared statement we exit here
		goto __exit_set_destination_hostgroup;
	}

	// handle here #509, #815 and #816
	if (CurrentQuery.QueryParserArgs.digest_text) {
		char *dig=CurrentQuery.QueryParserArgs.digest_text;
		unsigned int nTrx=NumActiveTransactions();
		if ((locked_on_hostgroup == -1) && (strncasecmp(dig,(char *)"SET ",4)==0)) {
			// this code is executed only if locked_on_hostgroup is not set yet
#ifdef DEBUG
			{
				string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Parsing SET command = %s\n", nqn.c_str());
			}
#endif
			if (index(dig,';')) {
				string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
				proxy_warning("Unable to parse multi-statements command with SET statement: setting lock hostgroup . Command: %s\n", nqn.c_str());
				*lock_hostgroup = true;
				return false;
			}
			int rc;
			string nq=string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
			RE2::GlobalReplace(&nq,(char *)"^/\\*!\\d\\d\\d\\d\\d SET(.*)\\*/",(char *)"SET\\1");
			RE2::GlobalReplace(&nq,(char *)"(?U)/\\*.*\\*/",(char *)"");
			if (match_regexes && match_regexes[0]->match(dig)) {
				re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
				opt2->set_case_sensitive(false);
				char *pattern=(char *)"(?: *)SET *(?:|SESSION +|@@|@@session.)SQL_LOG_BIN *(?:|:)= *(\\d+) *(?:(|;|-- .*|#.*))$";
				re2::RE2 *re=new RE2(pattern, *opt2);
				int i;
				rc=RE2::PartialMatch(nq, *re, &i);
				delete re;
				delete opt2;
				if (rc && ( i==0 || i==1) ) {
					//fprintf(stderr,"sql_log_bin=%d\n", i);
					client_myds->myconn->options.sql_log_bin=i;
#ifdef DEBUG
					proxy_info("Setting SQL_LOG_BIN to %d\n", i);
#endif
#ifdef DEBUG
					{
						string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
						proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Setting SQL_LOG_BIN to %d for query: %s\n", i, nqn.c_str());
					}
#endif
					if (command_type == _MYSQL_COM_QUERY) {
						client_myds->DSS=STATE_QUERY_SENT_NET;
						uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
						if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
						client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
						client_myds->DSS=STATE_SLEEP;
						status=WAITING_CLIENT_DATA;
						RequestEnd(NULL);
						l_free(pkt->size,pkt->ptr);
						return true;
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
						return true;
					} else {
						string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
						proxy_error("Unable to parse query. If correct, report it as a bug: %s\n", nqn.c_str());
						unable_to_parse_set_statement(lock_hostgroup);
						return false;
					}
				}
			}
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
				std::map<std::string, std::vector<std::string>> set = parser.parse1();
				for(auto it = std::begin(set); it != std::end(set); ++it) {
					std::string var = it->first;
					proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET variable %s\n", var.c_str());
					if (it->second.size() < 1 || it->second.size() > 2) {
						// error not enough arguments
						string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
						proxy_error("Unable to parse query. If correct, report it as a bug: %s\n", nqn.c_str());
						proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Locking hostgroup for query %s\n", nqn.c_str());
						unable_to_parse_set_statement(lock_hostgroup);
						return false;
					}
					auto values = std::begin(it->second);
					if (var == "sql_mode") {
						std::string value1 = *values;
						if (
							( strcasecmp(value1.c_str(),(char *)"CONCAT") == 0 )
							||
							( strcasecmp(value1.c_str(),(char *)"REPLACE") == 0 )
							||
							( strcasecmp(value1.c_str(),(char *)"IFNULL") == 0 )
						) {
							string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
							proxy_error("Unable to parse query. If correct, report it as a bug: %s\n", nqn.c_str());
							proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Locking hostgroup for query %s\n", nqn.c_str());
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
						if (mysql_variables->client_get_hash(SQL_SQL_MODE) != sql_mode_int) {
							mysql_variables->client_set_value(SQL_SQL_MODE, value1.c_str());
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection SQL Mode to %s\n", value1.c_str());
						}
						exit_after_SetParse = true;
					} else if (var == "sql_auto_is_null") {
						std::string value1 = *values;
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET sql_auto_is_null value %s\n", value1.c_str());
						int __tmp_value = -1;
						if (
							(strcasecmp(value1.c_str(),(char *)"0")==0) ||
							(strcasecmp(value1.c_str(),(char *)"false")==0) ||
							(strcasecmp(value1.c_str(),(char *)"off")==0)
						) {
							__tmp_value = 0;
						} else {
							if (
								(strcasecmp(value1.c_str(),(char *)"1")==0) ||
								(strcasecmp(value1.c_str(),(char *)"true")==0) ||
								(strcasecmp(value1.c_str(),(char *)"on")==0)
							) {
								__tmp_value = 1;
							}
						}
						if (__tmp_value >= 0) {
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 7, "Processing SET sql_auto_is_null value %s\n", value1.c_str());
							uint32_t sql_auto_is_null_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
							if (client_myds->myconn->options.sql_auto_is_null_int != sql_auto_is_null_int) {
								client_myds->myconn->options.sql_auto_is_null_int = sql_auto_is_null_int;
								if (client_myds->myconn->options.sql_auto_is_null) {
									free(client_myds->myconn->options.sql_auto_is_null);
								}
								proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Changing connection sql_auto_is_null to %s\n", value1.c_str());
								client_myds->myconn->options.sql_auto_is_null=strdup(value1.c_str());
							}
							exit_after_SetParse = true;
						} else {
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
					} else if (var == "sql_safe_updates") {
						std::string value1 = *values;
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET sql_safe_updates value %s\n", value1.c_str());
						int __tmp_value = -1;
						if (
							(strcasecmp(value1.c_str(),(char *)"0")==0) ||
							(strcasecmp(value1.c_str(),(char *)"false")==0) ||
							(strcasecmp(value1.c_str(),(char *)"off")==0)
						) {
							__tmp_value = 0;
						} else {
							if (
								(strcasecmp(value1.c_str(),(char *)"1")==0) ||
								(strcasecmp(value1.c_str(),(char *)"true")==0) ||
								(strcasecmp(value1.c_str(),(char *)"on")==0)
							) {
								__tmp_value = 1;
							}
						}
						if (__tmp_value >= 0) {
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 7, "Processing SET sql_safe_updates value %s\n", value1.c_str());
							uint32_t sql_safe_updates_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
							if (mysql_variables->client_get_hash(SQL_SAFE_UPDATES) != sql_safe_updates_int) {
								mysql_variables->client_set_value(SQL_SAFE_UPDATES, value1.c_str());
								proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Changing connection sql_safe_updates to %s\n", value1.c_str());
							}
							exit_after_SetParse = true;
						} else {
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
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
									exit_after_SetParse = true;
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
								exit_after_SetParse = true;
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
						uint32_t time_zone_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
						if (mysql_variables->client_get_hash(SQL_TIME_ZONE) != time_zone_int) {
							mysql_variables->client_set_value(SQL_TIME_ZONE, value1.c_str());
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection Time zone to %s\n", value1.c_str());
						}
						exit_after_SetParse = true;
					} else if (var == "session_track_gtids") {
						std::string value1 = *values;
						if ((strcasecmp(value1.c_str(),"OWN_GTID")==0) || (strcasecmp(value1.c_str(),"OFF")==0)) {
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
							exit_after_SetParse = true;
						} else {
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
					} else if (var == "max_join_size") {
						std::string value1 = *values;
						int vl = strlen(value1.c_str());
						const char *v = value1.c_str();
						bool only_digit_chars = true;
						for (int i=0; i<vl && only_digit_chars==true; i++) {
							if (is_digit(v[i])==0) {
								only_digit_chars=false;
							}
						}
						if (only_digit_chars) {
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 7, "Processing SET max_join_size value %s\n", value1.c_str());
							uint32_t max_join_size_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
							if (client_myds->myconn->options.max_join_size_int != max_join_size_int) {
								client_myds->myconn->options.max_join_size_int = max_join_size_int;
								if (client_myds->myconn->options.max_join_size) {
									free(client_myds->myconn->options.max_join_size);
								}
								proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Changing connection max_join_size to %s\n", value1.c_str());
								client_myds->myconn->options.max_join_size=strdup(value1.c_str());
							}
							exit_after_SetParse = true;
						} else {
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
					} else if (var == "net_write_timeout") {
						std::string value1 = *values;
						int vl = strlen(value1.c_str());
						const char *v = value1.c_str();
						bool only_digit_chars = true;
						for (int i=0; i<vl && only_digit_chars==true; i++) {
							if (is_digit(v[i])==0) {
								only_digit_chars=false;
							}
						}
						if (only_digit_chars) {
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 7, "Processing SET net_write_timeout value %s\n", value1.c_str());
							uint32_t net_write_timeout_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
							if (client_myds->myconn->options.net_write_timeout_int != net_write_timeout_int) {
								client_myds->myconn->options.net_write_timeout_int = net_write_timeout_int;
								if (client_myds->myconn->options.net_write_timeout) {
									free(client_myds->myconn->options.net_write_timeout);
								}
								proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Changing connection net_write_timeout to %s\n", value1.c_str());
								client_myds->myconn->options.net_write_timeout=strdup(value1.c_str());
							}
							exit_after_SetParse = true;
						} else {
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
					} else if (var == "sql_select_limit") {
						std::string value1 = *values;
						int vl = strlen(value1.c_str());
						const char *v = value1.c_str();
						bool only_digit_chars = true;
						for (int i=0; i<vl && only_digit_chars==true; i++) {
							if (is_digit(v[i])==0) {
								only_digit_chars=false;
							}
						}
						if (!only_digit_chars) {
							if (strcasecmp(v,"default")==0) {
								only_digit_chars = true;
							}
						}
						if (only_digit_chars) {
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 7, "Processing SET sql_select_limit value %s\n", value1.c_str());
							uint32_t sql_select_limit_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
							if (mysql_variables->client_get_hash(SQL_SELECT_LIMIT) != sql_select_limit_int) {
								mysql_variables->client_set_value(SQL_SELECT_LIMIT, value1.c_str());
								proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Changing connection sql_select_limit to %s\n", value1.c_str());
							}
							exit_after_SetParse = true;
						} else {
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
					} else if (var == "collation_connection") {
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
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 7, "Processing SET collation_connection value %s\n", value1.c_str());
							uint32_t collation_connection_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
							if (client_myds->myconn->options.collation_connection_int != collation_connection_int) {
								client_myds->myconn->options.collation_connection_int = collation_connection_int;
								if (client_myds->myconn->options.collation_connection) {
									free(client_myds->myconn->options.collation_connection);
								}
								proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Changing connection collation_connection to %s\n", value1.c_str());
								client_myds->myconn->options.collation_connection=strdup(value1.c_str());
							}
							exit_after_SetParse = true;
						} else {
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
					} else if (var == "character_set_results") {
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
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 7, "Processing SET character_set_results value %s\n", value1.c_str());
							uint32_t character_set_results_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
							if (mysql_variables->client_get_hash(SQL_CHARACTER_SET_RESULTS) != character_set_results_int) {
								mysql_variables->client_set_value(SQL_CHARACTER_SET_RESULTS, value1.c_str());
								proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Changing connection character_set_results to %s\n", value1.c_str());
							}
							exit_after_SetParse = true;
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
							exit_after_SetParse = true;
						}
					} else if (var == "tx_isolation") {
						std::string value1 = *values;
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET tx_isolation value %s\n", value1.c_str());
						auto pos = value1.find('-');
						if (pos != std::string::npos)
							value1[pos] = ' ';
						uint32_t isolation_level_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
						if (mysql_variables->client_get_hash(SQL_ISOLATION_LEVEL) != isolation_level_int) {
							mysql_variables->client_set_value(SQL_ISOLATION_LEVEL, value1.c_str());
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection TX ISOLATION to %s\n", value1.c_str());
						}
						exit_after_SetParse = true;
					} else {
						std::string value1 = *values;
						std::size_t found_at = value1.find("@");
						if (found_at != std::string::npos) {
							unable_to_parse_set_statement(lock_hostgroup);
							return false;
						}
					}
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
					int query_no_space_length = nq.length();
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
						if (mysql_variables->client_get_hash(SQL_SQL_MODE) != sql_mode_int) {
							mysql_variables->client_set_value(SQL_SQL_MODE, s1.c_str());
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
								string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
								proxy_error("Unable to parse query. If correct, report it as a bug: %s\n", nqn.c_str());
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
						client_myds->DSS=STATE_SLEEP;
						status=WAITING_CLIENT_DATA;
						RequestEnd(NULL);
						l_free(pkt->size,pkt->ptr);
						return true;
					}
				}
			} else if (match_regexes && match_regexes[2]->match(dig)) {
				SetParser parser(nq);
				std::map<std::string, std::vector<std::string>> set = parser.parse2();
				for(auto it = std::begin(set); it != std::end(set); ++it) {
					std::string var = it->first;
					auto values = std::begin(it->second);
					proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET variable %s\n", var.c_str());
					if (var == "isolation level") {
						std::string value1 = *values;
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET SESSION TRANSACTION ISOLATION LEVEL value %s\n", value1.c_str());
						uint32_t isolation_level_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
						if (mysql_variables->client_get_hash(SQL_ISOLATION_LEVEL) != isolation_level_int) {
							mysql_variables->client_set_value(SQL_ISOLATION_LEVEL, value1.c_str());
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection TRANSACTION ISOLATION LEVEL to %s\n", value1.c_str());
						}
						exit_after_SetParse = true;
					} else if (var == "read") {
						std::string value1 = *values;
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET SESSION TRANSACTION READ value %s\n", value1.c_str());
						uint32_t transaction_read_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
						if (mysql_variables->client_get_hash(SQL_TRANSACTION_READ) != transaction_read_int) {
							mysql_variables->client_set_value(SQL_TRANSACTION_READ, value1.c_str());
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection TRANSACTION READ to %s\n", value1.c_str());
						}
						exit_after_SetParse = true;
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
						client_myds->DSS=STATE_SLEEP;
						status=WAITING_CLIENT_DATA;
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
					exit_after_SetParse = true;
				}
				if (exit_after_SetParse) {
					if (command_type == _MYSQL_COM_QUERY) {
						client_myds->DSS=STATE_QUERY_SENT_NET;
						uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
						if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
						client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
						client_myds->DSS=STATE_SLEEP;
						status=WAITING_CLIENT_DATA;
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
	if ((pkt->size==SELECT_CONNECTION_ID_LEN+5 && strncasecmp((char *)SELECT_CONNECTION_ID,(char *)pkt->ptr+5,pkt->size-5)==0)) {
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
		myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
		char **p=(char **)malloc(sizeof(char*)*1);
		unsigned long *l=(unsigned long *)malloc(sizeof(unsigned long *)*1);
		l[0]=strlen(buf);
		p[0]=buf;
		myprot->generate_pkt_row(true,NULL,NULL,sid,1,l,p); sid++;
		myds->DSS=STATE_ROW;
		myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
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


			if (
				(pkt->size==SELECT_LAST_INSERT_ID_LEN+5 && strncasecmp((char *)SELECT_LAST_INSERT_ID,(char *)pkt->ptr+5,pkt->size-5)==0)
				||
				(pkt->size==SELECT_LAST_INSERT_ID_LIMIT1_LEN+5 && strncasecmp((char *)SELECT_LAST_INSERT_ID_LIMIT1,(char *)pkt->ptr+5,pkt->size-5)==0)
                ||
                (pkt->size==SELECT_VARIABLE_IDENTITY_LEN+5 && strncasecmp((char *)SELECT_VARIABLE_IDENTITY,(char *)pkt->ptr+5,pkt->size-5)==0)
                ||
                (pkt->size==SELECT_VARIABLE_IDENTITY_LIMIT1_LEN+5 && strncasecmp((char *)SELECT_VARIABLE_IDENTITY_LIMIT1,(char *)pkt->ptr+5,pkt->size-5)==0)
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
				myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
				char **p=(char **)malloc(sizeof(char*)*1);
				unsigned long *l=(unsigned long *)malloc(sizeof(unsigned long *)*1);
				l[0]=strlen(buf);
				p[0]=buf;
				myprot->generate_pkt_row(true,NULL,NULL,sid,1,l,p); sid++;
				myds->DSS=STATE_ROW;
				myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus); sid++;
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
	if (prepared == false) {
		if (handle_command_query_kill(pkt)) {
			return true;
		}
	}
	if (qpo->cache_ttl>0) {
		uint32_t resbuf=0;
		unsigned char *aa=GloQC->get(
			client_myds->myconn->userinfo->hash,
			(const unsigned char *)CurrentQuery.QueryPointer ,
			CurrentQuery.QueryLength ,
			&resbuf ,
			thread->curtime/1000 ,
			qpo->cache_ttl
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
				thread->status_variables.hostgroup_locked_queries++;
				RequestEnd(NULL);
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
			if (ldap_ctx==NULL) {
				GloMyAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->username);
			} else {
				GloMyLdapAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->username);
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
			/*free_users */GloMyAuth->increase_frontend_user_connections(client_myds->myconn->userinfo->username, &used_users);
			// FIXME: max_connections is not handled for CHANGE_USER
		} else {
			l_free(pkt->size,pkt->ptr);
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
			proxy_error("ProxySQL Error: Access denied for user '%s'@'%s' (using password: %s)", client_myds->myconn->userinfo->username, client_addr, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,2,1045,(char *)"28000", _s, true);
			free(_s);
			__sync_fetch_and_add(&MyHGM->status.access_denied_wrong_password, 1);
		}
	} else {
		//FIXME: send an error message saying "not supported" or disconnect
		l_free(pkt->size,pkt->ptr);
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
		if (session_fast_forward == false) {
			if (qpo->min_gtid) {
				gtid_uuid = qpo->min_gtid;
			} else if (qpo->gtid_from_hostgroup >= 0) {
				_gtid_from_backend = find_backend(qpo->gtid_from_hostgroup);
				if (_gtid_from_backend) {
					if (_gtid_from_backend->gtid_uuid[0]) {
						gtid_uuid = _gtid_from_backend->gtid_uuid;
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
				mc=thread->get_MyConn_local(mybe->hostgroup_id, this, uuid, trxid, -1);
			} else {
				mc=thread->get_MyConn_local(mybe->hostgroup_id, this, NULL, 0, (int)qpo->max_lag_ms);
			}
		}
		if (mc==NULL) {
			if (trxid) {
				mc=MyHGM->get_MyConn_from_pool(mybe->hostgroup_id, this, session_fast_forward, uuid, trxid, -1);
			} else {
				mc=MyHGM->get_MyConn_from_pool(mybe->hostgroup_id, this, session_fast_forward, NULL, 0, (int)qpo->max_lag_ms);
			}
		} else {
			thread->status_variables.ConnPool_get_conn_immediate++;
		}
		if (mc) {
			mybe->server_myds->attach_connection(mc);
			thread->status_variables.ConnPool_get_conn_success++;
		} else {
			thread->status_variables.ConnPool_get_conn_failure++;
		}
		if (qpo->max_lag_ms >= 0) {
			if (qpo->max_lag_ms <= 360000) { // this is a relative time , we convert it to absolute
				if (mc == NULL) {
					if (CurrentQuery.waiting_since == 0) {
						CurrentQuery.waiting_since = thread->curtime;
						thread->status_variables.queries_with_max_lag_ms__delayed++;
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
				thread->status_variables.queries_with_max_lag_ms__total_wait_time_us += waited;
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
	MYSQL_RES *stmt_result=myconn->query.stmt_result;
	if (stmt_result) {
		MySQL_ResultSet *MyRS=new MySQL_ResultSet();
		MyRS->init(&client_myds->myprot, stmt_result, stmt->mysql, stmt);
		MyRS->get_resultset(client_myds->PSarrayOUT);
		CurrentQuery.rows_sent = MyRS->num_rows;
		//removed  bool resultset_completed=MyRS->get_resultset(client_myds->PSarrayOUT);
		delete MyRS;
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
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,client_myds->pkt_sid+1,num_rows,mysql->insert_id, setStatus , mysql->warning_count,mysql->info);
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

void MySQL_Session::MySQL_Result_to_MySQL_wire(MYSQL *mysql, MySQL_ResultSet *MyRS, MySQL_Data_Stream *_myds) {
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
				if (mysql_errno(mysql)==0) { // no errors
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
						GloQC->set(
							client_myds->myconn->userinfo->hash ,
							(const unsigned char *)CurrentQuery.QueryPointer,
							CurrentQuery.QueryLength,
							aa ,
							client_myds->resultset_length ,
							thread->curtime/1000 ,
							thread->curtime/1000 ,
							thread->curtime/1000 + qpo->cache_ttl
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
			unsigned int nTrx=NumActiveTransactions();
			uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
			if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
			if (mysql->server_status & SERVER_MORE_RESULTS_EXIST)
				setStatus |= SERVER_MORE_RESULTS_EXIST;
			setStatus |= ( mysql->server_status & ~SERVER_STATUS_AUTOCOMMIT ); // get flags from server_status but ignore autocommit
			setStatus = setStatus & ~SERVER_STATUS_CURSOR_EXISTS; // Do not send cursor #1128
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,client_myds->pkt_sid+1,num_rows,mysql->insert_id, setStatus, mysql->warning_count,mysql->info);
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

void MySQL_Session::SQLite3_to_MySQL(SQLite3_result *result, char *error, int affected_rows, MySQL_Protocol *myprot, bool in_transaction) {
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
		if (in_transaction == false) {
			nTrx=NumActiveTransactions();
			setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
			if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
		} else {
			// this is for SQLite3 Server
			setStatus = SERVER_STATUS_AUTOCOMMIT;
			setStatus |= SERVER_STATUS_IN_TRANS;
		}
		myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, setStatus ); sid++;
		char **p=(char **)malloc(sizeof(char*)*result->columns);
		unsigned long *l=(unsigned long *)malloc(sizeof(unsigned long *)*result->columns);
		for (int r=0; r<result->rows_count; r++) {
		for (int i=0; i<result->columns; i++) {
			l[i]=result->rows[r]->sizes[i];
			p[i]=result->rows[r]->fields[i];
		}
		myprot->generate_pkt_row(true,NULL,NULL,sid,result->columns,l,p); sid++;
		}
		myds->DSS=STATE_ROW;
		myprot->generate_pkt_EOF(true,NULL,NULL,sid,0, 2 | setStatus ); sid++;
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

void MySQL_Session::set_unhealthy() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess:%p\n", this);
	healthy=0;
}


unsigned int MySQL_Session::NumActiveTransactions() {
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

int MySQL_Session::FindOneActiveTransaction() {
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

unsigned long long MySQL_Session::IdleTime() {
		if (client_myds==0) return 0;
		if (status!=WAITING_CLIENT_DATA) return 0;
		int idx=client_myds->poll_fds_idx;
		unsigned long long last_sent=thread->mypolls.last_sent[idx];
		unsigned long long last_recv=thread->mypolls.last_recv[idx];
		unsigned long long last_time=(last_sent > last_recv ? last_sent : last_recv);
    return thread->curtime - last_time;
}



// this is called either from RequestEnd(), or at the end of executing
// prepared statements 
void MySQL_Session::LogQuery(MySQL_Data_Stream *myds) {
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
// this should execute most of the commands executed when a request is finalized
// this should become the place to hook other functions
void MySQL_Session::RequestEnd(MySQL_Data_Stream *myds) {

	switch (status) {
		case PROCESSING_STMT_EXECUTE:
		case PROCESSING_STMT_PREPARE:
			// if a prepared statement is executed, LogQuery was already called
			break;
		default:
			LogQuery(myds);
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
	// reset status of the session
	status=WAITING_CLIENT_DATA;
	if (client_myds) {
		// reset status of client data stream
		client_myds->DSS=STATE_SLEEP;
		// finalize the query
		CurrentQuery.end();
	}
	started_sending_data_to_client=false;
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
	thread->status_variables.mysql_backend_buffers_bytes+=backend;
	thread->status_variables.mysql_frontend_buffers_bytes+=frontend;
	thread->status_variables.mysql_session_internal_bytes+=internal;
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
						int rc;
						rc=RE2::FullMatch(nq, *re, &tk, &id);
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
								client_myds->DSS=STATE_SLEEP;
								status=WAITING_CLIENT_DATA;
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
	if (ldap_ctx==NULL)
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
			b[1]=' ';
			b[2]=' ';
			b[strlen(b)-1] = ' ';
			b[strlen(b)-2] = ' ';
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
							myds->myconn->set_status_no_multiplex(true);
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
