#include "proxysql.h"
#include "cpp.h"
#include "re2/re2.h"
#include "re2/regexp.h"
#include "SpookyV2.h"

#define SELECT_VERSION_COMMENT "select @@version_comment limit 1"
#define SELECT_VERSION_COMMENT_LEN 32
#define PROXYSQL_VERSION_COMMENT "\x01\x00\x00\x01\x01\x27\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x11\x40\x40\x76\x65\x72\x73\x69\x6f\x6e\x5f\x63\x6f\x6d\x6d\x65\x6e\x74\x00\x0c\x21\x00\x18\x00\x00\x00\xfd\x00\x00\x1f\x00\x00\x05\x00\x00\x03\xfe\x00\x00\x02\x00\x0b\x00\x00\x04\x0a(ProxySQL)\x05\x00\x00\x05\xfe\x00\x00\x02\x00"
#define PROXYSQL_VERSION_COMMENT_LEN 81
#define SELECT_LAST_INSERT_ID "SELECT LAST_INSERT_ID()"
#define SELECT_LAST_INSERT_ID_LEN 23
#define SELECT_LAST_INSERT_ID_LIMIT1 "SELECT LAST_INSERT_ID() LIMIT 1"
#define SELECT_LAST_INSERT_ID_LIMIT1_LEN 31

#define EXPMARIA

extern const CHARSET_INFO * proxysql_find_charset_name(const char * const name);

extern MySQL_Authentication *GloMyAuth;
extern ProxySQL_Admin *GloAdmin;
extern MySQL_Logger *GloMyLogger;
#ifndef PROXYSQL_STMT_V14
extern MySQL_STMT_Manager *GloMyStmt;
#else
extern MySQL_STMT_Manager_v14 *GloMyStmt;
#endif

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

class KillArgs {
	public:
	char *username;
	char *password;
	char *hostname;
	unsigned int port;
	unsigned long id;
	KillArgs(char *u, char *p, char *h, unsigned int P, unsigned long i) {
		username=strdup(u);
		password=strdup(p);
		hostname=strdup(h);
		port=P;
		id=i;
	};
	~KillArgs() {
		free(username);
		free(password);
		free(hostname);
	};
};

static void * kill_query_thread(void *arg) {
	KillArgs *ka=(KillArgs *)arg;
	MYSQL *mysql;
	mysql=mysql_init(NULL);
	mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "program_name", "proxysql_killer");
	if (!mysql) {
		goto __exit_kill_query_thread;
	}
	MYSQL *ret;
	if (ka->port) {
		proxy_warning("KILL QUERY %lu on %s:%d\n", ka->id, ka->hostname, ka->port);
		ret=mysql_real_connect(mysql,ka->hostname,ka->username,ka->password,NULL,ka->port,NULL,0);
	} else {
		proxy_warning("KILL QUERY %lu on localhost\n", ka->id);
		ret=mysql_real_connect(mysql,"localhost",ka->username,ka->password,NULL,0,ka->hostname,0);
	}
	if (!ret) {
		goto __exit_kill_query_thread;
	}
	char buf[100];
	sprintf(buf,"KILL QUERY %lu", ka->id);
	// FIXME: these 2 calls are blocking, fortunately on their own thread
	mysql_query(mysql,buf);
	mysql_close(mysql);
__exit_kill_query_thread:
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
}

void Query_Info::end() {
	query_parser_update_counters();
	query_parser_free();
	if ((end_time-start_time) > (unsigned int)mysql_thread___long_query_time*1000) {
		__sync_add_and_fetch(&sess->thread->status_variables.queries_slow,1);
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
	}
}

void Query_Info::init(unsigned char *_p, int len, bool mysql_header) {
	QueryLength=(mysql_header ? len-5 : len);
	QueryPointer=(mysql_header ? _p+5 : _p);
	MyComQueryCmd=MYSQL_COM_QUERY_UNKNOWN;
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
	if (MyComQueryCmd==MYSQL_COM_QUERY_UNKNOWN) return 0; // this means that it was never initialized
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
	// to avoid an expensive strlen() on the digest_text, we consider only the real query
	if (QueryPointer==NULL) {
		return false;
	}
	if (QueryLength<7) {
		return false;
	}
	if (strncasecmp((char *)QueryPointer,(char *)"SELECT ",7)) {
		return false;
	}
	// if we arrive till here, it is a SELECT
	if (QueryLength>=17) {
		char *p=(char *)QueryPointer;
		p+=QueryLength-11;
		if (strncasecmp(p," FOR UPDATE",11)==0) {
			return false;
		}
	}
	return true;
}

void * MySQL_Session::operator new(size_t size) {
	return l_alloc(size);
}

void MySQL_Session::operator delete(void *ptr) {
	l_free(sizeof(MySQL_Session),ptr);
}


MySQL_Session::MySQL_Session() {
	thread_session_id=0;
	pause_until=0;
	qpo=new Query_Processor_Output();
	start_time=0;
#ifdef PROXYSQL_STATSCOUNTERS_NOLOCK
	command_counters=new StatCounters(15,10);
#else
	command_counters=new StatCounters(15,10,false);
#endif
	healthy=1;
	autocommit=true;
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
	next_query_flagIN=-1;
	mirror_hostgroup=-1;
	mirror_flagOUT=-1;
	active_transactions=0;

	match_regexes=NULL;
/*
	match_regexes=(Session_Regex **)malloc(sizeof(Session_Regex *)*3);
	match_regexes[0]=new Session_Regex((char *)"^SET (|SESSION |@@|@@session.)SQL_LOG_BIN( *)(:|)=( *)");
	match_regexes[1]=new Session_Regex((char *)"^SET (|SESSION |@@|@@session.)SQL_MODE( *)(:|)=( *)");
	match_regexes[2]=new Session_Regex((char *)"^SET (|SESSION |@@|@@session.)TIME_ZONE( *)(:|)=( *)");
*/
	init(); // we moved this out to allow CHANGE_USER

	last_insert_id=0; // #1093
}

void MySQL_Session::init() {
	transaction_persistent_hostgroup=-1;
	transaction_persistent=false;
	mybes= new PtrArray(4);
	sess_STMTs_meta=new MySQL_STMTs_meta();
	SLDH=new StmtLongDataHandler();
}

void MySQL_Session::reset() {
	autocommit=true;
	autocommit_on_hostgroup=-1;
	current_hostgroup=-1;
	default_hostgroup=-1;
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
}

MySQL_Session::~MySQL_Session() {

	reset(); // we moved this out to allow CHANGE_USER

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
	if (client_myds) {
		if (mirror==false) {
			bool runloop=false;
			int retbytes=client_myds->write_to_net_poll();
			if (retbytes==QUEUE_T_DEFAULT_SIZE) { // optimization to solve memory bloat
				runloop=true;
			}
			while (runloop) {
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
						if (retbytes==QUEUE_T_DEFAULT_SIZE) { // optimization to solve memory bloat
							runloop=true;
						}
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
		if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
		client_myds->DSS=STATE_SLEEP;
		status=WAITING_CLIENT_DATA;
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


// FIXME: This function is currently disabled . See #469
bool MySQL_Session::handler_SetAutocommit(PtrSize_t *pkt) {
	size_t sal=strlen("set autocommit");
	if ( pkt->size >= 7+sal) {
		if (strncasecmp((char *)"set autocommit",(char *)pkt->ptr+5,sal)==0) {
			__sync_fetch_and_add(&MyHGM->status.autocommit_cnt, 1);
			unsigned int i;
			bool eq=false;
			int fd=-1; // first digit
			for (i=5+sal;i<pkt->size;i++) {
				char c=((char *)pkt->ptr)[i];
				if (c!='0' && c!='1' && c!=' ' && c!='=' && c!='/') return false; // found a not valid char
				if (eq==false) {
					if (c!=' ' && c!='=') return false; // found a not valid char
					if (c=='=') eq=true;
				} else {
					if (c!='0' && c!='1' && c!=' ' && c!='/') return false; // found a not valid char
					if (fd==-1) {
						if (c=='0' || c=='1') { // found first digit
							if (c=='0')
								fd=0;
							else
								fd=1;
						}
					} else {
						if (c=='0' || c=='1') { // found second digit
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
				// we immeditately process the number of transactions
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
						autocommit_on_hostgroup=FindOneActiveTransaction();
						return false;
					} else {
						// as there is no active transaction, we do no need to forward it
						// just change internal state
						autocommit=true;
						goto __ret_autocommit_OK;
					}
				}

				if (fd==0) {
					autocommit=false;	// we set it, no matter if already set or not
					// it turned out I was wrong
					// set autocommit=0 has no effect if there is an acrive transaction
					// therefore, we never forward set autocommit = 0
					goto __ret_autocommit_OK;
				}
__ret_autocommit_OK:
				client_myds->DSS=STATE_QUERY_SENT_NET;
				uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
				if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
				client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
				client_myds->DSS=STATE_SLEEP;
				status=WAITING_CLIENT_DATA;
				l_free(pkt->size,pkt->ptr);
				__sync_fetch_and_add(&MyHGM->status.autocommit_cnt_filtered, 1);
				return true;
			}
		}
	}
	return false;
}

bool MySQL_Session::handler_special_queries(PtrSize_t *pkt) {

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
	if (pkt->size==SELECT_VERSION_COMMENT_LEN+5 && strncmp((char *)SELECT_VERSION_COMMENT,(char *)pkt->ptr+5,pkt->size-5)==0) {
		// FIXME: this doesn't return AUTOCOMMIT or IN_TRANS
		PtrSize_t pkt_2;
		pkt_2.size=PROXYSQL_VERSION_COMMENT_LEN;
		pkt_2.ptr=l_alloc(pkt_2.size);
		memcpy(pkt_2.ptr,PROXYSQL_VERSION_COMMENT,pkt_2.size);
		status=WAITING_CLIENT_DATA;
		client_myds->DSS=STATE_SLEEP;
		client_myds->PSarrayOUT->add(pkt_2.ptr,pkt_2.size);
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
	if ( (pkt->size < 35) && (pkt->size > 15) && (strncasecmp((char *)"SET NAMES ",(char *)pkt->ptr+5,10)==0) ) {
		char *unstripped=strndup((char *)pkt->ptr+15,pkt->size-15);
		char *name=trim_spaces_and_quotes_in_place(unstripped);
		const CHARSET_INFO * c = proxysql_find_charset_name(name);
		client_myds->DSS=STATE_QUERY_SENT_NET;
		if (!c) {
			char *m=(char *)"Unknown character set: '%s'";
			char *errmsg=(char *)malloc(strlen(name)+strlen(m));
			sprintf(errmsg,m,name);
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1115,(char *)"#42000",errmsg);
			free(errmsg);
		} else {
			client_myds->myconn->set_charset(c->nr);
			unsigned int nTrx=NumActiveTransactions();
			uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
			if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
		}
		client_myds->DSS=STATE_SLEEP;
		status=WAITING_CLIENT_DATA;
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
		l_free(pkt->size,pkt->ptr);
		return true;
	}
	return false;
}

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___create_mirror_session() {
	if (pktH->size < 15*1024*1024 && (qpo->mirror_hostgroup >= 0 || qpo->mirror_flagOUT >= 0)) {
		// check if there are too many mirror sessions in queue
		if (thread->mirror_queue_mysql_sessions->len >= mysql_thread___mirror_max_queue_length) {
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
			if (__sync_add_and_fetch(&GloMTH->status_variables.mirror_sessions_current,1) > mysql_thread___mirror_max_concurrency ) {
				// if the limit is reached, we queue it instead
				__sync_sub_and_fetch(&GloMTH->status_variables.mirror_sessions_current,1);
				thread->mirror_queue_mysql_sessions->add(newsess);
			}	else {
				thread->register_session(newsess);
				newsess->handler(); // execute immediately
				//newsess->to_process=0;
				if (newsess->status==WAITING_CLIENT_DATA) { // the mirror session has completed
					thread->unregister_session(thread->mysql_sessions->len-1);
					int l=mysql_thread___mirror_max_concurrency;
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
		if (mysql_thread___multiplexing && (myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
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
				proxy_error("Ping timeout during ping on %s , %d\n", myconn->parent->address, myconn->parent->port);
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
			KillArgs *ka = new KillArgs(ui->username, auth_password, myds->myconn->parent->address, myds->myconn->parent->port, myds->myconn->mysql->thread_id);
			pthread_attr_t attr;
			pthread_attr_init(&attr);
			pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
			pthread_attr_setstacksize (&attr, 256*1024);
			pthread_t pt;
			pthread_create(&pt, &attr, &kill_query_thread, ka);
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
	if (client_myds->myconn->options.charset != mybe->server_myds->myconn->mysql->charset->nr) {
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
		NEXT_IMMEDIATE_NEW(CHANGING_CHARSET);
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

bool MySQL_Session::handler_again___verify_backend_sql_mode() {
	if (mybe->server_myds->myconn->options.sql_mode_int==0) {
		// it is the first time we use this backend. Set sql_mode to default
		if (mybe->server_myds->myconn->options.sql_mode) {
			free(mybe->server_myds->myconn->options.sql_mode);
			mybe->server_myds->myconn->options.sql_mode=NULL;
		}
		mybe->server_myds->myconn->options.sql_mode=strdup(mysql_thread___default_sql_mode);
		uint32_t sql_mode_int=SpookyHash::Hash32(mybe->server_myds->myconn->options.sql_mode,strlen(mybe->server_myds->myconn->options.sql_mode),10);
		mybe->server_myds->myconn->options.sql_mode_int=sql_mode_int;
	}
	if (client_myds->myconn->options.sql_mode_int) {
		if (client_myds->myconn->options.sql_mode_int != mybe->server_myds->myconn->options.sql_mode_int) {
			{
				mybe->server_myds->myconn->options.sql_mode_int = client_myds->myconn->options.sql_mode_int;
				if (mybe->server_myds->myconn->options.sql_mode) {
					free(mybe->server_myds->myconn->options.sql_mode);
					mybe->server_myds->myconn->options.sql_mode=NULL;
					if (client_myds->myconn->options.sql_mode) {
						mybe->server_myds->myconn->options.sql_mode=strdup(client_myds->myconn->options.sql_mode);
					}
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
			NEXT_IMMEDIATE_NEW(SETTING_SQL_MODE);
		}
	}
	return false;
}

bool MySQL_Session::handler_again___verify_backend_time_zone() {
	if (mybe->server_myds->myconn->options.time_zone_int==0) {
		// it is the first time we use this backend. Set time_zone to default
		if (mybe->server_myds->myconn->options.time_zone) {
			free(mybe->server_myds->myconn->options.time_zone);
			mybe->server_myds->myconn->options.time_zone=NULL;
		}
		mybe->server_myds->myconn->options.time_zone=strdup(mysql_thread___default_time_zone);
		uint32_t time_zone_int=SpookyHash::Hash32(mybe->server_myds->myconn->options.time_zone,strlen(mybe->server_myds->myconn->options.time_zone),10);
		mybe->server_myds->myconn->options.time_zone_int=time_zone_int;
	}
	if (client_myds->myconn->options.time_zone_int) {
		if (client_myds->myconn->options.time_zone_int != mybe->server_myds->myconn->options.time_zone_int) {
			{
				mybe->server_myds->myconn->options.time_zone_int = client_myds->myconn->options.time_zone_int;
				if (mybe->server_myds->myconn->options.time_zone) {
					free(mybe->server_myds->myconn->options.time_zone);
					mybe->server_myds->myconn->options.time_zone=NULL;
					if (client_myds->myconn->options.time_zone) {
						mybe->server_myds->myconn->options.time_zone=strdup(client_myds->myconn->options.time_zone);
					}
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
			NEXT_IMMEDIATE_NEW(SETTING_TIME_ZONE);
		}
	}
	return false;
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

bool MySQL_Session::handler_again___verify_backend_autocommit() {
	if (autocommit != mybe->server_myds->myconn->IsAutoCommit()) {
		// see case #485
		if (mysql_thread___enforce_autocommit_on_reads == false) {
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
	}
	return false;
}

bool MySQL_Session::handler_again___verify_backend_user_schema() {
	MySQL_Data_Stream *myds=mybe->server_myds;
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
		st=previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			if (myerr > 2000) {
				bool retry_conn=false;
				// client error, serious
				proxy_error("Detected a broken connection while setting INIT CONNECT on %s , %d : %d, %s\n", myconn->parent->address, myconn->parent->port, myerr, mysql_error(myconn->mysql));
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
				proxy_warning("Error while setting INIT CONNECT: %d, %s\n", myerr, mysql_error(myconn->mysql));
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
		st=previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			if (myerr > 2000) {
				bool retry_conn=false;
				// client error, serious
				proxy_error("Detected a broken connection while setting SQL_LOG_BIN on %s , %d : %d, %s\n", myconn->parent->address, myconn->parent->port, myerr, mysql_error(myconn->mysql));
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
				proxy_warning("Error while setting SQL_LOG_BIN: %d, %s\n", myerr, mysql_error(myconn->mysql));
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
		char *q=(char *)"SET SQL_MODE='%s'";
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
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			if (myerr > 2000) {
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

bool MySQL_Session::handler_again___status_SETTING_TIME_ZONE(int *_rc) {
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
		char *q=(char *)"SET TIME_ZONE='%s'";
		query=(char *)malloc(strlen(q)+strlen(myconn->options.time_zone));
		sprintf(query,q,myconn->options.time_zone);
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
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			if (myerr > 2000) {
				bool retry_conn=false;
				// client error, serious
				proxy_error("Detected a broken connection while setting TIME_ZONE on %s , %d : %d, %s\n", myconn->parent->address, myconn->parent->port, myerr, mysql_error(myconn->mysql));
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
				proxy_warning("Error while setting TIME_ZONE: %d, %s\n", myerr, mysql_error(myconn->mysql));
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
		st=previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			if (myerr > 2000) {
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
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,9001,(char *)"HY000",buf);
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
						client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql));
					} else {
						char buf[256];
						sprintf(buf,"Max connect failure while reaching hostgroup %d", current_hostgroup);
						client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,9002,(char *)"HY000",buf);
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
#ifndef PROXYSQL_STMT_V14
	myconn->local_stmts=new MySQL_STMTs_local(false); // false by default, it is a backend
#else
	myconn->local_stmts=new MySQL_STMTs_local_v14(false); // false by default, it is a backend
#endif
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
			if (myerr > 2000) {
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
			// rc==1 , nothing to do for now
		}
	}
	return false;
}

bool MySQL_Session::handler_again___status_CHANGING_CHARSET(int *_rc) {
	assert(mybe->server_myds->myconn);
	MySQL_Data_Stream *myds=mybe->server_myds;
	MySQL_Connection *myconn=myds->myconn;
	myds->DSS=STATE_MARIADB_QUERY;
	enum session_status st=status;
	if (myds->mypolls==NULL) {
		thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
	}
	int rc=myconn->async_set_names(myds->revents, client_myds->myconn->options.charset);
	if (rc==0) {
		__sync_fetch_and_add(&MyHGM->status.backend_set_names, 1);
		st=previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			if (myerr > 2000) {
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
			}
		} else {
			// rc==1 , nothing to do for now
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
	int rc=myconn->async_set_autocommit(myds->revents, autocommit);
	if (rc==0) {
		st=previous_status.top();
		previous_status.pop();
		NEXT_IMMEDIATE_NEW(st);
	} else {
		if (rc==-1) {
			// the command failed
			int myerr=mysql_errno(myconn->mysql);
			if (myerr > 2000) {
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
	bool wrong_pass=false;
	if (to_process==0) return 0; // this should be redundant if the called does the same check
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Processing session %p\n" , this->thread, this, this);
	PtrSize_t pkt;
	pktH=&pkt;
	unsigned int j;
	unsigned char c;

	active_transactions=NumActiveTransactions();

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
					return 0;
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
						handler___status_CONNECTING_CLIENT___STATE_SSL_INIT(&pkt);
						break;
					default:
						proxy_error("Detected not valid state client state: %d\n", client_myds->DSS);
						return -1; //close connection
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
							current_hostgroup=default_hostgroup;
						}
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: WAITING_CLIENT_DATA - STATE_SLEEP\n");
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
								memcpy(_new_pkt.ptr+9 , pkt.ptr+5, pkt.size-5);
								l_free(pkt.size,pkt.ptr);
								pkt.size+=4;
								pkt.ptr = _new_pkt.ptr;
								c=*((unsigned char *)pkt.ptr+sizeof(mysql_hdr));
							}
						}
						switch ((enum_mysql_command)c) {
							case _MYSQL_COM_QUERY:
								__sync_add_and_fetch(&thread->status_variables.queries,1);
								if (session_type == PROXYSQL_SESSION_MYSQL) {
									bool rc_break=false;
									if (session_fast_forward==false) {
										// Note: CurrentQuery sees the query as sent by the client.
										// shortly after, the packets it used to contain the query will be deallocated
										CurrentQuery.begin((unsigned char *)pkt.ptr,pkt.size,true);
									}
									rc_break=handler_special_queries(&pkt);
									if (rc_break==true) {
										if (mirror==false) {
											// track also special queries
											RequestEnd(NULL);
											break;
										} else {
											return -1;
										}
									}
									{
										timespec begint;
										clock_gettime(CLOCK_THREAD_CPUTIME_ID,&begint);
										qpo=GloQPro->process_mysql_query(this,pkt.ptr,pkt.size,&CurrentQuery);
										timespec endt;
										clock_gettime(CLOCK_THREAD_CPUTIME_ID,&endt);
										thread->status_variables.query_processor_time=thread->status_variables.query_processor_time +
											(endt.tv_sec*1000000000+endt.tv_nsec) -
											(begint.tv_sec*1000000000+begint.tv_nsec);
									}
									assert(qpo);	// GloQPro->process_mysql_query() should always return a qpo
									rc_break=handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(&pkt);
									if (rc_break==true) {
										if (mirror==false) {
											break;
										} else {
											return -1;
										}
									}
									if (mirror==false) {
										handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY___create_mirror_session();
									}

									if (autocommit_on_hostgroup>=0) {
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
									mybe->server_myds->mysql_real_query.init(&pkt);
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
									if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
									client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
									client_myds->DSS=STATE_SLEEP;
									status=WAITING_CLIENT_DATA;
								}
								break;
							case _MYSQL_COM_STMT_CLOSE:
								{
#ifndef PROXYSQL_STMT_V14
									uint32_t stmt_global_id=0;
									memcpy(&stmt_global_id,(char *)pkt.ptr+5,sizeof(uint32_t));
									// FIXME: no input validation
									SLDH->reset(stmt_global_id);
									sess_STMTs_meta->erase(stmt_global_id);
									client_myds->myconn->local_stmts->erase(stmt_global_id);
#else
									uint32_t client_global_id=0;
									memcpy(&client_global_id,(char *)pkt.ptr+5,sizeof(uint32_t));
									// FIXME: no input validation
									SLDH->reset(client_global_id);
									sess_STMTs_meta->erase(client_global_id);
									client_myds->myconn->local_stmts->client_close(client_global_id);
#endif
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
									client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",(char *)"Command not supported");
									client_myds->DSS=STATE_SLEEP;
									status=WAITING_CLIENT_DATA;
									break;
								} else {
									thread->status_variables.frontend_stmt_prepare++;
									thread->status_variables.queries++;
									// if we reach here, we are not on MySQL module
									bool rc_break=false;

									// Note: CurrentQuery sees the query as sent by the client.
									// shortly after, the packets it used to contain the query will be deallocated
									// Note2 : we call the next function as if it was _MYSQL_COM_QUERY
									// because the offset will be identical
									CurrentQuery.begin((unsigned char *)pkt.ptr,pkt.size,true);

									qpo=GloQPro->process_mysql_query(this,pkt.ptr,pkt.size,&CurrentQuery);
									assert(qpo);	// GloQPro->process_mysql_query() should always return a qpo
									rc_break=handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(&pkt);
									if (rc_break==true) {
										break;
									}
									if (client_myds->myconn->local_stmts==NULL) {
#ifndef PROXYSQL_STMT_V14
										client_myds->myconn->local_stmts=new MySQL_STMTs_local(true);
#else
										client_myds->myconn->local_stmts=new MySQL_STMTs_local_v14(true);
#endif
									}
									uint64_t hash=client_myds->myconn->local_stmts->compute_hash(current_hostgroup,(char *)client_myds->myconn->userinfo->username,(char *)client_myds->myconn->userinfo->schemaname,(char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
									MySQL_STMT_Global_info *stmt_info=NULL;
#ifndef PROXYSQL_STMT_V14
									stmt_info=GloMyStmt->find_prepared_statement_by_hash(hash); // find_prepared_statement_by_hash() always increase ref_count_client
									if (stmt_info) {
										// FIXME: there is a very interesting race condition here
										// FIXME: it is possible that multiple statement have the same hash
										// FIXME: we should check local_stmts to verify is this stmt_id was already sent
										if (client_myds->myconn->local_stmts->exists(stmt_info->statement_id)) {
											// the client is asking to prepare another identical prepared statements
											__sync_fetch_and_sub(&stmt_info->ref_count_client,1); // since find_prepared_statement_by_hash() already increased red_count_client we decrease it here
											stmt_info=NULL;
										}
									}
									if (stmt_info) {
										l_free(pkt.size,pkt.ptr);
										client_myds->setDSS_STATE_QUERY_SENT_NET();
										client_myds->myprot.generate_STMT_PREPARE_RESPONSE(client_myds->pkt_sid+1,stmt_info);
										client_myds->myconn->local_stmts->insert(stmt_info->statement_id,NULL);
										__sync_fetch_and_sub(&stmt_info->ref_count_client,1); // since find_prepared_statement_by_hash() already increased red_count_client before insert(), we decrease it here
										client_myds->DSS=STATE_SLEEP;
										status=WAITING_CLIENT_DATA;
										CurrentQuery.end_time=thread->curtime;
										CurrentQuery.end();
										break;
									} else {
										mybe=find_or_create_backend(current_hostgroup);
										status=PROCESSING_STMT_PREPARE;
										mybe->server_myds->connect_retries_on_failure=mysql_thread___connect_retries_on_failure;
										mybe->server_myds->wait_until=0;
										pause_until=0;
										mybe->server_myds->killed_at=0;
										mybe->server_myds->mysql_real_query.init(&pkt); // fix memory leak for PREPARE in prepared statements #796
										client_myds->setDSS_STATE_QUERY_SENT_NET();
									}
#else // PROXYSQL_STMT_V14
									// we first lock GloStmt
									GloMyStmt->wrlock();
									stmt_info=GloMyStmt->find_prepared_statement_by_hash(hash,false);
									if (stmt_info) {
										// the prepared statement exists in GloMyStmt
										// for this reason, we do not need to prepare it again, and we can already reply to the client
										// we will now generate a unique stmt and send it to the client
										uint32_t new_stmt_id=client_myds->myconn->local_stmts->generate_new_client_stmt_id(stmt_info->statement_id);
										l_free(pkt.size,pkt.ptr);
										client_myds->setDSS_STATE_QUERY_SENT_NET();
										client_myds->myprot.generate_STMT_PREPARE_RESPONSE(client_myds->pkt_sid+1,stmt_info,new_stmt_id);
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
										mybe->server_myds->mysql_real_query.init(&pkt); // fix memory leak for PREPARE in prepared statements #796
										client_myds->setDSS_STATE_QUERY_SENT_NET();
									}
									GloMyStmt->unlock();
									break; // make sure to not break before unlocking GloMyStmt
#endif // PROXYSQL_STMT_V14
								}
								break;
							case _MYSQL_COM_STMT_EXECUTE:
								if (session_type != PROXYSQL_SESSION_MYSQL) { // only MySQL module supports prepared statement!!
									l_free(pkt.size,pkt.ptr);
									client_myds->setDSS_STATE_QUERY_SENT_NET();
									client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",(char *)"Command not supported");
									client_myds->DSS=STATE_SLEEP;
									status=WAITING_CLIENT_DATA;
									break;
								} else {
									// if we reach here, we are on MySQL module
									thread->status_variables.frontend_stmt_execute++;
									thread->status_variables.queries++;
									//bool rc_break=false;

#ifndef PROXYSQL_STMT_V14
									uint32_t stmt_global_id=0;
									memcpy(&stmt_global_id,(char *)pkt.ptr+5,sizeof(uint32_t));
									CurrentQuery.stmt_global_id=stmt_global_id;
									// now we get the statement information
									MySQL_STMT_Global_info *stmt_info=NULL;
									stmt_info=GloMyStmt->find_prepared_statement_by_stmt_id(stmt_global_id);
#else
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
#endif
									if (stmt_info==NULL) {
										// we couldn't find it
										l_free(pkt.size,pkt.ptr);
										client_myds->setDSS_STATE_QUERY_SENT_NET();
										client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",(char *)"Prepared statement doesn't exist");
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
										client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",(char *)"Error in prepared statement execution");
										client_myds->DSS=STATE_SLEEP;
										status=WAITING_CLIENT_DATA;
										//__sync_fetch_and_sub(&stmt_info->ref_count,1); // decrease reference count
										stmt_info=NULL;
										break;
									}
									// handle cases in which data was sent via STMT_SEND_LONG_DATA
									for (uint16_t ii=0; ii<stmt_meta->num_params; ii++) {
										void *_data=NULL;
										unsigned long *_l=0;
										_data=SLDH->get(stmt_global_id,ii,&_l);
										if (_data) { // data was sent via STMT_SEND_LONG_DATA
											stmt_meta->binds[ii].length=_l;
											stmt_meta->binds[ii].buffer=_data;
										}
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
								l_free(pkt.size,pkt.ptr);
								return -1;
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
								return -1; // immediately drop the connection
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
						return -1;
						break;
			}
				
				break;
			case FAST_FORWARD:
				mybe->server_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
				break;
			case NONE:
			default:
				proxy_error("Unexpected packet from client, disconnecting the client\n");
				return -1;
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
			// copy all packets from backend to frontend
			for (unsigned int k=0; k < mybe->server_myds->PSarrayIN->len; k++) {
				PtrSize_t pkt;
				mybe->server_myds->PSarrayIN->remove_index(0,&pkt);
				client_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
			}
			break;
		case CONNECTING_CLIENT:
			//fprintf(stderr,"CONNECTING_CLIENT\n");
			// FIXME: to implement
			break;
		case PINGING_SERVER:
			{
				int rc=handler_again___status_PINGING_SERVER();
				if (rc==-1) // if the ping fails, we destroy the session
					return -1;
			}
			break;

		case PROCESSING_STMT_PREPARE:
		case PROCESSING_STMT_EXECUTE:
		case PROCESSING_QUERY:
			//fprintf(stderr,"PROCESSING_QUERY\n");
			if (pause_until > thread->curtime) {
				return 0;
			}
			if (mysql_thread___connect_timeout_server_max) {
				if (mybe->server_myds->max_connect_time==0)
					mybe->server_myds->max_connect_time=thread->curtime+mysql_thread___connect_timeout_server_max*1000;
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
						if (handler_again___verify_init_connect()) {
							goto handler_again;
						}
						if (handler_again___verify_backend_charset()) {
							goto handler_again;
						}
						if (handler_again___verify_backend_autocommit()) {
							goto handler_again;
						}
						if (handler_again___verify_backend_sql_log_bin()) {
							goto handler_again;
						}
						if (handler_again___verify_backend_sql_mode()) {
							goto handler_again;
						}
						if (handler_again___verify_backend_time_zone()) {
							goto handler_again;
						}
					if (status==PROCESSING_STMT_EXECUTE) {
#ifndef PROXYSQL_STMT_V14
						CurrentQuery.mysql_stmt=myconn->local_stmts->find(CurrentQuery.stmt_global_id);
#else
						CurrentQuery.mysql_stmt=myconn->local_stmts->find_backend_stmt_by_global_id(CurrentQuery.stmt_global_id);
#endif
						if (CurrentQuery.mysql_stmt==NULL) {
							MySQL_STMT_Global_info *stmt_info=NULL;
							// the conection we too doesn't have the prepared statements prepared
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
				clock_gettime(CLOCK_THREAD_CPUTIME_ID,&begint);
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
				clock_gettime(CLOCK_THREAD_CPUTIME_ID,&endt);
				thread->status_variables.backend_query_time=thread->status_variables.backend_query_time +
					(endt.tv_sec*1000000000+endt.tv_nsec) -
					(begint.tv_sec*1000000000+begint.tv_nsec);
				if (rc==0) {
					// check if multiplexing needs to be disabled
					char *qdt=CurrentQuery.get_digest_text();
					if (qdt)
						myconn->ProcessQueryAndSetStatusFlags(qdt);

					// Support for LAST_INSERT_ID()
					if (myconn->mysql->insert_id) {
						last_insert_id=myconn->mysql->insert_id;
					}

					switch (status) {
						case PROCESSING_QUERY:
							MySQL_Result_to_MySQL_wire(myconn->mysql, myconn->MyRS);
							break;
						case PROCESSING_STMT_PREPARE:
							{
								thread->status_variables.backend_stmt_prepare++;
#ifndef PROXYSQL_STMT_V14
								uint32_t stmid;
#else
								uint32_t client_stmtid;
								uint64_t global_stmtid;
#endif
								bool is_new;
								MySQL_STMT_Global_info *stmt_info=NULL;
#ifndef PROXYSQL_STMT_V14
									stmt_info=GloMyStmt->add_prepared_statement(&is_new, current_hostgroup,
										(char *)client_myds->myconn->userinfo->username,
										(char *)client_myds->myconn->userinfo->schemaname,
										(char *)CurrentQuery.QueryPointer,
										CurrentQuery.QueryLength,
										CurrentQuery.mysql_stmt,
										qpo->cache_ttl,
										qpo->timeout,
										qpo->delay,
										true);
#else
									stmt_info=GloMyStmt->add_prepared_statement(current_hostgroup,
										(char *)client_myds->myconn->userinfo->username,
										(char *)client_myds->myconn->userinfo->schemaname,
										(char *)CurrentQuery.QueryPointer,
										CurrentQuery.QueryLength,
										CurrentQuery.mysql_stmt,
										qpo->cache_ttl,
										qpo->timeout,
										qpo->delay,
										true);
#endif
									if (CurrentQuery.QueryParserArgs.digest_text) {
										if (stmt_info->digest_text==NULL) {
											stmt_info->digest_text=strdup(CurrentQuery.QueryParserArgs.digest_text);
											stmt_info->digest=CurrentQuery.QueryParserArgs.digest;	// copy digest
											stmt_info->MyComQueryCmd=CurrentQuery.MyComQueryCmd; // copy MyComQueryCmd
										}
									}
#ifndef PROXYSQL_STMT_V14
									stmid=stmt_info->statement_id;
								myds->myconn->local_stmts->insert(stmid,CurrentQuery.mysql_stmt);
#else
								global_stmtid=stmt_info->statement_id;
								myds->myconn->local_stmts->backend_insert(global_stmtid,CurrentQuery.mysql_stmt);
								client_stmtid=client_myds->myconn->local_stmts->generate_new_client_stmt_id(global_stmtid);
#endif
								CurrentQuery.mysql_stmt=NULL;
								enum session_status st=status;
								size_t sts=previous_status.size();
								if (sts) {
									myconn->async_state_machine=ASYNC_IDLE;
									myds->DSS=STATE_MARIADB_GENERIC;
									st=previous_status.top();
									previous_status.pop();
									NEXT_IMMEDIATE(st);
								} else {
#ifndef PROXYSQL_STMT_V14
									client_myds->myprot.generate_STMT_PREPARE_RESPONSE(client_myds->pkt_sid+1,stmt_info);
									client_myds->myconn->local_stmts->insert(stmt_info->statement_id,NULL);
									if (is_new) __sync_fetch_and_sub(&stmt_info->ref_count_client,1);
#else
									client_myds->myprot.generate_STMT_PREPARE_RESPONSE(client_myds->pkt_sid+1,stmt_info,client_stmtid);
#endif
								}
							}
							break;
						case PROCESSING_STMT_EXECUTE:
							{
								thread->status_variables.backend_stmt_execute++;
								MySQL_Stmt_Result_to_MySQL_wire(CurrentQuery.mysql_stmt, myds->myconn);
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
					if (mysql_thread___multiplexing && (myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
						if (mysql_thread___connection_delay_multiplex_ms && mirror==false) {
							myds->wait_until=thread->curtime+mysql_thread___connection_delay_multiplex_ms*1000;
							myconn->async_state_machine=ASYNC_IDLE;
							myconn->multiplex_delayed=true;
							myds->DSS=STATE_MARIADB_GENERIC;
						} else {
							myconn->multiplex_delayed=false;
							myds->wait_until=0;
							myds->DSS=STATE_NOT_INITIALIZED;
							if (mysql_thread___autocommit_false_not_reusable && myds->myconn->IsAutoCommit()==false) {
								myds->destroy_MySQL_Connection_From_Pool(true);
							} else {
								myds->return_MySQL_Connection_To_Pool();
							}
						}
						if (transaction_persistent==true) {
							transaction_persistent_hostgroup=-1;
						}
					} else {
						myconn->multiplex_delayed=false;
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
				} else {
					if (rc==-1) {
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
							proxy_error("Detected an offline server during query: %s, %d\n", myconn->parent->address, myconn->parent->port);
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
							return -1;
						}
						int myerr=mysql_errno(myconn->mysql);
						if (myerr > 2000) {
							bool retry_conn=false;
							// client error, serious
							proxy_error("Detected a broken connection during query on (%d,%s,%d) , FD (Conn:%d , MyDS:%d) : %d, %s\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myds->fd, myds->myconn->fd, myerr, mysql_error(myconn->mysql));
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
									default:
										assert(0);
										break;
								}
								NEXT_IMMEDIATE(CONNECTING_SERVER);
							}
							return -1;
						} else {
							proxy_warning("Error during query on (%d,%s,%d): %d, %s\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myerr, mysql_error(myconn->mysql));

							bool retry_conn=false;
							switch (myerr) {
								case 1317:  // Query execution was interrupted
									if (killed==true) { // this session is being kiled
										return -1;
									}
									if (myds->killed_at) {
										// we intentionally killed the query
										break;
									}
								case 1290: // read-only
								case 1047: // WSREP has not yet prepared node for application use
								case 1053: // Server shutdown in progress
									if (myds->query_retries_on_failure > 0) {
										myds->query_retries_on_failure--;
										if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
											retry_conn=true;
											proxy_warning("Retrying query.\n");
										}
									}
									myds->destroy_MySQL_Connection_From_Pool(true);
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
										NEXT_IMMEDIATE(CONNECTING_SERVER);
									}
									return -1;
									break;
								case 1153: // ER_NET_PACKET_TOO_LARGE
									proxy_warning("Error ER_NET_PACKET_TOO_LARGE during query on (%d,%s,%d): %d, %s\n", myconn->parent->myhgc->hid, myconn->parent->address, myconn->parent->port, myerr, mysql_error(myconn->mysql));
									break;
								default:
									break; // continue normally
							}

							switch (status) {
								case PROCESSING_QUERY:
									MySQL_Result_to_MySQL_wire(myconn->mysql, myconn->MyRS, myds);
									break;
								case PROCESSING_STMT_PREPARE:
									{
										char sqlstate[10];
										sprintf(sqlstate,"%s",mysql_sqlstate(myconn->mysql));
										client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,mysql_errno(myconn->mysql),sqlstate,(char *)mysql_stmt_error(myconn->query.stmt));
										client_myds->pkt_sid++;
									}
									break;
								case PROCESSING_STMT_EXECUTE:
									{
										char sqlstate[10];
										sprintf(sqlstate,"%s",mysql_sqlstate(myconn->mysql));
										client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,mysql_errno(myconn->mysql),sqlstate,(char *)mysql_stmt_error(myconn->query.stmt));
										client_myds->pkt_sid++;
									}
									break;
								default:
									assert(0);
									break;
							}
							RequestEnd(myds);
							if (mysql_thread___multiplexing && (myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
								myds->DSS=STATE_NOT_INITIALIZED;
								if (mysql_thread___autocommit_false_not_reusable && myds->myconn->IsAutoCommit()==false) {
									myds->destroy_MySQL_Connection_From_Pool(true);
								} else {
									myds->return_MySQL_Connection_To_Pool();
								}
							} else {
								myconn->async_state_machine=ASYNC_IDLE;
								myds->DSS=STATE_MARIADB_GENERIC;
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
										delete myconn->MyRS;
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
				if (rc==-1) // we have an error we can't handle
					return -1;
			}
			break;

		case CHANGING_AUTOCOMMIT:
			{
				int rc=0;
				if (handler_again___status_CHANGING_AUTOCOMMIT(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) // we have an error we can't handle
					return -1;
			}
			break;

		case CHANGING_CHARSET:
			{
				int rc=0;
				if (handler_again___status_CHANGING_CHARSET(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) // we have an error we can't handle
					return -1;
			}
			break;

		case SETTING_SQL_LOG_BIN:
			{
				int rc=0;
				if (handler_again___status_SETTING_SQL_LOG_BIN(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) // we have an error we can't handle
					return -1;
			}
			break;

		case SETTING_SQL_MODE:
			{
				int rc=0;
				if (handler_again___status_SETTING_SQL_MODE(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) // we have an error we can't handle
					return -1;
			}
			break;

		case SETTING_TIME_ZONE:
			{
				int rc=0;
				if (handler_again___status_SETTING_TIME_ZONE(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) // we have an error we can't handle
					return -1;
			}
			break;

		case SETTING_INIT_CONNECT:
			{
				int rc=0;
				if (handler_again___status_SETTING_INIT_CONNECT(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) // we have an error we can't handle
					return -1;
			}
			break;

		case CHANGING_SCHEMA:
			{
				int rc=0;
				if (handler_again___status_CHANGING_SCHEMA(&rc))
					goto handler_again;	// we changed status
				if (rc==-1) // we have an error we can't handle
					return -1;
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
		return -1;
	}
	return 0;
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
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,2,0,0,0,0,NULL);	
		status=WAITING_CLIENT_DATA;
		client_myds->DSS=STATE_SLEEP;
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
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,2,1045,(char *)"28000", _s);
		free(_s);
	}
}

void MySQL_Session::handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(PtrSize_t *pkt, bool *wrong_pass) {
	if ( 
		(client_myds->myprot.process_pkt_handshake_response((unsigned char *)pkt->ptr,pkt->size)==true) 
		&&
		(
			//(default_hostgroup<0 && ( session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS || session_type == PROXYSQL_SESSION_SQLITE) )
			(default_hostgroup<0 && ( session_type == PROXYSQL_SESSION_ADMIN || session_type == PROXYSQL_SESSION_STATS) )
			||
			(default_hostgroup == 0 && session_type == PROXYSQL_SESSION_CLICKHOUSE)
			||
			//(default_hostgroup>=0 && session_type == PROXYSQL_SESSION_MYSQL)
			(default_hostgroup>=0 && ( session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE ) )
			||
			strncmp(client_myds->myconn->userinfo->username,mysql_thread___monitor_username,strlen(mysql_thread___monitor_username))==0 
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
		if (client_myds->encrypted==false) {
			if (client_myds->myconn->userinfo->schemaname==NULL) {
				client_myds->myconn->userinfo->set_schemaname(default_schema,strlen(default_schema));
			}
			int free_users=0;
			int used_users=0;
			if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_CLICKHOUSE || session_type == PROXYSQL_SESSION_SQLITE) {
			//if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_CLICKHOUSE) {
				client_authenticated=true;
				switch (session_type) {
					case PROXYSQL_SESSION_MYSQL:
					case PROXYSQL_SESSION_SQLITE:
						free_users=GloMyAuth->increase_frontend_user_connections(client_myds->myconn->userinfo->username, &used_users);
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
				*wrong_pass=true;
				client_myds->setDSS_STATE_QUERY_SENT_NET();
				if (max_connections_reached==true) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Too many connections\n");
					client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,2,1040,(char *)"08004", (char *)"Too many connections");
				} else { // see issue #794
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "User '%s' has exceeded the 'max_user_connections' resource (current value: %d)\n", client_myds->myconn->userinfo->username, used_users);
					char *a=(char *)"User '%s' has exceeded the 'max_user_connections' resource (current value: %d)";
					char *b=(char *)malloc(strlen(a)+strlen(client_myds->myconn->userinfo->username)+16);
					sprintf(b,a,client_myds->myconn->userinfo->username,used_users);
					client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,2,1226,(char *)"42000", b);
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
					if (
						(strcmp(client_addr,(char *)"127.0.0.1")==0)
						||
						(strcmp(client_addr,(char *)"localhost")==0)
					) {
						// we are good!
						client_myds->myprot.generate_pkt_OK(true,NULL,NULL,2,0,0,0,0,NULL);
						status=WAITING_CLIENT_DATA;
						client_myds->DSS=STATE_CLIENT_AUTH_OK;
					} else {
						char *a=(char *)"User '%s' can only connect locally";
						char *b=(char *)malloc(strlen(a)+strlen(client_myds->myconn->userinfo->username));
						sprintf(b,a,client_myds->myconn->userinfo->username);
						client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,2,1040,(char *)"42000", b);
						free(b);
					}
					free(client_addr);
				} else {
					// we are good!
					client_myds->myprot.generate_pkt_OK(true,NULL,NULL,2,0,0,0,0,NULL);
					status=WAITING_CLIENT_DATA;
					client_myds->DSS=STATE_CLIENT_AUTH_OK;
				}
			}
		} else {
			// use SSL
			client_myds->DSS=STATE_SSL_INIT;
			client_myds->ssl=SSL_new(GloVars.global.ssl_ctx);
			SSL_set_fd(client_myds->ssl, client_myds->fd);
			ioctl_FIONBIO(client_myds->fd,0);
			if (SSL_accept(client_myds->ssl)==-1) {
				ERR_print_errors_fp(stderr);
			}
			ioctl_FIONBIO(client_myds->fd,1);
		}
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
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,2,1045,(char *)"28000", _s);
		__sync_add_and_fetch(&MyHGM->status.client_connections_aborted,1);
		free(_s);
		client_myds->DSS=STATE_SLEEP;
	}
}

void MySQL_Session::handler___status_CONNECTING_CLIENT___STATE_SSL_INIT(PtrSize_t *pkt) {
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
}


// Note: as commented in issue #546 and #547 , some clients ignore the status of CLIENT_MULTI_STATEMENTS
// therefore tracking it is not needed, unless in future this should become a security enhancement,
// returning errors to all clients trying to send multi-statements .
// see also #1140
void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_SET_OPTION(PtrSize_t *pkt) {
	char v;
	v=*((char *)pkt->ptr+3);
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_SET_OPTION packet , value %d\n", v);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	unsigned int nTrx=NumActiveTransactions();
	uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
	if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
	if (v==1) { // disabled. MYSQL_OPTION_MULTI_STATEMENTS_OFF == 1
		client_myds->myprot.generate_pkt_EOF(true,NULL,NULL,1,0, setStatus );
	} else { // enabled, MYSQL_OPTION_MULTI_STATEMENTS_ON == 0
		client_myds->myprot.generate_pkt_EOF(true,NULL,NULL,1,0, setStatus );
	}
	client_myds->DSS=STATE_SLEEP;
	l_free(pkt->size,pkt->ptr);
}

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PING(PtrSize_t *pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_PING packet\n");
	l_free(pkt->size,pkt->ptr);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	unsigned int nTrx=NumActiveTransactions();
	uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
	if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
	client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
	client_myds->DSS=STATE_SLEEP;
}

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_FIELD_LIST(PtrSize_t *pkt) {
	if (session_type == PROXYSQL_SESSION_MYSQL) {
		/* FIXME: temporary */
		l_free(pkt->size,pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",(char *)"Command not supported");
		client_myds->DSS=STATE_SLEEP;
	} else {
		l_free(pkt->size,pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",(char *)"Command not supported");
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
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",(char *)"Command not supported");
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
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",(char *)"Command not supported");
		client_myds->DSS=STATE_SLEEP;
	}
}

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_PROCESS_KILL(PtrSize_t *pkt) {
	l_free(pkt->size,pkt->ptr);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,9003,(char *)"#28000",(char *)"Command not supported");
	client_myds->DSS=STATE_SLEEP;
}

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB(PtrSize_t *pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_INIT_DB packet\n");
	if (session_type == PROXYSQL_SESSION_MYSQL) {
		__sync_fetch_and_add(&MyHGM->status.frontend_init_db, 1);
		client_myds->myconn->userinfo->set_schemaname((char *)pkt->ptr+sizeof(mysql_hdr)+1,pkt->size-sizeof(mysql_hdr)-1);
		l_free(pkt->size,pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		unsigned int nTrx=NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,2,NULL);
		client_myds->DSS=STATE_SLEEP;
	} else {
		l_free(pkt->size,pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		unsigned int nTrx=NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
		client_myds->DSS=STATE_SLEEP;
	}
}

// this function was introduced due to isseu #718
// some application (like the one written in Perl) do not use COM_INIT_DB , but COM_QUERY with USE dbname
void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_USE_DB(PtrSize_t *pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_QUERY with USE dbname\n");
	if (session_type == PROXYSQL_SESSION_MYSQL) {
		__sync_fetch_and_add(&MyHGM->status.frontend_use_db, 1);
		char *schemaname=strndup((char *)pkt->ptr+sizeof(mysql_hdr)+5,pkt->size-sizeof(mysql_hdr)-5);
		char *schemanameptr=schemaname;
		//remove leading spaces
		while(isspace((unsigned char)*schemanameptr)) schemanameptr++;
		// remove trailing semicolon , issue #915
		if (schemanameptr[strlen(schemanameptr)-1]==';') {
			schemanameptr[strlen(schemanameptr)-1]='\0';
		}
		// handle cases like "USE `schemaname`
		if(schemanameptr[0]=='`' && schemanameptr[strlen(schemanameptr)-1]=='`') {
			schemanameptr[strlen(schemanameptr)-1]='\0';
			schemanameptr++;
		}
		client_myds->myconn->userinfo->set_schemaname(schemanameptr,strlen(schemanameptr));
		free(schemaname);
		l_free(pkt->size,pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		unsigned int nTrx=NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,2,NULL);
		client_myds->DSS=STATE_SLEEP;
	} else {
		l_free(pkt->size,pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		unsigned int nTrx=NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
		client_myds->DSS=STATE_SLEEP;
	}
}

bool MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(PtrSize_t *pkt, bool prepared) {
	unsigned char command_type=*((unsigned char *)pkt->ptr+sizeof(mysql_hdr));
	if (qpo->new_query) {
		// the query was rewritten
		l_free(pkt->size,pkt->ptr);	// free old pkt
		// allocate new pkt
		timespec begint;
		clock_gettime(CLOCK_THREAD_CPUTIME_ID,&begint);
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
		clock_gettime(CLOCK_THREAD_CPUTIME_ID,&endt);
		thread->status_variables.query_processor_time=thread->status_variables.query_processor_time +
			(endt.tv_sec*1000000000+endt.tv_nsec) -
			(begint.tv_sec*1000000000+begint.tv_nsec);
	}

	if (pkt->size > (unsigned int) mysql_thread___max_allowed_packet) {
		// ER_NET_PACKET_TOO_LARGE
		client_myds->DSS=STATE_QUERY_SENT_NET;
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,1153,(char *)"08S01",(char *)"Got a packet bigger than 'max_allowed_packet' bytes");
		l_free(pkt->size,pkt->ptr);
		RequestEnd(NULL);
		return true;
	}

	if (qpo->OK_msg) {
		client_myds->DSS=STATE_QUERY_SENT_NET;
		unsigned int nTrx=NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,client_myds->pkt_sid+1,0,0,setStatus,0,qpo->OK_msg);
		l_free(pkt->size,pkt->ptr);
		RequestEnd(NULL);
		return true;
	}

	if (qpo->error_msg) {
		client_myds->DSS=STATE_QUERY_SENT_NET;
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,1148,(char *)"42000",qpo->error_msg);
		l_free(pkt->size,pkt->ptr);
		RequestEnd(NULL);
		return true;
	}

	if (prepared) {	// for prepared statement we exit here
		goto __exit_set_destination_hostgroup;
	}

	// handle here #509, #815 and #816
	if (CurrentQuery.QueryParserArgs.digest_text) {
		char *dig=CurrentQuery.QueryParserArgs.digest_text;
		unsigned int nTrx=NumActiveTransactions();
		if (strncasecmp(dig,(char *)"SET ",4)==0) {
			int rc;
			string nq=string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
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
					if (command_type == _MYSQL_COM_QUERY) {
						client_myds->DSS=STATE_QUERY_SENT_NET;
						uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
						if (autocommit) setStatus= SERVER_STATUS_AUTOCOMMIT;
						client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
						client_myds->DSS=STATE_SLEEP;
						status=WAITING_CLIENT_DATA;
						l_free(pkt->size,pkt->ptr);
						RequestEnd(NULL);
						return true;
					}
				} else {
					proxy_error("Unable to parse query. If correct, report it as a bug: %s\n", nq.c_str());
					return false;
				}
			}
			if (match_regexes && match_regexes[1]->match(dig)) {
				// set sql_mode
				re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
				opt2->set_case_sensitive(false);
				char *pattern=(char *)"^(?: *)SET *(?:|SESSION +|@@|@@session.)SQL_MODE *(?:|:)= *(?:'||\")((\\w|,)*)(?:'||\") *(?:(|;|-- .*|#.*))$";
				re2::RE2 *re=new RE2(pattern, *opt2);
				string s;
				rc=RE2::PartialMatch(nq, *re, &s);
				delete re;
				delete opt2;
				if (rc) {
					//fprintf(stderr,"sql_mode='%s'\n", s.c_str());
					uint32_t sql_mode_int=SpookyHash::Hash32(s.c_str(),s.length(),10);
					if (client_myds->myconn->options.sql_mode_int != sql_mode_int) {
						//fprintf(stderr,"sql_mode_int='%u'\n", sql_mode_int);
						client_myds->myconn->options.sql_mode_int = sql_mode_int;
						if (client_myds->myconn->options.sql_mode) {
							free(client_myds->myconn->options.sql_mode);
						}
						client_myds->myconn->options.sql_mode=strdup(s.c_str());
					}
					if (command_type == _MYSQL_COM_QUERY) {
						client_myds->DSS=STATE_QUERY_SENT_NET;
						uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
						if (autocommit) setStatus= SERVER_STATUS_AUTOCOMMIT;
						client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
						client_myds->DSS=STATE_SLEEP;
						status=WAITING_CLIENT_DATA;
						l_free(pkt->size,pkt->ptr);
						RequestEnd(NULL);
						return true;
					}
				} else {
					proxy_error("Unable to parse query. If correct, report it as a bug: %s\n", nq.c_str());
					return false;
				}
			}
			if (match_regexes && match_regexes[2]->match(dig)) {
				// set time_zone
				re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
				opt2->set_case_sensitive(false);
				char *pattern=(char *)"^(?: *)SET *(?:|SESSION +|@@|@@session.)TIME_ZONE *(?:|:)= *(?:'||\")((\\w|/|:|\\d|\\+|-)*)(?:'||\") *(?:(|;|-- .*|#.*))$";
				re2::RE2 *re=new RE2(pattern, *opt2);
				string s;
				rc=RE2::PartialMatch(nq, *re, &s);
				delete re;
				delete opt2;
				if (rc) {
					//fprintf(stderr,"time_zone='%s'\n", s.c_str());
					uint32_t time_zone_int=SpookyHash::Hash32(s.c_str(),s.length(),10);
					if (client_myds->myconn->options.time_zone_int != time_zone_int) {
						//fprintf(stderr,"time_zone_int='%u'\n", time_zone_int);
						client_myds->myconn->options.time_zone_int = time_zone_int;
						if (client_myds->myconn->options.time_zone) {
							free(client_myds->myconn->options.time_zone);
						}
						client_myds->myconn->options.time_zone=strdup(s.c_str());
					}
					if (command_type == _MYSQL_COM_QUERY) {
						client_myds->DSS=STATE_QUERY_SENT_NET;
						uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
						if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
						client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
						client_myds->DSS=STATE_SLEEP;
						status=WAITING_CLIENT_DATA;
						l_free(pkt->size,pkt->ptr);
						RequestEnd(NULL);
						return true;
					}
				} else {
					proxy_error("Unable to parse query. If correct, report it as a bug: %s\n", nq.c_str());
					return false;
				}
			}
		}
	}

	if (mirror==true) { // for mirror session we exit here
		current_hostgroup=qpo->destination_hostgroup;
		return false;
	}
	if (qpo->cache_ttl>0) {
		uint32_t resbuf=0;
		unsigned char *aa=GloQC->get(
			client_myds->myconn->userinfo->hash,
			(const unsigned char *)CurrentQuery.QueryPointer ,
			CurrentQuery.QueryLength ,
			&resbuf ,
			thread->curtime/1000
		);
		if (aa) {
			l_free(pkt->size,pkt->ptr);
			client_myds->buffer2resultset(aa,resbuf);
			free(aa);
			client_myds->PSarrayOUT->copy_add(client_myds->resultset,0,client_myds->resultset->len);
			while (client_myds->resultset->len) client_myds->resultset->remove_index(client_myds->resultset->len-1,NULL);
			if (transaction_persistent_hostgroup == -1) {
				// not active, we can change it
				current_hostgroup=-1;
			}
			RequestEnd(NULL);
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
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_CHANGE_USER packet\n");
	//if (session_type == PROXYSQL_SESSION_MYSQL) {
	if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE) {
		reset();
		init();
		if (client_authenticated) {
			GloMyAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->username);
		}
		client_authenticated=false;
		if (client_myds->myprot.process_pkt_COM_CHANGE_USER((unsigned char *)pkt->ptr, pkt->size)==true) {
			l_free(pkt->size,pkt->ptr);
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,0,0,NULL);
			client_myds->DSS=STATE_SLEEP;
			status=WAITING_CLIENT_DATA;
			*wrong_pass=false;
			client_authenticated=true;
			int free_users=0;
			int used_users=0;
			free_users=GloMyAuth->increase_frontend_user_connections(client_myds->myconn->userinfo->username, &used_users);
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
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,2,1045,(char *)"28000", _s);
			free(_s);
		}
	} else {
		//FIXME: send an error message saying "not supported" or disconnect
		l_free(pkt->size,pkt->ptr);
	}
}

void MySQL_Session::handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection() {
			// Get a MySQL Connection
	
		MySQL_Connection *mc=NULL;
#ifdef STRESSTEST_POOL
		int i=100;
		while (i) {
			if (mc==NULL) {
				mc=MyHGM->get_MyConn_from_pool(mybe->hostgroup_id, session_fast_forward);
			}
			if (mc) {
				mybe->server_myds->attach_connection(mc);
				if (i > 1) {
					mybe->server_myds->return_MySQL_Connection_To_Pool();
					mc=NULL;
				}
			}
		i--;
		}
#else
		if (session_fast_forward == false) {
			mc=thread->get_MyConn_local(mybe->hostgroup_id); // experimental , #644
		}
		if (mc==NULL) {
			mc=MyHGM->get_MyConn_from_pool(mybe->hostgroup_id, session_fast_forward);
		} else {
			thread->status_variables.ConnPool_get_conn_immediate++;
		}
		if (mc) {
			mybe->server_myds->attach_connection(mc);
			thread->status_variables.ConnPool_get_conn_success++;
		} else {
			thread->status_variables.ConnPool_get_conn_failure++;
		}
#endif
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p -- server_myds=%p -- MySQL_Connection %p\n", this, mybe->server_myds,  mybe->server_myds->myconn);
	if (mybe->server_myds->myconn==NULL) {
		// we couldn't get a connection for whatever reason, ex: no backends, or too busy
		if (thread->mypolls.poll_timeout==0) { // tune poll timeout
			if (thread->mypolls.poll_timeout > (unsigned int)mysql_thread___poll_timeout_on_failure) {
				thread->mypolls.poll_timeout = mysql_thread___poll_timeout_on_failure;
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
		MySQL_ResultSet *MyRS=new MySQL_ResultSet(&client_myds->myprot, stmt_result, stmt->mysql, stmt);
		MyRS->get_resultset(client_myds->PSarrayOUT);
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
			if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
			if (mysql->server_status & SERVER_MORE_RESULTS_EXIST)
				setStatus += SERVER_MORE_RESULTS_EXIST;
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,client_myds->pkt_sid+1,num_rows,mysql->insert_id,mysql->server_status|setStatus,mysql->warning_count,mysql->info);
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
	if (MyRS) {
		assert(MyRS->result);
		bool transfer_started=MyRS->transfer_started;
		bool resultset_completed=MyRS->get_resultset(client_myds->PSarrayOUT);
		assert(resultset_completed); // the resultset should always be completed if MySQL_Result_to_MySQL_wire is called
		if (transfer_started==false) { // we have all the resultset when MySQL_Result_to_MySQL_wire was called
			if (qpo && qpo->cache_ttl>0) { // the resultset should be cached
				if (mysql_errno(mysql)==0) { // no errors
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
						thread->curtime/1000 + qpo->cache_ttl
					);
					l_free(client_myds->resultset_length,aa);
					client_myds->resultset_length=0;
				}
			}
		}
	} else { // no result set
		int myerrno=mysql_errno(mysql);
		if (myerrno==0) {
			unsigned int num_rows = mysql_affected_rows(mysql);
			unsigned int nTrx=NumActiveTransactions();
			uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
			if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
			if (mysql->server_status & SERVER_MORE_RESULTS_EXIST)
				setStatus += SERVER_MORE_RESULTS_EXIST;
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,client_myds->pkt_sid+1,num_rows,mysql->insert_id,mysql->server_status|setStatus,mysql->warning_count,mysql->info);
			client_myds->pkt_sid++;
		} else {
			// error
			char sqlstate[10];
			sprintf(sqlstate,"%s",mysql_sqlstate(mysql));
			if (_myds && _myds->killed_at) { // see case #750
				client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,1907,sqlstate,(char *)"Query execution was interrupted, query_timeout exceeded");
			} else {
				client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,mysql_errno(mysql),sqlstate,mysql_error(mysql));
			}
			client_myds->pkt_sid++;
		}
	}
}

void MySQL_Session::SQLite3_to_MySQL(SQLite3_result *result, char *error, int affected_rows, MySQL_Protocol *myprot) {
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

		unsigned int nTrx=NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
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
			myprot->generate_pkt_ERR(true,NULL,NULL,sid,1045,(char *)"#28000",error);
		} else {
			// no error, DML succeeded
			unsigned int nTrx=NumActiveTransactions();
			uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
			if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
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

// this should execute most of the commands executed when a request is finalized
// this should become the place to hook other functions
void MySQL_Session::RequestEnd(MySQL_Data_Stream *myds) {
	// we need to access statistics before calling CurrentQuery.end()
	// so we track the time here
	CurrentQuery.end_time=thread->curtime;

	if (qpo) {
		if (qpo->log==1) {
			GloMyLogger->log_request(this, myds);	// we send for logging only if logging is enabled for this query
		}
	}

	GloQPro->delete_QP_out(qpo);
	// if there is an associated myds, clean its status
	if (myds) {
		// if there is a mysql connection, clean its status
		if (myds->myconn) {
			myds->myconn->async_free_result();
		}
		myds->free_mysql_real_query();
	}
	// reset status of the session
	status=WAITING_CLIENT_DATA;
	// reset status of client data stream
	client_myds->DSS=STATE_SLEEP;
	// finalize the query
	CurrentQuery.end();
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
