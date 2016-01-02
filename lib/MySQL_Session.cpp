#include "proxysql.h"
#include "cpp.h"

#define SELECT_VERSION_COMMENT "select @@version_comment limit 1"
#define SELECT_VERSION_COMMENT_LEN 32
#define PROXYSQL_VERSION_COMMENT "\x01\x00\x00\x01\x01\x27\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x11\x40\x40\x76\x65\x72\x73\x69\x6f\x6e\x5f\x63\x6f\x6d\x6d\x65\x6e\x74\x00\x0c\x21\x00\x18\x00\x00\x00\xfd\x00\x00\x1f\x00\x00\x05\x00\x00\x03\xfe\x00\x00\x02\x00\x0b\x00\x00\x04\x0a(ProxySQL)\x05\x00\x00\x05\xfe\x00\x00\x02\x00"
#define PROXYSQL_VERSION_COMMENT_LEN 81
#define SELECT_LAST_INSERT_ID "SELECT LAST_INSERT_ID()"
#define SELECT_LAST_INSERT_ID_LEN 23

#define EXPMARIA

extern const CHARSET_INFO * proxysql_find_charset_name(const char * const name);

extern MySQL_Authentication *GloMyAuth;
extern ProxySQL_Admin *GloAdmin;
extern MySQL_Logger *GloMyLogger;

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
	QueryParserArgs=NULL;
}

Query_Info::~Query_Info() {
	if (QueryParserArgs) {
		GloQPro->query_parser_free(QueryParserArgs);
	}
	if (QueryPointer) {
		//l_free(QueryLength+1,QueryPointer);
	}
}

void Query_Info::begin(unsigned char *_p, int len, bool mysql_header) {
	MyComQueryCmd=MYSQL_COM_QUERY___NONE;
	QueryPointer=NULL;
	QueryLength=0;
	QueryParserArgs=NULL;
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
}

void Query_Info::init(unsigned char *_p, int len, bool mysql_header) {
	QueryLength=(mysql_header ? len-5 : len);
	//QueryPointer=(unsigned char *)l_alloc(QueryLength+1);
	//memcpy(QueryPointer,(mysql_header ? _p+5 : _p),QueryLength);
	QueryPointer=(mysql_header ? _p+5 : _p);
	//QueryPointer[QueryLength]=0;
	QueryParserArgs=NULL;
	MyComQueryCmd=MYSQL_COM_QUERY_UNKNOWN;
}

void Query_Info::query_parser_init() {
	QueryParserArgs=GloQPro->query_parser_init((char *)QueryPointer,QueryLength,0);
}

enum MYSQL_COM_QUERY_command Query_Info::query_parser_command_type() {
	MyComQueryCmd=GloQPro->query_parser_command_type(QueryParserArgs);
	return MyComQueryCmd;
}

void Query_Info::query_parser_free() {
	if (QueryParserArgs) {
		GloQPro->query_parser_free(QueryParserArgs);
		QueryParserArgs=NULL;
	}
}

unsigned long long Query_Info::query_parser_update_counters() {
	if (MyComQueryCmd==MYSQL_COM_QUERY___NONE) return 0; // this means that it was never initialized
	if (MyComQueryCmd==MYSQL_COM_QUERY_UNKNOWN) return 0; // this means that it was never initialized
	unsigned long long ret=GloQPro->query_parser_update_counters(sess, MyComQueryCmd, QueryParserArgs, end_time-start_time);
	MyComQueryCmd=MYSQL_COM_QUERY___NONE;
	//l_free(QueryLength+1,QueryPointer);
	QueryPointer=NULL;
	QueryLength=0;
	return ret;
}

char * Query_Info::get_digest_text() {
	return GloQPro->get_digest_text(QueryParserArgs);
}

void * MySQL_Session::operator new(size_t size) {
	return l_alloc(size);
}

void MySQL_Session::operator delete(void *ptr) {
	l_free(sizeof(MySQL_Session),ptr);
}


MySQL_Session::MySQL_Session() {
	thread_session_id=0;
	pause=0;
	pause_until=0;
	qpo=NULL;
	command_counters=new StatCounters(15,10,false);
	healthy=1;
	autocommit=true;
	autocommit_on_hostgroup=-1;
	killed=false;
	admin=false;
	connections_handler=false;
	max_connections_reached=false;
	stats=false;
	client_authenticated=false;
	default_schema=NULL;
	schema_locked=false;
	session_fast_forward=false;
	admin_func=NULL;
	//client_fd=0;
	//server_fd=0;
	client_myds=NULL;
	//server_myds=NULL;
	to_process=0;
	mybe=NULL;
	mybes= new (true) PtrArray(4,true);
	set_status(NONE);

	CurrentQuery.sess=this;

	current_hostgroup=-1;
	default_hostgroup=-1;
	transaction_persistent_hostgroup=-1;
	transaction_persistent=false;
	active_transactions=0;
}

MySQL_Session::~MySQL_Session() {
	if (client_myds) {
		if (client_authenticated) {
			GloMyAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->username);
		}
		delete client_myds;
	}
	//if (server_myds) {
	//	delete server_myds;
	//}
	reset_all_backends();
	delete mybes;
	if (default_schema) {
		int s=strlen(default_schema);
		l_free(s+1,default_schema);
	}
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Shutdown Session %p\n" , this->thread, this, this);
	delete command_counters;
	if (admin==false && connections_handler==false) {
		__sync_fetch_and_sub(&MyHGM->status.client_connections,1);
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
		//_mybe->server_myds->myconn = new MySQL_Connection();
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
		if (admin==false) {
			if (mybe->server_myds->net_failure==false) { 
				//if (mybe->server_myds->poll_fds_idx>-1 && (mybe->server_myds->mypolls->fds[mybe->server_myds->poll_fds_idx].revents & POLLOUT)) {
				if (mybe->server_myds->poll_fds_idx>-1) { // NOTE: attempt to force writes
					mybe->server_myds->array2buffer_full();
				}
			} else {
				mybe->server_myds->move_from_OUT_to_OUTpending();
			}
		} else {
			mybe->server_myds->array2buffer_full();
		}
	}
	// FIXME: experimental
	//if (client_myds) client_myds->set_pollout();
	//if (server_myds) server_myds->set_pollout();
	if (client_myds) client_myds->write_to_net_poll();
	//if (server_myds && server_myds->net_failure==false) server_myds->write_to_net_poll();
	if (mybe) {
		if (mybe->server_myds) mybe->server_myds->write_to_net_poll();
	}
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Writeout Session %p\n" , this->thread, this, this);
}

bool MySQL_Session::handler_special_queries(PtrSize_t *pkt) {
	if (pkt->size==SELECT_LAST_INSERT_ID_LEN+5 && strncasecmp((char *)SELECT_LAST_INSERT_ID,(char *)pkt->ptr+5,pkt->size-5)==0) {
		char buf[16];
		sprintf(buf,"%u",last_insert_id);
		unsigned int nTrx=NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
		MySQL_Data_Stream *myds=client_myds;
		MySQL_Protocol *myprot=&client_myds->myprot;
		myds->DSS=STATE_QUERY_SENT_DS;
		int sid=1;
		myprot->generate_pkt_column_count(true,NULL,NULL,sid,1); sid++;
		myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",(char *)"LAST_INSERT_ID()",(char *)"",33,15,MYSQL_TYPE_VAR_STRING,1,0x1f,false,0,NULL); sid++;
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
	if ( (pkt->size < 25) && (pkt->size > 15) && (strncasecmp((char *)"SET NAMES ",(char *)pkt->ptr+5,10)==0) ) {
		char *name=strndup((char *)pkt->ptr+15,pkt->size-15);
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
		free(name);
		return true;
	}

	size_t sal=strlen("set autocommit");
	if ( pkt->size > 7+sal) {
		if (strncasecmp((char *)"set autocommit",(char *)pkt->ptr+5,sal)==0) {
			unsigned int i;
			bool eq=false;
			int fd=-1; // first digit
			for (i=5+sal;i<pkt->size;i++) {
				char c=((char *)pkt->ptr)[i];
				if (c!='0' && c!='1' && c!=' ' && c!='=') return false; // found a not valid char
				if (eq==false) {
					if (c!=' ' && c!='=') return false; // found a not valid char
					if (c=='=') eq=true;
				} else {
					if (c!='0' && c!='1' && c!=' ') return false; // found a not valid char
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
						autocommit=false;
						goto __ret_autocommit_OK;
					}
				}

				if (fd==0) {
					autocommit=false;	// we set it, no matter if already set or not
					if (nTrx) {
						// there is an active transaction, we need to forward it
						// because this can potentially close the transaction
						autocommit_on_hostgroup=FindOneActiveTransaction();
						return false;
					} else {
						// as there is no active transaction, we do no need to forward it
						// just return OK
						goto __ret_autocommit_OK;
					}
				}
__ret_autocommit_OK:
				client_myds->DSS=STATE_QUERY_SENT_NET;
				uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
				if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
				client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
				client_myds->DSS=STATE_SLEEP;
				status=WAITING_CLIENT_DATA;
				l_free(pkt->size,pkt->ptr);
				return true;
			}
		}
	}

	return false;
}

int MySQL_Session::handler() {
	bool wrong_pass=false;
	if (to_process==0) return 0; // this should be redundant if the called does the same check
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Processing session %p\n" , this->thread, this, this);
	PtrSize_t pkt;
	unsigned int j;
	unsigned char c;

//	FIXME: Sessions without frontend are an ugly hack
	if (session_fast_forward==false) {
	if (client_myds==NULL) {
		// if we are here, probably we are trying to ping backends
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Processing session %p without client_myds\n", this);
		assert(mybe);
		assert(mybe->server_myds);
		goto handler_again;
		//goto __exit_DSS__STATE_NOT_INITIALIZED;
	}
	}

__get_pkts_from_client:

	for (j=0; j<client_myds->PSarrayIN->len;) {
		client_myds->PSarrayIN->remove_index(0,&pkt);
		//prot.parse_mysql_pkt(&pkt,client_myds);
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
				if (pkt.size==(0xFFFFFF+sizeof(mysql_hdr))) {
					// we are handling a multi-packet
					switch (client_myds->DSS) {
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
					case STATE_SLEEP:
						command_counters->incr(thread->curtime/1000000);
						if (transaction_persistent_hostgroup==-1) {
							current_hostgroup=default_hostgroup;
						}
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: WAITING_CLIENT_DATA - STATE_SLEEP\n");
						//unsigned char c;
						c=*((unsigned char *)pkt.ptr+sizeof(mysql_hdr));
						switch ((enum_mysql_command)c) {
							case _MYSQL_COM_QUERY:
								__sync_add_and_fetch(&thread->status_variables.queries,1);
								if (admin==false) {
									bool rc_break=false;
									if (session_fast_forward==false) {
										// Note: CurrentQuery sees the query as sent by the client.
										// shortly after, the packets it used to contain the query will be deallocated
										CurrentQuery.begin((unsigned char *)pkt.ptr,pkt.size,true);
									}
									rc_break=handler_special_queries(&pkt);
									if (rc_break==true) {
										// track also special queries
										RequestEnd(NULL);
										break;
									}

									qpo=GloQPro->process_mysql_query(this,pkt.ptr,pkt.size,&CurrentQuery);
									assert(qpo);	// GloQPro->process_mysql_query() should always return a qpo
									rc_break=handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(&pkt);
									if (rc_break==true) { break; }

									if (autocommit_on_hostgroup>=0) {
									}
									mybe=find_or_create_backend(current_hostgroup);
									status=PROCESSING_QUERY;
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
									// this is processed by the admin module
									admin_func(this, GloAdmin, &pkt);
									l_free(pkt.size,pkt.ptr);
								}
								break;
							case _MYSQL_COM_CHANGE_USER:
								handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_CHANGE_USER(&pkt, &wrong_pass);
								break;
							case _MYSQL_COM_STMT_PREPARE:
							case _MYSQL_COM_STMT_EXECUTE:
							case _MYSQL_COM_STMT_CLOSE:
								l_free(pkt.size,pkt.ptr);
								client_myds->setDSS_STATE_QUERY_SENT_NET();
								client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",(char *)"Command not supported");
								client_myds->DSS=STATE_SLEEP;
								status=WAITING_CLIENT_DATA;
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
							default:
								assert(0);
								break;
						}
						break;
					default:
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: WAITING_CLIENT_DATA - STATE_UNKNOWN\n");
						{
							char buf[256];
							if (client_myds->client_addr->sa_family==AF_INET) {
								struct sockaddr_in * ipv4addr=(struct sockaddr_in *)client_myds->client_addr;
								sprintf(buf,"%s:%d", inet_ntoa(ipv4addr->sin_addr), htons(ipv4addr->sin_port));
							} else {
								sprintf(buf,"localhost");
							}
						proxy_error("Unexpected packet from client %s . Session_status: %d , client_status: %d Disconnecting it\n", buf, status, client_myds->status);
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


#define NEXT_IMMEDIATE(new_st) do { set_status(new_st); goto handler_again; } while (0)

handler_again:

	switch (status) {
		case FAST_FORWARD:
			fprintf(stderr,"FAST_FORWARD\n");
			// FIXME: to implement
			break;
		case CONNECTING_CLIENT:
			//fprintf(stderr,"CONNECTING_CLIENT\n");
			// FIXME: to implement
			break;
		case PINGING_SERVER:
			
			assert(mybe->server_myds->myconn);
			{	
				MySQL_Data_Stream *myds=mybe->server_myds;
				MySQL_Connection *myconn=myds->myconn;
				int rc=myconn->async_ping(myds->revents);
//				if (myds->mypolls==NULL) {
//					thread->mypolls.add(POLLIN|POLLOUT, myds->fd, myds, thread->curtime);
//				}
				if (rc==0) {
					myconn->async_state_machine=ASYNC_IDLE;
					//if ((myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
					if ((myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
						myds->return_MySQL_Connection_To_Pool();
					}
					delete mybe->server_myds;
					mybe->server_myds=NULL;
					set_status(NONE);
					return -1;
				} else {
					if (rc==-1) {
						proxy_error("Detected a broken connection during ping on %s , %d\n", myconn->parent->address, myconn->parent->port);
						myds->destroy_MySQL_Connection_From_Pool();
						myds->fd=0;
						delete mybe->server_myds;
						mybe->server_myds=NULL;
						//thread->mypolls.remove_index_fast(myds->poll_fds_idx);
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
			}
			break;

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
				MySQL_Data_Stream *myds=mybe->server_myds;
				if (myds->myconn && myds->myconn->mysql) {
					if (myds->killed_at==0) {
						myds->wait_until=0;
						myds->killed_at=thread->curtime;
						//fprintf(stderr,"Expired: %llu, %llu\n", mybe->server_myds->wait_until, thread->curtime);
						MySQL_Connection_userinfo *ui=client_myds->myconn->userinfo;
						KillArgs *ka = new KillArgs(ui->username, ui->password, myds->myconn->parent->address, myds->myconn->parent->port, myds->myconn->mysql->thread_id);
						pthread_attr_t attr;
						pthread_attr_init(&attr);
						pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
						pthread_attr_setstacksize (&attr, 256*1024);
						pthread_t pt;
						pthread_create(&pt, &attr, &kill_query_thread, ka);
					}
				}
			}
			if (mybe->server_myds->DSS==STATE_NOT_INITIALIZED) {
				// we don't have a backend yet
				previous_status.push(PROCESSING_QUERY);
				NEXT_IMMEDIATE(CONNECTING_SERVER);
			} else {
				MySQL_Data_Stream *myds=mybe->server_myds;
				MySQL_Connection *myconn=myds->myconn;
				if (client_myds->myconn->userinfo->hash!=mybe->server_myds->myconn->userinfo->hash) {
					if (strcmp(client_myds->myconn->userinfo->username,myds->myconn->userinfo->username)) {
						previous_status.push(PROCESSING_QUERY);
						NEXT_IMMEDIATE(CHANGING_USER_SERVER);
					}
					if (strcmp(client_myds->myconn->userinfo->schemaname,myds->myconn->userinfo->schemaname)) {
						previous_status.push(PROCESSING_QUERY);
						NEXT_IMMEDIATE(CHANGING_SCHEMA);
					}
				}
				if (client_myds->myconn->options.charset != mybe->server_myds->myconn->mysql->charset->nr) {
					previous_status.push(PROCESSING_QUERY);
					NEXT_IMMEDIATE(CHANGING_CHARSET);
				}
				if (autocommit != mybe->server_myds->myconn->IsAutoCommit()) {
					previous_status.push(PROCESSING_QUERY);
					NEXT_IMMEDIATE(CHANGING_AUTOCOMMIT);
				}
				status=PROCESSING_QUERY;
				mybe->server_myds->max_connect_time=0;
				// we insert it in mypolls only if not already there
				if (myds->mypolls==NULL) {
					thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
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
				int rc=myconn->async_query(myds->revents, myds->mysql_real_query.QueryPtr,myds->mysql_real_query.QuerySize);

//				if (myconn->async_state_machine==ASYNC_QUERY_END) {
				if (rc==0) {
					// FIXME: deprecate old MySQL_Result_to_MySQL_wire , not completed yet
					//MySQL_Result_to_MySQL_wire(myconn->mysql,myconn->mysql_result,&client_myds->myprot);


					// check if multiplexing needs to be disabled
					char *qdt=CurrentQuery.get_digest_text();
					if (qdt)
						myconn->ProcessQueryAndSetStatusFlags(qdt);

					// Support for LAST_INSERT_ID()
					if (myconn->mysql->insert_id) {
						last_insert_id=myconn->mysql->insert_id;
					}
					MySQL_Result_to_MySQL_wire(myconn->mysql, myconn->MyRS);
//					GloQPro->delete_QP_out(qpo);
//					qpo=NULL;
//					myconn->async_free_result();
//					status=WAITING_CLIENT_DATA;
//					client_myds->DSS=STATE_SLEEP;
//					CurrentQuery.end();
//					myds->free_mysql_real_query();
					RequestEnd(myds);
					//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
					if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
						myds->DSS=STATE_NOT_INITIALIZED;
						myds->return_MySQL_Connection_To_Pool();
						if (transaction_persistent==true) {
							transaction_persistent_hostgroup=-1;
						}
					} else {
						myconn->async_state_machine=ASYNC_IDLE;
						myds->DSS=STATE_MARIADB_GENERIC;
						if (transaction_persistent==true) {
							transaction_persistent_hostgroup=current_hostgroup;
						}
					}
				} else {
					if (rc==-1) {
						// the query failed
						if (myconn->parent->status==MYSQL_SERVER_STATUS_OFFLINE_HARD) {
							// the query failed because the server is offline hard
							if (mysql_thread___connect_timeout_server_max) {
								myds->max_connect_time=thread->curtime+mysql_thread___connect_timeout_server_max*1000;
							}
							bool retry_conn=false;
							proxy_error("Detected an offline server during query: %s, %d\n", myconn->parent->address, myconn->parent->port);
							if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
								if (myds->myconn->MyRS && myds->myconn->MyRS->transfer_started) {
								// transfer to frontend has started, we cannot retry
								} else {
									retry_conn=true;
								}
							}
							myds->destroy_MySQL_Connection_From_Pool();
							myds->fd=0;
							if (retry_conn) {
								myds->DSS=STATE_NOT_INITIALIZED;
								previous_status.push(PROCESSING_QUERY);
								NEXT_IMMEDIATE(CONNECTING_SERVER);
							}
							return -1;
						}
						int myerr=mysql_errno(myconn->mysql);
						if (myerr > 2000) {
							bool retry_conn=false;
							// client error, serious
							proxy_error("Detected a broken connection during query on server %s, %d : %d, %s\n", myconn->parent->address, myconn->parent->port, myerr, mysql_error(myconn->mysql));
							//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
							if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
								if (myds->myconn->MyRS && myds->myconn->MyRS->transfer_started) {
								// transfer to frontend has started, we cannot retry
								} else {
									retry_conn=true;
								}
							}
							myds->destroy_MySQL_Connection_From_Pool();
							myds->fd=0;
							if (retry_conn) {
								myds->DSS=STATE_NOT_INITIALIZED;
								previous_status.push(PROCESSING_QUERY);
								NEXT_IMMEDIATE(CONNECTING_SERVER);
							}
							return -1;
						} else {
							proxy_warning("Error during query: %d, %s\n", myerr, mysql_error(myconn->mysql));
							// FIXME: deprecate old MySQL_Result_to_MySQL_wire , not completed yet
							//MySQL_Result_to_MySQL_wire(myconn->mysql,myconn->mysql_result,&client_myds->myprot);


							bool retry_conn=false;
							switch (myerr) {
								case 1317:  // Query execution was interrupted
									if (killed==true || myds->killed_at) {
										return -1;
									}
								case 1290: // read-only
									if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
										retry_conn=true;
									}
									myds->destroy_MySQL_Connection_From_Pool();
									myds->fd=0;
									if (retry_conn) {
										myds->DSS=STATE_NOT_INITIALIZED;
										previous_status.push(PROCESSING_QUERY);
										NEXT_IMMEDIATE(CONNECTING_SERVER);
									}
									return -1;
									break;
								default:
									break; // continue normally
							}

							MySQL_Result_to_MySQL_wire(myconn->mysql, myconn->MyRS);
//							CurrentQuery.end();
//							GloQPro->delete_QP_out(qpo);
//							qpo=NULL;
//							myconn->async_free_result();
							//myds->DSS=STATE_NOT_INITIALIZED;
//							status=WAITING_CLIENT_DATA;
//							client_myds->DSS=STATE_SLEEP;
//							myds->free_mysql_real_query();
							RequestEnd(myds);
							//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
							if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
								myds->DSS=STATE_NOT_INITIALIZED;
								myds->return_MySQL_Connection_To_Pool();
							} else {
								myconn->async_state_machine=ASYNC_IDLE;
								myds->DSS=STATE_MARIADB_GENERIC;
							}
						}
					} else {
						// rc==1 , query is still running
						// start sending to frontend if mysql_thread___threshold_resultset_size is reached
						if (myconn->MyRS && myconn->MyRS->result && myconn->MyRS->resultset_size > (unsigned int) mysql_thread___threshold_resultset_size) {
							myconn->MyRS->get_resultset(client_myds->PSarrayOUT);
						}
					}
				}

				goto __exit_DSS__STATE_NOT_INITIALIZED;


			}
			break;

		case CHANGING_USER_SERVER:
			//fprintf(stderr,"CHANGING_USER\n");
			assert(mybe->server_myds->myconn);
			{
				MySQL_Data_Stream *myds=mybe->server_myds;
				MySQL_Connection *myconn=myds->myconn;
				myds->DSS=STATE_MARIADB_QUERY;
				enum session_status st=status;
				if (myds->mypolls==NULL) {
					thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
				}
				int rc=myconn->async_change_user(myds->revents);
				if (rc==0) {
					myds->myconn->userinfo->set(client_myds->myconn->userinfo);
					st=previous_status.top();
					previous_status.pop();
					NEXT_IMMEDIATE(st);
				} else {
					if (rc==-1) {
						// the command failed
						int myerr=mysql_errno(myconn->mysql);
						if (myerr > 2000) {
							bool retry_conn=false;
							// client error, serious
							proxy_error("Detected a broken connection during change user on %s, %d : %d, %s\n", myconn->parent->address, myconn->parent->port, myerr, mysql_error(myconn->mysql));
							//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
							if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
								retry_conn=true;
							}
							myds->destroy_MySQL_Connection_From_Pool();
							myds->fd=0;
							if (retry_conn) {
								myds->DSS=STATE_NOT_INITIALIZED;
								//previous_status.push(PROCESSING_QUERY);
								NEXT_IMMEDIATE(CONNECTING_SERVER);
							}
							return -1;
						} else {
							proxy_warning("Error during change user: %d, %s\n", myerr, mysql_error(myconn->mysql));
								// we won't go back to PROCESSING_QUERY
							st=previous_status.top();
							previous_status.pop();
							char sqlstate[10];
							sprintf(sqlstate,"#%s",mysql_sqlstate(myconn->mysql));
							client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql));
							myds->destroy_MySQL_Connection_From_Pool();
							myds->fd=0;
							status=WAITING_CLIENT_DATA;
							client_myds->DSS=STATE_SLEEP;
						}
					} else {
						// rc==1 , nothing to do for now
					}
				}
			}
			break;

		case CHANGING_AUTOCOMMIT:
			//fprintf(stderr,"CHANGING_AUTOCOMMIT\n");
			assert(mybe->server_myds->myconn);
			{
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
					NEXT_IMMEDIATE(st);
				} else {
					if (rc==-1) {
						// the command failed
						int myerr=mysql_errno(myconn->mysql);
						if (myerr > 2000) {
							bool retry_conn=false;
							// client error, serious
							proxy_error("Detected a broken connection during SET AUTOCOMMIT on %s , %d : %d, %s\n", myconn->parent->address, myconn->parent->port, myerr, mysql_error(myconn->mysql));
							//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
							if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
								retry_conn=true;
							}
							myds->destroy_MySQL_Connection_From_Pool();
							myds->fd=0;
							if (retry_conn) {
								myds->DSS=STATE_NOT_INITIALIZED;
								//previous_status.push(PROCESSING_QUERY);
								NEXT_IMMEDIATE(CONNECTING_SERVER);
							}
							return -1;
						} else {
							proxy_warning("Error during SET AUTOCOMMIT: %d, %s\n", myerr, mysql_error(myconn->mysql));
								// we won't go back to PROCESSING_QUERY
							st=previous_status.top();
							previous_status.pop();
							char sqlstate[10];
							sprintf(sqlstate,"#%s",mysql_sqlstate(myconn->mysql));
							client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql));
								myds->destroy_MySQL_Connection_From_Pool();
								myds->fd=0;
							status=WAITING_CLIENT_DATA;
							client_myds->DSS=STATE_SLEEP;
						}
					} else {
						// rc==1 , nothing to do for now
					}
				}
			}
			break;

		case CHANGING_CHARSET:
			//fprintf(stderr,"CHANGING_SCHEMA\n");
			assert(mybe->server_myds->myconn);
			{
				MySQL_Data_Stream *myds=mybe->server_myds;
				MySQL_Connection *myconn=myds->myconn;
				myds->DSS=STATE_MARIADB_QUERY;
				enum session_status st=status;
				if (myds->mypolls==NULL) {
					thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
				}
				int rc=myconn->async_set_names(myds->revents, client_myds->myconn->options.charset);
				if (rc==0) {
					st=previous_status.top();
					previous_status.pop();
					NEXT_IMMEDIATE(st);
				} else {
					if (rc==-1) {
						// the command failed
						int myerr=mysql_errno(myconn->mysql);
						if (myerr > 2000) {
							bool retry_conn=false;
							// client error, serious
							proxy_error("Detected a broken connection during SET NAMES on %s , %d : %d, %s\n", myconn->parent->address, myconn->parent->port, myerr, mysql_error(myconn->mysql));
							//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
							if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
								retry_conn=true;
							}
							myds->destroy_MySQL_Connection_From_Pool();
							myds->fd=0;
							if (retry_conn) {
								myds->DSS=STATE_NOT_INITIALIZED;
								//previous_status.push(PROCESSING_QUERY);
								NEXT_IMMEDIATE(CONNECTING_SERVER);
							}
							return -1;
						} else {
							proxy_warning("Error during SET NAMES: %d, %s\n", myerr, mysql_error(myconn->mysql));
								// we won't go back to PROCESSING_QUERY
							st=previous_status.top();
							previous_status.pop();
							char sqlstate[10];
							sprintf(sqlstate,"#%s",mysql_sqlstate(myconn->mysql));
							client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql));
								myds->destroy_MySQL_Connection_From_Pool();
								myds->fd=0;
							status=WAITING_CLIENT_DATA;
							client_myds->DSS=STATE_SLEEP;
						}
					} else {
						// rc==1 , nothing to do for now
					}
				}
			}
			break;

		case CHANGING_SCHEMA:
			//fprintf(stderr,"CHANGING_SCHEMA\n");
			assert(mybe->server_myds->myconn);
			{
				MySQL_Data_Stream *myds=mybe->server_myds;
				MySQL_Connection *myconn=myds->myconn;
				myds->DSS=STATE_MARIADB_QUERY;
				enum session_status st=status;
				if (myds->mypolls==NULL) {
					thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, thread->curtime);
				}
				int rc=myconn->async_select_db(myds->revents);
				if (rc==0) {
					myds->myconn->userinfo->set(client_myds->myconn->userinfo);
					st=previous_status.top();
					previous_status.pop();
					NEXT_IMMEDIATE(st);
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
							myds->destroy_MySQL_Connection_From_Pool();
							myds->fd=0;
							if (retry_conn) {
								myds->DSS=STATE_NOT_INITIALIZED;
								//previous_status.push(PROCESSING_QUERY);
								NEXT_IMMEDIATE(CONNECTING_SERVER);
							}
							return -1;
						} else {
							proxy_warning("Error during INIT_DB: %d, %s\n", myerr, mysql_error(myconn->mysql));
								// we won't go back to PROCESSING_QUERY
							st=previous_status.top();
							previous_status.pop();
							char sqlstate[10];
							sprintf(sqlstate,"#%s",mysql_sqlstate(myconn->mysql));
							client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql));
//							CurrentQuery.end();
//							myds->free_mysql_real_query();
							myds->destroy_MySQL_Connection_From_Pool();
							myds->fd=0;
//							status=WAITING_CLIENT_DATA;
//							client_myds->DSS=STATE_SLEEP;
							RequestEnd(myds);
						}
					} else {
						// rc==1 , nothing to do for now
					}
				}
			}
			break;

		case CONNECTING_SERVER:
			//fprintf(stderr,"CONNECTING_SERVER\n");
			if (mybe->server_myds->max_connect_time) {
				if (thread->curtime >= mybe->server_myds->max_connect_time) {
					char buf[256];
					sprintf(buf,"Max connect timeout reached while reaching hostgroup %d after %llums", current_hostgroup, (thread->curtime - CurrentQuery.start_time)/1000 );
					client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",buf);
//					CurrentQuery.end();
//					mybe->server_myds->free_mysql_real_query();
//					client_myds->DSS=STATE_SLEEP;
					RequestEnd(mybe->server_myds);
					//enum session_status st;
					while (previous_status.size()) {
						previous_status.top();
						previous_status.pop();
					}
					if (mybe->server_myds->myconn) {
						//mybe->server_myds->destroy_MySQL_Connection();
						mybe->server_myds->destroy_MySQL_Connection_From_Pool();
					}
					mybe->server_myds->max_connect_time=0;
					NEXT_IMMEDIATE(WAITING_CLIENT_DATA);					
				}
			}
			if (mybe->server_myds->myconn==NULL) {
				handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection();
			}	
			if (mybe->server_myds->myconn==NULL) {
				pause_until=thread->curtime+mysql_thread___connect_retries_delay*1000;
				goto __exit_DSS__STATE_NOT_INITIALIZED;
			} else {
				MySQL_Data_Stream *myds=mybe->server_myds;
				MySQL_Connection *myconn=myds->myconn;
				int rc;
				enum session_status st=status;
				if (mybe->server_myds->myconn->async_state_machine==ASYNC_IDLE) {
					st=previous_status.top();
					previous_status.pop();
					NEXT_IMMEDIATE(st);
					assert(0);
				}
				assert(st==status);
				unsigned long long curtime=monotonic_time();
				//mybe->server_myds->myprot.init(&mybe->server_myds, mybe->server_myds->myconn->userinfo, this);
				if (myds->mypolls==NULL) {
					thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, curtime);
				}
/* */
				assert(myconn->async_state_machine!=ASYNC_IDLE);
				rc=myconn->async_connect(myds->revents);
				switch (rc) {
					case 0:
						myds->myds_type=MYDS_BACKEND;
						myds->DSS=STATE_MARIADB_GENERIC;
						status=WAITING_CLIENT_DATA;
						st=previous_status.top();
						previous_status.pop();
						myds->wait_until=0;
						NEXT_IMMEDIATE(st);
						break;
					case -1:
					case -2:
						// FIXME: experimental
						//wrong_pass=true;
						if (myds->connect_retries_on_failure >0 ) {
							myds->connect_retries_on_failure--;
							//myds->destroy_MySQL_Connection();
							myds->destroy_MySQL_Connection_From_Pool();
							NEXT_IMMEDIATE(CONNECTING_SERVER);
						} else {
							int myerr=mysql_errno(myconn->mysql);
							if (myerr) {
								char sqlstate[10];
								sprintf(sqlstate,"#%s",mysql_sqlstate(myconn->mysql));
								client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,mysql_errno(myconn->mysql),sqlstate,mysql_error(myconn->mysql));
							} else {
								char buf[256];
								sprintf(buf,"Max connect failure while reaching hostgroup %d", current_hostgroup);
								client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",buf);
							}
//							CurrentQuery.end();
//							myds->free_mysql_real_query();
//							client_myds->DSS=STATE_SLEEP;
							RequestEnd(myds);
							while (previous_status.size()) {
								st=previous_status.top();
								previous_status.pop();
							}
							//myds->destroy_MySQL_Connection();
							myds->destroy_MySQL_Connection_From_Pool();
							myds->max_connect_time=0;
							NEXT_IMMEDIATE(WAITING_CLIENT_DATA);
						}
						break;
					case 1: // continue on next loop
					default:
						break;
				}
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
		MySQL_Data_Stream *myds=mybe->server_myds;
		MySQL_Connection *myconn=mybe->server_myds->myconn;
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, status=%d, server_myds->DSS==%d , revents==%d , async_state_machine=%d\n", this, status, mybe->server_myds->DSS, myds->revents, myconn->async_state_machine);
	} else {


//	}


/*
		ATTEMPT TO COMMENT THIS BLOCK
		leaving ONLY FAST_FORWARD for now
		for (j=0; j<mybe->server_myds->PSarrayIN->len;) {
			mybe->server_myds->PSarrayIN->remove_index(0,&pkt);

		switch (status) {
			case FAST_FORWARD:
				client_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
				break;

			default:
					assert(0);
				break;
		}

		}
*/
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
		char *_s=(char *)malloc(strlen(client_myds->myconn->userinfo->username)+100);
		sprintf(_s,"Access denied for user '%s' (using password: %s)", client_myds->myconn->userinfo->username, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,2,1045,(char *)"#28000", _s);
		free(_s);
	}
}

void MySQL_Session::handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(PtrSize_t *pkt, bool *wrong_pass) {
	if ( 
		(client_myds->myprot.process_pkt_handshake_response((unsigned char *)pkt->ptr,pkt->size)==true) 
		&&
		( (default_hostgroup<0 && admin==true) || (default_hostgroup>=0 && admin==false) )
	)	{
		if (default_hostgroup<0 && admin==true) {
			if (default_hostgroup==STATS_HOSTGROUP) {
				stats=true;
			}
		}
		l_free(pkt->size,pkt->ptr);
		if (client_myds->encrypted==false) {
			if (client_myds->myconn->userinfo->schemaname==NULL) {
				//client_myds->myconn->userinfo->set_schemaname(mysql_thread___default_schema,strlen(mysql_thread___default_schema));
				client_myds->myconn->userinfo->set_schemaname(default_schema,strlen(default_schema));
			}
			int free_users=0;
			if (admin==false) {
				client_authenticated=true;
				free_users=GloMyAuth->increase_frontend_user_connections(client_myds->myconn->userinfo->username);
			}
			if (max_connections_reached==true || free_users<0) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Too many connections\n");
				*wrong_pass=true;
				client_myds->setDSS_STATE_QUERY_SENT_NET();
				client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,2,1040,(char *)"#HY000", (char *)"Too many connections");
				__sync_add_and_fetch(&MyHGM->status.client_connections_aborted,1);
				client_myds->DSS=STATE_SLEEP;
			} else {
				client_myds->myprot.generate_pkt_OK(true,NULL,NULL,2,0,0,0,0,NULL);
			//server_myds->myconn->userinfo->set(client_myds->myconn->userinfo);
				status=WAITING_CLIENT_DATA;
				client_myds->DSS=STATE_CLIENT_AUTH_OK;
			//MySQL_Connection *myconn=client_myds->myconn;
/*
			// enable compression
			if (myconn->options.server_capabilities & CLIENT_COMPRESS) {
				if (myconn->options.compression_min_length) {
					myconn->set_status_compression(true);
				}
			} else {
				//explicitly disable compression
				myconn->options.compression_min_length=0;
				myconn->set_status_compression(false);
			}
*/
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
		char *_s=(char *)malloc(strlen(client_myds->myconn->userinfo->username)+100);
		sprintf(_s,"Access denied for user '%s' (using password: %s)", client_myds->myconn->userinfo->username, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,2,1045,(char *)"#28000", _s);
		__sync_add_and_fetch(&MyHGM->status.client_connections_aborted,1);
		free(_s);
		client_myds->DSS=STATE_SLEEP;
		//return -1;
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





void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_SET_OPTION(PtrSize_t *pkt) {
	char v;
	v=*((char *)pkt->ptr+3);
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_SET_OPTION packet , value %d\n", v);
	// FIXME: ProxySQL doesn't support yet CLIENT_MULTI_STATEMENTS 
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	if (v==1) {
		unsigned int nTrx=NumActiveTransactions();
		uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
		if (autocommit) setStatus += SERVER_STATUS_AUTOCOMMIT;
		client_myds->myprot.generate_pkt_EOF(true,NULL,NULL,1,0, setStatus );
	} else {
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",(char *)"");
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
	if (admin==false) {
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
	if (admin==false) {
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
	if (admin==false) {
		//client_myds->myconn->has_prepared_statement_execute=true;
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


void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB(PtrSize_t *pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_INIT_DB packet\n");
	if (admin==false) {
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



bool MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(PtrSize_t *pkt) {
	if (qpo->error_msg) {
		client_myds->DSS=STATE_QUERY_SENT_NET;
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1148,(char *)"#42000",qpo->error_msg);
//		client_myds->DSS=STATE_SLEEP;
//		status=WAITING_CLIENT_DATA;
		l_free(pkt->size,pkt->ptr);
//		CurrentQuery.end();
//		GloQPro->delete_QP_out(qpo);
//		qpo=NULL;
		RequestEnd(NULL);
		return true;
	}
	if (qpo->new_query) {
		// the query was rewritten
		l_free(pkt->size,pkt->ptr);	// free old pkt
		// allocate new pkt
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
	}
	if (qpo->cache_ttl>0) {
		uint32_t resbuf=0;
		unsigned char *aa=GloQC->get(
			client_myds->myconn->userinfo->hash,
			(const unsigned char *)client_myds->mysql_real_query.QueryPtr ,
			client_myds->mysql_real_query.QuerySize ,
			&resbuf ,
			thread->curtime/1000
		);
		if (aa) {
			l_free(pkt->size,pkt->ptr);
			client_myds->buffer2resultset(aa,resbuf);
			free(aa);
			client_myds->PSarrayOUT->copy_add(client_myds->resultset,0,client_myds->resultset->len);
			while (client_myds->resultset->len) client_myds->resultset->remove_index(client_myds->resultset->len-1,NULL);
//			status=WAITING_CLIENT_DATA;
//			client_myds->DSS=STATE_SLEEP;
//			CurrentQuery.end();
//			GloQPro->delete_QP_out(qpo);
//			qpo=NULL;
			RequestEnd(NULL);
			return true;
		}
	}
	if ( qpo->destination_hostgroup >= 0 ) {
		if (transaction_persistent_hostgroup == -1) {
			current_hostgroup=qpo->destination_hostgroup;
		}
	}
	if (autocommit_on_hostgroup >= 0) {
		// the query is a "set autocommit=0"
		// we set current_hostgroup=autocommit_on_hostgroup if possible
		if (transaction_persistent_hostgroup == -1) {
			if (qpo->destination_hostgroup==-1) {
				current_hostgroup=autocommit_on_hostgroup;
			}
		}
		autocommit_on_hostgroup=-1;	// at the end, always reset autocommit_on_hostgroup to -1
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
	if (admin==false) {
		if (client_myds->myprot.process_pkt_COM_CHANGE_USER((unsigned char *)pkt->ptr, pkt->size)==true) {
			l_free(pkt->size,pkt->ptr);
			//client_myds->myprot.generate_pkt_auth_switch_request(true,NULL,NULL);
			//client_myds->DSS=STATE_CLIENT_HANDSHAKE;
			//status=CHANGING_USER_CLIENT;
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,0,0,NULL);
			client_myds->DSS=STATE_SLEEP;
			status=WAITING_CLIENT_DATA;
			*wrong_pass=false;
		} else {
			l_free(pkt->size,pkt->ptr);
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Wrong credentials for frontend: disconnecting\n");
			*wrong_pass=true;
		// FIXME: this should become close connection
			client_myds->setDSS_STATE_QUERY_SENT_NET();
			char *_s=(char *)malloc(strlen(client_myds->myconn->userinfo->username)+100);
			sprintf(_s,"Access denied for user '%s' (using password: %s)", client_myds->myconn->userinfo->username, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,2,1045,(char *)"#28000", _s);
			free(_s);
		}
	} else {
		//FIXME: send an error message saying "not supported" or disconnect
		l_free(pkt->size,pkt->ptr);
	}
}

void MySQL_Session::handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection() {
			// Get a MySQL Connection
	
//	if (rand()%3==0) {
		MySQL_Connection *mc=MyHGM->get_MyConn_from_pool(mybe->hostgroup_id);
		if (mc) {
			mybe->server_myds->attach_connection(mc);
		}
//	}
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
		// FIXME: set client_flags
		//mybe->server_myds->myconn->connect_start();
		//mybe->server_myds->fd=myconn->fd;

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
		}
	}
}

void MySQL_Session::MySQL_Result_to_MySQL_wire(MYSQL *mysql, MySQL_ResultSet *MyRS) {
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
						(const unsigned char *)client_myds->mysql_real_query.QueryPtr ,
						client_myds->mysql_real_query.QuerySize ,
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
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,client_myds->pkt_sid+1,num_rows,mysql->insert_id,mysql->server_status|setStatus,mysql->warning_count,mysql->info);
		} else {
			// error
			char sqlstate[10];
			sprintf(sqlstate,"#%s",mysql_sqlstate(mysql));
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,mysql_errno(mysql),sqlstate,mysql_error(mysql));
		}
	}
}

void MySQL_Session::SQLite3_to_MySQL(SQLite3_result *result, char *error, int affected_rows, MySQL_Protocol *myprot) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	int sid=1;
	if (result) {
//	sess->myprot_client.generate_pkt_OK(true,NULL,NULL,1,0,0,0,0,NULL);
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
		//p[0]="column test";
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

	GloMyLogger->log_request(this);

	// clean qpo
	if (qpo) {
		GloQPro->delete_QP_out(qpo);
		qpo=NULL;
	}
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
}
