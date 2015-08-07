#include "proxysql.h"
#include "cpp.h"

#define SELECT_VERSION_COMMENT "select @@version_comment limit 1"
#define SELECT_VERSION_COMMENT_LEN 32
#define PROXYSQL_VERSION_COMMENT "\x01\x00\x00\x01\x01\x27\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x11\x40\x40\x76\x65\x72\x73\x69\x6f\x6e\x5f\x63\x6f\x6d\x6d\x65\x6e\x74\x00\x0c\x21\x00\x18\x00\x00\x00\xfd\x00\x00\x1f\x00\x00\x05\x00\x00\x03\xfe\x00\x00\x02\x00\x0b\x00\x00\x04\x0a(ProxySQL)\x05\x00\x00\x05\xfe\x00\x00\x02\x00"
#define PROXYSQL_VERSION_COMMENT_LEN 81

#define EXPMARIA

extern MySQL_Authentication *GloMyAuth;

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
		ret=mysql_real_connect(mysql,ka->hostname,ka->username,ka->password,NULL,ka->port,NULL,0);
	} else {
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
		l_free(QueryLength+1,QueryPointer);
	}
}

void Query_Info::init(unsigned char *_p, int len, bool mysql_header) {
	QueryLength=(mysql_header ? len-5 : len);
	QueryPointer=(unsigned char *)l_alloc(QueryLength+1);
	memcpy(QueryPointer,(mysql_header ? _p+5 : _p),QueryLength);	
	QueryPointer[QueryLength]=0;
	//QueryPointer=(mysql_header ? _p+5 : _p);
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
	GloQPro->query_parser_free(QueryParserArgs);
	QueryParserArgs=NULL;
}

unsigned long long Query_Info::query_parser_update_counters() {
	if (MyComQueryCmd==MYSQL_COM_QUERY___NONE) return 0;
	unsigned long long ret=GloQPro->query_parser_update_counters(MyComQueryCmd, end_time-start_time);
	MyComQueryCmd=MYSQL_COM_QUERY___NONE;
	l_free(QueryLength+1,QueryPointer);
	QueryPointer=NULL;
	QueryLength=0;
	return ret;
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

	current_hostgroup=-1;
	default_hostgroup=-1;
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


	for (j=0; j<client_myds->PSarrayIN->len;) {
		client_myds->PSarrayIN->remove_index(0,&pkt);
		//prot.parse_mysql_pkt(&pkt,client_myds);
		switch (status) {
/*
			case CHANGING_USER_CLIENT:
				switch (client_myds->DSS) {
					case STATE_CLIENT_HANDSHAKE:
						handler___status_CHANGING_USER_CLIENT___STATE_CLIENT_HANDSHAKE(&pkt, &wrong_pass);
						break;
					default:
						assert(0);
				}
				break;
*/
			case CONNECTING_CLIENT:
				switch (client_myds->DSS) {
					case STATE_SERVER_HANDSHAKE:
						handler___status_CONNECTING_CLIENT___STATE_SERVER_HANDSHAKE(&pkt, &wrong_pass);
						break;
					case STATE_SSL_INIT:
						handler___status_CONNECTING_CLIENT___STATE_SSL_INIT(&pkt);
						break;
					default:
						assert(0); // FIXME: this should become close connection
				}
				break;

			case WAITING_CLIENT_DATA:
				switch (client_myds->DSS) {
					case STATE_SLEEP:
						command_counters->incr(thread->curtime/1000000);
						current_hostgroup=default_hostgroup;
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: WAITING_CLIENT_DATA - STATE_SLEEP\n");
						//unsigned char c;
						c=*((unsigned char *)pkt.ptr+sizeof(mysql_hdr));
						switch ((enum_mysql_command)c) {
							case _MYSQL_COM_QUERY:
#ifdef DEBUG
								if (mysql_thread___session_debug) {
									if ((pkt.size>9) && strncasecmp("dbg ",(const char *)pkt.ptr+sizeof(mysql_hdr)+1,4)==0) {
										if (mysql_thread___commands_stats==true) {
											CurrentQuery.init((unsigned char *)pkt.ptr,pkt.size,true);
											CurrentQuery.start_time=thread->curtime;
											CurrentQuery.query_parser_init();
											CurrentQuery.query_parser_command_type();
											CurrentQuery.query_parser_free();
										}
										handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_debug(&pkt);
										if (mysql_thread___commands_stats==true) {
											CurrentQuery.end_time=thread->curtime;
											CurrentQuery.query_parser_update_counters();
										}
										break;
									}
								}
#endif /* DEBUG */							
								if (admin==false) {
									if (session_fast_forward==false) {
										if (mysql_thread___commands_stats==true) {
											CurrentQuery.init((unsigned char *)pkt.ptr,pkt.size,true);
											CurrentQuery.start_time=thread->curtime;
											CurrentQuery.query_parser_init();
											CurrentQuery.query_parser_command_type();
											CurrentQuery.query_parser_free();
											//client_myds->myprot.process_pkt_COM_QUERY((unsigned char *)pkt.ptr,pkt.size);
										}
									}
									//if (strncmp((char *)"select @@version_comment limit 1",(char *)pkt.ptr+5,pkt.size-5)==0) {
									if (pkt.size==SELECT_VERSION_COMMENT_LEN+5 && strncmp((char *)SELECT_VERSION_COMMENT,(char *)pkt.ptr+5,pkt.size-5)==0) {
										PtrSize_t pkt_2;
										pkt_2.size=PROXYSQL_VERSION_COMMENT_LEN;
										pkt_2.ptr=l_alloc(pkt_2.size);
										//memcpy(pkt_2.ptr,"\x01\x00\x00\x01\x01\x27\x00\x00\x02\x03\x64\x65\x66\x00\x00\x00\x11\x40\x40\x76\x65\x72\x73\x69\x6f\x6e\x5f\x63\x6f\x6d\x6d\x65\x6e\x74\x00\x0c\x21\x00\x18\x00\x00\x00\xfd\x00\x00\x1f\x00\x00\x05\x00\x00\x03\xfe\x00\x00\x02\x00\x0b\x00\x00\x04\x0a(ProxySQL)\x05\x00\x00\x05\xfe\x00\x00\x02\x00",pkt_2.size);	
										memcpy(pkt_2.ptr,PROXYSQL_VERSION_COMMENT,pkt_2.size);
										status=WAITING_CLIENT_DATA;
										client_myds->DSS=STATE_SLEEP;
										client_myds->PSarrayOUT->add(pkt_2.ptr,pkt_2.size);
										l_free(pkt.size,pkt.ptr);
										break;
									}
									qpo=GloQPro->process_mysql_query(this,pkt.ptr,pkt.size,false);
									if (qpo) {
										bool rc_break=handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(&pkt);
										if (rc_break==true) { break; }
									}
									mybe=find_or_create_backend(current_hostgroup);
									status=PROCESSING_QUERY;
									mybe->server_myds->connect_retries_on_failure=mysql_thread___connect_retries_on_failure;
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
									//if (server_myds!=mybe->server_myds) {
									//	server_myds=mybe->server_myds;
									//}


#ifdef EXPMARIA
									proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Received query to be processed with MariaDB Client library\n");
									mybe->server_myds->mysql_real_query.size=pkt.size-5;
									mybe->server_myds->mysql_real_query.ptr=(char *)malloc(pkt.size-5);
//									mybe->server_myds->wait_until=0;
//									if (qpo) {
//										if (qpo->timeout > 0) {
//											mybe->server_myds->wait_until=thread->curtime+qpo->timeout*1000;
//										}
//									}
									mybe->server_myds->killed_at=0;
									//fprintf(stderr,"times: %llu, %llu\n", mybe->server_myds->wait_until, thread->curtime); 
									memcpy(mybe->server_myds->mysql_real_query.ptr,(char *)pkt.ptr+5,pkt.size-5);
									l_free(pkt.size,pkt.ptr);
#else
									mybe->server_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
#endif /* EXPMARIA */

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
						assert(0); // FIXME: this should become close connection
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
			
/*
			if (mybe->server_myds->revents) {
				MySQL_Data_Stream *myds=mybe->server_myds;
				MySQL_Connection *myconn=myds->myconn;
				myconn->handler(myds->revents);
				if (myconn->async_state_machine==ASYNC_PING_SUCCESSFUL) {
					myds->DSS=STATE_READY;
					myds->myconn->async_state_machine=ASYNC_IDLE;
					if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {

						return_MySQL_Connection_To_Poll(myds);
					}
					status=NONE;
				} else {
					if (myconn->async_state_machine==ASYNC_PING_FAILED) {
						// FIXME: treat gracefully
						assert(0);
					}
				}
			}
*/
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
					if ((myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false) {
						myds->return_MySQL_Connection_To_Pool();
					}
					delete mybe->server_myds;
					mybe->server_myds=NULL;
					set_status(NONE);
					return -1;
				} else {
					if (rc==-1) {
						proxy_error("Detected a broken connection during ping\n");
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
			if (mybe->server_myds->myconn && mybe->server_myds->wait_until && thread->curtime >= mybe->server_myds->wait_until) {
				// query timed out
				MySQL_Data_Stream *myds=mybe->server_myds;
				// FIXME: make sure the connection is established first
				if (myds->killed_at==0) {
					myds->wait_until=0;
					myds->killed_at=thread->curtime;
					//fprintf(stderr,"Expired: %llu, %llu\n", mybe->server_myds->wait_until, thread->curtime);
					MySQL_Connection_userinfo *ui=client_myds->myconn->userinfo;
					KillArgs *ka = new KillArgs(ui->username, ui->password, myds->myconn->parent->address, myds->myconn->parent->port, myds->myconn->mysql->thread_id);
					pthread_attr_t attr;
					pthread_attr_init(&attr);
					pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
					pthread_attr_setstacksize (&attr, 128*1024);
					pthread_t pt;
					pthread_create(&pt, &attr, &kill_query_thread, ka);
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
				}
				int rc=myconn->async_query(myds->revents, myds->mysql_real_query.ptr,myds->mysql_real_query.size);

//				if (myconn->async_state_machine==ASYNC_QUERY_END) {
				if (rc==0) {
					MySQL_Result_to_MySQL_wire(myconn->mysql,myconn->mysql_result,&client_myds->myprot);
					GloQPro->delete_QP_out(qpo);
					qpo=NULL;
					myconn->async_free_result();
					status=WAITING_CLIENT_DATA;
					client_myds->DSS=STATE_SLEEP;
					if (mysql_thread___commands_stats==true) {
						CurrentQuery.end_time=thread->curtime;
						CurrentQuery.query_parser_update_counters();
					}
					myds->free_mysql_real_query();
					//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
					if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false) {
						myds->DSS=STATE_NOT_INITIALIZED;
						myds->return_MySQL_Connection_To_Pool();
					} else {
						myconn->async_state_machine=ASYNC_IDLE;
						myds->DSS=STATE_MARIADB_GENERIC;
					}
				} else {
					if (rc==-1) {
						// the query failed
						int myerr=mysql_errno(myconn->mysql);
						if (myerr > 2000) {
							bool retry_conn=false;
							// client error, serious
							proxy_error("Detected a broken connection during query: %d, %s\n", myerr, mysql_error(myconn->mysql));
							//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
							if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false) {
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
						} else {
							proxy_warning("Error during query: %d, %s\n", myerr, mysql_error(myconn->mysql));

							MySQL_Result_to_MySQL_wire(myconn->mysql,myconn->mysql_result,&client_myds->myprot);
							GloQPro->delete_QP_out(qpo);
							qpo=NULL;
							myconn->async_free_result();
							//myds->DSS=STATE_NOT_INITIALIZED;
							status=WAITING_CLIENT_DATA;
							client_myds->DSS=STATE_SLEEP;
							myds->free_mysql_real_query();
							//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
							if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false) {
								myds->DSS=STATE_NOT_INITIALIZED;
								myds->return_MySQL_Connection_To_Pool();
							} else {
								myconn->async_state_machine=ASYNC_IDLE;
								myds->DSS=STATE_MARIADB_GENERIC;
							}
						}
					} else {
						// rc==1 , nothing to do for now
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
							proxy_error("Detected a broken connection during change user: %d, %s\n", myerr, mysql_error(myconn->mysql));
							//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
							if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false) {
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
//							MySQL_Result_to_MySQL_wire(myconn->mysql,myconn->mysql_result,&client_myds->myprot);
//							GloQPro->delete_QP_out(qpo);
//							qpo=NULL;
//							myconn->async_free_result();
//							myds->DSS=STATE_NOT_INITIALIZED;
//							myds->free_mysql_real_query();
//							if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
//								myds->return_MySQL_Connection_To_Pool();
//							} else {
								myds->destroy_MySQL_Connection_From_Pool();
								myds->fd=0;
//							}
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
							proxy_error("Detected a broken connection during INIT_DB: %d, %s\n", myerr, mysql_error(myconn->mysql));
							//if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
							if ((myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false) {
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

		case CONNECTING_SERVER:
			//fprintf(stderr,"CONNECTING_SERVER\n");
			if (mybe->server_myds->max_connect_time) {
				if (thread->curtime >= mybe->server_myds->max_connect_time) {
					client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",(char *)"Max connect timeout reached");
					client_myds->DSS=STATE_SLEEP;
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
						myds->DSS=STATE_READY;
						status=WAITING_CLIENT_DATA;
						st=previous_status.top();
						previous_status.pop();
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
								client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",(char *)"Max connect timeout reached");
							}
							client_myds->DSS=STATE_SLEEP;
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
//					case -2:
						// timeout
						//myds->destroy_MySQL_Connection();
//						myds->destroy_MySQL_Connection_From_Pool();
//						NEXT_IMMEDIATE(CONNECTING_SERVER);
//						break;
					case 1: // continue on next loop
					default:
						break;
				}
/*
				if (myds->revents) {
					myconn->handler(myds->revents);
					if (myconn->ret_mysql) {
						if (myconn->async_state_machine==ASYNC_CONNECT_SUCCESSFUL) {
							myds->myds_type=MYDS_BACKEND;
							myds->DSS=STATE_READY;
							status=WAITING_SERVER_DATA;
							myconn->async_state_machine=ASYNC_IDLE;
							enum session_status st=previous_status.top();
							previous_status.pop();
							NEXT_IMMEDIATE(st);
						} else {
							assert(0);
						}
					} else {
						if (myconn->async_state_machine!=ASYNC_CONNECT_CONT) {
							wrong_pass=true;
						}
					}
				}
 */
			}
			break;
		case NONE:
			fprintf(stderr,"NONE\n");
		default:
			break;
	}

	goto __exit_DSS__STATE_NOT_INITIALIZED;

__get_a_backend:
/*
	if (client_myds==NULL) {
		goto __exit_DSS__STATE_NOT_INITIALIZED;
	}

	//if ((client_myds->DSS==STATE_QUERY_SENT_NET && session_fast_forward==false) || session_fast_forward==true) {
	if (status!=FAST_FORWARD && client_myds->DSS==STATE_QUERY_SENT_NET) {
	// the client has completely sent the query, now we should handle it server side
	//
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, client_myds->DSS==STATE_QUERY_SENT_NET\n", this);
		if (mybe && mybe->server_myds->DSS==STATE_NOT_INITIALIZED) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, client_myds->DSS==STATE_QUERY_SENT_NET , server_myds==STATE_NOT_INITIALIZED\n", this);
			// DSS is STATE_NOT_INITIALIZED. It means we are not connected to any server
			// try to connect
			pending_connect=1;
			unsigned long long curtime=monotonic_time();

			// if DSS==STATE_NOT_INITIALIZED , we expect few pointers to be NULL . If it is not null, we have a bug
			//assert(server_myds->myconn==NULL);
			assert(mybe->server_myds->myconn==NULL);

			handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection();
			if (mybe->server_myds->myconn==NULL) {
				pause_until=thread->curtime+100*1000;
				goto __exit_DSS__STATE_NOT_INITIALIZED;
			}
			//mybe->server_myds->myprot.init(&mybe->server_myds, mybe->myconn->userinfo, this);
			mybe->server_myds->myprot.init(&mybe->server_myds, mybe->server_myds->myconn->userinfo, this);
			if (client_myds->myconn->has_prepared_statement==true) {
				mybe->server_myds->myconn->has_prepared_statement=true;
				mybe->server_myds->myconn->reusable=false;
			}
			// FIXME : handle missing connection from connection pool
			// FIXME : perhaps is a goto __exit_DSS__STATE_NOT_INITIALIZED after setting time wait

			thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, curtime);

			if (mybe->server_myds->DSS!=STATE_READY) {
				mybe->server_myds->move_from_OUT_to_OUTpending();
			}
			// END OF if (server_myds->DSS==STATE_NOT_INITIALIZED)
								//} else {  TRY #1
		}    // TRY #1
		if (session_fast_forward==true && mybe && mybe->server_myds && mybe->server_myds->myconn) {
			mybe->server_myds->myconn->reusable=false;
		}
		if (session_fast_forward==false) {
		if (mybe && mybe->server_myds->myds_type==MYDS_BACKEND && mybe->server_myds->DSS==STATE_READY) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, client_myds->DSS==STATE_QUERY_SENT_NET , server_myds==STATE_READY , server_myds->myds_type==MYDS_BACKEND\n", this);
			//if (strcmp(userinfo_client.schemaname,userinfo_server.schemaname)==0) {
			if (
				(client_myds->myconn->userinfo->hash!=mybe->server_myds->myconn->userinfo->hash)
			) {
				if (strcmp(client_myds->myconn->userinfo->username,mybe->server_myds->myconn->userinfo->username)) {
					// username don't match, we must change user
					handler___client_DSS_QUERY_SENT___send_CHANGE_USER_to_backend();
				} else {
					// we should chek that schema is different, but here we assume that if we reach here user is identical, but schema is not
					handler___client_DSS_QUERY_SENT___send_INIT_DB_to_backend();
				}
			} else {
#ifndef EXPMARIA
				if (client_myds->myconn->options.charset!=mybe->server_myds->myconn->options.charset ) {
					handler___client_DSS_QUERY_SENT___send_SET_NAMES_to_backend();
				} else {
#endif
					//server_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
#ifdef EXPMARIA
					MySQL_Data_Stream *myds=mybe->server_myds;
					myds->DSS=STATE_MARIADB_QUERY;
					status=PROCESSING_QUERY;
					myds->myconn->async_state_machine=ASYNC_QUERY_START;
					myds->myconn->set_query(myds->mysql_real_query.ptr,myds->mysql_real_query.size);
					myds->myconn->handler(0);
#else
					mybe->server_myds->DSS=STATE_QUERY_SENT_DS;
//					if (client_myds->myconn->processing_prepared_statement) {
						mybe->server_myds->myconn->processing_prepared_statement_prepare=client_myds->myconn->processing_prepared_statement_prepare;
						mybe->server_myds->myconn->processing_prepared_statement_execute=client_myds->myconn->processing_prepared_statement_execute;
//					}
					status=WAITING_SERVER_DATA;
#endif 
#ifndef EXPMARIA
				}
#endif
			}
		}
							//	}   TRY #1
		}
	}
*/
__exit_DSS__STATE_NOT_INITIALIZED:
		

	if (mybe && mybe->server_myds) {
	if (mybe->server_myds->DSS > STATE_MARIADB_BEGIN && mybe->server_myds->DSS < STATE_MARIADB_END) {
		MySQL_Data_Stream *myds=mybe->server_myds;
		MySQL_Connection *myconn=mybe->server_myds->myconn;
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, status=%d, server_myds->DSS==%d , revents==%d , async_state_machine=%d\n", this, status, mybe->server_myds->DSS, myds->revents, myconn->async_state_machine);
//		int ms_status = 0;
		switch (status) {
			case WAITING_CLIENT_DATA:
				break;
			case CONNECTING_SERVER:
			break;
		case CHANGING_USER_SERVER:
			break;
		case PROCESSING_QUERY:
			break;
		case PINGING_SERVER:
/*
			if (myds->revents) {
				myconn->handler(myds->revents);
				if (myconn->async_state_machine==ASYNC_PING_SUCCESSFUL) {
					myds->DSS=STATE_READY;
					/// multi-plexing attempt
					if ((myds->myconn->reusable==true) && ((myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
						myds->myconn->last_time_used=thread->curtime;
						myds->myconn->async_state_machine=ASYNC_IDLE;
						MyHGM->push_MyConn_to_pool(myds->myconn);
				//MyHGM->destroy_MyConn_from_pool(mybe->server_myds->myconn);
				//mybe->server_myds->myconn=NULL;
						myds->detach_connection();
						myds->unplug_backend();
					}
					// multi-plexing attempt
					status=NONE;
				}
			}
*/
			break;
		case CHANGING_SCHEMA:
/*
			if (myds->revents) {
				myconn->handler(myds->revents);
				if (myconn->async_state_machine==ASYNC_INITDB_SUCCESSFUL) {
					myds->DSS=STATE_READY;
					status=WAITING_CLIENT_DATA;
					unsigned int k;
					PtrSize_t pkt2;
					for (k=0; k<mybe->server_myds->PSarrayOUTpending->len;) {
						myds->PSarrayOUTpending->remove_index(0,&pkt2);
						myds->PSarrayOUT->add(pkt2.ptr, pkt2.size);
						myds->DSS=STATE_QUERY_SENT_DS;
					}
				}
				if (myconn->async_state_machine==ASYNC_INITDB_FAILED) {
					set_unhealthy();
					myds->myconn->reusable=false;
					return -1;
				}
			}
*/
			break;
		case CHANGING_CHARSET:
			if (myds->revents) {
				myconn->handler(myds->revents);
				if (myconn->async_state_machine==ASYNC_SET_NAMES_SUCCESSFUL) {
#ifdef EXPMARIA
					myds->DSS=STATE_MARIADB_QUERY;
					status=PROCESSING_QUERY;
					myds->myconn->async_state_machine=ASYNC_QUERY_START;
					myds->myconn->set_query(myds->mysql_real_query.ptr,myds->mysql_real_query.size);
					myds->myconn->handler(0);
#else
					myds->DSS=STATE_READY;
					status=WAITING_CLIENT_DATA;
#endif /* EXPMARIA */
					unsigned int k;
					PtrSize_t pkt2;
					for (k=0; k<mybe->server_myds->PSarrayOUTpending->len;) {
						myds->PSarrayOUTpending->remove_index(0,&pkt2);
						myds->PSarrayOUT->add(pkt2.ptr, pkt2.size);
						myds->DSS=STATE_QUERY_SENT_DS;
					}
				}
				if (myconn->async_state_machine==ASYNC_SET_NAMES_FAILED) {
					set_unhealthy();
					myds->myconn->reusable=false;
					return -1;
				}
			}
			break;
		default:
			assert(0);
			break;
		}
	} else {


//	}


/*
		ATTEMPT TO COMMENT THIS BLOCK
		for (j=0; j<mybe->server_myds->PSarrayIN->len;) {
			mybe->server_myds->PSarrayIN->remove_index(0,&pkt);

		switch (status) {
			case WAITING_SERVER_DATA:
				switch (mybe->server_myds->DSS) {
//					case STATE_PING_SENT_NET:
//						handler___status_WAITING_SERVER_DATA___STATE_PING_SENT(&pkt);
//						break;

					case STATE_QUERY_SENT_NET:
						handler___status_WAITING_SERVER_DATA___STATE_QUERY_SENT(&pkt);
						break;

					case STATE_ROW:
						handler___status_WAITING_SERVER_DATA___STATE_ROW(&pkt);
						break;

					case STATE_EOF1:
						handler___status_WAITING_SERVER_DATA___STATE_EOF1(&pkt);
						break;

					case STATE_READING_COM_STMT_PREPARE_RESPONSE:
						handler___status_WAITING_SERVER_DATA___STATE_READING_COM_STMT_PREPARE_RESPONSE(&pkt);
						break;

					default:
						assert(0);
				}
				break;

//			case CHANGING_SCHEMA:
//				if (handler___status_CHANGING_SCHEMA(&pkt)==false) {
//					return -1;
//				}
//				break;

			case CHANGING_USER_SERVER:
				if (handler___status_CHANGING_USER_SERVER(&pkt)==false) {
					return -1;
				}
				break;

//			case CHANGING_CHARSET:
//				if (handler___status_CHANGING_CHARSET(&pkt)==false) {
//					return -1;
//				}
//				break;

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

	// FIXME: see bug #211
	if (
		mybe
		&&
		mybe->server_myds
		&&
		mybe->server_myds->DSS==STATE_QUERY_SENT_DS
		&&
		mybe->server_myds->PSarrayOUT->len==0
		&&
		mybe->server_myds->PSarrayOUTpending->len==0
		&&
		mybe->server_myds->net_failure==false
		&&
		mybe->server_myds->available_data_out()==false
	) {
		if (connections_handler) {
			//fprintf(stderr,"time=%llu\n",monotonic_time());
			//mybe->server_myds->timeout=thread->curtime+100;
			//mybe->server_myds->DSS=STATE_PING_SENT_NET;
		} else {
			mybe->server_myds->setDSS_STATE_QUERY_SENT_NET();
		}
	}
	if (mybe && mybe->server_myds) {
		if (mybe->server_myds->net_failure) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess:%p , MYDS:%p , myds_type=%d, DSS=%d , myconn:%p\n" , this, mybe->server_myds , mybe->server_myds->myds_type , mybe->server_myds->DSS, mybe->server_myds->myconn);
			if (( mybe->server_myds->DSS==STATE_READY || mybe->server_myds->DSS==STATE_QUERY_SENT_DS ) && mybe->server_myds->myds_type==MYDS_BACKEND) {
				//mybe->server_myds->myconn=NULL;
				mybe->server_myds->detach_connection();
				mybe->server_myds->DSS=STATE_NOT_INITIALIZED;
				mybe->server_myds->move_from_OUT_to_OUTpending();
				if (mybe->server_myds->myconn) {
					MyHGM->destroy_MyConn_from_pool(mybe->server_myds->myconn);
					//mybe->server_myds->myconn=NULL;
					mybe->server_myds->detach_connection();
				}
				if (mybe->server_myds->fd) {
					mybe->server_myds->shut_hard();
//					shutdown(mybe->server_myds->fd,SHUT_RDWR);
//					close(mybe->server_myds->fd);
					mybe->server_myds->fd=0;
					thread->mypolls.remove_index_fast(mybe->server_myds->poll_fds_idx);
					//server_fd=0;
				}
				mybe->server_myds->clean_net_failure();
				mybe->server_myds->active=1;
				goto __get_a_backend;
			} else {
				set_unhealthy();
			}
		}
	}

	//writeout();

/*
	if (  // FIXME: this implementation is horrible
		(server_myds ? server_myds->PSarrayIN->len==0 : 1 ) && 
		(server_myds ? server_myds->PSarrayOUT->len==0 : 1 ) && 
		(client_myds ? client_myds->PSarrayIN->len==0 : 1 ) && 
		(client_myds ? client_myds->PSarrayOUT->len==0 : 1 )
	)
	{
	to_process=0;
	}
*/
	if (wrong_pass==true) {
		client_myds->array2buffer_full();
		client_myds->write_to_net();
		return -1;
	}
	return 0;
}


bool MySQL_Session::handler___status_CHANGING_USER_SERVER(PtrSize_t *pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: CHANGING_USER_SERVER - UNKNWON\n");
	if (mybe->server_myds->myprot.process_pkt_OK((unsigned char *)pkt->ptr,pkt->size)==true) {
		l_free(pkt->size,pkt->ptr);
		mybe->server_myds->DSS=STATE_READY;
		//mybe->myconn=server_myds->myconn;
		status=WAITING_SERVER_DATA;
		unsigned int k;
		PtrSize_t pkt2;
		for (k=0; k<mybe->server_myds->PSarrayOUTpending->len;) {
			mybe->server_myds->PSarrayOUTpending->remove_index(0,&pkt2);
			mybe->server_myds->PSarrayOUT->add(pkt2.ptr, pkt2.size);
			mybe->server_myds->DSS=STATE_QUERY_SENT_DS;
		}
		// set prepared statement processing
		mybe->server_myds->myconn->processing_prepared_statement_prepare=client_myds->myconn->processing_prepared_statement_prepare;
		return true;
	} else {
		l_free(pkt->size,pkt->ptr);	
		set_unhealthy();
		//mybe->myconn=server_myds->myconn;
		// if we reach here, server_myds->DSS should be STATE_QUERY_SENT , therefore the connection to the backend should be dropped anyway
		// although we enforce this here
		mybe->server_myds->myconn->reusable=false;
		return false;
	}
	return false;
}

void MySQL_Session::handler___status_WAITING_SERVER_DATA___STATE_QUERY_SENT(PtrSize_t *pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: WAITING_SERVER_DATA - STATE_QUERY_SENT\n");
	unsigned char c;
	c=*((unsigned char *)pkt->ptr+sizeof(mysql_hdr));
	if (mybe->server_myds->myconn->processing_prepared_statement_prepare==false && mybe->server_myds->myconn->processing_prepared_statement_execute==false) {
	if (c==0 || c==0xff) {
		mybe->server_myds->DSS=STATE_READY;
		/* multi-plexing attempt */
		if (c==0) {
			mybe->server_myds->myprot.process_pkt_OK((unsigned char *)pkt->ptr,pkt->size);
			if ((mybe->server_myds->myconn->reusable==true) && ((mybe->server_myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
				mybe->server_myds->return_MySQL_Connection_To_Pool();
//				mybe->server_myds->myconn->last_time_used=thread->curtime;
//				MyHGM->push_MyConn_to_pool(mybe->server_myds->myconn);
				//MyHGM->destroy_MyConn_from_pool(mybe->server_myds->myconn);
//				mybe->server_myds->myconn=NULL;
//				mybe->server_myds->unplug_backend();
			}
		}
		/* multi-plexing attempt */	
		status=WAITING_CLIENT_DATA;
		client_myds->DSS=STATE_SLEEP;
		client_myds->PSarrayOUT->add(pkt->ptr, pkt->size);
		if (mysql_thread___commands_stats==true) {
			CurrentQuery.end_time=thread->curtime;
			CurrentQuery.query_parser_update_counters();
		}
	} else {
		// this should be a result set
		if (qpo && qpo->cache_ttl>0) {
			mybe->server_myds->resultset->add(pkt->ptr, pkt->size);
			mybe->server_myds->resultset_length+=pkt->size;
		} else {
			client_myds->PSarrayOUT->add(pkt->ptr, pkt->size);
		}
		mybe->server_myds->DSS=STATE_ROW;	// FIXME: this is catch all for now
	}
	} else {
		// mybe->server_myds->myconn->processing_prepared_statement_prepare==true
		if (mybe->server_myds->myconn->processing_prepared_statement_prepare==true) {
			switch (c) {
				case 0xff:
				// ERR packet , send it to client
					mybe->server_myds->DSS=STATE_READY;
					mybe->server_myds->myconn->processing_prepared_statement_prepare=false;
					client_myds->myconn->processing_prepared_statement_prepare=false;
					status=WAITING_CLIENT_DATA;
					client_myds->DSS=STATE_SLEEP;
					client_myds->PSarrayOUT->add(pkt->ptr, pkt->size);
					break;
				case 0x00:
					if (mybe->server_myds->myprot.current_PreStmt) delete mybe->server_myds->myprot.current_PreStmt;
					mybe->server_myds->myprot.current_PreStmt=new MySQL_Prepared_Stmt_info((unsigned char *)pkt->ptr, pkt->size);
					if (mybe->server_myds->myprot.current_PreStmt->num_columns+mybe->server_myds->myprot.current_PreStmt->num_params) {
						mybe->server_myds->DSS=STATE_READING_COM_STMT_PREPARE_RESPONSE;
					} else {
						mybe->server_myds->DSS=STATE_READY;
						mybe->server_myds->myconn->processing_prepared_statement_prepare=false;
						client_myds->myconn->processing_prepared_statement_prepare=false;
						status=WAITING_CLIENT_DATA;
						client_myds->DSS=STATE_SLEEP;
					}
					client_myds->PSarrayOUT->add(pkt->ptr, pkt->size);
					break;
				default:
					assert(0);
					break;
			}
		} else {
		// mybe->server_myds->myconn->processing_prepared_statement_execute==true
			switch (c) {
				case 0x00:
				// OK packet , send it to client
				case 0xff:
				// ERR packet , send it to client
					mybe->server_myds->DSS=STATE_READY;
					mybe->server_myds->myconn->processing_prepared_statement_execute=false;
					client_myds->myconn->processing_prepared_statement_execute=false;
					status=WAITING_CLIENT_DATA;
					client_myds->DSS=STATE_SLEEP;
					break;
				default:
					mybe->server_myds->DSS=STATE_ROW;	// FIXME: this is catch all for now
					//assert(0);
					break;
			}
			// always send to client
			client_myds->PSarrayOUT->add(pkt->ptr, pkt->size);
		}
	}
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

void MySQL_Session::handler___status_WAITING_SERVER_DATA___STATE_ROW(PtrSize_t *pkt) {
	unsigned char c;
	c=*((unsigned char *)pkt->ptr+sizeof(mysql_hdr));
	if (c==0xfe && pkt->size < 13) {
		mybe->server_myds->DSS=STATE_EOF1;
	}
	if (qpo && qpo->cache_ttl>0) {
		mybe->server_myds->resultset->add(pkt->ptr, pkt->size);
		mybe->server_myds->resultset_length+=pkt->size;
	} else {
		client_myds->PSarrayOUT->add(pkt->ptr, pkt->size);
	}
}


void MySQL_Session::handler___status_WAITING_SERVER_DATA___STATE_EOF1(PtrSize_t *pkt) {
	unsigned char c;
	c=*((unsigned char *)pkt->ptr+sizeof(mysql_hdr));
	if (mybe->server_myds->myconn->processing_prepared_statement_prepare==false && mybe->server_myds->myconn->processing_prepared_statement_execute==false)
{
	if (qpo && qpo->cache_ttl>0) {
		mybe->server_myds->resultset->add(pkt->ptr, pkt->size);
		mybe->server_myds->resultset_length+=pkt->size;
	} else {
		client_myds->PSarrayOUT->add(pkt->ptr, pkt->size);
	}
	if ((c==0xfe && pkt->size < 13) || c==0xff) {
		mybe->server_myds->DSS=STATE_READY;
		status=WAITING_CLIENT_DATA;
		client_myds->DSS=STATE_SLEEP;


		/* multi-plexing attempt */
		if (c==0xfe) {
			mybe->server_myds->myprot.process_pkt_EOF((unsigned char *)pkt->ptr,pkt->size);
			//fprintf(stderr,"hid=%d status=%d\n", mybe->hostgroup_id, server_myds->myprot.prot_status);
			if ((mybe->server_myds->myconn->reusable==true) && ((mybe->server_myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
				mybe->server_myds->return_MySQL_Connection_To_Pool();
//				mybe->server_myds->myconn->last_time_used=thread->curtime;
//				MyHGM->push_MyConn_to_pool(mybe->server_myds->myconn);
//				//MyHGM->destroy_MyConn_from_pool(mybe->server_myds->myconn);;
//				mybe->server_myds->myconn=NULL;
//				mybe->server_myds->unplug_backend();
			}
		}
		/* multi-plexing attempt */	

		if (qpo) {
			if (qpo->cache_ttl>0) { // Fixed bug #145
				client_myds->PSarrayOUT->copy_add(mybe->server_myds->resultset,0,mybe->server_myds->resultset->len);
				unsigned char *aa=mybe->server_myds->resultset2buffer(false);
				while (mybe->server_myds->resultset->len) mybe->server_myds->resultset->remove_index(mybe->server_myds->resultset->len-1,NULL);	
				GloQC->set((unsigned char *)client_myds->query_SQL,strlen((char *)client_myds->query_SQL)+1,aa,mybe->server_myds->resultset_length,30);
				l_free(mybe->server_myds->resultset_length,aa);
				mybe->server_myds->resultset_length=0;
				l_free(strlen((char *)client_myds->query_SQL)+1,client_myds->query_SQL);
			}
			GloQPro->delete_QP_out(qpo);
			qpo=NULL;
		}
		if (mysql_thread___commands_stats==true) {
			CurrentQuery.end_time=thread->curtime;
			CurrentQuery.query_parser_update_counters();
		}
	}
} else {
	if (mybe->server_myds->myconn->processing_prepared_statement_prepare==true) {
//		fprintf(stderr,"EOF: %d %d\n", mybe->server_myds->myprot.current_PreStmt->pending_num_params, mybe->server_myds->myprot.current_PreStmt->pending_num_columns);
		if (mybe->server_myds->myprot.current_PreStmt->pending_num_params+mybe->server_myds->myprot.current_PreStmt->pending_num_columns) {
			if (mybe->server_myds->myprot.current_PreStmt->pending_num_params) {
				--mybe->server_myds->myprot.current_PreStmt->pending_num_params;
			} else {
				if (mybe->server_myds->myprot.current_PreStmt->pending_num_columns) {
					--mybe->server_myds->myprot.current_PreStmt->pending_num_columns;
				}
			}
			if (mybe->server_myds->myprot.current_PreStmt->pending_num_params+mybe->server_myds->myprot.current_PreStmt->pending_num_columns) {
				mybe->server_myds->DSS=STATE_READING_COM_STMT_PREPARE_RESPONSE;	
			}
		} else {
			mybe->server_myds->myconn->processing_prepared_statement_prepare=false;
			client_myds->myconn->processing_prepared_statement_prepare=false;
			mybe->server_myds->DSS=STATE_READY;
			status=WAITING_CLIENT_DATA;
			client_myds->DSS=STATE_SLEEP;
		}
		client_myds->PSarrayOUT->add(pkt->ptr, pkt->size);
	} else {
		//mybe->server_myds->myconn->processing_prepared_statement_execute==true 
		if ((c==0xfe && pkt->size < 13) || c==0xff) {
			mybe->server_myds->myconn->processing_prepared_statement_execute=false;
			client_myds->myconn->processing_prepared_statement_execute=false;
			mybe->server_myds->DSS=STATE_READY;
			status=WAITING_CLIENT_DATA;
			client_myds->DSS=STATE_SLEEP;
		}
		client_myds->PSarrayOUT->add(pkt->ptr, pkt->size);
	}
}
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
		client_myds->myprot.generate_pkt_EOF(true,NULL,NULL,1,0,0);
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
	client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,2,0,NULL);
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

#ifdef DEBUG
void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_debug(PtrSize_t *pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got ProxySQL dbg packet\n");
	//SQLite3_result * result = SQL3_Session_status();
	SQLite3_result * result=NULL;
	char *query=NULL;
	unsigned int query_length=pkt->size-sizeof(mysql_hdr);
	query=(char *)l_alloc(query_length);
	memcpy(query,(char *)pkt->ptr+sizeof(mysql_hdr)+1,query_length-1);
	query[query_length-1]=0;

	char *query_no_space=(char *)l_alloc(query_length);
	memcpy(query_no_space,query,query_length);

	/*unsigned int query_no_space_length=*/remove_spaces(query_no_space);

	if (!strcasecmp(query_no_space,"DBG THREAD STATUS")) {
		result = thread->SQL3_Thread_status(this);
		goto __exit_from_debug;
	}
	if (!strcasecmp(query_no_space,"DBG THREADS STATUS")) {
		result = GloMTH->SQL3_Threads_status(this);
		goto __exit_from_debug;
	}
	if (!strcasecmp(query_no_space,"DBG SESSION STATUS")) {
		result = SQL3_Session_status();
		goto __exit_from_debug;
	}




__exit_from_debug:
	l_free(query_length,query);
	l_free(query_length,query_no_space);
	l_free(pkt->size,pkt->ptr);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	if (result) {
	//	SQLite3_result * result = thread->SQL3_Thread_status(this);
		SQLite3_to_MySQL(result,NULL,0,&client_myds->myprot);
		delete result;
	} else {
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",(char *)"Command not supported");
	}
	client_myds->DSS=STATE_SLEEP;
}
#endif /* DEBUG */


void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_INIT_DB(PtrSize_t *pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_INIT_DB packet\n");
	if (admin==false) {
		client_myds->myconn->userinfo->set_schemaname((char *)pkt->ptr+sizeof(mysql_hdr)+1,pkt->size-sizeof(mysql_hdr)-1);
		l_free(pkt->size,pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,2,0,NULL);
		client_myds->DSS=STATE_SLEEP;
	} else {
		l_free(pkt->size,pkt->ptr);
		client_myds->setDSS_STATE_QUERY_SENT_NET();
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,2,0,NULL);
		client_myds->DSS=STATE_SLEEP;
	}
}



bool MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(PtrSize_t *pkt) {
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
		delete qpo->new_query;
	}
	if (qpo->cache_ttl>0) {
		client_myds->query_SQL=(unsigned char *)l_alloc(pkt->size-sizeof(mysql_hdr));
		memcpy(client_myds->query_SQL,(unsigned char *)pkt->ptr+sizeof(mysql_hdr)+1,pkt->size-sizeof(mysql_hdr)-1);
		client_myds->query_SQL[pkt->size-sizeof(mysql_hdr)-1]=0;
		uint32_t resbuf=0;
		unsigned char *aa=GloQC->get(client_myds->query_SQL,&resbuf);
		if (aa) {
			l_free(pkt->size,pkt->ptr);
			l_free(strlen((char *)client_myds->query_SQL)+1,client_myds->query_SQL);
			client_myds->buffer2resultset(aa,resbuf);
			free(aa);
			client_myds->PSarrayOUT->copy_add(client_myds->resultset,0,client_myds->resultset->len);
			while (client_myds->resultset->len) client_myds->resultset->remove_index(client_myds->resultset->len-1,NULL);
			status=WAITING_CLIENT_DATA;
			client_myds->DSS=STATE_SLEEP;
			if (mysql_thread___commands_stats==true) {
				CurrentQuery.end_time=thread->curtime;
				CurrentQuery.query_parser_update_counters();
			}
			GloQPro->delete_QP_out(qpo);
			qpo=NULL;
			return true;
		}
	}
	if ( qpo->destination_hostgroup >= 0 ) current_hostgroup=qpo->destination_hostgroup;
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
		//int __fd;
		MySQL_Connection *myconn=mybe->server_myds->myconn;
//		myconn->mysql=mysql_init(NULL);
//		assert(myconn->mysql);
//		mysql_options(myconn->mysql, MYSQL_OPT_NONBLOCK, 0);
		myconn->userinfo->set(client_myds->myconn->userinfo);
		// FIXME: set client_flags
		//mybe->server_myds->myconn->connect_start();
		//mybe->server_myds->fd=myconn->fd;

		//myconn->connect_start();
		myconn->handler(0);
/*
		if (myconn->parent->port) {
			myconn->async_exit_status=mysql_real_connect_start(&myconn->ret_mysql,myconn->mysql, myconn->parent->address, myconn->userinfo->username, myconn->userinfo->password, myconn->userinfo->schemaname, myconn->parent->port, NULL, 0);
		} else {
			myconn->async_exit_status=mysql_real_connect_start(&myconn->ret_mysql,myconn->mysql, "localhost", myconn->userinfo->username, myconn->userinfo->password, myconn->userinfo->schemaname, myconn->parent->port, myconn->parent->address, 0);
		}
		myconn->fd=mysql_get_socket(myconn->mysql);
		if (myconn->async_exit_status) {
//			myconn->async_state_machine=1;
		} else {
//			myconn->async_state_machine=2;	
		}
*/
		mybe->server_myds->fd=myconn->fd;
		mybe->server_myds->DSS=STATE_MARIADB_CONNECTING;
		status=CONNECTING_SERVER;
		mybe->server_myds->myconn->reusable=true;

/*
		__fd=mybe->server_myds->myds_connect(mybe->server_myds->myconn->parent->address, mybe->server_myds->myconn->parent->port, &pending_connect);

		if (__fd==-1) {
			MyHGM->destroy_MyConn_from_pool(mybe->server_myds->myconn);
			mybe->server_myds->myconn=NULL;
			return;
		}

		mybe->server_myds->init((pending_connect==1 ? MYDS_BACKEND_NOT_CONNECTED : MYDS_BACKEND), this, __fd);
		mybe->server_myds->myconn->reusable=true;
		mybe->server_myds->myconn->fd=mybe->server_myds->fd;
		status=CONNECTING_SERVER;
		mybe->server_myds->DSS=STATE_NOT_CONNECTED;
*/
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

void MySQL_Session::handler___client_DSS_QUERY_SENT___send_INIT_DB_to_backend() {
	mybe->server_myds->move_from_OUT_to_OUTpending();
	mybe->server_myds->myconn->userinfo->set_schemaname(client_myds->myconn->userinfo->schemaname,strlen(client_myds->myconn->userinfo->schemaname));
	status=CHANGING_SCHEMA;
	mybe->server_myds->DSS=STATE_MARIADB_INITDB;
	mybe->server_myds->myconn->async_state_machine=ASYNC_INITDB_START;
	mybe->server_myds->myconn->handler(0);
//	mybe->server_myds->move_from_OUT_to_OUTpending();
//	//userinfo_server.set_schemaname(userinfo_client.schemaname,strlen(userinfo_client.schemaname));
//	mybe->server_myds->myconn->userinfo->set_schemaname(client_myds->myconn->userinfo->schemaname,strlen(client_myds->myconn->userinfo->schemaname));
//	//myprot_server.generate_COM_INIT_DB(true,NULL,NULL,userinfo_server.schemaname);
//	mybe->server_myds->myprot.generate_COM_INIT_DB(true,NULL,NULL,mybe->server_myds->myconn->userinfo->schemaname);
//	mybe->server_myds->DSS=STATE_QUERY_SENT_DS;
//	status=CHANGING_SCHEMA;
}

void MySQL_Session::handler___client_DSS_QUERY_SENT___send_SET_NAMES_to_backend() {
	mybe->server_myds->move_from_OUT_to_OUTpending();
	mybe->server_myds->myconn->set_charset(client_myds->myconn->options.charset);
//	mybe->server_myds->myprot.generate_COM_QUERY(true,NULL,NULL,(char *)"SET NAMES utf8");
//	mybe->server_myds->DSS=STATE_QUERY_SENT_DS;
	mybe->server_myds->DSS=STATE_MARIADB_SET_NAMES;
	mybe->server_myds->myconn->async_state_machine=ASYNC_SET_NAMES_START;
	mybe->server_myds->myconn->handler(0);
	status=CHANGING_CHARSET;
}

void MySQL_Session::handler___client_DSS_QUERY_SENT___send_CHANGE_USER_to_backend() {
	mybe->server_myds->move_from_OUT_to_OUTpending();
	mybe->server_myds->myconn->userinfo->set(client_myds->myconn->userinfo);
	mybe->server_myds->myprot.generate_COM_CHANGE_USER(true,NULL,NULL);
	mybe->server_myds->DSS=STATE_QUERY_SENT_DS;
	status=CHANGING_USER_SERVER;
}


void MySQL_Session::MySQL_Result_to_MySQL_wire(MYSQL *mysql, MYSQL_RES *result, MySQL_Protocol *myprot) {
	assert(myprot);
	MySQL_Data_Stream *myds=myprot->get_myds();
	myds->DSS=STATE_QUERY_SENT_DS;
	int sid=1;
	unsigned int num_fields=mysql_field_count(mysql);
	unsigned int num_rows;
	unsigned int pkt_length=0;
	if (result) {
		// we have a result set, this should be a SELECT statement with result
		assert(result->current_field==0);
		myprot->generate_pkt_column_count(true,NULL,&pkt_length,sid,num_fields); sid++;
		client_myds->resultset_length+=pkt_length;
		for (unsigned int i=0; i<num_fields; i++) {
			MYSQL_FIELD *field=mysql_fetch_field(result);
			myprot->generate_pkt_field(true,NULL,&pkt_length,sid,field->db,field->table,field->org_table,field->name,field->org_name,field->charsetnr,field->length,field->type,field->flags,field->decimals,false,0,NULL);
			client_myds->resultset_length+=pkt_length;
			sid++;
		}
		myds->DSS=STATE_COLUMN_DEFINITION;
		num_rows=mysql_num_rows(result);
		myprot->generate_pkt_EOF(true,NULL,&pkt_length,sid,0,0); sid++;
		client_myds->resultset_length+=pkt_length;
		//char **p=(char **)malloc(sizeof(char*)*num_fields);
		//int *l=(int *)malloc(sizeof(int*)*num_fields);
		//p[0]="column test";
		for (unsigned int r=0; r<num_rows; r++) {
			MYSQL_ROW row=mysql_fetch_row(result);
			unsigned long *lengths=mysql_fetch_lengths(result);
//
//		for (int i=0; i<num_fields; i++) {
//			l[i]=result->rows[r]->sizes[i];
//			p[i]=result->rows[r]->fields[i];
//		}
			myprot->generate_pkt_row(true,NULL,&pkt_length,sid,num_fields,lengths,row); sid++;
			client_myds->resultset_length+=pkt_length;
		}
		myds->DSS=STATE_ROW;
		myprot->generate_pkt_EOF(true,NULL,&pkt_length,sid,0,2); sid++;
		client_myds->resultset_length+=pkt_length;
		if (qpo && qpo->cache_ttl>0 && mysql_error(mysql)==0) {
			client_myds->resultset->copy_add(client_myds->PSarrayOUT,0,client_myds->PSarrayOUT->len);
			unsigned char *aa=client_myds->resultset2buffer(false);
			while (client_myds->resultset->len) client_myds->resultset->remove_index(client_myds->resultset->len-1,NULL);	
			GloQC->set((unsigned char *)client_myds->query_SQL,strlen((char *)client_myds->query_SQL)+1,aa,client_myds->resultset_length,30);
			l_free(client_myds->resultset_length,aa);
			client_myds->resultset_length=0;
			l_free(strlen((char *)client_myds->query_SQL)+1,client_myds->query_SQL);
		}
		myds->DSS=STATE_SLEEP;
		//free(l);
		//free(p);
	} else { // no result set
		int myerrno=mysql_errno(mysql);
		if (myerrno==0) {
			num_rows = mysql_affected_rows(mysql);
			myprot->generate_pkt_OK(true,NULL,NULL,sid,num_rows,mysql->insert_id,mysql->status,mysql->warning_count,mysql->info);
		} else {
			// error
			char sqlstate[10];
			sprintf(sqlstate,"#%s",mysql_sqlstate(mysql));
			myprot->generate_pkt_ERR(true,NULL,NULL,sid,mysql_errno(mysql),sqlstate,mysql_error(mysql));
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

		myprot->generate_pkt_EOF(true,NULL,NULL,sid,0,0); sid++;
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
		myprot->generate_pkt_EOF(true,NULL,NULL,sid,0,2); sid++;
		myds->DSS=STATE_SLEEP;
		free(l);
		free(p);
	
	} else { // no result set
		if (error) {
			// there was an error
			myprot->generate_pkt_ERR(true,NULL,NULL,sid,1045,(char *)"#28000",error);
		} else {
			// no error, DML succeeded
			myprot->generate_pkt_OK(true,NULL,NULL,sid,affected_rows,0,0,0,NULL);
		}
		myds->DSS=STATE_SLEEP;
	}
}

SQLite3_result * MySQL_Session::SQL3_Session_status() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Dumping MySQL Session status\n");
  SQLite3_result *result=new SQLite3_result(4);
	result->add_column_definition(SQLITE_TEXT,"ThreadID");
	result->add_column_definition(SQLITE_TEXT,"Thread_ptr");
	result->add_column_definition(SQLITE_TEXT,"Session_ptr");
	result->add_column_definition(SQLITE_TEXT,"Status");

	char buf[1024];

	char **pta=(char **)malloc(sizeof(char *)*4);
	long long int thread_id=syscall(SYS_gettid);
	itostr(pta[0],thread_id);
	pta[1]=(char *)malloc(32);
	sprintf(pta[1],"%p",this->thread);
	pta[2]=(char *)malloc(32);
	sprintf(pta[2],"%p",this);
	
	std::string status_str;
	status_str.reserve(10000);
	status_str = "\n";
	status_str+= "============\n";
	status_str+= "MySQL Thread\n";
	status_str+= "============\n";
	status_str+= "ThreadID: ";
	status_str.append(pta[0]);
	status_str+= "\n";

	status_str+="\ndefault_schema : "; status_str.append(mysql_thread___default_schema);
	status_str+="\nserver_version : "; status_str.append(mysql_thread___server_version);
	sprintf(buf,"\ncapabilities   : %d\npoll_timeout   : %d\n", mysql_thread___server_capabilities, mysql_thread___poll_timeout);
	status_str.append(buf);
	status_str+= "\n";

	sprintf(buf, "Proxy_Polls: %p , len: %d , loops: %lu\n", &thread->mypolls, thread->mypolls.len, thread->mypolls.loops);
	status_str.append(buf);
	for (unsigned int i=0; i < thread->mypolls.len; i++) {
		MySQL_Data_Stream *_myds=thread->mypolls.myds[i];
		sprintf(buf, "myds[%d]: %p = { fd=%d , events=%d , revents=%d } , type=%d , dss=%d , sess=%p , conn=%p\n", i, _myds , thread->mypolls.fds[i].fd , thread->mypolls.fds[i].events , thread->mypolls.fds[i].revents , _myds->myds_type , _myds->DSS , _myds->sess , _myds->myconn);
		status_str.append(buf);
	}
	status_str+= "\n";

	sprintf(buf, "MySQL Sessions: %p, len: %d\n", thread->mysql_sessions, thread->mysql_sessions->len);
	status_str.append(buf);
	for (unsigned int i=0; i < thread->mysql_sessions->len; i++) {
		MySQL_Session *s=(MySQL_Session *)thread->mysql_sessions->pdata[i];
		MySQL_Connection_userinfo *ui=s->client_myds->myconn->userinfo;
		sprintf(buf, "session[%d] = %p :\n\tuserinfo={%s,%s} , status=%d , myds={%p,%p} , HG={d:%d,c:%d}\n\tLast query= ", i, s, ui->username, ui->schemaname, s->status, s->client_myds, s->mybe->server_myds, s->default_hostgroup, s->current_hostgroup);
		status_str.append(buf);
		if (mysql_thread___commands_stats==true) {
			if (s->CurrentQuery.QueryLength && s->CurrentQuery.MyComQueryCmd!=MYSQL_COM_QUERY___NONE) {
				status_str.append((char *)s->CurrentQuery.QueryPointer);
			}
		}
		status_str+= "\n";
	}
	
	


	pta[3]=(char *)status_str.c_str();
	result->add_row(pta);
	for (int i=0; i<3; i++)
		free(pta[i]);
	free(pta);
	return result;
}


void MySQL_Session::set_unhealthy() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess:%p\n", this);
	healthy=0;
}

/*
void MySQL_Session::return_MySQL_Connection_To_Poll(MySQL_Data_Stream *myds) {
	MySQL_Connection *myconn=myds->myconn;
	myds->myconn->last_time_used=thread->curtime;
	myds->detach_connection();
	myds->unplug_backend();
	myconn->async_state_machine=ASYNC_IDLE;
	MyHGM->push_MyConn_to_pool(myconn);
}

void MySQL_Session::destroy_MySQL_Connection(MySQL_Data_Stream *myds) {
	MySQL_Connection *myconn=myds->myconn;
	//myds->myconn->last_time_used=thread->curtime;
	myds->detach_connection();
	myds->unplug_backend();
	MyHGM->destroy_MyConn_from_pool(myconn);
}
*/
