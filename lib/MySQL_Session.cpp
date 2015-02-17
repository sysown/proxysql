#include "proxysql.h"
#include "cpp.h"

extern Query_Processor *GloQPro;
extern Query_Cache *GloQC;
extern ProxySQL_Admin *GloAdmin;
extern MySQL_Threads_Handler *GloMTH;

static unsigned int __debugging_mp=0;
/*
MySQL_Session_userinfo::MySQL_Session_userinfo() {
	username=NULL;
	password=NULL;
	schemaname=l_strdup(mysql_thread___default_schema);
}

MySQL_Session_userinfo::~MySQL_Session_userinfo() {
	if (username) l_free_string(username);
	if (password) l_free_string(password);
	if (schemaname) l_free_string(schemaname);
}

void MySQL_Session_userinfo::set(char *u, char *p, char *s) {
	if (u) {
		if (username) l_free_string(username);
		username=l_strdup(u);
	}
	if (p) {
		if (password) l_free_string(password);
		password=l_strdup(p);
	}
	if (s) {
		if (schemaname) l_free_string(schemaname);
		schemaname=l_strdup(s);
	}
}

void MySQL_Session_userinfo::set(MySQL_Session_userinfo *ui) {
	set(ui->username, ui->password, ui->schemaname);
}


bool MySQL_Session_userinfo::set_schemaname(char *_new, int l) {
	if (strncmp(_new,schemaname,l)) {
		l_free_string(schemaname);
		schemaname=(char *)l_alloc(l+1);
		memcpy(schemaname,_new,l);
		schemaname[l]=0;
		return true;
	}
	return false;
}
*/

Query_Info::Query_Info() {
	MyComQueryCmd=MYSQL_COM_QUERY___NONE;
	QueryPointer=NULL;
	QueryLength=0;
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
	pause=0;
	pause_until=0;
	status=NONE;
	qpo=NULL;
	command_counters=new StatCounters(15,10,false);
	healthy=1;
	admin=false;
	connections_handler=false;
	stats=false;
	admin_func=NULL;
	//client_fd=0;
	//server_fd=0;
	client_myds=NULL;
	//server_myds=NULL;
	to_process=0;
	mybe=NULL;
	mybes= new (true) PtrArray(4,true);

	current_hostgroup=-1;
	default_hostgroup=-1;
	transaction_persistent=false;
	active_transactions=0;
	//myprot_client.init(&client_myds, &userinfo_client, this);
	//myprot_server.init(&server_myds, &userinfo_server, this);
	//myprot_client.init(&client_myds, client_myds->myconn->userinfo, this);
	//myprot_server.init(&server_myds, NULL, this);
}

/*
MySQL_Session::MySQL_Session(int _fd) {
	MySQL_Session();
	client_fd=_fd;
}
*/

MySQL_Session::~MySQL_Session() {
	if (client_myds) {
		delete client_myds;
	}
	//if (server_myds) {
	//	delete server_myds;
	//}
	reset_all_backends();
	delete mybes;
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Shutdown Session %p\n" , this->thread, this, this);
	delete command_counters;
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
				if (mybe->server_myds->poll_fds_idx>-1 && (mybe->server_myds->mypolls->fds[mybe->server_myds->poll_fds_idx].revents & POLLOUT)) {
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

/*
 * FIXME: this code is obscure and needs improvements . Commenting for now
	if (pause>0 || (status==CONNECTING_SERVER && server_myds && ( server_myds->myds_type==MYDS_BACKEND_FAILED_CONNECT || server_myds->myds_type==MYDS_BACKEND_PAUSE_CONNECT ))) {
		server_myds->connect_tries++;
		if (server_myds->connect_tries<10) {
			int pending_connect=1;
			if (server_fd) {
				shutdown(server_myds->fd,SHUT_RDWR);
				close(server_myds->fd);
				server_myds->fd=0;
				thread->mypolls.remove_index_fast(server_myds->poll_fds_idx);
				server_fd=0;
			}
			if (pause<=0) {
				unsigned long long curtime=monotonic_time();
				//int rc=server_myds->assign_mshge(current_hostgroup);

				//mybe=find_backend(1);
				mybe=find_or_create_backend(current_hostgroup,server_myds);
				assert(server_myds);
				assert(server_myds->myconn);
				// FIXME: This part should be replaced
				//assert(server_myds->myconn->mshge);
				//assert(server_myds->myconn->mshge->MSptr);
	      //server_fd=server_myds->myds_connect(server_myds->myconn->mshge->MSptr->address, server_myds->myconn->mshge->MSptr->port, &pending_connect);
				server_myds->init((pending_connect==1 ? MYDS_BACKEND_NOT_CONNECTED : MYDS_BACKEND), this, server_fd);
				thread->mypolls.add(POLLIN|POLLOUT, server_fd, server_myds, curtime);
				status=CONNECTING_SERVER;
				server_myds->DSS=STATE_NOT_CONNECTED;
			}
		} else {
			if (server_fd) {
				shutdown(server_myds->fd,SHUT_RDWR);
				close(server_myds->fd);
				server_myds->fd=0;
				thread->mypolls.remove_index_fast(server_myds->poll_fds_idx);
				server_fd=0;
			}
			healthy=0;
			// give up
			//assert(0);
		}
	}
*/

	if (client_myds==NULL) {
		goto __exit_DSS__STATE_NOT_INITIALIZED;
	}

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
										CurrentQuery.init((unsigned char *)pkt.ptr,pkt.size,true);
										CurrentQuery.start_time=thread->curtime;
										CurrentQuery.query_parser_init();
										CurrentQuery.query_parser_command_type();
										CurrentQuery.query_parser_free();
										handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_debug(&pkt);
										CurrentQuery.end_time=thread->curtime;
										CurrentQuery.query_parser_update_counters();
										break;
									}
								}
#endif /* DEBUG */							
								if (admin==false) {
									CurrentQuery.init((unsigned char *)pkt.ptr,pkt.size,true);
									CurrentQuery.start_time=thread->curtime;
									CurrentQuery.query_parser_init();
									CurrentQuery.query_parser_command_type();
									CurrentQuery.query_parser_free();
									client_myds->myprot.process_pkt_COM_QUERY((unsigned char *)pkt.ptr,pkt.size);
									qpo=GloQPro->process_mysql_query(this,pkt.ptr,pkt.size,false);
									if (qpo) {
										bool rc_break=handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(&pkt);
										if (rc_break==true) { break; }
									}
									mybe=find_or_create_backend(current_hostgroup);
									//if (server_myds!=mybe->server_myds) {
									//	server_myds=mybe->server_myds;
									//} 
									mybe->server_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
									client_myds->DSS=STATE_QUERY_SENT_NET;
								} else {
									// this is processed by the admin module
									admin_func(this, GloAdmin, &pkt);
									l_free(pkt.size,pkt.ptr);
								}
								break;
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

			case NONE:
			default:
				assert(0);
		}
	}



__get_a_backend:

	if (client_myds==NULL) {
		goto __exit_DSS__STATE_NOT_INITIALIZED;
	}

	if (client_myds->DSS==STATE_QUERY_SENT_NET) {
	// the client has completely sent the query, now we should handle it server side
	//
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

			// FIXME : handle missing connection from connection pool
			// FIXME : perhaps is a goto __exit_DSS__STATE_NOT_INITIALIZED after setting time wait

			thread->mypolls.add(POLLIN|POLLOUT, mybe->server_myds->fd, mybe->server_myds, curtime);

			if (mybe->server_myds->DSS!=STATE_READY) {
				mybe->server_myds->move_from_OUT_to_OUTpending();
			}
			// END OF if (server_myds->DSS==STATE_NOT_INITIALIZED)
								//} else {  TRY #1
		}    // TRY #1
		if (mybe && mybe->server_myds->myds_type==MYDS_BACKEND && mybe->server_myds->DSS==STATE_READY) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p, client_myds->DSS==STATE_QUERY_SENT_NET , server_myds==STATE_READY , server_myds->myds_type==MYDS_BACKEND\n", this);
			//if (strcmp(userinfo_client.schemaname,userinfo_server.schemaname)==0) {
			if (
				(client_myds->myconn->userinfo->hash!=mybe->server_myds->myconn->userinfo->hash)
/*
				(mybe->myconn->userinfo->schemaname==NULL)
				||
				strcmp(client_myds->myconn->userinfo->schemaname,mybe->myconn->userinfo->schemaname)
				||
				strcmp(client_myds->myconn->userinfo->username,mybe->myconn->userinfo->username)
*/
			) {
				if (strcmp(client_myds->myconn->userinfo->username,mybe->server_myds->myconn->userinfo->username)) {
					// username don't match, we must change user
					handler___client_DSS_QUERY_SENT___send_CHANGE_USER_to_backend();
				} else {
					// we should chek that schema is different, but here we assume that if we reach here user is identical, but schema is not
					handler___client_DSS_QUERY_SENT___send_INIT_DB_to_backend();
				}
			} else {
				//server_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
				mybe->server_myds->DSS=STATE_QUERY_SENT_DS;
				status=WAITING_SERVER_DATA;
			}
		}
							//	}   TRY #1
	}

__exit_DSS__STATE_NOT_INITIALIZED:
		

//	}

	if (mybe && mybe->server_myds) {
		for (j=0; j<mybe->server_myds->PSarrayIN->len;) {
			mybe->server_myds->PSarrayIN->remove_index(0,&pkt);

		switch (status) {
			case CONNECTING_SERVER:

				switch (mybe->server_myds->DSS) {
					case STATE_NOT_CONNECTED:
						handler___status_CONNECTING_SERVER___STATE_NOT_CONNECTED(&pkt);
						break;
					case STATE_CLIENT_HANDSHAKE:
						handler___status_CONNECTING_SERVER___STATE_CLIENT_HANDSHAKE(&pkt, &wrong_pass);
						break;
					default:
						assert(0);

				}
				break;

			case WAITING_SERVER_DATA:

				switch (mybe->server_myds->DSS) {
					case STATE_PING_SENT_NET:
						handler___status_WAITING_SERVER_DATA___STATE_PING_SENT(&pkt);
						break;

					case STATE_QUERY_SENT_NET:
						handler___status_WAITING_SERVER_DATA___STATE_QUERY_SENT(&pkt);
						break;

					case STATE_ROW:
						handler___status_WAITING_SERVER_DATA___STATE_ROW(&pkt);
						break;

					case STATE_EOF1:
						handler___status_WAITING_SERVER_DATA___STATE_EOF1(&pkt);
						break;

					default:
						assert(0);
				}
				break;

			case CHANGING_SCHEMA:
				if (handler___status_CHANGING_SCHEMA(&pkt)==false) {
					return -1;
				}
				break;

			case CHANGING_USER_SERVER:
				if (handler___status_CHANGING_USER_SERVER(&pkt)==false) {
					return -1;
				}
				break;

			default:
				assert(0);
		}

		}
	}

	writeout();

	if (
		mybe
		&&
		mybe->server_myds
		&&
		mybe->server_myds->DSS==STATE_QUERY_SENT_DS
		&&
		mybe->server_myds->PSarrayOUT->len==0
		&&
		mybe->server_myds->net_failure==false
		&&
		mybe->server_myds->available_data_out()==false
	) {
		if (connections_handler) {
			mybe->server_myds->DSS=STATE_PING_SENT_NET;
		} else {
			mybe->server_myds->DSS=STATE_QUERY_SENT_NET;
		}
	}
	if (mybe && mybe->server_myds) {
		if (mybe->server_myds->net_failure) {
			if (( mybe->server_myds->DSS==STATE_READY || mybe->server_myds->DSS==STATE_QUERY_SENT_DS ) && mybe->server_myds->myds_type==MYDS_BACKEND) {
				mybe->server_myds->myconn=NULL;
				mybe->server_myds->DSS=STATE_NOT_INITIALIZED;
				mybe->server_myds->move_from_OUT_to_OUTpending();
				if (mybe->server_myds->myconn) {
					MyHGM->destroy_MyConn_from_pool(mybe->server_myds->myconn);
					mybe->server_myds->myconn=NULL;
				}
				if (mybe->server_myds->fd) {
					shutdown(mybe->server_myds->fd,SHUT_RDWR);
					close(mybe->server_myds->fd);
					mybe->server_myds->fd=0;
					thread->mypolls.remove_index_fast(mybe->server_myds->poll_fds_idx);
					//server_fd=0;
				}
				mybe->server_myds->net_failure=false;
				mybe->server_myds->active=1;
				goto __get_a_backend;
			} else {
				healthy=0;
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
	if (wrong_pass==true) return -1;
	return 0;
}


bool MySQL_Session::handler___status_CHANGING_SCHEMA(PtrSize_t *pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: CHANGING_SCHEMA - UNKNWON\n");
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
		return true;
	} else {
		l_free(pkt->size,pkt->ptr);
		healthy=0;
		//mybe->myconn=server_myds->myconn;
		// if we reach here, server_myds->DSS should be STATE_QUERY_SENT , therefore the connection to the backend should be dropped anyway
		// although we enforce this here
		mybe->server_myds->myconn->reusable=false;
		return false;
	}
	return false;
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
		return true;
	} else {
		l_free(pkt->size,pkt->ptr);	
		healthy=0;
		//mybe->myconn=server_myds->myconn;
		// if we reach here, server_myds->DSS should be STATE_QUERY_SENT , therefore the connection to the backend should be dropped anyway
		// although we enforce this here
		mybe->server_myds->myconn->reusable=false;
		return false;
	}
	return false;
}


void MySQL_Session::handler___status_WAITING_SERVER_DATA___STATE_PING_SENT(PtrSize_t *pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: WAITING_SERVER_DATA - STATE_PING_SENT\n");
	unsigned char c;
	c=*((unsigned char *)pkt->ptr+sizeof(mysql_hdr));
	if (c==0 || c==0xff) {
		mybe->server_myds->DSS=STATE_READY;
		/* multi-plexing attempt */
		if (c==0) {
			mybe->server_myds->myprot.process_pkt_OK((unsigned char *)pkt->ptr,pkt->size);
			//fprintf(stderr,"hid=%d status=%d\n", mybe->hostgroup_id, myprot_server.prot_status);
			if ((mybe->server_myds->myconn->reusable==true) && ((mybe->server_myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
				mybe->server_myds->myconn->last_time_used=thread->curtime;
				MyHGM->push_MyConn_to_pool(mybe->server_myds->myconn);
				//MyHGM->destroy_MyConn_from_pool(mybe->server_myds->myconn);
				mybe->server_myds->myconn=NULL;
				mybe->server_myds->unplug_backend();
				unsigned int aa=__sync_fetch_and_add(&__debugging_mp,1);
				if (aa%1000==0) fprintf(stderr,"mp=%u\n", aa);
			}
		}
		/* multi-plexing attempt */	
		status=NONE;
	}
	l_free(pkt->size,pkt->ptr);
}

void MySQL_Session::handler___status_WAITING_SERVER_DATA___STATE_QUERY_SENT(PtrSize_t *pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: WAITING_SERVER_DATA - STATE_QUERY_SENT\n");
	unsigned char c;
	c=*((unsigned char *)pkt->ptr+sizeof(mysql_hdr));
	if (c==0 || c==0xff) {
		mybe->server_myds->DSS=STATE_READY;
		/* multi-plexing attempt */
		if (c==0) {
			mybe->server_myds->myprot.process_pkt_OK((unsigned char *)pkt->ptr,pkt->size);
			//fprintf(stderr,"hid=%d status=%d\n", mybe->hostgroup_id, myprot_server.prot_status);
			if ((mybe->server_myds->myconn->reusable==true) && ((mybe->server_myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
				mybe->server_myds->myconn->last_time_used=thread->curtime;
				MyHGM->push_MyConn_to_pool(mybe->server_myds->myconn);
				//MyHGM->destroy_MyConn_from_pool(mybe->server_myds->myconn);
				mybe->server_myds->myconn=NULL;
				mybe->server_myds->unplug_backend();
				unsigned int aa=__sync_fetch_and_add(&__debugging_mp,1);
				if (aa%1000==0) fprintf(stderr,"mp=%u\n", aa);
			}
		}
		/* multi-plexing attempt */	
		status=WAITING_CLIENT_DATA;
		client_myds->DSS=STATE_SLEEP;
		client_myds->PSarrayOUT->add(pkt->ptr, pkt->size);
		CurrentQuery.end_time=thread->curtime;
		CurrentQuery.query_parser_update_counters();
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
				mybe->server_myds->myconn->last_time_used=thread->curtime;
				MyHGM->push_MyConn_to_pool(mybe->server_myds->myconn);
				//MyHGM->destroy_MyConn_from_pool(mybe->server_myds->myconn);;
				mybe->server_myds->myconn=NULL;
				mybe->server_myds->unplug_backend();
				unsigned int aa=__sync_fetch_and_add(&__debugging_mp,1);
				if (aa%1000==0) fprintf(stderr,"mp=%u\n", aa);
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
		CurrentQuery.end_time=thread->curtime;
		CurrentQuery.query_parser_update_counters();
	}
}


void MySQL_Session::handler___status_CONNECTING_SERVER___STATE_NOT_CONNECTED(PtrSize_t *pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: CONNECTING_SERVER - STATE_NOT_CONNECTED\n");
	if (mybe->server_myds->myprot.process_pkt_initial_handshake((unsigned char *)pkt->ptr,pkt->size)==true) {
		l_free(pkt->size,pkt->ptr);
		//myprot_server.generate_pkt_handshake_response(server_myds,true,NULL,NULL);
		mybe->server_myds->myconn->userinfo->set(client_myds->myconn->userinfo);
		mybe->server_myds->myprot.generate_pkt_handshake_response(true,NULL,NULL);
		////status=WAITING_CLIENT_DATA;
		mybe->server_myds->DSS=STATE_CLIENT_HANDSHAKE;
	} else {
		// FIXME: what to do here?
		l_free(pkt->size,pkt->ptr);
		//assert(0);
		MyHGM->destroy_MyConn_from_pool(mybe->server_myds->myconn);
		mybe->server_myds->myconn=NULL;
		mybe->server_myds->fd=-1;
		thread->mypolls.remove_index_fast(mybe->server_myds->poll_fds_idx);
		mybe->server_myds->DSS=STATE_NOT_CONNECTED;
		
	}
}

void MySQL_Session::handler___status_CONNECTING_SERVER___STATE_CLIENT_HANDSHAKE(PtrSize_t *pkt, bool *wrong_pass) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: CONNECTING_SERVER - STATE_CLIENT_HANDSHAKE\n");
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
	} else {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Wrong credentials for backend: disconnecting\n");
		l_free(pkt->size,pkt->ptr);	
		*wrong_pass=true;
		client_myds->DSS=STATE_QUERY_SENT_NET;
		char *_s=(char *)malloc(strlen(client_myds->myconn->userinfo->username)+100);
		sprintf(_s,"Access denied for user '%s' (using password: %s)", client_myds->myconn->userinfo->username, (client_myds->myconn->userinfo->password ? "YES" : "NO"));
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000", _s);
		free(_s);
		client_myds->DSS=STATE_SLEEP;
		status=WAITING_CLIENT_DATA;
		mybe->server_myds->myconn->reusable=false;
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
				client_myds->myconn->userinfo->set_schemaname(mysql_thread___default_schema,strlen(mysql_thread___default_schema));
			}
			client_myds->myprot.generate_pkt_OK(true,NULL,NULL,2,0,0,0,0,NULL);
			//server_myds->myconn->userinfo->set(client_myds->myconn->userinfo);
			status=WAITING_CLIENT_DATA;
			client_myds->DSS=STATE_SLEEP;
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
		client_myds->DSS=STATE_QUERY_SENT_NET;
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
	client_myds->DSS=STATE_QUERY_SENT_NET;
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
	client_myds->DSS=STATE_QUERY_SENT_NET;
	client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,2,0,NULL);
	client_myds->DSS=STATE_SLEEP;
}

void MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_FIELD_LIST(PtrSize_t *pkt) {
	if (admin==false) {
		/* FIXME: temporary */
		l_free(pkt->size,pkt->ptr);
		client_myds->DSS=STATE_QUERY_SENT_NET;
		client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",(char *)"Command not supported");
		client_myds->DSS=STATE_SLEEP;
	} else {
		l_free(pkt->size,pkt->ptr);
		client_myds->DSS=STATE_QUERY_SENT_NET;
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

	unsigned int query_no_space_length=remove_spaces(query_no_space);

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
	client_myds->DSS=STATE_QUERY_SENT_NET;
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
		client_myds->DSS=STATE_QUERY_SENT_NET;
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,2,0,NULL);
		client_myds->DSS=STATE_SLEEP;
	} else {
		l_free(pkt->size,pkt->ptr);
		client_myds->DSS=STATE_QUERY_SENT_NET;
		client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,2,0,NULL);
		client_myds->DSS=STATE_SLEEP;
	}
}



bool MySQL_Session::handler___status_WAITING_CLIENT_DATA___STATE_SLEEP___MYSQL_COM_QUERY_qpo(PtrSize_t *pkt) {
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
			CurrentQuery.end_time=thread->curtime;
			CurrentQuery.query_parser_update_counters();
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
	client_myds->DSS=STATE_QUERY_SENT_NET;
	client_myds->myprot.generate_statistics_response(true,NULL,NULL);
	client_myds->DSS=STATE_SLEEP;	
}

void MySQL_Session::handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection() {
			// Get a MySQL Connection
	
//	if (rand()%3==0) {
		mybe->server_myds->myconn=MyHGM->get_MyConn_from_pool(mybe->hostgroup_id);
//	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p -- server_myds=%p -- MySQL_Connection %p\n", this, mybe->server_myds,  mybe->server_myds->myconn);
	if (mybe->server_myds->myconn==NULL) { return; }
	//mybe->myconn->myds=mybe->server_myds;
	//mybe->myconn=mybe->server_myds->myconn;
	if (mybe->server_myds->myconn->fd==-1) {
		// we didn't get a valid connection, we need to create one
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p -- MySQL Connection has no FD\n", this);
		//server_myds->myconn=mybe->myconn;
		int __fd;
		__fd=mybe->server_myds->myds_connect(mybe->server_myds->myconn->parent->address, mybe->server_myds->myconn->parent->port, &pending_connect);

		if (__fd==-1) {
			MyHGM->destroy_MyConn_from_pool(mybe->server_myds->myconn);
			mybe->server_myds->myconn=NULL;
			return;
		}

		mybe->server_myds->init((pending_connect==1 ? MYDS_BACKEND_NOT_CONNECTED : MYDS_BACKEND), this, __fd);
		//mybe->myconn=server_myds->myconn;
		mybe->server_myds->myconn->reusable=true;
		mybe->server_myds->myconn->fd=mybe->server_myds->fd;
		status=CONNECTING_SERVER;
		mybe->server_myds->DSS=STATE_NOT_CONNECTED;
	} else {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Sess=%p -- MySQL Connection found = %p\n", this, mybe->server_myds->myconn);
		//server_myds->myconn=mybe->myconn;
		mybe->server_myds->assign_fd_from_mysql_conn();
		//server_fd=server_myds->fd;
		mybe->server_myds->myds_type=MYDS_BACKEND;
		mybe->server_myds->DSS=STATE_READY;
	}
}

void MySQL_Session::handler___client_DSS_QUERY_SENT___send_INIT_DB_to_backend() {
	mybe->server_myds->move_from_OUT_to_OUTpending();
	//userinfo_server.set_schemaname(userinfo_client.schemaname,strlen(userinfo_client.schemaname));
	mybe->server_myds->myconn->userinfo->set_schemaname(client_myds->myconn->userinfo->schemaname,strlen(client_myds->myconn->userinfo->schemaname));
	//myprot_server.generate_COM_INIT_DB(true,NULL,NULL,userinfo_server.schemaname);
	mybe->server_myds->myprot.generate_COM_INIT_DB(true,NULL,NULL,mybe->server_myds->myconn->userinfo->schemaname);
	mybe->server_myds->DSS=STATE_QUERY_SENT_DS;
	status=CHANGING_SCHEMA;
}

void MySQL_Session::handler___client_DSS_QUERY_SENT___send_CHANGE_USER_to_backend() {
	mybe->server_myds->move_from_OUT_to_OUTpending();
	//userinfo_server.set_schemaname(userinfo_client.schemaname,strlen(userinfo_client.schemaname));
	//mybe->myconn->userinfo->set_schemaname(client_myds->myconn->userinfo->schemaname,strlen(client_myds->myconn->userinfo->schemaname));
	mybe->server_myds->myconn->userinfo->set(client_myds->myconn->userinfo);
	//myprot_server.generate_COM_INIT_DB(true,NULL,NULL,userinfo_server.schemaname);
	mybe->server_myds->myprot.generate_COM_CHANGE_USER(true,NULL,NULL);
	mybe->server_myds->DSS=STATE_QUERY_SENT_DS;
	status=CHANGING_USER_SERVER;
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
			//myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",(char *)"alias",(char *)"",33,15,MYSQL_TYPE_VAR_STRING,1,0x1f,true,0,(char *)"");
			//myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",result->column_definition[i]->name,(char *)"",33,15,MYSQL_TYPE_VAR_STRING,1,0x1f,true,0,(char *)"");
			myprot->generate_pkt_field(true,NULL,NULL,sid,(char *)"",(char *)"",(char *)"",result->column_definition[i]->name,(char *)"",33,15,MYSQL_TYPE_VAR_STRING,1,0x1f,false,0,NULL);
			sid++;
		}
		myds->DSS=STATE_COLUMN_DEFINITION;

		myprot->generate_pkt_EOF(true,NULL,NULL,sid,0,0); sid++;
		char **p=(char **)malloc(sizeof(char*)*result->columns);
		int *l=(int *)malloc(sizeof(int*)*result->columns);
		//p[0]="column test";
		for (int r=0; r<result->rows_count; r++) {
		for (int i=0; i<result->columns; i++) {
			//int st=rand()%32+2;
			//p[i]=(char *)malloc(st+1);
			//for (int j=0; j<st; j++) {
			//	p[i][j]='a'+rand()%25;
			//}
			//p[i][st]='\0';
			//l[i]=strlen(p[i]);
			l[i]=result->rows[r]->sizes[i];
			p[i]=result->rows[r]->fields[i];
		}
		myprot->generate_pkt_row(true,NULL,NULL,sid,result->columns,l,p); sid++;
		}
		myds->DSS=STATE_ROW;
		myprot->generate_pkt_EOF(true,NULL,NULL,sid,0,2); sid++;
		myds->DSS=STATE_SLEEP;
		free(l);
		//free(p[0]);
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
		//sprintf(buf, "myds[%d]: %p = { fd=%d , events=%d , revents=%d }\n", i, thread->mypolls.myds[i] , thread->mypolls.fds[i].fd , thread->mypolls.fds[i].events , thread->mypolls.fds[i].revents );
		status_str.append(buf);
		if (s->CurrentQuery.QueryLength && s->CurrentQuery.MyComQueryCmd!=MYSQL_COM_QUERY___NONE) {
			//char *q=(char *)malloc(s->CurrentQuery.QueryLength+1);
			//memcpy(q,s->CurrentQuery.QueryPointer,s->CurrentQuery.QueryLength);
			//q[s->CurrentQuery.QueryLength]=0;`:
			status_str.append((char *)s->CurrentQuery.QueryPointer);
			//free(q);
		}
		status_str+= "\n";
	}
	
//	status_str+= "Proxy_Polls: "
	


	pta[3]=(char *)status_str.c_str();
	result->add_row(pta);
	for (int i=0; i<3; i++)
		free(pta[i]);
	free(pta);
	return result;
}
