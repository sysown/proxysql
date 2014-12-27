#include "proxysql.h"
#include "cpp.h"

extern Query_Processor *GloQPro;
extern Query_Cache *GloQC;
extern ProxySQL_Admin *GloAdmin;

MySQL_Session_userinfo::MySQL_Session_userinfo() {
	username=NULL;
	password=NULL;
	schemaname=l_strdup((char *)"information_schema");
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
/*	if (ui->username) {
		l_free_string(username);
		username=l_strdup(ui->username);
	}
	if (ui->password) {
		if (password) l_free_string(password);
		password=l_strdup(ui->password);
	}
	if (ui->schemaname) {
		l_free_string(schemaname);
		schemaname=l_strdup(ui->schemaname);
	}
*/
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

void * MySQL_Session::operator new(size_t size) {
	return l_alloc(size);
}

void MySQL_Session::operator delete(void *ptr) {
	l_free(sizeof(MySQL_Session),ptr);
}


MySQL_Session::MySQL_Session() {
	pause=0;
	status=NONE;
	qpo=NULL;
	healthy=1;
	admin=false;
	admin_func=NULL;
	client_fd=0;
	server_fd=0;
	//status=0;
//	username=NULL;
//	password=NULL;
//	schema_name=l_strdup((char *)"information_schema");
	//schema_cur=NULL;
	//schema_new=NULL;
	client_myds=NULL;
	server_myds=NULL;
	to_process=0;
	//mybes=g_ptr_array_new();
	//mybes= new PtrArray(4);
	//mybes= new (true) PtrArray(4,true);
	mybe=NULL;
	mybes= new (true) PtrArray(4,true);

	myprot_client.init(&client_myds, &userinfo_client, this);
	myprot_server.init(&server_myds, &userinfo_server, this);
}

MySQL_Session::MySQL_Session(int _fd) {
	MySQL_Session();
	client_fd=_fd;
}

MySQL_Session::~MySQL_Session() {
	//if (username) { free(username); }
	//if (password) { free(password); }
	//if (schema_cur) { free(schema_cur); }
	//if (schema_new) { free(schema_new); }
	//g_ptr_array_free(mybes,TRUE);
	if (client_myds) {
		delete client_myds;
	}
	if (server_myds) {
		delete server_myds;
	}
	reset_all_backends();
	delete mybes;
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Shutdown Session %p\n" , this->thread, this, this);
}


// scan the pointer array of mysql backends (mybes) looking for a backend for the specified hostgroup_id
MySQL_Backend * MySQL_Session::find_backend(int hostgroup_id) {
	MySQL_Backend *_mybe;
	unsigned int i;
	for (i=0; i < mybes->len; i++) {
		//mybe=(MySQL_Backend *)g_ptr_array_index(mybes,i);
		_mybe=(MySQL_Backend *)mybes->index(i);
		if (_mybe->hostgroup_id==hostgroup_id) {
			return _mybe;
		}
	}
	return NULL; // NULL = backend not found
};


MySQL_Backend * MySQL_Session::create_backend(int hostgroup_id, MySQL_Data_Stream *_myds) {
	MySQL_Backend *_mybe=new MySQL_Backend();
	_mybe->hostgroup_id=hostgroup_id;
	if (_myds) {
		_mybe->server_myds=_myds;
	} else {
		_mybe->server_myds = new MySQL_Data_Stream();
		_mybe->server_myds->myconn = new MySQL_Connection();
		_mybe->server_myds->DSS=STATE_NOT_INITIALIZED;
		_mybe->server_myds->init(MYDS_BACKEND_NOT_CONNECTED, this, 0);
	}
	mybes->add(_mybe);
	return _mybe;
};

MySQL_Backend * MySQL_Session::find_or_create_backend(int hostgroup_id, MySQL_Data_Stream *_myds) {
	MySQL_Backend *_mybe=find_backend(hostgroup_id);
	return ( _mybe ? _mybe : create_backend(hostgroup_id, _myds) );
};

void MySQL_Session::reset_all_backends() {
	MySQL_Backend *mybe;
	while(mybes->len) {
		//mybe=(MySQL_Backend *)g_ptr_array_remove_index_fast(mybes,0);
		mybe=(MySQL_Backend *)mybes->remove_index_fast(0);
		mybe->reset();
		delete mybe;
	}
};

void MySQL_Session::writeout() {
	//if (client_myds) client_myds->write_pkts();
	//if (server_myds) server_myds->write_pkts();
	if (client_myds) client_myds->array2buffer_full();
	//if (server_myds) server_myds->array2buffer_full();
	if (server_myds && server_myds->myds_type==MYDS_BACKEND) server_myds->array2buffer_full();

	// FIXME: experimental
	//if (client_myds) client_myds->set_pollout();
	//if (server_myds) server_myds->set_pollout();
	if (client_myds) client_myds->write_to_net_poll();
	if (server_myds) server_myds->write_to_net_poll();
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Writeout Session %p\n" , this->thread, this, this);
}

/*
MySQL_Data_Stream * MySQL_Session::inactive_handler(MySQL_Data_Stream *_myds) {
	if (_myds->active==TRUE) {
		return _myds;
	}
	rc=mypoll_del(&mypolls, n);
}
*/

int MySQL_Session::handler() {
	if (to_process==0) return 0; // this should be redundant if the called does the same check
	proxy_debug(PROXY_DEBUG_NET,1,"Thread=%p, Session=%p -- Processing session %p\n" , this->thread, this, this);
	//unsigned char *pkt;
	PtrSize_t pkt;
	unsigned int j;
	unsigned char c;

/*
	if (client_myds) {
		client_myds->read_from_net();
		client_myds->read_pkts();
	}
	if (server_myds) {
		server_myds->read_from_net();
		server_myds->read_pkts();
	}
*/
/*
	if (status==CONNECTING_SERVER && server_myds->myds_type==MYDS_BACKEND_PAUSED_CONNECT) {
		unsigned long curtime=monotonic_time();
		if (
		server_myds->myds_type=MYDS_BACKEND_FAILED_CONNECT;
	}
*/

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
				int rc=server_myds->assign_mshge(1);

				//mybe=find_backend(1);
				mybe=find_or_create_backend(1,server_myds);
				assert(server_myds);
				assert(server_myds->myconn);
				assert(server_myds->myconn->mshge);
				assert(server_myds->myconn->mshge->MSptr);
	      server_fd=server_myds->myds_connect(server_myds->myconn->mshge->MSptr->address, server_myds->myconn->mshge->MSptr->port, &pending_connect);
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

	for (j=0; j<client_myds->PSarrayIN->len;) {
		client_myds->PSarrayIN->remove_index(0,&pkt);
		//prot.parse_mysql_pkt(&pkt,client_myds);

		switch (status) {

			case CONNECTING_CLIENT:
				switch (client_myds->DSS) {
					case STATE_SERVER_HANDSHAKE:
						if (myprot_client.process_pkt_handshake_response((unsigned char *)pkt.ptr,pkt.size)==true) {
							l_free(pkt.size,pkt.ptr);
							if (client_myds->encrypted==false) {
								myprot_client.generate_pkt_OK(true,NULL,NULL,2,0,0,0,0,NULL);
								userinfo_server.set(&userinfo_client);
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
							l_free(pkt.size,pkt.ptr);
							// FIXME: this should become close connection
						}
						break;
					case STATE_SSL_INIT:
						if (myprot_client.process_pkt_handshake_response((unsigned char *)pkt.ptr,pkt.size)==true) {
							l_free(pkt.size,pkt.ptr);
							myprot_client.generate_pkt_OK(true,NULL,NULL,3,0,0,0,0,NULL);
							userinfo_server.set(&userinfo_client);
							status=WAITING_CLIENT_DATA;
							client_myds->DSS=STATE_SLEEP;
						} else {
							l_free(pkt.size,pkt.ptr);
							// FIXME: this should become close connection
						}	
						break;
					default:
						assert(0); // FIXME: this should become close connection
				}
				break;

			case WAITING_CLIENT_DATA:
				switch (client_myds->DSS) {
					case STATE_SLEEP:
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: WAITING_CLIENT_DATA - STATE_SLEEP\n");
						//unsigned char c;
						c=*((unsigned char *)pkt.ptr+sizeof(mysql_hdr));
						switch ((enum_mysql_command)c) {
							case _MYSQL_COM_QUERY:
							if (admin==false) {
								myprot_client.process_pkt_COM_QUERY((unsigned char *)pkt.ptr,pkt.size);
								qpo=GloQPro->process_mysql_query(this,pkt.ptr,pkt.size,false);
								if (qpo) {
									if (qpo->cache_ttl>0) {
										client_myds->query_SQL=(unsigned char *)l_alloc(pkt.size-sizeof(mysql_hdr));
										memcpy(client_myds->query_SQL,(unsigned char *)pkt.ptr+sizeof(mysql_hdr)+1,pkt.size-sizeof(mysql_hdr)-1);
										client_myds->query_SQL[pkt.size-sizeof(mysql_hdr)-1]=0;
//										fprintf(stderr,"Query to cache: %s\n", client_myds->query_SQL);
										uint32_t resbuf=0;
										unsigned char *aa=GloQC->get(client_myds->query_SQL,&resbuf);
										//unsigned char *aa=NULL;
										if (aa) {
											l_free(pkt.size,pkt.ptr);
											l_free(strlen((char *)client_myds->query_SQL)+1,client_myds->query_SQL);
//											fprintf(stderr,"Query found in cache: %s\n", client_myds->query_SQL);
											client_myds->buffer2resultset(aa,resbuf);
											free(aa);
											client_myds->PSarrayOUT->copy_add(client_myds->resultset,0,client_myds->resultset->len);
											while (client_myds->resultset->len) client_myds->resultset->remove_index(client_myds->resultset->len-1,NULL);
											status=WAITING_CLIENT_DATA;
											client_myds->DSS=STATE_SLEEP;
											GloQPro->delete_QP_out(qpo);
											qpo=NULL;
											break;
										}
									}
									//GloQPro->delete_QP_out(qpo);
									//qpo=NULL;
									//fprintf(stderr,"Query needs to be cached\n");
									//l_free(sizeof(QP_out_t), qpo);
									//break;
								}
								int destination_hostgroup=1;
								mybe=find_or_create_backend(destination_hostgroup);
								if (server_myds!=mybe->server_myds) {
									server_myds=mybe->server_myds;
								} 
/*
								if (server_myds==NULL) {
									//printf("Create new MYDS\n");
									server_myds = new MySQL_Data_Stream();
									server_myds->myconn = new MySQL_Connection(); // 20141011
          				int pending_connect=1;
									unsigned long long curtime=monotonic_time();
									int rc=server_myds->assign_mshge(1);

									//mybe=find_backend(1);
									mybe=find_or_create_backend(1,server_myds);
						assert(server_myds);
						assert(server_myds->myconn);
						assert(server_myds->myconn->mshge);
						assert(server_myds->myconn->mshge->MSptr);
	      					server_fd=server_myds->myds_connect(server_myds->myconn->mshge->MSptr->address, server_myds->myconn->mshge->MSptr->port, &pending_connect);
        //  				server_fd=server_myds->myds_connect((char *)"127.0.0.1", 3306, &pending_connect);
									server_myds->init((pending_connect==1 ? MYDS_BACKEND_NOT_CONNECTED : MYDS_BACKEND), this, server_fd);
									//thread->mypolls.add(POLLIN|POLLOUT, server_fd, server_myds, pending_connect==1 ? 0 : curtime);
									thread->mypolls.add(POLLIN|POLLOUT, server_fd, server_myds, curtime);
									status=CONNECTING_SERVER;
									server_myds->DSS=STATE_NOT_CONNECTED;
									server_myds->PSarrayOUTpending->add(pkt.ptr, pkt.size);
								} else {
									if (strcmp(userinfo_client.schemaname,userinfo_server.schemaname)==0) {
										server_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
										server_myds->DSS=STATE_QUERY_SENT;
										status=WAITING_SERVER_DATA;
									} else {
										userinfo_server.set_schemaname(userinfo_client.schemaname,strlen(userinfo_client.schemaname));
										server_myds->PSarrayOUTpending->add(pkt.ptr, pkt.size);
										myprot_server.generate_COM_INIT_DB(true,NULL,NULL,userinfo_server.schemaname);
										server_myds->DSS=STATE_QUERY_SENT;
										status=CHANGING_SCHEMA;
									}
								}
*/
//								if (server_myds->myds_type==MYDS_BACKEND && server_myds->DSS==STATE_READY) {
									server_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
//								} else {
//									server_myds->PSarrayOUTpending->add(pkt.ptr, pkt.size);
//								}
								client_myds->DSS=STATE_QUERY_SENT;
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
								proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_PING packet\n");
								l_free(pkt.size,pkt.ptr);
								client_myds->DSS=STATE_QUERY_SENT;
								myprot_client.generate_pkt_OK(true,NULL,NULL,1,0,0,2,0,NULL);
								client_myds->DSS=STATE_SLEEP;
								break;
							case _MYSQL_COM_STATISTICS:
								proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_STATISTICS packet\n");
								l_free(pkt.size,pkt.ptr);
								client_myds->DSS=STATE_QUERY_SENT;
								myprot_client.generate_statistics_response(true,NULL,NULL);
								client_myds->DSS=STATE_SLEEP;	
								break;
							case _MYSQL_COM_INIT_DB:
								proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_INIT_DB packet\n");
								if (admin==false) {
									userinfo_client.set_schemaname((char *)pkt.ptr+sizeof(mysql_hdr)+1,pkt.size-sizeof(mysql_hdr)-1);
/*
									char *_new_schema=(char *)l_alloc(pkt.size-sizeof(mysql_hdr));
									memcpy(_new_schema,(char *)pkt.ptr+sizeof(mysql_hdr)+1,pkt.size-sizeof(mysql_hdr)-1);
									_new_schema[pkt.size-sizeof(mysql_hdr)-1]=0;
									if (strcmp(_new_schema,userinfo_client.schemaname)) {
										l_free_string(userinfo_client.schemaname);
										userinfo_client.schemaname=_new_schema;
									} else {
										l_free_string(_new_schema);
									}
*/
									l_free(pkt.size,pkt.ptr);
									client_myds->DSS=STATE_QUERY_SENT;
									myprot_client.generate_pkt_OK(true,NULL,NULL,1,0,0,2,0,NULL);
									client_myds->DSS=STATE_SLEEP;
								} else {
									l_free(pkt.size,pkt.ptr);
									client_myds->DSS=STATE_QUERY_SENT;
									myprot_client.generate_pkt_OK(true,NULL,NULL,1,0,0,2,0,NULL);
									client_myds->DSS=STATE_SLEEP;
								}
								break;
							case _MYSQL_COM_FIELD_LIST:
								if (admin==false) {
									/* FIXME: temporary */
									l_free(pkt.size,pkt.ptr);
									client_myds->DSS=STATE_QUERY_SENT;
									myprot_client.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",(char *)"Command not supported");
									client_myds->DSS=STATE_SLEEP;
								} else {
									l_free(pkt.size,pkt.ptr);
									client_myds->DSS=STATE_QUERY_SENT;
									myprot_client.generate_pkt_ERR(true,NULL,NULL,1,1045,(char *)"#28000",(char *)"Command not supported");
									client_myds->DSS=STATE_SLEEP;
								}
								break;
//							case _MYSQL_COM_QUIT:
//								l_free(pkt.size,pkt.ptr);
//								healthy=0;
//								break;
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
/*
	if (client_myds) {
		//for (j=0; j<client_myds->PSarrayIN->len; j++) {
		for (j=0; j<client_myds->PSarrayIN->len;) {
			client_myds->PSarrayIN->remove_index(0,&pkt);
			if (server_myds) {
				server_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
			} else {
				l_free(pkt.size,pkt.ptr);
			}
		}
	}
*/

	//assert(server_myds);
	if (client_myds->DSS==STATE_QUERY_SENT)
		if (server_myds->DSS==STATE_NOT_INITIALIZED) {
/*
								if (server_myds==NULL) {
									//printf("Create new MYDS\n");
									server_myds = new MySQL_Data_Stream();
									server_myds->myconn = new MySQL_Connection(); // 20141011
*/
          				int pending_connect=1;
									unsigned long long curtime=monotonic_time();
									int rc=server_myds->assign_mshge(1);

									//mybe=find_backend(1);
//									mybe=find_or_create_backend(1,server_myds);
						assert(server_myds);
						assert(server_myds->myconn);
						assert(server_myds->myconn->mshge);
						assert(server_myds->myconn->mshge->MSptr);
	      					server_fd=server_myds->myds_connect(server_myds->myconn->mshge->MSptr->address, server_myds->myconn->mshge->MSptr->port, &pending_connect);
        //  				server_fd=server_myds->myds_connect((char *)"127.0.0.1", 3306, &pending_connect);
									server_myds->init((pending_connect==1 ? MYDS_BACKEND_NOT_CONNECTED : MYDS_BACKEND), this, server_fd);
									//thread->mypolls.add(POLLIN|POLLOUT, server_fd, server_myds, pending_connect==1 ? 0 : curtime);
									thread->mypolls.add(POLLIN|POLLOUT, server_fd, server_myds, curtime);
									status=CONNECTING_SERVER;
									server_myds->DSS=STATE_NOT_CONNECTED;
									//server_myds->PSarrayOUTpending->add(pkt.ptr, pkt.size);
              unsigned int k;
              PtrSize_t pkt2;
              for (k=0; k<server_myds->PSarrayOUT->len;) {
                server_myds->PSarrayOUT->remove_index(0,&pkt2);
                server_myds->PSarrayOUTpending->add(pkt2.ptr, pkt2.size);
              }

								} else {
									if (server_myds->myds_type==MYDS_BACKEND && server_myds->DSS==STATE_READY) {
									if (strcmp(userinfo_client.schemaname,userinfo_server.schemaname)==0) {
										//server_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
										server_myds->DSS=STATE_QUERY_SENT;
										status=WAITING_SERVER_DATA;
									} else {
              unsigned int k;
              PtrSize_t pkt2;
              for (k=0; k<server_myds->PSarrayOUT->len;) {
                server_myds->PSarrayOUT->remove_index(0,&pkt2);
                server_myds->PSarrayOUTpending->add(pkt2.ptr, pkt2.size);
              }
										userinfo_server.set_schemaname(userinfo_client.schemaname,strlen(userinfo_client.schemaname));
										//server_myds->PSarrayOUTpending->add(pkt.ptr, pkt.size);
										myprot_server.generate_COM_INIT_DB(true,NULL,NULL,userinfo_server.schemaname);
										server_myds->DSS=STATE_QUERY_SENT;
										status=CHANGING_SCHEMA;
									}
									}
								}
//
		

//	}

	if (server_myds) {
		for (j=0; j<server_myds->PSarrayIN->len;) {
			server_myds->PSarrayIN->remove_index(0,&pkt);

/*
			if (client_myds) {
				client_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
			} else {
				l_free(pkt.size,pkt.ptr);
			}
*/
		switch (status) {
			case CONNECTING_SERVER:

				switch (server_myds->DSS) {
					case STATE_NOT_CONNECTED:
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: CONNECTING_SERVER - STATE_NOT_CONNECTED\n");
						if (myprot_server.process_pkt_initial_handshake((unsigned char *)pkt.ptr,pkt.size)==true) {
							l_free(pkt.size,pkt.ptr);
							//myprot_server.generate_pkt_handshake_response(server_myds,true,NULL,NULL);
							myprot_server.generate_pkt_handshake_response(true,NULL,NULL);
							////status=WAITING_CLIENT_DATA;
							server_myds->DSS=STATE_CLIENT_HANDSHAKE;
						} else {
							l_free(pkt.size,pkt.ptr);	
						}
						break;
					case STATE_CLIENT_HANDSHAKE:
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: CONNECTING_SERVER - STATE_CLIENT_HANDSHAKE\n");
						if (myprot_server.process_pkt_OK((unsigned char *)pkt.ptr,pkt.size)==true) {
							l_free(pkt.size,pkt.ptr);
							server_myds->DSS=STATE_READY;
							mybe->myconn=server_myds->myconn;
							status=WAITING_SERVER_DATA;
							unsigned int k;
							PtrSize_t pkt2;
							for (k=0; k<server_myds->PSarrayOUTpending->len;) {
								server_myds->PSarrayOUTpending->remove_index(0,&pkt2);
								server_myds->PSarrayOUT->add(pkt2.ptr, pkt2.size);
								server_myds->DSS=STATE_QUERY_SENT;
							}
						} else {
							l_free(pkt.size,pkt.ptr);	
						}
						break;
					default:
						assert(0);

				}
				break;

			case WAITING_SERVER_DATA:

				switch (server_myds->DSS) {
					case STATE_QUERY_SENT:
						proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: WAITING_SERVER_DATA - STATE_QUERY_SENT\n");
						//unsigned char c;
						c=*((unsigned char *)pkt.ptr+sizeof(mysql_hdr));
						if (c==0 || c==0xff) {
							server_myds->DSS=STATE_READY;
							status=WAITING_CLIENT_DATA;
							client_myds->DSS=STATE_SLEEP;
							client_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
						} else {
							// this should be a result set
							if (qpo && qpo->cache_ttl>0) {
								server_myds->resultset->add(pkt.ptr, pkt.size);
								server_myds->resultset_length+=pkt.size;
							} else {
								client_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
							}
							server_myds->DSS=STATE_ROW;	// FIXME: this is catch all for now
						}
						break;

					case STATE_ROW:
						c=*((unsigned char *)pkt.ptr+sizeof(mysql_hdr));
						if (c==0xfe && pkt.size < 13) {
							server_myds->DSS=STATE_EOF1;
						}
						if (qpo && qpo->cache_ttl>0) {
							server_myds->resultset->add(pkt.ptr, pkt.size);
							server_myds->resultset_length+=pkt.size;
						} else {
							client_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
						}
						break;

					case STATE_EOF1:
						//unsigned char c;
						c=*((unsigned char *)pkt.ptr+sizeof(mysql_hdr));
						if (qpo && qpo->cache_ttl>0) {
							server_myds->resultset->add(pkt.ptr, pkt.size);
							server_myds->resultset_length+=pkt.size;
						} else {
							client_myds->PSarrayOUT->add(pkt.ptr, pkt.size);
						}
						if ((c==0xfe && pkt.size < 13) || c==0xff) {
							server_myds->DSS=STATE_READY;
							status=WAITING_CLIENT_DATA;
							client_myds->DSS=STATE_SLEEP;
							if (qpo) {
								GloQPro->delete_QP_out(qpo);
								qpo=NULL;
								client_myds->PSarrayOUT->copy_add(server_myds->resultset,0,server_myds->resultset->len);
								unsigned char *aa=server_myds->resultset2buffer(false);
								while (server_myds->resultset->len) server_myds->resultset->remove_index(server_myds->resultset->len-1,NULL);	
								GloQC->set((unsigned char *)client_myds->query_SQL,strlen((char *)client_myds->query_SQL)+1,aa,server_myds->resultset_length,30);
								l_free(server_myds->resultset_length,aa);
								server_myds->resultset_length=0;
								l_free(strlen((char *)client_myds->query_SQL)+1,client_myds->query_SQL);
							}
						}
						break;

					default:
						assert(0);
				}
				break;

			case CHANGING_SCHEMA:
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Statuses: CHANGING_SCHEMA - UNKNWON\n");
				if (myprot_server.process_pkt_OK((unsigned char *)pkt.ptr,pkt.size)==true) {
					l_free(pkt.size,pkt.ptr);
					server_myds->DSS=STATE_READY;
					mybe->myconn=server_myds->myconn;
					status=WAITING_SERVER_DATA;
					unsigned int k;
					PtrSize_t pkt2;
					for (k=0; k<server_myds->PSarrayOUTpending->len;) {
						server_myds->PSarrayOUTpending->remove_index(0,&pkt2);
						server_myds->PSarrayOUT->add(pkt2.ptr, pkt2.size);
						server_myds->DSS=STATE_QUERY_SENT;
					}
				} else {
					l_free(pkt.size,pkt.ptr);	
				}
				break;

			default:
				assert(0);
		}

		}
	}

/*
	if (client_myds) client_myds->array2buffer_full();
	if (server_myds) server_myds->array2buffer_full();

	if (client_myds) client_myds->write_to_net();
	if (server_myds) server_myds->write_to_net();
*/
	writeout();
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
	return 0;
}
