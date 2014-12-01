#include "proxysql.h"

static int mysql_session_default_hostgroup(mysql_session_t *sess) {
	//sess->default_hostgroup=-1;
	pthread_rwlock_rdlock(&gloDefHG.rwlock);
	sess->default_hostgroup_version=gloDefHG.version;
	sess->default_hostgroup=gloDefHG.find_defHG(&gloDefHG,(const unsigned char *)sess->mysql_username,(const unsigned char *)sess->mysql_schema_cur);
	pthread_rwlock_unlock(&gloDefHG.rwlock);
	return 0;
}

static void queue_back_client_pkt(mysql_session_t *sess, pkt *p) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 4, "No available backend, queuing back client packet\n");
	LPtrArray *new_input_pkts=l_ptr_array_sized_new(sess->client_myds->input.pkts->len);
	l_ptr_array_add(new_input_pkts,p);
	while(sess->client_myds->input.pkts->len) {
		pkt *pn=l_ptr_array_remove_index(sess->client_myds->input.pkts, 0);
		l_ptr_array_add(new_input_pkts,pn);
	}
	while(new_input_pkts->len) {
		pkt *pn=l_ptr_array_remove_index(new_input_pkts, 0);
		l_ptr_array_add(sess->client_myds->input.pkts,pn);
	}
	l_ptr_array_free1(new_input_pkts);
}


static void sync_server_bytes_at_cmd(mysql_session_t *sess) {
	if (sess->server_mybe && sess->server_mybe->server_myds) {
		PROXY_TRACE();
		proxy_debug(PROXY_DEBUG_NET, 7, "Syncing server_bytes_at_cmd: OK\n");
		sess->server_bytes_at_cmd.bytes_sent=sess->server_mybe->server_myds->bytes_info.bytes_sent;
		sess->server_bytes_at_cmd.bytes_recv=sess->server_mybe->server_myds->bytes_info.bytes_recv;
	} else {
		PROXY_TRACE();
		proxy_debug(PROXY_DEBUG_NET, 7, "Syncing server_bytes_at_cmd to zero\n");
		sess->server_bytes_at_cmd.bytes_sent=0;
		sess->server_bytes_at_cmd.bytes_recv=0;	
	}
}

static inline void compute_query_checksum(mysql_session_t *sess) {
	PROXY_TRACE();
	if (sess->query_info.query_checksum==NULL) {
		proxy_debug(PROXY_DEBUG_QUERY_CACHE, 7, "Checksum query on session %p\n", sess);
		sess->query_info.query_checksum=g_checksum_new(G_CHECKSUM_MD5);
		g_checksum_update(sess->query_info.query_checksum, (const unsigned char *)sess->query_info.query, sess->query_info.query_len);
		g_checksum_update(sess->query_info.query_checksum, (const unsigned char *)sess->mysql_username, strlen(sess->mysql_username));
		g_checksum_update(sess->query_info.query_checksum, (const unsigned char *)sess->mysql_schema_cur, strlen(sess->mysql_schema_cur));
	}
}



static int get_result_from_mysql_query_cache(mysql_session_t *sess, pkt *p) {
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	compute_query_checksum(sess);
	pkt *QCresult=NULL;
	QCresult=fdb_get(&QC, g_checksum_get_string(sess->query_info.query_checksum), sess);
	proxy_debug(PROXY_DEBUG_QUERY_CACHE, 4, "Called GET on QC for checksum %s in precheck\n", g_checksum_get_string(sess->query_info.query_checksum));
	if (QCresult) {
		proxy_debug(PROXY_DEBUG_QUERY_CACHE, 4, "Found QC entry for checksum %s in precheck\n", g_checksum_get_string(sess->query_info.query_checksum));
		MY_SESS_ADD_PKT_OUT_CLIENT(QCresult);
		//l_ptr_array_add(sess->client_myds->output.pkts, QCresult);
		sess->mysql_query_cache_hit=TRUE;
		sess->query_to_cache=FALSE;	// query already in cache
		mypkt_free1(p);
		if (glovars.mysql_query_statistics) {
			query_statistics_set(sess);
		}
		return 0;
	}
	PROXY_TRACE();
	return -1;
}



static inline void server_COM_QUIT(mysql_session_t *sess, pkt *p, enum MySQL_response_type r) {
	if (r==OK_Packet) {
		proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got OK on COM_QUIT\n");
		MY_SESS_ADD_PKT_OUT_CLIENT(p);
		//l_ptr_array_add(sess->client_myds->output.pkts, p);
	}
}
static inline void server_COM_STATISTICS(mysql_session_t *sess, pkt *p) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got packet on COM_STATISTICS\n");
	MY_SESS_ADD_PKT_OUT_CLIENT(p);
	//l_ptr_array_add(sess->client_myds->output.pkts, p);
	// sync for auto-reconnect
	sync_server_bytes_at_cmd(sess);
}

static inline void server_COM_INIT_DB(mysql_session_t *sess, pkt *p, enum MySQL_response_type r) {
	if (sess->server_mybe) {
		sess->server_mybe->last_mysql_connpool=NULL;
	}
	if (r==OK_Packet) {
		proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got OK on COM_INIT_DB for schema %s\n", sess->mysql_schema_new);
		if (sess->mysql_schema_cur) {
			g_free(sess->mysql_schema_cur);
			sess->mysql_schema_cur=g_strdup(sess->mysql_schema_new);
		}
		sess->mysql_schema_cur=g_strdup(sess->mysql_schema_new);
		MY_SESS_ADD_PKT_OUT_CLIENT(p);
		//l_ptr_array_add(sess->client_myds->output.pkts, p);
	}
	if (r==ERR_Packet) {
		proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got ERR on COM_INIT_DB for schema %s\n", sess->mysql_schema_new);
		MY_SESS_ADD_PKT_OUT_CLIENT(p);
		//l_ptr_array_add(sess->client_myds->output.pkts, p);
	}
	if (sess->mysql_schema_new) {
		PROXY_TRACE();
		g_free(sess->mysql_schema_new);
		sess->mysql_schema_new=NULL;
	}
	// sync for auto-reconnect
	sync_server_bytes_at_cmd(sess);
}


static inline void server_COM_QUERY(mysql_session_t *sess, pkt *p, enum MySQL_response_type r) {
	int i;
	if (r==OK_Packet) {
		PROXY_TRACE();
						// NOTE: we could receive a ROW packet that looks like an OK Packet. Do extra checks!
						if (sess->resultset_progress==RESULTSET_WAITING) {
			PROXY_TRACE();
							// this is really an OK Packet
							sess->resultset_progress=RESULTSET_COMPLETED;
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got OK on COM_QUERY\n");
							for (i=0; i<glovars.mysql_hostgroups; i++) {
								mysql_backend_t *mybe=l_ptr_array_index(sess->mybes,i);
								//    mybe->reset(mybe, sess->force_close_backends);  // commented for multiplexing
								if (ACTIVE_TRANSACTION(sess)==0) {
									if (glovars.mysql_share_connections==1) {
										mybe->bedetach(mybe, &mybe->last_mysql_connpool, 0);
									}
								}
								//glomybepools.detach(mybe, i, sess->force_close_backends);
								//sess->server_mybe=NULL;
							}
							sess->nfds=1;
						} else {
							// this is a ROW packet
		PROXY_TRACE();
							 sess->resultset_progress=RESULTSET_ROWS;
						}
					}
					if (r==ERR_Packet) {
						sess->resultset_progress=RESULTSET_COMPLETED;
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got ERR on COM_QUERY\n");
							//for (i=0; i<glovars.mysql_hostgroups; i++) {
							//	mysql_backend_t *mybe=l_ptr_array_index(sess->mybes,i);
								//    mybe->reset(mybe, sess->force_close_backends);  // commented for multiplexing
								//if (ACTIVE_TRANSACTION(sess)==0) {
								//	mybe->bedetach(mybe, &sess->last_mysql_connpool, 0);
								//}
								//glomybepools.detach(mybe, i, sess->force_close_backends);
								//sess->server_mybe=NULL;
							//}
							sess->nfds=1;
					}
					if (r==EOF_Packet) {
						if (sess->resultset_progress==RESULTSET_COLUMN_DEFINITIONS) {
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 6, "Got 1st EOF on COM_QUERY\n");
							sess->resultset_progress=RESULTSET_EOF1;
						} else {
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 6, "Got 2nd EOF on COM_QUERY\n");
							sess->resultset_progress=RESULTSET_COMPLETED;
							for (i=0; i<glovars.mysql_hostgroups; i++) {
								mysql_backend_t *mybe=l_ptr_array_index(sess->mybes,i);
								//    mybe->reset(mybe, sess->force_close_backends);  // commented for multiplexing
								if (ACTIVE_TRANSACTION(sess)==0) {
									if (glovars.mysql_share_connections==1) {
										mybe->bedetach(mybe, &mybe->last_mysql_connpool, 0);
									}
								}
								//glomybepools.detach(mybe, i, sess->force_close_backends);
								//sess->server_mybe=NULL;
							}
							sess->nfds=1;
						}
					}
					if (r==UNKNOWN_Packet) {
						switch (sess->resultset_progress) {
							case RESULTSET_WAITING:
								proxy_debug(PROXY_DEBUG_MYSQL_COM, 6, "Got column count on COM_QUERY\n");
								sess->resultset_progress=RESULTSET_COLUMN_COUNT;
								break;
							case RESULTSET_COLUMN_COUNT:
							case RESULTSET_COLUMN_DEFINITIONS:
								proxy_debug(PROXY_DEBUG_MYSQL_COM, 6, "Got column def on COM_QUERY\n");
								sess->resultset_progress=RESULTSET_COLUMN_DEFINITIONS;
								break;
							case RESULTSET_EOF1:
							case RESULTSET_ROWS:
									proxy_debug(PROXY_DEBUG_MYSQL_COM, 7, "Got row on COM_QUERY\n");
								sess->resultset_progress=RESULTSET_ROWS;
								break;
							case RESULTSET_COMPLETED:
								break;
						}
					}
					//g_ptr_array_add(conn->client_myds->output.pkts, p);
					sess->resultset_size+=p->length;
					if (sess->resultset_size < glovars.mysql_max_resultset_size ) { // the resultset is within limit, copy to sess->resultset
		PROXY_TRACE();
						l_ptr_array_add(sess->resultset, p);
					} else { // the resultset went above limit
		PROXY_TRACE();
						sess->query_to_cache=FALSE; // the query cannot be cached, as we are not saving the result
						while(sess->resultset->len) {	 // flush the resultset
							pkt *pt;
							pt=l_ptr_array_remove_index(sess->resultset, 0);
							MY_SESS_ADD_PKT_OUT_CLIENT(pt);
						}
						MY_SESS_ADD_PKT_OUT_CLIENT(p);
						//l_ptr_array_add(sess->client_myds->output.pkts, p); // copy the new packet directly into the output queue

					}
					if (sess->resultset_progress==RESULTSET_COMPLETED) {
		PROXY_TRACE();
						sess->resultset_progress=RESULTSET_WAITING;
						if (glovars.mysql_query_statistics) {
							query_statistics_set(sess);
						}
						// we have processed a complete result set, sync sess->server_bytes_at_cmd for auto-reconnect
						sync_server_bytes_at_cmd(sess);


						if (sess->send_to_slave==TRUE) {
		PROXY_TRACE();
							sess->send_to_slave=FALSE;
						}

//						conn->status &= ~CONNECTION_READING_SERVER;
						if (sess->query_to_cache==TRUE) {
							proxy_debug(PROXY_DEBUG_QUERY_CACHE, 4, "Query %s needs to be cached\n", g_checksum_get_string(sess->query_info.query_checksum));
							proxy_debug(PROXY_DEBUG_QUERY_CACHE, 4, "Resultset size = %d\n", sess->resultset_size);
							// prepare the entry to enter in the query cache
							int kl=strlen(g_checksum_get_string(sess->query_info.query_checksum));
							if ((kl+sess->resultset_size+sizeof(fdb_hash_entry)+sizeof(fdb_hash_entry *)) > fdb_hashes_group_free_mem(&QC)) {
								// there is no free memory
										__sync_fetch_and_add(&QC.cntSetERR,1);
								proxy_debug(PROXY_DEBUG_QUERY_CACHE, 4, "Query %s not cached because the QC is full\n", g_checksum_get_string(sess->query_info.query_checksum));
							} else {
		PROXY_TRACE();
								void *kp=g_strdup(g_checksum_get_string(sess->query_info.query_checksum));
								//void *kp=NULL;
								//int l=g_checksum_type_get_length(G_CHECKSUM_MD5);
								//kp=g_slice_alloc(l);
								//memcpy(kp,g_checksum_get_string(sess->query_info.query_checksum),l);
								void *vp=g_malloc(sess->resultset_size);
								//void *vp=g_slice_alloc(conn->resultset_size);
								size_t copied=0;
								for (i=0; i<sess->resultset->len; i++) {
									p=l_ptr_array_index(sess->resultset,i);
									memcpy(vp+copied,p->data,p->length);
									copied+=p->length;
								}
								// insert in the query cache
								proxy_debug(PROXY_DEBUG_QUERY_CACHE, 4, "Calling SET on QC , checksum %s, kl %d, vl %d\n", (char *)kp, kl, sess->resultset_size);
								fdb_set(&QC, kp, kl, vp, sess->resultset_size, sess->query_info.cache_ttl, FALSE);
								//g_free(kp);
								//g_free(vp);
							}
						}

						if (sess->resultset_size < glovars.mysql_max_resultset_size ) {
						// copy the query in the output queue
						// this happens only it wasn't flushed already
		PROXY_TRACE();
							for (i=0; i<sess->resultset->len; i++) {
								p=l_ptr_array_index(sess->resultset,i);
								MY_SESS_ADD_PKT_OUT_CLIENT(p);
								//l_ptr_array_add(sess->client_myds->output.pkts, p);
							}
							while (sess->resultset->len) {
								p=l_ptr_array_remove_index(sess->resultset, sess->resultset->len-1);
							}
							//if (glovars.mysql_query_statistics) {
							//	query_statistics_set(sess);
							//}
						} else {
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 4, "Query %s was too large ( %d bytes, min %d ) and wasn't stored\n", g_checksum_get_string(sess->query_info.query_checksum), sess->resultset_size , glovars.mysql_max_resultset_size );
						}
					}
}


static void process_server_pkts(mysql_session_t *sess) {
	pkt *p;
	//int i;
	if (sess->server_mybe==NULL || sess->server_mybe->server_myds==NULL) { // the backend is not initialized, return
		proxy_debug(PROXY_DEBUG_NET, 7, "No packets from server\n");
		return;
		}
	while(sess->server_mybe && sess->server_mybe->server_myds->input.pkts->len) {
		p=l_ptr_array_remove_index(sess->server_mybe->server_myds->input.pkts, 0);
		enum MySQL_response_type r=mysql_response(p);
		if (r==OK_Packet || r==EOF_Packet) {
			sess->server_mybe->server_myds->active_transaction=is_transaction_active(p);
			if (ACTIVE_TRANSACTION(sess)==1) {
				PROXY_TRACE();
			}
		}
		switch (sess->client_command) {
			case MYSQL_COM_QUIT:
				server_COM_QUIT(sess,p,r);
				break;
			case MYSQL_COM_INIT_DB:
				server_COM_INIT_DB(sess,p,r);
				break;
			case MYSQL_COM_STATISTICS:
				server_COM_STATISTICS(sess,p);
				break;
			case MYSQL_COM_QUERY:
				server_COM_QUERY(sess,p,r);
				break;
			default:
				MY_SESS_ADD_PKT_OUT_CLIENT(p);
				//l_ptr_array_add(sess->client_myds->output.pkts, p);
		}
	}
}



static void conn_poll(mysql_session_t *sess) {
	//int r;
	struct pollfd *fds=sess->fds;
	fds[0].events=0;
	if ((sess->status & CONNECTION_READING_CLIENT) == CONNECTION_READING_CLIENT) {
		PROXY_TRACE();
		queue_t *q=&sess->client_myds->input.queue;
		if (sess->client_myds->fd > 0 && queue_available(q)) {
			PROXY_TRACE();
			fds[0].events|=POLLIN;
		}
	}
	if ((sess->status & CONNECTION_WRITING_CLIENT) == CONNECTION_WRITING_CLIENT) {
		PROXY_TRACE();
		queue_t *q=&sess->client_myds->output.queue;
		if (sess->client_myds->fd > 0 && ( queue_data(q) || sess->client_myds->output.partial || sess->client_myds->output.pkts->len ) ) {
			PROXY_TRACE();
			fds[0].events|=POLLOUT;
		}
	}
	if (sess->nfds>1) {
		fds[1].events=0;
		if ((sess->status & CONNECTION_READING_SERVER) == CONNECTION_READING_SERVER) {
			queue_t *q=&sess->server_mybe->server_myds->input.queue;
			if (sess->server_mybe->server_myds->fd > 0 && queue_available(q)) {
				PROXY_TRACE();
				fds[1].events|=POLLIN;
			}
		}
		if ((sess->status & CONNECTION_WRITING_SERVER) == CONNECTION_WRITING_SERVER) {
			queue_t *q=&sess->server_mybe->server_myds->output.queue;
			if (sess->server_mybe->server_myds->fd > 0 && ( queue_data(q) || sess->server_mybe->server_myds->output.partial || sess->server_mybe->server_myds->output.pkts->len ) ) {
		PROXY_TRACE();
				fds[1].events|=POLLOUT;
			}
		}
	}
	if (sess->nfds==1) {
		proxy_debug(PROXY_DEBUG_POLL, 4, "setting poll: fd %d events %d\n", sess->fds[0].fd , sess->fds[0].events);
	} else {
		proxy_debug(PROXY_DEBUG_POLL, 4, "setting poll: fd %d events %d , fd %d events %d\n" , sess->fds[0].fd , sess->fds[0].events, sess->fds[1].fd , sess->fds[1].events);
	}
//	r=poll(fds,sess->nfds,glovars.mysql_poll_timeout);
	//return r;
}

static void read_from_net_2(mysql_session_t *sess) {
	// read_from_net for both sockets
	if ((sess->client_myds->fd > 0) && ((sess->fds[0].revents & POLLIN) == POLLIN)) {
		proxy_debug(PROXY_DEBUG_NET, 4, "Calling read_from_net for client\n");
		mysql_data_stream_t *myds=sess->client_myds;
		myds->read_from_net(myds);
	}
	if (
		(sess->server_mybe && sess->server_mybe->server_myds) && // the backend is initialized
		(sess->server_mybe->server_myds->fd > 0) &&
		(sess->server_mybe->server_mycpe) &&
		((sess->fds[1].revents & POLLIN) == POLLIN)) {
		proxy_debug(PROXY_DEBUG_NET, 4, "Calling read_from_net for server\n");
		mysql_data_stream_t *myds=sess->server_mybe->server_myds;
		myds->read_from_net(myds);
		//sess->server_mybe->server_myds->read_from_net(sess->server_mybe->server_myds);
	}
}

static void write_to_net_2(mysql_session_t *sess, int ignore_revents) {
	// write_to_net for both sockets
	if ((sess->client_myds->fd > 0) && ( ignore_revents || ((sess->fds[0].revents & POLLOUT) == POLLOUT) ) ) {
		proxy_debug(PROXY_DEBUG_NET, 4, "Calling write_to_net for client\n");
		sess->client_myds->write_to_net(sess->client_myds);
			// if I wrote everything to client, start reading from client
//			if ((queue_data(&conn->client_myds->output.queue)==0) && (conn->client_myds->output.pkts->len==0)) {
//				conn->status |= CONNECTION_READING_CLIENT;	
//			}
	}

	if (
		(sess->server_mybe) && (sess->server_mybe->server_myds) && // the backend is initialized
		(sess->server_mybe->server_myds->fd > 0)
		&& ( ignore_revents || ((sess->fds[1].revents & POLLOUT) == POLLOUT) ) ) {
		proxy_debug(PROXY_DEBUG_NET, 4, "Calling write_to_net for server\n");
		sess->server_mybe->server_myds->write_to_net(sess->server_mybe->server_myds);
			// if I wrote everything to server, start reading from server
//			if ((queue_data(&conn->server_myds->output.queue)==0) && (conn->server_myds->output.pkts->len==0)) {
//				conn->status |= CONNECTION_READING_SERVER;	
//			}
	}
}


static void buffer2array_2(mysql_session_t *sess) {
// buffer2array for both connections
	proxy_debug(PROXY_DEBUG_PKT_ARRAY, 6, "Calling buffer2array for client\n");
	while(sess->client_myds->buffer2array(sess->client_myds) && (sess->client_myds->fd > 0) ) { PROXY_TRACE(); }

	if (sess->server_mybe && sess->server_mybe->server_myds) { // the backend is initialized
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 6, "Calling buffer2array for server\n");
		while(sess->server_mybe->server_myds->buffer2array(sess->server_mybe->server_myds) && (sess->server_mybe->server_myds->fd > 0)) { PROXY_TRACE(); }
	}
}


static void array2buffer_2(mysql_session_t *sess) {
	proxy_debug(PROXY_DEBUG_PKT_ARRAY, 6, "Calling array2buffer for client\n");
	while(sess->client_myds->array2buffer(sess->client_myds)) { PROXY_TRACE(); }

	if (sess->server_mybe && sess->server_mybe->server_myds) { // the backend is initialized
		proxy_debug(PROXY_DEBUG_PKT_ARRAY, 6, "Calling array2buffer for server\n");
		while(sess->server_mybe->server_myds->array2buffer(sess->server_mybe->server_myds)) { PROXY_TRACE(); }
	}
}


static void check_fds_errors(mysql_session_t *sess) {
	if ( ((sess->fds[0].revents & POLLERR)==POLLERR) || ((sess->fds[0].revents & POLLHUP)==POLLHUP) || ((sess->fds[0].revents & POLLNVAL)==POLLNVAL) ) {
		proxy_debug(PROXY_DEBUG_NET, 4, "Detected error on client connection fd %d . events=%d , revents=%d\n", sess->fds[0].fd, sess->fds[0].events, sess->fds[0].revents);
		sess->client_myds->shut_soft(sess->client_myds);
	}
	if (sess->server_mybe && sess->server_mybe->server_myds) { // the backend is initialized
		PROXY_TRACE();
		if ( ((sess->fds[1].revents & POLLERR)==POLLERR) || ((sess->fds[1].revents & POLLHUP)==POLLHUP) || ((sess->fds[1].revents & POLLNVAL)==POLLNVAL) ) { 
			proxy_debug(PROXY_DEBUG_NET, 4, "Detected error on server connection fd %d . events=%d , revents=%d\n", sess->fds[1].fd, sess->fds[1].events, sess->fds[1].revents);
			sess->server_mybe->server_myds->shut_soft(sess->server_mybe->server_myds);
		}
	}
}


static gboolean sync_net(mysql_session_t *sess, int write_only) {
	if (write_only==0) {
		proxy_debug(PROXY_DEBUG_NET, 7, "calling read_from_net_2()\n");
		read_from_net_2(sess);
		if (sess->net_failure) {
			PROXY_TRACE();
			if (reconnect_server_on_shut_fd(sess)==FALSE) {
				PROXY_TRACE();
				return FALSE;
			}
		}
	}
	proxy_debug(PROXY_DEBUG_NET, 7, "calling write_net_2()\n");
	write_to_net_2(sess, write_only);
	if (sess->net_failure) {
		PROXY_TRACE();
		if (reconnect_server_on_shut_fd(sess)==FALSE) {
			proxy_debug(PROXY_DEBUG_NET, 3, "shutdown on failure from reconnect_server_on_shut_fd\n");
			return FALSE;
		}
	}
	PROXY_TRACE();
	return TRUE;
}


static inline void client_COM_QUIT(mysql_session_t *sess) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_QUIT packet\n");
}

static inline void client_COM_STATISTICS(mysql_session_t *sess) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_STATISTICS packet\n");
	if (sess->admin>0) {
	// we shouldn't forward this if we are in admin mode
		PROXY_TRACE();
		sess->healthy=0;
		return;
	}
}


static inline void client_COM_CHANGE_USER(mysql_session_t *sess, pkt *p) {
	if (sess->admin>0) {
	// we shouldn't forward this if we are in admin mode
		PROXY_TRACE();
		sess->healthy=0;
		return;
	}
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_CHANGE_USER packet\n");
	sess->mysql_query_cache_hit=TRUE;
	l_free(p->length, p->data);
	parse_change_user_packet(p,sess);
	create_auth_switch_request_packet(p, sess);
	sess->waiting_change_user_response=1;
	MY_SESS_ADD_PKT_OUT_CLIENT(p);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Resetting default_hostgroup from %d to -1 in session %p\n", sess->default_hostgroup, sess);
	sess->default_hostgroup=-1;
	//sess->last_mysql_connpool=NULL;
	if ( (sess->server_mybe) && (sess->server_mybe->server_mycpe) &&
		(sess->server_mybe->mshge) && (sess->server_mybe->mshge->MSptr) &&
		(sess->server_mybe->server_myds) && (sess->server_mybe->server_myds->fd)) {
			proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Disconnecting backend for hostgroup 0 : %p\n", sess->server_mybe);
			sess->server_mybe->last_mysql_connpool=NULL;
			sess->server_mybe->bereset(sess->server_mybe, &sess->server_mybe->last_mysql_connpool, 0);
	}
	PROXY_TRACE();
	int j;
	// start from 1, don't reset hostgroup 0
	for (j=0; j<glovars.mysql_hostgroups; j++) {
		proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Disconnecting backend for hostgroup %d : %p\n", j, sess->server_mybe);
		mysql_backend_t *mybe=l_ptr_array_index(sess->mybes,j);
		mybe->last_mysql_connpool=NULL;
		mybe->bereset(mybe, &mybe->last_mysql_connpool, 0);
	}
	sess->server_mybe=NULL;
}

static inline void client_COM_INIT_DB(mysql_session_t *sess, pkt *p) {
	if (sess->admin>0) {
	// we shouldn't forward this if we are in admin mode
		PROXY_TRACE();
		sess->healthy=0;
		return;
	}
	sess->mysql_schema_new=g_malloc0(p->length-sizeof(mysql_hdr));
	memcpy(sess->mysql_schema_new, p->data+sizeof(mysql_hdr)+1, p->length-sizeof(mysql_hdr)-1);
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_INIT_DB packet for schema %s\n", sess->mysql_schema_new);
	if ((sess->mysql_schema_cur) && (strcmp(sess->mysql_schema_new, sess->mysql_schema_cur)==0)) {
		// already on target schema, don't forward
		PROXY_TRACE();
		proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Old schemaname (%s) and new schemaname (%s) are identical: no action needed\n", sess->mysql_schema_cur, sess->mysql_schema_new);
		sess->mysql_query_cache_hit=TRUE;
		// destroy the client's packet
		//g_slice_free1(p->length, p->data);
		//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
		//l_free(thrLD->sfp,p->length, p->data);
		l_free(p->length, p->data);
		//--- g_slice_free1(sizeof(pkt), p);
		// create OK packet ...
		create_ok_packet(p,1);
		// .. end send it to client
		MY_SESS_ADD_PKT_OUT_CLIENT(p);
		//l_ptr_array_add(sess->client_myds->output.pkts, p);
		// reset conn->mysql_schema_new 
		g_free(sess->mysql_schema_new);
		sess->mysql_schema_new=NULL;
	} else {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Resetting default_hostgroup from %d to -1 in session %p\n", sess->default_hostgroup, sess);
		sess->default_hostgroup=-1;
		proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Old schemaname (%s) and new schemaname (%s) are NOT identical: resetting\n", sess->mysql_schema_cur, sess->mysql_schema_new);
		//sess->last_mysql_connpool=NULL;
		if ( (sess->server_mybe) && (sess->server_mybe->server_mycpe) &&
			(sess->server_mybe->mshge) && (sess->server_mybe->mshge->MSptr) &&
			(sess->server_mybe->server_myds) && (sess->server_mybe->server_myds->fd)) {
				proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Disconnecting backend for hostgroup 0 : %p\n", sess->server_mybe);
				sess->server_mybe->last_mysql_connpool=NULL;
				sess->server_mybe->bereset(sess->server_mybe, &sess->server_mybe->last_mysql_connpool, 0);
		}
		PROXY_TRACE();
		int j;
		// start from 1, don't reset hostgroup 0
		for (j=0; j<glovars.mysql_hostgroups; j++) {
			proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Disconnecting backend for hostgroup %d : %p\n", j, sess->server_mybe);
			mysql_backend_t *mybe=l_ptr_array_index(sess->mybes,j);
			mybe->last_mysql_connpool=NULL;
			mybe->bereset(mybe, &mybe->last_mysql_connpool, 0);
		}
		sess->server_mybe=NULL;
		PROXY_TRACE();
		sess->mysql_query_cache_hit=TRUE;
		l_free(p->length, p->data);
		create_ok_packet(p,1);
		MY_SESS_ADD_PKT_OUT_CLIENT(p);
		proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Swapping old schemaname (%s) with new schemaname (%s)\n", sess->mysql_schema_cur, sess->mysql_schema_new);
		g_free(sess->mysql_schema_cur);
		sess->mysql_schema_cur=g_strdup(sess->mysql_schema_new);
		g_free(sess->mysql_schema_new);
		sess->mysql_schema_new=NULL;
/*
		if ( (sess->server_mybe) && (sess->server_mybe->server_mycpe) &&
				(sess->server_mybe->mshge) && (sess->server_mybe->mshge->MSptr) &&
				(sess->server_mybe->server_myds) && (sess->server_mybe->server_myds->fd) &&
				(sess->server_mybe->server_myds->active_transaction==0)) {
			if (mysql_connpool_exists_global(sess->server_mybe->mshge->MSptr->address, sess->mysql_username, sess->mysql_password, sess->mysql_schema_new, sess->server_mybe->mshge->MSptr->port)) {
				// the combination of username/password/schema/host/port esists
				PROXY_TRACE();
				sess->mysql_query_cache_hit=TRUE;
				l_free(p->length, p->data);
				create_ok_packet(p,1);
				MY_SESS_ADD_PKT_OUT_CLIENT(p);
				g_free(sess->mysql_schema_new);
				sess->mysql_schema_new=NULL;
				sess->last_mysql_connpool=NULL;
				sess->server_mybe->bereset(sess->server_mybe, &sess->last_mysql_connpool, 0);
			}
		} else {
			PROXY_TRACE();
			int j;
			// start from 1, don't reset hostgroup 0
			for (j=1; j<glovars.mysql_hostgroups; j++) {
				mysql_backend_t *mybe=l_ptr_array_index(sess->mybes,j);
				mybe->bereset(mybe, &sess->last_mysql_connpool, 0);
			}
		}
*/
	}
}

static inline void client_COM_QUERY(mysql_session_t *sess, pkt *p) {
	if (mysql_pkt_get_size(p) > glovars.mysql_max_query_size) {
		// the packet is too big. Ignore any processing
		PROXY_TRACE();
		sess->client_command=MYSQL_COM_END;
	} else {
		PROXY_TRACE();
		init_query_metadata(sess, p);
		sess->resultset_progress=RESULTSET_WAITING;
		sess->resultset_size=0;

/*
if the query is cached:
	destroy the pkg
	get the packets from the cache and send it to the client
if the query is not cached, mark it as to be cached and modify the code on result set

*/
		if (glovars.mysql_query_cache_enabled && glovars.mysql_query_cache_precheck) {
			proxy_debug(PROXY_DEBUG_QUERY_CACHE, 7, "Trying to find the query from QC using precheck\n");
			if (get_result_from_mysql_query_cache(sess,p)==0) {
				proxy_debug(PROXY_DEBUG_QUERY_CACHE, 7, "Query successfully found in QC using precheck\n");
				return;
			} else {
				proxy_debug(PROXY_DEBUG_QUERY_CACHE, 7, "Query not found in QC using precheck\n");
			}
		}
		process_query_rules(sess);
		if (
			(sess->client_command==MYSQL_COM_QUERY) &&
			( sess->query_info.cache_ttl > 0 )
		) {
			sess->query_to_cache=TRUE;		// cache the query
			if (get_result_from_mysql_query_cache(sess,p)==0) {
			} else {
				proxy_debug(PROXY_DEBUG_QUERY_CACHE, 4, "Not found QC entry for checksum %s after query prepocessing\n", g_checksum_get_string(sess->query_info.query_checksum));

			}
		}
//					conn->status &= ~CONNECTION_READING_CLIENT; // NOTE: this is not true for packets >= 16MB , be careful
	}
}

static int active_backend_for_hostgroup(mysql_session_t *sess, int hostgroup_id) {
	assert(hostgroup_id < glovars.mysql_hostgroups);
	mysql_backend_t *mybe=l_ptr_array_index(sess->mybes,hostgroup_id);
	if (mybe->mshge && mybe->mshge->MSptr && mybe->server_mycpe) {
		// backend is active
		return 1;
	} else {
		// backend is NOT active
		return 0;
	}
}


static int process_client_pkts(mysql_session_t *sess) {
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Client packets queued: %d\n", sess->client_myds->input.pkts->len);
	while(sess->client_myds->input.pkts->len) {
		pkt *p;
		unsigned char c;
//			p=get_pkt(sess->client_myds->input.pkts);
		p=l_ptr_array_remove_index(sess->client_myds->input.pkts, 0);
		c=*((unsigned char *)p->data+sizeof(mysql_hdr));
		sess->client_command=c;	// a new packet is read from client, set the COM_
		sess->mysql_query_cache_hit=FALSE;
		sess->query_to_cache=FALSE;
		sess->send_to_slave=FALSE;
		if ( (sess->admin==0) && ( p->length < glovars.mysql_max_query_size ) ) {
			switch (sess->client_command) {
				case MYSQL_COM_INIT_DB:
				case MYSQL_COM_QUERY:
				case MYSQL_COM_STATISTICS:
					/* if (!transaction) */
					sess->mysql_server_reconnect=TRUE;
					break;
				default:
					sess->mysql_server_reconnect=FALSE;
					break;
			}
		} else {
			sess->mysql_server_reconnect=FALSE;
		}
		switch (sess->client_command) {
			case MYSQL_COM_QUIT:
				client_COM_QUIT(sess);
				mypkt_free1(p);
	//			mysql_session_close(sess);
				return -1;
				break;
			case MYSQL_COM_STATISTICS:
				client_COM_STATISTICS(sess);
				break;
			case MYSQL_COM_INIT_DB:
				client_COM_INIT_DB(sess, p);
				break;
			case MYSQL_COM_QUERY:
				//client_COM_QUERY(conn, p, regex1, regex2);
				if (sess->admin==0) {
					client_COM_QUERY(sess, p);
				} else {
					admin_COM_QUERY(sess, p);
				}
				break;
			case MYSQL_COM_CHANGE_USER:
				client_COM_CHANGE_USER(sess, p);
				break;
			default:
				if (sess->waiting_change_user_response==1) {
					// this code handle a response to change user
					int rc;
					rc=check_auth_switch_response_packet(p, sess);
					if (rc==-1) {
						sess->healthy=0;
					} else {
						l_free(p->length, p->data);
						create_ok_packet(p,3);
						MY_SESS_ADD_PKT_OUT_CLIENT(p);
						sess->mysql_query_cache_hit=TRUE;
					}
				}
				if (sess->admin>0) {
					// we received an unknown packet
					// we shouldn't forward this if we are in admin mode
					sess->healthy=0;
				}
				break;
		}
		// if the command will be sent to the server and there is no data queued for it
		// if ( (sess->mysql_query_cache_hit==FALSE) && (queue_data(&sess->server_myds->output.queue)==0) ) { // wrong logic , it breaks if the connection is killed via KILL while idle
		if (sess->healthy==0) {
			authenticate_mysql_client_send_ERR(sess, 1045, "#28000Access denied for user");
			return -1;
		}
		// is it a prepared statement?
		switch (sess->client_command) {
			case MYSQL_COM_STMT_PREPARE:
			case MYSQL_COM_STMT_EXECUTE:
			case MYSQL_COM_STMT_CLOSE:
			case MYSQL_COM_STMT_RESET:
			case MYSQL_COM_STMT_SEND_LONG_DATA:
				sess->query_info.prepared_statement=1;
				break;
			default:
				sess->query_info.prepared_statement=0;
				break;
		}
		if(sess->mysql_query_cache_hit==FALSE) {
			if ( sess->client_command != MYSQL_COM_QUERY ) { // if it is not a QUERY , always send to hostgroup 0
				// arguiable implementation, OK for now
				//sess->query_info.destination_hostgroup=0;
				if ( (sess->default_hostgroup==-1) || (sess->default_hostgroup_version != __sync_fetch_and_add(&gloDefHG.version,0)) ) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p has default_hostgroup %d version %d, system version %d\n", sess, sess->default_hostgroup, sess->default_hostgroup_version, gloDefHG.version);
					sess->query_info.destination_hostgroup=sess->default_hostgroup_func(sess);
				} else {
					sess->query_info.destination_hostgroup=sess->default_hostgroup;
				}
			}
			assert(sess->query_info.destination_hostgroup!=-1);

			if (active_backend_for_hostgroup(sess, sess->query_info.destination_hostgroup)==0) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Session %p doesn't have a backend for hostgroup %d\n", sess, sess->query_info.destination_hostgroup);
				mysql_session_create_backend_for_hostgroup(sess, sess->query_info.destination_hostgroup);
			}
			mysql_backend_t *mybe=l_ptr_array_index(sess->mybes, sess->query_info.destination_hostgroup);
			// if we have a backend and the current query is a prepared statement, set the backend as not reusable
			if (mybe->server_mycpe &&  sess->query_info.prepared_statement==1) {
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Prepared statement detected in session %p , marking connect %s:%d not reusable\n" , sess, mybe->server_mycpe->conn->host, mybe->server_mycpe->conn->port);
				mybe->server_mycpe->reusable=0;
			}
			if (mybe->mshge==NULL || mybe->mshge->MSptr==NULL) {
				// push the packet back to client queue
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Pushing back packet\n");
				queue_back_client_pkt(sess, p);
				return 0;
			}

			// here, mybe is NOT NULL

			if (mybe->server_mycpe==NULL) {
				// handle error!!
				proxy_error("No mycpe for session backend\n");
				proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "No server_mycpe for session %p backend %p hostgroup %d\n", sess, mybe, sess->query_info.destination_hostgroup);
				authenticate_mysql_client_send_ERR(sess, 1045, "#28000Access denied for user");
				return -1;
			}
/*
			if (mybe->server_myds) {
				sess->server_bytes_at_cmd.bytes_sent=mybe->server_myds->bytes_info.bytes_sent;
				sess->server_bytes_at_cmd.bytes_recv=mybe->server_myds->bytes_info.bytes_recv;
			}
*/
			if ( mybe->mshge->MSptr->status==MYSQL_SERVER_STATUS_OFFLINE_HARD ) {
				// we didn't manage to gracefully shutdown the connection , disconnect the client
				return -1;
			}
			if ( mybe->mshge->MSptr->status==MYSQL_SERVER_STATUS_OFFLINE_SOFT && mybe->server_myds->active_transaction==0) {
				// disconnect the backend and get a new one
				proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 7, "MySQL server %s:%d is OFFLINE_SOFT, disconnect\n", mybe->mshge->MSptr->address, mybe->mshge->MSptr->port);
				//reset_mysql_backend(mybe,0);
				mybe->bereset(mybe, &mybe->last_mysql_connpool, 0);
				mysql_session_create_backend_for_hostgroup(sess, sess->query_info.destination_hostgroup);
				if (mybe->mshge->MSptr==NULL) {
					// FIXME
					assert(0);
					return 0;
				}

			}
			if ( mybe->mshge->MSptr->status==MYSQL_SERVER_STATUS_ONLINE ) {
				proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 7, "MySQL server %s:%d is ONLINE, forward data\n", mybe->mshge->MSptr->address, mybe->mshge->MSptr->port);
				sess->server_mybe=mybe;
				//sess->server_myds=mybe->server_myds;
				sess->server_fd=mybe->fd;
				//sess->server_mycpe=mybe->server_mycpe;
				//sess->server_ptr=mybe->server_ptr;
				if (glovars.mysql_query_statistics) {
					if (sess->query_info.query_stats) {
						sess->query_info.query_stats->hostgroup_id=sess->query_info.destination_hostgroup;
						sess->query_info.query_stats->mysql_server_address=g_strdup(mybe->mshge->MSptr->address);
						sess->query_info.query_stats->mysql_server_port=mybe->mshge->MSptr->port;
					}
				}
				sync_server_bytes_at_cmd(sess);
				MY_SESS_ADD_PKT_OUT_SERVER(p);
				//l_ptr_array_add(sess->server_mybe->server_myds->output.pkts, p);
			} else {
				// we should never reach here, sanity check
				assert(0);
			}
		} else { //sess->mysql_query_cache_hit==TRUE
		}
	}
	return 0;
}

static int remove_all_backends_offline_soft(mysql_session_t *sess) {
	int j;
	int cnt=0;
	for (j=0; j<glovars.mysql_hostgroups; j++) {
		mysql_backend_t *mybe=l_ptr_array_index(sess->mybes,j);
// remove all the backends that are not active
		if (mybe->mshge->MSptr!=NULL) {
			proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 3, "Processing backend from session %p , backend %p , hostgroup %d , server %s:%d\n", sess, mybe, j, mybe->mshge->MSptr->address, mybe->mshge->MSptr->port);
			if (mybe->mshge->MSptr->status==MYSQL_SERVER_STATUS_OFFLINE_SOFT) {
				if (mybe->server_myds->active_transaction==0) {
					if (mybe==sess->server_mybe) {
						proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 3, "Removing inactive backend from session %p , backend %p , hostgroup %d , server %s:%d\n", sess, mybe, j, mybe->mshge->MSptr->address, mybe->mshge->MSptr->port);
						//reset_mysql_backend(mybe,0);
						mybe->bereset(mybe, &mybe->last_mysql_connpool, 0);
					} else {
						if (sess->server_bytes_at_cmd.bytes_sent==sess->server_mybe->server_myds->bytes_info.bytes_sent) {
							if (sess->server_bytes_at_cmd.bytes_recv==sess->server_mybe->server_myds->bytes_info.bytes_recv) {
								//reset_mysql_backend(mybe,0);
								proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 3, "Removing active(current) backend from session %p , backend %p , hostgroup %d , server %s:%d\n", sess, mybe, j, mybe->mshge->MSptr->address, mybe->mshge->MSptr->port);
								mybe->bereset(mybe, &mybe->last_mysql_connpool, 0);
								//sess->server_myds=NULL;
								//sess->server_mycpe=NULL;
							}
						}
					}
				}
			}
		}
	}
	// count after cleanup
	for (j=0; j<glovars.mysql_hostgroups; j++) {
		mysql_backend_t *mybe=l_ptr_array_index(sess->mybes,j);
		if (mybe->mshge->MSptr!=NULL)
			if (mybe->mshge->MSptr->status==MYSQL_SERVER_STATUS_OFFLINE_SOFT)
				cnt++;
	}
	proxy_debug(PROXY_DEBUG_MYSQL_SERVER, 3, "Backends that still need to removed from session %p : %d\n", sess, cnt);
	return cnt;
}



static inline void __mysql_session__drop_resultset(mysql_session_t *sess) {
	while (sess->resultset->len) {
		pkt *p;
		p=l_ptr_array_remove_index(sess->resultset, 0);
		mypkt_free1(p);
	}
	l_ptr_array_free1(sess->resultset);
}

static void inline __mysql_session__free_user_pass_schema(mysql_session_t *sess) {
	if (sess->mysql_username) { free(sess->mysql_username); sess->mysql_username=NULL; }
	if (sess->mysql_password) { free(sess->mysql_password); sess->mysql_password=NULL; }
	if (sess->mysql_schema_cur) { g_free(sess->mysql_schema_cur); sess->mysql_schema_cur=NULL; }
	if (sess->mysql_schema_new) { g_free(sess->mysql_schema_new); sess->mysql_schema_new=NULL; }
}


static void inline __mysql_session__initialize_backends(mysql_session_t *sess) {
	int i;
	sess->mybes=l_ptr_array_sized_new(glovars.mysql_hostgroups);
	for (i=0;i<glovars.mysql_hostgroups;i++) {
		mysql_backend_t *mybe=mysql_backend_new();
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 6, "Initialized mysql backend %p for session %p, hostgroup %d\n", sess, mybe, i);
		l_ptr_array_add(sess->mybes, mybe);
	}
}

static void inline __mysql_session__free_backends(mysql_session_t *sess) {
	int i;
	for (i=0; i<glovars.mysql_hostgroups; i++) {
		mysql_backend_t *mybe=l_ptr_array_index(sess->mybes,i);
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 6, "Freeing mysql backend %p for session %p, hostgroup %d\n", sess, mybe, i);
		mybe->bereset(mybe, &mybe->last_mysql_connpool, sess->force_close_backends);
	}

	while (sess->mybes->len) {
		mysql_backend_t *mybe=l_ptr_array_remove_index_fast(sess->mybes,0); // commented to avoid compiler warning
		mysql_backend_delete(mybe);  // commented for multiplexing
	}
	l_ptr_array_free1(sess->mybes);
}

static void inline __mysql_session__register_connection(mysql_session_t *sess) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 6, "registering session %p\n", sess);
	pthread_rwlock_wrlock(&glomysrvs.rwlock);
	g_ptr_array_add(glomysrvs.mysql_connections, sess);
	glomysrvs.mysql_connections_cur+=1;
	pthread_rwlock_unlock(&glomysrvs.rwlock);
}

static void inline __mysql_session__unregister_connection(mysql_session_t *sess) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 6, "un-registering session %p\n", sess);
	pthread_rwlock_wrlock(&glomysrvs.rwlock);
	g_ptr_array_remove_fast(glomysrvs.mysql_connections, sess);
	glomysrvs.mysql_connections_cur-=1;
	pthread_rwlock_unlock(&glomysrvs.rwlock);
}


static void sess_close(mysql_session_t *sess) {
//	int i;
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 4, "Closing connection on client fd %d (myds %d , sess %p)\n", sess->client_fd, sess->client_myds->fd, sess);
	if (sess->client_myds->fd) { sess->client_myds->shut_hard(sess->client_myds); }
	mysql_data_stream_delete(sess->client_myds);

	__mysql_session__drop_resultset(sess);
	__mysql_session__free_user_pass_schema(sess);

	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 6, "Freeing mysql backends for session %p\n", sess);
	__mysql_session__free_backends(sess);

	sess->healthy=0;
	init_query_metadata(sess, NULL);

	// unregister the connection
	__mysql_session__unregister_connection(sess);
}


static void process_authentication_pkt(mysql_session_t *sess) {
	//proxy_mysql_thread_t *thrLD=pthread_getspecific(tsd_key);
	pkt *hs=NULL;
	hs=l_ptr_array_remove_index(sess->client_myds->input.pkts, 0);
	sess->ret=check_client_authentication_packet(hs,sess);
	//g_slice_free1(hs->length, hs->data);
	//l_free(thrLD->sfp, hs->length, hs->data);
	l_free(hs->length, hs->data);
	if (sess->ret) {
 		create_err_packet(hs, 2, 1045, "#28000Access denied for user");
//        authenticate_mysql_client_send_ERR(sess, 1045, "#28000Access denied for user");
	} else {
		create_ok_packet(hs,2);
		if (sess->mysql_schema_cur==NULL) {
			sess->mysql_schema_cur=g_strdup(glovars.mysql_default_schema);
		}
	}
	MY_SESS_ADD_PKT_OUT_CLIENT(hs);
	//l_ptr_array_add(sess->client_myds->output.pkts, hs);
}


// thread that handles connection
static int session_handler(mysql_session_t *sess) {

  sess->status=CONNECTION_READING_CLIENT|CONNECTION_WRITING_CLIENT|CONNECTION_READING_SERVER|CONNECTION_WRITING_SERVER;
  if (sess->healthy) {


    if (sess->client_myds->active==FALSE) { // || sess->server_myds->active==FALSE) {
      goto exit_session_handler;
    }

    if (sess->sync_net(sess,0)==FALSE) {
      goto exit_session_handler;
    }

    buffer2array_2(sess);

    if (sess->client_myds->pkts_sent==1 && sess->client_myds->pkts_recv==1) {
      sess->process_authentication_pkt(sess);
    }
    // set status to all possible . Remove options during processing
//    sess->status=CONNECTION_READING_CLIENT|CONNECTION_WRITING_CLIENT|CONNECTION_READING_SERVER|CONNECTION_WRITING_SERVER;


    if (process_client_pkts(sess)==-1) {
      // we got a COM_QUIT
      goto exit_session_handler;
    }
    process_server_pkts(sess);

    array2buffer_2(sess);


    if ( (sess->server_mybe==NULL) || (sess->server_mybe->server_myds==NULL) || (sess->last_server_poll_fd==sess->server_mybe->server_myds->fd)) {
      // this optimization is possible only if a connection to the backend didn't break in the meantime,
      // or we never connected to a backend
      if (sess->sync_net(sess,1)==FALSE) {
        goto exit_session_handler;
      }
    }
    if (sess->client_myds->pkts_sent==2 && sess->client_myds->pkts_recv==1) {
      if (sess->mysql_schema_cur==NULL) {
        goto exit_session_handler;
        //sess->close(sess); return -1;
      }
    }
    return 0;
  } else {
  exit_session_handler:
  sess->close(sess);
  return -1;
  }
}


mysql_session_t * mysql_session_new(proxy_mysql_thread_t *handler_thread, int client_fd) {
	//int i;
	mysql_session_t *sess=g_malloc0(sizeof(mysql_session_t));
	sess->client_fd=client_fd;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 6, "Initializing new session %p for client connection with fd %d\n", sess, sess->client_fd);
	// register the connection
	__mysql_session__register_connection(sess);

	// generic initalization
	//sess->server_ptr=NULL;
	//sess->server_myds=NULL;
	//sess->server_mycpe=NULL;
	sess->server_mybe=NULL;
	sess->mysql_username=NULL;
	sess->mysql_password=NULL;
	sess->mysql_schema_cur=NULL;
	sess->mysql_schema_new=NULL;
	//sess->last_mysql_connpool=NULL;
	sess->server_bytes_at_cmd.bytes_sent=0;
	sess->server_bytes_at_cmd.bytes_recv=0;

	sess->mysql_server_reconnect=TRUE;
	sess->net_failure=0;
	sess->healthy=1;
	sess->force_close_backends=0;
	sess->admin=0;
	sess->resultset=l_ptr_array_new();
	sess->handler_thread=handler_thread;
	//sess->client_myds=mysql_data_stream_init(sess->client_fd, sess);
	sess->client_myds=mysql_data_stream_new(sess, NULL);
	sess->client_myds->setfd(sess->client_myds,sess->client_fd);
	sess->fds[0].fd=sess->client_myds->fd;
	sess->fds[0].events=POLLIN|POLLOUT;
	sess->nfds=1;
	sess->waiting_change_user_response=0;
	sess->query_to_cache=FALSE;
	sess->client_command=MYSQL_COM_END;	 // always reset this
	sess->send_to_slave=FALSE;
	memset(&sess->query_info,0,sizeof(mysql_query_metadata_t));
	
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 6, "Initializing mysql backends for session %p\n", sess);
	__mysql_session__initialize_backends(sess);

	sess->conn_poll = conn_poll;
	sess->sync_net = sync_net;
//	sess->array2buffer_2 = array2buffer_2;
//	sess->buffer2array_2 = buffer2array_2;
	sess->check_fds_errors = check_fds_errors;
	//sess->process_client_pkts = process_client_pkts;
	//sess->process_server_pkts = process_server_pkts;
	sess->remove_all_backends_offline_soft = remove_all_backends_offline_soft;
	sess->close = sess_close;
	sess->process_authentication_pkt = process_authentication_pkt;
	sess->handler = session_handler;
	sess->default_hostgroup=-1;
	sess->default_hostgroup_version=-1;
	sess->default_hostgroup_func = mysql_session_default_hostgroup;
	return sess;
}

void mysql_session_delete(mysql_session_t *sess) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 6, "Deleting session %p\n", sess);
	g_free(sess);
	sess=NULL;
}



static void __default_hostgroup__add_defHG(global_default_hostgroups_t *DefHG, const unsigned char *username, const unsigned char *schemaname, int hostgroup_id) {
	default_hostgroup_t *dhg=g_slice_alloc(sizeof(default_hostgroup_t));
	dhg->username=g_strdup((const gchar *)username);
	dhg->username=g_strdup((const gchar *)schemaname);
	dhg->hostgroup_id=hostgroup_id;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Adding default hostgroup entry in DefHG for username %s , schemaname %s, hostgroup_id\n", dhg->username, dhg->schemaname, dhg->hostgroup_id);
	g_ptr_array_add(DefHG->default_hostgroups,dhg);
}


static void __default_hostgroup__delete_one(default_hostgroup_t *dhg) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Deleting default hostgroup entry in DefHG for username %s , schemaname %s, hostgroup_id\n", dhg->username, dhg->schemaname, dhg->hostgroup_id);
	if (dhg->username) g_free(dhg->username);
	if (dhg->schemaname) g_free(dhg->schemaname);
	g_slice_free1(sizeof(default_hostgroup_t),dhg);
}

static void __default_hostgroup__delete_all(global_default_hostgroups_t *DefHG) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Deleting all default hostgroup entries in DefHG\n");
	while (DefHG->default_hostgroups->len) {
		default_hostgroup_t *dhg=g_ptr_array_remove_index_fast(DefHG->default_hostgroups,0);
		__default_hostgroup__delete_one(dhg);
	}
}

static int __default_hostgroup__find_defHG(global_default_hostgroups_t *DefHG, const unsigned char *username, const unsigned char *schemaname) {
	int i;
	// look for a perfect match
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Looking for a perfect match in DefHG for user %s and schema %s\n", username, schemaname);
	for (i=0; i<DefHG->default_hostgroups->len; i++) {
		default_hostgroup_t *dhg=g_ptr_array_index(DefHG->default_hostgroups,i);
		if ((g_strcmp0((const gchar *)username,dhg->username)==0) && (g_strcmp0((const gchar *)schemaname,dhg->schemaname)==0)) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Found for a perfect match in DefHG for user %s and schema %s: hostgroup_id %d\n", username, schemaname, dhg->hostgroup_id);
			return dhg->hostgroup_id;
		}
	}
	// look for a matching schema and NULL user
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Looking for a match in DefHG for user NULL and schema %s\n", schemaname);
	for (i=0; i<DefHG->default_hostgroups->len; i++) {
		default_hostgroup_t *dhg=g_ptr_array_index(DefHG->default_hostgroups,i);
		if ((dhg->username==NULL) && (dhg->schemaname) && (g_strcmp0((const gchar *)schemaname,dhg->schemaname)==0)) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Found for a match in DefHG for user NULL and schema %s: hostgroup_id %d\n", schemaname, dhg->hostgroup_id);
			return dhg->hostgroup_id;
		}
	}
	// look for a matching user and NULL schema
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Looking for a match in DefHG for user %s and schema NULL\n", username);
	for (i=0; i<DefHG->default_hostgroups->len; i++) {
		default_hostgroup_t *dhg=g_ptr_array_index(DefHG->default_hostgroups,i);
		if ((dhg->schemaname==NULL) && (dhg->username) && (g_strcmp0((const gchar *)username,dhg->username)==0)) {
			proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "Found for a match in DefHG for user %s and schema NULL: hostgroup_id %d\n", username, dhg->hostgroup_id);
			return dhg->hostgroup_id;
		}
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 7, "No default hostgroups found in DefHG, returning 0\n");
	return 0;	
}

void glo_DefHG_init(global_default_hostgroups_t *DefHG) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "Initializing global default hostgroups\n");
	DefHG->version=0;
	pthread_rwlock_init(&DefHG->rwlock,NULL);
	DefHG->default_hostgroups=g_ptr_array_new();
	DefHG->add_defHG=__default_hostgroup__add_defHG;
	DefHG->find_defHG=__default_hostgroup__find_defHG;
	DefHG->delete_all=__default_hostgroup__delete_all;
}

