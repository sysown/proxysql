#include "MySQL_Session.h"
#include "MySQL_Data_Stream.h"
#include "proxysql_utils.h"

#include "query_processor.h"
#include "MySQL_PreparedStatement.h"
#include "MySQL_Authentication.hpp"
#include "MySQL_LDAP_Authentication.hpp"

extern MySQL_Authentication *GloMyAuth;
extern MySQL_LDAP_Authentication *GloMyLdapAuth;
extern Query_Processor *GloQPro;
extern MySQL_STMT_Manager_v14 *GloMyStmt;

void MySQL_Session::handler_WCDSS_MYSQL_COM_RESET_CONNECTION(PtrSize_t *pkt) {
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

// Note: as commented in issue #546 and #547 , some clients ignore the status of CLIENT_MULTI_STATEMENTS
// therefore tracking it is not needed, unless in future this should become a security enhancement,
// returning errors to all clients trying to send multi-statements .
// see also #1140
void MySQL_Session::handler_WCDSS_MYSQL_COM_SET_OPTION(PtrSize_t *pkt) {
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

void MySQL_Session::handler_WCDSS_MYSQL_COM_PING(PtrSize_t *pkt) {
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

void MySQL_Session::handler_WCDSS_MYSQL_COM_FIELD_LIST(PtrSize_t *pkt) {
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

void MySQL_Session::handler_WCDSS_MYSQL_COM_PROCESS_KILL(PtrSize_t *pkt) {
	l_free(pkt->size,pkt->ptr);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,9003,(char *)"28000",(char *)"Command not supported");
	client_myds->DSS=STATE_SLEEP;
}

void MySQL_Session::handler_WCDSS_MYSQL_COM_CHANGE_USER(PtrSize_t *pkt, bool *wrong_pass) {
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


void MySQL_Session::handler_WCDSS_MYSQL_COM_STMT_RESET(PtrSize_t& pkt) {
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

void MySQL_Session::handler_WCDSS_MYSQL_COM_STMT_CLOSE(PtrSize_t& pkt) {
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


void MySQL_Session::handler_WCDSS_MYSQL_COM_STMT_SEND_LONG_DATA(PtrSize_t& pkt) {
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

// this function was inline inside Client_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP
// enum_mysql_command = _MYSQL_COM_STMT_PREPARE
//
// all break were replaced with a return
void MySQL_Session::handler_WCDSS_MYSQL_COM_STMT_PREPARE(PtrSize_t& pkt) {
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
void MySQL_Session::handler_WCDSS_MYSQL_COM_STMT_EXECUTE(PtrSize_t& pkt) {
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

// this function used to be inline.
// now it returns:
// true: NEXT_IMMEDIATE(st) needs to be called
// false: continue
bool MySQL_Session::handler_rc0_PROCESSING_STMT_PREPARE(enum session_status& st, MySQL_Data_Stream *myds, bool& prepared_stmt_with_no_params) {
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
void MySQL_Session::handler_rc0_PROCESSING_STMT_EXECUTE(MySQL_Data_Stream *myds) {
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


void MySQL_Session::mysql_session_init() {
	sess_STMTs_meta=new MySQL_STMTs_meta();
	SLDH=new StmtLongDataHandler();
}

void MySQL_Session::mysql_session_reset() {
	if (sess_STMTs_meta) {
		delete sess_STMTs_meta;
		sess_STMTs_meta=NULL;
	}
	if (SLDH) {
		delete SLDH;
		SLDH=NULL;
	}
}
