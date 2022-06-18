#include "MySQL_Session.h"
#include "ProxySQL_Data_Stream.h"
#include "MySQL_Data_Stream.h"
#include "proxysql_utils.h"

#include "re2/re2.h"
#include "re2/regexp.h"
#include "SpookyV2.h"
#include "query_processor.h"
#include "MySQL_PreparedStatement.h"
#include "MySQL_Authentication.hpp"
#include "MySQL_LDAP_Authentication.hpp"
#include "MySQL_Logger.hpp"
#include "set_parser.h"

#include "proxysql_admin.h"

#include "libinjection.h"
#include "libinjection_sqli.h"

#define SELECT_VERSION_COMMENT "select @@version_comment limit 1"
#define SELECT_VERSION_COMMENT_LEN 32

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
#define SELECT_LAST_INSERT_ID_LIMIT1 "SELECT LAST_INSERT_ID() LIMIT 1"
#define SELECT_LAST_INSERT_ID_LIMIT1_LEN 31
#define SELECT_VARIABLE_IDENTITY "SELECT @@IDENTITY"
#define SELECT_VARIABLE_IDENTITY_LEN 17
#define SELECT_VARIABLE_IDENTITY_LIMIT1 "SELECT @@IDENTITY LIMIT 1"
#define SELECT_VARIABLE_IDENTITY_LIMIT1_LEN 25

static const std::set<std::string> mysql_variables_boolean = {
	"aurora_read_replica_read_committed",
	"foreign_key_checks",
	"innodb_strict_mode",
	"innodb_table_locks",
	"sql_auto_is_null",
	"sql_big_selects",
	"sql_log_bin",
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
	"optimizer_prune_level",
	"optimizer_search_depth",
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
	"optimizer_switch",
	"wsrep_osu_method",
};

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
extern Query_Processor *GloQPro;
extern MySQL_STMT_Manager_v14 *GloMyStmt;
extern Query_Cache *GloQC;
extern ProxySQL_Admin *GloAdmin;
extern ProxyWorker_Threads_Handler *GloPWTH;

#ifdef PROXYSQLCLICKHOUSE
extern ClickHouse_Authentication *GloClickHouseAuth;
extern ClickHouse_Server *GloClickHouseServer;
#endif // PROXYSQLCLICKHOUSE


// NEXT_IMMEDIATE_NEW is a new macro to use *outside* handler().
// handler() should check the return code of the function it calls, and if
// true should jump to handler_again
#define NEXT_IMMEDIATE_NEW(new_st) do { set_status(new_st); return true; } while (0)

MySQL_Session::MySQL_Session() {
	session_type=PROXYSQL_SESSION_MYSQL; // set type
	client_myds = NULL;
}

MySQL_Session::~MySQL_Session() {
	if (client_myds) {
		if (client_authenticated) {
			switch (session_type) {
#ifdef PROXYSQLCLICKHOUSE
				case PROXYSQL_SESSION_CLICKHOUSE:
					GloClickHouseAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->username);
					break;
#endif // PROXYSQLCLICKHOUSE
				default:
					GloMyAuth->decrease_frontend_user_connections(client_myds->myconn->userinfo->username);
					break;
			}
		}
		delete client_myds;
	}
}

void MySQL_Session::handler_WCDSS_MYSQL_COM_RESET_CONNECTION(PtrSize_t *pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got MYSQL_COM_RESET_CONNECTION packet\n");

	if (session_type == PROXYSQL_SESSION_MYSQL || session_type == PROXYSQL_SESSION_SQLITE) {
		// Backup the current relevant session values
		int default_hostgroup = this->default_hostgroup;
		bool transaction_persistent = this->transaction_persistent;

		// Re-initialize the session
		mysql_session_reset();
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
		mysql_session_reset();
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

// this function was inline inside MySQL_Session::get_pkts_from_client
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

// this function was inline inside MySQL_Session::get_pkts_from_client
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
bool MySQL_Session::handler_rc0_PROCESSING_STMT_PREPARE(enum session_status& st, ProxySQL_Data_Stream *pds, bool& prepared_stmt_with_no_params) {
	MySQL_Data_Stream *myds = (MySQL_Data_Stream *)pds;
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
void MySQL_Session::handler_rc0_PROCESSING_STMT_EXECUTE(ProxySQL_Data_Stream *pds) {
	MySQL_Data_Stream *myds = (MySQL_Data_Stream *)pds;
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
	if (client_myds) {
		if (client_myds->myconn) {
			client_myds->myconn->reset();
		}
	}
	reset();
}

int MySQL_Session::handler_again___status_PINGING_SERVER() {
	MySQL_Data_Stream *myds=mybe->server_myds;
	assert(myds->myconn);
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

int MySQL_Session::handler_again___status_RESETTING_CONNECTION() {
	MySQL_Data_Stream *myds=mybe->server_myds;
	assert(myds->myconn);
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

void MySQL_Session::create_new_session_and_reset_mysql_connection(MySQL_Data_Stream *_myds) {
	MySQL_Data_Stream *new_myds = NULL;
	MySQL_Connection * mc = _myds->myconn;
	// we remove the connection from the original data stream
	_myds->detach_connection();
	_myds->unplug_backend();

	// we create a brand new session, a new data stream, and attach the connection to it
	MySQL_Session * new_sess = new MySQL_Session();
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

// this function used to be inline.
// now it returns:
// true: NEXT_IMMEDIATE(CONNECTING_SERVER) needs to be called
// false: continue
bool MySQL_Session::handler_minus1_ClientLibraryError(ProxySQL_Data_Stream *pds, int myerr, char **errmsg) {
	MySQL_Data_Stream *myds = (MySQL_Data_Stream *)pds;
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
bool MySQL_Session::handler_minus1_HandleErrorCodes(ProxySQL_Data_Stream *pds, int myerr, char **errmsg, int& handler_ret) {
	MySQL_Data_Stream *myds = (MySQL_Data_Stream *)pds;
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
						create_new_session_and_reset_mysql_connection(myds);
					} else {
						myds->destroy_MySQL_Connection_From_Pool(true);
					}
					break;
			}
			myconn = myds->myconn;
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
					// LCOV_EXCL_START
					assert(0);
					break;
					// LCOV_EXCL_STOP
				}
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
void MySQL_Session::handler_minus1_GenerateErrorMessage(ProxySQL_Data_Stream *pds, MySQL_Connection *myconn, bool& wrong_pass) {
	MySQL_Data_Stream *myds = (MySQL_Data_Stream *)pds;
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
					if (myconn->MyRS) {
						PROXY_TRACE2();
						((MySQL_Session *)(myds->sess))->handler_rc0_PROCESSING_STMT_EXECUTE(myds);
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
void MySQL_Session::handler_minus1_HandleBackendConnection(ProxySQL_Data_Stream *pds, MySQL_Connection *myconn) {
	MySQL_Data_Stream *myds = (MySQL_Data_Stream *)pds;
	if (myds->myconn) {
		myds->myconn->reduce_auto_increment_delay_token();
		if (mysql_thread___multiplexing && (myds->myconn->reusable==true) && myds->myconn->IsActiveTransaction()==false && myds->myconn->MultiplexDisabled()==false) {
			myds->DSS=STATE_NOT_INITIALIZED;
			if (mysql_thread___autocommit_false_not_reusable && myds->myconn->IsAutoCommit()==false) {
				if (mysql_thread___reset_connection_algorithm == 2) {
					create_new_session_and_reset_mysql_connection(myds);
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
					// LCOV_EXCL_START
					assert(0);
					break;
					// LCOV_EXCL_STOP
			}
			NEXT_IMMEDIATE_NEW(SETTING_LDAP_USER_VARIABLE);
		}
	}
	return false;
}

void MySQL_Session::MySQL_Result_to_MySQL_wire(MYSQL *mysql, MySQL_ResultSet *MyRS, ProxySQL_Data_Stream *_myds) {
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

bool MySQL_Session::handler_WCDSS_MYSQL_COM_QUERY_qpo(PtrSize_t *pkt, bool *lock_hostgroup, bool prepared) {
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
	MySQL_Data_Stream *client_myds = NULL;
	if (this->session_type==PROXYSQL_SESSION_MYSQL) {
		client_myds = ((MySQL_Session *)this)->client_myds;
	}
	assert(client_myds != NULL);

	if (qpo->new_query) {
		handler_WCD_SS_MCQ_qpo_QueryRewrite(pkt);
	}

	if (pkt->size > (unsigned int) mysql_thread___max_allowed_packet) {
		handler_WCD_SS_MCQ_qpo_LargePacket(pkt);
		return true;
	}

	if (qpo->OK_msg) {
		handler_WCD_SS_MCQ_qpo_OK_msg(pkt);
		return true;
	}

	if (qpo->error_msg) {
		handler_WCD_SS_MCQ_qpo_error_msg(pkt);
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
			// if locked_on_hostgroup is set, we do not try to parse the SET statement
#ifdef DEBUG
			{
				string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
				proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Parsing SET command = %s\n", nqn.c_str());
			}
#endif
			if (index(dig,';') && (index(dig,';') != dig + strlen(dig)-1)) {
				string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
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
				std::map<std::string, std::vector<std::string>> set = parser.parse1();
				// Flag to be set if any variable within the 'SET' statement fails to be tracked,
				// due to being unknown or because it's an user defined variable.
				bool failed_to_parse_var = false;
				for(auto it = std::begin(set); it != std::end(set); ++it) {
					std::string var = it->first;
					proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET variable %s\n", var.c_str());
					if (it->second.size() < 1 || it->second.size() > 2) {
						// error not enough arguments
						string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
						// PMC-10002: A query has failed to be parsed. This can be due a incorrect query or
						// due to ProxySQL not being able to properly parse it. In case the query is correct a
						// bug report should be filed including the offending query.
						proxy_error2(10002, "Unable to parse query. If correct, report it as a bug: %s\n", nqn.c_str());
						proxy_debug(PROXY_DEBUG_MYSQL_QUERY_PROCESSOR, 5, "Locking hostgroup for query %s\n", nqn.c_str());
						unable_to_parse_set_statement(lock_hostgroup);
						return false;
					}
					auto values = std::begin(it->second);
					if (var == "sql_mode") {
						std::string value1 = *values;
						if (strcasecmp(value1.c_str(),"NO_BACKSLASH_ESCAPE") != 0) {
							// client is setting NO_BACKSLASH_ESCAPE in sql_mode
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
							string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
							proxy_error2(10002, "Unable to parse query. If correct, report it as a bug: %s\n", nqn.c_str());
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
								string nqn = string((char *)CurrentQuery.QueryPointer,CurrentQuery.QueryLength);
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
						client_myds->DSS=STATE_SLEEP;
						status=WAITING_CLIENT_DATA;
						RequestEnd_mysql(NULL);
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
						if (mysql_variables.client_get_hash(this, SQL_ISOLATION_LEVEL) != isolation_level_int) {
							if (!mysql_variables.client_set_value(this, SQL_ISOLATION_LEVEL, value1.c_str()))
								return false;
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection TRANSACTION ISOLATION LEVEL to %s\n", value1.c_str());
						}
					} else if (var == "read") {
						std::string value1 = *values;
						proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Processing SET SESSION TRANSACTION READ value %s\n", value1.c_str());
						uint32_t transaction_read_int=SpookyHash::Hash32(value1.c_str(),value1.length(),10);
						if (mysql_variables.client_get_hash(this, SQL_TRANSACTION_READ) != transaction_read_int) {
							if (!mysql_variables.client_set_value(this, SQL_TRANSACTION_READ, value1.c_str()))
								return false;
							proxy_debug(PROXY_DEBUG_MYSQL_COM, 8, "Changing connection TRANSACTION READ to %s\n", value1.c_str());
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
						client_myds->DSS=STATE_SLEEP;
						status=WAITING_CLIENT_DATA;
						RequestEnd_mysql(NULL);
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
						client_myds->DSS=STATE_SLEEP;
						status=WAITING_CLIENT_DATA;
						RequestEnd_mysql(NULL);
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
		RequestEnd_mysql(NULL);
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
				_mybe = find_mysql_backend(last_HG_affected_rows);
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
				RequestEnd_mysql(NULL);
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
			RequestEnd_mysql(NULL);
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
				RequestEnd_mysql(NULL);
				l_free(pkt->size,pkt->ptr);
				return true;
			}
		}
	}
	return false;
}

void MySQL_Session::handler_WCDSS_MYSQL_COM_STATISTICS(PtrSize_t *pkt) {
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_STATISTICS packet\n");
	l_free(pkt->size,pkt->ptr);
	client_myds->setDSS_STATE_QUERY_SENT_NET();
	client_myds->myprot.generate_statistics_response(true,NULL,NULL);
	client_myds->DSS=STATE_SLEEP;	
}

// this function as inline in handler_WCDSS_MYSQL_COM_QUERY_qpo
void MySQL_Session::handler_WCD_SS_MCQ_qpo_LargePacket(PtrSize_t *pkt) {
	// ER_NET_PACKET_TOO_LARGE
	client_myds->DSS=STATE_QUERY_SENT_NET;
	client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,1153,(char *)"08S01",(char *)"Got a packet bigger than 'max_allowed_packet' bytes", true);
	RequestEnd_mysql(NULL);
	l_free(pkt->size,pkt->ptr);
}

// this should execute most of the commands executed when a request is finalized
// this should become the place to hook other functions
void MySQL_Session::RequestEnd_mysql(ProxySQL_Data_Stream *pds) {
	MySQL_Data_Stream *myds = (MySQL_Data_Stream *)pds;
	// check if multiplexing needs to be disabled
	char *qdt=CurrentQuery.get_digest_text();
	if (qdt && myds && myds->myconn) {
		myds->myconn->ProcessQueryAndSetStatusFlags(qdt);
	}

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
			RequestEnd_mysql(NULL);
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
					if (nTrx) {
						// there is an active transaction, we need to forward it
						// because this can potentially close the transaction
						autocommit=true;
						client_myds->myconn->set_autocommit(autocommit);
						autocommit_on_hostgroup=FindOneActiveTransaction();
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
				client_myds->DSS=STATE_QUERY_SENT_NET;
				uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
				if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
				client_myds->myprot.generate_pkt_OK(true,NULL,NULL,1,0,0,setStatus,0,NULL);
				client_myds->DSS=STATE_SLEEP;
				status=WAITING_CLIENT_DATA;
				if (mirror==false) {
					RequestEnd_mysql(NULL);
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

// this function was introduced due to isseu #718
// some application (like the one written in Perl) do not use COM_INIT_DB , but COM_QUERY with USE dbname
void MySQL_Session::handler_WCDSS_MYSQL_COM_QUERY_USE_DB(PtrSize_t *pkt) {
	gtid_hid=-1;
	proxy_debug(PROXY_DEBUG_MYSQL_COM, 5, "Got COM_QUERY with USE dbname\n");
	if (session_type == PROXYSQL_SESSION_MYSQL) {
		__sync_fetch_and_add(&MyHGM->status.frontend_use_db, 1);
		string nq=string((char *)pkt->ptr+sizeof(mysql_hdr)+1,pkt->size-sizeof(mysql_hdr)-1);
		RE2::GlobalReplace(&nq,(char *)"(?U)/\\*.*\\*/",(char *)" ");
		char *sn_tmp = (char *)nq.c_str();
		while (sn_tmp < ( nq.c_str() + nq.length() - 4 ) && *sn_tmp == ' ')
			sn_tmp++;
		//char *schemaname=strdup(nq.c_str()+4);
		char *schemaname=strdup(sn_tmp+3);
		char *schemanameptr=trim_spaces_and_quotes_in_place(schemaname);
		// handle cases like "USE `schemaname`
		if(schemanameptr[0]=='`' && schemanameptr[strlen(schemanameptr)-1]=='`') {
			schemanameptr[strlen(schemanameptr)-1]='\0';
			schemanameptr++;
		}
		client_myds->myconn->userinfo->set_schemaname(schemanameptr,strlen(schemanameptr));
		free(schemaname);
		if (mirror==false) {
			RequestEnd_mysql(NULL);
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


// this function as inline in handler_WCDSS_MYSQL_COM_QUERY_qpo
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

// this function as inline in handler_WCDSS_MYSQL_COM_QUERY_qpo
void MySQL_Session::handler_WCD_SS_MCQ_qpo_OK_msg(PtrSize_t *pkt) {
	gtid_hid = -1;
	client_myds->DSS=STATE_QUERY_SENT_NET;
	unsigned int nTrx=NumActiveTransactions();
	uint16_t setStatus = (nTrx ? SERVER_STATUS_IN_TRANS : 0 );
	if (autocommit) setStatus |= SERVER_STATUS_AUTOCOMMIT;
	client_myds->myprot.generate_pkt_OK(true,NULL,NULL,client_myds->pkt_sid+1,0,0,setStatus,0,qpo->OK_msg);
	RequestEnd_mysql(NULL);
	l_free(pkt->size,pkt->ptr);
}

// this function as inline in handler_WCDSS_MYSQL_COM_QUERY_qpo
void MySQL_Session::handler_WCD_SS_MCQ_qpo_error_msg(PtrSize_t *pkt) {
	client_myds->DSS=STATE_QUERY_SENT_NET;
	client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,client_myds->pkt_sid+1,1148,(char *)"42000",qpo->error_msg);
	RequestEnd_mysql(NULL);
	l_free(pkt->size,pkt->ptr);
}

void MySQL_Session::handler_WCDSS_MYSQL_COM_INIT_DB(PtrSize_t *pkt) {
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
	bool handshake_err = true;

	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION,8,"Session=%p , DS=%p , handshake_response=%d , switching_auth_stage=%d , is_encrypted=%d , client_encrypted=%d\n", this, client_myds, handshake_response_return, client_myds->switching_auth_stage, is_encrypted, client_myds->encrypted);
	if (
		(handshake_response_return == false) && (client_myds->switching_auth_stage == 1)
	) {
		l_free(pkt->size,pkt->ptr);
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
		client_myds->ssl = GloVars.get_SSL_ctx();
		SSL_set_fd(client_myds->ssl, client_myds->fd);
		SSL_set_accept_state(client_myds->ssl); 
		SSL_set_bio(client_myds->ssl, client_myds->rbio_ssl, client_myds->wbio_ssl);
		l_free(pkt->size,pkt->ptr);
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
						client_myds->myprot.generate_pkt_OK(true,NULL,NULL, _pid, 0,0,0,0,NULL);
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
					if (client_myds->switching_auth_stage) _pid+=2;
					if (is_encrypted) _pid++;
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
						client_myds->myprot.generate_pkt_OK(true,NULL,NULL, _pid, 0,0,0,0,NULL);
						handshake_err = false;
						status=WAITING_CLIENT_DATA;
						client_myds->DSS=STATE_CLIENT_AUTH_OK;
					}
				}
			}
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
		if (client_addr) {
			free(client_addr);
		}
		GloMyLogger->log_audit_entry(PROXYSQL_MYSQL_AUTH_ERR, this, NULL);
		__sync_add_and_fetch(&MyHGM->status.client_connections_aborted,1);
		client_myds->DSS=STATE_SLEEP;
	}

	if (mysql_thread___client_host_cache_size) {
		GloPWTH->update_client_host_cache(client_myds->client_addr, handshake_err);
	}
}

bool MySQL_Session::RunQuery_Success(MySQL_Connection *myconn, bool& prepared_stmt_with_no_params) {

					handler_rc0_Process_GTID(myconn);

					MySQL_Data_Stream *myds = myconn->myds;

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
							MySQL_Result_to_MySQL_wire(myconn->mysql, myconn->MyRS, myconn->myds);
							break;
						case PROCESSING_STMT_PREPARE:
							{
								enum session_status st;
								if (handler_rc0_PROCESSING_STMT_PREPARE(st, myds, prepared_stmt_with_no_params)) {
									NEXT_IMMEDIATE_NEW(st);
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
							RequestEnd_mysql(myds);
							writeout();

							myconn->async_state_machine=ASYNC_IDLE;
							myds->DSS=STATE_MARIADB_GENERIC;

							NEXT_IMMEDIATE_NEW(SHOW_WARNINGS);
						}
					}
					RequestEnd_mysql(myds);
					finishQuery(myds,myconn,prepared_stmt_with_no_params);
		return false;
}


bool MySQL_Session::RunQuery_Failed(MySQL_Connection *myconn, bool& wrong_pass, int& handler_ret) {
						MySQL_Data_Stream *myds = myconn->myds;
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
							return false;
						} else {
							if (rc1 == 1)
								NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
						}
						if (myerr >= 2000 && myerr < 3000) {
							if (handler_minus1_ClientLibraryError(myds, myerr, &errmsg)) {
								NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
							} else {
								handler_ret = -1;
								return false;
							}
						} else {
							handler_minus1_LogErrorDuringQuery(myconn, myerr, errmsg);
							if (handler_minus1_HandleErrorCodes(myds, myerr, &errmsg, handler_ret)) {
								if (handler_ret == 0)
									NEXT_IMMEDIATE_NEW(CONNECTING_SERVER);
							}
							handler_minus1_GenerateErrorMessage(myds, myconn, wrong_pass);
							RequestEnd_mysql(myds);
							handler_minus1_HandleBackendConnection(myds, myconn);
						}
	return false;
}

// this function was inline
void MySQL_Session::handler___status_WAITING_CLIENT_DATA() {
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
}

bool MySQL_Session::ProcessingRequest_MatchEnvironment(MySQL_Connection *myconn) {
	// if return true, the calling function will goto handler_again
							if (handler_again___verify_init_connect()) {
								return true;
							}
							if (use_ldap_auth) {
								if (handler_again___verify_ldap_user_variable()) {
									return true;
								}
							}
							if (handler_again___verify_backend_autocommit()) {
								return true;
							}
							if (locked_on_hostgroup == -1 || locked_on_hostgroup_and_all_variables_set == false ) {

								if (handler_again___verify_backend_multi_statement()) {
									return true;
								}

								if (handler_again___verify_backend_session_track_gtids()) {
									return true;
								}

								// Optimize network traffic when we can use 'SET NAMES'
								if (verify_set_names(this)) {
									return true;
								}

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

								if (locked_on_hostgroup != -1) {
									locked_on_hostgroup_and_all_variables_set=true;
								}
							}
	return false;
}

bool MySQL_Session::RunQuery_Continue(MySQL_Connection *myconn, int rc) {
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
								MySQL_Result_to_MySQL_wire(myconn->mysql, myconn->MyRS, myconn->myds);
								  if (myconn->MyRS) { // we also need to clear MyRS, so that the next staement will recreate it if needed
										if (myconn->MyRS_reuse) {
											delete myconn->MyRS_reuse;
										}
										//myconn->MyRS->reset_pid = false;
										myconn->MyRS_reuse = myconn->MyRS;
										myconn->MyRS=NULL;
									}
									NEXT_IMMEDIATE_NEW(PROCESSING_QUERY);
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
	return false;
}

void MySQL_Session::LogKillQueryTimeout(MySQL_Data_Stream *myds, char *filename, int line) {
				// we only log in case on timing out here. Logging for 'killed' is done in the places that hold that contextual information.
				if (myds->myconn && (mybe->server_myds->myconn->async_state_machine != ASYNC_IDLE) && myds->wait_until && (thread->curtime >= myds->wait_until)) {
					std::string query {};

					if (CurrentQuery.stmt_info == NULL) { // text protocol
						query = std::string { myds->myconn->query.ptr, myds->myconn->query.length };
					} else { // prepared statement
						query = std::string { CurrentQuery.stmt_info->query, CurrentQuery.stmt_info->query_length };
					}

					std::string client_addr { "" };
					int client_port = 0;

					if (client_myds) {
						client_addr = client_myds->addr.addr ? client_myds->addr.addr : "";
						client_port = client_myds->addr.port;
					}

					proxy_warning(
						" (%s:%d) Killing connection %s:%d because query '%s' from client '%s':%d timed out.\n",
						filename, line,
						myds->myconn->parent->address,
						myds->myconn->parent->port,
						query.c_str(),
						client_addr.c_str(),
						client_port
					);
				}
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

bool MySQL_Session::handler_again___verify_backend_multi_statement() {
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

bool MySQL_Session::handler_again___status_SETTING_INIT_CONNECT(int *_rc) {
	bool ret=false;
	MySQL_Data_Stream *myds=mybe->server_myds;
	assert(myds->myconn);
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

bool MySQL_Session::handler_again___status_SETTING_LDAP_USER_VARIABLE(int *_rc) {
	bool ret=false;
	MySQL_Data_Stream *myds=mybe->server_myds;
	assert(myds->myconn);
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
	MySQL_Data_Stream *myds=mybe->server_myds;
	assert(myds->myconn);
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

bool MySQL_Session::handler_again___status_CHANGING_CHARSET(int *_rc) {
	MySQL_Data_Stream *myds=mybe->server_myds;
	assert(myds->myconn);
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

bool MySQL_Session::handler_again___status_SETTING_GENERIC_VARIABLE(int *_rc, const char *var_name, const char *var_value, bool no_quote, bool set_transaction) {
	bool ret = false;
	MySQL_Data_Stream *myds=mybe->server_myds;
	assert(myds->myconn);
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
/*
						too complicated code?
						if (mysql_thread___multiplexing && (myconn->reusable==true) && myconn->IsActiveTransaction()==false && myconn->MultiplexDisabled()==false) {
							myds->DSS=STATE_NOT_INITIALIZED;
							if (mysql_thread___autocommit_false_not_reusable && myconn->IsAutoCommit()==false) {
								if (mysql_thread___reset_connection_algorithm == 2) {
									create_new_session_and_reset_mysql_connection(myds);
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
				RequestEnd_mysql(myds);
				ret=true;
			}
		} else {
			// rc==1 , nothing to do for now
		}
	}
	return ret;
}

bool MySQL_Session::handler_again___status_SETTING_MULTI_STMT(int *_rc) {
	MySQL_Data_Stream *myds=mybe->server_myds;
	assert(myds->myconn);
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
				RequestEnd_mysql(myds);
			}
		} else {
			// rc==1 , nothing to do for now
		}
	}
	return false;
}

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

// this function was inline inside Client_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP
// enum_mysql_command in a large list of possible values
// the most common values for enum_mysql_command are handled from the calling function
// here we only process the not so common ones
// we return false if the enum_mysql_command is not found
bool MySQL_Session::handler_WCDSS_MYSQL_COM__various(PtrSize_t* pkt, bool* wrong_pass) {
	unsigned char c;
	c=*((unsigned char *)pkt->ptr+sizeof(mysql_hdr));
	switch ((enum_mysql_command)c) {
		case _MYSQL_COM_CHANGE_USER:
			handler_WCDSS_MYSQL_COM_CHANGE_USER(pkt, wrong_pass);
			break;
		case _MYSQL_COM_PING:
			handler_WCDSS_MYSQL_COM_PING(pkt);
			break;
		case _MYSQL_COM_SET_OPTION:
			handler_WCDSS_MYSQL_COM_SET_OPTION(pkt);
			break;
		case _MYSQL_COM_STATISTICS:
			handler_WCDSS_MYSQL_COM_STATISTICS(pkt);
			break;
		case _MYSQL_COM_INIT_DB:
			handler_WCDSS_MYSQL_COM_INIT_DB(pkt);
			break;
		case _MYSQL_COM_FIELD_LIST:
			handler_WCDSS_MYSQL_COM_FIELD_LIST(pkt);
			break;
		case _MYSQL_COM_PROCESS_KILL:
			handler_WCDSS_MYSQL_COM_PROCESS_KILL(pkt);
			break;
		case _MYSQL_COM_RESET_CONNECTION:
			handler_WCDSS_MYSQL_COM_RESET_CONNECTION(pkt);
			break;
		default:
			return false;
			break;
	}
	return true;
}


// this function was inline inside Client_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP_MULTI_PACKET
//
// replacing the single goto with return true
bool MySQL_Session::handler_WCDSS_MULTI_PACKET(PtrSize_t& pkt) {
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

// this function was inline inside Client_Session::get_pkts_from_client
// where:
// status = WAITING_CLIENT_DATA
// client_myds->DSS = STATE_SLEEP
// enum_mysql_command = _MYSQL_COM_QUERY
// it searches for SQL injection
// it returns true if it detected an SQL injection
bool MySQL_Session::handler_WCDSS_MYSQL_COM_QUERY_detect_SQLi() {
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
					RequestEnd_mysql(NULL);
					return true;
				}
			}
		}
	}
	return false;
}

bool MySQL_Session::handler_again___status_CHANGING_AUTOCOMMIT(int *_rc) {
	//fprintf(stderr,"CHANGING_AUTOCOMMIT\n");
	assert(session_type==PROXYSQL_SESSION_MYSQL);
	MySQL_Data_Stream *myds=mybe->server_myds;
	MySQL_Connection *myconn=myds->myconn;
	assert(myconn != NULL);
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
							   RequestEnd_mysql(myds);
							   status=WAITING_CLIENT_DATA;
							   client_myds->DSS=STATE_SLEEP;
					   }
			   } else {
					   // rc==1 , nothing to do for now
			   }
	   }
	   return false;
}

void MySQL_Session::handler_WCDSS_MYSQL_COM_QUERY___create_mirror_session() {
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
			if (__sync_add_and_fetch(&GloPWTH->status_variables.mirror_sessions_current,1) > (unsigned int)mysql_thread___mirror_max_concurrency ) {
				// if the limit is reached, we queue it instead
				__sync_sub_and_fetch(&GloPWTH->status_variables.mirror_sessions_current,1);
				thread->mirror_queue_mysql_sessions->add(newsess);
			}	else {
				GloPWTH->status_variables.p_gauge_array[p_th_gauge::mirror_concurrency]->Increment();
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
							__sync_sub_and_fetch(&GloPWTH->status_variables.mirror_sessions_current,1);
							GloPWTH->status_variables.p_gauge_array[p_th_gauge::mirror_concurrency]->Decrement();
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


bool MySQL_Session::handler_special_queries(PtrSize_t *pkt) {
	bool deprecate_eof_active = client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF;

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
			RequestEnd_mysql(NULL);
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
			RequestEnd_mysql(NULL);
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
			client_myds->DSS=STATE_SLEEP;
			status=WAITING_CLIENT_DATA;
			if (mirror==false) {
				RequestEnd_mysql(NULL);
			}
			l_free(pkt->size,pkt->ptr);
			__sync_fetch_and_add(&MyHGM->status.frontend_set_names, 1);
			return true;
		}
	}
	if ( (pkt->size == 18) && (strncasecmp((char *)"SHOW WARNINGS",(char *)pkt->ptr+5,13)==0) ) {
		SQLite3_result * resultset=new SQLite3_result(3);
		resultset->add_column_definition(SQLITE_TEXT,"Level");
		resultset->add_column_definition(SQLITE_TEXT,"Code");
		resultset->add_column_definition(SQLITE_TEXT,"Message");
		SQLite3_to_MySQL(resultset, NULL, 0, &client_myds->myprot, false, deprecate_eof_active);
		delete resultset;
		client_myds->DSS=STATE_SLEEP;
		status=WAITING_CLIENT_DATA;
		if (mirror==false) {
			RequestEnd_mysql(NULL);
		}
		l_free(pkt->size,pkt->ptr);
		return true;
	}
	// 'LOAD DATA LOCAL INFILE' is unsupported. We report an specific error to inform clients about this fact. For more context see #833.
	if ( (pkt->size >= 22 + 5) && (strncasecmp((char *)"LOAD DATA LOCAL INFILE",(char *)pkt->ptr+5, 22)==0) ) {
		if (mysql_thread___enable_load_data_local_infile == false) {
			client_myds->DSS=STATE_QUERY_SENT_NET;
			client_myds->myprot.generate_pkt_ERR(true,NULL,NULL,1,1047,(char *)"HY000",(char *)"Unsupported 'LOAD DATA LOCAL INFILE' command",true);
			client_myds->DSS=STATE_SLEEP;
			status=WAITING_CLIENT_DATA;
			if (mirror==false) {
				RequestEnd_mysql(NULL);
			}
			l_free(pkt->size,pkt->ptr);
			return true;
		} else {
			if (mysql_thread___verbose_query_error) {
				proxy_warning(
					"Command '%.*s' refers to file in ProxySQL instance, NOT on client side!\n",
					pkt->size - sizeof(mysql_hdr) - 1,
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

