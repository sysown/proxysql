#include "proxysql.h"
#include "cpp.h"
#include "SpookyV2.h"
#include <fcntl.h>

#include "MySQL_PreparedStatement.h"
#include "MySQL_Data_Stream.h"
#include "query_processor.h"

extern const MARIADB_CHARSET_INFO * proxysql_find_charset_nr(unsigned int nr);

const char Variable::name[SQL_NAME_LAST][64] = {"sql_safe_updates", "sql_select_limit", "sql_mode"};

void Variable::fill_server_internal_session(json &j, int conn_num, int idx) {
	j["backends"][conn_num]["conn"][Variable::name[idx]] = std::string(value);
}

void Variable::fill_client_internal_session(json &j, int idx) {
	j["conn"][Variable::name[idx]] = value;
}

#define PROXYSQL_USE_RESULT

static int
mysql_status(short event, short cont) {
	int status= 0;
	if (event & POLLIN)
		status|= MYSQL_WAIT_READ;
	if (event & POLLOUT)
		status|= MYSQL_WAIT_WRITE;
//	if (event==0 && cont==true) {
//		status |= MYSQL_WAIT_TIMEOUT;
//	}
//	FIXME: handle timeout
//	if (event & PROXY_TIMEOUT)
//		status|= MYSQL_WAIT_TIMEOUT;
	return status;
}

// Defining list of session variables for comparison with query digest to disable multiplexing for "SET <variable_name>" commands
static char * session_vars[]= {
	// For issue #555 , multiplexing is disabled if --safe-updates is used
	//(char *)"SQL_SAFE_UPDATES=?,SQL_SELECT_LIMIT=?,MAX_JOIN_SIZE=?",
	// for issue #1832 , we are splitting the above into 3 variables
//	(char *)"SQL_SAFE_UPDATES",
//	(char *)"SQL_SELECT_LIMIT",
//	(char *)"MAX_JOIN_SIZE",
	(char *)"FOREIGN_KEY_CHECKS",
	(char *)"UNIQUE_CHECKS",
	(char *)"AUTO_INCREMENT_INCREMENT",
	(char *)"AUTO_INCREMENT_OFFSET",
	(char *)"TIMESTAMP",
	(char *)"GROUP_CONCAT_MAX_LEN"
};

MySQL_Connection_userinfo::MySQL_Connection_userinfo() {
	username=NULL;
	password=NULL;
	sha1_pass=NULL;
	schemaname=NULL;
	fe_username=NULL;
	hash=0;
}

MySQL_Connection_userinfo::~MySQL_Connection_userinfo() {
	if (username) free(username);
	if (fe_username) free(fe_username);
	if (password) free(password);
	if (sha1_pass) free(sha1_pass);
	if (schemaname) free(schemaname);
}

void MySQL_Connection::compute_unknown_transaction_status() {
	if (mysql) {
		int _myerrno=mysql_errno(mysql);
		if (_myerrno == 0) {
			unknown_transaction_status = false; // no error
			return;
		}
		if (_myerrno >= 2000 && _myerrno < 3000) { // client error
			// do not change it
			return;
		}
		if (_myerrno >= 1000 && _myerrno < 2000) { // server error
			unknown_transaction_status = true;
			return;
		}
		if (_myerrno >= 3000 && _myerrno < 4000) { // server error
			unknown_transaction_status = true;
			return;
		}
		// all other cases, server error
	}
}

uint64_t MySQL_Connection_userinfo::compute_hash() {
	int l=0;
	if (username)
		l+=strlen(username);
	if (password)
		l+=strlen(password);
	if (schemaname)
		l+=strlen(schemaname);
// two random seperator
#define _COMPUTE_HASH_DEL1_	"-ujhtgf76y576574fhYTRDF345wdt-"
#define _COMPUTE_HASH_DEL2_	"-8k7jrhtrgJHRgrefgreyhtRFewg6-"
	l+=strlen(_COMPUTE_HASH_DEL1_);
	l+=strlen(_COMPUTE_HASH_DEL2_);
	char *buf=(char *)malloc(l+1);
	l=0;
	if (username) {
		strcpy(buf+l,username);
		l+=strlen(username);
	}
	strcpy(buf+l,_COMPUTE_HASH_DEL1_);
	l+=strlen(_COMPUTE_HASH_DEL1_);
	if (password) {
		strcpy(buf+l,password);
		l+=strlen(password);
	}
	if (schemaname) {
		strcpy(buf+l,schemaname);
		l+=strlen(schemaname);
	}
	strcpy(buf+l,_COMPUTE_HASH_DEL2_);
	l+=strlen(_COMPUTE_HASH_DEL2_);
	hash=SpookyHash::Hash64(buf,l,0);
	free(buf);
	return hash;
}

void MySQL_Connection_userinfo::set(char *u, char *p, char *s, char *sh1) {
	if (u) {
		if (username) {
			if (strcmp(u,username)) {
				free(username);
				username=strdup(u);
			}
		} else {
			username=strdup(u);
		}
	}
	if (p) {
		if (password) {
			if (strcmp(p,password)) {
				free(password);
				password=strdup(p);
			}
		} else {
			password=strdup(p);
		}
	}
	if (s) {
		if (schemaname) free(schemaname);
		schemaname=strdup(s);
	}
	if (sh1) {
		if (sha1_pass) {
			free(sha1_pass);
		}
		sha1_pass=strdup(sh1);
	}
	compute_hash();
}

void MySQL_Connection_userinfo::set(MySQL_Connection_userinfo *ui) {
	set(ui->username, ui->password, ui->schemaname, ui->sha1_pass);
}


bool MySQL_Connection_userinfo::set_schemaname(char *_new, int l) {
	int _l=0;
	if (schemaname) {
		_l=strlen(schemaname); // bug fix for #609
	}
	if ((schemaname==NULL) || (l != _l) || (strncmp(_new,schemaname, l ))) {
		if (schemaname) {
			free(schemaname);
			schemaname=NULL;
		}
		if (l) {
			schemaname=(char *)malloc(l+1);
			memcpy(schemaname,_new,l);
			schemaname[l]=0;
		} else {
			int k=strlen(mysql_thread___default_schema);
			schemaname=(char *)malloc(k+1);
			memcpy(schemaname,mysql_thread___default_schema,k);
			schemaname[k]=0;
		}
		compute_hash();
		return true;
	}
	return false;
}



MySQL_Connection::MySQL_Connection() {
	mysql=NULL;
	async_state_machine=ASYNC_CONNECT_START;
	ret_mysql=NULL;
	send_quit=true;
	myds=NULL;
	inserted_into_pool=0;
	reusable=false;
	has_prepared_statement=false;
	processing_prepared_statement_prepare=false;
	processing_prepared_statement_execute=false;
	parent=NULL;
	userinfo=new MySQL_Connection_userinfo();
	fd=-1;
	status_flags=0;
	last_time_used=0;

	for (auto i = 0; i < SQL_NAME_LAST; i++) {
		variables[i].value = NULL;
		variables[i].hash = 0;
	}

	options.client_flag = 0;
	options.compression_min_length=0;
	options.server_version=NULL;
	options.last_set_autocommit=-1;	// -1 = never set
	options.autocommit=true;
	options.no_backslash_escapes=false;
	options.init_connect=NULL;
	options.init_connect_sent=false;
	options.character_set_results = NULL;
	options.isolation_level = NULL;
	options.tx_isolation = NULL;
	options.transaction_read = NULL;
	options.session_track_gtids = NULL;
	options.sql_auto_is_null = NULL;
	options.collation_connection = NULL;
	options.net_write_timeout = NULL;
	options.max_join_size = NULL;
	options.isolation_level_sent = false;
	options.tx_isolation_sent = false;
	options.transaction_read_sent = false;
	options.character_set_results_sent = false;
	options.session_track_gtids_sent = false;
	options.sql_auto_is_null_sent = false;
	options.collation_connection_sent = false;
	options.net_write_timeout_sent = false;
	options.max_join_size_sent = false;
	options.ldap_user_variable=NULL;
	options.ldap_user_variable_value=NULL;
	options.ldap_user_variable_sent=false;
	options.sql_log_bin=1;	// default #818
	options.time_zone=NULL;	// #819
	options.time_zone_int=0;	// #819
	options.isolation_level_int=0;
	options.tx_isolation_int=0;
	options.transaction_read_int=0;
	options.character_set_results_int=0;
	options.session_track_gtids_int=0;
	options.sql_auto_is_null_int=0;
	options.collation_connection_int=0;
	options.net_write_timeout_int=0;
	options.max_join_size_int=0;
	options.charset=0;
	options.charset_action=UNKNOWN;
	compression_pkt_id=0;
	mysql_result=NULL;
	query.ptr=NULL;
	query.length=0;
	query.stmt=NULL;
	query.stmt_meta=NULL;
	query.stmt_result=NULL;
	largest_query_length=0;
	multiplex_delayed=false;
	MyRS=NULL;
	MyRS_reuse=NULL;
	unknown_transaction_status = false;
	creation_time=0;
	auto_increment_delay_token = 0;
	processing_multi_statement=false;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Creating new MySQL_Connection %p\n", this);
	local_stmts=new MySQL_STMTs_local_v14(false); // false by default, it is a backend
	bytes_info.bytes_recv = 0;
	bytes_info.bytes_sent = 0;
	statuses.questions = 0;
	statuses.myconnpoll_get = 0;
	statuses.myconnpoll_put = 0;
	memset(gtid_uuid,0,sizeof(gtid_uuid));
};

MySQL_Connection::~MySQL_Connection() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Destroying MySQL_Connection %p\n", this);
	if (options.server_version) free(options.server_version);
	if (options.init_connect) free(options.init_connect);
	if (options.ldap_user_variable) free(options.ldap_user_variable);
	if (options.ldap_user_variable_value) free(options.ldap_user_variable_value);
	if (userinfo) {
		delete userinfo;
		userinfo=NULL;
	}
	if (local_stmts) {
		delete local_stmts;
	}
	if (mysql) {
		// always decrease the counter
		if (ret_mysql) {
			__sync_fetch_and_sub(&MyHGM->status.server_connections_connected,1);
			if (query.stmt_result) {
				if (query.stmt_result->handle) {
					query.stmt_result->handle->status = MYSQL_STATUS_READY; // avoid calling mthd_my_skip_result()
				}
			}
			if (mysql_result) {
				if (mysql_result->handle) {
					mysql_result->handle->status = MYSQL_STATUS_READY; // avoid calling mthd_my_skip_result()
				}
			}
			async_free_result();
		}
		close_mysql(); // this take care of closing mysql connection
		mysql=NULL;
	}
	if (MyRS) {
		delete MyRS;
		MyRS = NULL;
	}
	if (MyRS_reuse) {
		delete MyRS_reuse;
		MyRS_reuse = NULL;
	}
	if (query.stmt) {
		query.stmt=NULL;
	}

	for (auto i = 0; i < SQL_NAME_LAST; i++) {
		if (variables[i].value) {
			free(variables[i].value);
			variables[i].value = NULL;
		}
	}

	if (options.time_zone) {
		free(options.time_zone);
		options.time_zone=NULL;
	}
	if (options.isolation_level) {
		free(options.isolation_level);
		options.isolation_level=NULL;
	}
	if (options.tx_isolation) {
		free(options.tx_isolation);
		options.tx_isolation=NULL;
	}
	if (options.transaction_read) {
		free(options.transaction_read);
		options.transaction_read=NULL;
	}
	if (options.character_set_results) {
		free(options.character_set_results);
		options.character_set_results=NULL;
	}
	if (options.session_track_gtids) {
		free(options.session_track_gtids);
		options.session_track_gtids=NULL;
	}
	if (options.sql_auto_is_null) {
		free(options.sql_auto_is_null);
		options.sql_auto_is_null=NULL;
	}
	if (options.collation_connection) {
		free(options.collation_connection);
		options.collation_connection=NULL;
	}
	if (options.net_write_timeout) {
		free(options.net_write_timeout);
		options.net_write_timeout=NULL;
	}
	if (options.max_join_size) {
		free(options.max_join_size);
		options.max_join_size=NULL;
	}
};

bool MySQL_Connection::set_autocommit(bool _ac) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Setting autocommit %d\n", _ac);
	options.autocommit=_ac;
	return _ac;
}

bool MySQL_Connection::set_no_backslash_escapes(bool _ac) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Setting no_backslash_escapes %d\n", _ac);
	options.no_backslash_escapes=_ac;
	return _ac;
}

unsigned int MySQL_Connection::set_charset(unsigned int _c, enum charset_action action) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Setting charset %d\n", _c);
	options.charset=_c;
	options.charset_action = action;
	return _c;
}

bool MySQL_Connection::is_expired(unsigned long long timeout) {
// FIXME: here the check should be a sanity check
// FIXME: for now this is just a temporary (and stupid) check
	return false;
}

void MySQL_Connection::set_status_transaction(bool v) {
	if (v) {
		status_flags |= STATUS_MYSQL_CONNECTION_TRANSACTION;
	} else {
		status_flags &= ~STATUS_MYSQL_CONNECTION_TRANSACTION;
	}
}

void MySQL_Connection::set_status_compression(bool v) {
	if (v) {
		status_flags |= STATUS_MYSQL_CONNECTION_COMPRESSION;
	} else {
		status_flags &= ~STATUS_MYSQL_CONNECTION_COMPRESSION;
	}
}

void MySQL_Connection::set_status_get_lock(bool v) {
	if (v) {
		status_flags |= STATUS_MYSQL_CONNECTION_GET_LOCK;
	} else {
		status_flags &= ~STATUS_MYSQL_CONNECTION_GET_LOCK;
	}
}

void MySQL_Connection::set_status_found_rows(bool v) {
	if (v) {
		status_flags |= STATUS_MYSQL_CONNECTION_FOUND_ROWS;
	} else {
		status_flags &= ~STATUS_MYSQL_CONNECTION_FOUND_ROWS;
	}
}

void MySQL_Connection::set_status_lock_tables(bool v) {
	if (v) {
		status_flags |= STATUS_MYSQL_CONNECTION_LOCK_TABLES;
	} else {
		status_flags &= ~STATUS_MYSQL_CONNECTION_LOCK_TABLES;
	}
}

void MySQL_Connection::set_status_temporary_table(bool v) {
	if (v) {
		status_flags |= STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE;
	} else {
		status_flags &= ~STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE;
	}
}

void MySQL_Connection::set_status_no_backslash_escapes(bool v) {
	if (v) {
		status_flags |= STATUS_MYSQL_CONNECTION_NO_BACKSLASH_ESCAPES;
	} else {
		status_flags &= ~STATUS_MYSQL_CONNECTION_NO_BACKSLASH_ESCAPES;
	}
}

void MySQL_Connection::set_status_user_variable(bool v) {
	if (v) {
		status_flags |= STATUS_MYSQL_CONNECTION_USER_VARIABLE;
	} else {
		status_flags &= ~STATUS_MYSQL_CONNECTION_USER_VARIABLE;
	}
}

void MySQL_Connection::set_status_prepared_statement(bool v) {
	if (v) {
		status_flags |= STATUS_MYSQL_CONNECTION_PREPARED_STATEMENT;
	} else {
		status_flags &= ~STATUS_MYSQL_CONNECTION_PREPARED_STATEMENT;
	}
}

void MySQL_Connection::set_status_no_multiplex(bool v) {
	if (v) {
		status_flags |= STATUS_MYSQL_CONNECTION_NO_MULTIPLEX;
	} else {
		status_flags &= ~STATUS_MYSQL_CONNECTION_NO_MULTIPLEX;
	}
}

// pay attention here. set_status_sql_log_bin0 sets it sql_log_bin is ZERO
// sql_log_bin=0 => true
// sql_log_bin=1 => false
void MySQL_Connection::set_status_sql_log_bin0(bool v) {
	if (v) {
		status_flags |= STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0;
	} else {
		status_flags &= ~STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0;
	}
}

bool MySQL_Connection::get_status_transaction() {
	return status_flags & STATUS_MYSQL_CONNECTION_TRANSACTION;
}

bool MySQL_Connection::get_status_compression() {
	return status_flags & STATUS_MYSQL_CONNECTION_COMPRESSION;
}

bool MySQL_Connection::get_status_user_variable() {
	return status_flags & STATUS_MYSQL_CONNECTION_USER_VARIABLE;
}

bool MySQL_Connection::get_status_get_lock() {
	return status_flags & STATUS_MYSQL_CONNECTION_GET_LOCK;
}

bool MySQL_Connection::get_status_found_rows() {
	return status_flags & STATUS_MYSQL_CONNECTION_FOUND_ROWS;
}

bool MySQL_Connection::get_status_lock_tables() {
	return status_flags & STATUS_MYSQL_CONNECTION_LOCK_TABLES;
}

bool MySQL_Connection::get_status_temporary_table() {
	return status_flags & STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE;
}

bool MySQL_Connection::get_status_no_backslash_escapes() {
	return status_flags & STATUS_MYSQL_CONNECTION_NO_BACKSLASH_ESCAPES;
}

bool MySQL_Connection::get_status_prepared_statement() {
	return status_flags & STATUS_MYSQL_CONNECTION_PREPARED_STATEMENT;
}

bool MySQL_Connection::get_status_no_multiplex() {
	return status_flags & STATUS_MYSQL_CONNECTION_NO_MULTIPLEX;
}

bool MySQL_Connection::get_status_sql_log_bin0() {
	return status_flags & STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0;
}

bool MySQL_Connection::match_tracked_options(MySQL_Connection *c) {
	uint32_t cf1 = options.client_flag; // own client flags
	uint32_t cf2 = c->options.client_flag; // other client flags
	if ((cf1 & CLIENT_FOUND_ROWS) == (cf2 & CLIENT_FOUND_ROWS)) {
		if ((cf1 & CLIENT_MULTI_STATEMENTS) == (cf2 & CLIENT_MULTI_STATEMENTS)) {
			if ((cf1 & CLIENT_MULTI_RESULTS) == (cf2 & CLIENT_MULTI_RESULTS)) {
				if ((cf1 & CLIENT_IGNORE_SPACE) == (cf2 & CLIENT_IGNORE_SPACE)) {
					return true;
				}
			}
		}
	}
	return false;
}

// non blocking API
void MySQL_Connection::connect_start() {
	PROXY_TRACE();
	mysql=mysql_init(NULL);
	assert(mysql);
	mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
	mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "program_name", "proxysql");
	mysql_options4(mysql, MYSQL_OPT_CONNECT_ATTR_ADD, "_server_host", parent->address);
	if (parent->use_ssl) {
		mysql_ssl_set(mysql, mysql_thread___ssl_p2s_key, mysql_thread___ssl_p2s_cert, mysql_thread___ssl_p2s_ca, NULL, mysql_thread___ssl_p2s_cipher);
	}
	unsigned int timeout= 1;
	mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, (void *)&timeout);
	const MARIADB_CHARSET_INFO * c = proxysql_find_charset_nr(mysql_thread___default_charset);
	if (!c) {
		proxy_error("Not existing charset number %u\n", mysql_thread___default_charset);
		assert(0);
	}
	set_charset(c->nr, NAMES);
	mysql_options(mysql, MYSQL_SET_CHARSET_NAME, c->csname);
	unsigned long client_flags = 0;
	//if (mysql_thread___client_found_rows)
	//	client_flags += CLIENT_FOUND_ROWS;
	if (parent->compression)
		client_flags |= CLIENT_COMPRESS;
	//if (mysql_thread___client_multi_statements)
	//	client_flags += CLIENT_MULTI_STATEMENTS;

	if (myds) {
		if (myds->sess) {
			if (myds->sess->client_myds) {
				if (myds->sess->client_myds->myconn) {
					uint32_t orig_client_flags = myds->sess->client_myds->myconn->options.client_flag;
					if (orig_client_flags & CLIENT_FOUND_ROWS) {
						client_flags |= CLIENT_FOUND_ROWS;
					}
					if (orig_client_flags & CLIENT_MULTI_STATEMENTS) {
						client_flags |= CLIENT_MULTI_STATEMENTS;
					}
					if (orig_client_flags & CLIENT_MULTI_RESULTS) {
						client_flags |= CLIENT_MULTI_RESULTS;
					}
					if (orig_client_flags & CLIENT_IGNORE_SPACE) {
						client_flags |= CLIENT_IGNORE_SPACE;
					}
				}
			}
		}
	}

	char *auth_password=NULL;
	if (userinfo->password) {
		if (userinfo->password[0]=='*') { // we don't have the real password, let's pass sha1
			auth_password=userinfo->sha1_pass;
		} else {
			auth_password=userinfo->password;
		}
	}
	if (parent->port) {
		async_exit_status=mysql_real_connect_start(&ret_mysql, mysql, parent->address, userinfo->username, auth_password, userinfo->schemaname, parent->port, NULL, client_flags);
	} else {
		async_exit_status=mysql_real_connect_start(&ret_mysql, mysql, "localhost", userinfo->username, auth_password, userinfo->schemaname, parent->port, parent->address, client_flags);
	}
	fd=mysql_get_socket(mysql);
}

void MySQL_Connection::connect_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_real_connect_cont(&ret_mysql, mysql, mysql_status(event, true));
}

void MySQL_Connection::change_user_start() {
	PROXY_TRACE();
	//fprintf(stderr,"change_user_start FD %d\n", fd);
	MySQL_Connection_userinfo *_ui = NULL;
	if (myds->sess->client_myds == NULL) {
		// if client_myds is not defined, we are using CHANGE_USER to reset the connection
		_ui = userinfo;
	} else {
		_ui = myds->sess->client_myds->myconn->userinfo;
		userinfo->set(_ui);	// fix for bug #605
	}
	char *auth_password=NULL;
	if (userinfo->password) {
		if (userinfo->password[0]=='*') { // we don't have the real password, let's pass sha1
			auth_password=userinfo->sha1_pass;
		} else {
			auth_password=userinfo->password;
		}
	}
	async_exit_status = mysql_change_user_start(&ret_bool,mysql,_ui->username, auth_password, _ui->schemaname);
}

void MySQL_Connection::change_user_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_change_user_cont(&ret_bool, mysql, mysql_status(event, true));
}

void MySQL_Connection::ping_start() {
	PROXY_TRACE();
	//fprintf(stderr,"ping_start FD %d\n", fd);
	async_exit_status = mysql_ping_start(&interr,mysql);
}

void MySQL_Connection::ping_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	//fprintf(stderr,"ping_cont FD %d, event %d\n", fd, event);
	async_exit_status = mysql_ping_cont(&interr,mysql, mysql_status(event, true));
}

void MySQL_Connection::initdb_start() {
	PROXY_TRACE();
	MySQL_Connection_userinfo *client_ui=myds->sess->client_myds->myconn->userinfo;
	async_exit_status = mysql_select_db_start(&interr,mysql,client_ui->schemaname);
}

void MySQL_Connection::initdb_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_select_db_cont(&interr,mysql, mysql_status(event, true));
}

void MySQL_Connection::set_option_start() {
	PROXY_TRACE();

	enum_mysql_set_option set_option;
	set_option=((options.client_flag & CLIENT_MULTI_STATEMENTS) ? MYSQL_OPTION_MULTI_STATEMENTS_ON : MYSQL_OPTION_MULTI_STATEMENTS_OFF);
	async_exit_status = mysql_set_server_option_start(&interr,mysql,set_option);
}

void MySQL_Connection::set_option_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_set_server_option_cont(&interr,mysql, mysql_status(event, true));
}

void MySQL_Connection::set_autocommit_start() {
	PROXY_TRACE();
	async_exit_status = mysql_autocommit_start(&ret_bool, mysql, options.autocommit);
}

void MySQL_Connection::set_autocommit_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_autocommit_cont(&ret_bool, mysql, mysql_status(event, true));
}

void MySQL_Connection::set_names_start() {
	PROXY_TRACE();
	const MARIADB_CHARSET_INFO * c = proxysql_find_charset_nr(options.charset);
	if (!c) {
		proxy_error("Not existing charset number %u\n", options.charset);
		assert(0);
	}
	async_exit_status = mysql_set_character_set_start(&interr,mysql, NULL, options.charset);
}

void MySQL_Connection::set_names_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_set_character_set_cont(&interr,mysql, mysql_status(event, true));
}

void MySQL_Connection::set_query(char *stmt, unsigned long length) {
	query.length=length;
	query.ptr=stmt;
	if (length > largest_query_length) {
		largest_query_length=length;
	}
	if (query.stmt) {
		query.stmt=NULL;
	}
}

void MySQL_Connection::real_query_start() {
	PROXY_TRACE();
	async_exit_status = mysql_real_query_start(&interr , mysql, query.ptr, query.length);
}

void MySQL_Connection::real_query_cont(short event) {
	if (event == 0) return;
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_real_query_cont(&interr ,mysql , mysql_status(event, true));
}

void MySQL_Connection::stmt_prepare_start() {
	PROXY_TRACE();
	query.stmt=mysql_stmt_init(mysql);
	my_bool my_arg=true;
	mysql_stmt_attr_set(query.stmt, STMT_ATTR_UPDATE_MAX_LENGTH, &my_arg);
	async_exit_status = mysql_stmt_prepare_start(&interr , query.stmt, query.ptr, query.length);
}

void MySQL_Connection::stmt_prepare_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_stmt_prepare_cont(&interr , query.stmt , mysql_status(event, true));
}

void MySQL_Connection::stmt_execute_start() {
	PROXY_TRACE();
	int _rc=0;
	assert(query.stmt->mysql); // if we reached here, we hit bug #740
	_rc=mysql_stmt_bind_param(query.stmt, query.stmt_meta->binds); // FIXME : add error handling
	if (_rc) {
		proxy_error("mysql_stmt_bind_param() failed: %s", mysql_stmt_error(query.stmt));
	}
	//proxy_info("Calling mysql_stmt_execute_start, current state: %d\n", query.stmt->state);
	async_exit_status = mysql_stmt_execute_start(&interr , query.stmt);
	//fprintf(stderr,"Current state: %d\n", query.stmt->state);
}

void MySQL_Connection::stmt_execute_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	//proxy_info("Calling mysql_stmt_execute_cont, current state: %d\n", query.stmt->state);
	async_exit_status = mysql_stmt_execute_cont(&interr , query.stmt , mysql_status(event, true));
	//proxy_info("mysql_stmt_execute_cont , ret=%d\n", async_exit_status);
	//fprintf(stderr,"Current state: %d\n", query.stmt->state);
}

void MySQL_Connection::stmt_execute_store_result_start() {
	PROXY_TRACE();
	async_exit_status = mysql_stmt_store_result_start(&interr, query.stmt);
}

void MySQL_Connection::stmt_execute_store_result_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_stmt_store_result_cont(&interr , query.stmt , mysql_status(event, true));
}

void MySQL_Connection::store_result_start() {
	PROXY_TRACE();
	async_exit_status = mysql_store_result_start(&mysql_result, mysql);
}

void MySQL_Connection::store_result_cont(short event) {
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"event=%d\n", event);
	async_exit_status = mysql_store_result_cont(&mysql_result , mysql , mysql_status(event, true));
}

void MySQL_Connection::set_is_client() {
	local_stmts->set_is_client(myds->sess);
}

#define NEXT_IMMEDIATE(new_st) do { async_state_machine = new_st; goto handler_again; } while (0)

MDB_ASYNC_ST MySQL_Connection::handler(short event) {
	unsigned long long processed_bytes=0;	// issue #527 : this variable will store the amount of bytes processed during this event
	if (mysql==NULL) {
		// it is the first time handler() is being called
		async_state_machine=ASYNC_CONNECT_START;
		myds->wait_until=myds->sess->thread->curtime+mysql_thread___connect_timeout_server*1000;
		if (myds->max_connect_time) {
			if (myds->wait_until > myds->max_connect_time) {
				myds->wait_until = myds->max_connect_time;
			}
		}
	}
handler_again:
	proxy_debug(PROXY_DEBUG_MYSQL_PROTOCOL, 6,"async_state_machine=%d\n", async_state_machine);
	switch (async_state_machine) {
		case ASYNC_CONNECT_START:
			connect_start();
			if (async_exit_status) {
				next_event(ASYNC_CONNECT_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_CONNECT_END);
			}
			break;
		case ASYNC_CONNECT_CONT:
			if (event) {
				connect_cont(event);
			}
			if (async_exit_status) {
					if (myds->sess->thread->curtime >= myds->wait_until) {
						NEXT_IMMEDIATE(ASYNC_CONNECT_TIMEOUT);
					}
      	next_event(ASYNC_CONNECT_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_CONNECT_END);
			}
    break;
			break;
		case ASYNC_CONNECT_END:
			if (!ret_mysql) {
				// always increase the counter
				proxy_error("Failed to mysql_real_connect() on %s:%d , FD (Conn:%d , MyDS:%d) , %d: %s.\n", parent->address, parent->port, mysql->net.fd , myds->fd, mysql_errno(mysql), mysql_error(mysql));
    		NEXT_IMMEDIATE(ASYNC_CONNECT_FAILED);
			} else {
    		NEXT_IMMEDIATE(ASYNC_CONNECT_SUCCESSFUL);
			}
    	break;
		case ASYNC_CONNECT_SUCCESSFUL:
			__sync_fetch_and_add(&MyHGM->status.server_connections_connected,1);
			__sync_fetch_and_add(&parent->connect_OK,1);
			options.client_flag = mysql->client_flag;
			//assert(mysql->net.vio->async_context);
			//mysql->net.vio->async_context= mysql->options.extension->async_context;
			//if (parent->use_ssl) {
			{
				// mariadb client library disables NONBLOCK for SSL connections ... re-enable it!
				mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
				int f=fcntl(mysql->net.fd, F_GETFL);
#ifdef FD_CLOEXEC
				// asynchronously set also FD_CLOEXEC , this to prevent then when a fork happens the FD are duplicated to new process
				fcntl(mysql->net.fd, F_SETFL, f|O_NONBLOCK|FD_CLOEXEC);
#else
				fcntl(mysql->net.fd, F_SETFL, f|O_NONBLOCK);
#endif /* FD_CLOEXEC */
			}
			//if (parent->use_ssl) {
				// mariadb client library disables NONBLOCK for SSL connections ... re-enable it!
				//mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
				//ioctl_FIONBIO(mysql->net.fd,1);
				//vio_blocking(mysql->net.vio, FALSE, 0);
				//fcntl(mysql->net.vio->sd, F_SETFL, O_RDWR|O_NONBLOCK);
			//}
			break;
		case ASYNC_CONNECT_FAILED:
			parent->connect_error(mysql_errno(mysql));
			break;
		case ASYNC_CONNECT_TIMEOUT:
			//proxy_error("Connect timeout on %s:%d : %llu - %llu = %llu\n",  parent->address, parent->port, myds->sess->thread->curtime , myds->wait_until, myds->sess->thread->curtime - myds->wait_until);
			proxy_error("Connect timeout on %s:%d : exceeded by %lluus\n", parent->address, parent->port, myds->sess->thread->curtime - myds->wait_until);
			parent->connect_error(mysql_errno(mysql));
			break;
		case ASYNC_CHANGE_USER_START:
			change_user_start();
			if (async_exit_status) {
				next_event(ASYNC_CHANGE_USER_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_CHANGE_USER_END);
			}
			break;
		case ASYNC_CHANGE_USER_CONT:
			assert(myds->sess->status==CHANGING_USER_SERVER || myds->sess->status==RESETTING_CONNECTION);
			change_user_cont(event);
			if (async_exit_status) {
				if (myds->sess->thread->curtime >= myds->wait_until) {
					NEXT_IMMEDIATE(ASYNC_CHANGE_USER_TIMEOUT);
				} else {
					next_event(ASYNC_CHANGE_USER_CONT);
				}
			} else {
				NEXT_IMMEDIATE(ASYNC_CHANGE_USER_END);
			}
			break;
		case ASYNC_CHANGE_USER_END:
			if (ret_bool) {
				NEXT_IMMEDIATE(ASYNC_CHANGE_USER_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_CHANGE_USER_SUCCESSFUL);
			}
			break;
		case ASYNC_CHANGE_USER_SUCCESSFUL:
			mysql->server_status = SERVER_STATUS_AUTOCOMMIT; // we reset this due to bug https://jira.mariadb.org/browse/CONC-332
			break;
		case ASYNC_CHANGE_USER_FAILED:
			break;
		case ASYNC_CHANGE_USER_TIMEOUT:
			break;
		case ASYNC_PING_START:
			ping_start();
			if (async_exit_status) {
				next_event(ASYNC_PING_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_PING_END);
			}
			break;
		case ASYNC_PING_CONT:
			assert(myds->sess->status==PINGING_SERVER);
			if (event) {
				ping_cont(event);
			}
			if (async_exit_status) {
				if (myds->sess->thread->curtime >= myds->wait_until) {
					NEXT_IMMEDIATE(ASYNC_PING_TIMEOUT);
				} else {
					next_event(ASYNC_PING_CONT);
				}
			} else {
				NEXT_IMMEDIATE(ASYNC_PING_END);
			}
			break;
		case ASYNC_PING_END:
			if (interr) {
				NEXT_IMMEDIATE(ASYNC_PING_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_PING_SUCCESSFUL);
			}
			break;
		case ASYNC_PING_SUCCESSFUL:
			break;
		case ASYNC_PING_FAILED:
			break;
		case ASYNC_PING_TIMEOUT:
			break;
		case ASYNC_QUERY_START:
			real_query_start();
			__sync_fetch_and_add(&parent->queries_sent,1);
			__sync_fetch_and_add(&parent->bytes_sent,query.length);
			statuses.questions++;
			myds->sess->thread->status_variables.queries_backends_bytes_sent+=query.length;
			myds->bytes_info.bytes_sent += query.length;
			bytes_info.bytes_sent += query.length;
			if (myds->sess->with_gtid == true) {
				__sync_fetch_and_add(&parent->queries_gtid_sync,1);
			}
			if (async_exit_status) {
				next_event(ASYNC_QUERY_CONT);
			} else {
#ifdef PROXYSQL_USE_RESULT
				NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
#else
				NEXT_IMMEDIATE(ASYNC_STORE_RESULT_START);
#endif
			}
			break;
		case ASYNC_QUERY_CONT:
			real_query_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_QUERY_CONT);
			} else {
#ifdef PROXYSQL_USE_RESULT
				NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
#else
				NEXT_IMMEDIATE(ASYNC_STORE_RESULT_START);
#endif
			}
			break;

		case ASYNC_STMT_PREPARE_START:
			stmt_prepare_start();
			__sync_fetch_and_add(&parent->queries_sent,1);
			__sync_fetch_and_add(&parent->bytes_sent,query.length);
			myds->sess->thread->status_variables.queries_backends_bytes_sent+=query.length;
			myds->bytes_info.bytes_sent += query.length;
			bytes_info.bytes_sent += query.length;
			if (async_exit_status) {
				next_event(ASYNC_STMT_PREPARE_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_STMT_PREPARE_END);
			}
			break;
		case ASYNC_STMT_PREPARE_CONT:
			stmt_prepare_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_STMT_PREPARE_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_STMT_PREPARE_END);
			}
			break;

		case ASYNC_STMT_PREPARE_END:
			if (interr) {
				NEXT_IMMEDIATE(ASYNC_STMT_PREPARE_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_STMT_PREPARE_SUCCESSFUL);
			}
			break;
		case ASYNC_STMT_PREPARE_SUCCESSFUL:
			break;
		case ASYNC_STMT_PREPARE_FAILED:
			break;

		case ASYNC_STMT_EXECUTE_START:
			stmt_execute_start();
			__sync_fetch_and_add(&parent->queries_sent,1);
			__sync_fetch_and_add(&parent->bytes_sent,query.stmt_meta->size);
			myds->sess->thread->status_variables.queries_backends_bytes_sent+=query.stmt_meta->size;
			myds->bytes_info.bytes_sent += query.stmt_meta->size;
			bytes_info.bytes_sent += query.stmt_meta->size;
			if (async_exit_status) {
				next_event(ASYNC_STMT_EXECUTE_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_STORE_RESULT_START);
			}
			break;
		case ASYNC_STMT_EXECUTE_CONT:
			stmt_execute_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_STMT_EXECUTE_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_STORE_RESULT_START);
			}
			break;

		case ASYNC_STMT_EXECUTE_STORE_RESULT_START:
			if (mysql_stmt_errno(query.stmt)) {
				NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_END);
			}
			{
				query.stmt_result=mysql_stmt_result_metadata(query.stmt);
				if (query.stmt_result==NULL) {
					NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_END);
				}
			}
			stmt_execute_store_result_start();
			if (async_exit_status) {
				next_event(ASYNC_STMT_EXECUTE_STORE_RESULT_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_END);
			}
			break;
		case ASYNC_STMT_EXECUTE_STORE_RESULT_CONT:
			stmt_execute_store_result_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_STMT_EXECUTE_STORE_RESULT_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_END);
			}
			break;
		case ASYNC_STMT_EXECUTE_END:
			{
				if (query.stmt_result) {
					unsigned long long total_size=0;
					MYSQL_ROWS *r=query.stmt->result.data;
					if (r) {
						total_size+=r->length;
						if (r->length > 0xFFFFFF) {
							total_size+=(r->length / 0xFFFFFF) * sizeof(mysql_hdr);
						}
						total_size+=sizeof(mysql_hdr);
						while(r->next) {
							r=r->next;
							total_size+=r->length;
							if (r->length > 0xFFFFFF) {
								total_size+=(r->length / 0xFFFFFF) * sizeof(mysql_hdr);
							}
							total_size+=sizeof(mysql_hdr);
						}
					}
					__sync_fetch_and_add(&parent->bytes_recv,total_size);
					myds->sess->thread->status_variables.queries_backends_bytes_recv+=total_size;
					myds->bytes_info.bytes_recv += total_size;
					bytes_info.bytes_recv += total_size;
				}
			}
/*
			if (interr) {
				NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_STMT_EXECUTE_SUCCESSFUL);
			}
*/
			break;
//		case ASYNC_STMT_EXECUTE_SUCCESSFUL:
//			break;
//		case ASYNC_STMT_EXECUTE_FAILED:
//			break;

		case ASYNC_NEXT_RESULT_START:
			async_exit_status = mysql_next_result_start(&interr, mysql);
			if (async_exit_status) {
				next_event(ASYNC_NEXT_RESULT_CONT);
			} else {
#ifdef PROXYSQL_USE_RESULT
				NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
#else
				NEXT_IMMEDIATE(ASYNC_STORE_RESULT_START);
#endif
			}
			break;

		case ASYNC_NEXT_RESULT_CONT:
			if (event) {
				async_exit_status = mysql_next_result_cont(&interr, mysql, mysql_status(event, true));
			}
			if (async_exit_status) {
				next_event(ASYNC_NEXT_RESULT_CONT);
			} else {
#ifdef PROXYSQL_USE_RESULT
				NEXT_IMMEDIATE(ASYNC_USE_RESULT_START);
#else
				NEXT_IMMEDIATE(ASYNC_STORE_RESULT_START);
#endif
			}
			break;

		case ASYNC_NEXT_RESULT_END:
			break;

		case ASYNC_STORE_RESULT_START:
			if (mysql_errno(mysql)) {
				NEXT_IMMEDIATE(ASYNC_QUERY_END);
			}
			store_result_start();
			if (async_exit_status) {
				next_event(ASYNC_STORE_RESULT_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_QUERY_END);
			}
			break;
		case ASYNC_STORE_RESULT_CONT:
			store_result_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_STORE_RESULT_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_QUERY_END);
			}
			break;
		case ASYNC_USE_RESULT_START:
			if (mysql_errno(mysql)) {
				NEXT_IMMEDIATE(ASYNC_QUERY_END);
			}
			mysql_result=mysql_use_result(mysql);
			if (mysql_result==NULL) {
				NEXT_IMMEDIATE(ASYNC_QUERY_END);
			} else {
				if (myds->sess->mirror==false) {
					if (MyRS_reuse == NULL) {
						MyRS = new MySQL_ResultSet();
						MyRS->init(&myds->sess->client_myds->myprot, mysql_result, mysql);
					} else {
						MyRS = MyRS_reuse;
						MyRS_reuse = NULL;
						MyRS->init(&myds->sess->client_myds->myprot, mysql_result, mysql);
					}
				} else {
					if (MyRS_reuse == NULL) {
						MyRS = new MySQL_ResultSet();
						MyRS->init(NULL, mysql_result, mysql);
					} else {
						MyRS = MyRS_reuse;
						MyRS_reuse = NULL;
						MyRS->init(NULL, mysql_result, mysql);
					}
				}
				async_fetch_row_start=false;
				NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
			}
			break;
		case ASYNC_USE_RESULT_CONT:
			{
				if (myds->sess && myds->sess->client_myds && myds->sess->mirror==false) {
					unsigned int buffered_data=0;
					buffered_data = myds->sess->client_myds->PSarrayOUT->len * RESULTSET_BUFLEN;
					buffered_data += myds->sess->client_myds->resultset->len * RESULTSET_BUFLEN;
					if (buffered_data > (unsigned int)mysql_thread___threshold_resultset_size*8) {
						next_event(ASYNC_USE_RESULT_CONT); // we temporarily pause . See #1232
						break;
					}
				}
			}
			if (async_fetch_row_start==false) {
				async_exit_status=mysql_fetch_row_start(&mysql_row,mysql_result);
				async_fetch_row_start=true;
			} else {
				async_exit_status=mysql_fetch_row_cont(&mysql_row,mysql_result, mysql_status(event, true));
			}
			if (async_exit_status) {
				next_event(ASYNC_USE_RESULT_CONT);
			} else {
				async_fetch_row_start=false;
				if (mysql_row) {
					unsigned int br=MyRS->add_row(mysql_row);
					__sync_fetch_and_add(&parent->bytes_recv,br);
					myds->sess->thread->status_variables.queries_backends_bytes_recv+=br;
					myds->bytes_info.bytes_recv += br;
					bytes_info.bytes_recv += br;
					processed_bytes+=br;	// issue #527 : this variable will store the amount of bytes processed during this event
					if (
						(processed_bytes > (unsigned int)mysql_thread___threshold_resultset_size*8)
							||
						( mysql_thread___throttle_ratio_server_to_client && mysql_thread___throttle_max_bytes_per_second_to_client && (processed_bytes > (unsigned long long)mysql_thread___throttle_max_bytes_per_second_to_client/10*(unsigned long long)mysql_thread___throttle_ratio_server_to_client) )
					) {
						next_event(ASYNC_USE_RESULT_CONT); // we temporarily pause
					} else {
						NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT); // we continue looping
					}
				} else {
					if (mysql) {
						int _myerrno=mysql_errno(mysql);
						if (_myerrno) {
							if (myds) {
								MyRS->add_err(myds);
								NEXT_IMMEDIATE(ASYNC_QUERY_END);
							}
						}
					}
					// we reach here if there was no error
					MyRS->add_eof();
					NEXT_IMMEDIATE(ASYNC_QUERY_END);
				}
			}
			break;
		case ASYNC_QUERY_END:
			if (mysql) {
				int _myerrno=mysql_errno(mysql);
				if (_myerrno == 0) {
					unknown_transaction_status = false;
				} else {
					compute_unknown_transaction_status();
				}
			}
			if (mysql_result) {
				mysql_free_result(mysql_result);
				mysql_result=NULL;
			}
			//if (mysql_next_result(mysql)==0) {
			if (mysql->server_status & SERVER_MORE_RESULTS_EXIST) {
				async_state_machine=ASYNC_NEXT_RESULT_START;
			}
			break;
		case ASYNC_SET_AUTOCOMMIT_START:
			set_autocommit_start();
			if (async_exit_status) {
				next_event(ASYNC_SET_AUTOCOMMIT_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_AUTOCOMMIT_END);
			}
			break;
		case ASYNC_SET_AUTOCOMMIT_CONT:
			set_autocommit_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_SET_AUTOCOMMIT_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_AUTOCOMMIT_END);
			}
			break;
		case ASYNC_SET_AUTOCOMMIT_END:
			if (ret_bool) {
				NEXT_IMMEDIATE(ASYNC_SET_AUTOCOMMIT_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_AUTOCOMMIT_SUCCESSFUL);
			}
			break;
		case ASYNC_SET_AUTOCOMMIT_SUCCESSFUL:
			options.last_set_autocommit = ( options.autocommit ? 1 : 0 ) ; // we successfully set autocommit
			if ((mysql->server_status & SERVER_STATUS_AUTOCOMMIT) && options.autocommit==false) {
				proxy_warning("It seems we are hitting bug http://bugs.mysql.com/bug.php?id=66884\n");
			}
			break;
		case ASYNC_SET_AUTOCOMMIT_FAILED:
			fprintf(stderr,"%s\n",mysql_error(mysql));
			break;
		case ASYNC_SET_NAMES_START:
			set_names_start();
			if (async_exit_status) {
				next_event(ASYNC_SET_NAMES_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_NAMES_END);
			}
			break;
		case ASYNC_SET_NAMES_CONT:
			set_names_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_SET_NAMES_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_NAMES_END);
			}
			break;
		case ASYNC_SET_NAMES_END:
			if (interr) {
				NEXT_IMMEDIATE(ASYNC_SET_NAMES_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_NAMES_SUCCESSFUL);
			}
			break;
		case ASYNC_SET_NAMES_SUCCESSFUL:
			break;
		case ASYNC_SET_NAMES_FAILED:
			fprintf(stderr,"%s\n",mysql_error(mysql));
			break;
		case ASYNC_INITDB_START:
			initdb_start();
			if (async_exit_status) {
				next_event(ASYNC_INITDB_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_INITDB_END);
			}
			break;
		case ASYNC_INITDB_CONT:
			initdb_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_INITDB_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_INITDB_END);
			}
			break;
		case ASYNC_INITDB_END:
			if (interr) {
				NEXT_IMMEDIATE(ASYNC_INITDB_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_INITDB_SUCCESSFUL);
			}
			break;
		case ASYNC_INITDB_SUCCESSFUL:
			break;
		case ASYNC_INITDB_FAILED:
			fprintf(stderr,"%s\n",mysql_error(mysql));
			break;
		case ASYNC_SET_OPTION_START:
			set_option_start();
			if (async_exit_status) {
				next_event(ASYNC_SET_OPTION_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_OPTION_END);
			}
			break;
		case ASYNC_SET_OPTION_CONT:
			set_option_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_SET_OPTION_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_OPTION_END);
			}
			break;
		case ASYNC_SET_OPTION_END:
			if (interr) {
				NEXT_IMMEDIATE(ASYNC_SET_OPTION_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_SET_OPTION_SUCCESSFUL);
			}
			break;
		case ASYNC_SET_OPTION_SUCCESSFUL:
			break;
		case ASYNC_SET_OPTION_FAILED:
			proxy_error("Error setting MYSQL_OPTION_MULTI_STATEMENTS : %s\n", mysql_error(mysql));
			break;

		default:
			assert(0); //we should never reach here
			break;
		}
	return async_state_machine;
}


void MySQL_Connection::next_event(MDB_ASYNC_ST new_st) {
#ifdef DEBUG
	int fd;
#endif /* DEBUG */
	wait_events=0;

	if (async_exit_status & MYSQL_WAIT_READ)
		wait_events |= POLLIN;
	if (async_exit_status & MYSQL_WAIT_WRITE)
		wait_events|= POLLOUT;
	if (wait_events)
#ifdef DEBUG
		fd= mysql_get_socket(mysql);
#else
		mysql_get_socket(mysql);
#endif /* DEBUG */
	else
#ifdef DEBUG
		fd= -1;
#endif /* DEBUG */
	if (async_exit_status & MYSQL_WAIT_TIMEOUT) {
	timeout=10000;
	//tv.tv_sec= 0;
	//tv.tv_usec= 10000;
      //ptv= &tv;
	} else {
      //ptv= NULL;
	}
    //event_set(ev_mysql, fd, wait_event, state_machine_handler, this);
    //if (ev_mysql==NULL) {
    //  ev_mysql=event_new(base, fd, wait_event, state_machine_handler, this);
      //event_add(ev_mysql, ptv);
	//}
    //event_del(ev_mysql);
    //event_assign(ev_mysql, base, fd, wait_event, state_machine_handler, this);
    //event_add(ev_mysql, ptv);
	proxy_debug(PROXY_DEBUG_NET, 8, "fd=%d, wait_events=%d , old_ST=%d, new_ST=%d\n", fd, wait_events, async_state_machine, new_st);
	async_state_machine = new_st;
};


int MySQL_Connection::async_connect(short event) {
	PROXY_TRACE();
	if (mysql==NULL && async_state_machine!=ASYNC_CONNECT_START) {
		assert(0);
	}
	if (async_state_machine==ASYNC_IDLE) {
		myds->wait_until=0;
		return 0;
	}
	if (async_state_machine==ASYNC_CONNECT_SUCCESSFUL) {
		compute_unknown_transaction_status();
		async_state_machine=ASYNC_IDLE;
		myds->wait_until=0;
		creation_time = monotonic_time();
		return 0;
	}
	handler(event);
	switch (async_state_machine) {
		case ASYNC_CONNECT_SUCCESSFUL:
			compute_unknown_transaction_status();
			async_state_machine=ASYNC_IDLE;
			myds->wait_until=0;
			return 0;
			break;
		case ASYNC_CONNECT_FAILED:
			return -1;
			break;
		case ASYNC_CONNECT_TIMEOUT:
			return -2;
			break;
		default:
			return 1;
	}
	return 1;
}


bool MySQL_Connection::IsServerOffline() {
	bool ret=false;
	if (parent==NULL)
		return ret;
	server_status=parent->status; // we copy it here to avoid race condition. The caller will see this
	if (
		(server_status==MYSQL_SERVER_STATUS_OFFLINE_HARD) // the server is OFFLINE as specific by the user
		||
		(server_status==MYSQL_SERVER_STATUS_SHUNNED && parent->shunned_automatic==true && parent->shunned_and_kill_all_connections==true) // the server is SHUNNED due to a serious issue
		||
		(server_status==MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) // slave is lagging! see #774
	) {
		ret=true;
	}
	return ret;
}

// Returns:
// 0 when the query is completed
// 1 when the query is not completed
// the calling function should check mysql error in mysql struct
int MySQL_Connection::async_query(short event, char *stmt, unsigned long length, MYSQL_STMT **_stmt, stmt_execute_metadata_t *stmt_meta) {
	PROXY_TRACE();
	assert(mysql);
	assert(ret_mysql);
	server_status=parent->status; // we copy it here to avoid race condition. The caller will see this
	if (
		(server_status==MYSQL_SERVER_STATUS_OFFLINE_HARD) // the server is OFFLINE as specific by the user
		||
		(server_status==MYSQL_SERVER_STATUS_SHUNNED && parent->shunned_automatic==true && parent->shunned_and_kill_all_connections==true) // the server is SHUNNED due to a serious issue
		||
		(server_status==MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG) // slave is lagging! see #774
	) {
		return -1;
	}
	if (myds) {
		if (myds->DSS != STATE_MARIADB_QUERY) {
			myds->DSS = STATE_MARIADB_QUERY;
		}
	}
	switch (async_state_machine) {
		case ASYNC_QUERY_END:
			processing_multi_statement=false;	// no matter if we are processing a multi statement or not, we reached the end
			return 0;
			break;
		case ASYNC_IDLE:
			if (stmt_meta==NULL)
				set_query(stmt,length);
			async_state_machine=ASYNC_QUERY_START;
			if (_stmt) {
				query.stmt=*_stmt;
				if (stmt_meta==NULL) {
					async_state_machine=ASYNC_STMT_PREPARE_START;
				} else {
					if (query.stmt_meta==NULL) {
						query.stmt_meta=stmt_meta;
					}
					async_state_machine=ASYNC_STMT_EXECUTE_START;
				}
			}
		default:
			handler(event);
			break;
	}
	
	if (async_state_machine==ASYNC_QUERY_END) {
		compute_unknown_transaction_status();
		if (mysql_errno(mysql)) {
			return -1;
		} else {
			return 0;
		}
	}
	if (async_state_machine==ASYNC_STMT_EXECUTE_END) {
		query.stmt_meta=NULL;
		async_state_machine=ASYNC_QUERY_END;
		compute_unknown_transaction_status();
		if (mysql_stmt_errno(query.stmt)) {
			return -1;
		} else {
			return 0;
		}
	}
	if (async_state_machine==ASYNC_STMT_PREPARE_SUCCESSFUL || async_state_machine==ASYNC_STMT_PREPARE_FAILED) {
		query.stmt_meta=NULL;
		compute_unknown_transaction_status();
		if (async_state_machine==ASYNC_STMT_PREPARE_FAILED) {
			return -1;
		} else {
			*_stmt=query.stmt;
			return 0;
		}
	}
	if (async_state_machine==ASYNC_NEXT_RESULT_START) {
		// if we reached this point it measn we are processing a multi-statement
		// and we need to exit to give control to MySQL_Session
		processing_multi_statement=true;
		return 2;
	}
	if (processing_multi_statement==true) {
		// we are in the middle of processing a multi-statement
		return 3;
	}
	return 1;
}


// Returns:
// 0 when the ping is completed successfully
// -1 when the ping is completed not successfully
// 1 when the ping is not completed
// -2 on timeout
// the calling function should check mysql error in mysql struct
int MySQL_Connection::async_ping(short event) {
	PROXY_TRACE();
	assert(mysql);
	assert(ret_mysql);
	switch (async_state_machine) {
		case ASYNC_PING_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_PING_FAILED:
			return -1;
			break;
		case ASYNC_PING_TIMEOUT:
			return -2;
			break;
		case ASYNC_IDLE:
			async_state_machine=ASYNC_PING_START;
		default:
			handler(event);
			break;
	}
	
	// check again
	switch (async_state_machine) {
		case ASYNC_PING_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_PING_FAILED:
			return -1;
			break;
		case ASYNC_PING_TIMEOUT:
			return -2;
			break;
		default:
			return 1;
			break;
	}
	return 1;
}

int MySQL_Connection::async_change_user(short event) {
	PROXY_TRACE();
	assert(mysql);
	assert(ret_mysql);
	switch (async_state_machine) {
		case ASYNC_CHANGE_USER_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_CHANGE_USER_FAILED:
			return -1;
			break;
		case ASYNC_CHANGE_USER_TIMEOUT:
			return -2;
			break;
		case ASYNC_IDLE:
			async_state_machine=ASYNC_CHANGE_USER_START;
		default:
			handler(event);
			break;
	}

	// check again
	switch (async_state_machine) {
		case ASYNC_CHANGE_USER_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_CHANGE_USER_FAILED:
			return -1;
			break;
		case ASYNC_CHANGE_USER_TIMEOUT:
			return -2;
			break;
		default:
			return 1;
			break;
	}
	return 1;
}

int MySQL_Connection::async_select_db(short event) {
	PROXY_TRACE();
	assert(mysql);
	assert(ret_mysql);
	switch (async_state_machine) {
		case ASYNC_INITDB_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_INITDB_FAILED:
			return -1;
			break;
		case ASYNC_IDLE:
			async_state_machine=ASYNC_INITDB_START;
		default:
			handler(event);
			break;
	}

	// check again
	switch (async_state_machine) {
		case ASYNC_INITDB_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_INITDB_FAILED:
			return -1;
			break;
		default:
			return 1;
			break;
	}
	return 1;
}

int MySQL_Connection::async_set_autocommit(short event, bool ac) {
	PROXY_TRACE();
	assert(mysql);
	assert(ret_mysql);
	switch (async_state_machine) {
		case ASYNC_SET_AUTOCOMMIT_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_SET_AUTOCOMMIT_FAILED:
			return -1;
			break;
		case ASYNC_QUERY_END:
		case ASYNC_IDLE:
			set_autocommit(ac);
			async_state_machine=ASYNC_SET_AUTOCOMMIT_START;
		default:
			handler(event);
			break;
	}

	// check again
	switch (async_state_machine) {
		case ASYNC_SET_AUTOCOMMIT_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_SET_AUTOCOMMIT_FAILED:
			return -1;
			break;
		default:
			return 1;
			break;
	}
	return 1;
}

int MySQL_Connection::async_set_names(short event, unsigned int c) {
	PROXY_TRACE();
	assert(mysql);
	assert(ret_mysql);
	switch (async_state_machine) {
		case ASYNC_SET_NAMES_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_SET_NAMES_FAILED:
			return -1;
			break;
		case ASYNC_IDLE:
			set_charset(c, NAMES);
			async_state_machine=ASYNC_SET_NAMES_START;
		default:
			handler(event);
			break;
	}

	// check again
	switch (async_state_machine) {
		case ASYNC_SET_NAMES_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_SET_NAMES_FAILED:
			return -1;
			break;
		default:
			return 1;
			break;
	}
	return 1;
}

int MySQL_Connection::async_set_option(short event, bool mask) {
	PROXY_TRACE();
	assert(mysql);
	assert(ret_mysql);
	switch (async_state_machine) {
		case ASYNC_SET_OPTION_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_SET_OPTION_FAILED:
			return -1;
			break;
		case ASYNC_IDLE:
			if (mask)
				options.client_flag |= CLIENT_MULTI_STATEMENTS;
			else
				options.client_flag &= ~CLIENT_MULTI_STATEMENTS;
			async_state_machine=ASYNC_SET_OPTION_START;
		default:
			handler(event);
			break;
	}

	// check again
	switch (async_state_machine) {
		case ASYNC_SET_OPTION_SUCCESSFUL:
			unknown_transaction_status = false;
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_SET_OPTION_FAILED:
			return -1;
			break;
		default:
			return 1;
			break;
	}
	return 1;
}

void MySQL_Connection::async_free_result() {
	PROXY_TRACE();
	assert(mysql);
	//assert(ret_mysql);
	//assert(async_state_machine==ASYNC_QUERY_END);
	if (query.ptr) {
		query.ptr=NULL;
		query.length=0;
	}
	if (query.stmt_result) {
		mysql_free_result(query.stmt_result);
		query.stmt_result=NULL;
	}
	if (userinfo) {
		// if userinfo is NULL , the connection is being destroyed
		// because it is reset on destructor ( ~MySQL_Connection() )
		// therefore this section is skipped completely
		// this should prevent bug #1046
		if (query.stmt) {
			if (query.stmt->mysql) {
				if (query.stmt->mysql == mysql) { // extra check
					mysql_stmt_free_result(query.stmt);
				}
			}
			query.stmt=NULL;
		}
		if (mysql_result) {
			mysql_free_result(mysql_result);
			mysql_result=NULL;
		}
	}
	compute_unknown_transaction_status();
	async_state_machine=ASYNC_IDLE;
	if (MyRS) {
		if (MyRS_reuse) {
			delete (MyRS_reuse);
		}
		MyRS_reuse = MyRS;
		MyRS=NULL;
	}
}


bool MySQL_Connection::IsActiveTransaction() {
	bool ret=false;
	if (mysql) {
		ret = (mysql->server_status & SERVER_STATUS_IN_TRANS);
		if (ret == false && (mysql)->net.last_errno && unknown_transaction_status == true) {
			ret = true;
		}
		if (ret == false) {
			bool r = ( mysql_thread___autocommit_false_is_transaction || mysql_thread___forward_autocommit );
			if ( r && (IsAutoCommit() == false) ) {
				ret = true;
			}
		}
	}
	return ret;
}


bool MySQL_Connection::IsAutoCommit() {
	bool ret=false;
	if (mysql) {
		ret = (mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
		if (ret) {
			if (options.last_set_autocommit==0) {
				// it seems we hit bug http://bugs.mysql.com/bug.php?id=66884
				// we last sent SET AUTOCOMMIT = 0 , but the server says it is 1
				// we assume that what we sent last is correct .  #873
				ret = false;
			}
		} else {
			if (options.last_set_autocommit==-1) {
				// if a connection was reset (thus last_set_autocommit==-1)
				// the information related to SERVER_STATUS_AUTOCOMMIT is lost
				// therefore we fall back on the safe assumption that autocommit==1
				ret = true;
			}
		}
	}
	return ret;
}

bool MySQL_Connection::MultiplexDisabled() {
// status_flags stores information about the status of the connection
// can be used to determine if multiplexing can be enabled or not
	bool ret=false;
	if (status_flags & (STATUS_MYSQL_CONNECTION_TRANSACTION|STATUS_MYSQL_CONNECTION_USER_VARIABLE|STATUS_MYSQL_CONNECTION_PREPARED_STATEMENT|STATUS_MYSQL_CONNECTION_LOCK_TABLES|STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE|STATUS_MYSQL_CONNECTION_GET_LOCK|STATUS_MYSQL_CONNECTION_NO_MULTIPLEX|STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0|STATUS_MYSQL_CONNECTION_FOUND_ROWS|STATUS_MYSQL_CONNECTION_NO_BACKSLASH_ESCAPES) ) {
		ret=true;
	}
	if (auto_increment_delay_token) return true;
	return ret;
}

bool MySQL_Connection::IsKeepMultiplexEnabledVariables(char *query_digest_text) {
	if (query_digest_text==NULL) return true;

	char *query_digest_text_filter_select = NULL;
	unsigned long query_digest_text_len=strlen(query_digest_text);
	if (strncasecmp(query_digest_text,"SELECT ",strlen("SELECT "))==0){
		query_digest_text_filter_select=(char*)malloc(query_digest_text_len-7+1);
		memcpy(query_digest_text_filter_select,&query_digest_text[7],query_digest_text_len-7);
		query_digest_text_filter_select[query_digest_text_len-7]='\0';
	} else {
		return false;
	}
	//filter @@session. and @@
	char *match=NULL;
	while (query_digest_text_filter_select && (match = strcasestr(query_digest_text_filter_select,"@@session."))) {
		*match = '\0';
		strcat(query_digest_text_filter_select, match+strlen("@@session."));
	}
	while (query_digest_text_filter_select && (match = strcasestr(query_digest_text_filter_select,"@@"))) {
		*match = '\0';
		strcat(query_digest_text_filter_select, match+strlen("@@"));
	}

	std::vector<char*>query_digest_text_filter_select_v;
	char* query_digest_text_filter_select_tok = NULL;
	if (query_digest_text_filter_select) {
	query_digest_text_filter_select_tok = strtok(query_digest_text_filter_select, ",");
	}
	while(query_digest_text_filter_select_tok){
		//filter "as"/space/alias,such as select @@version as a, @@version b
		while (1){
			char c = *query_digest_text_filter_select_tok;
			if (!isspace(c)){
				break;
			}
			query_digest_text_filter_select_tok++;
		}
		char* match_as;
		match_as=strcasestr(query_digest_text_filter_select_tok," ");
		if(match_as){
			query_digest_text_filter_select_tok[match_as-query_digest_text_filter_select_tok]='\0';
			query_digest_text_filter_select_v.push_back(query_digest_text_filter_select_tok);
		}else{
			query_digest_text_filter_select_v.push_back(query_digest_text_filter_select_tok);
		}
		query_digest_text_filter_select_tok=strtok(NULL, ",");
	}

	std::vector<char*>keep_multiplexing_variables_v;
	char* keep_multiplexing_variables_tmp;
	unsigned long keep_multiplexing_variables_len=strlen(mysql_thread___keep_multiplexing_variables);
	keep_multiplexing_variables_tmp=(char*)malloc(keep_multiplexing_variables_len+1);
	memcpy(keep_multiplexing_variables_tmp, mysql_thread___keep_multiplexing_variables, keep_multiplexing_variables_len);
	keep_multiplexing_variables_tmp[keep_multiplexing_variables_len]='\0';
	char* keep_multiplexing_variables_tok=strtok(keep_multiplexing_variables_tmp, " ,");
	while (keep_multiplexing_variables_tok){
		keep_multiplexing_variables_v.push_back(keep_multiplexing_variables_tok);
		keep_multiplexing_variables_tok=strtok(NULL, " ,");
	}

	for (std::vector<char*>::iterator it=query_digest_text_filter_select_v.begin();it!=query_digest_text_filter_select_v.end();it++){
		bool is_match=false;
		for (std::vector<char*>::iterator it1=keep_multiplexing_variables_v.begin();it1!=keep_multiplexing_variables_v.end();it1++){
			//printf("%s,%s\n",*it,*it1);
			if (strncasecmp(*it,*it1,strlen(*it1))==0){
				is_match=true;
				break;
			}
		}
		if(is_match){
			is_match=false;
			continue;
		}else{
			free(query_digest_text_filter_select);
			free(keep_multiplexing_variables_tmp);
			return false;
		}
	}
	free(query_digest_text_filter_select);
	free(keep_multiplexing_variables_tmp);
	return true;
}

void MySQL_Connection::ProcessQueryAndSetStatusFlags(char *query_digest_text) {
	if (query_digest_text==NULL) return;
	// unknown what to do with multiplex
	int mul=-1;
	if (myds) {
		if (myds->sess) {
			if (myds->sess->qpo) {
				mul=myds->sess->qpo->multiplex;
				if (mul==0) {
					set_status_no_multiplex(true);
				} else {
					if (mul==1) {
						set_status_no_multiplex(false);
					}
				}
			}
		}
	}
	if (get_status_user_variable()==false) { // we search for variables only if not already set
//			if (
//				strncasecmp(query_digest_text,"SELECT @@tx_isolation", strlen("SELECT @@tx_isolation"))
//				&&
//				strncasecmp(query_digest_text,"SELECT @@version", strlen("SELECT @@version"))
		if (strncasecmp(query_digest_text,"SET ",4)==0) {
			// For issue #555 , multiplexing is disabled if --safe-updates is used (see session_vars definition)
			int sqloh = mysql_thread___set_query_lock_on_hostgroup;
			switch (sqloh) {
				case 0: // old algorithm
					if (mul!=2) {
						if (index(query_digest_text,'@')) { // mul = 2 has a special meaning : do not disable multiplex for variables in THIS QUERY ONLY
							if (!IsKeepMultiplexEnabledVariables(query_digest_text)) {
								set_status_user_variable(true);
							}
						} else {
							for (unsigned int i = 0; i < sizeof(session_vars)/sizeof(char *); i++) {
								if (strcasestr(query_digest_text,session_vars[i])!=NULL)  {
									set_status_user_variable(true);
									break;
								}
							}
						}
					}
					break;
				case 1: // new algorithm
					if (myds->sess->locked_on_hostgroup > -1) {
						// locked_on_hostgroup was set, so some variable wasn't parsed
						set_status_user_variable(true);
					}
					break;
				default:
					break;
			}
		} else {
			if (mul!=2 && index(query_digest_text,'@')) { // mul = 2 has a special meaning : do not disable multiplex for variables in THIS QUERY ONLY
				if (!IsKeepMultiplexEnabledVariables(query_digest_text)) {
					set_status_user_variable(true);
				}
			}
		}
	}
	if (get_status_prepared_statement()==false) { // we search if prepared was already executed
		if (!strncasecmp(query_digest_text,"PREPARE ", strlen("PREPARE "))) {
			set_status_prepared_statement(true);
		}
	}
	if (get_status_temporary_table()==false) { // we search for temporary if not already set
		if (!strncasecmp(query_digest_text,"CREATE TEMPORARY TABLE ", strlen("CREATE TEMPORARY TABLE "))) {
			set_status_temporary_table(true);
		}
	}
	if (get_status_lock_tables()==false) { // we search for lock tables only if not already set
		if (!strncasecmp(query_digest_text,"LOCK TABLE", strlen("LOCK TABLE"))) {
			set_status_lock_tables(true);
		}
	}
	if (get_status_lock_tables()==false) { // we search for lock tables only if not already set
		if (!strncasecmp(query_digest_text,"FLUSH TABLES WITH READ LOCK", strlen("FLUSH TABLES WITH READ LOCK"))) { // issue 613
			set_status_lock_tables(true);
		}
	}
	if (get_status_lock_tables()==true) {
		if (!strncasecmp(query_digest_text,"UNLOCK TABLES", strlen("UNLOCK TABLES"))) {
			set_status_lock_tables(false);
		}
	}
	if (get_status_get_lock()==false) { // we search for get_lock if not already set
		if (strcasestr(query_digest_text,"GET_LOCK(")) {
			set_status_get_lock(true);
		}
	}
	if (get_status_found_rows()==false) { // we search for SQL_CALC_FOUND_ROWS if not already set
		if (strcasestr(query_digest_text,"SQL_CALC_FOUND_ROWS")) {
			set_status_found_rows(true);
		}
	}
}

void MySQL_Connection::optimize() {
	if (mysql->net.max_packet > 65536) { // FIXME: temporary, maybe for very long time . This needs to become a global variable
		if ( ( mysql->net.buff == mysql->net.read_pos ) &&  ( mysql->net.read_pos == mysql->net.write_pos ) ) {
			free(mysql->net.buff);
			mysql->net.max_packet=8192;
			mysql->net.buff=(unsigned char *)malloc(mysql->net.max_packet);
			memset(mysql->net.buff,0,mysql->net.max_packet);
			mysql->net.read_pos=mysql->net.buff;
			mysql->net.write_pos=mysql->net.buff;
			mysql->net.buff_end=mysql->net.buff+mysql->net.max_packet;
		}
	}
}

// close_mysql() is a replacement for mysql_close()
// if avoids that a QUIT command stops forever
// FIXME: currently doesn't support encryption and compression
void MySQL_Connection::close_mysql() {
	if ((send_quit) && (mysql->net.pvio) && ret_mysql) {
		char buff[5];
		mysql_hdr myhdr;
		myhdr.pkt_id=0;
		myhdr.pkt_length=1;
		memcpy(buff, &myhdr, sizeof(mysql_hdr));
		buff[4]=0x01;
		int fd=mysql->net.fd;
#ifdef __APPLE__
		int arg_on=1;
		setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, (char *) &arg_on, sizeof(int));
		send(fd, buff, 5, 0);
#else
		send(fd, buff, 5, MSG_NOSIGNAL);
#endif
	}
//	int rc=0;
	mysql_close_no_command(mysql);
}


// this function is identical to async_query() , with the only exception that MyRS should never be set
int MySQL_Connection::async_send_simple_command(short event, char *stmt, unsigned long length) {
	PROXY_TRACE();
	assert(mysql);
	assert(ret_mysql);
	if (
		(parent->status==MYSQL_SERVER_STATUS_OFFLINE_HARD) // the server is OFFLINE as specific by the user
		||
		(parent->status==MYSQL_SERVER_STATUS_SHUNNED && parent->shunned_automatic==true && parent->shunned_and_kill_all_connections==true) // the server is SHUNNED due to a serious issue
	) {
		return -1;
	}
	switch (async_state_machine) {
		case ASYNC_QUERY_END:
			processing_multi_statement=false;	// no matter if we are processing a multi statement or not, we reached the end
			//return 0; <= bug. Do not return here, because we need to reach the if (async_state_machine==ASYNC_QUERY_END) few lines below
			break;
		case ASYNC_IDLE:
			set_query(stmt,length);
			async_state_machine=ASYNC_QUERY_START;
		default:
			handler(event);
			break;
	}
	if (MyRS) {
		// this is a severe mistake, we shouldn't have reach here
		// for now we do not assert but report the error
		proxy_error("Retrieved a resultset while running a simple command. This is an error!! Simple command: %s\n", stmt);
	}
	if (async_state_machine==ASYNC_QUERY_END) {
		compute_unknown_transaction_status();
		if (mysql_errno(mysql)) {
			return -1;
		} else {
			async_state_machine=ASYNC_IDLE;
			return 0;
		}
	}
	if (async_state_machine==ASYNC_NEXT_RESULT_START) {
		// if we reached this point it measn we are processing a multi-statement
		// and we need to exit to give control to MySQL_Session
		processing_multi_statement=true;
		return 2;
	}
	if (processing_multi_statement==true) {
		// we are in the middle of processing a multi-statement
		return 3;
	}
	return 1;
}

void MySQL_Connection::reset() {
	status_flags=0;
	reusable=true;
	options.last_set_autocommit=-1; // never sent
	{ // bug #1160
		options.time_zone_int = 0;
		if (options.time_zone) {
			free(options.time_zone);
			options.time_zone = NULL;
		}
	}
	delete local_stmts;
	local_stmts=new MySQL_STMTs_local_v14(false);
	creation_time = monotonic_time();

	for (auto i = 0; i < SQL_NAME_LAST; i++) {
		variables[i].hash = 0;
		if (variables[i].value) {
			free(variables[i].value);
			variables[i].value = NULL;
		}
	}

	options.isolation_level_int = 0;
	if (options.isolation_level) {
		free (options.isolation_level);
		options.isolation_level = NULL;
		options.isolation_level_sent = false;
	}
	options.tx_isolation_int = 0;
	if (options.tx_isolation) {
		free (options.tx_isolation);
		options.tx_isolation = NULL;
		options.tx_isolation_sent = false;
	}
	options.transaction_read_int = 0;
	if (options.transaction_read) {
		free (options.transaction_read);
		options.transaction_read = NULL;
		options.transaction_read_sent = false;
	}
	options.character_set_results_int = 0;
	if (options.character_set_results) {
		free (options.character_set_results);
		options.character_set_results = NULL;
		options.character_set_results_sent = false;
	}
	options.session_track_gtids_int = 0;
	if (options.session_track_gtids) {
		free (options.session_track_gtids);
		options.session_track_gtids = NULL;
		options.session_track_gtids_sent = false;
	}
	options.sql_auto_is_null_int = 0;
	if (options.sql_auto_is_null) {
		free (options.sql_auto_is_null);
		options.sql_auto_is_null = NULL;
		options.sql_auto_is_null_sent = false;
	}
	options.collation_connection_int = 0;
	if (options.collation_connection) {
		free (options.collation_connection);
		options.collation_connection = NULL;
		options.collation_connection_sent = false;
	}
	options.net_write_timeout_int = 0;
	if (options.net_write_timeout) {
		free (options.net_write_timeout);
		options.net_write_timeout = NULL;
		options.net_write_timeout_sent = false;
	}
	options.max_join_size_int = 0;
	if (options.max_join_size) {
		free (options.max_join_size);
		options.max_join_size = NULL;
		options.max_join_size_sent = false;
	}
	if (options.init_connect) {
		free(options.init_connect);
		options.init_connect = NULL;
		options.init_connect_sent = false;
	}
	auto_increment_delay_token = 0;
	if (options.ldap_user_variable) {
		if (options.ldap_user_variable_value) {
			free(options.ldap_user_variable_value);
			options.ldap_user_variable_value = NULL;
		}
		options.ldap_user_variable = NULL;
		options.ldap_user_variable_sent = false;
	}
}

bool MySQL_Connection::get_gtid(char *buff, uint64_t *trx_id) {
	// note: current implementation for for OWN GTID only!
	bool ret = false;
	if (buff==NULL || trx_id == NULL) {
		return ret;
	}
	if (mysql) {
		if (mysql->net.last_errno==0) { // only if there is no error
			if (mysql->server_status & SERVER_SESSION_STATE_CHANGED) { // only if status changed
				const char *data;
				size_t length;
				if (mysql_session_track_get_first(mysql, SESSION_TRACK_GTIDS, &data, &length) == 0) {
					if (length >= (sizeof(gtid_uuid) - 1)) {
						length = sizeof(gtid_uuid) - 1;
					}
					if (memcmp(gtid_uuid,data,length)) {
						// copy to local buffer in MySQL_Connection
						memcpy(gtid_uuid,data,length);
						gtid_uuid[length]=0;
						// copy to external buffer in MySQL_Backend
						memcpy(buff,data,length);
						buff[length]=0;
						__sync_fetch_and_add(&myds->sess->thread->status_variables.gtid_session_collected,1);
						ret = true;
					}
				}
			}
		}
	}
	return ret;
}
