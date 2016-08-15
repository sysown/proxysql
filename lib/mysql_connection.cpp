#include "proxysql.h"
#include "cpp.h"
#include "SpookyV2.h"

extern const CHARSET_INFO * proxysql_find_charset_nr(unsigned int nr);

#define PROXYSQL_USE_RESULT

// Bug https://mariadb.atlassian.net/browse/CONC-136
//int STDCALL mysql_select_db_start(int *ret, MYSQL *mysql, const char *db);
//int STDCALL mysql_select_db_cont(int *ret, MYSQL *mysql, int ready_status);

/*
void * MySQL_Connection::operator new(size_t size) {
	return l_alloc(size);
}

void MySQL_Connection::operator delete(void *ptr) {
	l_free(sizeof(MySQL_Connection),ptr);
}
*/

//extern __thread char *mysql_thread___default_schema;

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


MySQL_Connection_userinfo::MySQL_Connection_userinfo() {
	username=NULL;
	password=NULL;
	sha1_pass=NULL;
	schemaname=NULL;
	hash=0;
	//schemaname=strdup(mysql_thread___default_schema);
}

MySQL_Connection_userinfo::~MySQL_Connection_userinfo() {
	if (username) free(username);
	if (password) free(password);
	if (sha1_pass) free(sha1_pass);
	if (schemaname) free(schemaname);
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
		if (username) free(username);
		username=strdup(u);
	}
	if (p) {
		if (password) free(password);
		password=strdup(p);
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
	if ((schemaname==NULL) || (strncmp(_new,schemaname, (l > _l ? l : _l) ))) {
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
	//memset(&myconn,0,sizeof(MYSQL));
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
	options.compression_min_length=0;
	options.server_version=NULL;
	options.autocommit=true;
	options.init_connect=NULL;
	options.init_connect_sent=false;
	compression_pkt_id=0;
	mysql_result=NULL;
	query.ptr=NULL;
	query.length=0;
	query.stmt=NULL;
	query.stmt_meta=NULL;
	query.stmt_result=NULL;
	largest_query_length=0;
	MyRS=NULL;
	creation_time=0;
	processing_multi_statement=false;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Creating new MySQL_Connection %p\n", this);
	local_stmts=new MySQL_STMTs_local();
};

MySQL_Connection::~MySQL_Connection() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Destroying MySQL_Connection %p\n", this);
	if (options.server_version) free(options.server_version);
	if (options.init_connect) free(options.init_connect);
	if (userinfo) {
		delete userinfo;
		userinfo=NULL;
	}
	if (mysql) {
		// always decrease the counter
		if (ret_mysql)
			__sync_fetch_and_sub(&MyHGM->status.server_connections_connected,1);
		async_free_result();
		close_mysql(); // this take care of closing mysql connection
		mysql=NULL;
	}
//	// FIXME: with the use of mysql client library , this part should be gone.
//	// for now only commenting it to be sure it is not needed 
//	if (myds) {
//		myds->shut_hard();
//	} else {
//		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "MySQL_Connection %p , fd:%d\n", this, fd);
//		shutdown(fd, SHUT_RDWR);
//		close(fd);
//	}
	if (MyRS) {
		delete MyRS;
	}
	if (local_stmts) {
		delete local_stmts;
	}
	if (query.stmt) {
		mysql_stmt_close(query.stmt);
		query.stmt=NULL;
	}
};

bool MySQL_Connection::set_autocommit(bool _ac) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Setting autocommit %d\n", _ac);
	options.autocommit=_ac;
	return _ac;
}

uint8_t MySQL_Connection::set_charset(uint8_t _c) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Setting charset %d\n", _c);
	options.charset=_c;
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

bool MySQL_Connection::get_status_lock_tables() {
	return status_flags & STATUS_MYSQL_CONNECTION_LOCK_TABLES;
}

bool MySQL_Connection::get_status_temporary_table() {
	return status_flags & STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE;
}

bool MySQL_Connection::get_status_prepared_statement() {
	return status_flags & STATUS_MYSQL_CONNECTION_PREPARED_STATEMENT;
}

// non blocking API
void MySQL_Connection::connect_start() {
	PROXY_TRACE();
	mysql=mysql_init(NULL);
	assert(mysql);
	mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
	if (parent->use_ssl) {
		mysql_ssl_set(mysql, mysql_thread___ssl_p2s_key, mysql_thread___ssl_p2s_cert, mysql_thread___ssl_p2s_ca, NULL, mysql_thread___ssl_p2s_cipher);
	}
	unsigned int timeout= 1;
	mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, (void *)&timeout);
	const CHARSET_INFO * c = proxysql_find_charset_nr(mysql_thread___default_charset);
	if (!c) {
		proxy_error("Not existing charset number %u\n", mysql_thread___default_charset);
		assert(0);
	}
	mysql_options(mysql, MYSQL_SET_CHARSET_NAME, c->csname);
	unsigned long client_flags = 0;
	if (mysql_thread___client_found_rows)
		client_flags += CLIENT_FOUND_ROWS;
	if (parent->compression)
		client_flags += CLIENT_COMPRESS;
	client_flags += CLIENT_MULTI_STATEMENTS; // FIXME: add global variable
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
	MySQL_Connection_userinfo *_ui=myds->sess->client_myds->myconn->userinfo;
	char *auth_password=NULL;
	userinfo->set(_ui);	// fix for bug #605
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
	const CHARSET_INFO * c = proxysql_find_charset_nr(options.charset);
	if (!c) {
		proxy_error("Not existing charset number %u\n", options.charset);
		assert(0);
	}
	async_exit_status = mysql_set_character_set_start(&interr,mysql, c->csname);
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
		//mysql_stmt_close(query.stmt);
		query.stmt=NULL;
	}
	//query.ptr=(char *)malloc(length);
	//memcpy(query.ptr,stmt,length);
}

void MySQL_Connection::real_query_start() {
	PROXY_TRACE();
	async_exit_status = mysql_real_query_start(&interr , mysql, query.ptr, query.length);
}

void MySQL_Connection::real_query_cont(short event) {
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
	_rc=mysql_stmt_bind_param(query.stmt, query.stmt_meta->binds); // FIXME : add error handling
	if (_rc) {
	  fprintf(stderr, " mysql_stmt_bind_param() failed: %s\n", mysql_stmt_error(query.stmt));
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

#define NEXT_IMMEDIATE(new_st) do { async_state_machine = new_st; goto handler_again; } while (0)

MDB_ASYNC_ST MySQL_Connection::handler(short event) {
	unsigned int processed_bytes=0;	// issue #527 : this variable will store the amount of bytes processed during this event
	if (mysql==NULL) {
		// it is the first time handler() is being called
		async_state_machine=ASYNC_CONNECT_START;
		myds->wait_until=myds->sess->thread->curtime+mysql_thread___connect_timeout_server*1000;
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
			proxy_error("Connect timeout on %s:%d : %llu - %llu = %llu\n",  parent->address, parent->port, myds->sess->thread->curtime , myds->wait_until, myds->sess->thread->curtime - myds->wait_until);
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
			assert(myds->sess->status==CHANGING_USER_SERVER);
			change_user_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_CHANGE_USER_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_CHANGE_USER_END);
			}
			break;
		case ASYNC_CHANGE_USER_END:
			if (ret_bool) {
				fprintf(stderr,"Failed to mysql_change_user()");
				NEXT_IMMEDIATE(ASYNC_CHANGE_USER_FAILED);
			} else {
				NEXT_IMMEDIATE(ASYNC_CHANGE_USER_SUCCESSFUL);
			}
			break;
		case ASYNC_CHANGE_USER_SUCCESSFUL:
			break;
		case ASYNC_CHANGE_USER_FAILED:
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
			myds->sess->thread->status_variables.queries_backends_bytes_sent+=query.length;
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
//			__sync_fetch_and_add(&parent->bytes_sent,query.length);
//			myds->sess->thread->status_variables.queries_backends_bytes_sent+=query.length;
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
/*
				int row_count= 0;
				fprintf(stdout, "Fetching results ...\n");
				while (!mysql_stmt_fetch(query.stmt))
				{
					row_count++;
					fprintf(stdout, "  row %d\n", row_count);
				}
*/
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
			async_exit_status = mysql_next_result_cont(&interr, mysql, mysql_status(event, true));
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
					MyRS=new MySQL_ResultSet(&myds->sess->client_myds->myprot, mysql_result, mysql);
				} else {
					MyRS=new MySQL_ResultSet(NULL, mysql_result, mysql);
				}
				async_fetch_row_start=false;
				NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
			}
			break;
		case ASYNC_USE_RESULT_CONT:
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
					processed_bytes+=br;	// issue #527 : this variable will store the amount of bytes processed during this event
					if (processed_bytes > (unsigned int)mysql_thread___threshold_resultset_size*8) {
						next_event(ASYNC_USE_RESULT_CONT); // we temporarily pause
					} else {
						NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT); // we continue looping
					}
				} else {
					MyRS->add_eof();
					NEXT_IMMEDIATE(ASYNC_QUERY_END);
				}
			}
			break;
		case ASYNC_QUERY_END:
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
		async_state_machine=ASYNC_IDLE;
		myds->wait_until=0;
		creation_time=myds->sess->thread->curtime;
		return 0;
	}
	handler(event);
	switch (async_state_machine) {
		case ASYNC_CONNECT_SUCCESSFUL:
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



// Returns:
// 0 when the query is completed
// 1 when the query is not completed
// the calling function should check mysql error in mysql struct
int MySQL_Connection::async_query(short event, char *stmt, unsigned long length, MYSQL_STMT **_stmt, stmt_execute_metadata_t *stmt_meta) {
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
		if (mysql_errno(mysql)) {
			return -1;
		} else {
			return 0;
		}
	}
	if (async_state_machine==ASYNC_STMT_EXECUTE_END) {
		query.stmt_meta=NULL;
		async_state_machine=ASYNC_QUERY_END;
		if (mysql_stmt_errno(query.stmt)) {
			return -1;
		} else {
			return 0;
		}
	}
	if (async_state_machine==ASYNC_STMT_PREPARE_SUCCESSFUL || async_state_machine==ASYNC_STMT_PREPARE_FAILED) {
		query.stmt_meta=NULL;
		if (async_state_machine==ASYNC_STMT_PREPARE_FAILED) {
			//mysql_stmt_close(query.stmt);
			//query.stmt=NULL;
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
// the calling function should check mysql error in mysql struct
int MySQL_Connection::async_ping(short event) {
	PROXY_TRACE();
	assert(mysql);
	assert(ret_mysql);
	switch (async_state_machine) {
		case ASYNC_PING_SUCCESSFUL:
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
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_CHANGE_USER_FAILED:
			return -1;
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
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_CHANGE_USER_FAILED:
			return -1;
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
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_SET_AUTOCOMMIT_FAILED:
			return -1;
			break;
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

int MySQL_Connection::async_set_names(short event, uint8_t c) {
	PROXY_TRACE();
	assert(mysql);
	assert(ret_mysql);
	switch (async_state_machine) {
		case ASYNC_SET_NAMES_SUCCESSFUL:
			async_state_machine=ASYNC_IDLE;
			return 0;
			break;
		case ASYNC_SET_NAMES_FAILED:
			return -1;
			break;
		case ASYNC_IDLE:
			set_charset(c);
			async_state_machine=ASYNC_SET_NAMES_START;
		default:
			handler(event);
			break;
	}

	// check again
	switch (async_state_machine) {
		case ASYNC_SET_NAMES_SUCCESSFUL:
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

void MySQL_Connection::async_free_result() {
	PROXY_TRACE();
	assert(mysql);
	//assert(ret_mysql);
	//assert(async_state_machine==ASYNC_QUERY_END);
	if (query.ptr) {
		//free(query.ptr);
		query.ptr=NULL;
		query.length=0;
	}
	if (query.stmt_result) {
		mysql_free_result(query.stmt_result);
		query.stmt_result=NULL;
	}
	if (query.stmt) {
	}
	if (mysql_result) {
		mysql_free_result(mysql_result);
		mysql_result=NULL;
		mysql_stmt_free_result(query.stmt);
	}
	async_state_machine=ASYNC_IDLE;
	if (MyRS) {
		delete MyRS;
		MyRS=NULL;
	}
}

bool MySQL_Connection::IsActiveTransaction() {
	bool ret=false;
	if (mysql) {
		ret = (mysql->server_status & SERVER_STATUS_IN_TRANS);
	}
	return ret;
}

bool MySQL_Connection::IsAutoCommit() {
	bool ret=false;
	if (mysql) {
		ret = (mysql->server_status & SERVER_STATUS_AUTOCOMMIT);
	}
	return ret;
}

bool MySQL_Connection::MultiplexDisabled() {
// status_flags stores information about the status of the connection
// can be used to determine if multiplexing can be enabled or not
	bool ret=false;
	if (status_flags & (STATUS_MYSQL_CONNECTION_TRANSACTION|STATUS_MYSQL_CONNECTION_USER_VARIABLE|STATUS_MYSQL_CONNECTION_PREPARED_STATEMENT|STATUS_MYSQL_CONNECTION_LOCK_TABLES|STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE|STATUS_MYSQL_CONNECTION_GET_LOCK) ) {
		ret=true;
	}
	return ret;
}


void MySQL_Connection::ProcessQueryAndSetStatusFlags(char *query_digest_text) {
	if (query_digest_text==NULL) return;
	if (get_status_user_variable()==false) { // we search for variables only if not already set
		if (index(query_digest_text,'@')) {
			if (
				strncasecmp(query_digest_text,"SELECT @@tx_isolation", strlen("SELECT @@tx_isolation"))
				&&
				strncasecmp(query_digest_text,"SELECT @@version", strlen("SELECT @@version"))
			) {
				set_status_user_variable(true);
			}
		}
		// For issue #555 , multiplexing is disabled if --safe-updates is used
		if (strcasecmp(query_digest_text,"SET SQL_SAFE_UPDATES=?,SQL_SELECT_LIMIT=?,MAX_JOIN_SIZE=?")==0) {
				set_status_user_variable(true);
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
	if ((send_quit) && (mysql->net.vio)) {
		char buff[5];
		mysql_hdr myhdr;
		myhdr.pkt_id=0;
		myhdr.pkt_length=1;
		memcpy(buff, &myhdr, sizeof(mysql_hdr));
		buff[4]=0x01;
		int fd=mysql->net.fd;
		send(fd, buff, 5, MSG_NOSIGNAL);
	}
//	int rc=0;
	mysql_close_no_command(mysql);
/*
	if (mysql->net.vio) {
		rc=shutdown(fd, SHUT_RDWR);
		if (rc) {
			proxy_error("shutdown(): FD=%d , code=%d\n", fd, errno);
			assert(rc==0);
		}
		close(fd);
	}
*/
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
			return 0;
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
