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
	schemaname=NULL;
	hash=0;
	//schemaname=strdup(mysql_thread___default_schema);
}

MySQL_Connection_userinfo::~MySQL_Connection_userinfo() {
	if (username) free(username);
	if (password) free(password);
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

void MySQL_Connection_userinfo::set(char *u, char *p, char *s) {
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
	compute_hash();
}

void MySQL_Connection_userinfo::set(MySQL_Connection_userinfo *ui) {
	set(ui->username, ui->password, ui->schemaname);
}


bool MySQL_Connection_userinfo::set_schemaname(char *_new, int l) {
	if ((schemaname==NULL) || (strncmp(_new,schemaname,l))) {
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
	compression_pkt_id=0;
	mysql_result=NULL;
	query.ptr=NULL;
	query.length=0;
	largest_query_length=0;
	MyRS=NULL;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Creating new MySQL_Connection %p\n", this);
};

MySQL_Connection::~MySQL_Connection() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Destroying MySQL_Connection %p\n", this);
	if (options.server_version) free(options.server_version);
	if (userinfo) {
		delete userinfo;
		userinfo=NULL;
	}
	if (mysql) {
		async_free_result();
		mysql_close(mysql);
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
};

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

bool MySQL_Connection::get_status_prepared_statement() {
	return status_flags & STATUS_MYSQL_CONNECTION_PREPARED_STATEMENT;
}

// non blocking API
void MySQL_Connection::connect_start() {
	PROXY_TRACE();
	mysql=mysql_init(NULL);
	assert(mysql);
	mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
	unsigned int timeout= 1;
	mysql_options(mysql, MYSQL_OPT_CONNECT_TIMEOUT, (void *)&timeout);
	const CHARSET_INFO * c = proxysql_find_charset_nr(mysql_thread___default_charset);
	if (!c) {
		proxy_error("Not existing charset number %u\n", mysql_thread___default_charset);
		assert(0);
	}
	mysql_options(mysql, MYSQL_SET_CHARSET_NAME, c->csname);
	if (parent->port) {
		async_exit_status=mysql_real_connect_start(&ret_mysql, mysql, parent->address, userinfo->username, userinfo->password, userinfo->schemaname, parent->port, NULL, 0);
	} else {
		async_exit_status=mysql_real_connect_start(&ret_mysql, mysql, "localhost", userinfo->username, userinfo->password, userinfo->schemaname, parent->port, parent->address, 0);
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
	async_exit_status = mysql_change_user_start(&ret_bool,mysql,_ui->username, _ui->password, _ui->schemaname);
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

// FIXME: UTF8 is hardcoded for now, needs to be dynamic
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
				proxy_error("Failed to mysql_real_connect() on %s:%d , %d: %s\n", parent->address, parent->port, mysql_errno(mysql), mysql_error(mysql));
    		NEXT_IMMEDIATE(ASYNC_CONNECT_FAILED);
			} else {
    		NEXT_IMMEDIATE(ASYNC_CONNECT_SUCCESSFUL);
			}
    	break;
		case ASYNC_CONNECT_SUCCESSFUL:
			__sync_fetch_and_add(&parent->connect_OK,1);
			break;
		case ASYNC_CONNECT_FAILED:
			parent->connect_error();
			break;
		case ASYNC_CONNECT_TIMEOUT:
			proxy_error("Connect timeout on %s:%d : %llu - %llu = %llu\n",  parent->address, parent->port, myds->sess->thread->curtime , myds->wait_until, myds->sess->thread->curtime - myds->wait_until);
			parent->connect_error();
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
			ping_cont(event);
			if (async_exit_status) {
				next_event(ASYNC_PING_CONT);
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
				MyRS=new MySQL_ResultSet(&myds->sess->client_myds->myprot, mysql_result, mysql);
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
					NEXT_IMMEDIATE(ASYNC_USE_RESULT_CONT);
				} else {
					MyRS->add_eof();
					NEXT_IMMEDIATE(ASYNC_QUERY_END);
				}
			}
			break;
		case ASYNC_QUERY_END:
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
	int fd;
	wait_events=0;

	if (async_exit_status & MYSQL_WAIT_READ)
		wait_events |= POLLIN;
	if (async_exit_status & MYSQL_WAIT_WRITE)
		wait_events|= POLLOUT;
	if (wait_events)
		fd= mysql_get_socket(mysql);
	else
		fd= -1;
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
int MySQL_Connection::async_query(short event, char *stmt, unsigned long length) {
	PROXY_TRACE();
	assert(mysql);
	assert(ret_mysql);
	if (parent->status==MYSQL_SERVER_STATUS_OFFLINE_HARD)
		return -1;
	switch (async_state_machine) {
		case ASYNC_QUERY_END:
			return 0;
			break;
		case ASYNC_IDLE:
			set_query(stmt,length);
			async_state_machine=ASYNC_QUERY_START;
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
	if (mysql_result) {
		mysql_free_result(mysql_result);
		mysql_result=NULL;
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
