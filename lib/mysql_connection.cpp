#include "proxysql.h"
#include "cpp.h"
#include "SpookyV2.h"

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
mysql_status(short event) {
	int status= 0;
	if (event & POLLIN)
		status|= MYSQL_WAIT_READ;
	if (event & POLLOUT)
		status|= MYSQL_WAIT_WRITE;
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
	char *buf=(char *)malloc(l);
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
		if (schemaname) free(schemaname);
		schemaname=(char *)malloc(l+1);
		memcpy(schemaname,_new,l);
		schemaname[l]=0;
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
		mysql_close(mysql);
		mysql=NULL;
	}
	if (myds) { // FIXME: with the use of mysql client library , this part should be gone 
		myds->shut_hard();
	} else {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "MySQL_Connection %p , fd:%d\n", this, fd);
		shutdown(fd, SHUT_RDWR);
		close(fd);
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
	mysql=mysql_init(NULL);
	assert(mysql);
	mysql_options(mysql, MYSQL_OPT_NONBLOCK, 0);
	if (parent->port) {
		async_exit_status=mysql_real_connect_start(&ret_mysql, mysql, parent->address, userinfo->username, userinfo->password, userinfo->schemaname, parent->port, NULL, 0);
	} else {
		async_exit_status=mysql_real_connect_start(&ret_mysql, mysql, "localhost", userinfo->username, userinfo->password, userinfo->schemaname, parent->port, parent->address, 0);
	}
	fd=mysql_get_socket(mysql);
}

void MySQL_Connection::connect_cont(short event) {
	async_exit_status = mysql_real_connect_cont(&ret_mysql, mysql, mysql_status(event));
}

void MySQL_Connection::ping_start() {
	async_exit_status = mysql_ping_start(&interr,mysql);
}

void MySQL_Connection::ping_cont(short event) {
	async_exit_status = mysql_ping_cont(&interr,mysql, mysql_status(event));
}

void MySQL_Connection::initdb_start() {
	async_exit_status = mysql_select_db_start(&interr,mysql,userinfo->schemaname);
}

void MySQL_Connection::initdb_cont(short event) {
	async_exit_status = mysql_select_db_cont(&interr,mysql, mysql_status(event));
}

// FIXME: UTF8 is hardcoded for now, needs to be dynamic
void MySQL_Connection::set_names_start() {
	async_exit_status = mysql_set_character_set_start(&interr,mysql,"UTF8");
}

void MySQL_Connection::set_names_cont(short event) {
	async_exit_status = mysql_set_character_set_cont(&interr,mysql, mysql_status(event));
}

#define NEXT_IMMEDIATE(new_st) do { async_state_machine = new_st; goto handler_again; } while (0)

MDB_ASYNC_ST MySQL_Connection::handler(short event) {
	if (mysql==NULL) {
		// it is the first time handler() is being called
		async_state_machine=ASYNC_CONNECT_START;
	}
handler_again:
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
			connect_cont(event);
			if (async_exit_status) {
      	next_event(ASYNC_CONNECT_CONT);
			} else {
				NEXT_IMMEDIATE(ASYNC_CONNECT_END);
			}
    break;
			break;
		case ASYNC_CONNECT_END:
			if (!ret_mysql) {
				fprintf(stderr,"Failed to mysql_real_connect()");
    		NEXT_IMMEDIATE(ASYNC_CONNECT_FAILED);
			} else {
    		NEXT_IMMEDIATE(ASYNC_CONNECT_SUCCESSFUL);
			}
    	break;
		case ASYNC_CONNECT_SUCCESSFUL:
			break;
		case ASYNC_CONNECT_FAILED:
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
	async_state_machine = new_st;
};
