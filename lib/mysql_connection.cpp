#include "proxysql.h"
#include "cpp.h"
#include "SpookyV2.h"

/*
void * MySQL_Connection::operator new(size_t size) {
	return l_alloc(size);
}

void MySQL_Connection::operator delete(void *ptr) {
	l_free(sizeof(MySQL_Connection),ptr);
}
*/

//extern __thread char *mysql_thread___default_schema;

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
	if (myds) {
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
