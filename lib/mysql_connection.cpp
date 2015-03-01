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
	MCA=NULL;
	//mshge=NULL;
	myds=NULL;
	inserted_into_pool=0;
	reusable=false;
	parent=NULL;
	userinfo=new MySQL_Connection_userinfo();
	fd=-1;
	options.server_version=NULL;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Creating new MySQL_Connection %p\n", this);
};

MySQL_Connection::~MySQL_Connection() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Destroying MySQL_Connection %p\n", this);
	//if (myconn.host) free(myconn.host);
	//if (myconn.user) free(myconn.user);
	//if (myconn.passwd) free(myconn.passwd);
	//if (myconn.db) free(myconn.db);
/*
	if (myconn.user) l_free_string(myconn.user);
	if (myconn.passwd) l_free_string(myconn.passwd);
	if (myconn.db) l_free_string(myconn.db);
*/
	//if (myconn.unix_socket) free(myconn.unix_socket);
	if (options.server_version) free(options.server_version);
	//if (myconn.host_info) free(myconn.host_info);
	//if (myconn.info) free(myconn.info);
//	if (myconn.server_version) l_free_string(myconn.server_version);
	//if (myconn.charset) free(const_cast<charset_info_st *>(myconn.charset));
//	if (myconn.charset) l_free(sizeof(charset_info_st), const_cast<charset_info_st *>(myconn.charset));
//	if (myconn.charset) free(myconn.charset);
//	if (mshge) {
//	__sync_add_and_fetch(&mshge->references,-1);
//	};
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

MyConnArray * MySQL_Connection::set_MCA(MySQL_Connection_Pool *_MyConnPool, const char *hostname, const char *username, const char *password, const char *db, unsigned int port) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "MySQL_Connection_Pool=%p, Host=%s, user=%s, pass=%s, db=%s, port=%d\n", _MyConnPool, hostname, username, password, db, port);
	MCA=_MyConnPool->MyConnArray_lookup(hostname, username, password, db, port);
	assert(MCA);
	return MCA;
}

bool MySQL_Connection::return_to_connection_pool() {
	assert(MCA);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Returning MySQL_Connection %p at MCA=%p\n", this, MCA);
	MCA->add(this);
	return true;
}

/*
void MySQL_Connection::set_mshge(MySQL_Hostgroup_Entry *_mshge) {
	mshge=_mshge;
	__sync_add_and_fetch(&mshge->references,1);
};

void MySQL_Connection::free_mshge() {
	__sync_add_and_fetch(&mshge->references,-1);
	mshge=NULL;
};
*/
//int MySQL_Connection::assign_mshge(unsigned int hid) { // FIXME
/*	FIXME
		a) shouldn't always return 0
		b) MSHGE_find should get a random server
*/
	//MyHGH->rdlock();
//	if (mshge) { free_mshge(); }
	//MySQL_Hostgroup_Entry *_mshge=MyHGH->MSHGE_find(hid,(char *)"127.0.0.1", 3306);
	//MySQL_Hostgroup_Entry *_mshge=MyHGH->get_random_hostgroup_entry(hid);
	//assert(_mshge);
	//if (_mshge) {
	//	set_mshge(_mshge);
	//}
	//MyHGH->rdunlock();
//	return 0;
//};

bool MySQL_Connection::is_expired(unsigned long long timeout) {
// FIXME: here the check should be a sanity check
// FIXME: for now this is just a temporary (and stupid) check
	return false;
}
