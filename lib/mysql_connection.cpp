#include "proxysql.h"
#include "cpp.h"


void * MySQL_Connection::operator new(size_t size) {
	return l_alloc(size);
}

void MySQL_Connection::operator delete(void *ptr) {
	l_free(sizeof(MySQL_Connection),ptr);
}

MySQL_Connection::MySQL_Connection() {
	memset(&myconn,0,sizeof(MYSQL));
	MCA=NULL;
	mshge=NULL;
	myds=NULL;
	expire=0;
	reusable=false;
};

MySQL_Connection::~MySQL_Connection() {
	if (myconn.host) free(myconn.host);
/*
	if (myconn.user) free(myconn.user);
	if (myconn.passwd) free(myconn.passwd);
	if (myconn.db) free(myconn.db);
*/
	if (myconn.user) l_free_string(myconn.user);
	if (myconn.passwd) l_free_string(myconn.passwd);
	if (myconn.db) l_free_string(myconn.db);

	if (myconn.unix_socket) free(myconn.unix_socket);
	//if (myconn.server_version) free(myconn.server_version);
	if (myconn.host_info) free(myconn.host_info);
	if (myconn.info) free(myconn.info);
	if (myconn.server_version) l_free_string(myconn.server_version);
	//if (myconn.charset) free(const_cast<charset_info_st *>(myconn.charset));
	if (myconn.charset) l_free(sizeof(charset_info_st), const_cast<charset_info_st *>(myconn.charset));
//	if (myconn.charset) free(myconn.charset);
	if (mshge) {
	__sync_add_and_fetch(&mshge->references,-1);
	};
};

void MySQL_Connection::set_mshge(MySQL_Hostgroup_Entry *_mshge) {
	mshge=_mshge;
	__sync_add_and_fetch(&mshge->references,1);
};

void MySQL_Connection::free_mshge() {
	__sync_add_and_fetch(&mshge->references,-1);
	mshge=NULL;
};

int MySQL_Connection::assign_mshge(unsigned int hid) { // FIXME
/*	FIXME
		a) shouldn't always return 0
		b) MSHGE_find should get a random server
*/
	MyHGH->rdlock();
	if (mshge) { free_mshge(); }
	MySQL_Hostgroup_Entry *_mshge=MyHGH->MSHGE_find(hid,(char *)"127.0.0.1", 3306);
	assert(_mshge);
	if (_mshge) {
		set_mshge(_mshge);
	}
	MyHGH->rdunlock();
	return 0;
};
