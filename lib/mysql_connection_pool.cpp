#include "proxysql.h"
#include "cpp.h"




MyConnArray::MyConnArray(const char *__hostname, const char *__username, const char *__password, const char *__db, unsigned int __port) {
	hostname=strdup(__hostname);
	username=strdup(__username);
	password=strdup(__password);
	db=strdup(__db);
	port=__port;
	free_conns= new PtrArray();
}

MyConnArray * MyConnArray::match(const char *__hostname, const char *__username, const char *__password, const char *__db, unsigned int __port) {
	MyConnArray *ret=NULL;
	if (
		(strcmp(hostname,__hostname)==0) &&
		(strcmp(username,__username)==0) &&
		(strcmp(password,__password)==0) &&
		(strcmp(db,__db)==0) &&
		(port==__port)
	) { // we found the matching hostname/username/password/port
		ret=this;
	}
	return ret;
}

MyConnArray::~MyConnArray() {
	delete free_conns;
}

void MyConnArray::add(MySQL_Connection *myc) {
	myc->MCA=this;
	free_conns->add((void *)myc);
}

MySQL_Connection * MyConnArray::MyConn_find() {
	unsigned int l;
	MySQL_Connection *myc=NULL;
	MySQL_Connection *_myc_tmp=NULL;
	for (l=0; l<free_conns->len; l++) {
		_myc_tmp=(MySQL_Connection *)free_conns->index(l);
		if (_myc_tmp->is_expired(0)==false) { // FIXME: shouldn't pass 0
			myc=(MySQL_Connection *)free_conns->remove_index_fast(l);
			break;
		}
	}
	return myc;
}

MySQL_Connection * MySQL_Connection_Pool::MySQL_Connection_lookup(MyConnArray *MCA) {
	MySQL_Connection *myc=NULL;
	myc=MCA->MyConn_find();
	return myc;
}

MySQL_Connection * MySQL_Connection_Pool::MySQL_Connection_lookup(const char *hostname, const char *username, const char *password, const char *db, unsigned int port) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Host=%s, user=%s, pass=%s, db=%s, port=%d\n", hostname, username, password, db, port);
	MySQL_Connection *myc=NULL;
	MyConnArray *MCA=MyConnArray_find(hostname, username, password, db, port);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Found MCA=%p\n", MCA);
	if (MCA) {
		myc=MCA->MyConn_find();
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Returning MySQL_Connection=%p\n", myc);
	return myc;
}

MyConnArray * MySQL_Connection_Pool::MyConnArray_find(const char *hostname, const char *username, const char *password, const char *db, unsigned int port) {
	unsigned int l;
	MyConnArray *rc=NULL;
	for (l=0; l<MyConnArrays->len; l++) {
		MyConnArray *mca=(MyConnArray *)MyConnArrays->index(l);
		if (mca->match(hostname,username,password,db,port)) { // we found the matching hostname/username/password/port
			rc=mca;
			break;
		}
	}
	return rc;
}

MyConnArray * MySQL_Connection_Pool::MyConnArray_create(const char *hostname, const char *username, const char *password, const char *db, unsigned int port) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Host=%s, user=%s, pass=%s, db=%s, port=%d\n", hostname, username, password, db, port);
	MyConnArray *MCA= new MyConnArray(hostname, username, password, db, port);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Created MCA=%p\n", MCA);
	MyConnArrays->add(MCA);
	return MCA;
}

MyConnArray * MySQL_Connection_Pool::MyConnArray_lookup(const char *hostname, const char *username, const char *password, const char *db, unsigned int port) {
	MyConnArray *MCA=NULL;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Host=%s, user=%s, pass=%s, db=%s, port=%d\n", hostname, username, password, db, port);
	if (shared) {
		spin_lock(&mutex);
	}
	MCA=MyConnArray_find(hostname, username, password, db, port);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Found MCA=%p\n", MCA);
	if (MCA==NULL) {
		MCA=MyConnArray_create(hostname, username, password, db, port);
	}
	if (shared) {
		spin_unlock(&mutex);
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Returning MCA=%p\n", MCA);
	return MCA;
}

MySQL_Connection_Pool::MySQL_Connection_Pool(bool _shared) {
	shared=_shared;
	spinlock_init(&mutex);
	MyConnArrays= new PtrArray();
}

MySQL_Connection_Pool::~MySQL_Connection_Pool() {
	// TODO: destroy every entry
	delete MyConnArrays;
}
