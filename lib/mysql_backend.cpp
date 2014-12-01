#include "proxysql.h"
#include "cpp.h"

extern __thread MySQL_Connection_Pool * MyConnPool;

void * MySQL_Backend::operator new(size_t size) {
  return l_alloc(size);
};

void MySQL_Backend::operator delete(void *ptr) {
  l_free(sizeof(MySQL_Backend),ptr);
};

MySQL_Backend::MySQL_Backend() {
	hostgroup_id=-1;
	server_myds=NULL;
	myconn=NULL;
	server_bytes_at_cmd.bytes_recv=0;
	server_bytes_at_cmd.bytes_sent=0;
};

MySQL_Backend::~MySQL_Backend() {
};

void MySQL_Backend::reset() {
	if (server_myds) {
		//delete server_myds;
		server_myds=NULL;
	}
	if (myconn) {
		if (myconn->reusable==false) {
			//server_myds->myconn=NULL;
			delete myconn;
		} else {
//			MyConnArray *MCA=MyConnPool->MyConnArray_lookup(myconn->mshge->MSptr->address, myconn->myconn.user, myconn->mshge->MSptr->password, myconn->mshge->MSptr->db, myconn->mshge->MSptr->port);
		}
	};
	myconn=NULL;
};

