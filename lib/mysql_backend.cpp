#include "proxysql.h"
#include "cpp.h"

extern __thread MySQL_Connection_Pool * MyConnPool;

void * MySQL_Backend::operator new(size_t size) {
	return l_alloc(size);
}

void MySQL_Backend::operator delete(void *ptr) {
	l_free(sizeof(MySQL_Backend),ptr);
}

MySQL_Backend::MySQL_Backend() {
	hostgroup_id=-1;
	server_myds=NULL;
	server_bytes_at_cmd.bytes_recv=0;
	server_bytes_at_cmd.bytes_sent=0;
}

MySQL_Backend::~MySQL_Backend() {
}

void MySQL_Backend::reset() {
	if (server_myds->myconn) {
		if (server_myds->DSS==STATE_READY && server_myds->myconn->reusable==true && ((server_myds->myprot.prot_status & SERVER_STATUS_IN_TRANS)==0)) {
			server_myds->myconn->last_time_used=server_myds->sess->thread->curtime;
			MyHGM->push_MyConn_to_pool(server_myds->myconn);
			server_myds->myconn=NULL;
		} else {
			MyHGM->destroy_MyConn_from_pool(server_myds->myconn);
			server_myds->myconn=NULL;
		}
	};
	if (server_myds) {
		delete server_myds;
	}
}
