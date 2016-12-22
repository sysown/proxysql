#include "mysql_backend.h"

#include "MySQL_Session.h"
#include "MySQL_Thread.h"

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
	if (server_myds && server_myds->myconn) {
		MySQL_Connection *mc=server_myds->myconn;
		if (mysql_thread___multiplexing && (server_myds->DSS==STATE_MARIADB_GENERIC || server_myds->DSS==STATE_READY) && mc->reusable==true && mc->IsActiveTransaction()==false && mc->MultiplexDisabled()==false) {
			server_myds->myconn->last_time_used=server_myds->sess->thread->curtime;
			server_myds->return_MySQL_Connection_To_Pool();
		} else {
			server_myds->destroy_MySQL_Connection_From_Pool(true);
		}
	};
	//if (mshge) {
		// FIXME: what to do with it?
	//}
	if (server_myds) {
		delete server_myds;
	}
}
