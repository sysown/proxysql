#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Data_Stream.h"

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
	memset(gtid_uuid,0,sizeof(gtid_uuid));
	gtid_trxid=0;
}

MySQL_Backend::~MySQL_Backend() {
}

void MySQL_Backend::reset() {
	
	if (server_myds) {
		server_myds->reset_connection();
		delete server_myds;
	}
}
