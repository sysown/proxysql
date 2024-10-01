#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Data_Stream.h"

void * PgSQL_Backend::operator new(size_t size) {
	return l_alloc(size);
}

void PgSQL_Backend::operator delete(void *ptr) {
	l_free(sizeof(PgSQL_Backend),ptr);
}

PgSQL_Backend::PgSQL_Backend() {
	hostgroup_id=-1;
	server_myds=NULL;
	server_bytes_at_cmd.bytes_recv=0;
	server_bytes_at_cmd.bytes_sent=0;
	memset(gtid_uuid,0,sizeof(gtid_uuid));
	gtid_trxid=0;
}

PgSQL_Backend::~PgSQL_Backend() {
}

void PgSQL_Backend::reset() {
	
	if (server_myds) {
		server_myds->reset_connection();
		delete server_myds;
	}
}
