#include "proxysql.h"
#include "cpp.h"

MySQL_Backend::MySQL_Backend() {
	hostgroup_id=-1;
	server_myds=NULL;
	server_mycpe=NULL;
	server_bytes_at_cmd.bytes_recv=0;
	server_bytes_at_cmd.bytes_sent=0;
}

void MySQL_Backend::reset() {
	
}
