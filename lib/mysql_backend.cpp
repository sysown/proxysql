#include "proxysql.h"
#include "cpp.h"
#include "ProxySQL_Data_Stream.h"
#include "MySQL_Data_Stream.h"

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
	if (server_myds && server_myds->myconn) {
		MySQL_Connection *mc=server_myds->myconn;
		if (mysql_thread___multiplexing && (server_myds->DSS==STATE_MARIADB_GENERIC || server_myds->DSS==STATE_READY) && mc->reusable==true && mc->IsActiveTransaction()==false && mc->MultiplexDisabled()==false && mc->async_state_machine==ASYNC_IDLE) {
			server_myds->myconn->last_time_used=server_myds->sess->thread->curtime;
			server_myds->return_MySQL_Connection_To_Pool();
		} else {
			if (server_myds->sess && server_myds->sess->session_fast_forward == false) {
				server_myds->destroy_MySQL_Connection_From_Pool(true);
			} else {
				server_myds->destroy_MySQL_Connection_From_Pool(false);
			}
		}
	};
	if (server_myds) {
		delete server_myds;
	}
}
