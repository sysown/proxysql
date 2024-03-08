#ifndef __CLASS_POSTGRESQL_BACKEND_H
#define __CLASS_POSTGRESQL_BACKEND_H
#include "proxysql.h"
#include "cpp.h"


class PgSQL_Backend
{
	public:
	void * operator new(size_t);
	void operator delete(void *);
	int hostgroup_id;
	char gtid_uuid[128];
	uint64_t gtid_trxid;
	PgSQL_Data_Stream *server_myds;
	//  mysql_cp_entry_t *server_mycpe;
	bytes_stats_t server_bytes_at_cmd;
	//MySQL_Hostgroup_Entry *mshge;
	//MySQL_Connection *myconn;
	PgSQL_Backend();
	~PgSQL_Backend();
	void reset();
};

#endif /* __CLASS_POSTGRESQL_BACKEND_H */
