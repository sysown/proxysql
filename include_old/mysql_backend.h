#ifndef __CLASS_MYSQL_BACKEND_H
#define __CLASS_MYSQL_BACKEND_H
#include "proxysql.h"
#include "cpp.h"

class MySQL_Backend
{
	public:
	int hostgroup_id;
	MySQL_Data_Stream *server_myds;
  mysql_cp_entry_t *server_mycpe;
  bytes_stats_t server_bytes_at_cmd;

	MySQL_Backend();
	void reset();
};

#endif /* __CLASS_MYSQL_BACKEND_H */
