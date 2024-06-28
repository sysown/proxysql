#ifndef __CLASS_PGSQL_BACKEND_H
#define __CLASS_PGSQL_BACKEND_H
#include "proxysql.h"
#include "cpp.h"

/*
 * @brief A backend class handling connections and data streams for PostgreSQL clients.
 */
class PgSQL_Backend
{
	public:
	void * operator new(size_t);
	void operator delete(void *);
	int hostgroup_id; //< The ID of the host group this connection belongs to. Set to -1 if uninitialized
	char gtid_uuid[128]; //< An array to store a unique identifier for each transaction : for now unused
	uint64_t gtid_trxid; //< The ID of the current transaction : for now unused
	PgSQL_Data_Stream *server_myds;
	//  mysql_cp_entry_t *server_mycpe;
	bytes_stats_t server_bytes_at_cmd; //< A structure storing the number of bytes received and sent
	//MySQL_Hostgroup_Entry *mshge;
	//MySQL_Connection *myconn;
	PgSQL_Backend();
	~PgSQL_Backend();
	void reset(); //< A method that resets and releases resources associated with this backend instance
};

#endif /* __CLASS_PGSQLL_BACKEND_H */
