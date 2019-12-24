#ifndef __PROXYSQL_RESTAPI_H__
#define __PROXYSQL_RESTAPI_H__

#include "proxy_defines.h"
#include "proxysql.h"
#include "cpp.h"
#include <vector>

class SQLite3DB;

class Restapi_Row {
public:
	unsigned int id;
	bool is_active;
	unsigned int interval_ms;
	std::string uri;
	std::string script;
	std::string comment;
	unsigned int version;
	Restapi_Row(unsigned int _id, bool _is_active, unsigned int _in, const std::string& _uri, const std::string& _script, const std::string& _comment);
};

class ProxySQL_Restapi {
	SQLite3DB* admindb;
public:
	ProxySQL_Restapi(SQLite3DB* db);
	virtual ~ProxySQL_Restapi();

	unsigned int last_version;
	unsigned int version;
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_t rwlock;
#else
	rwlock_t rwlock;
#endif
	std::vector<Restapi_Row> Restapi_Rows;
	void update_table(SQLite3_result *result);
	void load_restapi_to_runtime();
	void save_restapi_runtime_to_database(bool);
	void flush_restapi__from_memory_to_disk();
	void flush_restapi__from_disk_to_memory();
};

#endif // #ifndef __PROXYSQL_RESTAPI_H__
