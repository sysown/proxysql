#include "proxysql_restapi.h"
#include "proxysql.h"
#include "proxysql_atomic.h"
#include "cpp.h"

#include <sstream>

ProxySQL_Restapi::ProxySQL_Restapi(SQLite3DB* db) {
	assert(db);

	admindb = db;	
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_init(&rwlock,NULL);
#else
	spinlock_rwlock_init(&rwlock);
#endif
	version=0;
}


ProxySQL_Restapi::~ProxySQL_Restapi() {}

void ProxySQL_Restapi::update_table(SQLite3_result *resultset) {
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&rwlock);
#else
	spin_wrlock(&rwlock);
#endif
	// delete all current rows
	Restapi_Rows.clear();
	for (auto r : resultset->rows) {
		unsigned int id = strtoul(r->fields[0], NULL, 10);
		bool is_active=false;
		if (atoi(r->fields[1])) {
			is_active=true;
		}
		unsigned int interval_ms=strtoul(r->fields[2], NULL, 10);
		Restapi_Rows.push_back({id, is_active, interval_ms, r->fields[3], r->fields[4], r->fields[5]});
	}

	// increase version
	__sync_fetch_and_add(&version,1);
	// unlock
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_unlock(&rwlock);
#else
	spin_wrunlock(&rwlock);
#endif
}

void ProxySQL_Restapi::flush_restapi__from_disk_to_memory() {
	admindb->wrlock();
	admindb->execute("DELETE FROM main.restapi_routes");
	admindb->execute("INSERT INTO main.restapi_routes SELECT * FROM disk.restapi_routes");
	admindb->wrunlock();
}

void ProxySQL_Restapi::flush_restapi__from_memory_to_disk() {
	admindb->wrlock();
	admindb->execute("DELETE FROM disk.restapi_routes");
	admindb->execute("INSERT INTO disk.restapi_routes SELECT * FROM main.restapi_routes");
	admindb->wrunlock();
}

void ProxySQL_Restapi::save_restapi_runtime_to_database(bool _runtime) {
	const char *query = _runtime ? "DELETE FROM main.runtime_restapi_routes" : "DELETE FROM main.restapi_routes";
	proxy_debug(PROXY_DEBUG_ADMIN, 4, "%s\n", query);
	admindb->execute(query);
	// read lock the scheduler
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_rdlock(&rwlock);
#else
	spin_rdlock(&rwlock);
#endif
	const char* table = _runtime ? " runtime_restapi_routes " : " restapi_routes ";
	for (auto r : Restapi_Rows) {
		std::stringstream ss;
		ss << "INSERT INTO " << table << " VALUES(" << r.id << "," <<  r.is_active << ","
			<< r.interval_ms << ",'" << r.uri << "','" << r.script << "','" << r.comment << "')";

		admindb->execute(ss.str().c_str());
	}
	// unlock the scheduler
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_unlock(&rwlock);
#else
	spin_rdunlock(&rwlock);
#endif
}

void ProxySQL_Restapi::load_restapi_to_runtime() {
	char *error=NULL;
	int cols=0;
	int affected_rows=0;
	SQLite3_result *resultset=NULL;
	char *query=(char *)"SELECT * FROM restapi_routes";
	admindb->execute_statement(query, &error , &cols , &affected_rows , &resultset);
	if (error) {
		proxy_error("Error on %s : %s\n", query, error);
	} else {
		update_table(resultset);
	}
	if (resultset) delete resultset;
	resultset=NULL;
}


