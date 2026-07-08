#ifndef CLASS_PGSQL_STATIC_HARVESTER_H
#define CLASS_PGSQL_STATIC_HARVESTER_H

#ifdef PROXYSQL40

#include "Discovery_Schema.h"
#include <string>
#include <vector>
#include <memory>
#include <pthread.h>

typedef struct pg_conn PGconn;

class PgSQL_Static_Harvester {
private:
	std::string pgsql_host;
	int pgsql_port;
	std::string pgsql_user;
	std::string pgsql_password;
	std::string pgsql_dbname;
	PGconn* pgsql_conn;
	pthread_mutex_t conn_lock;

	Discovery_Schema* catalog;

	int current_run_id;
	std::string source_dsn;
	std::string server_version;

	int connect_pgsql();
	void disconnect_pgsql();
	int execute_query(const std::string& query, std::vector<std::vector<std::string>>& results);
	std::string get_pgsql_version();
	static bool is_valid_schema_name(const std::string& name);
	// Helper to look up object_id using parameterized query (safe from SQL injection)
	int lookup_object_id(const std::string& schema_name, const std::string& object_name, const char* object_types);

public:
	PgSQL_Static_Harvester(
		const std::string& host,
		int port,
		const std::string& user,
		const std::string& password,
		const std::string& dbname,
		const std::string& catalog_path
	);
	~PgSQL_Static_Harvester();

	int init();
	void close();

	int start_run(const std::string& target_id, const std::string& notes = "");
	int finish_run(const std::string& notes = "");
	int get_run_id() const { return current_run_id; }

	int harvest_schemas(const std::string& only_schema = "");
	int harvest_objects(const std::string& only_schema = "");
	int harvest_columns(const std::string& only_schema = "");
	int harvest_indexes(const std::string& only_schema = "");
	int harvest_foreign_keys(const std::string& only_schema = "");
	int harvest_view_definitions(const std::string& only_schema = "");
	int build_quick_profiles();
	int rebuild_fts_index();

	int run_full_harvest(const std::string& target_id, const std::string& only_schema = "", const std::string& notes = "");
	std::string get_harvest_stats();
	std::string get_harvest_stats(int run_id);
};

#endif /* PROXYSQL40 */
#endif /* CLASS_PGSQL_STATIC_HARVESTER_H */
