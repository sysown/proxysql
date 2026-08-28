#ifdef PROXYSQL40

#include "PgSQL_Static_Harvester.h"
#include "proxysql.h"
#include "cpp.h"

#include <libpq-fe.h>
#include <sstream>
#include <map>
#include <algorithm>
#include <cctype>
#include "../deps/json/json.hpp"

using json = nlohmann::json;

PgSQL_Static_Harvester::PgSQL_Static_Harvester(
	const std::string& host,
	int port,
	const std::string& user,
	const std::string& password,
	const std::string& dbname,
	const std::string& catalog_path
) : pgsql_host(host),
    pgsql_port(port),
    pgsql_user(user),
    pgsql_password(password),
    pgsql_dbname(dbname),
    pgsql_conn(NULL),
    catalog(NULL),
    current_run_id(-1)
{
	pthread_mutex_init(&conn_lock, NULL);
	catalog = new Discovery_Schema(catalog_path);
}

PgSQL_Static_Harvester::~PgSQL_Static_Harvester() {
	close();
	if (catalog) {
		delete catalog;
		catalog = NULL;
	}
	pthread_mutex_destroy(&conn_lock);
}

int PgSQL_Static_Harvester::init() {
	if (catalog->init()) {
		proxy_error("PgSQL_Static_Harvester: Failed to initialize catalog\n");
		return -1;
	}
	return 0;
}

void PgSQL_Static_Harvester::close() {
	disconnect_pgsql();
}

int PgSQL_Static_Harvester::connect_pgsql() {
	pthread_mutex_lock(&conn_lock);

	if (pgsql_conn) {
		pthread_mutex_unlock(&conn_lock);
		return 0;
	}

	std::ostringstream conninfo;
	conninfo << "host=" << pgsql_host
	         << " port=" << pgsql_port
	         << " user=" << pgsql_user
	         << " password=" << pgsql_password
	         << " connect_timeout=30";
	if (!pgsql_dbname.empty()) {
		conninfo << " dbname=" << pgsql_dbname;
	}

	pgsql_conn = PQconnectdb(conninfo.str().c_str());
	if (pgsql_conn == NULL || PQstatus(pgsql_conn) != CONNECTION_OK) {
		proxy_error("PgSQL_Static_Harvester: PQconnectdb failed: %s\n",
			pgsql_conn ? PQerrorMessage(pgsql_conn) : "NULL connection");
		if (pgsql_conn) {
			PQfinish(pgsql_conn);
			pgsql_conn = NULL;
		}
		pthread_mutex_unlock(&conn_lock);
		return -1;
	}

	server_version = get_pgsql_version();
	source_dsn = "pgsql://" + pgsql_user + "@" + pgsql_host + ":" + std::to_string(pgsql_port) + "/" + pgsql_dbname;

	proxy_info("PgSQL_Static_Harvester: Connected to PostgreSQL %s at %s:%d\n",
		server_version.c_str(), pgsql_host.c_str(), pgsql_port);

	pthread_mutex_unlock(&conn_lock);
	return 0;
}

void PgSQL_Static_Harvester::disconnect_pgsql() {
	pthread_mutex_lock(&conn_lock);
	if (pgsql_conn) {
		PQfinish(pgsql_conn);
		pgsql_conn = NULL;
	}
	pthread_mutex_unlock(&conn_lock);
}

int PgSQL_Static_Harvester::execute_query(const std::string& query, std::vector<std::vector<std::string>>& results) {
	if (!pgsql_conn) {
		proxy_error("PgSQL_Static_Harvester: Not connected to PostgreSQL\n");
		return -1;
	}

	PGresult* res = PQexec(pgsql_conn, query.c_str());
	if (!res) {
		proxy_error("PgSQL_Static_Harvester: PQexec returned NULL\n");
		return -1;
	}
	ExecStatusType st = PQresultStatus(res);
	if (st != PGRES_TUPLES_OK && st != PGRES_COMMAND_OK) {
		proxy_error("PgSQL_Static_Harvester: Query failed: %s\n", PQresultErrorMessage(res));
		PQclear(res);
		return -1;
	}
	if (st == PGRES_COMMAND_OK) {
		PQclear(res);
		return 0;
	}

	int nrows = PQntuples(res);
	int ncols = PQnfields(res);
	results.clear();
	results.reserve(nrows);
	for (int r = 0; r < nrows; r++) {
		std::vector<std::string> row;
		row.reserve(ncols);
		for (int c = 0; c < ncols; c++) {
			row.push_back(PQgetisnull(res, r, c) ? "" : PQgetvalue(res, r, c));
		}
		results.push_back(row);
	}
	PQclear(res);
	return 0;
}

std::string PgSQL_Static_Harvester::get_pgsql_version() {
	std::vector<std::vector<std::string>> rows;
	if (execute_query("SELECT version();", rows) == 0 && !rows.empty() && !rows[0].empty()) {
		return rows[0][0];
	}
	return "";
}

bool PgSQL_Static_Harvester::is_valid_schema_name(const std::string& name) {
	if (name.empty()) {
		return true;
	}
	for (char c : name) {
		if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_' && c != '$') {
			return false;
		}
	}
	return true;
}

// Helper function to look up object_id using parameterized queries.
// This is defense-in-depth: schema_name and object_name are already validated
// by is_valid_schema_name(), but using parameterized queries ensures complete
// protection against SQL injection for the catalog database.
int PgSQL_Static_Harvester::lookup_object_id(const std::string& schema_name, const std::string& object_name, const char* object_types) {
	if (!catalog || !catalog->get_db()) return -1;

	int rc = SQLITE_OK;
	sqlite3_stmt* stmt = NULL;

	// Note: object_types parameter is used for future extensibility but currently
	// we only query for 'table' and 'view' types which covers all current use cases.
	// The parameter is kept for API consistency with the header declaration.
	(void)object_types;

	auto [prep_rc, stmt_unique] = catalog->get_db()->prepare_v2(
		"SELECT object_id FROM objects WHERE run_id=?1 AND schema_name=?2 AND object_name=?3 AND object_type IN ('table','view') LIMIT 1;"
	);
	stmt = stmt_unique.get();
	if (prep_rc != SQLITE_OK) {
		proxy_error("PgSQL_Static_Harvester: Failed to prepare object lookup statement\n");
		return -1;
	}

	(*proxy_sqlite3_bind_int64)(stmt, 1, current_run_id);
	(*proxy_sqlite3_bind_text)(stmt, 2, schema_name.c_str(), -1, SQLITE_TRANSIENT);
	(*proxy_sqlite3_bind_text)(stmt, 3, object_name.c_str(), -1, SQLITE_TRANSIENT);

	SAFE_SQLITE3_STEP2(stmt);
	int object_id = -1;
	if (rc == SQLITE_ROW) {
		object_id = (*proxy_sqlite3_column_int)(stmt, 0);
	}
	return object_id;
}

int PgSQL_Static_Harvester::start_run(const std::string& target_id, const std::string& notes) {
	if (current_run_id >= 0) {
		proxy_error("PgSQL_Static_Harvester: Run already active (run_id=%d)\n", current_run_id);
		return -1;
	}
	if (connect_pgsql()) {
		return -1;
	}

	current_run_id = catalog->create_run(target_id, "pgsql", source_dsn, server_version, notes);
	if (current_run_id < 0) {
		proxy_error("PgSQL_Static_Harvester: Failed to create run\n");
		return -1;
	}
	proxy_info("PgSQL_Static_Harvester: Started run_id=%d\n", current_run_id);
	return current_run_id;
}

int PgSQL_Static_Harvester::finish_run(const std::string& notes) {
	if (current_run_id < 0) {
		proxy_error("PgSQL_Static_Harvester: No active run\n");
		return -1;
	}
	int rc = catalog->finish_run(current_run_id, notes);
	if (rc) {
		proxy_error("PgSQL_Static_Harvester: Failed to finish run\n");
		return -1;
	}
	proxy_info("PgSQL_Static_Harvester: Finished run_id=%d\n", current_run_id);
	current_run_id = -1;
	return 0;
}

int PgSQL_Static_Harvester::harvest_schemas(const std::string& only_schema) {
	if (current_run_id < 0) {
		return -1;
	}
	if (!is_valid_schema_name(only_schema)) {
		return -1;
	}

	std::ostringstream sql;
	sql << "SELECT schema_name, COALESCE(default_character_set_name,''), '' "
	    << "FROM information_schema.schemata "
	    << "WHERE schema_name NOT IN ('pg_catalog','information_schema') "
	    << "AND schema_name NOT LIKE 'pg_toast%'";
	if (!only_schema.empty()) {
		sql << " AND schema_name='" << only_schema << "'";
	}
	sql << " ORDER BY schema_name";

	std::vector<std::vector<std::string>> rows;
	if (execute_query(sql.str(), rows)) {
		return -1;
	}

	int count = 0;
	for (const auto& r : rows) {
		if (r.size() < 3) continue;
		if (catalog->insert_schema(current_run_id, r[0], r[1], r[2]) >= 0) {
			count++;
		}
	}
	return count;
}

int PgSQL_Static_Harvester::harvest_objects(const std::string& only_schema) {
	if (current_run_id < 0) {
		return -1;
	}
	if (!is_valid_schema_name(only_schema)) {
		return -1;
	}

	std::vector<std::vector<std::string>> rows;
	std::ostringstream sql_tables;
	sql_tables << "SELECT table_schema, table_name, "
	           << "CASE WHEN table_type='BASE TABLE' THEN 'table' ELSE 'view' END "
	           << "FROM information_schema.tables "
	           << "WHERE table_schema NOT IN ('pg_catalog','information_schema') "
	           << "AND table_schema NOT LIKE 'pg_toast%'";
	if (!only_schema.empty()) {
		sql_tables << " AND table_schema='" << only_schema << "'";
	}
	if (execute_query(sql_tables.str(), rows)) {
		return -1;
	}

	int count = 0;
	for (const auto& r : rows) {
		if (r.size() < 3) continue;
		if (catalog->insert_object(
			current_run_id, r[0], r[1], r[2],
			"", 0, 0, 0, "", "", "", ""
		) >= 0) {
			count++;
		}
	}

	rows.clear();
	std::ostringstream sql_routines;
	sql_routines << "SELECT routine_schema, routine_name, 'routine', COALESCE(routine_definition,'') "
	             << "FROM information_schema.routines "
	             << "WHERE routine_schema NOT IN ('pg_catalog','information_schema')";
	if (!only_schema.empty()) {
		sql_routines << " AND routine_schema='" << only_schema << "'";
	}
	if (execute_query(sql_routines.str(), rows) == 0) {
		for (const auto& r : rows) {
			if (r.size() < 4) continue;
			if (catalog->insert_object(
				current_run_id, r[0], r[1], r[2],
				"", 0, 0, 0, "", "", "", r[3]
			) >= 0) {
				count++;
			}
		}
	}

	rows.clear();
	std::ostringstream sql_triggers;
	sql_triggers << "SELECT trigger_schema, trigger_name, 'trigger', COALESCE(action_statement,'') "
	             << "FROM information_schema.triggers "
	             << "WHERE trigger_schema NOT IN ('pg_catalog','information_schema')";
	if (!only_schema.empty()) {
		sql_triggers << " AND trigger_schema='" << only_schema << "'";
	}
	if (execute_query(sql_triggers.str(), rows) == 0) {
		for (const auto& r : rows) {
			if (r.size() < 4) continue;
			if (catalog->insert_object(
				current_run_id, r[0], r[1], r[2],
				"", 0, 0, 0, "", "", "", r[3]
			) >= 0) {
				count++;
			}
		}
	}

	return count;
}

int PgSQL_Static_Harvester::harvest_columns(const std::string& only_schema) {
	if (current_run_id < 0) return -1;
	if (!is_valid_schema_name(only_schema)) return -1;

	std::ostringstream sql;
	sql << "SELECT table_schema, table_name, ordinal_position, column_name, data_type, "
	    << "COALESCE(udt_name,''), CASE WHEN is_nullable='YES' THEN 1 ELSE 0 END, "
	    << "COALESCE(column_default,''), '', COALESCE(character_set_name,''), "
	    << "COALESCE(collation_name,''), COALESCE(column_name,'') "
	    << "FROM information_schema.columns "
	    << "WHERE table_schema NOT IN ('pg_catalog','information_schema') "
	    << "AND table_schema NOT LIKE 'pg_toast%'";
	if (!only_schema.empty()) {
		sql << " AND table_schema='" << only_schema << "'";
	}
	sql << " ORDER BY table_schema, table_name, ordinal_position";

	std::vector<std::vector<std::string>> rows;
	if (execute_query(sql.str(), rows)) return -1;

	int count = 0;
	for (const auto& r : rows) {
		if (r.size() < 12) continue;

		// Use parameterized query to look up object_id (safe from SQL injection)
		int object_id = lookup_object_id(r[0], r[1], "table,view");
		if (object_id < 0) {
			continue;
		}

		int is_time = 0;
		if (r[4] == "date" || r[4] == "time" || r[4] == "timestamp" ||
		    r[4] == "timestamptz" || r[4] == "timetz") {
			is_time = 1;
		}
		int is_id_like = (r[3] == "id" || (r[3].size() > 3 && r[3].substr(r[3].size() - 3) == "_id")) ? 1 : 0;

		if (catalog->insert_column(
			object_id,
			atoi(r[2].c_str()), r[3], r[4], r[5], atoi(r[6].c_str()),
			r[7], r[8], r[9], r[10], r[11],
			0, 0, 0, is_time, is_id_like
		) >= 0) {
			count++;
		}
	}
	catalog->update_object_flags(current_run_id);
	return count;
}

int PgSQL_Static_Harvester::harvest_indexes(const std::string& only_schema) {
	if (current_run_id < 0) return -1;
	if (!is_valid_schema_name(only_schema)) return -1;

	std::ostringstream sql;
	sql << "SELECT ns.nspname, t.relname, i.relname, "
	    << "CASE WHEN ix.indisunique THEN 1 ELSE 0 END, "
	    << "COALESCE(am.amname,''), k.ord, COALESCE(a.attname,''), 0, '', 0 "
	    << "FROM pg_class t "
	    << "JOIN pg_namespace ns ON ns.oid=t.relnamespace "
	    << "JOIN pg_index ix ON ix.indrelid=t.oid "
	    << "JOIN pg_class i ON i.oid=ix.indexrelid "
	    << "JOIN pg_am am ON am.oid=i.relam "
	    << "JOIN LATERAL unnest(ix.indkey) WITH ORDINALITY AS k(attnum, ord) ON TRUE "
	    << "LEFT JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=k.attnum "
	    << "WHERE t.relkind IN ('r','p') "
	    << "AND ns.nspname NOT IN ('pg_catalog','information_schema') "
	    << "AND ns.nspname NOT LIKE 'pg_toast%'";
	if (!only_schema.empty()) {
		sql << " AND ns.nspname='" << only_schema << "'";
	}
	sql << " ORDER BY ns.nspname, t.relname, i.relname, k.ord";

	std::vector<std::vector<std::string>> rows;
	if (execute_query(sql.str(), rows)) return -1;

	int count = 0;
	std::map<std::string, std::vector<std::vector<std::string>>> grouped;
	for (const auto& r : rows) {
		if (r.size() < 10) continue;
		std::string key = r[0] + "." + r[1] + "." + r[2];
		grouped[key].push_back(r);
	}

	for (const auto& entry : grouped) {
		const auto& rows_for_index = entry.second;
		if (rows_for_index.empty()) continue;
		const auto& first = rows_for_index[0];

		// Use parameterized query to look up object_id (safe from SQL injection)
		int object_id = lookup_object_id(first[0], first[1], "table");
		if (object_id < 0) {
			continue;
		}

		int is_primary = (first[2] == "PRIMARY" || first[2] == first[1] + "_pkey") ? 1 : 0;
		int index_id = catalog->insert_index(
			object_id, first[2], atoi(first[3].c_str()), is_primary, first[4], atol(first[9].c_str())
		);
		if (index_id < 0) {
			continue;
		}
		for (const auto& idx_col : rows_for_index) {
			catalog->insert_index_column(index_id, atoi(idx_col[5].c_str()), idx_col[6], atoi(idx_col[7].c_str()), idx_col[8]);
		}
		count++;
	}

	catalog->update_object_flags(current_run_id);
	return count;
}

int PgSQL_Static_Harvester::harvest_foreign_keys(const std::string& only_schema) {
	if (current_run_id < 0) return -1;
	if (!is_valid_schema_name(only_schema)) return -1;

	std::ostringstream sql;
	sql << "SELECT tc.table_schema, tc.table_name, tc.constraint_name, "
	    << "kcu.column_name, ccu.table_schema, ccu.table_name, ccu.column_name, "
	    << "kcu.ordinal_position, COALESCE(rc.update_rule,''), COALESCE(rc.delete_rule,'') "
	    << "FROM information_schema.table_constraints tc "
	    << "JOIN information_schema.key_column_usage kcu "
	    << "ON tc.constraint_name=kcu.constraint_name "
	    << "AND tc.table_schema=kcu.table_schema "
	    << "JOIN information_schema.constraint_column_usage ccu "
	    << "ON ccu.constraint_name=tc.constraint_name "
	    << "AND ccu.constraint_schema=tc.constraint_schema "
	    << "LEFT JOIN information_schema.referential_constraints rc "
	    << "ON rc.constraint_name=tc.constraint_name "
	    << "AND rc.constraint_schema=tc.constraint_schema "
	    << "WHERE tc.constraint_type='FOREIGN KEY' "
	    << "AND tc.table_schema NOT IN ('pg_catalog','information_schema') "
	    << "AND tc.table_schema NOT LIKE 'pg_toast%'";
	if (!only_schema.empty()) {
		sql << " AND tc.table_schema='" << only_schema << "'";
	}
	sql << " ORDER BY tc.table_schema, tc.table_name, tc.constraint_name, kcu.ordinal_position";

	std::vector<std::vector<std::string>> rows;
	if (execute_query(sql.str(), rows)) return -1;

	int count = 0;
	int last_fk_id = -1;
	std::string last_fk_key;
	for (const auto& r : rows) {
		if (r.size() < 10) continue;
		std::string fk_key = r[0] + "." + r[1] + "." + r[2];
		if (fk_key != last_fk_key) {
			// Use parameterized query to look up object_id (safe from SQL injection)
			int child_object_id = lookup_object_id(r[0], r[1], "table");
			if (child_object_id < 0) {
				last_fk_id = -1;
				last_fk_key.clear();
				continue;
			}
			last_fk_id = catalog->insert_foreign_key(
				current_run_id, child_object_id, r[2], r[4], r[5], r[8], r[9]
			);
			last_fk_key = fk_key;
		}
		if (last_fk_id >= 0) {
			catalog->insert_foreign_key_column(last_fk_id, atoi(r[7].c_str()), r[3], r[6]);
			count++;
		}
	}

	catalog->update_object_flags(current_run_id);
	return count;
}

int PgSQL_Static_Harvester::harvest_view_definitions(const std::string& only_schema) {
	if (current_run_id < 0) return -1;
	if (!is_valid_schema_name(only_schema)) return -1;

	std::ostringstream sql;
	sql << "SELECT schemaname, viewname, definition FROM pg_views "
	    << "WHERE schemaname NOT IN ('pg_catalog','information_schema') "
	    << "AND schemaname NOT LIKE 'pg_toast%'";
	if (!only_schema.empty()) {
		sql << " AND schemaname='" << only_schema << "'";
	}

	std::vector<std::vector<std::string>> rows;
	if (execute_query(sql.str(), rows)) return -1;

	int count = 0;
	for (const auto& row : rows) {
		if (row.size() < 3) continue;

		// Use parameterized query for UPDATE (safe from SQL injection)
		int rc = SQLITE_OK;
		sqlite3_stmt* stmt = NULL;
		const char* sql = "UPDATE objects SET definition_sql = ?1 WHERE run_id = ?2 AND schema_name = ?3 AND object_name = ?4 AND object_type = 'view';";
		auto [prep_rc, stmt_unique] = catalog->get_db()->prepare_v2(sql);
		stmt = stmt_unique.get();
		if (prep_rc != SQLITE_OK) {
			proxy_error("PgSQL_Static_Harvester: Failed to prepare view definition update statement\n");
			continue;
		}

		(*proxy_sqlite3_bind_text)(stmt, 1, row[2].c_str(), -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_int64)(stmt, 2, current_run_id);
		(*proxy_sqlite3_bind_text)(stmt, 3, row[0].c_str(), -1, SQLITE_TRANSIENT);
		(*proxy_sqlite3_bind_text)(stmt, 4, row[1].c_str(), -1, SQLITE_TRANSIENT);

		SAFE_SQLITE3_STEP2(stmt);
		if (rc == SQLITE_DONE) {
			int changes = (*proxy_sqlite3_changes)(catalog->get_db()->get_db());
			if (changes > 0) {
				count++;
			}
		}
	}
	return count;
}

int PgSQL_Static_Harvester::build_quick_profiles() {
	if (current_run_id < 0) return -1;

	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;
	std::ostringstream sql;
	sql << "SELECT object_id, object_name, table_rows_est, data_length, index_length, "
	       "has_primary_key, has_foreign_keys, has_time_column "
	       "FROM objects WHERE run_id=" << current_run_id << " AND object_type='table'";
	catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);
	if (error) {
		free(error);
		if (resultset) delete resultset;
		return -1;
	}

	int count = 0;
	if (resultset) {
		for (auto row : resultset->rows) {
			if (row->cnt < 8) continue;
			const std::string name = row->fields[1] ? row->fields[1] : "";
			std::string kind = "unknown";
			std::string lname = name;
			std::transform(lname.begin(), lname.end(), lname.begin(), ::tolower);
			if (lname.find("log") != std::string::npos || lname.find("event") != std::string::npos || lname.find("audit") != std::string::npos) {
				kind = "log";
			} else if (lname.find("order") != std::string::npos || lname.find("invoice") != std::string::npos || lname.find("payment") != std::string::npos || lname.find("transaction") != std::string::npos) {
				kind = "fact";
			} else if (lname.find("user") != std::string::npos || lname.find("customer") != std::string::npos || lname.find("account") != std::string::npos || lname.find("product") != std::string::npos) {
				kind = "entity";
			}

			json p;
			p["guessed_kind"] = kind;
			p["rows_est"] = row->fields[2] ? atoll(row->fields[2]) : 0;
			p["size_bytes"] = (row->fields[3] ? atoll(row->fields[3]) : 0) + (row->fields[4] ? atoll(row->fields[4]) : 0);
			p["engine"] = "pgsql";
			p["has_primary_key"] = row->fields[5] ? atoi(row->fields[5]) : 0;
			p["has_foreign_keys"] = row->fields[6] ? atoi(row->fields[6]) : 0;
			p["has_time_column"] = row->fields[7] ? atoi(row->fields[7]) : 0;

			if (catalog->upsert_profile(current_run_id, atoi(row->fields[0]), "table_quick", p.dump()) == 0) {
				count++;
			}
		}
		delete resultset;
	}
	return count;
}

int PgSQL_Static_Harvester::rebuild_fts_index() {
	if (current_run_id < 0) return -1;
	return catalog->rebuild_fts_index(current_run_id);
}

int PgSQL_Static_Harvester::run_full_harvest(const std::string& target_id, const std::string& only_schema, const std::string& notes) {
	if (start_run(target_id, notes) < 0) return -1;
	if (harvest_schemas(only_schema) < 0) { finish_run("Failed during schema harvest"); return -1; }
	if (harvest_objects(only_schema) < 0) { finish_run("Failed during object harvest"); return -1; }
	if (harvest_columns(only_schema) < 0) { finish_run("Failed during column harvest"); return -1; }
	if (harvest_indexes(only_schema) < 0) { finish_run("Failed during index harvest"); return -1; }
	if (harvest_foreign_keys(only_schema) < 0) { finish_run("Failed during foreign key harvest"); return -1; }
	if (harvest_view_definitions(only_schema) < 0) { finish_run("Failed during view definition harvest"); return -1; }
	if (build_quick_profiles() < 0) { finish_run("Failed during profile building"); return -1; }
	if (rebuild_fts_index() < 0) { finish_run("Failed during FTS rebuild"); return -1; }
	int final_run_id = current_run_id;
	finish_run("Harvest completed successfully");
	return final_run_id;
}

std::string PgSQL_Static_Harvester::get_harvest_stats() {
	if (current_run_id < 0) {
		return "{\"error\": \"No active run\"}";
	}
	return get_harvest_stats(current_run_id);
}

std::string PgSQL_Static_Harvester::get_harvest_stats(int run_id) {
	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;
	json stats;
	stats["run_id"] = run_id;
	stats["protocol"] = "pgsql";

	std::ostringstream q1;
	q1 << "SELECT object_type, COUNT(*) FROM objects WHERE run_id=" << run_id << " GROUP BY object_type";
	catalog->get_db()->execute_statement(q1.str().c_str(), &error, &cols, &affected, &resultset);
	json objects = json::object();
	if (!error && resultset) {
		for (auto row : resultset->rows) {
			if (row->cnt >= 2) {
				objects[row->fields[0] ? row->fields[0] : "unknown"] = row->fields[1] ? atoi(row->fields[1]) : 0;
			}
		}
		delete resultset;
	} else if (error) {
		free(error);
		error = NULL;
		if (resultset) delete resultset;
	}
	stats["objects"] = objects;

	auto get_count = [&](const std::string& table) -> int {
		char* e = NULL;
		int c = 0, a = 0;
		SQLite3_result* rs = NULL;
		std::ostringstream q;
		q << "SELECT COUNT(*) FROM " << table << " WHERE run_id=" << run_id;
		catalog->get_db()->execute_statement(q.str().c_str(), &e, &c, &a, &rs);
		int out = 0;
		if (!e && rs && !rs->rows.empty() && rs->rows[0]->cnt > 0 && rs->rows[0]->fields[0]) {
			out = atoi(rs->rows[0]->fields[0]);
		}
		if (e) free(e);
		if (rs) delete rs;
		return out;
	};

	stats["columns"] = get_count("columns");
	stats["foreign_keys"] = get_count("foreign_keys");

	return stats.dump();
}

#endif /* PROXYSQL40 */
