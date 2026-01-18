#include "Static_Harvester.h"
#include "proxysql_debug.h"
#include <sstream>
#include <algorithm>
#include <regex>
#include <cstring>

// MySQL client library
#include <mysql.h>

// JSON library
#include "../deps/json/json.hpp"
using json = nlohmann::json;

Static_Harvester::Static_Harvester(
	const std::string& host,
	int port,
	const std::string& user,
	const std::string& password,
	const std::string& schema,
	const std::string& catalog_path
)
	: mysql_host(host),
	  mysql_port(port),
	  mysql_user(user),
	  mysql_password(password),
	  mysql_schema(schema),
	  mysql_conn(NULL),
	  catalog(NULL),
	  current_run_id(-1)
{
	pthread_mutex_init(&conn_lock, NULL);
	catalog = new Discovery_Schema(catalog_path);
}

Static_Harvester::~Static_Harvester() {
	close();
	if (catalog) {
		delete catalog;
	}
	pthread_mutex_destroy(&conn_lock);
}

int Static_Harvester::init() {
	if (catalog->init()) {
		proxy_error("Static_Harvester: Failed to initialize catalog\n");
		return -1;
	}
	return 0;
}

void Static_Harvester::close() {
	disconnect_mysql();
}

int Static_Harvester::connect_mysql() {
	pthread_mutex_lock(&conn_lock);

	if (mysql_conn) {
		pthread_mutex_unlock(&conn_lock);
		return 0; // Already connected
	}

	mysql_conn = mysql_init(NULL);
	if (!mysql_conn) {
		proxy_error("Static_Harvester: mysql_init failed\n");
		pthread_mutex_unlock(&conn_lock);
		return -1;
	}

	// Set timeouts
	unsigned int timeout = 30;
	mysql_options(mysql_conn, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	mysql_options(mysql_conn, MYSQL_OPT_READ_TIMEOUT, &timeout);
	mysql_options(mysql_conn, MYSQL_OPT_WRITE_TIMEOUT, &timeout);

	// Connect
	if (!mysql_real_connect(
		mysql_conn,
		mysql_host.c_str(),
		mysql_user.c_str(),
		mysql_password.c_str(),
		NULL, // No default schema - we query information_schema
		mysql_port,
		NULL,
		CLIENT_MULTI_STATEMENTS
	)) {
		proxy_error("Static_Harvester: mysql_real_connect failed: %s\n", mysql_error(mysql_conn));
		mysql_close(mysql_conn);
		mysql_conn = NULL;
		pthread_mutex_unlock(&conn_lock);
		return -1;
	}

	// Get MySQL version
	mysql_version = get_mysql_version();
	source_dsn = "mysql://" + mysql_user + "@" + mysql_host + ":" + std::to_string(mysql_port) + "/" + mysql_schema;

	proxy_info("Static_Harvester: Connected to MySQL %s at %s:%d\n",
		mysql_version.c_str(), mysql_host.c_str(), mysql_port);

	pthread_mutex_unlock(&conn_lock);
	return 0;
}

void Static_Harvester::disconnect_mysql() {
	pthread_mutex_lock(&conn_lock);
	if (mysql_conn) {
		mysql_close(mysql_conn);
		mysql_conn = NULL;
	}
	pthread_mutex_unlock(&conn_lock);
}

std::string Static_Harvester::get_mysql_version() {
	if (!mysql_conn) {
		return "";
	}

	MYSQL_RES* result = mysql_list_tables(mysql_conn, NULL);
	if (!result) {
		return mysql_get_server_info(mysql_conn);
	}
	mysql_free_result(result);

	return mysql_get_server_info(mysql_conn);
}

int Static_Harvester::execute_query(const std::string& query, std::vector<std::vector<std::string>>& results) {
	pthread_mutex_lock(&conn_lock);

	if (!mysql_conn) {
		pthread_mutex_unlock(&conn_lock);
		proxy_error("Static_Harvester: Not connected to MySQL\n");
		return -1;
	}

	proxy_debug(PROXY_DEBUG_GENERIC, 3, "Static_Harvester: Executing query: %s\n", query.c_str());

	if (mysql_query(mysql_conn, query.c_str())) {
		proxy_error("Static_Harvester: Query failed: %s\n", mysql_error(mysql_conn));
		pthread_mutex_unlock(&conn_lock);
		return -1;
	}

	MYSQL_RES* res = mysql_store_result(mysql_conn);
	if (!res) {
		// No result set (e.g., INSERT/UPDATE)
		pthread_mutex_unlock(&conn_lock);
		return 0;
	}

	int num_fields = mysql_num_fields(res);
	MYSQL_ROW row;

	while ((row = mysql_fetch_row(res))) {
		std::vector<std::string> row_data;
		for (int i = 0; i < num_fields; i++) {
			row_data.push_back(row[i] ? row[i] : "");
		}
		results.push_back(row_data);
	}

	mysql_free_result(res);
	pthread_mutex_unlock(&conn_lock);
	return 0;
}

bool Static_Harvester::is_time_type(const std::string& data_type) {
	std::string dt = data_type;
	std::transform(dt.begin(), dt.end(), dt.begin(), ::tolower);

	return dt == "date" || dt == "datetime" || dt == "timestamp" ||
	       dt == "time" || dt == "year";
}

bool Static_Harvester::is_id_like_name(const std::string& column_name) {
	std::string cn = column_name;
	std::transform(cn.begin(), cn.end(), cn.begin(), ::tolower);

	// Check if name ends with '_id' or is exactly 'id'
	if (cn == "id") return true;
	if (cn.length() > 3 && cn.substr(cn.length() - 3) == "_id") return true;

	return false;
}

int Static_Harvester::start_run(const std::string& notes) {
	if (current_run_id >= 0) {
		proxy_error("Static_Harvester: Run already active (run_id=%d)\n", current_run_id);
		return -1;
	}

	if (connect_mysql()) {
		return -1;
	}

	current_run_id = catalog->create_run(source_dsn, mysql_version, notes);
	if (current_run_id < 0) {
		proxy_error("Static_Harvester: Failed to create run\n");
		return -1;
	}

	proxy_info("Static_Harvester: Started run_id=%d\n", current_run_id);
	return current_run_id;
}

int Static_Harvester::finish_run(const std::string& notes) {
	if (current_run_id < 0) {
		proxy_error("Static_Harvester: No active run\n");
		return -1;
	}

	int rc = catalog->finish_run(current_run_id, notes);
	if (rc) {
		proxy_error("Static_Harvester: Failed to finish run\n");
		return -1;
	}

	proxy_info("Static_Harvester: Finished run_id=%d\n", current_run_id);
	current_run_id = -1;
	return 0;
}

std::vector<Static_Harvester::SchemaRow> Static_Harvester::fetch_schemas(const std::string& filter) {
	std::vector<SchemaRow> schemas;

	std::ostringstream sql;
	sql << "SELECT SCHEMA_NAME, DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME "
	    << "FROM information_schema.SCHEMATA";

	if (!filter.empty()) {
		sql << " WHERE SCHEMA_NAME = '" << filter << "'";
	}

	sql << " ORDER BY SCHEMA_NAME;";

	std::vector<std::vector<std::string>> results;
	if (execute_query(sql.str(), results) == 0) {
		for (const auto& row : results) {
			SchemaRow s;
			s.schema_name = row[0];
			s.charset = row[1];
			s.collation = row[2];
			schemas.push_back(s);
		}
	}

	return schemas;
}

int Static_Harvester::harvest_schemas(const std::string& only_schema) {
	if (current_run_id < 0) {
		proxy_error("Static_Harvester: No active run\n");
		return -1;
	}

	std::vector<SchemaRow> schemas = fetch_schemas(only_schema);
	int count = 0;

	for (const auto& s : schemas) {
		// Skip system schemas
		if (s.schema_name == "mysql" || s.schema_name == "information_schema" ||
		    s.schema_name == "performance_schema" || s.schema_name == "sys") {
			continue;
		}

		if (catalog->insert_schema(current_run_id, s.schema_name, s.charset, s.collation) >= 0) {
			count++;
		}
	}

	proxy_info("Static_Harvester: Harvested %d schemas\n", count);
	return count;
}

std::vector<Static_Harvester::ObjectRow> Static_Harvester::fetch_tables_views(const std::string& filter) {
	std::vector<ObjectRow> objects;

	std::ostringstream sql;
	sql << "SELECT TABLE_SCHEMA, TABLE_NAME, TABLE_TYPE, ENGINE, TABLE_ROWS, "
	    << "DATA_LENGTH, INDEX_LENGTH, CREATE_TIME, UPDATE_TIME, TABLE_COMMENT "
	    << "FROM information_schema.TABLES "
	    << "WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')";

	if (!filter.empty()) {
		sql << " AND TABLE_SCHEMA = '" << filter << "'";
	}

	sql << " ORDER BY TABLE_SCHEMA, TABLE_NAME;";

	std::vector<std::vector<std::string>> results;
	if (execute_query(sql.str(), results) == 0) {
		for (const auto& row : results) {
			ObjectRow o;
			o.schema_name = row[0];
			o.object_name = row[1];
			o.object_type = (row[2] == "VIEW") ? "view" : "table";
			o.engine = row[3];
			o.table_rows_est = row[4].empty() ? 0 : atol(row[4].c_str());
			o.data_length = row[5].empty() ? 0 : atol(row[5].c_str());
			o.index_length = row[6].empty() ? 0 : atol(row[6].c_str());
			o.create_time = row[7];
			o.update_time = row[8];
			o.object_comment = row[9];
			objects.push_back(o);
		}
	}

	return objects;
}

std::vector<Static_Harvester::ColumnRow> Static_Harvester::fetch_columns(const std::string& filter) {
	std::vector<ColumnRow> columns;

	std::ostringstream sql;
	sql << "SELECT TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION, COLUMN_NAME, "
	    << "DATA_TYPE, COLUMN_TYPE, IS_NULLABLE, COLUMN_DEFAULT, EXTRA, "
	    << "CHARACTER_SET_NAME, COLLATION_NAME, COLUMN_COMMENT "
	    << "FROM information_schema.COLUMNS "
	    << "WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')";

	if (!filter.empty()) {
		sql << " AND TABLE_SCHEMA = '" << filter << "'";
	}

	sql << " ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION;";

	std::vector<std::vector<std::string>> results;
	if (execute_query(sql.str(), results) == 0) {
		for (const auto& row : results) {
			ColumnRow c;
			c.schema_name = row[0];
			c.object_name = row[1];
			c.ordinal_pos = atoi(row[2].c_str());
			c.column_name = row[3];
			c.data_type = row[4];
			c.column_type = row[5];
			c.is_nullable = (row[6] == "YES") ? 1 : 0;
			c.column_default = row[7];
			c.extra = row[8];
			c.charset = row[9];
			c.collation = row[10];
			c.column_comment = row[11];
			columns.push_back(c);
		}
	}

	return columns;
}

std::vector<Static_Harvester::IndexRow> Static_Harvester::fetch_indexes(const std::string& filter) {
	std::vector<IndexRow> indexes;

	std::ostringstream sql;
	sql << "SELECT TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, NON_UNIQUE, INDEX_TYPE, "
	    << "SEQ_IN_INDEX, COLUMN_NAME, SUB_PART, COLLATION, CARDINALITY "
	    << "FROM information_schema.STATISTICS "
	    << "WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')";

	if (!filter.empty()) {
		sql << " AND TABLE_SCHEMA = '" << filter << "'";
	}

	sql << " ORDER BY TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX;";

	std::vector<std::vector<std::string>> results;
	if (execute_query(sql.str(), results) == 0) {
		for (const auto& row : results) {
			IndexRow i;
			i.schema_name = row[0];
			i.object_name = row[1];
			i.index_name = row[2];
			i.is_unique = (row[3] == "0") ? 1 : 0;
			i.index_type = row[4];
			i.seq_in_index = atoi(row[5].c_str());
			i.column_name = row[6];
			i.sub_part = row[7].empty() ? 0 : atoi(row[7].c_str());
			i.collation = row[8];
			i.cardinality = row[9].empty() ? 0 : atol(row[9].c_str());
			indexes.push_back(i);
		}
	}

	return indexes;
}

std::vector<Static_Harvester::FKRow> Static_Harvester::fetch_foreign_keys(const std::string& filter) {
	std::vector<FKRow> fks;

	std::ostringstream sql;
	sql << "SELECT kcu.CONSTRAINT_SCHEMA AS child_schema, "
	    << "kcu.TABLE_NAME AS child_table, kcu.CONSTRAINT_NAME AS fk_name, "
	    << "kcu.COLUMN_NAME AS child_column, kcu.REFERENCED_TABLE_SCHEMA AS parent_schema, "
	    << "kcu.REFERENCED_TABLE_NAME AS parent_table, kcu.REFERENCED_COLUMN_NAME AS parent_column, "
	    << "kcu.ORDINAL_POSITION AS seq, rc.UPDATE_RULE AS on_update, rc.DELETE_RULE AS on_delete "
	    << "FROM information_schema.KEY_COLUMN_USAGE kcu "
	    << "JOIN information_schema.REFERENTIAL_CONSTRAINTS rc "
	    << "  ON rc.CONSTRAINT_SCHEMA = kcu.CONSTRAINT_SCHEMA "
	    << " AND rc.CONSTRAINT_NAME = kcu.CONSTRAINT_NAME "
	    << "WHERE kcu.TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')";

	if (!filter.empty()) {
		sql << " AND kcu.TABLE_SCHEMA = '" << filter << "'";
	}

	sql << "  AND kcu.REFERENCED_TABLE_NAME IS NOT NULL "
	    << "ORDER BY child_schema, child_table, fk_name, seq;";

	std::vector<std::vector<std::string>> results;
	if (execute_query(sql.str(), results) == 0) {
		for (const auto& row : results) {
			FKRow fk;
			fk.child_schema = row[0];
			fk.child_table = row[1];
			fk.fk_name = row[2];
			fk.child_column = row[3];
			fk.parent_schema = row[4];
			fk.parent_table = row[5];
			fk.parent_column = row[6];
			fk.seq = atoi(row[7].c_str());
			fk.on_update = row[8];
			fk.on_delete = row[9];
			fks.push_back(fk);
		}
	}

	return fks;
}

int Static_Harvester::harvest_objects(const std::string& only_schema) {
	if (current_run_id < 0) {
		proxy_error("Static_Harvester: No active run\n");
		return -1;
	}

	// Fetch tables and views
	std::vector<ObjectRow> objects = fetch_tables_views(only_schema);
	int count = 0;

	for (const auto& o : objects) {
		int object_id = catalog->insert_object(
			current_run_id, o.schema_name, o.object_name, o.object_type,
			o.engine, o.table_rows_est, o.data_length, o.index_length,
			o.create_time, o.update_time, o.object_comment, ""
		);

		if (object_id >= 0) {
			count++;
		}
	}

	// Fetch and insert routines (stored procedures/functions)
	std::ostringstream sql;
	sql << "SELECT ROUTINE_SCHEMA, ROUTINE_NAME, ROUTINE_TYPE, ROUTINE_COMMENT "
	    << "FROM information_schema.ROUTINES "
	    << "WHERE ROUTINE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')";

	if (!only_schema.empty()) {
		sql << " AND ROUTINE_SCHEMA = '" << only_schema << "'";
	}

	sql << " ORDER BY ROUTINE_SCHEMA, ROUTINE_NAME;";

	std::vector<std::vector<std::string>> results;
	if (execute_query(sql.str(), results) == 0) {
		for (const auto& row : results) {
			int object_id = catalog->insert_object(
				current_run_id, row[0], row[1], "routine",
				"", 0, 0, 0, "", "", row[3], ""
			);
			if (object_id >= 0) {
				count++;
			}
		}
	}

	proxy_info("Static_Harvester: Harvested %d objects\n", count);
	return count;
}

int Static_Harvester::harvest_columns(const std::string& only_schema) {
	if (current_run_id < 0) {
		proxy_error("Static_Harvester: No active run\n");
		return -1;
	}

	std::vector<ColumnRow> columns = fetch_columns(only_schema);
	int count = 0;

	for (const auto& c : columns) {
		// Find the object_id for this column
		std::string object_key = c.schema_name + "." + c.object_name;

		// Query catalog to get object_id
		char* error = NULL;
		int cols = 0, affected = 0;
		SQLite3_result* resultset = NULL;

		std::ostringstream sql;
		sql << "SELECT object_id FROM objects "
		    << "WHERE run_id = " << current_run_id
		    << " AND schema_name = '" << c.schema_name << "'"
		    << " AND object_name = '" << c.object_name << "'"
		    << " AND object_type IN ('table', 'view') LIMIT 1;";

		catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);

		if (!resultset || resultset->rows.empty()) {
			delete resultset;
			continue; // Object not found
		}

		int object_id = atoi(resultset->rows[0]->fields[0]);
		delete resultset;

		// Compute derived flags
		int is_time = is_time_type(c.data_type) ? 1 : 0;
		int is_id_like = is_id_like_name(c.column_name) ? 1 : 0;

		if (catalog->insert_column(
			object_id, c.ordinal_pos, c.column_name, c.data_type,
			c.column_type, c.is_nullable, c.column_default, c.extra,
			c.charset, c.collation, c.column_comment,
			0, 0, 0, is_time, is_id_like
		) >= 0) {
			count++;
		}
	}

	// Update object flags
	catalog->update_object_flags(current_run_id);

	proxy_info("Static_Harvester: Harvested %d columns\n", count);
	return count;
}

int Static_Harvester::harvest_indexes(const std::string& only_schema) {
	if (current_run_id < 0) {
		proxy_error("Static_Harvester: No active run\n");
		return -1;
	}

	std::vector<IndexRow> indexes = fetch_indexes(only_schema);

	// Group by index
	std::map<std::string, std::vector<IndexRow>> index_map;
	for (const auto& i : indexes) {
		std::string key = i.schema_name + "." + i.object_name + "." + i.index_name;
		index_map[key].push_back(i);
	}

	int count = 0;
	for (const auto& entry : index_map) {
		const auto& idx_rows = entry.second;
		if (idx_rows.empty()) continue;

		const IndexRow& first = idx_rows[0];

		// Get object_id
		char* error = NULL;
		int cols = 0, affected = 0;
		SQLite3_result* resultset = NULL;

		std::ostringstream sql;
		sql << "SELECT object_id FROM objects "
		    << "WHERE run_id = " << current_run_id
		    << " AND schema_name = '" << first.schema_name << "'"
		    << " AND object_name = '" << first.object_name << "'"
		    << " AND object_type = 'table' LIMIT 1;";

		catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);

		if (!resultset || resultset->rows.empty()) {
			delete resultset;
			continue;
		}

		int object_id = atoi(resultset->rows[0]->fields[0]);
		delete resultset;

		// Check if this is the primary key
		int is_primary = (first.index_name == "PRIMARY") ? 1 : 0;

		// Insert index
		int index_id = catalog->insert_index(
			object_id, first.index_name, first.is_unique, is_primary,
			first.index_type, first.cardinality
		);

		if (index_id < 0) continue;

		// Insert index columns
		for (const auto& idx_row : idx_rows) {
			catalog->insert_index_column(
				index_id, idx_row.seq_in_index, idx_row.column_name,
				idx_row.sub_part, idx_row.collation
			);
		}

		count++;
	}

	// Update column is_pk, is_unique, is_indexed flags
	char* error = NULL;
	int cols, affected;
	std::ostringstream sql;

	// Mark indexed columns
	sql << "UPDATE columns SET is_indexed = 1 "
	    << "WHERE object_id IN (SELECT object_id FROM objects WHERE run_id = " << current_run_id << ") "
	    << "AND (object_id, column_name) IN ("
	    << "  SELECT i.object_id, ic.column_name FROM indexes i JOIN index_columns ic ON i.index_id = ic.index_id"
	    << ");";
	catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected);

	// Mark PK columns
	sql.str("");
	sql << "UPDATE columns SET is_pk = 1 "
	    << "WHERE object_id IN (SELECT object_id FROM objects WHERE run_id = " << current_run_id << ") "
	    << "AND (object_id, column_name) IN ("
	    << "  SELECT i.object_id, ic.column_name FROM indexes i JOIN index_columns ic ON i.index_id = ic.index_id "
	    << "  WHERE i.is_primary = 1"
	    << ");";
	catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected);

	// Mark unique columns (simplified - for single-column unique indexes)
	sql.str("");
	sql << "UPDATE columns SET is_unique = 1 "
	    << "WHERE object_id IN (SELECT object_id FROM objects WHERE run_id = " << current_run_id << ") "
	    << "AND (object_id, column_name) IN ("
	    << "  SELECT i.object_id, ic.column_name FROM indexes i JOIN index_columns ic ON i.index_id = ic.index_id "
	    << "  WHERE i.is_unique = 1 AND i.is_primary = 0 "
	    << "  GROUP BY i.object_id, ic.column_name HAVING COUNT(*) = 1"
	    << ");";
	catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected);

	// Update object has_primary_key flag
	catalog->update_object_flags(current_run_id);

	proxy_info("Static_Harvester: Harvested %d indexes\n", count);
	return count;
}

int Static_Harvester::harvest_foreign_keys(const std::string& only_schema) {
	if (current_run_id < 0) {
		proxy_error("Static_Harvester: No active run\n");
		return -1;
	}

	std::vector<FKRow> fks = fetch_foreign_keys(only_schema);

	// Group by FK
	std::map<std::string, std::vector<FKRow>> fk_map;
	for (const auto& fk : fks) {
		std::string key = fk.child_schema + "." + fk.child_table + "." + fk.fk_name;
		fk_map[key].push_back(fk);
	}

	int count = 0;
	for (const auto& entry : fk_map) {
		const auto& fk_rows = entry.second;
		if (fk_rows.empty()) continue;

		const FKRow& first = fk_rows[0];

		// Get child object_id
		char* error = NULL;
		int cols = 0, affected = 0;
		SQLite3_result* resultset = NULL;

		std::ostringstream sql;
		sql << "SELECT object_id FROM objects "
		    << "WHERE run_id = " << current_run_id
		    << " AND schema_name = '" << first.child_schema << "'"
		    << " AND object_name = '" << first.child_table << "'"
		    << " AND object_type = 'table' LIMIT 1;";

		catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);

		if (!resultset || resultset->rows.empty()) {
			delete resultset;
			continue;
		}

		int child_object_id = atoi(resultset->rows[0]->fields[0]);
		delete resultset;

		// Insert FK
		int fk_id = catalog->insert_foreign_key(
			current_run_id, child_object_id, first.fk_name,
			first.parent_schema, first.parent_table,
			first.on_update, first.on_delete
		);

		if (fk_id < 0) continue;

		// Insert FK columns
		for (const auto& fk_row : fk_rows) {
			catalog->insert_foreign_key_column(
				fk_id, fk_row.seq, fk_row.child_column, fk_row.parent_column
			);
		}

		count++;
	}

	// Update object has_foreign_keys flag
	catalog->update_object_flags(current_run_id);

	proxy_info("Static_Harvester: Harvested %d foreign keys\n", count);
	return count;
}

int Static_Harvester::harvest_view_definitions(const std::string& only_schema) {
	if (current_run_id < 0) {
		proxy_error("Static_Harvester: No active run\n");
		return -1;
	}

	std::ostringstream sql;
	sql << "SELECT TABLE_SCHEMA, TABLE_NAME, VIEW_DEFINITION "
	    << "FROM information_schema.VIEWS "
	    << "WHERE TABLE_SCHEMA NOT IN ('mysql','information_schema','performance_schema','sys')";

	if (!only_schema.empty()) {
		sql << " AND TABLE_SCHEMA = '" << only_schema << "'";
	}

	sql << ";";

	std::vector<std::vector<std::string>> results;
	if (execute_query(sql.str(), results) != 0) {
		return -1;
	}

	int count = 0;
	for (const auto& row : results) {
		std::string schema_name = row[0];
		std::string view_name = row[1];
		std::string view_def = row[2];

		// Update object with definition
		char* error = NULL;
		int cols = 0, affected = 0;
		std::ostringstream update_sql;
		update_sql << "UPDATE objects SET definition_sql = '" << view_def << "' "
		           << "WHERE run_id = " << current_run_id
		           << " AND schema_name = '" << schema_name << "'"
		           << " AND object_name = '" << view_name << "'"
		           << " AND object_type = 'view';";

		catalog->get_db()->execute_statement(update_sql.str().c_str(), &error, &cols, &affected);
		if (affected > 0) {
			count++;
		}
	}

	proxy_info("Static_Harvester: Updated %d view definitions\n", count);
	return count;
}

int Static_Harvester::build_quick_profiles() {
	if (current_run_id < 0) {
		proxy_error("Static_Harvester: No active run\n");
		return -1;
	}

	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;

	std::ostringstream sql;
	sql << "SELECT object_id, schema_name, object_name, object_type, engine, table_rows_est, "
	    << "data_length, index_length, has_primary_key, has_foreign_keys, has_time_column "
	    << "FROM objects WHERE run_id = " << current_run_id
	    << " AND object_type IN ('table', 'view')";

	catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);

	if (!resultset) {
		return -1;
	}

	int count = 0;
	for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin();
	     it != resultset->rows.end(); ++it) {
		SQLite3_row* row = *it;

		int object_id = atoi(row->fields[0]);
		std::string object_name = std::string(row->fields[2] ? row->fields[2] : "");

		// Guess kind from name
		std::string guessed_kind = "unknown";
		std::string name_lower = object_name;
		std::transform(name_lower.begin(), name_lower.end(), name_lower.begin(), ::tolower);

		if (name_lower.find("log") != std::string::npos ||
		    name_lower.find("event") != std::string::npos ||
		    name_lower.find("audit") != std::string::npos) {
			guessed_kind = "log/event";
		} else if (name_lower.find("order") != std::string::npos ||
		           name_lower.find("invoice") != std::string::npos ||
		           name_lower.find("payment") != std::string::npos ||
		           name_lower.find("transaction") != std::string::npos) {
			guessed_kind = "fact";
		} else if (name_lower.find("user") != std::string::npos ||
		           name_lower.find("customer") != std::string::npos ||
		           name_lower.find("account") != std::string::npos ||
		           name_lower.find("product") != std::string::npos) {
			guessed_kind = "entity";
		}

		// Build profile JSON
		json profile;
		profile["guessed_kind"] = guessed_kind;
		profile["rows_est"] = row->fields[4] ? atol(row->fields[4]) : 0;
		profile["size_bytes"] = (atol(row->fields[5] ? row->fields[5] : "0") +
		                       atol(row->fields[6] ? row->fields[6] : "0"));
		profile["engine"] = std::string(row->fields[3] ? row->fields[3] : "");
		profile["has_primary_key"] = atoi(row->fields[7]) != 0;
		profile["has_foreign_keys"] = atoi(row->fields[8]) != 0;
		profile["has_time_column"] = atoi(row->fields[9]) != 0;

		if (catalog->upsert_profile(current_run_id, object_id, "table_quick", profile.dump()) == 0) {
			count++;
		}
	}

	delete resultset;
	proxy_info("Static_Harvester: Built %d quick profiles\n", count);
	return count;
}

int Static_Harvester::rebuild_fts_index() {
	if (current_run_id < 0) {
		proxy_error("Static_Harvester: No active run\n");
		return -1;
	}

	int rc = catalog->rebuild_fts_index(current_run_id);
	if (rc) {
		proxy_error("Static_Harvester: Failed to rebuild FTS index\n");
		return -1;
	}

	proxy_info("Static_Harvester: Rebuilt FTS index\n");
	return 0;
}

int Static_Harvester::run_full_harvest(const std::string& only_schema, const std::string& notes) {
	if (start_run(notes) < 0) {
		return -1;
	}

	if (harvest_schemas(only_schema) < 0) {
		finish_run("Failed during schema harvest");
		return -1;
	}

	if (harvest_objects(only_schema) < 0) {
		finish_run("Failed during object harvest");
		return -1;
	}

	if (harvest_columns(only_schema) < 0) {
		finish_run("Failed during column harvest");
		return -1;
	}

	if (harvest_indexes(only_schema) < 0) {
		finish_run("Failed during index harvest");
		return -1;
	}

	if (harvest_foreign_keys(only_schema) < 0) {
		finish_run("Failed during foreign key harvest");
		return -1;
	}

	if (harvest_view_definitions(only_schema) < 0) {
		finish_run("Failed during view definition harvest");
		return -1;
	}

	if (build_quick_profiles() < 0) {
		finish_run("Failed during profile building");
		return -1;
	}

	if (rebuild_fts_index() < 0) {
		finish_run("Failed during FTS rebuild");
		return -1;
	}

	int final_run_id = current_run_id;
	finish_run("Harvest completed successfully");
	return final_run_id;
}

std::string Static_Harvester::get_harvest_stats() {
	if (current_run_id < 0) {
		return "{\"error\": \"No active run\"}";
	}
	return get_harvest_stats(current_run_id);
}

std::string Static_Harvester::get_harvest_stats(int run_id) {
	char* error = NULL;
	int cols = 0, affected = 0;
	SQLite3_result* resultset = NULL;

	std::ostringstream sql;

	json stats;
	stats["run_id"] = run_id;

	// Count objects
	sql.str("");
	sql << "SELECT object_type, COUNT(*) FROM objects WHERE run_id = " << run_id
	    << " GROUP BY object_type;";
	catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);

	if (resultset) {
		json obj_counts = json::object();
		for (std::vector<SQLite3_row*>::iterator it = resultset->rows.begin();
		     it != resultset->rows.end(); ++it) {
			obj_counts[(*it)->fields[0]] = atol((*it)->fields[1]);
		}
		stats["objects"] = obj_counts;
		delete resultset;
		resultset = NULL;
	}

	// Count columns
	sql.str("");
	sql << "SELECT COUNT(*) FROM columns c JOIN objects o ON c.object_id = o.object_id "
	    << "WHERE o.run_id = " << run_id << ";";
	catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);

	if (resultset && !resultset->rows.empty()) {
		stats["columns"] = atol(resultset->rows[0]->fields[0]);
		delete resultset;
		resultset = NULL;
	}

	// Count indexes
	sql.str("");
	sql << "SELECT COUNT(*) FROM indexes i JOIN objects o ON i.object_id = o.object_id "
	    << "WHERE o.run_id = " << run_id << ";";
	catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);

	if (resultset && !resultset->rows.empty()) {
		stats["indexes"] = atol(resultset->rows[0]->fields[0]);
		delete resultset;
		resultset = NULL;
	}

	// Count foreign keys
	sql.str("");
	sql << "SELECT COUNT(*) FROM foreign_keys WHERE run_id = " << run_id << ";";
	catalog->get_db()->execute_statement(sql.str().c_str(), &error, &cols, &affected, &resultset);

	if (resultset && !resultset->rows.empty()) {
		stats["foreign_keys"] = atol(resultset->rows[0]->fields[0]);
		delete resultset;
	}

	return stats.dump();
}
