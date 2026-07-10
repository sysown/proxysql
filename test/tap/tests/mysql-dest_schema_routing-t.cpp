/**
 * @file mysql-dest_schema_routing-t.cpp
 * @brief E2E test for logical db routing via mysql_query_rules.attributes
 *  {"destination_schema": "..."}. A matching rule switches the session schema
 *  before backend connection selection, so queries land on the remapped
 *  schema regardless of the db requested by the client. Verifies all three
 *  schema-selection paths (handshake db, COM_INIT_DB, USE statement) and
 *  that removing the rule restores the original behavior.
 */

#include <unistd.h>
#include <string>

#include "mysql.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

const char* SRC_DB = "dsr_src";
const char* DST_DB = "dsr_dst";
const int RULE_ID = 2; // must sort before the infra read/write split rules (3,4)

#define MYSQL_QUERY_ON_ERR_CLEANUP(mysql, query) \
	do { \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s (%s)\n", __FILE__, __LINE__, mysql_error(mysql), query); \
			goto cleanup; \
		} \
	} while(0)

/**
 * @brief Run a single-value query and return the value ("" on NULL/error).
 */
std::string fetch_single(MYSQL* mysql, const char* query) {
	std::string result {};
	if (mysql_query(mysql, query)) {
		diag("Query failed: '%s' error: '%s'", query, mysql_error(mysql));
		return result;
	}
	MYSQL_RES* res = mysql_store_result(mysql);
	if (res) {
		MYSQL_ROW row = mysql_fetch_row(res);
		if (row && row[0]) {
			result = row[0];
		}
		mysql_free_result(res);
	}
	return result;
}

/**
 * @brief Open a fresh proxy connection with 'db' as the handshake schema.
 */
MYSQL* connect_proxy(const char* db) {
	MYSQL* conn = mysql_init(NULL);
	if (!mysql_real_connect(conn, cl.host, cl.username, cl.password, db, cl.port, NULL, 0)) {
		diag("Failed to connect to proxy (db=%s): %s", db ? db : "NULL", mysql_error(conn));
		mysql_close(conn);
		return NULL;
	}
	return conn;
}

int main() {
	plan(12);

	if (cl.getEnv())
		return exit_status();

	MYSQL* admin = mysql_init(NULL);
	MYSQL* setup = NULL;
	MYSQL* conn = NULL;
	std::string val {};
	char query[512];

	if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(admin));
		return -1;
	}

	// setup: create the two schemas with distinct markers, before any rule exists
	setup = connect_proxy(NULL);
	if (!setup) {
		goto cleanup;
	}
	snprintf(query, sizeof(query), "CREATE DATABASE IF NOT EXISTS %s", SRC_DB);
	MYSQL_QUERY_ON_ERR_CLEANUP(setup, query);
	snprintf(query, sizeof(query), "CREATE DATABASE IF NOT EXISTS %s", DST_DB);
	MYSQL_QUERY_ON_ERR_CLEANUP(setup, query);
	snprintf(query, sizeof(query), "CREATE TABLE IF NOT EXISTS %s.marker (v VARCHAR(32))", SRC_DB);
	MYSQL_QUERY_ON_ERR_CLEANUP(setup, query);
	snprintf(query, sizeof(query), "CREATE TABLE IF NOT EXISTS %s.marker (v VARCHAR(32))", DST_DB);
	MYSQL_QUERY_ON_ERR_CLEANUP(setup, query);
	snprintf(query, sizeof(query), "DELETE FROM %s.marker", SRC_DB);
	MYSQL_QUERY_ON_ERR_CLEANUP(setup, query);
	snprintf(query, sizeof(query), "INSERT INTO %s.marker VALUES ('in_src')", SRC_DB);
	MYSQL_QUERY_ON_ERR_CLEANUP(setup, query);
	snprintf(query, sizeof(query), "DELETE FROM %s.marker", DST_DB);
	MYSQL_QUERY_ON_ERR_CLEANUP(setup, query);
	snprintf(query, sizeof(query), "INSERT INTO %s.marker VALUES ('in_dst')", DST_DB);
	MYSQL_QUERY_ON_ERR_CLEANUP(setup, query);
	// let replicas catch up: reads may be routed to a reader hostgroup
	sleep(2);

	// baseline: no rule, handshake db is honored
	conn = connect_proxy(SRC_DB);
	if (!conn) {
		goto cleanup;
	}
	val = fetch_single(conn, "SELECT DATABASE()");
	ok(val == SRC_DB, "baseline: DATABASE() should be '%s', got '%s'", SRC_DB, val.c_str());
	val = fetch_single(conn, "SELECT v FROM marker");
	ok(val == "in_src", "baseline: marker should be 'in_src', got '%s'", val.c_str());
	mysql_close(conn);
	conn = NULL;

	// add destination_schema rule for this user (apply=0: compose with later rules)
	snprintf(query, sizeof(query), "DELETE FROM mysql_query_rules WHERE rule_id=%d", RULE_ID);
	MYSQL_QUERY_ON_ERR_CLEANUP(admin, query);
	snprintf(query, sizeof(query),
		"INSERT INTO mysql_query_rules (rule_id, active, username, apply, attributes) "
		"VALUES (%d, 1, '%s', 0, '{\"destination_schema\": \"%s\"}')", RULE_ID, cl.username, DST_DB);
	MYSQL_QUERY_ON_ERR_CLEANUP(admin, query);
	MYSQL_QUERY_ON_ERR_CLEANUP(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	// path 1: handshake db
	conn = connect_proxy(SRC_DB);
	if (!conn) {
		goto cleanup;
	}
	val = fetch_single(conn, "SELECT DATABASE()");
	ok(val == DST_DB, "handshake path: DATABASE() should be remapped to '%s', got '%s'", DST_DB, val.c_str());
	val = fetch_single(conn, "SELECT v FROM marker");
	ok(val == "in_dst", "handshake path: marker should be 'in_dst', got '%s'", val.c_str());

	// path 2: COM_INIT_DB resets the schema, next query remaps again
	if (mysql_select_db(conn, SRC_DB)) {
		diag("mysql_select_db failed: %s", mysql_error(conn));
	}
	val = fetch_single(conn, "SELECT DATABASE()");
	ok(val == DST_DB, "COM_INIT_DB path: DATABASE() should be remapped to '%s', got '%s'", DST_DB, val.c_str());

	// path 3: USE statement resets the schema, next query remaps again
	snprintf(query, sizeof(query), "USE %s", SRC_DB);
	if (mysql_query(conn, query)) {
		diag("USE failed: %s", mysql_error(conn));
	}
	val = fetch_single(conn, "SELECT DATABASE()");
	ok(val == DST_DB, "USE path: DATABASE() should be remapped to '%s', got '%s'", DST_DB, val.c_str());
	mysql_close(conn);
	conn = NULL;

	// query cache interaction: the schema switch must happen before the cache
	// lookup, so cache keys use the remapped schema and a cache HIT still
	// leaves the session on the remapped schema
	snprintf(query, sizeof(query),
		"UPDATE mysql_query_rules SET cache_ttl=60000 WHERE rule_id=%d", RULE_ID);
	MYSQL_QUERY_ON_ERR_CLEANUP(admin, query);
	MYSQL_QUERY_ON_ERR_CLEANUP(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	conn = connect_proxy(SRC_DB);
	if (!conn) {
		goto cleanup;
	}
	val = fetch_single(conn, "SELECT v FROM marker");
	ok(val == "in_dst", "cache path: first (cache-miss) marker should be 'in_dst', got '%s'", val.c_str());
	{
		std::string hits_before = fetch_single(admin,
			"SELECT variable_value FROM stats_mysql_global WHERE variable_name='Query_Cache_count_GET_OK'");
		val = fetch_single(conn, "SELECT v FROM marker");
		ok(val == "in_dst", "cache path: second (cache-hit) marker should be 'in_dst', got '%s'", val.c_str());
		std::string hits_after = fetch_single(admin,
			"SELECT variable_value FROM stats_mysql_global WHERE variable_name='Query_Cache_count_GET_OK'");
		ok(atoll(hits_after.c_str()) > atoll(hits_before.c_str()),
			"cache path: Query_Cache_count_GET_OK should increase (before=%s, after=%s)",
			hits_before.c_str(), hits_after.c_str());
	}
	// even after a cache hit the session must stay on the remapped schema
	val = fetch_single(conn, "SELECT DATABASE()");
	ok(val == DST_DB, "cache path: DATABASE() after cache hit should be '%s', got '%s'", DST_DB, val.c_str());
	mysql_close(conn);
	conn = NULL;

	// remove the rule: behavior must revert
	snprintf(query, sizeof(query), "DELETE FROM mysql_query_rules WHERE rule_id=%d", RULE_ID);
	MYSQL_QUERY_ON_ERR_CLEANUP(admin, query);
	MYSQL_QUERY_ON_ERR_CLEANUP(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	conn = connect_proxy(SRC_DB);
	if (!conn) {
		goto cleanup;
	}
	val = fetch_single(conn, "SELECT DATABASE()");
	ok(val == SRC_DB, "after rule removal: DATABASE() should be '%s', got '%s'", SRC_DB, val.c_str());
	val = fetch_single(conn, "SELECT v FROM marker");
	ok(val == "in_src", "after rule removal: marker should be 'in_src', got '%s'", val.c_str());
	mysql_close(conn);
	conn = NULL;

cleanup:
	if (conn) {
		mysql_close(conn);
	}
	if (setup) {
		snprintf(query, sizeof(query), "DROP DATABASE IF EXISTS %s", SRC_DB);
		mysql_query(setup, query);
		snprintf(query, sizeof(query), "DROP DATABASE IF EXISTS %s", DST_DB);
		mysql_query(setup, query);
		mysql_close(setup);
	}
	snprintf(query, sizeof(query), "DELETE FROM mysql_query_rules WHERE rule_id=%d", RULE_ID);
	mysql_query(admin, query);
	mysql_query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
	mysql_close(admin);

	return exit_status();
}
