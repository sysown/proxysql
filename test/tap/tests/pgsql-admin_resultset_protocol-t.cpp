/**
 * @file pgsql-admin_resultset_protocol-t.cpp
 * @brief Regression test for #6136: admin queries whose resultset is built by a
 *   dedicated handler (cluster 'PROXY_SELECT' queries, 'SHOW PROMETHEUS METRICS',
 *   'SELECT CONFIG FILE', 'SHOW TABLE STATUS', 'SHOW FIELDS') must be answered
 *   using the PostgreSQL wire protocol when received on the PostgreSQL admin
 *   interface. Previously they were serialized with the MySQL protocol, crashing
 *   ProxySQL.
 *
 * The test also checks, on both admin interfaces, that 'SELECT CONFIG INTO OUTFILE'
 *   with an empty file name sends a single error reply, leaving the connection in sync.
 *
 * Finally, it checks the CommandComplete tag: the three entries answered by a dedicated
 *   SHOW handler must report 'SHOW', not the 'SELECT <nrows>' tag of the generic path.
 */

#include <string>
#include <sstream>
#include <vector>
#include <cstring>
#include <libpq-fe.h>

#include "mysql.h"

#include "command_line.h"
#include "tap.h"
#include "utils.h"

using std::string;
using std::vector;

// Copies of the definitions in 'include/ProxySQL_Cluster.hpp'. The admin handler
// matches them by prefix, so they must be kept identical.
const vector<string> resultset_queries {
	"PROXY_SELECT hostgroup_id, hostname, port, CASE status WHEN 'ONLINE' THEN 'ONLINE' WHEN 'SHUNNED' THEN 'ONLINE' WHEN 'OFFLINE_SOFT' THEN 'OFFLINE_SOFT' WHEN 'OFFLINE_HARD' THEN 'OFFLINE_HARD' ELSE status END status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM runtime_pgsql_servers WHERE status<>'OFFLINE_HARD' ORDER BY hostgroup_id, hostname, port",
	"PROXY_SELECT hostgroup_id, hostname, port, CASE WHEN status='SHUNNED' THEN 'ONLINE' ELSE status END AS status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM pgsql_servers_v2 WHERE status<>'OFFLINE_HARD' ORDER BY hostgroup_id, hostname, port",
	"PROXY_SELECT writer_hostgroup, reader_hostgroup, check_type, comment FROM runtime_pgsql_replication_hostgroups ORDER BY writer_hostgroup",
	"PROXY_SELECT hostgroup_id, max_num_online_servers, autocommit, free_connections_pct, init_connect, multiplex, connection_warming, throttle_connections_per_sec, ignore_session_variables, hostgroup_settings, servers_defaults, comment FROM runtime_pgsql_hostgroup_attributes ORDER BY hostgroup_id",
	"PROXY_SELECT hostname, port, username, ssl_ca, ssl_cert, ssl_key, ssl_crl, ssl_crlpath, ssl_protocol_version_range, comment FROM runtime_pgsql_servers_ssl_params ORDER BY hostname, port, username",
	"PROXY_SELECT username, password, use_ssl, default_hostgroup, transaction_persistent, fast_forward, backend, frontend, max_connections, attributes, comment FROM runtime_pgsql_users",
	"PROXY_SELECT rule_id, username, database, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, log, apply, attributes, comment FROM runtime_pgsql_query_rules ORDER BY rule_id",
	"PROXY_SELECT username, database, flagIN, destination_hostgroup, comment FROM runtime_pgsql_query_rules_fast_routing ORDER BY username, database, flagIN",
	"PROXY_SELECT hostgroup_id, hostname, port, gtid_port, status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM runtime_mysql_servers WHERE status<>'OFFLINE_HARD' ORDER BY hostgroup_id, hostname, port",
	"PROXY_SELECT hostgroup_id, hostname, port, gtid_port, status, weight, compression, max_connections, max_replication_lag, use_ssl, max_latency_ms, comment FROM mysql_servers_v2 WHERE status<>'OFFLINE_HARD' ORDER BY hostgroup_id, hostname, port",
	"PROXY_SELECT writer_hostgroup, reader_hostgroup, comment FROM runtime_mysql_replication_hostgroups ORDER BY writer_hostgroup",
	"PROXY_SELECT username, password, use_ssl, default_hostgroup, default_schema, schema_locked, transaction_persistent, fast_forward, backend, frontend, max_connections, attributes, comment FROM runtime_mysql_users",
	"PROXY_SELECT rule_id, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, ok_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, attributes, comment FROM runtime_mysql_query_rules ORDER BY rule_id",
	"PROXY_SELECT username, schemaname, flagIN, destination_hostgroup, comment FROM runtime_mysql_query_rules_fast_routing ORDER BY username, schemaname, flagIN",
	"SHOW PROMETHEUS METRICS",
	"SELECT CONFIG FILE",
	"SHOW TABLE STATUS LIKE 'pgsql_servers'",
	"SHOW FIELDS FROM pgsql_servers",
};

// The dedicated SHOW handlers ('SHOW TABLE STATUS', 'SHOW FIELDS FROM',
// 'SHOW PROMETHEUS METRICS') build their resultset outside the generic
// dispatcher, so they must report 'SHOW' as CommandComplete tag too. Every other
// query here is answered as a SELECT, hence carries a 'SELECT <nrows>' tag.
bool expects_show_tag(const string& query) {
	return query.size() > 5 && query.compare(0, 5, "SHOW ") == 0;
}

PGconn* connect_pgsql_admin(const CommandLine& cl) {
	std::stringstream cs;
	cs << "host=" << cl.pgsql_admin_host
	   << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username
	   << " password=" << cl.admin_password
	   << " dbname=postgres";
	return PQconnectdb(cs.str().c_str());
}

// Returns true if 'SELECT 1' returns exactly the expected single-row resultset.
bool check_select_1(PGconn* conn) {
	PGresult* res = PQexec(conn, "SELECT 1");
	bool rc = PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1 &&
		PQnfields(res) == 1 && strcmp(PQgetvalue(res, 0, 0), "1") == 0;
	if (!rc) {
		diag("'SELECT 1' failed: status='%s' error='%s'",
			PQresStatus(PQresultStatus(res)), PQerrorMessage(conn));
	}
	PQclear(res);
	return rc;
}

// Returns true if 'SELECT 1' returns exactly the expected single-row resultset.
bool check_mysql_select_1(MYSQL* admin) {
	if (mysql_query(admin, "SELECT 1")) {
		diag("'SELECT 1' failed: error='%s'", mysql_error(admin));
		return false;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
	bool rc = res && mysql_num_rows(res) == 1 && mysql_num_fields(res) == 1 &&
		row && row[0] && strcmp(row[0], "1") == 0;
	if (!rc) {
		diag("'SELECT 1' returned an unexpected resultset: error='%s'", mysql_error(admin));
	}
	if (res) mysql_free_result(res);
	return rc;
}

int main(int argc, char** argv) {
	CommandLine cl;

	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(resultset_queries.size() + 5);

	PGconn* conn = connect_pgsql_admin(cl);
	if (PQstatus(conn) != CONNECTION_OK) {
		BAIL_OUT("Failed to connect to PostgreSQL admin interface: %s", PQerrorMessage(conn));
	}

	for (const string& query : resultset_queries) {
		PGresult* res = PQexec(conn, query.c_str());
		ExecStatusType status = PQresultStatus(res);
		const char* tag = PQcmdStatus(res);
		// 'SHOW' for the three dedicated SHOW handlers, 'SELECT ...' for the rest
		bool tag_ok = expects_show_tag(query) ? strcmp(tag, "SHOW") == 0
			: strncmp(tag, "SELECT", sizeof("SELECT") - 1) == 0;
		ok(status == PGRES_TUPLES_OK && tag_ok,
			"PostgreSQL admin returns a resultset for '%.60s...' with the expected CommandComplete tag - expected='%s' status='%s' tag='%s' rows=%d error='%s'",
			query.c_str(), expects_show_tag(query) ? "SHOW" : "SELECT ...", PQresStatus(status),
			tag, PQntuples(res), status == PGRES_TUPLES_OK ? "" : PQerrorMessage(conn));
		PQclear(res);

		if (PQstatus(conn) != CONNECTION_OK) {
			diag("Connection lost, ProxySQL likely crashed");
			PQfinish(conn);
			return exit_status();
		}
	}

	{
		PGresult* res = PQexec(conn, "SELECT CONFIG INTO OUTFILE");
		ExecStatusType status = PQresultStatus(res);
		ok(status == PGRES_FATAL_ERROR,
			"'SELECT CONFIG INTO OUTFILE' with an empty file name returns an error - status='%s' error='%s'",
			PQresStatus(status), PQerrorMessage(conn));
		PQclear(res);
	}

	ok(check_select_1(conn), "PostgreSQL admin connection is still in sync after the error reply");
	PQfinish(conn);

	// A fresh connection over the MySQL admin interface confirms the process is alive
	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password,
		NULL, cl.admin_port, NULL, 0)) {
		BAIL_OUT("ProxySQL is not alive, MySQL admin connection failed: %s", mysql_error(admin));
	}
	ok(check_mysql_select_1(admin), "ProxySQL is still alive");

	// The empty file name fix applies to MySQL admin clients too
	int rc = mysql_query(admin, "SELECT CONFIG INTO OUTFILE");
	ok(rc != 0,
		"MySQL admin: 'SELECT CONFIG INTO OUTFILE' with an empty file name returns an error - error='%s'",
		mysql_error(admin));
	ok(check_mysql_select_1(admin), "MySQL admin connection is still in sync after the error reply");
	mysql_close(admin);

	return exit_status();
}
