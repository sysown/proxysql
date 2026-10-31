#include "tap.h"
#include "ProxySQL_PluginManager.h"
#include "ProxySQL_ServerDiscovery.h"
#include "ProxySQL_Cluster.hpp"
#include "MySQL_Thread.h"
#include "ProxySQL_Statistics.hpp"
#include "MySQL_Monitor.hpp"
#include "PgSQL_HostGroups_Manager.h"
#include "proxysql_admin.h"
#include "proxysql_utils.h"
#include "test_globals.h"
#include "test_init.h"

#include "ProxySQL_ConfigurationAccess.h"

#include <algorithm>
#include <cstdlib>
#include <dlfcn.h>
#include <memory>
#include <set>
#include <string>
#include <unistd.h>
#include <utility>
#include <vector>

extern ProxySQL_Admin* GloAdmin;
extern ProxySQL_Statistics* GloProxyStats;
extern MySQL_Monitor* GloMyMon;

#ifndef PROXYSQL_FAKE_PLUGIN_PATH
#error "PROXYSQL_FAKE_PLUGIN_PATH must be defined"
#endif

// A server reload (Admin LOAD, managed discovery install, Cluster pull) keeps
// the live rows of hostgroups held by managed discovery claims instead of
// replacing them with configuration rows. Unclaimed hostgroups are unchanged.

namespace {

struct Observed {
	ProxySQL_ServerRuntimeSnapshot snapshot {};
	std::vector<std::pair<uint64_t, bool>> acks;
};

class ManagedController final : public ProxySQL_ServerDiscoveryController {
public:
	explicit ManagedController(Observed& value) : value_(value) {}
	void runtime_configuration_installed(ProxySQL_ServerRuntimeSnapshot snapshot) override {
		value_.snapshot = std::move(snapshot);
	}
	void desired_set_applied(uint64_t generation, bool applied) override {
		value_.acks.emplace_back(generation, applied);
	}
	void shutdown() override {}
private:
	Observed& value_;
};

void destroy_controller(ProxySQL_ServerDiscoveryController* value) { delete value; }

ProxySQL_ServerHostgroupClaim role_claim(ProxySQL_ServerProtocol protocol,
	uint32_t writer, uint32_t reader) {
	ProxySQL_ServerHostgroupClaim claim {writer, reader};
	claim.role_monitor.kind = protocol == ProxySQL_ServerProtocol::mysql
		? ProxySQL_ServerRoleMonitor::mysql_replication
		: ProxySQL_ServerRoleMonitor::pgsql_replication;
	return claim;
}

void create_server_load_schema(SQLite3DB& db) {
	db.execute("CREATE TABLE mysql_servers (hostgroup_id INTEGER, hostname TEXT, port INTEGER, gtid_port INTEGER, status TEXT, weight INTEGER, compression INTEGER, max_connections INTEGER, max_replication_lag INTEGER, use_ssl INTEGER, max_latency_ms INTEGER, comment TEXT)");
	db.execute("CREATE TABLE pgsql_servers (hostgroup_id INTEGER, hostname TEXT, port INTEGER, status TEXT, weight INTEGER, compression INTEGER, max_connections INTEGER, max_replication_lag INTEGER, use_ssl INTEGER, max_latency_ms INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INTEGER, reader_hostgroup INTEGER, check_type TEXT, comment TEXT)");
	db.execute("CREATE TABLE pgsql_replication_hostgroups (writer_hostgroup INTEGER, reader_hostgroup INTEGER, check_type TEXT, comment TEXT)");
	db.execute("CREATE TABLE mysql_group_replication_hostgroups (writer_hostgroup INTEGER, backup_writer_hostgroup INTEGER, reader_hostgroup INTEGER, offline_hostgroup INTEGER, active INTEGER, max_writers INTEGER, writer_is_also_reader INTEGER, max_transactions_behind INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_galera_hostgroups (writer_hostgroup INTEGER, backup_writer_hostgroup INTEGER, reader_hostgroup INTEGER, offline_hostgroup INTEGER, active INTEGER, max_writers INTEGER, writer_is_also_reader INTEGER, max_transactions_behind INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_aws_aurora_hostgroups (writer_hostgroup INTEGER, reader_hostgroup INTEGER, active INTEGER, aurora_port INTEGER, domain_name TEXT, max_lag_ms INTEGER, check_interval_ms INTEGER, check_timeout_ms INTEGER, writer_is_also_reader INTEGER, new_reader_weight INTEGER, add_lag_ms INTEGER, min_lag_ms INTEGER, lag_num_checks INTEGER, autopurge_missing_checks INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_aws_rds_bgd_hostgroups (writer_hostgroup INTEGER, reader_hostgroup INTEGER, green_writer_hostgroup INTEGER, green_reader_hostgroup INTEGER, active INTEGER, writer_is_also_reader INTEGER, check_interval_ms INTEGER, check_timeout_ms INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_hostgroup_attributes (hostgroup_id INTEGER, max_num_online_servers INTEGER, autocommit INTEGER, free_connections_pct INTEGER, init_connect TEXT, multiplex INTEGER, connection_warming INTEGER, throttle_connections_per_sec INTEGER, ignore_session_variables TEXT, hostgroup_settings TEXT, comment TEXT)");
	db.execute("CREATE TABLE pgsql_hostgroup_attributes (hostgroup_id INTEGER, max_num_online_servers INTEGER, free_connections_pct INTEGER, init_connect TEXT, multiplex INTEGER, connection_warming INTEGER, throttle_connections_per_sec INTEGER, ignore_session_variables TEXT, hostgroup_settings TEXT, comment TEXT)");
	db.execute("CREATE TABLE mysql_servers_ssl_params (hostgroup_id INTEGER, hostname TEXT, port INTEGER, username TEXT)");
	db.execute("CREATE TABLE pgsql_servers_ssl_params (hostgroup_id INTEGER, hostname TEXT, port INTEGER, username TEXT)");
}

/** Admin tables written by a full save from runtime (column sets of the real save). */
void create_server_save_schema(SQLite3DB& db) {
	db.execute("CREATE TABLE mysql_servers (hostgroup_id INTEGER, hostname TEXT, port INTEGER, gtid_port INTEGER, status TEXT, weight INTEGER, compression INTEGER, max_connections INTEGER, max_replication_lag INTEGER, use_ssl INTEGER, max_latency_ms INTEGER, comment TEXT)");
	db.execute("CREATE TABLE pgsql_servers (hostgroup_id INTEGER, hostname TEXT, port INTEGER, status TEXT, weight INTEGER, compression INTEGER, max_connections INTEGER, max_replication_lag INTEGER, use_ssl INTEGER, max_latency_ms INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INTEGER, reader_hostgroup INTEGER, check_type TEXT, comment TEXT)");
	db.execute("CREATE TABLE mysql_group_replication_hostgroups (writer_hostgroup INTEGER, backup_writer_hostgroup INTEGER, reader_hostgroup INTEGER, offline_hostgroup INTEGER, active INTEGER, max_writers INTEGER, writer_is_also_reader INTEGER, max_transactions_behind INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_galera_hostgroups (writer_hostgroup INTEGER, backup_writer_hostgroup INTEGER, reader_hostgroup INTEGER, offline_hostgroup INTEGER, active INTEGER, max_writers INTEGER, writer_is_also_reader INTEGER, max_transactions_behind INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_aws_aurora_hostgroups (writer_hostgroup INTEGER, reader_hostgroup INTEGER, active INTEGER, aurora_port INTEGER, domain_name TEXT, max_lag_ms INTEGER, check_interval_ms INTEGER, check_timeout_ms INTEGER, writer_is_also_reader INTEGER, new_reader_weight INTEGER, add_lag_ms INTEGER, min_lag_ms INTEGER, lag_num_checks INTEGER, autopurge_missing_checks INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_aws_rds_bgd_hostgroups (writer_hostgroup INTEGER, reader_hostgroup INTEGER, green_writer_hostgroup INTEGER, green_reader_hostgroup INTEGER, active INTEGER, writer_is_also_reader INTEGER, check_interval_ms INTEGER, check_timeout_ms INTEGER, comment TEXT)");
	db.execute("CREATE TABLE mysql_hostgroup_attributes (hostgroup_id INTEGER, max_num_online_servers INTEGER, autocommit INTEGER, free_connections_pct INTEGER, init_connect TEXT, multiplex INTEGER, connection_warming INTEGER, throttle_connections_per_sec INTEGER, ignore_session_variables TEXT, hostgroup_settings TEXT, servers_defaults TEXT, comment TEXT)");
	db.execute("CREATE TABLE mysql_servers_ssl_params (hostname TEXT, port INTEGER, username TEXT, ssl_ca TEXT, ssl_cert TEXT, ssl_key TEXT, ssl_capath TEXT, ssl_crl TEXT, ssl_crlpath TEXT, ssl_cipher TEXT, tls_version TEXT, comment TEXT)");
	db.execute("CREATE TABLE pgsql_replication_hostgroups (writer_hostgroup INTEGER, reader_hostgroup INTEGER, check_type TEXT, comment TEXT)");
	db.execute("CREATE TABLE pgsql_hostgroup_attributes (hostgroup_id INTEGER, max_num_online_servers INTEGER, autocommit INTEGER, free_connections_pct INTEGER, init_connect TEXT, multiplex INTEGER, connection_warming INTEGER, throttle_connections_per_sec INTEGER, ignore_session_variables TEXT, hostgroup_settings TEXT, servers_defaults TEXT, comment TEXT)");
	db.execute("CREATE TABLE pgsql_servers_ssl_params (hostname TEXT, port INTEGER, username TEXT, ssl_ca TEXT, ssl_cert TEXT, ssl_key TEXT, ssl_crl TEXT, ssl_crlpath TEXT, ssl_protocol_version_range TEXT, comment TEXT)");
}

/** Inserts one configuration row into main.mysql_servers or main.pgsql_servers. */
void insert_config_row(SQLite3DB& db, bool mysql, uint32_t hostgroup,
	const std::string& hostname, uint16_t port, int weight) {
	const std::string sql = mysql
		? "INSERT INTO mysql_servers VALUES (" + std::to_string(hostgroup) + ",'" + hostname + "'," +
			std::to_string(port) + ",0,'ONLINE'," + std::to_string(weight) + ",0,1000,0,1,0,'')"
		: "INSERT INTO pgsql_servers VALUES (" + std::to_string(hostgroup) + ",'" + hostname + "'," +
			std::to_string(port) + ",'ONLINE'," + std::to_string(weight) + ",0,1000,0,1,0,'')";
	db.execute(sql.c_str());
}

/** Builds the peer resultset of a Cluster v1 pull (12 MySQL or 11 PostgreSQL columns). */
SQLite3_result* peer_rows(bool mysql, const std::vector<ProxySQL_ServerRow>& rows) {
	auto* result = new SQLite3_result(mysql ? 12 : 11);
	for (const auto& row : rows) {
		std::vector<std::string> values {std::to_string(row.hostgroup_id), row.hostname,
			std::to_string(row.port)};
		if (mysql) values.push_back(std::to_string(row.gtid_port));
		values.insert(values.end(), {row.status, std::to_string(row.weight),
			std::to_string(row.compression), std::to_string(row.max_connections),
			std::to_string(row.max_replication_lag), std::to_string(row.use_ssl),
			std::to_string(row.max_latency_ms), row.comment});
		std::vector<char*> fields;
		for (auto& value : values) fields.push_back(value.data());
		result->add_row(fields.data());
	}
	return result;
}

void load_servers(bool mysql) {
	if (mysql) {
		GloAdmin->mysql_servers_wrlock();
		GloAdmin->load_mysql_servers_to_runtime();
		GloAdmin->mysql_servers_wrunlock();
	} else {
		GloAdmin->pgsql_servers_wrlock();
		GloAdmin->load_pgsql_servers_to_runtime();
		GloAdmin->pgsql_servers_wrunlock();
	}
}

bool install_claims(ProxySQL_ServerProtocol protocol, uint64_t revision,
	const std::vector<ProxySQL_ServerHostgroupClaim>& claims, uint64_t& generation) {
	std::string error;
	proxysql_lock_configuration();
	const bool installed = proxysql_install_managed_discovery_locked(
		protocol, revision, claims, generation, error);
	proxysql_unlock_configuration();
	if (!installed) diag("managed discovery install failed: %s", error.c_str());
	return installed;
}

bool apply_rows(ProxySQL_PluginManager& manager, Observed& observed,
	ProxySQL_ServerProtocol protocol, std::vector<uint32_t> scope,
	std::vector<ProxySQL_ServerRow> rows) {
	const size_t before = observed.acks.size();
	return manager.post_server_desired_set({protocol, observed.snapshot.generation,
		std::move(scope), std::move(rows), ProxySQL_ServerPersistence::runtime_only}) &&
		GloAdmin->drain_server_discovery_updates() == 1 &&
		observed.acks.size() == before + 1 && observed.acks.back().second;
}

std::unique_ptr<SQLite3_result> runtime_rows(bool mysql) {
	return std::unique_ptr<SQLite3_result>(mysql ? MyHGM->dump_table_mysql("mysql_servers") :
		PgHGM->dump_table_pgsql("pgsql_servers"));
}

const SQLite3_row* find_row(const SQLite3_result& rows, uint32_t hg,
	const std::string& hostname, uint16_t port) {
	for (const auto* row : rows.rows) {
		if (row != nullptr && row->fields != nullptr &&
			static_cast<uint32_t>(strtoul(row->fields[0], nullptr, 10)) == hg &&
			hostname == row->fields[1] &&
			static_cast<uint16_t>(strtoul(row->fields[2], nullptr, 10)) == port) return row;
	}
	return nullptr;
}

/** Status text of a runtime row, or "" when the row is absent. */
std::string row_status(bool mysql, uint32_t hg, const std::string& hostname, uint16_t port) {
	const auto rows = runtime_rows(mysql);
	const SQLite3_row* row = rows ? find_row(*rows, hg, hostname, port) : nullptr;
	return row != nullptr && row->fields[mysql ? 4 : 3] ? row->fields[mysql ? 4 : 3] : "";
}

/** Weight of a runtime row, or -1 when the row is absent. */
long row_weight(bool mysql, uint32_t hg, const std::string& hostname, uint16_t port) {
	const auto rows = runtime_rows(mysql);
	const SQLite3_row* row = rows ? find_row(*rows, hg, hostname, port) : nullptr;
	return row != nullptr && row->fields[mysql ? 5 : 4] ? atol(row->fields[mysql ? 5 : 4]) : -1;
}

/** The HGM server object of a row: the same object means its connection pool survived. */
const void* server_object(bool mysql, uint32_t hg, const std::string& hostname, uint16_t port) {
	const void* server = nullptr;
	if (mysql) {
		MyHGM->wrlock();
		server = MyHGM->find_server_in_hg(hg, hostname, port);
		MyHGM->wrunlock();
	} else {
		PgHGM->wrlock();
		server = PgHGM->find_server_in_hg(hg, hostname, port);
		PgHGM->wrunlock();
	}
	return server;
}

bool shun(bool mysql, const std::string& hostname, uint16_t port) {
	char* host = const_cast<char*>(hostname.c_str());
	return mysql ? MyHGM->shun_and_killall(host, port) : PgHGM->shun_and_killall(host, port);
}

std::set<uint32_t> as_set(const std::vector<uint32_t>& values) {
	return std::set<uint32_t>(values.begin(), values.end());
}

/** "hostgroup:hostname" of every row of main.mysql_servers or main.pgsql_servers, sorted. */
std::vector<std::string> saved_servers(SQLite3DB& db, bool mysql) {
	char* error = nullptr;
	int cols = 0, affected = 0;
	SQLite3_result* raw = nullptr;
	db.execute_statement(mysql
		? "SELECT hostgroup_id, hostname FROM main.mysql_servers ORDER BY hostgroup_id, hostname"
		: "SELECT hostgroup_id, hostname FROM main.pgsql_servers ORDER BY hostgroup_id, hostname",
		&error, &cols, &affected, &raw);
	if (error) { diag("saved_servers failed: %s", error); free(error); }
	std::unique_ptr<SQLite3_result> rows(raw);
	std::vector<std::string> values;
	if (rows) for (const auto* row : rows->rows)
		values.push_back(std::string(row->fields[0]) + ":" + row->fields[1]);
	return values;
}

/**
 * A save from runtime into main (Admin SAVE ... FROM RUNTIME, and the save that
 * follows a Cluster pull) leaves the configuration rows of claimed hostgroups
 * as they are: the live discovered servers there are runtime state, never
 * configuration. Claim A holds 901/902; 99 is unclaimed.
 */
void test_save_keeps_claimed_configuration(bool mysql, uint16_t port) {
	const char* label = mysql ? "MySQL" : "PostgreSQL";
	SQLite3DB save_db;
	char memory_db[] = ":memory:";
	save_db.open(memory_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	create_server_save_schema(save_db);
	insert_config_row(save_db, mysql, 901, "configured-writer.example", port, 1);
	insert_config_row(save_db, mysql, 902, "configured-reader.example", port, 1);
	insert_config_row(save_db, mysql, 99, "old-plain.example", port, 1);
	SQLite3DB* admin_db = GloAdmin->admindb;
	GloAdmin->admindb = &save_db;
	if (mysql) {
		GloAdmin->mysql_servers_wrlock();
		GloAdmin->save_mysql_servers_runtime_to_database(false);
		GloAdmin->mysql_servers_wrunlock();
	} else {
		GloAdmin->pgsql_servers_wrlock();
		GloAdmin->save_pgsql_servers_runtime_to_database(false);
		GloAdmin->pgsql_servers_wrunlock();
	}
	GloAdmin->admindb = admin_db;
	const auto saved = saved_servers(save_db, mysql);
	const std::vector<std::string> expected {"99:peer-plain.example",
		"901:configured-writer.example", "902:configured-reader.example"};
	ok(saved == expected && row_status(mysql, 901, "writer.example", port) == "ONLINE",
		"%s: a save from runtime keeps the configuration rows of claimed hostgroups, never writes "
		"their live discovered servers, and saves the runtime rows of unclaimed hostgroups", label);
}

/** Pure rules: which hostgroups a reload keeps, before any HGM is involved. */
void test_retained_hostgroup_rules() {
	const auto mysql = ProxySQL_ServerProtocol::mysql;
	const auto a = role_claim(mysql, 901, 902);
	const auto b = role_claim(mysql, 911, 912);
	ok(as_set(proxysql_server_reload_retained_hostgroups({a, b}, {a, b})) ==
		std::set<uint32_t>({901, 902, 911, 912}),
		"rules: unchanged claims keep every claimed hostgroup");
	ok(proxysql_server_reload_retained_hostgroups({}, {}).empty() &&
		proxysql_server_reload_retained_hostgroups({a}, {}).empty() &&
		proxysql_server_reload_retained_hostgroups({}, {a}).empty(),
		"rules: no claim, a released claim and a new claim keep nothing");
	ok(as_set(proxysql_server_reload_retained_hostgroups({a, b}, {b})) ==
		std::set<uint32_t>({911, 912}),
		"rules: a removed claim keeps nothing while a surviving claim keeps its hostgroups");
	const auto moved = role_claim(mysql, 901, 903);
	ok(proxysql_server_reload_retained_hostgroups({a}, {moved}).empty(),
		"rules: a claim that moves one hostgroup keeps neither, not even the shared writer");
	auto kind_changed = a;
	kind_changed.role_monitor.kind = ProxySQL_ServerRoleMonitor::none;
	auto placement_changed = a;
	placement_changed.role_monitor.writer_is_also_reader = 1;
	ProxySQL_ServerHostgroupClaim aurora {931, 932};
	aurora.role_monitor.kind = ProxySQL_ServerRoleMonitor::mysql_aws_aurora;
	aurora.role_monitor.domain_name = ".cluster-a.example";
	auto aurora_domain = aurora;
	aurora_domain.role_monitor.domain_name = ".cluster-b.example";
	auto aurora_port = aurora;
	aurora_port.role_monitor.aurora_port = 3307;
	ok(proxysql_server_reload_retained_hostgroups({a}, {kind_changed}).empty() &&
		proxysql_server_reload_retained_hostgroups({a}, {placement_changed}).empty() &&
		proxysql_server_reload_retained_hostgroups({aurora}, {aurora_domain}).empty() &&
		proxysql_server_reload_retained_hostgroups({aurora}, {aurora_port}).empty(),
		"rules: the same hostgroups with another monitor kind, placement, domain or port keep nothing");
	auto tuned = aurora;
	tuned.role_monitor.check_interval_ms = 5000;
	tuned.role_monitor.max_lag_ms = 1000;
	ok(as_set(proxysql_server_reload_retained_hostgroups({aurora}, {tuned})) ==
		std::set<uint32_t>({931, 932}),
		"rules: a change of monitor tuning only keeps the claimed rows");
	const auto zero = role_claim(mysql, 0, 1);
	ok(as_set(proxysql_server_reload_retained_hostgroups({zero}, {zero})) ==
		std::set<uint32_t>({0, 1}),
		"rules: hostgroup 0 is an ordinary claimed hostgroup");
	ProxySQL_ServerHostgroupClaim bgd {921, 922};
	bgd.role_monitor.kind = ProxySQL_ServerRoleMonitor::mysql_aws_rds_blue_green;
	bgd.role_monitor.green_writer_hostgroup = 923;
	bgd.role_monitor.green_reader_hostgroup = 924;
	auto bgd_moved = bgd;
	bgd_moved.role_monitor.green_reader_hostgroup = 925;
	ok(as_set(proxysql_server_reload_retained_hostgroups({bgd}, {bgd})) ==
		std::set<uint32_t>({921, 922, 923, 924}) &&
		proxysql_server_reload_retained_hostgroups({bgd}, {bgd_moved}).empty(),
		"rules: blue/green claims keep their green hostgroups and a moved green pair keeps nothing");
	// Claim validation ignores the fields of another monitor kind, so a plugin
	// may leave anything there: they are not part of the claim identity.
	auto a_other_fields = a;
	a_other_fields.role_monitor.domain_name = ".ignored.example";
	a_other_fields.role_monitor.aurora_port = 3399;
	a_other_fields.role_monitor.green_writer_hostgroup = 941;
	a_other_fields.role_monitor.green_reader_hostgroup = 942;
	auto aurora_green = aurora;
	aurora_green.role_monitor.green_writer_hostgroup = 943;
	auto none_claim = role_claim(mysql, 951, 952);
	none_claim.role_monitor.kind = ProxySQL_ServerRoleMonitor::none;
	auto none_other_fields = none_claim;
	none_other_fields.role_monitor.domain_name = ".ignored.example";
	none_other_fields.role_monitor.green_reader_hostgroup = 953;
	ok(as_set(proxysql_server_reload_retained_hostgroups({a}, {a_other_fields})) ==
		std::set<uint32_t>({901, 902}) &&
		as_set(proxysql_server_reload_retained_hostgroups({aurora}, {aurora_green})) ==
		std::set<uint32_t>({931, 932}) &&
		as_set(proxysql_server_reload_retained_hostgroups({none_claim}, {none_other_fields})) ==
		std::set<uint32_t>({951, 952}),
		"rules: Aurora and blue/green fields of a claim of another kind are not part of its identity");
}

/** MySQL gtid_port is an operator setting: an edit in a retained hostgroup is counted. */
void test_reload_counts_gtid_port_edit() {
	SQLite3DB db;
	char memory_db[] = ":memory:";
	db.open(memory_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	db.execute(MYHGM_MYSQL_SERVERS);
	db.execute(MYHGM_MYSQL_SERVERS_INCOMING);
	db.execute("INSERT INTO mysql_servers VALUES (901,'gtid.example',3306,0,5,0,0,1000,0,1,0,'',1901)");
	db.execute("INSERT INTO mysql_servers VALUES (902,'same.example',3306,7000,5,0,0,1000,0,1,0,'',1902)");
	db.execute("INSERT INTO mysql_servers_incoming VALUES (901,'gtid.example',3306,7000,5,0,0,1000,0,1,0,'')");
	db.execute("INSERT INTO mysql_servers_incoming VALUES (902,'same.example',3306,7000,5,0,0,1000,0,1,0,'')");
	std::vector<ProxySQL_ServerReloadOverride> overrides;
	std::string error;
	ok(proxysql_collect_server_reload_overrides(db, ProxySQL_ServerProtocol::mysql, {901, 902},
			overrides, error) &&
		overrides.size() == 1 && overrides[0].hostgroup_id == 901 &&
		overrides[0].ignored == 0 && overrides[0].changed == 1,
		"MySQL rows: a gtid_port edit to a live server counts as a change, an equal gtid_port does not");
}

/** The incoming-table rewrite on plain HGM tables, including OFFLINE_HARD rows. */
void test_retain_rows_on_hgm_tables(bool mysql) {
	const auto protocol = mysql ? ProxySQL_ServerProtocol::mysql : ProxySQL_ServerProtocol::pgsql;
	const char* label = mysql ? "MySQL" : "PostgreSQL";
	SQLite3DB db;
	char memory_db[] = ":memory:";
	db.open(memory_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	const std::string table = mysql ? "mysql_servers" : "pgsql_servers";
	const std::string gtid = mysql ? "0," : "";
	db.execute(mysql ? MYHGM_MYSQL_SERVERS : MYHGM_PgSQL_SERVERS);
	db.execute(mysql ? MYHGM_MYSQL_SERVERS_INCOMING : MYHGM_PgSQL_SERVERS_INCOMING);
	const auto live = [&](uint32_t hg, const char* host, int status, int weight) {
		const std::string sql = "INSERT INTO " + table + " VALUES (" + std::to_string(hg) + ",'" +
			host + "',3306," + gtid + std::to_string(weight) + "," + std::to_string(status) +
			",0,1000,0,1,0,'live'," + std::to_string(1000 + hg) + ")";
		db.execute(sql.c_str());
	};
	const auto incoming = [&](uint32_t hg, const char* host, int weight,
		int status = MYSQL_SERVER_STATUS_ONLINE, const char* comment = "live") {
		const std::string sql = "INSERT INTO " + table + "_incoming VALUES (" + std::to_string(hg) +
			",'" + host + "',3306," + gtid + std::to_string(weight) + "," + std::to_string(status) +
			",0,1000,0,1,0,'" + comment + "')";
		db.execute(sql.c_str());
	};
	live(901, "writer.example", MYSQL_SERVER_STATUS_ONLINE, 5);
	live(901, "gone.example", MYSQL_SERVER_STATUS_OFFLINE_HARD, 5);
	live(902, "reader.example", MYSQL_SERVER_STATUS_SHUNNED, 6);
	live(902, "soft.example", MYSQL_SERVER_STATUS_ONLINE, 6);
	live(99, "plain.example", MYSQL_SERVER_STATUS_ONLINE, 7);
	incoming(901, "writer.example", 77);                 // operator edit: weight
	incoming(901, "configured.example", 1);              // not live
	incoming(902, "reader.example", 6);                  // ONLINE vs monitor SHUNNED: not an edit
	incoming(902, "soft.example", 6, MYSQL_SERVER_STATUS_OFFLINE_SOFT); // operator edit: status
	incoming(99, "plain.example", 8, MYSQL_SERVER_STATUS_ONLINE, "config");
	const std::string count_sql = "SELECT hostgroup_id, hostname, weight, status FROM " + table +
		"_incoming ORDER BY hostgroup_id, hostname";
	const auto snapshot = [&]() {
		char* error = nullptr;
		int cols = 0, affected = 0;
		SQLite3_result* raw = nullptr;
		db.execute_statement(count_sql.c_str(), &error, &cols, &affected, &raw);
		if (error) free(error);
		std::vector<std::string> rows;
		if (raw) for (const auto* row : raw->rows)
			rows.push_back(std::string(row->fields[0]) + ":" + row->fields[1] + ":" +
				row->fields[2] + ":" + row->fields[3]);
		delete raw;
		return rows;
	};
	const auto before = snapshot();
	ok(proxysql_retain_server_reload_rows(db, protocol, {}) && snapshot() == before,
		"%s rows: an empty retained set leaves the incoming rows untouched", label);
	std::vector<ProxySQL_ServerReloadOverride> overrides;
	std::string error;
	const bool collected = proxysql_collect_server_reload_overrides(
		db, protocol, {901, 902}, overrides, error);
	ok(collected && overrides.size() == 2 &&
		overrides[0].hostgroup_id == 901 && overrides[0].ignored == 1 && overrides[0].changed == 1 &&
		overrides[1].hostgroup_id == 902 && overrides[1].ignored == 0 && overrides[1].changed == 1,
		"%s rows: per hostgroup, configured servers that are not live and operator edits of live "
		"servers are counted, monitor-owned status is not", label);
	ok(proxysql_retain_server_reload_rows(db, protocol, {901, 902}, "configured"),
		"%s rows: retention succeeds", label);
	const std::vector<std::string> expected {
		"99:plain.example:8:0",
		"901:writer.example:5:" + std::to_string(MYSQL_SERVER_STATUS_ONLINE),
		"902:reader.example:6:" + std::to_string(MYSQL_SERVER_STATUS_SHUNNED),
		"902:soft.example:6:" + std::to_string(MYSQL_SERVER_STATUS_ONLINE)};
	ok(snapshot() == expected,
		"%s rows: claimed hostgroups take their live rows and status, configuration rows there are "
		"ignored, OFFLINE_HARD rows are not kept, and unclaimed rows are untouched", label);

	// A failure while copying the live rows rolls back: the reload stays a plain replace.
	db.execute(("DELETE FROM " + table + "_incoming").c_str());
	incoming(901, "writer.example", 77);
	incoming(99, "plain.example", 8, MYSQL_SERVER_STATUS_ONLINE, "config");
	live(901, "boom.example", MYSQL_SERVER_STATUS_ONLINE, 5);
	db.execute(("CREATE TRIGGER fail_copy BEFORE INSERT ON " + table + "_incoming"
		" WHEN NEW.hostname='boom.example' BEGIN SELECT RAISE(ABORT, 'injected failure'); END").c_str());
	const auto before_failure = snapshot();
	ok(!proxysql_retain_server_reload_rows(db, protocol, {901, 902}, "configured") &&
		snapshot() == before_failure,
		"%s rows: a failed copy rolls back the incoming rows and reports failure", label);
}

/**
 * A live row in OFFLINE_HARD is a server being removed whose row lingers until
 * its used connections end. A reload treats it as absent in a claimed hostgroup.
 */
void test_retain_rows_ignore_offline_hard(bool mysql) {
	const auto protocol = mysql ? ProxySQL_ServerProtocol::mysql : ProxySQL_ServerProtocol::pgsql;
	const char* label = mysql ? "MySQL" : "PostgreSQL";
	SQLite3DB db;
	char memory_db[] = ":memory:";
	db.open(memory_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	const std::string table = mysql ? "mysql_servers" : "pgsql_servers";
	const std::string gtid = mysql ? "0," : "";
	db.execute(mysql ? MYHGM_MYSQL_SERVERS : MYHGM_PgSQL_SERVERS);
	db.execute(mysql ? MYHGM_MYSQL_SERVERS_INCOMING : MYHGM_PgSQL_SERVERS_INCOMING);
	const auto insert = [&](const std::string& target, uint32_t hg, const char* host, int status,
		const std::string& tail) {
		const std::string sql = "INSERT INTO " + target + " VALUES (" + std::to_string(hg) + ",'" +
			host + "',3306," + gtid + "5," + std::to_string(status) + ",0,1000,0,1,0,''" + tail + ")";
		db.execute(sql.c_str());
	};
	const auto live = [&](uint32_t hg, const char* host, int status) {
		insert(table, hg, host, status, "," + std::to_string(1000 + hg));
	};
	const auto incoming = [&](uint32_t hg, const char* host) {
		insert(table + "_incoming", hg, host, MYSQL_SERVER_STATUS_ONLINE, "");
	};
	// Claimed 901: the configuration row has the key of a live OFFLINE_HARD row.
	live(901, "hard.example", MYSQL_SERVER_STATUS_OFFLINE_HARD);
	incoming(901, "hard.example");
	// 911 was claimed and is released by this reload: it is not retained.
	live(911, "released.example", MYSQL_SERVER_STATUS_OFFLINE_HARD);
	incoming(911, "released.example");
	std::vector<ProxySQL_ServerReloadOverride> overrides;
	std::string error;
	ok(proxysql_collect_server_reload_overrides(db, protocol, {901, 902}, overrides, error) &&
		overrides.size() == 1 && overrides[0].hostgroup_id == 901 &&
		overrides[0].ignored == 1 && overrides[0].changed == 0,
		"%s rows: a configuration row matching a live OFFLINE_HARD row counts as not live", label);
	char* sql_error = nullptr;
	int cols = 0, affected = 0;
	SQLite3_result* raw = nullptr;
	const bool retained = proxysql_retain_server_reload_rows(db, protocol, {901, 902}, "configured");
	db.execute_statement(("SELECT hostgroup_id, hostname, status FROM " + table +
		"_incoming ORDER BY hostgroup_id, hostname").c_str(), &sql_error, &cols, &affected, &raw);
	if (sql_error) free(sql_error);
	std::unique_ptr<SQLite3_result> rows(raw);
	ok(retained && rows && rows->rows.size() == 1 &&
		std::string(rows->rows[0]->fields[0]) == "911" &&
		std::string(rows->rows[0]->fields[1]) == "released.example" &&
		std::string(rows->rows[0]->fields[2]) == std::to_string(MYSQL_SERVER_STATUS_ONLINE),
		"%s rows: a claimed hostgroup neither keeps nor revives an OFFLINE_HARD row, and a "
		"hostgroup released in the same reload keeps its configuration row", label);
}

/**
 * Desired-set merge with lingering OFFLINE_HARD runtime rows. Active claims:
 * A = 901/902 and B = 911/912 with a native monitor, C = 921/922 with none.
 */
void test_merge_ignores_offline_hard(ProxySQL_ServerProtocol protocol, uint16_t port) {
	const char* label = protocol == ProxySQL_ServerProtocol::mysql ? "MySQL" : "PostgreSQL";
	const auto row = [port](uint32_t hg, const char* host, const char* status) {
		ProxySQL_ServerRow value {hg, host, port};
		value.status = status;
		return value;
	};
	ProxySQL_ServerRuntimeSnapshot current {};
	current.protocol = protocol;
	current.servers = {
		row(901, "hard-only.example", "OFFLINE_HARD"),
		row(901, "moved.example", "OFFLINE_HARD"),
		row(902, "moved.example", "SHUNNED"),
		row(902, "soft.example", "OFFLINE_SOFT"),
		row(911, "other-hard.example", "OFFLINE_HARD"),
		row(911, "other-live.example", "ONLINE"),
		row(921, "none-hard.example", "OFFLINE_HARD"),
		row(922, "none-shunned.example", "SHUNNED")};
	const auto merge = [&](std::vector<uint32_t> scope, std::vector<ProxySQL_ServerRow> rows,
		std::vector<ProxySQL_ServerRow>& merged) {
		std::string error;
		const bool merged_ok = proxysql_merge_server_desired_set(current, {protocol, 1,
			std::move(scope), std::move(rows), ProxySQL_ServerPersistence::runtime_only}, merged, error);
		if (!merged_ok) diag("%s merge failed: %s", label, error.c_str());
		return merged_ok;
	};
	const auto status_of = [](const std::vector<ProxySQL_ServerRow>& merged, uint32_t hg,
		const std::string& host) {
		for (const auto& value : merged)
			if (value.hostgroup_id == hg && value.hostname == host) return value.status;
		return std::string();
	};

	auto hard_only = row(901, "hard-only.example", "ONLINE");
	hard_only.weight = 3;
	std::vector<ProxySQL_ServerRow> claim_a;
	const bool merged_a = merge({901, 902},
		{hard_only, row(901, "moved.example", "ONLINE"), row(902, "soft.example", "ONLINE")}, claim_a);
	const auto hard_only_row = std::find_if(claim_a.begin(), claim_a.end(),
		[](const ProxySQL_ServerRow& value) { return value.hostname == "hard-only.example"; });
	ok(merged_a && hard_only_row != claim_a.end() && hard_only_row->hostgroup_id == 901 &&
		hard_only_row->status == "ONLINE" && hard_only_row->weight == 3 &&
		std::count_if(claim_a.begin(), claim_a.end(), [](const ProxySQL_ServerRow& value) {
			return value.hostname == "hard-only.example"; }) == 1,
		"%s merge: an endpoint live only as OFFLINE_HARD takes the desired row and status", label);
	ok(merged_a && status_of(claim_a, 902, "moved.example") == "SHUNNED" &&
		status_of(claim_a, 901, "moved.example").empty(),
		"%s merge: native placement comes from the live rows, an OFFLINE_HARD row is not kept", label);
	ok(merged_a && status_of(claim_a, 902, "soft.example") == "OFFLINE_SOFT",
		"%s merge: a live OFFLINE_SOFT status still wins over the desired status", label);
	ok(merged_a && status_of(claim_a, 911, "other-hard.example").empty() &&
		status_of(claim_a, 911, "other-live.example") == "ONLINE" &&
		status_of(claim_a, 921, "none-hard.example").empty() &&
		status_of(claim_a, 922, "none-shunned.example") == "SHUNNED",
		"%s merge: rows of other claims are kept except OFFLINE_HARD rows", label);
	std::vector<ProxySQL_ServerRow> claim_c;
	ok(merge({921, 922}, {row(921, "none-hard.example", "ONLINE"),
			row(922, "none-shunned.example", "ONLINE")}, claim_c) &&
		status_of(claim_c, 921, "none-hard.example") == "ONLINE" &&
		status_of(claim_c, 922, "none-shunned.example") == "SHUNNED",
		"%s merge: without a monitor an OFFLINE_HARD endpoint takes the desired status, "
		"a SHUNNED one keeps its status", label);
}

} // namespace

int main() {
	plan(9 + 1 + 2 * 5 + 2 * 2 + 2 * (18 + 5));
	test_init_minimal();
	test_retained_hostgroup_rules();
	test_reload_counts_gtid_port_edit();
	test_retain_rows_on_hgm_tables(true);
	test_retain_rows_on_hgm_tables(false);
	test_retain_rows_ignore_offline_hard(true);
	test_retain_rows_ignore_offline_hard(false);
	test_init_query_processor();
	test_init_hostgroups();
	GloVars.statsdb_disk = const_cast<char*>(":memory:");
	GloProxyStats = new ProxySQL_Statistics();
	GloMyMon = new MySQL_Monitor();
	MyHGM->gtid_ev_loop = ev_loop_new(0);
	ev_async_init(MyHGM->gtid_ev_async, [](EV_P_ ev_async*, int) {});
	GloAdmin = new ProxySQL_Admin(); // Real, process-scoped fixture.
	if (pipe(GloAdmin->pipefd) != 0) diag("Admin wake pipe is unavailable");
	SQLite3DB admin_db;
	char memory_db[] = ":memory:";
	admin_db.open(memory_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	create_server_load_schema(admin_db);
	GloAdmin->admindb = &admin_db;
	std::unique_ptr<ProxySQL_PluginManager> manager;
	std::string error;
	if (!proxysql_load_configured_plugins(manager, {PROXYSQL_FAKE_PLUGIN_PATH}, error) ||
		!proxysql_init_configured_plugins(manager.get(), error)) {
		diag("plugin manager failed to start: %s", error.c_str());
		return exit_status();
	}

	Observed observations[2];
	for (int index = 0; index < 2; ++index) {
		const bool mysql = index == 0;
		const auto protocol = mysql ? ProxySQL_ServerProtocol::mysql : ProxySQL_ServerProtocol::pgsql;
		const char* label = mysql ? "MySQL" : "PostgreSQL";
		const uint16_t port = mysql ? 3306 : 5432;
		auto& observed = observations[index];
		ok(manager->install_server_discovery_controller(protocol, new ManagedController(observed),
			destroy_controller, dlopen(PROXYSQL_FAKE_PLUGIN_PATH, RTLD_NOW | RTLD_LOCAL)),
			"%s: discovery controller installs", label);

		// Claim A = 901/902 holds a discovered writer and a SHUNNED reader.
		insert_config_row(admin_db, mysql, 99, "plain.example", port, 1);
		load_servers(mysql);
		uint64_t generation = 0;
		const auto claim_a = role_claim(protocol, 901, 902);
		const auto claim_b = role_claim(protocol, 911, 912);
		ProxySQL_ServerRow writer {901, "writer.example", port};
		ProxySQL_ServerRow reader {902, "reader.example", port};
		ok(install_claims(protocol, 1, {claim_a}, generation) &&
			apply_rows(*manager, observed, protocol, {901, 902}, {writer, reader}) &&
			shun(mysql, "reader.example", port) &&
			row_status(mysql, 902, "reader.example", port) == "SHUNNED",
			"%s: claim A holds a runtime-only writer and a SHUNNED reader", label);
		const void* writer_object = server_object(mysql, 901, "writer.example", port);
		const void* reader_object = server_object(mysql, 902, "reader.example", port);

		// Admin LOAD with configuration rows inside the claimed hostgroup.
		insert_config_row(admin_db, mysql, 901, "writer.example", port, 77);
		insert_config_row(admin_db, mysql, 901, "configured.example", port, 1);
		load_servers(mysql);
		ok(writer_object != nullptr &&
			server_object(mysql, 901, "writer.example", port) == writer_object &&
			row_status(mysql, 901, "writer.example", port) == "ONLINE",
			"%s: LOAD keeps the claimed writer online with its server object and pool", label);
		ok(reader_object != nullptr &&
			server_object(mysql, 902, "reader.example", port) == reader_object &&
			row_status(mysql, 902, "reader.example", port) == "SHUNNED",
			"%s: LOAD keeps the claimed reader and its monitor status", label);
		ok(row_weight(mysql, 901, "writer.example", port) == 1 &&
			row_status(mysql, 901, "configured.example", port).empty(),
			"%s: configuration rows in a claimed hostgroup are ignored, the live row wins", label);
		ok(row_status(mysql, 99, "plain.example", port) == "ONLINE",
			"%s: LOAD installs configuration rows of unclaimed hostgroups", label);
		admin_db.execute(mysql ? "DELETE FROM mysql_servers WHERE hostgroup_id=99" :
			"DELETE FROM pgsql_servers WHERE hostgroup_id=99");
		load_servers(mysql);
		ok(row_status(mysql, 99, "plain.example", port).empty() &&
			server_object(mysql, 901, "writer.example", port) == writer_object,
			"%s: LOAD still removes unclaimed rows missing from configuration", label);
		ok(observed.snapshot.generation != 0 &&
			observed.snapshot.servers.size() == 2,
			"%s: the published snapshot keeps carrying the configuration rows only", label);

		// The managed install path reloads too, once per configuration write.
		ok(install_claims(protocol, 2, {claim_a}, generation) &&
			server_object(mysql, 901, "writer.example", port) == writer_object &&
			row_status(mysql, 902, "reader.example", port) == "SHUNNED",
			"%s: reinstalling the same claim keeps its rows, objects and status", label);

		// Cluster v1 pull: peer rows in the claimed hostgroup are ignored.
		std::vector<ProxySQL_ServerRow> peer {
			{99, "peer-plain.example", port},
			{901, "peer-claimed.example", port},
			{901, "writer.example", port, 0, "ONLINE", 55}};
		SQLite3_result* peer_result = peer_rows(mysql, peer);
		const std::string peer_checksum = get_checksum_from_hash(peer_result->raw_checksum());
		const auto stage = [mysql](SQLite3_result* rows) {
			if (mysql) MyHGM->servers_add(rows); else PgHGM->servers_add(rows);
		};
		const auto commit = [mysql](SQLite3_result* rows, const std::vector<uint32_t>& retained) {
			if (mysql) MyHGM->commit({rows, {}}, {nullptr, {}}, true, true, true, retained, "peer");
			else PgHGM->commit({rows, {}}, {nullptr, {}}, true, true, retained, "peer");
		};
		if (mysql) GloAdmin->mysql_servers_wrlock(); else GloAdmin->pgsql_servers_wrlock();
		proxysql_cluster_install_v1_runtime_post_fetch(protocol, peer_result, stage, commit);
		if (mysql) GloAdmin->mysql_servers_wrunlock(); else GloAdmin->pgsql_servers_wrunlock();
		ok(server_object(mysql, 901, "writer.example", port) == writer_object &&
			row_weight(mysql, 901, "writer.example", port) == 1 &&
			row_status(mysql, 902, "reader.example", port) == "SHUNNED",
			"%s: a Cluster pull keeps the local claimed rows", label);
		ok(row_status(mysql, 901, "peer-claimed.example", port).empty() &&
			row_status(mysql, 99, "peer-plain.example", port) == "ONLINE",
			"%s: a Cluster pull ignores peer rows in claimed hostgroups and installs the others", label);
		const char* advertised = mysql ? GloVars.checksums_values.mysql_servers.checksum :
			GloVars.checksums_values.pgsql_servers.checksum;
		ok(advertised != nullptr && peer_checksum == advertised,
			"%s: after a pull the advertised runtime checksum equals the peer checksum", label);
		test_save_keeps_claimed_configuration(mysql, port);

		// Claim A removed, claim B kept, across one install. The configuration
		// row left in 901 shows the hostgroup returning to configuration ownership.
		admin_db.execute(mysql
			? "DELETE FROM mysql_servers WHERE hostgroup_id=901 AND hostname='writer.example'"
			: "DELETE FROM pgsql_servers WHERE hostgroup_id=901 AND hostname='writer.example'");
		ProxySQL_ServerRow b_writer {911, "b-writer.example", port};
		ProxySQL_ServerHostgroupClaim claim_c {921, 922};
		claim_c.role_monitor.kind = ProxySQL_ServerRoleMonitor::none;
		ok(install_claims(protocol, 3, {claim_a, claim_b, claim_c}, generation) &&
			apply_rows(*manager, observed, protocol, {911, 912}, {b_writer}) &&
			server_object(mysql, 901, "writer.example", port) == writer_object,
			"%s: adding claims B and C keeps claim A rows", label);
		test_merge_ignores_offline_hard(protocol, port);
		const void* b_object = server_object(mysql, 911, "b-writer.example", port);
		ok(install_claims(protocol, 4, {claim_b}, generation) &&
			row_status(mysql, 901, "writer.example", port).empty() &&
			row_status(mysql, 902, "reader.example", port).empty() &&
			b_object != nullptr && server_object(mysql, 911, "b-writer.example", port) == b_object,
			"%s: a removed claim drops its rows while a surviving claim keeps them", label);
		ok(row_status(mysql, 901, "configured.example", port) == "ONLINE",
			"%s: a released hostgroup loads its configuration rows again", label);

		// Claim B moves its reader hostgroup: the shared writer hostgroup is not kept.
		ok(install_claims(protocol, 5, {role_claim(protocol, 911, 913)}, generation) &&
			row_status(mysql, 911, "b-writer.example", port).empty(),
			"%s: a moved claim drops the rows of its previous hostgroups", label);

		// Releasing every claim returns the hostgroups to configuration ownership.
		ProxySQL_ServerRow moved_writer {911, "moved-writer.example", port};
		ok(apply_rows(*manager, observed, protocol, {911, 913}, {moved_writer}) &&
			manager->uninstall_server_discovery_controller(protocol) &&
			proxysql_active_server_hostgroup_claims(protocol).empty() &&
			row_status(mysql, 911, "moved-writer.example", port).empty() &&
			row_status(mysql, 901, "configured.example", port) == "ONLINE",
			"%s: controller retirement releases the claim, drops its rows and loads configuration rows", label);
		admin_db.execute(mysql ? "DELETE FROM mysql_servers" : "DELETE FROM pgsql_servers");
		load_servers(mysql);
	}
	return exit_status();
}
