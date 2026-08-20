#include "tap.h"
#include "ProxySQL_PluginManager.h"
#include "ProxySQL_Cluster.hpp"
#include "ProxySQL_ServerDiscovery.h"
#include "ProxySQL_ServerModuleCluster.h"
#include "MySQL_Thread.h"
#include "ProxySQL_Statistics.hpp"
#include "MySQL_Monitor.hpp"
#include "PgSQL_HostGroups_Manager.h"
#include "proxysql_admin.h"
#include "proxysql_glovars.hpp"
#include "test_globals.h"
#include "test_init.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <dlfcn.h>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

extern ProxySQL_Admin* GloAdmin;
extern ProxySQL_Statistics* GloProxyStats;
extern MySQL_Monitor* GloMyMon;
extern ProxySQL_Cluster* GloProxyCluster;

#ifndef PROXYSQL_FAKE_PLUGIN_PATH
#error "PROXYSQL_FAKE_PLUGIN_PATH must be defined"
#endif

namespace {

std::unique_ptr<SQLite3_result> select_rows(SQLite3DB& db, const std::string& sql) {
	char* error = nullptr;
	int columns = 0;
	int affected = 0;
	SQLite3_result* rows = nullptr;
	db.execute_statement(sql.c_str(), &error, &columns, &affected, &rows);
	if (error != nullptr) {
		free(error);
		delete rows;
		return nullptr;
	}
	return std::unique_ptr<SQLite3_result>(rows);
}

std::string snapshot(SQLite3DB& db, const std::string& table) {
	auto rows = select_rows(db, "SELECT * FROM " + table + " ORDER BY 1,2,3");
	if (!rows) return "<query-error>";
	std::string value;
	for (const auto* row : rows->rows) {
		for (int column = 0; column < rows->columns; ++column) {
			if (column) value.push_back('|');
			value += row->fields[column] == nullptr ? "<NULL>" : row->fields[column];
		}
		value.push_back('\n');
	}
	return value;
}

void create_schema(SQLite3DB& db) {
	db.execute("ATTACH DATABASE ':memory:' AS disk");
	db.execute("CREATE TABLE mysql_servers (hostgroup_id INTEGER, hostname TEXT, port INTEGER, gtid_port INTEGER, status TEXT, weight INTEGER, compression INTEGER, max_connections INTEGER, max_replication_lag INTEGER, use_ssl INTEGER, max_latency_ms INTEGER, comment TEXT)");
	db.execute("CREATE TABLE pgsql_servers (hostgroup_id INTEGER, hostname TEXT, port INTEGER, status TEXT, weight INTEGER, compression INTEGER, max_connections INTEGER, max_replication_lag INTEGER, use_ssl INTEGER, max_latency_ms INTEGER, comment TEXT)");
	db.execute("CREATE TABLE disk.mysql_servers AS SELECT * FROM main.mysql_servers WHERE 0");
	db.execute("CREATE TABLE disk.pgsql_servers AS SELECT * FROM main.pgsql_servers WHERE 0");
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
	db.execute("CREATE TABLE mysql_fake_server_module_claims (writer INTEGER, label TEXT)");
	db.execute("CREATE TABLE pgsql_fake_server_module_claims (writer INTEGER, label TEXT)");
	db.execute("CREATE TABLE disk.mysql_fake_server_module_claims (writer INTEGER, label TEXT)");
	db.execute("CREATE TABLE disk.pgsql_fake_server_module_claims (writer INTEGER, label TEXT)");
	db.execute("CREATE TABLE runtime_checksums_values (name VARCHAR NOT NULL, version INT NOT NULL, epoch INT NOT NULL, checksum VARCHAR NOT NULL, PRIMARY KEY(name))");
}

struct ChecksumSnapshot {
	uint64_t version {0};
	uint64_t epoch {0};
	std::string checksum;
};

ChecksumSnapshot checksum_snapshot(const ProxySQL_Checksum_Value& value) {
	return {value.version, value.epoch, value.checksum ? value.checksum : ""};
}

bool dumped_checksum_matches(SQLite3DB& db, const char* name,
	const ChecksumSnapshot& expected) {
	auto rows = select_rows(db, std::string("SELECT version,epoch,checksum FROM runtime_checksums_values WHERE name='") + name + "'");
	return rows && rows->rows.size() == 1 && rows->rows[0]->fields[0] &&
		std::stoull(rows->rows[0]->fields[0]) == expected.version &&
		std::stoull(rows->rows[0]->fields[1]) == expected.epoch &&
		expected.checksum == rows->rows[0]->fields[2];
}

class OneRowMysqlResult {
public:
	OneRowMysqlResult(const std::string& name, uint64_t version, uint64_t epoch,
		const std::string& checksum) :
		values_ {name, std::to_string(version), std::to_string(epoch), checksum} {
		for (size_t i = 0; i < 4; ++i) fields_[i] = values_[i].data();
		row_.data = fields_;
		data_.data = &row_;
		result_.data = &data_;
		result_.field_count = 4;
	}

	MYSQL_RES* reset() {
		row_.next = nullptr;
		result_.data_cursor = &row_;
		return &result_;
	}

private:
	std::string values_[4];
	char* fields_[4] {};
	MYSQL_ROWS row_ {};
	MYSQL_DATA data_ {};
	MYSQL_RES result_ {};
};

bool set_checksums_schedules_v2(const char* name, const ChecksumSnapshot& peer,
	pthread_mutex_t& pull_mutex) {
	char host[] = "127.0.0.1";
	char comment[] = "materialization";
	char ip[] = "127.0.0.1";
	ProxySQL_Node_Entry node(host, 1, 1, comment, ip);
	OneRowMysqlResult result(name, peer.version, peer.epoch, peer.checksum);
	std::mutex done_mutex;
	std::condition_variable done_cv;
	bool done = false;
	pthread_mutex_lock(&pull_mutex);
	std::thread worker([&] {
		node.set_checksums(result.reset());
		{
			std::lock_guard<std::mutex> lock(done_mutex);
			done = true;
		}
		done_cv.notify_one();
	});
	std::unique_lock<std::mutex> lock(done_mutex);
	const bool completed = done_cv.wait_for(lock, std::chrono::milliseconds(200), [&] { return done; });
	lock.unlock();
	pthread_mutex_unlock(&pull_mutex);
	worker.join();
	return !completed;
}

std::unique_ptr<SQLite3_result> mysql_rows(std::initializer_list<ProxySQL_ServerRow> rows) {
	auto result = std::make_unique<SQLite3_result>(12);
	for (const auto& row : rows) {
		std::string hg = std::to_string(row.hostgroup_id);
		std::string port = std::to_string(row.port);
		std::string gtid = std::to_string(row.gtid_port);
		std::string weight = std::to_string(row.weight);
		std::string compression = std::to_string(row.compression);
		std::string max_connections = std::to_string(row.max_connections);
		std::string max_lag = std::to_string(row.max_replication_lag);
		std::string ssl = std::to_string(row.use_ssl);
		std::string latency = std::to_string(row.max_latency_ms);
		char* fields[] = {hg.data(), const_cast<char*>(row.hostname.c_str()), port.data(), gtid.data(),
			const_cast<char*>(row.status.c_str()), weight.data(), compression.data(),
			max_connections.data(), max_lag.data(), ssl.data(), latency.data(),
			const_cast<char*>(row.comment.c_str())};
		result->add_row(fields);
	}
	return result;
}

std::unique_ptr<SQLite3_result> pgsql_rows(std::initializer_list<ProxySQL_ServerRow> rows) {
	auto result = std::make_unique<SQLite3_result>(11);
	for (const auto& row : rows) {
		std::string hg = std::to_string(row.hostgroup_id);
		std::string port = std::to_string(row.port);
		std::string weight = std::to_string(row.weight);
		std::string compression = std::to_string(row.compression);
		std::string max_connections = std::to_string(row.max_connections);
		std::string max_lag = std::to_string(row.max_replication_lag);
		std::string ssl = std::to_string(row.use_ssl);
		std::string latency = std::to_string(row.max_latency_ms);
		char* fields[] = {hg.data(), const_cast<char*>(row.hostname.c_str()), port.data(),
			const_cast<char*>(row.status.c_str()), weight.data(), compression.data(),
			max_connections.data(), max_lag.data(), ssl.data(), latency.data(),
			const_cast<char*>(row.comment.c_str())};
		result->add_row(fields);
	}
	return result;
}

bool runtime_contains(ProxySQL_ServerProtocol protocol, uint32_t hostgroup,
	const std::string& hostname) {
	std::unique_ptr<SQLite3_result> rows(protocol == ProxySQL_ServerProtocol::mysql
		? MyHGM->dump_table_mysql("mysql_servers") : PgHGM->dump_table_pgsql("pgsql_servers"));
	if (!rows) return false;
	return std::any_of(rows->rows.begin(), rows->rows.end(), [&](const SQLite3_row* row) {
		return row && row->fields && std::to_string(hostgroup) == row->fields[0] &&
			hostname == row->fields[1];
	});
}

struct AckObservation {
	uint64_t generation {0};
	bool applied {false};
	std::string memory;
	std::string disk;
	std::string memory_policy;
	std::string disk_policy;
	ChecksumSnapshot v2;
};

struct AckState {
	SQLite3DB* db {nullptr};
	ProxySQL_ServerProtocol protocol {ProxySQL_ServerProtocol::mysql};
	std::vector<AckObservation> observations;
	std::atomic<unsigned int> destroyed {0};
};

class Controller final : public ProxySQL_ServerDiscoveryController {
public:
	explicit Controller(AckState* state) : state_(state) {}
	void runtime_configuration_installed(ProxySQL_ServerRuntimeSnapshot) override {}
	void desired_set_applied(uint64_t generation, bool applied) override {
		const bool mysql = state_->protocol == ProxySQL_ServerProtocol::mysql;
		const std::string core = mysql ? "mysql_servers" : "pgsql_servers";
		const std::string policy = mysql ? "mysql_fake_server_module_claims" :
			"pgsql_fake_server_module_claims";
		const auto& v2 = mysql ? GloVars.checksums_values.mysql_servers_v2 :
			GloVars.checksums_values.pgsql_servers_v2;
		state_->observations.push_back({generation, applied,
			snapshot(*state_->db, "main." + core), snapshot(*state_->db, "disk." + core),
			snapshot(*state_->db, "main." + policy), snapshot(*state_->db, "disk." + policy),
			checksum_snapshot(v2)});
	}
	void shutdown() override {}
	AckState* state() const { return state_; }
private:
	AckState* state_;
};

void destroy_controller(ProxySQL_ServerDiscoveryController* controller) {
	auto* owned = static_cast<Controller*>(controller);
	owned->state()->destroyed.fetch_add(1);
	delete owned;
}

ProxySQL_ServerDesiredSet desired(ProxySQL_ServerProtocol protocol, uint64_t generation,
	ProxySQL_ServerPersistence persistence, ProxySQL_ServerRow row) {
	return {protocol, generation, {17, 18}, {std::move(row)}, persistence};
}

bool post_and_drain(ProxySQL_PluginManager& manager, ProxySQL_Admin& admin,
	ProxySQL_ServerDesiredSet request) {
	return manager.post_server_desired_set(std::move(request)) &&
		admin.drain_server_discovery_updates() == 1;
}

} // namespace

int main() {
	plan(53);
	test_init_minimal();
	test_init_query_processor();
	test_init_hostgroups();
	char stats_memory_db[] = ":memory:";
	GloVars.statsdb_disk = stats_memory_db;
	GloProxyStats = new ProxySQL_Statistics();
	GloMyMon = new MySQL_Monitor();
	auto cluster = std::make_unique<ProxySQL_Cluster>();
	GloProxyCluster = cluster.get();
	cluster->cluster_mysql_servers_diffs_before_sync = 1;
	cluster->cluster_pgsql_servers_diffs_before_sync = 1;
	cluster->cluster_mysql_servers_sync_algorithm =
		static_cast<int>(mysql_servers_sync_algorithm::mysql_servers_v2);
	MyHGM->gtid_ev_loop = ev_loop_new(0);
	ev_async_init(MyHGM->gtid_ev_async, [](EV_P_ ev_async*, int) {});

	SQLite3DB admin_db;
	char memory_db[] = ":memory:";
	admin_db.open(memory_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	create_schema(admin_db);
	auto* admin = new ProxySQL_Admin();
	admin->admindb = &admin_db;
	GloAdmin = admin;
	ok(pipe(admin->pipefd) == 0, "Admin materialization fixture has a worker wake pipe");

	admin_db.execute("INSERT INTO mysql_servers VALUES (17,'memory-old.mysql',3306,0,'ONLINE',1,0,100,0,1,0,'memory-old'),(18,'memory-reader.mysql',3306,0,'ONLINE',2,0,100,0,1,0,'memory-reader'),(99,'pending-memory.mysql',3306,0,'ONLINE',99,0,100,0,1,0,'pending')");
	admin_db.execute("INSERT INTO disk.mysql_servers SELECT * FROM main.mysql_servers");
	admin_db.execute("UPDATE disk.mysql_servers SET hostname='disk-unrelated.mysql',comment='disk' WHERE hostgroup_id=99");
	admin_db.execute("INSERT INTO pgsql_servers VALUES (17,'memory-old.pgsql',5432,'ONLINE',1,0,100,0,1,0,'memory-old'),(18,'memory-reader.pgsql',5432,'ONLINE',2,0,100,0,1,0,'memory-reader'),(99,'pending-memory.pgsql',5432,'ONLINE',99,0,100,0,1,0,'pending')");
	admin_db.execute("INSERT INTO disk.pgsql_servers SELECT * FROM main.pgsql_servers");
	admin_db.execute("UPDATE disk.pgsql_servers SET hostname='disk-unrelated.pgsql',comment='disk' WHERE hostgroup_id=99");
	admin_db.execute("INSERT INTO mysql_fake_server_module_claims VALUES (17,'mysql-memory-policy')");
	admin_db.execute("INSERT INTO disk.mysql_fake_server_module_claims VALUES (18,'mysql-disk-policy')");
	admin_db.execute("INSERT INTO pgsql_fake_server_module_claims VALUES (17,'pgsql-memory-policy')");
	admin_db.execute("INSERT INTO disk.pgsql_fake_server_module_claims VALUES (18,'pgsql-disk-policy')");

	auto mysql_initial = mysql_rows({
		{17, "runtime-old.mysql", 3306, 0, "ONLINE", 10, 0, 100, 0, 1, 0, "runtime"},
		{18, "runtime-reader.mysql", 3306, 0, "ONLINE", 20, 0, 100, 0, 1, 0, "runtime"},
		{99, "runtime-unrelated.mysql", 3306, 0, "ONLINE", 90, 0, 100, 0, 1, 0, "runtime"}});
	MyHGM->servers_add(mysql_initial.get());
	ok(MyHGM->commit({}, {}, false), "MySQL HGM starts with delegated and unrelated runtime rows");
	auto pgsql_initial = pgsql_rows({
		{17, "runtime-old.pgsql", 5432, 0, "ONLINE", 10, 0, 100, 0, 1, 0, "runtime"},
		{18, "runtime-reader.pgsql", 5432, 0, "ONLINE", 20, 0, 100, 0, 1, 0, "runtime"},
		{99, "runtime-unrelated.pgsql", 5432, 0, "ONLINE", 90, 0, 100, 0, 1, 0, "runtime"}});
	PgHGM->servers_add(pgsql_initial.get());
	ok(PgHGM->commit({}, {}, false), "PostgreSQL HGM starts with delegated and unrelated runtime rows");

	const std::string mysql_memory_initial = snapshot(admin_db, "main.mysql_servers");
	const std::string mysql_disk_initial = snapshot(admin_db, "disk.mysql_servers");
	const std::string pgsql_memory_initial = snapshot(admin_db, "main.pgsql_servers");
	const std::string pgsql_disk_initial = snapshot(admin_db, "disk.pgsql_servers");
	const std::string mysql_memory_policy = snapshot(admin_db, "main.mysql_fake_server_module_claims");
	const std::string mysql_disk_policy = snapshot(admin_db, "disk.mysql_fake_server_module_claims");
	const std::string pgsql_memory_policy = snapshot(admin_db, "main.pgsql_fake_server_module_claims");
	const std::string pgsql_disk_policy = snapshot(admin_db, "disk.pgsql_fake_server_module_claims");
	const std::string mysql_pending_memory = snapshot(admin_db,
		"main.mysql_servers WHERE hostgroup_id=99");
	const std::string mysql_unrelated_disk = snapshot(admin_db,
		"disk.mysql_servers WHERE hostgroup_id=99");
	const std::string pgsql_pending_memory = snapshot(admin_db,
		"main.pgsql_servers WHERE hostgroup_id=99");
	const std::string pgsql_unrelated_disk = snapshot(admin_db,
		"disk.pgsql_servers WHERE hostgroup_id=99");
	ok(admin->save_mysql_servers_runtime_to_database_scoped({}) &&
		admin->save_mysql_servers_memory_to_disk_scoped({}) &&
		snapshot(admin_db, "main.mysql_servers") == mysql_memory_initial &&
		snapshot(admin_db, "disk.mysql_servers") == mysql_disk_initial,
		"empty MySQL delegated scope is a transactional no-op");
	ok(admin->save_pgsql_servers_runtime_to_database_scoped({}) &&
		admin->save_pgsql_servers_memory_to_disk_scoped({}) &&
		snapshot(admin_db, "main.pgsql_servers") == pgsql_memory_initial &&
		snapshot(admin_db, "disk.pgsql_servers") == pgsql_disk_initial,
		"empty PostgreSQL delegated scope is a transactional no-op");

	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_SERVER_DISCOVERY", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_AFFILIATED", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_BOTH_PROTOCOLS", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_CONFLICT_CLAIM", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_SNAPSHOT", "1", 1);
	std::unique_ptr<ProxySQL_PluginManager> manager;
	std::string error;
	ok(proxysql_load_configured_plugins(manager, {PROXYSQL_FAKE_PLUGIN_PATH}, error) &&
		proxysql_init_configured_plugins(manager.get(), error),
		"materialization fixture installs delegated MySQL and PostgreSQL module claims");
	AckState mysql_acks {&admin_db, ProxySQL_ServerProtocol::mysql};
	AckState pgsql_acks {&admin_db, ProxySQL_ServerProtocol::pgsql};
	void* mysql_handle = dlopen(PROXYSQL_FAKE_PLUGIN_PATH, RTLD_NOW | RTLD_LOCAL);
	void* pgsql_handle = dlopen(PROXYSQL_FAKE_PLUGIN_PATH, RTLD_NOW | RTLD_LOCAL);
	ok(mysql_handle && manager->install_server_discovery_controller(ProxySQL_ServerProtocol::mysql,
		new Controller(&mysql_acks), &destroy_controller, mysql_handle),
		"MySQL acknowledgement observer is retained");
	ok(pgsql_handle && manager->install_server_discovery_controller(ProxySQL_ServerProtocol::pgsql,
		new Controller(&pgsql_acks), &destroy_controller, pgsql_handle),
		"PostgreSQL acknowledgement observer is retained");
	std::string mysql_module_checksum_before;
	std::string pgsql_module_checksum_before;
	std::string checksum_error;
	const bool initial_module_checksums = proxysql_server_module_cluster_poll_checksum(
		ProxySQL_ServerProtocol::mysql, ProxySQL_ServerModuleClusterVersion::memory_v2,
		admin_db, mysql_module_checksum_before, checksum_error) &&
		proxysql_server_module_cluster_poll_checksum(ProxySQL_ServerProtocol::pgsql,
			ProxySQL_ServerModuleClusterVersion::memory_v2, admin_db,
			pgsql_module_checksum_before, checksum_error);
	ProxySQL_ServerRuntimeSnapshot mysql_installed {};
	mysql_installed.protocol = ProxySQL_ServerProtocol::mysql;
	ProxySQL_ServerRuntimeInstallTransaction mysql_install(mysql_installed.protocol, error);
	const uint64_t mysql_generation = mysql_install.generation();
	ok(mysql_install.prepare(mysql_installed, error) && mysql_install.commit(mysql_installed),
		"MySQL runtime generation records the delegated scope");
	ProxySQL_ServerRuntimeSnapshot pgsql_installed {};
	pgsql_installed.protocol = ProxySQL_ServerProtocol::pgsql;
	ProxySQL_ServerRuntimeInstallTransaction pgsql_install(pgsql_installed.protocol, error);
	const uint64_t pgsql_generation = pgsql_install.generation();
	ok(pgsql_install.prepare(pgsql_installed, error) && pgsql_install.commit(pgsql_installed),
		"PostgreSQL runtime generation records the delegated scope");

	const std::string mysql_checksum_before = GloVars.checksums_values.mysql_servers.checksum;
	const ChecksumSnapshot mysql_v2_before = checksum_snapshot(GloVars.checksums_values.mysql_servers_v2);
	ProxySQL_ServerRow mysql_runtime {17, "runtime-only.mysql", 3306, 0, "ONLINE", 31, 0, 101, 0, 1, 0, "runtime-only"};
	ok(post_and_drain(*manager, *admin, desired(ProxySQL_ServerProtocol::mysql,
		mysql_generation, ProxySQL_ServerPersistence::runtime_only, mysql_runtime)) &&
		mysql_acks.observations.size() == 1 && mysql_acks.observations.back().applied,
		"MySQL runtime-only request is acknowledged after runtime reconciliation");
	ok(runtime_contains(ProxySQL_ServerProtocol::mysql, 17, "runtime-only.mysql") &&
		mysql_acks.observations.back().memory == mysql_memory_initial &&
		mysql_acks.observations.back().disk == mysql_disk_initial,
		"MySQL runtime-only changes HGM without materializing MEMORY or DISK");
	ok(mysql_acks.observations.back().memory_policy == mysql_memory_policy &&
		mysql_acks.observations.back().disk_policy == mysql_disk_policy,
		"MySQL runtime-only does not copy affiliated policy tables");
	ok(mysql_checksum_before != GloVars.checksums_values.mysql_servers.checksum,
		"MySQL reconciliation recomputes the existing Servers checksum");
	admin->dump_checksums_values_table();
	ok(checksum_snapshot(GloVars.checksums_values.mysql_servers_v2).checksum == mysql_v2_before.checksum &&
		checksum_snapshot(GloVars.checksums_values.mysql_servers_v2).version == mysql_v2_before.version &&
		checksum_snapshot(GloVars.checksums_values.mysql_servers_v2).epoch == mysql_v2_before.epoch &&
		dumped_checksum_matches(admin_db, "mysql_servers_v2", mysql_v2_before),
		"MySQL runtime-only leaves the published and dumped v2 checksum state unchanged");
	ok(!set_checksums_schedules_v2("mysql_servers_v2", mysql_v2_before,
		cluster->update_mysql_servers_v2_mutex),
		"MySQL runtime-only leaves a matching v2 cluster poll unscheduled");

	const std::string mysql_disk_before_memory = snapshot(admin_db, "disk.mysql_servers");
	ProxySQL_ServerRow mysql_memory {18, "memory.mysql", 3306, 0, "ONLINE", 41, 0, 111, 0, 1, 0, "memory"};
	ok(post_and_drain(*manager, *admin, desired(ProxySQL_ServerProtocol::mysql,
		mysql_generation, ProxySQL_ServerPersistence::memory, mysql_memory)) &&
		mysql_acks.observations.size() == 2 && mysql_acks.observations.back().applied,
		"MySQL MEMORY request is acknowledged only after scoped runtime-to-MEMORY save");
	ok(mysql_acks.observations.back().memory.find("memory.mysql") != std::string::npos &&
		snapshot(admin_db, "main.mysql_servers WHERE hostgroup_id=99") == mysql_pending_memory &&
		mysql_acks.observations.back().disk == mysql_disk_before_memory,
		"MySQL MEMORY replaces only delegated rows and preserves pending unrelated edits");
	const ChecksumSnapshot mysql_v2_memory = checksum_snapshot(GloVars.checksums_values.mysql_servers_v2);
	admin->dump_checksums_values_table();
	ok(mysql_v2_memory.checksum != mysql_v2_before.checksum &&
		mysql_v2_memory.version == mysql_v2_before.version + 1 &&
		mysql_v2_memory.epoch >= mysql_v2_before.epoch &&
		mysql_acks.observations.back().v2.checksum == mysql_v2_memory.checksum &&
		mysql_acks.observations.back().v2.version == mysql_v2_memory.version &&
		mysql_acks.observations.back().v2.epoch == mysql_v2_memory.epoch &&
		dumped_checksum_matches(admin_db, "mysql_servers_v2", mysql_v2_memory),
		"MySQL MEMORY publishes exactly one v2 version and its runtime_checksums_values row");
	ChecksumSnapshot mysql_old_peer {mysql_v2_memory.version + 1, mysql_v2_memory.epoch + 1,
		mysql_v2_before.checksum};
	ok(set_checksums_schedules_v2("mysql_servers_v2", mysql_old_peer,
		cluster->update_mysql_servers_v2_mutex),
		"MySQL MEMORY publishes a changed v2 checksum consumed by cluster scheduling");
	ok(post_and_drain(*manager, *admin, desired(ProxySQL_ServerProtocol::mysql,
		mysql_generation, ProxySQL_ServerPersistence::memory, mysql_memory)) &&
		mysql_acks.observations.size() == 3 && mysql_acks.observations.back().applied,
		"repeated MySQL MEMORY materialization is acknowledged through the normal scoped path");
	const ChecksumSnapshot mysql_v2_memory_repeat = checksum_snapshot(GloVars.checksums_values.mysql_servers_v2);
	admin->dump_checksums_values_table();
	ok(mysql_v2_memory_repeat.checksum == mysql_v2_memory.checksum &&
		mysql_v2_memory_repeat.version == mysql_v2_memory.version + 1 &&
		mysql_v2_memory_repeat.epoch >= mysql_v2_memory.epoch &&
		dumped_checksum_matches(admin_db, "mysql_servers_v2", mysql_v2_memory_repeat),
		"unchanged MySQL MEMORY rows preserve normal v2 checksum/version publication semantics");

	ProxySQL_ServerRow mysql_disk {17, "memory-disk.mysql", 3306, 0, "ONLINE", 51, 0, 121, 0, 1, 0, "memory-disk"};
	ok(post_and_drain(*manager, *admin, desired(ProxySQL_ServerProtocol::mysql,
		mysql_generation, ProxySQL_ServerPersistence::memory_and_disk, mysql_disk)) &&
		mysql_acks.observations.size() == 4 && mysql_acks.observations.back().applied,
		"MySQL MEMORY+DISK request is acknowledged after both scoped saves");
	ok(mysql_acks.observations.back().memory.find("memory-disk.mysql") != std::string::npos &&
		mysql_acks.observations.back().disk.find("memory-disk.mysql") != std::string::npos &&
		snapshot(admin_db, "main.mysql_servers WHERE hostgroup_id=99") == mysql_pending_memory &&
		snapshot(admin_db, "disk.mysql_servers WHERE hostgroup_id=99") == mysql_unrelated_disk,
		"MySQL MEMORY+DISK changes only delegated rows at each persistence layer");
	ok(mysql_acks.observations.back().memory_policy == mysql_memory_policy &&
		mysql_acks.observations.back().disk_policy == mysql_disk_policy,
		"automatic MySQL materialization never copies plugin policy tables");
	const ChecksumSnapshot mysql_v2_disk = checksum_snapshot(GloVars.checksums_values.mysql_servers_v2);
	admin->dump_checksums_values_table();
	ok(mysql_v2_disk.checksum != mysql_v2_memory_repeat.checksum &&
		mysql_v2_disk.version == mysql_v2_memory_repeat.version + 1 &&
		mysql_v2_disk.epoch >= mysql_v2_memory_repeat.epoch &&
		mysql_acks.observations.back().v2.checksum == mysql_v2_disk.checksum &&
		mysql_acks.observations.back().v2.version == mysql_v2_disk.version &&
		mysql_acks.observations.back().v2.epoch == mysql_v2_disk.epoch &&
		dumped_checksum_matches(admin_db, "mysql_servers_v2", mysql_v2_disk),
		"MySQL MEMORY+DISK publishes exactly one v2 version before acknowledgement");
	ChecksumSnapshot mysql_memory_peer {mysql_v2_disk.version + 1, mysql_v2_disk.epoch + 1,
		mysql_v2_memory.checksum};
	ok(set_checksums_schedules_v2("mysql_servers_v2", mysql_memory_peer,
		cluster->update_mysql_servers_v2_mutex),
		"MySQL MEMORY+DISK publishes a changed v2 checksum consumed by cluster scheduling");
	ProxySQL_ServerDesiredSet mysql_empty {ProxySQL_ServerProtocol::mysql, mysql_generation,
		{17, 18}, {}, ProxySQL_ServerPersistence::memory_and_disk};
	ok(post_and_drain(*manager, *admin, std::move(mysql_empty)) &&
		mysql_acks.observations.size() == 5 && mysql_acks.observations.back().applied &&
		snapshot(admin_db, "main.mysql_servers WHERE hostgroup_id IN (17,18)").empty() &&
		snapshot(admin_db, "disk.mysql_servers WHERE hostgroup_id IN (17,18)").empty() &&
		snapshot(admin_db, "main.mysql_servers WHERE hostgroup_id=99") == mysql_pending_memory &&
		snapshot(admin_db, "disk.mysql_servers WHERE hostgroup_id=99") == mysql_unrelated_disk,
		"empty desired servers clear exactly the delegated MySQL scope through MEMORY and DISK");

	const std::string pgsql_checksum_before = GloVars.checksums_values.pgsql_servers.checksum;
	const ChecksumSnapshot pgsql_v2_before = checksum_snapshot(GloVars.checksums_values.pgsql_servers_v2);
	ProxySQL_ServerRow pgsql_runtime {17, "runtime-only.pgsql", 5432, 0, "ONLINE", 31, 0, 101, 0, 1, 0, "runtime-only"};
	ok(post_and_drain(*manager, *admin, desired(ProxySQL_ServerProtocol::pgsql,
		pgsql_generation, ProxySQL_ServerPersistence::runtime_only, pgsql_runtime)) &&
		pgsql_acks.observations.size() == 1 && pgsql_acks.observations.back().applied,
		"PostgreSQL runtime-only request is acknowledged after runtime reconciliation");
	ok(runtime_contains(ProxySQL_ServerProtocol::pgsql, 17, "runtime-only.pgsql") &&
		pgsql_acks.observations.back().memory == pgsql_memory_initial &&
		pgsql_acks.observations.back().disk == pgsql_disk_initial,
		"PostgreSQL runtime-only changes HGM without materializing MEMORY or DISK");
	ok(pgsql_checksum_before != GloVars.checksums_values.pgsql_servers.checksum,
		"PostgreSQL reconciliation recomputes the existing Servers checksum");
	admin->dump_checksums_values_table();
	ok(checksum_snapshot(GloVars.checksums_values.pgsql_servers_v2).checksum == pgsql_v2_before.checksum &&
		checksum_snapshot(GloVars.checksums_values.pgsql_servers_v2).version == pgsql_v2_before.version &&
		checksum_snapshot(GloVars.checksums_values.pgsql_servers_v2).epoch == pgsql_v2_before.epoch &&
		dumped_checksum_matches(admin_db, "pgsql_servers_v2", pgsql_v2_before),
		"PostgreSQL runtime-only leaves the published and dumped v2 checksum state unchanged");
	ok(!set_checksums_schedules_v2("pgsql_servers_v2", pgsql_v2_before,
		cluster->update_mysql_servers_v2_mutex),
		"PostgreSQL runtime-only leaves a matching v2 cluster poll unscheduled");

	const std::string pgsql_disk_before_memory = snapshot(admin_db, "disk.pgsql_servers");
	ProxySQL_ServerRow pgsql_memory {18, "memory.pgsql", 5432, 0, "ONLINE", 41, 0, 111, 0, 1, 0, "memory"};
	ok(post_and_drain(*manager, *admin, desired(ProxySQL_ServerProtocol::pgsql,
		pgsql_generation, ProxySQL_ServerPersistence::memory, pgsql_memory)) &&
		pgsql_acks.observations.size() == 2 && pgsql_acks.observations.back().applied,
		"PostgreSQL MEMORY request is acknowledged only after scoped runtime-to-MEMORY save");
	ok(pgsql_acks.observations.back().memory.find("memory.pgsql") != std::string::npos &&
		snapshot(admin_db, "main.pgsql_servers WHERE hostgroup_id=99") == pgsql_pending_memory &&
		pgsql_acks.observations.back().disk == pgsql_disk_before_memory,
		"PostgreSQL MEMORY preserves unrelated pending MEMORY and DISK rows");
	const ChecksumSnapshot pgsql_v2_memory = checksum_snapshot(GloVars.checksums_values.pgsql_servers_v2);
	admin->dump_checksums_values_table();
	ok(pgsql_v2_memory.checksum != pgsql_v2_before.checksum &&
		pgsql_v2_memory.version == pgsql_v2_before.version + 1 &&
		pgsql_v2_memory.epoch >= pgsql_v2_before.epoch &&
		pgsql_acks.observations.back().v2.checksum == pgsql_v2_memory.checksum &&
		pgsql_acks.observations.back().v2.version == pgsql_v2_memory.version &&
		pgsql_acks.observations.back().v2.epoch == pgsql_v2_memory.epoch &&
		dumped_checksum_matches(admin_db, "pgsql_servers_v2", pgsql_v2_memory),
		"PostgreSQL MEMORY publishes exactly one v2 version and its runtime_checksums_values row");
	ChecksumSnapshot pgsql_old_peer {pgsql_v2_memory.version + 1, pgsql_v2_memory.epoch + 1,
		pgsql_v2_before.checksum};
	ok(set_checksums_schedules_v2("pgsql_servers_v2", pgsql_old_peer,
		cluster->update_mysql_servers_v2_mutex),
		"PostgreSQL MEMORY publishes a changed v2 checksum consumed by cluster scheduling");
	ok(post_and_drain(*manager, *admin, desired(ProxySQL_ServerProtocol::pgsql,
		pgsql_generation, ProxySQL_ServerPersistence::memory, pgsql_memory)) &&
		pgsql_acks.observations.size() == 3 && pgsql_acks.observations.back().applied,
		"repeated PostgreSQL MEMORY materialization is acknowledged through the normal scoped path");
	const ChecksumSnapshot pgsql_v2_memory_repeat = checksum_snapshot(GloVars.checksums_values.pgsql_servers_v2);
	admin->dump_checksums_values_table();
	ok(pgsql_v2_memory_repeat.checksum == pgsql_v2_memory.checksum &&
		pgsql_v2_memory_repeat.version == pgsql_v2_memory.version + 1 &&
		pgsql_v2_memory_repeat.epoch >= pgsql_v2_memory.epoch &&
		dumped_checksum_matches(admin_db, "pgsql_servers_v2", pgsql_v2_memory_repeat),
		"unchanged PostgreSQL MEMORY rows preserve normal v2 checksum/version publication semantics");

	ProxySQL_ServerRow pgsql_disk {17, "memory-disk.pgsql", 5432, 0, "ONLINE", 51, 0, 121, 0, 1, 0, "memory-disk"};
	ok(post_and_drain(*manager, *admin, desired(ProxySQL_ServerProtocol::pgsql,
		pgsql_generation, ProxySQL_ServerPersistence::memory_and_disk, pgsql_disk)) &&
		pgsql_acks.observations.size() == 4 && pgsql_acks.observations.back().applied,
		"PostgreSQL MEMORY+DISK request is acknowledged after both scoped saves");
	ok(pgsql_acks.observations.back().memory.find("memory-disk.pgsql") != std::string::npos &&
		pgsql_acks.observations.back().disk.find("memory-disk.pgsql") != std::string::npos &&
		snapshot(admin_db, "main.pgsql_servers WHERE hostgroup_id=99") == pgsql_pending_memory &&
		snapshot(admin_db, "disk.pgsql_servers WHERE hostgroup_id=99") == pgsql_unrelated_disk,
		"PostgreSQL MEMORY+DISK changes only delegated rows at each persistence layer");
	ok(pgsql_acks.observations.back().memory_policy == pgsql_memory_policy &&
		pgsql_acks.observations.back().disk_policy == pgsql_disk_policy,
		"automatic PostgreSQL materialization never copies plugin policy tables");
	const ChecksumSnapshot pgsql_v2_disk = checksum_snapshot(GloVars.checksums_values.pgsql_servers_v2);
	admin->dump_checksums_values_table();
	ok(pgsql_v2_disk.checksum != pgsql_v2_memory_repeat.checksum &&
		pgsql_v2_disk.version == pgsql_v2_memory_repeat.version + 1 &&
		pgsql_v2_disk.epoch >= pgsql_v2_memory_repeat.epoch &&
		pgsql_acks.observations.back().v2.checksum == pgsql_v2_disk.checksum &&
		pgsql_acks.observations.back().v2.version == pgsql_v2_disk.version &&
		pgsql_acks.observations.back().v2.epoch == pgsql_v2_disk.epoch &&
		dumped_checksum_matches(admin_db, "pgsql_servers_v2", pgsql_v2_disk),
		"PostgreSQL MEMORY+DISK publishes exactly one v2 version before acknowledgement");
	ChecksumSnapshot pgsql_memory_peer {pgsql_v2_disk.version + 1, pgsql_v2_disk.epoch + 1,
		pgsql_v2_memory.checksum};
	ok(set_checksums_schedules_v2("pgsql_servers_v2", pgsql_memory_peer,
		cluster->update_mysql_servers_v2_mutex),
		"PostgreSQL MEMORY+DISK publishes a changed v2 checksum consumed by cluster scheduling");
	std::string mysql_module_checksum_after;
	std::string pgsql_module_checksum_after;
	ok(initial_module_checksums &&
		proxysql_server_module_cluster_poll_checksum(ProxySQL_ServerProtocol::mysql,
			ProxySQL_ServerModuleClusterVersion::memory_v2, admin_db,
			mysql_module_checksum_after, checksum_error) &&
		proxysql_server_module_cluster_poll_checksum(ProxySQL_ServerProtocol::pgsql,
			ProxySQL_ServerModuleClusterVersion::memory_v2, admin_db,
			pgsql_module_checksum_after, checksum_error) &&
		!mysql_module_checksum_after.empty() && !pgsql_module_checksum_after.empty() &&
		mysql_module_checksum_after == mysql_module_checksum_before &&
		pgsql_module_checksum_after == pgsql_module_checksum_before,
		"Task 2 module checksum path recomputes unchanged policy checksums after scoped saves");

	admin_db.execute("DROP TABLE disk.pgsql_servers");
	const ChecksumSnapshot pgsql_v2_before_disk_failure =
		checksum_snapshot(GloVars.checksums_values.pgsql_servers_v2);
	ProxySQL_ServerRow pgsql_failure {18, "disk-failure.pgsql", 5432, 0, "ONLINE", 61, 0, 131, 0, 1, 0, "failure"};
	ok(post_and_drain(*manager, *admin, desired(ProxySQL_ServerProtocol::pgsql,
		pgsql_generation, ProxySQL_ServerPersistence::memory_and_disk, pgsql_failure)) &&
		pgsql_acks.observations.size() == 5 && !pgsql_acks.observations.back().applied,
		"a failed scoped DISK save produces one false acknowledgement");
	ok(runtime_contains(ProxySQL_ServerProtocol::pgsql, 18, "disk-failure.pgsql") &&
		pgsql_acks.observations.back().memory.find("disk-failure.pgsql") != std::string::npos,
		"failure acknowledgement occurs after the configured runtime then MEMORY sequence");
	const ChecksumSnapshot pgsql_v2_after_disk_failure =
		checksum_snapshot(GloVars.checksums_values.pgsql_servers_v2);
	ok(pgsql_v2_after_disk_failure.checksum != pgsql_v2_before_disk_failure.checksum &&
		pgsql_v2_after_disk_failure.version == pgsql_v2_before_disk_failure.version + 1 &&
		pgsql_v2_after_disk_failure.epoch >= pgsql_v2_before_disk_failure.epoch &&
		pgsql_acks.observations.back().v2.checksum == pgsql_v2_after_disk_failure.checksum &&
		pgsql_acks.observations.back().v2.version == pgsql_v2_after_disk_failure.version &&
		pgsql_acks.observations.back().v2.epoch == pgsql_v2_after_disk_failure.epoch,
		"PostgreSQL v2 state is published before a later DISK failure is acknowledged false");

	ProxySQL_ServerRow mysql_operator {17, "operator-save.mysql", 3306, 0, "ONLINE", 71, 0, 141, 0, 1, 0, "operator"};
	ProxySQL_ServerRow pgsql_operator {17, "operator-save.pgsql", 5432, 0, "ONLINE", 71, 0, 141, 0, 1, 0, "operator"};
	ok(post_and_drain(*manager, *admin, desired(ProxySQL_ServerProtocol::mysql,
		mysql_generation, ProxySQL_ServerPersistence::runtime_only, mysql_operator)) &&
		post_and_drain(*manager, *admin, desired(ProxySQL_ServerProtocol::pgsql,
		pgsql_generation, ProxySQL_ServerPersistence::runtime_only, pgsql_operator)),
		"runtime-only discovered rows remain ordinary runtime state before operator SAVE");
	ok(manager->uninstall_server_discovery_controller(ProxySQL_ServerProtocol::mysql) &&
		manager->uninstall_server_discovery_controller(ProxySQL_ServerProtocol::pgsql) &&
		proxysql_stop_configured_plugins(manager, error),
		"materialization controllers and module retire before ordinary full SAVE fixture");
	admin->mysql_servers_wrlock();
	const bool mysql_full_save = admin->save_mysql_servers_runtime_to_database(false);
	admin->mysql_servers_wrunlock();
	admin->pgsql_servers_wrlock();
	const bool pgsql_full_save = admin->save_pgsql_servers_runtime_to_database(false);
	admin->pgsql_servers_wrunlock();
	ok(mysql_full_save && snapshot(admin_db, "main.mysql_servers").find("operator-save.mysql") != std::string::npos &&
		snapshot(admin_db, "main.mysql_servers").find("runtime-unrelated.mysql") != std::string::npos,
		"ordinary full SAVE MYSQL SERVERS copies discovered and unrelated runtime hostgroups");
	ok(pgsql_full_save && snapshot(admin_db, "main.pgsql_servers").find("operator-save.pgsql") != std::string::npos &&
		snapshot(admin_db, "main.pgsql_servers").find("runtime-unrelated.pgsql") != std::string::npos,
		"ordinary full SAVE PGSQL SERVERS copies discovered and unrelated runtime hostgroups");
	ok(mysql_acks.destroyed.load() == 1 && pgsql_acks.destroyed.load() == 1,
		"no hidden persistence mode changes controller or runtime lifetime semantics");

	GloAdmin = nullptr;
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B");
	unsetenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_SERVER_DISCOVERY");
	unsetenv("PROXYSQL_FAKE_PLUGIN_AFFILIATED");
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_BOTH_PROTOCOLS");
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_CONFLICT_CLAIM");
	unsetenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_SNAPSHOT");
	return exit_status();
}
