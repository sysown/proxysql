#include "tap.h"
#include "ProxySQL_PluginManager.h"
#include "ProxySQL_ServerDiscovery.h"
#include "MySQL_Thread.h"
#include "ProxySQL_Statistics.hpp"
#include "MySQL_Monitor.hpp"
#include "PgSQL_HostGroups_Manager.h"
#include "proxysql_admin.h"
#include "test_globals.h"
#include "test_init.h"

#include <cstdlib>
#include <dlfcn.h>
#include <memory>
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

#include "ProxySQL_ConfigurationAccess.h"


namespace {
struct Observed {
    ProxySQL_ServerRuntimeSnapshot snapshot {};
    std::vector<std::pair<uint64_t,bool>> acks;
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

bool has_topology_pair(const SQLite3_result& rows, uint32_t writer, uint32_t reader) {
	for (const auto* row : rows.rows) {
		if (row != nullptr && row->fields != nullptr && row->fields[0] != nullptr &&
			row->fields[1] != nullptr &&
			static_cast<uint32_t>(strtoul(row->fields[0], nullptr, 10)) == writer &&
			static_cast<uint32_t>(strtoul(row->fields[1], nullptr, 10)) == reader) return true;
	}
	return false;
}

bool has_monitor_endpoint(const SQLite3_result& rows, bool mysql,
		const std::string& hostname, uint16_t port) {
	const size_t hostname_index = mysql ? 0 : 1;
	const size_t port_index = mysql ? 1 : 2;
	for (const auto* row : rows.rows) {
		if (row != nullptr && row->fields != nullptr &&
			row->fields[hostname_index] != nullptr && row->fields[port_index] != nullptr &&
			hostname == row->fields[hostname_index] &&
			static_cast<uint16_t>(strtoul(row->fields[port_index], nullptr, 10)) == port) return true;
	}
	return false;
}

bool has_aurora_monitor_endpoint(const std::string& hostname, uint16_t port) {
	bool found = false;
	pthread_mutex_lock(&GloMyMon->aws_aurora_mutex);
	if (GloMyMon->AWS_Aurora_Hosts_resultset != nullptr) {
		for (const auto* row : GloMyMon->AWS_Aurora_Hosts_resultset->rows) {
			if (row != nullptr && row->fields != nullptr && row->fields[2] != nullptr &&
				row->fields[3] != nullptr && hostname == row->fields[2] &&
				static_cast<uint16_t>(strtoul(row->fields[3], nullptr, 10)) == port) {
				found = true;
				break;
			}
		}
	}
	pthread_mutex_unlock(&GloMyMon->aws_aurora_mutex);
	return found;
}

template <typename HGM>
bool execute_hgm_statement(HGM* hgm, const char* sql) {
	char* error = nullptr;
	std::unique_ptr<SQLite3_result> ignored(
		hgm->execute_query(const_cast<char*>(sql), &error));
	const bool success = error == nullptr;
	if (error != nullptr) free(error);
	return success;
}

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


} // namespace
int main() {
    plan(83);
    test_init_minimal();
    test_init_query_processor();
    test_init_hostgroups();
    GloVars.statsdb_disk = const_cast<char*>(":memory:");
    GloProxyStats = new ProxySQL_Statistics();
    GloMyMon = new MySQL_Monitor();
    MyHGM->gtid_ev_loop = ev_loop_new(0);
    ev_async_init(MyHGM->gtid_ev_async, [](EV_P_ ev_async*, int) {});
    GloAdmin = new ProxySQL_Admin(); // Real, process-scoped fixture.
    pipe(GloAdmin->pipefd);
	SQLite3DB admin_db;
	char memory_db[] = ":memory:";
	admin_db.open(memory_db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	create_server_load_schema(admin_db);
	GloAdmin->admindb = &admin_db;
    std::unique_ptr<ProxySQL_PluginManager> manager;
    std::string error;
    // No AWS policy tables in this fixture.
    ok(proxysql_load_configured_plugins(manager, {PROXYSQL_FAKE_PLUGIN_PATH}, error) &&
        proxysql_init_configured_plugins(manager.get(), error), "plugin manager starts without a policy plugin");
    Observed observations[2];
    for (int index=0; index<2; ++index) {
        const auto protocol = index == 0 ? ProxySQL_ServerProtocol::mysql : ProxySQL_ServerProtocol::pgsql;
        const bool mysql = index == 0;
        const uint16_t port = mysql ? 3306 : 5432;
        auto* controller = new ManagedController(observations[index]);
        auto& observed = observations[index];
        ok(manager->install_server_discovery_controller(protocol, controller, destroy_controller,
            dlopen(PROXYSQL_FAKE_PLUGIN_PATH, RTLD_NOW | RTLD_LOCAL)), "%s controller installs", mysql?"MySQL":"PostgreSQL");
        ProxySQL_ServerRow seed {701, "managed.example", port};
		if (mysql) {
			admin_db.execute("INSERT INTO mysql_servers VALUES (701,'managed.example',3306,0,'ONLINE',1,0,1000,0,1,0,'')");
			GloAdmin->mysql_servers_wrlock();
			GloAdmin->load_mysql_servers_to_runtime();
			GloAdmin->mysql_servers_wrunlock();
		} else {
			admin_db.execute("INSERT INTO pgsql_servers VALUES (701,'managed.example',5432,'ONLINE',1,0,1000,0,1,0,'')");
			GloAdmin->pgsql_servers_wrlock();
			GloAdmin->load_pgsql_servers_to_runtime();
			GloAdmin->pgsql_servers_wrunlock();
		}
		const uint64_t configured_generation = observed.snapshot.generation;
		ok(configured_generation != 0 && observed.snapshot.servers.size() == 1,
			"shared MEMORY server configuration is loaded into runtime");
        const bool shunned = mysql ? MyHGM->shun_and_killall(const_cast<char*>("managed.example"),port) :
            PgHGM->shun_and_killall(const_cast<char*>("managed.example"),port);
        ok(shunned, "real HGM has monitor-owned SHUNNED state before policy installation");
        uint64_t generation=0;
        proxysql_lock_configuration();
        bool installed = proxysql_install_managed_discovery_locked(
            protocol, 1, {role_claim(protocol,701,702)}, generation,error);
        proxysql_unlock_configuration();
        ok(installed && generation == configured_generation+1 && observed.snapshot.generation == generation,
            "typed policy installs its native topology row and publishes one generation: %s",error.c_str());
        const auto claims = proxysql_active_server_hostgroup_claims(protocol);
        ok(claims.size()==1 && claims[0].writer_hostgroup==701 &&
            claims[0].reader_hostgroup==702 &&
            claims[0].role_monitor.kind==(mysql
                ? ProxySQL_ServerRoleMonitor::mysql_replication
                : ProxySQL_ServerRoleMonitor::pgsql_replication),
            "explicit typed managed claim pair is active");
        std::unique_ptr<SQLite3_result> readonly(mysql ? MyHGM->get_read_only_servers() : PgHGM->get_read_only_servers());
        bool monitors_seed = false;
        if (readonly) for (const auto* row : readonly->rows) {
            if (row && row->fields[mysql?0:1] && std::string(row->fields[mysql?0:1])=="managed.example") monitors_seed=true;
        }
        ok(monitors_seed,
            "typed claims materialize a native topology row for monitor enumeration");
		ok(observed.snapshot.servers.size()==1 && observed.snapshot.servers[0].status=="ONLINE",
			"controller snapshot contains the configured server status");
        std::unique_ptr<SQLite3_result> health(mysql ? MyHGM->dump_table_mysql("mysql_servers") : PgHGM->dump_table_pgsql("pgsql_servers"));
        const auto* health_row=find_row(*health,701,"managed.example",port);
		ok(health_row && std::string(health_row->fields[mysql?4:3])=="ONLINE",
			"topology installation activates the shared MEMORY server configuration");
        ProxySQL_ServerDesiredSet old {protocol,generation,{701,702},{seed},ProxySQL_ServerPersistence::runtime_only};
        ok(manager->post_server_desired_set(old), "old generation work queues before revision change");
        uint64_t next=0;
        proxysql_lock_configuration();
        installed=proxysql_install_managed_discovery_locked(
            protocol,2,{role_claim(protocol,703,704)},next,error);
        proxysql_unlock_configuration();
        ok(installed && next==generation+1 && !manager->revalidate_server_desired_set(protocol,controller,old),
            "new revision fences old generation before its delayed apply");
        ok(GloAdmin->drain_server_discovery_updates()==1 && observed.acks.size()==1 && !observed.acks[0].second,
            "delayed old generation gets a negative acknowledgement");
        seed.hostgroup_id=703;
        ProxySQL_ServerDesiredSet fresh {protocol,next,{703,704},{seed},ProxySQL_ServerPersistence::runtime_only};
        ok(manager->post_server_desired_set(fresh) && GloAdmin->drain_server_discovery_updates()==1 && observed.acks.back().second,
            "new generation discovery applies through the existing runtime-only queue");
        health.reset(mysql ? MyHGM->dump_table_mysql("mysql_servers") : PgHGM->dump_table_pgsql("pgsql_servers"));
		ok(find_row(*health,703,"managed.example",port) != nullptr,
			"runtime-only discovery applies the active claimed inventory");
		if (mysql) {
			ProxySQL_ServerRow reader_one {704, "reader-one.example", 3306};
			ProxySQL_ServerRow reader_two {704, "reader-two.example", 3306};
			ProxySQL_ServerDesiredSet replicated {
				protocol, next, {703, 704}, {seed, reader_one, reader_two},
				ProxySQL_ServerPersistence::runtime_only
			};
			ok(manager->post_server_desired_set(replicated) &&
				GloAdmin->drain_server_discovery_updates() == 1 &&
				observed.acks.back().second,
				"replication inventory applies one writer and two readers");
			std::unique_ptr<SQLite3_result> replication_monitor(MyHGM->get_read_only_servers());
			ok(replication_monitor &&
				has_monitor_endpoint(*replication_monitor, true, "managed.example", 3306) &&
				has_monitor_endpoint(*replication_monitor, true, "reader-one.example", 3306) &&
				has_monitor_endpoint(*replication_monitor, true, "reader-two.example", 3306),
				"replication monitor enumerates the reconciled writer and readers");
			ProxySQL_ServerRow reader_three {704, "reader-three.example", 3306};
			replicated.servers.push_back(reader_three);
			ok(manager->post_server_desired_set(replicated) &&
				GloAdmin->drain_server_discovery_updates() == 1 &&
				observed.acks.back().second,
				"replication inventory adds a reader without reinstalling topology");
			replication_monitor.reset(MyHGM->get_read_only_servers());
			ok(replication_monitor &&
				has_monitor_endpoint(*replication_monitor, true, "reader-three.example", 3306),
				"replication monitor enumerates the later-added reader");
		}
        proxysql_lock_configuration();
        bool stale=proxysql_install_managed_discovery_locked(
            protocol,1,{role_claim(protocol,705,706)},generation,error);
        bool overlap=proxysql_install_managed_discovery_locked(protocol,3,
            {role_claim(protocol,705,706),role_claim(protocol,706,707)},generation,error);
        proxysql_unlock_configuration();
        ok(!stale && !overlap && proxysql_pending_server_runtime_generation(protocol)==next+1,
            "stale revisions and overlapping claims reject without consuming a generation");
		ProxySQL_ServerRuntimeSnapshot reload {protocol,0,{seed},{}};
        const uint64_t before_reload = proxysql_pending_server_runtime_generation(protocol);
        proxysql_publish_server_runtime(std::move(reload));
        ok(proxysql_pending_server_runtime_generation(protocol)==before_reload+1 &&
            proxysql_active_server_hostgroup_claims(protocol).size()==1,
            "ordinary server installation retains separately owned managed claims");
		ProxySQL_ServerRuntimeSnapshot conflict {protocol,0,{seed},{703}};
        const uint64_t before_conflict = proxysql_pending_server_runtime_generation(protocol);
        proxysql_publish_server_runtime(std::move(conflict));
        ok(proxysql_pending_server_runtime_generation(protocol)==before_conflict+1 &&
            proxysql_active_server_hostgroup_claims(protocol).size()==1,
            "builtin topology overlapping a managed claim is logged and never rejects the installation");
        proxysql_lock_configuration();
        const bool removed=proxysql_install_managed_discovery_locked(protocol,3,{},next,error);
        proxysql_unlock_configuration();
		std::unique_ptr<SQLite3_result> removed_topology(mysql
			? MyHGM->dump_table_mysql("mysql_replication_hostgroups")
			: PgHGM->dump_table_pgsql("pgsql_replication_hostgroups"));
		std::unique_ptr<SQLite3_result> removed_monitor(mysql
			? MyHGM->get_read_only_servers() : PgHGM->get_read_only_servers());
		ok(removed && proxysql_active_server_hostgroup_claims(protocol).empty() &&
			removed_topology && !has_topology_pair(*removed_topology,703,704) &&
			removed_monitor && !has_monitor_endpoint(*removed_monitor,mysql,
				"managed.example",port),
			"empty managed policy removes claims and native topology rows");
        proxysql_lock_configuration();
        installed=proxysql_install_managed_discovery_locked(
            protocol,4,{role_claim(protocol,703,704)},next,error);
        proxysql_unlock_configuration();
        ok(installed && proxysql_active_server_hostgroup_claims(protocol).size()==1,
            "controller owns a live claim before lifecycle retirement");
		const bool retired = manager->uninstall_server_discovery_controller(protocol);
		std::unique_ptr<SQLite3_result> retired_topology(mysql
			? MyHGM->dump_table_mysql("mysql_replication_hostgroups")
			: PgHGM->dump_table_pgsql("pgsql_replication_hostgroups"));
		std::unique_ptr<SQLite3_result> retired_monitor(mysql
			? MyHGM->get_read_only_servers() : PgHGM->get_read_only_servers());
		ok(retired && proxysql_active_server_hostgroup_claims(protocol).empty() &&
			retired_topology && !has_topology_pair(*retired_topology,703,704) &&
			retired_monitor && !has_monitor_endpoint(*retired_monitor,mysql,
				"managed.example",port),
            "controller retirement releases its claims and native topology rows");
    }

	Observed aurora_observed;
	auto* aurora_controller = new ManagedController(aurora_observed);
	ok(manager->install_server_discovery_controller(
		ProxySQL_ServerProtocol::mysql, aurora_controller, destroy_controller,
		dlopen(PROXYSQL_FAKE_PLUGIN_PATH, RTLD_NOW | RTLD_LOCAL)),
		"Aurora discovery controller installs");
	ProxySQL_ServerHostgroupClaim aurora_claim {801, 802};
	aurora_claim.role_monitor.kind = ProxySQL_ServerRoleMonitor::mysql_aws_aurora;
	aurora_claim.role_monitor.domain_name = ".example";
	uint64_t aurora_generation = 0;
	proxysql_lock_configuration();
	const bool aurora_installed = proxysql_install_managed_discovery_locked(
		ProxySQL_ServerProtocol::mysql, 1, {aurora_claim}, aurora_generation, error);
	proxysql_unlock_configuration();
	ok(aurora_installed && aurora_generation != 0 &&
		!has_aurora_monitor_endpoint("aurora-writer.example", 3306),
		"Aurora topology installs before its runtime inventory");
	ProxySQL_ServerRow aurora_writer {801, "aurora-writer.example", 3306};
	ProxySQL_ServerRow aurora_reader {802, "aurora-reader.example", 3306};
	ProxySQL_ServerDesiredSet aurora_initial {
		ProxySQL_ServerProtocol::mysql, aurora_generation, {801, 802},
		{aurora_writer, aurora_reader}, ProxySQL_ServerPersistence::runtime_only
	};
	ok(manager->post_server_desired_set(aurora_initial) &&
		GloAdmin->drain_server_discovery_updates() == 1 &&
		aurora_observed.acks.back().second,
		"runtime-only Aurora inventory applies after topology installation");
	ok(has_aurora_monitor_endpoint("aurora-writer.example", 3306) &&
		has_aurora_monitor_endpoint("aurora-reader.example", 3306),
		"runtime-only inventory refreshes the Aurora monitor input");
	MyHGM->update_aws_aurora_set_reader(
		801, 802, const_cast<char*>("aurora-absent"), true);
	std::unique_ptr<SQLite3_result> aurora_runtime(
		MyHGM->dump_table_mysql("mysql_servers"));
	ok(find_row(*aurora_runtime, 802, "aurora-absent.example", 3306) == nullptr,
		"managed Aurora monitoring does not discover an endpoint outside plugin inventory");
	MyHGM->wrlock();
	MySrvC* offline_reader = MyHGM->find_server_in_hg(
		802, "aurora-reader.example", 3306);
	if (offline_reader != nullptr)
		offline_reader->set_status(MYSQL_SERVER_STATUS_OFFLINE_HARD);
	MyHGM->wrunlock();
	const bool offline_recorded = execute_hgm_statement(MyHGM,
		"UPDATE mysql_servers SET status=3 WHERE hostgroup_id=802 "
		"AND hostname='aurora-reader.example' AND port=3306");
	MyHGM->update_aws_aurora_set_reader(
		801, 802, const_cast<char*>("aurora-reader"), true);
	aurora_runtime.reset(MyHGM->dump_table_mysql("mysql_servers"));
	const SQLite3_row* revived_reader = find_row(
		*aurora_runtime, 802, "aurora-reader.example", 3306);
	ok(offline_reader != nullptr && offline_recorded && revived_reader != nullptr &&
		std::string(revived_reader->fields[4]) == "ONLINE",
		"managed Aurora monitoring restores an existing OFFLINE_HARD endpoint");
	MyHGM->update_aws_aurora_set_writer(
		801, 802, const_cast<char*>("aurora-reader"), true);
	aurora_runtime.reset(MyHGM->dump_table_mysql("mysql_servers"));
	ok(find_row(*aurora_runtime, 801, "aurora-reader.example", 3306) != nullptr &&
		find_row(*aurora_runtime, 802, "aurora-reader.example", 3306) == nullptr &&
		find_row(*aurora_runtime, 802, "aurora-writer.example", 3306) != nullptr,
		"managed Aurora monitoring continues to apply writer and reader placement");
	MyHGM->update_aws_aurora_set_reader(
		801, 802, const_cast<char*>("aurora-native"), false);
	aurora_runtime.reset(MyHGM->dump_table_mysql("mysql_servers"));
	ok(find_row(*aurora_runtime, 802, "aurora-native.example", 3306) != nullptr,
		"unmanaged Aurora monitoring retains native endpoint discovery");
	ProxySQL_ServerRow replacement_reader {802, "aurora-reader-2.example", 3306};
	ProxySQL_ServerDesiredSet aurora_replacement {
		ProxySQL_ServerProtocol::mysql, aurora_generation, {801, 802},
		{aurora_writer, replacement_reader}, ProxySQL_ServerPersistence::runtime_only
	};
	ok(manager->post_server_desired_set(aurora_replacement) &&
		GloAdmin->drain_server_discovery_updates() == 1 &&
		aurora_observed.acks.back().second,
		"a complete Aurora desired set replaces runtime inventory");
	ok(has_aurora_monitor_endpoint("aurora-writer.example", 3306) &&
		!has_aurora_monitor_endpoint("aurora-reader.example", 3306) &&
		!has_aurora_monitor_endpoint("aurora-native.example", 3306) &&
		has_aurora_monitor_endpoint("aurora-reader-2.example", 3306),
		"the refreshed Aurora monitor input removes stale endpoints");
	ok(manager->uninstall_server_discovery_controller(ProxySQL_ServerProtocol::mysql),
		"Aurora discovery controller retires cleanly");

	Observed bgd_observed;
	auto* bgd_controller = new ManagedController(bgd_observed);
	ok(manager->install_server_discovery_controller(
		ProxySQL_ServerProtocol::mysql, bgd_controller, destroy_controller,
		dlopen(PROXYSQL_FAKE_PLUGIN_PATH, RTLD_NOW | RTLD_LOCAL)),
		"Blue/Green discovery controller installs");
	auto bgd_claim = role_claim(ProxySQL_ServerProtocol::mysql, 901, 902);
	bgd_claim.role_monitor.green_writer_hostgroup = 903;
	bgd_claim.role_monitor.green_reader_hostgroup = 904;
	bgd_claim.role_monitor.writer_is_also_reader = 1;
	uint64_t bgd_generation = 0;
	proxysql_lock_configuration();
	const bool bgd_installed = proxysql_install_managed_discovery_locked(
		ProxySQL_ServerProtocol::mysql, 1, {bgd_claim}, bgd_generation, error);
	proxysql_unlock_configuration();
	std::unique_ptr<SQLite3_result> bgd_replication(
		MyHGM->dump_table_mysql("mysql_replication_hostgroups"));
	std::unique_ptr<SQLite3_result> bgd_topology(
		MyHGM->dump_table_mysql("mysql_aws_rds_bgd_hostgroups"));
	ok(bgd_installed && bgd_generation != 0 &&
		bgd_replication && has_topology_pair(*bgd_replication, 901, 902) &&
		bgd_topology && !has_topology_pair(*bgd_topology, 901, 902),
		"four-group reservation keeps blue replication and waits to start BGD");
	ProxySQL_ServerDesiredSet bgd_four {
		ProxySQL_ServerProtocol::mysql, bgd_generation, {901, 902, 903, 904},
		{{901, "blue-writer.example", 3306},
		 {902, "blue-reader.example", 3306},
		 {902, "blue-reader-two.example", 3306},
		 {903, "green-writer.example", 3306},
		 {904, "green-reader.example", 3306},
		 {904, "green-other.example", 3306}},
		ProxySQL_ServerPersistence::runtime_only
	};
	ok(manager->post_server_desired_set(bgd_four) &&
		GloAdmin->drain_server_discovery_updates() == 1 &&
		!bgd_observed.acks.empty() && bgd_observed.acks.back().second,
		"one accepted publication installs blue and green members together");
	std::unique_ptr<SQLite3_result> bgd_runtime(MyHGM->dump_table_mysql("mysql_servers"));
	ok(bgd_runtime &&
		find_row(*bgd_runtime, 901, "blue-writer.example", 3306) &&
		find_row(*bgd_runtime, 902, "blue-reader.example", 3306) &&
		find_row(*bgd_runtime, 902, "blue-reader-two.example", 3306) &&
		find_row(*bgd_runtime, 903, "green-writer.example", 3306) &&
		find_row(*bgd_runtime, 904, "green-reader.example", 3306) &&
		find_row(*bgd_runtime, 904, "green-other.example", 3306),
		"all four hostgroups contain their discovered server rows");
	ProxySQL_ManagedBlueGreenHandoff handoff;
	handoff.generation = bgd_generation;
	handoff.writer_hostgroup = 901;
	handoff.reader_hostgroup = 902;
	handoff.green_writer_hostgroup = 903;
	handoff.green_reader_hostgroup = 904;
	handoff.deployment_id = "bgd-test";
	handoff.pairs = {
		{"arn:aws:rds:us-east-1:1:db:blue-writer",
		 "arn:aws:rds:us-east-1:1:db:green-writer",
		 "db-BLUEW", "db-GREENW", "blue-writer.example",
		 "green-writer.example", 3306, true},
		{"arn:aws:rds:us-east-1:1:db:blue-reader",
		 "arn:aws:rds:us-east-1:1:db:green-reader",
		 "db-BLUER", "db-GREENR", "blue-reader.example",
		 "green-reader.example", 3306, false},
		{"arn:aws:rds:us-east-1:1:db:blue-reader-two",
		 "arn:aws:rds:us-east-1:1:db:green-other",
		 "db-BLUER2", "db-GREENR2", "blue-reader-two.example",
		 "green-other.example", 3306, false}
	};
	auto invalid_handoff = handoff;
	invalid_handoff.pairs[1].green_resource_id = "db-GREENW";
	ok(!proxysql_activate_managed_blue_green(invalid_handoff, error),
		"duplicate physical green member cannot activate a BGD row");
	invalid_handoff = handoff;
	++invalid_handoff.generation;
	ok(!proxysql_activate_managed_blue_green(invalid_handoff, error),
		"stale or future inventory generation cannot activate a BGD row");
	const bool activated = proxysql_activate_managed_blue_green(handoff, error);
	bgd_replication.reset(MyHGM->dump_table_mysql("mysql_replication_hostgroups"));
	bgd_topology.reset(MyHGM->dump_table_mysql("mysql_aws_rds_bgd_hostgroups"));
	ok(activated && bgd_replication &&
		has_topology_pair(*bgd_replication, 901, 902) &&
		bgd_topology && has_topology_pair(*bgd_topology, 901, 902),
		"complete handoff starts BGD monitoring and retains blue replication");
	bool writer_reader_policy_retained = false;
	if (bgd_topology) for (const auto* row : bgd_topology->rows) {
		if (row && row->fields && row->fields[0] && row->fields[5] &&
			std::string(row->fields[0]) == "901" && std::string(row->fields[5]) == "1")
			writer_reader_policy_retained = true;
	}
	ok(writer_reader_policy_retained,
		"managed BGD row carries the writer-is-also-reader policy");
	const auto accepted_handoff = proxysql_active_managed_blue_green(901);
	ok(accepted_handoff && accepted_handoff->deployment_id == "bgd-test" &&
		accepted_handoff->pairs.size() == 3 &&
		accepted_handoff->pairs[1].green_hostname == "green-reader.example",
		"core retains exact writer and replica pairs for its native worker");
	AWS_RDS_BGD_State managed_state;
	managed_state.writer_hg = 901;
	managed_state.reader_hg = 902;
	managed_state.green_writer_hg = 903;
	managed_state.green_reader_hg = 904;
	AWS_RDS_Topology_Result managed_topology;
	managed_topology.blue_green = true;
	managed_topology.nodes.push_back({"green-writer", "green-writer.example", 3306,
		"BLUE_GREEN_DEPLOYMENT_TARGET", "AVAILABLE"});
	// The public state-machine entry point resolves green hosts after building the map.
	// Keep these fake names local so this unit test does not depend on external DNS.
	GloMyMon->dns_cache->add("green-writer.example", {"127.0.0.1"});
	GloMyMon->dns_cache->add("green-reader.example", {"127.0.0.2"});
	GloMyMon->dns_cache->add("green-other.example", {"127.0.0.3"});
	GloMyMon->handle_aws_rds_bgd(managed_state, managed_topology);
	ok(managed_state.bg_map.size() == 3 && managed_state.bg_map[0].is_writer &&
		managed_state.bg_map[0].blue_host == "blue-writer.example" &&
		managed_state.bg_map[1].blue_host == "blue-reader.example" &&
		managed_state.bg_map[1].green_host == "green-reader.example" &&
		managed_state.bg_map[2].blue_host == "blue-reader-two.example" &&
		managed_state.bg_map[2].green_host == "green-other.example",
		"native BGD worker uses two exact replica pairs without a name suffix");
	managed_state.bg_map.clear();
	managed_topology.nodes[0].endpoint = "other-green.example";
	GloMyMon->handle_aws_rds_bgd(managed_state, managed_topology);
	ok(managed_state.bg_map.empty(),
		"native BGD worker rejects an unrelated topology TARGET");
	ProxySQL_ServerDesiredSet bgd_partial = bgd_four;
	bgd_partial.delegated_hostgroups = {901, 902};
	ok(manager->post_server_desired_set(bgd_partial) &&
		GloAdmin->drain_server_discovery_updates() == 1 &&
		!bgd_observed.acks.back().second,
		"blue-only publication cannot replace a four-group claim");
	const size_t bgd_ack_count = bgd_observed.acks.size();
	ok(manager->post_server_desired_set(bgd_four) &&
		GloAdmin->drain_server_discovery_updates() == 1 &&
		bgd_observed.acks.size() == bgd_ack_count + 1 &&
		!bgd_observed.acks.back().second,
		"active native BGD ownership blocks plugin replacement of all four groups");
	MyHGM->wrlock();
	const bool reader_shunned = MyHGM->aws_rds_bgd_set_shun_server(
		902, "blue-reader.example", 3306, true);
	MyHGM->wrunlock();
	ok(reader_shunned, "native BGD can shun a blue reader before reload");
	uint64_t reloaded_generation = 0;
	proxysql_lock_configuration();
	const bool safe_reload = proxysql_install_managed_discovery_locked(
		ProxySQL_ServerProtocol::mysql, 2, {bgd_claim}, reloaded_generation, error);
	proxysql_unlock_configuration();
	bgd_replication.reset(MyHGM->dump_table_mysql("mysql_replication_hostgroups"));
	bgd_topology.reset(MyHGM->dump_table_mysql("mysql_aws_rds_bgd_hostgroups"));
	ok(safe_reload && reloaded_generation > bgd_generation &&
		bgd_replication && has_topology_pair(*bgd_replication, 901, 902) &&
		bgd_topology && has_topology_pair(*bgd_topology, 901, 902) &&
		proxysql_active_managed_blue_green(901).has_value(),
		"safe claim reload retains the BGD row and exact pairs");
	bgd_runtime.reset(MyHGM->dump_table_mysql("mysql_servers"));
	ok(bgd_runtime &&
		find_row(*bgd_runtime, 901, "blue-writer.example", 3306) &&
		find_row(*bgd_runtime, 902, "blue-reader.example", 3306) &&
		find_row(*bgd_runtime, 902, "blue-reader-two.example", 3306) &&
		find_row(*bgd_runtime, 903, "green-writer.example", 3306) &&
		find_row(*bgd_runtime, 904, "green-reader.example", 3306) &&
		find_row(*bgd_runtime, 904, "green-other.example", 3306),
		"safe claim reload retains live runtime-only blue and green members");
	const auto* shunned_after_reload = bgd_runtime ?
		find_row(*bgd_runtime, 902, "blue-reader.example", 3306) : nullptr;
	ok(shunned_after_reload && shunned_after_reload->fields[4] &&
		std::string(shunned_after_reload->fields[4]) == "SHUNNED_AWS_BGD",
		"safe claim reload keeps native BGD reader shun state");
	auto changed_bgd_claim = bgd_claim;
	changed_bgd_claim.role_monitor.green_reader_hostgroup = 905;
	uint64_t rejected_generation = 0;
	proxysql_lock_configuration();
	const bool changed_reload = proxysql_install_managed_discovery_locked(
		ProxySQL_ServerProtocol::mysql, 3, {changed_bgd_claim},
		rejected_generation, error);
	proxysql_unlock_configuration();
	ok(!changed_reload && rejected_generation == 0 &&
		proxysql_active_managed_blue_green(901).has_value(),
		"active BGD rejects a claim that changes reserved green hostgroups");
	ok(!proxysql_complete_managed_blue_green(901, "other-deployment", error) &&
		proxysql_active_managed_blue_green(901).has_value(),
		"an unrelated completion cannot release the active deployment");
	const bool completed = proxysql_complete_managed_blue_green(901, "bgd-test", error);
	bgd_replication.reset(MyHGM->dump_table_mysql("mysql_replication_hostgroups"));
	bgd_topology.reset(MyHGM->dump_table_mysql("mysql_aws_rds_bgd_hostgroups"));
	ok(completed && bgd_replication && has_topology_pair(*bgd_replication, 901, 902) &&
		bgd_topology && !has_topology_pair(*bgd_topology, 901, 902),
		"native completion removes only the managed BGD monitor row");
	ok(!proxysql_active_managed_blue_green(901),
		"native completion releases the exact pair map");
	auto second_handoff = handoff;
	second_handoff.generation = reloaded_generation;
	second_handoff.deployment_id = "bgd-second";
	second_handoff.pairs[0].green_resource_id = "db-GREENW2";
	second_handoff.pairs[1].green_resource_id = "db-GREENR2";
	second_handoff.pairs[2].green_resource_id = "db-GREENR3";
	const bool second_activated = proxysql_activate_managed_blue_green(second_handoff, error);
	bgd_topology.reset(MyHGM->dump_table_mysql("mysql_aws_rds_bgd_hostgroups"));
	const auto second_active = proxysql_active_managed_blue_green(901);
	ok(second_activated && bgd_topology && has_topology_pair(*bgd_topology, 901, 902) &&
		second_active && second_active->deployment_id == "bgd-second",
		"another complete deployment can activate after cleanup");
	AWS_RDS_BGD_State native_cleanup;
	native_cleanup.writer_hg = 901;
	native_cleanup.reader_hg = 902;
	native_cleanup.green_writer_hg = 903;
	native_cleanup.green_reader_hg = 904;
	native_cleanup.writer_is_also_reader = 1;
	native_cleanup.bgd_status = AWS_RDS_BGD_Status::AVAILABLE;
	native_cleanup.shunned_readers.push_back({"blue-reader.example", 3306});
	managed_topology.nodes[0].endpoint = "green-writer.example";
	GloMyMon->handle_aws_rds_bgd(native_cleanup, managed_topology);
	GloMyMon->aws_rds_bgd_handle_topology_absent(native_cleanup);
	bgd_topology.reset(MyHGM->dump_table_mysql("mysql_aws_rds_bgd_hostgroups"));
	ok(native_cleanup.bgd_status == AWS_RDS_BGD_Status::NONE &&
		bgd_topology && !has_topology_pair(*bgd_topology, 901, 902) &&
		!proxysql_active_managed_blue_green(901),
		"native topology-absent cleanup removes the managed BGD row and pairs");
	bgd_runtime.reset(MyHGM->dump_table_mysql("mysql_servers"));
	const auto* reader_after_cleanup = bgd_runtime ?
		find_row(*bgd_runtime, 902, "blue-reader.example", 3306) : nullptr;
	ok(reader_after_cleanup && reader_after_cleanup->fields[4] &&
		std::string(reader_after_cleanup->fields[4]) == "ONLINE",
		"native cleanup restores the shunned blue reader");
	auto third_handoff = second_handoff;
	third_handoff.deployment_id = "bgd-third";
	third_handoff.pairs[0].green_resource_id = "db-GREENW3";
	third_handoff.pairs[1].green_resource_id = "db-GREENR3";
	third_handoff.pairs[2].green_resource_id = "db-GREENR4";
	ok(proxysql_activate_managed_blue_green(third_handoff, error) &&
		proxysql_active_managed_blue_green(901)->deployment_id == "bgd-third",
		"a third deployment can start after native cleanup");
	AWS_RDS_BGD_State no_first_topology;
	no_first_topology.writer_hg = 901;
	GloMyMon->aws_rds_bgd_handle_topology_absent(no_first_topology);
	bgd_topology.reset(MyHGM->dump_table_mysql("mysql_aws_rds_bgd_hostgroups"));
	ok(bgd_topology && !has_topology_pair(*bgd_topology, 901, 902) &&
		!proxysql_active_managed_blue_green(901),
		"an absent first topology probe releases a managed BGD handoff");
	auto fourth_handoff = third_handoff;
	fourth_handoff.deployment_id = "bgd-fourth";
	fourth_handoff.pairs[0].green_resource_id = "db-GREENW4";
	fourth_handoff.pairs[1].green_resource_id = "db-GREENR5";
	fourth_handoff.pairs[2].green_resource_id = "db-GREENR6";
	ok(proxysql_activate_managed_blue_green(fourth_handoff, error) &&
		proxysql_active_managed_blue_green(901)->deployment_id == "bgd-fourth",
		"a fresh deployment can activate after an absent first probe");
	ok(manager->uninstall_server_discovery_controller(ProxySQL_ServerProtocol::mysql),
		"Blue/Green discovery controller retires cleanly");
	ok(!proxysql_active_managed_blue_green(901),
		"controller retirement releases the fourth deployment pair map");
    return exit_status();
}
