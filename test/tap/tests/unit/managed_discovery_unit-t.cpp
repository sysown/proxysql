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
    plan(39);
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
        ok(removed && proxysql_active_server_hostgroup_claims(protocol).empty(),
			"empty managed policy removes claims and native topology rows");
        proxysql_lock_configuration();
        installed=proxysql_install_managed_discovery_locked(
            protocol,4,{role_claim(protocol,703,704)},next,error);
        proxysql_unlock_configuration();
        ok(installed && proxysql_active_server_hostgroup_claims(protocol).size()==1,
            "controller owns a live claim before lifecycle retirement");
        ok(manager->uninstall_server_discovery_controller(protocol) &&
            proxysql_active_server_hostgroup_claims(protocol).empty(),
            "controller retirement releases its claims and native topology rows");
    }
    return exit_status();
}
