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


} // namespace
int main() {
    plan(43);
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
    std::unique_ptr<ProxySQL_PluginManager> manager;
    std::string error;
    // No server-module registration or AWS policy tables in this fixture.
    ok(proxysql_load_configured_plugins(manager, {PROXYSQL_FAKE_PLUGIN_PATH}, error) &&
        proxysql_init_configured_plugins(manager.get(), error), "plugin manager starts without a policy module");
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
        ProxySQL_ServerRow unrelated {799, "unrelated.example", port};
        auto rows = mysql ? mysql_rows({seed,unrelated}) : pgsql_rows({seed,unrelated});
        bool hgm_commit;
        if (mysql) { MyHGM->servers_add(rows.get()); hgm_commit = MyHGM->commit({}, {}, false); }
        else { PgHGM->servers_add(rows.get()); hgm_commit = PgHGM->commit({}, {}, false); }
        ProxySQL_ServerRuntimeSnapshot configured {protocol, 0, {seed,unrelated}, {}};
        ProxySQL_ServerRuntimeInstallTransaction install(protocol,error);
        ok(hgm_commit && install.prepare(configured,error) && install.commit(configured), "seed configuration installed");
        const bool shunned = mysql ? MyHGM->shun_and_killall(const_cast<char*>("managed.example"),port) :
            PgHGM->shun_and_killall(const_cast<char*>("managed.example"),port);
        ok(shunned, "real HGM has monitor-owned SHUNNED state before policy installation");
        const uint64_t monitor_epoch = proxysql_server_read_only_monitor_epoch(protocol);
        uint64_t generation=0;
        proxysql_lock_configuration();
        bool installed = proxysql_install_managed_discovery_locked(protocol, 1, {{701,702}}, generation,error);
        proxysql_unlock_configuration();
        ok(installed && generation == configured.generation+1 && observed.snapshot.generation == generation,
            "new policy installs without LOAD, a server module, or SQL policy tables: %s",error.c_str());
        const auto claims = proxysql_active_server_hostgroup_claims(protocol);
        ok(claims.size()==1 && claims[0].writer_hostgroup==701 && claims[0].reader_hostgroup==702,
            "explicit managed claim pair is active");
        std::unique_ptr<SQLite3_result> readonly(mysql ? MyHGM->get_read_only_servers() : PgHGM->get_read_only_servers());
        bool monitors_seed = false;
        if (readonly) for (const auto* row : readonly->rows) {
            if (row && row->fields[mysql?0:1] && std::string(row->fields[mysql?0:1])=="managed.example") monitors_seed=true;
        }
        ok(monitors_seed && proxysql_server_read_only_monitor_epoch(protocol)==monitor_epoch+1,
            "new claims immediately enumerate for the existing read-only monitor without LOAD");
        ok(observed.snapshot.servers.size()==2 && observed.snapshot.servers[0].status=="ONLINE",
            "monitor SHUNNED state is not materialized into authoritative configuration snapshot");
        std::unique_ptr<SQLite3_result> health(mysql ? MyHGM->dump_table_mysql("mysql_servers") : PgHGM->dump_table_pgsql("pgsql_servers"));
        const auto* health_row=find_row(*health,701,"managed.example",port);
        ok(health_row && std::string(health_row->fields[mysql?4:3])=="SHUNNED" &&
            find_row(*health,799,"unrelated.example",port), "policy installation preserves health and unrelated runtime servers");
        manager->commit_and_install_server_runtime_snapshot(observed.snapshot, {{801,802}});
        ok(proxysql_active_server_hostgroup_claims(protocol).size()==2,
            "generic module publication retains distinct managed claims");
        uint64_t rejected_generation=0;
        proxysql_lock_configuration();
        const bool collision=proxysql_install_managed_discovery_locked(protocol,2,{{801,803}},rejected_generation,error);
        proxysql_unlock_configuration();
        ok(!collision && proxysql_pending_server_runtime_generation(protocol)==generation+1,
            "managed policy cannot overlap generic module claims or consume a generation on rejection");
        manager->commit_and_install_server_runtime_snapshot(observed.snapshot, {});
        ok(proxysql_active_server_hostgroup_claims(protocol).size()==1,
            "clearing generic claims leaves managed policy installed");
        ProxySQL_ServerDesiredSet old {protocol,generation,{701,702},{seed},ProxySQL_ServerPersistence::runtime_only};
        ok(manager->post_server_desired_set(old), "old generation work queues before revision change");
        uint64_t next=0;
        proxysql_lock_configuration();
        installed=proxysql_install_managed_discovery_locked(protocol,2,{{703,704}},next,error);
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
        ok(find_row(*health,799,"unrelated.example",port) != nullptr, "runtime-only discovery preserves unrelated hostgroup");
        proxysql_lock_configuration();
        bool stale=proxysql_install_managed_discovery_locked(protocol,1,{{705,706}},generation,error);
        bool overlap=proxysql_install_managed_discovery_locked(protocol,3,{{705,706},{706,707}},generation,error);
        proxysql_unlock_configuration();
        ok(!stale && !overlap && proxysql_pending_server_runtime_generation(protocol)==next+1,
            "stale revisions and overlapping claims reject without consuming a generation");
        ProxySQL_ServerRuntimeSnapshot reload {protocol,0,{unrelated},{}};
        ProxySQL_ServerRuntimeInstallTransaction ordinary(protocol,error);
        ok(ordinary.prepare(reload,error) && ordinary.commit(reload) && proxysql_active_server_hostgroup_claims(protocol).size()==1,
            "ordinary server installation retains separately owned managed claims");
        ProxySQL_ServerRuntimeSnapshot conflict {protocol,0,{unrelated},{703}};
        ProxySQL_ServerRuntimeInstallTransaction conflicting(protocol,error);
        ok(!conflicting.prepare(conflict,error), "builtin topology cannot silently overlap an installed managed claim");
        proxysql_lock_configuration();
        const bool removed=proxysql_install_managed_discovery_locked(protocol,3,{},next,error);
        proxysql_unlock_configuration();
        ok(removed && proxysql_active_server_hostgroup_claims(protocol).empty(),
            "empty managed policy removes claims without a server LOAD");
        ok(manager->uninstall_server_discovery_controller(protocol), "controller shuts down cleanly");
    }
    return exit_status();
}
