/**
 * @file hgm_mapping_commit_sentinel_unit-t.cpp
 * @brief Reproduces the stale 'hostgroup_server_mapping' after read_only_action_v2()
 *   consumed the "runtime diverged from config" sentinel (CI cluster_sim_rds_bgd-g1 crash).
 *
 * Sequence (mirrors test_rds_bgd_remove_during_switchover-t):
 *   1. config: S writer in HG 10, replication pair (10,11); commit.
 *   2. read_only_action_v2(S, RO=1): S moved to reader HG 11, writer removed.
 *   3. read_only_action_v2({}) : any later monitor pass.
 *   4. commit the SAME config again: S restored in HG 10, HG 11 copy -> OFFLINE_HARD.
 *   5. read runtime mysql_servers (purges the OFFLINE_HARD HG 11 MySrvC).
 *   6. read_only_action_v2(S, RO=0): must find S as writer and do nothing.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Monitor.hpp"
#include "ProxySQL_Statistics.hpp"
#include "proxysql_admin.h"

#include <memory>
#include <string>

extern MySQL_HostGroups_Manager *MyHGM;
extern ProxySQL_Admin* GloAdmin;
extern ProxySQL_Statistics* GloProxyStats;
extern MySQL_Monitor* GloMyMon;

namespace {

std::unique_ptr<SQLite3_result> config_servers() {
	auto result = std::make_unique<SQLite3_result>(12);
	char hg[] = "10", host[] = "s.example", port[] = "3306", gtid[] = "0", status[] = "ONLINE",
		weight[] = "1", cmp[] = "0", maxc[] = "100", lag[] = "0", ssl[] = "0", lat[] = "0", cmt[] = "s";
	char* fields[] = {hg, host, port, gtid, status, weight, cmp, maxc, lag, ssl, lat, cmt};
	result->add_row(fields);
	return result;
}

std::unique_ptr<SQLite3_result> config_replication() {
	auto result = std::make_unique<SQLite3_result>(4);
	char w[] = "10", r[] = "11", check[] = "read_only", cmt[] = "";
	char* fields[] = {w, r, check, cmt};
	result->add_row(fields);
	return result;
}

bool install_config() {
	auto servers = config_servers();
	MyHGM->save_incoming_mysql_table(config_replication().release(), "mysql_replication_hostgroups");
	MyHGM->servers_add(servers.get());
	return MyHGM->commit({}, {}, false);
}

int count_rows(uint32_t hg, const char* host) {
	std::unique_ptr<SQLite3_result> rows(MyHGM->dump_table_mysql("mysql_servers"));
	int n = 0;
	for (const auto* row : rows->rows) {
		if (strtoul(row->fields[0], nullptr, 10) == hg && strcmp(row->fields[1], host) == 0 &&
			strcmp(row->fields[4], "ONLINE") == 0) n++;
	}
	return n;
}

} // namespace

int main() {
	plan(5);
	test_init_minimal();
	test_init_query_processor();
	test_init_hostgroups();
	char stats_memory_db[] = ":memory:";
	GloVars.statsdb_disk = stats_memory_db;
	GloProxyStats = new ProxySQL_Statistics();
	GloMyMon = new MySQL_Monitor();
	MyHGM->gtid_ev_loop = ev_loop_new(0);
	ev_async_init(MyHGM->gtid_ev_async, [](EV_P_ ev_async*, int) {});
	GloAdmin = new ProxySQL_Admin();

	ok(install_config() && count_rows(10, "s.example") == 1, "S starts as the only writer in HG 10");

	MyHGM->read_only_action_v2({{"s.example", 3306, 1}}, true);
	ok(count_rows(10, "s.example") == 0 && count_rows(11, "s.example") == 1,
		"read_only=1 moves S from writer HG 10 to reader HG 11");

	// any later monitor pass (empty result set) before the next commit
	MyHGM->read_only_action_v2({}, true);

	ok(install_config() && count_rows(10, "s.example") == 1,
		"re-installing the unchanged config restores S in HG 10");

	// count_rows() reads runtime mysql_servers, which purges the OFFLINE_HARD HG 11 copy

	MyHGM->read_only_action_v2({{"s.example", 3306, 0}}, true);
	ok(count_rows(10, "s.example") == 1,
		"read_only=0 on the restored writer is a no-op (no duplicate writer from a stale mapping)");
	ok(count_rows(11, "s.example") == 0, "S is not re-added to the reader hostgroup");
	return exit_status();
}
