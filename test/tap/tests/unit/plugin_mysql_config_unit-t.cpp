#include "ProxySQL_PluginConfig.h"
#include "MySQL_Authentication.hpp"
#include "MySQL_HostGroups_Manager.h"
#include "ProxySQL_Statistics.hpp"
#include "proxysql_admin.h"
#include "sqlite3db.h"
#include "tap.h"
#include "test_init.h"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

extern MySQL_Authentication* GloMyAuth;
extern MySQL_HostGroups_Manager* MyHGM;
extern ProxySQL_Statistics* GloProxyStats;

namespace {

constexpr const char* k_ledger =
	"CREATE TABLE proxysql_plugin_owned_objects (owner TEXT NOT NULL, object_type TEXT NOT NULL, "
	"object_key TEXT NOT NULL, generation INTEGER NOT NULL, PRIMARY KEY(owner,object_type,object_key))";
constexpr const char* k_generations =
	"CREATE TABLE proxysql_plugin_config_generations (owner TEXT PRIMARY KEY, generation INTEGER NOT NULL)";
constexpr const char* k_servers =
	"CREATE TABLE mysql_servers (hostgroup_id INT NOT NULL, hostname TEXT NOT NULL, port INT NOT NULL, "
	"gtid_port INT NOT NULL, status TEXT NOT NULL, weight INT NOT NULL, compression INT NOT NULL, "
	"max_connections INT NOT NULL, max_replication_lag INT NOT NULL, use_ssl INT NOT NULL, "
	"max_latency_ms INT NOT NULL, comment TEXT NOT NULL, PRIMARY KEY(hostgroup_id,hostname,port))";
constexpr const char* k_repl =
	"CREATE TABLE mysql_replication_hostgroups (writer_hostgroup INT PRIMARY KEY, reader_hostgroup INT UNIQUE, "
	"check_type TEXT NOT NULL, comment TEXT NOT NULL)";
constexpr const char* k_gr =
	"CREATE TABLE mysql_group_replication_hostgroups (writer_hostgroup INT PRIMARY KEY, backup_writer_hostgroup INT UNIQUE, "
	"reader_hostgroup INT UNIQUE, offline_hostgroup INT UNIQUE, active INT, max_writers INT, writer_is_also_reader INT, "
	"max_transactions_behind INT, comment TEXT)";
constexpr const char* k_attrs =
	"CREATE TABLE mysql_hostgroup_attributes (hostgroup_id INT PRIMARY KEY, max_num_online_servers INT, autocommit INT, "
	"free_connections_pct INT, init_connect TEXT, multiplex INT, connection_warming INT, throttle_connections_per_sec INT, "
	"ignore_session_variables TEXT, hostgroup_settings TEXT, servers_defaults TEXT, comment TEXT)";
constexpr const char* k_users =
	"CREATE TABLE mysql_users (username TEXT NOT NULL, password TEXT, active INT, use_ssl INT, default_hostgroup INT, "
	"default_schema TEXT, schema_locked INT, transaction_persistent INT, fast_forward INT, backend INT, frontend INT, "
	"max_connections INT, attributes TEXT, comment TEXT, PRIMARY KEY(username,backend), UNIQUE(username,frontend))";
constexpr const char* k_rules =
	"CREATE TABLE mysql_query_rules (rule_id INTEGER PRIMARY KEY, active INT, username TEXT, schemaname TEXT, flagIN INT, "
	"client_addr TEXT, proxy_addr TEXT, proxy_port INT, digest TEXT, match_digest TEXT, match_pattern TEXT, "
	"negate_match_pattern INT, re_modifiers TEXT, flagOUT INT, replace_pattern TEXT, destination_hostgroup INT, "
	"cache_ttl INT, cache_empty_result INT, cache_timeout INT, reconnect INT, timeout INT, retries INT, delay INT, "
	"next_query_flagIN INT, mirror_flagOUT INT, mirror_hostgroup INT, error_msg TEXT, OK_msg TEXT, sticky_conn INT, "
	"multiplex INT, gtid_from_hostgroup INT, log INT, apply INT, attributes TEXT NOT NULL DEFAULT '', comment TEXT)";
constexpr const char* k_globals =
	"CREATE TABLE global_variables (variable_name TEXT PRIMARY KEY, variable_value TEXT NOT NULL)";

long long scalar(SQLite3DB& db, const std::string& sql) {
	char* error = nullptr;
	int cols = 0;
	int affected = 0;
	SQLite3_result* result = nullptr;
	db.execute_statement(sql.c_str(), &error, &cols, &affected, &result);
	if (error != nullptr) {
		free(error);
		delete result;
		return -999999;
	}
	long long value = (result && !result->rows.empty() && result->rows[0]->fields[0])
		? std::strtoll(result->rows[0]->fields[0], nullptr, 10) : 0;
	delete result;
	return value;
}

std::string text_value(SQLite3DB& db, const std::string& sql) {
	char* error = nullptr;
	int cols = 0;
	int affected = 0;
	SQLite3_result* result = nullptr;
	db.execute_statement(sql.c_str(), &error, &cols, &affected, &result);
	std::string value;
	if (!error && result && !result->rows.empty() && result->rows[0]->fields[0]) value = result->rows[0]->fields[0];
	free(error);
	delete result;
	return value;
}

std::unique_ptr<SQLite3_result> result_value(SQLite3DB& db, const std::string& sql) {
	char* error = nullptr;
	int cols = 0;
	int affected = 0;
	SQLite3_result* result = nullptr;
	db.execute_statement(sql.c_str(), &error, &cols, &affected, &result);
	free(error);
	return std::unique_ptr<SQLite3_result>(result);
}

void create_schema(SQLite3DB& db, const char* prefix) {
	for (const char* ddl : {k_ledger, k_generations, k_servers, k_repl, k_gr, k_attrs, k_users, k_rules, k_globals}) {
		std::string sql(ddl);
		const size_t at = sql.find("TABLE ");
		sql.insert(at + 6, prefix);
		ok(db.execute(sql.c_str()), "fixture schema object is created in %s", *prefix ? "disk" : "main");
	}
}

struct Runtime {
	uint64_t servers {12};
	uint64_t users {12};
	uint64_t rules {12};
	uint64_t interfaces {12};
	uint64_t captured_servers {0};
	uint64_t captured_users {0};
	uint64_t captured_rules {0};
	uint64_t captured_interfaces {0};
	ProxySQL_PluginConfigStage fail {ProxySQL_PluginConfigStage::none};
	std::vector<std::string> trace;
	char* mutate_owner {nullptr};

	static bool lock(void* ptr, ProxySQL_PluginConfigLock which, std::string&) {
		auto& self = *static_cast<Runtime*>(ptr);
		self.trace.push_back("L" + std::to_string(static_cast<int>(which)));
		if (which == ProxySQL_PluginConfigLock::admin && self.mutate_owner) self.mutate_owner[0] = 'X';
		return true;
	}
	static void unlock(void* ptr, ProxySQL_PluginConfigLock which) {
		auto& self = *static_cast<Runtime*>(ptr);
		self.trace.push_back("U" + std::to_string(static_cast<int>(which)));
	}
	static bool capture(void* ptr, ProxySQL_PluginMysqlRuntimeSnapshot&, std::string&) {
		auto& self = *static_cast<Runtime*>(ptr);
		self.captured_servers = self.servers;
		self.captured_users = self.users;
		self.captured_rules = self.rules;
		self.captured_interfaces = self.interfaces;
		self.trace.push_back("snapshot");
		return true;
	}
	static bool publish(void* ptr, ProxySQL_PluginConfigStage stage, SQLite3DB&, uint64_t generation, std::string& error) {
		auto& self = *static_cast<Runtime*>(ptr);
		self.trace.push_back("P" + std::to_string(static_cast<int>(stage)));
		if (stage == ProxySQL_PluginConfigStage::servers) self.servers = generation;
		if (stage == ProxySQL_PluginConfigStage::users) self.users = generation;
		if (stage == ProxySQL_PluginConfigStage::rules) self.rules = generation;
		if (stage == ProxySQL_PluginConfigStage::interfaces) self.interfaces = generation;
		if (self.fail == stage) { error = "injected publication failure"; return false; }
		return true;
	}
	static void restore(void* ptr, ProxySQL_PluginConfigStage stage, const ProxySQL_PluginMysqlRuntimeSnapshot&) {
		auto& self = *static_cast<Runtime*>(ptr);
		self.trace.push_back("R" + std::to_string(static_cast<int>(stage)));
		if (stage == ProxySQL_PluginConfigStage::servers) self.servers = self.captured_servers;
		if (stage == ProxySQL_PluginConfigStage::users) self.users = self.captured_users;
		if (stage == ProxySQL_PluginConfigStage::rules) self.rules = self.captured_rules;
		if (stage == ProxySQL_PluginConfigStage::interfaces) self.interfaces = self.captured_interfaces;
	}
	static bool checkpoint(void* ptr, ProxySQL_PluginConfigStage stage, std::string& error) {
		auto& self = *static_cast<Runtime*>(ptr);
		self.trace.push_back("C" + std::to_string(static_cast<int>(stage)));
		if (self.fail == stage) { error = "injected checkpoint failure"; return false; }
		return true;
	}
	ProxySQL_PluginConfigRuntimeHooks hooks() {
		return {this, &lock, &unlock, &capture, &publish, &restore, &checkpoint};
	}
};

struct Fixture {
	SQLite3DB db;
	Runtime runtime;
	int hostgroups[2] {8100, 8101};
	ProxySQL_PluginMysqlServerRow servers[3] {
		{8100, "writer-new", 3306, 0, 0, 10, 0, 100, 0, true, 50, "mysql_router:writer"},
		{8101, "reader-a", 3306, 0, 0, 5, 0, 100, 0, true, 50, "mysql_router:reader"},
		{8101, "reader-b", 3307, 0, 0, 5, 0, 100, 0, true, 50, "mysql_router:reader"},
	};
	ProxySQL_PluginMysqlReplicationHostgroupRow repl[1] {{8100, 8101, "read_only", "mysql_router:repl"}};
	ProxySQL_PluginMysqlHostgroupAttributesRow attrs[2] {
		{8100, 10, -1, 10, "", true, false, 1000, "", "{}", "{}", "mysql_router:writer"},
		{8101, 10, -1, 10, "", true, false, 1000, "", "{}", "{}", "mysql_router:reader"},
	};
	ProxySQL_PluginMysqlUserRow users[3] {
		{"router_app", "new-secret", true, true, 8100, "appdb", false, true, false, true, true, 500, "{}", "mysql_router:managed"},
		{"router_meta", "must-not-win", true, true, 8100, "appdb", false, true, false, true, true, 100, "{}", "mysql_router:collision"},
		{"router_front", "must-not-win", true, true, 8100, "appdb", false, true, false, true, true, 100, "{}", "mysql_router:collision"},
	};
	ProxySQL_PluginMysqlRuleRow rules[2] {
		{9000, true, 6450, "^SELECT", nullptr, false, "CASELESS", 8101, true, "mysql_router:read"},
		{9001, true, 6446, nullptr, ".*", false, "CASELESS", 8100, true, "mysql_router:write"},
	};
	const char* interfaces[2] {"127.0.0.1:6446", "0.0.0.0:6447"};
	char owner[32] {"mysql_router"};
	ProxySQL_PluginMysqlConfigPlan plan {};

	Fixture() {
		db.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
		ok(db.execute("ATTACH DATABASE ':memory:' AS disk"), "fixture attaches persistent disk schema");
		create_schema(db, "");
		create_schema(db, "disk.");
		for (const char* schema : {"main", "disk"}) {
			std::string p(schema);
			ok(db.execute(("INSERT INTO " + p + ".mysql_servers VALUES "
				"(10,'operator-a',3306,0,'ONLINE',1,0,100,0,0,0,'operator'),"
				"(20,'operator-b',3306,0,'ONLINE',1,0,100,0,0,0,'operator'),"
				"(8100,'old-writer',3306,0,'ONLINE',1,0,100,0,0,0,'mysql_router:old'),"
				"(8101,'old-reader',3306,0,'ONLINE',1,0,100,0,0,0,'mysql_router:old')").c_str()),
				"server fixture is seeded in %s", schema);
			ok(db.execute(("INSERT INTO " + p + ".mysql_users VALUES "
				"('app','operator',1,0,10,'',0,1,0,1,1,100,'','operator'),"
				"('router_meta','operator',1,0,10,'',0,1,0,1,0,100,'','operator'),"
				"('router_front','operator',1,0,10,'',0,1,0,0,1,100,'','operator'),"
				"('old_owned','old',1,0,8100,'',0,1,0,1,1,100,'','mysql_router:old')").c_str()),
				"user fixture is seeded in %s", schema);
			ok(db.execute(("INSERT INTO " + p + ".mysql_query_rules(rule_id,active,proxy_port,destination_hostgroup,apply,attributes,comment) VALUES "
				"(5,1,6033,10,1,'','operator'),(9000,1,6450,8101,1,'','mysql_router:old'),"
				"(9001,1,6446,10,1,'','operator')").c_str()),
				"rule fixture is seeded in %s", schema);
			ok(db.execute(("INSERT INTO " + p + ".global_variables VALUES "
				"('mysql-interfaces','0.0.0.0:6033;127.0.0.1:6446;127.0.0.1:7000')").c_str()),
				"interface fixture is seeded in %s", schema);
			ok(db.execute(("INSERT INTO " + p + ".proxysql_plugin_owned_objects VALUES "
				"('mysql_router','hostgroup','8100',12),('mysql_router','hostgroup','8101',12),"
				"('mysql_router','mysql_user','old_owned',12),('mysql_router','mysql_query_rule','9000',12),"
				"('mysql_router','mysql_interface','127.0.0.1:6446',12)").c_str()),
				"ownership fixture is seeded in %s", schema);
			ok(db.execute(("INSERT INTO " + p + ".proxysql_plugin_config_generations VALUES ('mysql_router',12)").c_str()),
				"generation fixture is seeded in %s", schema);
		}
		plan = {owner, 13, hostgroups, 2, servers, 3, repl, 1, nullptr, 0, attrs, 2,
			users, 3, rules, 2, interfaces, 2};
	}
};

bool all_runtime_at(const Runtime& runtime, uint64_t generation) {
	return runtime.servers == generation && runtime.users == generation &&
		runtime.rules == generation && runtime.interfaces == generation;
}

bool rejected_without_lock(Fixture& f, const ProxySQL_PluginMysqlConfigPlan& plan) {
	f.runtime.trace.clear();
	const auto result = proxysql_apply_plugin_mysql_config(f.db, plan, f.runtime.hooks());
	return !result.applied && f.runtime.trace.empty() &&
		scalar(f.db, "SELECT generation FROM proxysql_plugin_config_generations WHERE owner='mysql_router'") == 12;
}

} // namespace

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(113);
	const bool globals_ready = test_init_minimal() == 0;

	Fixture f;
	f.runtime.mutate_owner = f.owner;
	const auto result = proxysql_apply_plugin_mysql_config(f.db, f.plan, f.runtime.hooks());
	ok(result.applied && result.generation == 13, "a complete scoped generation is applied");
	ok(std::strcmp(f.owner, "Xysql_router") == 0 && result.collisions.size() == 3,
		"the plan is deep-copied before locks and every collision is returned");
	ok(scalar(f.db, "SELECT COUNT(*) FROM mysql_servers WHERE hostgroup_id=8100") == 1 &&
		scalar(f.db, "SELECT COUNT(*) FROM mysql_servers WHERE hostgroup_id=8101") == 2,
		"owned hostgroups are replaced exactly");
	ok(scalar(f.db, "SELECT COUNT(*) FROM mysql_servers WHERE hostgroup_id IN (10,20)") == 2,
		"operator hostgroups are untouched");
	ok(text_value(f.db, "SELECT password FROM mysql_users WHERE username='app'") == "operator",
		"unrelated operator user survives");
	ok(text_value(f.db, "SELECT password FROM mysql_users WHERE username='router_meta'") == "operator" &&
		text_value(f.db, "SELECT password FROM mysql_users WHERE username='router_front'") == "operator",
		"both backend-key and frontend-key username collisions are preserved");
	ok(text_value(f.db, "SELECT password FROM mysql_users WHERE username='router_app'") == "new-secret" &&
		scalar(f.db, "SELECT COUNT(*) FROM mysql_users WHERE username='old_owned'") == 0,
		"owned users are inserted and obsolete owned users are deleted");
	ok(scalar(f.db, "SELECT COUNT(*) FROM mysql_query_rules WHERE rule_id=5") == 1 &&
		text_value(f.db, "SELECT comment FROM mysql_query_rules WHERE rule_id=9000") == "mysql_router:read" &&
		text_value(f.db, "SELECT comment FROM mysql_query_rules WHERE rule_id=9001") == "operator",
		"operator rules and collisions survive while owned rules are replaced");
	ok(text_value(f.db, "SELECT variable_value FROM global_variables WHERE variable_name='mysql-interfaces'") ==
		"0.0.0.0:6033;127.0.0.1:7000;127.0.0.1:6446;0.0.0.0:6447",
		"owned interfaces merge with operator interfaces and never replace 6033");
	ok(scalar(f.db, "SELECT generation FROM proxysql_plugin_config_generations WHERE owner='mysql_router'") == 13 &&
		scalar(f.db, "SELECT generation FROM disk.proxysql_plugin_config_generations WHERE owner='mysql_router'") == 13,
		"the complete generation is recorded in Admin and configdb");
	ok(scalar(f.db, "SELECT COUNT(*) FROM disk.mysql_servers WHERE hostgroup_id=8101") == 2 &&
		text_value(f.db, "SELECT password FROM disk.mysql_users WHERE username='router_meta'") == "operator",
		"disk receives the same scoped generation and preserves collisions");
	ok(all_runtime_at(f.runtime, 13), "every runtime module publishes the complete generation");
	const std::vector<std::string> expected_locks {"L1","L2","L3","L4","L5"};
	ok(f.runtime.trace.size() >= expected_locks.size() &&
		std::equal(expected_locks.begin(), expected_locks.end(), f.runtime.trace.begin()),
		"locks are acquired in Admin, HGM, Auth, QPro, MTH order");
	const std::vector<std::string> expected_unlocks {"U5","U4","U3","U2","U1"};
	ok(f.runtime.trace.size() >= expected_unlocks.size() &&
		std::equal(expected_unlocks.begin(), expected_unlocks.end(), f.runtime.trace.end() - expected_unlocks.size()),
		"locks are released in reverse MTH, QPro, Auth, HGM, Admin order");
	std::strcpy(f.owner, "mysql_router");
	f.runtime.mutate_owner = nullptr;

	for (ProxySQL_PluginConfigStage stage : {
		ProxySQL_PluginConfigStage::admin_staging,
		ProxySQL_PluginConfigStage::servers,
		ProxySQL_PluginConfigStage::users,
		ProxySQL_PluginConfigStage::rules,
		ProxySQL_PluginConfigStage::interfaces,
		ProxySQL_PluginConfigStage::commit}) {
		f.runtime.fail = stage;
		f.runtime.trace.clear();
		f.plan.generation = 14;
		const auto failed = proxysql_apply_plugin_mysql_config(f.db, f.plan, f.runtime.hooks());
		ok(!failed.applied, "failure after stage %d rejects the candidate generation", static_cast<int>(stage));
		ok(scalar(f.db, "SELECT generation FROM proxysql_plugin_config_generations WHERE owner='mysql_router'") == 13 &&
			scalar(f.db, "SELECT generation FROM disk.proxysql_plugin_config_generations WHERE owner='mysql_router'") == 13,
			"failure after stage %d restores the last complete Admin generation", static_cast<int>(stage));
		ok(all_runtime_at(f.runtime, 13),
			"failure after stage %d restores every runtime module", static_cast<int>(stage));
	}
	f.runtime.fail = ProxySQL_PluginConfigStage::none;

	Fixture v;
	ProxySQL_PluginMysqlConfigPlan bad = v.plan;
	bad.generation = 0;
	ok(rejected_without_lock(v, bad), "generation zero is rejected before locks");
	bad = v.plan; bad.generation = 12;
	ok(rejected_without_lock(v, bad), "a non-newer generation is rejected before locks");
	int duplicate_hgs[2] {8100, 8100};
	bad = v.plan; bad.owned_hostgroups = duplicate_hgs;
	ok(rejected_without_lock(v, bad), "duplicate owned hostgroups are rejected before locks");
	int out_of_range_hgs[2] {0, 8101};
	bad = v.plan; bad.owned_hostgroups = out_of_range_hgs;
	ok(rejected_without_lock(v, bad), "hostgroups outside 1..999999 are rejected before locks");
	ProxySQL_PluginMysqlServerRow outsider = v.servers[0]; outsider.hostgroup_id = 10;
	bad = v.plan; bad.servers = &outsider; bad.server_count = 1;
	ok(rejected_without_lock(v, bad), "servers outside the owned hostgroup set are rejected before locks");
	ProxySQL_PluginMysqlServerRow duplicate_servers[2] {v.servers[0], v.servers[0]};
	bad = v.plan; bad.servers = duplicate_servers; bad.server_count = 2;
	ok(rejected_without_lock(v, bad), "duplicate server keys are rejected before locks");
	ProxySQL_PluginMysqlUserRow duplicate_users[2] {v.users[0], v.users[0]};
	bad = v.plan; bad.users = duplicate_users; bad.user_count = 2;
	ok(rejected_without_lock(v, bad), "duplicate usernames are rejected before locks");
	ProxySQL_PluginMysqlRuleRow duplicate_rules[2] {v.rules[0], v.rules[0]};
	bad = v.plan; bad.rules = duplicate_rules;
	ok(rejected_without_lock(v, bad), "duplicate rule IDs are rejected before locks");
	ProxySQL_PluginMysqlRuleRow bad_tag = v.rules[0]; bad_tag.comment = "operator";
	bad = v.plan; bad.rules = &bad_tag; bad.rule_count = 1;
	ok(rejected_without_lock(v, bad), "rules without the exact owner prefix are rejected before locks");
	ProxySQL_PluginMysqlServerRow bad_port = v.servers[0]; bad_port.port = 0;
	bad = v.plan; bad.servers = &bad_port; bad.server_count = 1;
	ok(rejected_without_lock(v, bad), "server ports outside 1..65535 are rejected before locks");
	const char* reserved_interface[1] {"127.0.0.1:6032"};
	bad = v.plan; bad.interfaces = reserved_interface; bad.interface_count = 1;
	ok(rejected_without_lock(v, bad), "Admin port 6032 is rejected before locks");
	const char* default_interface[1] {"127.0.0.1:6033"};
	bad = v.plan; bad.interfaces = default_interface; bad.interface_count = 1;
	ok(rejected_without_lock(v, bad), "default MySQL port 6033 is rejected before locks");
	const char* invalid_interface[1] {"127.0.0.1:70000"};
	bad = v.plan; bad.interfaces = invalid_interface; bad.interface_count = 1;
	ok(rejected_without_lock(v, bad), "invalid interface ports are rejected before locks");
	ProxySQL_PluginMysqlReplicationHostgroupRow bad_mapping {8100, 10, "read_only", "mysql_router:bad"};
	bad = v.plan; bad.replication_hostgroups = &bad_mapping;
	ok(rejected_without_lock(v, bad), "hostgroup mappings cannot escape the owned set");
	bad = v.plan; bad.owner = "bad/owner";
	ok(rejected_without_lock(v, bad), "invalid owners are rejected before locks");

	const bool live_modules_ready = globals_ready && test_init_auth() == 0 &&
		test_init_hostgroups() == 0;
	ok(live_modules_ready, "real Auth and HGM modules initialize for live snapshot coverage");
	auto live_users = result_value(v.db,
		"SELECT username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,"
		"transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment "
		"FROM mysql_users ORDER BY username,backend DESC");
	auto live_servers = result_value(v.db,
		"SELECT hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,"
		"max_replication_lag,use_ssl,max_latency_ms,comment FROM mysql_servers "
		"ORDER BY hostgroup_id,hostname,port");
	GloMyAuth->save_mysql_users(std::move(live_users));
	MyHGM->wrlock();
	MyHGM->save_runtime_mysql_servers(live_servers.release());
	MyHGM->wrunlock();
	char statsdb_path[] = ":memory:";
	GloVars.statsdb_disk = statsdb_path;
	auto proxy_stats = std::make_unique<ProxySQL_Statistics>();
	GloProxyStats = proxy_stats.get();
	GloProxyStats->init();
	ProxySQL_Admin* admin = new ProxySQL_Admin(); // Process-scoped partial fixture; production teardown is unavailable here.
	auto users_one = std::unique_ptr<SQLite3_result>(admin->get_mysql_users_snapshot());
	auto users_two = std::unique_ptr<SQLite3_result>(admin->get_mysql_users_snapshot());
	ok(users_one && users_two && users_one->rows_count == 4 && users_one.get() != users_two.get() &&
		users_one.get() != GloMyAuth->get_current_mysql_users(),
		"live mysql_users snapshots are complete caller-owned copies");
	auto servers_one = std::unique_ptr<SQLite3_result>(admin->get_mysql_servers_snapshot());
	auto servers_two = std::unique_ptr<SQLite3_result>(admin->get_mysql_servers_snapshot());
	ok(servers_one && servers_two && servers_one->rows_count == 4 && servers_one.get() != servers_two.get() &&
		servers_one.get() != MyHGM->get_current_mysql_table("cluster_mysql_servers"),
		"live mysql_servers snapshots are complete caller-owned copies");
	auto gr_one = std::unique_ptr<SQLite3_result>(admin->get_mysql_group_replication_hostgroups_snapshot());
	auto gr_two = std::unique_ptr<SQLite3_result>(admin->get_mysql_group_replication_hostgroups_snapshot());
	ok(gr_one && gr_two && gr_one.get() != gr_two.get(),
		"live group-replication snapshots are caller-owned copies under the HGM lock");
	GloProxyStats = nullptr;

	return exit_status();
}
