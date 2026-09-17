#include "ProxySQL_PluginConfig.h"
#include "MySQL_Authentication.hpp"
#include "MySQL_Authentication_test.h"
#include "MySQL_HostGroups_Manager.h"
#include "MySQL_Monitor.hpp"
#include "MySQL_Query_Processor.h"
#include "MySQL_Thread.h"
#include "MySQL_Thread_test.h"
#include "ProxySQL_PluginConfig_test.h"
#include "ProxySQL_PluginSecrets.h"
#include "ProxySQL_Statistics.hpp"
#include "proxysql_admin.h"
#include "proxysql_utils.h"
#include "sqlite3db.h"
#include "tap.h"
#include "test_init.h"

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <netinet/in.h>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

extern MySQL_Authentication* GloMyAuth;
extern MySQL_HostGroups_Manager* MyHGM;
extern MySQL_Query_Processor* GloMyQPro;
extern MySQL_Monitor* GloMyMon;
extern ProxySQL_Statistics* GloProxyStats;
extern MySQL_Threads_Handler* GloMTH;

class TestDiskUpgrade {
public:
	static bool materialize_plugin_ownership_schema(SQLite3DB& db) {
		void* storage = calloc(1, sizeof(ProxySQL_Admin));
		auto* admin = reinterpret_cast<ProxySQL_Admin*>(storage);
		std::vector<table_def_t*> definitions;
		admin->insert_into_tables_defs(&definitions, "proxysql_plugin_owned_objects",
			PROXYSQL_PLUGIN_OWNED_OBJECTS_DDL);
		const bool materialized = admin->check_and_build_standard_tables(&db, &definitions);
		admin->drop_tables_defs(&definitions);
		free(storage);
		return materialized;
	}

	static bool materialize_plugin_secret_schema(SQLite3DB& db) {
		void* storage = calloc(1, sizeof(ProxySQL_Admin));
		auto* admin = reinterpret_cast<ProxySQL_Admin*>(storage);
		std::vector<table_def_t*> definitions;
		admin->insert_into_tables_defs(&definitions, "proxysql_plugin_secrets",
			proxysql_plugin_secrets_table_definition());
		const bool materialized = admin->check_and_build_standard_tables(&db, &definitions);
		admin->drop_tables_defs(&definitions);
		free(storage);
		return materialized;
	}

	static bool restore_plugin_config_runtime_state(SQLite3DB& db) {
		void* storage = calloc(1, sizeof(ProxySQL_Admin));
		auto* admin = reinterpret_cast<ProxySQL_Admin*>(storage);
		admin->admindb = &db;
		const bool restored = admin->restore_plugin_config_runtime_state();
		free(storage);
		return restored;
	}
};

namespace {

constexpr const char* k_ledger =
	"CREATE TABLE proxysql_plugin_owned_objects (owner TEXT NOT NULL, object_type TEXT NOT NULL, "
	"object_key TEXT NOT NULL, generation INTEGER NOT NULL, PRIMARY KEY(owner,object_type,object_key))";
constexpr const char* k_ledger_pre_round_2 =
	"CREATE TABLE IF NOT EXISTS proxysql_plugin_owned_objects ("
	"owner TEXT NOT NULL, object_type TEXT NOT NULL CHECK(object_type IN "
	"('hostgroup','mysql_user','mysql_query_rule','mysql_interface')), "
	"object_key TEXT NOT NULL, generation INTEGER NOT NULL, "
	"PRIMARY KEY(owner, object_type, object_key))";
constexpr const char* k_ledger_current =
	"CREATE TABLE IF NOT EXISTS proxysql_plugin_owned_objects ("
	"owner TEXT NOT NULL, object_type TEXT NOT NULL CHECK(object_type IN "
	"('hostgroup','mysql_user','mysql_user_v2','mysql_query_rule','mysql_interface')), "
	"object_key TEXT NOT NULL, generation INTEGER NOT NULL, "
	"PRIMARY KEY(owner, object_type, object_key))";
constexpr const char* k_ledger_backup_pre_round_2 =
	"CREATE TABLE IF NOT EXISTS proxysql_plugin_owned_objects_v1_migrate ("
	"owner TEXT NOT NULL, object_type TEXT NOT NULL CHECK(object_type IN "
	"('hostgroup','mysql_user','mysql_query_rule','mysql_interface')), "
	"object_key TEXT NOT NULL, generation INTEGER NOT NULL, "
	"PRIMARY KEY(owner, object_type, object_key))";
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
constexpr const char* k_fast_rules =
	"CREATE TABLE mysql_query_rules_fast_routing (username TEXT, schemaname TEXT, flagIN INT, "
	"destination_hostgroup INT, comment TEXT, PRIMARY KEY(username,schemaname,flagIN))";
constexpr const char* k_galera =
	"CREATE TABLE mysql_galera_hostgroups (writer_hostgroup INT, backup_writer_hostgroup INT, "
	"reader_hostgroup INT, offline_hostgroup INT, active INT, max_writers INT, "
	"writer_is_also_reader INT, max_transactions_behind INT, comment TEXT)";
constexpr const char* k_aurora =
	"CREATE TABLE mysql_aws_aurora_hostgroups (writer_hostgroup INT, reader_hostgroup INT, active INT, "
	"aurora_port INT, domain_name TEXT, max_lag_ms INT, check_interval_ms INT, check_timeout_ms INT, "
	"writer_is_also_reader INT, new_reader_weight INT, add_lag_ms INT, min_lag_ms INT, "
	"lag_num_checks INT, autopurge_missing_checks INT, comment TEXT)";
constexpr const char* k_rds =
	"CREATE TABLE mysql_aws_rds_bgd_hostgroups (writer_hostgroup INT, reader_hostgroup INT, "
	"green_writer_hostgroup INT, green_reader_hostgroup INT, active INT, writer_is_also_reader INT, "
	"check_interval_ms INT, check_timeout_ms INT, comment TEXT)";
constexpr const char* k_ssl_params =
	"CREATE TABLE mysql_servers_ssl_params (hostname TEXT, port INT, username TEXT, ssl_ca TEXT, "
	"ssl_cert TEXT, ssl_key TEXT, ssl_capath TEXT, ssl_crl TEXT, ssl_crlpath TEXT, ssl_cipher TEXT, "
	"tls_version TEXT, comment TEXT)";

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

bool table_schema_matches(SQLite3DB& db, const char* table_name, const char* ddl) {
	std::string canonical_ddl {ddl};
	const std::string if_not_exists {" IF NOT EXISTS"};
	const size_t modifier = canonical_ddl.find(if_not_exists);
	if (modifier != std::string::npos) canonical_ddl.erase(modifier, if_not_exists.size());
	sqlite3_stmt* statement = nullptr;
	if (sqlite3_prepare_v2(db.get_db(),
		"SELECT sql FROM sqlite_master WHERE type='table' AND name=?1",
		-1, &statement, nullptr) != SQLITE_OK) return false;
	sqlite3_bind_text(statement, 1, table_name, -1, SQLITE_STATIC);
	const bool found = sqlite3_step(statement) == SQLITE_ROW;
	const unsigned char* stored_ddl = found ? sqlite3_column_text(statement, 0) : nullptr;
	const bool matches = stored_ddl != nullptr &&
		canonical_ddl == reinterpret_cast<const char*>(stored_ddl);
	sqlite3_finalize(statement);
	return matches;
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

SQLite3_row* result_row(SQLite3_result* result, int column, const std::string& value) {
	if (result == nullptr || column < 0 || column >= result->columns) return nullptr;
	for (SQLite3_row* row : result->rows) {
		if (row != nullptr && row->fields[column] != nullptr && value == row->fields[column]) return row;
	}
	return nullptr;
}

void create_schema(SQLite3DB& db, const char* prefix) {
	for (const char* ddl : {k_ledger, k_generations, k_servers, k_repl, k_gr, k_attrs, k_users, k_rules, k_globals, k_fast_rules}) {
		std::string sql(ddl);
		const size_t at = sql.find("TABLE ");
		sql.insert(at + 6, prefix);
		ok(db.execute(sql.c_str()), "fixture schema object is created in %s", *prefix ? "disk" : "main");
	}
}

struct Runtime {
	enum class Mutation { none, newer_generation, late_collision };
	uint64_t servers {12};
	uint64_t users {12};
	uint64_t rules {12};
	uint64_t interfaces {12};
	uint64_t captured_servers {0};
	uint64_t captured_users {0};
	uint64_t captured_rules {0};
	uint64_t captured_interfaces {0};
	bool runtime_rule_present {true};
	bool captured_runtime_rule_present {false};
	std::string runtime_rule_attributes;
	std::string captured_runtime_rule_attributes;
	ProxySQL_PluginConfigStage fail {ProxySQL_PluginConfigStage::none};
	ProxySQL_PluginConfigLock throw_lock {static_cast<ProxySQL_PluginConfigLock>(0)};
	ProxySQL_PluginConfigLock throw_unlock {static_cast<ProxySQL_PluginConfigLock>(0)};
	ProxySQL_PluginConfigStage throw_publish {ProxySQL_PluginConfigStage::none};
	ProxySQL_PluginConfigStage throw_restore {ProxySQL_PluginConfigStage::none};
	std::vector<std::string> trace;
	char* mutate_owner {nullptr};
	SQLite3DB* db {nullptr};
	SQLite3DB* live_db {nullptr};
	Mutation mutation {Mutation::none};
	bool mutation_ok {true};

	void mutate_under_admin_lock() {
		if (db == nullptr || mutation == Mutation::none) return;
		for (const char* schema : {"main", "disk"}) {
			const std::string p(schema);
			if (mutation == Mutation::newer_generation) {
				mutation_ok = mutation_ok && db->execute(("INSERT INTO " + p + ".mysql_users VALUES "
					"('newer_owned','newer',1,0,8100,'',0,1,0,1,1,100,'{}','mysql_router:newer')").c_str());
				mutation_ok = mutation_ok && db->execute(("INSERT INTO " + p +
					".mysql_query_rules(rule_id,active,proxy_port,destination_hostgroup,apply,attributes,comment) "
					"VALUES (9010,1,6450,8101,1,'','mysql_router:newer')").c_str());
				mutation_ok = mutation_ok && db->execute(("UPDATE " + p + ".global_variables SET variable_value="
					"variable_value||';127.0.0.1:6550' WHERE variable_name='mysql-interfaces'").c_str());
				mutation_ok = mutation_ok && db->execute(("INSERT INTO " + p + ".proxysql_plugin_owned_objects VALUES "
					"('mysql_router','mysql_user','newer_owned',13),"
					"('mysql_router','mysql_query_rule','9010',13),"
					"('mysql_router','mysql_interface','127.0.0.1:6550',13)").c_str());
				mutation_ok = mutation_ok && db->execute(("UPDATE " + p +
					".proxysql_plugin_config_generations SET generation=13 WHERE owner='mysql_router'").c_str());
			} else {
				mutation_ok = mutation_ok && db->execute(("INSERT INTO " + p + ".mysql_users VALUES "
					"('late_user','operator-late',1,0,10,'',0,1,0,1,1,100,'{}','operator')").c_str());
			}
		}
		mutation = Mutation::none;
	}

	static bool lock(void* ptr, ProxySQL_PluginConfigLock which, std::string&) {
		auto& self = *static_cast<Runtime*>(ptr);
		self.trace.push_back("L" + std::to_string(static_cast<int>(which)));
		if (which == ProxySQL_PluginConfigLock::admin) {
			if (self.mutate_owner) self.mutate_owner[0] = 'X';
			self.mutate_under_admin_lock();
		}
		if (which == self.throw_lock) throw std::runtime_error("injected lock exception");
		return true;
	}
	static void unlock(void* ptr, ProxySQL_PluginConfigLock which) {
		auto& self = *static_cast<Runtime*>(ptr);
		self.trace.push_back("U" + std::to_string(static_cast<int>(which)));
		if (which == self.throw_unlock) throw std::runtime_error("injected unlock exception");
	}
	static bool capture(void* ptr, ProxySQL_PluginMysqlRuntimeSnapshot&, std::string&) {
		auto& self = *static_cast<Runtime*>(ptr);
		self.captured_servers = self.servers;
		self.captured_users = self.users;
		self.captured_rules = self.rules;
		self.captured_interfaces = self.interfaces;
		self.captured_runtime_rule_present = self.runtime_rule_present;
		self.captured_runtime_rule_attributes = self.runtime_rule_attributes;
		self.trace.push_back("snapshot");
		return true;
	}
	static bool publish(void* ptr, ProxySQL_PluginConfigStage stage, SQLite3DB& db, uint64_t generation, std::string& error) {
		auto& self = *static_cast<Runtime*>(ptr);
		self.trace.push_back("P" + std::to_string(static_cast<int>(stage)));
		if (stage == ProxySQL_PluginConfigStage::servers && self.live_db != nullptr) {
			char* sqlite_error = nullptr;
			const int rc = sqlite3_exec(self.live_db->get_db(),
				"INSERT INTO runtime_publications VALUES (1)", nullptr, nullptr, &sqlite_error);
			if (rc != SQLITE_OK) {
				error = sqlite_error != nullptr ? sqlite_error : sqlite3_errstr(rc);
				sqlite3_free(sqlite_error);
				return false;
			}
		}
		if (stage == self.throw_publish) throw std::runtime_error("injected publish exception");
		if (stage == ProxySQL_PluginConfigStage::servers) self.servers = generation;
		if (stage == ProxySQL_PluginConfigStage::users) self.users = generation;
		if (stage == ProxySQL_PluginConfigStage::rules) {
			self.rules = generation;
			self.runtime_rule_present = scalar(db,
				"SELECT COUNT(*) FROM main.mysql_query_rules WHERE rule_id=9000") == 1;
			self.runtime_rule_attributes = self.runtime_rule_present
				? text_value(db, "SELECT attributes FROM main.mysql_query_rules WHERE rule_id=9000")
				: std::string();
		}
		if (stage == ProxySQL_PluginConfigStage::interfaces) self.interfaces = generation;
		if (self.fail == stage) { error = "injected publication failure"; return false; }
		return true;
	}
	static bool restore(void* ptr, ProxySQL_PluginConfigStage stage,
		const ProxySQL_PluginMysqlRuntimeSnapshot&, std::string& error) {
		auto& self = *static_cast<Runtime*>(ptr);
		self.trace.push_back("R" + std::to_string(static_cast<int>(stage)));
		if (stage == self.throw_restore) throw std::runtime_error("injected restore exception");
		if (stage == ProxySQL_PluginConfigStage::servers) self.servers = self.captured_servers;
		if (stage == ProxySQL_PluginConfigStage::users) self.users = self.captured_users;
		if (stage == ProxySQL_PluginConfigStage::rules) {
			self.rules = self.captured_rules;
			self.runtime_rule_present = self.captured_runtime_rule_present;
			self.runtime_rule_attributes = self.captured_runtime_rule_attributes;
		}
		if (stage == ProxySQL_PluginConfigStage::interfaces) self.interfaces = self.captured_interfaces;
		if (stage == self.fail) {
			error = "injected restore failure";
			return false;
		}
		return true;
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
				"(5,1,6033,10,1,'{\"operator\":true}','operator'),(9000,1,6450,8101,1,'','mysql_router:old'),"
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
	const ProxySQL_PluginConfigStage saved_failure = f.runtime.fail;
	f.runtime.fail = ProxySQL_PluginConfigStage::admin_staging;
	const auto result = proxysql_apply_plugin_mysql_config(f.db, plan, f.runtime.hooks());
	f.runtime.fail = saved_failure;
	return !result.applied && f.runtime.trace.empty() &&
		scalar(f.db, "SELECT generation FROM proxysql_plugin_config_generations WHERE owner='mysql_router'") == 12;
}

bool rejected_v2_without_lock(Fixture& f, const ProxySQL_PluginMysqlConfigPlanV2& plan,
	const std::string& expected_message) {
	f.runtime.trace.clear();
	const std::string main_before = text_value(f.db,
		"SELECT group_concat(rule_id||'|'||attributes,';') FROM "
		"(SELECT rule_id,attributes FROM main.mysql_query_rules ORDER BY rule_id)");
	const std::string disk_before = text_value(f.db,
		"SELECT group_concat(rule_id||'|'||attributes,';') FROM "
		"(SELECT rule_id,attributes FROM disk.mysql_query_rules ORDER BY rule_id)");
	const bool runtime_present_before = f.runtime.runtime_rule_present;
	const std::string runtime_attributes_before = f.runtime.runtime_rule_attributes;
	const auto result = proxysql_apply_plugin_mysql_config_v2(f.db, plan, f.runtime.hooks());
	return !result.applied && result.message == expected_message && f.runtime.trace.empty() &&
		text_value(f.db,
			"SELECT group_concat(rule_id||'|'||attributes,';') FROM "
			"(SELECT rule_id,attributes FROM main.mysql_query_rules ORDER BY rule_id)") == main_before &&
		text_value(f.db,
			"SELECT group_concat(rule_id||'|'||attributes,';') FROM "
			"(SELECT rule_id,attributes FROM disk.mysql_query_rules ORDER BY rule_id)") == disk_before &&
		f.runtime.runtime_rule_present == runtime_present_before &&
		f.runtime.runtime_rule_attributes == runtime_attributes_before &&
		scalar(f.db, "SELECT generation FROM main.proxysql_plugin_config_generations "
			"WHERE owner='mysql_router'") == 12 &&
		scalar(f.db, "SELECT generation FROM disk.proxysql_plugin_config_generations "
			"WHERE owner='mysql_router'") == 12;
}

bool has_collision(const ProxySQL_PluginMysqlConfigResult& result, const std::string& collision) {
	return std::find(result.collisions.begin(), result.collisions.end(), collision) != result.collisions.end();
}

int deny_mysql_interfaces_read(void*, int action, const char* table, const char* column,
	const char*, const char*) {
	if (action == SQLITE_READ && table != nullptr && column != nullptr &&
		std::strcmp(table, "global_variables") == 0 &&
		std::strcmp(column, "variable_value") == 0) {
		return SQLITE_DENY;
	}
	return SQLITE_OK;
}

int reject_one_commit(void* opaque) {
	auto& reject = *static_cast<bool*>(opaque);
	if (!reject) return 0;
	reject = false;
	return 1;
}

struct LiveTransactionFailure {
	int commit_attempts {0};
	int rollback_attempts {0};
	bool persistent_rollback_failure {false};

	static proxysql_plugin_config_test::sql_action control(void* opaque, const char* sql) {
		auto* self = static_cast<LiveTransactionFailure*>(opaque);
		if (strcmp(sql, "COMMIT") == 0 && self->commit_attempts++ == 0) {
			return proxysql_plugin_config_test::sql_action::fail;
		}
		if (strcmp(sql, "ROLLBACK") == 0) {
			const int attempt = self->rollback_attempts++;
			if (attempt == 0 || self->persistent_rollback_failure) {
				return proxysql_plugin_config_test::sql_action::fail;
			}
		}
		return proxysql_plugin_config_test::sql_action::normal;
	}
};

void throw_before_plan_copy(void*) {
	throw std::runtime_error("private allocation detail must not cross the service boundary");
}

int reserve_loopback_port(int& port) {
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return -1;
	sockaddr_in address {};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = 0;
	if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
		close(fd);
		return -1;
	}
	socklen_t length = sizeof(address);
	if (getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) != 0) {
		close(fd);
		return -1;
	}
	port = ntohs(address.sin_port);
	return fd;
}

bool can_connect_loopback(int port) {
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return false;
	sockaddr_in address {};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = htons(port);
	const bool connected = connect(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0;
	close(fd);
	return connected;
}

void live_gtid_async_noop(struct ev_loop*, struct ev_async*, int) {}

struct AuthPublishBarrier {
	std::atomic<bool> reached {false};
	std::atomic<bool> frontend_attempting {false};
	std::atomic<bool> backend_attempting {false};
};

void auth_publish_barrier(void* opaque) {
	auto& barrier = *static_cast<AuthPublishBarrier*>(opaque);
	barrier.reached.store(true, std::memory_order_release);
	while (!barrier.frontend_attempting.load(std::memory_order_acquire) ||
		!barrier.backend_attempting.load(std::memory_order_acquire)) {
		std::this_thread::yield();
	}
}

struct AuthMidpointThrowOnce {
	int calls {0};

	static void hook(void* opaque) {
		auto& self = *static_cast<AuthMidpointThrowOnce*>(opaque);
		if (self.calls++ == 0) {
			throw std::runtime_error("injected Auth midpoint exception");
		}
	}
};

struct InterfaceRecoveryFailure {
	std::string old_interface;
	int rejected_commits {1};
	int old_add_failures {1};
	int old_add_attempts {0};

	static bool fail_add(void* opaque, const char* iface) {
		auto& self = *static_cast<InterfaceRecoveryFailure*>(opaque);
		if (self.old_interface != iface) return false;
		++self.old_add_attempts;
		if (self.old_add_failures < 0) return true;
		if (self.old_add_failures == 0) return false;
		--self.old_add_failures;
		return true;
	}

	static bool reject_commit(void* opaque) {
		auto& self = *static_cast<InterfaceRecoveryFailure*>(opaque);
		if (self.rejected_commits == 0) return false;
		--self.rejected_commits;
		return true;
	}
};

} // namespace

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(NO_PLAN);
	const bool globals_ready = test_init_minimal() == 0;
	SQLite3DB ownership_schema;
	ownership_schema.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	ok(ownership_schema.execute("ATTACH DATABASE ':memory:' AS disk") &&
		proxysql_ensure_plugin_mysql_config_schema(ownership_schema, "main") &&
		proxysql_ensure_plugin_mysql_config_schema(ownership_schema, "disk"),
		"the ownership schema is created in main and disk");
	ok(ownership_schema.execute("INSERT INTO main.proxysql_plugin_owned_objects VALUES "
		"('mysql_router','mysql_user_v2','v2:1:0:41',1)") &&
		ownership_schema.execute("INSERT INTO disk.proxysql_plugin_owned_objects VALUES "
			"('mysql_router','mysql_user_v2','v2:1:0:41',1)"),
		"the ownership schema accepts discriminated exact user keys in main and disk");

	SQLite3DB secret_schema;
	secret_schema.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	const bool secret_seeded = secret_schema.execute(proxysql_plugin_secrets_table_definition()) &&
		secret_schema.execute("INSERT INTO proxysql_plugin_secrets VALUES "
			"('mysql_router','metadata-topology',X'000000000000000000000000',X'01',"
			"X'00000000000000000000000000000000',1)");
	const bool secret_materialized = TestDiskUpgrade::materialize_plugin_secret_schema(secret_schema);
	const bool secret_materialized_again = TestDiskUpgrade::materialize_plugin_secret_schema(secret_schema);
	ok(secret_seeded && secret_materialized && secret_materialized_again &&
		scalar(secret_schema, "SELECT COUNT(*) FROM proxysql_plugin_secrets "
			"WHERE owner='mysql_router' AND secret_name='metadata-topology'") == 1,
		"production schema materialization preserves encrypted plugin credentials across restarts");

	Fixture attached_runtime;
	SQLite3DB live_runtime;
	char live_runtime_uri[] = "file:plugin_config_live_runtime?mode=memory&cache=shared";
	live_runtime.open(live_runtime_uri,
		SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI | SQLITE_OPEN_SHAREDCACHE);
	const bool attached_runtime_ready = live_runtime.execute(
		"CREATE TABLE runtime_publications (generation INTEGER NOT NULL)") &&
		attached_runtime.db.execute(
			"ATTACH DATABASE 'file:plugin_config_live_runtime?mode=memory&cache=shared' AS myhgm");
	attached_runtime.runtime.live_db = &live_runtime;
	const auto attached_runtime_result = proxysql_apply_plugin_mysql_config(
		attached_runtime.db, attached_runtime.plan, attached_runtime.runtime.hooks());
	ok(attached_runtime_ready && attached_runtime_result.applied &&
		scalar(live_runtime, "SELECT COUNT(*) FROM runtime_publications") == 1 &&
		scalar(attached_runtime.db,
			"SELECT COUNT(*) FROM myhgm.runtime_publications") == 1 &&
		scalar(attached_runtime.db, "SELECT generation FROM proxysql_plugin_config_generations "
			"WHERE owner='mysql_router'") == 13 &&
		scalar(attached_runtime.db, "SELECT generation FROM disk.proxysql_plugin_config_generations "
			"WHERE owner='mysql_router'") == 13,
		"publication updates a separately connected runtime database attached to Admin in DEBUG");

	SQLite3DB upgraded_admin;
	SQLite3DB upgraded_config;
	upgraded_admin.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	char upgrade_config_uri[] = "file:plugin_owned_upgrade?mode=memory&cache=shared";
	upgraded_config.open(upgrade_config_uri,
		SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI | SQLITE_OPEN_SHAREDCACHE);
	create_schema(upgraded_admin, "");
	create_schema(upgraded_config, "");
	bool old_schemas_seeded = true;
	for (SQLite3DB* db : {&upgraded_admin, &upgraded_config}) {
		old_schemas_seeded = old_schemas_seeded &&
			db->execute("DROP TABLE proxysql_plugin_owned_objects") &&
			db->execute(k_ledger_pre_round_2) &&
			db->execute("INSERT INTO mysql_users VALUES "
				"('A','operator-a',1,0,10,'',0,1,0,1,0,100,'{}','operator'),"
				"('legacy_user','legacy',1,0,8100,'',0,1,0,1,1,100,'{}','mysql_router:legacy'),"
				"('round1','round1',1,0,8100,'',0,1,0,1,1,100,'{}','mysql_router:round1')") &&
			db->execute("INSERT INTO proxysql_plugin_owned_objects VALUES "
				"('mysql_router','hostgroup','8100',12),"
				"('mysql_router','mysql_user','legacy_user',12),"
				"('mysql_router','mysql_user','v2:1:1:726F756E6431',12),"
				"('mysql_router','mysql_query_rule','9000',12),"
				"('mysql_router','mysql_interface','127.0.0.1:6446',12)") &&
			db->execute("INSERT INTO proxysql_plugin_config_generations VALUES ('mysql_router',12)") &&
			db->execute("INSERT INTO global_variables VALUES "
				"('mysql-interfaces','127.0.0.1:6446')");
	}
	ok(old_schemas_seeded &&
		scalar(upgraded_admin, "SELECT COUNT(*) FROM proxysql_plugin_owned_objects") == 5 &&
		scalar(upgraded_config, "SELECT COUNT(*) FROM proxysql_plugin_owned_objects") == 5,
		"pre-round-2 Admin and config schemas contain complete representative ownership ledgers");
	const bool admin_schema_materialized =
		TestDiskUpgrade::materialize_plugin_ownership_schema(upgraded_admin);
	const bool config_schema_materialized =
		TestDiskUpgrade::materialize_plugin_ownership_schema(upgraded_config);
	const bool admin_schema_materialized_again =
		TestDiskUpgrade::materialize_plugin_ownership_schema(upgraded_admin);
	const bool config_schema_materialized_again =
		TestDiskUpgrade::materialize_plugin_ownership_schema(upgraded_config);
	const bool admin_exact_type_accepted = upgraded_admin.execute(
		"INSERT INTO proxysql_plugin_owned_objects VALUES "
		"('other_plugin','mysql_user_v2','v2:0:1:42',12)");
	const bool config_exact_type_accepted = upgraded_config.execute(
		"INSERT INTO proxysql_plugin_owned_objects VALUES "
		"('other_plugin','mysql_user_v2','v2:0:1:42',12)");
	ok(admin_schema_materialized && config_schema_materialized &&
		admin_schema_materialized_again && config_schema_materialized_again &&
		admin_exact_type_accepted && config_exact_type_accepted &&
		table_schema_matches(upgraded_admin,
			"proxysql_plugin_owned_objects", k_ledger_current) &&
		table_schema_matches(upgraded_config,
			"proxysql_plugin_owned_objects", k_ledger_current) &&
		scalar(upgraded_admin, "SELECT COUNT(*) FROM proxysql_plugin_owned_objects") == 6 &&
		scalar(upgraded_config, "SELECT COUNT(*) FROM proxysql_plugin_owned_objects") == 6,
		"production materialization preserves every ledger row and enables exact ownership in both tiers");

	SQLite3DB absent_ownership_schema;
	absent_ownership_schema.open(
		const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	const bool absent_materialized =
		TestDiskUpgrade::materialize_plugin_ownership_schema(absent_ownership_schema);
	ok(absent_materialized && table_schema_matches(absent_ownership_schema,
			"proxysql_plugin_owned_objects", k_ledger_current) &&
		scalar(absent_ownership_schema,
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
			"AND name='proxysql_plugin_owned_objects_v1_migrate'") == 0,
		"production materialization creates and verifies an absent ownership table");

	SQLite3DB current_with_stale_backup;
	current_with_stale_backup.open(
		const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	const bool current_stale_seeded = current_with_stale_backup.execute(k_ledger_current) &&
		current_with_stale_backup.execute(k_ledger_backup_pre_round_2) &&
		current_with_stale_backup.execute("INSERT INTO proxysql_plugin_owned_objects VALUES "
			"('mysql_router','mysql_user_v2','v2:1:0:63757272656E74',21)") &&
		current_with_stale_backup.execute("INSERT INTO proxysql_plugin_owned_objects_v1_migrate VALUES "
			"('mysql_router','mysql_user','stale_backup',20)");
	const bool current_stale_materialized =
		TestDiskUpgrade::materialize_plugin_ownership_schema(current_with_stale_backup);
	ok(current_stale_seeded && !current_stale_materialized &&
		table_schema_matches(current_with_stale_backup,
			"proxysql_plugin_owned_objects", k_ledger_current) &&
		table_schema_matches(current_with_stale_backup,
			"proxysql_plugin_owned_objects_v1_migrate", k_ledger_backup_pre_round_2) &&
		text_value(current_with_stale_backup,
			"SELECT owner||'|'||object_type||'|'||object_key||'|'||generation "
			"FROM proxysql_plugin_owned_objects") ==
				"mysql_router|mysql_user_v2|v2:1:0:63757272656E74|21" &&
		text_value(current_with_stale_backup,
			"SELECT owner||'|'||object_type||'|'||object_key||'|'||generation "
			"FROM proxysql_plugin_owned_objects_v1_migrate") ==
				"mysql_router|mysql_user|stale_backup|20",
		"a current target with a stale migration table fails unchanged");

	SQLite3DB absent_with_stale_backup;
	absent_with_stale_backup.open(
		const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	const bool absent_stale_seeded = absent_with_stale_backup.execute(k_ledger_backup_pre_round_2) &&
		absent_with_stale_backup.execute("INSERT INTO proxysql_plugin_owned_objects_v1_migrate VALUES "
			"('mysql_router','mysql_user','stale_only',22)");
	const bool absent_stale_materialized =
		TestDiskUpgrade::materialize_plugin_ownership_schema(absent_with_stale_backup);
	ok(absent_stale_seeded && !absent_stale_materialized &&
		scalar(absent_with_stale_backup,
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
			"AND name='proxysql_plugin_owned_objects'") == 0 &&
		table_schema_matches(absent_with_stale_backup,
			"proxysql_plugin_owned_objects_v1_migrate", k_ledger_backup_pre_round_2) &&
		text_value(absent_with_stale_backup,
			"SELECT owner||'|'||object_type||'|'||object_key||'|'||generation "
			"FROM proxysql_plugin_owned_objects_v1_migrate") ==
				"mysql_router|mysql_user|stale_only|22",
		"an absent target with a stale migration table fails without creating the target");

	SQLite3DB legacy_with_stale_backup;
	legacy_with_stale_backup.open(
		const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	const bool legacy_stale_seeded = legacy_with_stale_backup.execute(k_ledger_pre_round_2) &&
		legacy_with_stale_backup.execute(k_ledger_backup_pre_round_2) &&
		legacy_with_stale_backup.execute("INSERT INTO proxysql_plugin_owned_objects VALUES "
			"('mysql_router','mysql_user','legacy_target',23)") &&
		legacy_with_stale_backup.execute("INSERT INTO proxysql_plugin_owned_objects_v1_migrate VALUES "
			"('mysql_router','mysql_user','legacy_backup',22)");
	const bool legacy_stale_materialized =
		TestDiskUpgrade::materialize_plugin_ownership_schema(legacy_with_stale_backup);
	ok(legacy_stale_seeded && !legacy_stale_materialized &&
		table_schema_matches(legacy_with_stale_backup,
			"proxysql_plugin_owned_objects", k_ledger_pre_round_2) &&
		table_schema_matches(legacy_with_stale_backup,
			"proxysql_plugin_owned_objects_v1_migrate", k_ledger_backup_pre_round_2) &&
		text_value(legacy_with_stale_backup,
			"SELECT owner||'|'||object_type||'|'||object_key||'|'||generation "
			"FROM proxysql_plugin_owned_objects") ==
				"mysql_router|mysql_user|legacy_target|23" &&
		text_value(legacy_with_stale_backup,
			"SELECT owner||'|'||object_type||'|'||object_key||'|'||generation "
			"FROM proxysql_plugin_owned_objects_v1_migrate") ==
				"mysql_router|mysql_user|legacy_backup|22",
		"a V1 target with a stale migration table fails unchanged");

	SQLite3DB legacy_in_transaction;
	legacy_in_transaction.open(
		const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	const bool transaction_seeded = legacy_in_transaction.execute(k_ledger_pre_round_2) &&
		legacy_in_transaction.execute("INSERT INTO proxysql_plugin_owned_objects VALUES "
			"('mysql_router','mysql_user','transaction_target',24)") &&
		legacy_in_transaction.execute("BEGIN IMMEDIATE");
	const bool transaction_materialized =
		TestDiskUpgrade::materialize_plugin_ownership_schema(legacy_in_transaction);
	const bool transaction_unchanged = transaction_seeded && !transaction_materialized &&
		sqlite3_get_autocommit(legacy_in_transaction.get_db()) == 0 &&
		table_schema_matches(legacy_in_transaction,
			"proxysql_plugin_owned_objects", k_ledger_pre_round_2) &&
		text_value(legacy_in_transaction,
			"SELECT owner||'|'||object_type||'|'||object_key||'|'||generation "
			"FROM proxysql_plugin_owned_objects") ==
				"mysql_router|mysql_user|transaction_target|24" &&
		scalar(legacy_in_transaction,
			"SELECT COUNT(*) FROM sqlite_master WHERE type='table' "
			"AND name='proxysql_plugin_owned_objects_v1_migrate'") == 0;
	ok(transaction_unchanged,
		"a V1 target inside an existing transaction fails intact without creating a backup");
	if (sqlite3_get_autocommit(legacy_in_transaction.get_db()) == 0) {
		legacy_in_transaction.execute("ROLLBACK");
	}

	SQLite3DB unknown_ownership_schema;
	unknown_ownership_schema.open(
		const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	const bool unknown_seeded = unknown_ownership_schema.execute(k_ledger) &&
		unknown_ownership_schema.execute("INSERT INTO proxysql_plugin_owned_objects VALUES "
			"('mysql_router','mysql_user','operator_owned',12)");
	const bool unknown_materialized =
		TestDiskUpgrade::materialize_plugin_ownership_schema(unknown_ownership_schema);
	ok(unknown_seeded && !unknown_materialized &&
		scalar(unknown_ownership_schema, "SELECT COUNT(*) FROM proxysql_plugin_owned_objects") == 1 &&
		unknown_ownership_schema.check_table_structure(
			"proxysql_plugin_owned_objects", k_ledger) == 1,
		"an unknown ownership schema fails closed without destructive generic rebuilding");

	SQLite3DB restored_plugin_state;
	restored_plugin_state.open(
		const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	const bool restore_seeded = restored_plugin_state.execute(k_ledger_current) &&
		restored_plugin_state.execute(k_generations) &&
		restored_plugin_state.execute("ATTACH DATABASE ':memory:' AS disk") &&
		restored_plugin_state.execute((std::string(k_ledger_current).replace(
			std::string(k_ledger_current).find("proxysql_plugin_owned_objects"),
			strlen("proxysql_plugin_owned_objects"), "disk.proxysql_plugin_owned_objects")).c_str()) &&
		restored_plugin_state.execute("CREATE TABLE disk.proxysql_plugin_config_generations "
			"(owner TEXT PRIMARY KEY, generation INTEGER NOT NULL)") &&
		restored_plugin_state.execute("INSERT INTO main.proxysql_plugin_owned_objects VALUES "
			"('stale','hostgroup','1',1)") &&
		restored_plugin_state.execute("INSERT INTO main.proxysql_plugin_config_generations VALUES "
			"('stale',1)") &&
		restored_plugin_state.execute("INSERT INTO disk.proxysql_plugin_owned_objects VALUES "
			"('mysql_router','hostgroup','8100',12),"
			"('other_plugin','mysql_query_rule','77',8)") &&
		restored_plugin_state.execute("INSERT INTO disk.proxysql_plugin_config_generations VALUES "
			"('mysql_router',12),('other_plugin',8)");
	const bool state_restored = restore_seeded &&
		TestDiskUpgrade::restore_plugin_config_runtime_state(restored_plugin_state);
	const bool state_restored_again = state_restored &&
		TestDiskUpgrade::restore_plugin_config_runtime_state(restored_plugin_state);
	ok(state_restored_again &&
		text_value(restored_plugin_state,
			"SELECT group_concat(value,';') FROM (SELECT owner||'|'||object_type||'|'||object_key||'|'||generation value "
			"FROM main.proxysql_plugin_owned_objects ORDER BY owner,object_type,object_key)") ==
		text_value(restored_plugin_state,
			"SELECT group_concat(value,';') FROM (SELECT owner||'|'||object_type||'|'||object_key||'|'||generation value "
			"FROM disk.proxysql_plugin_owned_objects ORDER BY owner,object_type,object_key)") &&
		text_value(restored_plugin_state,
			"SELECT group_concat(value,';') FROM (SELECT owner||'|'||generation value "
			"FROM main.proxysql_plugin_config_generations ORDER BY owner)") ==
		text_value(restored_plugin_state,
			"SELECT group_concat(value,';') FROM (SELECT owner||'|'||generation value "
			"FROM disk.proxysql_plugin_config_generations ORDER BY owner)"),
		"startup restores the exact persistent plugin ownership and generation state idempotently");
	ok(upgraded_admin.execute((std::string("ATTACH DATABASE '") + upgrade_config_uri + "' AS disk").c_str()),
		"the upgraded persistent config tier attaches as disk for publication");
	char upgrade_owner[] = "mysql_router";
	ProxySQL_PluginMysqlConfigPlan upgrade_plan {};
	upgrade_plan.owner = upgrade_owner;
	upgrade_plan.generation = 13;
	Runtime upgrade_runtime;
	const auto upgraded_publication = proxysql_apply_plugin_mysql_config(
		upgraded_admin, upgrade_plan, upgrade_runtime.hooks());
	ok(upgraded_publication.applied && all_runtime_at(upgrade_runtime, 13) &&
		text_value(upgraded_admin,
			"SELECT password FROM main.mysql_users WHERE username='A'") == "operator-a" &&
		text_value(upgraded_admin,
			"SELECT password FROM disk.mysql_users WHERE username='A'") == "operator-a" &&
		scalar(upgraded_admin,
			"SELECT COUNT(*) FROM main.mysql_users WHERE username IN ('legacy_user','round1')") == 0 &&
		scalar(upgraded_admin,
			"SELECT COUNT(*) FROM disk.mysql_users WHERE username IN ('legacy_user','round1')") == 0 &&
		scalar(upgraded_admin,
			"SELECT COUNT(*) FROM main.proxysql_plugin_owned_objects WHERE owner='other_plugin'") == 1 &&
		scalar(upgraded_admin,
			"SELECT COUNT(*) FROM disk.proxysql_plugin_owned_objects WHERE owner='other_plugin'") == 1,
		"publication migrates marker-proven ownership and preserves operator rows after schema upgrade");

	Fixture v2_validation;
	ProxySQL_PluginMysqlRuleAttributesRow valid_v2_attribute {
		9000, "{\"switch_to_fast_forward\":true}"
	};
	ProxySQL_PluginMysqlConfigPlanV2 valid_v2_plan {
		v2_validation.plan, &valid_v2_attribute, 1
	};
	ProxySQL_PluginMysqlConfigPlanV2 null_v2_array {v2_validation.plan, nullptr, 1};
	ok(rejected_v2_without_lock(v2_validation, null_v2_array,
		"rule_attributes is null while its count is non-zero"),
		"a null V2 attributes array is rejected before locking without changing any tier");
	ProxySQL_PluginMysqlRuleAttributesRow duplicate_v2_attributes[] {
		{9000, "{}"}, {9000, "{\"switch_to_fast_forward\":true}"}
	};
	ProxySQL_PluginMysqlConfigPlanV2 duplicate_v2_plan {
		v2_validation.plan, duplicate_v2_attributes, 2
	};
	ok(rejected_v2_without_lock(v2_validation, duplicate_v2_plan,
		"duplicate mysql query rule attributes for rule_id: 9000"),
		"duplicate V2 rule attributes are rejected before locking without changing any tier");
	ProxySQL_PluginMysqlRuleAttributesRow unknown_v2_attribute {9009, "{}"};
	ProxySQL_PluginMysqlConfigPlanV2 unknown_v2_plan {
		v2_validation.plan, &unknown_v2_attribute, 1
	};
	ok(rejected_v2_without_lock(v2_validation, unknown_v2_plan,
		"mysql query rule attributes reference an unknown rule_id: 9009"),
		"unknown V2 rule IDs are rejected before locking without changing any tier");
	ProxySQL_PluginMysqlRuleAttributesRow null_v2_attribute {9000, nullptr};
	ProxySQL_PluginMysqlConfigPlanV2 null_v2_value_plan {
		v2_validation.plan, &null_v2_attribute, 1
	};
	ok(rejected_v2_without_lock(v2_validation, null_v2_value_plan,
		"mysql query rule attributes must be a JSON object for rule_id: 9000"),
		"a null V2 rule value is rejected before locking without changing any tier");
	for (const auto& invalid : std::vector<std::pair<const char*, const char*>> {
		{"{", "malformed JSON"}, {"[]", "a JSON array"}, {"true", "a JSON scalar"}}) {
		ProxySQL_PluginMysqlRuleAttributesRow invalid_attribute {9000, invalid.first};
		ProxySQL_PluginMysqlConfigPlanV2 invalid_plan {
			v2_validation.plan, &invalid_attribute, 1
		};
		ok(rejected_v2_without_lock(v2_validation, invalid_plan,
			"mysql query rule attributes must be a JSON object for rule_id: 9000"),
			"%s is rejected before locking without changing any tier", invalid.second);
	}

	Fixture v2;
	ProxySQL_PluginMysqlRuleAttributesRow v2_attribute {
		9000, "{\"switch_to_fast_forward\":true}"
	};
	ProxySQL_PluginMysqlConfigPlanV2 v2_plan {v2.plan, &v2_attribute, 1};
	const auto v2_generation_one = proxysql_apply_plugin_mysql_config_v2(
		v2.db, v2_plan, v2.runtime.hooks());
	ok(v2_generation_one.applied && v2_generation_one.generation == 13 &&
		text_value(v2.db, "SELECT attributes FROM main.mysql_query_rules WHERE rule_id=9000") ==
			"{\"switch_to_fast_forward\":true}" &&
		text_value(v2.db, "SELECT attributes FROM disk.mysql_query_rules WHERE rule_id=9000") ==
			"{\"switch_to_fast_forward\":true}" &&
		v2.runtime.runtime_rule_present &&
		v2.runtime.runtime_rule_attributes == "{\"switch_to_fast_forward\":true}",
		"V2 generation 1 publishes the exact rule attributes to main, disk, and runtime");
	v2.plan.generation = 14;
	v2_attribute.attributes = "{}";
	v2_plan.base = v2.plan;
	const auto v2_generation_two = proxysql_apply_plugin_mysql_config_v2(
		v2.db, v2_plan, v2.runtime.hooks());
	ok(v2_generation_two.applied && v2_generation_two.generation == 14 &&
		text_value(v2.db, "SELECT attributes FROM main.mysql_query_rules WHERE rule_id=9000") == "{}" &&
		text_value(v2.db, "SELECT attributes FROM disk.mysql_query_rules WHERE rule_id=9000") == "{}" &&
		v2.runtime.runtime_rule_present && v2.runtime.runtime_rule_attributes == "{}",
		"V2 generation 2 replaces rule attributes atomically in all three tiers");
	v2.plan.generation = 15;
	v2_attribute.attributes = "{\"switch_to_fast_forward\":false}";
	v2_plan.base = v2.plan;
	v2.runtime.fail = ProxySQL_PluginConfigStage::interfaces;
	const auto v2_failed = proxysql_apply_plugin_mysql_config_v2(
		v2.db, v2_plan, v2.runtime.hooks());
	ok(!v2_failed.applied &&
		text_value(v2.db, "SELECT attributes FROM main.mysql_query_rules WHERE rule_id=9000") == "{}" &&
		text_value(v2.db, "SELECT attributes FROM disk.mysql_query_rules WHERE rule_id=9000") == "{}" &&
		v2.runtime.runtime_rule_present && v2.runtime.runtime_rule_attributes == "{}" &&
		scalar(v2.db, "SELECT generation FROM main.proxysql_plugin_config_generations "
			"WHERE owner='mysql_router'") == 14 &&
		scalar(v2.db, "SELECT generation FROM disk.proxysql_plugin_config_generations "
			"WHERE owner='mysql_router'") == 14,
		"a post-rules V2 failure restores prior attributes and generation in all three tiers");
	v2.runtime.fail = ProxySQL_PluginConfigStage::none;
	v2.plan.rules = nullptr;
	v2.plan.rule_count = 0;
	v2_plan = {v2.plan, nullptr, 0};
	const auto v2_generation_three = proxysql_apply_plugin_mysql_config_v2(
		v2.db, v2_plan, v2.runtime.hooks());
	ok(v2_generation_three.applied && v2_generation_three.generation == 15 &&
		scalar(v2.db, "SELECT COUNT(*) FROM main.mysql_query_rules WHERE rule_id=9000") == 0 &&
		scalar(v2.db, "SELECT COUNT(*) FROM disk.mysql_query_rules WHERE rule_id=9000") == 0 &&
		!v2.runtime.runtime_rule_present &&
		text_value(v2.db, "SELECT attributes FROM main.mysql_query_rules WHERE rule_id=5") ==
			"{\"operator\":true}" &&
		text_value(v2.db, "SELECT attributes FROM disk.mysql_query_rules WHERE rule_id=5") ==
			"{\"operator\":true}",
		"V2 generation 3 removes only the managed rule and preserves operator attributes");

	Fixture f;
	Fixture released_user;
	const std::string release_comment = proxysql_plugin_release_user_comment("released-to-operator");
	ProxySQL_PluginMysqlUserRow release_row {
		"old_owned", "old", true, false, 8100, "", false, true, false,
		true, true, 100, "", release_comment.c_str()};
	released_user.plan.users = &release_row;
	released_user.plan.user_count = 1;
	const std::string released_main_before = text_value(released_user.db,
		"SELECT username||'|'||password||'|'||active||'|'||use_ssl||'|'||default_hostgroup||'|'||"
		"default_schema||'|'||schema_locked||'|'||transaction_persistent||'|'||fast_forward||'|'||"
		"backend||'|'||frontend||'|'||max_connections||'|'||attributes||'|'||comment "
		"FROM main.mysql_users WHERE username='old_owned'");
	const std::string released_disk_before = text_value(released_user.db,
		"SELECT username||'|'||password||'|'||active||'|'||use_ssl||'|'||default_hostgroup||'|'||"
		"default_schema||'|'||schema_locked||'|'||transaction_persistent||'|'||fast_forward||'|'||"
		"backend||'|'||frontend||'|'||max_connections||'|'||attributes||'|'||comment "
		"FROM disk.mysql_users WHERE username='old_owned'");
	const auto released_result = proxysql_apply_plugin_mysql_config(
		released_user.db, released_user.plan, released_user.runtime.hooks());
	ok(released_result.applied,
		"an exact previously-owned user can be released in one complete generation");
	ok(text_value(released_user.db,
		"SELECT username||'|'||password||'|'||active||'|'||use_ssl||'|'||default_hostgroup||'|'||"
		"default_schema||'|'||schema_locked||'|'||transaction_persistent||'|'||fast_forward||'|'||"
		"backend||'|'||frontend||'|'||max_connections||'|'||attributes||'|'||comment "
		"FROM main.mysql_users WHERE username='old_owned'") != released_main_before &&
	   text_value(released_user.db,
		"SELECT username||'|'||password||'|'||active||'|'||use_ssl||'|'||default_hostgroup||'|'||"
		"default_schema||'|'||schema_locked||'|'||transaction_persistent||'|'||fast_forward||'|'||"
		"backend||'|'||frontend||'|'||max_connections||'|'||attributes||'|'||comment "
		"FROM disk.mysql_users WHERE username='old_owned'") != released_disk_before &&
	   text_value(released_user.db,
		"SELECT comment FROM main.mysql_users WHERE username='old_owned'") ==
			"released-to-operator" &&
	   text_value(released_user.db,
		"SELECT comment FROM disk.mysql_users WHERE username='old_owned'") ==
			"released-to-operator",
		"ownership release decodes and stores the operator comment in both tiers");
	ok(scalar(released_user.db,
		"SELECT COUNT(*) FROM main.proxysql_plugin_owned_objects WHERE owner='mysql_router' "
		"AND object_type IN ('mysql_user','mysql_user_v2')") == 0 &&
	   scalar(released_user.db,
		"SELECT COUNT(*) FROM disk.proxysql_plugin_owned_objects WHERE owner='mysql_router' "
		"AND object_type IN ('mysql_user','mysql_user_v2')") == 0,
		"ownership release removes the exact user ledger in both storage tiers");

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

	Fixture unowned_hostgroup;
	bool unowned_hostgroup_seeded = true;
	for (const char* schema : {"main", "disk"}) {
		const std::string prefix = std::string(schema) + ".";
		unowned_hostgroup_seeded = unowned_hostgroup_seeded &&
			unowned_hostgroup.db.execute(("DELETE FROM " + prefix +
				"proxysql_plugin_owned_objects WHERE owner='mysql_router' AND object_type='hostgroup'").c_str()) &&
			unowned_hostgroup.db.execute(("INSERT INTO " + prefix +
				"mysql_servers VALUES (8100,'operator-host',4406,0,'ONLINE',77,0,321,0,0,0,'operator')").c_str());
	}
	const auto unowned_hostgroup_result = proxysql_apply_plugin_mysql_config(
		unowned_hostgroup.db, unowned_hostgroup.plan, unowned_hostgroup.runtime.hooks());
	ok(unowned_hostgroup_seeded && !unowned_hostgroup_result.applied &&
		scalar(unowned_hostgroup.db, "SELECT COUNT(*) FROM main.mysql_servers "
			"WHERE hostgroup_id=8100 AND hostname='operator-host' AND port=4406") == 1 &&
		scalar(unowned_hostgroup.db, "SELECT COUNT(*) FROM disk.mysql_servers "
			"WHERE hostgroup_id=8100 AND hostname='operator-host' AND port=4406") == 1 &&
		all_runtime_at(unowned_hostgroup.runtime, 12),
		"an unowned existing hostgroup collision fails closed without deleting operator servers");

	Fixture unowned_interface;
	ok(unowned_interface.db.execute("DELETE FROM main.proxysql_plugin_owned_objects "
			"WHERE owner='mysql_router' AND object_type='mysql_interface'") &&
		unowned_interface.db.execute("DELETE FROM disk.proxysql_plugin_owned_objects "
			"WHERE owner='mysql_router' AND object_type='mysql_interface'"),
		"an existing listener is made operator-owned in both tiers");
	const auto unowned_interface_result = proxysql_apply_plugin_mysql_config(
		unowned_interface.db, unowned_interface.plan, unowned_interface.runtime.hooks());
	ok(!unowned_interface_result.applied &&
		text_value(unowned_interface.db, "SELECT variable_value FROM main.global_variables "
			"WHERE variable_name='mysql-interfaces'").find("127.0.0.1:6446") != std::string::npos &&
		text_value(unowned_interface.db, "SELECT variable_value FROM disk.global_variables "
			"WHERE variable_name='mysql-interfaces'").find("127.0.0.1:6446") != std::string::npos &&
		all_runtime_at(unowned_interface.runtime, 12),
		"an unowned existing mysql-interface collision fails closed without claiming the listener");

	Fixture tier_divergent_user;
	ProxySQL_PluginMysqlUserRow tier_user {
		"tier_user", "plugin-secret", true, false, 8100, "appdb", false, true, false,
		true, true, 100, "{}", "mysql_router:managed"};
	tier_divergent_user.plan.users = &tier_user;
	tier_divergent_user.plan.user_count = 1;
	ok(tier_divergent_user.db.execute("INSERT INTO disk.mysql_users VALUES "
		"('tier_user','operator-disk',1,0,10,'',0,1,0,1,1,77,'{}','operator')"),
		"a disk-only operator user collision is seeded");
	const auto tier_divergent_result = proxysql_apply_plugin_mysql_config(
		tier_divergent_user.db, tier_divergent_user.plan, tier_divergent_user.runtime.hooks());
	ok(!tier_divergent_result.applied &&
		scalar(tier_divergent_user.db, "SELECT COUNT(*) FROM main.mysql_users WHERE username='tier_user'") == 0 &&
		text_value(tier_divergent_user.db,
			"SELECT password FROM disk.mysql_users WHERE username='tier_user'") == "operator-disk" &&
		all_runtime_at(tier_divergent_user.runtime, 12),
		"a collision present in only one storage tier rejects the generation without divergent publication");

	Fixture unreadable_interfaces;
	sqlite3_set_authorizer(unreadable_interfaces.db.get_db(), &deny_mysql_interfaces_read, nullptr);
	const auto unreadable_interfaces_result = proxysql_apply_plugin_mysql_config(
		unreadable_interfaces.db, unreadable_interfaces.plan, unreadable_interfaces.runtime.hooks());
	sqlite3_set_authorizer(unreadable_interfaces.db.get_db(), nullptr, nullptr);
	ok(!unreadable_interfaces_result.applied &&
		scalar(unreadable_interfaces.db,
			"SELECT generation FROM main.proxysql_plugin_config_generations WHERE owner='mysql_router'") == 12 &&
		scalar(unreadable_interfaces.db,
			"SELECT generation FROM disk.proxysql_plugin_config_generations WHERE owner='mysql_router'") == 12 &&
		all_runtime_at(unreadable_interfaces.runtime, 12),
		"a mysql-interfaces read failure aborts publication without replacing operator listeners");
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

	Fixture interleaved;
	interleaved.plan.generation = 14;
	interleaved.runtime.db = &interleaved.db;
	interleaved.runtime.mutation = Runtime::Mutation::newer_generation;
	const auto interleaved_result = proxysql_apply_plugin_mysql_config(
		interleaved.db, interleaved.plan, interleaved.runtime.hooks());
	ok(interleaved.runtime.mutation_ok && interleaved_result.applied &&
		scalar(interleaved.db, "SELECT COUNT(*) FROM mysql_users WHERE username='newer_owned'") == 0 &&
		scalar(interleaved.db, "SELECT COUNT(*) FROM disk.mysql_users WHERE username='newer_owned'") == 0 &&
		scalar(interleaved.db, "SELECT COUNT(*) FROM mysql_query_rules WHERE rule_id=9010") == 0 &&
		scalar(interleaved.db, "SELECT COUNT(*) FROM disk.mysql_query_rules WHERE rule_id=9010") == 0 &&
		text_value(interleaved.db, "SELECT variable_value FROM global_variables WHERE variable_name='mysql-interfaces'").find(":6550") == std::string::npos &&
		text_value(interleaved.db, "SELECT variable_value FROM disk.global_variables WHERE variable_name='mysql-interfaces'").find(":6550") == std::string::npos,
		"ownership and generation are recomputed under lock after a newer main/disk publication interleaves");
	interleaved.users[0].username = "late_user";
	interleaved.plan.generation = 15;
	interleaved.runtime.mutation = Runtime::Mutation::late_collision;
	const auto late_collision = proxysql_apply_plugin_mysql_config(
		interleaved.db, interleaved.plan, interleaved.runtime.hooks());
	ok(interleaved.runtime.mutation_ok && late_collision.applied &&
		has_collision(late_collision, "mysql_user:late_user") &&
		text_value(interleaved.db, "SELECT password FROM mysql_users WHERE username='late_user'") == "operator-late" &&
		text_value(interleaved.db, "SELECT password FROM disk.mysql_users WHERE username='late_user'") == "operator-late",
		"collisions introduced while waiting for locks are recomputed and preserved in both schemas");

	Fixture divergent;
	ok(divergent.db.execute("INSERT INTO disk.mysql_users VALUES "
		"('disk_obsolete','disk',1,0,8100,'',0,1,0,1,1,100,'{}','mysql_router:disk')") &&
		divergent.db.execute("INSERT INTO disk.mysql_query_rules(rule_id,active,proxy_port,destination_hostgroup,apply,attributes,comment) "
			"VALUES (9020,1,6450,8101,1,'','mysql_router:disk')") &&
		divergent.db.execute("UPDATE disk.global_variables SET variable_value=variable_value||';127.0.0.1:6551' "
			"WHERE variable_name='mysql-interfaces'") &&
		divergent.db.execute("INSERT INTO disk.proxysql_plugin_owned_objects VALUES "
			"('mysql_router','mysql_user','disk_obsolete',12),"
			"('mysql_router','mysql_query_rule','9020',12),"
			"('mysql_router','mysql_interface','127.0.0.1:6551',12)"),
		"divergent disk-only ownership is seeded");
	const auto divergent_result = proxysql_apply_plugin_mysql_config(
		divergent.db, divergent.plan, divergent.runtime.hooks());
	ok(divergent_result.applied &&
		scalar(divergent.db, "SELECT COUNT(*) FROM disk.mysql_users WHERE username='disk_obsolete'") == 0 &&
		scalar(divergent.db, "SELECT COUNT(*) FROM disk.mysql_query_rules WHERE rule_id=9020") == 0 &&
		text_value(divergent.db, "SELECT variable_value FROM disk.global_variables WHERE variable_name='mysql-interfaces'").find(":6551") == std::string::npos,
		"disk ledger divergence is reconciled before its ownership ledger is replaced");
	ok(divergent.db.execute("UPDATE mysql_replication_hostgroups SET reader_hostgroup=10 WHERE writer_hostgroup=8100") &&
		divergent.db.execute("UPDATE disk.mysql_replication_hostgroups SET reader_hostgroup=10 WHERE writer_hostgroup=8100"),
		"hybrid owned-to-operator hostgroup mappings are seeded");
	divergent.plan.generation = static_cast<uint64_t>(scalar(divergent.db,
		"SELECT generation FROM proxysql_plugin_config_generations WHERE owner='mysql_router'")) + 1;
	const auto hybrid_result = proxysql_apply_plugin_mysql_config(
		divergent.db, divergent.plan, divergent.runtime.hooks());
	ok(!hybrid_result.applied &&
		scalar(divergent.db, "SELECT reader_hostgroup FROM mysql_replication_hostgroups WHERE writer_hostgroup=8100") == 10 &&
		scalar(divergent.db, "SELECT reader_hostgroup FROM disk.mysql_replication_hostgroups WHERE writer_hostgroup=8100") == 10,
		"a mapping crossing the owned/unowned hostgroup boundary is never deleted");
	ok(divergent.db.execute("UPDATE mysql_replication_hostgroups SET reader_hostgroup=8101 WHERE writer_hostgroup=8100") &&
		divergent.db.execute("UPDATE disk.mysql_replication_hostgroups SET reader_hostgroup=8101 WHERE writer_hostgroup=8100"),
		"hybrid mapping fixture is restored before nullable collision coverage");
	ProxySQL_PluginMysqlRuleRow nullable_rule {
		9021, true, 6450, "^SELECT", nullptr, false, "CASELESS", 8101, true, "mysql_router:replacement"};
	ok(divergent.db.execute("INSERT INTO mysql_query_rules(rule_id,active,proxy_port,destination_hostgroup,apply,attributes,comment) "
			"VALUES (9021,1,6450,8101,1,'',NULL)") &&
		divergent.db.execute("INSERT INTO disk.mysql_query_rules(rule_id,active,proxy_port,destination_hostgroup,apply,attributes,comment) "
			"VALUES (9021,1,6450,8101,1,'',NULL)") &&
		divergent.db.execute("INSERT INTO proxysql_plugin_owned_objects VALUES "
			"('mysql_router','mysql_query_rule','9021',13)") &&
		divergent.db.execute("INSERT INTO disk.proxysql_plugin_owned_objects VALUES "
			"('mysql_router','mysql_query_rule','9021',13)"),
		"nullable-comment query-rule collision is seeded in both schemas");
	divergent.plan.generation = static_cast<uint64_t>(scalar(divergent.db,
		"SELECT generation FROM proxysql_plugin_config_generations WHERE owner='mysql_router'")) + 1;
	divergent.plan.rules = &nullable_rule;
	divergent.plan.rule_count = 1;
	const auto nullable_collision = proxysql_apply_plugin_mysql_config(
		divergent.db, divergent.plan, divergent.runtime.hooks());
	ok(nullable_collision.applied && has_collision(nullable_collision, "mysql_query_rule:9021") &&
		scalar(divergent.db, "SELECT COUNT(*) FROM mysql_query_rules WHERE rule_id=9021 AND comment IS NULL") == 1 &&
		scalar(divergent.db, "SELECT COUNT(*) FROM disk.mysql_query_rules WHERE rule_id=9021 AND comment IS NULL") == 1,
		"nullable rule comments are non-owned collisions and remain untouched");

	Fixture runtime_saved_user;
	ProxySQL_PluginMysqlUserRow combined_user {
		"runtime_saved", "plugin-secret", true, false, 8100, "appdb", false, true, false,
		true, true, 100, "{}", "mysql_router:managed"};
	runtime_saved_user.plan.users = &combined_user;
	runtime_saved_user.plan.user_count = 1;
	const auto combined_initial = proxysql_apply_plugin_mysql_config(
		runtime_saved_user.db, runtime_saved_user.plan, runtime_saved_user.runtime.hooks());
	bool split_saved = combined_initial.applied;
	for (const char* schema : {"main", "disk"}) {
		const std::string prefix = std::string(schema) + ".";
		split_saved = split_saved && runtime_saved_user.db.execute(("DELETE FROM " + prefix +
			"mysql_users WHERE username='runtime_saved'").c_str()) &&
			runtime_saved_user.db.execute(("INSERT INTO " + prefix + "mysql_users VALUES "
				"('runtime_saved','plugin-secret',1,0,8100,'appdb',0,1,0,1,0,100,'{}','mysql_router:managed'),"
				"('runtime_saved','plugin-secret',1,0,8100,'appdb',0,1,0,0,1,100,'{}','mysql_router:managed')").c_str());
	}
	ok(split_saved,
		"a standard runtime-user save materializes complementary rows under the combined ownership key");
	runtime_saved_user.plan.generation = 14;
	const auto split_recombined = proxysql_apply_plugin_mysql_config(
		runtime_saved_user.db, runtime_saved_user.plan, runtime_saved_user.runtime.hooks());
	ok(split_recombined.applied &&
		!has_collision(split_recombined, "mysql_user:runtime_saved") &&
		scalar(runtime_saved_user.db, "SELECT COUNT(*) FROM main.mysql_users WHERE "
			"username='runtime_saved' AND backend=1 AND frontend=1") == 1 &&
		scalar(runtime_saved_user.db, "SELECT COUNT(*) FROM disk.mysql_users WHERE "
			"username='runtime_saved' AND backend=1 AND frontend=1") == 1 &&
		scalar(runtime_saved_user.db, "SELECT COUNT(*) FROM main.mysql_users WHERE "
			"username='runtime_saved'") == 1 &&
		scalar(runtime_saved_user.db, "SELECT COUNT(*) FROM disk.mysql_users WHERE "
			"username='runtime_saved'") == 1,
		"an owned complementary runtime split canonicalizes without becoming an operator collision");

	Fixture drifted_runtime_saved_user;
	drifted_runtime_saved_user.plan.users = &combined_user;
	drifted_runtime_saved_user.plan.user_count = 1;
	const auto drifted_combined_initial = proxysql_apply_plugin_mysql_config(
		drifted_runtime_saved_user.db, drifted_runtime_saved_user.plan,
		drifted_runtime_saved_user.runtime.hooks());
	bool drifted_split_seeded = drifted_combined_initial.applied;
	for (const char* schema : {"main", "disk"}) {
		const std::string prefix = std::string(schema) + ".";
		drifted_split_seeded = drifted_split_seeded &&
			drifted_runtime_saved_user.db.execute(("DELETE FROM " + prefix +
				"mysql_users WHERE username='runtime_saved'").c_str()) &&
			drifted_runtime_saved_user.db.execute(("INSERT INTO " + prefix + "mysql_users VALUES "
				"('runtime_saved','plugin-secret',1,0,8100,'appdb',0,1,0,1,0,100,'{}','mysql_router:managed'),"
				"('runtime_saved','drifted-secret',1,0,8100,'appdb',0,1,0,0,1,100,'{}','mysql_router:managed')").c_str());
	}
	drifted_runtime_saved_user.plan.generation = 14;
	const auto drifted_split_result = proxysql_apply_plugin_mysql_config(
		drifted_runtime_saved_user.db, drifted_runtime_saved_user.plan,
		drifted_runtime_saved_user.runtime.hooks());
	ok(drifted_split_seeded && !drifted_split_result.applied &&
		drifted_split_result.message.find("split") != std::string::npos &&
		scalar(drifted_runtime_saved_user.db,
			"SELECT generation FROM main.proxysql_plugin_config_generations "
			"WHERE owner='mysql_router'") == 13 &&
		scalar(drifted_runtime_saved_user.db,
			"SELECT generation FROM disk.proxysql_plugin_config_generations "
			"WHERE owner='mysql_router'") == 13 &&
		scalar(drifted_runtime_saved_user.db,
			"SELECT COUNT(*) FROM main.mysql_users WHERE username='runtime_saved'") == 2 &&
		scalar(drifted_runtime_saved_user.db,
			"SELECT COUNT(*) FROM disk.mysql_users WHERE username='runtime_saved'") == 2,
		"a drifted owned runtime split fails closed without orphaning rows or advancing ledgers");

	Fixture complementary_variants;
	ProxySQL_PluginMysqlUserRow backend_only {
		"split_user", "plugin-backend-v1", true, false, 8100, "appdb", false, true, false,
		false, true, 100, "{}", "mysql_router:managed"};
	complementary_variants.plan.users = &backend_only;
	complementary_variants.plan.user_count = 1;
	const auto initial_variant = proxysql_apply_plugin_mysql_config(
		complementary_variants.db, complementary_variants.plan, complementary_variants.runtime.hooks());
	ok(initial_variant.applied &&
		scalar(complementary_variants.db,
			"SELECT COUNT(*) FROM mysql_users WHERE username='split_user' AND backend=1 AND frontend=0") == 1 &&
		scalar(complementary_variants.db,
			"SELECT COUNT(*) FROM disk.mysql_users WHERE username='split_user' AND backend=1 AND frontend=0") == 1,
		"a backend-only plugin user is materialized in both configuration tiers");
	ok(complementary_variants.db.execute(
		"INSERT INTO mysql_users VALUES ('split_user','operator-frontend',1,0,10,'',0,1,0,0,1,77,'{}','operator')") &&
		complementary_variants.db.execute(
		"INSERT INTO disk.mysql_users VALUES ('split_user','operator-frontend',1,0,10,'',0,1,0,0,1,77,'{}','operator')"),
		"an operator adds the complementary frontend-only variant in both tiers");
	backend_only.password = "plugin-backend-v2"; // NOSONAR: synthetic test credential.
	complementary_variants.plan.generation = 14;
	const auto replaced_variant = proxysql_apply_plugin_mysql_config(
		complementary_variants.db, complementary_variants.plan, complementary_variants.runtime.hooks());
	ok(replaced_variant.applied &&
		text_value(complementary_variants.db,
			"SELECT password FROM mysql_users WHERE username='split_user' AND backend=1 AND frontend=0") ==
				"plugin-backend-v2" &&
		text_value(complementary_variants.db,
			"SELECT password FROM mysql_users WHERE username='split_user' AND backend=0 AND frontend=1") ==
				"operator-frontend" &&
		text_value(complementary_variants.db,
			"SELECT password FROM disk.mysql_users WHERE username='split_user' AND backend=1 AND frontend=0") ==
				"plugin-backend-v2" &&
		text_value(complementary_variants.db,
			"SELECT password FROM disk.mysql_users WHERE username='split_user' AND backend=0 AND frontend=1") ==
				"operator-frontend",
		"plugin replacement owns only its exact variant and preserves the operator complement in both tiers");
	complementary_variants.plan.generation = 15;
	complementary_variants.plan.users = nullptr;
	complementary_variants.plan.user_count = 0;
	const auto removed_variant = proxysql_apply_plugin_mysql_config(
		complementary_variants.db, complementary_variants.plan, complementary_variants.runtime.hooks());
	ok(removed_variant.applied &&
		scalar(complementary_variants.db,
			"SELECT COUNT(*) FROM mysql_users WHERE username='split_user' AND backend=1 AND frontend=0") == 0 &&
		text_value(complementary_variants.db,
			"SELECT password FROM mysql_users WHERE username='split_user' AND backend=0 AND frontend=1") ==
				"operator-frontend" &&
		scalar(complementary_variants.db,
			"SELECT COUNT(*) FROM disk.mysql_users WHERE username='split_user' AND backend=1 AND frontend=0") == 0 &&
		text_value(complementary_variants.db,
			"SELECT password FROM disk.mysql_users WHERE username='split_user' AND backend=0 AND frontend=1") ==
				"operator-frontend",
		"plugin removal deletes only its exact variant and preserves the operator complement in both tiers");

	Fixture round_one_exact;
	for (const char* schema : {"main", "disk"}) {
		const std::string prefix = std::string(schema) + ".";
		ok(round_one_exact.db.execute(("UPDATE " + prefix +
			"proxysql_plugin_owned_objects SET object_key='v2:1:1:6F6C645F6F776E6564' "
			"WHERE owner='mysql_router' AND object_type='mysql_user' AND object_key='old_owned'").c_str()),
			"a round-1 exact ownership key is seeded in %s", schema);
	}
	const auto round_one_migrated = proxysql_apply_plugin_mysql_config(
		round_one_exact.db, round_one_exact.plan, round_one_exact.runtime.hooks());
	ok(round_one_migrated.applied &&
		scalar(round_one_exact.db,
			"SELECT COUNT(*) FROM main.mysql_users WHERE username='old_owned'") == 0 &&
		scalar(round_one_exact.db,
			"SELECT COUNT(*) FROM disk.mysql_users WHERE username='old_owned'") == 0 &&
		all_runtime_at(round_one_exact.runtime, 13),
		"a marker-proven round-1 exact key remains compatible during migration");
	ok(scalar(round_one_exact.db,
		"SELECT COUNT(*) FROM main.proxysql_plugin_owned_objects "
		"WHERE owner='mysql_router' AND object_type='mysql_user_v2'") == 1 &&
		scalar(round_one_exact.db,
			"SELECT COUNT(*) FROM disk.proxysql_plugin_owned_objects "
			"WHERE owner='mysql_router' AND object_type='mysql_user_v2'") == 1 &&
		scalar(round_one_exact.db,
			"SELECT COUNT(*) FROM main.proxysql_plugin_owned_objects "
			"WHERE owner='mysql_router' AND object_type='mysql_user'") == 0 &&
		scalar(round_one_exact.db,
			"SELECT COUNT(*) FROM disk.proxysql_plugin_owned_objects "
			"WHERE owner='mysql_router' AND object_type='mysql_user'") == 0,
		"migration rewrites exact user ownership into the discriminated v2 ledger namespace");

	Fixture ambiguous_legacy;
	for (const char* schema : {"main", "disk"}) {
		const std::string prefix = std::string(schema) + ".";
		ok(ambiguous_legacy.db.execute(("INSERT INTO " + prefix + "mysql_users VALUES "
			"('legacy_split','operator-backend',1,0,10,'',0,1,0,1,0,100,'{}','operator'),"
			"('legacy_split','operator-frontend',1,0,10,'',0,1,0,0,1,100,'{}','operator')").c_str()) &&
			ambiguous_legacy.db.execute(("INSERT INTO " + prefix +
				"proxysql_plugin_owned_objects VALUES ('mysql_router','mysql_user','legacy_split',12)").c_str()),
			"an ambiguous username-only legacy ownership row is seeded in %s", schema);
	}
	ambiguous_legacy.plan.users = nullptr;
	ambiguous_legacy.plan.user_count = 0;
	const auto ambiguous_result = proxysql_apply_plugin_mysql_config(
		ambiguous_legacy.db, ambiguous_legacy.plan, ambiguous_legacy.runtime.hooks());
	ok(!ambiguous_result.applied && ambiguous_result.message.find("ambiguous") != std::string::npos &&
		scalar(ambiguous_legacy.db, "SELECT COUNT(*) FROM mysql_users WHERE username='legacy_split'") == 2 &&
		scalar(ambiguous_legacy.db, "SELECT COUNT(*) FROM disk.mysql_users WHERE username='legacy_split'") == 2 &&
		scalar(ambiguous_legacy.db,
			"SELECT generation FROM proxysql_plugin_config_generations WHERE owner='mysql_router'") == 12 &&
		all_runtime_at(ambiguous_legacy.runtime, 12),
		"ambiguous legacy username ownership fails closed without deleting either variant");

	Fixture unmarked_legacy;
	for (const char* schema : {"main", "disk"}) {
		const std::string prefix = std::string(schema) + ".";
		ok(unmarked_legacy.db.execute(("INSERT INTO " + prefix + "mysql_users VALUES "
			"('legacy_single','operator-only',1,0,10,'',0,1,0,1,0,100,'{}','operator')").c_str()) &&
			unmarked_legacy.db.execute(("INSERT INTO " + prefix +
				"proxysql_plugin_owned_objects VALUES ('mysql_router','mysql_user','legacy_single',12)").c_str()),
			"a single unmarked legacy username row is seeded in %s", schema);
	}
	unmarked_legacy.plan.users = nullptr;
	unmarked_legacy.plan.user_count = 0;
	const auto unmarked_result = proxysql_apply_plugin_mysql_config(
		unmarked_legacy.db, unmarked_legacy.plan, unmarked_legacy.runtime.hooks());
	ok(!unmarked_result.applied && unmarked_result.message.find("ambiguous") != std::string::npos &&
		text_value(unmarked_legacy.db,
			"SELECT password FROM mysql_users WHERE username='legacy_single'") == "operator-only" &&
		text_value(unmarked_legacy.db,
			"SELECT password FROM disk.mysql_users WHERE username='legacy_single'") == "operator-only" &&
		all_runtime_at(unmarked_legacy.runtime, 12),
		"a username-only legacy ledger cannot claim a single unmarked operator row");

	Fixture encoded_name_legacy;
	for (const char* schema : {"main", "disk"}) {
		const std::string prefix = std::string(schema) + ".";
		ok(encoded_name_legacy.db.execute(("INSERT INTO " + prefix + "mysql_users VALUES "
			"('v2:1:0:41','operator-encoded-name',1,0,10,'',0,1,0,1,0,100,'{}','operator')").c_str()) &&
			encoded_name_legacy.db.execute(("INSERT INTO " + prefix +
				"proxysql_plugin_owned_objects VALUES ('mysql_router','mysql_user','v2:1:0:41',12)").c_str()),
			"an exact-key-shaped legacy username is seeded in %s", schema);
	}
	encoded_name_legacy.plan.users = nullptr;
	encoded_name_legacy.plan.user_count = 0;
	const auto encoded_name_result = proxysql_apply_plugin_mysql_config(
		encoded_name_legacy.db, encoded_name_legacy.plan, encoded_name_legacy.runtime.hooks());
	ok(!encoded_name_result.applied && encoded_name_result.message.find("ambiguous") != std::string::npos &&
		text_value(encoded_name_legacy.db,
			"SELECT password FROM mysql_users WHERE username='v2:1:0:41'") == "operator-encoded-name" &&
		text_value(encoded_name_legacy.db,
			"SELECT password FROM disk.mysql_users WHERE username='v2:1:0:41'") == "operator-encoded-name" &&
		all_runtime_at(encoded_name_legacy.runtime, 12),
		"an exact-key-shaped legacy username fails closed instead of being misparsed as ownership");

	Fixture cleanup;
	bool reject_commit = true;
	sqlite3_commit_hook(cleanup.db.get_db(), &reject_one_commit, &reject_commit);
	const auto commit_failure = proxysql_apply_plugin_mysql_config(
		cleanup.db, cleanup.plan, cleanup.runtime.hooks());
	sqlite3_commit_hook(cleanup.db.get_db(), nullptr, nullptr);
	ok(!commit_failure.applied && !reject_commit && sqlite3_get_autocommit(cleanup.db.get_db()) != 0 &&
		scalar(cleanup.db, "SELECT generation FROM proxysql_plugin_config_generations WHERE owner='mysql_router'") == 12 &&
		scalar(cleanup.db, "SELECT generation FROM disk.proxysql_plugin_config_generations WHERE owner='mysql_router'") == 12 &&
		all_runtime_at(cleanup.runtime, 12) &&
		commit_failure.message.find("commit") != std::string::npos &&
		commit_failure.message.find("rollback") != std::string::npos,
		"an actual SQLite COMMIT failure rolls back SQL, restores runtime, and reports rollback status");

	Fixture live_transaction_cleanup;
	LiveTransactionFailure live_transaction_failure;
	ProxySQL_PluginMysqlConfigResult live_transaction_result;
	{
		proxysql_plugin_config_test::scoped_hooks hooks(
			&LiveTransactionFailure::control, nullptr, &live_transaction_failure);
		live_transaction_result = proxysql_apply_plugin_mysql_config(
			live_transaction_cleanup.db, live_transaction_cleanup.plan,
			live_transaction_cleanup.runtime.hooks());
	}
	const bool unrelated_commit = live_transaction_cleanup.db.execute("COMMIT");
	ok(!live_transaction_result.applied && live_transaction_failure.commit_attempts == 1 &&
		live_transaction_failure.rollback_attempts >= 2 &&
		sqlite3_get_autocommit(live_transaction_cleanup.db.get_db()) != 0 && !unrelated_commit &&
		scalar(live_transaction_cleanup.db,
			"SELECT generation FROM proxysql_plugin_config_generations WHERE owner='mysql_router'") == 12 &&
		scalar(live_transaction_cleanup.db,
			"SELECT generation FROM disk.proxysql_plugin_config_generations WHERE owner='mysql_router'") == 12 &&
		all_runtime_at(live_transaction_cleanup.runtime, 12) &&
		live_transaction_result.message.find("rollback failed") != std::string::npos,
		"a live transaction surviving COMMIT and the first ROLLBACK failure is terminated before locks are released");

	Fixture quarantined_cleanup;
	LiveTransactionFailure persistent_failure;
	persistent_failure.persistent_rollback_failure = true;
	ProxySQL_PluginMysqlConfigResult quarantined_result;
	{
		proxysql_plugin_config_test::scoped_hooks hooks(
			&LiveTransactionFailure::control, nullptr, &persistent_failure);
		quarantined_result = proxysql_apply_plugin_mysql_config(
			quarantined_cleanup.db, quarantined_cleanup.plan, quarantined_cleanup.runtime.hooks());
	}
	const bool commit_on_quarantined_connection = quarantined_cleanup.db.execute("COMMIT");
	const pid_t quarantined_query_pid = fork();
	if (quarantined_query_pid == 0) {
		char* query_error = nullptr;
		int query_columns = 0;
		int query_affected = 0;
		SQLite3_result* query_result = nullptr;
		const bool query_ok = quarantined_cleanup.db.execute_statement(
			"SELECT 1", &query_error, &query_columns, &query_affected, &query_result);
		free(query_error);
		delete query_result;
		const int structure = quarantined_cleanup.db.check_table_structure(
			"never", "CREATE TABLE never(value INT)");
		_exit(!query_ok && structure == 0 ? 0 : 1);
	}
	int quarantined_query_status = 0;
	const bool quarantined_query_waited = quarantined_query_pid > 0 &&
		waitpid(quarantined_query_pid, &quarantined_query_status, 0) == quarantined_query_pid;
	ok(!quarantined_result.applied && persistent_failure.commit_attempts == 1 &&
		persistent_failure.rollback_attempts >= 2 &&
		quarantined_cleanup.db.get_db() == nullptr && !commit_on_quarantined_connection &&
		quarantined_query_waited && WIFEXITED(quarantined_query_status) &&
		WEXITSTATUS(quarantined_query_status) == 0 &&
		all_runtime_at(quarantined_cleanup.runtime, 12) &&
		quarantined_result.message.find("quarantined") != std::string::npos,
		"persistent rollback failure quarantines the Admin connection before an unrelated COMMIT can publish staged rows");

	Fixture prelock_exception;
	prelock_exception.runtime.trace.clear();
	bool prelock_exception_escaped = false;
	ProxySQL_PluginMysqlConfigResult prelock_exception_result;
	{
		proxysql_plugin_config_test::scoped_hooks hooks(nullptr, &throw_before_plan_copy, nullptr);
		try {
			prelock_exception_result = proxysql_apply_plugin_mysql_config(
				prelock_exception.db, prelock_exception.plan, prelock_exception.runtime.hooks());
		} catch (...) {
			prelock_exception_escaped = true;
		}
	}
	ok(!prelock_exception_escaped && !prelock_exception_result.applied &&
		prelock_exception_result.message == "plugin publication failed before lock acquisition" &&
		prelock_exception.runtime.trace.empty(),
		"pre-lock plan-copy exceptions are sanitized and cannot cross the plugin-config service boundary");

	bool escaped = false;
	ProxySQL_PluginMysqlConfigResult exception_result;
	cleanup.runtime.throw_lock = ProxySQL_PluginConfigLock::auth;
	cleanup.runtime.trace.clear();
	try {
		exception_result = proxysql_apply_plugin_mysql_config(cleanup.db, cleanup.plan, cleanup.runtime.hooks());
	} catch (...) { escaped = true; }
	ok(!escaped && !exception_result.applied && cleanup.runtime.trace ==
		std::vector<std::string>({"L1", "L2", "L3", "U2", "U1"}),
		"lock exceptions are contained and release every previously acquired lock in reverse order");
	cleanup.runtime.throw_lock = static_cast<ProxySQL_PluginConfigLock>(0);
	cleanup.runtime.throw_publish = ProxySQL_PluginConfigStage::rules;
	cleanup.runtime.trace.clear();
	escaped = false;
	try {
		exception_result = proxysql_apply_plugin_mysql_config(cleanup.db, cleanup.plan, cleanup.runtime.hooks());
	} catch (...) { escaped = true; }
	ok(!escaped && !exception_result.applied && sqlite3_get_autocommit(cleanup.db.get_db()) != 0 &&
		all_runtime_at(cleanup.runtime, 12) &&
		std::find(cleanup.runtime.trace.begin(), cleanup.runtime.trace.end(), "R2") != cleanup.runtime.trace.end() &&
		cleanup.runtime.trace.size() >= 5 && cleanup.runtime.trace.back() == "U1",
		"publish exceptions cannot skip reverse runtime restore, SQL rollback, or reverse unlock");
	if (sqlite3_get_autocommit(cleanup.db.get_db()) == 0) cleanup.db.execute("ROLLBACK");
	cleanup.runtime.servers = cleanup.runtime.users = cleanup.runtime.rules = cleanup.runtime.interfaces = 12;
	cleanup.runtime.throw_publish = ProxySQL_PluginConfigStage::none;
	cleanup.runtime.fail = ProxySQL_PluginConfigStage::interfaces;
	cleanup.runtime.throw_restore = ProxySQL_PluginConfigStage::interfaces;
	cleanup.runtime.throw_unlock = ProxySQL_PluginConfigLock::mysql_threads;
	cleanup.runtime.trace.clear();
	escaped = false;
	try {
		exception_result = proxysql_apply_plugin_mysql_config(cleanup.db, cleanup.plan, cleanup.runtime.hooks());
	} catch (...) { escaped = true; }
	ok(!escaped && !exception_result.applied && sqlite3_get_autocommit(cleanup.db.get_db()) != 0 &&
		std::find(cleanup.runtime.trace.begin(), cleanup.runtime.trace.end(), "R2") != cleanup.runtime.trace.end() &&
		std::find(cleanup.runtime.trace.begin(), cleanup.runtime.trace.end(), "U1") != cleanup.runtime.trace.end() &&
		exception_result.message.find("restore") != std::string::npos &&
		exception_result.message.find("unlock") != std::string::npos,
		"restore and unlock exceptions are each reported without skipping remaining cleanup");
	if (sqlite3_get_autocommit(cleanup.db.get_db()) == 0) cleanup.db.execute("ROLLBACK");
	cleanup.runtime.servers = cleanup.runtime.users = cleanup.runtime.rules = cleanup.runtime.interfaces = 12;
	cleanup.runtime.fail = ProxySQL_PluginConfigStage::none;
	cleanup.runtime.throw_restore = ProxySQL_PluginConfigStage::none;
	cleanup.runtime.throw_unlock = static_cast<ProxySQL_PluginConfigLock>(0);

	Fixture v;
	ProxySQL_PluginMysqlConfigPlan bad = v.plan;
	bad.generation = 0;
	ok(rejected_without_lock(v, bad), "generation zero is rejected before locks");
	bad = v.plan; bad.generation = 12;
	v.runtime.trace.clear();
	const auto stale = proxysql_apply_plugin_mysql_config(v.db, bad, v.runtime.hooks());
	ok(!stale.applied && !v.runtime.trace.empty() &&
		scalar(v.db, "SELECT generation FROM proxysql_plugin_config_generations WHERE owner='mysql_router'") == 12,
		"a non-newer generation is rejected from authoritative state under lock");
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
	ProxySQL_PluginMysqlServerRow bad_weight = v.servers[0]; bad_weight.weight = 10000001;
	bad = v.plan; bad.servers = &bad_weight; bad.server_count = 1;
	ok(rejected_without_lock(v, bad), "server weights above the Admin schema maximum are rejected before locks");
	ProxySQL_PluginMysqlServerRow bad_lag = v.servers[0]; bad_lag.max_replication_lag = 126144001;
	bad = v.plan; bad.servers = &bad_lag; bad.server_count = 1;
	ok(rejected_without_lock(v, bad), "server replication lag above the Admin schema maximum is rejected before locks");
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
	ProxySQL_PluginMysqlReplicationHostgroupRow bad_check_type {8100, 8101, "not_a_check", "mysql_router:bad"};
	bad = v.plan; bad.replication_hostgroups = &bad_check_type;
	ok(rejected_without_lock(v, bad), "unsupported replication check_type values are rejected before locks");
	int gr_hostgroups[7] {8100, 8101, 8102, 8103, 8104, 8105, 8106};
	ProxySQL_PluginMysqlGroupReplicationHostgroupRow overlapping_gr[2] {
		{8100, 8101, 8102, 8103, true, 1, 0, 0, "mysql_router:first"},
		{8104, 8105, 8102, 8106, true, 1, 0, 0, "mysql_router:second"},
	};
	bad = v.plan; bad.owned_hostgroups = gr_hostgroups; bad.owned_hostgroup_count = 7;
	bad.servers = nullptr; bad.server_count = 0; bad.replication_hostgroups = nullptr;
	bad.replication_hostgroup_count = 0; bad.group_replication_hostgroups = overlapping_gr;
	bad.group_replication_hostgroup_count = 2; bad.hostgroup_attributes = nullptr;
	bad.hostgroup_attribute_count = 0; bad.rules = nullptr; bad.rule_count = 0;
	ok(rejected_without_lock(v, bad), "group-replication role hostgroups are unique across rows");
	ProxySQL_PluginMysqlHostgroupAttributesRow bad_attr_range = v.attrs[0]; bad_attr_range.free_connections_pct = 101;
	bad = v.plan; bad.hostgroup_attributes = &bad_attr_range; bad.hostgroup_attribute_count = 1;
	ok(rejected_without_lock(v, bad), "hostgroup attribute ranges are rejected before locks");
	ProxySQL_PluginMysqlHostgroupAttributesRow bad_attr_json = v.attrs[0]; bad_attr_json.hostgroup_settings = "{broken";
	bad = v.plan; bad.hostgroup_attributes = &bad_attr_json; bad.hostgroup_attribute_count = 1;
	ok(rejected_without_lock(v, bad), "invalid hostgroup attribute JSON is rejected before locks");
	ProxySQL_PluginMysqlUserRow bad_user_json = v.users[0]; bad_user_json.attributes = "[broken";
	bad = v.plan; bad.users = &bad_user_json; bad.user_count = 1;
	ok(rejected_without_lock(v, bad), "invalid mysql user attribute JSON is rejected before locks");
	ProxySQL_PluginMysqlRuleRow bad_rule_modifiers = v.rules[0]; bad_rule_modifiers.re_modifiers = "CASELESS,UNKNOWN";
	bad = v.plan; bad.rules = &bad_rule_modifiers; bad.rule_count = 1;
	ok(rejected_without_lock(v, bad), "unsupported query-rule modifiers are rejected before locks");
	bad = v.plan; bad.owner = "bad/owner";
	ok(rejected_without_lock(v, bad), "invalid owners are rejected before locks");
	bad = v.plan; bad.generation = std::numeric_limits<uint64_t>::max();
	ok(rejected_without_lock(v, bad), "generations outside SQLite's signed INTEGER domain are rejected before locks");

	const bool live_modules_ready = globals_ready && test_init_auth() == 0 &&
		test_init_query_processor() == 0 && test_init_hostgroups() == 0;
	ok(live_modules_ready, "real Auth and HGM modules initialize for live snapshot coverage");
	int old_port = 0;
	int new_port = 0;
	const int old_reservation = reserve_loopback_port(old_port);
	const int new_reservation = reserve_loopback_port(new_port);
	if (old_reservation >= 0) close(old_reservation);
	if (new_reservation >= 0) close(new_reservation);
	const std::string old_interface = "127.0.0.1:" + std::to_string(old_port);
	const std::string new_interface = "127.0.0.1:" + std::to_string(new_port);
	std::string interface_error;
	const bool initial_interface = old_port > 0 && new_port > 0 &&
		GloMTH->set_variable("caching_sha2_password_auto_generate_rsa_keys", "false") &&
		GloMTH->set_variable("caching_sha2_password_private_key_path", "") &&
		GloMTH->set_variable("caching_sha2_password_public_key_path", "") &&
		GloMTH->set_variable("interfaces", old_interface.c_str()) &&
		GloMTH->listener_add(old_interface.c_str()) >= 0;
	GloMTH->wrlock();
	const bool changed_interface = initial_interface &&
		GloMTH->apply_interfaces_under_lock(new_interface.c_str(), interface_error);
	GloMTH->wrunlock();
	char* changed_value = GloMTH->get_variable("interfaces");
	const bool changed_listener = changed_interface && changed_value != nullptr &&
		new_interface == changed_value && !can_connect_loopback(old_port) && can_connect_loopback(new_port);
	free(changed_value);
	GloMTH->wrlock();
	const bool restored_interface = changed_listener &&
		GloMTH->apply_interfaces_under_lock(old_interface.c_str(), interface_error);
	GloMTH->wrunlock();
	char* restored_value = GloMTH->get_variable("interfaces");
	ok(restored_interface && restored_value != nullptr && old_interface == restored_value &&
		can_connect_loopback(old_port) && !can_connect_loopback(new_port),
		"initialized mysql-interfaces changes remove, add, and restore real listeners under lock");
	free(restored_value);
	auto live_users = result_value(v.db,
		"SELECT username,password,use_ssl,default_hostgroup,default_schema,schema_locked,"
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

	admin->admindb = &v.db;
	bool admin_boundary_escaped = false;
	ProxySQL_PluginMysqlConfigResult admin_boundary_result;
	{
		proxysql_plugin_config_test::scoped_hooks hooks(nullptr, &throw_before_plan_copy, nullptr);
		try {
			admin_boundary_result = admin->apply_plugin_mysql_config(v.plan);
		} catch (...) {
			admin_boundary_escaped = true;
		}
	}
	ok(!admin_boundary_escaped && !admin_boundary_result.applied &&
		admin_boundary_result.message == "plugin publication failed before lock acquisition" &&
		scalar(v.db, "SELECT generation FROM proxysql_plugin_config_generations WHERE owner='mysql_router'") == 12,
		"pre-lock exceptions cannot cross the live Admin plugin-config ABI wrapper");
	MySQL_Monitor* live_monitor = new MySQL_Monitor(); // Process-scoped fixture; HGM retains the global.
	GloMyMon = live_monitor;
	MyHGM->gtid_ev_loop = ev_loop_new(EVBACKEND_POLL | EVFLAG_NOENV);
	ev_async_init(MyHGM->gtid_ev_async, live_gtid_async_noop);
	ev_async_start(MyHGM->gtid_ev_loop, MyHGM->gtid_ev_async);
	ok(v.db.execute(k_galera) && v.db.execute(k_aurora) && v.db.execute(k_rds) &&
		v.db.execute(k_ssl_params),
		"live Admin fixture supplies the unchanged HGM companion tables");
	ok(v.db.execute("UPDATE main.mysql_query_rules SET flagIN=0,negate_match_pattern=0,"
		"re_modifiers='CASELESS' WHERE flagIN IS NULL OR negate_match_pattern IS NULL OR re_modifiers IS NULL") &&
		v.db.execute("UPDATE disk.mysql_query_rules SET flagIN=0,negate_match_pattern=0,"
		"re_modifiers='CASELESS' WHERE flagIN IS NULL OR negate_match_pattern IS NULL OR re_modifiers IS NULL"),
		"live query-rule fixture supplies the canonical non-null defaults");
	ok(v.db.execute(("UPDATE main.global_variables SET variable_value='" + old_interface +
		"' WHERE variable_name='mysql-interfaces'").c_str()) &&
		v.db.execute(("UPDATE disk.global_variables SET variable_value='" + old_interface +
		"' WHERE variable_name='mysql-interfaces'").c_str()) &&
		v.db.execute(("UPDATE main.proxysql_plugin_owned_objects SET object_key='" + old_interface +
		"' WHERE owner='mysql_router' AND object_type='mysql_interface'").c_str()) &&
		v.db.execute(("UPDATE disk.proxysql_plugin_owned_objects SET object_key='" + old_interface +
		"' WHERE owner='mysql_router' AND object_type='mysql_interface'").c_str()),
		"Admin and live listener fixtures agree on the old owned interface");
	v.interfaces[0] = new_interface.c_str();
	v.plan.interface_count = 1;

	incoming_servers_t initial_hgm;
	initial_hgm.runtime_mysql_servers = result_value(v.db,
		"SELECT hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,"
		"max_replication_lag,use_ssl,max_latency_ms,comment FROM main.mysql_servers "
		"ORDER BY hostgroup_id,hostname,port").release();
	initial_hgm.incoming_replication_hostgroups = result_value(v.db,
		"SELECT writer_hostgroup,reader_hostgroup,check_type,comment FROM main.mysql_replication_hostgroups "
		"ORDER BY writer_hostgroup").release();
	initial_hgm.incoming_group_replication_hostgroups = result_value(v.db,
		"SELECT writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,"
		"max_writers,writer_is_also_reader,max_transactions_behind,comment "
		"FROM main.mysql_group_replication_hostgroups ORDER BY writer_hostgroup").release();
	initial_hgm.incoming_hostgroup_attributes = result_value(v.db,
		"SELECT hostgroup_id,max_num_online_servers,autocommit,free_connections_pct,init_connect,"
		"multiplex,connection_warming,throttle_connections_per_sec,ignore_session_variables,"
		"hostgroup_settings,servers_defaults,comment FROM main.mysql_hostgroup_attributes "
		"ORDER BY hostgroup_id").release();
	admin->mysql_servers_wrlock();
	const bool initial_hgm_loaded = admin->load_mysql_servers_to_runtime(initial_hgm);
	admin->mysql_servers_wrunlock();
	char* initial_rules_error = admin->load_mysql_query_rules_to_runtime();
	ok(initial_hgm_loaded && initial_rules_error == nullptr,
		"real HGM and query processor are seeded from generation 12");
	free(initial_rules_error);

	auto atomic_old_users = result_value(v.db,
		"SELECT 'atomic_front','front-old',0,8100,'db',0,1,0,0,1,100,'{}','old' "
		"UNION ALL SELECT 'atomic_back','back-old',0,8101,'db',0,1,0,1,0,100,'{}','old'");
	std::string atomic_old_error;
	ok(admin->init_users_under_lock(std::move(atomic_old_users), atomic_old_error),
		"atomic Auth fixture starts with complete old frontend and backend groups");
	GloMyAuth->add(const_cast<char*>("admin_atomic"), const_cast<char*>("admin-secret"),
		USERNAME_ADMIN, false, ADMIN_HOSTGROUP, const_cast<char*>(""), false, false,
		false, 0, const_cast<char*>(""), const_cast<char*>("admin"));
	GloMyAuth->add(const_cast<char*>("stats_atomic"), const_cast<char*>("stats-secret"),
		USERNAME_ADMIN, false, STATS_HOSTGROUP, const_cast<char*>(""), false, false,
		false, 0, const_cast<char*>(""), const_cast<char*>("stats"));
	auto atomic_new_users = result_value(v.db,
		"SELECT 'atomic_front','front-new',1,8200,'newdb',1,0,1,0,1,321,'{\"k\":1}','new' "
		"UNION ALL SELECT 'atomic_back','back-new',1,8201,'newdb',1,0,1,1,0,654,'{\"k\":2}','new'");
	AuthPublishBarrier auth_barrier;
	mysql_authentication_test::scoped_atomic_replace_hook auth_hook(&auth_publish_barrier, &auth_barrier);
	std::string atomic_publish_error;
	bool atomic_published = false;
	account_details_t frontend_seen {};
	account_details_t backend_seen {};
	std::thread publisher([&] {
		atomic_published = admin->init_users_under_lock(std::move(atomic_new_users), atomic_publish_error);
	});
	std::thread frontend_reader([&] {
		while (!auth_barrier.reached.load(std::memory_order_acquire)) std::this_thread::yield();
		auth_barrier.frontend_attempting.store(true, std::memory_order_release);
		frontend_seen = GloMyAuth->lookup(const_cast<char*>("atomic_front"), USERNAME_FRONTEND,
			{true, true, true});
	});
	std::thread backend_reader([&] {
		while (!auth_barrier.reached.load(std::memory_order_acquire)) std::this_thread::yield();
		auth_barrier.backend_attempting.store(true, std::memory_order_release);
		backend_seen = GloMyAuth->lookup(const_cast<char*>("atomic_back"), USERNAME_BACKEND,
			{true, true, true});
	});
	publisher.join();
	frontend_reader.join();
	backend_reader.join();
	ok(atomic_published && auth_barrier.reached.load(std::memory_order_acquire) &&
		frontend_seen.password != nullptr && std::string(frontend_seen.password) == "front-new" &&
		frontend_seen.default_hostgroup == 8200 && frontend_seen.max_connections == 321 &&
		backend_seen.password != nullptr && std::string(backend_seen.password) == "back-new" &&
		backend_seen.default_hostgroup == 8201 && backend_seen.max_connections == 654,
		"frontend and backend lookups attempted mid-publish observe complete new Auth groups");
	free_account_details(frontend_seen);
	free_account_details(backend_seen);
	account_details_t admin_seen = GloMyAuth->lookup(const_cast<char*>("admin_atomic"),
		USERNAME_ADMIN, {true, true, true});
	account_details_t stats_seen = GloMyAuth->lookup(const_cast<char*>("stats_atomic"),
		USERNAME_ADMIN, {true, true, true});
	ok(admin_seen.password != nullptr && std::string(admin_seen.password) == "admin-secret" &&
		stats_seen.password != nullptr && std::string(stats_seen.password) == "stats-secret",
		"atomic mysql_users replacement preserves the separate Admin and stats credential scope");
	free_account_details(admin_seen);
	free_account_details(stats_seen);

	auto malformed_users = result_value(v.db,
		"SELECT username,password,active,use_ssl,default_hostgroup,default_schema,schema_locked,"
		"transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment "
		"FROM main.mysql_users ORDER BY username,backend DESC");
	const uint64_t auth_before_malformed = GloMyAuth->get_current_mysql_users()->raw_checksum();
	std::string malformed_users_error;
	ok(!admin->init_users_under_lock(std::move(malformed_users), malformed_users_error) &&
		malformed_users_error.find("13 columns") != std::string::npos &&
		GloMyAuth->get_current_mysql_users()->raw_checksum() == auth_before_malformed,
		"the live Auth adapter rejects the old 14-column shape without changing users");

	const uint64_t hgm_before_error = MyHGM->get_current_mysql_table("cluster_mysql_servers")->raw_checksum();
	ok(v.db.execute("DROP TABLE main.mysql_galera_hostgroups"),
		"an early real HGM companion-table failure is injected");
	admin->mysql_servers_wrlock();
	const bool hgm_error_reported = admin->load_mysql_servers_to_runtime();
	admin->mysql_servers_wrunlock();
	ok(!hgm_error_reported &&
		MyHGM->get_current_mysql_table("cluster_mysql_servers")->raw_checksum() == hgm_before_error,
		"the live HGM adapter propagates an early SQL failure after later reads succeed");
	ok(v.db.execute(k_galera), "the HGM failure fixture is repaired");

	const auto live_applied = admin->apply_plugin_mysql_config(v.plan);
	SQLite3_result* applied_users = GloMyAuth->get_current_mysql_users();
	const std::string applied_users_checksum = get_checksum_from_hash(GloMyAuth->get_runtime_checksum());
	SQLite3_row* applied_router = result_row(applied_users, 0, "router_app");
	SQLite3_result* applied_servers = MyHGM->get_current_mysql_table("cluster_mysql_servers");
	SQLite3_result* applied_rules = GloMyQPro->get_current_query_rules_inner();
	SQLite3_row* applied_router_rule = result_row(applied_rules, 0, "9000");
	char* applied_interfaces = GloMTH->get_variable("interfaces");
	ok(live_applied.applied && live_applied.generation == 13 && applied_router != nullptr &&
		std::string(applied_router->fields[1]) == "new-secret" &&
		std::string(applied_router->fields[2]) == "1" &&
		std::string(applied_router->fields[3]) == "8100" &&
		std::string(applied_router->fields[4]) == "appdb" &&
		std::string(applied_router->fields[5]) == "0" &&
		std::string(applied_router->fields[6]) == "1" &&
		std::string(applied_router->fields[7]) == "0" &&
		std::string(applied_router->fields[8]) == "1" &&
		std::string(applied_router->fields[9]) == "1" &&
		std::string(applied_router->fields[10]) == "500" &&
		std::string(applied_router->fields[11]) == "{}" &&
		std::string(applied_router->fields[12]) == "mysql_router:managed",
		"real Admin publication loads exact canonical Auth field values");
	ok(!applied_users_checksum.empty() &&
		applied_users_checksum == GloVars.checksums_values.mysql_users.checksum,
		"real Admin publication exposes the canonical checksum of the complete live Auth state");
	ok(applied_servers != nullptr && result_row(applied_servers, 1, "writer-new") != nullptr &&
		applied_rules != nullptr && applied_rules->rows_count == 3 && applied_router_rule != nullptr &&
		applied_router_rule->fields[3] != nullptr && std::string(applied_router_rule->fields[3]) == "0" &&
		scalar(v.db, "SELECT flagIN FROM mysql_query_rules WHERE rule_id=9000") == 0 &&
		applied_interfaces != nullptr &&
		new_interface == applied_interfaces && !can_connect_loopback(old_port) && can_connect_loopback(new_port),
		"real Admin publication updates HGM, canonical QPro flagIN, and initialized MySQL listeners");
	free(applied_interfaces);

	const uint64_t stable_auth_checksum = GloMyAuth->get_current_mysql_users()->raw_checksum();
	const uint64_t stable_server_checksum = MyHGM->get_current_mysql_table("cluster_mysql_servers")->raw_checksum();
	const uint64_t stable_rule_checksum = GloMyQPro->get_current_query_rules_inner()->raw_checksum();
	const std::string stable_users_module_checksum = GloVars.checksums_values.mysql_users.checksum;
	const unsigned long long stable_users_checksum_version = GloVars.checksums_values.mysql_users.version;
	const unsigned long long stable_users_checksum_epoch = GloVars.checksums_values.mysql_users.epoch;
	v.plan.generation = 14;
	int recovery_port = 0;
	const int recovery_reservation = reserve_loopback_port(recovery_port);
	if (recovery_reservation >= 0) close(recovery_reservation);
	const std::string recovery_interface = "127.0.0.1:" + std::to_string(recovery_port);
	v.interfaces[0] = recovery_interface.c_str();
	InterfaceRecoveryFailure transient_readd {new_interface, 1, 1, 0};
	ProxySQL_PluginMysqlConfigResult transient_recovery;
	{
		mysql_thread_test::scoped_interface_hooks hooks(
			&InterfaceRecoveryFailure::fail_add, &InterfaceRecoveryFailure::reject_commit,
			&transient_readd);
		transient_recovery = admin->apply_plugin_mysql_config(v.plan);
	}
	char* transient_interfaces = GloMTH->get_variable("interfaces");
	ok(recovery_port > 0 && !transient_recovery.applied && transient_readd.old_add_attempts >= 2 &&
		transient_interfaces != nullptr && new_interface == transient_interfaces &&
		can_connect_loopback(new_port) && !can_connect_loopback(recovery_port) &&
		transient_recovery.message.find("restore failed") == std::string::npos,
		"outer interface restore reconciles a listener missed by the rejected publish's first re-add");
	free(transient_interfaces);

	int persistent_port = 0;
	const int persistent_reservation = reserve_loopback_port(persistent_port);
	if (persistent_reservation >= 0) close(persistent_reservation);
	const std::string persistent_interface = "127.0.0.1:" + std::to_string(persistent_port);
	v.interfaces[0] = persistent_interface.c_str();
	InterfaceRecoveryFailure persistent_readd {new_interface, 1, -1, 0};
	ProxySQL_PluginMysqlConfigResult persistent_recovery;
	{
		mysql_thread_test::scoped_interface_hooks hooks(
			&InterfaceRecoveryFailure::fail_add, &InterfaceRecoveryFailure::reject_commit,
			&persistent_readd);
		persistent_recovery = admin->apply_plugin_mysql_config(v.plan);
	}
	char* persistent_interfaces = GloMTH->get_variable("interfaces");
	ok(persistent_port > 0 && !persistent_recovery.applied && persistent_readd.old_add_attempts >= 2 &&
		persistent_recovery.message.find("restore failed") != std::string::npos &&
		persistent_interfaces != nullptr && new_interface != persistent_interfaces &&
		!can_connect_loopback(new_port) && !can_connect_loopback(persistent_port),
		"persistent listener re-add failure is reported and never claims the old interface string was restored");
	free(persistent_interfaces);
	std::string recovery_error;
	GloMTH->wrlock();
	const bool recovered_after_injection =
		GloMTH->apply_interfaces_under_lock(new_interface.c_str(), recovery_error);
	GloMTH->wrunlock();
	ok(recovered_after_injection && can_connect_loopback(new_port),
		"listener state is repaired after persistent recovery-failure coverage");
	v.interfaces[0] = new_interface.c_str();

	v.users[0].password = "must-rollback"; // NOSONAR: synthetic rollback marker.
	ok(v.db.execute("DROP TABLE main.mysql_query_rules_fast_routing"),
		"query processor failure is injected through its real Admin input table");
	const auto qpro_failure = admin->apply_plugin_mysql_config(v.plan);
	char* after_qpro_interfaces = GloMTH->get_variable("interfaces");
	ok(!qpro_failure.applied && qpro_failure.message.find("mysql_query_rules_fast_routing") != std::string::npos &&
		scalar(v.db, "SELECT generation FROM proxysql_plugin_config_generations WHERE owner='mysql_router'") == 13 &&
		GloMyAuth->get_current_mysql_users()->raw_checksum() == stable_auth_checksum &&
		std::string(GloVars.checksums_values.mysql_users.checksum) == stable_users_module_checksum &&
		GloVars.checksums_values.mysql_users.version == stable_users_checksum_version &&
		GloVars.checksums_values.mysql_users.epoch == stable_users_checksum_epoch &&
		MyHGM->get_current_mysql_table("cluster_mysql_servers")->raw_checksum() == stable_server_checksum &&
		GloMyQPro->get_current_query_rules_inner()->raw_checksum() == stable_rule_checksum &&
		after_qpro_interfaces != nullptr && new_interface == after_qpro_interfaces &&
		can_connect_loopback(new_port),
		"a real QPro adapter failure restores exact Auth checksum state, HGM, and listeners at generation 13");
	free(after_qpro_interfaces);
	ok(v.db.execute(k_fast_rules), "query processor failure fixture is repaired");

	int occupied_port = 0;
	const int occupied_fd = reserve_loopback_port(occupied_port);
	const std::string occupied_interface = "127.0.0.1:" + std::to_string(occupied_port);
	v.interfaces[0] = occupied_interface.c_str();
	const auto interface_failure = admin->apply_plugin_mysql_config(v.plan);
	char* after_interface_failure = GloMTH->get_variable("interfaces");
	ok(occupied_fd >= 0 && !interface_failure.applied &&
		interface_failure.message.find("cannot add MySQL listener") != std::string::npos &&
		scalar(v.db, "SELECT generation FROM proxysql_plugin_config_generations WHERE owner='mysql_router'") == 13 &&
		GloMyAuth->get_current_mysql_users()->raw_checksum() == stable_auth_checksum &&
		MyHGM->get_current_mysql_table("cluster_mysql_servers")->raw_checksum() == stable_server_checksum &&
		GloMyQPro->get_current_query_rules_inner()->raw_checksum() == stable_rule_checksum &&
		after_interface_failure != nullptr && new_interface == after_interface_failure &&
		can_connect_loopback(new_port),
		"a real interface failure reverses QPro, Auth, and HGM and restores the prior listener");
	free(after_interface_failure);
	if (occupied_fd >= 0) close(occupied_fd);
	v.interfaces[0] = new_interface.c_str();

	const pid_t auth_exception_pid = fork();
	if (auth_exception_pid == 0) {
		alarm(5);
		const uint64_t checksum_version_before = GloVars.checksums_values.mysql_users.version;
		AuthMidpointThrowOnce midpoint;
		bool exception_crossed_admin = false;
		ProxySQL_PluginMysqlConfigResult failed_publish;
		try {
			mysql_authentication_test::scoped_atomic_replace_hook hook(
				&AuthMidpointThrowOnce::hook, &midpoint);
			failed_publish = admin->apply_plugin_mysql_config(v.plan);
		} catch (...) {
			exception_crossed_admin = true;
		}
		account_details_t old_user = GloMyAuth->lookup(const_cast<char*>("router_app"),
			USERNAME_FRONTEND, {true, true, true});
		const bool old_state_intact = old_user.password != nullptr &&
			std::string(old_user.password) == "new-secret" && old_user.default_hostgroup == 8100 &&
			old_user.max_connections == 500 && GloMyAuth->get_current_mysql_users() != nullptr &&
			GloMyAuth->get_current_mysql_users()->raw_checksum() == stable_auth_checksum;
		free_account_details(old_user);
		const uint64_t checksum_version_after_restore = GloVars.checksums_values.mysql_users.version;
		const bool generations_rolled_back =
			scalar(v.db, "SELECT generation FROM proxysql_plugin_config_generations "
				"WHERE owner='mysql_router'") == 13 &&
			scalar(v.db, "SELECT generation FROM disk.proxysql_plugin_config_generations "
				"WHERE owner='mysql_router'") == 13;
		const auto retry_publish = admin->apply_plugin_mysql_config(v.plan);
		account_details_t new_user = GloMyAuth->lookup(const_cast<char*>("router_app"),
			USERNAME_FRONTEND, {true, true, true});
		const bool retry_loaded_users = new_user.password != nullptr &&
			std::string(new_user.password) == "must-rollback";
		free_account_details(new_user);
		const bool generations_published =
			scalar(v.db, "SELECT generation FROM proxysql_plugin_config_generations "
				"WHERE owner='mysql_router'") == 14 &&
			scalar(v.db, "SELECT generation FROM disk.proxysql_plugin_config_generations "
				"WHERE owner='mysql_router'") == 14;
		const bool complete = !exception_crossed_admin && !failed_publish.applied &&
			failed_publish.message.find("exception") != std::string::npos && midpoint.calls >= 2 &&
			generations_rolled_back && old_state_intact &&
			checksum_version_after_restore == checksum_version_before && retry_publish.applied &&
			retry_publish.generation == 14 && generations_published && retry_loaded_users &&
			GloVars.checksums_values.mysql_users.version > checksum_version_after_restore;
		_exit(complete ? 0 : 1);
	}
	int auth_exception_status = 0;
	const bool auth_exception_waited = auth_exception_pid > 0 &&
		waitpid(auth_exception_pid, &auth_exception_status, 0) == auth_exception_pid;
	ok(auth_exception_waited && WIFEXITED(auth_exception_status) &&
		WEXITSTATUS(auth_exception_status) == 0,
		"a real Auth midpoint exception completes reverse checksum restore and releases every publication lock");

	ProxySQL_PluginMysqlUserRow live_backend_only {
		"split_live", "plugin-live-v1", true, false, 8100, "appdb", false, true, false,
		false, true, 90, "{}", "mysql_router:managed"};
	v.plan.generation = 14;
	v.plan.users = &live_backend_only;
	v.plan.user_count = 1;
	const auto live_variant_initial = admin->apply_plugin_mysql_config(v.plan);
	ok(live_variant_initial.applied &&
		v.db.execute("INSERT INTO main.mysql_users VALUES "
			"('split_live','operator-live',1,0,10,'',0,1,0,0,1,88,'{}','operator')") &&
		v.db.execute("INSERT INTO disk.mysql_users VALUES "
			"('split_live','operator-live',1,0,10,'',0,1,0,0,1,88,'{}','operator')"),
		"the live fixture adds an operator frontend variant after plugin backend ownership");
	live_backend_only.password = "plugin-live-v2"; // NOSONAR: synthetic test credential.
	v.plan.generation = 15;
	const auto live_variant_replaced = admin->apply_plugin_mysql_config(v.plan);
	account_details_t live_backend = GloMyAuth->lookup(
		const_cast<char*>("split_live"), USERNAME_BACKEND, {true, true, true});
	account_details_t live_frontend = GloMyAuth->lookup(
		const_cast<char*>("split_live"), USERNAME_FRONTEND, {true, true, true});
	const bool live_replacement_exact = live_backend.password != nullptr && live_frontend.password != nullptr &&
		std::string(live_backend.password) == "plugin-live-v2" &&
		std::string(live_frontend.password) == "operator-live";
	free_account_details(live_backend);
	free_account_details(live_frontend);
	ok(live_variant_replaced.applied && live_replacement_exact &&
		text_value(v.db, "SELECT password FROM main.mysql_users WHERE username='split_live' AND backend=0") ==
			"operator-live" &&
		text_value(v.db, "SELECT password FROM disk.mysql_users WHERE username='split_live' AND backend=0") ==
			"operator-live",
		"replacement preserves the complementary operator variant in main, disk, and live Auth");
	v.plan.generation = 16;
	v.plan.users = nullptr;
	v.plan.user_count = 0;
	const auto live_variant_removed = admin->apply_plugin_mysql_config(v.plan);
	account_details_t removed_backend = GloMyAuth->lookup(
		const_cast<char*>("split_live"), USERNAME_BACKEND, {true, true, true});
	account_details_t surviving_frontend = GloMyAuth->lookup(
		const_cast<char*>("split_live"), USERNAME_FRONTEND, {true, true, true});
	const bool live_removal_exact = removed_backend.password == nullptr && surviving_frontend.password != nullptr &&
		std::string(surviving_frontend.password) == "operator-live";
	free_account_details(removed_backend);
	free_account_details(surviving_frontend);
	ok(live_variant_removed.applied && live_removal_exact &&
		scalar(v.db, "SELECT COUNT(*) FROM main.mysql_users WHERE username='split_live' AND backend=1") == 0 &&
		text_value(v.db, "SELECT password FROM main.mysql_users WHERE username='split_live' AND backend=0") ==
			"operator-live" &&
		scalar(v.db, "SELECT COUNT(*) FROM disk.mysql_users WHERE username='split_live' AND backend=1") == 0 &&
		text_value(v.db, "SELECT password FROM disk.mysql_users WHERE username='split_live' AND backend=0") ==
			"operator-live",
		"removal deletes only the plugin variant from main, disk, and live Auth");

	ProxySQL_PluginMysqlRuleAttributesRow live_v2_attribute {
		9000, "{\"switch_to_fast_forward\":true}"
	};
	v.plan.generation = 17;
	ProxySQL_PluginMysqlConfigPlanV2 live_v2_plan {v.plan, &live_v2_attribute, 1};
	const auto live_v2_result = admin->apply_plugin_mysql_config_v2(live_v2_plan);
	std::unique_ptr<SQLite3_result> live_rules(GloMyQPro->get_current_query_rules());
	SQLite3_row* live_rule = result_row(live_rules.get(), 0, "9000");
	ok(live_v2_result.applied && live_v2_result.generation == 17 &&
		text_value(v.db, "SELECT attributes FROM main.mysql_query_rules WHERE rule_id=9000") ==
			"{\"switch_to_fast_forward\":true}" &&
		text_value(v.db, "SELECT attributes FROM disk.mysql_query_rules WHERE rule_id=9000") ==
			"{\"switch_to_fast_forward\":true}" &&
		live_rule != nullptr && live_rule->fields[33] != nullptr &&
		std::string(live_rule->fields[33]) == "{\"switch_to_fast_forward\":true}",
		"the live Admin V2 service publishes exact attributes to main, disk, and QPro");

	bool misleading_legacy_seeded = true;
	for (const char* schema : {"main", "disk"}) {
		const std::string prefix = std::string(schema) + ".";
		misleading_legacy_seeded = misleading_legacy_seeded &&
			v.db.execute(("INSERT INTO " + prefix + "mysql_users VALUES "
				"('A','operator-a',1,0,10,'',0,1,0,1,0,100,'{}','operator')").c_str()) &&
			v.db.execute(("INSERT INTO " + prefix + "proxysql_plugin_owned_objects VALUES "
				"('mysql_router','mysql_user','v2:1:0:41',17)").c_str());
	}
	auto misleading_legacy_users = result_value(v.db,
		"SELECT username,password,use_ssl,default_hostgroup,default_schema,schema_locked,"
		"transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment "
		"FROM mysql_users ORDER BY username,backend DESC");
	admin->init_users(std::move(misleading_legacy_users));
	account_details_t operator_a_before = GloMyAuth->lookup(
		const_cast<char*>("A"), USERNAME_BACKEND, {true, true, true});
	const bool operator_a_live_before = operator_a_before.password != nullptr &&
		std::string(operator_a_before.password) == "operator-a";
	free_account_details(operator_a_before);
	ok(misleading_legacy_seeded && operator_a_live_before &&
		scalar(v.db, "SELECT COUNT(*) FROM main.mysql_users WHERE username='v2:1:0:41'") == 0 &&
		scalar(v.db, "SELECT COUNT(*) FROM disk.mysql_users WHERE username='v2:1:0:41'") == 0,
		"the live fixture seeds an encoded-looking legacy ledger beside unrelated operator user A");
	v.plan.generation = 18;
	const auto misleading_legacy_result = admin->apply_plugin_mysql_config(v.plan);
	account_details_t operator_a_after = GloMyAuth->lookup(
		const_cast<char*>("A"), USERNAME_BACKEND, {true, true, true});
	const bool operator_a_live_after = operator_a_after.password != nullptr &&
		std::string(operator_a_after.password) == "operator-a";
	free_account_details(operator_a_after);
	ok(!misleading_legacy_result.applied &&
		misleading_legacy_result.message.find("ambiguous") != std::string::npos &&
		scalar(v.db, "SELECT generation FROM main.proxysql_plugin_config_generations "
			"WHERE owner='mysql_router'") == 17 &&
		scalar(v.db, "SELECT generation FROM disk.proxysql_plugin_config_generations "
			"WHERE owner='mysql_router'") == 17 &&
		text_value(v.db, "SELECT password FROM main.mysql_users WHERE username='A' AND backend=1") ==
			"operator-a" &&
		text_value(v.db, "SELECT password FROM disk.mysql_users WHERE username='A' AND backend=1") ==
			"operator-a" &&
		operator_a_live_after,
		"an encoded-looking legacy ledger fails closed and preserves operator A in main, disk, and live Auth");
	ev_async_stop(MyHGM->gtid_ev_loop, MyHGM->gtid_ev_async);
	ev_loop_destroy(MyHGM->gtid_ev_loop);
	MyHGM->gtid_ev_loop = nullptr;
	GloProxyStats = nullptr;

	return exit_status();
}
