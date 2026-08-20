#ifdef PROXYSQL_ROUTER_CONTRACT_FAKE

#include "ProxySQL_Plugin.h"

#include <cstring>
#include <string>
#include <vector>

namespace {

ProxySQL_PluginServices* g_services = nullptr;
std::string g_events;
bool g_secret_round_trip = false;

void record(const char* event) {
	if (!g_events.empty()) g_events += ',';
	g_events += event;
}

bool register_cli_options(ProxySQL_PluginCLIRegistry* registry) {
	if (registry == nullptr || registry->add == nullptr) return false;
	const ProxySQL_PluginCLIOptionDef option {
		"", "--fake-plugin-action", 1, false,
		"Exercise the Router chassis contract"
	};
	const char* error = nullptr;
	if (!registry->add(registry->opaque, option, &error)) return false;
	record("register_cli");
	return true;
}

bool register_schemas(ProxySQL_PluginServices* services) {
	if (services == nullptr || services->register_table == nullptr) return false;
	const ProxySQL_PluginTableDef table {
		ProxySQL_PluginDBKind::config_db,
		"router_contract_fake_state",
		"CREATE TABLE router_contract_fake_state (name TEXT PRIMARY KEY, value TEXT NOT NULL)"
	};
	services->register_table(table);
	record("register_schemas");
	return true;
}

ProxySQL_PluginEarlyActionResult early_action(
	const ProxySQL_PluginEarlyActionContext& context) {
	if (context.services == nullptr || context.is_set == nullptr ||
		context.get_string == nullptr ||
		!context.is_set(context.option_context, "--fake-plugin-action")) {
		return ProxySQL_PluginEarlyActionResult::exit_failure;
	}
	std::string action;
	if (!context.get_string(context.option_context, "--fake-plugin-action", action) ||
		action != "bootstrap") {
		return ProxySQL_PluginEarlyActionResult::exit_failure;
	}
	g_services = context.services;
	const uint8_t secret[] {'r', 'o', 'u', 't', 'e', 'r'};
	std::vector<uint8_t> round_trip;
	g_secret_round_trip = g_services->put_secret != nullptr &&
		g_services->get_secret != nullptr &&
		g_services->put_secret("router_contract_fake", "metadata_password",
			secret, sizeof(secret)) == ProxySQL_PluginSecretResult::ok &&
		g_services->get_secret("router_contract_fake", "metadata_password",
			round_trip) == ProxySQL_PluginSecretResult::ok &&
		round_trip.size() == sizeof(secret) &&
		std::memcmp(round_trip.data(), secret, sizeof(secret)) == 0;
	record("early_action");
	return g_secret_round_trip
		? ProxySQL_PluginEarlyActionResult::continue_startup
		: ProxySQL_PluginEarlyActionResult::exit_failure;
}

bool init(ProxySQL_PluginServices* services) {
	g_services = services;
	record("init");
	return services != nullptr;
}

bool start() {
	record("start");
	return g_services != nullptr;
}

bool runtime_ready(ProxySQL_PluginRuntimeContext* context) {
	if (context == nullptr || context->services == nullptr) return false;
	g_services = context->services;
	record("runtime_ready");
	return true;
}

bool stop() {
	record("stop");
	return true;
}

const char* status_json() {
	return "{\"name\":\"router_contract_fake\",\"state\":\"running\"}";
}

const ProxySQL_PluginDescriptor descriptor {
	"router_contract_fake",
	8,
	&init,
	&start,
	&stop,
	&status_json,
	&register_schemas,
	&register_cli_options,
	&early_action,
	&runtime_ready,
};

} // namespace

extern "C" const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1() {
	return &descriptor;
}

extern "C" ProxySQL_PluginServices* proxysql_router_contract_services() {
	return g_services;
}

extern "C" const char* proxysql_router_contract_events() {
	return g_events.c_str();
}

extern "C" bool proxysql_router_contract_secret_round_trip() {
	return g_secret_round_trip;
}

#else

#include "ProxySQL_PluginCLI.h"
#include "ProxySQL_PluginListenerGate.h"
#include "ProxySQL_PluginManager.h"
#include "ProxySQL_PluginSecrets.h"
#include "MySQL_Authentication.hpp"
#include "MySQL_HostGroups_Manager.h"
#include "MySQL_Monitor.hpp"
#include "MySQL_Query_Processor.h"
#include "MySQL_Thread.h"
#include "ProxySQL_Statistics.hpp"
#include "proxysql_admin.h"
#include "proxysql_glovars.hpp"
#include "sqlite3db.h"
#include "tap.h"
#include "test_init.h"

#include <arpa/inet.h>
#include <dlfcn.h>
#include <fstream>
#include <memory>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#ifndef PROXYSQL_ROUTER_CONTRACT_FAKE_PATH
#error "PROXYSQL_ROUTER_CONTRACT_FAKE_PATH must be defined"
#endif

extern MySQL_Authentication* GloMyAuth;
extern MySQL_HostGroups_Manager* MyHGM;
extern MySQL_Query_Processor* GloMyQPro;
extern MySQL_Monitor* GloMyMon;
extern ProxySQL_Statistics* GloProxyStats;
extern MySQL_Threads_Handler* GloMTH;
extern ProxySQL_Admin* GloAdmin;
extern ProxySQL_GlobalVariables GloVars;

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
constexpr const char* k_fast_rules =
	"CREATE TABLE mysql_query_rules_fast_routing (username TEXT, schemaname TEXT, flagIN INT, "
	"destination_hostgroup INT, comment TEXT, PRIMARY KEY(username,schemaname,flagIN))";
constexpr const char* k_globals =
	"CREATE TABLE global_variables (variable_name TEXT PRIMARY KEY, variable_value TEXT NOT NULL)";
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

struct ArgV {
	std::vector<std::string> values;
	std::vector<const char*> argv;

	ArgV(std::initializer_list<std::string> input) : values(input) {
		for (const auto& value : values) argv.push_back(value.c_str());
	}
};

std::string make_temp_dir() {
	char path[] = "/tmp/proxysql_router_contract.XXXXXX";
	return mkdtemp(path) == nullptr ? "" : path;
}

std::string parent_directory(const std::string& path) {
	const size_t slash = path.rfind('/');
	return slash == std::string::npos ? "." : path.substr(0, slash);
}

std::string canonical(const std::string& path) {
	char* resolved = realpath(path.c_str(), nullptr);
	if (resolved == nullptr) return {};
	std::string result(resolved);
	free(resolved);
	return result;
}

long long scalar(SQLite3DB& db, const std::string& sql) {
	char* error = nullptr;
	int columns = 0;
	int affected = 0;
	SQLite3_result* result = nullptr;
	db.execute_statement(sql.c_str(), &error, &columns, &affected, &result);
	if (error != nullptr) {
		free(error);
		delete result;
		return -1;
	}
	const long long value = result != nullptr && !result->rows.empty() &&
		result->rows[0]->fields[0] != nullptr
		? std::strtoll(result->rows[0]->fields[0], nullptr, 10) : 0;
	delete result;
	return value;
}

std::unique_ptr<SQLite3_result> result_value(SQLite3DB& db, const std::string& sql) {
	char* error = nullptr;
	int columns = 0;
	int affected = 0;
	SQLite3_result* result = nullptr;
	db.execute_statement(sql.c_str(), &error, &columns, &affected, &result);
	free(error);
	return std::unique_ptr<SQLite3_result>(result);
}

SQLite3_row* result_row(SQLite3_result* result, int column, const std::string& value) {
	if (result == nullptr || column < 0 || column >= result->columns) return nullptr;
	for (SQLite3_row* row : result->rows) {
		if (row != nullptr && row->fields[column] != nullptr && value == row->fields[column]) {
			return row;
		}
	}
	return nullptr;
}

bool create_publication_schema(SQLite3DB& db) {
	for (const char* schema : {"", "disk."}) {
		for (const char* ddl : {k_ledger, k_generations, k_servers, k_repl, k_gr,
			k_attrs, k_users, k_rules, k_fast_rules, k_globals}) {
			std::string sql(ddl);
			const size_t table = sql.find("TABLE ");
			sql.insert(table + 6, schema);
			if (!db.execute(sql.c_str())) return false;
		}
	}
	return db.execute(k_galera) && db.execute(k_aurora) && db.execute(k_rds) &&
		db.execute(k_ssl_params);
}

bool seed_unrelated_rows(SQLite3DB& db, const std::string& operator_interface) {
	for (const char* schema : {"main", "disk"}) {
		const std::string prefix(schema);
		if (!db.execute(("INSERT INTO " + prefix + ".mysql_servers VALUES "
			"(10,'operator-server',3306,0,'ONLINE',1,0,100,0,0,0,'operator')").c_str()) ||
			!db.execute(("INSERT INTO " + prefix + ".mysql_users VALUES "
			"('operator_user','operator-secret',1,0,10,'operator_db',0,1,0,1,1,100,'{}','operator')").c_str()) ||
			!db.execute(("INSERT INTO " + prefix +
			".mysql_query_rules(rule_id,active,flagIN,proxy_port,negate_match_pattern,re_modifiers,"
			"destination_hostgroup,apply,attributes,comment) VALUES "
			"(5,1,0,6033,0,'CASELESS',10,1,'','operator')").c_str()) ||
			!db.execute(("INSERT INTO " + prefix + ".global_variables VALUES "
			"('mysql-interfaces','" + operator_interface + "')").c_str())) {
			return false;
		}
	}
	return true;
}

int reserve_loopback_port() {
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) return 0;
	sockaddr_in address {};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = 0;
	if (bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0) {
		close(fd);
		return 0;
	}
	socklen_t size = sizeof(address);
	const bool named = getsockname(fd, reinterpret_cast<sockaddr*>(&address), &size) == 0;
	const int port = named ? ntohs(address.sin_port) : 0;
	close(fd);
	return port;
}

void live_gtid_async_noop(struct ev_loop*, struct ev_async*, int) {}

struct FakeControl {
	using services_fn = ProxySQL_PluginServices* (*)();
	using events_fn = const char* (*)();
	using secret_fn = bool (*)();

	void* handle {nullptr};
	services_fn services {nullptr};
	events_fn events {nullptr};
	secret_fn secret_round_trip {nullptr};

	bool open(const std::string& path) {
		handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
		if (handle == nullptr) return false;
		services = reinterpret_cast<services_fn>(
			dlsym(handle, "proxysql_router_contract_services"));
		events = reinterpret_cast<events_fn>(
			dlsym(handle, "proxysql_router_contract_events"));
		secret_round_trip = reinterpret_cast<secret_fn>(
			dlsym(handle, "proxysql_router_contract_secret_round_trip"));
		return services != nullptr && events != nullptr && secret_round_trip != nullptr;
	}

	~FakeControl() {
		if (handle != nullptr) dlclose(handle);
	}
};

} // namespace

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(NO_PLAN);
	ok(test_init_minimal() == 0, "minimal core globals initialize");

	const std::string temp_dir = make_temp_dir();
	const std::string config_path = temp_dir + "/proxysql.cnf";
	std::ofstream(config_path) << "";
	const std::string plugin_dir = parent_directory(PROXYSQL_ROUTER_CONTRACT_FAKE_PATH);
	ArgV discovery_args {
		"proxysql", "--config", config_path, "--plugin-dir", plugin_dir,
		"--load-plugin", "router_contract_fake"
	};
	const auto found = proxysql_prescan_plugins(
		static_cast<int>(discovery_args.argv.size()), discovery_args.argv.data(),
		nullptr, plugin_dir.c_str());
	ok(found.error.empty() && found.module_paths.size() == 1 &&
		found.module_paths.front() == canonical(PROXYSQL_ROUTER_CONTRACT_FAKE_PATH),
		"logical plugin name resolves through the production named-plugin path");

	std::unique_ptr<ProxySQL_PluginManager> manager;
	std::string error;
	ok(proxysql_discover_configured_plugins(manager, found.module_paths, error) &&
		manager != nullptr && manager->size() == 1,
		"the named ABI-8 contract fake is discovered (err='%s')", error.c_str());
	FakeControl fake;
	ok(fake.open(found.module_paths.front()),
		"minimal test-control exports resolve from the discovered module");

	ez::ezOptionParser parser;
	ok(proxysql_register_configured_plugin_cli(manager.get(), parser, error),
		"the fake registers its ABI-6 command-line option (err='%s')", error.c_str());
	ArgV parsed_args {"proxysql", "--fake-plugin-action", "bootstrap"};
	parser.parse(static_cast<int>(parsed_args.argv.size()), parsed_args.argv.data());
	std::string action;
	parser.get("--fake-plugin-action")->getString(action);
	ok(action == "bootstrap", "the definitive parser owns the fake action value");
	ok(proxysql_register_configured_plugin_schemas(manager.get(), error) &&
		manager->tables(ProxySQL_PluginDBKind::config_db).size() == 1,
		"schema registration records the fake config table (err='%s')", error.c_str());
	ok(std::string(fake.events()) == "register_cli,register_schemas",
		"discovery callbacks run in CLI then schema order");

	SQLite3DB admindb;
	SQLite3DB configdb;
	SQLite3DB statsdb;
	admindb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	configdb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	statsdb.open(const_cast<char*>(":memory:"), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	const bool databases_created = admindb.execute("ATTACH DATABASE ':memory:' AS disk") &&
		create_publication_schema(admindb);
	bool plugin_schema_created = databases_created;
	for (const auto& table : manager->tables(ProxySQL_PluginDBKind::config_db)) {
		plugin_schema_created = plugin_schema_created && configdb.execute(table.table_def);
	}
	plugin_schema_created = plugin_schema_created &&
		configdb.execute(proxysql_plugin_secrets_table_definition());
	ok(plugin_schema_created && scalar(configdb,
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='router_contract_fake_state'") == 1,
		"Admin DBs materialize the plugin and built-in secret schemas");

	const int operator_port = reserve_loopback_port();
	const int fake_port = reserve_loopback_port();
	const std::string operator_interface = "127.0.0.1:" + std::to_string(operator_port);
	const std::string fake_interface = "127.0.0.1:" + std::to_string(fake_port);
	ok(operator_port > 0 && fake_port > 0 && operator_port != fake_port &&
		seed_unrelated_rows(admindb, operator_interface),
		"unrelated operator rows and a distinct fake listener port are seeded");

	char statsdb_path[] = ":memory:";
	GloVars.statsdb_disk = statsdb_path;
	auto proxy_stats = std::make_unique<ProxySQL_Statistics>();
	GloProxyStats = proxy_stats.get();
	GloProxyStats->init();
	ProxySQL_Admin* admin = new ProxySQL_Admin();
	admin->admindb = &admindb;
	admin->configdb = &configdb;
	admin->statsdb = &statsdb;
	GloAdmin = admin;
	GloVars.datadir = const_cast<char*>(temp_dir.c_str());
	ProxySQL_PluginParsedOptionContext parsed_options(parser);
	const auto action_result = proxysql_run_configured_plugin_early_actions(
		manager.get(), parsed_options.early_action_context(config_path.c_str(), temp_dir.c_str()), error);
	ok(action_result == ProxySQL_PluginEarlyActionResult::not_requested ||
		action_result == ProxySQL_PluginEarlyActionResult::continue_startup,
		"the aggregate early-action result continues normal startup");
	ok(fake.secret_round_trip() && scalar(configdb,
			"SELECT COUNT(*) FROM proxysql_plugin_secrets WHERE owner='router_contract_fake' "
			"AND secret_name='metadata_password'") == 1,
		"the bootstrap action stores and reads its encrypted secret");

	const bool modules_ready = test_init_auth() == 0 && test_init_query_processor() == 0 &&
		test_init_hostgroups() == 0;
	GloMyMon = new MySQL_Monitor();
	MyHGM->gtid_ev_loop = ev_loop_new(EVBACKEND_POLL | EVFLAG_NOENV);
	ev_async_init(MyHGM->gtid_ev_async, live_gtid_async_noop);
	ev_async_start(MyHGM->gtid_ev_loop, MyHGM->gtid_ev_async);
	const bool listener_ready = modules_ready &&
		GloMTH->set_variable("caching_sha2_password_auto_generate_rsa_keys", "false") &&
		GloMTH->set_variable("caching_sha2_password_private_key_path", "") &&
		GloMTH->set_variable("caching_sha2_password_public_key_path", "") &&
		GloMTH->set_variable("interfaces", operator_interface.c_str()) &&
		GloMTH->listener_add(operator_interface.c_str()) >= 0;
	ok(listener_ready, "real Auth, HGM, QPro, MTH, monitor, and operator listener initialize");

	auto live_users = result_value(admindb,
		"SELECT username,password,use_ssl,default_hostgroup,default_schema,schema_locked,"
		"transaction_persistent,fast_forward,backend,frontend,max_connections,attributes,comment "
		"FROM main.mysql_users ORDER BY username,backend DESC");
	GloMyAuth->save_mysql_users(std::move(live_users));
	incoming_servers_t initial_hgm;
	initial_hgm.runtime_mysql_servers = result_value(admindb,
		"SELECT hostgroup_id,hostname,port,gtid_port,status,weight,compression,max_connections,"
		"max_replication_lag,use_ssl,max_latency_ms,comment FROM main.mysql_servers "
		"ORDER BY hostgroup_id,hostname,port").release();
	initial_hgm.incoming_replication_hostgroups = result_value(admindb,
		"SELECT writer_hostgroup,reader_hostgroup,check_type,comment "
		"FROM main.mysql_replication_hostgroups ORDER BY writer_hostgroup").release();
	initial_hgm.incoming_group_replication_hostgroups = result_value(admindb,
		"SELECT writer_hostgroup,backup_writer_hostgroup,reader_hostgroup,offline_hostgroup,active,"
		"max_writers,writer_is_also_reader,max_transactions_behind,comment "
		"FROM main.mysql_group_replication_hostgroups ORDER BY writer_hostgroup").release();
	initial_hgm.incoming_hostgroup_attributes = result_value(admindb,
		"SELECT hostgroup_id,max_num_online_servers,autocommit,free_connections_pct,init_connect,"
		"multiplex,connection_warming,throttle_connections_per_sec,ignore_session_variables,"
		"hostgroup_settings,servers_defaults,comment FROM main.mysql_hostgroup_attributes "
		"ORDER BY hostgroup_id").release();
	admin->mysql_servers_wrlock();
	const bool initial_hgm_loaded = admin->load_mysql_servers_to_runtime(initial_hgm);
	admin->mysql_servers_wrunlock();
	char* initial_rules_error = admin->load_mysql_query_rules_to_runtime();
	ok(initial_hgm_loaded && initial_rules_error == nullptr &&
		GloMyAuth->get_current_mysql_users() != nullptr,
		"real Admin adapters seed the initial Auth, HGM, and QPro snapshots");
	free(initial_rules_error);
	ok(proxysql_init_configured_plugins(manager.get(), error) &&
		proxysql_start_configured_plugins(manager.get(), error),
		"the fake initializes and starts after its continuing action (err='%s')", error.c_str());

	int owned_hostgroups[4] {8100, 8101, 8102, 8103};
	ProxySQL_PluginMysqlServerRow servers[2] {
		{8100, "writer-g1", 3306, 0, 0, 10, 0, 100, 0, false, 50, "router_contract_fake:writer"},
		{8101, "reader-g1", 3306, 0, 0, 10, 0, 100, 0, false, 50, "router_contract_fake:reader"},
	};
	ProxySQL_PluginMysqlGroupReplicationHostgroupRow group_replication[1] {
		{8100, 8102, 8101, 8103, true, 1, 0, 0, "router_contract_fake:gr"}
	};
	ProxySQL_PluginMysqlUserRow users[1] {
		{"router_app", "generation-one", true, false, 8100, "router_db", false,
			true, false, true, true, 100, "{}", "router_contract_fake:managed"}
	};
	ProxySQL_PluginMysqlRuleRow rules[1] {
		{9000, true, fake_port, "^SELECT", nullptr, false, "CASELESS", 8101, true,
			"router_contract_fake:read"}
	};
	const char* interfaces[1] {fake_interface.c_str()};
	ProxySQL_PluginMysqlConfigPlan generation {
		"router_contract_fake", 1, owned_hostgroups, 4, servers, 2,
		nullptr, 0, group_replication, 1, nullptr, 0, users, 1, rules, 1,
		interfaces, 1
	};
	ProxySQL_PluginServices* services = fake.services();
	const auto generation_one = services != nullptr && services->apply_mysql_config != nullptr
		? services->apply_mysql_config(generation)
		: ProxySQL_PluginMysqlConfigResult{};
	ok(generation_one.applied && generation_one.generation == 1,
		"the fake consumes the live service table to publish generation 1 (message='%s')",
		generation_one.message.c_str());

	const ProxySQL_PluginListenerGate closed_gate {
		"router_contract_fake", "127.0.0.1", static_cast<uint16_t>(fake_port),
		ProxySQL_PluginListenerState::closed, "waiting for generation 2"
	};
	const bool gate_closed = services != nullptr && services->set_listener_gate != nullptr &&
		services->set_listener_gate(closed_gate);
	const auto closed_snapshot = proxysql_plugin_listener_gate_lookup(
		"127.0.0.1", static_cast<uint16_t>(fake_port));
	ok(gate_closed && closed_snapshot &&
		closed_snapshot->state == ProxySQL_PluginListenerState::closed &&
		closed_snapshot->reason == "waiting for generation 2",
		"the fake listener is closed while generation 2 is reconciled");

	ProxySQL_PluginRuntimeContext runtime_context {nullptr, 123456};
	ok(proxysql_runtime_ready_configured_plugins(manager.get(), runtime_context, error) &&
		std::string(fake.events()) ==
		"register_cli,register_schemas,early_action,init,start,runtime_ready",
		"runtime readiness follows init and start exactly once (err='%s')", error.c_str());

	servers[0].hostname = "writer-g2";
	servers[1].hostname = "reader-g2";
	users[0].password = "generation-two";
	generation.generation = 2;
	const auto generation_two = services->apply_mysql_config(generation);
	ok(generation_two.applied && generation_two.generation == 2,
		"the real publisher replaces generation 1 with generation 2 (message='%s')",
		generation_two.message.c_str());

	const ProxySQL_PluginListenerGate ready_gate {
		"router_contract_fake", "127.0.0.1", static_cast<uint16_t>(fake_port),
		ProxySQL_PluginListenerState::ready, "generation 2 published"
	};
	const bool gate_ready = services->set_listener_gate(ready_gate);
	const auto ready_snapshot = proxysql_plugin_listener_gate_lookup(
		"127.0.0.1", static_cast<uint16_t>(fake_port));
	ok(gate_ready && ready_snapshot &&
		ready_snapshot->state == ProxySQL_PluginListenerState::ready,
		"the fake listener opens only after generation 2 is live");

	auto live_users_snapshot = std::unique_ptr<SQLite3_result>(
		services->get_mysql_users_snapshot());
	auto live_servers_snapshot = std::unique_ptr<SQLite3_result>(
		services->get_mysql_servers_snapshot());
	auto live_gr_snapshot = std::unique_ptr<SQLite3_result>(
		services->get_mysql_group_replication_hostgroups_snapshot());
	SQLite3_row* live_router_user = result_row(live_users_snapshot.get(), 0, "router_app");
	ok(live_users_snapshot && live_servers_snapshot && live_gr_snapshot &&
		live_router_user != nullptr && live_router_user->fields[1] != nullptr &&
		std::string(live_router_user->fields[1]) == "generation-two" &&
		result_row(live_servers_snapshot.get(), 1, "writer-g2") != nullptr &&
		result_row(live_servers_snapshot.get(), 1, "reader-g2") != nullptr &&
		result_row(live_servers_snapshot.get(), 1, "writer-g1") == nullptr &&
		result_row(live_gr_snapshot.get(), 0, "8100") != nullptr,
		"all caller-owned live snapshots expose only generation 2 state");

	ok(scalar(admindb,
		"SELECT COUNT(*) FROM main.proxysql_plugin_config_generations "
		"WHERE owner='router_contract_fake' AND generation=2") == 1 &&
		scalar(admindb,
		"SELECT COUNT(*) FROM disk.proxysql_plugin_config_generations "
		"WHERE owner='router_contract_fake' AND generation=2") == 1 &&
		scalar(admindb,
		"SELECT COUNT(DISTINCT generation) FROM main.proxysql_plugin_owned_objects "
		"WHERE owner='router_contract_fake'") == 1 &&
		scalar(admindb,
		"SELECT MIN(generation) FROM main.proxysql_plugin_owned_objects "
		"WHERE owner='router_contract_fake'") == 2,
		"main, disk, and the ownership ledger retain one active generation");

	ok(scalar(admindb,
		"SELECT COUNT(*) FROM main.mysql_servers WHERE hostgroup_id=10 AND hostname='operator-server'") == 1 &&
		scalar(admindb,
		"SELECT COUNT(*) FROM disk.mysql_servers WHERE hostgroup_id=10 AND hostname='operator-server'") == 1 &&
		scalar(admindb,
		"SELECT COUNT(*) FROM main.mysql_users WHERE username='operator_user'") == 1 &&
		scalar(admindb,
		"SELECT COUNT(*) FROM disk.mysql_users WHERE username='operator_user'") == 1 &&
		scalar(admindb,
		"SELECT COUNT(*) FROM main.mysql_query_rules WHERE rule_id=5") == 1 &&
		scalar(admindb,
		"SELECT COUNT(*) FROM disk.mysql_query_rules WHERE rule_id=5") == 1 &&
		result_row(live_users_snapshot.get(), 0, "operator_user") != nullptr &&
		result_row(live_servers_snapshot.get(), 1, "operator-server") != nullptr,
		"unrelated operator rows survive both publications in storage and runtime");

	ok(manager->stop_all(), "the configured fake stops cleanly");
	ok(std::string(fake.events()) ==
		"register_cli,register_schemas,early_action,init,start,runtime_ready,stop",
		"the complete ABI-8 callback order is exact");
	ok(!proxysql_plugin_listener_gate_lookup(
		"127.0.0.1", static_cast<uint16_t>(fake_port)).has_value(),
		"stopping the plugin removes its owned listener gate");
	manager.reset();
	ev_async_stop(MyHGM->gtid_ev_loop, MyHGM->gtid_ev_async);
	ev_loop_destroy(MyHGM->gtid_ev_loop);
	MyHGM->gtid_ev_loop = nullptr;
	GloProxyStats = nullptr;
	(void)unlink((temp_dir + "/proxysql-plugin-secrets.key").c_str());
	(void)unlink(config_path.c_str());
	(void)rmdir(temp_dir.c_str());
	return exit_status();
}

#endif
