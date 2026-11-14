/*
 * Focused Admin/plugin tests for the native TCP proxy.
 *
 * The test binary links the real SQLite3DB wrapper and an isolated in-memory
 * database, but replaces the frozen Engine with a deterministic test double.
 * Production DSO verification uses the real Engine sources copied by the
 * coordinator; this target intentionally does not link a second production
 * relay.
 */

#include "tap.h"

#include "tcp_proxy_plugin.h"

#include "ProxySQL_PluginRawBackend.h"

#include "sqlite3db.h"

#include "prometheus/counter.h"
#include "prometheus/gauge.h"
#include "prometheus/registry.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

extern "C" const ProxySQL_PluginDescriptor* proxysql_plugin_descriptor_v1();

/* Minimal TAP noise-injection hooks used by test/tap/tap/tap.cpp. */
std::vector<std::string> noise_failures;
std::mutex noise_failure_mutex;
extern "C" int get_noise_tools_count() { return 0; }
extern "C" void stop_noise_tools() {}

extern "C" void proxy_error_func(int, const char* fmt, ...) {
	va_list args;
	va_start(args, fmt);
	vfprintf(stderr, fmt, args);
	va_end(args);
}

/* ------------------------------------------------------------------------- */
/* Deterministic Engine test double.                                         */
/* ------------------------------------------------------------------------- */

namespace tcp_proxy {

struct Engine::Impl {};

struct FakeEngine {
	std::mutex mutex;
	std::condition_variable cv;
	tcp_proxy::Config config;
	tcp_proxy::Snapshot snapshot;
	bool fail_start { false };
	bool fail_apply { false };
	bool block_apply { false };
	bool apply_entered { false };
	bool release_apply { false };
	bool throw_snapshot { false };
	bool throw_config { false };
	bool generation_changes_every_read { false };
	int start_calls { 0 };
	int apply_calls { 0 };
	int stop_calls { 0 };
	uint64_t generation { 0 };
};

FakeEngine& fake() {
	static FakeEngine value;
	return value;
}

Engine::Engine() = default;
Engine::Engine(std::shared_ptr<BackendProvider>) {}
Engine::~Engine() = default;

bool Engine::start(const Config& config, std::string& error) {
	FakeEngine& state = fake();
	std::lock_guard<std::mutex> guard(state.mutex);
	++state.start_calls;
	if (state.fail_start) {
		error = "test start failure";
		return false;
	}
	state.config = config;
	state.snapshot = Snapshot {};
	state.snapshot.running = true;
	state.generation = 1;
	state.snapshot.generation = 1;
	error.clear();
	return true;
}

bool Engine::apply(const Config& config, std::string& error) {
	FakeEngine& state = fake();
	std::unique_lock<std::mutex> guard(state.mutex);
	++state.apply_calls;
	if (state.block_apply) {
		state.apply_entered = true;
		state.cv.notify_all();
		state.cv.wait(guard, [&state]() { return state.release_apply; });
	}
	if (state.fail_apply) {
		error = "test apply failure";
		return false;
	}
	state.config = config;
	++state.generation;
	state.snapshot.generation = state.generation;
	state.snapshot.running = true;
	error.clear();
	return true;
}

void Engine::stop() {
	FakeEngine& state = fake();
	std::lock_guard<std::mutex> guard(state.mutex);
	++state.stop_calls;
	state.snapshot.running = false;
}

Snapshot Engine::snapshot() const {
	FakeEngine& state = fake();
	std::lock_guard<std::mutex> guard(state.mutex);
	if (state.throw_snapshot) {
		throw std::runtime_error("test snapshot read failure");
	}
	if (state.generation_changes_every_read) {
		++state.generation;
		state.snapshot.generation = state.generation;
	}
	return state.snapshot;
}

Config Engine::config() const {
	FakeEngine& state = fake();
	std::lock_guard<std::mutex> guard(state.mutex);
	if (state.throw_config) {
		throw std::runtime_error("test config read failure");
	}
	return state.config;
}

bool Engine::running() const {
	FakeEngine& state = fake();
	std::lock_guard<std::mutex> guard(state.mutex);
	return state.snapshot.running;
}

bool validate_config(const Config& config, std::string& error) {
	std::set<int> hostgroups;
	for (const auto& hostgroup : config.hostgroups) {
		if (hostgroup.source_protocol != "MYSQL" &&
			hostgroup.source_protocol != "PGSQL") {
			error = "hostgroup source protocol must be MYSQL or PGSQL";
			return false;
		}
		if (hostgroup.source_hostgroup < 0) {
			error = "hostgroup source hostgroup must be nonnegative";
			return false;
		}
		if (!hostgroups.insert(hostgroup.hostgroup_id).second) {
			error = "duplicate hostgroup";
			return false;
		}
	}
	std::set<int> listeners;
	for (const auto& listener : config.listeners) listeners.insert(listener.listener_id);
	for (const auto& listener : config.listeners) {
		if (hostgroups.count(listener.default_hostgroup) == 0) {
			error = "listener references unknown hostgroup";
			return false;
		}
	}
	for (const auto& rule : config.rules) {
		if (rule.source_cidr.has_value() && rule.source_cidr->empty()) {
			error = "CIDR is empty";
			return false;
		}
		if (rule.listener_id.has_value() && listeners.count(*rule.listener_id) == 0) {
			error = "rule references unknown listener";
			return false;
		}
		if (rule.action == "ROUTE") {
			if (!rule.destination_hostgroup.has_value() ||
				hostgroups.count(*rule.destination_hostgroup) == 0) {
				error = "ROUTE references unknown destination hostgroup";
				return false;
			}
		} else if (rule.destination_hostgroup.has_value()) {
			error = "REJECT must have NULL destination_hostgroup";
			return false;
		}
	}
	error.clear();
	return true;
}

std::string listener_interfaces(const Config& config) {
	std::string out;
	for (const auto& listener : config.listeners) {
		if (listener.active != 1) continue;
		if (!out.empty()) out += ';';
		if (listener.bind_address.find(':') != std::string::npos) {
			out += "[" + listener.bind_address + "]:" + std::to_string(listener.bind_port);
		} else {
			out += listener.bind_address + ":" + std::to_string(listener.bind_port);
		}
	}
	return out;
}

} // namespace tcp_proxy

/* ------------------------------------------------------------------------- */
/* Fake plugin services and schema materialization.                          */
/* ------------------------------------------------------------------------- */

namespace {

struct FakeTable {
	ProxySQL_PluginDBKind kind;
	std::string name;
	std::string ddl;
};

struct FakeView {
	std::string name;
	void (*refresh)(SQLite3DB*, void*) { nullptr };
	ProxySQL_PluginDBKind kind { ProxySQL_PluginDBKind::admin_db };
};

struct FakeServices {
	SQLite3DB* db { nullptr };
	prometheus::Registry registry;
	std::vector<FakeTable> tables;
	std::map<std::string, proxysql_plugin_admin_command_cb> commands;
	std::vector<std::pair<std::string, std::string>> aliases;
	std::vector<FakeView> views;
	int admin_db_calls { 0 };
	int config_db_calls { 0 };
	int stats_db_calls { 0 };
	std::atomic<bool> listener_validation_ok { true };
	std::string listener_validation_error;
	std::string last_interfaces;
	std::atomic<int> admin_releases { 0 };
	std::atomic<int> admin_acquires { 0 };
	std::atomic<bool> admin_released { false };
	/* Models Admin's SQL lock so teardown can be tested while its caller owns
	 * the lock (the fast SHUTDOWN/KILL path). */
	std::mutex admin_db_mutex;
	std::atomic<int> with_admin_db_lock_calls { 0 };
	std::atomic<int> admin_db_lock_depth { 0 };
};

struct FakeRawState {
	ProxySQL_RawBackend* handle {
		reinterpret_cast<ProxySQL_RawBackend*>(static_cast<uintptr_t>(1)) };
	int acquire_calls { 0 };
	int destroy_calls { 0 };
	int connect_calls { 0 };
	int last_connect_errno { -1 };
	uint64_t sent { 0 };
	uint64_t received { 0 };
	bool hard { false };
	bool destroy_result { false };
	bool fail_acquire { false };
	std::string error { "fake raw acquire failure" };
	ProxySQL_RawBackendProtocol protocol {
		ProxySQL_RawBackendProtocol::mysql };
	uint32_t hostgroup { 0 };
	std::string address { "127.0.0.1" };
	uint16_t port { 3306 };
};

FakeRawState* g_raw = nullptr;

ProxySQL_RawBackend* fake_raw_acquire(ProxySQL_RawBackendProtocol protocol,
		uint32_t hostgroup, ProxySQL_RawBackendEndpoint& endpoint,
		std::string& error) {
	if (g_raw == nullptr) {
		error = "no fake raw state";
		return nullptr;
	}
	++g_raw->acquire_calls;
	g_raw->protocol = protocol;
	g_raw->hostgroup = hostgroup;
	if (g_raw->fail_acquire) {
		error = g_raw->error;
		return nullptr;
	}
	endpoint.address = g_raw->address;
	endpoint.port = g_raw->port;
	error.clear();
	return g_raw->handle;
}

void fake_raw_connect_result(ProxySQL_RawBackend*, int socket_errno) noexcept {
	if (g_raw != nullptr) {
		++g_raw->connect_calls;
		g_raw->last_connect_errno = socket_errno;
	}
}

void fake_raw_account_io(ProxySQL_RawBackend*, uint64_t sent,
		uint64_t received) noexcept {
	if (g_raw != nullptr) {
		g_raw->sent += sent;
		g_raw->received += received;
	}
}

bool fake_raw_offline_hard(const ProxySQL_RawBackend*) noexcept {
	return g_raw != nullptr && g_raw->hard;
}

bool fake_raw_destroy(ProxySQL_RawBackend*) noexcept {
	if (g_raw == nullptr) {
		return false;
	}
	++g_raw->destroy_calls;
	return g_raw->destroy_result;
}

ProxySQL_RawBackendServiceV2 fake_raw_service() {
	ProxySQL_RawBackendServiceV2 service {};
	service.version = 2;
	service.acquire = &fake_raw_acquire;
	service.connect_result = &fake_raw_connect_result;
	service.account_io = &fake_raw_account_io;
	service.offline_hard = &fake_raw_offline_hard;
	service.destroy = &fake_raw_destroy;
	return service;
}

ProxySQL_RawBackendServiceV2 g_default_raw_service = fake_raw_service();

const ProxySQL_RawBackendServiceV2* fake_get_raw_backend_service() {
	return &g_default_raw_service;
}

struct RawProviderFixture {
	FakeRawState raw;
	ProxySQL_RawBackendServiceV2 service { fake_raw_service() };

	RawProviderFixture() { g_raw = &raw; }
	~RawProviderFixture() { g_raw = nullptr; }

	std::shared_ptr<tcp_proxy::BackendProvider> provider() {
		return tcp_proxy_plugin::make_raw_backend_provider(&service);
	}
};

FakeServices* g_services = nullptr;

void fake_register_table(const ProxySQL_PluginTableDef& def) {
	if (g_services == nullptr) return;
	g_services->tables.push_back({ def.db_kind, def.table_name, def.table_def });
}

void fake_register_command(const char* sql, proxysql_plugin_admin_command_cb callback) {
	if (g_services == nullptr) return;
	g_services->commands.emplace(sql != nullptr ? sql : "", callback);
}

void fake_register_alias(const char* canonical, const char* alias) {
	if (g_services == nullptr) return;
	g_services->aliases.emplace_back(canonical != nullptr ? canonical : "",
		alias != nullptr ? alias : "");
}

bool fake_register_view(const ProxySQL_PluginRuntimeView& view) {
	if (g_services == nullptr) return false;
	g_services->views.push_back({ view.table_name != nullptr ? view.table_name : "",
		view.refresh, view.db_kind });
	return true;
}

SQLite3DB* fake_admindb() {
	if (g_services == nullptr) return nullptr;
	++g_services->admin_db_calls;
	return g_services->db;
}
SQLite3DB* fake_configdb() {
	if (g_services == nullptr) return nullptr;
	++g_services->config_db_calls;
	return g_services->db;
}
SQLite3DB* fake_statsdb() {
	if (g_services == nullptr) return nullptr;
	++g_services->stats_db_calls;
	return g_services->db;
}
prometheus::Registry* fake_registry() {
	return g_services != nullptr ? &g_services->registry : nullptr;
}
bool fake_with_admin_db_lock(bool (*body)(void*), void* opaque) {
	if (g_services == nullptr || body == nullptr) return false;
	FakeServices& env = *g_services;
	std::lock_guard<std::mutex> guard(env.admin_db_mutex);
	++env.with_admin_db_lock_calls;
	++env.admin_db_lock_depth;
	bool result = false;
	try {
		result = body(opaque);
	} catch (...) {
		result = false;
	}
	--env.admin_db_lock_depth;
	return result;
}
void fake_log(int level, const char* message) {
	fprintf(stderr, "plugin_log[%d]: %s\n", level, message != nullptr ? message : "(null)");
}

bool fake_validate_listener_interfaces(const char* owner, const char* interfaces,
		std::string& error) {
	if (g_services == nullptr) return false;
	if (owner == nullptr || std::strcmp(owner, "tcp_proxy") != 0) {
		error = "unexpected owner";
		return false;
	}
	g_services->last_interfaces = interfaces != nullptr ? interfaces : "";
	if (!g_services->listener_validation_ok.load()) {
		error = g_services->listener_validation_error;
		return false;
	}
	error.clear();
	return true;
}

void fake_release_admin(void* opaque) {
	auto* services = static_cast<FakeServices*>(opaque);
	if (services == nullptr) return;
	++services->admin_releases;
	services->admin_released.store(true);
}
void fake_acquire_admin(void* opaque) {
	auto* services = static_cast<FakeServices*>(opaque);
	if (services == nullptr) return;
	++services->admin_acquires;
	services->admin_released.store(false);
}

ProxySQL_PluginServices make_services(FakeServices& env) {
	ProxySQL_PluginServices services {};
	services.register_table = &fake_register_table;
	services.register_command = &fake_register_command;
	services.log_message = &fake_log;
	services.get_admindb = &fake_admindb;
	services.get_configdb = &fake_configdb;
	services.get_statsdb = &fake_statsdb;
	services.register_query_hook = nullptr;
	services.get_prometheus_registry = &fake_registry;
	services.register_command_alias = &fake_register_alias;
	services.register_runtime_view = &fake_register_view;
	services.validate_listener_interfaces = &fake_validate_listener_interfaces;
	services.with_admin_db_lock = &fake_with_admin_db_lock;
	services.get_raw_backend_service = &fake_get_raw_backend_service;
	(void)env;
	return services;
}

std::string disk_ddl(const std::string& ddl) {
	const std::string token = "CREATE TABLE ";
	const size_t position = ddl.find(token);
	if (position == std::string::npos) return ddl;
	return ddl.substr(0, position) + "CREATE TABLE \"disk\"." +
		ddl.substr(position + token.size());
}

bool create_schema(SQLite3DB& db, FakeServices& env) {
	for (const auto& table : env.tables) {
		if (table.kind == ProxySQL_PluginDBKind::config_db) {
			if (!db.execute(disk_ddl(table.ddl).c_str())) return false;
		} else if (table.kind == ProxySQL_PluginDBKind::admin_db ||
			table.kind == ProxySQL_PluginDBKind::stats_db) {
			if (!db.execute(table.ddl.c_str())) return false;
		}
	}
	return true;
}

bool execute(SQLite3DB& db, const std::string& sql) {
	return db.execute(sql.c_str());
}

int one_int(SQLite3DB& db, const std::string& sql) {
	return db.return_one_int(sql.c_str());
}

std::string one_text(SQLite3DB& db, const std::string& sql) {
	std::unique_ptr<SQLite3_result> result;
	char* error = nullptr;
	result.reset(db.execute_statement(sql.c_str(), &error));
	if (error != nullptr) free(error);
	if (!result || result->rows.empty() || result->rows[0]->fields[0] == nullptr) {
		return {};
	}
	return std::string(result->rows[0]->fields[0], result->rows[0]->sizes[0]);
}

struct Database {
	SQLite3DB db;
	Database() {
		db.open(const_cast<char*>(":memory:"),
			SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
		db.execute("ATTACH ':memory:' AS disk");
	}
};

struct Scenario {
	Database database;
	FakeServices env;
	ProxySQL_PluginServices services;
	const ProxySQL_PluginDescriptor* descriptor { nullptr };

	explicit Scenario(bool create_tables = true) : services(make_services(env)) {
		g_services = &env;
		env.db = &database.db;
		descriptor = proxysql_plugin_descriptor_v1();
		(void)descriptor->register_schemas(&services);
		if (create_tables) create_schema(database.db, env);
	}

	~Scenario() {
		(void)descriptor->stop();
		tcp_proxy_plugin::context().metrics.reset();
		g_services = nullptr;
	}
};

proxysql_plugin_admin_command_cb command(FakeServices& env, const std::string& sql) {
	const auto found = env.commands.find(sql);
	return found != env.commands.end() ? found->second : nullptr;
}

ProxySQL_PluginCommandContext command_context(FakeServices& env, bool handoff = true) {
	ProxySQL_PluginCommandContext context {};
	context.admindb = env.db;
	context.configdb = env.db;
	context.statsdb = env.db;
	if (handoff) {
		context.admin_mutex_context = &env;
		context.release_admin_mutex = &fake_release_admin;
		context.acquire_admin_mutex = &fake_acquire_admin;
	}
	return context;
}

bool insert_base_rows(SQLite3DB& db) {
	return execute(db,
		"INSERT INTO tcp_hostgroups(hostgroup_id,source_protocol,"
		"source_hostgroup,comment) VALUES(10,'MYSQL',10,'hg')") &&
		execute(db,
		"INSERT INTO tcp_listeners(listener_id,active,bind_address,bind_port,"
		"default_hostgroup,max_connections,connect_timeout_ms,idle_timeout_ms,"
		"max_connect_attempts,comment) "
		"VALUES(5,1,'127.0.0.1',7001,10,50,2000,60000,3,'listener')") &&
		execute(db,
		"INSERT INTO tcp_routing_rules(rule_id,active,listener_id,source_cidr,"
		"action,destination_hostgroup,comment) "
		"VALUES(7,1,NULL,NULL,'ROUTE',10,'rule')");
}

bool insert_mapping_rows(SQLite3DB& db) {
	return execute(db,
		"INSERT INTO tcp_hostgroups(hostgroup_id,source_protocol,"
		"source_hostgroup,comment) VALUES(20,'PGSQL',11,'map row')");
}

void reset_fake_engine() {
	tcp_proxy::FakeEngine& state = tcp_proxy::fake();
	std::lock_guard<std::mutex> guard(state.mutex);
	state.config = tcp_proxy::Config {};
	state.snapshot = tcp_proxy::Snapshot {};
	state.fail_start = false;
	state.fail_apply = false;
	state.block_apply = false;
	state.apply_entered = false;
	state.release_apply = false;
	state.throw_snapshot = false;
	state.throw_config = false;
	state.generation_changes_every_read = false;
	state.start_calls = 0;
	state.apply_calls = 0;
	state.stop_calls = 0;
	state.generation = 0;
}

int count_metric_families(prometheus::Registry& registry, const std::string& prefix) {
	int count = 0;
	for (const auto& family : registry.Collect()) {
		if (family.name.rfind(prefix, 0) == 0) ++count;
	}
	return count;
}

bool find_metric_family(prometheus::Registry& registry, const std::string& name,
		prometheus::MetricFamily& out) {
	for (const auto& family : registry.Collect()) {
		if (family.name == name) {
			out = family;
			return true;
		}
	}
	return false;
}

bool metric_family_type(prometheus::Registry& registry, const std::string& name,
		prometheus::MetricType expected) {
	prometheus::MetricFamily family;
	return find_metric_family(registry, name, family) && family.type == expected;
}

/* Value of the single global series (scope=global/id=0) or a scalar family
 * whose only label is the fixed component label. */
double global_metric_value(prometheus::Registry& registry, const std::string& name) {
	prometheus::MetricFamily family;
	if (!find_metric_family(registry, name, family)) return -1;
	for (const auto& metric : family.metric) {
		bool has_scope = false;
		bool scope_global = false;
		bool other_label = false;
		for (const auto& label : metric.label) {
			if (label.name == "scope") {
				has_scope = true;
				if (label.value == "global") scope_global = true;
			} else if (label.name == "component" &&
				label.value == "tcp_proxy") {
				continue;
			} else if (label.name == "id") {
				continue;
			} else {
				other_label = true;
			}
		}
		if (!scope_global && (has_scope || other_label)) continue;
		return family.type == prometheus::MetricType::Counter
			? metric.counter.value : metric.gauge.value;
	}
	return -1;
}

prometheus::Labels tcp_component_labels() {
	return prometheus::Labels { { "component", "tcp_proxy" } };
}

const char* const kRetainedGaugeNames[] {
	"proxysql_tcp_active_connections",
	"proxysql_tcp_generation",
	"proxysql_tcp_running",
	"proxysql_tcp_retired_connections",
};

const char* const kRetainedCounterNames[] {
	"proxysql_tcp_accepted_total",
	"proxysql_tcp_rejected_total",
	"proxysql_tcp_connect_errors_total",
	"proxysql_tcp_matched_total",
	"proxysql_tcp_bytes_client_to_server_total",
	"proxysql_tcp_bytes_server_to_client_total",
};

/* Merge/rebind the ten stable families exactly as the plugin does.  The
 * returned pointers identify the core-retained objects; an empty family cannot
 * be seen through Registry::Collect(), so pointer identity is the observable
 * proof that repeated lifecycles do not create a second family set. */
std::vector<void*> register_retained_families(prometheus::Registry& registry) {
	std::vector<void*> families;
	families.reserve(10);
	for (const char* name : kRetainedGaugeNames) {
		families.push_back(&prometheus::BuildGauge()
			.Name(name)
			.Help("retained family probe")
			.Labels(tcp_component_labels())
			.Register(registry));
	}
	for (const char* name : kRetainedCounterNames) {
		families.push_back(&prometheus::BuildCounter()
			.Name(name)
			.Help("retained family probe")
			.Labels(tcp_component_labels())
			.Register(registry));
	}
	return families;
}

bool retained_families_have_no_samples(prometheus::Registry& registry) {
	for (const char* name : kRetainedGaugeNames) {
		prometheus::Family<prometheus::Gauge>& family =
			prometheus::BuildGauge()
				.Name(name)
				.Help("retained family probe")
				.Labels(tcp_component_labels())
				.Register(registry);
		if (!family.Collect().empty()) return false;
	}
	for (const char* name : kRetainedCounterNames) {
		prometheus::Family<prometheus::Counter>& family =
			prometheus::BuildCounter()
				.Name(name)
				.Help("retained family probe")
				.Labels(tcp_component_labels())
				.Register(registry);
		if (!family.Collect().empty()) return false;
	}
	return true;
}

int deny_sqlite_master_reads(void*, int action, const char* arg1, const char*,
		const char*, const char*) {
	if (action == SQLITE_READ && arg1 != nullptr &&
		(std::strcmp(arg1, "sqlite_master") == 0 ||
			std::strcmp(arg1, "sqlite_temp_master") == 0)) {
		return SQLITE_DENY;
	}
	return SQLITE_OK;
}

/* Finds a sample by one dynamic label (for example owner=foreign). */
bool find_labeled_sample(prometheus::Registry& registry, const std::string& name,
		const std::string& label_name, const std::string& label_value,
		double& value) {
	prometheus::MetricFamily family;
	if (!find_metric_family(registry, name, family)) return false;
	for (const auto& metric : family.metric) {
		bool match = false;
		for (const auto& label : metric.label) {
			if (label.name == label_name && label.value == label_value) match = true;
		}
		if (!match) continue;
		value = family.type == prometheus::MetricType::Counter
			? metric.counter.value : metric.gauge.value;
		return true;
	}
	return false;
}

} // namespace

/* ------------------------------------------------------------------------- */

int main() {
	setvbuf(stdout, nullptr, _IOLBF, 0);
	plan(NO_PLAN);
	diag("=== tcp_proxy admin_unit-t starting ===");

	const ProxySQL_PluginDescriptor* descriptor = proxysql_plugin_descriptor_v1();
	ok(descriptor != nullptr, "descriptor entry point is exported");
	ok(descriptor != nullptr && std::strcmp(descriptor->name, "tcp_proxy") == 0,
		"descriptor name is tcp_proxy");
	ok(descriptor != nullptr && descriptor->abi_version == PROXYSQL_PLUGIN_ABI_VERSION,
		"descriptor ABI matches frozen header");
	ok(descriptor != nullptr && descriptor->init != nullptr &&
		descriptor->start != nullptr && descriptor->stop != nullptr &&
		descriptor->register_schemas != nullptr,
		"descriptor lifecycle callbacks are present");

	/* Phase B: schema/command registration must not touch DB handles. */
	{
		diag(">>> Phase B schema and command registration");
		FakeServices env;
		g_services = &env;
		ProxySQL_PluginServices services = make_services(env);
		ok(descriptor->register_schemas(&services),
			"register_schemas succeeds without database handles");
		ok(env.admin_db_calls == 0 && env.config_db_calls == 0 &&
			env.stats_db_calls == 0,
			"register_schemas performs no DB getter calls (admin=%d config=%d stats=%d)",
			env.admin_db_calls, env.config_db_calls, env.stats_db_calls);
		ok(env.tables.size() == 15, "registered 4 admin+config pairs, 5 runtime and 2 stats tables (got %zu)",
			env.tables.size());
		ok(env.commands.size() == 4, "registered exactly four canonical commands (got %zu)",
			env.commands.size());
		ok(env.aliases.size() == 4, "registered exactly four aliases (got %zu)",
			env.aliases.size());
		ok(env.views.size() == 7, "registered 5 runtime and 2 stats refresh views (got %zu)",
			env.views.size());

		int pairs = 0;
		for (const auto& config : env.tables) {
			if (config.kind != ProxySQL_PluginDBKind::config_db) continue;
			bool twin = false;
			for (const auto& admin : env.tables) {
				if (admin.kind == ProxySQL_PluginDBKind::admin_db &&
					admin.name == config.name && admin.ddl == config.ddl) {
					twin = true;
					break;
				}
			}
			ok(twin, "config_db table %s has an identical admin twin", config.name.c_str());
			++pairs;
		}
		ok(pairs == 4, "four persistent config/admin table pairs (got %d)", pairs);
		ok(command(env, "LOAD TCP CONFIG TO RUNTIME") != nullptr &&
			command(env, "SAVE TCP CONFIG FROM RUNTIME") != nullptr &&
			command(env, "LOAD TCP CONFIG FROM DISK") != nullptr &&
			command(env, "SAVE TCP CONFIG TO DISK") != nullptr,
			"all canonical command callbacks are callable");
		const std::set<std::string> alias_names {
			"LOAD TCP CONFIG FROM MEMORY", "SAVE TCP CONFIG TO MEMORY",
			"LOAD TCP CONFIG TO MEMORY", "SAVE TCP CONFIG FROM MEMORY",
		};
		bool aliases_exact = true;
		for (const auto& alias : env.aliases) {
			if (alias_names.count(alias.second) == 0) aliases_exact = false;
		}
		ok(aliases_exact, "alias spellings match the design exactly");
		const std::map<std::string, std::vector<std::string>> expected_columns {
			{ "tcp_settings", { "id", "worker_threads", "max_connections",
				"buffer_size", "shutdown_timeout_ms", "half_close_timeout_ms" } },
			{ "tcp_hostgroups", { "hostgroup_id", "source_protocol",
				"source_hostgroup", "comment" } },
			{ "tcp_listeners", { "listener_id", "active", "bind_address",
				"bind_port", "default_hostgroup", "max_connections",
				"connect_timeout_ms", "idle_timeout_ms",
				"max_connect_attempts", "comment" } },
			{ "tcp_routing_rules", { "rule_id", "active", "listener_id",
				"source_cidr", "action", "destination_hostgroup", "comment" } },
		};
		for (const auto& expected : expected_columns) {
			std::string ddl;
			for (const auto& table : env.tables) {
				if (table.kind == ProxySQL_PluginDBKind::admin_db &&
					table.name == expected.first) {
					ddl = table.ddl;
					break;
				}
			}
			bool complete = !ddl.empty();
			for (const auto& column : expected.second) {
				if (ddl.find(" " + column + " ") == std::string::npos &&
					ddl.find("(" + column + " ") == std::string::npos &&
					ddl.find("," + column + " ") == std::string::npos) {
					complete = false;
				}
			}
			ok(complete, "%s DDL includes every configured column",
				expected.first.c_str());
		}
		const std::string authoritative =
			"CREATE TABLE tcp_hostgroups ( hostgroup_id INTEGER PRIMARY KEY "
			"CHECK(hostgroup_id >= 0), source_protocol TEXT NOT NULL "
			"CHECK(source_protocol IN ('MYSQL','PGSQL')), source_hostgroup "
			"INTEGER NOT NULL CHECK(source_hostgroup >= 0), comment TEXT NOT "
			"NULL DEFAULT '')";
		bool authoritative_exact = false;
		for (const auto& table : env.tables) {
			if (table.kind == ProxySQL_PluginDBKind::admin_db &&
				table.name == "tcp_hostgroups") {
				authoritative_exact = table.ddl == authoritative;
			}
		}
		ok(authoritative_exact,
			"tcp_hostgroups uses the exact authoritative DDL string");
		const std::set<std::string> forbidden {
			"tcp_servers", "tcp_hostgroup_mappings", "runtime_tcp_servers",
			"runtime_tcp_hostgroup_mappings", "stats_tcp_servers",
		};
		bool no_server_artifacts = true;
		for (const auto& table : env.tables) {
			if (forbidden.count(table.name) != 0) no_server_artifacts = false;
		}
		for (const auto& view : env.views) {
			if (forbidden.count(view.name) != 0) no_server_artifacts = false;
		}
		ok(no_server_artifacts, "no server or separate mapping tables/views are registered");
		g_services = nullptr;
	}

	/* Init seeds settings defaults, restores disk and starts/stops cleanly. */
	{
		diag(">>> init defaults and start/stop lifecycle");
		reset_fake_engine();
		Scenario scenario;
		ok(descriptor->init(&scenario.services), "init succeeds with defaults");
		ok(one_int(scenario.database.db, "SELECT COUNT(*) FROM tcp_settings") == 1,
			"init seeds exactly one tcp_settings row");
		ok(one_int(scenario.database.db,
			"SELECT worker_threads FROM tcp_settings WHERE id=1") == 2,
			"settings worker_threads default is 2");
		ok(one_int(scenario.database.db,
			"SELECT COUNT(*) FROM disk.tcp_settings") == 1,
			"empty disk startup is seeded with the settings default");
		ok(descriptor->start(), "start succeeds with zero listeners");
		ok(g_services->last_interfaces.empty(),
			"start validates an empty active-listener set");
		ok(tcp_proxy_plugin::context().started.load(), "plugin reports started");
		ok(tcp_proxy_plugin::runtime_ready(nullptr) == false,
			"runtime_ready rejects a null context");
		auto runtime_context = ProxySQL_PluginRuntimeContext {
			&scenario.services, 0 };
		ok(tcp_proxy_plugin::runtime_ready(&runtime_context),
			"runtime_ready reports the running engine");
		tcp_proxy::Snapshot snapshot = tcp_proxy_plugin::copy_engine(
			tcp_proxy_plugin::context())->snapshot();
		ok(snapshot.running && snapshot.generation == 1,
			"start publishes generation 1");
		const std::string status = descriptor->status_json();
		ok(status.find("\"running\":true") != std::string::npos,
			"status JSON reports running state");
		ok(descriptor->stop(), "stop succeeds");
		ok(tcp_proxy::fake().stop_calls == 1, "stop calls Engine::stop exactly once");
		ok(count_metric_families(scenario.env.registry, "proxysql_tcp_") == 0,
			"stop removes every TCP metric family");
	}

	/* Strict parsing, all columns, and runtime-vs-memory distinction. */
	{
		diag(">>> strict parse, LOAD and runtime projection");
		reset_fake_engine();
		Scenario scenario;
		ok(insert_base_rows(scenario.database.db), "inserted complete base configuration");
		ok(descriptor->init(&scenario.services), "init parses the complete configuration");
		ok(descriptor->start(), "start applies the restored configuration");
		auto engine = tcp_proxy_plugin::copy_engine(tcp_proxy_plugin::context());
		ok(engine != nullptr && engine->config().hostgroups.size() == 1,
			"Engine received the hostgroup mapping row");
		ok(engine != nullptr && engine->config().hostgroups[0].comment == "hg",
			"hostgroup comment parsed exactly");
		ok(engine != nullptr && engine->config().listeners[0].comment == "listener",
			"listener comment parsed exactly");
		ok(engine != nullptr && !engine->config().rules[0].listener_id.has_value() &&
			!engine->config().rules[0].source_cidr.has_value(),
			"NULL rule references stay NULL optionals");
		ok(engine != nullptr &&
			engine->config().hostgroups[0].source_protocol == "MYSQL" &&
			engine->config().hostgroups[0].source_hostgroup == 10 &&
			engine->config().hostgroups[0].comment == "hg",
			"mandatory hostgroup mapping columns parsed exactly");
		ok(engine != nullptr && engine->config().listeners[0].active == 1 &&
			engine->config().listeners[0].bind_address == "127.0.0.1" &&
			engine->config().listeners[0].bind_port == 7001 &&
			engine->config().listeners[0].default_hostgroup == 10 &&
			engine->config().listeners[0].max_connections == 50 &&
			engine->config().listeners[0].connect_timeout_ms == 2000 &&
			engine->config().listeners[0].idle_timeout_ms == 60000 &&
			engine->config().listeners[0].max_connect_attempts == 3,
			"listener columns parsed exactly");
		ok(engine != nullptr && engine->config().rules[0].active == 1 &&
			engine->config().rules[0].action == "ROUTE" &&
			engine->config().rules[0].destination_hostgroup.value_or(-1) == 10,
			"rule columns parsed exactly");

		/* Unactivated Main edit must not appear in runtime views. */
		ok(execute(scenario.database.db,
			"UPDATE tcp_hostgroups SET comment='main-edit' WHERE hostgroup_id=10"),
			"edit Main without activating");
		auto refresh = [&](const std::string& table) {
			for (const auto& view : scenario.env.views) {
				if (view.name == table) {
					view.refresh(&scenario.database.db, nullptr);
					return true;
				}
			}
			return false;
		};
		ok(refresh("runtime_tcp_hostgroups"), "runtime hostgroup view refresh is registered");
		ok(one_text(scenario.database.db,
			"SELECT comment FROM runtime_tcp_hostgroups WHERE hostgroup_id=10") == "hg",
			"runtime view still reflects the installed Engine, not Main edits");
		ok(one_int(scenario.database.db,
			"SELECT generation FROM runtime_tcp_hostgroups WHERE hostgroup_id=10") == 1,
			"runtime row carries the active generation");

		ProxySQL_PluginCommandContext context = command_context(scenario.env);
		ProxySQL_PluginCommandResult result = command(scenario.env,
			"LOAD TCP CONFIG TO RUNTIME")(context, nullptr);
		ok(result.error_code == 0, "LOAD TO RUNTIME succeeds: %s", result.message.c_str());
		ok(tcp_proxy::fake().apply_calls == 1, "LOAD called Engine::apply once");
		ok(scenario.env.admin_releases.load() == 1 &&
			scenario.env.admin_acquires.load() == 1,
			"LOAD released and reacquired Admin exactly once");
		ok(!scenario.env.admin_released.load(), "Admin is reacquired before LOAD returns");
		refresh("runtime_tcp_hostgroups");
		ok(one_text(scenario.database.db,
			"SELECT comment FROM runtime_tcp_hostgroups WHERE hostgroup_id=10") == "main-edit",
			"runtime view follows a successful activation");
		ok(one_int(scenario.database.db,
			"SELECT generation FROM runtime_tcp_hostgroups WHERE hostgroup_id=10") == 2,
			"runtime generation advanced after activation");

		/* SAVE FROM RUNTIME copies Engine state back, not Main edits. */
		ok(execute(scenario.database.db,
			"UPDATE tcp_hostgroups SET comment='later-edit' WHERE hostgroup_id=10"),
			"make a second unactivated Main edit");
		result = command(scenario.env, "SAVE TCP CONFIG FROM RUNTIME")(context, nullptr);
		ok(result.error_code == 0, "SAVE FROM RUNTIME succeeds: %s", result.message.c_str());
		ok(one_text(scenario.database.db,
			"SELECT comment FROM tcp_hostgroups WHERE hostgroup_id=10") == "main-edit",
			"SAVE FROM RUNTIME restored the effective Engine value");
		ok(tcp_proxy::fake().apply_calls == 1,
			"SAVE FROM RUNTIME does not activate a new generation");
	}

	/* Mandatory hostgroup mappings: projection, activation and disk roundtrip. */
	{
		diag(">>> mandatory hostgroup mapping projection and persistence");
		reset_fake_engine();
		Scenario scenario;
		ok(insert_base_rows(scenario.database.db) &&
			insert_mapping_rows(scenario.database.db),
			"inserted base configuration plus a second mapped hostgroup");
		ok(descriptor->init(&scenario.services),
			"init parses the complete four-table configuration");
		ok(descriptor->start(), "start applies the restored mapping");
		auto engine = tcp_proxy_plugin::copy_engine(tcp_proxy_plugin::context());
		ok(engine != nullptr && engine->config().hostgroups.size() == 2,
			"Engine received both hostgroup mapping rows");
		ok(engine != nullptr &&
			engine->config().hostgroups[1].hostgroup_id == 20 &&
			engine->config().hostgroups[1].source_protocol == "PGSQL" &&
			engine->config().hostgroups[1].source_hostgroup == 11 &&
			engine->config().hostgroups[1].comment == "map row",
			"all mandatory mapping columns parsed exactly");

		auto refresh = [&](const std::string& table) {
			for (const auto& view : scenario.env.views) {
				if (view.name == table) {
					view.refresh(&scenario.database.db, nullptr);
					return true;
				}
			}
			return false;
		};
		ok(refresh("runtime_tcp_hostgroups"),
			"runtime hostgroup view refresh is registered");
		ok(one_int(scenario.database.db,
			"SELECT COUNT(*) FROM runtime_tcp_hostgroups") == 2 &&
			one_text(scenario.database.db,
				"SELECT source_protocol FROM runtime_tcp_hostgroups "
				"WHERE hostgroup_id=20") == "PGSQL" &&
			one_int(scenario.database.db,
				"SELECT source_hostgroup FROM runtime_tcp_hostgroups "
				"WHERE hostgroup_id=20") == 11 &&
			one_int(scenario.database.db,
				"SELECT generation FROM runtime_tcp_hostgroups "
				"WHERE hostgroup_id=20") == 1,
			"runtime mapping projection reflects the active generation");

		ok(execute(scenario.database.db,
			"UPDATE tcp_hostgroups SET comment='activated' "
			"WHERE hostgroup_id=20"),
			"edit the mapping without activating");
		refresh("runtime_tcp_hostgroups");
		ok(one_text(scenario.database.db,
			"SELECT comment FROM runtime_tcp_hostgroups "
			"WHERE hostgroup_id=20") == "map row",
			"runtime mapping projection ignores unactivated Main edits");
		ProxySQL_PluginCommandContext context = command_context(scenario.env);
		ProxySQL_PluginCommandResult result = command(scenario.env,
			"LOAD TCP CONFIG TO RUNTIME")(context, nullptr);
		ok(result.error_code == 0,
			"LOAD TO RUNTIME accepts the mapping: %s", result.message.c_str());
		ok(tcp_proxy::fake().apply_calls == 1 &&
			tcp_proxy::fake().config.hostgroups.size() == 2 &&
			tcp_proxy::fake().config.hostgroups[1].comment == "activated",
			"LOAD copied the mapping into the Engine generation");
		refresh("runtime_tcp_hostgroups");
		ok(one_text(scenario.database.db,
			"SELECT comment FROM runtime_tcp_hostgroups "
			"WHERE hostgroup_id=20") == "activated",
			"runtime projection follows a successful activation");

		ok(execute(scenario.database.db,
			"UPDATE tcp_hostgroups SET comment='later' "
			"WHERE hostgroup_id=20"),
			"make a second unactivated mapping edit");
		result = command(scenario.env, "SAVE TCP CONFIG FROM RUNTIME")(
			context, nullptr);
		ok(result.error_code == 0,
			"SAVE FROM RUNTIME includes mappings: %s", result.message.c_str());
		ok(one_text(scenario.database.db,
			"SELECT comment FROM tcp_hostgroups WHERE hostgroup_id=20") ==
			"activated",
			"SAVE restored the effective mapping row");

		result = command(scenario.env, "SAVE TCP CONFIG TO DISK")(
			context, nullptr);
		ok(result.error_code == 0,
			"SAVE TO DISK persists the mapping: %s", result.message.c_str());
		ok(one_int(scenario.database.db,
			"SELECT COUNT(*) FROM disk.tcp_hostgroups") == 2,
			"disk contains both hostgroup mapping rows");
		ok(execute(scenario.database.db,
			"DELETE FROM tcp_hostgroups"),
			"clear the editable hostgroup table");
		result = command(scenario.env, "LOAD TCP CONFIG FROM DISK")(
			context, nullptr);
		ok(result.error_code == 0,
			"LOAD FROM DISK restores the mapping: %s", result.message.c_str());
		ok(one_text(scenario.database.db,
			"SELECT source_protocol FROM tcp_hostgroups "
			"WHERE hostgroup_id=20") == "PGSQL" &&
			one_int(scenario.database.db,
				"SELECT source_hostgroup FROM tcp_hostgroups "
				"WHERE hostgroup_id=20") == 11,
			"four-table disk roundtrip preserved mapping values");
	}

		/* Strict mapping rejection never reaches a new Engine generation. */
	{
		diag(">>> strict mapping validation");
		reset_fake_engine();
		Scenario scenario;
		ok(insert_base_rows(scenario.database.db) &&
			insert_mapping_rows(scenario.database.db),
			"inserted base mapping configuration");
		ok(descriptor->init(&scenario.services),
			"init parses mapping validation configuration");
		ok(descriptor->start(), "started for mapping validation");
		ProxySQL_PluginCommandContext context = command_context(scenario.env);
		auto load = command(scenario.env, "LOAD TCP CONFIG TO RUNTIME");
		const int applies_before = tcp_proxy::fake().apply_calls;

		ok(execute(scenario.database.db,
			"PRAGMA ignore_check_constraints=ON") &&
			execute(scenario.database.db,
				"UPDATE tcp_hostgroups SET source_protocol='ORACLE' "
				"WHERE hostgroup_id=20") &&
			execute(scenario.database.db,
				"PRAGMA ignore_check_constraints=OFF"),
			"store an invalid mapping protocol");
		ProxySQL_PluginCommandResult result = load(context, nullptr);
		ok(result.error_code != 0 &&
			result.message.find("source_protocol") != std::string::npos,
			"invalid protocol is rejected: %s", result.message.c_str());
		ok(tcp_proxy::fake().apply_calls == applies_before,
			"invalid protocol did not reach Engine::apply");
		ok(execute(scenario.database.db,
			"PRAGMA ignore_check_constraints=ON") &&
			execute(scenario.database.db,
				"UPDATE tcp_hostgroups SET source_protocol='PGSQL' "
				"WHERE hostgroup_id=20") &&
			execute(scenario.database.db,
				"PRAGMA ignore_check_constraints=OFF"),
			"restore a valid PGSQL mapping");

		ok(execute(scenario.database.db,
			"PRAGMA ignore_check_constraints=ON") &&
			execute(scenario.database.db,
				"UPDATE tcp_hostgroups SET source_hostgroup=-1 "
				"WHERE hostgroup_id=20") &&
			execute(scenario.database.db,
				"PRAGMA ignore_check_constraints=OFF"),
			"store a negative source hostgroup");
		result = load(context, nullptr);
		ok(result.error_code != 0 &&
			result.message.find("source_hostgroup") != std::string::npos,
			"invalid source hostgroup is rejected: %s", result.message.c_str());
		ok(tcp_proxy::fake().apply_calls == applies_before,
			"invalid source hostgroup did not reach Engine::apply");
		ok(execute(scenario.database.db,
			"PRAGMA ignore_check_constraints=ON") &&
			execute(scenario.database.db,
				"UPDATE tcp_hostgroups SET source_hostgroup=10 "
				"WHERE hostgroup_id=20") &&
			execute(scenario.database.db,
				"PRAGMA ignore_check_constraints=OFF"),
			"restore the source hostgroup");

		ok(execute(scenario.database.db,
			"UPDATE tcp_listeners SET default_hostgroup=99 WHERE listener_id=5"),
			"point a listener default at an unconfigured TCP hostgroup");
		result = load(context, nullptr);
		ok(result.error_code != 0 &&
			result.message.find("hostgroup") != std::string::npos,
			"dangling listener destination is rejected: %s",
			result.message.c_str());
		ok(tcp_proxy::fake().apply_calls == applies_before,
			"dangling listener did not reach Engine::apply");
		ok(execute(scenario.database.db,
			"UPDATE tcp_listeners SET default_hostgroup=10 WHERE listener_id=5"),
			"restore the listener default");

		ok(!execute(scenario.database.db,
			"INSERT INTO tcp_hostgroups(hostgroup_id,source_protocol,"
			"source_hostgroup) VALUES(20,'MYSQL',10)"),
			"duplicate hostgroup_id is rejected by the primary key");
		result = load(context, nullptr);
		ok(result.error_code == 0,
			"valid mapping configuration loads after repairs: %s",
			result.message.c_str());
	}

		/* Four-table save/load copies are transactional: a late rule failure
	 * rolls back every earlier table in the same command. */
	{
		diag(">>> four-table transaction rollback");
		reset_fake_engine();
		Scenario scenario;
		ok(insert_base_rows(scenario.database.db) &&
			insert_mapping_rows(scenario.database.db),
			"inserted base mapping configuration");
		ok(descriptor->init(&scenario.services),
			"init parses transaction rollback configuration");
		ok(descriptor->start(), "started for transaction rollback");
		ProxySQL_PluginCommandContext context = command_context(scenario.env);
		ProxySQL_PluginCommandResult result = command(scenario.env,
			"SAVE TCP CONFIG TO DISK")(context, nullptr);
		ok(result.error_code == 0, "initial disk save succeeds: %s",
			result.message.c_str());
		ok(execute(scenario.database.db,
			"UPDATE tcp_hostgroups SET comment='disk-before' "
			"WHERE hostgroup_id=20") &&
			execute(scenario.database.db,
				"UPDATE tcp_listeners SET comment='listener-before' "
				"WHERE listener_id=5"),
			"prepare recognizable disk rows");
		result = command(scenario.env, "SAVE TCP CONFIG TO DISK")(
			context, nullptr);
		ok(result.error_code == 0, "second disk save succeeds: %s",
			result.message.c_str());
		ok(execute(scenario.database.db,
			"CREATE TRIGGER disk.fail_rule BEFORE INSERT ON "
			"tcp_routing_rules BEGIN SELECT RAISE(ABORT,'rule fail'); END"),
			"install a late failure trigger on the disk rule table");
		ok(execute(scenario.database.db,
			"UPDATE tcp_hostgroups SET comment='disk-after' "
			"WHERE hostgroup_id=20"),
			"prepare a new hostgroup value");
		result = command(scenario.env, "SAVE TCP CONFIG TO DISK")(
			context, nullptr);
		ok(result.error_code != 0, "late rule insert fails the save");
		ok(one_text(scenario.database.db,
			"SELECT comment FROM disk.tcp_hostgroups "
			"WHERE hostgroup_id=20") == "disk-before",
			"SAVE TO DISK rolled back the hostgroup table");
		ok(one_text(scenario.database.db,
			"SELECT comment FROM disk.tcp_listeners WHERE listener_id=5") ==
			"listener-before",
			"SAVE TO DISK rolled back earlier tables too");
		ok(execute(scenario.database.db, "DROP TRIGGER disk.fail_rule"),
			"remove the disk failure trigger");

		ok(execute(scenario.database.db,
			"UPDATE tcp_hostgroups SET comment='main-before' "
			"WHERE hostgroup_id=20") &&
			execute(scenario.database.db,
				"UPDATE tcp_listeners SET comment='main-listener-before' "
				"WHERE listener_id=5"),
			"prepare recognizable Main rows");
		ok(execute(scenario.database.db,
			"CREATE TRIGGER main.fail_rule BEFORE INSERT ON "
			"tcp_routing_rules BEGIN SELECT RAISE(ABORT,'rule fail'); END"),
			"install a late failure trigger on the Main rule table");
		result = command(scenario.env, "LOAD TCP CONFIG FROM DISK")(
			context, nullptr);
		ok(result.error_code != 0, "late rule insert fails the load");
		ok(one_text(scenario.database.db,
			"SELECT comment FROM tcp_hostgroups "
			"WHERE hostgroup_id=20") == "main-before",
			"LOAD FROM DISK rolled back the hostgroup table");
		ok(one_text(scenario.database.db,
			"SELECT comment FROM tcp_listeners WHERE listener_id=5") ==
			"main-listener-before",
			"LOAD FROM DISK rolled back earlier tables too");
		ok(execute(scenario.database.db, "DROP TRIGGER main.fail_rule"),
			"remove the Main failure trigger");
	}

	/* Raw backend adapter: construction, calls and Release semantics. */
	{
		diag(">>> raw backend provider adapter");
		FakeRawState raw;
		g_raw = &raw;
		ProxySQL_RawBackendServiceV2 service = fake_raw_service();
		auto provider = tcp_proxy_plugin::make_raw_backend_provider(&service);
		ok(provider != nullptr && provider->available(),
			"a complete V2 service yields an available provider");

		auto connection = provider->acquire("MYSQL", 42);
		ok(connection != nullptr &&
			connection->hostname() == "127.0.0.1" &&
			connection->port() == 3306,
			"acquire returns the numeric core endpoint");
		ok(raw.acquire_calls == 1 &&
			raw.protocol == ProxySQL_RawBackendProtocol::mysql &&
			raw.hostgroup == 42,
			"acquire forwards protocol and source hostgroup");
		connection->connect_result(0);
		connection->connect_result(0);
		ok(raw.connect_calls == 1 && raw.last_connect_errno == 0,
			"duplicate connect results are suppressed by the adapter");
		connection->account_io(7, 9);
		ok(raw.sent == 7 && raw.received == 9,
			"account_io forwards actual wire-byte batches");
		raw.hard = true;
		ok(connection->offline_hard(), "offline_hard reflects the core handle");
		raw.hard = false;
		connection.reset();
		ok(raw.destroy_calls == 1, "connection release destroys exactly once");
		connection.reset();
		ok(raw.destroy_calls == 1, "a released handle is never destroyed twice");

		connection = provider->acquire("PGSQL", 7);
		ok(connection != nullptr &&
			raw.protocol == ProxySQL_RawBackendProtocol::pgsql &&
			raw.hostgroup == 7,
			"PGSQL mappings use the PostgreSQL protocol namespace");
		connection.reset();
		ok(raw.destroy_calls == 2, "each acquired handle is destroyed once");

		bool threw = false;
		try {
			connection = provider->acquire("ORACLE", 1);
		} catch (const std::exception&) {
			threw = true;
		}
		ok(threw, "unknown source_protocol is rejected");

		raw.fail_acquire = true;
		threw = false;
		std::string failure;
		try {
			connection = provider->acquire("MYSQL", 1);
		} catch (const std::exception& exception) {
			threw = true;
			failure = exception.what();
		}
		ok(threw && failure.find("fake raw acquire failure") != std::string::npos,
			"core acquisition diagnostics are preserved: %s", failure.c_str());
		raw.fail_acquire = false;

		raw.port = 0;
		const int destroyed_before = raw.destroy_calls;
		threw = false;
		try {
			connection = provider->acquire("MYSQL", 1);
		} catch (const std::exception&) {
			threw = true;
		}
		ok(threw && raw.destroy_calls == destroyed_before + 1,
			"an invalid numeric endpoint releases the acquired core handle");

		// A throw while constructing the C++ wrapper must also release the
		// already-acquired core handle through the RAII guard.
		raw.port = 3306;
		const int alloc_destroyed_before = raw.destroy_calls;
		const int alloc_acquired_before = raw.acquire_calls;
		tcp_proxy_plugin::raw_backend_provider_test_fail_wrapper_allocation_once(
			true);
		threw = false;
		try {
			connection = provider->acquire("MYSQL", 1);
		} catch (...) {
			threw = true;
		}
		tcp_proxy_plugin::raw_backend_provider_test_fail_wrapper_allocation_once(
			false);
		ok(threw &&
			raw.acquire_calls == alloc_acquired_before + 1 &&
			raw.destroy_calls == alloc_destroyed_before + 1,
			"wrapper allocation failure balances acquire and destroy");

		ProxySQL_PluginServices no_provider {};
		ok(tcp_proxy_plugin::core_backend_provider(&no_provider) == nullptr,
			"a null ABI18 services getter yields no provider");

		// Explicit destroy returns and caches the final HARD fence exactly once.
		raw.port = 3306;
		raw.destroy_result = true;
		auto destroy_true = provider->acquire("MYSQL", 1);
		const int true_calls_before = raw.destroy_calls;
		ok(destroy_true != nullptr && destroy_true->destroy(),
			"explicit destroy returns the final true HARD fence");
		ok(raw.destroy_calls == true_calls_before + 1,
			"explicit destroy invokes the core exactly once");
		ok(destroy_true->destroy() && destroy_true->destroy(),
			"repeated destroy returns the cached true fence");
		ok(raw.destroy_calls == true_calls_before + 1,
			"repeated destroy never double-destroys");
		raw.hard = false;
		raw.destroy_result = false;
		ok(destroy_true->offline_hard(),
			"offline_hard after destruction preserves the cached true fence");
		destroy_true.reset();
		ok(raw.destroy_calls == true_calls_before + 1,
			"the wrapper destructor does not destroy an explicitly retired handle");

		raw.destroy_result = false;
		auto destroy_false = provider->acquire("MYSQL", 1);
		const int false_calls_before = raw.destroy_calls;
		ok(destroy_false != nullptr && !destroy_false->destroy(),
			"explicit destroy returns false when the final fence is clear");
		ok(!destroy_false->destroy() &&
			raw.destroy_calls == false_calls_before + 1,
			"a false destroy result is cached and core-destroyed exactly once");
		destroy_false.reset();
		ok(raw.destroy_calls == false_calls_before + 1,
			"destructor fallback after false explicit destroy is a no-op");

		ProxySQL_RawBackendServiceV2 foreign = fake_raw_service();
		foreign.version = 1;
		auto unavailable = tcp_proxy_plugin::make_raw_backend_provider(&foreign);
		ok(unavailable != nullptr && !unavailable->available(),
			"the retired version-1 service table is rejected");
		threw = false;
		try {
			connection = unavailable->acquire("MYSQL", 1);
		} catch (const std::exception&) {
			threw = true;
		}
		ok(threw, "an unavailable adapter rejects acquisition");

		auto missing = tcp_proxy_plugin::make_raw_backend_provider(nullptr);
		ok(missing != nullptr && !missing->available(),
			"a missing service table yields an unavailable provider");
		g_raw = nullptr;
	}

	/* A mapped plugin start is rejected before publication when the core
	 * provider is unavailable (the fake Engine cannot enforce it itself). */
	{
		diag(">>> mapped start requires an available provider");
		reset_fake_engine();
		Scenario scenario;
		ok(insert_base_rows(scenario.database.db) &&
			insert_mapping_rows(scenario.database.db),
			"inserted mapping configuration");
		ok(descriptor->init(&scenario.services),
			"init still restores mapping configuration");
		tcp_proxy_plugin::context().backend_provider.reset();
		ok(tcp_proxy_plugin::context().backend_provider == nullptr,
			"no core raw backend service is available for the rejection case");
		ok(!descriptor->start(),
			"start rejects mapped configuration without a provider");
		std::string last_error;
		tcp_proxy_plugin::state_snapshot(tcp_proxy_plugin::context(),
			last_error);
		ok(last_error.find("raw backend") != std::string::npos,
			"start diagnostic names the missing raw backend service: %s",
			last_error.c_str());

		FakeRawState raw;
		g_raw = &raw;
		ProxySQL_RawBackendServiceV2 service = fake_raw_service();
		tcp_proxy_plugin::context().backend_provider =
			tcp_proxy_plugin::make_raw_backend_provider(&service);
		ok(tcp_proxy_plugin::context().backend_provider != nullptr &&
			tcp_proxy_plugin::context().backend_provider->available(),
			"test installs an available provider");
		ok(descriptor->start(),
			"mapped start succeeds once the provider is available");
		ok(descriptor->stop(), "mapped stop succeeds");
		ok(tcp_proxy_plugin::context().backend_provider == nullptr,
			"stop releases the plugin-owned provider reference");
		g_raw = nullptr;
	}

	/* Malformed rows never reach Engine::apply. */
	{
		diag(">>> malformed rows are rejected without activation");
		reset_fake_engine();
		Scenario scenario;
		ok(insert_base_rows(scenario.database.db), "inserted base rows");
		ok(descriptor->init(&scenario.services) && descriptor->start(),
			"started with valid base rows");
		ProxySQL_PluginCommandContext context = command_context(scenario.env);
		auto load = command(scenario.env, "LOAD TCP CONFIG TO RUNTIME");

		ok(execute(scenario.database.db,
			"PRAGMA ignore_check_constraints=ON") &&
			execute(scenario.database.db,
				"UPDATE tcp_hostgroups SET source_protocol='ORACLE' "
				"WHERE hostgroup_id=10") &&
			execute(scenario.database.db,
				"PRAGMA ignore_check_constraints=OFF"),
			"insert invalid source protocol");
		ProxySQL_PluginCommandResult result = load(context, nullptr);
		ok(result.error_code != 0 &&
			result.message.find("source_protocol") != std::string::npos,
			"invalid enum is rejected: %s", result.message.c_str());
		ok(tcp_proxy::fake().apply_calls == 0, "invalid enum did not reach Engine::apply");
		ok(execute(scenario.database.db,
			"PRAGMA ignore_check_constraints=ON") &&
			execute(scenario.database.db,
				"UPDATE tcp_hostgroups SET source_protocol='MYSQL' "
				"WHERE hostgroup_id=10") &&
			execute(scenario.database.db,
				"PRAGMA ignore_check_constraints=OFF"),
			"restore base hostgroup");

		ok(execute(scenario.database.db,
			"UPDATE tcp_hostgroups SET comment=CAST(x'6f6b00626164' AS TEXT) "
			"WHERE hostgroup_id=10"),
			"insert embedded NUL in comment");
		result = load(context, nullptr);
		ok(result.error_code != 0 && result.message.find("NUL") != std::string::npos,
			"embedded NUL is rejected: %s", result.message.c_str());
		ok(tcp_proxy::fake().apply_calls == 0, "NUL row did not reach Engine::apply");
		ok(execute(scenario.database.db,
			"UPDATE tcp_hostgroups SET comment='hg' WHERE hostgroup_id=10"),
			"restore comment");

		ok(execute(scenario.database.db,
			"UPDATE tcp_hostgroups SET hostgroup_id=2147483648 WHERE hostgroup_id=10"),
			"insert signed-32 overflow in hostgroup_id");
		result = load(context, nullptr);
		ok(result.error_code != 0 && result.message.find("signed 32-bit") != std::string::npos,
			"int32 overflow is rejected: %s", result.message.c_str());
		ok(tcp_proxy::fake().apply_calls == 0, "overflow row did not reach Engine::apply");
		ok(execute(scenario.database.db,
			"UPDATE tcp_hostgroups SET hostgroup_id=10 WHERE hostgroup_id=2147483648"),
			"restore hostgroup_id");

		ok(execute(scenario.database.db,
			"UPDATE tcp_listeners SET default_hostgroup='abc' WHERE listener_id=5"),
			"insert non-numeric text into an integer column");
		result = load(context, nullptr);
		ok(result.error_code != 0 && result.message.find("INTEGER") != std::string::npos,
			"non-integer storage is rejected: %s", result.message.c_str());
		ok(tcp_proxy::fake().apply_calls == 0, "text integer did not reach Engine::apply");
		ok(execute(scenario.database.db,
			"UPDATE tcp_listeners SET default_hostgroup=10 WHERE listener_id=5"),
			"restore default_hostgroup");

		ok(execute(scenario.database.db,
			"UPDATE tcp_routing_rules SET source_cidr='' WHERE rule_id=7"),
			"store empty string (not NULL) in source_cidr");
		result = load(context, nullptr);
		ok(result.error_code != 0 && result.message.find("empty") != std::string::npos,
			"empty optional CIDR is distinct from NULL and rejected: %s",
			result.message.c_str());
		ok(tcp_proxy::fake().apply_calls == 0, "empty CIDR did not reach Engine::apply");

		ok(execute(scenario.database.db,
			"UPDATE tcp_routing_rules SET source_cidr=NULL WHERE rule_id=7"),
			"restore NULL source_cidr");
		result = load(context, nullptr);
		ok(result.error_code == 0, "NULL optional CIDR remains accepted: %s",
			result.message.c_str());
	}

	/* LOAD try-lock and SAVE while the first LOAD has released Admin. */
	{
		diag(">>> concurrent LOAD guard and Admin handoff");
		reset_fake_engine();
		Scenario scenario;
		ok(insert_base_rows(scenario.database.db), "inserted base rows");
		ok(descriptor->init(&scenario.services) && descriptor->start(),
			"started for concurrency test");
		ProxySQL_PluginCommandContext first_context = command_context(scenario.env);
		ProxySQL_PluginCommandContext second_context = command_context(scenario.env);
		auto load = command(scenario.env, "LOAD TCP CONFIG TO RUNTIME");
		auto save = command(scenario.env, "SAVE TCP CONFIG FROM RUNTIME");

		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().block_apply = true;
			tcp_proxy::fake().release_apply = false;
			tcp_proxy::fake().apply_entered = false;
		}
		ProxySQL_PluginCommandResult first_result {};
		std::thread first([&]() { first_result = load(first_context, nullptr); });
		{
			std::unique_lock<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().cv.wait_for(guard, std::chrono::seconds(5), []() {
				return tcp_proxy::fake().apply_entered;
			});
		}
		ok(tcp_proxy::fake().apply_entered, "first LOAD entered Engine::apply");
		ok(scenario.env.admin_released.load(),
			"first LOAD has released Admin while applying");

		const auto start = std::chrono::steady_clock::now();
		ProxySQL_PluginCommandResult second_result = load(second_context, nullptr);
		const auto elapsed = std::chrono::steady_clock::now() - start;
		ok(second_result.error_code != 0 &&
			second_result.message.find("already in progress") != std::string::npos,
			"competing LOAD returns busy immediately: %s", second_result.message.c_str());
		ok(elapsed < std::chrono::seconds(1),
			"competing LOAD did not block behind the applying thread");

		ok(execute(scenario.database.db,
			"UPDATE tcp_hostgroups SET comment='unsaved' WHERE hostgroup_id=10"),
			"make an unactivated Main edit during the first LOAD");
		ProxySQL_PluginCommandResult save_result = save(second_context, nullptr);
		ok(save_result.error_code == 0,
			"SAVE succeeds while the first LOAD is unlocked: %s",
			save_result.message.c_str());
		ok(one_text(scenario.database.db,
			"SELECT comment FROM tcp_hostgroups WHERE hostgroup_id=10") != "unsaved",
			"SAVE used runtime Engine state while LOAD was unlocked");

		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().release_apply = true;
			tcp_proxy::fake().cv.notify_all();
		}
		first.join();
		ok(first_result.error_code == 0, "first LOAD completed: %s",
			first_result.message.c_str());
		ok(scenario.env.admin_acquires.load() >= 1,
			"first LOAD reacquired Admin before returning");
		ok(!scenario.env.admin_released.load(), "Admin is held again after the handoff");

		/* Failure still reacquires Admin and releases the dedicated LOAD guard. */
		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().block_apply = false;
			tcp_proxy::fake().fail_apply = true;
		}
		const int releases_before = scenario.env.admin_releases.load();
		const int acquires_before = scenario.env.admin_acquires.load();
		ProxySQL_PluginCommandResult failed = load(first_context, nullptr);
		ok(failed.error_code != 0 && failed.message == "test apply failure",
			"apply failure is propagated: %s", failed.message.c_str());
		ok(scenario.env.admin_releases.load() == releases_before + 1 &&
			scenario.env.admin_acquires.load() == acquires_before + 1,
			"apply failure reacquires Admin exactly once");
		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().fail_apply = false;
		}
		ProxySQL_PluginCommandResult retry = load(first_context, nullptr);
		ok(retry.error_code == 0, "LOAD guard is released after failure: %s",
			retry.message.c_str());
	}

	/* Disk roundtrip and empty-source clearing. */
	{
		diag(">>> disk persistence");
		reset_fake_engine();
		Scenario scenario;
		ok(insert_base_rows(scenario.database.db), "inserted base rows");
		ok(descriptor->init(&scenario.services) && descriptor->start(),
			"started for disk test");
		ProxySQL_PluginCommandContext context = command_context(scenario.env);
		const int applies_before = tcp_proxy::fake().apply_calls;
		ProxySQL_PluginCommandResult result = command(scenario.env,
			"SAVE TCP CONFIG TO DISK")(context, nullptr);
		ok(result.error_code == 0, "SAVE TO DISK succeeds: %s", result.message.c_str());
		ok(one_int(scenario.database.db,
			"SELECT COUNT(*) FROM disk.tcp_hostgroups") == 1,
			"SAVE TO DISK persisted the hostgroup row");
		ok(execute(scenario.database.db, "DELETE FROM tcp_hostgroups") &&
			execute(scenario.database.db, "DELETE FROM tcp_listeners") &&
			execute(scenario.database.db, "DELETE FROM tcp_routing_rules") &&
			execute(scenario.database.db, "DELETE FROM tcp_hostgroups"),
			"clear editable Main tables");
		result = command(scenario.env, "LOAD TCP CONFIG FROM DISK")(context, nullptr);
		ok(result.error_code == 0, "LOAD FROM DISK succeeds: %s", result.message.c_str());
		ok(one_int(scenario.database.db,
			"SELECT COUNT(*) FROM tcp_hostgroups") == 1,
			"LOAD FROM DISK restored the hostgroup row");
		ok(tcp_proxy::fake().apply_calls == applies_before,
			"LOAD/Save DISK never implicitly activates the runtime");

		ok(execute(scenario.database.db, "DELETE FROM disk.tcp_settings") &&
			execute(scenario.database.db, "DELETE FROM disk.tcp_hostgroups") &&
			execute(scenario.database.db, "DELETE FROM disk.tcp_listeners") &&
			execute(scenario.database.db, "DELETE FROM disk.tcp_routing_rules"),
			"empty every disk table");
		result = command(scenario.env, "LOAD TCP CONFIG FROM DISK")(context, nullptr);
		ok(result.error_code == 0, "LOAD FROM DISK accepts an empty disk source");
		ok(one_int(scenario.database.db,
			"SELECT COUNT(*) FROM tcp_settings") == 1,
			"empty disk settings are replaced by the absent-only defaults");
		ok(one_int(scenario.database.db,
			"SELECT worker_threads FROM tcp_settings WHERE id=1") == 2,
			"seeded settings after empty disk LOAD carry the defaults");
		ok(one_int(scenario.database.db,
			"SELECT COUNT(*) FROM tcp_hostgroups") == 0,
			"empty disk still clears the non-settings tables");
		result = command(scenario.env, "LOAD TCP CONFIG FROM DISK")(context, nullptr);
		ok(result.error_code == 0,
			"a second LOAD FROM DISK remains usable after an empty settings source: %s",
			result.message.c_str());
		ok(one_int(scenario.database.db,
			"SELECT COUNT(*) FROM tcp_settings") == 1,
			"repeated empty-disk LOAD keeps exactly one settings row");
	}

	/* Stats/runtime status projections from the Engine snapshot. */
	{
		diag(">>> statistics and runtime status projections");
		reset_fake_engine();
		Scenario scenario;
		ok(descriptor->init(&scenario.services) && descriptor->start(),
			"started for stats projection");
		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().snapshot.running = true;
			tcp_proxy::fake().snapshot.generation = 9;
			tcp_proxy::fake().snapshot.active_connections = 4;
			tcp_proxy::fake().snapshot.retired_connections = 2;
			tcp_proxy::fake().snapshot.accepted_total = 11;
			tcp_proxy::fake().snapshot.rejected_total = 3;
			tcp_proxy::fake().snapshot.connect_errors = 1;
			tcp_proxy::fake().snapshot.bytes_client_to_server = 100;
			tcp_proxy::fake().snapshot.bytes_server_to_client = 200;
			tcp_proxy::ListenerStats listener;
			listener.listener_id = 5;
			listener.retired = true;
			listener.active_connections = 2;
			listener.accepted_total = 11;
			listener.rejected_total = 3;
			listener.connect_errors = 1;
			listener.bytes_client_to_server = 100;
			listener.bytes_server_to_client = 200;
			tcp_proxy::fake().snapshot.listeners = { listener };
			tcp_proxy::RuleStats rule;
			rule.rule_id = 7;
			rule.matched_total = 5;
			rule.rejected_total = 1;
			rule.bytes_client_to_server = 100;
			rule.bytes_server_to_client = 200;
			tcp_proxy::fake().snapshot.rules = { rule };
		}
		for (const auto& view : scenario.env.views) {
			if (view.name == "stats_tcp_listeners" ||
				view.name == "stats_tcp_rules" ||
				view.name == "runtime_tcp_status") {
				view.refresh(&scenario.database.db, nullptr);
			}
		}
		ok(one_int(scenario.database.db,
			"SELECT retired FROM stats_tcp_listeners WHERE listener_id=5") == 1,
			"stats listener preserves retired identity");
		ok(one_int(scenario.database.db,
			"SELECT accepted_total FROM stats_tcp_listeners WHERE listener_id=5") == 11,
			"stats listener accepted total is copied");
		ok(one_int(scenario.database.db,
			"SELECT matched_total FROM stats_tcp_rules WHERE rule_id=7") == 5,
			"stats rule matched total is copied");
		ok(one_int(scenario.database.db,
			"SELECT generation FROM runtime_tcp_status WHERE id=1") == 9,
			"runtime status exposes the Engine generation");
		ok(one_int(scenario.database.db,
			"SELECT active_connections FROM runtime_tcp_status WHERE id=1") == 4 &&
			one_int(scenario.database.db,
			"SELECT retired_connections FROM runtime_tcp_status WHERE id=1") == 2,
			"runtime status exposes active and retired connections");
	}

	/* Metrics registration, cleanup and repeated lifecycle. */
	{
		diag(">>> metrics lifecycle and pruning");
		reset_fake_engine();
		Scenario scenario;
		ok(descriptor->init(&scenario.services), "init registers metrics");
		ok(descriptor->start(), "start begins the metrics sampler");
		std::this_thread::sleep_for(std::chrono::milliseconds(150));
		ok(count_metric_families(scenario.env.registry, "proxysql_tcp_") >= 9,
			"TCP metric families publish samples after sampling");
		ok(scenario.env.with_admin_db_lock_calls.load() == 0,
			"the sampler never waits for the Admin SQL mutex");
		bool component_labeled = true;
		for (const auto& family : scenario.env.registry.Collect()) {
			if (family.name.rfind("proxysql_tcp_", 0) != 0) continue;
			for (const auto& metric : family.metric) {
				bool component = false;
				for (const auto& label : metric.label) {
					if (label.name == "component" &&
						label.value == "tcp_proxy") component = true;
				}
				if (!component) component_labeled = false;
			}
		}
		ok(component_labeled,
			"every TCP sample carries the fixed component=tcp_proxy label");
		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::ListenerStats listener;
			listener.listener_id = 42;
			listener.active_connections = 1;
			tcp_proxy::fake().snapshot.listeners = { listener };
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1200));
		bool listener_label_present = false;
		for (const auto& family : scenario.env.registry.Collect()) {
			if (family.name != "proxysql_tcp_active_connections") continue;
			for (const auto& metric : family.metric) {
				bool listener_scope = false;
				bool matching_id = false;
				for (const auto& label : metric.label) {
					if (label.name == "scope" && label.value == "listener") listener_scope = true;
					if (label.name == "id" && label.value == "42") matching_id = true;
				}
				if (listener_scope && matching_id) listener_label_present = true;
			}
		}
		ok(listener_label_present, "configured listener samples are published before removal");
		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().snapshot.listeners.clear();
			tcp_proxy::fake().snapshot.rules.clear();
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1200));
		bool pruned = true;
		for (const auto& family : scenario.env.registry.Collect()) {
			if (family.name == "proxysql_tcp_active_connections") {
				for (const auto& metric : family.metric) {
					bool listener_scope = false;
					bool matching_id = false;
					for (const auto& label : metric.label) {
						if (label.name == "scope" && label.value == "listener") listener_scope = true;
						if (label.name == "id" && label.value == "42") matching_id = true;
					}
					if (listener_scope && matching_id) pruned = false;
				}
			}
		}
		ok(pruned, "retired per-ID metric series are pruned after removal");
		ok(descriptor->stop(), "stop after sampling succeeds");
		ok(count_metric_families(scenario.env.registry, "proxysql_tcp_") == 0,
			"metrics are unregistered before stop returns");
		ok(retained_families_have_no_samples(scenario.env.registry),
			"stop removes every plugin-owned sample from the retained families");
		const std::vector<void*> retained =
			register_retained_families(scenario.env.registry);
		ok(retained.size() == 10,
			"the process retains exactly ten stable TCP families");

		ok(descriptor->init(&scenario.services) && descriptor->start() &&
			descriptor->stop(), "second init/start/stop cycle succeeds");
		ok(count_metric_families(scenario.env.registry, "proxysql_tcp_") == 0,
			"repeated lifecycle leaves no duplicate or stale families");
		ok(register_retained_families(scenario.env.registry) == retained,
			"repeated lifecycle rebinds the same core-owned family objects");
		ok(retained_families_have_no_samples(scenario.env.registry),
			"repeated lifecycle leaves zero plugin-owned samples");
	}

	/* Coherent runtime read: generation churn and copy failures must fail
	 * safely without touching the editable tables. */
	{
		diag(">>> coherent runtime read failures");
		reset_fake_engine();
		Scenario scenario;
		ok(insert_base_rows(scenario.database.db), "inserted base rows");
		ok(descriptor->init(&scenario.services) && descriptor->start(),
			"started for coherent-read tests");
		ProxySQL_PluginCommandContext context = command_context(scenario.env);
		auto save = command(scenario.env, "SAVE TCP CONFIG FROM RUNTIME");
		auto refresh = [&](const std::string& table) {
			for (const auto& view : scenario.env.views) {
				if (view.name == table) {
					view.refresh(&scenario.database.db, nullptr);
					return true;
				}
			}
			return false;
		};

		ok(execute(scenario.database.db,
			"UPDATE tcp_hostgroups SET comment='unactivated-churn' WHERE hostgroup_id=10"),
			"make an unactivated Main edit");
		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().generation_changes_every_read = true;
		}
		ProxySQL_PluginCommandResult result = save(context, nullptr);
		ok(result.error_code != 0 &&
			result.message.find("changing") != std::string::npos,
			"SAVE rejects a generation that changes on every fence: %s",
			result.message.c_str());
		ok(one_text(scenario.database.db,
			"SELECT comment FROM tcp_hostgroups WHERE hostgroup_id=10") ==
			"unactivated-churn",
			"failed coherent SAVE leaves the editable tables untouched");
		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().generation_changes_every_read = false;
		}

		ok(execute(scenario.database.db,
			"UPDATE tcp_hostgroups SET comment='unactivated-copy' WHERE hostgroup_id=10"),
			"prepare a second unactivated edit");
		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().throw_config = true;
		}
		result = save(context, nullptr);
		ok(result.error_code != 0 &&
			result.message.find("cannot read TCP runtime configuration") !=
				std::string::npos,
			"SAVE propagates a config copy failure as an error: %s",
			result.message.c_str());
		ok(one_text(scenario.database.db,
			"SELECT comment FROM tcp_hostgroups WHERE hostgroup_id=10") ==
			"unactivated-copy",
			"config copy failure preserves the editable tables");
		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().throw_config = false;
		}

		result = save(context, nullptr);
		ok(result.error_code == 0,
			"SAVE works again once the Engine reads are coherent: %s",
			result.message.c_str());
		ok(one_text(scenario.database.db,
			"SELECT comment FROM tcp_hostgroups WHERE hostgroup_id=10") == "hg",
			"successful SAVE restored the effective runtime row");

		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().throw_snapshot = true;
		}
		bool views_survived = true;
		try {
			for (const char* table : { "runtime_tcp_settings",
					"runtime_tcp_hostgroups", "runtime_tcp_listeners",
					"runtime_tcp_routing_rules", "runtime_tcp_status",
					"stats_tcp_listeners", "stats_tcp_rules" }) {
				if (!refresh(table)) views_survived = false;
			}
		} catch (...) {
			views_survived = false;
		}
		ok(views_survived,
			"projection refreshes contain snapshot read exceptions");
		const char* status = descriptor->status_json();
		ok(status != nullptr && std::strstr(status, "\"plugin\":\"tcp_proxy\"") != nullptr,
			"status_json returns module-owned JSON during a read failure");
		ok(status != nullptr &&
			std::strstr(status, "\"state\":\"error\"") != nullptr,
			"status_json falls back to the static error document");
		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().throw_snapshot = false;
		}
	}

	/* Metrics use Counter families for cumulative totals, add only monotonic
	 * deltas, recreate reset series and contain sampler read exceptions. */
	{
		diag(">>> metrics counters, deltas and sampler containment");
		reset_fake_engine();
		Scenario scenario;
		ok(descriptor->init(&scenario.services) && descriptor->start(),
			"started for counter projection");
		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::FakeEngine& state = tcp_proxy::fake();
			state.snapshot.generation = 5;
			state.snapshot.active_connections = 4;
			state.snapshot.accepted_total = 10;
			state.snapshot.rejected_total = 2;
			state.snapshot.connect_errors = 1;
			state.snapshot.bytes_client_to_server = 100;
			state.snapshot.bytes_server_to_client = 200;
			tcp_proxy::ListenerStats listener;
			listener.listener_id = 5;
			listener.active_connections = 1;
			state.snapshot.listeners = { listener };
			tcp_proxy::RuleStats rule;
			rule.rule_id = 7;
			rule.matched_total = 2;
			state.snapshot.rules = { rule };
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1300));
		const std::set<std::string> counters {
			"proxysql_tcp_accepted_total",
			"proxysql_tcp_rejected_total",
			"proxysql_tcp_connect_errors_total",
			"proxysql_tcp_matched_total",
			"proxysql_tcp_bytes_client_to_server_total",
			"proxysql_tcp_bytes_server_to_client_total",
		};
		bool counters_typed = true;
		for (const auto& name : counters) {
			if (!metric_family_type(scenario.env.registry, name,
					prometheus::MetricType::Counter)) {
				counters_typed = false;
			}
		}
		ok(counters_typed, "cumulative TCP totals are Counter families");
		ok(metric_family_type(scenario.env.registry,
			"proxysql_tcp_active_connections", prometheus::MetricType::Gauge) &&
			metric_family_type(scenario.env.registry,
				"proxysql_tcp_generation", prometheus::MetricType::Gauge) &&
			metric_family_type(scenario.env.registry,
				"proxysql_tcp_running", prometheus::MetricType::Gauge) &&
			metric_family_type(scenario.env.registry,
				"proxysql_tcp_retired_connections", prometheus::MetricType::Gauge),
			"point-in-time TCP state remains Gauge families");
		ok(global_metric_value(scenario.env.registry,
			"proxysql_tcp_accepted_total") == 10 &&
			global_metric_value(scenario.env.registry,
				"proxysql_tcp_bytes_client_to_server_total") == 100,
			"first sample exposes the Engine cumulative values");
		ok(global_metric_value(scenario.env.registry,
			"proxysql_tcp_active_connections") == 4 &&
			global_metric_value(scenario.env.registry,
				"proxysql_tcp_generation") == 5,
			"gauge samples expose active connections and generation");

		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::FakeEngine& state = tcp_proxy::fake();
			state.snapshot.active_connections = 6;
			state.snapshot.accepted_total = 25;
			state.snapshot.bytes_client_to_server = 300;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1300));
		ok(global_metric_value(scenario.env.registry,
			"proxysql_tcp_accepted_total") == 25,
			"counter adds only the positive delta between samples");
		ok(global_metric_value(scenario.env.registry,
			"proxysql_tcp_bytes_client_to_server_total") == 300,
			"byte counter follows the Engine cumulative total");
		ok(global_metric_value(scenario.env.registry,
			"proxysql_tcp_active_connections") == 6,
			"active gauge tracks decreases and increases");

		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().snapshot.accepted_total = 5;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1300));
		ok(global_metric_value(scenario.env.registry,
			"proxysql_tcp_accepted_total") == 5,
			"a decreased Engine total recreates the counter series at zero");

		std::string diagnostic;
		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().throw_snapshot = true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1300));
		{
			std::lock_guard<std::mutex> guard(
				tcp_proxy_plugin::context().status_mutex);
			diagnostic = tcp_proxy_plugin::context().metrics_diagnostic;
		}
		ok(!diagnostic.empty() && diagnostic.size() <= 512,
			"sampler records a bounded diagnostic after a read exception (size %zu)",
			diagnostic.size());
		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().throw_snapshot = false;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(1300));
		ok(global_metric_value(scenario.env.registry,
			"proxysql_tcp_running") == 1,
			"sampler keeps publishing after containing a read exception");
		ok(descriptor->stop(), "stop after contained sampler failure succeeds");
	}

	/* A late registration conflict must roll back every owned family, keep the
	 * preexisting foreign family and allow a later plugin init to succeed. */
	{
		diag(">>> metrics partial registration rollback");
		reset_fake_engine();
		Scenario scenario;
		prometheus::Family<prometheus::Gauge>& foreign =
			prometheus::BuildGauge()
				.Name("proxysql_tcp_matched_total")
				.Help("foreign preexisting family marker.")
				.Register(scenario.env.registry);
		/* Give the foreign family a sample so Registry::Collect() exposes it
		 * (an empty family is intentionally absent from Collect()). */
		foreign.Add({ { "owner", "foreign" } }).Set(1);
		ok(!descriptor->init(&scenario.services),
			"init fails on a late conflicting family name");
		ok(count_metric_families(scenario.env.registry, "proxysql_tcp_") == 1,
			"failed init rolls back every family it already registered (got %d)",
			count_metric_families(scenario.env.registry, "proxysql_tcp_"));
		prometheus::MetricFamily preserved;
		ok(find_metric_family(scenario.env.registry,
				"proxysql_tcp_matched_total", preserved) &&
			preserved.help == "foreign preexisting family marker.",
			"the preexisting foreign family is preserved exactly");
		scenario.env.registry.Remove(foreign);
		/* Registry::Collect() hides empty families, but a leaked early family
		 * would still occupy its name.  A same-name Counter probe therefore
		 * detects the different-type orphan that a missing rollback leaves. */
		bool early_family_rolled_back = true;
		try {
			prometheus::Family<prometheus::Counter>& probe =
				prometheus::BuildCounter()
					.Name("proxysql_tcp_active_connections")
					.Help("rollback probe.")
					.Register(scenario.env.registry);
			scenario.env.registry.Remove(probe);
		} catch (...) {
			early_family_rolled_back = false;
		}
		ok(early_family_rolled_back,
			"failed init leaves no earlier owned family registered");
		ok(descriptor->init(&scenario.services),
			"a later plugin init succeeds after the conflict is removed");
		ok(descriptor->start(), "metrics start after the recovered init");
		ok(descriptor->stop(), "stop after the recovered init succeeds");
		ok(count_metric_families(scenario.env.registry, "proxysql_tcp_") == 0,
			"recovered lifecycle removes all owned families cleanly");
	}

	/* Same-type preexisting families must never be adopted or removed. */
	{
		diag(">>> metrics same-type foreign family ownership");
		reset_fake_engine();
		Scenario scenario;
		prometheus::Family<prometheus::Gauge>& foreign =
			prometheus::BuildGauge()
				.Name("proxysql_tcp_active_connections")
				.Help("foreign same-type family marker.")
				.Labels(tcp_component_labels())
				.Register(scenario.env.registry);
		prometheus::Gauge& foreign_sample =
			foreign.Add({ { "owner", "foreign" } });
		foreign_sample.Set(42);
		ok(!descriptor->init(&scenario.services),
			"init rejects a visible same-type foreign family");
		double value = -1;
		ok(find_labeled_sample(scenario.env.registry,
				"proxysql_tcp_active_connections", "owner", "foreign", value) &&
			value == 42,
			"the foreign family and its original sample are preserved");
		bool adopted_foreign_label = false;
		for (const auto& family : scenario.env.registry.Collect()) {
			if (family.name != "proxysql_tcp_active_connections") continue;
			for (const auto& metric : family.metric) {
				for (const auto& label : metric.label) {
					if (label.name == "scope" && label.value == "global") {
						adopted_foreign_label = true;
					}
				}
			}
		}
		ok(!adopted_foreign_label,
			"the plugin does not adopt a sample into the foreign family");
		scenario.env.registry.Remove(foreign);
		ok(descriptor->init(&scenario.services),
			"init succeeds after the foreign same-type family is removed");
		ok(descriptor->stop(), "stop after same-type conflict recovery succeeds");
		ok(retained_families_have_no_samples(scenario.env.registry),
			"conflict recovery leaves zero plugin-owned samples");
	}

	/* A hidden (empty) incompatible family makes Register throw; a hidden
	 * compatible family is borrowed and reused after stop. */
	{
		diag(">>> metrics empty family borrowing");
		reset_fake_engine();
		Scenario scenario;
		prometheus::Family<prometheus::Gauge>& incompatible =
			prometheus::BuildGauge()
				.Name("proxysql_tcp_active_connections")
				.Help("hidden incompatible empty family.")
				.Register(scenario.env.registry);
		ok(!descriptor->init(&scenario.services),
			"an empty same-type family with different constant labels is rejected");
		ok(incompatible.Collect().empty() && incompatible.GetName() ==
			"proxysql_tcp_active_connections",
			"the incompatible empty family is left untouched");
		scenario.env.registry.Remove(incompatible);

		prometheus::Family<prometheus::Gauge>& borrowed =
			prometheus::BuildGauge()
				.Name("proxysql_tcp_active_connections")
				.Help("compatible empty family.")
				.Labels(tcp_component_labels())
				.Register(scenario.env.registry);
		ok(descriptor->init(&scenario.services),
			"a compatible empty same-type family is borrowed, not replaced");
		ok(&prometheus::BuildGauge()
				.Name("proxysql_tcp_active_connections")
				.Help("compatible empty family.")
				.Labels(tcp_component_labels())
				.Register(scenario.env.registry) == &borrowed,
			"the borrowed family pointer is rebound on restart");
		ok(descriptor->start() && descriptor->stop(),
			"borrowed-family lifecycle succeeds");
		ok(borrowed.Collect().empty(),
			"stop leaves the borrowed family empty");
		prometheus::Gauge& post_stop =
			borrowed.Add({ { "owner", "post-stop" } });
		post_stop.Set(5);
		double value = -1;
		ok(find_labeled_sample(scenario.env.registry,
				"proxysql_tcp_active_connections", "owner", "post-stop", value) &&
			value == 5,
			"the borrowed family reference remains usable after stop");
		borrowed.Remove(&post_stop);
		ok(borrowed.Collect().empty(),
			"the test removed its own post-stop sample");
	}

	/* A foreign sample that appears after registration but before Add is
	 * detected with Family::Has() and never adopted or deleted. */
	{
		diag(">>> metrics foreign sample label collision");
		reset_fake_engine();
		Scenario scenario;
		ok(descriptor->init(&scenario.services),
			"init registers empty families for the collision test");
		prometheus::Family<prometheus::Gauge>& family =
			prometheus::BuildGauge()
				.Name("proxysql_tcp_active_connections")
				.Help("collision family probe.")
				.Labels(tcp_component_labels())
				.Register(scenario.env.registry);
		prometheus::Gauge& foreign =
			family.Add({ { "scope", "global" }, { "id", "0" } });
		foreign.Set(99);
		ok(descriptor->start(),
			"sampler starts with a colliding foreign sample present");
		std::this_thread::sleep_for(std::chrono::milliseconds(1300));
		double value = -1;
		ok(find_labeled_sample(scenario.env.registry,
				"proxysql_tcp_active_connections", "scope", "global", value) &&
			value == 99,
			"the foreign sample keeps its value instead of being adopted");
		std::string diagnostic;
		{
			std::lock_guard<std::mutex> guard(
				tcp_proxy_plugin::context().status_mutex);
			diagnostic = tcp_proxy_plugin::context().metrics_diagnostic;
		}
		ok(!diagnostic.empty(),
			"the sampler records the foreign sample label collision");
		ok(descriptor->stop(),
			"stop with a foreign colliding sample succeeds");
		value = -1;
		ok(find_labeled_sample(scenario.env.registry,
				"proxysql_tcp_active_connections", "scope", "global", value) &&
			value == 99,
			"stop never removes the foreign colliding sample");
		family.Remove(&foreign);
		ok(retained_families_have_no_samples(scenario.env.registry),
			"after test cleanup the retained families hold no owned samples");
	}

	/* Tracking bookkeeping allocation failures must not orphan samples,
	 * including counter last-value nodes and the scalar gauges. */
	{
		diag(">>> metric tracking rollback");
		reset_fake_engine();
		Scenario scenario;
		tcp_proxy_plugin::Context& ctx = tcp_proxy_plugin::context();
		ok(descriptor->init(&scenario.services),
			"init for tracking-failure tests");
		bool contained = true;
		for (int stage : { 1, 2, 3, 4, 5 }) {
			tcp_proxy_plugin::metrics_test_set_failure_stage(stage);
			std::string publish_error;
			const bool published =
				tcp_proxy_plugin::metrics_test_publish_once(ctx, publish_error);
			ok(!published && !publish_error.empty(),
				"forced publish allocation failure stage %d is contained", stage);
			if (published) contained = false;
			tcp_proxy_plugin::metrics_unregister(ctx);
			ok(retained_families_have_no_samples(scenario.env.registry),
				"publish failure stage %d leaves no untracked sample", stage);
			std::string init_error;
			const bool reinitialized =
				tcp_proxy_plugin::metrics_init(scenario.services, ctx, init_error);
			ok(reinitialized,
				"metrics re-init after publish failure stage %d: %s", stage,
				init_error.c_str());
			if (!reinitialized) contained = false;
		}
		for (int index = 1; index <= 3; ++index) {
			tcp_proxy_plugin::metrics_unregister(ctx);
			tcp_proxy_plugin::metrics_test_set_failure_stage(10 + index);
			std::string init_error;
			ok(!tcp_proxy_plugin::metrics_init(scenario.services, ctx, init_error) &&
				!init_error.empty(),
				"forced scalar tracking failure %d fails init", index);
			ok(retained_families_have_no_samples(scenario.env.registry),
				"scalar failure %d rolls back every sample it created", index);
		}
		ok(contained, "every injected tracking failure was contained");
		tcp_proxy_plugin::metrics_test_set_failure_stage(-1);
		std::string init_error;
		ok(tcp_proxy_plugin::metrics_init(scenario.services, ctx, init_error),
			"metrics init succeeds after forced tracking failures: %s",
			init_error.c_str());
		ok(descriptor->start(), "sampler starts after tracking failure recovery");
		std::this_thread::sleep_for(std::chrono::milliseconds(1200));
		ok(count_metric_families(scenario.env.registry, "proxysql_tcp_") >= 9,
			"metrics publish normally after tracking failure recovery");
		ok(descriptor->stop(),
			"stop after tracking failure recovery succeeds");
		ok(retained_families_have_no_samples(scenario.env.registry),
			"tracking failure recovery leaves zero owned samples after stop");
	}

	/* Fast Admin SHUTDOWN/KILL exits while the caller owns the SQL mutex.
	 * Plugin teardown must join its sampler without waiting for that mutex. */
	{
		diag(">>> sampler teardown while Admin SQL mutex is held");
		reset_fake_engine();
		Scenario scenario;
		ok(descriptor->init(&scenario.services), "init before locked Admin teardown");
		std::unique_lock<std::mutex> admin_guard(scenario.env.admin_db_mutex);
		ok(descriptor->start(), "start while Admin SQL mutex is held");
		std::this_thread::sleep_for(std::chrono::milliseconds(150));
		std::atomic<bool> finished { false };
		std::atomic<bool> stopped { false };
		std::thread stopper([&]() {
			stopped.store(descriptor->stop());
			finished.store(true);
		});
		const auto deadline = std::chrono::steady_clock::now() +
			std::chrono::seconds(1);
		while (!finished.load() && std::chrono::steady_clock::now() < deadline) {
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
		}
		const bool completed_while_locked = finished.load();
		/* Release even on failure so this regression reports instead of hangs. */
		admin_guard.unlock();
		stopper.join();
		ok(completed_while_locked && stopped.load(),
			"stop joins sampler while its caller still owns Admin SQL mutex");
		ok(scenario.env.with_admin_db_lock_calls.load() == 0,
			"sampler teardown has no dependency on Admin SQL serialization");
		ok(retained_families_have_no_samples(scenario.env.registry),
			"locked Admin teardown leaves zero plugin-owned samples");
		/* Core v4 resets counters only after plugin/worker teardown. */
		scenario.env.registry.ResetCounters();
		ok(descriptor->init(&scenario.services) && descriptor->start(),
			"restart after quiesced counter reset succeeds");
		std::this_thread::sleep_for(std::chrono::milliseconds(150));
		ok(count_metric_families(scenario.env.registry, "proxysql_tcp_") >= 9,
			"sampler republishes retained families after restart");
		ok(descriptor->stop(), "stop after quiesced counter reset succeeds");
	}

	/* Legacy artifacts are refused without dropping or migrating any data. */
	{
		diag(">>> legacy artifact refusal");
		reset_fake_engine();
		{
			Scenario scenario;
			ok(execute(scenario.database.db,
				"CREATE TABLE tcp_servers(server_id INTEGER PRIMARY KEY, "
				"hostgroup_id INTEGER, hostname TEXT, port INTEGER)") &&
				execute(scenario.database.db,
					"INSERT INTO tcp_servers VALUES(1,10,'127.0.0.1',9001)"),
				"create a legacy main tcp_servers artifact");
			ok(!descriptor->init(&scenario.services),
				"init refuses a legacy main tcp_servers table");
			ok(one_int(scenario.database.db,
				"SELECT COUNT(*) FROM tcp_servers") == 1,
				"legacy main rows are preserved");
			std::string last_error;
			tcp_proxy_plugin::state_snapshot(tcp_proxy_plugin::context(),
				last_error);
			ok(last_error.find("legacy") != std::string::npos,
				"main artifact diagnostic names the legacy table: %s",
				last_error.c_str());
		}
		reset_fake_engine();
		{
			Scenario scenario;
			ok(execute(scenario.database.db,
				"CREATE TABLE disk.tcp_hostgroup_mappings(hostgroup_id INTEGER "
				"PRIMARY KEY, source_protocol TEXT, source_hostgroup INTEGER)") &&
				execute(scenario.database.db,
					"INSERT INTO disk.tcp_hostgroup_mappings "
					"VALUES(10,'MYSQL',10)"),
				"create a legacy disk mapping artifact");
			ok(!descriptor->init(&scenario.services),
				"init refuses a legacy disk mapping table");
			ok(one_int(scenario.database.db,
				"SELECT COUNT(*) FROM disk.tcp_hostgroup_mappings") == 1,
				"legacy disk rows are preserved");
		}
		reset_fake_engine();
		{
			Scenario scenario;
			ok(execute(scenario.database.db,
				"CREATE TABLE \"TCP_Servers\"(server_id INTEGER PRIMARY KEY)") &&
				execute(scenario.database.db,
					"INSERT INTO \"TCP_Servers\" VALUES(1)"),
				"create a mixed-case main legacy table");
			ok(!descriptor->init(&scenario.services),
				"init refuses a mixed-case legacy table");
			ok(one_int(scenario.database.db,
				"SELECT COUNT(*) FROM \"TCP_Servers\"") == 1,
				"mixed-case legacy rows are preserved");
		}
		reset_fake_engine();
		{
			Scenario scenario;
			ok(execute(scenario.database.db,
				"CREATE VIEW tcp_hostgroup_mappings AS SELECT 1 AS hostgroup_id"),
				"create a legacy view");
			ok(!descriptor->init(&scenario.services),
				"init refuses a legacy view");
		}
		reset_fake_engine();
		{
			Scenario scenario;
			ok(execute(scenario.database.db,
				"CREATE TABLE harmless(id INTEGER)") &&
				execute(scenario.database.db,
					"CREATE INDEX tcp_servers ON harmless(id)"),
				"create a legacy index name");
			ok(!descriptor->init(&scenario.services),
				"init refuses a legacy index object");
		}
		{
			SQLite3DB isolated;
			isolated.open(const_cast<char*>(":memory:"),
				SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
			std::string error;
			ok(tcp_proxy_plugin::reject_legacy_artifacts(isolated, "disk", error),
				"an unattached disk schema is accepted as absent");
		}
		reset_fake_engine();
		{
			Scenario scenario;
			sqlite3* raw = scenario.database.db.get_db();
			ok(raw != nullptr &&
				sqlite3_set_authorizer(raw, &deny_sqlite_master_reads, nullptr) ==
					SQLITE_OK,
				"install a metadata-read denial");
			std::string error;
			const bool accepted = tcp_proxy_plugin::reject_legacy_artifacts(
				scenario.database.db, "main", error);
			ok(!accepted && !error.empty(),
				"metadata query errors fail closed: %s", error.c_str());
			if (raw != nullptr) {
				sqlite3_set_authorizer(raw, nullptr, nullptr);
			}
		}
		reset_fake_engine();
		{
			Scenario scenario;
			ok(descriptor->init(&scenario.services) && descriptor->start(),
				"started before a late disk artifact appears");
			ProxySQL_PluginCommandContext context = command_context(scenario.env);
			const int applies_before = tcp_proxy::fake().apply_calls;
			ok(execute(scenario.database.db,
				"CREATE TABLE disk.tcp_servers(server_id INTEGER PRIMARY KEY)") &&
				execute(scenario.database.db,
					"INSERT INTO disk.tcp_servers VALUES(1)"),
				"create a disk artifact after init");
			ProxySQL_PluginCommandResult result = command(scenario.env,
				"LOAD TCP CONFIG TO RUNTIME")(context, nullptr);
			ok(result.error_code != 0 &&
				result.message.find("legacy") != std::string::npos,
				"LOAD TO RUNTIME refuses a disk artifact: %s",
				result.message.c_str());
			ok(tcp_proxy::fake().apply_calls == applies_before,
				"disk artifact refusal never reaches Engine::apply");
			ok(one_int(scenario.database.db,
				"SELECT COUNT(*) FROM disk.tcp_servers") == 1,
				"late disk legacy rows are preserved");
		}
	}

	/* SQLite schema aliases are case-insensitive, including disk attachments. */
	{
		diag(">>> legacy artifact in a mixed-case disk attachment");
		reset_fake_engine();
		Scenario scenario;
		std::string error;
		ok(tcp_proxy_plugin::seed_settings_defaults(scenario.database.db, error) &&
			execute(scenario.database.db, "DETACH DATABASE disk") &&
			execute(scenario.database.db, "ATTACH ':memory:' AS DiSk") &&
			execute(scenario.database.db,
				"CREATE TABLE DiSk.TCP_SERVERS(payload TEXT)") &&
			execute(scenario.database.db,
				"INSERT INTO DiSk.TCP_SERVERS VALUES('retained')"),
			"create a legacy artifact under a mixed-case disk alias");
		tcp_proxy::Config parsed;
		const bool accepted = tcp_proxy_plugin::read_config(
			scenario.database.db, parsed, error);
		ok(!accepted &&
			error.find("legacy") != std::string::npos,
			"read_config refuses legacy artifacts under the DiSk alias: %s",
			error.c_str());
		ok(!descriptor->init(&scenario.services),
			"init refuses legacy artifacts under the DiSk alias");
		ok(one_text(scenario.database.db,
			"SELECT payload FROM disk.TCP_SERVERS") == "retained",
			"mixed-case disk attachment retains legacy data");
	}

	/* Initialization/start failure cleanup. */
	{
		diag(">>> failure cleanup");
		reset_fake_engine();
		{
			Scenario scenario;
			ok(execute(scenario.database.db,
				"PRAGMA ignore_check_constraints=ON") &&
				execute(scenario.database.db,
					"INSERT INTO tcp_hostgroups(hostgroup_id,source_protocol,"
					"source_hostgroup) VALUES(10,'invalid',10)") &&
				execute(scenario.database.db,
					"PRAGMA ignore_check_constraints=OFF"),
				"persist an invalid hostgroup row");
			ok(!descriptor->init(&scenario.services),
				"invalid persisted configuration fails init");
			ok(one_text(scenario.database.db,
				"SELECT source_protocol FROM tcp_hostgroups "
				"WHERE hostgroup_id=10") == "invalid",
				"invalid persisted rows are not overwritten");
			ok(count_metric_families(scenario.env.registry, "proxysql_tcp_") == 0,
				"failed init leaves no metric families");
		}
		reset_fake_engine();
		Scenario scenario;
		{
			std::lock_guard<std::mutex> guard(tcp_proxy::fake().mutex);
			tcp_proxy::fake().fail_start = true;
		}
		ok(descriptor->init(&scenario.services), "init succeeds before a failed start");
		ok(!descriptor->start(), "Engine start failure is propagated");
		ok(descriptor->stop(), "stop tolerates a start failure");
		ok(count_metric_families(scenario.env.registry, "proxysql_tcp_") == 0,
			"failed start cleanup removes metrics");
	}

	/* Module-owned Context storage: idle finalization must not invalidate a
	 * freshly fetched reference, and stop remains idempotent. */
	{
		diag(">>> module context lifetime and idempotent stop");
		reset_fake_engine();
		ok(descriptor->stop(), "stop tolerates a never-initialized context");
		{
			Scenario scenario;
			ok(descriptor->init(&scenario.services) && descriptor->start() &&
				descriptor->stop(), "short lifecycle before finalization");
		}
		tcp_proxy_plugin::context_finalize_if_idle();
		tcp_proxy_plugin::Context& fresh = tcp_proxy_plugin::context();
		std::string last_error;
		ok(tcp_proxy_plugin::state_snapshot(fresh, last_error) == "stopped" &&
			!fresh.initialized.load() && !fresh.started.load() &&
			last_error.empty(),
			"idle finalization leaves a fresh usable stopped Context");
		ok(descriptor->stop(), "stop on the fresh Context is idempotent");
	}

	return exit_status();
}
