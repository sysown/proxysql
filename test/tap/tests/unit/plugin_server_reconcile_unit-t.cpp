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

#include <algorithm>
#include <atomic>
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

#ifndef PROXYSQL_FAKE_PLUGIN_PATH
#error "PROXYSQL_FAKE_PLUGIN_PATH must be defined"
#endif

namespace {

struct AckState {
	std::mutex mutex;
	std::vector<std::pair<uint64_t, bool>> values;
	std::atomic<unsigned int> shutdowns {0};
	std::atomic<unsigned int> destroyed {0};
};

class Controller final : public ProxySQL_ServerDiscoveryController {
public:
	explicit Controller(AckState* state) : state_(state) {}
	void runtime_configuration_installed(ProxySQL_ServerRuntimeSnapshot) override {}
	void desired_set_applied(uint64_t generation, bool applied) override {
		std::lock_guard<std::mutex> lock(state_->mutex);
		state_->values.emplace_back(generation, applied);
	}
	void shutdown() override { state_->shutdowns.fetch_add(1); }
	AckState* state() const { return state_; }
private:
	AckState* state_;
};

void destroy_controller(ProxySQL_ServerDiscoveryController* controller) {
	auto* owned = static_cast<Controller*>(controller);
	owned->state()->destroyed.fetch_add(1);
	delete owned;
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

std::unique_ptr<SQLite3_result> replication_rows(uint32_t writer, uint32_t reader) {
	auto result = std::make_unique<SQLite3_result>(4);
	std::string writer_text = std::to_string(writer);
	std::string reader_text = std::to_string(reader);
	char check[] = "read_only";
	char comment[] = "discovery test";
	char* fields[] = {writer_text.data(), reader_text.data(), check, comment};
	result->add_row(fields);
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

std::unique_ptr<SQLite3_result> runtime_rows() {
	return std::unique_ptr<SQLite3_result>(MyHGM->dump_table_mysql("mysql_servers"));
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

size_t ack_count(AckState& state, uint64_t generation, bool applied) {
	std::lock_guard<std::mutex> lock(state.mutex);
	return std::count(state.values.begin(), state.values.end(), std::make_pair(generation, applied));
}

void clear_acks(AckState& state) {
	std::lock_guard<std::mutex> lock(state.mutex);
	state.values.clear();
}

ProxySQL_ServerDesiredSet desired(uint64_t generation, std::vector<ProxySQL_ServerRow> rows) {
	return {ProxySQL_ServerProtocol::mysql, generation, {18, 17}, std::move(rows),
		ProxySQL_ServerPersistence::runtime_only};
}

ProxySQL_ServerDesiredSet pgsql_desired(uint64_t generation,
	std::vector<ProxySQL_ServerRow> rows) {
	return {ProxySQL_ServerProtocol::pgsql, generation, {18, 17}, std::move(rows),
		ProxySQL_ServerPersistence::runtime_only};
}

} // namespace

int main() {
	plan(41);
	test_init_minimal();
	test_init_query_processor();
	test_init_hostgroups();
	char stats_memory_db[] = ":memory:";
	GloVars.statsdb_disk = stats_memory_db;
	GloProxyStats = new ProxySQL_Statistics();
	GloMyMon = new MySQL_Monitor();
	MyHGM->gtid_ev_loop = ev_loop_new(0);
	ev_async_init(MyHGM->gtid_ev_async, [](EV_P_ ev_async*, int) {});

	auto* admin = new ProxySQL_Admin();
	GloAdmin = admin;
	ok(pipe(admin->pipefd) == 0, "Admin wake pipe is available to worker posts");

	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_SERVER_DISCOVERY", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_AFFILIATED", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_BOTH_PROTOCOLS", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_SERVER_MODULE_CONFLICT_CLAIM", "1", 1);
	std::unique_ptr<ProxySQL_PluginManager> manager;
	std::string error;
	ok(proxysql_load_configured_plugins(manager, {PROXYSQL_FAKE_PLUGIN_PATH}, error) &&
		proxysql_init_configured_plugins(manager.get(), error),
		"affiliated server module is live for reconciliation claims");

	AckState acks;
	void* controller_handle = dlopen(PROXYSQL_FAKE_PLUGIN_PATH, RTLD_NOW | RTLD_LOCAL);
	ok(controller_handle != nullptr && manager->install_server_discovery_controller(
		ProxySQL_ServerProtocol::mysql, new Controller(&acks), &destroy_controller, controller_handle),
		"controller is registered with a retained DSO boundary");
	AckState pgsql_acks;
	void* pgsql_controller_handle = dlopen(PROXYSQL_FAKE_PLUGIN_PATH, RTLD_NOW | RTLD_LOCAL);
	ok(pgsql_controller_handle != nullptr && manager->install_server_discovery_controller(
		ProxySQL_ServerProtocol::pgsql, new Controller(&pgsql_acks), &destroy_controller,
		pgsql_controller_handle), "PostgreSQL controller shares the retained queue boundary");

	ProxySQL_ServerRuntimeSnapshot installed {};
	installed.protocol = ProxySQL_ServerProtocol::mysql;
	ProxySQL_ServerRuntimeInstallTransaction install(installed.protocol, error);
	const uint64_t generation = install.generation();
	ok(install.prepare(installed, error) && install.commit(installed),
		"runtime generation installs the module's delegated writer/reader claims");
	ProxySQL_ServerRuntimeSnapshot pgsql_installed {};
	pgsql_installed.protocol = ProxySQL_ServerProtocol::pgsql;
	ProxySQL_ServerRuntimeInstallTransaction pgsql_install(pgsql_installed.protocol, error);
	const uint64_t pgsql_generation = pgsql_install.generation();
	ok(pgsql_install.prepare(pgsql_installed, error) && pgsql_install.commit(pgsql_installed),
		"PostgreSQL runtime generation installs independent delegated claims");

	auto initial = mysql_rows({
		{17, "old.example", 3306, 0, "ONLINE", 10, 0, 100, 0, 1, 0, "old"},
		{18, "reader.example", 3306, 0, "ONLINE", 20, 0, 100, 0, 1, 0, "reader"},
		{99, "unrelated.example", 3306, 0, "ONLINE", 90, 0, 100, 0, 1, 0, "keep"}});
	MyHGM->save_incoming_mysql_table(replication_rows(17, 18).release(),
		"mysql_replication_hostgroups");
	MyHGM->servers_add(initial.get());
	ok(MyHGM->commit({}, {}, false),
		"real MySQL HGM fixture starts with delegated topology and unrelated runtime members");
	std::atomic<unsigned int> concurrent_posts {0};
	std::vector<std::thread> producers;
	for (unsigned int index = 0; index < 4; ++index) {
		producers.emplace_back([&, index] {
			ProxySQL_ServerRow outside {static_cast<uint32_t>(70 + index),
				"worker-" + std::to_string(index) + ".example", 3306};
			if (manager->post_server_desired_set(desired(generation, {outside})))
				concurrent_posts.fetch_add(1);
		});
	}
	for (auto& producer : producers) producer.join();
	ok(concurrent_posts.load() == 4 && find_row(*runtime_rows(), 17, "old.example", 3306) != nullptr,
		"multiple worker threads post without mutating owner-thread runtime state");
	ok(admin->drain_server_discovery_updates() == 4 && ack_count(acks, generation, false) == 4,
		"owner thread rejects and acknowledges every accepted concurrent malformed update once");
	clear_acks(acks);

	ProxySQL_ServerRow copied {17, "deep-copy.example", 3306, 0, "ONLINE", 31, 0, 101, 0, 1, 0, "copied"};
	copied.topology_role_epoch = 7;
	copied.force_topology_role = true;
	ProxySQL_ServerDesiredSet copied_set = desired(generation, {copied});
	std::atomic<bool> posted {false};
	std::thread worker([&] { posted = manager->post_server_desired_set(copied_set); });
	worker.join();
	copied_set.servers[0].hostname = "mutated-after-post.example";
	copied_set.servers[0].comment = "mutated";
	auto before_drain = runtime_rows();
	ok(posted && find_row(*before_drain, 17, "old.example", 3306) != nullptr &&
		find_row(*before_drain, 17, "deep-copy.example", 3306) == nullptr,
		"worker post deep-copies and returns without touching HGM or SQLite");
	ok(admin->drain_server_discovery_updates() == 1, "Admin owner drains one posted update");
	auto after_copy = runtime_rows();
	const SQLite3_row* copied_row = find_row(*after_copy, 17, "deep-copy.example", 3306);
	ok(copied_row != nullptr && std::string(copied_row->fields[11]) == "copied" &&
		find_row(*after_copy, 17, "mutated-after-post.example", 3306) == nullptr,
		"drain applies the copied strings, not producer-owned storage");
	ok(find_row(*after_copy, 99, "unrelated.example", 3306) != nullptr &&
		ack_count(acks, generation, true) == 1,
		"delegated replacement preserves unrelated runtime state and acknowledges once after apply");

	ProxySQL_ServerRow malformed {77, "outside.example", 3306};
	ok(manager->post_server_desired_set(desired(generation, {malformed})) &&
		admin->drain_server_discovery_updates() == 1 && ack_count(acks, generation, false) == 1,
		"non-delegated desired rows are rejected with one false acknowledgement");
	ProxySQL_ServerRow duplicate {17, "duplicate.example", 3306};
	ok(manager->post_server_desired_set(desired(generation, {duplicate, duplicate})) &&
		admin->drain_server_discovery_updates() == 1 && ack_count(acks, generation, false) == 2,
		"duplicate desired rows are rejected before mutation");
	ProxySQL_ServerRow bad_host {17, "", 3306};
	ok(manager->post_server_desired_set(desired(generation, {bad_host})) &&
		admin->drain_server_discovery_updates() == 1 && ack_count(acks, generation, false) == 3,
		"malformed desired rows are rejected before mutation");
	ok(manager->post_server_desired_set({ProxySQL_ServerProtocol::mysql, generation, {}, {},
		ProxySQL_ServerPersistence::runtime_only}) && admin->drain_server_discovery_updates() == 1 &&
		ack_count(acks, generation, false) == 4,
		"inactive empty delegation is no-touch and rejected");
	ProxySQL_ServerDesiredSet unsupported_persistence = desired(generation, {copied});
	unsupported_persistence.persistence = ProxySQL_ServerPersistence::memory;
	ok(manager->post_server_desired_set(std::move(unsupported_persistence)) &&
		admin->drain_server_discovery_updates() == 1 &&
		ack_count(acks, generation, false) == 5,
		"Task 4 fails closed for persistence modes owned by the later persistence adapter");

	ProxySQL_ServerRow hinted_writer {17, "role.example", 3306, 0, "ONLINE", 41, 0, 121, 0, 1, 0, "writer"};
	hinted_writer.topology_role_epoch = 10;
	hinted_writer.force_topology_role = true;
	ok(manager->post_server_desired_set(desired(generation, {hinted_writer})) &&
		admin->drain_server_discovery_updates() == 1,
		"newly discovered member is accepted with a forced role hint");
	auto writer_rows = runtime_rows();
	ok(find_row(*writer_rows, 17, "role.example", 3306) != nullptr,
		"new member is placed in the supplied writer hostgroup");

	MyHGM->read_only_action_v2({{"role.example", 3306, 1}});
	hinted_writer.force_topology_role = false;
	hinted_writer.weight = 42;
	ok(manager->post_server_desired_set(desired(generation, {hinted_writer})) &&
		admin->drain_server_discovery_updates() == 1,
		"unchanged topology epoch is reconciled after a monitor role move");
	auto preserved_role = runtime_rows();
	const SQLite3_row* preserved_reader = find_row(*preserved_role, 18, "role.example", 3306);
	ok(preserved_reader != nullptr && std::string(preserved_reader->fields[5]) == "42" &&
		find_row(*preserved_role, 17, "role.example", 3306) == nullptr,
		"unchanged hint preserves monitor role while applying same-endpoint configured options");
	hinted_writer.topology_role_epoch = 11;
	hinted_writer.force_topology_role = true;
	ok(manager->post_server_desired_set(desired(generation, {hinted_writer})) &&
		admin->drain_server_discovery_updates() == 1,
		"changed topology epoch requests one forced placement update");
	auto forced_role = runtime_rows();
	ok(find_row(*forced_role, 17, "role.example", 3306) != nullptr &&
		find_row(*forced_role, 18, "role.example", 3306) == nullptr,
		"changed hint forces the member back to the writer role");

	ProxySQL_ServerRow both_writer = hinted_writer;
	both_writer.force_topology_role = true;
	ProxySQL_ServerRow both_reader = both_writer;
	both_reader.hostgroup_id = 18;
	both_reader.weight = 51;
	ok(manager->post_server_desired_set(desired(generation, {both_writer, both_reader})) &&
		admin->drain_server_discovery_updates() == 1,
		"an explicit writer-as-reader desired set is accepted");
	auto both_rows = runtime_rows();
	ok(find_row(*both_rows, 17, "role.example", 3306) != nullptr &&
		find_row(*both_rows, 18, "role.example", 3306) != nullptr,
		"the same writer endpoint may exist in both delegated hostgroups");

	ProxySQL_ServerRow shunned = both_writer;
	shunned.hostname = "shunned.example";
	shunned.force_topology_role = true;
	ok(manager->post_server_desired_set(desired(generation, {shunned})) &&
		admin->drain_server_discovery_updates() == 1 &&
		MyHGM->shun_and_killall(const_cast<char*>(shunned.hostname.c_str()), shunned.port),
		"fixture creates monitor-controlled status on an existing discovered member");
	MySrvC* shunned_pool = MyHGM->find_server_in_hg(17, shunned.hostname, shunned.port);
	shunned.force_topology_role = false;
	shunned.weight = 88;
	ok(manager->post_server_desired_set(desired(generation, {shunned})) &&
		admin->drain_server_discovery_updates() == 1,
		"existing member options reconcile without a forced topology role");
	auto shunned_rows = runtime_rows();
	const SQLite3_row* shunned_row = find_row(*shunned_rows, 17, "shunned.example", 3306);
	ok(shunned_row != nullptr && std::string(shunned_row->fields[4]) == "SHUNNED" &&
		std::string(shunned_row->fields[5]) == "88",
		"reconcile preserves monitor status while applying configured options");
	ok(shunned_pool != nullptr &&
		MyHGM->find_server_in_hg(17, shunned.hostname, shunned.port) == shunned_pool,
		"ordinary same-key runtime reconciliation preserves the existing connection pool object");

	ProxySQL_ServerDesiredSet stale = desired(generation, {shunned});
	ok(manager->post_server_desired_set(stale), "currently valid generation queues successfully");
	ProxySQL_ServerRuntimeSnapshot newer {};
	newer.protocol = ProxySQL_ServerProtocol::mysql;
	ProxySQL_ServerRuntimeInstallTransaction newer_install(newer.protocol, error);
	const uint64_t newer_generation = newer_install.generation();
	ok(newer_install.prepare(newer, error) && newer_install.commit(newer),
		"a newer runtime installation advances the controller generation before drain");
	shunned.weight = 99;
	ok(manager->post_server_desired_set(desired(newer_generation, {shunned})) &&
		admin->drain_server_discovery_updates() == 2 &&
		ack_count(acks, generation, false) == 6 && ack_count(acks, newer_generation, true) == 1,
		"owner drain rejects stale work and applies only the newest live generation with exact acknowledgements");

	auto pgsql_initial = pgsql_rows({
		{17, "pgsql-old.example", 5432, 0, "ONLINE", 61, 0, 131, 0, 1, 0, "old"},
		{99, "pgsql-unrelated.example", 5432, 0, "ONLINE", 62, 0, 132, 0, 1, 0, "keep"}});
	PgHGM->servers_add(pgsql_initial.get());
	ok(PgHGM->commit(), "real PostgreSQL HGM fixture starts with unrelated runtime state");
	ProxySQL_ServerRow pgsql_new {18, "pgsql-new.example", 5432, 0, "ONLINE", 71, 0, 141, 0, 1, 0, "new"};
	pgsql_new.topology_role_epoch = 3;
	pgsql_new.force_topology_role = true;
	ok(manager->post_server_desired_set(pgsql_desired(pgsql_generation, {pgsql_new})) &&
		admin->drain_server_discovery_updates() == 1,
		"shared owner queue drains a PostgreSQL desired set through its 11-column adapter");
	std::unique_ptr<SQLite3_result> pgsql_runtime(PgHGM->dump_table_pgsql("pgsql_servers"));
	ok(find_row(*pgsql_runtime, 18, "pgsql-new.example", 5432) != nullptr &&
		find_row(*pgsql_runtime, 99, "pgsql-unrelated.example", 5432) != nullptr &&
		ack_count(pgsql_acks, pgsql_generation, true) == 1,
		"PostgreSQL replacement preserves unrelated rows and acknowledges exactly once");

	size_t accepted = 0;
	for (uint32_t hg = 1000; hg < 1256; ++hg) {
		ProxySQL_ServerDesiredSet queued {ProxySQL_ServerProtocol::mysql,
			hg == 1000 ? generation : newer_generation, {hg}, {},
			ProxySQL_ServerPersistence::runtime_only};
		accepted += manager->post_server_desired_set(std::move(queued)) ? 1 : 0;
	}
	const size_t displaced_before = ack_count(acks, generation, false);
	ok(manager->post_server_desired_set({ProxySQL_ServerProtocol::mysql, newer_generation, {1000}, {},
		ProxySQL_ServerPersistence::runtime_only}) &&
		ack_count(acks, generation, false) == displaced_before + 1,
		"full-queue exact-key coalescing false-acknowledges the displaced accepted generation once");
	ok(accepted == 256 && !manager->post_server_desired_set(
		{ProxySQL_ServerProtocol::mysql, newer_generation, {2000}, {}, ProxySQL_ServerPersistence::runtime_only}),
		"shared inbox is bounded at 256 and fails closed for a different delegation set");
	admin->shutdown_server_discovery_updates();
	ok(!manager->post_server_desired_set(desired(newer_generation, {shunned})),
		"queue shutdown rejects new work after freeing/rejecting copied updates");
	ok(manager->uninstall_server_discovery_controller(ProxySQL_ServerProtocol::mysql) &&
		manager->uninstall_server_discovery_controller(ProxySQL_ServerProtocol::pgsql) &&
		acks.shutdowns.load() == 1 && acks.destroyed.load() == 1 &&
		pgsql_acks.shutdowns.load() == 1 && pgsql_acks.destroyed.load() == 1,
		"shutdown releases all queued leases before one destroy per protocol controller");
	ok(!manager->post_server_desired_set(desired(newer_generation, {shunned})),
		"an unregistered controller rejects desired work without an acknowledgement");

	close(admin->pipefd[0]);
	close(admin->pipefd[1]);
	return exit_status();
}
