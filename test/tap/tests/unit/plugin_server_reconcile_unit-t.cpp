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
#include <chrono>
#include <condition_variable>
#include <cerrno>
#include <cstdlib>
#include <dlfcn.h>
#include <fcntl.h>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unistd.h>
#include <utility>
#include <vector>

extern ProxySQL_Admin* GloAdmin;
extern ProxySQL_Admin* SPA;
extern ProxySQL_Statistics* GloProxyStats;
extern MySQL_Monitor* GloMyMon;
extern void proxysql_wake_server_discovery_admin();

#ifndef PROXYSQL_FAKE_PLUGIN_PATH
#error "PROXYSQL_FAKE_PLUGIN_PATH must be defined"
#endif

// The fixture uses the real constructor but never starts the Admin daemon.
// Initialize the private state normally supplied by init() so scoped owners
// can run the real destructor without joining a nonexistent Admin thread.
class TestDiskUpgrade {
public:
	/** Return an owned, constructor-only Admin prepared for real destruction. */
	static std::unique_ptr<ProxySQL_Admin> make_admin() {
		auto admin = std::make_unique<ProxySQL_Admin>();
		admin->main_shutdown = 0;
		admin->admin_threads_shutdown = true;
		admin->main_poll_nfds = 0;
		admin->main_poll_fds = nullptr;
		admin->main_callback_func = nullptr;
		admin->tables_defs_admin = std::make_unique<std::vector<table_def_t*>>().release();
		admin->tables_defs_stats = std::make_unique<std::vector<table_def_t*>>().release();
		admin->tables_defs_config = std::make_unique<std::vector<table_def_t*>>().release();
		admin->AdminHTTPServer = nullptr;
		admin->AdminRestApiServer = nullptr;
		return admin;
	}
};

namespace {

struct AckState {
	std::mutex mutex;
	std::condition_variable cv;
	std::vector<std::pair<uint64_t, bool>> values;
	std::atomic<unsigned int> shutdowns {0};
	std::atomic<unsigned int> destroyed {0};
	uint64_t blocked_generation {0};
	bool callback_entered {false};
	bool release_callback {false};
};

class Controller final : public ProxySQL_ServerDiscoveryController {
public:
	explicit Controller(AckState* state) : state_(state) {}
	void runtime_configuration_installed(ProxySQL_ServerRuntimeSnapshot) override {}
	void desired_set_applied(uint64_t generation, bool applied) override {
		std::unique_lock<std::mutex> lock(state_->mutex);
		state_->values.emplace_back(generation, applied);
		if (generation == state_->blocked_generation) {
			state_->callback_entered = true;
			state_->cv.notify_all();
			state_->cv.wait(lock, [this] { return state_->release_callback; });
		}
	}
	void shutdown() override { state_->shutdowns.fetch_add(1); }
	AckState* state() const { return state_; }
private:
	AckState* state_;
};

enum class ReconcileHookMode : uint8_t { none, final_apply, hgm_snapshot };

struct ReconcileHookState {
	std::mutex mutex;
	std::condition_variable cv;
	ReconcileHookMode mode {ReconcileHookMode::none};
	bool reached {false};
	bool release {false};
	bool retirement_attempted {false};
};

ReconcileHookState reconcile_hook;

void wait_at_reconcile_hook(ReconcileHookMode expected) {
	std::unique_lock<std::mutex> lock(reconcile_hook.mutex);
	if (reconcile_hook.mode != expected) return;
	reconcile_hook.reached = true;
	reconcile_hook.cv.notify_all();
	reconcile_hook.cv.wait(lock, [] { return reconcile_hook.release; });
}

void after_final_revalidation_hook(ProxySQL_ServerProtocol) {
	wait_at_reconcile_hook(ReconcileHookMode::final_apply);
}

void after_hgm_snapshot_hook(ProxySQL_ServerProtocol) {
	wait_at_reconcile_hook(ReconcileHookMode::hgm_snapshot);
}

void retirement_attempt_hook(ProxySQL_ServerProtocol) {
	std::lock_guard<std::mutex> lock(reconcile_hook.mutex);
	reconcile_hook.retirement_attempted = true;
	reconcile_hook.cv.notify_all();
}

void arm_reconcile_hook(ReconcileHookMode mode) {
	std::lock_guard<std::mutex> lock(reconcile_hook.mutex);
	reconcile_hook.mode = mode;
	reconcile_hook.reached = false;
	reconcile_hook.release = false;
	reconcile_hook.retirement_attempted = false;
}

bool wait_for_hook(bool retirement_attempt = false) {
	std::unique_lock<std::mutex> lock(reconcile_hook.mutex);
	return reconcile_hook.cv.wait_for(lock, std::chrono::seconds(2), [&] {
		return retirement_attempt ? reconcile_hook.retirement_attempted : reconcile_hook.reached;
	});
}

void release_reconcile_hook() {
	std::lock_guard<std::mutex> lock(reconcile_hook.mutex);
	reconcile_hook.release = true;
	reconcile_hook.cv.notify_all();
}

struct RetirementObservation {
	AckState* acks {nullptr};
	uint64_t generation {0};
	std::atomic<size_t> true_acks_at_detach {0};
	std::atomic<bool> detached {false};
};

size_t ack_count(AckState& state, uint64_t generation, bool applied);

void observe_controller_retirement(ProxySQL_ServerProtocol, bool controller, void* opaque) {
	auto* observation = static_cast<RetirementObservation*>(opaque);
	if (!controller || observation == nullptr) return;
	observation->true_acks_at_detach.store(
		ack_count(*observation->acks, observation->generation, true));
	observation->detached.store(true);
}

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

std::unique_ptr<SQLite3_result> replication_rows(
	std::initializer_list<std::pair<uint32_t, uint32_t>> pairs) {
	auto result = std::make_unique<SQLite3_result>(4);
	for (const auto& [writer, reader] : pairs) {
		std::string writer_text = std::to_string(writer);
		std::string reader_text = std::to_string(reader);
		char check[] = "read_only";
		char comment[] = "discovery test";
		char* fields[] = {writer_text.data(), reader_text.data(), check, comment};
		result->add_row(fields);
	}
	return result;
}

std::unique_ptr<SQLite3_result> replication_rows(uint32_t writer, uint32_t reader) {
	return replication_rows({{writer, reader}});
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

bool has_readonly_endpoint(const SQLite3_result& rows, size_t hostname_field,
	const std::string& hostname, uint16_t port) {
	for (const auto* row : rows.rows) {
		if (row != nullptr && row->fields != nullptr && row->fields[hostname_field] != nullptr &&
			hostname == row->fields[hostname_field] &&
			static_cast<uint16_t>(strtoul(row->fields[hostname_field + 1], nullptr, 10)) == port)
			return true;
	}
	return false;
}

std::vector<ProxySQL_ServerHostgroupClaim> large_hostgroup_claim_set() {
	std::vector<ProxySQL_ServerHostgroupClaim> claims {{17, 18}, {27, 28}};
	claims.reserve(500);
	for (uint32_t index = 0; index < 498; ++index)
		claims.push_back({1000 + index * 2, 1001 + index * 2});
	return claims;
}

template <typename HGM>
bool execute_hgm_statement(HGM* hgm, const char* sql) {
	char* error = nullptr;
	std::unique_ptr<SQLite3_result> ignored(hgm->execute_query(const_cast<char*>(sql), &error));
	const bool ok = error == nullptr;
	if (error != nullptr) free(error);
	return ok;
}

struct PublicationRaceState {
	std::mutex mutex;
	std::condition_variable cv;
	bool monitor_started {false};
	bool monitor_done {false};
};

bool run_claim_publication_race(ProxySQL_ServerProtocol protocol,
	const std::function<bool()>& mutate_hgm, const std::function<bool()>& publish_claims,
	const std::function<void()>& monitor_action) {
	PublicationRaceState state;
	proxysql_lock_server_discovery_protocol(protocol);
	const bool hgm_committed = mutate_hgm();
	std::thread monitor([&] {
		{
			std::lock_guard<std::mutex> lock(state.mutex);
			state.monitor_started = true;
			state.cv.notify_all();
		}
		monitor_action();
		{
			std::lock_guard<std::mutex> lock(state.mutex);
			state.monitor_done = true;
			state.cv.notify_all();
		}
	});
	bool completed_before_publication = false;
	{
		std::unique_lock<std::mutex> lock(state.mutex);
		state.cv.wait(lock, [&] { return state.monitor_started; });
		completed_before_publication = state.cv.wait_for(lock, std::chrono::milliseconds(100),
			[&] { return state.monitor_done; });
	}
	const bool install_committed = hgm_committed && publish_claims();
	proxysql_unlock_server_discovery_protocol(protocol);
	monitor.join();
	return install_committed && !completed_before_publication;
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

/** Check server reconciliation and teardown of constructor-only Admin fixtures. */
int main() {
	plan(91);
	proxysql_server_discovery_after_final_revalidation_for_test = &after_final_revalidation_hook;
	proxysql_server_reconcile_after_hgm_snapshot_for_test = &after_hgm_snapshot_hook;
	proxysql_server_discovery_retirement_attempt_for_test = &retirement_attempt_hook;
	test_init_minimal();
	test_init_query_processor();
	test_init_hostgroups();
	char stats_memory_db[] = ":memory:";
	GloVars.statsdb_disk = stats_memory_db;
	GloProxyStats = new ProxySQL_Statistics();
	GloMyMon = new MySQL_Monitor();
	MyHGM->gtid_ev_loop = ev_loop_new(0);
	ev_async_init(MyHGM->gtid_ev_async, [](EV_P_ ev_async*, int) {});

	auto admin_owner = TestDiskUpgrade::make_admin();
	auto* admin = admin_owner.get();
	GloAdmin = admin;
	ok(pipe(admin->pipefd) == 0, "Admin wake pipe is available to worker posts");

	std::unique_ptr<ProxySQL_PluginManager> manager;
	std::string error;
	ok(proxysql_load_configured_plugins(manager, {PROXYSQL_FAKE_PLUGIN_PATH}, error) &&
		proxysql_init_configured_plugins(manager.get(), error),
		"plugin manager is live for reconciliation claims");
	const auto set_claims = [&](ProxySQL_ServerProtocol protocol,
		std::vector<ProxySQL_ServerHostgroupClaim> claims) {
		manager->replace_managed_server_hostgroup_claims_for_test(protocol, std::move(claims));
	};
	const std::vector<ProxySQL_ServerHostgroupClaim> two_claims {{17, 18}, {27, 28}};

	AckState acks;
	void* controller_handle = dlopen(PROXYSQL_FAKE_PLUGIN_PATH, RTLD_NOW | RTLD_LOCAL);
	auto* mysql_controller = new Controller(&acks);
	ok(controller_handle != nullptr && manager->install_server_discovery_controller(
		ProxySQL_ServerProtocol::mysql, mysql_controller, &destroy_controller, controller_handle),
		"controller is registered with a retained DSO boundary");
	AckState pgsql_acks;
	void* pgsql_controller_handle = dlopen(PROXYSQL_FAKE_PLUGIN_PATH, RTLD_NOW | RTLD_LOCAL);
	auto* pgsql_controller = new Controller(&pgsql_acks);
	ok(pgsql_controller_handle != nullptr && manager->install_server_discovery_controller(
		ProxySQL_ServerProtocol::pgsql, pgsql_controller, &destroy_controller,
		pgsql_controller_handle), "PostgreSQL controller shares the retained queue boundary");

	ProxySQL_ServerRuntimeSnapshot installed {};
	installed.protocol = ProxySQL_ServerProtocol::mysql;
	const uint64_t generation = proxysql_publish_server_runtime(installed);
	installed.generation = generation;
	set_claims(ProxySQL_ServerProtocol::mysql, two_claims);
	ok(generation != 0 &&
		proxysql_active_server_hostgroup_claims(ProxySQL_ServerProtocol::mysql).size() == 2,
		"runtime generation carries the delegated writer/reader claims");
	ProxySQL_ServerRuntimeSnapshot pgsql_installed {};
	pgsql_installed.protocol = ProxySQL_ServerProtocol::pgsql;
	const uint64_t pgsql_generation = proxysql_publish_server_runtime(pgsql_installed);
	pgsql_installed.generation = pgsql_generation;
	set_claims(ProxySQL_ServerProtocol::pgsql, two_claims);
	ok(pgsql_generation != 0 &&
		proxysql_active_server_hostgroup_claims(ProxySQL_ServerProtocol::pgsql).size() == 2,
		"PostgreSQL runtime generation carries independent delegated claims");
	const auto mysql_claims = proxysql_active_server_hostgroup_claims(
		ProxySQL_ServerProtocol::mysql);
	const auto pgsql_claims = proxysql_active_server_hostgroup_claims(
		ProxySQL_ServerProtocol::pgsql);
	ok(mysql_claims.size() == 2 && mysql_claims[0].writer_hostgroup == 17 &&
		mysql_claims[0].reader_hostgroup == 18 && mysql_claims[1].writer_hostgroup == 27 &&
		mysql_claims[1].reader_hostgroup == 28 && pgsql_claims.size() == 2 &&
		pgsql_claims[0].writer_hostgroup == 17 && pgsql_claims[0].reader_hostgroup == 18 &&
		pgsql_claims[1].writer_hostgroup == 27 && pgsql_claims[1].reader_hostgroup == 28,
		"the exact two claim pairs are active for each protocol");
	const ProxySQL_ServerDesiredSet partial_writer {ProxySQL_ServerProtocol::mysql, generation,
		{17}, {}, ProxySQL_ServerPersistence::runtime_only};
	const ProxySQL_ServerDesiredSet partial_reader {ProxySQL_ServerProtocol::mysql, generation,
		{18}, {}, ProxySQL_ServerPersistence::runtime_only};
	const ProxySQL_ServerDesiredSet partial_mixed {ProxySQL_ServerProtocol::mysql, generation,
		{17, 27, 28}, {}, ProxySQL_ServerPersistence::runtime_only};
	const ProxySQL_ServerDesiredSet valid_first_claim {ProxySQL_ServerProtocol::mysql, generation,
		{17, 18}, {}, ProxySQL_ServerPersistence::runtime_only};
	const ProxySQL_ServerDesiredSet valid_second_claim {ProxySQL_ServerProtocol::mysql, generation,
		{27, 28}, {}, ProxySQL_ServerPersistence::runtime_only};
	const ProxySQL_ServerDesiredSet valid_both_claims {ProxySQL_ServerProtocol::mysql, generation,
		{17, 18, 27, 28}, {}, ProxySQL_ServerPersistence::runtime_only};
	ok(manager->revalidate_server_desired_set(ProxySQL_ServerProtocol::mysql,
		mysql_controller, valid_first_claim) &&
		manager->revalidate_server_desired_set(ProxySQL_ServerProtocol::mysql,
			mysql_controller, valid_second_claim) &&
		manager->revalidate_server_desired_set(ProxySQL_ServerProtocol::mysql,
			mysql_controller, valid_both_claims),
		"one or more complete managed discovery claims revalidate");
	const auto rejected_by_both = [&](ProxySQL_ServerDesiredSet candidate,
		ProxySQL_ServerProtocol callback_protocol = ProxySQL_ServerProtocol::mysql,
		const ProxySQL_ServerDiscoveryController* callback_controller = nullptr) {
		if (callback_controller == nullptr) callback_controller = mysql_controller;
		return !manager->revalidate_server_desired_set(
			callback_protocol, callback_controller, candidate) &&
			!manager->begin_server_desired_set_apply(
				callback_protocol, callback_controller, candidate);
	};
	Controller wrong_controller(&acks);
	ok(rejected_by_both(partial_writer) && rejected_by_both(partial_reader) &&
		rejected_by_both(partial_mixed) &&
		rejected_by_both({ProxySQL_ServerProtocol::mysql, generation, {}, {},
			ProxySQL_ServerPersistence::runtime_only}) &&
		rejected_by_both({ProxySQL_ServerProtocol::mysql, generation, {18, 17}, {},
			ProxySQL_ServerPersistence::runtime_only}) &&
		rejected_by_both({ProxySQL_ServerProtocol::mysql, generation, {17, 17, 18}, {},
			ProxySQL_ServerPersistence::runtime_only}) &&
		rejected_by_both({ProxySQL_ServerProtocol::mysql, generation, {17, 18, 29}, {},
			ProxySQL_ServerPersistence::runtime_only}) &&
		rejected_by_both({ProxySQL_ServerProtocol::pgsql, generation, {17, 18}, {},
			ProxySQL_ServerPersistence::runtime_only}) &&
		rejected_by_both({ProxySQL_ServerProtocol::mysql, generation + 1, {17, 18}, {},
			ProxySQL_ServerPersistence::runtime_only}) &&
		rejected_by_both(valid_first_claim, ProxySQL_ServerProtocol::mysql, &wrong_controller),
		"partial claims and invalid scope, protocol, generation, or controller inputs reject");
	const auto merge_accepts = [&](const ProxySQL_ServerDesiredSet& candidate) {
		std::vector<ProxySQL_ServerRow> merged;
		std::string merge_error;
		return proxysql_merge_server_desired_set(installed, candidate, merged, merge_error);
	};
	ok(merge_accepts(valid_first_claim) && merge_accepts(valid_second_claim) &&
		merge_accepts(valid_both_claims) && !merge_accepts(partial_writer) &&
		!merge_accepts(partial_reader) && !merge_accepts(partial_mixed),
		"the merge boundary accepts complete claims and rejects partial claims");
	GloAdmin = nullptr;
	const bool unavailable_post = manager->post_server_desired_set(desired(generation, {}));
	GloAdmin = admin;
	ok(!unavailable_post && ack_count(acks, generation, false) == 0,
		"an unavailable Admin owner rejects at entry without an acknowledgement");
	clear_acks(acks);

	const auto apply_scope = [&](std::vector<uint32_t> scope) {
		return manager->post_server_desired_set({ProxySQL_ServerProtocol::mysql, generation,
			std::move(scope), {}, ProxySQL_ServerPersistence::runtime_only}) &&
			admin->drain_server_discovery_updates() == 1;
	};
	ok(apply_scope({17, 18}) && apply_scope({27, 28}) &&
		ack_count(acks, generation, true) == 2,
		"two independent claimed policy pairs under one protocol each apply");
	ok(apply_scope({17}) && ack_count(acks, generation, true) == 2 &&
		ack_count(acks, generation, false) == 1,
		"a partial desired claim is rejected without applying inventory changes");
	clear_acks(acks);

	auto initial = mysql_rows({
		{17, "old.example", 3306, 0, "ONLINE", 10, 0, 100, 0, 1, 0, "old"},
		{18, "reader.example", 3306, 0, "ONLINE", 20, 0, 100, 0, 1, 0, "reader"},
		{27, "second-writer.example", 3306, 0, "ONLINE", 21, 0, 100, 0, 1, 0, "writer"},
		{28, "second-reader.example", 3306, 0, "ONLINE", 22, 0, 100, 0, 1, 0, "reader"},
		{0, "zero-writer.example", 3306, 0, "ONLINE", 23, 0, 100, 0, 1, 0, "zero"},
		{1, "zero-reader.example", 3306, 0, "ONLINE", 24, 0, 100, 0, 1, 0, "zero"},
		{99, "unrelated.example", 3306, 0, "ONLINE", 90, 0, 100, 0, 1, 0, "keep"}});
	auto empty_replication = std::make_unique<SQLite3_result>(4);
	MyHGM->save_incoming_mysql_table(empty_replication.get(),
		"mysql_replication_hostgroups");
	MyHGM->servers_add(initial.get());
	ok(MyHGM->commit({}, {}, false),
		"real MySQL HGM fixture starts without configured replication rows");
	std::unique_ptr<SQLite3_result> mysql_replication_table(
		MyHGM->dump_table_mysql("mysql_replication_hostgroups"));
	std::unique_ptr<SQLite3_result> mysql_readonly(MyHGM->get_read_only_servers());
	ok(mysql_replication_table && mysql_replication_table->rows_count == 0 && mysql_readonly &&
		mysql_readonly->rows_count == 0,
		"plugin claims are not converted into virtual MySQL replication rows");
	set_claims(ProxySQL_ServerProtocol::mysql, large_hostgroup_claim_set());
	mysql_readonly.reset(MyHGM->get_read_only_servers());
	MyHGM->read_only_action_v2({{"second-writer.example", 3306, 1}});
	ok(proxysql_active_server_hostgroup_claims(ProxySQL_ServerProtocol::mysql).size() == 500 &&
		mysql_readonly && mysql_readonly->rows_count == 0 &&
		find_row(*runtime_rows(), 27, "second-writer.example", 3306) != nullptr,
		"claim volume does not enroll endpoints in the MySQL read-only monitor");
	set_claims(ProxySQL_ServerProtocol::mysql, mysql_claims);
	MyHGM->read_only_action_v2({{"second-writer.example", 3306, 0}});
	const bool mysql_table_hidden = execute_hgm_statement(MyHGM,
		"ALTER TABLE mysql_replication_hostgroups RENAME TO mysql_replication_hostgroups_hidden");
	set_claims(ProxySQL_ServerProtocol::mysql, large_hostgroup_claim_set());
	char* mysql_enumeration_error = nullptr;
	mysql_readonly.reset(MyHGM->get_read_only_servers(&mysql_enumeration_error));
	MyHGM->read_only_action_v2({{"second-writer.example", 3306, 1}});
	const bool mysql_failed_refresh_untouched =
		find_row(*runtime_rows(), 27, "second-writer.example", 3306) != nullptr;
	const bool mysql_table_restored = execute_hgm_statement(MyHGM,
		"ALTER TABLE mysql_replication_hostgroups_hidden RENAME TO mysql_replication_hostgroups");
	MyHGM->read_only_action_v2({{"second-writer.example", 3306, 1}});
	ok(mysql_table_hidden && mysql_readonly && mysql_readonly->rows_count == 0 &&
		mysql_enumeration_error != nullptr && mysql_failed_refresh_untouched &&
		mysql_table_restored &&
		find_row(*runtime_rows(), 27, "second-writer.example", 3306) != nullptr,
		"MySQL query failures return an empty set, do not act, and preserve retryable mappings");
	if (mysql_enumeration_error != nullptr) free(mysql_enumeration_error);
	set_claims(ProxySQL_ServerProtocol::mysql, {{0, 1}});
	const ProxySQL_ServerDesiredSet mysql_zero_scope {ProxySQL_ServerProtocol::mysql,
		generation, {0, 1}, {}, ProxySQL_ServerPersistence::runtime_only};
	const bool mysql_zero_revalidated = manager->revalidate_server_desired_set(
		ProxySQL_ServerProtocol::mysql, mysql_controller, mysql_zero_scope);
	mysql_readonly.reset(MyHGM->get_read_only_servers());
	MyHGM->read_only_action_v2({{"zero-writer.example", 3306, 1}});
	const bool mysql_zero_mapped =
		find_row(*runtime_rows(), 0, "zero-writer.example", 3306) != nullptr;
	const bool mysql_zero_applied = manager->post_server_desired_set(mysql_zero_scope) &&
		admin->drain_server_discovery_updates() == 1 &&
		ack_count(acks, generation, true) == 1;
	ok(mysql_zero_revalidated && mysql_zero_applied && mysql_readonly &&
		mysql_readonly->rows_count == 0 &&
		mysql_zero_mapped,
		"MySQL desired-set scope treats hostgroup 0 as an ordinary inventory claim");
	clear_acks(acks);
	set_claims(ProxySQL_ServerProtocol::mysql, mysql_claims);
	MyHGM->servers_add(initial.get());
	const bool mysql_inventory_restored = MyHGM->commit({}, {}, false);
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
	ok(mysql_inventory_restored && concurrent_posts.load() == 4 &&
		find_row(*runtime_rows(), 17, "old.example", 3306) != nullptr,
		"multiple worker threads post without mutating owner-thread runtime state");
	ok(admin->drain_server_discovery_updates() == 4 && ack_count(acks, generation, false) == 4,
		"owner thread rejects and acknowledges every accepted concurrent malformed update once");
	clear_acks(acks);

	ProxySQL_ServerRow atomic_update {17, "old.example", 3306, 0, "ONLINE", 11,
		0, 100, 0, 1, 0, "atomic"};
	ok(manager->post_server_desired_set(desired(generation, {atomic_update})),
		"atomic HGM fixture queues a delegated update");
	arm_reconcile_hook(ReconcileHookMode::hgm_snapshot);
	std::thread atomic_drain([&] { admin->drain_server_discovery_updates(); });
	const bool snapshot_barrier_reached = wait_for_hook();
	std::atomic<unsigned int> monitor_threads_started {0};
	std::atomic<unsigned int> monitor_updates {0};
	std::thread delegated_monitor([&] {
		monitor_threads_started.fetch_add(1);
		if (MyHGM->shun_and_killall(const_cast<char*>("old.example"), 3306))
			monitor_updates.fetch_add(1);
	});
	while (monitor_threads_started.load() != 1) std::this_thread::yield();
	release_reconcile_hook();
	delegated_monitor.join();
	atomic_drain.join();
	arm_reconcile_hook(ReconcileHookMode::none);
	ok(snapshot_barrier_reached,
		"HGM reconciliation exposes the deterministic locked-snapshot interleave barrier");
	auto atomic_rows = runtime_rows();
	const SQLite3_row* atomic_delegated = find_row(*atomic_rows, 17, "old.example", 3306);
	ok(monitor_updates.load() == 1 && atomic_delegated != nullptr &&
		std::string(atomic_delegated->fields[4]) == "SHUNNED" &&
		std::string(atomic_delegated->fields[5]) == "11" &&
		find_row(*atomic_rows, 99, "unrelated.example", 3306) == nullptr &&
		find_row(*atomic_rows, 27, "second-writer.example", 3306) != nullptr,
		"monitor status survives reconcile while unclaimed rows are removed and other claims remain");
	clear_acks(acks);

	ProxySQL_ServerRow copied {17, "deep-copy.example", 3306, 0, "ONLINE", 31, 0, 101, 0, 1, 0, "copied"};
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
	ok(find_row(*after_copy, 99, "unrelated.example", 3306) == nullptr &&
		find_row(*after_copy, 27, "second-writer.example", 3306) != nullptr &&
		ack_count(acks, generation, true) == 1,
		"replacement removes unclaimed runtime rows, preserves other claims, and acknowledges once");

	ProxySQL_ServerRow malformed {77, "outside.example", 3306};
	ok(manager->post_server_desired_set(desired(generation, {malformed})) &&
		admin->drain_server_discovery_updates() == 1 && ack_count(acks, generation, false) == 1,
		"non-delegated desired rows are rejected with one false acknowledgement");
	ok(find_row(*runtime_rows(), 77, "outside.example", 3306) == nullptr,
		"rejected out-of-claim rows do not mutate runtime inventory");
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
	ok(manager->post_server_desired_set(desired(generation, {hinted_writer})) &&
		admin->drain_server_discovery_updates() == 1,
		"newly discovered member is accepted with initial plugin placement");
	ok(ack_count(acks, generation, true) == 2,
		"successful inventory placement is acknowledged once");
	auto writer_rows = runtime_rows();
	ok(find_row(*writer_rows, 17, "role.example", 3306) != nullptr,
		"new member is placed in the supplied writer hostgroup");

	MyHGM->read_only_action_v2({{"role.example", 3306, 1}});
	hinted_writer.weight = 42;
	ok(manager->post_server_desired_set(desired(generation, {hinted_writer})) &&
		admin->drain_server_discovery_updates() == 1,
		"inventory-only claim reconciles configured endpoint options");
	ok(ack_count(acks, generation, true) == 3,
		"inventory option update is acknowledged without a monitor wake API");
	auto preserved_role = runtime_rows();
	const SQLite3_row* preserved_writer = find_row(*preserved_role, 17, "role.example", 3306);
	ok(preserved_writer != nullptr && std::string(preserved_writer->fields[5]) == "42" &&
		find_row(*preserved_role, 18, "role.example", 3306) == nullptr,
		"a monitor-kind none claim keeps plugin-selected placement");
	ok(manager->post_server_desired_set(desired(generation, {hinted_writer})) &&
		admin->drain_server_discovery_updates() == 1,
		"repeated inventory publication remains accepted");
	ok(ack_count(acks, generation, true) == 4,
		"repeated inventory publication has no separate role-force trigger");
	auto forced_role = runtime_rows();
	ok(find_row(*forced_role, 17, "role.example", 3306) != nullptr &&
		find_row(*forced_role, 18, "role.example", 3306) == nullptr,
		"changed hint forces the member back to the writer role");

	ProxySQL_ServerRow both_writer = hinted_writer;
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
	ok(manager->post_server_desired_set(desired(generation, {shunned})) &&
		admin->drain_server_discovery_updates() == 1 &&
		MyHGM->shun_and_killall(const_cast<char*>(shunned.hostname.c_str()), shunned.port),
		"fixture creates monitor-controlled status on an existing discovered member");
	MySrvC* shunned_pool = MyHGM->find_server_in_hg(17, shunned.hostname, shunned.port);
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

	ProxySQL_ServerHostgroupClaim writer_only_claim {117, 118};
	writer_only_claim.role_monitor.kind = ProxySQL_ServerRoleMonitor::mysql_replication;
	writer_only_claim.role_monitor.writer_is_also_reader = 0;
	ProxySQL_ServerHostgroupClaim writer_reader_claim {127, 128};
	writer_reader_claim.role_monitor.kind = ProxySQL_ServerRoleMonitor::mysql_replication;
	writer_reader_claim.role_monitor.writer_is_also_reader = 1;
	auto placement_topologies = replication_rows({{117, 118}, {127, 128}, {137, 138}});
	auto placement_servers = mysql_rows({
		{117, "managed-writer-only.example", 3306, 0, "ONLINE", 1, 0, 100, 0, 1, 0, "writer"},
		{118, "managed-writer-only.example", 3306, 0, "ONLINE", 1, 0, 100, 0, 1, 0, "reader"},
		{117, "mixed-managed.example", 3306, 0, "ONLINE", 1, 0, 100, 0, 1, 0, "writer"},
		{118, "mixed-managed.example", 3306, 0, "ONLINE", 1, 0, 100, 0, 1, 0, "reader"},
		{128, "mixed-managed.example", 3306, 0, "ONLINE", 1, 0, 100, 0, 1, 0, "reader"},
		{138, "native-writer.example", 3306, 0, "ONLINE", 1, 0, 100, 0, 1, 0, "reader"}});
	MyHGM->save_incoming_mysql_table(placement_topologies.get(),
		"mysql_replication_hostgroups");
	MyHGM->servers_add(placement_servers.get());
	ok(MyHGM->commit({}, {}, false),
		"writer placement fixture installs three native replication pairs");
	set_claims(ProxySQL_ServerProtocol::mysql, {writer_only_claim, writer_reader_claim});
	uint8_t writer_only_value = 1;
	uint8_t writer_reader_value = 0;
	uint8_t unclaimed_value = 1;
	ok(proxysql_is_server_inventory_managed(ProxySQL_ServerProtocol::mysql,
			117, 118, &writer_only_value) && writer_only_value == 0 &&
		proxysql_is_server_inventory_managed(ProxySQL_ServerProtocol::mysql,
			127, 128, &writer_reader_value) && writer_reader_value == 1 &&
		!proxysql_is_server_inventory_managed(ProxySQL_ServerProtocol::mysql,
			137, 138, &unclaimed_value) && unclaimed_value == 0,
		"managed inventory lookup returns each claim value and clears an unclaimed output");
	const bool original_writer_is_also_reader = mysql_thread___monitor_writer_is_also_reader;
	mysql_thread___monitor_writer_is_also_reader = true;
	MyHGM->read_only_action_v2({{"managed-writer-only.example", 3306, 0}});
	auto writer_only_rows = runtime_rows();
	ok(find_row(*writer_only_rows, 117, "managed-writer-only.example", 3306) != nullptr &&
		find_row(*writer_only_rows, 118, "managed-writer-only.example", 3306) == nullptr,
		"managed writer_is_also_reader=0 removes an existing reader copy when the global value is true");
	mysql_thread___monitor_writer_is_also_reader = false;
	MyHGM->read_only_action_v2({{"mixed-managed.example", 3306, 0}});
	auto writer_reader_rows = runtime_rows();
	ok(find_row(*writer_reader_rows, 117, "mixed-managed.example", 3306) != nullptr &&
		find_row(*writer_reader_rows, 118, "mixed-managed.example", 3306) == nullptr &&
		find_row(*writer_reader_rows, 127, "mixed-managed.example", 3306) != nullptr &&
		find_row(*writer_reader_rows, 128, "mixed-managed.example", 3306) != nullptr,
		"one monitor result applies each managed writer placement value to its matching pair");
	MyHGM->read_only_action_v2({{"native-writer.example", 3306, 0}});
	auto native_writer_rows = runtime_rows();
	ok(find_row(*native_writer_rows, 137, "native-writer.example", 3306) != nullptr &&
		find_row(*native_writer_rows, 138, "native-writer.example", 3306) == nullptr,
		"an unclaimed replication pair continues to use the global writer placement value");
	mysql_thread___monitor_writer_is_also_reader = original_writer_is_also_reader;
	set_claims(ProxySQL_ServerProtocol::mysql, mysql_claims);

	ProxySQL_ServerDesiredSet stale = desired(generation, {shunned});
	ok(manager->post_server_desired_set(stale), "currently valid generation queues successfully");
	ProxySQL_ServerRuntimeSnapshot newer {};
	newer.protocol = ProxySQL_ServerProtocol::mysql;
	const uint64_t newer_generation = proxysql_publish_server_runtime(std::move(newer));
	ok(newer_generation > generation,
		"a newer runtime installation advances the controller generation before drain");
	shunned.weight = 99;
	ok(manager->post_server_desired_set(desired(newer_generation, {shunned})) &&
		admin->drain_server_discovery_updates() == 2 &&
		ack_count(acks, generation, false) == 6 && ack_count(acks, newer_generation, true) == 1,
		"owner drain rejects stale work and applies only the newest live generation with exact acknowledgements");

	auto pgsql_initial = pgsql_rows({
		{17, "pgsql-old.example", 5432, 0, "ONLINE", 61, 0, 131, 0, 1, 0, "old"},
		{27, "pgsql-second-writer.example", 5432, 0, "ONLINE", 65, 0, 135, 0, 1, 0, "writer"},
		{1, "pgsql-zero-writer.example", 5432, 0, "ONLINE", 63, 0, 133, 0, 1, 0, "zero"},
		{0, "pgsql-zero-reader.example", 5432, 0, "ONLINE", 64, 0, 134, 0, 1, 0, "zero"},
		{99, "pgsql-unrelated.example", 5432, 0, "ONLINE", 62, 0, 132, 0, 1, 0, "keep"}});
	PgHGM->servers_add(pgsql_initial.get());
	ok(PgHGM->commit(), "real PostgreSQL HGM fixture starts with unrelated runtime state");
	set_claims(ProxySQL_ServerProtocol::pgsql, large_hostgroup_claim_set());
	std::unique_ptr<SQLite3_result> large_pgsql_readonly(PgHGM->get_read_only_servers());
	PgHGM->read_only_action_v2({{"pgsql-old.example", 5432, 1}}, false);
	auto large_pgsql_runtime = std::unique_ptr<SQLite3_result>(
		PgHGM->dump_table_pgsql("pgsql_servers"));
	ok(proxysql_active_server_hostgroup_claims(ProxySQL_ServerProtocol::pgsql).size() == 500 &&
		large_pgsql_readonly && large_pgsql_readonly->rows_count == 0 &&
		large_pgsql_runtime &&
		find_row(*large_pgsql_runtime, 17, "pgsql-old.example", 5432) != nullptr,
		"claims do not create virtual PostgreSQL replication rows");
	set_claims(ProxySQL_ServerProtocol::pgsql, pgsql_claims);
	PgHGM->read_only_action_v2({{"pgsql-old.example", 5432, 0}}, false);
	const bool pgsql_table_hidden = execute_hgm_statement(PgHGM,
		"ALTER TABLE pgsql_replication_hostgroups RENAME TO pgsql_replication_hostgroups_hidden");
	set_claims(ProxySQL_ServerProtocol::pgsql, large_hostgroup_claim_set());
	char* pgsql_enumeration_error = nullptr;
	large_pgsql_readonly.reset(PgHGM->get_read_only_servers(&pgsql_enumeration_error));
	PgHGM->read_only_action_v2({{"pgsql-old.example", 5432, 1}}, false);
	large_pgsql_runtime.reset(PgHGM->dump_table_pgsql("pgsql_servers"));
	const bool pgsql_failed_refresh_untouched = large_pgsql_runtime &&
		find_row(*large_pgsql_runtime, 17, "pgsql-old.example", 5432) != nullptr;
	const bool pgsql_table_restored = execute_hgm_statement(PgHGM,
		"ALTER TABLE pgsql_replication_hostgroups_hidden RENAME TO pgsql_replication_hostgroups");
	PgHGM->read_only_action_v2({{"pgsql-old.example", 5432, 1}}, false);
	large_pgsql_runtime.reset(PgHGM->dump_table_pgsql("pgsql_servers"));
	ok(pgsql_table_hidden && large_pgsql_readonly && large_pgsql_readonly->rows_count == 0 &&
		pgsql_enumeration_error != nullptr && pgsql_failed_refresh_untouched &&
		pgsql_table_restored && large_pgsql_runtime &&
		find_row(*large_pgsql_runtime, 17, "pgsql-old.example", 5432) != nullptr,
		"PostgreSQL query failures return an empty set, do not act, and preserve retryable mappings");
	if (pgsql_enumeration_error != nullptr) free(pgsql_enumeration_error);
	set_claims(ProxySQL_ServerProtocol::pgsql, {{1, 0}});
	const ProxySQL_ServerDesiredSet pgsql_zero_scope {ProxySQL_ServerProtocol::pgsql,
		pgsql_generation, {0, 1}, {}, ProxySQL_ServerPersistence::runtime_only};
	const bool pgsql_zero_revalidated = manager->revalidate_server_desired_set(
		ProxySQL_ServerProtocol::pgsql, pgsql_controller, pgsql_zero_scope);
	large_pgsql_readonly.reset(PgHGM->get_read_only_servers());
	PgHGM->read_only_action_v2({{"pgsql-zero-writer.example", 5432, 1}}, false);
	large_pgsql_runtime.reset(PgHGM->dump_table_pgsql("pgsql_servers"));
	const bool pgsql_zero_unmapped = large_pgsql_runtime &&
		find_row(*large_pgsql_runtime, 1, "pgsql-zero-writer.example", 5432) != nullptr &&
		find_row(*large_pgsql_runtime, 0, "pgsql-zero-writer.example", 5432) == nullptr;
	const bool pgsql_zero_applied = manager->post_server_desired_set(pgsql_zero_scope) &&
		admin->drain_server_discovery_updates() == 1 &&
		ack_count(pgsql_acks, pgsql_generation, true) == 1;
	ok(pgsql_zero_revalidated && pgsql_zero_applied && large_pgsql_readonly &&
		large_pgsql_readonly->rows_count == 0 &&
		pgsql_zero_unmapped,
		"PostgreSQL desired-set scope treats hostgroup 0 as an ordinary inventory claim");
	clear_acks(pgsql_acks);
	set_claims(ProxySQL_ServerProtocol::pgsql, pgsql_claims);
	PgHGM->servers_add(pgsql_initial.get());
	const bool pgsql_inventory_restored = PgHGM->commit({}, {}, false);
	ProxySQL_ServerRow pgsql_new {18, "pgsql-new.example", 5432, 0, "ONLINE", 71, 0, 141, 0, 1, 0, "new"};
	ok(pgsql_inventory_restored &&
		manager->post_server_desired_set(pgsql_desired(pgsql_generation, {pgsql_new})) &&
		admin->drain_server_discovery_updates() == 1,
		"shared owner queue drains a PostgreSQL desired set through its 11-column adapter");
	std::unique_ptr<SQLite3_result> pgsql_runtime(PgHGM->dump_table_pgsql("pgsql_servers"));
	ok(find_row(*pgsql_runtime, 18, "pgsql-new.example", 5432) != nullptr &&
		find_row(*pgsql_runtime, 99, "pgsql-unrelated.example", 5432) == nullptr &&
		find_row(*pgsql_runtime, 27, "pgsql-second-writer.example", 5432) != nullptr &&
		ack_count(pgsql_acks, pgsql_generation, true) == 1,
		"PostgreSQL replacement removes unclaimed rows, preserves other claims, and acknowledges once");
	std::unique_ptr<SQLite3_result> pgsql_replication_table(
		PgHGM->dump_table_pgsql("pgsql_replication_hostgroups"));
	std::unique_ptr<SQLite3_result> pgsql_readonly(PgHGM->get_read_only_servers());
	ok(pgsql_replication_table && pgsql_replication_table->rows_count == 0 && pgsql_readonly &&
		pgsql_readonly->rows_count == 0,
		"PostgreSQL plugin endpoints require a real native topology row for role monitoring");
	PgHGM->read_only_action_v2({{"pgsql-new.example", 5432, 0}}, false);
	pgsql_runtime.reset(PgHGM->dump_table_pgsql("pgsql_servers"));
	ok(find_row(*pgsql_runtime, 18, "pgsql-new.example", 5432) != nullptr &&
		find_row(*pgsql_runtime, 17, "pgsql-new.example", 5432) == nullptr,
		"PostgreSQL read-only action ignores claims without a native topology row");

	ProxySQL_ServerRow pgsql_retirement = pgsql_new;
	pgsql_retirement.weight = 72;
	ok(manager->post_server_desired_set(pgsql_desired(pgsql_generation, {pgsql_retirement})),
		"retirement race fixture queues a live PostgreSQL update");
	RetirementObservation retirement {&pgsql_acks, pgsql_generation};
	manager->set_server_retirement_observer_for_test(&observe_controller_retirement, &retirement);
	arm_reconcile_hook(ReconcileHookMode::final_apply);
	std::thread retirement_drain([&] { admin->drain_server_discovery_updates(); });
	const bool final_apply_barrier_reached = wait_for_hook();
	bool uninstall_result = false;
	std::thread retirement_thread([&] {
		uninstall_result = manager->uninstall_server_discovery_controller(
			ProxySQL_ServerProtocol::pgsql);
	});
	const bool retirement_attempt_reached = wait_for_hook(true);
	release_reconcile_hook();
	retirement_drain.join();
	retirement_thread.join();
	arm_reconcile_hook(ReconcileHookMode::none);
	ok(final_apply_barrier_reached && retirement_attempt_reached,
		"uninstall deterministically attempts detachment inside the final validate/apply window");
	pgsql_runtime.reset(PgHGM->dump_table_pgsql("pgsql_servers"));
	const SQLite3_row* retired_apply = find_row(*pgsql_runtime, 18, "pgsql-new.example", 5432);
	ok(uninstall_result && retirement.detached.load() &&
		retirement.true_acks_at_detach.load() == 2 && retired_apply != nullptr &&
		std::string(retired_apply->fields[4]) == "72" &&
		pgsql_acks.shutdowns.load() == 1 && pgsql_acks.destroyed.load() == 1,
		"apply and true acknowledgement complete before controller detachment and retirement");
	manager->set_server_retirement_observer_for_test(nullptr, nullptr);

	size_t accepted = 0;
	ProxySQL_ServerRow ordered_old = shunned;
	ordered_old.hostname = "ordering.example";
	ordered_old.weight = 201;
	ProxySQL_ServerRow ordered_second = ordered_old;
	ordered_second.weight = 202;
	accepted += manager->post_server_desired_set(desired(newer_generation, {ordered_old})) ? 1 : 0;
	accepted += manager->post_server_desired_set(desired(newer_generation, {ordered_second})) ? 1 : 0;
	for (uint32_t hg = 1000; hg < 1254; ++hg) {
		ProxySQL_ServerDesiredSet queued {ProxySQL_ServerProtocol::mysql,
			newer_generation, {hg}, {},
			ProxySQL_ServerPersistence::runtime_only};
		accepted += manager->post_server_desired_set(std::move(queued)) ? 1 : 0;
	}
	const size_t displaced_before = ack_count(acks, newer_generation, false);
	ProxySQL_ServerRow ordered_newest = ordered_old;
	ordered_newest.weight = 203;
	ok(manager->post_server_desired_set(desired(newer_generation, {ordered_newest})) &&
		ack_count(acks, newer_generation, false) == displaced_before + 1,
		"full-queue exact-key coalescing false-acknowledges the displaced accepted generation once");
	ok(accepted == 256 && !manager->post_server_desired_set(
		{ProxySQL_ServerProtocol::mysql, newer_generation, {2000}, {}, ProxySQL_ServerPersistence::runtime_only}),
		"shared inbox is bounded at 256 and fails closed for a different delegation set");
	ok(admin->drain_server_discovery_updates() == 256,
		"owner drains the full mixed-key queue after coalescing");
	auto ordered_rows = runtime_rows();
	const SQLite3_row* ordered_row = find_row(*ordered_rows, 17, "ordering.example", 3306);
	ok(ordered_row != nullptr && std::string(ordered_row->fields[5]) == "203",
		"newest accepted same-key replacement remains last in FIFO application order");

	const uint64_t blocked_shutdown_generation = newer_generation + 1000;
	{
		std::lock_guard<std::mutex> lock(acks.mutex);
		acks.blocked_generation = blocked_shutdown_generation;
		acks.callback_entered = false;
		acks.release_callback = false;
	}
	ok(manager->post_server_desired_set({ProxySQL_ServerProtocol::mysql,
		blocked_shutdown_generation, {17, 18}, {}, ProxySQL_ServerPersistence::runtime_only}),
		"reload fixture retains one accepted request across inbox shutdown");
	std::thread closing_inbox([&] { admin->shutdown_server_discovery_updates(); });
	{
		std::unique_lock<std::mutex> lock(acks.mutex);
		acks.cv.wait(lock, [&] { return acks.callback_entered; });
	}
	auto premature_admin_owner = TestDiskUpgrade::make_admin();
	auto* premature_admin = premature_admin_owner.get();
	ok(pipe(premature_admin->pipefd) == 0, "concurrent replacement Admin has a wake pipe");
	GloAdmin = premature_admin;
	ok(!manager->post_server_desired_set(desired(newer_generation, {shunned})),
		"Admin lifecycle cannot reopen while an old accepted callback lease remains");
	{
		std::lock_guard<std::mutex> lock(acks.mutex);
		acks.release_callback = true;
		acks.cv.notify_all();
	}
	closing_inbox.join();
	auto reopened_admin_owner = TestDiskUpgrade::make_admin();
	auto* reopened_admin = reopened_admin_owner.get();
	ok(pipe(reopened_admin->pipefd) == 0, "fresh Admin lifecycle has a wake pipe after shutdown drains");
	GloAdmin = reopened_admin;
	ProxySQL_ServerRow reloaded = shunned;
	reloaded.hostname = "reloaded.example";
	reloaded.weight = 301;
	const bool reloaded_post = manager->post_server_desired_set(desired(newer_generation, {reloaded}));
	auto duplicate_admin_owner = TestDiskUpgrade::make_admin();
	auto* duplicate_admin = duplicate_admin_owner.get();
	ok(pipe(duplicate_admin->pipefd) == 0, "duplicate in-process Admin lifecycle has a wake pipe");
	GloAdmin = duplicate_admin;
	ok(reloaded_post && duplicate_admin->drain_server_discovery_updates() == 1,
		"completed shutdown reopens the empty inbox once without losing accepted work");
	auto reloaded_rows = runtime_rows();
	ok(find_row(*reloaded_rows, 17, "reloaded.example", 3306) != nullptr,
		"post-shutdown Admin lifecycle applies newly accepted runtime work");
	duplicate_admin->shutdown_server_discovery_updates();
	ok(!manager->post_server_desired_set(desired(newer_generation, {shunned})),
		"reopened queue closes again and rejects new work without acknowledgement");
	ok(manager->uninstall_server_discovery_controller(ProxySQL_ServerProtocol::mysql) &&
		acks.shutdowns.load() == 1 && acks.destroyed.load() == 1 &&
		pgsql_acks.shutdowns.load() == 1 && pgsql_acks.destroyed.load() == 1,
		"shutdown releases all queued leases before one destroy per protocol controller");
	ok(!manager->post_server_desired_set(desired(newer_generation, {shunned})),
		"an unregistered controller rejects desired work without an acknowledgement");
	uint8_t unregistered_writer_is_also_reader = 1;
	ok(!proxysql_is_server_inventory_managed(ProxySQL_ServerProtocol::mysql,
			17, 18, &unregistered_writer_is_also_reader) &&
		unregistered_writer_is_also_reader == 0,
		"an unregistered controller clears the managed writer placement output");
	// The duplicate Admin above exists only to exercise inbox reopening. Restore
	// the fully initialized fixture before later HGM commits consult GloAdmin's
	// admindb while recomputing their v2 checksums.
	GloAdmin = admin;

	auto inactive_mysql_rows = mysql_rows({
		{17, "inactive-mysql.example", 3306, 0, "ONLINE", 1, 0, 100, 0, 1, 0, "race"}});
	const bool inactive_mysql_race =
		run_claim_publication_race(ProxySQL_ServerProtocol::mysql,
			[&] {
				MyHGM->servers_add(inactive_mysql_rows.get());
				return MyHGM->commit();
			},
			[&] { set_claims(ProxySQL_ServerProtocol::mysql, {}); return true; },
			[&] { MyHGM->read_only_action_v2({{"inactive-mysql.example", 3306, 1}}); });
	ok(inactive_mysql_race &&
		proxysql_active_server_hostgroup_claims(ProxySQL_ServerProtocol::mysql).empty(),
		"MySQL monitor waits across HGM mutation until inactive claims are published");
	auto inactive_pgsql_rows = pgsql_rows({
		{18, "inactive-pgsql.example", 5432, 0, "ONLINE", 1, 0, 100, 0, 1, 0, "race"}});
	const bool inactive_pgsql_race =
		run_claim_publication_race(ProxySQL_ServerProtocol::pgsql,
			[&] {
				PgHGM->servers_add(inactive_pgsql_rows.get());
				return PgHGM->commit();
			},
			[&] { set_claims(ProxySQL_ServerProtocol::pgsql, {}); return true; },
			[&] { PgHGM->read_only_action_v2({{"inactive-pgsql.example", 5432, 0}}, false); });
	ok(inactive_pgsql_race &&
		proxysql_active_server_hostgroup_claims(ProxySQL_ServerProtocol::pgsql).empty(),
		"PostgreSQL monitor waits across HGM mutation until inactive claims are published");
	auto inactive_pgsql_runtime = std::unique_ptr<SQLite3_result>(
		PgHGM->dump_table_pgsql("pgsql_servers"));
	ok(find_row(*runtime_rows(), 17, "inactive-mysql.example", 3306) != nullptr &&
		find_row(*runtime_rows(), 18, "inactive-mysql.example", 3306) == nullptr &&
		inactive_pgsql_runtime &&
		find_row(*inactive_pgsql_runtime, 18, "inactive-pgsql.example", 5432) != nullptr &&
		find_row(*inactive_pgsql_runtime, 17, "inactive-pgsql.example", 5432) == nullptr,
		"inactive claims remove stale MySQL and PostgreSQL role mappings before monitor action");
	set_claims(ProxySQL_ServerProtocol::mysql, two_claims);
	set_claims(ProxySQL_ServerProtocol::pgsql, two_claims);
	const bool restored_claims =
		proxysql_active_server_hostgroup_claims(ProxySQL_ServerProtocol::mysql).size() == 2 &&
		proxysql_active_server_hostgroup_claims(ProxySQL_ServerProtocol::pgsql).size() == 2;
	MyHGM->read_only_action_v2({{"inactive-mysql.example", 3306, 0}});
	PgHGM->read_only_action_v2({{"inactive-pgsql.example", 5432, 1}}, false);
	set_claims(ProxySQL_ServerProtocol::mysql, {});
	set_claims(ProxySQL_ServerProtocol::pgsql, {});
	MyHGM->read_only_action_v2({{"inactive-mysql.example", 3306, 1}});
	PgHGM->read_only_action_v2({{"inactive-pgsql.example", 5432, 0}}, false);
	auto unregistered_pgsql_runtime = std::unique_ptr<SQLite3_result>(
		PgHGM->dump_table_pgsql("pgsql_servers"));
	ok(restored_claims &&
		proxysql_active_server_hostgroup_claims(ProxySQL_ServerProtocol::mysql).empty() &&
		proxysql_active_server_hostgroup_claims(ProxySQL_ServerProtocol::pgsql).empty() &&
		find_row(*runtime_rows(), 17, "inactive-mysql.example", 3306) != nullptr &&
		find_row(*runtime_rows(), 18, "inactive-mysql.example", 3306) == nullptr &&
		unregistered_pgsql_runtime &&
		find_row(*unregistered_pgsql_runtime, 18, "inactive-pgsql.example", 5432) != nullptr &&
		find_row(*unregistered_pgsql_runtime, 17, "inactive-pgsql.example", 5432) == nullptr,
		"clearing the claims removes restored active claim snapshots");

	auto configured_mysql = mysql_rows({
		{31, "configured-mysql.example", 3306, 0, "ONLINE", 1, 0, 100, 0, 1, 0, "writer"}});
	auto configured_mysql_replication = replication_rows(31, 32);
	MyHGM->save_incoming_mysql_table(configured_mysql_replication.get(),
		"mysql_replication_hostgroups");
	MyHGM->servers_add(configured_mysql.get());
	auto configured_pgsql = pgsql_rows({
		{31, "configured-pgsql.example", 5432, 0, "ONLINE", 1, 0, 100, 0, 1, 0, "writer"}});
	auto configured_pgsql_replication = replication_rows(31, 32);
	PgHGM->save_incoming_pgsql_table(configured_pgsql_replication.get(),
		"pgsql_replication_hostgroups");
	PgHGM->servers_add(configured_pgsql.get());
	ok(MyHGM->commit({}, {}, false) && PgHGM->commit({}, {}, false),
		"configured replication-pair control fixture commits after plugin retirement");
	mysql_readonly.reset(MyHGM->get_read_only_servers());
	pgsql_readonly.reset(PgHGM->get_read_only_servers());
	MyHGM->read_only_action_v2({{"configured-mysql.example", 3306, 1}});
	PgHGM->read_only_action_v2({{"configured-pgsql.example", 5432, 1}}, false);
	auto configured_pgsql_runtime = std::unique_ptr<SQLite3_result>(
		PgHGM->dump_table_pgsql("pgsql_servers"));
	ok(mysql_readonly && has_readonly_endpoint(*mysql_readonly, 0,
			"configured-mysql.example", 3306) && pgsql_readonly &&
		has_readonly_endpoint(*pgsql_readonly, 1, "configured-pgsql.example", 5432) &&
		find_row(*runtime_rows(), 32, "configured-mysql.example", 3306) != nullptr &&
		configured_pgsql_runtime && find_row(*configured_pgsql_runtime,
			32, "configured-pgsql.example", 5432) != nullptr,
		"configured MySQL and PostgreSQL replication pairs still enumerate and map normally");

	const bool stopped = proxysql_stop_configured_plugins(manager, error);
	uint8_t missing_manager_writer_is_also_reader = 1;
	ok(stopped && !manager &&
		!proxysql_is_server_inventory_managed(ProxySQL_ServerProtocol::mysql,
			31, 32, &missing_manager_writer_is_also_reader) &&
		missing_manager_writer_is_also_reader == 0,
		"a missing plugin manager clears the managed writer placement output");

	const std::vector<int> scoped_admin_descriptors {
		admin->pipefd[0], admin->pipefd[1],
		premature_admin->pipefd[0], premature_admin->pipefd[1],
		reopened_admin->pipefd[0], reopened_admin->pipefd[1]};
	GloAdmin = duplicate_admin;
	duplicate_admin->close_server_discovery_wake_pipe();
	int replacement_pipe[2] {-1, -1};
	const bool replacement_opened = pipe(replacement_pipe) == 0;
	if (replacement_opened) {
		const int flags = fcntl(replacement_pipe[0], F_GETFL, 0);
		fcntl(replacement_pipe[0], F_SETFL, flags | O_NONBLOCK);
	}
	proxysql_wake_server_discovery_admin();
	unsigned char unexpected_wake = 0;
	errno = 0;
	const ssize_t replacement_read = replacement_opened
		? read(replacement_pipe[0], &unexpected_wake, sizeof(unexpected_wake)) : -2;
	ok(duplicate_admin->pipefd[0] == -1 && duplicate_admin->pipefd[1] == -1 &&
		GloAdmin == nullptr && replacement_opened && replacement_read == -1 &&
		(errno == EAGAIN || errno == EWOULDBLOCK),
		"closed Admin wake descriptors cannot receive a later discovery wake after reuse");
	if (replacement_opened) {
		close(replacement_pipe[0]);
		close(replacement_pipe[1]);
	}
	// All controllers and queued leases have retired. The destructor now owns
	// cleanup of the constructor allocations and remaining Admin wake pipes.
	duplicate_admin_owner.reset();
	reopened_admin_owner.reset();
	premature_admin_owner.reset();
	GloAdmin = admin;
	admin_owner.reset();
	SPA = nullptr;
	const bool scoped_descriptors_closed = std::all_of(
		scoped_admin_descriptors.begin(), scoped_admin_descriptors.end(), [](int fd) {
			errno = 0;
			return fcntl(fd, F_GETFD) == -1 && errno == EBADF;
		});
	ok(GloAdmin == nullptr && scoped_descriptors_closed,
		"scoped Admin destructors close every remaining wake descriptor and clear the active Admin");
	return exit_status();
}
