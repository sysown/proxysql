/**
 * @file cluster_admin_lock_order_unit-t.cpp
 * @brief Lock order between ProxySQL_Cluster_Nodes::mutex and
 *        ProxySQL_Admin::sql_query_global_mutex.
 *
 * A Cluster peer thread holds ProxySQL_Cluster_Nodes::mutex across
 * ProxySQL_Node_Entry::set_checksums(). The servers and query rules pulls
 * started from there take sql_query_global_mutex after fetching from the peer.
 * So the only allowed order is nodes mutex -> global mutex, and an Admin
 * session (which holds the global mutex for the whole statement) must never
 * wait for the nodes mutex.
 *
 * Covered here, with the real ProxySQL_Cluster_Nodes code:
 *  - LOAD ADMIN VARIABLES TO RUNTIME re-enabling a
 *    cluster_*_diffs_before_sync calls Reset_Global_Checksums(true) with the
 *    global mutex held. It must complete while a peer thread holds the nodes
 *    mutex and waits for the global mutex. Before the fix it locked the nodes
 *    mutex and the two threads deadlocked; the scenario then times out.
 *  - The deferred reset keeps its effect: the next Update_Global_Checksum()
 *    sees the reset value, reports the peer as changed (so the full
 *    checksums are fetched) and consumes the request exactly once.
 *  - Reset_Global_Checksums(false), used by a caller that already holds the
 *    nodes mutex, still resets immediately.
 *  - SHOW PROMETHEUS METRICS collects the metrics with the global mutex held
 *    and reaches update_prometheus_nodes_metrics(). Called by an owner of the
 *    global mutex while a peer thread holds the nodes mutex and waits for the
 *    global mutex, it must return (skipping the refresh) instead of waiting.
 *    Before the fix it locked the nodes mutex and the threads deadlocked.
 *  - Without contention, the same call from an owner of the global mutex
 *    takes and releases the nodes mutex (the trylock path is balanced).
 *
 * Every scenario runs on worker threads with a timeout so a deadlock fails
 * the test instead of hanging it.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "thread.h"
#include "wqueue.h"
#include "ProxySQL_ServerDiscovery.h"
#include "prometheus/counter.h"
#include "prometheus/gauge.h"
#include "proxysql_admin_global_sql_lock.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

// The nodes mutex and map are private; the test needs to hold the mutex the
// way a Cluster peer thread does and to seed one peer entry.
#define private public
#include "ProxySQL_Cluster.hpp"
#undef private

namespace {

constexpr int TIMEOUT_MS = 3000;

// One-row, one-column stored result, as returned by the global checksum query.
class OneValueMysqlResult {
public:
	explicit OneValueMysqlResult(const std::string& value) : value_(value) {
		fields_[0] = value_.data();
		row_.data = fields_;
		data_.data = &row_;
		result_.data = &data_;
		result_.field_count = 1;
	}
	MYSQL_RES* reset() {
		row_.next = nullptr;
		result_.data_cursor = &row_;
		return &result_;
	}
private:
	std::string value_;
	char* fields_[1] {};
	MYSQL_ROWS row_ {};
	MYSQL_DATA data_ {};
	MYSQL_RES result_ {};
};

char peer_host[] = "127.0.0.1";
constexpr uint16_t peer_port = 16032;

ProxySQL_Node_Entry* seed_peer(ProxySQL_Cluster_Nodes& nodes) {
	char comment[] = "lock order";
	char ip[] = "127.0.0.1";
	auto* node = new ProxySQL_Node_Entry(peer_host, peer_port, 1, comment, ip);
	nodes.umap_proxy_nodes.insert({ nodes.generate_hash(peer_host, peer_port), node });
	return node;
}

bool ready(std::future<void>& f, int timeout_ms = TIMEOUT_MS) {
	return f.wait_for(std::chrono::milliseconds(timeout_ms)) == std::future_status::ready;
}

/**
 * Runs the ABBA shape: a "peer" thread takes the nodes mutex, then (once the
 * "admin" thread owns the global mutex) takes the global mutex like a servers
 * pull does. The "admin" thread owns the global mutex like an Admin statement
 * and runs @p admin_body once the peer holds the nodes mutex.
 * Returns true when both threads finish in time.
 */
bool run_abba(ProxySQL_Cluster_Nodes& nodes, pthread_mutex_t& global,
		const std::function<void()>& admin_body) {
	auto peer_has_nodes = std::make_shared<std::promise<void>>();
	auto admin_has_global = std::make_shared<std::promise<void>>();
	auto peer_done = std::make_shared<std::promise<void>>();
	auto admin_done = std::make_shared<std::promise<void>>();
	std::shared_future<void> peer_has_nodes_f = peer_has_nodes->get_future().share();
	std::shared_future<void> admin_has_global_f = admin_has_global->get_future().share();
	std::future<void> peer_done_f = peer_done->get_future();
	std::future<void> admin_done_f = admin_done->get_future();
	ProxySQL_Cluster_Nodes* n = &nodes;
	pthread_mutex_t* g = &global;

	std::thread([=] {
		pthread_mutex_lock(&n->mutex);                  // Update_Node_Checksums()
		peer_has_nodes->set_value();
		admin_has_global_f.wait_for(std::chrono::milliseconds(TIMEOUT_MS));
		// Give the admin side time to block on the nodes mutex if it is going to.
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
		proxysql_admin_global_sql_lock(*g);             // servers pull, after the fetch
		proxysql_admin_global_sql_unlock(*g);
		pthread_mutex_unlock(&n->mutex);
		peer_done->set_value();
	}).detach();

	std::thread([=] {
		proxysql_admin_global_sql_lock(*g);             // Admin_Handler, per statement
		admin_has_global->set_value();
		peer_has_nodes_f.wait_for(std::chrono::milliseconds(TIMEOUT_MS));
		admin_body();
		proxysql_admin_global_sql_unlock(*g);
		admin_done->set_value();
	}).detach();

	const bool peer_ok = ready(peer_done_f);
	const bool admin_ok = ready(admin_done_f);
	return peer_ok && admin_ok;
}

void test_reset_request_does_not_wait_for_nodes_mutex(ProxySQL_Cluster_Nodes& nodes,
		pthread_mutex_t& global, ProxySQL_Node_Entry* node) {
	node->global_checksum = 0xABCD;
	const bool finished = run_abba(nodes, global, [&nodes] {
		nodes.Reset_Global_Checksums(true);
	});
	ok(finished,
	   "Reset_Global_Checksums(true) under the global mutex completes while a peer thread "
	   "holds the nodes mutex and waits for the global mutex (no ABBA deadlock)");
	if (!finished) {
		BAIL_OUT("threads are deadlocked; cannot continue");
	}
}

void test_deferred_reset_is_applied(ProxySQL_Cluster_Nodes& nodes, ProxySQL_Node_Entry* node) {
	OneValueMysqlResult same(std::to_string(0xABCD));

	ok(nodes.global_checksums_reset_pending.load(),
	   "the reset request is recorded for the next checksum check");
	ok(nodes.Update_Global_Checksum(peer_host, peer_port, same.reset()) == true,
	   "the next Update_Global_Checksum() applies the reset and reports the peer as changed");
	ok(node->global_checksum == 0xABCD && !nodes.global_checksums_reset_pending.load(),
	   "it stores the fetched checksum and consumes the request");
	ok(nodes.Update_Global_Checksum(peer_host, peer_port, same.reset()) == false,
	   "a later check with the same checksum reports no change (request applied once)");
}

void test_locked_reset_is_immediate(ProxySQL_Cluster_Nodes& nodes, ProxySQL_Node_Entry* node) {
	node->global_checksum = 0x1234;
	pthread_mutex_lock(&nodes.mutex);
	nodes.Reset_Global_Checksums(false);
	const bool reset_now = node->global_checksum == 0;
	pthread_mutex_unlock(&nodes.mutex);
	ok(reset_now && !nodes.global_checksums_reset_pending.load(),
	   "Reset_Global_Checksums(false) from a nodes-mutex owner resets immediately");
}

void test_prometheus_refresh_never_waits(ProxySQL_Cluster_Nodes& nodes, pthread_mutex_t& global) {
	const bool finished = run_abba(nodes, global, [&nodes] {
		nodes.update_prometheus_nodes_metrics();
	});
	ok(finished,
	   "update_prometheus_nodes_metrics() from an owner of the global mutex completes "
	   "while a peer thread holds the nodes mutex and waits for the global mutex");

	proxysql_admin_global_sql_lock(global);
	nodes.update_prometheus_nodes_metrics();
	const int depth = proxysql_admin_global_sql_lock_depth();
	proxysql_admin_global_sql_unlock(global);
	const bool nodes_free = pthread_mutex_trylock(&nodes.mutex) == 0;
	if (nodes_free) {
		pthread_mutex_unlock(&nodes.mutex);
	}
	ok(nodes_free && depth == 1,
	   "without contention the refresh releases the nodes mutex and leaves the global mutex "
	   "ownership unchanged (depth=%d)", depth);
}

} // namespace

int main() {
	plan(8);
	test_init_minimal();

	pthread_mutex_t global;
	pthread_mutex_init(&global, nullptr);
	// Leaked on purpose: if a scenario deadlocks, its detached threads still
	// reference the object.
	auto* nodes = new ProxySQL_Cluster_Nodes();
	ProxySQL_Node_Entry* node = seed_peer(*nodes);

	test_reset_request_does_not_wait_for_nodes_mutex(*nodes, global, node);
	test_deferred_reset_is_applied(*nodes, node);
	test_locked_reset_is_immediate(*nodes, node);
	test_prometheus_refresh_never_waits(*nodes, global);

	return exit_status();
}
