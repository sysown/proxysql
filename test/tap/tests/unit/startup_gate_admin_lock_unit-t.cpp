/**
 * @file startup_gate_admin_lock_unit-t.cpp
 * @brief Startup gate: an Admin session that queued on the global SQL mutex
 *   before PROXYSQL START closed the gate must not run during the plugin
 *   lifecycle.
 *
 * With --no-start, PROXYSQL START closes the gate while holding Admin's global
 * SQL mutex. A second session that already passed the gate is queued on that
 * mutex. If it then ran its statement (for example LOAD MYSQL SERVERS TO
 * RUNTIME, which pins the plugin manager) while the main thread runs plugin
 * init() holding the plugin manager exclusively and asking for the global
 * mutex (secret store), the two threads deadlock.
 *
 * The test reproduces that interleaving with stand-ins for the two locks: a
 * mutex for sql_query_global_mutex and a shared mutex for the plugin
 * manager. proxysql_startup_gate_lock_for_admin() must make the queued
 * session step aside, so the "plugin init" thread gets the global mutex. With
 * a gate check that only runs before the lock, the session keeps the mutex
 * while waiting for the plugin manager and the lifecycle side times out.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "ProxySQL_StartupGate.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <shared_mutex>
#include <thread>

namespace {

using namespace std::chrono_literals;

// Time given to a thread to reach (or wrongly pass) a blocking point.
constexpr auto kSettle = 300ms;
// Time the lifecycle side waits for the global mutex before reporting the deadlock.
constexpr auto kLifecycleLockTimeout = 2s;
// A thread that must be released gets this long to finish.
constexpr auto kReleaseTimeout = 10s;

std::mutex global_sql_mutex;           // stands in for sql_query_global_mutex
std::shared_mutex plugin_manager;      // stands in for g_active_plugin_manager_mutex

bool never_stop() { return false; }

bool wait_for(const std::atomic<bool>& flag, std::chrono::milliseconds limit) {
	const auto deadline = std::chrono::steady_clock::now() + limit;
	while (!flag && std::chrono::steady_clock::now() < deadline)
		std::this_thread::sleep_for(5ms);
	return flag;
}

// Probed from another thread: try_lock on a mutex the caller owns is undefined.
bool held_elsewhere() {
	bool acquired = false;
	std::thread probe([&acquired] {
		acquired = global_sql_mutex.try_lock();
		if (acquired) global_sql_mutex.unlock();
	});
	probe.join();
	return !acquired;
}

// Bounded acquisition, so a deadlock is reported instead of hanging the test.
bool try_lock_global_for(std::chrono::milliseconds limit) {
	const auto deadline = std::chrono::steady_clock::now() + limit;
	while (!global_sql_mutex.try_lock()) {
		if (std::chrono::steady_clock::now() >= deadline) return false;
		std::this_thread::sleep_for(5ms);
	}
	return true;
}

bool lock_global() {
	return proxysql_startup_gate_lock_for_admin(
		[] { global_sql_mutex.lock(); },
		[] { global_sql_mutex.unlock(); },
		never_stop);
}

} // namespace

int main() {
	plan(9);
	test_init_minimal();

	// Open gate (every build that never configures it): lock and go.
	ok(lock_global(), "open gate: the lock is taken and the command may run");
	ok(held_elsewhere(), "open gate: the lock is held on return");
	global_sql_mutex.unlock();

	// --no-start, before PROXYSQL START: commands run normally.
	proxysql_startup_gate_reset(true);
	ok(lock_global(), "prestart_open: the lock is taken and the command may run");
	global_sql_mutex.unlock();

	// Session A runs PROXYSQL START: it holds the global mutex.
	global_sql_mutex.lock();

	// Session B sends LOAD MYSQL SERVERS TO RUNTIME: it passes the gate (still
	// prestart_open) and queues on the global mutex.
	std::atomic<bool> b_entered{false};
	std::atomic<bool> b_done{false};
	std::atomic<bool> b_result{false};
	std::atomic<bool> b_saw_closed{false};
	std::thread session_b([&] {
		b_result = lock_global();
		b_saw_closed = proxysql_startup_gate_state() == ProxySQL_StartupGateState::closed;
		b_entered = true;
		// The statement pins the plugin manager while holding the global mutex.
		{ std::shared_lock<std::shared_mutex> pin(plugin_manager); }
		global_sql_mutex.unlock();
		b_done = true;
	});
	ok(!wait_for(b_entered, kSettle), "session B is queued on the global mutex held by PROXYSQL START");

	// PROXYSQL START closes the gate and returns; the main thread enters
	// phase 3 and plugin init() holds the plugin manager exclusively.
	proxysql_startup_gate_close_for_start();
	std::unique_lock<std::shared_mutex> init_lock(plugin_manager);
	global_sql_mutex.unlock();
	std::this_thread::sleep_for(kSettle);

	// Plugin init() reads a secret: it needs the global mutex.
	const bool lifecycle_got_lock = try_lock_global_for(kLifecycleLockTimeout);
	ok(lifecycle_got_lock,
		"plugin init() gets the global mutex: the queued session stepped aside instead of deadlocking");
	ok(!b_entered, "session B did not run its statement while the gate was closed");
	if (lifecycle_got_lock) global_sql_mutex.unlock();

	// The lifecycle completes and the gate opens.
	init_lock.unlock();
	proxysql_startup_gate_open();

	ok(wait_for(b_done, kReleaseTimeout), "session B runs once the plugin lifecycle has finished");
	session_b.join();
	ok(b_result && !b_saw_closed, "session B ran with the gate open");

	// Shutdown ends the wait; the lock is still held on return, as before.
	proxysql_startup_gate_reset(false);
	const bool shutdown_result = proxysql_startup_gate_lock_for_admin(
		[] { global_sql_mutex.lock(); },
		[] { global_sql_mutex.unlock(); },
		[] { return true; });
	ok(!shutdown_result && held_elsewhere(), "shutdown ends the wait with the lock held and reports false");
	global_sql_mutex.unlock();
	proxysql_startup_gate_open();

	return exit_status();
}
