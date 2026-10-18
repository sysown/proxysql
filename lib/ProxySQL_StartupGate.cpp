#include "ProxySQL_StartupGate.h"

#include <chrono>
#include <condition_variable>
#include <mutex>

namespace {

std::mutex gate_mutex;
std::condition_variable gate_cv;
ProxySQL_StartupGateState gate_state = ProxySQL_StartupGateState::open;

constexpr std::chrono::milliseconds stop_poll_interval{100};

bool wait_until(const std::function<bool(ProxySQL_StartupGateState)>& allowed,
	const std::function<bool()>& stop) {
	std::unique_lock<std::mutex> lock(gate_mutex);
	while (!allowed(gate_state)) {
		if (stop && stop()) return false;
		gate_cv.wait_for(lock, stop_poll_interval);
	}
	return true;
}

} // namespace

void proxysql_startup_gate_reset(bool nostart) {
	std::lock_guard<std::mutex> lock(gate_mutex);
	gate_state = nostart ? ProxySQL_StartupGateState::prestart_open
		: ProxySQL_StartupGateState::closed;
	gate_cv.notify_all();
}

void proxysql_startup_gate_close_for_start() {
	std::lock_guard<std::mutex> lock(gate_mutex);
	if (gate_state == ProxySQL_StartupGateState::prestart_open)
		gate_state = ProxySQL_StartupGateState::closed;
}

void proxysql_startup_gate_open() {
	std::lock_guard<std::mutex> lock(gate_mutex);
	gate_state = ProxySQL_StartupGateState::open;
	gate_cv.notify_all();
}

ProxySQL_StartupGateState proxysql_startup_gate_state() {
	std::lock_guard<std::mutex> lock(gate_mutex);
	return gate_state;
}

bool proxysql_startup_gate_wait_for_admin(const std::function<bool()>& stop) {
	return wait_until([](ProxySQL_StartupGateState state) {
		return state != ProxySQL_StartupGateState::closed;
	}, stop);
}

bool proxysql_startup_gate_lock_for_admin(const std::function<void()>& lock,
	const std::function<void()>& unlock, const std::function<bool()>& stop) {
	for (;;) {
		const bool allowed = proxysql_startup_gate_wait_for_admin(stop);
		lock();
		if (!allowed) return false;
		// Only PROXYSQL START closes the gate after Admin is up, and it does so
		// while holding this same lock. Checked under the lock, the state can
		// therefore no longer move to closed until the caller releases it. If
		// it was closed while this caller queued on the lock, step aside so the
		// plugin lifecycle can take the lock, and wait for the gate to reopen.
		// This holds only while the lock is held: a statement that later opens
		// a manual release window (proxysql_admin_global_sql_release_scope)
		// can resume after the gate was closed, so such a window must not be
		// followed by anything that waits on the plugin manager.
		if (proxysql_startup_gate_state() != ProxySQL_StartupGateState::closed) return true;
		unlock();
	}
}

bool proxysql_startup_gate_wait_for_runtime(const std::function<bool()>& stop) {
	return wait_until([](ProxySQL_StartupGateState state) {
		return state == ProxySQL_StartupGateState::open;
	}, stop);
}
