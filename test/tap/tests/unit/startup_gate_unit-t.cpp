/**
 * @file startup_gate_unit-t.cpp
 * @brief Startup ordering gate: Admin commands and Cluster peer threads must
 *   not run while the plugin lifecycle is in progress.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "ProxySQL_StartupGate.h"

#include <atomic>
#include <chrono>
#include <thread>

namespace {

using namespace std::chrono_literals;

// A waiter that must stay blocked is given this long to (wrongly) get through.
constexpr auto kBlockedProbe = 300ms;
// A waiter that must be released gets this long to finish.
constexpr auto kReleaseTimeout = 10s;

struct Waiter {
	std::atomic<bool> done{false};
	std::atomic<bool> result{false};
	std::thread thread;

	template <typename Wait>
	explicit Waiter(Wait wait) {
		thread = std::thread([this, wait] {
			result = wait();
			done = true;
		});
	}
	~Waiter() { if (thread.joinable()) thread.join(); }

	bool finishes_within(std::chrono::milliseconds limit) {
		const auto deadline = std::chrono::steady_clock::now() + limit;
		while (!done && std::chrono::steady_clock::now() < deadline)
			std::this_thread::sleep_for(5ms);
		return done;
	}
};

bool never_stop() { return false; }

} // namespace

int main() {
	plan(15);
	test_init_minimal();

	ok(proxysql_startup_gate_state() == ProxySQL_StartupGateState::open,
		"gate starts open, so builds that never configure it never wait");
	ok(proxysql_startup_gate_wait_for_admin(never_stop) &&
		proxysql_startup_gate_wait_for_runtime(never_stop),
		"an open gate lets Admin commands and Cluster threads through immediately");

	// Normal startup: closed until the plugin lifecycle finishes.
	proxysql_startup_gate_reset(false);
	ok(proxysql_startup_gate_state() == ProxySQL_StartupGateState::closed,
		"normal startup closes the gate");
	{
		Waiter admin([] { return proxysql_startup_gate_wait_for_admin(never_stop); });
		Waiter cluster([] { return proxysql_startup_gate_wait_for_runtime(never_stop); });
		ok(!admin.finishes_within(kBlockedProbe), "Admin command waits while startup is in progress");
		ok(!cluster.finishes_within(kBlockedProbe), "Cluster thread waits while startup is in progress");
		proxysql_startup_gate_open();
		ok(admin.finishes_within(kReleaseTimeout) && admin.result,
			"opening the gate releases the waiting Admin command");
		ok(cluster.finishes_within(kReleaseTimeout) && cluster.result,
			"opening the gate releases the waiting Cluster thread");
	}

	// --no-start: Admin works before PROXYSQL START, Cluster does not.
	proxysql_startup_gate_reset(true);
	ok(proxysql_startup_gate_state() == ProxySQL_StartupGateState::prestart_open,
		"--no-start starts in prestart_open");
	ok(proxysql_startup_gate_wait_for_admin(never_stop),
		"Admin commands run before PROXYSQL START");
	{
		Waiter cluster([] { return proxysql_startup_gate_wait_for_runtime(never_stop); });
		ok(!cluster.finishes_within(kBlockedProbe), "Cluster thread waits before PROXYSQL START");
		proxysql_startup_gate_close_for_start();
		ok(proxysql_startup_gate_state() == ProxySQL_StartupGateState::closed,
			"PROXYSQL START closes the gate for the plugin lifecycle");
		Waiter admin([] { return proxysql_startup_gate_wait_for_admin(never_stop); });
		ok(!admin.finishes_within(kBlockedProbe), "Admin command waits after PROXYSQL START until startup completes");
		proxysql_startup_gate_open();
		ok(admin.finishes_within(kReleaseTimeout) && cluster.finishes_within(kReleaseTimeout),
			"opening the gate releases both waiters");
	}

	proxysql_startup_gate_close_for_start();
	ok(proxysql_startup_gate_state() == ProxySQL_StartupGateState::open,
		"PROXYSQL START after startup completed does not close the gate again");

	// Shutdown abandons the wait.
	proxysql_startup_gate_reset(false);
	std::atomic<bool> stopping{false};
	{
		Waiter admin([&stopping] {
			return proxysql_startup_gate_wait_for_admin([&stopping] { return stopping.load(); });
		});
		stopping = true;
		ok(admin.finishes_within(kReleaseTimeout) && !admin.result,
			"shutdown ends a wait and reports that the gate did not open");
	}
	proxysql_startup_gate_open();

	return exit_status();
}
