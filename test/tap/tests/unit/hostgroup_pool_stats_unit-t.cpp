#include "tap.h"

#include "HostgroupPoolStats.h"

#include <atomic>
#include <thread>
#include <vector>

static void test_immediate_acquisition() {
	HostgroupPoolStats stats;
	HostgroupPoolWait wait;

	wait.observe(&stats, 100, true);

	const auto lifetime = stats.lifetime_snapshot();
	ok(lifetime.acquisitions_total == 1, "immediate acquisition increments acquisitions once");
	ok(lifetime.waits_total == 0, "immediate acquisition does not create a wait episode");
	ok(lifetime.wait_time_us_total == 0, "immediate acquisition records no wait time");
	ok(lifetime.waiters == 0, "immediate acquisition leaves no current waiter");
}

static void test_retry_is_one_wait_episode() {
	HostgroupPoolStats stats;
	HostgroupPoolWait wait;

	wait.observe(&stats, 1'000, false);
	wait.observe(&stats, 2'000, false);

	auto lifetime = stats.lifetime_snapshot();
	ok(lifetime.waits_total == 1, "repeated misses count as one logical wait episode");
	ok(lifetime.waiters == 1, "repeated misses keep exactly one current waiter");

	wait.observe(&stats, 6'000, true);
	lifetime = stats.lifetime_snapshot();
	ok(lifetime.acquisitions_total == 1, "acquisition after retries increments acquisitions once");
	ok(lifetime.waits_total == 1, "successful completion does not recount the wait episode");
	ok(lifetime.wait_time_us_total == 5'000, "successful completion records full wait duration");
	ok(lifetime.waiters == 0, "successful completion removes the current waiter");
}

static void test_abandoned_wait() {
	HostgroupPoolStats stats;
	HostgroupPoolWait wait;

	wait.observe(&stats, 10'000, false);
	wait.finish(13'500);
	wait.finish(20'000);

	const auto lifetime = stats.lifetime_snapshot();
	ok(lifetime.waits_total == 1, "abandoned acquisition remains one wait episode");
	ok(lifetime.wait_time_us_total == 3'500, "abandoned acquisition contributes wait duration once");
	ok(lifetime.waiters == 0, "abandoned acquisition removes the current waiter exactly once");
}

static void test_reroute_moves_wait_between_hostgroups() {
	HostgroupPoolStats first;
	HostgroupPoolStats second;
	HostgroupPoolWait wait;

	wait.observe(&first, 100, false);
	wait.observe(&second, 400, false);

	const auto first_lifetime = first.lifetime_snapshot();
	const auto second_lifetime = second.lifetime_snapshot();
	ok(first_lifetime.waiters == 0 && first_lifetime.wait_time_us_total == 300,
		"reroute closes the wait episode in the original hostgroup");
	ok(second_lifetime.waiters == 1 && second_lifetime.waits_total == 1,
		"reroute starts one wait episode in the new hostgroup");

	wait.observe(&second, 900, true);
	ok(second.lifetime_snapshot().wait_time_us_total == 500,
		"rerouted acquisition records time only in its target hostgroup");
}

static void test_reset_preserves_lifetime_and_live_gauge() {
	HostgroupPoolStats stats;
	HostgroupPoolWait wait;

	wait.observe(&stats, 1'000, true);
	wait.observe(&stats, 2'000, false);

	const auto before_reset = stats.reset_window();
	ok(before_reset.acquisitions_total == 1 && before_reset.waits_total == 1,
		"reset returns the completed Admin counter window");
	ok(before_reset.waiters == 1, "reset reports the live waiter gauge");
	ok(stats.lifetime_snapshot().acquisitions_total == 1 &&
		stats.lifetime_snapshot().waits_total == 1,
		"reset preserves monotonic lifetime counters");
	ok(stats.window_snapshot().acquisitions_total == 0 &&
		stats.window_snapshot().waits_total == 0,
		"reset starts a fresh Admin counter window");
	ok(stats.window_snapshot().waiters == 1,
		"reset never clears the live waiter gauge");

	wait.finish(5'000);
	ok(stats.window_snapshot().wait_time_us_total == 3'000 &&
		stats.window_snapshot().waiters == 0,
		"wait completion after reset is retained without gauge underflow");
}

static void test_destructor_balances_waiter_gauge() {
	HostgroupPoolStats stats;
	{
		HostgroupPoolWait wait;
		wait.observe(&stats, 7'000, false);
	}

	ok(stats.lifetime_snapshot().waiters == 0,
		"wait-state destruction cannot leak the current waiter gauge");
}

static void test_concurrent_resets_preserve_acquisitions() {
	HostgroupPoolStats stats;
	std::atomic<bool> done {false};
	std::thread recorder([&stats, &done]() {
		for (uint64_t i = 0; i < 100'000; ++i) {
			stats.record_acquisition();
		}
		done.store(true);
	});

	uint64_t reset_total = 0;
	while (!done.load()) {
		reset_total += stats.reset_window().acquisitions_total;
	}
	recorder.join();
	reset_total += stats.reset_window().acquisitions_total;

	ok(stats.lifetime_snapshot().acquisitions_total == 100'000,
		"concurrent Admin resets preserve the monotonic lifetime counter");
	ok(reset_total == 100'000,
		"concurrent Admin reset windows neither lose nor duplicate acquisitions");
}

static void test_concurrent_resetters_partition_acquisitions() {
	HostgroupPoolStats stats;
	std::atomic<bool> start {false};
	std::atomic<bool> done {false};
	std::atomic<uint64_t> reset_total {0};
	std::vector<std::thread> resetters;

	for (unsigned int i = 0; i < 32; ++i) {
		resetters.emplace_back([&stats, &start, &done, &reset_total]() {
			uint64_t local_total = 0;
			while (!start.load()) {
				std::this_thread::yield();
			}
			while (!done.load()) {
				local_total += stats.reset_window().acquisitions_total;
			}
			reset_total.fetch_add(local_total);
		});
	}

	std::thread recorder([&stats, &start, &done]() {
		while (!start.load()) {
			std::this_thread::yield();
		}
		for (uint64_t i = 0; i < 1'000'000; ++i) {
			stats.record_acquisition();
		}
		done.store(true);
	});

	start.store(true);
	recorder.join();
	for (std::thread& resetter : resetters) {
		resetter.join();
	}
	reset_total.fetch_add(stats.reset_window().acquisitions_total);

	ok(stats.lifetime_snapshot().acquisitions_total == 1'000'000,
		"multiple concurrent resetters preserve the lifetime acquisition count");
	ok(reset_total.load() == 1'000'000,
		"multiple concurrent resetters partition acquisitions without overlap or gaps");
}

int main() {
	plan(27);
	test_immediate_acquisition();
	test_retry_is_one_wait_episode();
	test_abandoned_wait();
	test_reroute_moves_wait_between_hostgroups();
	test_reset_preserves_lifetime_and_live_gauge();
	test_destructor_balances_waiter_gauge();
	test_concurrent_resets_preserve_acquisitions();
	test_concurrent_resetters_partition_acquisitions();
	return exit_status();
}
