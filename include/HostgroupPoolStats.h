#ifndef HOSTGROUP_POOL_STATS_H
#define HOSTGROUP_POOL_STATS_H

#ifdef PROXYSQL31

#include <atomic>
#include <cstdint>

struct HostgroupPoolStatsSnapshot {
	uint64_t acquisitions_total {0};
	uint64_t waits_total {0};
	uint64_t wait_time_us_total {0};
	uint64_t waiters {0};
};

class HostgroupPoolStats {
public:
	void record_acquisition() {
		acquisitions_total_.fetch_add(1, std::memory_order_relaxed);
	}

	void begin_wait() {
		waits_total_.fetch_add(1, std::memory_order_relaxed);
		waiters_.fetch_add(1, std::memory_order_relaxed);
	}

	void end_wait(uint64_t duration_us) {
		wait_time_us_total_.fetch_add(duration_us, std::memory_order_relaxed);
		waiters_.fetch_sub(1, std::memory_order_relaxed);
	}

	void cancel_wait() {
		waiters_.fetch_sub(1, std::memory_order_relaxed);
	}

	HostgroupPoolStatsSnapshot lifetime_snapshot() const {
		return {
			acquisitions_total_.load(std::memory_order_relaxed),
			waits_total_.load(std::memory_order_relaxed),
			wait_time_us_total_.load(std::memory_order_relaxed),
			waiters_.load(std::memory_order_relaxed)
		};
	}

	HostgroupPoolStatsSnapshot window_snapshot() const {
		const auto lifetime = lifetime_snapshot();
		return {
			lifetime.acquisitions_total - acquisitions_baseline_.load(std::memory_order_relaxed),
			lifetime.waits_total - waits_baseline_.load(std::memory_order_relaxed),
			lifetime.wait_time_us_total - wait_time_us_baseline_.load(std::memory_order_relaxed),
			lifetime.waiters
		};
	}

	HostgroupPoolStatsSnapshot reset_window() {
		const auto lifetime = lifetime_snapshot();
		const uint64_t acquisitions_baseline = acquisitions_baseline_.exchange(
			lifetime.acquisitions_total, std::memory_order_relaxed);
		const uint64_t waits_baseline = waits_baseline_.exchange(
			lifetime.waits_total, std::memory_order_relaxed);
		const uint64_t wait_time_us_baseline = wait_time_us_baseline_.exchange(
			lifetime.wait_time_us_total, std::memory_order_relaxed);

		return {
			lifetime.acquisitions_total - acquisitions_baseline,
			lifetime.waits_total - waits_baseline,
			lifetime.wait_time_us_total - wait_time_us_baseline,
			lifetime.waiters
		};
	}

private:
	std::atomic<uint64_t> acquisitions_total_ {0};
	std::atomic<uint64_t> waits_total_ {0};
	std::atomic<uint64_t> wait_time_us_total_ {0};
	std::atomic<uint64_t> waiters_ {0};

	std::atomic<uint64_t> acquisitions_baseline_ {0};
	std::atomic<uint64_t> waits_baseline_ {0};
	std::atomic<uint64_t> wait_time_us_baseline_ {0};
};

class HostgroupPoolWait {
public:
	HostgroupPoolWait() = default;
	HostgroupPoolWait(const HostgroupPoolWait&) = delete;
	HostgroupPoolWait& operator=(const HostgroupPoolWait&) = delete;

	~HostgroupPoolWait() {
		cancel();
	}

	void observe(HostgroupPoolStats* stats, uint64_t now_us, bool acquired) {
		if (acquired) {
			finish(now_us);
			if (stats) {
				stats->record_acquisition();
			}
			return;
		}

		if (!stats || stats_ == stats) {
			return;
		}

		finish(now_us);
		stats_ = stats;
		started_us_ = now_us;
		stats_->begin_wait();
	}

	void finish(uint64_t now_us) {
		if (!stats_) {
			return;
		}

		const uint64_t duration_us = now_us >= started_us_ ? now_us - started_us_ : 0;
		stats_->end_wait(duration_us);
		stats_ = nullptr;
		started_us_ = 0;
	}

	void cancel() {
		if (!stats_) {
			return;
		}

		stats_->cancel_wait();
		stats_ = nullptr;
		started_us_ = 0;
	}

	bool active() const {
		return stats_ != nullptr;
	}

private:
	HostgroupPoolStats* stats_ {nullptr};
	uint64_t started_us_ {0};
};

#endif // PROXYSQL31

#endif // HOSTGROUP_POOL_STATS_H
