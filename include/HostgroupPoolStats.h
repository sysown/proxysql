#ifndef __CLASS_HOSTGROUP_POOL_STATS_H
#define __CLASS_HOSTGROUP_POOL_STATS_H

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
		acquisitions_total_.fetch_add(1);
	}

	void begin_wait() {
		waits_total_.fetch_add(1);
		waiters_.fetch_add(1);
	}

	void end_wait(uint64_t duration_us) {
		wait_time_us_total_.fetch_add(duration_us);
		waiters_.fetch_sub(1);
	}

	void cancel_wait() {
		waiters_.fetch_sub(1);
	}

	HostgroupPoolStatsSnapshot lifetime_snapshot() const {
		return {
			acquisitions_total_.load(),
			waits_total_.load(),
			wait_time_us_total_.load(),
			waiters_.load()
		};
	}

	HostgroupPoolStatsSnapshot window_snapshot() const {
		return {
			window_value(acquisitions_total_, acquisitions_baseline_),
			window_value(waits_total_, waits_baseline_),
			window_value(wait_time_us_total_, wait_time_us_baseline_),
			waiters_.load()
		};
	}

	HostgroupPoolStatsSnapshot reset_window() {
		return {
			reset_counter(acquisitions_total_, acquisitions_baseline_),
			reset_counter(waits_total_, waits_baseline_),
			reset_counter(wait_time_us_total_, wait_time_us_baseline_),
			waiters_.load()
		};
	}

private:
	static uint64_t window_value(
		const std::atomic<uint64_t>& total, const std::atomic<uint64_t>& baseline
	) {
		const uint64_t baseline_value = baseline.load();
		return total.load() - baseline_value;
	}

	static uint64_t reset_counter(
		const std::atomic<uint64_t>& total, std::atomic<uint64_t>& baseline
	) {
		const uint64_t current = total.load();
		uint64_t previous = baseline.load();
		while (previous < current) {
			if (baseline.compare_exchange_weak(previous, current)) {
				return current - previous;
			}
		}
		return 0;
	}

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

	HostgroupPoolStats* active_stats(unsigned int hostgroup_id) const {
		return stats_ && hostgroup_id_ == hostgroup_id ? stats_ : nullptr;
	}

	void observe(
		HostgroupPoolStats* stats, uint64_t now_us, bool acquired, unsigned int hostgroup_id
	) {
		if (acquired) {
			finish(now_us);
			if (stats) {
				stats->record_acquisition();
			}
			return;
		}

		if (!stats || (stats_ == stats && hostgroup_id_ == hostgroup_id)) {
			return;
		}

		finish(now_us);
		stats_ = stats;
		hostgroup_id_ = hostgroup_id;
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
		hostgroup_id_ = 0;
		started_us_ = 0;
	}

	void cancel() {
		if (!stats_) {
			return;
		}

		stats_->cancel_wait();
		stats_ = nullptr;
		hostgroup_id_ = 0;
		started_us_ = 0;
	}

	bool active() const {
		return stats_ != nullptr;
	}

private:
	HostgroupPoolStats* stats_ {nullptr};
	unsigned int hostgroup_id_ {0};
	uint64_t started_us_ {0};
};

#endif // PROXYSQL31

#endif // __CLASS_HOSTGROUP_POOL_STATS_H
