#ifndef PROXYSQL_MYSQL_PASSTHROUGH_AUTH_CACHE_H
#define PROXYSQL_MYSQL_PASSTHROUGH_AUTH_CACHE_H

#include <pthread.h>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <string>
#include <unordered_map>
#include <vector>

#ifdef DEBUG
#define MYSQL_PASSTHROUGH_AUTH_CACHE_DEB "_DEBUG"
#else
#define MYSQL_PASSTHROUGH_AUTH_CACHE_DEB ""
#endif
#define MYSQL_PASSTHROUGH_AUTH_CACHE_VERSION "0.1.0000" MYSQL_PASSTHROUGH_AUTH_CACHE_DEB

struct passthrough_entry_view {
	std::string username;
	uint64_t learned_at_us;
	int hostgroup_probed;
};

class MySQL_Passthrough_Auth_Cache {
	private:
		struct entry_t {
			std::string cleartext_password;
			uint64_t learned_at_us;
			int hostgroup_probed;
		};
		mutable pthread_rwlock_t lock;
		std::unordered_map<std::string, entry_t> entries;
		std::atomic<int> inflight_probes;
		// Sliding-window failure counters (spec §7.2). Per-username and
		// per-source-IP. Mutated only behind failure_lock — a separate
		// mutex from `lock` since these are write-mostly and accessed on
		// every probe.
		mutable pthread_mutex_t failure_lock;
		mutable std::unordered_map<std::string, std::deque<uint64_t>> failures_by_user;
		mutable std::unordered_map<std::string, std::deque<uint64_t>> failures_by_ip;

	public:
		MySQL_Passthrough_Auth_Cache();
		~MySQL_Passthrough_Auth_Cache();

		// Look up a cached credential. Returns true on hit (and populates
		// out_cleartext); false on miss. If ttl_s > 0 and the entry is older
		// than ttl_s, the entry is evicted and a miss is returned.
		bool lookup(const std::string& username, std::string& out_cleartext, uint32_t ttl_s);

		// Insert or replace a cached credential.
		void insert(const std::string& username, const std::string& cleartext, int hostgroup_probed);

		// Evict a single entry. Returns true if the entry was present.
		bool evict(const std::string& username);

		// Remove every entry.
		void clear();

		// Number of entries currently held.
		size_t size() const;

		// Snapshot of entries (without password) for stats / observability.
		std::vector<passthrough_entry_view> snapshot() const;

		// Global in-flight probe counter (spec §7.3). Sessions wishing to
		// start a backend probe call try_acquire_inflight with the current
		// configured cap; on true they MUST pair with release_inflight when
		// the probe completes (success or failure). On false the session
		// must reject the auth with a generic ERR.
		bool try_acquire_inflight(int max_inflight);
		void release_inflight();
		int  inflight() const;

		// Sliding-window failure counters (spec §7.2). Sessions check
		// would_lockout before probing; on probe failure, record a
		// failure. window_s defines the sliding window in seconds; older
		// timestamps are dropped lazily on check.
		bool would_lockout_user(const std::string& username, int max_failures, uint32_t window_s) const;
		bool would_lockout_ip(const std::string& ip, int max_failures, uint32_t window_s) const;
		void record_failure(const std::string& username, const std::string& ip);

		void print_version();
};

#endif // PROXYSQL_MYSQL_PASSTHROUGH_AUTH_CACHE_H
