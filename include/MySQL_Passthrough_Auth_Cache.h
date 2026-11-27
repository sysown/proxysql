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

/**
 * @brief Forward declaration of re2::RE2 to keep this header light.
 *
 * The full re2/re2.h pulls in a large set of headers and dependencies; we
 * only need a pointer to RE2 in the class state, so a forward declaration
 * suffices. The translation unit that owns the compiled regex
 * (lib/MySQL_Passthrough_Auth_Cache.cpp) includes the full header.
 */
namespace re2 { class RE2; }

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
		/** @brief Cache entry whose destructor cleanses its owned cleartext credential. */
		struct entry_t {
			std::string cleartext_password;
			uint64_t learned_at_us { 0 };
			int hostgroup_probed { 0 };
			entry_t() = default;
			~entry_t();
			entry_t(const entry_t&) = delete;
			entry_t& operator=(const entry_t&) = delete;
			entry_t(entry_t&&) = delete;
			entry_t& operator=(entry_t&&) = delete;
		};
		mutable pthread_rwlock_t lock;
		std::unordered_map<std::string, entry_t> entries;
		std::atomic<int> inflight_probes;

		/**
		 * @brief Atomic counters for operational observability (spec §7.4 follow-up).
		 *
		 * Exposed via @c stats_mysql_passthrough_auth_metrics. Each
		 * counter increments at exactly one well-defined point in
		 * @c handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT
		 * (see the corresponding @c bump_* methods below). Monotonic
		 * since process start; reset only by process restart.
		 *
		 * Naming mirrors the existing @c stats_mysql_global pattern of
		 * "what happened" snake-case-counters; no special suffixes.
		 */
		std::atomic<uint64_t> stat_probes_attempted;
		std::atomic<uint64_t> stat_probes_ok;
		std::atomic<uint64_t> stat_probes_failed_credentials;
		std::atomic<uint64_t> stat_probes_failed_transport;
		std::atomic<uint64_t> stat_lockouts_user;
		std::atomic<uint64_t> stat_lockouts_ip;
		std::atomic<uint64_t> stat_inflight_cap_rejects;
		std::atomic<uint64_t> stat_cache_hits;
		std::atomic<uint64_t> stat_cache_invalidations;
		// Sliding-window failure counters (spec §7.2). Per-username and
		// per-source-IP. Mutated only behind failure_lock — a separate
		// mutex from `lock` since these are write-mostly and accessed on
		// every probe.
		mutable pthread_mutex_t failure_lock;
		mutable std::unordered_map<std::string, std::deque<uint64_t>> failures_by_user;
		mutable std::unordered_map<std::string, std::deque<uint64_t>> failures_by_ip;

		/**
		 * @brief Compiled-regex cache for the username allowlist (spec §7.1).
		 *
		 * Compiling an re2::RE2 is cheap (single-digit microseconds) but
		 * is paid every time a candidate connect is checked. Cache the
		 * last-seen pattern string alongside its compiled form so that as
		 * long as @c mysql-passthrough_auth_username_pattern is unchanged
		 * we hit the compiled form. A pattern change (admin SET, reload)
		 * triggers a re-compile under the write lock.
		 *
		 * @c pattern_lock is a pthread_rwlock so the COMMON case
		 * (steady-state pattern, every probe takes the read lock for
		 * FullMatch) doesn't serialize through a single mutex. The write
		 * lock is taken only when the pattern STRING changes, which
		 * happens on admin SET / LOAD MYSQL VARIABLES TO RUNTIME and is
		 * effectively rare. re2::RE2::FullMatch is documented as
		 * thread-safe on a const RE2 instance, so concurrent readers
		 * are fine.
		 *
		 * Holds a raw pointer (forward-declared above) rather than
		 * unique_ptr so we don't need to drag re2/re2.h into this header.
		 */
		mutable pthread_rwlock_t pattern_lock;
		mutable std::string compiled_pattern_str;
		mutable re2::RE2 *compiled_pattern;

		/**
		 * @brief Compiled mysql-passthrough_auth_ephemeral_pattern, cached the
		 * same way as @c compiled_pattern (its own lock: the two patterns
		 * change independently).
		 */
		mutable pthread_rwlock_t ephemeral_pattern_lock;
		mutable std::string ephemeral_compiled_pattern_str;
		mutable re2::RE2 *ephemeral_compiled_pattern;

	public:
		MySQL_Passthrough_Auth_Cache();
		~MySQL_Passthrough_Auth_Cache();

		// Look up a cached credential. Returns true on hit (and populates
		// out_cleartext); false on miss. If ttl_s > 0 and the entry is older
		// than ttl_s, the entry is evicted and a miss is returned.
		bool lookup(const std::string& username, std::string& out_cleartext, uint32_t ttl_s);

		/**
		 * @brief Copy a non-null cleartext credential into the cache.
		 * @details Replacing an entry cleanses the previously owned credential.
		 */
		void insert(const std::string& username, const char* cleartext, int hostgroup_probed);

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
		/**
		 * @brief Record a probe failure against (username, ip) deques.
		 *
		 * @param max_keys Operator-tunable cap on the size of each
		 *                 failure map (failures_by_user, failures_by_ip).
		 *                 Driven by @c mysql-passthrough_auth_failure_map_cap.
		 *                 When the map exceeds the cap, evict_oldest
		 *                 reclaims an entry (defense-in-depth against
		 *                 username/IP churn that would otherwise grow
		 *                 the maps unbounded).
		 */
		void record_failure(const std::string& username, const std::string& ip, int max_keys);

		/**
		 * @brief Observability counters (B7 follow-up).
		 *
		 * Each @c bump_* method increments the corresponding atomic at
		 * the single call site documented in @c MySQL_Session.cpp. The
		 * @c metrics_snapshot helper returns the current values for the
		 * @c stats_mysql_passthrough_auth_metrics virtual table.
		 */
		void bump_probes_attempted();
		void bump_probes_ok();
		void bump_probes_failed_credentials();
		void bump_probes_failed_transport();
		void bump_lockouts_user();
		void bump_lockouts_ip();
		void bump_inflight_cap_rejects();
		void bump_cache_hits();
		void bump_cache_invalidations();

		/**
		 * @brief Snapshot of metric counters + current-state gauges.
		 *
		 * Returns a vector of (name, value) pairs ordered for stable JSON /
		 * stats-table output. Values are read with relaxed memory ordering
		 * since stats are advisory, not synchronizing.
		 */
		struct metric_kv {
			std::string name;
			uint64_t value;
		};
		std::vector<metric_kv> metrics_snapshot() const;

		/**
		 * @brief Check whether @p username matches the configured allowlist
		 * regex (spec §7.1, mysql-passthrough_auth_username_pattern).
		 *
		 * @param username Frontend user attempting pass-through.
		 * @param pattern  Regex string from the global variable. Empty means
		 *                 "allow every username" (back-compat default).
		 * @return @c true when the pattern is empty or @p username FullMatches
		 *         the compiled regex; @c false when the regex is set and
		 *         either fails to compile or the username doesn't match.
		 *
		 * The compiled regex is cached on the class behind @c pattern_lock;
		 * a pattern-string change triggers a re-compile on the next call.
		 * Match semantics are RE2 FullMatch (the entire username must
		 * match), matching how query rules use re2 elsewhere in ProxySQL.
		 * A regex that fails to compile is treated as a deny-all -- the
		 * fail-safe direction for a security gate.
		 */
		bool username_allowed(const std::string& username, const std::string& pattern);

		/**
		 * @brief Whether @p cleartext is an ephemeral credential
		 * (mysql-passthrough_auth_ephemeral_pattern).
		 *
		 * An ephemeral credential is short-lived and differs per client (for
		 * example a signed, expiring token validated by a backend auth
		 * plugin). It is verified against the backend on every frontend
		 * connection and is never inserted into this cache.
		 *
		 * @param cleartext Cleartext captured during full authentication.
		 * @param pattern   Regex string from the global variable. Empty means
		 *                  the feature is off.
		 * @return @c true only when the pattern is non-empty, compiles, and
		 *         FullMatches @p cleartext. A pattern that fails to compile
		 *         matches nothing.
		 */
		bool credential_is_ephemeral(const char *cleartext, const std::string& pattern);

		/**
		 * @brief Value stored in @c userinfo->password for a session that
		 * authenticated with an ephemeral credential while a standing backend
		 * credential is configured. It is never sent to a backend as is: every
		 * place that hands a password to the client library replaces it with
		 * the standing credential first.
		 *
		 * The value is generated once per process from random bytes, so a
		 * client cannot know it and cannot present it as its own credential
		 * (pass-through additionally rejects a cleartext equal to it).
		 */
		static const char *ephemeral_backend_marker();

		/** @brief Whether @p password is the marker (NULL-safe). */
		static bool is_ephemeral_backend_marker(const char *password);

		/**
		 * @brief Set the file that holds the standing backend credential
		 * (mysql-passthrough_auth_ephemeral_backend_credential_file). Empty or
		 * NULL disables it.
		 */
		static void set_ephemeral_backend_credential_file(const char *path);

		/** @brief Whether a standing backend credential file is configured. */
		static bool ephemeral_backend_credential_configured();

		/**
		 * @brief Copy the standing backend credential into @p out.
		 *
		 * The credential is the first line of the configured file. The file
		 * is stat()ed on every call and re-read only when it changed, so the
		 * credential can be rotated without touching existing frontend
		 * sessions. File I/O happens outside the internal lock.
		 *
		 * The caller owns @p out and must keep it alive until the backend
		 * operation that uses it has completed (connects are asynchronous).
		 *
		 * @return @c false, with @p out empty, when no file is configured or
		 *         it is unreadable or empty. Callers then send the marker and
		 *         the backend rejects it (fail closed).
		 *
		 * Callable from any thread.
		 */
		static bool read_ephemeral_backend_credential(std::string& out);

		void print_version();
};

#endif // PROXYSQL_MYSQL_PASSTHROUGH_AUTH_CACHE_H
