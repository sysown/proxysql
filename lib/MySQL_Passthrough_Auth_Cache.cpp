#include "MySQL_Passthrough_Auth_Cache.h"

#include "gen_utils.h"

#include "re2/re2.h"

#include <cstdio>

MySQL_Passthrough_Auth_Cache::MySQL_Passthrough_Auth_Cache()
	: inflight_probes(0),
	  stat_probes_attempted(0),
	  stat_probes_ok(0),
	  stat_probes_failed_credentials(0),
	  stat_probes_failed_transport(0),
	  stat_lockouts_user(0),
	  stat_lockouts_ip(0),
	  stat_inflight_cap_rejects(0),
	  stat_cache_hits(0),
	  stat_cache_invalidations(0),
	  compiled_pattern(NULL) {
	pthread_rwlock_init(&lock, NULL);
	pthread_mutex_init(&failure_lock, NULL);
	pthread_rwlock_init(&pattern_lock, NULL);
}

MySQL_Passthrough_Auth_Cache::~MySQL_Passthrough_Auth_Cache() {
	pthread_rwlock_wrlock(&lock);
	entries.clear();
	pthread_rwlock_unlock(&lock);
	pthread_rwlock_destroy(&lock);
	pthread_mutex_lock(&failure_lock);
	failures_by_user.clear();
	failures_by_ip.clear();
	pthread_mutex_unlock(&failure_lock);
	pthread_mutex_destroy(&failure_lock);
	pthread_rwlock_wrlock(&pattern_lock);
	if (compiled_pattern) {
		delete compiled_pattern;
		compiled_pattern = NULL;
	}
	compiled_pattern_str.clear();
	pthread_rwlock_unlock(&pattern_lock);
	pthread_rwlock_destroy(&pattern_lock);
}

bool MySQL_Passthrough_Auth_Cache::lookup(
	const std::string& username, std::string& out_cleartext, uint32_t ttl_s
) {
	pthread_rwlock_wrlock(&lock);
	auto it = entries.find(username);
	if (it == entries.end()) {
		pthread_rwlock_unlock(&lock);
		return false;
	}
	if (ttl_s > 0) {
		const uint64_t now_us = monotonic_time();
		const uint64_t age_us = now_us - it->second.learned_at_us;
		if (age_us > static_cast<uint64_t>(ttl_s) * 1000000ULL) {
			entries.erase(it);
			pthread_rwlock_unlock(&lock);
			return false;
		}
	}
	out_cleartext = it->second.cleartext_password;
	pthread_rwlock_unlock(&lock);
	return true;
}

void MySQL_Passthrough_Auth_Cache::insert(
	const std::string& username, const std::string& cleartext, int hostgroup_probed
) {
	pthread_rwlock_wrlock(&lock);
	entry_t& e = entries[username];
	e.cleartext_password = cleartext;
	e.learned_at_us = monotonic_time();
	e.hostgroup_probed = hostgroup_probed;
	pthread_rwlock_unlock(&lock);
}

bool MySQL_Passthrough_Auth_Cache::evict(const std::string& username) {
	pthread_rwlock_wrlock(&lock);
	const bool removed = (entries.erase(username) > 0);
	pthread_rwlock_unlock(&lock);
	return removed;
}

void MySQL_Passthrough_Auth_Cache::clear() {
	pthread_rwlock_wrlock(&lock);
	entries.clear();
	pthread_rwlock_unlock(&lock);
}

size_t MySQL_Passthrough_Auth_Cache::size() const {
	pthread_rwlock_rdlock(&lock);
	const size_t n = entries.size();
	pthread_rwlock_unlock(&lock);
	return n;
}

std::vector<passthrough_entry_view> MySQL_Passthrough_Auth_Cache::snapshot() const {
	std::vector<passthrough_entry_view> out;
	pthread_rwlock_rdlock(&lock);
	out.reserve(entries.size());
	for (const auto& kv : entries) {
		passthrough_entry_view v;
		v.username = kv.first;
		v.learned_at_us = kv.second.learned_at_us;
		v.hostgroup_probed = kv.second.hostgroup_probed;
		out.push_back(std::move(v));
	}
	pthread_rwlock_unlock(&lock);
	return out;
}

bool MySQL_Passthrough_Auth_Cache::try_acquire_inflight(int max_inflight) {
	if (max_inflight <= 0) {
		// 0 or negative means "no cap"; succeed without bookkeeping.
		// Practically the variable is bounded to [1, 10000] by the
		// VariablesPointers_int registration, but be defensive.
		inflight_probes.fetch_add(1, std::memory_order_relaxed);
		return true;
	}
	int prev = inflight_probes.fetch_add(1, std::memory_order_relaxed);
	if (prev >= max_inflight) {
		inflight_probes.fetch_sub(1, std::memory_order_relaxed);
		return false;
	}
	return true;
}

void MySQL_Passthrough_Auth_Cache::release_inflight() {
	inflight_probes.fetch_sub(1, std::memory_order_relaxed);
}

int MySQL_Passthrough_Auth_Cache::inflight() const {
	return inflight_probes.load(std::memory_order_relaxed);
}

namespace {
// Drop timestamps older than the window from a deque; return how many
// remain. Caller holds failure_lock.
size_t prune_and_count(std::deque<uint64_t>& dq, uint64_t now_us, uint64_t window_us) {
	while (!dq.empty() && dq.front() + window_us < now_us) {
		dq.pop_front();
	}
	return dq.size();
}

/**
 * @brief Erase the map entry when the corresponding deque is empty.
 *
 * Without this, every distinct (username, source-IP) pair that ever
 * triggered a failure stays in the map as an entry with an empty
 * deque after its timestamps expire. An attacker churning random
 * usernames/IPs grows the map at line-rate until the process runs
 * out of memory. Erase on empty so the map size is bounded by the
 * currently-active failure population, not the cumulative history.
 *
 * Caller holds failure_lock.
 */
void erase_if_empty(
	std::unordered_map<std::string, std::deque<uint64_t>>& m,
	std::unordered_map<std::string, std::deque<uint64_t>>::iterator it
) {
	if (it != m.end() && it->second.empty()) {
		m.erase(it);
	}
}

/**
 * @brief Hard cap on the size of the failure maps.
 *
 * A defense-in-depth bound for the case where erase_if_empty
 * isn't fast enough to keep up with a high-burst attacker (every
 * unique key is in its window so erase_if_empty cannot evict).
 * When the map grows beyond this threshold we drop the oldest
 * entry (smallest front()-timestamp deque) -- losing rate-limit
 * state for one historical user/IP to protect the process from
 * runaway memory growth. Picked an order of magnitude above
 * what's plausible for legitimate active workloads but well
 * below memory pressure on typical proxy hosts.
 */
constexpr size_t FAILURE_MAP_HARD_CAP = 100000;

/**
 * @brief Evict the oldest entry in @p m to bring size under the cap.
 *
 * Linear scan; OK because eviction is rare (only fires when the cap
 * is hit). Caller holds failure_lock.
 *
 * Opportunistic empty-deque sweep: as we walk the map looking for the
 * oldest non-empty deque, we also reclaim every empty-deque "zombie"
 * we encounter. This protects against the failure mode where empty
 * deques accumulate (because would_lockout_* only calls
 * erase_if_empty on the specific key being checked, NOT a global
 * sweep): under sustained-churn workload where each unique
 * username/IP appears exactly once, no would_lockout_* call ever
 * re-touches a given key, so prune_and_count's eviction never gets a
 * chance to run on those zombies. The map fills with empty deques
 * until the hard cap fires, and without this sweep evict_oldest would
 * be forced to choose between the only remaining non-empty deque
 * (i.e. the entry we JUST inserted) -- silently dropping the lockout
 * signal that triggered the cap.
 *
 * The sweep is bounded by the current map size, and we also use a
 * second iterator-safe pass to actually erase: collecting empty
 * iterators during the find pass and erasing them after, so we don't
 * invalidate @c oldest mid-iteration. The "find oldest non-empty +
 * collect empties" is one pass; the erase loop is the second.
 *
 * Worst case stays O(N); attack-time cost unchanged. Best case is
 * better because empties get removed as we go, so subsequent
 * evict_oldest calls walk a smaller map.
 */
void evict_oldest(
	std::unordered_map<std::string, std::deque<uint64_t>>& m
) {
	auto oldest = m.end();
	uint64_t oldest_ts = UINT64_MAX;
	std::vector<std::unordered_map<std::string, std::deque<uint64_t>>::iterator> empties;
	for (auto it = m.begin(); it != m.end(); ++it) {
		if (it->second.empty()) {
			empties.push_back(it);
		} else if (it->second.front() < oldest_ts) {
			oldest_ts = it->second.front();
			oldest = it;
		}
	}
	/* Phase 1: reclaim every empty-deque zombie. This is the work
	 * erase_if_empty would have done lazily on a would_lockout_* call
	 * that never came. */
	for (auto& it : empties) {
		m.erase(it);
	}
	/* Phase 2: if after sweeping zombies we're still above the cap,
	 * drop the oldest real entry. The just-inserted entry by definition
	 * has the LATEST timestamp at its front(), so this never picks it
	 * up unless every other entry has been swept (in which case the
	 * cap was never really exceeded by genuine activity -- only by
	 * accumulated zombies). */
	if (oldest != m.end()) {
		m.erase(oldest);
	}
}
} // anonymous namespace

bool MySQL_Passthrough_Auth_Cache::would_lockout_user(
	const std::string& username, int max_failures, uint32_t window_s
) const {
	if (max_failures <= 0 || window_s == 0 || username.empty()) return false;
	const uint64_t now_us = monotonic_time();
	const uint64_t window_us = static_cast<uint64_t>(window_s) * 1000000ULL;
	pthread_mutex_lock(&failure_lock);
	auto it = failures_by_user.find(username);
	bool lockout = false;
	if (it != failures_by_user.end()) {
		lockout = prune_and_count(it->second, now_us, window_us)
			>= static_cast<size_t>(max_failures);
		/* Reclaim the map entry if the prune left an empty deque -- bounds
		 * unconditional map growth from churn (spec §7.2 / B8 follow-up). */
		erase_if_empty(failures_by_user, it);
	}
	pthread_mutex_unlock(&failure_lock);
	return lockout;
}

bool MySQL_Passthrough_Auth_Cache::would_lockout_ip(
	const std::string& ip, int max_failures, uint32_t window_s
) const {
	if (max_failures <= 0 || window_s == 0 || ip.empty()) return false;
	const uint64_t now_us = monotonic_time();
	const uint64_t window_us = static_cast<uint64_t>(window_s) * 1000000ULL;
	pthread_mutex_lock(&failure_lock);
	auto it = failures_by_ip.find(ip);
	bool lockout = false;
	if (it != failures_by_ip.end()) {
		lockout = prune_and_count(it->second, now_us, window_us)
			>= static_cast<size_t>(max_failures);
		erase_if_empty(failures_by_ip, it);
	}
	pthread_mutex_unlock(&failure_lock);
	return lockout;
}

void MySQL_Passthrough_Auth_Cache::record_failure(
	const std::string& username, const std::string& ip
) {
	const uint64_t now_us = monotonic_time();
	pthread_mutex_lock(&failure_lock);
	if (!username.empty()) {
		failures_by_user[username].push_back(now_us);
		/* Defense-in-depth: if attacker is churning usernames faster than
		 * the window expires, evict the oldest entry to keep memory
		 * bounded. We lose lockout state for one historical user; the
		 * alternative is unbounded growth. */
		if (failures_by_user.size() > FAILURE_MAP_HARD_CAP) {
			evict_oldest(failures_by_user);
		}
	}
	if (!ip.empty()) {
		failures_by_ip[ip].push_back(now_us);
		if (failures_by_ip.size() > FAILURE_MAP_HARD_CAP) {
			evict_oldest(failures_by_ip);
		}
	}
	pthread_mutex_unlock(&failure_lock);
}

bool MySQL_Passthrough_Auth_Cache::username_allowed(
	const std::string& username, const std::string& pattern
) {
	/**
	 * @brief Spec §7.1 username allowlist (re2 FullMatch).
	 *
	 * An empty pattern means "allow every username" -- this matches the
	 * variable's default (mysql-passthrough_auth_username_pattern="") and
	 * preserves the pre-fix behavior for operators who haven't opted in.
	 */
	if (pattern.empty()) return true;

	/**
	 * @brief Reader fast-path.
	 *
	 * Steady state: the pattern hasn't changed since the last call. Take
	 * the read lock, observe the cached compiled regex, run FullMatch
	 * (which is documented thread-safe on a const RE2), drop the lock.
	 * Concurrent probes don't serialize through a mutex -- they share
	 * the read lock. This is the dominant path because operators set
	 * the pattern infrequently relative to connect rate.
	 */
	{
		pthread_rwlock_rdlock(&pattern_lock);
		if (compiled_pattern != NULL && pattern == compiled_pattern_str) {
			const bool ok = compiled_pattern->ok()
				&& re2::RE2::FullMatch(username, *compiled_pattern);
			pthread_rwlock_unlock(&pattern_lock);
			return ok;
		}
		pthread_rwlock_unlock(&pattern_lock);
	}

	/**
	 * @brief Writer slow-path -- compile (or recompile) under the write lock.
	 *
	 * The pattern string didn't match the cached one, so we need a new
	 * compiled RE2. Acquire the write lock. Re-check under the write lock
	 * (between the rdlock drop and wrlock acquire another thread may
	 * have already done the compile we want), and only do the alloc /
	 * destroy / assign work if we're still the one who needs to.
	 *
	 * RE2::Quiet suppresses log spam on operator-supplied bad regexes;
	 * we discover the bad-ness via ok() below and fail-safe deny.
	 */
	pthread_rwlock_wrlock(&pattern_lock);
	if (compiled_pattern == NULL || pattern != compiled_pattern_str) {
		if (compiled_pattern) {
			delete compiled_pattern;
			compiled_pattern = NULL;
		}
		re2::RE2::Options opts(re2::RE2::Quiet);
		opts.set_case_sensitive(true);
		compiled_pattern = new re2::RE2(pattern, opts);
		compiled_pattern_str = pattern;
	}

	/**
	 * @brief Fail safe on bad regex.
	 *
	 * If the operator supplies a regex that doesn't compile (typo, unsupported
	 * syntax, ...), RE2::ok() returns false. Treat that as a deny-all rather
	 * than allow-all: a misconfigured allowlist must NOT default to permitting
	 * every username (which would re-open the unknown-user surface that the
	 * pattern exists to gate).
	 */
	const bool ok = compiled_pattern->ok()
		&& re2::RE2::FullMatch(username, *compiled_pattern);

	pthread_rwlock_unlock(&pattern_lock);
	return ok;
}

void MySQL_Passthrough_Auth_Cache::bump_probes_attempted() {
	stat_probes_attempted.fetch_add(1, std::memory_order_relaxed);
}
void MySQL_Passthrough_Auth_Cache::bump_probes_ok() {
	stat_probes_ok.fetch_add(1, std::memory_order_relaxed);
}
void MySQL_Passthrough_Auth_Cache::bump_probes_failed_credentials() {
	stat_probes_failed_credentials.fetch_add(1, std::memory_order_relaxed);
}
void MySQL_Passthrough_Auth_Cache::bump_probes_failed_transport() {
	stat_probes_failed_transport.fetch_add(1, std::memory_order_relaxed);
}
void MySQL_Passthrough_Auth_Cache::bump_lockouts_user() {
	stat_lockouts_user.fetch_add(1, std::memory_order_relaxed);
}
void MySQL_Passthrough_Auth_Cache::bump_lockouts_ip() {
	stat_lockouts_ip.fetch_add(1, std::memory_order_relaxed);
}
void MySQL_Passthrough_Auth_Cache::bump_inflight_cap_rejects() {
	stat_inflight_cap_rejects.fetch_add(1, std::memory_order_relaxed);
}
void MySQL_Passthrough_Auth_Cache::bump_cache_hits() {
	stat_cache_hits.fetch_add(1, std::memory_order_relaxed);
}
void MySQL_Passthrough_Auth_Cache::bump_cache_invalidations() {
	stat_cache_invalidations.fetch_add(1, std::memory_order_relaxed);
}

std::vector<MySQL_Passthrough_Auth_Cache::metric_kv>
MySQL_Passthrough_Auth_Cache::metrics_snapshot() const {
	/**
	 * @brief Order matters here: this is the order @c
	 * stats_mysql_passthrough_auth_metrics returns to admin clients.
	 * Counters first (monotonic-since-startup), gauges last
	 * (current-state). All values are read with relaxed memory
	 * ordering -- stats are advisory and don't need to synchronize
	 * with the increments.
	 */
	std::vector<metric_kv> out;
	out.reserve(11);
	out.push_back({ "probes_attempted",          stat_probes_attempted.load(std::memory_order_relaxed) });
	out.push_back({ "probes_ok",                 stat_probes_ok.load(std::memory_order_relaxed) });
	out.push_back({ "probes_failed_credentials", stat_probes_failed_credentials.load(std::memory_order_relaxed) });
	out.push_back({ "probes_failed_transport",   stat_probes_failed_transport.load(std::memory_order_relaxed) });
	out.push_back({ "lockouts_user",             stat_lockouts_user.load(std::memory_order_relaxed) });
	out.push_back({ "lockouts_ip",               stat_lockouts_ip.load(std::memory_order_relaxed) });
	out.push_back({ "inflight_cap_rejects",      stat_inflight_cap_rejects.load(std::memory_order_relaxed) });
	out.push_back({ "cache_hits",                stat_cache_hits.load(std::memory_order_relaxed) });
	out.push_back({ "cache_invalidations",       stat_cache_invalidations.load(std::memory_order_relaxed) });
	/* Current-state gauges. Use the public accessors so the locking
	 * lives in one place. */
	out.push_back({ "inflight_probes",           static_cast<uint64_t>(inflight()) });
	out.push_back({ "cache_entries",             static_cast<uint64_t>(size()) });
	return out;
}

void MySQL_Passthrough_Auth_Cache::print_version() {
	fprintf(stderr, "MySQL_Passthrough_Auth_Cache rev. " MYSQL_PASSTHROUGH_AUTH_CACHE_VERSION "\n");
}
