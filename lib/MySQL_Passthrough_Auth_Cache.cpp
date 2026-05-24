#include "MySQL_Passthrough_Auth_Cache.h"

#include "gen_utils.h"

#include "re2/re2.h"

#include <cstdio>

MySQL_Passthrough_Auth_Cache::MySQL_Passthrough_Auth_Cache()
	: inflight_probes(0), compiled_pattern(NULL) {
	pthread_rwlock_init(&lock, NULL);
	pthread_mutex_init(&failure_lock, NULL);
	pthread_mutex_init(&pattern_lock, NULL);
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
	pthread_mutex_lock(&pattern_lock);
	if (compiled_pattern) {
		delete compiled_pattern;
		compiled_pattern = NULL;
	}
	compiled_pattern_str.clear();
	pthread_mutex_unlock(&pattern_lock);
	pthread_mutex_destroy(&pattern_lock);
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
}

bool MySQL_Passthrough_Auth_Cache::would_lockout_user(
	const std::string& username, int max_failures, uint32_t window_s
) const {
	if (max_failures <= 0 || window_s == 0 || username.empty()) return false;
	const uint64_t now_us = monotonic_time();
	const uint64_t window_us = static_cast<uint64_t>(window_s) * 1000000ULL;
	pthread_mutex_lock(&failure_lock);
	auto it = failures_by_user.find(username);
	const bool lockout = (it != failures_by_user.end())
		&& (prune_and_count(it->second, now_us, window_us) >= static_cast<size_t>(max_failures));
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
	const bool lockout = (it != failures_by_ip.end())
		&& (prune_and_count(it->second, now_us, window_us) >= static_cast<size_t>(max_failures));
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
	}
	if (!ip.empty()) {
		failures_by_ip[ip].push_back(now_us);
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

	pthread_mutex_lock(&pattern_lock);

	/**
	 * @brief Recompile when the pattern string has changed since the last
	 * call, or when no compiled form is held yet.
	 *
	 * The compiled-regex cache is keyed on the exact pattern string so an
	 * admin SET mysql-passthrough_auth_username_pattern='...' picks up
	 * immediately on the next probe attempt without a restart or flush.
	 * Compilation is done with RE2::Quiet to avoid log spam on operator-
	 * supplied bad regexes.
	 */
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
	bool ok = false;
	if (compiled_pattern->ok()) {
		ok = re2::RE2::FullMatch(username, *compiled_pattern);
	}

	pthread_mutex_unlock(&pattern_lock);
	return ok;
}

void MySQL_Passthrough_Auth_Cache::print_version() {
	fprintf(stderr, "MySQL_Passthrough_Auth_Cache rev. " MYSQL_PASSTHROUGH_AUTH_CACHE_VERSION "\n");
}
