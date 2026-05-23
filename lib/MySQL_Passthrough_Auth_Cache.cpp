#include "MySQL_Passthrough_Auth_Cache.h"

#include "gen_utils.h"

#include <cstdio>

MySQL_Passthrough_Auth_Cache::MySQL_Passthrough_Auth_Cache() {
	pthread_rwlock_init(&lock, NULL);
}

MySQL_Passthrough_Auth_Cache::~MySQL_Passthrough_Auth_Cache() {
	pthread_rwlock_wrlock(&lock);
	entries.clear();
	pthread_rwlock_unlock(&lock);
	pthread_rwlock_destroy(&lock);
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

void MySQL_Passthrough_Auth_Cache::print_version() {
	fprintf(stderr, "MySQL_Passthrough_Auth_Cache rev. " MYSQL_PASSTHROUGH_AUTH_CACHE_VERSION "\n");
}
