#include "DNS_Cache.hpp"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <cstdlib>
#include <cstring>

#include "proxysql.h"
#include "proxysql_debug.h"
#include "proxysql_utils.h"
#include "proxysql_glovars.hpp"
#include "gen_utils.h"

#include <random>


bool validate_ip(const std::string& ip) {
	// inet_pton returns 1 on success, 0 if input is not a valid address for
	// the family, -1 on error (e.g. unsupported family).  Treating != 0 as
	// success would misclassify -1 errors as valid IPs.
	struct sockaddr_in sa4;
	if (inet_pton(AF_INET, ip.c_str(), &(sa4.sin_addr)) == 1)
		return true;

	struct sockaddr_in6 sa6;
	if (inet_pton(AF_INET6, ip.c_str(), &(sa6.sin6_addr)) == 1)
		return true;

	return false;
}

std::string get_connected_peer_ip_from_socket(int socket_fd) {
	std::string result;
	char ip_addr[INET6_ADDRSTRLEN];

	struct sockaddr_storage custom_sockaddr;
	socklen_t addrlen = sizeof(custom_sockaddr);
	memset(&custom_sockaddr, 0, sizeof(custom_sockaddr));

	if (getpeername(socket_fd, (struct sockaddr*)&custom_sockaddr, &addrlen) != 0)
		return result;

	// Only assign to result when sa_family is one we know how to format.
	// Other families (AF_UNIX, AF_NETLINK, ...) shouldn't happen for a TCP
	// peer fd, but if they ever do we'd previously emit uninitialized memory
	// from ip_addr.
	if (custom_sockaddr.ss_family == AF_INET) {
		const struct sockaddr_in* ipv4 = (const struct sockaddr_in*)&custom_sockaddr;
		if (inet_ntop(AF_INET, &ipv4->sin_addr, ip_addr, INET_ADDRSTRLEN))
			result = ip_addr;
	}
	else if (custom_sockaddr.ss_family == AF_INET6) {
		const struct sockaddr_in6* ipv6 = (const struct sockaddr_in6*)&custom_sockaddr;
		if (inet_ntop(AF_INET6, &ipv6->sin6_addr, ip_addr, INET6_ADDRSTRLEN))
			result = ip_addr;
	}

	return result;
}

/**
* @brief Resolve a hostname to its IP(s) via getaddrinfo.
*
* @param hostname  Hostname to resolve.
* @param ai_family Address family for getaddrinfo (an AF_* value; AF_UNSPEC for OS default).
*
* @return The resolved IPs, or an empty vector on failure.
*/
std::vector<std::string> dns_resolve(const std::string& hostname, int ai_family) {
	std::vector<std::string> ips;

	struct addrinfo hints, *res = NULL;
	memset(&hints, 0, sizeof(hints));
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_socktype = SOCK_STREAM;
	// AI_ADDRCONFIG: only return AF_INET addrs if the local system has at least
	// one IPv4 address configured, and AF_INET6 only if it has at least one
	// IPv6 address configured.  Loopback is not considered configured for this
	// purpose.  Useful on IPv4-only hosts so getaddrinfo() doesn't return IPv6
	// addresses that connect/bind would always fail on.
	hints.ai_flags = AI_ADDRCONFIG;
	hints.ai_family = ai_family;

	int gai_rc = getaddrinfo(hostname.c_str(), NULL, &hints, &res);
	if (gai_rc != 0 || !res) {
		proxy_error("An error occurred while resolving hostname: %s [%d]\n", hostname.c_str(), gai_rc);
		return ips;
	}

	char ip_addr[INET6_ADDRSTRLEN];
	for (auto p = res; p != NULL; p = p->ai_next) {
		if (p->ai_family == AF_INET) {
			struct sockaddr_in* ipv4 = (struct sockaddr_in*)p->ai_addr;
			inet_ntop(p->ai_addr->sa_family, &ipv4->sin_addr, ip_addr, INET_ADDRSTRLEN);
			ips.push_back(ip_addr);
		}
		else {
			struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)p->ai_addr;
			inet_ntop(p->ai_addr->sa_family, &ipv6->sin6_addr, ip_addr, INET6_ADDRSTRLEN);
			ips.push_back(ip_addr);
		}
	}

	freeaddrinfo(res);
	return ips;
}

void* monitor_dns_resolver_thread(const std::vector<DNS_Resolve_Data*>& dns_resolve_data_list) {
	assert(!dns_resolve_data_list.empty());
	DNS_Resolve_Data* data = dns_resolve_data_list.front();

	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
		"Resolving hostname:[%s] to its mapped IP address.\n",
		data->hostname.c_str());

	try {
		std::vector<std::string> ips = dns_resolve(data->hostname, data->ai_family);
		if (!ips.empty()) {
			unsigned int cache_ttl = data->ttl;
			if (data->ttl > data->refresh_intv) {
				// NOSONAR cpp:S2245 — mt19937 used here only as a DNS-cache
				// TTL jitter source (non-cryptographic timing tweak); no
				// security boundary. Inline annotation on the construction
				// line because Sonar attributes the hotspot to it.
				thread_local std::mt19937 gen(std::random_device{}()); // NOSONAR cpp:S2245
				const int jitter = static_cast<int>(data->ttl * 0.025);
				std::uniform_int_distribution<int> dis(-jitter, jitter);
				cache_ttl += dis(gen);
			}

			bool to_update_cache = true;
			unsigned long long expiry = monotonic_time() + (1000ULL * (unsigned long long)cache_ttl);

			if (!data->cached_ips.empty()
				&& data->cached_ips.size() == ips.size()) {
				bool match_all = std::all_of(
					ips.begin(),
					ips.end(),
					[&](const std::string& ip) { return data->cached_ips.count(ip) != 0; }
				);
				if (match_all) {
					// keep the existing record, just refresh its expiry
					to_update_cache = false;
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
						"DNS cache record already up-to-date. (Hostname:[%s] IP:[%s])\n",
						data->hostname.c_str(), debug_iplisttostring(ips).c_str());
					data->result.set_value(std::make_tuple<>(true,
						DNS_Cache_Record(data->hostname, std::move(data->cached_ips), expiry)));
				}
			}

			if (to_update_cache) {
				data->result.set_value(std::make_tuple<>(true, DNS_Cache_Record(data->hostname, ips, expiry)));
				data->dns_cache->add(data->hostname, std::move(ips));
			}

			return NULL;
		}
	}
	catch (std::exception& ex) {
		proxy_error("An exception occurred while resolving hostname: %s [%s]\n",
			data->hostname.c_str(), ex.what());
	}
	catch (...) {
		proxy_error("An unknown exception has occurred while resolving hostname: %s\n",
			data->hostname.c_str());
	}

	data->result.set_value(std::make_tuple<>(false, DNS_Cache_Record()));

	return NULL;
}


void* DNSResolverWorker::run() {
	set_thread_name(thr_name_, GloVars.set_thread_name);

	while (true) {
		DNS_Resolve_Data* item = static_cast<DNS_Resolve_Data*>(queue_.remove());
		if (item == nullptr) {
			// Sentinel: caller pushed NULL to ask the worker to exit.
			break;
		}
		std::vector<DNS_Resolve_Data*> list { item };
		try {
			monitor_dns_resolver_thread(list);
		} catch (...) {
			// monitor_dns_resolver_thread() can in principle throw
			// (allocations inside the try/catch in there are guarded, but
			// other paths — set_thread_name, vector growth, etc. — aren't).
			// If it did and the promise was not satisfied, future::get() on
			// the producer side would block forever and hang shutdown.
			// Forcibly satisfy the promise with a failure result.  set_value
			// throws if the promise is already satisfied, which we also
			// swallow here.
			try {
				item->result.set_value(std::make_tuple<>(false, DNS_Cache_Record()));
			} catch (...) { }
		}
		delete item;
	}
	return nullptr;
}

bool DNS_Cache::is_ip_valid(const std::string& hostname, const std::string& ip) const {
	if (hostname.empty() || ip.empty()) {
		return false;
	}

	int rc = pthread_rwlock_rdlock(&rwlock_);
	assert(rc == 0);

	bool valid = false;
	auto itr = records.find(hostname);
	if (itr != records.end()) {
		const unsigned long long now = monotonic_time();
		const bool pin_active = !itr->second.pinned_ip.empty()
								&& (itr->second.pinned_until == 0 || now <= itr->second.pinned_until);
		if (pin_active) {
			valid = ip == itr->second.pinned_ip;
		} else if (enabled) {
			valid = std::find(itr->second.ips.begin(), itr->second.ips.end(), ip) != itr->second.ips.end();
		}
	}

	rc = pthread_rwlock_unlock(&rwlock_);
	assert(rc == 0);

	return valid;
}

bool DNS_Cache::add(const std::string& hostname, std::vector<std::string>&& ips) {
	if (!enabled) return false;

	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
		"Updating DNS cache. (Hostname:[%s] IP:[%s])\n",
		hostname.c_str(), debug_iplisttostring(ips).c_str());

	int rc = pthread_rwlock_wrlock(&rwlock_);
	assert(rc == 0);

	auto& ip_addr = records[hostname];
	ip_addr.ips = std::move(ips);

	__sync_fetch_and_and(&ip_addr.counter, 0);

	rc = pthread_rwlock_unlock(&rwlock_);
	assert(rc == 0);

	if (counter_record_updated_)
		counter_record_updated_->fetch_add(1, std::memory_order_relaxed);

	return true;
}

bool DNS_Cache::add_if_not_exist(const std::string& hostname, std::vector<std::string>&& ips) {
	if (!enabled) return false;

	bool inserted = false;
	int rc = pthread_rwlock_wrlock(&rwlock_);
	assert(rc == 0);

	auto itr = records.find(hostname);
	if (itr == records.end() || itr->second.ips.empty()) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
			"Updating DNS cache. (Hostname:[%s] IP:[%s])\n",
			hostname.c_str(), debug_iplisttostring(ips).c_str());
		auto& ip_addr = records[hostname];
		ip_addr.ips = std::move(ips);

		__sync_fetch_and_and(&ip_addr.counter, 0);
		inserted = true;
	}

	rc = pthread_rwlock_unlock(&rwlock_);
	assert(rc == 0);

	if (inserted && counter_record_updated_)
		counter_record_updated_->fetch_add(1, std::memory_order_relaxed);

	return inserted;
}

/**
* @brief Next round-robin IP for 'ip_addr' and the size of the served set.
*
* @param ip_addr Cache record to select from.
*
* @return Selected resolved IP details plus current pin metadata.
*/
DNS_Cache::lookup_result_t DNS_Cache::get_next_ip(const IP_ADDR& ip_addr) const {
	lookup_result_t result;

	if (!ip_addr.ips.empty()) {
		const auto counter_val = __sync_fetch_and_add(&ip_addr.counter, 1);
		result.ip_count = ip_addr.ips.size();
		result.resolved_ip = ip_addr.ips[counter_val % result.ip_count];
	}

	result.pinned_ip = ip_addr.pinned_ip;
	result.pinned_until = ip_addr.pinned_until;

	return result;
}

std::string DNS_Cache::lookup(const std::string& hostname, size_t* ip_count) {
	std::string ip;
	bool clear_expired_pin = false;

	if (counter_queried_)
		counter_queried_->fetch_add(1, std::memory_order_relaxed);

	int rc = pthread_rwlock_rdlock(&rwlock_);
	assert(rc == 0);
	auto itr = records.find(hostname);

	if (itr != records.end()) {
		lookup_result_t result = get_next_ip(itr->second);

		const unsigned long long now = monotonic_time();
		const bool pin_active = !result.pinned_ip.empty()
								&& (result.pinned_until == 0 || now <= result.pinned_until);
		clear_expired_pin = !result.pinned_ip.empty()
							&& result.pinned_until != 0 && now > result.pinned_until;

		if (pin_active) {
			ip = result.pinned_ip;
			if (ip_count)
				*ip_count = 1;
		} else if (enabled) {
			ip = result.resolved_ip;
			if (ip_count)
				*ip_count = result.ip_count;
		} else if (ip_count) {
			*ip_count = 0;
		}

		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
			"DNS cache lookup success. (Hostname:[%s] IP returned:[%s])\n",
			hostname.c_str(), ip.c_str());
	}
	else {
		if (ip_count)
			*ip_count = 0;
	}
	rc = pthread_rwlock_unlock(&rwlock_);
	assert(rc == 0);

	if (!ip.empty() && counter_lookup_success_)
		counter_lookup_success_->fetch_add(1, std::memory_order_relaxed);

	// cleanup expired pinned IP
	if (clear_expired_pin) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
			"Removing expired DNS cache pin. (Hostname:[%s])\n", hostname.c_str());
		unpin(hostname);
	}

	return ip;
}

/**
* @brief Pin a hostname to a fixed IP until it is explicitly unpinned.
*
* @param hostname Hostname whose cached resolution is overridden.
* @param ip       IP address to serve for 'hostname' while pinned.
*/
void DNS_Cache::pin(const std::string& hostname, const std::string& ip) {
	pin(hostname, ip, 0);
}

/**
* @brief Pin a hostname to a fixed IP for a bounded time.
*
* @details While the pin is active, lookup() serves 'ip' instead of the resolved
*   address set. Once ttl_ms expires, lookup() serves the resolved address and
*   clears the expired pin before returning.
*
* @param hostname Hostname whose cached resolution is overridden.
* @param ip       IP address to serve for 'hostname' while pinned.
* @param ttl_ms   Pin lifetime in milliseconds; 0 means no expiry.
*/
void DNS_Cache::pin(const std::string& hostname, const std::string& ip, unsigned long long ttl_ms) {
	if (hostname.empty() || ip.empty()) return;

	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
		"Pinning DNS cache record. (Hostname:[%s] IP:[%s])\n",
		hostname.c_str(), ip.c_str());

	int rc = pthread_rwlock_wrlock(&rwlock_);
	assert(rc == 0);

	// Store on the record's 'pinned_ip' so a concurrent resolver add() (which
	// only rewrites 'ips') cannot drop the override on a TTL refresh.
	auto& ip_addr = records[hostname];
	ip_addr.pinned_ip = ip;
	ip_addr.pinned_until = ttl_ms ? monotonic_time() + (ttl_ms * 1000) : 0;
	__sync_fetch_and_and(&ip_addr.counter, 0);

	rc = pthread_rwlock_unlock(&rwlock_);
	assert(rc == 0);

	if (counter_record_updated_)
		counter_record_updated_->fetch_add(1, std::memory_order_relaxed);
}

/**
* @brief Remove a pin set by pin(), restoring normal resolution (no-op if not pinned).
*
* @param hostname Hostname to unpin.
*/
void DNS_Cache::unpin(const std::string& hostname) {
	bool item_removed = false;

	int rc = pthread_rwlock_wrlock(&rwlock_);
	assert(rc == 0);

	auto itr = records.find(hostname);
	if (itr != records.end() && !itr->second.pinned_ip.empty()) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
			"Unpinning DNS cache record. (Hostname:[%s] IP:[%s])\n",
			hostname.c_str(), itr->second.pinned_ip.c_str());
		itr->second.pinned_ip.clear();
		itr->second.pinned_until = 0;
		// drop the record entirely if pinning was the only thing keeping it alive
		// (e.g. the host is not otherwise resolved into the cache).
		if (itr->second.ips.empty())
			records.erase(itr);
		item_removed = true;
	}

	rc = pthread_rwlock_unlock(&rwlock_);
	assert(rc == 0);

	if (item_removed && counter_record_updated_)
		counter_record_updated_->fetch_add(1, std::memory_order_relaxed);
}

void DNS_Cache::remove(const std::string& hostname) {
	bool item_removed = false;

	int rc = pthread_rwlock_wrlock(&rwlock_);
	assert(rc == 0);
	auto itr = records.find(hostname);
	if (itr != records.end()) {
		proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
			"Removing DNS cache record. (Hostname:[%s] IP:[%s])\n",
			hostname.c_str(), debug_iplisttostring(itr->second.ips).c_str());
		records.erase(itr);
		item_removed = true;
	}
	rc = pthread_rwlock_unlock(&rwlock_);

	if (item_removed && counter_record_updated_)
		counter_record_updated_->fetch_add(1, std::memory_order_relaxed);

	assert(rc == 0);
}

/**
 * @brief Clear ordinary DNS resolutions while retaining explicit pins.
 *
 * @details Unpinned records are removed. Pinned records keep their fixed
 *   address while their ordinary resolution list and rotation counter are reset.
 */
void DNS_Cache::clear() {
	size_t records_removed = 0;
	int rc = pthread_rwlock_wrlock(&rwlock_);
	assert(rc == 0);
	for (auto itr = records.begin(); itr != records.end(); ) {
		if (itr->second.pinned_ip.empty()) {
			itr = records.erase(itr);
			++records_removed;
		} else {
			itr->second.ips.clear();
			itr->second.counter = 0;
			++itr;
		}
	}
	rc = pthread_rwlock_unlock(&rwlock_);
	assert(rc == 0);
	if (records_removed && counter_record_updated_)
		counter_record_updated_->fetch_add(records_removed, std::memory_order_relaxed);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
		"DNS cache resolved records were cleared; explicit pins were preserved.\n");
}

bool DNS_Cache::empty() const {
	bool result = true;

	int rc = pthread_rwlock_rdlock(&rwlock_);
	assert(rc == 0);
	result = records.empty();
	rc = pthread_rwlock_unlock(&rwlock_);
	assert(rc == 0);

	return result;
}
