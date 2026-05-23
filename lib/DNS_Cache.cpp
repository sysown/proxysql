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

void* monitor_dns_resolver_thread(const std::vector<DNS_Resolve_Data*>& dns_resolve_data_list) {
	assert(!dns_resolve_data_list.empty());
	DNS_Resolve_Data* dns_resolve_data = dns_resolve_data_list.front();

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
	hints.ai_family = dns_resolve_data->ai_family;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
		"Resolving hostname:[%s] to its mapped IP address.\n",
		dns_resolve_data->hostname.c_str());
	int gai_rc = getaddrinfo(dns_resolve_data->hostname.c_str(), NULL, &hints, &res);

	if (gai_rc != 0 || !res) {
		proxy_error("An error occurred while resolving hostname: %s [%d]\n",
			dns_resolve_data->hostname.c_str(), gai_rc);
		goto __error;
	}

	try {
		std::vector<std::string> ips;
		ips.reserve(64);

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

		if (!ips.empty()) {

			bool to_update_cache = false;
			int cache_ttl = dns_resolve_data->ttl;
			if (dns_resolve_data->ttl > dns_resolve_data->refresh_intv) {
				thread_local std::mt19937 gen(std::random_device{}());
				const int jitter = static_cast<int>(dns_resolve_data->ttl * 0.025);
				std::uniform_int_distribution<int> dis(-jitter, jitter);
				cache_ttl += dis(gen);
			}

			if (!dns_resolve_data->cached_ips.empty()) {

				if (dns_resolve_data->cached_ips.size() == ips.size()) {
					for (const std::string& ip : ips) {
						if (dns_resolve_data->cached_ips.find(ip) == dns_resolve_data->cached_ips.end()) {
							to_update_cache = true;
							break;
						}
					}
				}
				else
					to_update_cache = true;

				if (!to_update_cache) {
					proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5,
						"DNS cache record already up-to-date. (Hostname:[%s] IP:[%s])\n",
						dns_resolve_data->hostname.c_str(),
						debug_iplisttostring(ips).c_str());
					dns_resolve_data->result.set_value(std::make_tuple<>(true,
						DNS_Cache_Record(dns_resolve_data->hostname,
							std::move(dns_resolve_data->cached_ips),
							monotonic_time() + (1000ULL * static_cast<unsigned long long>(cache_ttl)))));
				}
			}
			else
				to_update_cache = true;

			if (to_update_cache) {
				dns_resolve_data->result.set_value(std::make_tuple<>(true,
					DNS_Cache_Record(dns_resolve_data->hostname, ips,
						monotonic_time() + (1000ULL * static_cast<unsigned long long>(cache_ttl)))));
				dns_resolve_data->dns_cache->add(dns_resolve_data->hostname, std::move(ips));
			}

			return NULL;
		}
	}
	catch (std::exception& ex) {
		proxy_error("An exception occurred while resolving hostname: %s [%s]\n",
			dns_resolve_data->hostname.c_str(), ex.what());
	}
	catch (...) {
		proxy_error("An unknown exception has occurred while resolving hostname: %s\n",
			dns_resolve_data->hostname.c_str());
	}

__error:
	dns_resolve_data->result.set_value(std::make_tuple<>(false, DNS_Cache_Record()));

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
	if (records.find(hostname) == records.end()) {
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

std::string DNS_Cache::get_next_ip(const IP_ADDR& ip_addr) const {

	if (ip_addr.ips.empty())
		return "";

	const auto counter_val = __sync_fetch_and_add(&ip_addr.counter, 1);

	return ip_addr.ips[counter_val % ip_addr.ips.size()];
}

std::string DNS_Cache::lookup(const std::string& hostname, size_t* ip_count) const {
	if (!enabled) {
		if (ip_count)
			*ip_count = 0;
		return "";
	}

	std::string ip;

	if (counter_queried_)
		counter_queried_->fetch_add(1, std::memory_order_relaxed);

	int rc = pthread_rwlock_rdlock(&rwlock_);
	assert(rc == 0);
	auto itr = records.find(hostname);

	if (itr != records.end()) {
		ip = get_next_ip(itr->second);

		if (ip_count)
			*ip_count = itr->second.ips.size();

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

	return ip;
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

void DNS_Cache::clear() {
	size_t records_removed = 0;
	int rc = pthread_rwlock_wrlock(&rwlock_);
	assert(rc == 0);
	records_removed = records.size();
	records.clear();
	rc = pthread_rwlock_unlock(&rwlock_);
	assert(rc == 0);
	if (records_removed && counter_record_updated_)
		counter_record_updated_->fetch_add(records_removed, std::memory_order_relaxed);
	proxy_debug(PROXY_DEBUG_MYSQL_CONNECTION, 5, "DNS cache was cleared.\n");
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
