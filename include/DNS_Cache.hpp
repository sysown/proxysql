#ifndef __CLASS_DNS_CACHE_H
#define __CLASS_DNS_CACHE_H

// Shared DNS cache infrastructure used by both MySQL_Monitor and PgSQL_Monitor.
// The cache itself is just a hostname -> [IP] map with TTL; the resolver thread
// does getaddrinfo and feeds the cache.  Each monitor instantiates its own
// DNS_Cache and supplies its own counters, so the two protocols share code but
// have independent cache state.

#include <pthread.h>
#include <sys/socket.h>

#include <algorithm>
#include <atomic>
#include <cassert>
#include <future>
#include <iterator>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <utility>
#include <vector>

#include "thread.h"
#include "wqueue.h"

struct DNS_Cache_Record {
	DNS_Cache_Record() = default;
	DNS_Cache_Record(DNS_Cache_Record&&) = default;
	DNS_Cache_Record(const DNS_Cache_Record&) = default;
	DNS_Cache_Record& operator=(DNS_Cache_Record&&) = default;
	DNS_Cache_Record& operator=(const DNS_Cache_Record&) = default;
	DNS_Cache_Record(const std::string& hostname, const std::vector<std::string>& ips, unsigned long long ttl = 0)
		: hostname_(hostname), ttl_(ttl) {
		std::copy(ips.begin(), ips.end(), std::inserter(ips_, ips_.end()));
	}
	DNS_Cache_Record(const std::string& hostname, std::set<std::string>&& ips, unsigned long long ttl = 0)
		: hostname_(hostname), ips_(std::move(ips)), ttl_(ttl) { }

	~DNS_Cache_Record() = default;

	std::string hostname_;
	std::set<std::string> ips_;
	unsigned long long ttl_ = 0;
};

class DNS_Cache {

public:
	DNS_Cache() : enabled(true) {
		int rc = pthread_rwlock_init(&rwlock_, nullptr);
		assert(rc == 0);
	}

	~DNS_Cache() {
		pthread_rwlock_destroy(&rwlock_);
	}

	inline
	void set_enabled_flag(bool value) {
		enabled = value;
	}

	// Wire the cache up to per-instance counters maintained by the owning
	// monitor.  Pass nullptr to leave any counter unincremented; this is what
	// keeps MySQL_Monitor and PgSQL_Monitor cache state independent.  The
	// counters are atomic because resolver workers increment them while
	// p_update_metrics() reads them from another thread.
	inline
	void set_counters(std::atomic<unsigned long long>* queried,
		std::atomic<unsigned long long>* lookup_success,
		std::atomic<unsigned long long>* record_updated) {
		counter_queried_ = queried;
		counter_lookup_success_ = lookup_success;
		counter_record_updated_ = record_updated;
	}

	bool add(const std::string& hostname, std::vector<std::string>&& ips);
	bool add_if_not_exist(const std::string& hostname, std::vector<std::string>&& ips);
	void remove(const std::string& hostname);
	void clear();
	bool empty() const;
	bool is_ip_valid(const std::string& hostname, const std::string& ip) const;
	std::string lookup(const std::string& hostname, size_t* ip_count);

	/**
	* @brief Pin a hostname to a fixed IP until it is explicitly unpinned.
	*
	* @param hostname Hostname whose cached resolution is overridden.
	* @param ip       IP address to serve for 'hostname' while pinned.
	*/
	void pin(const std::string& hostname, const std::string& ip);

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
	void pin(const std::string& hostname, const std::string& ip, unsigned long long ttl_ms);

	/**
	* @brief Remove a pin set by pin(), restoring normal resolution (no-op if not pinned).
	*
	* @param hostname Hostname to unpin.
	*/
	void unpin(const std::string& hostname);

private:
	struct IP_ADDR {
		std::vector<std::string> ips;
		// Pinned override: when non-empty, lookup() serves it instead of 'ips'
		// while pinned_until is not expired.
		std::string pinned_ip;
		unsigned long long pinned_until = 0;
		// 'counter' is bumped by get_next_ip() (a const method) for
		// round-robin selection; the logical state of the cache record is
		// unchanged, so mutable is the right tool here and lets us drop a
		// const_cast at the call site.
		mutable unsigned long counter = 0;
	};

	struct lookup_result_t {
		std::string resolved_ip;
		size_t ip_count = 0;
		std::string pinned_ip;
		unsigned long long pinned_until = 0;
	};

	/**
	* @brief Next round-robin IP for 'ip_addr' and the size of the served set.
	*
	* @param ip_addr Cache record to select from.
	*
	* @return Selected resolved IP details plus current pin metadata.
	*/
	lookup_result_t get_next_ip(const IP_ADDR& ip_addr) const;

	mutable std::unordered_map<std::string, IP_ADDR> records;
	std::atomic_bool enabled;
	mutable pthread_rwlock_t rwlock_;

	std::atomic<unsigned long long>* counter_queried_ { nullptr };
	std::atomic<unsigned long long>* counter_lookup_success_ { nullptr };
	std::atomic<unsigned long long>* counter_record_updated_ { nullptr };
};

struct DNS_Resolve_Data {
	std::promise<std::tuple<bool, DNS_Cache_Record>> result;
	std::shared_ptr<DNS_Cache> dns_cache;
	std::string hostname;
	std::set<std::string> cached_ips;
	unsigned int ttl = 0;
	unsigned int refresh_intv = 0;
	// Address family for getaddrinfo, set by the caller from its protocol's
	// resolution_family setting.  AF_UNSPEC keeps the OS default behavior.
	int ai_family = AF_UNSPEC;
};

// Worker function for the DNS resolver thread pool.  Performs getaddrinfo
// on dns_resolve_data->hostname, populates the cache, and fulfils the
// future on dns_resolve_data->result.
void* monitor_dns_resolver_thread(const std::vector<DNS_Resolve_Data*>& dns_resolve_data_list);

// Minimal worker thread that drains a wqueue<DNS_Resolve_Data*> and calls
// monitor_dns_resolver_thread() on each item.  Independent of any monitor
// singleton so it can back PgSQL_Monitor's DNS cache loop alongside (or
// instead of) MySQL_Monitor's existing ConsumerThread-based pool.
//
// Each item ownership is transferred to this worker: the worker frees it
// after running monitor_dns_resolver_thread.  A NULL dequeue is the exit
// signal — the loop terminates cleanly so callers can shut the pool down by
// pushing one NULL per worker.
class DNSResolverWorker : public Thread {
public:
	DNSResolverWorker(wqueue<DNS_Resolve_Data*>& q, const char* name = nullptr)
		: queue_(q) {
		if (name && name[0])
			snprintf(thr_name_, sizeof(thr_name_), "%.15s", name);
		else
			snprintf(thr_name_, sizeof(thr_name_), "DNSResolver");
	}

	void* run() override;

private:
	wqueue<DNS_Resolve_Data*>& queue_;
	char thr_name_[16] {};
};

// Return true if 'ip' is a valid IPv4 or IPv6 address string.
bool validate_ip(const std::string& ip);

// Return the IP address of the peer connected to 'socket_fd', or "" on
// failure / non-IP families.
std::string get_connected_peer_ip_from_socket(int socket_fd);

/**
* @brief Resolve a hostname to its IP(s) via getaddrinfo.
*
* @param hostname  Hostname to resolve.
* @param ai_family Address family for getaddrinfo (an AF_* value; AF_UNSPEC for OS default).
*
* @return The resolved IPs, or an empty vector on failure.
*/
std::vector<std::string> dns_resolve(const std::string& hostname, int ai_family);

// Helper: stringify a list of IPs for debug logging.  Defined inline because
// it's templated over the iterable type used by the various call sites.
template<class T>
std::string debug_iplisttostring(const T& ips) {
	std::stringstream sstr;
	for (const std::string& ip : ips)
		sstr << ip << " ";
	return sstr.str();
}

#endif // __CLASS_DNS_CACHE_H
