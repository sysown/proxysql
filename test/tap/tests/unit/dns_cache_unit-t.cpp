/**
 * @file dns_cache_unit-t.cpp
 * @brief Unit tests for DNS_Cache::contains_ip() used by Aurora blue/green detection.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "MySQL_Monitor.hpp"

/** @brief Test basic IP lookup in a populated cache. */
static void test_contains_ip_basic() {
	DNS_Cache cache;

	// Add a hostname with two IPs
	cache.add("host1.cluster.amazonaws.com", {"10.0.0.1", "10.0.0.2"});

	ok(cache.contains_ip("host1.cluster.amazonaws.com", "10.0.0.1") == true,
		"contains_ip: finds first IP in cache");
	ok(cache.contains_ip("host1.cluster.amazonaws.com", "10.0.0.2") == true,
		"contains_ip: finds second IP in cache");
	ok(cache.contains_ip("host1.cluster.amazonaws.com", "10.0.0.3") == false,
		"contains_ip: returns false for IP not in cache");
}

/** @brief Test that unknown hostnames return true (no mismatch evidence). */
static void test_contains_ip_unknown_hostname() {
	DNS_Cache cache;

	cache.add("known.host.com", {"192.168.1.1"});

	ok(cache.contains_ip("unknown.host.com", "192.168.1.1") == true,
		"contains_ip: returns true for unknown hostname (no evidence of mismatch)");
	ok(cache.contains_ip("unknown.host.com", "10.0.0.1") == true,
		"contains_ip: returns true for unknown hostname with any IP");
}

/** @brief Test cache update simulating blue/green DNS switchover. */
static void test_contains_ip_after_update() {
	DNS_Cache cache;

	// Initial state: hostname resolves to blue cluster IP
	cache.add("writer.cluster.amazonaws.com", {"10.0.1.100"});
	ok(cache.contains_ip("writer.cluster.amazonaws.com", "10.0.1.100") == true,
		"contains_ip: finds blue cluster IP before switchover");

	// Simulate DNS update after blue/green switchover: hostname now resolves to green cluster IP
	cache.add("writer.cluster.amazonaws.com", {"10.0.2.200"});
	ok(cache.contains_ip("writer.cluster.amazonaws.com", "10.0.1.100") == false,
		"contains_ip: old blue IP not found after DNS update");
	ok(cache.contains_ip("writer.cluster.amazonaws.com", "10.0.2.200") == true,
		"contains_ip: new green IP found after DNS update");
}

/** @brief Test that disabled cache returns true (skip detection). */
static void test_contains_ip_disabled_cache() {
	DNS_Cache cache;
	cache.add("host.com", {"10.0.0.1"});

	// Disable the cache — returns true (no evidence of mismatch, skip detection)
	cache.set_enabled_flag(false);

	ok(cache.contains_ip("host.com", "10.0.0.1") == true,
		"contains_ip: returns true when cache is disabled (skip detection)");
	ok(cache.contains_ip("host.com", "99.99.99.99") == true,
		"contains_ip: returns true for any IP when cache is disabled");

	// Re-enable
	cache.set_enabled_flag(true);
	ok(cache.contains_ip("host.com", "10.0.0.1") == true,
		"contains_ip: returns true again when cache re-enabled");
	ok(cache.contains_ip("host.com", "99.99.99.99") == false,
		"contains_ip: returns false for wrong IP when cache re-enabled");
}

/** @brief Test that empty cache returns true (hostname not tracked). */
static void test_contains_ip_empty_cache() {
	DNS_Cache cache;

	ok(cache.contains_ip("any.host.com", "1.2.3.4") == true,
		"contains_ip: returns true on empty cache (hostname not tracked)");
}

/** @brief Test IPv6 address lookup. */
static void test_contains_ip_ipv6() {
	DNS_Cache cache;

	cache.add("host.com", {"2001:db8::1", "2001:db8::2"});

	ok(cache.contains_ip("host.com", "2001:db8::1") == true,
		"contains_ip: finds IPv6 address");
	ok(cache.contains_ip("host.com", "2001:db8::3") == false,
		"contains_ip: returns false for missing IPv6 address");
}

/** @brief Test that removed hostname returns true (no longer tracked). */
static void test_contains_ip_after_remove() {
	DNS_Cache cache;

	cache.add("host.com", {"10.0.0.1"});
	ok(cache.contains_ip("host.com", "10.0.0.1") == true,
		"contains_ip: finds IP before removal");

	cache.remove("host.com");
	ok(cache.contains_ip("host.com", "10.0.0.1") == true,
		"contains_ip: returns true after hostname removed (no longer tracked)");
}

/** @brief Entry point for dns_cache unit tests. */
int main() {
	plan(18);

	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	test_contains_ip_basic();           // 3
	test_contains_ip_unknown_hostname();// 2
	test_contains_ip_after_update();    // 3
	test_contains_ip_disabled_cache();  // 4
	test_contains_ip_empty_cache();     // 1
	test_contains_ip_ipv6();            // 2
	test_contains_ip_after_remove();    // 2

	test_cleanup_minimal();
	return exit_status();
}
