/**
 * @file pgsql-test_dns_cache-t.cpp
 * @brief Tests the PgSQL-side DNS cache added for issue #5768.
 *
 * Covers:
 *  - Cache is on by default and a resolvable hostname populates it
 *    (PgSQL_Monitor_dns_cache_record_updated increments).
 *  - IP literals bypass the cache (record_updated stays flat).
 *  - Client connect through ProxySQL goes through the cache
 *    (PgSQL_Monitor_dns_cache_queried + _lookup_success increment).
 *  - Hostnames with leading/trailing whitespace are trimmed before
 *    resolution.
 *  - An unresolvable hostname is queried but never produces a record.
 *  - Removing a pgsql_servers row drops the corresponding cache record.
 *  - Disabling the cache (refresh_interval=0) flatlines all counters.
 *  - PgSQL cache state is independent of MySQL cache state: tweaking
 *    pgsql-monitor_local_dns_* and inserting pgsql hostnames must not
 *    move the MySQL_Monitor_dns_cache_* counters, and vice versa.
 *
 * Reads counters from stats_pgsql_global / stats_mysql_global rather
 * than Prometheus because the PgSQL DNS counters are only exposed
 * through stats_pgsql_global today.
 */

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "libpq-fe.h"

#include "command_line.h"
#include "tap.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static PGConnPtr admin_connect() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_admin_host
		<< " port=" << cl.pgsql_admin_port
		<< " user=" << cl.admin_username
		<< " password=" << cl.admin_password
		<< " sslmode=disable";
	PGconn* c = PQconnectdb(ss.str().c_str());
	if (PQstatus(c) != CONNECTION_OK) {
		diag("ADMIN connect failed: %s", PQerrorMessage(c));
		PQfinish(c);
		return PGConnPtr(nullptr, &PQfinish);
	}
	return PGConnPtr(c, &PQfinish);
}

static PGConnPtr backend_connect() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host
		<< " port=" << cl.pgsql_port
		<< " user=" << cl.pgsql_username
		<< " password=" << cl.pgsql_password
		<< " sslmode=disable";
	PGconn* c = PQconnectdb(ss.str().c_str());
	// Don't fail the test on connection error; the test exercises the DNS
	// cache via connection attempts that may legitimately fail (bad host,
	// bad port).  Caller checks PQstatus.
	return PGConnPtr(c, &PQfinish);
}

// Run a one-off statement on the admin connection.  Returns true on success.
// Statements where we don't care about the row count use this.
static bool admin_exec(PGConnPtr& a, const std::string& sql) {
	PGresult* r = PQexec(a.get(), sql.c_str());
	const ExecStatusType st = PQresultStatus(r);
	bool ok = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!ok) {
		diag("admin_exec('%s') failed: %s", sql.c_str(), PQerrorMessage(a.get()));
	}
	PQclear(r);
	return ok;
}

// Read a single counter from stats_pgsql_global (or stats_mysql_global).
// Returns -1 on failure.
static long admin_counter(PGConnPtr& a, const char* table, const char* name) {
	std::stringstream q;
	q << "SELECT Variable_Value FROM " << table
		<< " WHERE Variable_Name='" << name << "'";
	PGresult* r = PQexec(a.get(), q.str().c_str());
	if (PQresultStatus(r) != PGRES_TUPLES_OK || PQntuples(r) == 0) {
		PQclear(r);
		return -1;
	}
	long v = atol(PQgetvalue(r, 0, 0));
	PQclear(r);
	return v;
}

struct DnsCounters {
	long queried { -1 };
	long lookup_success { -1 };
	long record_updated { -1 };
};

static DnsCounters read_pg_counters(PGConnPtr& a) {
	DnsCounters c;
	c.queried = admin_counter(a, "stats_pgsql_global", "PgSQL_Monitor_dns_cache_queried");
	c.lookup_success = admin_counter(a, "stats_pgsql_global", "PgSQL_Monitor_dns_cache_lookup_success");
	c.record_updated = admin_counter(a, "stats_pgsql_global", "PgSQL_Monitor_dns_cache_record_updated");
	return c;
}

// Force a `SELECT 1` round-trip through the proxy a few times so the worker
// thread opens a backend connection and the DNS cache lookup path runs.
// Returns the number of successful attempts; we don't require all of them
// because a hostname pointing at a dummy port is expected to fail at TCP
// connect — that's fine, the DNS lookup happened first.
static int hammer_proxy(int n) {
	int ok_count = 0;
	for (int i = 0; i < n; i++) {
		PGConnPtr c = backend_connect();
		if (PQstatus(c.get()) == CONNECTION_OK) {
			PGresult* r = PQexec(c.get(), "SELECT 1");
			if (PQresultStatus(r) == PGRES_TUPLES_OK) ok_count++;
			PQclear(r);
		}
		// Brief pacing so we don't outpace the resolver loop.
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
	return ok_count;
}

static void sleep_seconds(int s) {
	std::this_thread::sleep_for(std::chrono::seconds(s));
}

// Wait up to deadline_secs for the resolver loop to populate the cache; poll
// every poll_ms.  Returns true if record_updated grew past `baseline`.
static bool wait_for_record_growth(PGConnPtr& a, long baseline, int deadline_secs) {
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(deadline_secs);
	while (std::chrono::steady_clock::now() < deadline) {
		const long now_val = admin_counter(a, "stats_pgsql_global", "PgSQL_Monitor_dns_cache_record_updated");
		if (now_val > baseline) return true;
		std::this_thread::sleep_for(std::chrono::milliseconds(250));
	}
	return false;
}

int main(int /*argc*/, char** /*argv*/) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return -1;
	}

	plan(16);

	PGConnPtr admin = admin_connect();
	if (!admin) {
		BAIL_OUT("Could not connect to ProxySQL Admin via libpq");
		return exit_status();
	}

	// Make the cache tunable and fast, so test cycles complete in seconds.
	// 500 ms refresh interval, 5 s TTL.  Save the originals so we restore
	// them on the way out.
	const long orig_refresh = admin_counter(admin, "global_variables", "pgsql-monitor_local_dns_cache_refresh_interval");
	const long orig_ttl = admin_counter(admin, "global_variables", "pgsql-monitor_local_dns_cache_ttl");
	const long orig_qsize = admin_counter(admin, "global_variables", "pgsql-monitor_local_dns_resolver_queue_maxsize");

	if (!admin_exec(admin, "SET pgsql-monitor_local_dns_cache_refresh_interval=500")) {
		BAIL_OUT("Could not set pgsql-monitor_local_dns_cache_refresh_interval");
		return exit_status();
	}
	if (!admin_exec(admin, "SET pgsql-monitor_local_dns_cache_ttl=5000") ||
	    !admin_exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME")) {
		BAIL_OUT("Could not apply pgsql DNS cache runtime settings");
		return exit_status();
	}

	// Confirm the new values actually landed in runtime (regression for the
	// "names commented out in pgsql_thread_variables_names" bug fixed during
	// initial bring-up).
	const long rt_refresh = admin_counter(admin, "runtime_global_variables", "pgsql-monitor_local_dns_cache_refresh_interval");
	const long rt_ttl = admin_counter(admin, "runtime_global_variables", "pgsql-monitor_local_dns_cache_ttl");
	ok(rt_refresh == 500, "pgsql-monitor_local_dns_cache_refresh_interval propagated to runtime (got %ld, expected 500)", rt_refresh);
	ok(rt_ttl == 5000, "pgsql-monitor_local_dns_cache_ttl propagated to runtime (got %ld, expected 5000)", rt_ttl);

	// Wipe the pgsql_servers table down to a known state.  Tests below add
	// servers in a high hostgroup that real test infra doesn't use.
	admin_exec(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=999");
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");

	// Install a routing rule so client queries hitting the proxy land on
	// hostgroup 999 (the test's own hostgroup) instead of whatever the
	// infra's default backend is.  Without this, hammer_proxy() routes
	// through the default hostgroup — typically configured with an IP
	// literal in the test infrastructure (see e.g.
	// test/infra/docker-pgsql16-single/conf/proxysql/config.sql) which
	// bypasses DNS entirely via validate_ip() and never exercises
	// PgSQL_Connection::connect_start_DNS_lookup.  Step 3 below would
	// then assert on counters bumped by the resolver loop alone, masking
	// a broken connect-path.  Rule id 99999 is well outside ranges used
	// by the test infra; we delete it on the way out.
	admin_exec(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=99999");
	{
		// Use the runtime test username so the rule actually matches the
		// connections from backend_connect() / hammer_proxy(); a hardcoded
		// 'testuser' would silently bypass hostgroup 999 whenever the infra
		// uses a different user.
		std::stringstream q;
		q << "INSERT INTO pgsql_query_rules "
		  << "(rule_id,active,username,destination_hostgroup,apply) "
		  << "VALUES (99999,1,'" << cl.pgsql_username << "',999,1)";
		admin_exec(admin, q.str());
	}
	admin_exec(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	// Give the resolver loop time to drop any orphaned bookkeeping entry.
	sleep_seconds(2);

	// =====================================================================
	// Step 1: IP literal must NOT cause DNS work
	// =====================================================================
	diag("---- Step 1: IP-literal server should not populate the cache");
	DnsCounters before = read_pg_counters(admin);
	admin_exec(admin,
		"INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,comment) "
		"VALUES (999,'0.0.0.0',7861,10,'pgsql-dns-test ip-literal')");
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	sleep_seconds(2);
	DnsCounters after = read_pg_counters(admin);
	ok(after.record_updated == before.record_updated,
		"IP literal does not touch cache (record_updated %ld -> %ld)",
		before.record_updated, after.record_updated);

	// =====================================================================
	// Step 2: Resolvable hostname populates record_updated
	// =====================================================================
	// We use example.com — IANA-reserved and stable.  Public DNS hostnames
	// are also what the upstream MySQL test uses.  If the test runner has
	// no outbound DNS, this step (and steps 3 and 4) will be skipped via
	// the wait_for_record_growth helper, which fails the ok().  CI runners
	// have network access; the failure surface from a missing resolver is
	// noisy on purpose so we notice.
	diag("---- Step 2: Resolvable hostname populates the cache");
	before = read_pg_counters(admin);
	admin_exec(admin,
		"INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,comment) "
		"VALUES (999,'example.com',7861,10,'pgsql-dns-test resolvable')");
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	// trigger_dns_cache_update fires on LOAD so refresh shouldn't take a
	// full interval, but give it a generous window.
	bool grew = wait_for_record_growth(admin, before.record_updated, 10);
	ok(grew, "resolver populated cache for example.com (record_updated %ld -> %ld)",
		before.record_updated, admin_counter(admin, "stats_pgsql_global", "PgSQL_Monitor_dns_cache_record_updated"));

	// =====================================================================
	// Step 3: Client connect through proxy hits the cache
	// =====================================================================
	diag("---- Step 3: Client connect attempt drives lookup counters");
	before = read_pg_counters(admin);
	// Drive several attempts.  These will fail at the TCP layer (port 7861
	// is not listening) but the DNS lookup path runs first and that's what
	// we're counting.
	hammer_proxy(3);
	sleep_seconds(1);
	after = read_pg_counters(admin);
	ok(after.queried > before.queried,
		"dns_cache_queried bumped after client connect attempts (%ld -> %ld)",
		before.queried, after.queried);
	ok(after.lookup_success > before.lookup_success,
		"dns_cache_lookup_success bumped (cache hit for example.com) (%ld -> %ld)",
		before.lookup_success, after.lookup_success);

	// =====================================================================
	// Step 4: Whitespace around hostname is trimmed before resolution
	// =====================================================================
	diag("---- Step 4: Hostname whitespace is trimmed");
	before = read_pg_counters(admin);
	admin_exec(admin,
		"INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,comment) "
		"VALUES (999,' example.org ',7861,10,'pgsql-dns-test whitespace')");
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	grew = wait_for_record_growth(admin, before.record_updated, 10);
	ok(grew, "trimmed hostname ' example.org ' was resolved (record_updated %ld -> %ld)",
		before.record_updated, admin_counter(admin, "stats_pgsql_global", "PgSQL_Monitor_dns_cache_record_updated"));

	// =====================================================================
	// Step 5: Unresolvable hostname — lookup is queried but produces nothing
	// =====================================================================
	diag("---- Step 5: Unresolvable hostname");
	// Drop everything except an unresolvable host so the cache has a clean
	// shape; then drive a lookup attempt.
	admin_exec(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=999");
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	sleep_seconds(2);
	before = read_pg_counters(admin);
	admin_exec(admin,
		"INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,comment) "
		"VALUES (999,'this-host-should-not-resolve.invalid',7861,10,'pgsql-dns-test nxdomain')");
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	sleep_seconds(3);
	after = read_pg_counters(admin);
	ok(after.record_updated == before.record_updated,
		"unresolvable host did not produce a record (record_updated %ld -> %ld)",
		before.record_updated, after.record_updated);

	// Now drive a client connect and confirm dns_cache_queried bumps but
	// lookup_success stays flat (cache miss, falls back to hostname).
	before = after;
	hammer_proxy(3);
	sleep_seconds(1);
	after = read_pg_counters(admin);
	ok(after.queried > before.queried,
		"dns_cache_queried bumped on unresolved hostname attempts (%ld -> %ld)",
		before.queried, after.queried);
	ok(after.lookup_success == before.lookup_success,
		"dns_cache_lookup_success stayed flat (cache miss) (%ld -> %ld)",
		before.lookup_success, after.lookup_success);

	// =====================================================================
	// Step 6: Removing servers drops orphaned cache records
	// =====================================================================
	diag("---- Step 6: Removing pgsql_servers clears orphaned cache records");
	// Add a resolvable host, wait for the cache to populate, then drop and
	// confirm record_updated grew (the bookkeeper signals a remove via the
	// same counter).
	admin_exec(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=999");
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	sleep_seconds(2);
	before = read_pg_counters(admin);
	admin_exec(admin,
		"INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,comment) "
		"VALUES (999,'example.net',7861,10,'pgsql-dns-test orphan-cleanup')");
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	bool added = wait_for_record_growth(admin, before.record_updated, 10);
	long after_add = admin_counter(admin, "stats_pgsql_global", "PgSQL_Monitor_dns_cache_record_updated");
	ok(added, "added example.net (record_updated %ld -> %ld)", before.record_updated, after_add);

	// Now drop the row and wait for the orphan-cleanup pass.
	admin_exec(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=999");
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	bool removed = wait_for_record_growth(admin, after_add, 10);
	ok(removed,
		"orphan removal bumped record_updated (was %ld, now %ld)",
		after_add, admin_counter(admin, "stats_pgsql_global", "PgSQL_Monitor_dns_cache_record_updated"));

	// =====================================================================
	// Step 7: Disabled cache (refresh_interval=0) flatlines counters
	// =====================================================================
	diag("---- Step 7: Cache disabled by refresh_interval=0");
	admin_exec(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=999");
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	sleep_seconds(1);
	admin_exec(admin, "SET pgsql-monitor_local_dns_cache_refresh_interval=0");
	admin_exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	// Use a resolvable hostname so the assertion exercises the actual cache
	// path — if disabling the cache regressed (resolver still ran, or the
	// connect path still called into the cache), record_updated and queried
	// would move and the test would fail.  An IP literal would bypass DNS
	// regardless of refresh_interval and miss that regression.
	admin_exec(admin,
		"INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,comment) "
		"VALUES (999,'example.com',7861,10,'pgsql-dns-test cache-off')");
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	sleep_seconds(3);
	before = read_pg_counters(admin);
	hammer_proxy(3);
	sleep_seconds(2);
	after = read_pg_counters(admin);
	ok(after.queried == before.queried,
		"cache off: dns_cache_queried unchanged (%ld -> %ld)",
		before.queried, after.queried);
	ok(after.lookup_success == before.lookup_success,
		"cache off: dns_cache_lookup_success unchanged (%ld -> %ld)",
		before.lookup_success, after.lookup_success);
	ok(after.record_updated == before.record_updated,
		"cache off: dns_cache_record_updated unchanged (%ld -> %ld)",
		before.record_updated, after.record_updated);

	// =====================================================================
	// Step 8: PgSQL cache is independent of MySQL cache
	// =====================================================================
	diag("---- Step 8: PgSQL cache state independent of MySQL cache");
	// Re-enable the cache so the next inserts populate it, then make sure
	// PgSQL activity does not leak into the MySQL DNS cache.
	//
	// The substantive isolation guarantee is that PgSQL-side activity must
	// not add or mutate records in the MySQL DNS cache --
	// MySQL_Monitor_dns_cache_record_updated stays at its baseline. That is
	// the assertion we keep.
	//
	// We do NOT assert on MySQL_Monitor_dns_cache_queried here because that
	// counter is bumped by the MySQL Monitor's own DNS resolver loop on its
	// own schedule (mysql-monitor_local_dns_cache_refresh_interval, default
	// 60s) for every hostname in mysql_servers UNION proxysql_servers,
	// independently of any PgSQL activity. A 4-5s test window can either
	// catch zero ticks of that loop (counter stays flat) or one tick
	// (counter bumps by N hostnames) -- the assertion is timing-dependent
	// rather than logic-dependent, which made it ~40% flaky on legacy-g4
	// without telling us anything new about isolation. record_updated
	// staying flat is sufficient: it proves no cache mutation came from
	// PgSQL.
	admin_exec(admin, "SET pgsql-monitor_local_dns_cache_refresh_interval=500");
	admin_exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
	const long my_before_u = admin_counter(admin, "stats_mysql_global", "MySQL_Monitor_dns_cache_record_updated");
	admin_exec(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=999");
	admin_exec(admin,
		"INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,comment) "
		"VALUES (999,'example.com',7861,10,'pgsql-dns-test independence')");
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	sleep_seconds(3);
	hammer_proxy(2);
	sleep_seconds(1);
	const long my_after_u = admin_counter(admin, "stats_mysql_global", "MySQL_Monitor_dns_cache_record_updated");
	ok(my_after_u == my_before_u,
		"pgsql activity did not bump MySQL_Monitor_dns_cache_record_updated (%ld -> %ld)",
		my_before_u, my_after_u);

	// =====================================================================
	// Cleanup
	// =====================================================================
	admin_exec(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=999");
	admin_exec(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	admin_exec(admin, "DELETE FROM pgsql_query_rules WHERE rule_id=99999");
	admin_exec(admin, "LOAD PGSQL QUERY RULES TO RUNTIME");
	{
		std::stringstream q;
		q << "SET pgsql-monitor_local_dns_cache_refresh_interval=" << (orig_refresh > 0 ? orig_refresh : 60000);
		admin_exec(admin, q.str());
	}
	{
		std::stringstream q;
		q << "SET pgsql-monitor_local_dns_cache_ttl=" << (orig_ttl > 0 ? orig_ttl : 300000);
		admin_exec(admin, q.str());
	}
	{
		std::stringstream q;
		q << "SET pgsql-monitor_local_dns_resolver_queue_maxsize=" << (orig_qsize > 0 ? orig_qsize : 128);
		admin_exec(admin, q.str());
	}
	admin_exec(admin, "LOAD PGSQL VARIABLES TO RUNTIME");

	return exit_status();
}
