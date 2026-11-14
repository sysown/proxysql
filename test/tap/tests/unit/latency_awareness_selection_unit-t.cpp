/**
 * @file latency_awareness_selection_unit-t.cpp
 * @brief Latency-aware server selection never leaves a zero total weight.
 *
 * When `{mysql,pgsql}-min_num_servers_lantency_awareness` is not larger than
 * the number of candidates, get_random_MySrvC() drops every candidate whose
 * ping latency is above the average, then runs the weighted lottery
 * `random % total_weight` over the survivors. Weight-0 servers are
 * candidates too. If a weight-0 server is the fastest one, the filter used to
 * keep only that server, the total weight became 0 and the modulo raised
 * SIGFPE, killing the process on the first query routed to the hostgroup.
 *
 * The filter is now skipped when it would keep no weight, so selection falls
 * back to all candidates, exactly as it does when a server has no latency.
 *
 * Each protocol is checked with the real MyHGC / PgSQL_HGC::get_random_MySrvC():
 *   1. weight-0 server at 1 ms + weight-1 server at 9 ms: before the fix the
 *      call crashes with SIGFPE; now it returns the weight-1 server, and the
 *      latency-awareness counter is not incremented (the filter was skipped).
 *   2. both servers weight 1: the filter still applies, as in v3.0.11, and
 *      always returns the faster server, incrementing the counter.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Logger.hpp"
#include "PgSQL_Logger.hpp"
#include "MySQL_Session.h"
#include "PgSQL_Session.h"

extern MySQL_HostGroups_Manager *MyHGM;
extern PgSQL_HostGroups_Manager *PgHGM;
extern MySQL_Logger *GloMyLogger;
extern PgSQL_Logger *GloPgSQL_Logger;

static const int kIterations = 200;

static MySrvC *add_mysql_server(unsigned int hid, const char *addr, int port, int64_t weight) {
	srv_info_t info;
	info.addr = addr;
	info.port = port;
	info.kind = "latency-awareness-unit";

	srv_opts_t opts;
	opts.weigth = weight;
	opts.max_conns = 100;
	opts.use_ssl = 0;

	MyHGM->wrlock();
	int rc = MyHGM->create_new_server_in_hg(hid, info, opts);
	MyHGC *hgc = MyHGM->MyHGC_find(hid);
	MySrvC *server = nullptr;
	if (hgc != nullptr) {
		for (unsigned int i = 0; i < hgc->mysrvs->cnt(); i++) {
			MySrvC *candidate = hgc->mysrvs->idx(i);
			if (strcmp(candidate->address, addr) == 0) {
				server = candidate;
			}
		}
	}
	MyHGM->wrunlock();
	if (rc != 0 || server == nullptr) {
		BAIL_OUT("failed to add MySQL server %s to hostgroup %u", addr, hid);
	}
	return server;
}

static PgSQL_SrvC *add_pgsql_server(unsigned int hid, const char *addr, int port, int64_t weight) {
	PgSQL_srv_info_t info;
	info.addr = addr;
	info.port = port;
	info.kind = "latency-awareness-unit";

	PgSQL_srv_opts_t opts;
	opts.weigth = weight;
	opts.max_conns = 100;
	opts.use_ssl = 0;

	PgHGM->wrlock();
	int rc = PgHGM->create_new_server_in_hg(hid, info, opts);
	PgSQL_HGC *hgc = PgHGM->MyHGC_find(hid);
	PgSQL_SrvC *server = nullptr;
	if (hgc != nullptr) {
		for (unsigned int i = 0; i < hgc->mysrvs->cnt(); i++) {
			PgSQL_SrvC *candidate = hgc->mysrvs->idx(i);
			if (strcmp(candidate->address, addr) == 0) {
				server = candidate;
			}
		}
	}
	PgHGM->wrunlock();
	if (rc != 0 || server == nullptr) {
		BAIL_OUT("failed to add PgSQL server %s to hostgroup %u", addr, hid);
	}
	return server;
}

static void test_mysql_latency_awareness() {
	const unsigned int hid = 9301;
	MySrvC *near_srv = add_mysql_server(hid, "lat-mysql-near", 13306, 0);
	MySrvC *far_srv = add_mysql_server(hid, "lat-mysql-far", 13307, 1);
	MyHGC *hgc = MyHGM->MyHGC_find(hid);
	near_srv->current_latency_us = 1000;
	far_srv->current_latency_us = 9000;

	// The worker is declared before the session so that the session, whose
	// destructor dereferences its thread, is destroyed first.
	MySQL_Thread worker;
	if (!worker.init()) {
		BAIL_OUT("MySQL_Thread::init() failed");
	}
	MySQL_Session session;
	session.thread = &worker;
	worker.variables.min_num_servers_lantency_awareness = 2;

	const int old_default_max_latency_ms = mysql_thread___default_max_latency_ms;
	const int old_session_track_variables = mysql_thread___session_track_variables;
	mysql_thread___default_max_latency_ms = 1000;
	mysql_thread___session_track_variables = session_track_variables::DISABLED;

	unsigned long long &counter = worker.status_variables.stvar[st_var_ConnPool_get_conn_latency_awareness];

	// Case 1: only the weight-0 server is at or below the average latency.
	counter = 0;
	int picked_far = 0;
	MyHGM->wrlock();
	for (int i = 0; i < kIterations; i++) {
		if (hgc->get_random_MySrvC(nullptr, 0, -1, &session) == far_srv) {
			picked_far++;
		}
	}
	MyHGM->wrunlock();
	ok(picked_far == kIterations,
		"MySQL: weight-0 fastest server does not empty the lottery, weighted server selected %d/%d",
		picked_far, kIterations);
	ok(counter == 0,
		"MySQL: latency filter is skipped when it would keep no weight (counter=%llu)", counter);

	// Case 2: both servers have weight, the filter still applies.
	near_srv->weight = 1;
	counter = 0;
	int picked_near = 0;
	MyHGM->wrlock();
	for (int i = 0; i < kIterations; i++) {
		if (hgc->get_random_MySrvC(nullptr, 0, -1, &session) == near_srv) {
			picked_near++;
		}
	}
	MyHGM->wrunlock();
	ok(picked_near == kIterations && counter == (unsigned long long)kIterations,
		"MySQL: latency filter still keeps only the faster weighted server (%d/%d, counter=%llu)",
		picked_near, kIterations, counter);

	mysql_thread___default_max_latency_ms = old_default_max_latency_ms;
	mysql_thread___session_track_variables = old_session_track_variables;
}

static void test_pgsql_latency_awareness() {
	const unsigned int hid = 9302;
	PgSQL_SrvC *near_srv = add_pgsql_server(hid, "lat-pgsql-near", 15306, 0);
	PgSQL_SrvC *far_srv = add_pgsql_server(hid, "lat-pgsql-far", 15307, 1);
	PgSQL_HGC *hgc = PgHGM->MyHGC_find(hid);
	near_srv->current_latency_us = 1000;
	far_srv->current_latency_us = 9000;

	PgSQL_Thread worker;
	if (!worker.init()) {
		BAIL_OUT("PgSQL_Thread::init() failed");
	}
	PgSQL_Session session;
	session.thread = &worker;
	worker.variables.min_num_servers_lantency_awareness = 2;

	const int old_default_max_latency_ms = pgsql_thread___default_max_latency_ms;
	pgsql_thread___default_max_latency_ms = 1000;

	unsigned long long &counter = worker.status_variables.stvar[st_var_ConnPool_get_conn_latency_awareness];

	counter = 0;
	int picked_far = 0;
	PgHGM->wrlock();
	for (int i = 0; i < kIterations; i++) {
		if (hgc->get_random_MySrvC(nullptr, 0, -1, &session) == far_srv) {
			picked_far++;
		}
	}
	PgHGM->wrunlock();
	ok(picked_far == kIterations,
		"PgSQL: weight-0 fastest server does not empty the lottery, weighted server selected %d/%d",
		picked_far, kIterations);
	ok(counter == 0,
		"PgSQL: latency filter is skipped when it would keep no weight (counter=%llu)", counter);

	near_srv->weight = 1;
	counter = 0;
	int picked_near = 0;
	PgHGM->wrlock();
	for (int i = 0; i < kIterations; i++) {
		if (hgc->get_random_MySrvC(nullptr, 0, -1, &session) == near_srv) {
			picked_near++;
		}
	}
	PgHGM->wrunlock();
	ok(picked_near == kIterations && counter == (unsigned long long)kIterations,
		"PgSQL: latency filter still keeps only the faster weighted server (%d/%d, counter=%llu)",
		picked_near, kIterations, counter);

	pgsql_thread___default_max_latency_ms = old_default_max_latency_ms;
}

int main() {
	plan(6);

	if (test_init_minimal() != 0) {
		BAIL_OUT("test_init_minimal() failed");
	}
	if (test_init_query_processor() != 0) {
		BAIL_OUT("test_init_query_processor() failed");
	}
	GloMyLogger = new MySQL_Logger();
	GloPgSQL_Logger = new PgSQL_Logger();
	if (test_init_hostgroups() != 0) {
		BAIL_OUT("test_init_hostgroups() failed");
	}

	test_mysql_latency_awareness();
	test_pgsql_latency_awareness();

	test_cleanup_hostgroups();
	delete GloPgSQL_Logger;
	GloPgSQL_Logger = nullptr;
	delete GloMyLogger;
	GloMyLogger = nullptr;
	test_cleanup_query_processor();
	test_cleanup_minimal();

	return exit_status();
}
