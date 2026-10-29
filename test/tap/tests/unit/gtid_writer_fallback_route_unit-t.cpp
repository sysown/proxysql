/**
 * @file gtid_writer_fallback_route_unit-t.cpp
 * @brief An unusable tracked GTID routes the causal read to its source hostgroup
 *   while the destination is chosen, never by swapping the backend later (#6415).
 *
 * The writer fallback used to replace the session's backend inside
 * get_connection(), after the query had been attached to the reader backend's
 * data stream, so the writer received an empty query. The fallback is now a
 * routing decision taken before any backend is selected. These tests drive the
 * real MySQL_Session decision with real backends and tracked GTID values, then
 * run the real get_connection() step on the backend the caller selects from
 * that decision, and check that it neither swaps the backend nor applies the
 * wrong pool predicate.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#define private public
#include "cpp.h"
#undef private
#include "MySQL_Data_Stream.h"
#include "MySQL_Query_Processor.h"
#include "MySQL_Logger.hpp"
#include "proxysql_gtid.h"

#include <cstring>
#include <memory>

extern MySQL_Threads_Handler* GloMTH;
extern MySQL_Logger* GloMyLogger;

namespace {

constexpr int kWriter = 6415;
constexpr int kReader = 6416;
// A multi-UUID set: the pool filter accepts one (uuid, trxid) pair, so it can
// never be used as a routing predicate.
const char kUnusable[] =
	"aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:5,bbbbbbbb-0000-1111-2222-bbbbbbbbbbbb:7";
// A single-UUID set routes on its highest transaction id.
const char kUsable[] = "aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:582-584";

class SessionFixture {
public:
	explicit SessionFixture(MySQL_Thread& worker) : session(new MySQL_Session()) {
		session->thread = &worker;
		session->connections_handler = true;
		auto* stream = new MySQL_Data_Stream();
		stream->init(MYDS_FRONTEND, session.get(), -1);
		auto* frontend = new MySQL_Connection();
		stream->attach_connection(frontend);
		// get_connection() resolves the backend auth policy from the client
		// user; a user without a backend row is plain PASSWORD auth.
		frontend->userinfo->set((char*)"gtid_user", (char*)"", (char*)"test", nullptr);
		stream->myprot.init(&stream, frontend->userinfo, session.get());
		session->client_myds = stream;
		writer = session->find_or_create_backend(kWriter);
		session->find_or_create_backend(kReader);
	}

	/** @brief Restore a fresh causal read routed to the reader by its rule. */
	void reset(const char* tracked) {
		MySQL_Session& s = *session;
		s.qpo->min_gtid = nullptr;
		s.qpo->gtid_from_hostgroup = kWriter;
		s.qpo->create_new_conn = false;
		s.session_fast_forward = SESSION_FORWARD_TYPE_NONE;
		s.transaction_persistent_hostgroup = -1;
		s.locked_on_hostgroup = -1;
		s.current_hostgroup = kReader;
		s.qpo->max_lag_ms = -1;
		std::strncpy(writer->gtid_uuid, tracked, sizeof(writer->gtid_uuid) - 1);
		writer->gtid_uuid[sizeof(writer->gtid_uuid) - 1] = '\0';
	}

	bool route() { return session->route_unusable_tracked_gtid_to_writer(); }
	int hostgroup() const { return session->current_hostgroup; }

	std::unique_ptr<MySQL_Session> session;
	MySQL_Backend* writer = nullptr;
};

void test_routing(SessionFixture& f) {
	f.reset(kUnusable);
	ok(f.route() && f.hostgroup() == kWriter,
		"an unusable tracked GTID routes the read to the GTID source hostgroup");

	f.reset(kUsable);
	ok(!f.route() && f.hostgroup() == kReader,
		"a usable tracked GTID set keeps the read on the reader, constrained in get_connection()");

	f.reset("");
	ok(!f.route() && f.hostgroup() == kReader, "no tracked GTID: no constraint and no rerouting");

	// A value too long to track is stored as SESSION_GTID_UNTRACKABLE (#6465):
	// it must take the same fail-closed route as any unusable value.
	f.reset(SESSION_GTID_UNTRACKABLE);
	ok(f.route() && f.hostgroup() == kWriter,
		"an untrackable tracked GTID routes the read to the GTID source hostgroup");

	f.reset(kUnusable);
	f.session->qpo->gtid_from_hostgroup = -1;
	ok(!f.route() && f.hostgroup() == kReader, "a rule without gtid_from_hostgroup is not rerouted");

	f.reset(kUnusable);
	char min_gtid[] = "aaaaaaaa-0000-1111-2222-aaaaaaaaaaaa:5";
	f.session->qpo->min_gtid = min_gtid;
	ok(!f.route() && f.hostgroup() == kReader, "a min_gtid annotation takes precedence over gtid_from_hostgroup");
	f.session->qpo->min_gtid = nullptr;
}

void test_fixed_hostgroups(SessionFixture& f) {
	f.reset(kUnusable);
	f.session->transaction_persistent_hostgroup = kReader;
	ok(!f.route() && f.hostgroup() == kReader,
		"a transaction-persistent hostgroup is never changed by the fallback");

	f.reset(kUnusable);
	f.session->locked_on_hostgroup = kReader;
	ok(!f.route() && f.hostgroup() == kReader, "a hostgroup locked by SET is never changed by the fallback");

	f.reset(kUnusable);
	f.session->session_fast_forward = SESSION_FORWARD_TYPE_PERMANENT;
	ok(!f.route() && f.hostgroup() == kReader, "fast-forward sessions apply no GTID constraint, so no rerouting");

	f.reset(kUnusable);
	f.session->qpo->create_new_conn = true;
	ok(!f.route() && f.hostgroup() == kReader, "create_new_conn applies no GTID constraint, so no rerouting");
}

/**
 * @brief Runs the steps that follow the routing decision for a COM_QUERY:
 *   the caller selects 'mybe' from current_hostgroup and attaches the query
 *   to that backend's data stream (represented here by the backend pointer
 *   itself), then get_connection() checks a connection out of the pool (none
 *   exists here, so the session is left waiting).
 *
 * @param poison_gtid Value preloaded into last_pool_gtid (PROXYSQL31).
 * @return The backend the query was attached to.
 */
MySQL_Backend* select_and_get_connection(SessionFixture& f, bool poison_gtid) {
	MySQL_Session& s = *f.session;
	s.mybe = s.find_or_create_backend(s.current_hostgroup);
	MySQL_Backend* attached = s.mybe;
#ifdef PROXYSQL31
	// Poison the recorded pool request with the opposite of the expected
	// value, so each check can only pass on what this call records.
	s.last_pool_gtid = poison_gtid;
	s.last_pool_max_lag_ms = 12345;
#endif // PROXYSQL31
	s.handler___client_DSS_QUERY_SENT___server_DSS_NOT_INITIALIZED__get_connection();
#ifdef PROXYSQL31
	s.thread->leave_waiter(&s, false);
#endif // PROXYSQL31
	return attached;
}

void test_get_connection(SessionFixture& f) {
	// A regression that switches backends inside get_connection() (the
	// original fallback did 'mybe = _gtid_from_backend') leaves the query on
	// the data stream of the backend it was attached to while the connection
	// is requested for another one.

	// Rerouted: the query is attached to the writer backend and stays there.
	f.reset(kUnusable);
	f.session->qpo->max_lag_ms = 500;
	f.route();
	MySQL_Backend* attached = select_and_get_connection(f, true);
	ok(attached == f.writer && f.session->mybe == attached &&
		f.session->mybe->hostgroup_id == kWriter && f.session->current_hostgroup == kWriter,
		"rerouted: get_connection() keeps the writer backend the query is attached to");
#ifdef PROXYSQL31
	ok(!f.session->last_pool_gtid && f.session->last_pool_max_lag_ms == -1,
		"rerouted: the writer is read without a GTID predicate and without the lag filter");
#else
	ok(true, "rerouted: pool predicate not observable without PROXYSQL31 (skipped)");
#endif // PROXYSQL31

	// Not rerouted (hostgroup locked on the reader): the query stays on the
	// reader backend and waits on an unsatisfiable predicate.
	f.reset(kUnusable);
	f.session->locked_on_hostgroup = kReader;
	f.route();
	MySQL_Backend* reader = f.session->find_backend(kReader);
	attached = select_and_get_connection(f, false);
	ok(attached == reader && f.session->mybe == reader && f.session->mybe->hostgroup_id == kReader,
		"locked: get_connection() does not swap the reader backend for the GTID source");
#ifdef PROXYSQL31
	ok(f.session->last_pool_gtid, "locked: the reader is asked for an unsatisfiable GTID predicate");
#else
	ok(true, "locked: pool predicate not observable without PROXYSQL31 (skipped)");
#endif // PROXYSQL31

	// Usable value: the reader backend, constrained on the highest trxid.
	f.reset(kUsable);
	f.route();
	attached = select_and_get_connection(f, false);
	ok(attached == reader && f.session->mybe == reader,
		"usable value: get_connection() keeps the reader backend");
#ifdef PROXYSQL31
	ok(f.session->last_pool_gtid, "usable value: the reader is asked for the GTID predicate");
#else
	ok(true, "usable value: pool predicate not observable without PROXYSQL31 (skipped)");
#endif // PROXYSQL31
}

} // namespace

int main() {
	plan(16);
	if (test_init_minimal() != 0 || test_init_auth() != 0 ||
		test_init_query_processor() != 0 || test_init_hostgroups() != 0) {
		BAIL_OUT("failed to initialize unit-test globals");
	}
	GloMyLogger = new MySQL_Logger();
	GloMTH->num_threads = 1;
#ifdef PROXYSQL40
	GloMTH->set_variable("aws_locality_awareness", "false");
#endif
	{
		MySQL_Thread worker;
		if (!worker.init()) BAIL_OUT("MySQL_Thread::init() failed");
		SessionFixture fixture(worker);
		test_routing(fixture);
		test_fixed_hostgroups(fixture);
		test_get_connection(fixture);
	}
	test_cleanup_hostgroups();
	delete GloMyLogger;
	GloMyLogger = nullptr;
	test_cleanup_query_processor();
	test_cleanup_auth();
	test_cleanup_minimal();
	return exit_status();
}
