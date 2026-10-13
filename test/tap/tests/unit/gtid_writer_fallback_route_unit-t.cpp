/**
 * @file gtid_writer_fallback_route_unit-t.cpp
 * @brief An unusable tracked GTID routes the causal read to its source hostgroup
 *   while the destination is chosen, never by swapping the backend later (#6415).
 *
 * The writer fallback used to replace the session's backend inside
 * get_connection(), after the query had been attached to the reader backend's
 * data stream, so the writer received an empty query. The fallback is now a
 * routing decision taken before any backend is selected. These tests drive the
 * real MySQL_Session decision with real backends and tracked GTID values.
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

void test_backend_untouched(SessionFixture& f) {
	// The decision only selects the destination: the backend and the data
	// stream that will carry the query are chosen afterwards from it.
	f.reset(kUnusable);
	// With the reader backend active, as when a previous query used it.
	f.session->mybe = f.session->find_backend(kReader);
	MySQL_Backend* before = f.session->mybe;
	f.route();
	ok(before != nullptr && f.session->mybe == before && f.session->find_backend(kWriter) == f.writer,
		"the fallback does not swap the session's active backend");
}

} // namespace

int main() {
	plan(10);
	if (test_init_minimal() != 0 || test_init_query_processor() != 0 ||
		test_init_hostgroups() != 0) {
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
		test_backend_untouched(fixture);
	}
	test_cleanup_hostgroups();
	delete GloMyLogger;
	GloMyLogger = nullptr;
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
}
