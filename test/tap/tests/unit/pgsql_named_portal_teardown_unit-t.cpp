/**
 * @file pgsql_named_portal_teardown_unit-t.cpp
 * @brief Regression test for bug_tobe_fixed P2-05 / P3-35.
 *
 * named_portals describes portals bound on ONE specific backend connection.
 * Both bugs are the same root cause: nothing cleared the registry when that
 * connection was detached from the session -- P2-05 via a query-error teardown
 * that leaves the session to reconnect, P3-35 via the deliberate discard of a
 * connection left mid-batch after a locally-refused extended-query frame.
 * Either way the portals died with the connection; the registry must not keep
 * describing them.
 *
 * This test drives the fix's actual choke point directly:
 * PgSQL_Data_Stream::detach_connection(), the one place every connection-
 * release path (destroy, return-to-pool, reset-and-repool-for-a-new-session)
 * bottoms out in.
 *
 * It also pins the half that is easy to "simplify" into a use-after-free: the
 * discarded entries are PARKED, not destroyed, because the Bind bytes they own
 * are what CurrentQuery -- and the event logger reading it at RequestEnd --
 * still points at. Freeing them at detach is the crash d561b767c fixed.
 */
#include <cstring>
#include <memory>
#include <string>

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Session.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Backend.h"
// Needed so PgSQL_Portal_Entry's unique_ptr<const PgSQL_Bind_Message> member has a
// complete type to destroy -- PgSQL_Session.h only forward-declares PgSQL_Bind_Message.
#include "PgSQL_Extended_Query_Message.h"

// Friend of PgSQL_Session (see include/PgSQL_Session.h) -- direct access to the
// private portal registries so the test can arrange/observe portal state.
class PgSQL_Session_PortalTeardownTest {
public:
	static void add_portal(PgSQL_Session* s, const std::string& name, const PgSQL_Connection* conn,
		std::unique_ptr<const PgSQL_Bind_Message> msg = nullptr) {
		PgSQL_Portal_Entry entry;
		entry.bound_conn = conn;
		entry.bind_msg = std::move(msg);
		s->named_portals[name] = std::move(entry);
	}
	static size_t portal_count(PgSQL_Session* s) {
		return s->named_portals.size();
	}
	static size_t parked_count(PgSQL_Session* s) {
		return s->detached_portals.size();
	}
	// The registry KEY itself, which is what an in-flight Execute/Describe points
	// stmt_client_portal_name at.
	static const char* portal_key_ptr(PgSQL_Session* s, const std::string& name) {
		auto it = s->named_portals.find(name);
		return it == s->named_portals.end() ? nullptr : it->first.c_str();
	}
};

// Minimal session with a wired-up sess->mybe->server_myds->myconn chain --
// enough for detach_connection() to run without a live backend or PgHGM.
static PgSQL_Session* create_test_session() {
	PgSQL_Session* sess = new PgSQL_Session();
	sess->connections_handler = true; // avoid PgHGM deref in the destructor

	PgSQL_Backend* be = new PgSQL_Backend();
	PgSQL_Data_Stream* server_ds = new PgSQL_Data_Stream();
	PgSQL_Connection* server_conn = new PgSQL_Connection(false);
	server_ds->myconn = server_conn;
	server_ds->sess = sess;
	be->server_myds = server_ds;
	sess->mybe = be;

	return sess;
}

static void destroy_test_session(PgSQL_Session* sess) {
	if (sess->mybe) {
		PgSQL_Backend* be = sess->mybe;
		if (be->server_myds) {
			PgSQL_Data_Stream* sds = be->server_myds;
			if (sds->myconn) {
				delete sds->myconn;
				sds->myconn = nullptr;
			}
			be->server_myds = nullptr;
			delete sds;
		}
		sess->mybe = nullptr;
		delete be;
	}
	delete sess;
}

// A real Bind message, so the entry owns raw packet bytes exactly like it does in
// production: data().stmt_name points INTO them, which is what the event logger reads.
static std::unique_ptr<const PgSQL_Bind_Message> make_bind_msg(const char* portal, const char* stmt) {
	const size_t plen = strlen(portal) + 1;
	const size_t slen = strlen(stmt) + 1;
	const uint32_t body = 4 + plen + slen + 6;  // length field + both names + three int16 counts
	const uint32_t total = 1 + body;
	unsigned char* buf = (unsigned char*)malloc(total);
	size_t o = 0;
	buf[o++] = 'B';
	buf[o++] = (body >> 24) & 0xff;
	buf[o++] = (body >> 16) & 0xff;
	buf[o++] = (body >> 8) & 0xff;
	buf[o++] = body & 0xff;
	memcpy(buf + o, portal, plen); o += plen;
	memcpy(buf + o, stmt, slen); o += slen;
	memset(buf + o, 0, 6);  // no param formats, no params, no result formats

	PtrSize_t pkt;
	pkt.ptr = buf;
	pkt.size = total;
	PgSQL_Bind_Message* msg = new PgSQL_Bind_Message();
	if (msg->parse(pkt) == false) {  // on success the message owns buf
		delete msg;
		free(buf);
		return nullptr;
	}
	return std::unique_ptr<const PgSQL_Bind_Message>(msg);
}

// P2-05 / P3-35: whatever path severs the connection a portal was bound on, the
// portal must not survive the severing.
static void test_detach_owning_backend_clears_portals() {
	PgSQL_Session* sess = create_test_session();
	PgSQL_Connection* conn = sess->mybe->server_myds->myconn;
	PgSQL_Session_PortalTeardownTest::add_portal(sess, "p1", conn);
	ok(PgSQL_Session_PortalTeardownTest::portal_count(sess) == 1, "setup: named portal registered");

	sess->mybe->server_myds->detach_connection();

	ok(PgSQL_Session_PortalTeardownTest::portal_count(sess) == 0,
		"detaching the connection that held the portal clears it from named_portals");

	destroy_test_session(sess);
}

// Scoping check: portals are matched by the connection they were bound on, so a
// different connection going away must not wipe them.
static void test_detach_other_connection_keeps_portals() {
	PgSQL_Session* sess = create_test_session();
	PgSQL_Session_PortalTeardownTest::add_portal(sess, "p1", sess->mybe->server_myds->myconn);

	PgSQL_Data_Stream* other_ds = new PgSQL_Data_Stream();
	PgSQL_Connection* other_conn = new PgSQL_Connection(false);
	other_ds->myconn = other_conn;
	other_ds->sess = sess;

	other_ds->detach_connection();

	ok(PgSQL_Session_PortalTeardownTest::portal_count(sess) == 1,
		"detaching a different connection leaves that portal registered");
	ok(PgSQL_Session_PortalTeardownTest::parked_count(sess) == 0,
		"detaching a different connection parks nothing");

	delete other_conn;
	delete other_ds;
	destroy_test_session(sess);
}

// The entry must outlive the detach: CurrentQuery still points into the Bind bytes it
// owns, and the event logger reads them at RequestEnd, which on the teardown paths runs
// after the connection is gone. Under ASAN the strcmp below is the use-after-free canary;
// in any build, freeing at detach makes the parked count wrong.
static void test_detached_entry_is_parked_not_freed() {
	PgSQL_Session* sess = create_test_session();
	PgSQL_Connection* conn = sess->mybe->server_myds->myconn;

	std::unique_ptr<const PgSQL_Bind_Message> msg = make_bind_msg("p1", "stmt1");
	if (msg == nullptr) {
		BAIL_OUT("could not build a Bind message");
		return;
	}
	const char* stmt_name_in_packet = msg->data().stmt_name;
	PgSQL_Session_PortalTeardownTest::add_portal(sess, "p1", conn, std::move(msg));
	// what the session does for a named-portal Execute/Describe: the statement name points
	// into the registry entry's Bind packet, and the portal name at the registry key.
	sess->CurrentQuery.extended_query_info.stmt_client_name = stmt_name_in_packet;
	sess->CurrentQuery.extended_query_info.stmt_client_portal_name =
		PgSQL_Session_PortalTeardownTest::portal_key_ptr(sess, "p1");

	sess->mybe->server_myds->detach_connection();

	ok(PgSQL_Session_PortalTeardownTest::portal_count(sess) == 0 &&
		PgSQL_Session_PortalTeardownTest::parked_count(sess) == 1,
		"the discarded entry is parked, not destroyed");
	ok(strcmp(sess->CurrentQuery.extended_query_info.stmt_client_name, "stmt1") == 0,
		"the statement name the event logger reads is still valid after the detach");
	ok(strcmp(sess->CurrentQuery.extended_query_info.stmt_client_portal_name, "p1") == 0,
		"the portal name, which points at the registry key, is still valid after the detach");

	sess->CurrentQuery.extended_query_info.stmt_client_name = nullptr;
	sess->CurrentQuery.extended_query_info.stmt_client_portal_name = nullptr;
	destroy_test_session(sess);
}

int main(int, char**) {
	plan(7);
	test_detach_owning_backend_clears_portals();
	test_detach_other_connection_keeps_portals();
	test_detached_entry_is_parked_not_freed();
	return exit_status();
}
