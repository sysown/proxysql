/**
 * @file pgsql_midbatch_reset_refused_unit-t.cpp
 * @brief Regression test for bug_tobe_fixed P2-36.
 *
 * A backend holding an unfinished extended-query batch must never be reset for reuse.
 * The reset sends a Sync (libpq) or DISCARD ALL (native), and either one tells the
 * backend the batch is over -- which COMMITS work the client was told had failed.
 * PgSQL_Session::create_new_session_and_reset_connection() is where every scrub-and-keep
 * route bottoms out, so that is where the refusal lives: mid-batch connections are
 * destroyed there instead, and closing the socket is what makes PostgreSQL roll back.
 *
 * Why a unit test and not a TAP test: nothing in the running proxy can hand that
 * function a mid-batch connection any more. Every route that abandons a frame destroys
 * the connection first, and a frame that finished has taken its ReadyForQuery. The
 * branch is unreachable from outside -- which is the point of the guard -- so the only
 * way to execute it is to call it directly.
 *
 * Only the native path is driven. is_pipeline_active() asks libpq for the pipeline
 * status of a real PGconn, which a fabricated connection cannot own, and
 * PQpipelineStatus(NULL) answers PQ_PIPELINE_OFF. The guard reads that one
 * protocol-agnostic accessor, and pgsql-native_extq_orphaned_sync-t exercises both
 * paths end to end.
 */
#include <poll.h>

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Session.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Backend.h"
#include "PgSQL_HostGroups_Manager.h"
#include "PgSQL_Thread.h"
#include "ProxySQL_Poll.h"

// A backend connection wired into just enough session for the release path to run:
// no live socket, no running thread, no real hostgroup.
struct Fixture {
	PgSQL_Thread* thread = nullptr;
	PgSQL_Session* sess = nullptr;
	PgSQL_SrvC* srv = nullptr;
	PgSQL_Data_Stream* ds = nullptr;
	PgSQL_Connection* conn = nullptr;
	ProxySQL_Poll<PgSQL_Data_Stream>* polls = nullptr;
};

static Fixture build_backend(bool mid_batch) {
	Fixture f;

	f.thread = new PgSQL_Thread();
	f.thread->curtime = 1000000;          // destroy path stamps last_time_used from this

	f.sess = new PgSQL_Session();
	f.sess->thread = f.thread;
	f.sess->connections_handler = true;   // keeps the session destructor away from PgHGM

	f.srv = new PgSQL_SrvC((char*)"127.0.0.1", 5432, 1, MYSQL_SERVER_STATUS_ONLINE, 0,
	                       100, 0, 0, 0, (char*)"midbatch unit fixture");

	f.conn = new PgSQL_Connection(false); // false = backend, not client
	f.conn->parent = f.srv;
	f.conn->native_mode = true;
	// The whole condition under test: the backend still owes a ReadyForQuery.
	f.conn->native_unsynced_work = mid_batch;
	// destroy_MyConn_from_pool() removes the connection from this list and asserts it is
	// there, so the fixture has to put it there.
	f.srv->ConnectionsUsed->add(f.conn);

	f.ds = new PgSQL_Data_Stream();
	f.ds->sess = f.sess;
	f.ds->myconn = f.conn;

	// unplug_backend() dereferences mypolls unconditionally.
	f.polls = new ProxySQL_Poll<PgSQL_Data_Stream>();
	f.polls->add(POLLIN, -1, f.ds, 0);

	PgSQL_Backend* be = new PgSQL_Backend();
	be->server_myds = f.ds;
	f.sess->mybe = be;

	return f;
}

int main(int, char**) {
	plan(3);

	if (test_init_hostgroups() != 0) {
		BAIL_OUT("could not create the hostgroups manager");
	}

	Fixture f = build_backend(true);

	ok(f.conn->is_pipeline_active() == true,
	   "precondition: a backend that still owes a ReadyForQuery reports as mid-batch -- "
	   "if this ever reads false the assertions below would pass without testing anything");

	const unsigned long destroyed_before = PgHGM->status.pgconnpoll_destroy;
	f.sess->create_new_session_and_reset_connection(f.ds);
	const unsigned long destroyed_after = PgHGM->status.pgconnpoll_destroy;

	ok(destroyed_after == destroyed_before + 1,
	   "a mid-batch backend handed to the scrub-and-keep path is DESTROYED instead -- "
	   "resetting it would send DISCARD ALL, ending the batch and committing work the "
	   "client was told had failed [pool destroy count %lu -> %lu]",
	   destroyed_before, destroyed_after);

	ok(f.ds->myconn == nullptr,
	   "and the data stream is left detached, the same state the reset path would have "
	   "left behind, so no caller can tell the two apart");

	// The connection was freed by the destroy path; everything else is left to process exit.
	// A fake session cannot be torn down safely here -- it never had a live thread.

	test_cleanup_hostgroups();
	return exit_status();
}
