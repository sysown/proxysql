/**
 * Result-buffer flushes must retain their bytes and ownership when allocation
 * fails, including the replacement allocation for the large-buffer handoff.
 * Interception is local to the included production source, not a runtime hook.
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>
#include <limits>
#include <locale>
#include "proxysql.h"
#include "cpp.h"
#include "gen_utils.h"
#include "PgSQL_Authentication.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Protocol.h"
#include "PgSQL_PreparedStatement.h"
extern "C" {
#include "usual/time.h"
}
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <poll.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

static bool fail_next_allocation = false;
static unsigned int allocation_attempts = 0;

static void* result_malloc(size_t size) {
	++allocation_attempts;
	if (fail_next_allocation) {
		fail_next_allocation = false;
		return nullptr;
	}
	return malloc(size);
}

#define malloc result_malloc
#include "../../../../lib/PgSQL_Protocol.cpp"
#undef malloc

// Explicit instantiation permits inspection of private ownership state without
// altering the production API or redefining access modifiers in shared headers.
template<class Tag, typename Tag::type Member> struct ResultMember {
	friend typename Tag::type member(Tag) { return Member; }
};
struct BufferTag {
	using type = unsigned char* PgSQL_Query_Result::*;
	friend type member(BufferTag);
};
struct UsedTag {
	using type = unsigned int PgSQL_Query_Result::*;
	friend type member(UsedTag);
};
struct QueueTag {
	using type = PtrSizeArray PgSQL_Query_Result::*;
	friend type member(QueueTag);
};
template struct ResultMember<BufferTag, &PgSQL_Query_Result::buffer>;
template struct ResultMember<UsedTag, &PgSQL_Query_Result::buffer_used>;
template struct ResultMember<QueueTag, &PgSQL_Query_Result::PSarrayOUT>;

static unsigned char* buffer(PgSQL_Query_Result& result) { return result.*member(BufferTag{}); }
static unsigned int used(PgSQL_Query_Result& result) { return result.*member(UsedTag{}); }
static PtrSizeArray& result_queue(PgSQL_Query_Result& result) { return result.*member(QueueTag{}); }

static void append(PgSQL_Query_Result& result, const std::string& bytes) {
	result.add_native_data_rows(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size(), 1);
}

static void seed_result_queue(PgSQL_Query_Result& result) {
	result.clear();
	append(result, "queued");
	result.get_resultset(nullptr); // proto is null, so output stays owned by result
}

static void test_flush_failure(unsigned int size) {
	PgSQL_Query_Result result;
	seed_result_queue(result);
	PtrSize_t queued = *result_queue(result).index(0);
	const std::string bytes(size, 'x');
	append(result, bytes);
	unsigned char* original = buffer(result);
	const auto result_size = result.get_resultset_size();

	fail_next_allocation = true;
	bool caught = false;
	try {
		result.get_resultset(nullptr);
	} catch (const PgSQL_Query_Result::AllocationError&) {
		caught = true;
	}
	ok(caught && !fail_next_allocation, "%u bytes: allocation failure propagates", size);
	ok(buffer(result) == original && used(result) == size,
		"%u bytes: failed flush preserves buffer ownership and occupancy", size);
	ok(memcmp(buffer(result), bytes.data(), size) == 0,
		"%u bytes: failed flush preserves buffered bytes", size);
	ok(result_queue(result).len == 1 && result_queue(result).index(0)->ptr == queued.ptr &&
		result_queue(result).index(0)->size == queued.size && memcmp(queued.ptr, "queued", 6) == 0,
		"%u bytes: failed flush preserves previously queued output", size);
	ok(result.get_resultset_size() == result_size,
		"%u bytes: failed flush preserves result accounting", size);

	result.get_resultset(nullptr);
	ok(result_queue(result).len == 2 && used(result) == 0 &&
		result_queue(result).index(1)->size == size &&
		memcmp(result_queue(result).index(1)->ptr, bytes.data(), size) == 0,
		"%u bytes: retry flushes all bytes once in order", size);
	const bool small = size < PGSQL_RESULTSET_BUFLEN / 2;
	ok(small ? buffer(result) == original && result_queue(result).index(1)->ptr != original :
		buffer(result) != original && result_queue(result).index(1)->ptr == original,
		"%u bytes: successful flush %s", size, small ? "reuses accumulation buffer" : "transfers original buffer");
	append(result, "next");
	ok(used(result) == 4 && memcmp(buffer(result), "next", 4) == 0,
		"%u bytes: replacement or retained buffer accepts next result", size);
}

static void test_reserve_failure() {
	PgSQL_Query_Result result;
	seed_result_queue(result);
	const std::string first(PGSQL_RESULTSET_BUFLEN / 2, 'a');
	const std::string next(PGSQL_RESULTSET_BUFLEN / 2 + 1, 'b');
	append(result, first);
	unsigned char* original = buffer(result);
	const auto result_size = result.get_resultset_size();
	const auto rows = result.get_num_rows();
	fail_next_allocation = true;
	bool caught = false;
	try {
		append(result, next); // must flush before reserving space for this row
	} catch (const PgSQL_Query_Result::AllocationError&) {
		caught = true;
	}
	ok(caught && !fail_next_allocation, "reserve propagates failed flush instead of using standalone fallback");
	ok(buffer(result) == original && used(result) == first.size() &&
		memcmp(buffer(result), first.data(), first.size()) == 0,
		"failed reserve keeps the original bytes and occupancy");
	ok(result_queue(result).len == 1 && result.get_resultset_size() == result_size &&
		result.get_num_rows() == rows, "failed reserve neither queues nor counts the next row");
	append(result, next);
	ok(result_queue(result).len == 2 && result_queue(result).index(1)->ptr == original &&
		result_queue(result).index(1)->size == first.size() &&
		memcmp(original, first.data(), first.size()) == 0 &&
		used(result) == next.size() && memcmp(buffer(result), next.data(), next.size()) == 0,
		"retry preserves row ordering across the large-buffer handoff");
}

static void test_ready_failure() {
	PgSQL_Query_Result result;
	seed_result_queue(result);
	append(result, "row");
	unsigned char* original = buffer(result);
	fail_next_allocation = true;
	bool caught = false;
	try {
		result.add_native_backend_message('Z', reinterpret_cast<const unsigned char*>("I"), 1);
	} catch (const PgSQL_Query_Result::AllocationError&) {
		caught = true;
	}
	ok(caught && !fail_next_allocation, "ReadyForQuery flush propagates allocation failure");
	ok(buffer(result) == original && used(result) == 9 && result_queue(result).len == 1 &&
		memcmp(buffer(result), "rowZ\0\0\0\5I", 9) == 0,
		"ReadyForQuery failure keeps complete buffered response owned until teardown");
}

// Drive the actual session -> deferred readiness -> connection-handler path.
// Isolate the partial worker fixture just as the cache-allocation test does:
// it has no running worker or authentication globals for session destruction.
static int session_allocation_failure() {
	if (test_init_hostgroups() != 0) return 1;
	auto* thread = new PgSQL_Thread();
	thread->curtime = 1000000;
	auto* sess = new PgSQL_Session();
	sess->thread = thread;
	sess->connections_handler = true;
	sess->to_process = 1;
	sess->status = PROCESSING_QUERY;
	auto* srv = new PgSQL_SrvC((char*)"127.0.0.1", 5432, 1, MYSQL_SERVER_STATUS_ONLINE,
		0, 100, 0, 0, 0, (char*)"result allocation unit fixture");
	auto* conn = new PgSQL_Connection(false);
	conn->parent = srv;
	srv->ConnectionsUsed->add(conn);
	conn->native_mode = true;
	conn->handler_first_call = false;
	conn->async_state_machine = ASYNC_USE_RESULT_CONT;
	conn->native_fetch_paused = true; // drain the framer, without a real socket
	conn->query_result = new PgSQL_Query_Result();
	seed_result_queue(*conn->query_result);
	static const unsigned char command[] = "UPDATE 1";
	conn->query_result->add_native_backend_message('C', command, sizeof(command));
	unsigned char* original = buffer(*conn->query_result);
	// The second ReadyForQuery must still be unread when the first fails to flush.
	static const unsigned char reply[] = "Z\0\0\0\5IZ\0\0\0\5I";
	conn->native_framer.feed(reply, sizeof(reply) - 1);

	auto* ds = new PgSQL_Data_Stream();
	ds->sess = sess;
	ds->myconn = conn;
	conn->myds = ds;
	// Select deferred connection-state-machine dispatch, rather than raw socket
	// forwarding. There is deliberately no frontend or live socket in this fixture.
	ds->myds_type = MYDS_BACKEND_NOT_CONNECTED;
	ds->DSS = STATE_MARIADB_GENERIC;
	ds->pending_poll_revents = POLLIN;
	ds->pending_poll_events = POLLIN;
	auto* polls = new ProxySQL_Poll<PgSQL_Data_Stream>();
	polls->add(POLLIN, -1, ds, 0);
	auto* backend = new PgSQL_Backend();
	backend->server_myds = ds;
	sess->mybe = backend;
	sess->mybes->add(backend);

	fail_next_allocation = true;
	const int rc = sess->handler();
	if (fail_next_allocation || rc != -1) return 2;
	if (sess->healthy || conn->healthy) return 3;
	if (buffer(*conn->query_result) != original || used(*conn->query_result) != 20 ||
		result_queue(*conn->query_result).len != 1 || conn->native_framer.empty()) return 4;
	const unsigned long destroyed_before = PgHGM->status.pgconnpoll_destroy;
	// This is the same connection release used by session destruction. A failed
	// response must destroy the backend, with no pool return or reset session.
	ds->reset_connection();
	if (ds->myconn || PgHGM->status.pgconnpoll_destroy != destroyed_before + 1) return 5;
	return 0;
}

static void test_session_failure() {
	fflush(nullptr);
	const pid_t child = fork();
	if (child == 0) {
		const struct rlimit no_core = {0, 0};
		setrlimit(RLIMIT_CORE, &no_core);
		_exit(session_allocation_failure());
	}
	int status = 0;
	pid_t waited = -1;
	if (child > 0) {
		do {
			waited = waitpid(child, &status, 0);
		} while (waited == -1 && errno == EINTR);
	}
	const bool passed = child > 0 && waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
	ok(passed, "session catches flush failure and destroys backend holding unread response bytes");
	if (!passed) diag("child=%ld wait=%ld status=%d (2: containment, 3: health, 4: ownership/unread bytes, 5: disposal)",
		static_cast<long>(child), static_cast<long>(waited), status);
}

int main() {
	plan(40);
	if (test_init_minimal() != 0) return EXIT_FAILURE;
	{
		PgSQL_Query_Result result;
		result.clear();
		const unsigned int before = allocation_attempts;
		result.get_resultset(nullptr);
		ok(allocation_attempts == before && used(result) == 0 && result_queue(result).len == 0,
			"empty flush performs no allocation");
	}
	test_flush_failure(7);
	test_flush_failure(PGSQL_RESULTSET_BUFLEN / 2 - 1);
	test_flush_failure(PGSQL_RESULTSET_BUFLEN / 2);
	test_flush_failure(PGSQL_RESULTSET_BUFLEN);
	test_reserve_failure();
	test_ready_failure();
	test_session_failure();
	test_cleanup_minimal();
	return exit_status();
}
