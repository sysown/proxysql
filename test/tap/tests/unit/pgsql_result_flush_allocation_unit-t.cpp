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
#include <fcntl.h>
#include <memory>
#include <sys/socket.h>
#include <arpa/inet.h>

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

#ifdef __linux__
// Observe frees from the real vendored libpq; do not replace its parser or
// allocator. A notice's errMsg points at pqGetErrorNotice3's local work buffer.
// Keep libpq internal header configuration local to this fixture; libusual
// and ProxySQL have their own definitions of these configuration macros.
#pragma push_macro("OPENSSL_API_COMPAT")
#ifdef OPENSSL_API_COMPAT
#undef OPENSSL_API_COMPAT
#endif
#pragma push_macro("PACKAGE_BUGREPORT")
#ifdef PACKAGE_BUGREPORT
#undef PACKAGE_BUGREPORT
#endif
#pragma push_macro("PACKAGE_NAME")
#ifdef PACKAGE_NAME
#undef PACKAGE_NAME
#endif
#pragma push_macro("PACKAGE_STRING")
#ifdef PACKAGE_STRING
#undef PACKAGE_STRING
#endif
#pragma push_macro("PACKAGE_TARNAME")
#ifdef PACKAGE_TARNAME
#undef PACKAGE_TARNAME
#endif
#pragma push_macro("PACKAGE_URL")
#ifdef PACKAGE_URL
#undef PACKAGE_URL
#endif
#pragma push_macro("PACKAGE_VERSION")
#ifdef PACKAGE_VERSION
#undef PACKAGE_VERSION
#endif
#pragma push_macro("restrict")
#ifdef restrict
#undef restrict
#endif
#pragma push_macro("likely")
#ifdef likely
#undef likely
#endif
#pragma push_macro("unlikely")
#ifdef unlikely
#undef unlikely
#endif
#pragma push_macro("Assert")
#ifdef Assert
#undef Assert
#endif
#pragma push_macro("PG_PROTOCOL_LATEST")
#ifdef PG_PROTOCOL_LATEST
#undef PG_PROTOCOL_LATEST
#endif
extern "C" {
#include "postgres_fe.h"
#include "libpq-int.h"
void __real_free(void*);
int __real_PQgetCopyData(PGconn*, char**, int);
}
#pragma pop_macro("PG_PROTOCOL_LATEST")
#pragma pop_macro("Assert")
#pragma pop_macro("unlikely")
#pragma pop_macro("likely")
#pragma pop_macro("restrict")
#pragma pop_macro("PACKAGE_VERSION")
#pragma pop_macro("PACKAGE_URL")
#pragma pop_macro("PACKAGE_TARNAME")
#pragma pop_macro("PACKAGE_STRING")
#pragma pop_macro("PACKAGE_NAME")
#pragma pop_macro("PACKAGE_BUGREPORT")
#pragma pop_macro("OPENSSL_API_COMPAT")

struct NoticeOwnership {
	const PGresult* result = nullptr;
	const char* work_buffer = nullptr;
	bool result_freed = false;
	bool work_buffer_freed = false;
};
static NoticeOwnership notices[4];
static unsigned int notice_count = 0;
static bool callback_escaped = false;
static char* copy_buffer = nullptr;
static unsigned int copy_buffers_freed = 0;

extern "C" void __wrap_free(void* ptr) {
	if (ptr) {
		for (unsigned int i = 0; i < notice_count; ++i) {
			if (ptr == notices[i].result) notices[i].result_freed = true;
			if (ptr == notices[i].work_buffer) notices[i].work_buffer_freed = true;
		}
		if (ptr == copy_buffer) {
			++copy_buffers_freed;
			copy_buffer = nullptr;
		}
	}
	__real_free(ptr);
}

extern "C" int __wrap_PQgetCopyData(PGconn* conn, char** out, int async) {
	const int len = __real_PQgetCopyData(conn, out, async);
	if (len > 0) copy_buffer = *out;
	return len;
}

struct NoticeCallbackTag {
	using type = void (*)(void*, const PGresult*);
	friend type member(NoticeCallbackTag);
};
struct NumFieldsTag {
	using type = unsigned int PgSQL_Query_Result::*;
	friend type member(NumFieldsTag);
};
template struct ResultMember<NumFieldsTag, &PgSQL_Query_Result::num_fields>;
struct CopyOutTag {
	using type = bool (PgSQL_Connection::*)(const PGresult*, uint64_t*);
	friend type member(CopyOutTag);
};
template struct ResultMember<NoticeCallbackTag, &PgSQL_Connection::notice_handler_cb>;
template struct ResultMember<CopyOutTag, &PgSQL_Connection::handle_copy_out>;

static void observed_notice(void* arg, const PGresult* result) {
	assert(notice_count < 4);
	notices[notice_count++] = {result, PQresultErrorMessage(result), false, false};
	try {
		member(NoticeCallbackTag{})(arg, result);
	} catch (...) {
		callback_escaped = true;
		throw;
	}
}

static std::string frame(char type, const char* body, size_t size) {
	std::string wire(1, type);
	const uint32_t length = htonl(size + 4);
	wire.append(reinterpret_cast<const char*>(&length), sizeof(length));
	wire.append(body, size);
	return wire;
}

static std::string notice_wire() {
	static const char body[] = "SNOTICE\0VNOTICE\0C00000\0Mallocation test\0\0";
	return frame('N', body, sizeof(body) - 1);
}

static void feed_libpq(PGconn* conn, const std::string& wire, PGAsyncStatusType state) {
	assert(wire.size() <= static_cast<size_t>(conn->inBufSize));
	memcpy(conn->inBuffer, wire.data(), wire.size());
	conn->inStart = conn->inCursor = 0;
	conn->inEnd = wire.size();
	conn->asyncStatus = state;
}

enum class LibpqFailure { CALLBACK, FETCH, RESET, COPY_ROW, COPY_NOTICE, STICKY, SUCCESS };

// Keep the worker globals/fixture isolated, while explicitly destroying the
// connection under test. A socketpair supplies a nonblocking libpq transport;
// all protocol messages are parsed by the real vendored library.
static int libpq_allocation_failure(LibpqFailure kind) {
	if (test_init_hostgroups() != 0) return 1;
	auto* thread = new PgSQL_Thread();
	auto* sess = new PgSQL_Session();
	sess->thread = thread;
	auto* ds = new PgSQL_Data_Stream();
	ds->sess = sess;
	auto* srv = new PgSQL_SrvC((char*)"127.0.0.1", 5432, 1, MYSQL_SERVER_STATUS_ONLINE,
		0, 100, 0, 0, 0, (char*)"libpq allocation unit fixture");
	PgSQL_Protocol proto;
	auto conn = std::unique_ptr<PgSQL_Connection>(new PgSQL_Connection(false));
	conn->parent = srv;
	conn->myds = ds;
	ds->myconn = conn.get();
	conn->native_mode = false;
	conn->new_result = false;
	// Invalid conninfo allocates libpq's object without connecting anywhere.
	conn->pgsql_conn = PQconnectStart("invalid_allocation_test_option=1");
	PGconn* pq = conn->pgsql_conn;
	if (!pq || !pq->inBuffer) return 2;
	int sockets[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) != 0) return 3;
	fcntl(sockets[0], F_SETFL, O_NONBLOCK);
	pq->sock = sockets[0];
	pq->status = CONNECTION_OK;
	pq->pversion = 196608;
	pq->nonblocking = true;
	PQsetNoticeReceiver(pq, observed_notice, conn.get());
	conn->query_result = new PgSQL_Query_Result();
	conn->query_result->init(&proto, ds, conn.get());
	conn->query_result->*member(NumFieldsTag{}) = 1;
	const std::string original_bytes(PGSQL_RESULTSET_BUFLEN, 'x');
	if (kind != LibpqFailure::SUCCESS) append(*conn->query_result, original_bytes);
	unsigned char* original = buffer(*conn->query_result);

	const bool copy = kind == LibpqFailure::COPY_ROW || kind == LibpqFailure::COPY_NOTICE;
	std::string wire;
	if (kind != LibpqFailure::COPY_ROW) wire = notice_wire() + notice_wire();
	if (copy) wire += frame('d', "copy row", 8);
	else wire += frame('C', "SELECT 0", 9) + frame('Z', "I", 1);
	feed_libpq(pq, wire, copy ? PGASYNC_COPY_OUT : PGASYNC_BUSY);
	conn->is_copy_out = copy;
	conn->fetch_result_start();
	fail_next_allocation = kind != LibpqFailure::SUCCESS;
	bool caught = false;
	uint64_t processed = 0;
	try {
		if (kind == LibpqFailure::CALLBACK || kind == LibpqFailure::STICKY ||
			kind == LibpqFailure::SUCCESS) {
			PQisBusy(pq);
		} else if (kind == LibpqFailure::RESET) {
			conn->reset_session_cont(POLLIN);
		} else if (copy) {
			(conn.get()->*member(CopyOutTag{}))(nullptr, &processed);
		} else {
			conn->fetch_result_cont(POLLIN);
		}
	} catch (const PgSQL_Query_Result::AllocationError&) {
		caught = true;
	}
	if (fail_next_allocation) return 4; // injection must reach production flush
	if (callback_escaped) return 5; // C library cleanup was bypassed
	if (kind == LibpqFailure::SUCCESS) {
		const std::string expected = notice_wire() + notice_wire();
		if (caught || !conn->healthy || notice_count != 2 ||
			!(conn->query_result->get_result_packet_type() & PGSQL_QUERY_RESULT_NOTICE) ||
			used(*conn->query_result) != expected.size() ||
			memcmp(buffer(*conn->query_result), expected.data(), expected.size())) return 6;
	} else {
		const bool direct = kind == LibpqFailure::CALLBACK || kind == LibpqFailure::STICKY;
		if (caught == direct) return 7; // callbacks return; C++ entrypoints throw
		if (kind != LibpqFailure::COPY_ROW && conn->healthy) return 8;
		if (buffer(*conn->query_result) != original || used(*conn->query_result) != original_bytes.size() ||
			memcmp(original, original_bytes.data(), original_bytes.size()) ||
			result_queue(*conn->query_result).len || processed) return 9;
	}
	if (kind != LibpqFailure::COPY_ROW) {
		if (notice_count != 2) return 10;
		for (unsigned int i = 0; i < notice_count; ++i) {
			if (!notices[i].result_freed || !notices[i].work_buffer_freed) return 11;
		}
	}
	if (copy && (copy_buffer || copy_buffers_freed != 1)) return 12;
	if (kind == LibpqFailure::CALLBACK || kind == LibpqFailure::STICKY) {
		// A pending result must not bypass a previous callback failure. Neither
		// async result cleanup nor connection reset may make the connection usable.
		if (kind == LibpqFailure::STICKY) {
			conn->async_free_result();
			for (int i = 0; i < PGSQL_NAME_LAST_LOW_WM; ++i) {
				conn->startup_parameters_hash[i] = 1;
				conn->startup_parameters[i] = strdup("fixture");
			}
			conn->reset();
			conn->query_result = new PgSQL_Query_Result();
			conn->query_result->init(&proto, ds, conn.get());
			static const char row[] = "\0\0";
			feed_libpq(pq, frame('D', row, 2), PGASYNC_BUSY);
		}
		bool surfaced = false;
		try { conn->fetch_result_cont(POLLIN); }
		catch (const PgSQL_Query_Result::AllocationError&) { surfaced = true; }
		if (!surfaced || conn->healthy || conn->is_connection_in_reusable_state()) return 13;
	}
	conn.reset();
	close(sockets[1]);
	return 0;
}

static void test_libpq_failure(LibpqFailure kind, const char* description) {
	fflush(nullptr);
	const pid_t child = fork();
	if (child == 0) {
		const struct rlimit no_core = {0, 0};
		setrlimit(RLIMIT_CORE, &no_core);
		_exit(libpq_allocation_failure(kind));
	}
	int status = 0;
	pid_t waited = -1;
	if (child > 0) {
		do { waited = waitpid(child, &status, 0); } while (waited == -1 && errno == EINTR);
	}
	const bool passed = child > 0 && waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
	ok(passed, "%s", description);
	if (!passed) diag("child status=%d (4: injection, 5: crossed C callback, 6: success, 7: boundary, "
		"8: health, 9: output ownership, 10: notices, 11: notice cleanup, 12: COPY cleanup, 13: sticky failure)", status);
}
#endif

int main() {
	plan(47);
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
#ifdef __linux__
	test_libpq_failure(LibpqFailure::CALLBACK, "notice failure returns through libpq cleanup before C++ rethrow");
	test_libpq_failure(LibpqFailure::FETCH, "libpq fetch surfaces notice failure before response serialization");
	test_libpq_failure(LibpqFailure::RESET, "libpq reset surfaces notice failure after C cleanup");
	test_libpq_failure(LibpqFailure::COPY_ROW, "COPY row flush failure releases libpq-owned row buffer");
	test_libpq_failure(LibpqFailure::COPY_NOTICE, "COPY notice failure cleans C temporaries and returned COPY buffer");
	test_libpq_failure(LibpqFailure::STICKY, "notice failure survives result cleanup and reset and prevents reuse");
	test_libpq_failure(LibpqFailure::SUCCESS, "successful libpq notices retain output and release temporary storage");
#else
	skip(7, "libpq ownership observations require GNU ld --wrap");
#endif
	test_cleanup_minimal();
	return exit_status();
}
