/**
 * @file version_check_thread_owner_unit-t.cpp
 * @brief Ownership contract for the production version-check thread owner.
 *
 * The tests drive the real ProxySQL_VersionCheckThread header with real
 * pthread workers. On Linux, GNU --wrap hooks observe pthread_create and
 * pthread_join without substituting for the join: every successful join is
 * delegated to __real_pthread_join. The worker gate is a mutex/condition
 * variable, so the tests do not rely on sleeps or on observing absence.
 *
 * A worker-local TLS object records its destructor completion. That proves the
 * native thread-exit cleanup finished before drain() returned, not merely that
 * the worker callback body returned.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "ProxySQL_VersionCheckThread.h"

#if defined(__linux__)

#include <cerrno>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <pthread.h>

namespace {

constexpr int kMaxWorkers = 8;

struct WorkerState {
	std::mutex mutex;
	std::condition_variable cv;
	bool entered = false;
	bool release = false;
	bool callback_done = false;
	bool tls_done = false;
};

struct ThreadRecord {
	bool occupied = false;
	bool joined = false;
	int worker_index = -1;
	pthread_t thread {};
};

WorkerState g_workers[kMaxWorkers];
ThreadRecord g_records[kMaxWorkers];
int g_worker_args[kMaxWorkers];
std::mutex g_registry_mutex;

bool g_fail_next_create = false;
int g_create_error = 0;
bool g_fail_next_join = false;
int g_join_error = 0;
int g_create_attempts = 0;
int g_owner_create_successes = 0;
int g_join_attempts = 0;
int g_join_successes = 0;
int g_unknown_join_attempts = 0;
bool g_live_handle_overwrite = false;

int g_next_worker = 0;
thread_local int tl_worker_index = -1;

struct TlsCompletion {
	TlsCompletion() = default;
	TlsCompletion(const TlsCompletion &) = delete;
	TlsCompletion &operator=(const TlsCompletion &) = delete;
	void touch() {
		// Odr-use initializes this worker's thread-local destructor probe.
	}
	~TlsCompletion() {
		const int index = tl_worker_index;
		if (index < 0) {
			return;
		}
		WorkerState& worker = g_workers[index];
		std::lock_guard<std::mutex> lock(worker.mutex);
		worker.tls_done = true;
		worker.cv.notify_all();
	}
};

// Genuine native thread-local storage. The worker odr-uses this object so its
// dynamic initialization and destructor registration happen in that worker.
thread_local TlsCompletion tl_tls_completion;

void *test_worker(void *arg) {
	const int index = *static_cast<int *>(arg);
	tl_worker_index = index;
	tl_tls_completion.touch();
	WorkerState& worker = g_workers[index];

	{
		std::lock_guard<std::mutex> lock(worker.mutex);
		worker.entered = true;
		worker.cv.notify_all();
	}

	{
		std::unique_lock<std::mutex> lock(worker.mutex);
		worker.cv.wait(lock, [&worker] { return worker.release; });
	}

	{
		std::lock_guard<std::mutex> lock(worker.mutex);
		worker.callback_done = true;
		worker.cv.notify_all();
	}
	return nullptr;
}

void wait_entered(int index) {
	WorkerState& worker = g_workers[index];
	std::unique_lock<std::mutex> lock(worker.mutex);
	worker.cv.wait(lock, [&worker] { return worker.entered; });
}

void wait_tls_done(int index) {
	WorkerState& worker = g_workers[index];
	std::unique_lock<std::mutex> lock(worker.mutex);
	worker.cv.wait(lock, [&worker] { return worker.tls_done; });
}

void release_worker(int index) {
	WorkerState& worker = g_workers[index];
	{
		std::lock_guard<std::mutex> lock(worker.mutex);
		worker.release = true;
	}
	worker.cv.notify_all();
}

bool callback_done(int index) {
	WorkerState& worker = g_workers[index];
	std::lock_guard<std::mutex> lock(worker.mutex);
	return worker.callback_done;
}

bool tls_done(int index) {
	WorkerState& worker = g_workers[index];
	std::lock_guard<std::mutex> lock(worker.mutex);
	return worker.tls_done;
}

int join_attempts() {
	std::lock_guard<std::mutex> lock(g_registry_mutex);
	return g_join_attempts;
}

int owner_create_successes() {
	std::lock_guard<std::mutex> lock(g_registry_mutex);
	return g_owner_create_successes;
}

bool live_handle_overwrite() {
	std::lock_guard<std::mutex> lock(g_registry_mutex);
	return g_live_handle_overwrite;
}

} // namespace

extern "C" int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
extern "C" int __real_pthread_join(pthread_t, void **);

extern "C" int __wrap_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
	void *(*start_routine)(void *), void *arg) {
	int worker_index = -1;
	if (start_routine == &test_worker && arg != nullptr) {
		worker_index = *static_cast<int *>(arg);
	}

	{
		std::lock_guard<std::mutex> lock(g_registry_mutex);
		if (g_fail_next_create) {
			g_fail_next_create = false;
			g_create_attempts++;
			return g_create_error;
		}
		g_create_attempts++;
		if (worker_index >= 0) {
			for (int i = 0; i < kMaxWorkers; ++i) {
				if (g_records[i].occupied && !g_records[i].joined) {
					g_live_handle_overwrite = true;
				}
			}
		}
	}

	const int rc = __real_pthread_create(thread, attr, start_routine, arg);
	if (rc == 0 && worker_index >= 0) {
		std::lock_guard<std::mutex> lock(g_registry_mutex);
		for (int i = 0; i < kMaxWorkers; ++i) {
			if (!g_records[i].occupied) {
				g_records[i].occupied = true;
				g_records[i].joined = false;
				g_records[i].worker_index = worker_index;
				g_records[i].thread = *thread;
				g_owner_create_successes++;
				break;
			}
		}
	}
	return rc;
}

extern "C" int __wrap_pthread_join(pthread_t thread, void **retval) {
	int worker_index = -1;
	{
		std::lock_guard<std::mutex> lock(g_registry_mutex);
		for (int i = 0; i < kMaxWorkers; ++i) {
			if (g_records[i].occupied && !g_records[i].joined &&
				pthread_equal(g_records[i].thread, thread)) {
				worker_index = g_records[i].worker_index;
				break;
			}
		}
		if (worker_index < 0) {
			g_unknown_join_attempts++;
			return EINVAL;
		}
		g_join_attempts++;
		if (g_fail_next_join) {
			g_fail_next_join = false;
			return g_join_error;
		}
	}

	release_worker(worker_index);
	const int rc = __real_pthread_join(thread, retval);
	if (rc == 0) {
		std::lock_guard<std::mutex> lock(g_registry_mutex);
		for (int i = 0; i < kMaxWorkers; ++i) {
			if (g_records[i].occupied && !g_records[i].joined &&
				pthread_equal(g_records[i].thread, thread)) {
				g_records[i].joined = true;
				break;
			}
		}
		g_join_successes++;
	}
	return rc;
}

namespace {

bool cleanup_live_workers() {
	for (;;) {
		pthread_t thread {};
		int worker_index = -1;
		int found = -1;
		{
			std::lock_guard<std::mutex> lock(g_registry_mutex);
			for (int i = 0; i < kMaxWorkers; ++i) {
				if (g_records[i].occupied && !g_records[i].joined) {
					found = i;
					break;
				}
			}
			if (found < 0) {
				return true;
			}
			thread = g_records[found].thread;
			worker_index = g_records[found].worker_index;
		}

		release_worker(worker_index);
		wait_tls_done(worker_index);
		const int rc = __real_pthread_join(thread, nullptr);
		if (rc != 0) {
			diag("cleanup pthread_join failed: %s", strerror(rc));
			return false;
		}

		std::lock_guard<std::mutex> lock(g_registry_mutex);
		if (!g_records[found].occupied || g_records[found].joined) {
			diag("cleanup joined worker record was not live");
			return false;
		}
		g_records[found].joined = true;
	}
}

bool reset_fixture() {
	if (!cleanup_live_workers()) {
		return false;
	}
	std::lock_guard<std::mutex> lock(g_registry_mutex);
	g_fail_next_create = false;
	g_create_error = 0;
	g_fail_next_join = false;
	g_join_error = 0;
	g_create_attempts = 0;
	g_owner_create_successes = 0;
	g_join_attempts = 0;
	g_join_successes = 0;
	g_unknown_join_attempts = 0;
	g_live_handle_overwrite = false;
	for (int i = 0; i < kMaxWorkers; ++i) {
		g_records[i] = ThreadRecord{};
	}
	return true;
}

int take_worker_index() {
	return g_next_worker++;
}

void arm_create_failure(int error) {
	std::lock_guard<std::mutex> lock(g_registry_mutex);
	g_fail_next_create = true;
	g_create_error = error;
}

void arm_join_failure(int error) {
	std::lock_guard<std::mutex> lock(g_registry_mutex);
	g_fail_next_join = true;
	g_join_error = error;
}

// ---------------------------------------------------------------------------
// Worker completion, native TLS destructor completion, idempotent drain.
// ---------------------------------------------------------------------------
void test_worker_completion_and_idempotent_drain() {
	if (!reset_fixture()) {
		ok(false, "fixture reset requires every tracked live worker to be joined");
		return;
	}
	ProxySQL_VersionCheckThread owner;
	const int index = take_worker_index();

	const int start_rc = owner.start(test_worker, &g_worker_args[index]);
	ok(start_rc == 0, "owner starts one real pthread");
	if (start_rc != 0) {
		diag("start failed: %s", strerror(start_rc));
		return;
	}
	ok(owner.owned(), "owner records a successful create");

	wait_entered(index);
	const int joins_before = join_attempts();
	const int drain_rc = owner.drain();
	ok(drain_rc == 0, "drain joins the completed worker");
	ok(join_attempts() == joins_before + 1, "drain performs exactly one real join");
	ok(callback_done(index), "worker callback completed before drain returned");
	ok(tls_done(index), "native pthread TLS destructor completed before drain returned");
	ok(!owner.owned(), "successful join clears ownership");

	const int drain_again_rc = owner.drain();
	ok(drain_again_rc == 0, "idempotent drain returns success");
	ok(join_attempts() == joins_before + 1, "idempotent drain performs no second join");
}

// ---------------------------------------------------------------------------
// Replacement is refused while owned; relaunch joins the old worker first.
// ---------------------------------------------------------------------------
void test_replacement_and_relaunch() {
	if (!reset_fixture()) {
		ok(false, "fixture reset requires every tracked live worker to be joined");
		return;
	}
	ProxySQL_VersionCheckThread owner;
	const int first = take_worker_index();
	const int refused = take_worker_index();
	const int second = take_worker_index();

	const int start_rc = owner.start(test_worker, &g_worker_args[first]);
	ok(start_rc == 0, "first launch starts");
	if (start_rc != 0) {
		diag("start failed: %s", strerror(start_rc));
		return;
	}
	wait_entered(first);

	const int creates_before_refusal = owner_create_successes();
	const int refuse_rc = owner.start(test_worker, &g_worker_args[refused]);
	ok(refuse_rc != 0, "start refuses to overwrite a live owned handle");
	ok(owner_create_successes() == creates_before_refusal,
		"refused replacement does not create a second worker");
	ok(owner.owned(), "refused replacement retains the old owner");

	const int joins_before = join_attempts();
	const int first_drain_rc = owner.drain();
	ok(first_drain_rc == 0, "relaunch path drains the old worker");
	ok(join_attempts() == joins_before + 1, "old worker is joined before replacement");
	ok(callback_done(first) && tls_done(first),
		"old worker callback and TLS destructor completed before relaunch");
	ok(!owner.owned(), "old ownership cleared before replacement");

	const int relaunch_rc = owner.start(test_worker, &g_worker_args[second]);
	ok(relaunch_rc == 0, "relaunch creates the replacement worker");
	ok(!live_handle_overwrite(), "no live handle is overwritten by relaunch");
	if (relaunch_rc != 0) {
		diag("relaunch failed: %s", strerror(relaunch_rc));
		return;
	}
	wait_entered(second);

	const int second_drain_rc = owner.drain();
	ok(second_drain_rc == 0, "replacement worker drains");
	ok(callback_done(second) && tls_done(second),
		"replacement worker completes before its drain returns");
	ok(join_attempts() == joins_before + 2, "each lifecycle performs exactly one real join");
}

// ---------------------------------------------------------------------------
// Creation failure leaves no invalid owner and never joins a nonexistent handle.
// ---------------------------------------------------------------------------
void test_create_failure() {
	if (!reset_fixture()) {
		ok(false, "fixture reset requires every tracked live worker to be joined");
		return;
	}
	ProxySQL_VersionCheckThread owner;
	const int failed = take_worker_index();
	const int recovered = take_worker_index();

	arm_create_failure(EAGAIN);
	const int start_rc = owner.start(test_worker, &g_worker_args[failed]);
	ok(start_rc == EAGAIN, "create failure is reported to the caller");
	ok(!owner.owned(), "create failure leaves no owned handle");

	const int joins_before = join_attempts();
	const int failed_drain_rc = owner.drain();
	ok(failed_drain_rc == 0, "drain after create failure is a no-op");
	ok(join_attempts() == joins_before, "create failure does not trigger a join");

	const int recovery_rc = owner.start(test_worker, &g_worker_args[recovered]);
	ok(recovery_rc == 0, "a later create succeeds after an injected failure");
	if (recovery_rc != 0) {
		diag("recovery start failed: %s", strerror(recovery_rc));
		return;
	}
	wait_entered(recovered);
	const int recovery_drain_rc = owner.drain();
	ok(recovery_drain_rc == 0, "recovered worker drains");
	ok(callback_done(recovered) && tls_done(recovered),
		"recovered worker completes before drain returns");
}

// ---------------------------------------------------------------------------
// Failed join retains ownership, forbids replacement, and can be retried.
// ---------------------------------------------------------------------------
void test_failed_join() {
	if (!reset_fixture()) {
		ok(false, "fixture reset requires every tracked live worker to be joined");
		return;
	}
	ProxySQL_VersionCheckThread owner;
	const int live = take_worker_index();
	const int refused = take_worker_index();

	const int start_rc = owner.start(test_worker, &g_worker_args[live]);
	ok(start_rc == 0, "failed-join case starts one worker");
	if (start_rc != 0) {
		diag("start failed: %s", strerror(start_rc));
		return;
	}
	wait_entered(live);

	arm_join_failure(EDEADLK);
	const int joins_before = join_attempts();
	const int failed_join_rc = owner.drain();
	ok(failed_join_rc == EDEADLK, "failed join returns the pthread error");
	ok(owner.owned(), "failed join retains ownership");
	ok(join_attempts() == joins_before + 1, "failed join was a real join attempt");

	const int creates_before_refusal = owner_create_successes();
	const int refuse_rc = owner.start(test_worker, &g_worker_args[refused]);
	ok(refuse_rc != 0, "replacement is forbidden after a failed join");
	ok(owner_create_successes() == creates_before_refusal,
		"failed join plus refused replacement creates no new worker");

	release_worker(live);
	wait_tls_done(live);
	ok(tls_done(live), "worker independently completes native TLS cleanup");

	const int retry_rc = owner.drain();
	ok(retry_rc == 0, "a later drain can safely join the retained worker");
	ok(!owner.owned(), "successful retry clears ownership");
	ok(join_attempts() == joins_before + 2, "retry performs the second real join");
	ok(callback_done(live), "retained worker callback completed before the retry returned");
}

} // namespace

int main() {
	plan(NO_PLAN);
	test_init_minimal();
	for (int i = 0; i < kMaxWorkers; ++i) {
		g_worker_args[i] = i;
	}

	test_worker_completion_and_idempotent_drain();
	test_replacement_and_relaunch();
	test_create_failure();
	test_failed_join();

	if (!cleanup_live_workers()) {
		ok(false, "final fixture cleanup joins every tracked live worker");
	}
	test_cleanup_minimal();
	return exit_status();
}

#else

int main() {
	plan(1);
	test_init_minimal();
	skip(1, "GNU --wrap pthread ownership probes require Linux");
	test_cleanup_minimal();
	return exit_status();
}

#endif
