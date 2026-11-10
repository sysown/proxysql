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
 *
 * The bounded-drain cases use fresh posix_spawn/self-exec children. Child-mode
 * dispatch precedes each child's TAP plan. In the deadline case, the callback
 * returns, its native thread_local destructor blocks, and main calls
 * production drain(). Progress bytes prove callback/destructor/drain/join
 * ordering; an atexit marker must remain absent because the fatal policy uses
 * a direct process exit.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "ProxySQL_VersionCheckThread.h"

#if defined(__linux__)

#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <mutex>
#include <pthread.h>
#include <spawn.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

extern char **environ;

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

enum ChildMode {
	kChildNone = 0,
	kChildDeadline = 1,
	kChildCreateFailure = 2,
};

ChildMode g_child_mode = kChildNone;

// The parent places the progress pipe at this descriptor in the child.
constexpr int kChildProgressFd = 9;

void child_progress(char marker) {
	if (g_child_mode == kChildNone) {
		return;
	}
	const ssize_t written = write(kChildProgressFd, &marker, 1);
	(void)written;
}

std::mutex g_child_gate_mutex;
std::condition_variable g_child_gate_cv;
bool g_child_tls_entered = false;

// A genuine native thread_local destructor blocks here forever. The only way
// the child can leave is the production drain() fatal deadline path.
void child_block_tls() {
	std::unique_lock<std::mutex> lock(g_child_gate_mutex);
	g_child_tls_entered = true;
	g_child_gate_cv.notify_all();
	for (;;) {
		g_child_gate_cv.wait(lock);
	}
}

void child_wait_tls_entered() {
	std::unique_lock<std::mutex> lock(g_child_gate_mutex);
	g_child_gate_cv.wait(lock, [] { return g_child_tls_entered; });
}

void child_atexit_marker() {
	child_progress('X');
}

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
		if (g_child_mode == kChildDeadline) {
			child_progress('T');
			child_block_tls();
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
	if (g_child_mode != kChildNone) {
		child_progress('C');
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
			if (g_child_mode == kChildCreateFailure) {
				child_progress('F');
			}
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
	if (g_child_mode != kChildNone) {
		child_progress('J');
	}
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
// Fresh-child bounded-drain cases. These deliberately run before the parent
// TAP plan when the executable is re-executed with a mode argument.
// ---------------------------------------------------------------------------
int run_deadline_child() {
	g_child_mode = kChildDeadline;
	std::atexit(child_atexit_marker);

	ProxySQL_VersionCheckThread owner;
	g_worker_args[0] = 0;
	if (owner.start(test_worker, &g_worker_args[0]) != 0) {
		return EXIT_FAILURE;
	}
	wait_entered(0);
	release_worker(0);
	child_wait_tls_entered();

	child_progress('D');
	(void)owner.drain();

	// The bounded production drain must exit the process at its deadline.
	child_progress('A');
	return EXIT_SUCCESS;
}

int run_create_failure_child() {
	g_child_mode = kChildCreateFailure;
	std::atexit(child_atexit_marker);

	ProxySQL_VersionCheckThread owner;
	g_worker_args[0] = 0;
	if (owner.start(test_worker, &g_worker_args[0]) != 0) {
		return EXIT_FAILURE;
	}
	wait_entered(0);
	child_progress('S');

	// Let the real checker finish so an unbounded plain join would return
	// promptly; then arm the very next create, which is the helper create.
	release_worker(0);
	wait_tls_done(0);
	arm_create_failure(EAGAIN);

	child_progress('D');
	(void)owner.drain();

	child_progress('A');
	return EXIT_SUCCESS;
}

struct ChildRun {
	bool spawned = false;
	bool guard_killed = false;
	bool reaped = false;
	bool exited_normally = false;
	int exit_code = -1;
	int term_signal = 0;
	double elapsed_seconds = 0.0;
	bool callback_done = false;
	bool tls_entered = false;
	bool drain_entered = false;
	bool native_join_reached = false;
	bool after_drain = false;
	bool atexit_ran = false;
	bool checker_started = false;
	bool create_failure_injected = false;
};

void record_child_marker(ChildRun& run, char marker) {
	switch (marker) {
		case 'C': run.callback_done = true; break;
		case 'T': run.tls_entered = true; break;
		case 'D': run.drain_entered = true; break;
		case 'J': run.native_join_reached = true; break;
		case 'A': run.after_drain = true; break;
		case 'X': run.atexit_ran = true; break;
		case 'S': run.checker_started = true; break;
		case 'F': run.create_failure_injected = true; break;
		default: break;
	}
}

void drain_child_progress(int fd, ChildRun& run) {
	char buffer[64];
	for (;;) {
		const ssize_t count = read(fd, buffer, sizeof(buffer));
		if (count > 0) {
			for (ssize_t i = 0; i < count; ++i) {
				record_child_marker(run, buffer[i]);
			}
			continue;
		}
		if (count < 0 && errno == EINTR) {
			continue;
		}
		break;
	}
}

ChildRun run_child_mode(const char *mode, double guard_seconds) {
	ChildRun run;
	int fds[2] = { -1, -1 };
	if (pipe(fds) != 0) {
		return run;
	}
	const int read_flags = fcntl(fds[0], F_GETFL, 0);
	if (read_flags < 0 || fcntl(fds[0], F_SETFL, read_flags | O_NONBLOCK) != 0) {
		close(fds[0]);
		close(fds[1]);
		return run;
	}

	posix_spawn_file_actions_t actions;
	if (posix_spawn_file_actions_init(&actions) != 0) {
		close(fds[0]);
		close(fds[1]);
		return run;
	}
	posix_spawn_file_actions_adddup2(&actions, fds[1], kChildProgressFd);
	if (fds[1] != kChildProgressFd) {
		posix_spawn_file_actions_addclose(&actions, fds[1]);
	}
	if (fds[0] != kChildProgressFd) {
		posix_spawn_file_actions_addclose(&actions, fds[0]);
	}

	char *child_argv[] = {
		const_cast<char *>("version_check_thread_owner_unit-t"),
		const_cast<char *>(mode),
		nullptr
	};
	pid_t pid = -1;
	const int spawn_rc = posix_spawn(&pid, "/proc/self/exe", &actions, nullptr,
		child_argv, environ);
	posix_spawn_file_actions_destroy(&actions);
	close(fds[1]);
	if (spawn_rc != 0) {
		diag("posix_spawn failed for %s: %s", mode, strerror(spawn_rc));
		close(fds[0]);
		return run;
	}
	run.spawned = true;

	const auto started = std::chrono::steady_clock::now();
	int status = 0;
	bool reaped = false;

	for (;;) {
		drain_child_progress(fds[0], run);

		const pid_t waited = waitpid(pid, &status, WNOHANG);
		if (waited == pid) {
			reaped = true;
			break;
		}
		if (waited < 0 && errno != EINTR) {
			break;
		}

		const double elapsed =
			std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
		if (elapsed >= guard_seconds) {
			run.guard_killed = true;
			kill(pid, SIGKILL);
			for (;;) {
				const pid_t killed = waitpid(pid, &status, 0);
				if (killed == pid || (killed < 0 && errno != EINTR)) {
					break;
				}
			}
			reaped = true;
			break;
		}

		struct timespec pause { 0, 2000000 };
		nanosleep(&pause, nullptr);
	}

	drain_child_progress(fds[0], run);
	close(fds[0]);

	run.reaped = reaped;
	run.elapsed_seconds =
		std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
	if (reaped && !run.guard_killed) {
		if (WIFEXITED(status)) {
			run.exited_normally = true;
			run.exit_code = WEXITSTATUS(status);
		} else if (WIFSIGNALED(status)) {
			run.term_signal = WTERMSIG(status);
		}
	} else if (reaped && WIFSIGNALED(status)) {
		run.term_signal = WTERMSIG(status);
	}
	return run;
}

void test_deadline_child() {
	const ChildRun run = run_child_mode("--deadline-child", 35.0);
	const bool natural =
		run.spawned && !run.guard_killed && run.reaped && run.exited_normally;

	ok(run.spawned, "deadline child is spawned with posix_spawn/self-exec");
	ok(natural, "deadline child terminates naturally without the 35-second guard kill");
	ok(natural && run.exit_code == EXIT_FAILURE,
		"deadline child exits directly with EXIT_FAILURE (code=%d signal=%d)",
		run.exit_code, run.term_signal);
	ok(run.elapsed_seconds >= 29.0 && run.elapsed_seconds < 35.0,
		"deadline child honors the fixed 30-second budget (elapsed %.3f s)",
		run.elapsed_seconds);
	ok(run.callback_done, "deadline child observed the checker callback completion");
	ok(run.tls_entered, "deadline child observed the blocked native TLS destructor entry");
	ok(run.drain_entered, "deadline child observed production drain entry");
	ok(run.native_join_reached, "deadline child reached the actual native checker join");
	ok(!run.after_drain, "deadline child never resumed after drain");
	ok(!run.atexit_ran, "deadline child never ran atexit/teardown handlers");
	diag("deadline child: elapsed=%.3f spawned=%d killed=%d reaped=%d exited=%d "
		"code=%d signal=%d C=%d T=%d D=%d J=%d A=%d X=%d",
		run.elapsed_seconds, run.spawned, run.guard_killed, run.reaped,
		run.exited_normally, run.exit_code, run.term_signal, run.callback_done,
		run.tls_entered, run.drain_entered, run.native_join_reached,
		run.after_drain, run.atexit_ran);
}

void test_helper_create_failure_child() {
	const ChildRun run = run_child_mode("--create-fail-child", 20.0);
	const bool natural =
		run.spawned && !run.guard_killed && run.reaped && run.exited_normally;

	ok(run.spawned, "helper-create-failure child is spawned with posix_spawn/self-exec");
	ok(natural, "helper-create-failure child terminates naturally without the guard kill");
	ok(natural && run.exit_code == EXIT_FAILURE,
		"helper-create-failure child exits directly with EXIT_FAILURE (code=%d signal=%d)",
		run.exit_code, run.term_signal);
	ok(run.elapsed_seconds < 10.0,
		"helper-create-failure child fails promptly (elapsed %.3f s)",
		run.elapsed_seconds);
	ok(run.checker_started,
		"helper-create-failure child started the real checker before injection");
	ok(run.drain_entered, "helper-create-failure child entered production drain");
	ok(run.create_failure_injected,
		"helper-create-failure child consumed the injected helper-create failure");
	ok(!run.native_join_reached,
		"helper-create-failure child performed no real checker join");
	ok(!run.after_drain, "helper-create-failure child never resumed after drain");
	ok(!run.atexit_ran, "helper-create-failure child never ran atexit/teardown handlers");
	diag("helper-create-failure child: elapsed=%.3f spawned=%d killed=%d reaped=%d "
		"exited=%d code=%d signal=%d S=%d D=%d F=%d J=%d A=%d X=%d",
		run.elapsed_seconds, run.spawned, run.guard_killed, run.reaped,
		run.exited_normally, run.exit_code, run.term_signal, run.checker_started,
		run.drain_entered, run.create_failure_injected, run.native_join_reached,
		run.after_drain, run.atexit_ran);
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

int main(int argc, char **argv) {
	if (argc > 1) {
		if (strcmp(argv[1], "--deadline-child") == 0) {
			return run_deadline_child();
		}
		if (strcmp(argv[1], "--create-fail-child") == 0) {
			return run_create_failure_child();
		}
	}

	plan(NO_PLAN);
	test_init_minimal();
	for (int i = 0; i < kMaxWorkers; ++i) {
		g_worker_args[i] = i;
	}

	test_worker_completion_and_idempotent_drain();
	test_replacement_and_relaunch();
	test_create_failure();
	test_failed_join();
	test_deadline_child();
	test_helper_create_failure_child();

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
