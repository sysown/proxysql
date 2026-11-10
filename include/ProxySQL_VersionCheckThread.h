#ifndef __PROXYSQL_VERSIONCHECKTHREAD_H
#define __PROXYSQL_VERSIONCHECKTHREAD_H

#include <errno.h>
#include <pthread.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <new>

/**
 * @brief Main-thread-owned handle for the single version-check worker.
 *
 * The caller must explicitly start and drain this owner. There is deliberately
 * no destructor or atexit handler that joins: a static destructor could run
 * after the modules and OpenSSL state the worker uses have been torn down.
 *
 * The owner holds at most one joinable thread. start() refuses to replace a
 * live owner; the caller must successfully drain() first. drain() clears the
 * owner only after the worker's native join succeeds, so a failed join retains
 * ownership and forbids replacement.
 *
 * drain() waits for one fixed 30-second steady-clock budget. The checker stays
 * joinable and a detached pure joiner performs the actual pthread_join, so a
 * blocked native thread-exit destructor cannot keep the owner alive forever.
 * The joiner only joins, stores the result, releases its state reference, and
 * publishes completion as its last state access. It never touches the owner,
 * modules, Curl/OpenSSL, logging, or application thread-local objects.
 *
 * Expiry of the budget and failures to set up the joiner terminate directly
 * with std::_Exit(EXIT_FAILURE). That is a deliberate availability policy: no
 * logging, stdio, abort handler, unwinding, or userland teardown. A native
 * join error is still returned to the caller with ownership retained.
 */
class ProxySQL_VersionCheckThread {
public:
	ProxySQL_VersionCheckThread() = default;

	ProxySQL_VersionCheckThread(const ProxySQL_VersionCheckThread&) = delete;
	ProxySQL_VersionCheckThread& operator=(const ProxySQL_VersionCheckThread&) = delete;

	/**
	 * @brief Start one worker if no joinable worker is owned.
	 *
	 * @param worker Thread entry point.
	 * @param arg Opaque worker argument.
	 * @return 0 on success, EDEADLK when a worker is already owned, or the
	 *         pthread_create error.
	 */
	int start(void *(*worker)(void *), void *arg) {
		if (owned_) {
			return EDEADLK;
		}
		int rc = pthread_create(&thread_, nullptr, worker, arg);
		if (rc == 0) {
			owned_ = true;
		}
		return rc;
	}

	/**
	 * @brief Join the owned worker, if any, within one fixed drain budget.
	 *
	 * @return 0 when there is nothing to join or the join succeeded, or the
	 *         actual pthread_join error. On failure ownership is retained.
	 */
	int drain() {
		if (!owned_) {
			return 0;
		}

		// The one absolute deadline starts before any allocation or helper
		// setup. Later wakeups cannot reset or extend it.
		const auto deadline =
			std::chrono::steady_clock::now() + std::chrono::seconds(30);

		int previous_cancel_state = 0;
		if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
			&previous_cancel_state) != 0) {
			std::_Exit(EXIT_FAILURE);
		}

		JoinState *state = new (std::nothrow) JoinState();
		if (state == nullptr) {
			std::_Exit(EXIT_FAILURE);
		}
		state->checker = thread_;
		state->refs.store(2, std::memory_order_relaxed);
		state->done.store(false, std::memory_order_relaxed);
		state->result = 0;

		pthread_attr_t attr;
		if (pthread_attr_init(&attr) != 0) {
			std::_Exit(EXIT_FAILURE);
		}
		if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0) {
			std::_Exit(EXIT_FAILURE);
		}

		pthread_t joiner;
		if (pthread_create(&joiner, &attr, &ProxySQL_VersionCheckThread::joiner_entry,
			state) != 0) {
			std::_Exit(EXIT_FAILURE);
		}
		// A post-create attribute cleanup failure must not become a retryable
		// owner error while the detached joiner may already consume the
		// checker. The narrow fatal policy applies instead.
		if (pthread_attr_destroy(&attr) != 0) {
			std::_Exit(EXIT_FAILURE);
		}

		for (;;) {
			if (state->done.load(std::memory_order_acquire)) {
				break;
			}
			if (std::chrono::steady_clock::now() >= deadline) {
				std::_Exit(EXIT_FAILURE);
			}
			struct timespec pause = { 0, 2000000 };
			nanosleep(&pause, nullptr);
		}

		// A completion observed at or after the deadline is still late.
		if (std::chrono::steady_clock::now() >= deadline) {
			std::_Exit(EXIT_FAILURE);
		}

		const int result = state->result;
		if (state->refs.fetch_sub(1, std::memory_order_acq_rel) == 1) {
			delete state;
		}
		if (result == 0) {
			owned_ = false;
		}

		// Restore the caller only after result, state, and ownership settled.
		if (pthread_setcancelstate(previous_cancel_state, nullptr) != 0) {
			std::_Exit(EXIT_FAILURE);
		}
		return result;
	}

	/** @brief Whether this owner still holds a joinable worker. */
	bool owned() const {
		return owned_;
	}

private:
	struct JoinState {
		pthread_t checker {};
		std::atomic<unsigned> refs { 2 };
		std::atomic<bool> done { false };
		int result = 0;
	};

	static void *joiner_entry(void *arg) {
		JoinState *state = static_cast<JoinState *>(arg);

		int previous_cancel_state = 0;
		if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,
			&previous_cancel_state) != 0) {
			std::_Exit(EXIT_FAILURE);
		}

		const int rc = pthread_join(state->checker, nullptr);
		state->result = rc;
		state->refs.fetch_sub(1, std::memory_order_acq_rel);
		// Last access to the borrowed state. The main reference keeps it alive
		// until the acquired done below.
		state->done.store(true, std::memory_order_release);
		return nullptr;
	}

	pthread_t thread_ {};
	bool owned_ = false;
};

#endif /* __PROXYSQL_VERSIONCHECKTHREAD_H */
