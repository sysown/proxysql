#ifndef __PROXYSQL_VERSIONCHECKTHREAD_H
#define __PROXYSQL_VERSIONCHECKTHREAD_H

#include <errno.h>
#include <pthread.h>

/**
 * @brief Main-thread-owned handle for the single version-check worker.
 *
 * The caller must explicitly start and drain this owner. There is deliberately
 * no destructor or atexit handler that joins: a static destructor could run
 * after the modules and OpenSSL state the worker uses have been torn down.
 *
 * The owner holds at most one joinable thread. start() refuses to replace a
 * live owner; the caller must successfully drain() first. drain() clears the
 * owner only after pthread_join succeeds, so a failed join retains ownership
 * and forbids replacement.
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
	 * @brief Join the owned worker, if any.
	 *
	 * @return 0 when there is nothing to join or the join succeeded, or the
	 *         pthread_join error. On failure ownership is retained.
	 */
	int drain() {
		if (!owned_) {
			return 0;
		}
		int rc = pthread_join(thread_, nullptr);
		if (rc == 0) {
			owned_ = false;
		}
		return rc;
	}

	/** @brief Whether this owner still holds a joinable worker. */
	bool owned() const {
		return owned_;
	}

private:
	pthread_t thread_ {};
	bool owned_ = false;
};

#endif /* __PROXYSQL_VERSIONCHECKTHREAD_H */
