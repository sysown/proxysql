/**
 * @file admin_global_sql_lock_unit-t.cpp
 * @brief Regression tests for #6468: the re-entrancy protocol of
 *        ProxySQL_Admin::sql_query_global_mutex.
 *
 * The protocol used to be a 0/1 per-thread flag: a nested acquisition was a
 * no-op but the matching nested release really unlocked the mutex and zeroed
 * the flag, so an inner door (ConfigurationLock, services.lock_configuration)
 * released the outer owner's lock and the outer owner then unlocked a mutex it
 * no longer owned. drain_server_discovery_updates() locked unconditionally and
 * deadlocked when entered by a thread that already held the mutex.
 *
 * Covered here:
 *  - nested lock/unlock is a balanced counter; only the outermost pair
 *    touches the mutex;
 *  - release_all/restore and the RAII release scope fully release and restore
 *    exactly the held levels (including on exceptions and when the window
 *    re-acquired the lock itself);
 *  - (PROXYSQL40) a nested ConfigurationLock door inside with_admin_db_lock and
 *    inside an Admin-statement-style acquisition keeps the outer ownership;
 *  - (PROXYSQL40) nested with_admin_db_lock (the #6440 router publication
 *    shape) and drain_server_discovery_updates() under a held lock do not
 *    deadlock.
 *
 * Every scenario runs on a worker thread with a timeout so a regression to a
 * self-deadlock fails the test instead of hanging it.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "proxysql_admin.h"
#include "ProxySQL_Statistics.hpp"
#include "proxysql_admin_global_sql_lock.h"
#ifdef PROXYSQL40
#include "ProxySQL_ConfigurationAccess.h"
#endif

#include <cerrno>
#include <chrono>
#include <functional>
#include <future>
#include <stdexcept>
#include <thread>

extern ProxySQL_Admin* GloAdmin;
extern ProxySQL_Statistics* GloProxyStats;
#ifdef PROXYSQL40
bool proxysql_plugin_with_admin_db_lock(bool (*body)(void*), void* opaque);
#endif

namespace {

int depth() { return proxysql_admin_global_sql_lock_depth(); }

// True when another thread cannot take the mutex right now.
bool held_elsewhere(pthread_mutex_t& mutex) {
	bool held = false;
	std::thread probe([&] {
		const int rc = pthread_mutex_trylock(&mutex);
		if (rc == 0) {
			pthread_mutex_unlock(&mutex);
			held = false;
		} else {
			held = (rc == EBUSY);
		}
	});
	probe.join();
	return held;
}

// Runs a scenario on its own thread (depth is per-thread). Returns false when
// it does not finish in time: the thread is left behind, blocked.
bool completes(const std::function<void()>& scenario, int timeout_ms = 3000) {
	auto task = std::make_shared<std::packaged_task<void()>>(scenario);
	std::future<void> done = task->get_future();
	std::thread([task] { (*task)(); }).detach();
	return done.wait_for(std::chrono::milliseconds(timeout_ms)) == std::future_status::ready;
}

void test_counter(pthread_mutex_t& m) {
	bool finished = completes([&] {
		proxysql_admin_global_sql_lock(m);
		ok(depth() == 1 && held_elsewhere(m), "outermost lock acquires the mutex (depth=%d)", depth());
		proxysql_admin_global_sql_lock(m);
		ok(depth() == 2, "nested lock only increments the depth (depth=%d)", depth());
		proxysql_admin_global_sql_unlock(m);
		ok(depth() == 1 && held_elsewhere(m),
		   "nested unlock keeps the outer owner's mutex locked (depth=%d)", depth());
		proxysql_admin_global_sql_unlock(m);
		ok(depth() == 0 && !held_elsewhere(m), "outermost unlock releases the mutex (depth=%d)", depth());
		proxysql_admin_global_sql_unlock(m);
		ok(depth() == 0 && !held_elsewhere(m), "unlock on a thread holding nothing is a no-op");
	});
	ok(finished, "counter scenario completes without self-deadlock");
}

void test_guard(pthread_mutex_t& m) {
	bool finished = completes([&] {
		proxysql_admin_global_sql_guard outer(m);
		{
			proxysql_admin_global_sql_guard inner(m);
			ok(outer.owns_lock() && !inner.owns_lock() && depth() == 2,
			   "only the outer guard performs the acquisition (depth=%d)", depth());
		}
		ok(depth() == 1 && held_elsewhere(m), "inner guard release keeps the outer guard's lock");
	});
	ok(finished && depth() == 0 && !held_elsewhere(m), "guards release the mutex at scope exit");
}

void test_release_restore(pthread_mutex_t& m) {
	bool finished = completes([&] {
		proxysql_admin_global_sql_lock(m);
		proxysql_admin_global_sql_lock(m);
		const int levels = proxysql_admin_global_sql_release_all(m);
		ok(levels == 2 && depth() == 0 && !held_elsewhere(m),
		   "release_all frees the mutex whatever the depth (levels=%d)", levels);
		proxysql_admin_global_sql_lock(m);
		ok(depth() == 1 && held_elsewhere(m), "a door inside the release window locks the free mutex");
		proxysql_admin_global_sql_unlock(m);
		ok(depth() == 0 && !held_elsewhere(m), "and releases it again before the window closes");
		proxysql_admin_global_sql_restore(m, levels);
		ok(depth() == 2 && held_elsewhere(m), "restore re-acquires exactly the released levels");
		proxysql_admin_global_sql_unlock(m);
		proxysql_admin_global_sql_unlock(m);
		ok(depth() == 0 && !held_elsewhere(m), "restored levels unwind normally");

		ok(proxysql_admin_global_sql_release_all(m) == 0 && !held_elsewhere(m),
		   "release_all on a thread holding nothing releases nothing");
		proxysql_admin_global_sql_restore(m, 0);
		ok(depth() == 0 && !held_elsewhere(m), "restoring zero levels acquires nothing");

		// An unbalanced acquisition inside the window must not make restore
		// self-deadlock on the non-recursive mutex.
		proxysql_admin_global_sql_lock(m);
		const int one = proxysql_admin_global_sql_release_all(m);
		proxysql_admin_global_sql_lock(m);
		proxysql_admin_global_sql_restore(m, one);
		ok(depth() == 2 && held_elsewhere(m), "restore over a re-acquired lock adds levels without relocking");
		proxysql_admin_global_sql_unlock(m);
		proxysql_admin_global_sql_unlock(m);
	});
	ok(finished && !held_elsewhere(m), "release/restore scenario completes without self-deadlock");
}

void test_release_scope(pthread_mutex_t& m) {
	bool finished = completes([&] {
		proxysql_admin_global_sql_lock(m);
		proxysql_admin_global_sql_lock(m);
		proxysql_admin_global_sql_lock(m);
		{
			proxysql_admin_global_sql_release_scope window(m);
			ok(window.released_levels() == 3 && depth() == 0 && !held_elsewhere(m),
			   "release scope frees the mutex inside the window");
		}
		ok(depth() == 3 && held_elsewhere(m), "release scope restores all levels at scope exit");
		try {
			proxysql_admin_global_sql_release_scope window(m);
			throw std::runtime_error("window failure");
		} catch (const std::exception&) {
		}
		ok(depth() == 3 && held_elsewhere(m), "release scope restores the levels on the exception path");
		proxysql_admin_global_sql_unlock(m);
		proxysql_admin_global_sql_unlock(m);
		proxysql_admin_global_sql_unlock(m);
		{
			proxysql_admin_global_sql_release_scope window(m);
			ok(window.released_levels() == 0, "release scope on a thread holding nothing is a no-op");
		}
		ok(depth() == 0 && !held_elsewhere(m), "and leaves the mutex free afterwards");
	});
	ok(finished, "release scope scenario completes without self-deadlock");
}

#ifdef PROXYSQL40
bool configuration_door_body(void* opaque) {
	auto* mutex = static_cast<pthread_mutex_t*>(opaque);
	// ConfigurationLock (put/get/erase_secret_service) and the ABI
	// services.lock_configuration/unlock_configuration are these two calls.
	proxysql_lock_configuration();
	const bool nested = depth() == 2;
	proxysql_unlock_configuration();
	return nested && depth() == 1 && held_elsewhere(*mutex);
}

bool nested_with_admin_db_lock_body(void* opaque) {
	auto* mutex = static_cast<pthread_mutex_t*>(opaque);
	const bool inner = proxysql_plugin_with_admin_db_lock([](void*) { return depth() == 2; }, nullptr);
	return inner && depth() == 1 && held_elsewhere(*mutex);
}

void test_admin_doors() {
	pthread_mutex_t& m = GloAdmin->sql_query_global_mutex;

	bool body_ok = false;
	bool finished = completes([&] {
		body_ok = proxysql_plugin_with_admin_db_lock(&configuration_door_body, &m);
	});
	ok(finished && body_ok,
	   "nested ConfigurationLock inside with_admin_db_lock keeps the outer lock held");
	ok(finished && !held_elsewhere(m), "with_admin_db_lock releases the mutex exactly once");

	finished = completes([&] {
		// Admin statement scope (Admin_Handler) followed by a plugin service.
		proxysql_admin_global_sql_lock(m);
		proxysql_lock_configuration();
		proxysql_unlock_configuration();
		ok(depth() == 1 && held_elsewhere(m),
		   "nested ConfigurationLock inside an Admin statement keeps the statement's lock");
		proxysql_admin_global_sql_unlock(m);
	});
	ok(finished && !held_elsewhere(m), "Admin statement scope releases the mutex at its end");

	body_ok = false;
	finished = completes([&] {
		body_ok = proxysql_plugin_with_admin_db_lock(&nested_with_admin_db_lock_body, &m);
	});
	ok(finished && body_ok,
	   "with_admin_db_lock re-entered from its own body (router publish_users shape) does not deadlock");
	ok(finished && !held_elsewhere(m), "nested with_admin_db_lock leaves the mutex free afterwards");

	bool still_held = false;
	finished = completes([&] {
		proxysql_admin_global_sql_lock(m);
		GloAdmin->drain_server_discovery_updates();
		still_held = depth() == 1 && held_elsewhere(m);
		proxysql_admin_global_sql_unlock(m);
	});
	ok(finished, "drain_server_discovery_updates() re-enters a lock its caller already holds");
	ok(finished && still_held, "and leaves the caller's ownership intact");
	ok(finished && !held_elsewhere(m), "the caller's release then frees the mutex");
}
#endif

} // namespace

int main() {
#ifdef PROXYSQL40
	plan(33);
#else
	plan(24);
#endif
	test_init_minimal();

	pthread_mutex_t m;
	pthread_mutex_init(&m, nullptr);
	test_counter(m);
	test_guard(m);
	test_release_restore(m);
	test_release_scope(m);

#ifdef PROXYSQL40
	GloVars.statsdb_disk = const_cast<char*>(":memory:");
	GloProxyStats = new ProxySQL_Statistics();
	GloAdmin = new ProxySQL_Admin();
	test_admin_doors();
#endif

	return exit_status();
}
