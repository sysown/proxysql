#ifndef __PROXYSQL_ADMIN_GLOBAL_SQL_LOCK_H
#define __PROXYSQL_ADMIN_GLOBAL_SQL_LOCK_H

#include <pthread.h>

// ProxySQL_Admin::sql_query_global_mutex serializes the single shared SQLite3
// connections (admindb/configdb/statsdb) between Admin sessions, Cluster pulls
// and plugin services. The mutex is non-recursive, but re-entrant ownership on
// the SAME thread is a legitimate core pattern: a plugin entering through
// with_admin_db_lock() can reach another door of the same lock inside its
// publication (apply_mysql_config_v2, the secret store's ConfigurationLock),
// and an Admin session holds the lock for the whole duration of a statement
// while the plugin commands it dispatches release/re-acquire it. Every door
// must therefore route through these helpers: a nested door on an owning
// thread re-enters instead of double-locking.
//
// The reference deadlock (issue #6440 review, phase 3 runtime_ready):
// packages/mainpublish runs under with_admin_db_lock() and reaches
// PluginBootstrapStore::publish_generation -> apply_mysql_config_v2, whose
// admin_db_lock_guard re-locked the held mutex: the main thread blocked
// forever, the startup gate never opened, and every admin session (plus the
// CI fixture LOAD heredoc) waited on Admin_Handler's startup gate/gate wait
// until the two-hour job timeout.
//
// Depth is a per-thread COUNTER of open acquisitions. Only the outermost
// acquisition locks the mutex and only the matching outermost release unlocks
// it, so any nesting of doors (Admin statement -> plugin service ->
// ConfigurationLock -> ...) is balanced. Threads that do not hold the lock
// still serialize normally.
//
// Manual release windows (SAVE/LOAD PROXYSQL SERVERS around the Cluster
// mutex, Admin_Stats around the Cluster snapshots, plugin commands handing
// the mutex off while they wait) must NOT touch the mutex or the depth
// directly: they use proxysql_admin_global_sql_release_all() /
// proxysql_admin_global_sql_restore(), or the RAII
// proxysql_admin_global_sql_release_scope, which fully release whatever this
// thread holds and later restore exactly that many levels. A service invoked
// inside the window then locks the (now free) mutex normally.
//
// No other code may lock/unlock sql_query_global_mutex directly.

// Per-thread acquisition depth. Deliberately defined out of line, in
// lib/ProxySQL_Admin.cpp: plugins are built with -fvisibility=hidden, so an
// inline function's thread_local would give every plugin its own private
// counter. One definition in the core keeps a single counter per thread for
// the core and every plugin that includes this header.
int& proxysql_admin_global_sql_lock_depth();

// Re-entrant acquisition: locks the mutex only when this thread does not
// already hold it, and records one more open level.
inline void proxysql_admin_global_sql_lock(pthread_mutex_t& mutex) {
	int& depth = proxysql_admin_global_sql_lock_depth();
	if (depth <= 0) {
		pthread_mutex_lock(&mutex);
		depth = 0;
	}
	++depth;
}

// Balanced release: closes one level; unlocks the mutex only when the
// outermost level is closed. A release on a thread holding nothing is a
// no-op (never unlocks a mutex this thread does not own).
inline void proxysql_admin_global_sql_unlock(pthread_mutex_t& mutex) {
	int& depth = proxysql_admin_global_sql_lock_depth();
	if (depth <= 0) return;
	if (--depth == 0) {
		pthread_mutex_unlock(&mutex);
	}
}

// Fully release the mutex for a manual window, whatever the nesting depth.
// Returns the number of levels this thread held (0 when it held nothing, in
// which case nothing is unlocked); pass it to proxysql_admin_global_sql_restore().
inline int proxysql_admin_global_sql_release_all(pthread_mutex_t& mutex) {
	int& depth = proxysql_admin_global_sql_lock_depth();
	const int levels = depth;
	if (levels <= 0) return 0;
	depth = 0;
	pthread_mutex_unlock(&mutex);
	return levels;
}

// Restore the levels returned by proxysql_admin_global_sql_release_all().
// Re-locks the mutex unless this thread already holds it again (an
// unbalanced acquisition inside the window), so a restore can never
// self-deadlock; the levels are added on top of whatever is held.
inline void proxysql_admin_global_sql_restore(pthread_mutex_t& mutex, int levels) {
	if (levels <= 0) return;
	int& depth = proxysql_admin_global_sql_lock_depth();
	if (depth <= 0) {
		pthread_mutex_lock(&mutex);
		depth = 0;
	}
	depth += levels;
}

// RAII owner for function-scope critical sections: one level acquired on
// construction, released on destruction (including the exception unwinding
// path). Nested guards only move the counter.
class proxysql_admin_global_sql_guard {
public:
	explicit proxysql_admin_global_sql_guard(pthread_mutex_t& mutex) : mutex_(mutex) {
		owned_ = proxysql_admin_global_sql_lock_depth() <= 0;
		proxysql_admin_global_sql_lock(mutex_);
	}
	~proxysql_admin_global_sql_guard() {
		proxysql_admin_global_sql_unlock(mutex_);
	}
	proxysql_admin_global_sql_guard(const proxysql_admin_global_sql_guard&) = delete;
	proxysql_admin_global_sql_guard& operator=(const proxysql_admin_global_sql_guard&) = delete;
	// True when this instance performed the actual acquisition (i.e. the
	// thread did not already hold the lock on entry).
	bool owns_lock() const { return owned_; }
private:
	pthread_mutex_t& mutex_;
	bool owned_ { false };
};

// RAII manual release window: fully releases what this thread holds on
// construction and restores exactly those levels on destruction (including
// the exception unwinding path). A no-op on a thread holding nothing.
class proxysql_admin_global_sql_release_scope {
public:
	explicit proxysql_admin_global_sql_release_scope(pthread_mutex_t& mutex)
		: mutex_(mutex), levels_(proxysql_admin_global_sql_release_all(mutex)) { }
	~proxysql_admin_global_sql_release_scope() {
		proxysql_admin_global_sql_restore(mutex_, levels_);
	}
	proxysql_admin_global_sql_release_scope(const proxysql_admin_global_sql_release_scope&) = delete;
	proxysql_admin_global_sql_release_scope& operator=(const proxysql_admin_global_sql_release_scope&) = delete;
	int released_levels() const { return levels_; }
private:
	pthread_mutex_t& mutex_;
	const int levels_;
};

#endif // __PROXYSQL_ADMIN_GLOBAL_SQL_LOCK_H
