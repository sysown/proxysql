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
// Depth is per-thread: threads that do not hold the lock still serialize
// normally. Manual release/re-acquire windows (e.g. SAVE PROXYSQL SERVERS
// unlocking around the disk dump, Admin_Stats releasing around uploads)
// lower/lift the depth so a service invoked inside the relaxed window still
// locks the - now free - mutex instead of skipping the acquisition.

inline int& proxysql_admin_global_sql_lock_depth() {
	static thread_local int depth = 0;
	return depth;
}

// Re-entrant-aware acquisition: no-op when this thread already owns an open
// critical section; otherwise locks the mutex and records the ownership.
inline void proxysql_admin_global_sql_lock(pthread_mutex_t& mutex) {
	if (proxysql_admin_global_sql_lock_depth() > 0) return;
	pthread_mutex_lock(&mutex);
	proxysql_admin_global_sql_lock_depth() = 1;
}

// Balanced release: no-op unless this thread owns an open critical section.
inline void proxysql_admin_global_sql_unlock(pthread_mutex_t& mutex) {
	if (proxysql_admin_global_sql_lock_depth() <= 0) return;
	pthread_mutex_unlock(&mutex);
	proxysql_admin_global_sql_lock_depth() = 0;
}

// RAII owner for function-scope critical sections: acquires on construction
// unless the thread already holds the lock, and releases exactly what it
// acquired (a nested guard is a no-op on both ends, including on the
// exception unwinding path).
class proxysql_admin_global_sql_guard {
public:
	explicit proxysql_admin_global_sql_guard(pthread_mutex_t& mutex) : mutex_(mutex) {
		owned_ = proxysql_admin_global_sql_lock_depth() <= 0;
		if (owned_) {
			pthread_mutex_lock(&mutex_);
			proxysql_admin_global_sql_lock_depth() = 1;
		}
	}
	~proxysql_admin_global_sql_guard() {
		if (owned_) {
			proxysql_admin_global_sql_lock_depth() = 0;
			pthread_mutex_unlock(&mutex_);
		}
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

#endif // __PROXYSQL_ADMIN_GLOBAL_SQL_LOCK_H
