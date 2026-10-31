#ifndef PROXYSQL_CONFIGURATION_ACCESS_H
#define PROXYSQL_CONFIGURATION_ACCESS_H

class SQLite3DB;

/** @brief Lock the existing Admin SQL configuration mutex. */
void proxysql_lock_configuration();
/** @brief Unlock the configuration mutex held by this caller. */
void proxysql_unlock_configuration() noexcept;
/**
 * @brief Borrow the current configuration database under the caller's lock.
 * @return Current proxysql.db connection, valid only while lock is held.
 */
SQLite3DB* proxysql_configdb_locked();

#endif // PROXYSQL_CONFIGURATION_ACCESS_H
