/**
 * @file test_init.h
 * @brief Component initialization helpers for ProxySQL unit tests.
 *
 * Provides functions to selectively initialize individual ProxySQL
 * components for isolated testing, without requiring the full daemon
 * startup sequence. Each init function has a matching cleanup function
 * that frees all resources.
 *
 * Typical usage:
 * @code
 *   #include "test_globals.h"
 *   #include "test_init.h"
 *   #include "tap.h"
 *
 *   int main() {
 *       plan(3);
 *       test_init_minimal();
 *       test_init_auth();
 *
 *       // ... run tests against GloMyAuth ...
 *
 *       test_cleanup_auth();
 *       test_cleanup_minimal();
 *       return exit_status();
 *   }
 * @endcode
 *
 * @note All init functions are idempotent — calling them multiple
 *       times is safe (subsequent calls are no-ops).
 * @note Always call cleanup functions in reverse init order.
 *
 * @see test_globals.h for the global stub definitions.
 * @see Phase 2.1 of the Unit Testing Framework (GitHub issue #5473)
 */

#ifndef TEST_INIT_H
#define TEST_INIT_H

/**
 * @brief Initialize minimal global state required by all unit tests.
 *
 * Sets up GloVars with safe defaults. This is the foundation that all
 * other test_init_* functions build upon. Must be called first.
 *
 * @return 0 on success, non-zero on failure.
 */
int test_init_minimal();

/**
 * @brief Clean up resources allocated by test_init_minimal().
 */
void test_cleanup_minimal();

/**
 * @brief Initialize MySQL and PostgreSQL Authentication components.
 *
 * Creates real MySQL_Authentication and PgSQL_Authentication objects
 * (assigned to GloMyAuth and GloPgAuth). The auth stores are empty
 * and ready for test data via add()/lookup()/del().
 *
 * @pre test_init_minimal() must have been called.
 * @return 0 on success, non-zero on failure.
 */
int test_init_auth();

/**
 * @brief Clean up resources allocated by test_init_auth().
 *
 * Destroys GloMyAuth and GloPgAuth, setting them back to nullptr.
 */
void test_cleanup_auth();

/**
 * @brief Initialize MySQL and PostgreSQL Query Cache components.
 *
 * Creates real MySQL_Query_Cache and PgSQL_Query_Cache objects
 * (assigned to GloMyQC and GloPgQC). The purge thread is NOT started;
 * callers can invoke purgeHash() manually for deterministic testing.
 *
 * @pre test_init_minimal() must have been called.
 * @return 0 on success, non-zero on failure.
 */
int test_init_query_cache();

/**
 * @brief Clean up resources allocated by test_init_query_cache().
 *
 * Destroys GloMyQC and GloPgQC, setting them back to nullptr.
 */
void test_cleanup_query_cache();

/**
 * @brief Initialize MySQL and PostgreSQL Query Processor components.
 *
 * Creates real MySQL_Query_Processor and PgSQL_Query_Processor objects
 * (assigned to GloMyQPro and GloPgQPro) with empty rulesets. Rules
 * can be added via new_query_rule() for testing.
 *
 * @pre test_init_minimal() must have been called.
 * @return 0 on success, non-zero on failure.
 */
int test_init_query_processor();

/**
 * @brief Clean up resources allocated by test_init_query_processor().
 *
 * Destroys GloMyQPro and GloPgQPro, setting them back to nullptr.
 */
void test_cleanup_query_processor();

/**
 * @brief Initialize MySQL and PostgreSQL HostGroups Managers.
 *
 * Creates real MySQL_HostGroups_Manager and PgSQL_HostGroups_Manager
 * objects (assigned to MyHGM and PgHGM) with internal SQLite3 databases.
 * Servers can be added via create_new_server_in_hg() for testing.
 *
 * @pre test_init_minimal() must have been called.
 * @return 0 on success, non-zero on failure.
 */
int test_init_hostgroups();

/**
 * @brief Clean up resources allocated by test_init_hostgroups().
 *
 * Destroys MyHGM and PgHGM, setting them back to nullptr.
 */
void test_cleanup_hostgroups();

#endif /* TEST_INIT_H */
