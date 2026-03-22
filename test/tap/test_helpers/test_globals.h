/**
 * @file test_globals.h
 * @brief Stub global definitions for ProxySQL unit tests.
 *
 * This header is the entry point for unit tests that need to link against
 * libproxysql.a without the real main.cpp. It provides:
 *
 *   1. All Glo* pointer stubs (initialized to nullptr)
 *   2. GloVars (ProxySQL_GlobalVariables) with safe defaults
 *   3. All __thread variable definitions via the PROXYSQL_EXTERN mechanism
 *   4. Other extern symbols normally provided by main.cpp
 *
 * Usage in test files:
 * @code
 *   #include "test_globals.h"
 *   #include "test_init.h"
 *   // ... test code ...
 * @endcode
 *
 * @note This file must NOT be included by production code.
 * @see test_globals.cpp for the corresponding definitions.
 * @see Phase 2.1 of the Unit Testing Framework (GitHub issue #5473)
 */

#ifndef TEST_GLOBALS_H
#define TEST_GLOBALS_H

/**
 * @brief Initialize minimal global state required for unit tests.
 *
 * Sets up GloVars with safe defaults (tmpdir-based datadir, no SSL,
 * no pidfile). Must be called before any component initialization.
 *
 * @return 0 on success, non-zero on failure.
 */
int test_globals_init();

/**
 * @brief Clean up global state allocated by test_globals_init().
 *
 * Frees any memory allocated during initialization. Safe to call
 * multiple times.
 */
void test_globals_cleanup();

#endif /* TEST_GLOBALS_H */
