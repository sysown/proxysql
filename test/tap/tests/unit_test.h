#ifndef UNIT_TEST_H
#define UNIT_TEST_H

/**
 * The following macros and headers are required to avoid various linker errors when compiling unit tests.
 * TODO: Fix this by improving the include hierarchy.
 */

#define PROXYSQL_EXTERN
#define EXCLUDE_TRACKING_VARIABLES
#define MAIN_PROXY_SQLITE3

#include <memory>
#include <cstdint>
#include <cstring>
#include "openssl/ssl.h"
#include "sqlite3.h"
#include "proxysql_structs.h"
#include "MySQL_LDAP_Authentication.hpp"

/**
 * IMPORTANT: This is an ODR (One Definition Rule) violation.
 * DO NOT copy this pattern in production code or other contexts.
 *
 * Background: GloMyLdapAuth is declared as 'extern' in multiple source files in the 'lib' directory.
 * Since unit tests link against ProxySQL libraries without the full binary, this causes linker errors.
 *
 * This definition provides a stub implementation to satisfy the linker when building unit tests.
 * This is acceptable because:
 *   1. Unit tests are standalone executables that don't share symbols with each other
 *   2. This is a temporary workaround until the include hierarchy is properly refactored
 */
MySQL_LDAP_Authentication* GloMyLdapAuth = nullptr;

#endif // UNIT_TEST_H
