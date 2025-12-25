/**
 * The following macro and headers are required to avoid various linker errors when compiling unit tests.
 * TODO: Fix this by improving include hierarchy.
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
MySQL_LDAP_Authentication* GloMyLdapAuth = nullptr;
