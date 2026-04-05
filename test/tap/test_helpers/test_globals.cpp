/**
 * @file test_globals.cpp
 * @brief Stub definitions of ProxySQL global symbols for unit testing.
 *
 * This file serves as a replacement for both src/proxysql_global.cpp and
 * the global variable definitions in src/main.cpp. It allows unit test
 * binaries to link against libproxysql.a without pulling in main() or
 * the full daemon initialization sequence.
 *
 * The PROXYSQL_EXTERN mechanism (defined in include/proxysql_structs.h)
 * controls whether global variables are declared as 'extern' or defined.
 * By defining PROXYSQL_EXTERN here, we cause the headers to emit actual
 * definitions for:
 *   - GloVars (ProxySQL_GlobalVariables)
 *   - MyHGM, PgHGM (HostGroups Manager pointers)
 *   - glovars (global_variables struct)
 *   - All __thread per-thread variables (mysql_thread_*, pgsql_thread_*)
 *   - mysql_tracked_variables[], pgsql_tracked_variables[]
 *
 * Additionally, this file defines the Glo* pointers that are normally
 * declared in main.cpp (GloMyQC, GloMyAuth, GloAdmin, GloMTH, etc.),
 * all initialized to nullptr.
 *
 * @see test_globals.h for the public interface.
 * @see Phase 2.1 of the Unit Testing Framework (GitHub issue #5473)
 */

// Define PROXYSQL_EXTERN before including headers to emit global
// variable definitions (same mechanism as src/proxysql_global.cpp).
#define PROXYSQL_EXTERN

#include "../deps/json/json.hpp"

using json = nlohmann::json;
#define PROXYJSON

#include <iostream>
#include <thread>
#include <atomic>
#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"

#include "ProxySQL_Statistics.hpp"
#include "MySQL_PreparedStatement.h"
#include "PgSQL_PreparedStatement.h"
#include "ProxySQL_Cluster.hpp"
#include "MySQL_Logger.hpp"
#include "PgSQL_Logger.hpp"

#ifdef PROXYSQLGENAI
#include "MCP_Thread.h"
#include "GenAI_Thread.h"
#include "AI_Features_Manager.h"
#endif /* PROXYSQLGENAI */

#include "SQLite3_Server.h"
#include "MySQL_Query_Processor.h"
#include "PgSQL_Query_Processor.h"
#include "MySQL_Authentication.hpp"
#include "PgSQL_Authentication.h"
#include "MySQL_LDAP_Authentication.hpp"
#include "MySQL_Query_Cache.h"
#include "PgSQL_Query_Cache.h"
#include "proxysql_restapi.h"
#include "Web_Interface.hpp"
#include "proxysql_utils.h"

#include "test_globals.h"

// ============================================================================
// Glo* pointer stubs — normally defined in src/main.cpp
//
// These are the global singleton pointers that most ProxySQL classes
// reference directly. For unit tests, they start as nullptr and are
// selectively initialized by the test_init_*() helpers.
// ============================================================================

MySQL_Query_Cache *GloMyQC = nullptr;
PgSQL_Query_Cache *GloPgQC = nullptr;
MySQL_Authentication *GloMyAuth = nullptr;
PgSQL_Authentication *GloPgAuth = nullptr;
MySQL_LDAP_Authentication *GloMyLdapAuth = nullptr;

#ifdef PROXYSQLCLICKHOUSE
ClickHouse_Authentication *GloClickHouseAuth = nullptr;
#endif /* PROXYSQLCLICKHOUSE */

MySQL_Query_Processor *GloMyQPro = nullptr;
PgSQL_Query_Processor *GloPgQPro = nullptr;
ProxySQL_Admin *GloAdmin = nullptr;
MySQL_Threads_Handler *GloMTH = nullptr;
PgSQL_Threads_Handler *GloPTH = nullptr;

#ifdef PROXYSQLGENAI
MCP_Threads_Handler *GloMCPH = nullptr;
GenAI_Threads_Handler *GloGATH = nullptr;
AI_Features_Manager *GloAI = nullptr;
#endif /* PROXYSQLGENAI */

Web_Interface *GloWebInterface = nullptr;
MySQL_STMT_Manager_v14 *GloMyStmt = nullptr;
PgSQL_STMT_Manager *GloPgStmt = nullptr;

MySQL_Monitor *GloMyMon = nullptr;
PgSQL_Monitor *GloPgMon = nullptr;
std::thread *MyMon_thread = nullptr;

MySQL_Logger *GloMyLogger = nullptr;
PgSQL_Logger *GloPgSQL_Logger = nullptr;

MySQL_Variables mysql_variables;
PgSQL_Variables pgsql_variables;

SQLite3_Server *GloSQLite3Server = nullptr;

#ifdef PROXYSQLCLICKHOUSE
ClickHouse_Server *GloClickHouseServer = nullptr;
#endif /* PROXYSQLCLICKHOUSE */

ProxySQL_Cluster *GloProxyCluster = nullptr;
ProxySQL_Statistics *GloProxyStats = nullptr;

// ============================================================================
// TAP noise testing stubs — normally defined in noise_utils.cpp.
// Unit tests do not use noise testing, so these are empty stubs to
// satisfy the extern references in tap.cpp.
// ============================================================================

std::vector<std::string> noise_failures;
std::mutex noise_failure_mutex;

// ============================================================================
// Other symbols from main.cpp
// ============================================================================

/// Atomic load counter used during daemon startup. Unused in tests.
std::atomic<int> load_{0};

/// File descriptors for the proxy listener sockets. Unused in tests.
int listen_fd = -1;
int socket_fd = -1;

/// SHA1 checksum of the binary. Unused in tests.
char *binary_sha1 = nullptr;

// ============================================================================
// Stub functions for symbols referenced by libproxysql.a that are
// normally defined in src/ object files (proxy_tls.o, SQLite3_Server.o).
// These are no-ops since unit tests don't exercise TLS bootstrap or
// the SQLite3 server module.
// ============================================================================

#include "SQLite3_Server.h"

int ProxySQL_create_or_load_TLS(bool, std::string &) { return 0; }

char *SQLite3_Server::get_variable(char *) { return nullptr; }
bool SQLite3_Server::has_variable(const char *) { return false; }
bool SQLite3_Server::set_variable(char *, char *) { return false; }
char **SQLite3_Server::get_variables_list() { return nullptr; }
void SQLite3_Server::wrlock() {}
void SQLite3_Server::wrunlock() {}

// ============================================================================
// TAP noise testing stubs — exit_status() in tap.cpp calls these.
// Normally defined in noise_utils.cpp (test/tap/tap/utils.cpp).
// ============================================================================

extern "C" void stop_noise_tools() {}
extern "C" int get_noise_tools_count() { return 0; }

/// jemalloc configuration string. Required at link time on non-FreeBSD.
#ifndef __FreeBSD__
const char *malloc_conf =
	"xmalloc:true,lg_tcache_max:16,prof:false";
#endif

// ============================================================================
// ProxySQL_GlobalVariables SSL helpers (from src/proxysql_global.cpp)
//
// These methods access GloVars.global.ssl_ctx which will be nullptr
// in tests. The stubs return nullptr/noop to avoid crashes.
// ============================================================================

SSL_CTX *ProxySQL_GlobalVariables::get_SSL_ctx() {
	std::lock_guard<std::mutex> lock(global.ssl_mutex);
	return global.ssl_ctx;
}

SSL *ProxySQL_GlobalVariables::get_SSL_new() {
	std::lock_guard<std::mutex> lock(global.ssl_mutex);
	if (global.ssl_ctx == nullptr) return nullptr;
	return SSL_new(global.ssl_ctx);
}

void ProxySQL_GlobalVariables::get_SSL_pem_mem(char **key, char **cert) {
	std::lock_guard<std::mutex> lock(global.ssl_mutex);
	if (global.ssl_key_pem_mem != nullptr)
		*key = strdup(global.ssl_key_pem_mem);
	else
		*key = nullptr;
	if (global.ssl_cert_pem_mem != nullptr)
		*cert = strdup(global.ssl_cert_pem_mem);
	else
		*cert = nullptr;
}

// ============================================================================
// test_globals_init / test_globals_cleanup
// ============================================================================

/**
 * @brief Sets up GloVars with minimal safe defaults for unit testing.
 *
 * Configures GloVars to use a temporary directory as datadir, disables
 * SSL, monitoring, and other features that require infrastructure.
 * This function is idempotent.
 *
 * @return 0 on success, non-zero on failure.
 */
int test_globals_init() {
	// Ensure the global debug flag matches the build type so that
	// components which validate debug compatibility in their
	// constructors do not abort.
#ifdef DEBUG
	glovars.has_debug = true;
#else
	glovars.has_debug = false;
#endif

	// Set safe defaults for the global configuration
	GloVars.global.nostart = true;
	GloVars.global.foreground = true;
	GloVars.global.gdbg = false;
	GloVars.global.my_monitor = false;
	GloVars.global.pg_monitor = false;
	GloVars.global.version_check = false;
	GloVars.global.sqlite3_server = false;
#ifdef PROXYSQLCLICKHOUSE
	GloVars.global.clickhouse_server = false;
#endif
	GloVars.global.ssl_keylog_enabled = false;
	GloVars.global.gr_bootstrap_mode = 0;
	GloVars.global.gr_bootstrap_uri = nullptr;
	GloVars.global.data_packets_history_size = 0;

	// SSL pointers — nullptr means no SSL
	GloVars.global.ssl_ctx = nullptr;
	GloVars.global.tmp_ssl_ctx = nullptr;
	GloVars.global.ssl_key_pem_mem = nullptr;
	GloVars.global.ssl_cert_pem_mem = nullptr;

	// File paths — use a temp directory so tests don't touch real data.
	// These are strdup'd so cleanup can safely free() them.
	const char *tmpdir = getenv("TMPDIR");
	if (tmpdir == nullptr) tmpdir = "/tmp";

	if (GloVars.datadir == nullptr) {
		std::string datadir_path = std::string(tmpdir)
			+ "/proxysql_unit_test_" + std::to_string(getpid());
		GloVars.datadir = strdup(datadir_path.c_str());
	}

	return 0;
}

/**
 * @brief Frees resources allocated by test_globals_init().
 *
 * Safe to call multiple times or even if test_globals_init() was never called.
 */
void test_globals_cleanup() {
	if (GloVars.datadir != nullptr) {
		free(GloVars.datadir);
		GloVars.datadir = nullptr;
	}
}
