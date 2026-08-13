/**
 * @file test_init.cpp
 * @brief Implementation of component initialization helpers for unit tests.
 *
 * Each test_init_*() function creates real instances of ProxySQL components,
 * bypassing the full daemon startup sequence. Components are assigned to
 * their respective Glo* global pointers so that internal cross-references
 * work correctly.
 *
 * @see test_init.h for the public interface and usage examples.
 * @see Phase 2.1 of the Unit Testing Framework (GitHub issue #5473)
 */

#include "proxysql.h"
#include "cpp.h"

#include "MySQL_Authentication.hpp"
#include "PgSQL_Authentication.h"
#include "MySQL_Query_Cache.h"
#include "PgSQL_Query_Cache.h"
#include "MySQL_Query_Processor.h"
#include "PgSQL_Query_Processor.h"
#include "MySQL_Monitor.hpp"

#include "test_globals.h"
#include "test_init.h"

// Extern declarations for Glo* pointers defined in test_globals.cpp.
// These are normally defined in main.cpp and have no header declarations.
extern MySQL_Authentication *GloMyAuth;
extern PgSQL_Authentication *GloPgAuth;
extern MySQL_Query_Cache *GloMyQC;
extern PgSQL_Query_Cache *GloPgQC;
extern MySQL_Query_Processor *GloMyQPro;
extern PgSQL_Query_Processor *GloPgQPro;
extern MySQL_Monitor *GloMyMon;

// GloMTH is declared extern in proxysql_utils.h.
// GloPTH has no extern declaration in any header, so we add one here.
extern PgSQL_Threads_Handler *GloPTH;

// ============================================================================
// Minimal initialization
// ============================================================================

int test_init_minimal() {
	return test_globals_init();
}

void test_cleanup_minimal() {
	test_globals_cleanup();
}

// ============================================================================
// Authentication
// ============================================================================

int test_init_auth() {
	if (GloMyAuth != nullptr || GloPgAuth != nullptr) {
		// Already initialized — idempotent
		return 0;
	}

	GloMyAuth = new MySQL_Authentication();
	GloPgAuth = new PgSQL_Authentication();

	return 0;
}

void test_cleanup_auth() {
	if (GloMyAuth != nullptr) {
		delete GloMyAuth;
		GloMyAuth = nullptr;
	}
	if (GloPgAuth != nullptr) {
		delete GloPgAuth;
		GloPgAuth = nullptr;
	}
}

// ============================================================================
// Query Cache
// ============================================================================

int test_init_query_cache() {
	if (GloMyQC != nullptr || GloPgQC != nullptr) {
		return 0;
	}

	// The Query_Cache constructor registers Prometheus metrics via
	// GloVars.prometheus_registry. Provide a real registry so the
	// constructor doesn't crash on nullptr dereference.
	if (GloVars.prometheus_registry == nullptr) {
		GloVars.prometheus_registry = std::make_shared<prometheus::Registry>();
	}

	GloMyQC = new MySQL_Query_Cache();
	GloPgQC = new PgSQL_Query_Cache();

	// NOTE: We intentionally do NOT start the purge thread here.
	// Unit tests should call purgeHash() explicitly for deterministic
	// behavior.

	return 0;
}

void test_cleanup_query_cache() {
	if (GloMyQC != nullptr) {
		delete GloMyQC;
		GloMyQC = nullptr;
	}
	if (GloPgQC != nullptr) {
		delete GloPgQC;
		GloPgQC = nullptr;
	}
}

// ============================================================================
// Query Processor
// ============================================================================

int test_init_query_processor() {
	if (GloMyQPro != nullptr || GloPgQPro != nullptr) {
		return 0;
	}

	// Query Processor constructors register Prometheus metrics and
	// read variables from GloMTH/GloPTH. Ensure both are available.
	if (GloVars.prometheus_registry == nullptr) {
		GloVars.prometheus_registry = std::make_shared<prometheus::Registry>();
	}
	if (GloMTH == nullptr) {
		GloMTH = new MySQL_Threads_Handler();
	}
	if (GloPTH == nullptr) {
		GloPTH = new PgSQL_Threads_Handler();
	}

	// Trigger lazy initialization of VariablesPointers maps.
	// The QP constructor calls get_variable_int() which requires
	// these maps to be populated.
	char **vl = GloMTH->get_variables_list();
	if (vl) {
		for (char **p = vl; *p != nullptr; ++p) free(*p);
		free(vl);
	}
	vl = GloPTH->get_variables_list();
	if (vl) {
		for (char **p = vl; *p != nullptr; ++p) free(*p);
		free(vl);
	}

	GloMyQPro = new MySQL_Query_Processor();
	GloPgQPro = new PgSQL_Query_Processor();

	return 0;
}

void test_cleanup_query_processor() {
	if (GloMyQPro != nullptr) {
		delete GloMyQPro;
		GloMyQPro = nullptr;
	}
	if (GloPgQPro != nullptr) {
		delete GloPgQPro;
		GloPgQPro = nullptr;
	}
	// NOTE: We do NOT delete GloMTH/GloPTH here because other
	// components may still reference them. Their cleanup relies
	// on process exit.
}

// ============================================================================
// HostGroups Manager
// ============================================================================

int test_init_hostgroups() {
	// HostGroups Manager constructors register Prometheus metrics.
	if (GloVars.prometheus_registry == nullptr) {
		GloVars.prometheus_registry = std::make_shared<prometheus::Registry>();
	}

	if (MyHGM == nullptr) {
		MyHGM = new MySQL_HostGroups_Manager();
		// NOTE: We intentionally do NOT call MyHGM->init() here.
		// init() starts background threads (HGCU_thread, GTID_syncer)
		// that run forever and would cause the test process to hang on
		// exit. The constructor alone sets up the internal SQLite3
		// database and all data structures needed for unit testing.
	}

	if (PgHGM == nullptr) {
		PgHGM = new PgSQL_HostGroups_Manager();
		// PgHGM->init() is a no-op, but we skip it for consistency.
	}

	return 0;
}

void test_cleanup_hostgroups() {
	if (MyHGM != nullptr) {
		delete MyHGM;
		MyHGM = nullptr;
	}
	if (PgHGM != nullptr) {
		delete PgHGM;
		PgHGM = nullptr;
	}
}

// ============================================================================
// MySQL Monitor
// ============================================================================

int test_init_monitor() {
	if (GloMyMon == nullptr) {
		GloMyMon = new MySQL_Monitor();
	}
	return 0;
}

void test_cleanup_monitor() {
	if (GloMyMon != nullptr) {
		delete GloMyMon;
		GloMyMon = nullptr;
	}
}
