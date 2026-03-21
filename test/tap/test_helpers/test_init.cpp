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
}
