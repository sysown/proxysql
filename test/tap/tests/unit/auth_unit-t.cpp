/**
 * @file auth_unit-t.cpp
 * @brief Unit tests for MySQL_Authentication and PgSQL_Authentication.
 *
 * Tests the authentication subsystem in isolation without a running
 * ProxySQL instance. Covers:
 *   - Core CRUD: add, lookup, del, exists
 *   - Credential management: SHA1, clear-text passwords
 *   - Connection counting and max_connections enforcement
 *   - Bulk operations: set_all_inactive, remove_inactives, reset
 *   - Runtime checksums
 *   - Memory tracking
 *   - Frontend vs backend separation
 *   - PgSQL Authentication parity
 *
 * @see Phase 2.2 of the Unit Testing Framework (GitHub issue #5474)
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "MySQL_Authentication.hpp"
#include "PgSQL_Authentication.h"

#include <cstring>
#include <openssl/sha.h>

// Extern declarations for Glo* pointers (defined in test_globals.cpp)
extern MySQL_Authentication *GloMyAuth;
extern PgSQL_Authentication *GloPgAuth;

// ============================================================================
// Helper: add a MySQL frontend user with common defaults
// ============================================================================
static bool mysql_add_frontend(MySQL_Authentication *auth,
	const char *user, const char *pass,
	int default_hg = 0, int max_conn = 100)
{
	return auth->add(
		(char *)user, (char *)pass, USERNAME_FRONTEND,
		false,            // use_ssl
		default_hg,       // default_hostgroup
		(char *)"",       // default_schema
		false,            // schema_locked
		false,            // transaction_persistent
		false,            // fast_forward
		max_conn,         // max_connections
		(char *)"",       // attributes
		(char *)""        // comment
	);
}

static bool mysql_add_frontend_with_attributes(MySQL_Authentication *auth,
	const char *user, bool use_ssl, const char *attributes)
{
	return auth->add(
		(char *)user, (char *)"pass", USERNAME_FRONTEND,
		use_ssl, 0, (char *)"", false, false, false,
		100, (char *)attributes, (char *)"");
}

// ============================================================================
// Helper: add a MySQL backend user
// ============================================================================
static bool mysql_add_backend(MySQL_Authentication *auth,
	const char *user, const char *pass,
	int default_hg = 0, int max_conn = 100)
{
	return auth->add(
		(char *)user, (char *)pass, USERNAME_BACKEND,
		false, default_hg, (char *)"", false, false, false,
		max_conn, (char *)"", (char *)""
	);
}

// ============================================================================
// Helper: add a PgSQL frontend user
// ============================================================================
static bool pgsql_add_frontend(PgSQL_Authentication *auth,
	const char *user, const char *pass,
	int default_hg = 0, int max_conn = 100)
{
	return auth->add(
		(char *)user, (char *)pass, USERNAME_FRONTEND,
		false,            // use_ssl
		default_hg,       // default_hostgroup
		false,            // transaction_persistent
		false,            // fast_forward
		max_conn,         // max_connections
		(char *)"",       // attributes
		(char *)""        // comment
	);
}

// ============================================================================
// 1. MySQL_Authentication: Core CRUD
// ============================================================================

/**
 * @brief Test basic add + exists + lookup cycle.
 */
static void test_mysql_add_exists_lookup() {
	mysql_add_frontend(GloMyAuth, "alice", "pass123", 1, 50);

	ok(GloMyAuth->exists((char *)"alice") == true,
		"MySQL: exists() returns true for added frontend user");

	ok(GloMyAuth->exists((char *)"unknown") == false,
		"MySQL: exists() returns false for nonexistent user");

	// Lookup with dup options
	dup_account_details_t dup = {true, true, true};
	account_details_t ad = GloMyAuth->lookup(
		(char *)"alice", USERNAME_FRONTEND, dup);

	ok(ad.password != nullptr && strcmp(ad.password, "pass123") == 0,
		"MySQL: lookup() returns correct password");
	ok(ad.default_hostgroup == 1,
		"MySQL: lookup() returns correct default_hostgroup");
	ok(ad.max_connections == 50,
		"MySQL: lookup() returns correct max_connections");

	free_account_details(ad);
}

/**
 * @brief Test that exists() only checks frontends, not backends.
 */
static void test_mysql_exists_frontend_only() {
	mysql_add_backend(GloMyAuth, "backend_only", "secret");

	ok(GloMyAuth->exists((char *)"backend_only") == false,
		"MySQL: exists() returns false for backend-only user");

	// But lookup with USERNAME_BACKEND should find it
	dup_account_details_t dup = {false, false, false};
	account_details_t ad = GloMyAuth->lookup(
		(char *)"backend_only", USERNAME_BACKEND, dup);

	ok(ad.password != nullptr && strcmp(ad.password, "secret") == 0,
		"MySQL: lookup(BACKEND) finds backend user");

	free_account_details(ad);
}

/**
 * @brief Test that add() overwrites on duplicate username.
 */
static void test_mysql_add_overwrites() {
	mysql_add_frontend(GloMyAuth, "bob", "old_pass", 1, 10);
	mysql_add_frontend(GloMyAuth, "bob", "new_pass", 2, 20);

	dup_account_details_t dup = {true, false, false};
	account_details_t ad = GloMyAuth->lookup(
		(char *)"bob", USERNAME_FRONTEND, dup);

	ok(ad.password != nullptr && strcmp(ad.password, "new_pass") == 0,
		"MySQL: add() overwrites password on duplicate");
	ok(ad.default_hostgroup == 2,
		"MySQL: add() overwrites default_hostgroup on duplicate");
	ok(ad.max_connections == 20,
		"MySQL: add() overwrites max_connections on duplicate");

	free_account_details(ad);
}

/**
 * @brief Test del() removes a user.
 */
static void test_mysql_del() {
	mysql_add_frontend(GloMyAuth, "charlie", "pass");

	ok(GloMyAuth->exists((char *)"charlie") == true,
		"MySQL: user exists before del()");

	bool deleted = GloMyAuth->del((char *)"charlie", USERNAME_FRONTEND);
	ok(deleted == true, "MySQL: del() returns true for existing user");

	ok(GloMyAuth->exists((char *)"charlie") == false,
		"MySQL: user gone after del()");

	bool deleted_again = GloMyAuth->del((char *)"charlie", USERNAME_FRONTEND);
	ok(deleted_again == false,
		"MySQL: del() returns false for already-deleted user");
}

/**
 * @brief Test lookup() returns empty struct for nonexistent user.
 */
static void test_mysql_lookup_not_found() {
	dup_account_details_t dup = {true, true, true};
	account_details_t ad = GloMyAuth->lookup(
		(char *)"nonexistent", USERNAME_FRONTEND, dup);

	ok(ad.password == nullptr,
		"MySQL: lookup() returns null password for nonexistent user");
	ok(ad.username == nullptr,
		"MySQL: lookup() returns null username for nonexistent user");
}

// ============================================================================
// 2. MySQL_Authentication: Credential Management
// ============================================================================

/**
 * @brief Test set_SHA1() stores and retrieves SHA1 hash.
 */
static void test_mysql_sha1() {
	mysql_add_frontend(GloMyAuth, "sha1user", "pass");

	unsigned char sha1_hash[SHA_DIGEST_LENGTH];
	SHA1((unsigned char *)"pass", 4, sha1_hash);

	bool set_ok = GloMyAuth->set_SHA1(
		(char *)"sha1user", USERNAME_FRONTEND, sha1_hash);
	ok(set_ok == true, "MySQL: set_SHA1() returns true");

	// Lookup with sha1 duplication
	dup_account_details_t dup = {false, true, false};
	account_details_t ad = GloMyAuth->lookup(
		(char *)"sha1user", USERNAME_FRONTEND, dup);

	ok(ad.sha1_pass != nullptr, "MySQL: SHA1 pass retrieved via lookup()");
	if (ad.sha1_pass != nullptr) {
		ok(memcmp(ad.sha1_pass, sha1_hash, SHA_DIGEST_LENGTH) == 0,
			"MySQL: SHA1 hash matches what was set");
	} else {
		ok(0, "MySQL: SHA1 hash was unexpectedly null");
	}

	// set_SHA1 on nonexistent user
	bool set_fail = GloMyAuth->set_SHA1(
		(char *)"nobody", USERNAME_FRONTEND, sha1_hash);
	ok(set_fail == false,
		"MySQL: set_SHA1() returns false for nonexistent user");

	free_account_details(ad);
}

/**
 * @brief Test set_clear_text_password() for PRIMARY and ADDITIONAL,
 *        and verify stored values are retrievable via lookup().
 */
static void test_mysql_clear_text_password() {
	mysql_add_frontend(GloMyAuth, "ctpuser", "original");

	bool set_ok = GloMyAuth->set_clear_text_password(
		(char *)"ctpuser", USERNAME_FRONTEND,
		"clearpass", PASSWORD_TYPE::PRIMARY);
	ok(set_ok == true,
		"MySQL: set_clear_text_password(PRIMARY) returns true");

	set_ok = GloMyAuth->set_clear_text_password(
		(char *)"ctpuser", USERNAME_FRONTEND,
		"altpass", PASSWORD_TYPE::ADDITIONAL);
	ok(set_ok == true,
		"MySQL: set_clear_text_password(ADDITIONAL) returns true");

	// Verify stored clear-text passwords are retrievable
	dup_account_details_t dup = {false, false, false};
	account_details_t ad = GloMyAuth->lookup(
		(char *)"ctpuser", USERNAME_FRONTEND, dup);
	ok(ad.clear_text_password[PASSWORD_TYPE::PRIMARY] != nullptr
		&& strcmp(ad.clear_text_password[PASSWORD_TYPE::PRIMARY], "clearpass") == 0,
		"MySQL: PRIMARY clear_text_password retrievable via lookup()");
	ok(ad.clear_text_password[PASSWORD_TYPE::ADDITIONAL] != nullptr
		&& strcmp(ad.clear_text_password[PASSWORD_TYPE::ADDITIONAL], "altpass") == 0,
		"MySQL: ADDITIONAL clear_text_password retrievable via lookup()");
	free_account_details(ad);

	bool set_fail = GloMyAuth->set_clear_text_password(
		(char *)"nobody", USERNAME_FRONTEND,
		"pass", PASSWORD_TYPE::PRIMARY);
	ok(set_fail == false,
		"MySQL: set_clear_text_password() returns false for nonexistent user");
}

// ============================================================================
// 3. MySQL_Authentication: Connection Counting
// ============================================================================

/**
 * @brief Test increase/decrease frontend user connections.
 */
static void test_mysql_connection_counting() {
	mysql_add_frontend(GloMyAuth, "connuser", "pass", 0, 3);

	// Increase connections until limit
	int remaining;
	remaining = GloMyAuth->increase_frontend_user_connections(
		(char *)"connuser", PASSWORD_TYPE::PRIMARY);
	ok(remaining > 0, "MySQL: 1st connection: remaining > 0");

	remaining = GloMyAuth->increase_frontend_user_connections(
		(char *)"connuser", PASSWORD_TYPE::PRIMARY);
	ok(remaining > 0, "MySQL: 2nd connection: remaining > 0");

	remaining = GloMyAuth->increase_frontend_user_connections(
		(char *)"connuser", PASSWORD_TYPE::PRIMARY);
	ok(remaining > 0, "MySQL: 3rd connection: remaining > 0");

	// At limit now — next should return 0
	remaining = GloMyAuth->increase_frontend_user_connections(
		(char *)"connuser", PASSWORD_TYPE::PRIMARY);
	ok(remaining == 0, "MySQL: 4th connection rejected (max_connections=3)");

	// Decrease and verify we can connect again
	GloMyAuth->decrease_frontend_user_connections(
		(char *)"connuser", PASSWORD_TYPE::PRIMARY);

	remaining = GloMyAuth->increase_frontend_user_connections(
		(char *)"connuser", PASSWORD_TYPE::PRIMARY);
	ok(remaining > 0,
		"MySQL: connection allowed after decrease");
}

// ============================================================================
// 4. MySQL_Authentication: Bulk Operations
// ============================================================================

/**
 * @brief Test set_all_inactive + remove_inactives pattern.
 */
static void test_mysql_inactive_pattern() {
	// Start fresh
	GloMyAuth->reset();

	mysql_add_frontend(GloMyAuth, "keep_me", "pass1");
	mysql_add_frontend(GloMyAuth, "remove_me", "pass2");

	// Mark all inactive
	GloMyAuth->set_all_inactive(USERNAME_FRONTEND);

	// Re-add the one we want to keep (sets __active = true)
	mysql_add_frontend(GloMyAuth, "keep_me", "pass1");

	// Remove inactive users
	GloMyAuth->remove_inactives(USERNAME_FRONTEND);

	ok(GloMyAuth->exists((char *)"keep_me") == true,
		"MySQL: re-added user survives remove_inactives()");
	ok(GloMyAuth->exists((char *)"remove_me") == false,
		"MySQL: inactive user removed by remove_inactives()");
}

/**
 * @brief Test reset() clears all users.
 */
static void test_mysql_reset() {
	mysql_add_frontend(GloMyAuth, "user1", "p1");
	mysql_add_frontend(GloMyAuth, "user2", "p2");
	mysql_add_backend(GloMyAuth, "user3", "p3");

	GloMyAuth->reset();

	ok(GloMyAuth->exists((char *)"user1") == false,
		"MySQL: frontend user gone after reset()");

	dup_account_details_t dup = {false, false, false};
	account_details_t ad = GloMyAuth->lookup(
		(char *)"user3", USERNAME_BACKEND, dup);
	ok(ad.password == nullptr,
		"MySQL: backend user gone after reset()");
}

// ============================================================================
// 5. MySQL_Authentication: Checksums
// ============================================================================

/**
 * @brief Test runtime checksum behavior.
 */
static void test_mysql_checksums() {
	GloMyAuth->reset();

	uint64_t empty_checksum = GloMyAuth->get_runtime_checksum();
	ok(empty_checksum == 0,
		"MySQL: checksum is 0 with no users");

	mysql_add_frontend(GloMyAuth, "checksumA", "passA", 1);
	uint64_t checksum1 = GloMyAuth->get_runtime_checksum();
	ok(checksum1 != 0,
		"MySQL: checksum is non-zero with users");

	mysql_add_frontend(GloMyAuth, "checksumB", "passB", 2);
	uint64_t checksum2 = GloMyAuth->get_runtime_checksum();
	ok(checksum2 != checksum1,
		"MySQL: checksum changes when users are added");

	// Modify a user and verify checksum changes
	mysql_add_frontend(GloMyAuth, "checksumA", "passA_changed", 1);
	uint64_t checksum3 = GloMyAuth->get_runtime_checksum();
	ok(checksum3 != checksum2,
		"MySQL: checksum changes when password is modified");
}

// ============================================================================
// 6. MySQL_Authentication: Memory Usage
// ============================================================================

/**
 * @brief Test memory_usage() tracking.
 */
static void test_mysql_memory() {
	GloMyAuth->reset();

	unsigned int mem_empty = GloMyAuth->memory_usage();

	mysql_add_frontend(GloMyAuth, "memuser1", "password1");
	unsigned int mem_one = GloMyAuth->memory_usage();
	ok(mem_one > mem_empty,
		"MySQL: memory_usage() increases after add()");

	mysql_add_frontend(GloMyAuth, "memuser2", "password2_longer");
	unsigned int mem_two = GloMyAuth->memory_usage();
	ok(mem_two > mem_one,
		"MySQL: memory_usage() increases with more users");

	GloMyAuth->reset();
	unsigned int mem_after_reset = GloMyAuth->memory_usage();
	ok(mem_after_reset <= mem_empty,
		"MySQL: memory_usage() returns to baseline after reset()");
}

// ============================================================================
// 7. MySQL_Authentication: Frontend vs Backend Separation
// ============================================================================

/**
 * @brief Test that frontend and backend are independent.
 */
static void test_mysql_frontend_backend_separation() {
	GloMyAuth->reset();

	// Same username in both frontend and backend with different passwords
	mysql_add_frontend(GloMyAuth, "dualuser", "frontend_pass", 1);
	mysql_add_backend(GloMyAuth, "dualuser", "backend_pass", 2);

	dup_account_details_t dup = {false, false, false};

	account_details_t fe = GloMyAuth->lookup(
		(char *)"dualuser", USERNAME_FRONTEND, dup);
	ok(fe.password != nullptr && strcmp(fe.password, "frontend_pass") == 0,
		"MySQL: frontend lookup returns frontend password");
	ok(fe.default_hostgroup == 1,
		"MySQL: frontend lookup returns frontend hostgroup");

	account_details_t be = GloMyAuth->lookup(
		(char *)"dualuser", USERNAME_BACKEND, dup);
	ok(be.password != nullptr && strcmp(be.password, "backend_pass") == 0,
		"MySQL: backend lookup returns backend password");
	ok(be.default_hostgroup == 2,
		"MySQL: backend lookup returns backend hostgroup");

	free_account_details(fe);
	free_account_details(be);
}

static void test_mysql_spiffe_requires_ssl() {
	GloMyAuth->reset();

	mysql_add_frontend_with_attributes(
		GloMyAuth, "spiffe-user", false,
		R"({"spiffe_id":"spiffe://example.org/ns/default/sa/client"})");
	account_details_t account = GloMyAuth->lookup(
		(char *)"spiffe-user", USERNAME_FRONTEND, { false, false, false });
	ok(account.use_ssl, "MySQL: SPIFFE user requires TLS");
	free_account_details(account);

	mysql_add_frontend_with_attributes(
		GloMyAuth, "spiffe-user", false,
		R"({"spiffe_id":"spiffe://example.org/ns/default/sa/client"})");
	account = GloMyAuth->lookup(
		(char *)"spiffe-user", USERNAME_FRONTEND, { false, false, false });
	ok(account.use_ssl, "MySQL: SPIFFE user remains TLS-required on update");
	free_account_details(account);

	mysql_add_frontend_with_attributes(
		GloMyAuth, "plain-user", false, R"({"role":"client"})");
	account = GloMyAuth->lookup(
		(char *)"plain-user", USERNAME_FRONTEND, { false, false, false });
	ok(!account.use_ssl, "MySQL: non-SPIFFE user preserves explicit TLS setting");
	free_account_details(account);
}

static void test_mysql_invalid_spiffe_attributes_do_not_require_ssl() {
	GloMyAuth->reset();

	mysql_add_frontend_with_attributes(
		GloMyAuth, "invalid-spiffe-user", false, R"({"role":"client"})");
	mysql_add_frontend_with_attributes(
		GloMyAuth, "invalid-spiffe-user", false,
		R"({"spiffe_id":"spiffe://example.org/ns/default/sa/client","default-transaction_isolation":123})");
	account_details_t account = GloMyAuth->lookup(
		(char *)"invalid-spiffe-user", USERNAME_FRONTEND, { false, false, true });
	ok(!account.use_ssl, "MySQL: invalid SPIFFE attributes preserve explicit TLS setting");
	ok(account.attributes != nullptr && account.attributes[0] == '\0',
		"MySQL: invalid SPIFFE attributes are cleared");
	free_account_details(account);
}

static void test_mysql_spiffe_attributes_case_variant_requires_ssl() {
	GloMyAuth->reset();

	mysql_add_frontend_with_attributes(
		GloMyAuth, "case-variant-spiffe-user", false,
		R"({"spiffe_id":"spiffe://example.org/ns/default/sa/client"})");
	mysql_add_frontend_with_attributes(
		GloMyAuth, "case-variant-spiffe-user", false,
		R"({"SPIFFE_ID":"spiffe://example.org/ns/default/sa/client"})");
	account_details_t account = GloMyAuth->lookup(
		(char *)"case-variant-spiffe-user", USERNAME_FRONTEND,
		{ false, false, true });
	ok(account.use_ssl, "MySQL: retained SPIFFE attributes require TLS");
	ok(account.attributes != nullptr &&
		strcmp(account.attributes,
			R"({"spiffe_id":"spiffe://example.org/ns/default/sa/client"})") == 0,
		"MySQL: case-variant update retains recognized SPIFFE attributes");
	free_account_details(account);
}

static void test_mysql_spiffe_changed_attributes_toggle_ssl() {
	GloMyAuth->reset();

	mysql_add_frontend_with_attributes(
		GloMyAuth, "changed-spiffe-user", false, R"({"role":"client"})");
	mysql_add_frontend_with_attributes(
		GloMyAuth, "changed-spiffe-user", false,
		R"({"spiffe_id":"spiffe://example.org/ns/default/sa/client","role":"client"})");
	account_details_t account = GloMyAuth->lookup(
		(char *)"changed-spiffe-user", USERNAME_FRONTEND, { false, false, false });
	ok(account.use_ssl, "MySQL: changed SPIFFE attributes require TLS");
	free_account_details(account);

	mysql_add_frontend_with_attributes(
		GloMyAuth, "changed-spiffe-user", false, R"({"role":"updated"})");
	account = GloMyAuth->lookup(
		(char *)"changed-spiffe-user", USERNAME_FRONTEND, { false, false, false });
	ok(!account.use_ssl, "MySQL: changed non-SPIFFE attributes clear TLS requirement");
	free_account_details(account);
}

// ============================================================================
// 8. PgSQL_Authentication: Core CRUD
// ============================================================================

/**
 * @brief Test PgSQL basic add + exists + lookup cycle.
 */
static void test_pgsql_add_exists_lookup() {
	pgsql_add_frontend(GloPgAuth, "pg_alice", "pgpass", 1, 50);

	ok(GloPgAuth->exists((char *)"pg_alice") == true,
		"PgSQL: exists() returns true for added frontend user");
	ok(GloPgAuth->exists((char *)"pg_unknown") == false,
		"PgSQL: exists() returns false for nonexistent user");

	// PgSQL lookup has different signature — returns password string
	bool use_ssl = false;
	int default_hg = -1, max_conn = -1;
	bool trans_persist = false, fast_fwd = false;
	void *sha1 = nullptr;
	char *attrs = nullptr;

	char *password = GloPgAuth->lookup(
		(char *)"pg_alice", USERNAME_FRONTEND,
		&use_ssl, &default_hg, &trans_persist, &fast_fwd,
		&max_conn, &sha1, &attrs);

	ok(password != nullptr && strcmp(password, "pgpass") == 0,
		"PgSQL: lookup() returns correct password");
	ok(default_hg == 1,
		"PgSQL: lookup() returns correct default_hostgroup");
	ok(max_conn == 50,
		"PgSQL: lookup() returns correct max_connections");

	if (password) free(password);
	if (attrs) free(attrs);
	if (sha1) free(sha1);
}

/**
 * @brief Test PgSQL del() and reset().
 */
static void test_pgsql_del_and_reset() {
	pgsql_add_frontend(GloPgAuth, "pg_del", "pass");
	ok(GloPgAuth->exists((char *)"pg_del") == true,
		"PgSQL: user exists before del()");

	bool del_ok = GloPgAuth->del((char *)"pg_del", USERNAME_FRONTEND);
	ok(del_ok == true, "PgSQL: del() returns true");
	ok(GloPgAuth->exists((char *)"pg_del") == false,
		"PgSQL: user gone after del()");

	// Test reset
	pgsql_add_frontend(GloPgAuth, "pg_r1", "p1");
	pgsql_add_frontend(GloPgAuth, "pg_r2", "p2");
	GloPgAuth->reset();
	ok(GloPgAuth->exists((char *)"pg_r1") == false,
		"PgSQL: user gone after reset()");
}

/**
 * @brief Test PgSQL connection counting.
 */
static void test_pgsql_connection_counting() {
	GloPgAuth->reset();
	pgsql_add_frontend(GloPgAuth, "pg_conn", "pass", 0, 2);

	int r1 = GloPgAuth->increase_frontend_user_connections(
		(char *)"pg_conn");
	ok(r1 > 0, "PgSQL: 1st connection allowed");

	int r2 = GloPgAuth->increase_frontend_user_connections(
		(char *)"pg_conn");
	ok(r2 > 0, "PgSQL: 2nd connection allowed");

	int r3 = GloPgAuth->increase_frontend_user_connections(
		(char *)"pg_conn");
	ok(r3 == 0, "PgSQL: 3rd connection rejected (max=2)");

	GloPgAuth->decrease_frontend_user_connections((char *)"pg_conn");
	int r4 = GloPgAuth->increase_frontend_user_connections(
		(char *)"pg_conn");
	ok(r4 > 0, "PgSQL: connection allowed after decrease");
}

/**
 * @brief Test PgSQL inactive pattern.
 */
static void test_pgsql_inactive_pattern() {
	GloPgAuth->reset();
	pgsql_add_frontend(GloPgAuth, "pg_keep", "p1");
	pgsql_add_frontend(GloPgAuth, "pg_drop", "p2");

	GloPgAuth->set_all_inactive(USERNAME_FRONTEND);
	pgsql_add_frontend(GloPgAuth, "pg_keep", "p1");
	GloPgAuth->remove_inactives(USERNAME_FRONTEND);

	ok(GloPgAuth->exists((char *)"pg_keep") == true,
		"PgSQL: re-added user survives remove_inactives()");
	ok(GloPgAuth->exists((char *)"pg_drop") == false,
		"PgSQL: inactive user removed");
}


// ============================================================================
// Main
// ============================================================================

int main() {
	plan(69);

	test_init_minimal();
	test_init_auth();

	// MySQL tests
	test_mysql_add_exists_lookup();          // 5 tests
	test_mysql_exists_frontend_only();       // 2 tests
	test_mysql_add_overwrites();             // 3 tests
	test_mysql_del();                        // 4 tests
	test_mysql_lookup_not_found();           // 2 tests
	test_mysql_sha1();                       // 4 tests
	test_mysql_clear_text_password();        // 3 tests
	test_mysql_connection_counting();        // 5 tests
	test_mysql_inactive_pattern();           // 2 tests
	test_mysql_reset();                      // 2 tests
	test_mysql_checksums();                  // 4 tests
	test_mysql_memory();                     // 3 tests
	test_mysql_frontend_backend_separation();// 4 tests
	test_mysql_spiffe_requires_ssl();        // 3 tests
	test_mysql_invalid_spiffe_attributes_do_not_require_ssl(); // 2 tests
	test_mysql_spiffe_attributes_case_variant_requires_ssl(); // 2 tests
	test_mysql_spiffe_changed_attributes_toggle_ssl(); // 2 tests

	// PgSQL tests
	test_pgsql_add_exists_lookup();          // 5 tests
	test_pgsql_del_and_reset();              // 4 tests (49-52)
	test_pgsql_connection_counting();        // 4 tests (53-56)
	test_pgsql_inactive_pattern();           // 2 tests (57-58)
	// Note: PgSQL does not have set_clear_text_password()
	// Note: PgSQL does not have default_schema or schema_locked

	test_cleanup_auth();
	test_cleanup_minimal();

	return exit_status();
}
