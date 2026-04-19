/**
 * @file charset_find_unit-t.cpp
 * @brief Unit tests for the four charset lookup functions in proxysql_find_charset.cpp.
 *
 * Tests:
 *   - proxysql_find_charset_nr()
 *   - proxysql_find_charset_name()
 *   - proxysql_find_charset_collate_names()
 *   - proxysql_find_charset_collate()
 *
 * These are pure lookup functions over the static mariadb_compiled_charsets table.
 * Coverage gaps addressed: NULL return paths, utf8mb3 translation, edge cases.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "proxysql_find_charset.h"

// ============================================================================
// 1. proxysql_find_charset_nr — lookup by charset number
// ============================================================================

static void test_find_charset_nr_known() {
	const MARIADB_CHARSET_INFO *c;

	c = proxysql_find_charset_nr(33);
	ok(c != NULL, "nr(33) returns non-NULL");
	ok(c != NULL && strcmp(c->csname, "utf8") == 0,
		"nr(33) csname is utf8");
	ok(c != NULL && strcmp(c->name, "utf8_general_ci") == 0,
		"nr(33) collation is utf8_general_ci");

	c = proxysql_find_charset_nr(45);
	ok(c != NULL, "nr(45) returns non-NULL");
	ok(c != NULL && strcmp(c->csname, "utf8mb4") == 0,
		"nr(45) csname is utf8mb4");

	c = proxysql_find_charset_nr(63);
	ok(c != NULL, "nr(63) returns non-NULL");
	ok(c != NULL && strcmp(c->csname, "binary") == 0,
		"nr(63) csname is binary");

	c = proxysql_find_charset_nr(8);
	ok(c != NULL, "nr(8) returns non-NULL");
	ok(c != NULL && strcmp(c->csname, "latin1") == 0,
		"nr(8) csname is latin1");
}

static void test_find_charset_nr_not_found() {
	const MARIADB_CHARSET_INFO *c;

	c = proxysql_find_charset_nr(99999);
	ok(c == NULL, "nr(99999) returns NULL for non-existent charset");

	c = proxysql_find_charset_nr(0);
	ok(c == NULL, "nr(0) returns NULL (0 is the sentinel)");
}

// ============================================================================
// 2. proxysql_find_charset_name — lookup by charset name
// ============================================================================

static void test_find_charset_name_known() {
	MARIADB_CHARSET_INFO *c;

	// Set default collation to NULL so we get first match and break immediately
	mysql_thread___default_variables[SQL_COLLATION_CONNECTION] = NULL;

	c = proxysql_find_charset_name("utf8");
	ok(c != NULL, "name('utf8') returns non-NULL");
	ok(c != NULL && strcmp(c->csname, "utf8") == 0,
		"name('utf8') csname is utf8");

	c = proxysql_find_charset_name("utf8mb4");
	ok(c != NULL, "name('utf8mb4') returns non-NULL");
	ok(c != NULL && strcmp(c->csname, "utf8mb4") == 0,
		"name('utf8mb4') csname is utf8mb4");

	c = proxysql_find_charset_name("latin1");
	ok(c != NULL, "name('latin1') returns non-NULL");
	ok(c != NULL && strcmp(c->csname, "latin1") == 0,
		"name('latin1') csname is latin1");

	c = proxysql_find_charset_name("binary");
	ok(c != NULL, "name('binary') returns non-NULL");
	ok(c != NULL && strcmp(c->csname, "binary") == 0,
		"name('binary') csname is binary");
}

static void test_find_charset_name_not_found() {
	mysql_thread___default_variables[SQL_COLLATION_CONNECTION] = NULL;

	MARIADB_CHARSET_INFO *c = proxysql_find_charset_name("nonexistent_charset");
	ok(c == NULL, "name('nonexistent_charset') returns NULL");
}

static void test_find_charset_name_utf8mb3() {
	mysql_thread___default_variables[SQL_COLLATION_CONNECTION] = NULL;

	MARIADB_CHARSET_INFO *c = proxysql_find_charset_name("utf8mb3");
	ok(c != NULL, "name('utf8mb3') returns non-NULL (translates to utf8)");
	ok(c != NULL && strcmp(c->csname, "utf8") == 0,
		"name('utf8mb3') csname resolves to utf8");
}

static void test_find_charset_name_case_insensitive() {
	mysql_thread___default_variables[SQL_COLLATION_CONNECTION] = NULL;

	MARIADB_CHARSET_INFO *c;

	c = proxysql_find_charset_name("UTF8");
	ok(c != NULL, "name('UTF8') case-insensitive returns non-NULL");
	ok(c != NULL && strcmp(c->csname, "utf8") == 0,
		"name('UTF8') csname is utf8");

	c = proxysql_find_charset_name("Latin1");
	ok(c != NULL, "name('Latin1') case-insensitive returns non-NULL");

	c = proxysql_find_charset_name("UTF8MB3");
	ok(c != NULL, "name('UTF8MB3') case-insensitive utf8mb3 translation");
	ok(c != NULL && strcmp(c->csname, "utf8") == 0,
		"name('UTF8MB3') resolves to utf8");
}

static void test_find_charset_name_with_collation() {
	// When default_collation is set, proxysql_find_charset_name should
	// prefer the matching collation entry
	mysql_thread___default_variables[SQL_COLLATION_CONNECTION] =
		(char *)"utf8_bin";

	MARIADB_CHARSET_INFO *c = proxysql_find_charset_name("utf8");
	ok(c != NULL, "name('utf8') with collation 'utf8_bin' returns non-NULL");
	ok(c != NULL && strcmp(c->name, "utf8_bin") == 0,
		"name('utf8') with collation prefers utf8_bin");

	// If collation doesn't match any entry, should return first found
	mysql_thread___default_variables[SQL_COLLATION_CONNECTION] =
		(char *)"nonexistent_collation";

	c = proxysql_find_charset_name("utf8");
	ok(c != NULL, "name('utf8') with non-matching collation returns non-NULL");
	ok(c != NULL && strcmp(c->csname, "utf8") == 0,
		"name('utf8') with non-matching collation falls back to first match");
}

// ============================================================================
// 3. proxysql_find_charset_collate_names — lookup by charset + collation name
// ============================================================================

static void test_find_charset_collate_names_known() {
	MARIADB_CHARSET_INFO *c;

	c = proxysql_find_charset_collate_names("utf8", "utf8_general_ci");
	ok(c != NULL, "collate_names('utf8','utf8_general_ci') returns non-NULL");
	ok(c != NULL && c->nr == 33,
		"collate_names('utf8','utf8_general_ci') nr is 33");

	c = proxysql_find_charset_collate_names("utf8mb4", "utf8mb4_general_ci");
	ok(c != NULL, "collate_names('utf8mb4','utf8mb4_general_ci') returns non-NULL");
	ok(c != NULL && c->nr == 45,
		"collate_names('utf8mb4','utf8mb4_general_ci') nr is 45");

	c = proxysql_find_charset_collate_names("latin1", "latin1_swedish_ci");
	ok(c != NULL, "collate_names('latin1','latin1_swedish_ci') returns non-NULL");
	ok(c != NULL && c->nr == 8,
		"collate_names('latin1','latin1_swedish_ci') nr is 8");
}

static void test_find_charset_collate_names_not_found() {
	MARIADB_CHARSET_INFO *c;

	c = proxysql_find_charset_collate_names("utf8", "nonexistent_collation");
	ok(c == NULL, "collate_names('utf8','nonexistent') returns NULL");

	c = proxysql_find_charset_collate_names("nonexistent", "utf8_general_ci");
	ok(c == NULL, "collate_names('nonexistent','utf8_general_ci') returns NULL");

	c = proxysql_find_charset_collate_names("nonexistent", "also_nonexistent");
	ok(c == NULL, "collate_names both non-existent returns NULL");
}

static void test_find_charset_collate_names_utf8mb3() {
	MARIADB_CHARSET_INFO *c;

	// utf8mb3 csname should translate to utf8
	c = proxysql_find_charset_collate_names("utf8mb3", "utf8_general_ci");
	ok(c != NULL, "collate_names('utf8mb3','utf8_general_ci') returns non-NULL");
	ok(c != NULL && c->nr == 33,
		"collate_names('utf8mb3','utf8_general_ci') nr is 33");

	// utf8mb3 in collation name should also translate
	c = proxysql_find_charset_collate_names("utf8", "utf8mb3_general_ci");
	ok(c != NULL, "collate_names('utf8','utf8mb3_general_ci') returns non-NULL");
	ok(c != NULL && c->nr == 33,
		"collate_names('utf8','utf8mb3_general_ci') nr is 33");

	// Both utf8mb3
	c = proxysql_find_charset_collate_names("utf8mb3", "utf8mb3_general_ci");
	ok(c != NULL, "collate_names('utf8mb3','utf8mb3_general_ci') returns non-NULL");
	ok(c != NULL && c->nr == 33,
		"collate_names('utf8mb3','utf8mb3_general_ci') nr is 33");
}

static void test_find_charset_collate_names_case_insensitive() {
	MARIADB_CHARSET_INFO *c;

	c = proxysql_find_charset_collate_names("UTF8", "UTF8_GENERAL_CI");
	ok(c != NULL, "collate_names case-insensitive returns non-NULL");
	ok(c != NULL && c->nr == 33,
		"collate_names case-insensitive nr is 33");
}

// ============================================================================
// 4. proxysql_find_charset_collate — lookup by collation name only
// ============================================================================

static void test_find_charset_collate_known() {
	MARIADB_CHARSET_INFO *c;

	c = proxysql_find_charset_collate("utf8_general_ci");
	ok(c != NULL, "collate('utf8_general_ci') returns non-NULL");
	ok(c != NULL && c->nr == 33,
		"collate('utf8_general_ci') nr is 33");

	c = proxysql_find_charset_collate("utf8mb4_general_ci");
	ok(c != NULL, "collate('utf8mb4_general_ci') returns non-NULL");
	ok(c != NULL && c->nr == 45,
		"collate('utf8mb4_general_ci') nr is 45");

	c = proxysql_find_charset_collate("binary");
	ok(c != NULL, "collate('binary') returns non-NULL");
	ok(c != NULL && c->nr == 63,
		"collate('binary') nr is 63");

	c = proxysql_find_charset_collate("latin1_swedish_ci");
	ok(c != NULL, "collate('latin1_swedish_ci') returns non-NULL");
	ok(c != NULL && c->nr == 8,
		"collate('latin1_swedish_ci') nr is 8");
}

static void test_find_charset_collate_not_found() {
	MARIADB_CHARSET_INFO *c;

	c = proxysql_find_charset_collate("nonexistent_collation");
	ok(c == NULL, "collate('nonexistent_collation') returns NULL");

	c = proxysql_find_charset_collate("");
	ok(c == NULL, "collate('') empty string returns NULL");
}

static void test_find_charset_collate_case_insensitive() {
	MARIADB_CHARSET_INFO *c;

	c = proxysql_find_charset_collate("UTF8_GENERAL_CI");
	ok(c != NULL, "collate('UTF8_GENERAL_CI') case-insensitive returns non-NULL");
	ok(c != NULL && c->nr == 33,
		"collate('UTF8_GENERAL_CI') case-insensitive nr is 33");

	c = proxysql_find_charset_collate("Utf8mb4_General_Ci");
	ok(c != NULL, "collate('Utf8mb4_General_Ci') mixed case returns non-NULL");
}

// ============================================================================
// Main
// ============================================================================

int main() {
	plan(62);
	int rc = test_init_minimal();
	ok(rc == 0, "test_init_minimal() succeeds");

	// 1. proxysql_find_charset_nr
	test_find_charset_nr_known();          // 9
	test_find_charset_nr_not_found();      // 2

	// 2. proxysql_find_charset_name
	test_find_charset_name_known();        // 8
	test_find_charset_name_not_found();    // 1
	test_find_charset_name_utf8mb3();      // 2
	test_find_charset_name_case_insensitive(); // 5
	test_find_charset_name_with_collation(); // 4

	// 3. proxysql_find_charset_collate_names
	test_find_charset_collate_names_known();          // 6
	test_find_charset_collate_names_not_found();      // 3
	test_find_charset_collate_names_utf8mb3();        // 6
	test_find_charset_collate_names_case_insensitive(); // 2

	// 4. proxysql_find_charset_collate
	test_find_charset_collate_known();          // 8
	test_find_charset_collate_not_found();      // 2
	test_find_charset_collate_case_insensitive(); // 3

	// Reset thread-local to avoid any leaks
	mysql_thread___default_variables[SQL_COLLATION_CONNECTION] = NULL;

	test_cleanup_minimal();
	return exit_status();
}
