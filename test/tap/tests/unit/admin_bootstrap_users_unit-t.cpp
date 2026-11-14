/**
 * @file admin_bootstrap_users_unit-t.cpp
 * @brief Regression coverage for bootstrap user imports (issue #6159).
 */

#include "tap.h"

#ifdef PROXYSQL40

int main() {
	plan(1);
	skip(1, "legacy bootstrap-user import is replaced by plugin publication in PROXYSQL40");
	return exit_status();
}

#else

#include "test_globals.h"
#include "test_init.h"

#include "ProxySQL_Admin_Tables_Definitions.h"
#include "mysql.h"
#include "sqlite3db.h"

#include <array>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>

bool import_bootstrap_users(SQLite3DB* db, MYSQL_RES* users, std::string& error);

namespace {

constexpr size_t USER_FIELD_COUNT = 6;
using user_row_t = std::array<std::string, USER_FIELD_COUNT>;

// rows whose username field (index 0) becomes a real NULL pointer, which
// insert_bootstrap_user() rejects -- used to trigger genuine row failures.
constexpr size_t USER_FIELD_IDX = 0;

class MySQL_Result_Fixture {
public:
	explicit MySQL_Result_Fixture(const std::vector<user_row_t>& values,
		const std::vector<size_t>& null_user_rows = {})
		: buffers_(values.size()), row_ptrs_(values.size()), rows_(values.size()) {
		for (size_t row_idx = 0; row_idx < values.size(); ++row_idx) {
			size_t buffer_size = 0;
			for (const std::string& value : values[row_idx]) {
				buffer_size += value.size() + 1;
			}

			buffers_[row_idx].resize(buffer_size);
			size_t offset = 0;
			for (size_t field_idx = 0; field_idx < USER_FIELD_COUNT; ++field_idx) {
				const std::string& value = values[row_idx][field_idx];
				row_ptrs_[row_idx][field_idx] = buffers_[row_idx].data() + offset;
				memcpy(buffers_[row_idx].data() + offset, value.data(), value.size());
				offset += value.size();
				buffers_[row_idx][offset++] = '\0';
			}
			for (size_t null_idx : null_user_rows) {
				if (null_idx == row_idx) {
					row_ptrs_[row_idx][USER_FIELD_IDX] = nullptr;
				}
			}
			// MariaDB Connector/C derives buffered-result lengths from the next
			// field pointer, including this sentinel after the final field.
			row_ptrs_[row_idx][USER_FIELD_COUNT] = buffers_[row_idx].data() + offset;
			rows_[row_idx].data = row_ptrs_[row_idx].data();
			rows_[row_idx].next = row_idx + 1 < rows_.size() ? &rows_[row_idx + 1] : nullptr;
		}

		data_.data = rows_.empty() ? nullptr : rows_.data();
		data_.rows = rows_.size();
		data_.fields = USER_FIELD_COUNT;
		result_.field_count = USER_FIELD_COUNT;
		result_.row_count = rows_.size();
		result_.data = &data_;
		result_.data_cursor = data_.data;
		result_.lengths = lengths_.data();
	}

	MYSQL_RES* get() { return &result_; }

private:
	MYSQL_RES result_ {};
	MYSQL_DATA data_ {};
	// mysql_fetch_lengths() derives lengths from pointer offsets and writes one
	// entry past the last field (the sentinel column is part of the sweep), so
	// the buffer needs USER_FIELD_COUNT + 1 slots.
	std::array<unsigned long, USER_FIELD_COUNT + 1> lengths_ {};
	std::vector<std::vector<char>> buffers_;
	std::vector<std::array<char*, USER_FIELD_COUNT + 1>> row_ptrs_;
	std::vector<MYSQL_ROWS> rows_;
};

void test_import_preserves_sql_metacharacters() {
	SQLite3DB db;
	char db_path[] { ":memory:" };
	db.open(db_path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	db.execute(ADMIN_SQLITE_TABLE_MYSQL_USERS);
	db.execute("INSERT INTO mysql_users (username,password) VALUES ('old_user','old_password')");

	const std::string username { "quoted\"user" };
	const std::string auth_string {
		"$A$005$[:V=2k#\t\"SP+AgqtYBw6HA0wp/3.73nwB/oSh5eAzZxtu2Vc1SJMTrUTn8WLB"
	};
	MySQL_Result_Fixture users {{
		{ username, "ANY", auth_string, "caching_sha2_password", "N", "%" },
		{ "plain_user", "", "plain_password", "mysql_native_password", "N", "%" }
	}};
	// Bootstrap import must not depend on whether another reader inspected the result.
	mysql_fetch_row(users.get());

	std::string error;
	const bool imported = import_bootstrap_users(&db, users.get(), error);
	ok(imported, "bootstrap import accepts quotes and control characters: %s", error.c_str());
	ok(db.return_one_int("SELECT COUNT(*) FROM mysql_users") == 2,
		"bootstrap import atomically replaces the previous users");

	std::unique_ptr<SQLite3_result> result { db.execute_statement(
		"SELECT username,password,use_ssl FROM mysql_users WHERE username='quoted\"user'"
	) };
	ok(result != nullptr && result->rows_count == 1,
		"bootstrap import stores a username containing a double quote");
	if (result != nullptr && result->rows_count == 1) {
		SQLite3_row* row = result->rows[0];
		ok(std::string(row->fields[0], row->sizes[0]) == username,
			"bootstrap import preserves the exact username bytes");
		ok(std::string(row->fields[1], row->sizes[1]) == auth_string,
			"bootstrap import preserves the exact caching_sha2_password bytes");
		ok(strcmp(row->fields[2], "1") == 0,
			"bootstrap import maps a non-empty ssl_type to use_ssl=1");
	} else {
		ok(false, "bootstrap import preserves the exact username bytes");
		ok(false, "bootstrap import preserves the exact caching_sha2_password bytes");
		ok(false, "bootstrap import maps a non-empty ssl_type to use_ssl=1");
	}
}

// A duplicate username is a legal mysql.user shape (one account per host, and
// caching_sha2_password salts make the credential columns differ). It must
// import exactly one account, preferring the wildcard host, and start up.
void test_duplicate_username_imports_single_account() {
	SQLite3DB db;
	char db_path[] { ":memory:" };
	db.open(db_path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	db.execute(ADMIN_SQLITE_TABLE_MYSQL_USERS);

	// The wildcard row comes first, as BOOTSTRAP_SELECT_USERS orders it.
	MySQL_Result_Fixture users {{
		{ "duplicate", "", "first", "mysql_native_password", "N", "%" },
		{ "duplicate", "", "second", "mysql_native_password", "N", "localhost" }
	}};

	std::string error;
	const bool imported = import_bootstrap_users(&db, users.get(), error);
	ok(imported, "bootstrap import accepts a username defined under several hosts: %s", error.c_str());
	ok(db.return_one_int("SELECT COUNT(*) FROM mysql_users WHERE username='duplicate'") == 1,
		"bootstrap import stores exactly one row per username");

	std::unique_ptr<SQLite3_result> result { db.execute_statement(
		"SELECT password FROM mysql_users WHERE username='duplicate'"
	) };
	ok(result != nullptr && result->rows_count == 1 &&
		std::string(result->rows[0]->fields[0], result->rows[0]->sizes[0]) == "first",
		"bootstrap import keeps the deterministic first row (wildcard host)");
}

// The wildcard preference is enforced in the importer, not only by the SQL
// ORDER BY: a '%' row arriving after the others must still win.
void test_duplicate_username_prefers_wildcard_host() {
	SQLite3DB db;
	char db_path[] { ":memory:" };
	db.open(db_path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	db.execute(ADMIN_SQLITE_TABLE_MYSQL_USERS);

	MySQL_Result_Fixture users {{
		{ "late_wildcard", "", "local_pw", "mysql_native_password", "N", "localhost" },
		{ "late_wildcard", "", "wildcard_pw", "mysql_native_password", "N", "%" }
	}};

	std::string error;
	const bool imported = import_bootstrap_users(&db, users.get(), error);
	ok(imported, "bootstrap import succeeds when the wildcard row arrives last: %s", error.c_str());

	std::unique_ptr<SQLite3_result> result { db.execute_statement(
		"SELECT password FROM mysql_users WHERE username='late_wildcard'"
	) };
	ok(result != nullptr && result->rows_count == 1 &&
		std::string(result->rows[0]->fields[0], result->rows[0]->sizes[0]) == "wildcard_pw",
		"bootstrap import prefers the wildcard-host credentials");
}

/**
 * @brief Run import_bootstrap_users() with stderr captured into @p log, where
 *   proxy_warning() writes in the unit harness.
 */
bool import_capturing_stderr(SQLite3DB* db, MYSQL_RES* users, std::string& error, std::string& log) {
	FILE* captured = tmpfile();
	if (captured == nullptr) {
		error = "tmpfile() failed";
		return false;
	}
	fflush(stderr);
	const int saved_stderr = dup(STDERR_FILENO);
	if (saved_stderr < 0 || dup2(fileno(captured), STDERR_FILENO) < 0) {
		if (saved_stderr >= 0) close(saved_stderr);
		fclose(captured);
		error = "stderr redirection failed";
		return false;
	}
	const bool imported = import_bootstrap_users(db, users, error);
	fflush(stderr);
	dup2(saved_stderr, STDERR_FILENO);
	close(saved_stderr);

	char buffer[512];
	rewind(captured);
	while (fgets(buffer, sizeof(buffer), captured) != nullptr) {
		log += buffer;
	}
	fclose(captured);
	return imported;
}

void open_users_db(SQLite3DB& db) {
	char db_path[] { ":memory:" };
	db.open(db_path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	db.execute(ADMIN_SQLITE_TABLE_MYSQL_USERS);
}

// Issue #6427: the skipped-host warning must be logged only when accounts of
// other hosts were really skipped, and list only those hosts. The '%' row
// imported by the first pass used to be re-read by the second pass and listed
// as "skipped", so every user with a '%' account warned, even with one host.
void test_single_wildcard_host_does_not_warn() {
	SQLite3DB db;
	open_users_db(db);
	MySQL_Result_Fixture users {{
		{ "only_wildcard", "", "secret_pw_1", "mysql_native_password", "N", "%" },
		{ "other_user", "", "secret_pw_2", "mysql_native_password", "N", "%" }
	}};

	std::string error;
	std::string log;
	ok(import_capturing_stderr(&db, users.get(), error, log),
		"bootstrap import of single-host '%%' users succeeds: %s", error.c_str());
	ok(log.find("exists for multiple hosts") == std::string::npos,
		"a user with only a '%%' account does not log the multiple-hosts warning");
}

void test_wildcard_plus_other_hosts_lists_only_skipped_hosts() {
	SQLite3DB db;
	open_users_db(db);
	// BOOTSTRAP_SELECT_USERS order: ORDER BY user, host<>'%', host
	MySQL_Result_Fixture users {{
		{ "multi", "", "wildcard_secret", "mysql_native_password", "N", "%" },
		{ "multi", "", "net_secret", "mysql_native_password", "N", "10.0.0.%" },
		{ "multi", "", "local_secret", "mysql_native_password", "N", "localhost" }
	}};

	std::string error;
	std::string log;
	ok(import_capturing_stderr(&db, users.get(), error, log),
		"bootstrap import of a '%%' user with other hosts succeeds: %s", error.c_str());
	ok(log.find("Bootstrap: user 'multi' exists for multiple hosts; imported credentials of "
		"'multi'@'%' only, skipped host(s): '10.0.0.%', 'localhost'\n") != std::string::npos,
		"the warning names the imported '%%' account and lists only the skipped hosts");
	ok(log.find("'%', ") == std::string::npos && log.find(", '%'") == std::string::npos,
		"the imported '%%' host is not listed among the skipped hosts");
	ok(log.find("_secret") == std::string::npos,
		"the warning does not contain credential material");
}

void test_no_wildcard_host_imports_first_host() {
	SQLite3DB db;
	open_users_db(db);
	// Without '%', ORDER BY user, host<>'%', host makes the lowest host first.
	MySQL_Result_Fixture users {{
		{ "nowild", "", "first_secret", "mysql_native_password", "N", "10.0.0.1" },
		{ "nowild", "", "second_secret", "mysql_native_password", "N", "localhost" }
	}};

	std::string error;
	std::string log;
	ok(import_capturing_stderr(&db, users.get(), error, log),
		"bootstrap import of a user without a '%%' account succeeds: %s", error.c_str());
	std::unique_ptr<SQLite3_result> result { db.execute_statement(
		"SELECT password FROM mysql_users WHERE username='nowild'"
	) };
	ok(result != nullptr && result->rows_count == 1 &&
		std::string(result->rows[0]->fields[0], result->rows[0]->sizes[0]) == "first_secret",
		"without a '%%' account the first host in ORDER BY order is imported");
	ok(log.find("Bootstrap: user 'nowild' exists for multiple hosts; imported credentials of "
		"'nowild'@'10.0.0.1' only, skipped host(s): 'localhost'\n") != std::string::npos,
		"the warning names the imported host and lists only the skipped host");
	ok(log.find("_secret") == std::string::npos,
		"the warning does not contain credential material");
}

void test_failed_import_rolls_back() {
	SQLite3DB db;
	char db_path[] { ":memory:" };
	db.open(db_path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	db.execute(ADMIN_SQLITE_TABLE_MYSQL_USERS);
	db.execute("INSERT INTO mysql_users (username,password) VALUES ('old_user','old_password')");

	// Duplicate usernames are legal input now -- a row whose username is NULL is
	// the genuine-failure trigger (insert_bootstrap_user rejects it).
	MySQL_Result_Fixture users {{
		{ "", "", "good", "mysql_native_password", "N", "%" },
		{ "valid_user", "", "valid", "mysql_native_password", "N", "%" }
	}, std::vector<size_t> { 0 }};

	std::string error;
	const bool imported = import_bootstrap_users(&db, users.get(), error);
	ok(!imported, "bootstrap import reports a row insertion failure");
	ok(!error.empty(), "bootstrap import supplies an error for a failed row");
	ok(db.return_one_int("SELECT COUNT(*) FROM mysql_users") == 1,
		"failed bootstrap import preserves the previous user set");
	ok(db.return_one_int("SELECT COUNT(*) FROM mysql_users WHERE username='old_user'") == 1,
		"failed bootstrap import rolls back the initial delete");
}

} // namespace

int main() {
	plan(25);
	test_init_minimal();

	test_import_preserves_sql_metacharacters();
	test_duplicate_username_imports_single_account();
	test_duplicate_username_prefers_wildcard_host();
	test_failed_import_rolls_back();
	test_single_wildcard_host_does_not_warn();
	test_wildcard_plus_other_hosts_lists_only_skipped_hosts();
	test_no_wildcard_host_imports_first_host();

	test_cleanup_minimal();
	return exit_status();
}

#endif
