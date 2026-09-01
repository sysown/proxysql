/**
 * @file admin_bootstrap_users_unit-t.cpp
 * @brief Regression coverage for bootstrap user imports (issue #6159).
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "ProxySQL_Admin_Tables_Definitions.h"
#include "mysql.h"
#include "sqlite3db.h"

#include <array>
#include <cstring>
#include <string>
#include <vector>

bool import_bootstrap_users(SQLite3DB* db, MYSQL_RES* users, std::string& error);

namespace {

constexpr size_t USER_FIELD_COUNT = 5;
using user_row_t = std::array<std::string, USER_FIELD_COUNT>;

class mysql_result_fixture_t {
public:
	explicit mysql_result_fixture_t(const std::vector<user_row_t>& values)
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
	std::array<unsigned long, USER_FIELD_COUNT> lengths_ {};
	std::vector<std::vector<char>> buffers_;
	std::vector<std::array<char*, USER_FIELD_COUNT + 1>> row_ptrs_;
	std::vector<MYSQL_ROWS> rows_;
};

SQLite3_result* query(SQLite3DB& db, const char* sql) {
	char* error = nullptr;
	SQLite3_result* result = db.execute_statement(sql, &error);
	if (error != nullptr) {
		diag("Query failed: %s", error);
		free(error);
	}
	return result;
}

void test_import_preserves_sql_metacharacters() {
	SQLite3DB db;
	db.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	db.execute(ADMIN_SQLITE_TABLE_MYSQL_USERS);
	db.execute("INSERT INTO mysql_users (username,password) VALUES ('old_user','old_password')");

	const std::string username { "quoted\"user" };
	const std::string password {
		"$A$005$[:V=2k#\t\"SP+AgqtYBw6HA0wp/3.73nwB/oSh5eAzZxtu2Vc1SJMTrUTn8WLB"
	};
	mysql_result_fixture_t users {{
		{ username, "ANY", password, "caching_sha2_password", "N" },
		{ "plain_user", "", "plain_password", "mysql_native_password", "N" }
	}};

	std::string error;
	const bool imported = import_bootstrap_users(&db, users.get(), error);
	ok(imported, "bootstrap import accepts quotes and control characters: %s", error.c_str());
	ok(db.return_one_int("SELECT COUNT(*) FROM mysql_users") == 2,
		"bootstrap import atomically replaces the previous users");

	SQLite3_result* result = query(db,
		"SELECT username,password,use_ssl FROM mysql_users WHERE username='quoted\"user'");
	ok(result != nullptr && result->rows_count == 1,
		"bootstrap import stores a username containing a double quote");
	if (result != nullptr && result->rows_count == 1) {
		SQLite3_row* row = result->rows[0];
		ok(std::string(row->fields[0], row->sizes[0]) == username,
			"bootstrap import preserves the exact username bytes");
		ok(std::string(row->fields[1], row->sizes[1]) == password,
			"bootstrap import preserves the exact caching_sha2_password bytes");
		ok(strcmp(row->fields[2], "1") == 0,
			"bootstrap import maps a non-empty ssl_type to use_ssl=1");
	} else {
		ok(false, "bootstrap import preserves the exact username bytes");
		ok(false, "bootstrap import preserves the exact caching_sha2_password bytes");
		ok(false, "bootstrap import maps a non-empty ssl_type to use_ssl=1");
	}
	delete result;
}

void test_failed_import_rolls_back() {
	SQLite3DB db;
	db.open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
	db.execute(ADMIN_SQLITE_TABLE_MYSQL_USERS);
	db.execute("INSERT INTO mysql_users (username,password) VALUES ('old_user','old_password')");

	mysql_result_fixture_t users {{
		{ "duplicate", "", "first", "mysql_native_password", "N" },
		{ "duplicate", "", "second", "mysql_native_password", "N" }
	}};

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
	plan(10);
	test_init_minimal();

	test_import_preserves_sql_metacharacters();
	test_failed_import_rolls_back();

	test_cleanup_minimal();
	return exit_status();
}
