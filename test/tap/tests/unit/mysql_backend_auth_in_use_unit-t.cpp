/**
 * @file mysql_backend_auth_in_use_unit-t.cpp
 * @brief MySQL_Authentication::has_non_password_backend_auth().
 *
 * The flag lets the per-query backend auth policy resolution be skipped when no
 * backend row can resolve to anything but PASSWORD. These tests check:
 * - it is false with no users and with PASSWORD-only backend rows;
 * - any backend row with AWS IAM, or with a 'backend_auth' that fails closed
 *   (INVALID, also from rejected attributes), sets it; frontend rows do not;
 * - a reload that drops those rows (set_all_inactive/remove_inactives), and
 *   reset(), clear it again; del() alone leaves it set;
 * - replace_mysql_users_atomically() (PROXYSQL40) takes the replacement's value;
 * - while it is false, resolve_mysql_backend_auth_policy() still returns
 *   INVALID for a null username and PASSWORD with database_user otherwise.
 */

#ifndef PROXYSQL40
#error "mysql_backend_auth_in_use_unit-t tests v4.0 code: build it with PROXYSQL40=1"
#endif // PROXYSQL40

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "MySQL_Authentication.hpp"
#include "MySQL_Backend_Auth.h"
#include "sqlite3db.h"

#include <string>

extern MySQL_Authentication *GloMyAuth;

namespace {

const char k_iam[] = R"({"backend_auth":{"type":"aws_iam"}})";
const char k_unsupported[] = R"({"backend_auth":{"type":"kerberos"}})";
// Accepted by SQLite JSON_VALID, rejected by nlohmann: kept as rejected text.
const char k_rejected_iam[] = R"({"backend_auth":{"type":"aws_iam"},"a":1e400})";

bool add_user(const char* username, enum cred_username_type type, const char* attributes,
	const char* password = "") {
	std::string owned_username(username);
	std::string owned_password(password);
	std::string empty("");
	std::string owned_attributes(attributes);
	return GloMyAuth->add(
		&owned_username[0], &owned_password[0], type, false, 0, &empty[0], false, false, false, 100,
		&owned_attributes[0], &empty[0]);
}

bool del_user(const char* username, enum cred_username_type type) {
	std::string owned_username(username);
	return GloMyAuth->del(&owned_username[0], type);
}

bool in_use() { return GloMyAuth->has_non_password_backend_auth(); }

// Reload the backend rows the way ProxySQL_Admin does for LOAD MYSQL USERS.
void reload_backend_rows(std::initializer_list<std::pair<const char*, const char*>> rows) {
	GloMyAuth->set_all_inactive(USERNAME_BACKEND);
	for (const auto& r : rows) add_user(r.first, USERNAME_BACKEND, r.second);
	GloMyAuth->remove_inactives(USERNAME_BACKEND);
}

void test_password_only() {
	ok(!in_use(), "no users: no non-PASSWORD backend auth");
	add_user("pw_plain", USERNAME_BACKEND, "", "pw");
	add_user("pw_attrs", USERNAME_BACKEND, R"({"default-transaction_isolation":"READ COMMITTED"})", "pw");
	ok(!in_use(), "PASSWORD backend rows, with and without attributes, leave it false");
	add_user("fe_iam", USERNAME_FRONTEND, k_iam, "pw");
	ok(!in_use(), "a frontend row with backend_auth does not count");

	const MySQLBackendAuthPolicy p = resolve_mysql_backend_auth_policy(*GloMyAuth, "pw_plain");
	ok(p.type == MySQLBackendAuthType::PASSWORD && p.database_user == "pw_plain",
		"while false, the resolver returns PASSWORD with the database user");
	const MySQLBackendAuthPolicy unknown = resolve_mysql_backend_auth_policy(*GloMyAuth, "no_such_user");
	ok(unknown.type == MySQLBackendAuthType::PASSWORD, "while false, an unknown user resolves to PASSWORD");
	const MySQLBackendAuthPolicy null_user = resolve_mysql_backend_auth_policy(*GloMyAuth, nullptr);
	ok(null_user.type == MySQLBackendAuthType::INVALID && null_user.failure_code == "backend_user_not_found",
		"while false, a null username still resolves to INVALID");
}

void test_iam_row_sets_and_reload_clears() {
	add_user("iam_user", USERNAME_BACKEND, k_iam);
	ok(in_use(), "an AWS IAM backend row sets it");
	ok(resolve_mysql_backend_auth_policy(*GloMyAuth, "iam_user").type == MySQLBackendAuthType::AWS_IAM,
		"the IAM user resolves to AWS_IAM");
	ok(resolve_mysql_backend_auth_policy(*GloMyAuth, "pw_plain").type == MySQLBackendAuthType::PASSWORD,
		"a PASSWORD user still resolves to PASSWORD while it is set");

	reload_backend_rows({ { "pw_plain", "" }, { "iam_user", k_iam } });
	ok(in_use(), "a reload that keeps the IAM row keeps it set");
	reload_backend_rows({ { "pw_plain", "" }, { "iam_user", "" } });
	ok(!in_use(), "a reload that turns the IAM row into PASSWORD clears it");
	ok(resolve_mysql_backend_auth_policy(*GloMyAuth, "iam_user").type == MySQLBackendAuthType::PASSWORD,
		"the former IAM user resolves to PASSWORD");
}

void test_fail_closed_rows_set_it() {
	add_user("unsupported", USERNAME_BACKEND, k_unsupported);
	ok(in_use(), "an unsupported backend_auth type (INVALID) sets it");
	ok(resolve_mysql_backend_auth_policy(*GloMyAuth, "unsupported").type == MySQLBackendAuthType::INVALID,
		"the unsupported row still fails closed");
	reload_backend_rows({ { "pw_plain", "" } });
	ok(!in_use(), "removing the INVALID row clears it");

	add_user("rejected_iam", USERNAME_BACKEND, k_rejected_iam);
	ok(in_use(), "rejected attributes mentioning backend_auth set it");
	ok(resolve_mysql_backend_auth_policy(*GloMyAuth, "rejected_iam").type == MySQLBackendAuthType::INVALID,
		"the rejected row still fails closed");
	reload_backend_rows({ { "pw_plain", "" } });
	ok(!in_use(), "removing the rejected row clears it");
}

void test_del_and_reset() {
	add_user("iam_user", USERNAME_BACKEND, k_iam);
	const bool deleted = del_user("iam_user", USERNAME_BACKEND);
	ok(deleted && in_use(), "del() removes the row and leaves it set (conservative)");
	reload_backend_rows({ { "pw_plain", "" } });
	ok(!in_use(), "the next reload recomputes it");

	add_user("iam_user", USERNAME_BACKEND, k_iam);
	GloMyAuth->reset();
	ok(!in_use(), "reset() clears it");
}

// One backend+frontend row in the 13-column runtime layout.
bool replace_with(const char* username, const char* attributes) {
	SQLite3_result users(13);
	const char* row[13] = { username, "pw", "0", "0", "", "0", "0", "0", "1", "1", "100", attributes, "" };
	users.add_row(row);
	std::string error;
	return GloMyAuth->replace_mysql_users_atomically(users, error);
}

void test_atomic_replace() {
	ok(replace_with("iam_user", k_iam) && in_use(), "an atomic replace with an IAM row sets it");
	ok(replace_with("pw_plain", "") && !in_use(), "an atomic replace with PASSWORD rows clears it");
}

} // namespace

int main() {
	plan(6 + 6 + 6 + 3 + 2);
	test_init_minimal();
	test_init_auth();

	test_password_only();
	test_iam_row_sets_and_reload_clears();
	test_fail_closed_rows_set_it();
	test_del_and_reset();
	test_atomic_replace();

	test_cleanup_auth();
	test_cleanup_minimal();
	return exit_status();
}
