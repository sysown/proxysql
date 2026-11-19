/**
 * @file azure_entra_policy_unit-t.cpp
 * @brief 'backend_auth' policy type 'azure_entra' (issue #6649).
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "MySQL_Authentication.hpp"
#include "MySQL_Backend_Auth.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

extern MySQL_Authentication *GloMyAuth;

static constexpr const char *kEntraAttrs = R"({"backend_auth":{"type":"azure_entra"}})";

/** add() a backend row and return what it logged on stderr. */
static std::string add_backend_user_log(const char *username, const char *password,
	const char *attributes) {
	std::string owned_username(username), owned_password(password), empty;
	std::string owned_attributes(attributes);
	FILE *captured = tmpfile();
	if (captured == nullptr) return "<tmpfile failed>";
	fflush(stderr);
	const int saved_stderr = dup(STDERR_FILENO);
	if (saved_stderr < 0 || dup2(fileno(captured), STDERR_FILENO) < 0) {
		fclose(captured);
		return "<stderr redirect failed>";
	}
	GloMyAuth->add(&owned_username[0], &owned_password[0], USERNAME_BACKEND,
		false, 0, &empty[0], false, false, false, 100, &owned_attributes[0], &empty[0]);
	fflush(stderr);
	dup2(saved_stderr, STDERR_FILENO);
	close(saved_stderr);
	std::string log;
	char buffer[256];
	rewind(captured);
	while (fgets(buffer, sizeof(buffer), captured) != nullptr) log += buffer;
	fclose(captured);
	return log;
}

static void test_parse() {
	const MySQLBackendAuthPolicy p = parse_mysql_backend_auth_policy("app", kEntraAttrs, true);
	ok(p.type == MySQLBackendAuthType::AZURE_ENTRA, "azure_entra selects AZURE_ENTRA");
	ok(p.database_user == "app", "policy keeps the backend username");
	ok(p.ignored_password, "a stored password is marked ignored");
	ok(!parse_mysql_backend_auth_policy("app", kEntraAttrs, false).ignored_password,
		"an empty password is not marked ignored");
	ok(strcmp(mysql_backend_auth_type_name(MySQLBackendAuthType::AZURE_ENTRA), "azure_entra") == 0,
		"type name is azure_entra");
	ok(parse_mysql_backend_auth_policy("app", R"({"backend_auth":{"type":"Azure_Entra"}})", false).type
		== MySQLBackendAuthType::INVALID, "type match is case-sensitive: unknown spelling fails closed");
}

static void test_uses_token() {
	ok(mysql_backend_auth_uses_token(MySQLBackendAuthType::AZURE_ENTRA) &&
		mysql_backend_auth_uses_token(MySQLBackendAuthType::AWS_IAM) &&
		!mysql_backend_auth_uses_token(MySQLBackendAuthType::PASSWORD) &&
		!mysql_backend_auth_uses_token(MySQLBackendAuthType::INVALID),
		"only AWS_IAM and AZURE_ENTRA use a token");
}

static void test_loaded_rows() {
	ok(!GloMyAuth->has_non_password_backend_auth(), "flag is clear before any token row");
	const std::string entra_log = add_backend_user_log("entra_app", "secret", kEntraAttrs);
	ok(GloMyAuth->has_non_password_backend_auth(), "an azure_entra row sets the fast-path flag");
	ok(entra_log.find("uses azure_entra authentication; clear the unused backend password")
		!= std::string::npos, "azure_entra row with a password warns");
	const std::string aws_log = add_backend_user_log("iam_app", "secret",
		R"({"backend_auth":{"type":"aws_iam"}})");
	ok(aws_log.find("uses aws_iam authentication; clear the unused backend password")
		!= std::string::npos, "aws_iam warning text is unchanged");
}

int main() {
	plan(11);
	test_init_minimal();
	test_init_auth();
	test_parse();
	test_uses_token();
	test_loaded_rows();
	test_cleanup_auth();
	test_cleanup_minimal();
	return exit_status();
}
