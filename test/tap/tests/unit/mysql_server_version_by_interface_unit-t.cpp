#include "tap.h"

#include "MySQL_Server_Version_By_Interface.h"

#include <string>

static void test_empty_catalog() {
	const auto parsed = parse_mysql_server_version_by_interface("{}");

	ok(parsed.accepted(), "an empty JSON object is accepted");
	ok(parsed.catalog != nullptr && parsed.catalog->empty(),
		"an empty JSON object publishes an empty catalog");
}

static void test_exact_interface_resolution() {
	const auto parsed = parse_mysql_server_version_by_interface(
		R"({"127.0.0.1:6033":"8.0.30-a","[::1]:6033":"8.0.31-v6","/tmp/proxysql.sock":"8.4.1-socket"})"
	);

	ok(parsed.accepted(), "a catalog with TCP and Unix interfaces is accepted");
	ok(parsed.catalog != nullptr && parsed.catalog->size() == 3,
		"every configured pair is retained");
	ok(resolve_mysql_server_version_for_interface(
		*parsed.catalog, "127.0.0.1:6033", "8.0.11") == "8.0.30-a",
		"an IPv4 interface resolves its mapped version");
	ok(resolve_mysql_server_version_for_interface(
		*parsed.catalog, "[::1]:6033", "8.0.11") == "8.0.31-v6",
		"an IPv6 interface resolves by its original bracketed text");
	ok(resolve_mysql_server_version_for_interface(
		*parsed.catalog, "/tmp/proxysql.sock", "8.0.11") == "8.4.1-socket",
		"a Unix socket resolves its mapped version");
	ok(resolve_mysql_server_version_for_interface(
		*parsed.catalog, "127.0.0.1:6034", "8.0.11") == "8.0.11",
		"an unmapped interface uses the scalar fallback");
	ok(resolve_mysql_server_version_for_interface(
		*parsed.catalog, "127.0.0.1:6033 ", "8.0.11") == "8.0.11",
		"interface lookup is exact and does not normalize text");
}

static void test_invalid_catalogs() {
	const auto malformed = parse_mysql_server_version_by_interface("{");
	ok(!malformed.accepted() && !malformed.error.empty(),
		"malformed JSON is rejected with an error");

	const auto array = parse_mysql_server_version_by_interface(R"(["8.0.30"])");
	ok(!array.accepted(), "a JSON array is rejected");

	const auto scalar = parse_mysql_server_version_by_interface(R"("8.0.30")");
	ok(!scalar.accepted(), "a JSON scalar is rejected");

	const auto number_value = parse_mysql_server_version_by_interface(
		R"({"127.0.0.1:6033":8030})"
	);
	ok(!number_value.accepted(), "a non-string version is rejected");

	const auto null_value = parse_mysql_server_version_by_interface(
		R"({"127.0.0.1:6033":null})"
	);
	ok(!null_value.accepted(), "a null version is rejected");

	const auto empty_key = parse_mysql_server_version_by_interface(R"({"":"8.0.30"})");
	ok(!empty_key.accepted(), "an empty interface key is rejected");

	const auto empty_value = parse_mysql_server_version_by_interface(
		R"({"127.0.0.1:6033":""})"
	);
	ok(!empty_value.accepted(), "an empty version is rejected");

	const auto nul_key = parse_mysql_server_version_by_interface(
		R"({"127.0.0.1\u0000:6033":"8.0.30"})"
	);
	ok(!nul_key.accepted(), "an interface key containing NUL is rejected");

	const auto nul_value = parse_mysql_server_version_by_interface(
		R"({"127.0.0.1:6033":"8.0\u0000.30"})"
	);
	ok(!nul_value.accepted(), "a version containing NUL is rejected");

	const auto duplicate = parse_mysql_server_version_by_interface(
		R"({"127.0.0.1:6033":"8.0.30","127.0.0.1:6033":"8.0.31"})"
	);
	ok(!duplicate.accepted(), "duplicate textual interface keys are rejected");
}

static void test_loose_correlation() {
	std::string json = "{";
	for (int i = 0; i < 1000; ++i) {
		if (i != 0) {
			json += ',';
		}
		json += "\"unused-interface-" + std::to_string(i) +
			"\":\"version-" + std::to_string(i) + "\"";
	}
	json += '}';

	const auto parsed = parse_mysql_server_version_by_interface(json);
	ok(parsed.accepted() && parsed.catalog != nullptr && parsed.catalog->size() == 1000,
		"a catalog can retain 1000 mappings without active-listener validation");
	ok(resolve_mysql_server_version_for_interface(
		*parsed.catalog, "unused-interface-999", "fallback") == "version-999",
		"a retained mapping resolves when its exact interface is requested");
	ok(resolve_mysql_server_version_for_interface(
		*parsed.catalog, "the-only-active-interface", "fallback") == "fallback",
		"an active interface absent from a large catalog still uses the fallback");
}

int main() {
	plan(22);

	test_empty_catalog();
	test_exact_interface_resolution();
	test_invalid_catalogs();
	test_loose_correlation();

	return exit_status();
}
