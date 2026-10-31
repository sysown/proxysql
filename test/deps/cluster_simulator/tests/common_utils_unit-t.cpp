#include <string>
#include <tuple>
#include <vector>

#include "common_utils.h"
#include "tap.h"

namespace {

server_status make_status_with_comment(const std::string& comment) {
	return std::make_tuple(
		10U,
		"127.0.0.1",
		3306U,
		"ONLINE",
		1,
		1000,
		0,
		comment,
		true
	);
}

std::vector<server_status> extract_status(
	const ordered_json& server,
	const char* description
) {
	const ordered_json test_definition {
		{ "proxysql_init_state", ordered_json::array({ server }) }
	};
	std::vector<server_status> result {};
	const auto extraction_result = extract_cluster_status(
		cluster_state::init_state,
		test_definition,
		result
	);

	ok(
		extraction_result.first == EXIT_SUCCESS,
		"%s",
		description
	);
	return result;
}

}  // namespace

int main() {
	plan(9);

	const server_status actual { make_status_with_comment("runtime comment") };
	const ordered_json base_server {
		{ "hostgroup_id", 10 },
		{ "hostname", "127.0.0.1" },
		{ "port", 3306 },
		{ "status", "ONLINE" }
	};
	const std::vector<server_status> omitted_status = extract_status(
		base_server,
		"a payload with an omitted comment is extracted"
	);
	ordered_json explicit_server = base_server;
	explicit_server["comment"] = "runtime comment";
	const std::vector<server_status> explicit_status = extract_status(
		explicit_server,
		"a payload with a nonempty comment is extracted"
	);
	ordered_json empty_server = base_server;
	empty_server["comment"] = "";
	const std::vector<server_status> empty_status = extract_status(
		empty_server,
		"a payload with an empty comment is extracted"
	);

	ok(
		matching_server_status(omitted_status.at(0), actual),
		"an omitted expected comment matches a runtime comment"
	);
	ok(
		matching_server_status(explicit_status.at(0), actual),
		"an explicit matching comment is accepted"
	);
	ok(
		!matching_server_status(make_status_with_comment("different"), actual),
		"an explicit different comment is rejected"
	);
	ok(
		!matching_server_status(empty_status.at(0), actual),
		"an explicitly empty comment is compared exactly"
	);

	const ordered_json omitted_json =
		cluster_status_to_json(omitted_status);
	ok(
		!omitted_json.at(0).contains("comment"),
		"an omitted comment stays omitted in diagnostic JSON"
	);

	const ordered_json specified_json =
		cluster_status_to_json(explicit_status);
	ok(
		specified_json.at(0).at("comment") == "runtime comment",
		"a specified comment is included in diagnostic JSON"
	);

	return exit_status();
}
