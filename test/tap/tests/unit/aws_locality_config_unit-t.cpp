#include "tap.h"
#include "test_globals.h"

#include "Aws_Locality_Manager.h"
#include "MySQL_HostGroups_Manager.h"
#include "MySQL_Thread.h"
#include "proxysql_utils.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>

void init_myhgc_hostgroup_settings(const char* hostgroup_settings, MyHGC* myhgc);

namespace {

bool contains_variable(char** variables, const char* expected) {
	for (char** item = variables; item != nullptr && *item != nullptr; ++item) {
		if (strcmp(*item, expected) == 0) {
			return true;
		}
	}
	return false;
}

void free_variables(char** variables) {
	if (variables == nullptr) {
		return;
	}
	for (char** item = variables; *item != nullptr; ++item) {
		free(*item);
	}
	free(variables);
}

std::string capture_invalid_policy_log(MyHGC& hostgroup) {
	FILE* captured = tmpfile();
	if (captured == nullptr) {
		return {};
	}
	fflush(stderr);
	const int saved_stderr = dup(STDERR_FILENO);
	if (saved_stderr < 0 || dup2(fileno(captured), STDERR_FILENO) < 0) {
		if (saved_stderr >= 0) {
			close(saved_stderr);
		}
		fclose(captured);
		return {};
	}

	init_myhgc_hostgroup_settings(
		R"({"aws":{"locality_awareness":{"same_region_multiplier":2.0,"same_az_multiplier":"FAKE_SECRET_MULTIPLIER"}}})",
		&hostgroup);
	fflush(stderr);
	dup2(saved_stderr, STDERR_FILENO);
	close(saved_stderr);

	std::string output;
	char buffer[256];
	rewind(captured);
	while (fgets(buffer, sizeof(buffer), captured) != nullptr) {
		output += buffer;
	}
	fclose(captured);
	return output;
}

} // namespace

int main() {
	plan(21);

	MyHGC hostgroup(42);
	init_myhgc_hostgroup_settings(
		R"({"aws_iam_region":"us-east-1","aws":{"locality_awareness":{"same_region_multiplier":2.5,"same_az_multiplier":4.75}}})",
		&hostgroup);
	ok(hostgroup.attributes.aws_locality_policy.valid,
		"valid nested AWS locality policy is owned by the hostgroup");
	ok(hostgroup.attributes.aws_locality_policy.same_region_multiplier == 2.5 &&
		hostgroup.attributes.aws_locality_policy.same_az_multiplier == 4.75,
		"hostgroup retains both floating-point multipliers");
	ok(hostgroup.attributes.aws_locality_policy.refresh_interval_seconds == 300 &&
		hostgroup.attributes.aws_locality_policy.stale_ttl_seconds == 1800,
		"hostgroup policy receives the documented timing defaults");
	ok(hostgroup.attributes.aws_iam_region != nullptr &&
		strcmp(hostgroup.attributes.aws_iam_region, "us-east-1") == 0,
		"locality policy does not alter the independent IAM authentication Region");

	init_myhgc_hostgroup_settings(
		R"({"aws":{"locality_awareness":{"same_region_multiplier":1.0,"same_az_multiplier":10.0,"refresh_interval_seconds":30,"stale_ttl_seconds":604800}}})",
		&hostgroup);
	ok(hostgroup.attributes.aws_locality_policy.valid &&
		hostgroup.attributes.aws_locality_policy.refresh_interval_seconds == 30 &&
		hostgroup.attributes.aws_locality_policy.stale_ttl_seconds == 604800,
		"inclusive policy bounds survive hostgroup parsing");

	init_myhgc_hostgroup_settings(
		R"({"aws":{"locality_awareness":{"same_region_multiplier":5.0,"same_az_multiplier":4.0}}})",
		&hostgroup);
	ok(!hostgroup.attributes.aws_locality_policy.valid,
		"invalid reload clears the previously accepted policy");
	init_myhgc_hostgroup_settings(R"({"aws":[]})", &hostgroup);
	ok(!hostgroup.attributes.aws_locality_policy.valid,
		"non-object AWS settings remain disabled");
	init_myhgc_hostgroup_settings("{}", &hostgroup);
	ok(!hostgroup.attributes.aws_locality_policy.valid,
		"removing locality settings removes the runtime policy");

	const std::string diagnostics = capture_invalid_policy_log(hostgroup);
	ok(diagnostics.find("hostgroup 42") != std::string::npos &&
		diagnostics.find("same_az_multiplier") != std::string::npos,
		"invalid locality diagnostic identifies only hostgroup and field");
	ok(diagnostics.find("FAKE_SECRET_MULTIPLIER") == std::string::npos,
		"invalid locality diagnostic never prints the hostgroup JSON payload");
	ok(!hostgroup.attributes.aws_locality_policy.valid,
		"rejected diagnostic case leaves no active locality policy");

	test_globals_init();
	{
		MySQL_Threads_Handler handler;
		char** variables = handler.get_variables_list();
#ifdef PROXYSQL31
		handler.set_variable("caching_sha2_password_auto_generate_rsa_keys", "false");
		handler.set_variable("caching_sha2_password_private_key_path", "");
		handler.set_variable("caching_sha2_password_public_key_path", "");
#endif
		mf_unique_ptr<char> default_value { handler.get_variable("aws_locality_awareness") };
		ok(contains_variable(variables, "aws_locality_awareness"),
			"v4 MySQL variable list exposes aws_locality_awareness");
		ok(default_value != nullptr && strcmp(default_value.get(), "false") == 0,
			"aws_locality_awareness defaults to false");
		ok(handler.set_variable("aws_locality_awareness", "true") &&
			handler.get_variable_int("aws_locality_awareness") == 1,
			"master switch accepts true");
		ok(handler.set_variable("AWS_LOCALITY_AWARENESS", "0") &&
			handler.get_variable_int("aws_locality_awareness") == 0,
			"master switch is case-insensitive and accepts zero");
		ok(!handler.set_variable("aws_locality_awareness", "yes") &&
			handler.get_variable_int("aws_locality_awareness") == 0,
			"master switch rejects non-boolean spelling");
		handler.set_variable("aws_locality_awareness", "1");
		ok(handler.commit().rejected_variables.empty() &&
			handler.get_variable_int("aws_locality_awareness") == 1,
			"MySQL variable commit preserves the accepted master switch");
		free_variables(variables);
	}
	test_globals_cleanup();

	auto refresh_method = &MySQL_HostGroups_Manager::refresh_aws_locality_configuration;
	ok(refresh_method != nullptr,
		"Hostgroup Manager exposes the post-commit locality refresh boundary");

	GloVars.prometheus_registry = std::make_shared<prometheus::Registry>();
	{
		MySQL_HostGroups_Manager manager;
		MySQL_HostGroups_Manager *previous_hgm = MyHGM;
		MyHGM = &manager;
		srv_info_t info;
		info.addr = "db.abcdef.us-east-1.rds.amazonaws.com";
		info.port = 3306;
		info.kind = "AWS locality test";
		srv_opts_t options;
		options.weigth = 7;
		options.max_conns = 10;
		options.use_ssl = 1;

		manager.wrlock();
		manager.create_new_server_in_hg(420, info, options);
		MyHGC* configured_hostgroup = manager.MyHGC_find(420);
		init_myhgc_hostgroup_settings(
			R"({"aws":{"locality_awareness":{"same_region_multiplier":2.0,"same_az_multiplier":4.0}}})",
			configured_hostgroup);
		MySrvC* configured_server = static_cast<MySrvC*>(
			configured_hostgroup->mysrvs->servers->index(0));
		manager.wrunlock();

		manager.refresh_aws_locality_configuration();
		auto snapshot = manager.aws_locality_manager()->snapshot();
		const auto* entry = snapshot->find(420, info.addr, info.port);
		ok(entry != nullptr && entry->configured_weight == 7,
			"post-commit refresh copies hostgroup policy and backend identity into the manager");

		manager.set_aws_locality_awareness_enabled(true);
		manager.set_aws_locality_awareness_enabled(false);
		ok(!manager.aws_locality_manager()->snapshot()->enabled &&
			configured_server->weight == 7,
			"master-switch transitions never mutate the configured runtime server weight");

		init_myhgc_hostgroup_settings("{}", configured_hostgroup);
		manager.refresh_aws_locality_configuration();
		ok(manager.aws_locality_manager()->snapshot()->entries.empty(),
			"removing the hostgroup policy removes its manager configuration");
		MyHGM = previous_hgm;
	}
	GloVars.prometheus_registry.reset();

	return exit_status();
}
