/**
 * @file azure_entra_plugin_unit-t.cpp
 * @brief Azure Entra provider plugin: configuration and token exchange (issue #6649).
 */
#include "tap.h"

#include "entra_config.h"
#include "entra_exchange.h"

#include <map>
#include <string>

namespace {

constexpr const char *kTenant = "11111111-2222-3333-4444-555555555555";
constexpr const char *kClient = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";

using Env = std::map<std::string, std::string>;

std::function<const char *(const char *)> env_of(const Env& env) {
	return [&env](const char *name) -> const char * {
		const auto it = env.find(name);
		return it == env.end() ? nullptr : it->second.c_str();
	};
}

Env base_env() {
	return {
		{ "AZURE_TENANT_ID", kTenant },
		{ "AZURE_CLIENT_ID", kClient },
		{ "AZURE_FEDERATED_TOKEN_FILE", "/var/run/secrets/azure/tokens/azure-identity-token" },
	};
}

void test_config() {
	EntraConfig cfg;
	std::string error;
	Env env = base_env();
	ok(load_entra_config(env_of(env), cfg, error) &&
		cfg.tenant_id == kTenant && cfg.client_id == kClient &&
		cfg.federated_token_file == "/var/run/secrets/azure/tokens/azure-identity-token" &&
		cfg.authority_host == "https://login.microsoftonline.com/" &&
		cfg.scope == "https://ossrdbms-aad.database.windows.net/.default",
		"config_defaults");

	env = base_env();
	env.erase("AZURE_TENANT_ID");
	ok(!load_entra_config(env_of(env), cfg, error) && error.find("AZURE_TENANT_ID") != std::string::npos,
		"config_missing_tenant_fails");

	env = base_env();
	env.erase("AZURE_FEDERATED_TOKEN_FILE");
	ok(!load_entra_config(env_of(env), cfg, error) &&
		error.find("AZURE_FEDERATED_TOKEN_FILE") != std::string::npos,
		"config_missing_token_file_fails");

	env = base_env();
	env["AZURE_AUTHORITY_HOST"] = "http://login.microsoftonline.com/";
	ok(!load_entra_config(env_of(env), cfg, error) && error.find("AZURE_AUTHORITY_HOST") != std::string::npos,
		"config_http_authority_rejected");

	env = base_env();
	env["AZURE_AUTHORITY_HOST"] = "https://login.microsoftonline.us";
	env["PROXYSQL_AZURE_ENTRA_SCOPE"] = "https://ossrdbms-aad.database.usgovcloudapi.net/.default";
	ok(load_entra_config(env_of(env), cfg, error) &&
		cfg.authority_host == "https://login.microsoftonline.us/" &&
		cfg.scope == "https://ossrdbms-aad.database.usgovcloudapi.net/.default",
		"authority without a trailing slash is normalized; scope can be overridden");

	env = base_env();
	env["AZURE_TENANT_ID"] = "abc/../x";
	ok(!load_entra_config(env_of(env), cfg, error) && error.find("AZURE_TENANT_ID") != std::string::npos,
		"config_non_guid_rejected: tenant");
	env = base_env();
	env["AZURE_CLIENT_ID"] = "a&scope=x";
	ok(!load_entra_config(env_of(env), cfg, error) && error.find("AZURE_CLIENT_ID") != std::string::npos,
		"config_non_guid_rejected: client");
}

EntraConfig valid_config() {
	EntraConfig cfg;
	std::string error;
	Env env = base_env();
	load_entra_config(env_of(env), cfg, error);
	return cfg;
}

struct Recorder {
	std::string url, body;
	std::chrono::milliseconds timeout { 0 };
	int calls { 0 };
	HttpResponse reply { 200, R"({"token_type":"Bearer","expires_in":3599,"access_token":"tok"})" };
	HttpPostFn fn() {
		return [this](const std::string& u, const std::string& b, std::chrono::milliseconds t) {
			++calls; url = u; body = b; timeout = t;
			return reply;
		};
	}
};

std::function<bool(std::string&)> assertion_is(const char *value) {
	return [value](std::string& out) { out = value; return true; };
}

void test_exchange() {
	const EntraConfig cfg = valid_config();
	Recorder rec;
	EntraTokenResponse r = exchange_workload_identity(cfg, assertion_is("hdr.pay+load/x.sig"), rec.fn());
	ok(rec.calls == 1 &&
		rec.url == std::string("https://login.microsoftonline.com/") + kTenant + "/oauth2/v2.0/token" &&
		rec.timeout == std::chrono::milliseconds(4000) &&
		rec.body.find(std::string("client_id=") + kClient) != std::string::npos &&
		rec.body.find("scope=https%3A%2F%2Fossrdbms-aad.database.windows.net%2F.default") != std::string::npos &&
		rec.body.find("grant_type=client_credentials") != std::string::npos &&
		rec.body.find("client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer")
			!= std::string::npos &&
		rec.body.find("client_assertion=hdr.pay%2Bload%2Fx.sig") != std::string::npos,
		"exchange_builds_form");
	ok(r.ok && std::string(r.access_token.c_str()) == "tok" && r.expires_in == std::chrono::seconds(3599),
		"exchange_parses_success");

	rec.reply = { 200, R"({"access_token":"tok2","expires_in":"1800"})" };
	r = exchange_workload_identity(cfg, assertion_is("a"), rec.fn());
	ok(r.ok && std::string(r.access_token.c_str()) == "tok2" && r.expires_in == std::chrono::seconds(1800),
		"expires_in as a string is accepted");

	rec.reply = { 400, R"({"error":"invalid_client","error_description":"AADSTS700016 hdr.pay+load/x.sig","correlation_id":"abc"})" };
	r = exchange_workload_identity(cfg, assertion_is("hdr.pay+load/x.sig"), rec.fn());
	ok(!r.ok && r.failure.category == "provider_error" && r.failure.aws_error_code == "invalid_client" &&
		r.failure.request_id == "abc" && r.access_token.empty() &&
		r.failure.category.find("hdr.pay") == std::string::npos &&
		r.failure.aws_error_code.find("hdr.pay") == std::string::npos &&
		r.failure.request_id.find("hdr.pay") == std::string::npos,
		"exchange_parses_error without leaking the assertion");

	rec.reply = { 400, R"({"error":")" + std::string(5000, 'e') +
		R"(","correlation_id":")" + std::string(5000, 'c') + R"("})" };
	r = exchange_workload_identity(cfg, assertion_is("a"), rec.fn());
	ok(!r.ok && r.failure.aws_error_code == std::string(128, 'e') &&
		r.failure.request_id == std::string(128, 'c'),
		"exchange_caps_error_fields: error and correlation_id are cut to 128 characters");

	rec.reply = { 200, "not json" };
	r = exchange_workload_identity(cfg, assertion_is("a"), rec.fn());
	ok(!r.ok && r.failure.category == "provider_error", "a malformed 200 response is a provider error");

	rec.reply = { 200, R"({"access_token":"","expires_in":3599})" };
	r = exchange_workload_identity(cfg, assertion_is("a"), rec.fn());
	ok(!r.ok && r.failure.category == "provider_error", "an empty access_token is a provider error");

	rec.reply = { 200, R"({"access_token":"t","expires_in":60})" };
	r = exchange_workload_identity(cfg, assertion_is("a"), rec.fn());
	ok(!r.ok && r.failure.category == "provider_error" && r.failure.aws_error_code == "invalid_token_response",
		"expires_in of 60 s or less is refused: the token would never be usable");

	rec.reply = { 200, R"({"access_token":"t","expires_in":"99999999999999999999"})" };
	r = exchange_workload_identity(cfg, assertion_is("a"), rec.fn());
	ok(r.ok && r.expires_in == std::chrono::hours(24), "a huge expires_in is capped at 24 h");

	const int calls_before = rec.calls;
	r = exchange_workload_identity(cfg, [](std::string&) { return false; }, rec.fn());
	ok(!r.ok && r.failure.category == "credential_provider_error" && rec.calls == calls_before,
		"an unreadable assertion fails before any HTTP call");

	rec.reply = { 200, R"({"access_token":"t","expires_in":60})" };
	int reads = 0;
	auto rotating = [&reads](std::string& out) { out = ++reads == 1 ? "a1" : "a2"; return true; };
	exchange_workload_identity(cfg, rotating, rec.fn());
	exchange_workload_identity(cfg, rotating, rec.fn());
	ok(reads == 2 && rec.body.find("client_assertion=a2") != std::string::npos,
		"assertion_reread_each_exchange");
}

} // namespace

int main() {
	plan(0);
	test_config();
	test_exchange();
	return exit_status();
}
