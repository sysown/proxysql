/**
 * @file monitor_entra_auth_unit-t.cpp
 * @brief The MySQL monitor authenticates with an Azure Entra token (issue #6649).
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "Aws_Iam_Provider.h"
#include "MySQL_Monitor_Token_Auth.h"
#include "MySQL_Monitor.hpp"
#include "MySQL_HostGroups_Manager.h"

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <cstdio>
#include <string>

#include <unistd.h>

using Clock = std::chrono::steady_clock;

namespace {

constexpr const char *kEndpoint = "app.mysql.database.azure.com";

template <typename Action> std::string capture_stderr(Action action) {
	FILE *captured = tmpfile();
	if (captured == nullptr) BAIL_OUT("tmpfile() failed");
	fflush(stderr);
	const int saved = dup(STDERR_FILENO);
	if (saved < 0 || dup2(fileno(captured), STDERR_FILENO) < 0) BAIL_OUT("stderr redirect failed");
	action();
	fflush(stderr);
	dup2(saved, STDERR_FILENO);
	close(saved);
	std::string out;
	char buf[4096];
	rewind(captured);
	while (fgets(buf, sizeof(buf), captured) != nullptr) out += buf;
	fclose(captured);
	return out;
}

class FakeSource final : public AwsIamTokenSource {
public:
	AwsIamRequestHandle request(const AwsIamTokenKey&, uint64_t,
		std::weak_ptr<AwsIamCompletionSink>) override { return {}; }
	AwsIamTokenResult request_blocking(const AwsIamTokenKey& key, Clock::time_point deadline) override {
		last_key = key;
		last_deadline = deadline;
		++calls;
		AwsIamTokenResult r;
		if (refuse) {
			r.status = AwsIamStatus::PROVIDER_ERROR;
			r.failure = { "provider_error", "unauthorized_client", "corr-1" };
			return r;
		}
		r.status = AwsIamStatus::OK;
		r.generation = 4;
		r.token = SecureString("ENTRA_MONITOR_TOKEN");
		return r;
	}
	void cancel(AwsIamRequestHandle) override {}
	void invalidate(const AwsIamTokenKey&, uint64_t) override {}
	void record_backend_connection(bool) override {}
	void record_waiting_session(bool) override {}
	AwsIamStatsSnapshot snapshot() const override { return {}; }
	AwsIamTokenKey last_key;
	Clock::time_point last_deadline;
	int calls { 0 };
	bool refuse { false };
};

void test_variable() {
	ok(!GloMTH->set_variable((char *)"monitor_backend_auth", (char *)"foo"),
		"monitor_variable_rejects_unknown: 'foo' is refused");
	ok(GloMTH->set_variable((char *)"monitor_backend_auth", (char *)"azure_entra") &&
		GloMTH->set_variable((char *)"monitor_backend_auth", (char *)"password"),
		"monitor_backend_auth accepts 'azure_entra' and 'password'");
	char *value = GloMTH->get_variable_string((char *)"monitor_backend_auth");
	ok(value != nullptr && strcmp(value, "password") == 0, "the default and current value reads back");
	free(value);
}

void test_helper(FakeSource& source) {
	MYSQL *mysql = mysql_init(nullptr);
	MonitorTokenAuth out;
	const bool ready = prepare_monitor_token_auth(mysql, kEndpoint, 3306, true, nullptr, "monitor",
		1000, out);
	const AwsIamTokenKey expected { kEndpoint, 3306, "", "monitor" };
	ok(ready && std::string(out.token.c_str()) == "ENTRA_MONITOR_TOKEN" && out.generation == 4 &&
		out.key == expected && source.last_key == expected,
		"monitor_helper_gets_token: the monitor user gets a token from the Azure slot");
	mysql_close(mysql);

	mysql = mysql_init(nullptr);
	MonitorTokenAuth cold;
	const Clock::time_point before = Clock::now();
	prepare_monitor_token_auth(mysql, kEndpoint, 3306, true, nullptr, "monitor", 600, cold);
	ok(source.last_deadline - before >= std::chrono::milliseconds(4900),
		"monitor_token_wait: a 600 ms connect timeout still waits up to 5 s for a cold Entra fetch");
	mysql_close(mysql);

	mysql = mysql_init(nullptr);
	const int calls = source.calls;
	MonitorTokenAuth socket;
	ok(!prepare_monitor_token_auth(mysql, "/var/run/mysqld/mysqld.sock", 0, true, nullptr, "monitor",
		1000, socket) &&
		socket.failure_code == "unix_socket_not_allowed" && source.calls == calls,
		"monitor_helper_unix_socket_fails before any token request");
	mysql_close(mysql);
}

void test_no_source() {
	MYSQL *mysql = mysql_init(nullptr);
	MonitorTokenAuth out;
	ok(!prepare_monitor_token_auth(mysql, kEndpoint, 3306, true, nullptr, "monitor",
		1000, out) &&
		out.failure_code == "token_source_unavailable" && out.token.empty(),
		"monitor_helper_no_source_fails: no Azure source, no token, no password fallback");
	mysql_close(mysql);
}

void test_monitor_connect_failure_reported() {
	free(mysql_thread___monitor_backend_auth);
	mysql_thread___monitor_backend_auth = strdup("azure_entra");
	if (mysql_thread___monitor_username == nullptr) mysql_thread___monitor_username = strdup("monitor");
	const std::string key = std::string("7:") + kEndpoint + ":3306:9002";
	MySQL_Monitor_State_Data mmsd(MON_CONNECT, (char *)kEndpoint, 3306, true, 7);
	const std::string log = capture_stderr([&mmsd] { mmsd.create_new_connection(); });
	ok(mmsd.mysql == nullptr && mmsd.mysql_error_msg != nullptr &&
		std::string(mmsd.mysql_error_msg) == "azure_entra: token_source_unavailable" &&
		MyHGM->status.p_mysql_errors_map.count(key) == 1 &&
		log.find("Azure Entra monitor connection failure") != std::string::npos &&
		log.find("token_source_unavailable") != std::string::npos,
		"monitor_entra_failure_reported: the error counter and the log get the token failure, no connect");
	free(mysql_thread___monitor_backend_auth);
	mysql_thread___monitor_backend_auth = strdup("password");
}

void test_monitor_provider_failure_logged(FakeSource& source) {
	source.refuse = true;
	free(mysql_thread___monitor_backend_auth);
	mysql_thread___monitor_backend_auth = strdup("azure_entra");
	if (mysql_thread___monitor_username == nullptr) mysql_thread___monitor_username = strdup("monitor");
	MySQL_Monitor_State_Data mmsd(MON_CONNECT, (char *)kEndpoint, 3306, true, 7);
	const std::string log = capture_stderr([&mmsd] { mmsd.create_new_connection(); });
	ok(mmsd.mysql == nullptr && mmsd.mysql_error_msg != nullptr &&
		std::string(mmsd.mysql_error_msg) == "azure_entra: provider_error" &&
		log.find("category='provider_error' code='unauthorized_client' request_id='corr-1'")
			!= std::string::npos,
		"monitor_entra_provider_failure_logged: the log line has the Entra error code and correlation id");
	free(mysql_thread___monitor_backend_auth);
	mysql_thread___monitor_backend_auth = strdup("password");
	source.refuse = false;
}

void set_monitor_mode(const char *mode) {
	free(mysql_thread___monitor_backend_auth);
	mysql_thread___monitor_backend_auth = strdup(mode);
}

// A pooled monitor connection serves only the auth mode it was created with.
void test_pool_follows_auth_mode() {
	MYSQL *password_conn = mysql_init(nullptr);
	password_conn->passwd = strdup("monitor-password");
	MYSQL *token_conn = mysql_init(nullptr);
	token_conn->passwd = strdup("ENTRA_MONITOR_TOKEN");
	cleanse_monitor_connector_password(token_conn);

	set_monitor_mode("azure_entra");
	ok(!monitor_connection_matches_auth_mode(password_conn) &&
		monitor_connection_matches_auth_mode(token_conn),
		"monitor_pool_entra_mode: a pooled password connection is refused, a token connection is kept");
	set_monitor_mode("password");
	ok(monitor_connection_matches_auth_mode(password_conn) &&
		!monitor_connection_matches_auth_mode(token_conn),
		"monitor_pool_password_mode: a pooled token connection is refused, a password connection is kept");
	mysql_close(password_conn);
	mysql_close(token_conn);
}

} // namespace

int main() {
	plan(11);
	if (test_init_minimal() != 0 || test_init_query_processor() != 0 ||
		test_init_hostgroups() != 0) {
		BAIL_OUT("failed to initialize unit-test globals");
	}
	GloMTH->set_variable((char *)"ssl_p2s_ca", (char *)"/unit/fake-ca.pem");
	GloMTH->commit();
	mysql_thread___ssl_p2s_ca = strdup("/unit/fake-ca.pem");
	test_variable();
	{
		FakeSource source;
		publish_global_backend_token_source(BackendTokenProvider::AZURE_ENTRA, &source);
		test_helper(source);
		test_monitor_provider_failure_logged(source);
		publish_global_backend_token_source(BackendTokenProvider::AZURE_ENTRA, nullptr);
	}
	test_no_source();
	test_monitor_connect_failure_reported();
	test_pool_follows_auth_mode();
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
}
