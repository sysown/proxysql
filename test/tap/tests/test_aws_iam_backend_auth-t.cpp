/**
 * @file test_aws_iam_backend_auth-t.cpp
 * @brief Controlled TLS/MySQL-protocol coverage for AWS IAM backend auth.
 *
 * The production SDK is intentionally not required here. A deterministic fake
 * source supplies a recognizable 2 KiB value to the real MySQL_Connection and
 * bundled Connector/C. A one-shot loopback server performs the real MySQL TLS
 * and mysql_clear_password exchange and reports only length/digest metadata.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "frontend_x509_test_utils.h"

#include "proxysql.h"
#include "cpp.h"
#include "Aws_Iam_Sdk.h"
#include "Aws_Iam_Token_Manager.h"
#include "MySQL_Data_Stream.h"
#include "MySQL_Logger.hpp"
#include "MySQL_Monitor.hpp"

#include <openssl/sha.h>

#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>
#include <utility>

extern MySQL_HostGroups_Manager *MyHGM;
extern MySQL_Logger *GloMyLogger;
extern MySQL_Monitor *GloMyMon;

namespace {

using Clock = std::chrono::steady_clock;

constexpr const char *kEndpoint = "db.cluster-test.us-east-1.rds.amazonaws.com";
constexpr const char *kWrongEndpoint = "wrong.cluster-test.us-east-1.rds.amazonaws.com";
constexpr const char *kUsername = "iam_protocol_user";

struct ChildServer {
	pid_t pid { -1 };
	FILE *output { nullptr };
	int stage_fd { -1 };
	unsigned int port { 0 };
	std::string result;
};

struct CertificateFixture {
	std::string directory;
	std::string ca;
	std::string untrusted_ca;
	std::string valid_cert;
	std::string valid_key;
	std::string wrong_cert;
	std::string wrong_key;
	std::string untrusted_cert;
	std::string untrusted_key;
	bool ready { false };

	CertificateFixture() = default;
	CertificateFixture(const CertificateFixture&) = delete;
	CertificateFixture& operator=(const CertificateFixture&) = delete;
	CertificateFixture& operator=(CertificateFixture&&) = delete;
	CertificateFixture(CertificateFixture&& other) noexcept :
		directory(std::move(other.directory)), ca(std::move(other.ca)),
		untrusted_ca(std::move(other.untrusted_ca)),
		valid_cert(std::move(other.valid_cert)), valid_key(std::move(other.valid_key)),
		wrong_cert(std::move(other.wrong_cert)), wrong_key(std::move(other.wrong_key)),
		untrusted_cert(std::move(other.untrusted_cert)),
		untrusted_key(std::move(other.untrusted_key)), ready(other.ready) {
		other.directory.clear();
		other.ready = false;
	}

	~CertificateFixture() {
		if (directory.empty()) return;
		const char *files[] {
			"ca.key", "ca.pem", "ca.srl", "untrusted-ca.key", "untrusted-ca.pem",
			"untrusted-ca.srl", "valid.key", "valid.csr", "valid.pem", "valid.ext",
			"wrong.key", "wrong.csr", "wrong.pem", "wrong.ext",
			"untrusted.key", "untrusted.csr", "untrusted.pem", "untrusted.ext"
		};
		for (const char *file : files) unlink((directory + "/" + file).c_str());
		rmdir(directory.c_str());
	}
};

class FakeSource final : public AwsIamTokenSource {
public:
	AwsIamRequestHandle request(const AwsIamTokenKey&, uint64_t,
		std::weak_ptr<AwsIamCompletionSink>) override { return {}; }
	AwsIamTokenResult request_blocking(const AwsIamTokenKey&, Clock::time_point) override {
		++blocking_requests;
		AwsIamTokenResult result;
		result.status = AwsIamStatus::OK;
		result.generation = 1;
		result.token = SecureString(token);
		return result;
	}
	void cancel(AwsIamRequestHandle) override {}
	void invalidate(const AwsIamTokenKey&, uint64_t) override {}
	void record_backend_connection(bool) override {}
	void record_waiting_session(bool) override {}
	AwsIamStatsSnapshot snapshot() const override { return {}; }

	std::string token;
	unsigned int blocking_requests { 0 };
};

class ScopedPublishedTokenSource {
public:
	explicit ScopedPublishedTokenSource(AwsIamTokenSource *source) {
		publish_global_aws_iam_token_source(source);
	}
	~ScopedPublishedTokenSource() { publish_global_aws_iam_token_source(nullptr); }

	ScopedPublishedTokenSource(const ScopedPublishedTokenSource&) = delete;
	ScopedPublishedTokenSource& operator=(const ScopedPublishedTokenSource&) = delete;
};

bool write_text_file(const std::string& path, const std::string& contents) {
	std::ofstream output(path);
	output << contents;
	return output.good();
}

bool make_leaf(const CertificateFixture& fixture, const std::string& name,
	const std::string& common_name, const std::string& ca, const std::string& ca_key,
	unsigned int serial) {
	const std::string prefix = fixture.directory + "/" + name;
	const std::string ext = prefix + ".ext";
	return write_text_file(ext, "subjectAltName=DNS:" + common_name + "\n") &&
		run_openssl({ "req", "-new", "-newkey", "rsa:2048", "-nodes",
			"-subj", "/CN=" + common_name, "-keyout", prefix + ".key", "-out", prefix + ".csr" }) &&
		run_openssl({ "x509", "-req", "-days", "1", "-set_serial",
			std::to_string(serial), "-in", prefix + ".csr", "-CA", ca, "-CAkey", ca_key,
			"-extfile", ext, "-out", prefix + ".pem" });
}

CertificateFixture create_certificates() {
	CertificateFixture fixture;
	const std::string path_template = "./proxysql-aws-iam-protocol-XXXXXX";
	std::vector<char> path(path_template.begin(), path_template.end());
	path.push_back('\0');
	char *directory = mkdtemp(path.data());
	if (directory == nullptr) return fixture;
	fixture.directory = directory;
	fixture.ca = fixture.directory + "/ca.pem";
	fixture.untrusted_ca = fixture.directory + "/untrusted-ca.pem";
	const std::string ca_key = fixture.directory + "/ca.key";
	const std::string untrusted_ca_key = fixture.directory + "/untrusted-ca.key";

	const bool roots =
		run_openssl({ "req", "-x509", "-newkey", "rsa:2048", "-nodes",
			"-days", "1", "-subj", "/CN=ProxySQL AWS IAM Test CA",
			"-keyout", ca_key, "-out", fixture.ca }) &&
		run_openssl({ "req", "-x509", "-newkey", "rsa:2048", "-nodes",
			"-days", "1", "-subj", "/CN=ProxySQL AWS IAM Untrusted CA",
			"-keyout", untrusted_ca_key, "-out", fixture.untrusted_ca });
	fixture.valid_cert = fixture.directory + "/valid.pem";
	fixture.valid_key = fixture.directory + "/valid.key";
	fixture.wrong_cert = fixture.directory + "/wrong.pem";
	fixture.wrong_key = fixture.directory + "/wrong.key";
	fixture.untrusted_cert = fixture.directory + "/untrusted.pem";
	fixture.untrusted_key = fixture.directory + "/untrusted.key";
	fixture.ready = roots &&
		make_leaf(fixture, "valid", kEndpoint, fixture.ca, ca_key, 820001) &&
		make_leaf(fixture, "wrong", kWrongEndpoint, fixture.ca, ca_key, 820002) &&
		make_leaf(fixture, "untrusted", kEndpoint, fixture.untrusted_ca, untrusted_ca_key, 820003);
	return fixture;
}

std::string sha256(const std::string& input) {
	unsigned char digest[SHA256_DIGEST_LENGTH] {};
	SHA256(reinterpret_cast<const unsigned char *>(input.data()), input.size(), digest);
	static const char digits[] = "0123456789abcdef";
	std::string output;
	output.reserve(sizeof(digest) * 2);
	for (unsigned char byte : digest) {
		output.push_back(digits[byte >> 4U]);
		output.push_back(digits[byte & 0x0fU]);
	}
	return output;
}

std::string hex(const std::string& input) {
	static const char digits[] = "0123456789abcdef";
	std::string output;
	output.reserve(input.size() * 2);
	for (unsigned char byte : input) {
		output.push_back(digits[byte >> 4U]);
		output.push_back(digits[byte & 0x0fU]);
	}
	return output;
}

std::string field(const std::string& record, const std::string& name) {
	const std::string prefix = name + "=";
	const size_t begin = record.find(prefix);
	if (begin == std::string::npos) return {};
	const size_t value_begin = begin + prefix.size();
	const size_t end = record.find(' ', value_begin);
	return record.substr(value_begin, end == std::string::npos ? std::string::npos : end - value_begin);
}

bool read_control_line(int fd, std::string& line, unsigned int timeout_ms) {
	const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
	while (Clock::now() < deadline && line.size() < 2048) {
		pollfd descriptor { fd, POLLIN, 0 };
		const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
			deadline - Clock::now()).count();
		const int ready = poll(&descriptor, 1, static_cast<int>(remaining > 0 ? remaining : 1));
		if (ready < 0 && errno == EINTR) continue;
		if (ready <= 0 || (descriptor.revents & POLLIN) == 0) return false;
		char byte = 0;
		if (read(fd, &byte, 1) != 1) return false;
		line.push_back(byte);
		if (byte == '\n') return true;
	}
	return false;
}

ChildServer start_server(const std::string& mode, const std::string& certificate,
	const std::string& private_key, unsigned int delay_ms = 1500) {
	ChildServer child;
	int pipefd[2] {};
	int stage_pipe[2] {};
	if (pipe(pipefd) != 0) return child;
	if (pipe(stage_pipe) != 0) {
		close(pipefd[0]);
		close(pipefd[1]);
		return child;
	}
	const std::string server { AWS_IAM_MYSQL_SERVER_PATH };
	child.pid = fork();
	if (child.pid == 0) {
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		close(stage_pipe[0]);
		execl(server.c_str(), server.c_str(), "--mode", mode.c_str(),
			"--cert", certificate.c_str(), "--key", private_key.c_str(),
			"--delay-ms", std::to_string(delay_ms).c_str(), "--stage-fd",
			std::to_string(stage_pipe[1]).c_str(), static_cast<char *>(nullptr));
		_exit(127);
	}
	close(pipefd[1]);
	close(stage_pipe[1]);
	if (child.pid < 0) {
		close(pipefd[0]);
		close(stage_pipe[0]);
		return child;
	}
	child.stage_fd = stage_pipe[0];
	std::string ready_line;
	if (read_control_line(pipefd[0], ready_line, 5000)) {
		unsigned int port = 0;
		if (sscanf(ready_line.c_str(), "READY port=%u", &port) == 1) child.port = port;
	}
	child.output = fdopen(pipefd[0], "r");
	if (child.output != nullptr) setvbuf(child.output, nullptr, _IONBF, 0);
	return child;
}

void finish_server(ChildServer& child) {
	if (child.pid > 0) {
		const auto deadline = Clock::now() + std::chrono::seconds(8);
		int status = 0;
		while (Clock::now() < deadline) {
			const pid_t result = waitpid(child.pid, &status, WNOHANG);
			if (result == child.pid || (result < 0 && errno == ECHILD)) {
				child.pid = -1;
				break;
			}
			if (result < 0 && errno != EINTR) break;
			pollfd descriptor { child.output == nullptr ? -1 : fileno(child.output), POLLIN, 0 };
			(void)poll(&descriptor, 1, 25);
		}
		if (child.pid > 0) {
			(void)kill(child.pid, SIGTERM);
			const auto terminate_deadline = Clock::now() + std::chrono::milliseconds(250);
			while (Clock::now() < terminate_deadline) {
				const pid_t result = waitpid(child.pid, &status, WNOHANG);
				if (result == child.pid || (result < 0 && errno == ECHILD)) {
					child.pid = -1;
					break;
				}
				if (result < 0 && errno != EINTR) break;
				poll(nullptr, 0, 10);
			}
		}
		if (child.pid > 0) {
			(void)kill(child.pid, SIGKILL);
			while (waitpid(child.pid, &status, 0) < 0 && errno == EINTR) {}
			child.pid = -1;
		}
	}
	if (child.output != nullptr) {
		char line[2048] {};
		while (fgets(line, sizeof(line), child.output) != nullptr) child.result = line;
		fclose(child.output);
		child.output = nullptr;
	}
	if (child.stage_fd >= 0) {
		close(child.stage_fd);
		child.stage_fd = -1;
	}
	while (!child.result.empty() &&
		(child.result.back() == '\n' || child.result.back() == '\r')) {
		child.result.pop_back();
	}
}

MySrvC *create_server(unsigned int hostgroup, const char *endpoint, unsigned int port,
	bool use_ssl) {
	srv_info_t info;
	info.addr = const_cast<char *>(endpoint);
	info.port = port;
	info.kind = "aws-iam-protocol-test";
	srv_opts_t opts;
	opts.weigth = 1;
	opts.max_conns = 100;
	opts.use_ssl = use_ssl ? 1 : 0;
	MyHGM->wrlock();
	const int result = MyHGM->create_new_server_in_hg(hostgroup, info, opts);
	MyHGC *group = MyHGM->MyHGC_find(hostgroup);
	MyHGM->wrunlock();
	if (result != 0 || group == nullptr) return nullptr;
	MySrvC *server = nullptr;
	for (unsigned int i = 0; i < group->mysrvs->cnt(); ++i) {
		MySrvC *candidate = group->mysrvs->idx(i);
		if (candidate != nullptr && candidate->port == port &&
			strcmp(candidate->address, endpoint) == 0) {
			server = candidate;
			break;
		}
	}
	if (server == nullptr) return nullptr;
	server->use_ssl = use_ssl ? 1 : 0;
	return server;
}

class ConnectionFixture {
public:
	ConnectionFixture(MySQL_Thread& worker, MySrvC *server) {
		session = new MySQL_Session();
		session->thread = &worker;
		session->connections_handler = true;
		frontend_stream = new MySQL_Data_Stream();
		frontend_stream->init(MYDS_FRONTEND, session, -1);
		frontend = new MySQL_Connection();
		frontend_stream->attach_connection(frontend);
		session->client_myds = frontend_stream;
		frontend->userinfo->set(const_cast<char *>("frontend_user"),
			const_cast<char *>("frontend-password-must-not-change"),
			const_cast<char *>("frontend_schema"), nullptr);
		stream = new MySQL_Data_Stream();
		stream->init(MYDS_BACKEND_NOT_CONNECTED, session, -1);
		connection = new MySQL_Connection();
		connection->send_quit = false;
		connection->parent = server;
		stream->attach_connection(connection);
		session->mybe = session->create_backend(server->myhgc->hid, stream);
		connection->userinfo->set(const_cast<char *>(kUsername),
			const_cast<char *>("ordinary-password-must-not-leak"),
			const_cast<char *>(""), nullptr);
	}
	~ConnectionFixture() {
		if (connection != nullptr) {
			stream->myconn = nullptr;
			connection->myds = nullptr;
			delete connection;
		}
		delete session;
	}

	MySQL_Session *session { nullptr };
	MySQL_Data_Stream *frontend_stream { nullptr };
	MySQL_Connection *frontend { nullptr };
	MySQL_Data_Stream *stream { nullptr };
	MySQL_Connection *connection { nullptr };
};

MDB_ASYNC_ST drive(MySQL_Thread& worker, MySQL_Connection *connection,
	unsigned int timeout_ms = 5000) {
	worker.curtime = monotonic_time();
	MDB_ASYNC_ST state = connection->handler(0);
	const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
	while (state == ASYNC_CONNECT_CONT && Clock::now() < deadline) {
		pollfd descriptor { connection->fd,
			connection->wait_events != 0 ? connection->wait_events : static_cast<short>(POLLIN | POLLOUT), 0 };
		const int ready = poll(&descriptor, 1, 50);
		short events = 0;
		if (ready > 0) {
			if ((descriptor.revents & POLLIN) != 0) events |= POLLIN;
			if ((descriptor.revents & POLLOUT) != 0) events |= POLLOUT;
		}
		worker.curtime = monotonic_time();
		state = connection->handler(events);
	}
	return state;
}

struct StagedConnect {
	MDB_ASYNC_ST state { ASYNC_CONNECT_FAILED };
	bool server_reached_stage { false };
};

StagedConnect drive_until_server_stage(MySQL_Thread& worker, MySQL_Connection *connection,
	ChildServer& server) {
	worker.curtime = monotonic_time();
	MDB_ASYNC_ST state = connection->handler(0);
	for (unsigned int attempt = 0; state == ASYNC_CONNECT_CONT && attempt != 100; ++attempt) {
		pollfd descriptors[2] {
			{ connection->fd, connection->wait_events != 0 ? connection->wait_events :
				static_cast<short>(POLLIN | POLLOUT), 0 },
			{ server.stage_fd, POLLIN, 0 }
		};
		const int ready = poll(descriptors, 2, 20);
		if (ready <= 0) continue;
		if ((descriptors[1].revents & POLLIN) != 0) {
			char stage = 0;
			if (read(server.stage_fd, &stage, 1) == 1 && stage == 'S') return { state, true };
		}
		short events = 0;
		if ((descriptors[0].revents & POLLIN) != 0) events |= POLLIN;
		if ((descriptors[0].revents & POLLOUT) != 0) events |= POLLOUT;
		if (events == 0) continue;
		worker.curtime = monotonic_time();
		state = connection->handler(events);
	}
	return { state, false };
}

AwsIamTokenKey key(unsigned int port) {
	return { kEndpoint, static_cast<uint16_t>(port), "us-east-1", kUsername };
}

AwsIamTokenResult token_result(const std::string& token) {
	AwsIamTokenResult result;
	result.status = AwsIamStatus::OK;
	result.generation = 7;
	result.token = SecureString(token);
	return result;
}

void run_success_case(MySQL_Thread& worker, const CertificateFixture& certificates,
	const std::string& token) {
	ChildServer server = start_server("success", certificates.valid_cert, certificates.valid_key);
	if (server.port == 0) BAIL_OUT("controlled server did not become ready");
	MySrvC *backend = create_server(1101, kEndpoint, server.port, true);
	ConnectionFixture fixture(worker, backend);
	fixture.connection->set_backend_auth_type(MySQLBackendAuthType::AWS_IAM);
	FakeSource source;
	source.token = token;
	fixture.connection->attach_aws_iam_token(key(server.port),
		source.request_blocking(key(server.port), Clock::now() + std::chrono::seconds(1)));
	const MDB_ASYNC_ST status = drive(worker, fixture.connection);
	finish_server(server);

	ok(status == ASYNC_CONNECT_SUCCESSFUL && source.blocking_requests == 1,
		"one fake-source result authenticates through the real Connector/C TLS path");
	ok(field(server.result, "tls") == "1" && field(server.result, "pre_tls") == "0",
		"mysql_clear_password payload is requested only after SSL_accept");
	ok(field(server.result, "min_tls") == std::to_string(TLS1_2_VERSION),
		"the controlled IAM backend refuses TLS protocol versions older than TLS 1.2");
	ok(field(server.result, "username_hex") == hex(kUsername) &&
		field(server.result, "token_len") == std::to_string(token.size()) &&
		field(server.result, "token_sha256") == sha256(token),
		"the expected backend user and 2 KiB-plus token arrive byte-for-byte without being logged");
	ok(field(server.result, "sni_hex") == "64622e636c75737465722d746573742e75732d656173742d312e7264732e616d617a6f6e6177732e636f6d" &&
		field(server.result, "peer") == "127.0.0.1",
		"socket uses loopback while SNI and certificate verification use the configured RDS endpoint");
	ok(!fixture.connection->has_aws_iam_handshake_secret() &&
		(fixture.connection->mysql == nullptr || fixture.connection->mysql->passwd == nullptr) &&
		fixture.connection->userinfo->password != nullptr &&
		strcmp(fixture.connection->userinfo->password, "ordinary-password-must-not-leak") == 0,
		"successful authentication cleanses transient token copies without replacing the stored password");
}

void run_certificate_failure(MySQL_Thread& worker, const CertificateFixture& certificates,
	const std::string& mode, const std::string& certificate, const std::string& private_key,
	unsigned int hostgroup, const char *label) {
	ChildServer server = start_server(mode, certificate, private_key);
	if (server.port == 0) BAIL_OUT("controlled certificate-failure server did not become ready");
	MySrvC *backend = create_server(hostgroup, kEndpoint, server.port, true);
	ConnectionFixture fixture(worker, backend);
	fixture.connection->set_backend_auth_type(MySQLBackendAuthType::AWS_IAM);
	fixture.connection->attach_aws_iam_token(key(server.port), token_result("TOKEN_MUST_NOT_CROSS_FAILED_TLS"));
	const MDB_ASYNC_ST status = drive(worker, fixture.connection);
	finish_server(server);
	ok(status == ASYNC_CONNECT_FAILED && field(server.result, "token_len") == "0",
		"%s fails before token transmission", label);
}

void run_pre_auth_abort_cases(MySQL_Thread& worker, const CertificateFixture& certificates,
	const std::string& token) {
	ChildServer closed = start_server("close_transport", certificates.valid_cert, certificates.valid_key);
	if (closed.port == 0) BAIL_OUT("controlled transport-close server did not become ready");
	MySrvC *closed_backend = create_server(1106, kEndpoint, closed.port, true);
	{
		ConnectionFixture fixture(worker, closed_backend);
		fixture.connection->set_backend_auth_type(MySQLBackendAuthType::AWS_IAM);
		fixture.connection->attach_aws_iam_token(key(closed.port), token_result(token));
		const MDB_ASYNC_ST status = drive(worker, fixture.connection);
		finish_server(closed);
		ok(status == ASYNC_CONNECT_FAILED && field(closed.result, "token_len") == "0" &&
			!fixture.connection->has_aws_iam_handshake_secret(),
			"transport loss before TLS authentication sends no token and clears the handshake secret");
	}

	ChildServer delayed = start_server("delay_handshake", certificates.valid_cert,
		certificates.valid_key, 2000);
	if (delayed.port == 0) BAIL_OUT("controlled delayed-handshake server did not become ready");
	MySrvC *delayed_backend = create_server(1107, kEndpoint, delayed.port, true);
	{
		ConnectionFixture fixture(worker, delayed_backend);
		fixture.connection->set_backend_auth_type(MySQLBackendAuthType::AWS_IAM);
		fixture.connection->attach_aws_iam_token(key(delayed.port), token_result(token));
		const StagedConnect initial = drive_until_server_stage(worker, fixture.connection, delayed);
		fixture.connection->clear_aws_iam_handshake_secret();
		finish_server(delayed);
		ok(initial.state == ASYNC_CONNECT_CONT && initial.server_reached_stage &&
			field(delayed.result, "token_len") == "0" &&
			!fixture.connection->has_aws_iam_handshake_secret() && fixture.connection->mysql == nullptr,
			"connection cancellation during a delayed server handshake leaves no live Connector/C token owner");
	}
}

} // namespace

int main() {
	plan(17);
	diag("SDK-independent controlled TLS/protocol coverage; no SDK-on provider/signing verification is claimed");
	if (test_init_minimal() != 0 || test_init_query_processor() != 0 ||
		test_init_hostgroups() != 0) BAIL_OUT("failed to initialize component globals");
	GloMyLogger = new MySQL_Logger();
	GloMyMon = new MySQL_Monitor();
	GloMyMon->dns_cache->pin(kEndpoint, "127.0.0.1");

	CertificateFixture certificates = create_certificates();
	ok(certificates.ready, "temporary CA and SAN server certificates were generated");
	if (!certificates.ready) BAIL_OUT("could not generate controlled TLS certificates");

	{
		MySQL_Thread worker;
		if (!worker.init()) BAIL_OUT("MySQL_Thread::init failed");
		worker.curtime = monotonic_time();
		mysql_thread___ssl_p2s_ca = strdup(certificates.ca.c_str());
		const std::string token = std::string(kEndpoint) + ":3306/?Action=connect&" + std::string(2048, 'x');
		run_success_case(worker, certificates, token);
		run_certificate_failure(worker, certificates, "wrong_hostname",
			certificates.wrong_cert, certificates.wrong_key, 1102, "wrong hostname");
		run_certificate_failure(worker, certificates, "untrusted_ca",
			certificates.untrusted_cert, certificates.untrusted_key, 1103, "untrusted CA");
		run_pre_auth_abort_cases(worker, certificates, token);

		ChildServer denied = start_server("access_denied", certificates.valid_cert, certificates.valid_key);
		if (denied.port == 0) BAIL_OUT("controlled access-denied server did not become ready");
		MySrvC *denied_backend = create_server(1104, kEndpoint, denied.port, true);
		{
			ConnectionFixture fixture(worker, denied_backend);
			fixture.connection->set_backend_auth_type(MySQLBackendAuthType::AWS_IAM);
			fixture.connection->attach_aws_iam_token(key(denied.port), token_result(token));
			const MDB_ASYNC_ST status = drive(worker, fixture.connection);
			finish_server(denied);
			ok(status == ASYNC_CONNECT_FAILED && field(denied.result, "token_len") == std::to_string(token.size()),
				"access denied occurs after one TLS-protected clear-password transmission");
			ok(!fixture.connection->has_aws_iam_handshake_secret() &&
				(fixture.connection->mysql == nullptr || fixture.connection->mysql->passwd == nullptr),
				"access denied cleanses both token owners");
		}

		ChildServer ordinary = start_server("success", certificates.valid_cert, certificates.valid_key);
		if (ordinary.port == 0) BAIL_OUT("controlled ordinary-password server did not become ready");
		MySrvC *ordinary_backend = create_server(1101, kEndpoint, ordinary.port, false);
		FakeSource fake;
		fake.token = token;
		ScopedPublishedTokenSource published(&fake);
		{
			ConnectionFixture fixture(worker, ordinary_backend);
			const MDB_ASYNC_ST status = drive(worker, fixture.connection);
			finish_server(ordinary);
			ok(status == ASYNC_CONNECT_FAILED && field(ordinary.result, "pre_tls") == "1" &&
				field(ordinary.result, "token_len") == "0",
				"ordinary password mode coexists in the IAM hostgroup, keeps cleartext auth disabled, and sends no IAM token");
			ok(fake.blocking_requests == 0, "ordinary password mode never calls the published fake IAM source");
		}

		AwsIamConnectionConfigInput invalid { kUsername, kEndpoint, 3306, "us-east-1", false,
			certificates.ca, "", true };
		ok(validate_mysql_aws_iam_connection(invalid).status == AwsIamConnectionConfigStatus::TLS_REQUIRED,
			"use_ssl=0 is rejected before token acquisition");
		invalid.use_ssl = true;
		invalid.ssl_ca.clear();
		ok(validate_mysql_aws_iam_connection(invalid).status == AwsIamConnectionConfigStatus::CA_TRUST_REQUIRED,
			"missing CA trust is rejected before token acquisition");
	}

	delete GloMyMon;
	GloMyMon = nullptr;
	delete GloMyLogger;
	GloMyLogger = nullptr;
	test_cleanup_hostgroups();
	test_cleanup_query_processor();
	test_cleanup_minimal();
	return exit_status();
}
