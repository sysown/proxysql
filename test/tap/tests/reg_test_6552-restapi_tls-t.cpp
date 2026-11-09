/**
 * @file reg_test_6552-restapi_tls-t.cpp
 * @brief End-to-end coverage for REST API TLS/mTLS/interface/reload (#6552).
 *
 * Requires the isolated TAP infra: the test-runner and ProxySQL share the
 * ProxySQL datadir at /var/lib/proxysql, so this test can install a known
 * CA/server certificate, sign client certificates, and observe the listener.
 */

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "curl/curl.h"
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "proxysql_utils.h"
#include "frontend_x509_test_utils.h"

using std::string;

static const char* RESTAPI_ROUTE = "reload6552";
static const int RESTAPI_TEST_PORT = 6070;

struct http_result {
	long code { 0 };
	CURLcode rc { CURLE_OK };
	string body {};
};

static size_t write_body_cb(void* data, size_t size, size_t nmemb, void* userp) {
	string* out = static_cast<string*>(userp);
	out->append(static_cast<char*>(data), size * nmemb);
	return size * nmemb;
}

static http_result http_get(
	const string& url,
	const string& ca = "",
	const string& cert = "",
	const string& key = "",
	const string& unix_socket = "",
	long timeout_s = 8
) {
	http_result result {};
	CURL* curl = curl_easy_init();
	if (!curl) {
		result.rc = CURLE_FAILED_INIT;
		return result;
	}
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout_s);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.body);
	if (!unix_socket.empty()) {
		curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, unix_socket.c_str());
	}
	if (!ca.empty()) {
		curl_easy_setopt(curl, CURLOPT_CAINFO, ca.c_str());
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		// Chain verification is what matters here; the fixture CN may not be
		// the address used by the shared Docker network.
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	} else {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	}
	if (!cert.empty()) {
		curl_easy_setopt(curl, CURLOPT_SSLCERT, cert.c_str());
	}
	if (!key.empty()) {
		curl_easy_setopt(curl, CURLOPT_SSLKEY, key.c_str());
	}
	result.rc = curl_easy_perform(curl);
	if (result.rc == CURLE_OK) {
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &result.code);
	}
	curl_easy_cleanup(curl);
	return result;
}

static bool wait_for_http(
	const string& url,
	long expected_code,
	const string& ca = "",
	const string& cert = "",
	const string& key = "",
	const string& unix_socket = "",
	int timeout_ms = 10000
) {
	const auto deadline = std::chrono::steady_clock::now() +
		std::chrono::milliseconds(timeout_ms);
	do {
		http_result r = http_get(url, ca, cert, key, unix_socket, 3);
		if (r.rc == CURLE_OK && r.code == expected_code) {
			return true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(150));
	} while (std::chrono::steady_clock::now() < deadline);
	return false;
}

static void drain_results(MYSQL* mysql) {
	while (true) {
		MYSQL_RES* res = mysql_store_result(mysql);
		if (res) mysql_free_result(res);
		if (mysql_next_result(mysql) != 0) break;
	}
}

static bool admin_query(MYSQL* admin, const string& query, bool log_failure = true) {
	if (mysql_query(admin, query.c_str()) != 0) {
		if (log_failure) {
			diag("Admin query failed: %s -- %s", query.c_str(), mysql_error(admin));
		}
		return false;
	}
	drain_results(admin);
	return true;
}

static string scalar(MYSQL* admin, const string& query) {
	if (mysql_query(admin, query.c_str()) != 0) {
		diag("Scalar query failed: %s -- %s", query.c_str(), mysql_error(admin));
		return {};
	}
	MYSQL_RES* res = mysql_store_result(admin);
	string value;
	if (res) {
		MYSQL_ROW row = mysql_fetch_row(res);
		if (row && row[0]) value = row[0];
		mysql_free_result(res);
	}
	drain_results(admin);
	return value;
}

static string read_file(const string& path) {
	std::ifstream in(path, std::ios::in | std::ios::binary);
	if (!in.is_open()) return {};
	return string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

static bool write_file(const string& path, const string& data, mode_t mode) {
	std::ofstream out(path, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!out.is_open()) return false;
	out.write(data.data(), static_cast<std::streamsize>(data.size()));
	out.close();
	chmod(path.c_str(), mode);
	return out.good();
}

static string resolve_ipv4(const string& host) {
	struct addrinfo hints {};
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	struct addrinfo* result = nullptr;
	if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || !result) {
		return {};
	}
	char buf[INET_ADDRSTRLEN] {};
	const auto* addr = reinterpret_cast<const struct sockaddr_in*>(result->ai_addr);
	const char* rc = inet_ntop(AF_INET, &addr->sin_addr, buf, sizeof(buf));
	freeaddrinfo(result);
	return rc ? string(buf) : string {};
}

static string resolve_ipv6(const string& host) {
	struct addrinfo hints {};
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	struct addrinfo* result = nullptr;
	if (getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0 || !result) {
		return {};
	}
	char buf[INET6_ADDRSTRLEN] {};
	const auto* addr = reinterpret_cast<const struct sockaddr_in6*>(result->ai_addr);
	const char* rc = inet_ntop(AF_INET6, &addr->sin6_addr, buf, sizeof(buf));
	freeaddrinfo(result);
	return rc ? string(buf) : string {};
}

class pem_backup {
public:
	explicit pem_backup(std::vector<string> paths) : paths_(std::move(paths)) {
		for (const auto& path : paths_) {
			contents_.push_back(read_file(path));
		}
	}
	~pem_backup() {
		for (size_t i = 0; i < paths_.size(); ++i) {
			if (!contents_[i].empty()) {
				const mode_t mode = paths_[i].find("-key.pem") != string::npos ? 0600 : 0644;
				write_file(paths_[i], contents_[i], mode);
			}
		}
	}
	bool complete() const {
		for (const auto& content : contents_) {
			if (content.empty()) return false;
		}
		return true;
	}
private:
	std::vector<string> paths_;
	std::vector<string> contents_;
};

static bool install_pem(const string& src, const string& dst, mode_t mode) {
	const string data = read_file(src);
	if (data.empty()) {
		diag("Cannot read generated PEM %s", src.c_str());
		return false;
	}
	if (!write_file(dst, data, mode)) {
		diag("Cannot write PEM %s", dst.c_str());
		return false;
	}
	return true;
}

static bool create_ca(const string& ca_key, const string& ca_pem) {
	return run_openssl({
		"req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
		"-set_serial", "6552001", "-subj", "/CN=ProxySQL-6552-Test-CA",
		"-keyout", ca_key, "-out", ca_pem
	});
}

static bool create_server_cert(
	const string& dir, const string& ca_pem, const string& ca_key,
	const string& key, const string& cert, const string& serial
) {
	const string csr = dir + "/server.csr";
	const bool req = run_openssl({
		"req", "-new", "-newkey", "rsa:2048", "-nodes",
		"-subj", "/CN=proxysql", "-keyout", key, "-out", csr
	});
	const bool sign = req && run_openssl({
		"x509", "-req", "-days", "2", "-set_serial", serial, "-in", csr,
		"-CA", ca_pem, "-CAkey", ca_key, "-out", cert
	});
	return sign && run_openssl({ "verify", "-CAfile", ca_pem, cert });
}

static bool create_client_cert_with_eku(
	const string& dir, const string& ca_pem, const string& ca_key,
	const string& name, const string& eku, client_tls_material& material
) {
	const string prefix = dir + "/" + name;
	material.key = prefix + ".key";
	const string csr = prefix + ".csr";
	material.cert = prefix + ".pem";
	material.ca = ca_pem;
	const string ext = prefix + ".ext";

	FILE* fp = fopen(ext.c_str(), "w");
	if (!fp) return false;
	const bool wrote = fprintf(fp, "extendedKeyUsage=%s\n", eku.c_str()) > 0;
	if (fclose(fp) != 0 || !wrote) return false;

	const bool req = run_openssl({
		"req", "-new", "-newkey", "rsa:2048", "-nodes",
		"-subj", "/CN=" + name, "-keyout", material.key, "-out", csr
	});
	const bool sign = req && run_openssl({
		"x509", "-req", "-days", "2", "-set_serial", "6552100", "-in", csr,
		"-CA", ca_pem, "-CAkey", ca_key, "-extfile", ext, "-out", material.cert
	});
	return sign && run_openssl({ "verify", "-CAfile", ca_pem, material.cert });
}

static bool create_expired_client_certificate(
	const string& dir, const string& ca_pem, const string& ca_key,
	client_tls_material& material
) {
	material.key = dir + "/expired-client.key";
	const string csr = dir + "/expired-client.csr";
	material.cert = dir + "/expired-client.pem";
	material.ca = ca_pem;
	const string ca_dir = dir + "/expired-ca";
	mkdir(ca_dir.c_str(), 0755);
	const string config = ca_dir + "/ca.cnf";
	const string database = ca_dir + "/index.txt";
	const string serial_file = ca_dir + "/serial";
	const string newcerts = ca_dir + "/newcerts";
	mkdir(newcerts.c_str(), 0755);
	write_file(database, "", 0600);
	write_file(serial_file, "1000\n", 0600);

	char cfg[2048];
	snprintf(
		cfg, sizeof(cfg),
		"[ ca ]\n"
		"default_ca = CA_default\n"
		"[ CA_default ]\n"
		"dir = %s\n"
		"database = %s\n"
		"new_certs_dir = %s\n"
		"certificate = %s\n"
		"private_key = %s\n"
		"serial = %s\n"
		"default_md = sha256\n"
		"policy = policy_any\n"
		"[ policy_any ]\n"
		"commonName = supplied\n"
		"[ client_ext ]\n"
		"extendedKeyUsage = clientAuth\n",
		ca_dir.c_str(), database.c_str(), newcerts.c_str(), ca_pem.c_str(),
		ca_key.c_str(), serial_file.c_str()
	);
	if (!write_file(config, cfg, 0600)) return false;

	const bool req = run_openssl({
		"req", "-new", "-newkey", "rsa:2048", "-nodes",
		"-subj", "/CN=expired-client", "-keyout", material.key, "-out", csr
	});
	const bool sign = req && run_openssl({
		"ca", "-batch", "-config", config, "-in", csr, "-out", material.cert,
		"-startdate", "20200101000000Z", "-enddate", "20200102000000Z",
		"-extensions", "client_ext"
	});
	return sign && run_openssl({
		"verify", "-no_check_time", "-CAfile", ca_pem, material.cert
	});
}

static string served_cert_serial(const string& host, int port) {
	char cmd[512];
	snprintf(
		cmd, sizeof(cmd),
		"timeout 4 openssl s_client -connect %s:%d -servername %s </dev/null 2>/dev/null "
		"| openssl x509 -noout -serial 2>/dev/null",
		host.c_str(), port, host.c_str()
	);
	FILE* fp = popen(cmd, "r");
	if (!fp) return {};
	char buf[256] {};
	string serial;
	if (fgets(buf, sizeof(buf), fp)) {
		serial = buf;
		while (!serial.empty() &&
			(serial.back() == '\n' || serial.back() == '\r' || serial.back() == ' ')) {
			serial.pop_back();
		}
		const size_t eq = serial.find('=');
		if (eq != string::npos) serial = serial.substr(eq + 1);
	}
	pclose(fp);
	return serial;
}

static string cert_serial_from_file(const string& path) {
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "openssl x509 -in '%s' -noout -serial 2>/dev/null", path.c_str());
	FILE* fp = popen(cmd, "r");
	if (!fp) return {};
	char buf[256] {};
	string serial;
	if (fgets(buf, sizeof(buf), fp)) {
		serial = buf;
		while (!serial.empty() &&
			(serial.back() == '\n' || serial.back() == '\r' || serial.back() == ' ')) {
			serial.pop_back();
		}
		const size_t eq = serial.find('=');
		if (eq != string::npos) serial = serial.substr(eq + 1);
	}
	pclose(fp);
	return serial;
}

static bool wait_for_serial(
	const string& host, int port, const string& expected, int timeout_ms = 15000
) {
	const auto deadline = std::chrono::steady_clock::now() +
		std::chrono::milliseconds(timeout_ms);
	do {
		if (served_cert_serial(host, port) == expected) return true;
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
	} while (std::chrono::steady_clock::now() < deadline);
	return false;
}

struct cleanup_guard {
	MYSQL* admin { nullptr };
	pem_backup* backup { nullptr };
	~cleanup_guard() {
		if (!admin) return;
		admin_query(admin, "DELETE FROM restapi_routes WHERE uri='" + string(RESTAPI_ROUTE) + "'", false);
		admin_query(admin, "LOAD RESTAPI TO RUNTIME", false);
		admin_query(admin, "SET admin-restapi_use_ssl='false'", false);
		admin_query(admin, "SET admin-restapi_ssl_verify_client='false'", false);
		admin_query(admin, "SET admin-restapi_interface=''", false);
		admin_query(admin, "SET admin-restapi_ssl_ca=''", false);
		admin_query(admin, "SET admin-restapi_enabled='true'", false);
		if (backup) {
			// Destructor restores the PEM files; reload them before the next
			// listener apply so later tests see ProxySQL's original cert.
			delete backup;
			backup = nullptr;
		}
		admin_query(admin, "PROXYSQL RELOAD TLS", false);
		admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME", false);
	}
};

static int configure_reload_route(MYSQL* admin, const string& datadir, const CommandLine& cl) {
	const string script = datadir + "/reg_test_6552_reload.sh";
	char content[1024];
	snprintf(
		content, sizeof(content),
		"#!/bin/sh\n"
		"export MYSQL_PWD='%s'\n"
		"mysql -u'%s' -h127.0.0.1 -P%d -e 'PROXYSQL RELOAD TLS' >/dev/null || exit 1\n"
		"mysql -u'%s' -h127.0.0.1 -P%d -N -e 'SELECT 1' >/dev/null || exit 1\n"
		"touch '%s/reg_test_6552_sync_marker'\n"
		"echo '{\"ok\":true}'\n",
		cl.admin_password, cl.admin_username, cl.admin_port,
		cl.admin_username, cl.admin_port, datadir.c_str()
	);
	if (content[0] == '\0' || !write_file(script, content, 0755)) {
		diag("Cannot create /sync reload script %s", script.c_str());
		return EXIT_FAILURE;
	}

	if (!admin_query(admin, "DELETE FROM restapi_routes WHERE uri='" + string(RESTAPI_ROUTE) + "'")) {
		return EXIT_FAILURE;
	}
	const string insert =
		"INSERT INTO restapi_routes (active,timeout_ms,method,uri,script,comment) VALUES "
		"(1,15000,'GET','" + string(RESTAPI_ROUTE) + "','" + script + "','6552 reload')";
	if (!admin_query(admin, insert)) {
		return EXIT_FAILURE;
	}
	if (!admin_query(admin, "LOAD RESTAPI TO RUNTIME")) {
		return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int main() {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	const char* datadir_env = getenv("REGULAR_INFRA_DATADIR");
	const string datadir = datadir_env ? datadir_env : "/var/lib/proxysql";
	const string cert_dir = datadir + "/reg_test_6552_certs";
	mkdir(cert_dir.c_str(), 0755);
	temporary_certificate_directory client_fixtures(cert_dir);
	if (!client_fixtures.valid()) {
		diag("Cannot create client certificate fixture directory under %s", cert_dir.c_str());
		return EXIT_FAILURE;
	}

	const string ca_key = cert_dir + "/ca.key";
	const string ca_pem = cert_dir + "/ca.pem";
	const string server_key = cert_dir + "/server.key";
	const string server_cert = cert_dir + "/server.pem";
	const string server_cert2 = cert_dir + "/server2.pem";
	const string server_key2 = cert_dir + "/server2.key";

	const string installed_ca = datadir + "/proxysql-ca.pem";
	const string installed_key = datadir + "/proxysql-key.pem";
	const string installed_cert = datadir + "/proxysql-cert.pem";

	pem_backup* backup = new pem_backup({ installed_ca, installed_key, installed_cert });
	if (!backup->complete()) {
		diag("Cannot back up existing ProxySQL PEM files in %s", datadir.c_str());
		delete backup;
		return EXIT_FAILURE;
	}

	MYSQL* admin = mysql_init(nullptr);
	if (!admin || !mysql_real_connect(
			admin, cl.admin_host, cl.admin_username, cl.admin_password,
			nullptr, cl.admin_port, nullptr, 0)) {
		diag("Admin connect failed: %s", admin ? mysql_error(admin) : "mysql_init failed");
		return EXIT_FAILURE;
	}

	cleanup_guard cleanup;
	cleanup.admin = admin;
	cleanup.backup = backup;

	curl_global_init(CURL_GLOBAL_ALL);
	plan(NO_PLAN);

	const string host = cl.admin_host;
	const string restapi_host = host + ":" + std::to_string(RESTAPI_TEST_PORT);
	const string http_url = "http://" + restapi_host + "/metrics";
	const string https_url = "https://" + restapi_host + "/metrics";

	// ---------------------------------------------------------------- setup
	ok(create_ca(ca_key, ca_pem), "generated test CA");
	ok(create_server_cert(cert_dir, ca_pem, ca_key, server_key, server_cert, "6552201"),
		"generated CA-signed server certificate");
	ok(create_server_cert(cert_dir, ca_pem, ca_key, server_key2, server_cert2, "6552202"),
		"generated second CA-signed server certificate");
	ok(install_pem(ca_pem, installed_ca, 0644), "installed test CA in ProxySQL datadir");
	ok(install_pem(server_key, installed_key, 0600), "installed test server key");
	ok(install_pem(server_cert, installed_cert, 0644), "installed test server certificate");

	admin_query(admin, "SET admin-restapi_enabled='true'");
	admin_query(admin, "SET admin-restapi_port=" + std::to_string(RESTAPI_TEST_PORT));
	admin_query(admin, "SET admin-restapi_use_ssl='false'");
	admin_query(admin, "SET admin-restapi_ssl_verify_client='false'");
	admin_query(admin, "SET admin-restapi_interface=''");
	admin_query(admin, "SET admin-restapi_ssl_ca=''");
	ok(admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME"), "LOAD ADMIN VARIABLES succeeds");
	ok(admin_query(admin, "PROXYSQL RELOAD TLS"), "PROXYSQL RELOAD TLS succeeds");

	// --------------------------------------------------- defaults / roundtrip
	ok(wait_for_http(http_url, 200), "default HTTP listener serves /metrics on all interfaces");

	ok(scalar(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='admin-restapi_use_ssl'") == "false",
		"global_variables round-trips admin-restapi_use_ssl=false");
	ok(scalar(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='admin-restapi_ssl_verify_client'") == "false",
		"global_variables round-trips admin-restapi_ssl_verify_client=false");
	ok(scalar(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='admin-restapi_interface'").empty(),
		"global_variables round-trips empty admin-restapi_interface");
	ok(scalar(admin,
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='admin-restapi_use_ssl'") == "false",
		"runtime_global_variables has admin-restapi_use_ssl");
	ok(scalar(admin,
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='admin-restapi_ssl_verify_client'") == "false",
		"runtime_global_variables has admin-restapi_ssl_verify_client");
	ok(admin_query(admin, "SAVE ADMIN VARIABLES TO DISK"),
		"SAVE ADMIN VARIABLES TO DISK succeeds");
	ok(scalar(admin,
		"SELECT variable_value FROM disk.global_variables WHERE variable_name='admin-restapi_use_ssl'") == "false",
		"disk.global_variables round-trips admin-restapi_use_ssl=false");

	// ------------------------------------------------------------- HTTPS
	admin_query(admin, "SET admin-restapi_use_ssl='true'");
	admin_query(admin, "SET admin-restapi_ssl_verify_client='false'");
	admin_query(admin, "SET admin-restapi_ssl_ca=''");
	admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	ok(wait_for_http(https_url, 200), "HTTPS listener serves /metrics with ProxySQL cert");
	{
		http_result plain = http_get(http_url);
		ok(!(plain.rc == CURLE_OK && plain.code == 200),
			"plain HTTP does not return 200 on an HTTPS listener (rc=%d code=%ld)",
			static_cast<int>(plain.rc), plain.code);
	}

	// ----------------------------------- /sync calls RELOAD TLS + new admin
	ok(configure_reload_route(admin, datadir, cl) == EXIT_SUCCESS,
		"configured /sync route that reloads TLS and opens a second admin connection");
	{
		const string sync_marker = datadir + "/reg_test_6552_sync_marker";
		unlink(sync_marker.c_str());
		http_result sync_result {};
		const auto started = std::chrono::steady_clock::now();
		// curl has its own bounded timeout; always join before cleanup.
		std::thread sync_call([&]() {
			sync_result = http_get(
				"https://" + restapi_host + "/sync/" + RESTAPI_ROUTE,
				"", "", "", "", 20);
		});
		sync_call.join();
		const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now() - started).count();
		// The reload intentionally restarts the listener, so the connection
		// that requested it may be reset after the script has already run.
		// What matters is that the admin path did not deadlock: the script
		// completed promptly, opened its second admin connection, and created
		// the marker. A clean 200 is also accepted.
		ok(elapsed_ms < 10000,
			"/sync RELOAD TLS did not deadlock the admin path (%lld ms)",
			static_cast<long long>(elapsed_ms));
		ok(access(sync_marker.c_str(), F_OK) == 0,
			"/sync script completed, including its second admin connection "
			"(rc=%d code=%ld)", static_cast<int>(sync_result.rc), sync_result.code);
		if (sync_result.rc == CURLE_OK && sync_result.code == 200) {
			ok(sync_result.body.find("\"ok\":true") != string::npos,
				"/sync RELOAD TLS returned the script JSON");
		} else {
			diag("note: /sync connection was reset by the intentional listener "
				"restart after the script completed (rc=%d code=%ld)",
				static_cast<int>(sync_result.rc), sync_result.code);
			skip(1, "/sync response body unavailable on restarted listener");
		}
	}
	ok(wait_for_http(https_url, 200), "HTTPS listener recovered after /sync TLS reload");

	// TLS reload changes the served certificate without process restart.
	{
		const string before = served_cert_serial(host, RESTAPI_TEST_PORT);
		const string expected_after = cert_serial_from_file(server_cert2);
		ok(!before.empty(), "read certificate serial before TLS reload");
		ok(!expected_after.empty() && before != expected_after,
			"generated second certificate has a distinct serial (%s -> %s)",
			before.c_str(), expected_after.c_str());
		ok(install_pem(server_key2, installed_key, 0600) &&
			install_pem(server_cert2, installed_cert, 0644),
			"installed second server certificate");
		ok(admin_query(admin, "PROXYSQL RELOAD TLS"), "PROXYSQL RELOAD TLS for certificate rotation");
		ok(wait_for_serial(host, RESTAPI_TEST_PORT, expected_after),
			"HTTPS serves the newly loaded certificate serial after RELOAD TLS");
	}

	// ------------------------------------------------------------- mTLS
	client_tls_material trusted {};
	client_tls_material untrusted {};
	client_tls_material server_auth_only {};
	client_tls_material expired {};
	ok(create_trusted_client_certificate(client_fixtures, ca_pem, ca_key, trusted),
		"generated trusted client certificate");
	ok(create_untrusted_client_certificate(client_fixtures, ca_pem, untrusted),
		"generated untrusted client certificate");
	ok(create_client_cert_with_eku(
		cert_dir, ca_pem, ca_key, "server-auth-only", "serverAuth", server_auth_only),
		"generated serverAuth-only client certificate");
	ok(create_expired_client_certificate(cert_dir, ca_pem, ca_key, expired),
		"generated expired client certificate");

	admin_query(admin, "SET admin-restapi_ssl_verify_client='true'");
	admin_query(admin, "SET admin-restapi_ssl_ca='proxysql-ca.pem'");
	admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	// Readiness means BOTH the positive and the enforced-negative paths work
	// simultaneously; a closed port during async restart would otherwise make
	// a rejection assertion pass spuriously.
	bool mtls_ready = false;
	http_result mtls_trusted {};
	http_result mtls_missing {};
	const auto mtls_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
	do {
		mtls_trusted = http_get(https_url, ca_pem, trusted.cert, trusted.key);
		mtls_missing = http_get(https_url, ca_pem);
		if (mtls_trusted.rc == CURLE_OK && mtls_trusted.code == 200 &&
			mtls_missing.rc == CURLE_OK && mtls_missing.code == 403) {
			mtls_ready = true;
			break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
	} while (std::chrono::steady_clock::now() < mtls_deadline);
	ok(mtls_ready,
		"mTLS listener enforces certs while still accepting the trusted client "
		"(trusted=%ld missing=%ld)", mtls_trusted.code, mtls_missing.code);

	{
		http_result invalid = http_get(https_url, ca_pem, untrusted.cert, untrusted.key);
		ok(invalid.code == 403 || invalid.rc != CURLE_OK,
			"mTLS rejects a client certificate from an untrusted CA (rc=%d code=%ld)",
			static_cast<int>(invalid.rc), invalid.code);
	}
	{
		http_result wrong_purpose = http_get(
			https_url, ca_pem, server_auth_only.cert, server_auth_only.key);
		ok(wrong_purpose.code == 403 || wrong_purpose.rc != CURLE_OK,
			"mTLS rejects a serverAuth-only client certificate (rc=%d code=%ld)",
			static_cast<int>(wrong_purpose.rc), wrong_purpose.code);
	}
	{
		http_result expired_result = http_get(
			https_url, ca_pem, expired.cert, expired.key);
		ok(expired_result.code == 403 || expired_result.rc != CURLE_OK,
			"mTLS rejects an expired client certificate (rc=%d code=%ld)",
			static_cast<int>(expired_result.rc), expired_result.code);
	}

	// Every resource is behind the same gate, including /sync and TSDB.
	const string sync_marker = datadir + "/reg_test_6552_sync_marker";
	unlink(sync_marker.c_str());
	{
		http_result sync_missing = http_get(
			"https://" + restapi_host + "/sync/" + RESTAPI_ROUTE, ca_pem);
		ok(sync_missing.code == 403 || sync_missing.rc != CURLE_OK,
			"mTLS rejects /sync without a client certificate (rc=%d code=%ld)",
			static_cast<int>(sync_missing.rc), sync_missing.code);
		ok(access(sync_marker.c_str(), F_OK) != 0,
			"rejected /sync request did not execute the script");
	}
	{
		http_result tsdb_missing = http_get(
			"https://" + restapi_host + "/api/tsdb/status", ca_pem);
		ok(tsdb_missing.code == 403 || tsdb_missing.rc != CURLE_OK,
			"mTLS rejects TSDB resources without a client certificate (rc=%d code=%ld)",
			static_cast<int>(tsdb_missing.rc), tsdb_missing.code);
	}
	ok(wait_for_http(https_url, 200, ca_pem, trusted.cert, trusted.key),
		"mTLS listener still accepts the trusted client after rejections");

	// ---------------------------------------------- fail closed configuration
	admin_query(admin, "SET admin-restapi_use_ssl='false'");
	admin_query(admin, "SET admin-restapi_ssl_verify_client='true'");
	admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	std::this_thread::sleep_for(std::chrono::milliseconds(1500));
	{
		http_result plain = http_get(http_url);
		http_result tls = http_get(https_url);
		ok(!(plain.rc == CURLE_OK && plain.code == 200),
			"verify_client without use_ssl does not serve plain HTTP (rc=%d code=%ld)",
			static_cast<int>(plain.rc), plain.code);
		ok(!(tls.rc == CURLE_OK && tls.code == 200),
			"verify_client without use_ssl does not silently become HTTPS either");
	}

	// ---------------------------------------------------------- interface bind
	admin_query(admin, "SET admin-restapi_ssl_verify_client='false'");
	admin_query(admin, "SET admin-restapi_port=" + std::to_string(RESTAPI_TEST_PORT));
	const string proxysql_ip = resolve_ipv4(host);
	ok(!proxysql_ip.empty(), "resolved ProxySQL container address");
	if (!proxysql_ip.empty()) {
		const string bound_url = "http://" + proxysql_ip + ":" + std::to_string(RESTAPI_TEST_PORT) + "/metrics";
		admin_query(admin, "SET admin-restapi_interface='" + proxysql_ip + "'");
		ok(admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME"), "LOAD bound interface");
		ok(wait_for_http(bound_url, 200), "listener binds the configured IPv4 address");
	}

	const string proxysql_ip6 = resolve_ipv6(host);
	if (!proxysql_ip6.empty()) {
		const string bound_url6 =
			"http://[" + proxysql_ip6 + "]:" + std::to_string(RESTAPI_TEST_PORT) + "/metrics";
		admin_query(admin, "SET admin-restapi_interface='" + proxysql_ip6 + "'");
		ok(admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME"), "LOAD bound IPv6 interface");
		ok(wait_for_http(bound_url6, 200), "listener actually binds the configured IPv6 address");
	} else {
		skip(2, "ProxySQL container has no IPv6 address to bind");
	}

	admin_query(admin, "SET admin-restapi_interface='not-an-ip'");
	admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	std::this_thread::sleep_for(std::chrono::milliseconds(1200));
	{
		http_result invalid = http_get(http_url);
		ok(!(invalid.rc == CURLE_OK && invalid.code == 200),
			"invalid interface fails closed instead of binding all interfaces (rc=%d code=%ld)",
			static_cast<int>(invalid.rc), invalid.code);
	}

	// A pre-existing non-socket path must be rejected and left untouched.
	const string blocked_path = datadir + "/reg_test_6552_blocked.sock";
	ok(write_file(blocked_path, "do-not-delete", 0644), "created non-socket path fixture");
	admin_query(admin, "SET admin-restapi_interface='" + blocked_path + "'");
	admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	std::this_thread::sleep_for(std::chrono::milliseconds(1200));
	ok(read_file(blocked_path) == "do-not-delete",
		"pre-existing non-socket path is not unlinked");
	unlink(blocked_path.c_str());

	const string unix_socket_path = datadir + "/reg_test_6552.sock";
	unlink(unix_socket_path.c_str());
	admin_query(admin, "SET admin-restapi_interface='" + unix_socket_path + "'");
	admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	ok(wait_for_http("http://localhost/metrics", 200, "", "", "", unix_socket_path),
		"Unix socket listener serves /metrics");

	// Leaving the Unix socket configuration removes the owned socket path.
	admin_query(admin, "SET admin-restapi_interface=''");
	admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	ok(wait_for_http(http_url, 200), "returned to all-interface TCP bind");
	{
		const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		while (access(unix_socket_path.c_str(), F_OK) == 0 &&
			std::chrono::steady_clock::now() < deadline) {
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
		ok(access(unix_socket_path.c_str(), F_OK) != 0,
			"owned Unix socket path is removed when the listener is reconfigured");
	}

	// ---------------------------------------------- rapid reload coalescing
	for (int i = 0; i < 5; ++i) {
		admin_query(admin, "PROXYSQL RELOAD TLS");
		admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	}
	ok(wait_for_http(http_url, 200), "rapid RELOAD TLS / LOAD coalesces to a serving listener");

	// Restore the original files and HTTP defaults before other tests run.
	admin_query(admin, "DELETE FROM restapi_routes WHERE uri='" + string(RESTAPI_ROUTE) + "'");
	admin_query(admin, "LOAD RESTAPI TO RUNTIME");
	admin_query(admin, "SET admin-restapi_use_ssl='false'");
	admin_query(admin, "SET admin-restapi_ssl_verify_client='false'");
	admin_query(admin, "SET admin-restapi_interface=''");
	admin_query(admin, "SET admin-restapi_ssl_ca=''");
	admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	delete cleanup.backup;
	cleanup.backup = nullptr;
	ok(admin_query(admin, "PROXYSQL RELOAD TLS"), "restore original TLS material");
	ok(wait_for_http(http_url, 200), "restored default HTTP listener is healthy");

	curl_global_cleanup();
	cleanup.admin = nullptr;
	mysql_close(admin);
	return exit_status();
}
