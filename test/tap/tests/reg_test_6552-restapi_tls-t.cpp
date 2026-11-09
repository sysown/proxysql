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

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <sstream>
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

struct variable_row {
	string name;
	string value;
};

struct http_result {
	long code { 0 };
	CURLcode rc { CURLE_OK };
	string body {};
};

static size_t write_body_cb(char* data, size_t size, size_t nmemb, void* userp) {
	string* out = static_cast<string*>(userp);
	out->append(data, size * nmemb);
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
	curl_easy_setopt(curl, CURLOPT_SSLVERSION, static_cast<long>(CURL_SSLVERSION_TLSv1_2));
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_body_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &result.body);
	if (!unix_socket.empty()) {
		curl_easy_setopt(curl, CURLOPT_UNIX_SOCKET_PATH, unix_socket.c_str());
	}
	if (!ca.empty()) {
		curl_easy_setopt(curl, CURLOPT_CAINFO, ca.c_str());
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
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

static bool tcp_port_closed(const string& url) {
	CURL* curl = curl_easy_init();
	if (curl == nullptr) return false;
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1L);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2L);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 3L);
	const CURLcode rc = curl_easy_perform(curl);
	curl_easy_cleanup(curl);
	return rc == CURLE_COULDNT_CONNECT;
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

static string sql_quote(const string& value) {
	string quoted;
	quoted.reserve(value.size());
	for (const char c : value) {
		// Admin SQL is executed by SQLite, whose literals escape apostrophes
		// by doubling them. Backslashes are ordinary characters.
		if (c == '\'') quoted.push_back('\'');
		quoted.push_back(c);
	}
	return quoted;
}

static bool cleanup_query(MYSQL* admin, const string& query, const string& step) {
	if (mysql_query(admin, query.c_str()) != 0) {
		diag("Cleanup failed at %s: %s", step.c_str(), mysql_error(admin));
		return false;
	}
	drain_results(admin);
	return true;
}

static bool query_rows(
	MYSQL* admin, const string& query, std::vector<variable_row>& rows,
	const string& purpose
) {
	rows.clear();
	if (mysql_query(admin, query.c_str()) != 0) {
		diag("Snapshot query failed for %s: %s", purpose.c_str(), mysql_error(admin));
		return false;
	}
	MYSQL_RES* res = mysql_store_result(admin);
	if (res == nullptr) {
		diag("Snapshot result failed for %s: %s", purpose.c_str(), mysql_error(admin));
		drain_results(admin);
		return false;
	}
	MYSQL_ROW row = nullptr;
	while ((row = mysql_fetch_row(res)) != nullptr) {
		rows.push_back({
			row[0] != nullptr ? row[0] : "",
			row[1] != nullptr ? row[1] : ""
		});
	}
	mysql_free_result(res);
	drain_results(admin);
	return true;
}

static bool read_variable(
	MYSQL* admin, const string& table, const string& name, string& value
) {
	std::vector<variable_row> rows;
	if (!query_rows(
			admin,
			"SELECT variable_name, variable_value FROM " + table +
				" WHERE variable_name='" + sql_quote(name) + "'",
			rows, table + " " + name)) {
		return false;
	}
	if (rows.size() != 1) {
		diag("Snapshot row count for %s in %s was %zu, expected 1",
			name.c_str(), table.c_str(), rows.size());
		return false;
	}
	value = rows[0].value;
	return true;
}

static bool log_offset(const string& path, std::streamoff& offset) {
	std::ifstream log(path, std::ios::binary | std::ios::ate);
	if (!log.is_open()) return false;
	offset = log.tellg();
	return offset >= 0;
}

static bool wait_for_log_text_after(
	const string& path, std::streamoff offset, const string& needle,
	int timeout_ms = 15000
) {
	if (offset < 0) return false;
	const auto deadline = std::chrono::steady_clock::now() +
		std::chrono::milliseconds(timeout_ms);
	do {
		std::ifstream log(path, std::ios::binary);
		if (!log.is_open()) return false;
		log.seekg(offset);
		if (!log) return false;
		std::ostringstream content;
		content << log.rdbuf();
		if (content.str().find(needle) != string::npos) return true;
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	} while (std::chrono::steady_clock::now() < deadline);
	return false;
}

static bool wait_for_mtls_ready(
	const string& url, const string& ca, const string& cert, const string& key,
	long& trusted_code, long& missing_code, int timeout_ms = 15000
) {
	const auto deadline = std::chrono::steady_clock::now() +
		std::chrono::milliseconds(timeout_ms);
	do {
		http_result trusted = http_get(url, ca, cert, key);
		http_result missing = http_get(url, ca);
		trusted_code = trusted.rc == CURLE_OK ? trusted.code : -1;
		missing_code = missing.rc == CURLE_OK ? missing.code : -1;
		if (trusted.rc == CURLE_OK && trusted.code == 200 &&
			missing.rc == CURLE_OK && missing.code == 403) {
			return true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(200));
	} while (std::chrono::steady_clock::now() < deadline);
	return false;
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
	pem_backup(const pem_backup&) = delete;
	pem_backup& operator=(const pem_backup&) = delete;
	pem_backup(pem_backup&&) = delete;
	pem_backup& operator=(pem_backup&&) = delete;
	~pem_backup() {
		try {
			if (!restored_) {
				if (!restore()) {
					diag("Fallback PEM restoration failed; see diagnostics above");
				}
			}
		} catch (const std::exception& e) {
			diag("Fallback PEM restoration threw: %s", e.what());
		} catch (...) {
			diag("Fallback PEM restoration threw an unknown exception");
		}
	}
	bool restore() {
		bool ok = true;
		for (size_t i = 0; i < paths_.size(); ++i) {
			if (contents_[i].empty()) {
				ok = false;
				diag("Cannot restore empty PEM snapshot for %s", paths_[i].c_str());
				continue;
			}
			const mode_t mode = paths_[i].find("-key.pem") != string::npos ? 0600 : 0644;
			if (!write_file(paths_[i], contents_[i], mode)) {
				ok = false;
				diag("Cannot restore PEM file %s", paths_[i].c_str());
			}
		}
		restored_ = ok;
		return ok;
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
	bool restored_ { false };
};

/**
 * Own a unique fixture tree below the shared datadir. Never removes a path this
 * test did not create. The tree stays world-traversable so the ProxySQL process
 * can read fixture CAs; only explicitly created files are removed with it.
 */
class owned_fixture_tree {
public:
	explicit owned_fixture_tree(const string& parent) {
		const string template_value = parent + "/reg_test_6552-XXXXXX";
		std::vector<char> template_path(template_value.begin(), template_value.end());
		template_path.push_back('\0');
		char* made = mkdtemp(template_path.data());
		if (made != nullptr) {
			path_ = made;
			chmod(path_.c_str(), 0755);
		}
	}
	~owned_fixture_tree() {
		try {
			if (!cleaned_ && !path_.empty()) {
				if (!cleanup()) {
					diag("Fallback fixture cleanup failed for %s", path_.c_str());
				}
			}
		} catch (const std::exception& e) {
			diag("Fallback fixture cleanup threw: %s", e.what());
		} catch (...) {
			diag("Fallback fixture cleanup threw an unknown exception");
		}
	}
	owned_fixture_tree(const owned_fixture_tree&) = delete;
	owned_fixture_tree& operator=(const owned_fixture_tree&) = delete;

	bool cleanup() {
		if (path_.empty()) return true;
		if (cleaned_) return true;
		std::error_code ec;
		std::filesystem::remove_all(path_, ec);
		if (ec) {
			diag("Cannot remove owned fixture tree %s: %s",
				path_.c_str(), ec.message().c_str());
			return false;
		}
		cleaned_ = true;
		return true;
	}
	bool valid() const { return !path_.empty(); }
	const string& path() const { return path_; }
private:
	string path_ {};
	bool cleaned_ { false };
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
	mkdir(ca_dir.c_str(), 0700);
	const string config = ca_dir + "/ca.cnf";
	const string database = ca_dir + "/index.txt";
	const string serial_file = ca_dir + "/serial";
	const string newcerts = ca_dir + "/newcerts";
	mkdir(newcerts.c_str(), 0700);
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
	cleanup_guard() = default;
	cleanup_guard(const cleanup_guard&) = delete;
	cleanup_guard& operator=(const cleanup_guard&) = delete;
	cleanup_guard(cleanup_guard&&) = delete;
	cleanup_guard& operator=(cleanup_guard&&) = delete;

	MYSQL* admin { nullptr };
	pem_backup* backup { nullptr };
	owned_fixture_tree* fixtures { nullptr };
	std::vector<variable_row> disk_admin_before {};
	std::vector<variable_row> memory_admin_before {};
	std::vector<variable_row> runtime_admin_before {};
	bool state_ready { false };
	bool done { false };

	bool restore_admin_rows(
		const string& table, const std::vector<variable_row>& before
	) {
		bool ok = cleanup_query(
			admin,
			"DELETE FROM " + table + " WHERE variable_name LIKE 'admin-%'",
			"clear admin variables in " + table);
		for (const variable_row& row : before) {
			const string query =
				"INSERT OR REPLACE INTO " + table + " "
				"(variable_name, variable_value) VALUES ('" +
				sql_quote(row.name) + "','" + sql_quote(row.value) + "')";
			ok = cleanup_query(admin, query, "restore " + row.name + " in " + table) && ok;
		}
		return ok;
	}

	bool restore_disk_admin() {
		return restore_admin_rows("disk.global_variables", disk_admin_before);
	}

	bool restore_runtime_and_memory() {
		// Apply the original runtime values through memory, then put the
		// original memory values back. This preserves intentional
		// memory/runtime differences for every admin variable: LOAD applies
		// the entire admin scope, including values unrelated to this test.
		bool ok = restore_admin_rows("global_variables", runtime_admin_before);
		ok = cleanup_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME",
			"load runtime baseline") && ok;
		ok = restore_admin_rows("global_variables", memory_admin_before) && ok;
		return ok;
	}

	bool matches_baseline(const string& table, const std::vector<variable_row>& before) {
		std::vector<variable_row> actual;
		if (!query_rows(admin,
				"SELECT variable_name, variable_value FROM " + table +
				" WHERE variable_name LIKE 'admin-%' ORDER BY variable_name",
				actual, "verify restored " + table)) return false;
		if (actual.size() != before.size()) return false;
		for (size_t i = 0; i < before.size(); ++i) {
			if (actual[i].name != before[i].name || actual[i].value != before[i].value) return false;
		}
		return true;
	}

	bool run() {
		if (done) return true;
		done = true;
		bool ok = true;
		if (state_ready && admin != nullptr) {
			ok = cleanup_query(
				admin,
				"DELETE FROM restapi_routes WHERE uri='" + string(RESTAPI_ROUTE) + "'",
				"delete RESTAPI route") && ok;
			ok = cleanup_query(admin, "LOAD RESTAPI TO RUNTIME", "load RESTAPI routes") && ok;
			ok = restore_disk_admin() && ok;
			ok = restore_runtime_and_memory() && ok;
		}
		if (backup != nullptr) {
			ok = backup->restore() && ok;
		}
		if (state_ready && admin != nullptr) {
			ok = cleanup_query(admin, "PROXYSQL RELOAD TLS", "reload restored TLS material") && ok;
		}
		if (fixtures != nullptr) {
			ok = fixtures->cleanup() && ok;
		}
		return ok;
	}

	~cleanup_guard() {
		try {
			if (!done) {
				if (!run()) {
					diag("Fallback cleanup failed; see diagnostics above");
				}
			}
		} catch (const std::exception& e) {
			diag("Fallback cleanup threw: %s", e.what());
		} catch (...) {
			diag("Fallback cleanup threw an unknown exception");
		}
	}
};

static bool snapshot_test_state(MYSQL* admin, cleanup_guard& cleanup) {
	return query_rows(admin,
		"SELECT variable_name, variable_value FROM global_variables "
		"WHERE variable_name LIKE 'admin-%' ORDER BY variable_name",
		cleanup.memory_admin_before, "memory admin rows") &&
		query_rows(admin,
		"SELECT variable_name, variable_value FROM runtime_global_variables "
		"WHERE variable_name LIKE 'admin-%' ORDER BY variable_name",
		cleanup.runtime_admin_before, "runtime admin rows") && query_rows(
		admin,
		"SELECT variable_name, variable_value FROM disk.global_variables "
		"WHERE variable_name LIKE 'admin-%' ORDER BY variable_name",
		cleanup.disk_admin_before, "disk.global_variables admin rows");
}

static void test_distinct_admin_baselines(MYSQL* admin, cleanup_guard& original) {
	// Use an unrelated setting to prove that the SAVE/LOAD scope is wider
	// than REST, and a quoted value to exercise SQLite literal restoration.
	const string quoted_ca = "disk's\\CA.pem";
	const bool seeded =
		admin_query(admin, "SET admin-refresh_interval='2222'") &&
		admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME") &&
		admin_query(admin, "SET admin-refresh_interval='3333'") &&
		admin_query(admin, "UPDATE disk.global_variables SET variable_value='1111' "
			"WHERE variable_name='admin-refresh_interval'") &&
		admin_query(admin, "UPDATE disk.global_variables SET variable_value='" +
			sql_quote(quoted_ca) + "' WHERE variable_name='admin-restapi_ssl_ca'");
	ok(seeded, "created distinct unrelated disk, memory and runtime admin baselines");
	cleanup_guard probe;
	probe.admin = admin;
	probe.done = true; // The outer guard owns restoration on every exit path.
	const bool captured = seeded && snapshot_test_state(admin, probe);
	ok(captured, "captured all three distinct admin baselines");
	if (captured) {
		const bool overwritten = admin_query(admin, "SET admin-refresh_interval='4444'") &&
			admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME") &&
			admin_query(admin, "SAVE ADMIN VARIABLES TO DISK");
		const bool disk_restored = probe.restore_disk_admin();
		const bool runtime_restored = probe.restore_runtime_and_memory();
		const bool restored = disk_restored && runtime_restored;
		ok(overwritten && restored &&
			probe.matches_baseline("disk.global_variables", probe.disk_admin_before) &&
			probe.matches_baseline("global_variables", probe.memory_admin_before) &&
			probe.matches_baseline("runtime_global_variables", probe.runtime_admin_before),
			"restoration preserves the complete, independently differing admin layers");
		string restored_ca;
		ok(read_variable(admin, "disk.global_variables", "admin-restapi_ssl_ca", restored_ca) &&
			restored_ca == quoted_ca, "disk restoration preserves apostrophes and backslashes");
	} else {
		skip(2, "distinct-baseline fixture could not be prepared");
	}
	const bool disk_restored = original.restore_disk_admin();
	const bool runtime_restored = original.restore_runtime_and_memory();
	const bool restored = disk_restored && runtime_restored;
	ok(restored, "returned to the original admin state after the mismatch probe");
}

static int configure_reload_route(MYSQL* admin, const string& fixture_runtime_dir, const CommandLine& cl) {
	const string script = fixture_runtime_dir + "/reg_test_6552_reload.sh";
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
		cl.admin_username, cl.admin_port, fixture_runtime_dir.c_str()
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
	owned_fixture_tree fixture_tree(datadir);
	if (!fixture_tree.valid()) {
		diag("Cannot create owned fixture tree under %s: %s",
			datadir.c_str(), strerror(errno));
		return EXIT_FAILURE;
	}
	const string fixture_root = fixture_tree.path();
	const string cert_dir = fixture_root;
	const string runtime_dir = fixture_root + "/runtime";
	if ((mkdir(runtime_dir.c_str(), 0777) != 0 && errno != EEXIST) ||
		chmod(runtime_dir.c_str(), 0777) != 0) {
		diag("Cannot create runtime fixture directory %s: %s",
			runtime_dir.c_str(), strerror(errno));
		return EXIT_FAILURE;
	}
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
	const string retry_ca = cert_dir + "/retry-ca.pem";

	const string installed_ca = datadir + "/proxysql-ca.pem";
	const string installed_key = datadir + "/proxysql-key.pem";
	const string installed_cert = datadir + "/proxysql-cert.pem";

	pem_backup backup({ installed_ca, installed_key, installed_cert });
	if (!backup.complete()) {
		diag("Cannot back up existing ProxySQL PEM files in %s", datadir.c_str());
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
	cleanup.backup = &backup;
	cleanup.fixtures = &fixture_tree;
	if (!snapshot_test_state(admin, cleanup)) {
		diag("Cannot snapshot REST/admin state before test mutations");
		mysql_close(admin);
		return EXIT_FAILURE;
	}
	cleanup.state_ready = true;

	curl_global_init(CURL_GLOBAL_ALL);
	plan(NO_PLAN);
	test_distinct_admin_baselines(admin, cleanup);

	const string host = cl.admin_host;
	const string restapi_host = host + ":" + std::to_string(RESTAPI_TEST_PORT);
	const string http_url = "http://" + restapi_host + "/metrics";
	const string https_url = "https://" + restapi_host + "/metrics";
	const string proxysql_log = datadir + "/proxysql.log";

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
		"SELECT COUNT(*) FROM global_variables WHERE variable_name='admin-restapi_interface'") == "1",
		"global_variables contains the admin-restapi_interface row");
	ok(scalar(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='admin-restapi_interface'").empty(),
		"global_variables round-trips empty admin-restapi_interface");
	ok(scalar(admin,
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='admin-restapi_use_ssl'") == "false",
		"runtime_global_variables has admin-restapi_use_ssl");
	ok(scalar(admin,
		"SELECT variable_value FROM runtime_global_variables WHERE variable_name='admin-restapi_ssl_verify_client'") == "false",
		"runtime_global_variables has admin-restapi_ssl_verify_client");
	ok(admin_query(admin, "SET admin-restapi_ssl_ca='proxysql-ca.pem'"),
		"set admin-restapi_ssl_ca for persistence round-trip");
	ok(scalar(admin,
		"SELECT COUNT(*) FROM global_variables WHERE variable_name='admin-restapi_ssl_ca'") == "1",
		"global_variables contains the admin-restapi_ssl_ca row");
	ok(scalar(admin,
		"SELECT variable_value FROM global_variables WHERE variable_name='admin-restapi_ssl_ca'") == "proxysql-ca.pem",
		"global_variables round-trips explicit admin-restapi_ssl_ca");
	ok(admin_query(admin, "SAVE ADMIN VARIABLES TO DISK"),
		"SAVE ADMIN VARIABLES TO DISK succeeds");
	ok(scalar(admin,
		"SELECT variable_value FROM disk.global_variables WHERE variable_name='admin-restapi_use_ssl'") == "false",
		"disk.global_variables round-trips admin-restapi_use_ssl=false");
	ok(scalar(admin,
		"SELECT variable_value FROM disk.global_variables WHERE variable_name='admin-restapi_ssl_ca'") == "proxysql-ca.pem",
		"disk.global_variables round-trips explicit admin-restapi_ssl_ca");

	// ------------------------------------------------------------- HTTPS
	admin_query(admin, "SET admin-restapi_use_ssl='true'");
	admin_query(admin, "SET admin-restapi_ssl_verify_client='false'");
	admin_query(admin, "SET admin-restapi_ssl_ca=''");
	admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	ok(wait_for_http(https_url, 200, ca_pem), "HTTPS listener serves /metrics with ProxySQL cert");
	{
		http_result plain = http_get(http_url);
		ok(!(plain.rc == CURLE_OK && plain.code == 200),
			"plain HTTP does not return 200 on an HTTPS listener (rc=%d code=%ld)",
			static_cast<int>(plain.rc), plain.code);
	}

	// ----------------------------------- /sync calls RELOAD TLS + new admin
	ok(configure_reload_route(admin, runtime_dir, cl) == EXIT_SUCCESS,
		"configured /sync route that reloads TLS and opens a second admin connection");
	{
		const string sync_marker = runtime_dir + "/reg_test_6552_sync_marker";
		unlink(sync_marker.c_str());
		http_result sync_result {};
		const auto started = std::chrono::steady_clock::now();
		// curl has its own bounded timeout; always join before cleanup.
		std::thread sync_call([&sync_result, &restapi_host, &ca_pem]() {
			sync_result = http_get(
				"https://" + restapi_host + "/sync/" + RESTAPI_ROUTE,
				ca_pem, "", "", "", 20);
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
	ok(wait_for_http(https_url, 200, ca_pem), "HTTPS listener recovered after /sync TLS reload");

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

	// The empty CA value exercises GloVars.get_SSL_ca_pem_mem() fallback to
	// ProxySQL's global proxysql-ca.pem before the explicit path variant.
	admin_query(admin, "SET admin-restapi_ssl_verify_client='true'");
	admin_query(admin, "SET admin-restapi_ssl_ca=''");
	admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");

	// Readiness means BOTH the positive and the enforced-negative paths work
	// simultaneously; a closed port during async restart would otherwise make
	// a rejection assertion pass spuriously.
	long mtls_trusted_code = 0;
	long mtls_missing_code = 0;
	ok(wait_for_mtls_ready(
			https_url, ca_pem, trusted.cert, trusted.key,
			mtls_trusted_code, mtls_missing_code),
		"mTLS listener accepts trusted clients and rejects missing certs "
		"through ProxySQL's global CA fallback (trusted=%ld missing=%ld)",
		mtls_trusted_code, mtls_missing_code);

	admin_query(admin, "SET admin-restapi_ssl_ca='proxysql-ca.pem'");
	admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	ok(wait_for_mtls_ready(
			https_url, ca_pem, trusted.cert, trusted.key,
			mtls_trusted_code, mtls_missing_code),
		"mTLS listener accepts trusted clients and rejects missing certs "
		"through the explicit custom CA path (trusted=%ld missing=%ld)",
		mtls_trusted_code, mtls_missing_code);

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
	const string sync_marker = runtime_dir + "/reg_test_6552_sync_marker";
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

	// A failed apply for a missing explicit CA must be retried by an identical
	// LOAD after the CA appears at the same path. Poll the shared error log for
	// the unique path so the CA cannot be installed before the first async
	// apply has definitely failed.
	{
		unlink(retry_ca.c_str());
		admin_query(admin, "SET admin-restapi_use_ssl='true'");
		admin_query(admin, "SET admin-restapi_ssl_verify_client='true'");
		admin_query(admin, "SET admin-restapi_ssl_ca='" + retry_ca + "'");
		std::streamoff log_start = -1;
		const bool have_log_start = log_offset(proxysql_log, log_start);
		admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
		ok(have_log_start && wait_for_log_text_after(
				proxysql_log, log_start,
				"cannot read admin-restapi_ssl_ca '" + retry_ca + "'"),
			"failed listener apply for the missing custom CA completed");
		http_result absent_ca = http_get(https_url, ca_pem, trusted.cert, trusted.key);
		ok(!(absent_ca.rc == CURLE_OK && absent_ca.code == 200),
			"missing custom CA leaves no mTLS listener (rc=%d code=%ld)",
			static_cast<int>(absent_ca.rc), absent_ca.code);

		ok(install_pem(ca_pem, retry_ca, 0644),
			"installed a valid CA at the previously missing path");
		admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
		ok(wait_for_mtls_ready(
				https_url, ca_pem, trusted.cert, trusted.key,
				mtls_trusted_code, mtls_missing_code),
			"identical LOAD retries and recovers the listener after the CA appears "
			"(trusted=%ld missing=%ld)", mtls_trusted_code, mtls_missing_code);
	}

	// ---------------------------------------------- fail closed configuration
	admin_query(admin, "SET admin-restapi_use_ssl='false'");
	admin_query(admin, "SET admin-restapi_ssl_verify_client='true'");
	std::streamoff fail_closed_log_start = -1;
	const bool have_fail_closed_log_start = log_offset(proxysql_log, fail_closed_log_start);
	admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	ok(have_fail_closed_log_start && wait_for_log_text_after(
			proxysql_log, fail_closed_log_start,
			"admin-restapi_ssl_verify_client=true requires admin-restapi_use_ssl=true"),
		"rejected verify_client/use_ssl combination completed after this LOAD");
	http_result plain {};
	http_result trusted_tls {};
	bool listener_stopped = false;
	const auto stopped_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	do {
		plain = http_get(http_url);
		// The old listener was mTLS, so a trusted client would still get 200
		// if the invalid configuration had been ignored.
		trusted_tls = http_get(https_url, ca_pem, trusted.cert, trusted.key);
		if (plain.rc != CURLE_OK && trusted_tls.rc != CURLE_OK && tcp_port_closed(http_url)) {
			listener_stopped = true;
			break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(150));
	} while (std::chrono::steady_clock::now() < stopped_deadline);
	ok(listener_stopped,
		"verify_client without use_ssl stops the previous mTLS listener "
		"(plain rc=%d code=%ld trusted_tls rc=%d code=%ld)",
		static_cast<int>(plain.rc), plain.code,
		static_cast<int>(trusted_tls.rc), trusted_tls.code);
	ok(plain.rc != CURLE_OK,
		"verify_client without use_ssl does not serve plain HTTP");
	ok(trusted_tls.rc != CURLE_OK,
		"verify_client without use_ssl does not keep the old trusted HTTPS listener");

	// ---------------------------------------------------------- interface bind
	admin_query(admin, "SET admin-restapi_ssl_verify_client='false'");
	admin_query(admin, "SET admin-restapi_port=" + std::to_string(RESTAPI_TEST_PORT));
	string last_bound_url;
	const string proxysql_ip = resolve_ipv4(host);
	ok(!proxysql_ip.empty(), "resolved ProxySQL container address");
	if (!proxysql_ip.empty()) {
		const string bound_url = "http://" + proxysql_ip + ":" + std::to_string(RESTAPI_TEST_PORT) + "/metrics";
		admin_query(admin, "SET admin-restapi_interface='" + proxysql_ip + "'");
		ok(admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME"), "LOAD bound interface");
		if (wait_for_http(bound_url, 200)) last_bound_url = bound_url;
		ok(!last_bound_url.empty(), "listener binds the configured IPv4 address");
	}

	const string proxysql_ip6 = resolve_ipv6(host);
	if (!proxysql_ip6.empty()) {
		const string bound_url6 =
			"http://[" + proxysql_ip6 + "]:" + std::to_string(RESTAPI_TEST_PORT) + "/metrics";
		admin_query(admin, "SET admin-restapi_interface='" + proxysql_ip6 + "'");
		ok(admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME"), "LOAD bound IPv6 interface");
		if (wait_for_http(bound_url6, 200)) last_bound_url = bound_url6;
		ok(last_bound_url == bound_url6, "listener actually binds the configured IPv6 address");
	} else {
		skip(2, "ProxySQL container has no IPv6 address to bind");
	}

	admin_query(admin, "SET admin-restapi_interface='not-an-ip'");
	std::streamoff invalid_log_start = -1;
	const bool have_invalid_log_start = log_offset(proxysql_log, invalid_log_start);
	admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	ok(have_invalid_log_start && wait_for_log_text_after(
			proxysql_log, invalid_log_start,
			"Invalid admin-restapi_interface 'not-an-ip'"),
		"rejected invalid interface completed after this LOAD");
	http_result invalid {};
	http_result previous {};
	bool previous_stopped = false;
	const auto invalid_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	do {
		invalid = http_get(http_url);
		if (!last_bound_url.empty()) previous = http_get(last_bound_url);
		const bool previous_serving = !last_bound_url.empty() &&
			previous.rc == CURLE_OK && previous.code == 200;
		if (!previous_serving && tcp_port_closed(http_url) &&
			(last_bound_url.empty() || tcp_port_closed(last_bound_url))) {
			previous_stopped = true;
			break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(150));
	} while (std::chrono::steady_clock::now() < invalid_deadline);
	ok(previous_stopped,
		"invalid interface stops the prior listener and does not bind all interfaces "
		"(default rc=%d code=%ld previous rc=%d code=%ld)",
		static_cast<int>(invalid.rc), invalid.code,
		static_cast<int>(previous.rc), previous.code);

	// Restore a known TCP listener, then prove an existing Unix path is
	// rejected without leaving that listener running.
	admin_query(admin, "SET admin-restapi_interface=''");
	admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	ok(wait_for_http(http_url, 200), "recovered default listener before blocked-path test");

	const string blocked_path = runtime_dir + "/blocked.sock";
	ok(write_file(blocked_path, "do-not-delete", 0644), "created non-socket path fixture");
	admin_query(admin, "SET admin-restapi_interface='" + blocked_path + "'");
	std::streamoff blocked_log_start = -1;
	const bool have_blocked_log_start = log_offset(proxysql_log, blocked_log_start);
	admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	ok(have_blocked_log_start && wait_for_log_text_after(
			proxysql_log, blocked_log_start,
			"Unix socket path '" + blocked_path + "' already exists; refusing to replace it"),
		"rejected pre-existing Unix path completed after this LOAD");
	bool blocked_listener_stopped = false;
	const auto blocked_deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
	do {
		plain = http_get(http_url);
		if (tcp_port_closed(http_url)) {
			blocked_listener_stopped = true;
			break;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(150));
	} while (std::chrono::steady_clock::now() < blocked_deadline);
	ok(blocked_listener_stopped,
		"blocked Unix path stops the prior listener (rc=%d code=%ld)",
		static_cast<int>(plain.rc), plain.code);
	ok(read_file(blocked_path) == "do-not-delete",
		"pre-existing non-socket path is not unlinked");
	unlink(blocked_path.c_str());

	const string unix_socket_path = runtime_dir + "/restapi.sock";
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
	// Exercise the HTTPS path so RELOAD TLS is not intentionally ignored.
	admin_query(admin, "SET admin-restapi_use_ssl='true'");
	admin_query(admin, "SET admin-restapi_ssl_verify_client='false'");
	admin_query(admin, "SET admin-restapi_interface=''");
	admin_query(admin, "SET admin-restapi_ssl_ca=''");
	admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	ok(wait_for_http(https_url, 200, ca_pem), "HTTPS listener ready for rapid reload test");
	ok(install_pem(server_key, installed_key, 0600) &&
		install_pem(server_cert, installed_cert, 0644),
		"installed replacement certificate for rapid reload test");
	const string expected_rapid_serial = cert_serial_from_file(server_cert);
	ok(!expected_rapid_serial.empty(), "read expected serial for rapid reload test");
	for (int i = 0; i < 5; ++i) {
		admin_query(admin, "PROXYSQL RELOAD TLS");
		admin_query(admin, "LOAD ADMIN VARIABLES TO RUNTIME");
	}
	ok(wait_for_serial(host, RESTAPI_TEST_PORT, expected_rapid_serial),
		"rapid RELOAD TLS / LOAD coalesces to HTTPS serving the rotated certificate serial");

	const bool cleanup_ok = cleanup.run();
	ok(cleanup_ok, "cleanup restored disk, memory, runtime and PEM state");
	ok(cleanup.matches_baseline("disk.global_variables", cleanup.disk_admin_before),
		"all original disk admin rows are restored exactly");
	ok(cleanup.matches_baseline("global_variables", cleanup.memory_admin_before),
		"all original memory admin rows are restored exactly");
	ok(cleanup.matches_baseline("runtime_global_variables", cleanup.runtime_admin_before),
		"all original runtime admin rows are restored exactly");
	ok(access(fixture_root.c_str(), F_OK) != 0 && errno == ENOENT,
		"the complete owned fixture tree is removed");
	curl_global_cleanup();
	mysql_close(admin);
	return exit_status();
}
