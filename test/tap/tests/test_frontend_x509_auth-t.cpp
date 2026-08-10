/**
 * @file test_frontend_x509_auth-t.cpp
 * @brief Covers the frontend mysql_users.attributes require_x509 policy.
 *
 * The certificate fixture deliberately signs a client certificate without a
 * SAN.  Frontend require_x509 is a client-certificate policy, not a hostname
 * validation policy, so that certificate must remain acceptable.
 */

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits.h>
#include <memory>
#include <string>

#include <sys/stat.h>
#include <unistd.h>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"
#include "command_line.h"

using std::string;

static constexpr const char* USER_NONE = "tap_x509_none";
static constexpr const char* USER_REQUIRED = "tap_x509_required";
static constexpr const char* USER_FALSE = "tap_x509_false";
static constexpr const char* USER_BAD_TYPE = "tap_x509_bad_type";
static constexpr const char* USER_CHANGE_SOURCE = "tap_x509_source";
static constexpr const char* USER_CHANGE_TARGET = "tap_x509_target";
static constexpr const char* USER_SPIFFE_SOURCE = "tap_spiffe_source";
static constexpr const char* USER_SPIFFE_TARGET = "tap_spiffe_target";
static constexpr const char* PASSWORD = "tap-x509-password";
static constexpr const char* WRONG_PASSWORD = "tap-x509-wrong-password";
static constexpr const char* CHANGE_SOURCE_PASSWORD = "source-password";
static constexpr const char* CHANGE_TARGET_PASSWORD = "target-password";

struct client_tls_material {
	string key;
	string cert;
	string ca;
};

struct mysql_closer {
	void operator()(MYSQL* mysql) const {
		if (mysql) mysql_close(mysql);
	}
};

using mysql_ptr = std::unique_ptr<MYSQL, mysql_closer>;

/** Quote one shell argument, including paths derived from the environment. */
static string shell_quote(const string& value) {
	string quoted { "'" };
	for (const char c : value) {
		if (c == '\'') {
			quoted += "'\\''";
		} else {
			quoted += c;
		}
	}
	quoted += "'";
	return quoted;
}

static bool run_openssl(const string& command) {
	diag("Running: %s", command.c_str());
	const int status = system(command.c_str());
	if (status != 0) {
		diag("openssl command failed with status %d", status);
		return false;
	}
	return true;
}

/**
 * Own exactly the path returned by mkdtemp().  Cleanup never follows a path
 * assembled from REGULAR_INFRA_DATADIR or another unchecked environment value.
 */
class temporary_certificate_directory {
	string path_ {};

public:
	temporary_certificate_directory() {
		char template_path[] = "/tmp/proxysql-require-x509-XXXXXX";
		char* made = mkdtemp(template_path);
		if (made) path_ = made;
	}

	~temporary_certificate_directory() {
		if (path_.empty()) return;
		const char* const files[] {
			"trusted-client.key", "trusted-client.csr", "trusted-client.pem",
			"untrusted-client.key", "untrusted-client.pem",
			"spiffe-source.key", "spiffe-source.csr", "spiffe-source.pem", "spiffe-source.ext",
			"spiffe-target.key", "spiffe-target.csr", "spiffe-target.pem", "spiffe-target.ext"
		};
		for (const char* file : files) {
			const string filename { path_ + "/" + file };
			unlink(filename.c_str());
		}
		rmdir(path_.c_str());
	}

	bool valid() const { return !path_.empty(); }
	const string& path() const { return path_; }
};

static bool file_is_readable(const string& path) {
	if (access(path.c_str(), R_OK) == 0) return true;
	diag("Required certificate fixture file is unavailable: %s: %s", path.c_str(), strerror(errno));
	return false;
}

static bool create_trusted_client_certificate(
	const temporary_certificate_directory& directory,
	const string& ca, const string& ca_key, client_tls_material& material
) {
	material.key = directory.path() + "/trusted-client.key";
	const string csr { directory.path() + "/trusted-client.csr" };
	material.cert = directory.path() + "/trusted-client.pem";
	material.ca = ca;

	const bool req_ok = run_openssl(
		"openssl req -new -newkey rsa:2048 -nodes -subj /CN=tap-require-x509"
		" -keyout " + shell_quote(material.key) + " -out " + shell_quote(csr)
	);
	const bool sign_ok = req_ok && run_openssl(
		"openssl x509 -req -days 1 -set_serial 5928001 -in " + shell_quote(csr) +
		" -CA " + shell_quote(ca) + " -CAkey " + shell_quote(ca_key) +
		" -out " + shell_quote(material.cert)
	);
	return sign_ok && run_openssl(
		"openssl verify -CAfile " + shell_quote(ca) + " " + shell_quote(material.cert)
	);
}

static bool create_untrusted_client_certificate(
	const temporary_certificate_directory& directory, const string& ca, client_tls_material& material
) {
	material.key = directory.path() + "/untrusted-client.key";
	material.cert = directory.path() + "/untrusted-client.pem";
	material.ca = ca;
	return run_openssl(
		"openssl req -x509 -newkey rsa:2048 -nodes -days 1 -set_serial 5928002"
		" -subj /CN=tap-untrusted -keyout " + shell_quote(material.key) +
		" -out " + shell_quote(material.cert)
	);
}

static bool create_spiffe_client_certificate(
	const temporary_certificate_directory& directory, const string& ca, const string& ca_key,
	const char* name, const char* spiffe_id, unsigned long serial, client_tls_material& material
) {
	const string prefix { directory.path() + "/" + name };
	material.key = prefix + ".key";
	const string csr { prefix + ".csr" };
	material.cert = prefix + ".pem";
	material.ca = ca;
	const string extfile { prefix + ".ext" };

	FILE* extensions = fopen(extfile.c_str(), "w");
	if (!extensions) {
		diag("Could not create SPIFFE extension file %s: %s", extfile.c_str(), strerror(errno));
		return false;
	}
	const int written = fprintf(extensions, "subjectAltName=URI:%s\n", spiffe_id);
	if (fclose(extensions) != 0 || written < 0) {
		diag("Could not write SPIFFE extension file %s: %s", extfile.c_str(), strerror(errno));
		return false;
	}

	const bool req_ok = run_openssl(
		"openssl req -new -newkey rsa:2048 -nodes -subj /CN=" + string(name) +
		" -keyout " + shell_quote(material.key) + " -out " + shell_quote(csr)
	);
	const bool sign_ok = req_ok && run_openssl(
		"openssl x509 -req -days 1 -set_serial " + std::to_string(serial) +
		" -in " + shell_quote(csr) + " -CA " + shell_quote(ca) +
		" -CAkey " + shell_quote(ca_key) + " -extfile " + shell_quote(extfile) +
		" -out " + shell_quote(material.cert)
	);
	return sign_ok && run_openssl(
		"openssl verify -CAfile " + shell_quote(ca) + " " + shell_quote(material.cert)
	);
}

/**
 * Attempt one frontend connection and return 0 on success or the client error.
 * A null client_identity means TLS is requested without a client certificate.
 */
static mysql_ptr connect_frontend(
	const CommandLine& cl,
	const char* username,
	const char* password,
	bool use_tls,
	const client_tls_material* client_identity = nullptr,
	unsigned int* connection_error = nullptr
) {
	mysql_ptr mysql { mysql_init(NULL) };
	if (!mysql) {
		if (connection_error) *connection_error = UINT_MAX;
		return nullptr;
	}

	unsigned long flags = 0;
	if (use_tls) {
		if (client_identity) {
			mysql_ssl_set(mysql.get(),
				client_identity->key.c_str(),
				client_identity->cert.c_str(),
				client_identity->ca.c_str(), nullptr, nullptr);
		} else {
			mysql_ssl_set(mysql.get(), nullptr, nullptr, nullptr, nullptr, nullptr);
		}
		flags |= CLIENT_SSL;
	}

	MYSQL* connected = mysql_real_connect(
		mysql.get(), cl.host, username, password, nullptr, cl.port, nullptr, flags);
	const unsigned int result = connected ? 0 : mysql_errno(mysql.get());
	if (connection_error) *connection_error = result;
	diag("Frontend connect user='%s' tls=%s client_cert=%s -> errno=%u '%s'",
		username, use_tls ? "yes" : "no", client_identity ? "yes" : "no",
		result, connected ? "connected" : mysql_error(mysql.get()));
	return connected ? std::move(mysql) : nullptr;
}

static unsigned int try_frontend_connect(
	const CommandLine& cl,
	const char* username,
	const char* password,
	bool use_tls,
	const client_tls_material* client_identity = nullptr
) {
	unsigned int connection_error = UINT_MAX;
	mysql_ptr mysql { connect_frontend(cl, username, password, use_tls, client_identity, &connection_error) };
	return mysql ? 0 : connection_error;
}

static unsigned int try_change_user(
	MYSQL* connection,
	const char* target_user,
	const char* target_password
) {
	return mysql_change_user(connection, target_user, target_password, nullptr) == 0
		? 0 : mysql_errno(connection);
}

static bool do_query(MYSQL* mysql, const string& query) {
	if (mysql_query(mysql, query.c_str()) == 0) return true;
	diag("Query failed: %s -- %s", query.c_str(), mysql_error(mysql));
	return false;
}

static bool read_global_variable(MYSQL* admin, const char* name, string& value) {
	const string query {
		string("SELECT variable_value FROM global_variables WHERE variable_name='") + name + "'"
	};
	if (!do_query(admin, query)) return false;
	MYSQL_RES* result = mysql_store_result(admin);
	if (!result) return false;
	MYSQL_ROW row = mysql_fetch_row(result);
	const bool found = row && row[0];
	if (found) value = row[0];
	mysql_free_result(result);
	return found;
}

int main() {
	CommandLine cl;

	const char* const datadir_env = getenv("REGULAR_INFRA_DATADIR");
	if (!datadir_env || !*datadir_env) {
		diag("SKIP: REGULAR_INFRA_DATADIR is unset; run through the isolated TAP runner, which mounts /var/lib/proxysql.");
		plan(0);
		return exit_status();
	}
	const string datadir { datadir_env };
	const string ca { datadir + "/proxysql-ca.pem" };
	const string ca_key { datadir + "/proxysql-key.pem" };
	const string server_cert { datadir + "/proxysql-cert.pem" };
	if (!file_is_readable(ca) || !file_is_readable(ca_key) || !file_is_readable(server_cert)) {
		diag("SKIP: require_x509 test needs the standard ProxySQL certificate fixture in REGULAR_INFRA_DATADIR.");
		plan(0);
		return exit_status();
	}

	if (cl.getEnv()) {
		diag("Failed to get the required TAP connection environmental variables.");
		return EXIT_FAILURE;
	}

	/*
	 * 4 setup + 4 certificate fixtures + 9 initial-login probes + 8
	 * COM_CHANGE_USER probes + 2 cleanup checks.
	 * A custom environment whose CA private key cannot sign our certificate
	 * emits TAP SKIPs only for the probes that need that trusted certificate.
	 */
	plan(27);

	mysql_ptr admin { mysql_init(NULL) };
	if (!admin || !mysql_real_connect(admin.get(), cl.host, cl.admin_username, cl.admin_password,
		NULL, cl.admin_port, NULL, 0)) {
		ok(false, "Connected to ProxySQL Admin: %s", admin ? mysql_error(admin.get()) : "mysql_init failed");
		return exit_status();
	}
	ok(true, "Connected to ProxySQL Admin at %s:%d", cl.host, cl.admin_port);

	string original_passthrough_enabled;
	const bool saved_passthrough = read_global_variable(
		admin.get(), "mysql-passthrough_auth_enabled", original_passthrough_enabled);
	ok(saved_passthrough, "Saved mysql-passthrough_auth_enabled before the test");

	const bool passthrough_disabled = saved_passthrough &&
		do_query(admin.get(), "SET mysql-passthrough_auth_enabled='false'") &&
		do_query(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME");
	ok(passthrough_disabled, "Disabled mysql-passthrough_auth_enabled for this test");

	const string user_list {
		"'tap_x509_none','tap_x509_required','tap_x509_false','tap_x509_bad_type',"
		"'tap_x509_source','tap_x509_target','tap_spiffe_source','tap_spiffe_target'"
	};
	const bool users_provisioned = do_query(admin.get(), "DELETE FROM mysql_users WHERE username IN (" + user_list + ")") &&
		do_query(admin.get(),
			"INSERT INTO mysql_users(username,password,default_hostgroup,active,attributes) VALUES "
			"('tap_x509_none','tap-x509-password',0,1,''),"
			"('tap_x509_required','tap-x509-password',0,1,'{\"require_x509\":true}'),"
			"('tap_x509_false','tap-x509-password',0,1,'{\"require_x509\":false}'),"
			"('tap_x509_bad_type','tap-x509-password',0,1,'{\"require_x509\":\"true\"}'),"
			"('tap_x509_source','source-password',0,1,''),"
			"('tap_x509_target','target-password',0,1,'{\"require_x509\":true}'),"
			"('tap_spiffe_source','',0,1,'{\"spiffe_id\":\"spiffe://tap/source\"}'),"
			"('tap_spiffe_target','',0,1,'{\"spiffe_id\":\"spiffe://tap/target\"}')") &&
		do_query(admin.get(), "LOAD MYSQL USERS TO RUNTIME");
	ok(users_provisioned, "Provisioned dedicated frontend require_x509 users");

	temporary_certificate_directory certificate_directory;
	if (!certificate_directory.valid()) {
		diag("Could not create a temporary certificate directory: %s", strerror(errno));
	}
	client_tls_material trusted_client;
	client_tls_material untrusted_client;
	client_tls_material spiffe_source_client;
	client_tls_material spiffe_target_client;
	const bool trusted_client_ready = certificate_directory.valid() &&
		create_trusted_client_certificate(certificate_directory, ca, ca_key, trusted_client);
	if (!trusted_client_ready) {
		diag("Trusted client certificate fixture unavailable. This can happen when a custom CA certificate has no matching private key; trusted-certificate probes will be skipped.");
	}
	if (trusted_client_ready) {
		ok(true, "Trusted client certificate generated and verified");
	} else if (certificate_directory.valid()) {
		ok(true, "Trusted client certificate generated and verified # SKIP custom CA cannot sign the standard test client certificate");
	} else {
		ok(false, "Trusted client certificate generated and verified (temporary directory unavailable)");
	}

	const bool untrusted_client_ready = certificate_directory.valid() &&
		create_untrusted_client_certificate(certificate_directory, ca, untrusted_client);
	ok(untrusted_client_ready, "Untrusted self-signed client certificate generated");

	const bool spiffe_source_client_ready = certificate_directory.valid() &&
		create_spiffe_client_certificate(
			certificate_directory, ca, ca_key, "spiffe-source", "spiffe://tap/source", 5928003,
			spiffe_source_client);
	if (spiffe_source_client_ready) {
		ok(true, "Trusted SPIFFE source client certificate generated and verified");
	} else {
		ok(true, "Trusted SPIFFE source client certificate generated and verified # SKIP custom CA cannot sign the SPIFFE source certificate");
	}
	const bool spiffe_target_client_ready = certificate_directory.valid() &&
		create_spiffe_client_certificate(
			certificate_directory, ca, ca_key, "spiffe-target", "spiffe://tap/target", 5928004,
			spiffe_target_client);
	if (spiffe_target_client_ready) {
		ok(true, "Trusted SPIFFE target client certificate generated and verified");
	} else {
		ok(true, "Trusted SPIFFE target client certificate generated and verified # SKIP custom CA cannot sign the SPIFFE target certificate");
	}

	ok(try_frontend_connect(cl, USER_NONE, PASSWORD, false) == 0,
		"No require_x509 attribute permits plaintext authentication");
	ok(try_frontend_connect(cl, USER_NONE, PASSWORD, true) == 0,
		"No require_x509 attribute permits TLS authentication without a client certificate");
	ok(try_frontend_connect(cl, USER_FALSE, PASSWORD, true) == 0,
		"require_x509=false permits TLS authentication without a client certificate");
	ok(try_frontend_connect(cl, USER_REQUIRED, PASSWORD, false) == ER_ACCESS_DENIED_ERROR,
		"require_x509=true rejects plaintext authentication with ER_ACCESS_DENIED_ERROR");
	ok(try_frontend_connect(cl, USER_REQUIRED, PASSWORD, true) == ER_ACCESS_DENIED_ERROR,
		"require_x509=true rejects TLS authentication without a client certificate with ER_ACCESS_DENIED_ERROR");
	ok(untrusted_client_ready &&
		try_frontend_connect(cl, USER_REQUIRED, PASSWORD, true, &untrusted_client) == ER_ACCESS_DENIED_ERROR,
		"require_x509=true rejects an untrusted client certificate with ER_ACCESS_DENIED_ERROR");
	if (trusted_client_ready) {
		ok(try_frontend_connect(cl, USER_REQUIRED, PASSWORD, true, &trusted_client) == 0,
			"require_x509=true accepts a trusted client certificate without a SAN");
		ok(try_frontend_connect(cl, USER_REQUIRED, WRONG_PASSWORD, true, &trusted_client) == ER_ACCESS_DENIED_ERROR,
			"require_x509=true still rejects a wrong password with ER_ACCESS_DENIED_ERROR");
		ok(try_frontend_connect(cl, USER_BAD_TYPE, PASSWORD, true, &trusted_client) == ER_ACCESS_DENIED_ERROR,
			"string require_x509=true fails closed with ER_ACCESS_DENIED_ERROR");
	} else {
		ok(true, "require_x509 trusted certificate success # SKIP trusted certificate fixture unavailable");
		ok(true, "require_x509 trusted certificate wrong-password rejection # SKIP trusted certificate fixture unavailable");
		ok(true, "string require_x509=true fails closed # SKIP trusted certificate fixture unavailable");
	}

	{
		mysql_ptr source { connect_frontend(cl, USER_CHANGE_SOURCE, CHANGE_SOURCE_PASSWORD, false) };
		ok(source && try_change_user(source.get(), USER_CHANGE_TARGET, CHANGE_TARGET_PASSWORD) == ER_ACCESS_DENIED_ERROR,
			"COM_CHANGE_USER from plaintext rejects require_x509=true with ER_ACCESS_DENIED_ERROR");
	}
	{
		mysql_ptr source { connect_frontend(cl, USER_CHANGE_SOURCE, CHANGE_SOURCE_PASSWORD, true) };
		// Reconnecting with trusted_client succeeds below; CHANGE_USER cannot acquire a certificate on this TLS connection.
		ok(source && try_change_user(source.get(), USER_CHANGE_TARGET, CHANGE_TARGET_PASSWORD) == ER_ACCESS_DENIED_ERROR,
			"COM_CHANGE_USER from TLS without a client certificate rejects require_x509=true with ER_ACCESS_DENIED_ERROR");
	}
	{
		mysql_ptr source { connect_frontend(cl, USER_CHANGE_SOURCE, CHANGE_SOURCE_PASSWORD, true, &untrusted_client) };
		ok(untrusted_client_ready && source &&
			try_change_user(source.get(), USER_CHANGE_TARGET, CHANGE_TARGET_PASSWORD) == ER_ACCESS_DENIED_ERROR,
			"COM_CHANGE_USER from an untrusted client certificate rejects require_x509=true with ER_ACCESS_DENIED_ERROR");
	}
	if (trusted_client_ready) {
		mysql_ptr source { connect_frontend(cl, USER_CHANGE_SOURCE, CHANGE_SOURCE_PASSWORD, true, &trusted_client) };
		ok(source && try_change_user(source.get(), USER_CHANGE_TARGET, CHANGE_TARGET_PASSWORD) == 0,
			"COM_CHANGE_USER from a trusted client certificate accepts require_x509=true");
	} else {
		ok(true, "COM_CHANGE_USER trusted certificate require_x509 success # SKIP trusted certificate fixture unavailable");
	}
	if (trusted_client_ready) {
		mysql_ptr source { connect_frontend(cl, USER_CHANGE_SOURCE, CHANGE_SOURCE_PASSWORD, true, &trusted_client) };
		ok(source && try_change_user(source.get(), USER_CHANGE_TARGET, WRONG_PASSWORD) == ER_ACCESS_DENIED_ERROR,
			"COM_CHANGE_USER require_x509=true still rejects a wrong target password with ER_ACCESS_DENIED_ERROR");
	} else {
		ok(true, "COM_CHANGE_USER trusted certificate wrong-password rejection # SKIP trusted certificate fixture unavailable");
	}
	if (trusted_client_ready) {
		mysql_ptr source { connect_frontend(cl, USER_CHANGE_SOURCE, CHANGE_SOURCE_PASSWORD, true, &trusted_client) };
		ok(source && try_change_user(source.get(), USER_NONE, PASSWORD) == 0,
			"COM_CHANGE_USER from a trusted client certificate accepts an ordinary password target");
	} else {
		ok(true, "COM_CHANGE_USER ordinary target control # SKIP trusted certificate fixture unavailable");
	}
	if (spiffe_source_client_ready) {
		mysql_ptr source { connect_frontend(cl, USER_SPIFFE_SOURCE, "", true, &spiffe_source_client) };
		ok(source && try_change_user(source.get(), USER_NONE, PASSWORD) == ER_ACCESS_DENIED_ERROR,
			"COM_CHANGE_USER rejects a SPIFFE-authenticated source identity with ER_ACCESS_DENIED_ERROR");
	} else {
		ok(true, "COM_CHANGE_USER SPIFFE-authenticated source rejection # SKIP trusted SPIFFE source fixture unavailable");
	}
	if (spiffe_target_client_ready) {
		mysql_ptr source { connect_frontend(cl, USER_CHANGE_SOURCE, CHANGE_SOURCE_PASSWORD, true, &spiffe_target_client) };
		ok(source && try_change_user(source.get(), USER_SPIFFE_TARGET, "") == ER_ACCESS_DENIED_ERROR,
			"COM_CHANGE_USER rejects a SPIFFE target with ER_ACCESS_DENIED_ERROR");
	} else {
		ok(true, "COM_CHANGE_USER SPIFFE target rejection # SKIP trusted SPIFFE target fixture unavailable");
	}

	const bool users_cleaned = do_query(admin.get(), "DELETE FROM mysql_users WHERE username IN (" + user_list + ")") &&
		do_query(admin.get(), "LOAD MYSQL USERS TO RUNTIME");
	ok(users_cleaned, "Cleanup removed dedicated frontend require_x509 users");

	const bool passthrough_restored = saved_passthrough &&
		do_query(admin.get(), "SET mysql-passthrough_auth_enabled='" + original_passthrough_enabled + "'") &&
		do_query(admin.get(), "LOAD MYSQL VARIABLES TO RUNTIME");
	ok(passthrough_restored, "Cleanup restored mysql-passthrough_auth_enabled");

	return exit_status();
}
