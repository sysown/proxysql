/**
 * @file frontend_x509_test_utils.h
 * @brief Header-only TLS fixture helpers for frontend X.509 TAP tests.
 */

#ifndef __FRONTEND_X509_TEST_UTILS_H
#define __FRONTEND_X509_TEST_UTILS_H

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

#include <limits.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"

using std::string;

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
static inline string shell_quote(const string& value) {
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

static inline bool run_openssl(const string& command) {
	diag("Running: %s", command.c_str());
	const int status = system(command.c_str());
	if (status != 0) {
		diag("openssl command failed with status %d", status);
		return false;
	}
	return true;
}

/**
 * Own exactly the path returned by mkdtemp(). Cleanup never follows a path
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
			"spiffe-target.key", "spiffe-target.csr", "spiffe-target.pem", "spiffe-target.ext",
			"spiffe-passthrough.key", "spiffe-passthrough.csr", "spiffe-passthrough.pem", "spiffe-passthrough.ext"
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

static inline bool file_is_readable(const string& path) {
	if (access(path.c_str(), R_OK) == 0) return true;
	diag("Required certificate fixture file is unavailable: %s: %s", path.c_str(), strerror(errno));
	return false;
}

static inline bool create_trusted_client_certificate(
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

static inline bool create_untrusted_client_certificate(
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

static inline bool create_spiffe_client_certificate(
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
 * Attempt one frontend connection and return the connected handle on success.
 * A null client_identity means TLS is requested without a client certificate.
 */
static inline mysql_ptr connect_frontend(
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

static inline unsigned int try_frontend_connect(
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

#endif /* __FRONTEND_X509_TEST_UTILS_H */
