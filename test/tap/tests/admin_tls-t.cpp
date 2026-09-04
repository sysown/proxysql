/**
 * End-to-end coverage for the dedicated Admin TLS context.
 *
 * The test intentionally starts with plaintext connections to verify backward
 * compatibility, enables TLS for both Admin protocols, exercises atomic reload
 * failure, and finally enables required client-certificate verification.
 */

#include <cstdlib>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <unistd.h>

#include "libpq-fe.h"
#include "mysql.h"

#include "command_line.h"
#include "tap.h"

using MysqlPtr = std::unique_ptr<MYSQL, decltype(&mysql_close)>;
using PgPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static MysqlPtr mysql_connect(
	const CommandLine& cl, bool tls, const std::string& key = "", const std::string& cert = "",
	const std::string& ca = ""
) {
	MYSQL *raw = mysql_init(NULL);
	if (raw == NULL) {
		return MysqlPtr(NULL, &mysql_close);
	}
	if (tls) {
		mysql_ssl_set(
			raw, key.empty() ? NULL : key.c_str(), cert.empty() ? NULL : cert.c_str(),
			ca.empty() ? NULL : ca.c_str(), NULL, NULL
		);
	}
	if (mysql_real_connect(
		raw, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL,
		tls ? CLIENT_SSL : 0
	) == NULL) {
		mysql_close(raw);
		return MysqlPtr(NULL, &mysql_close);
	}
	return MysqlPtr(raw, &mysql_close);
}

static PgPtr pg_connect(
	const CommandLine& cl, bool tls, const std::string& key = "", const std::string& cert = "",
	const std::string& ca = ""
) {
	const std::string port = std::to_string(cl.pgsql_admin_port);
	const char *keywords[] = {
		"host", "port", "user", "password", "sslmode", "sslkey", "sslcert", "sslrootcert", NULL
	};
	const char *values[] = {
		cl.pgsql_admin_host, port.c_str(), cl.admin_username, cl.admin_password,
		tls ? "require" : "disable",
		key.empty() ? NULL : key.c_str(), cert.empty() ? NULL : cert.c_str(),
		ca.empty() ? NULL : ca.c_str(), NULL
	};
	return PgPtr(PQconnectdbParams(keywords, values, 0), &PQfinish);
}

static bool query_ok(MYSQL *mysql, const std::string& query) {
	if (mysql_query(mysql, query.c_str()) != 0) {
		diag("Query failed: %s; error: %s", query.c_str(), mysql_error(mysql));
		return false;
	}
	MYSQL_RES *result = mysql_store_result(mysql);
	if (result != NULL) {
		mysql_free_result(result);
	}
	return true;
}

static std::string scalar(MYSQL *mysql, const std::string& query) {
	if (mysql_query(mysql, query.c_str()) != 0) {
		diag("Query failed: %s; error: %s", query.c_str(), mysql_error(mysql));
		return "";
	}
	MYSQL_RES *result = mysql_store_result(mysql);
	if (result == NULL) {
		return "";
	}
	MYSQL_ROW row = mysql_fetch_row(result);
	const std::string value = row != NULL && row[0] != NULL ? row[0] : "";
	mysql_free_result(result);
	return value;
}

static std::string sql_quote(MYSQL *mysql, const std::string& value) {
	std::string escaped(value.size() * 2 + 1, '\0');
	const unsigned long size = mysql_real_escape_string(
		mysql, escaped.data(), value.c_str(), value.size()
	);
	escaped.resize(size);
	return "'" + escaped + "'";
}

static bool set_variable(MYSQL *mysql, const char *name, const std::string& value) {
	return query_ok(mysql, std::string("SET ") + name + "=" + sql_quote(mysql, value));
}

static std::string make_libpq_key_copy(const std::string& source) {
	const size_t separator = source.find_last_of('/');
	const std::string directory =
		separator == std::string::npos ? "." : source.substr(0, separator);
	const std::string path_template = directory + "/proxysql-admin-tls-key-XXXXXX";
	std::vector<char> path(path_template.begin(), path_template.end());
	path.push_back('\0');

	const int fd = mkstemp(path.data());
	if (fd == -1) {
		return "";
	}
	close(fd);

	std::ifstream input(source, std::ios::binary);
	std::ofstream output(path.data(), std::ios::binary | std::ios::trunc);
	output << input.rdbuf();
	if (!input || !output) {
		unlink(path.data());
		return "";
	}
	return path.data();
}

int main() {
	plan(23);

	CommandLine cl;
	if (cl.getEnv()) {
		BAIL_OUT("Failed to get the required environment variables");
		return exit_status();
	}

	auto control = mysql_connect(cl, false);
	if (!control) {
		BAIL_OUT("Unable to connect to the MySQL Admin interface");
		return exit_status();
	}

	ok(
		scalar(control.get(),
			"SELECT variable_value FROM runtime_global_variables "
			"WHERE variable_name='admin-ssl_enabled'") == "false",
		"dedicated Admin TLS is disabled by default"
	);
	ok(mysql_connect(cl, false) != nullptr, "default MySQL Admin behavior accepts plaintext");
	auto default_pg = pg_connect(cl, false);
	ok(
		default_pg && PQstatus(default_pg.get()) == CONNECTION_OK,
		"default PostgreSQL Admin behavior accepts plaintext"
	);

	const std::string key = scalar(
		control.get(),
		"SELECT Variable_Value FROM stats.stats_proxysql_global WHERE Variable_Name='TLS_Key_File'"
	);
	const std::string cert = scalar(
		control.get(),
		"SELECT Variable_Value FROM stats.stats_proxysql_global "
		"WHERE Variable_Name='TLS_Server_Cert_File'"
	);
	const std::string ca = scalar(
		control.get(),
		"SELECT Variable_Value FROM stats.stats_proxysql_global "
		"WHERE Variable_Name='TLS_CA_Cert_File'"
	);
	ok(!key.empty() && !cert.empty() && !ca.empty(), "default TLS certificate paths are available");

	bool configured =
		set_variable(control.get(), "admin-ssl_key", key)
		&& set_variable(control.get(), "admin-ssl_cert", cert)
		&& set_variable(control.get(), "admin-ssl_ca", ca)
		&& set_variable(control.get(), "admin-ssl_enabled", "true")
		&& query_ok(control.get(), "LOAD ADMIN VARIABLES TO RUNTIME");
	ok(configured, "dedicated Admin TLS context loads successfully");

	const bool invalid_set =
		set_variable(control.get(), "admin-ssl_cert", "/no/such/admin-cert.pem");
	const bool invalid_rejected =
		invalid_set && mysql_query(control.get(), "LOAD ADMIN VARIABLES TO RUNTIME") != 0;
	ok(invalid_rejected, "invalid Admin TLS reload is rejected");
	ok(
		scalar(control.get(),
			"SELECT variable_value FROM runtime_global_variables "
			"WHERE variable_name='admin-ssl_cert'") == cert,
		"failed reload preserves the previous runtime configuration"
	);
	const bool restored =
		set_variable(control.get(), "admin-ssl_cert", cert)
		&& query_ok(control.get(), "LOAD ADMIN VARIABLES TO RUNTIME");
	ok(restored, "valid Admin TLS configuration can be loaded after a failed reload");

	ok(mysql_connect(cl, false) == nullptr, "MySQL Admin rejects new plaintext connections");
	auto mysql_tls = mysql_connect(cl, true);
	ok(
		mysql_tls && mysql_get_ssl_cipher(mysql_tls.get()) != NULL,
		"MySQL Admin negotiates the dedicated TLS context"
	);
	auto pg_plain = pg_connect(cl, false);
	ok(
		pg_plain && PQstatus(pg_plain.get()) != CONNECTION_OK,
		"PostgreSQL Admin rejects new plaintext connections"
	);
	auto pg_tls = pg_connect(cl, true);
	ok(
		pg_tls && PQstatus(pg_tls.get()) == CONNECTION_OK && PQsslInUse(pg_tls.get()) == 1,
		"PostgreSQL Admin negotiates the dedicated TLS context"
	);
	ok(query_ok(control.get(), "PROXYSQL RELOAD ADMIN TLS"), "explicit Admin TLS reload succeeds");

	const bool optional =
		set_variable(control.get(), "admin-ssl_verify_client", "OPTIONAL")
		&& query_ok(control.get(), "LOAD ADMIN VARIABLES TO RUNTIME");
	ok(optional, "optional client-certificate verification loads");
	ok(mysql_connect(cl, true) != nullptr, "optional mTLS accepts a MySQL client without a certificate");

	const bool required =
		set_variable(control.get(), "admin-ssl_verify_client", "REQUIRED")
		&& query_ok(control.get(), "LOAD ADMIN VARIABLES TO RUNTIME");
	ok(required, "required client-certificate verification loads");
	ok(mysql_connect(cl, true) == nullptr, "required mTLS rejects a MySQL client without a certificate");
	ok(
		mysql_connect(cl, true, key, cert, ca) != nullptr,
		"required mTLS accepts a MySQL client with a trusted certificate"
	);
	auto pg_without_cert = pg_connect(cl, true);
	ok(
		pg_without_cert && PQstatus(pg_without_cert.get()) != CONNECTION_OK,
		"required mTLS rejects a PostgreSQL client without a certificate"
	);
	// libpq rejects private key files with permissions wider than 0600. ProxySQL's
	// generated test key can be wider, so keep its permissions untouched and use
	// a private test-only copy.
	const std::string libpq_key = make_libpq_key_copy(key);
	auto pg_with_cert = pg_connect(cl, true, libpq_key, cert, ca);
	if (!libpq_key.empty()) {
		unlink(libpq_key.c_str());
	}
	ok(
		pg_with_cert && PQstatus(pg_with_cert.get()) == CONNECTION_OK
			&& PQsslInUse(pg_with_cert.get()) == 1,
		"required mTLS accepts a PostgreSQL client with a trusted certificate"
	);

	const bool disabled =
		set_variable(control.get(), "admin-ssl_verify_client", "DISABLED")
		&& set_variable(control.get(), "admin-ssl_enabled", "false")
		&& set_variable(control.get(), "admin-ssl_key", "")
		&& set_variable(control.get(), "admin-ssl_cert", "")
		&& set_variable(control.get(), "admin-ssl_ca", "")
		&& query_ok(control.get(), "LOAD ADMIN VARIABLES TO RUNTIME");
	ok(disabled, "dedicated Admin TLS can be disabled at runtime");
	ok(mysql_connect(cl, false) != nullptr, "MySQL Admin plaintext behavior is restored after disable");
	auto final_pg = pg_connect(cl, false);
	ok(
		final_pg && PQstatus(final_pg.get()) == CONNECTION_OK,
		"PostgreSQL Admin plaintext behavior is restored after disable"
	);

	return exit_status();
}
