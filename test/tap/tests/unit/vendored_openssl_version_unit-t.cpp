#include "tap.h"

#include <openssl/crypto.h>
#include <openssl/opensslv.h>

#include <string>

#ifndef PROXYSQL_VENDORED_OPENSSL_VERSION
#error "PROXYSQL_VENDORED_OPENSSL_VERSION must be supplied by the build"
#endif

int main() {
	const std::string expected_version { PROXYSQL_VENDORED_OPENSSL_VERSION };
	const std::string expected_runtime_prefix { "OpenSSL " + expected_version };
	const std::string header_version { OPENSSL_VERSION_STR };
	const std::string runtime_version { OpenSSL_version(OPENSSL_VERSION) };
	const unsigned long runtime_version_num { OpenSSL_version_num() };

	plan(6);
	ok(expected_version == "3.5.7", "build pin is OpenSSL 3.5.7");
	ok(header_version == expected_version,
		"vendored headers report OpenSSL %s", expected_version.c_str());
	ok(runtime_version.rfind(expected_runtime_prefix, 0) == 0,
		"embedded runtime reports %s", expected_runtime_prefix.c_str());
	ok((runtime_version_num >> 28) == 3, "embedded runtime major version is 3");
	ok(((runtime_version_num & 0x0FF00000L) >> 20) == 5,
		"embedded runtime minor version is 5");
	ok(((runtime_version_num & 0x00000FF0L) >> 4) == 7,
		"embedded runtime patch version is 7");

	return exit_status();
}
