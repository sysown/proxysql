/**
 * @file azure_entra_plugin_load_unit-t.cpp
 * @brief Loading proxysql_azure_entra.so through the plugin manager (issue #6649).
 */
#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "Aws_Iam_Provider.h"
#include "ProxySQL_PluginManager.h"

#include <cstdio>
#include <cstdlib>
#include <string>
#include <unistd.h>

#ifndef PROXYSQL_AZURE_ENTRA_PLUGIN_PATH
#error "PROXYSQL_AZURE_ENTRA_PLUGIN_PATH must be defined"
#endif

namespace {

void unset_env() {
	for (const char *name : { "AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_FEDERATED_TOKEN_FILE",
			"AZURE_AUTHORITY_HOST", "PROXYSQL_AZURE_ENTRA_SCOPE" }) {
		unsetenv(name);
	}
}

void test_missing_environment_fails_init() {
	unset_env();
	ProxySQL_PluginManager mgr;
	std::string err;
	const bool loaded = mgr.load(PROXYSQL_AZURE_ENTRA_PLUGIN_PATH, err);
	const bool initialized = loaded && mgr.init_all(err);
	ok(loaded && !initialized && !acquire_backend_token_source(BackendTokenProvider::AZURE_ENTRA),
		"without workload identity settings init fails and no source is installed");
}

void test_valid_environment_installs_source() {
	char token_file[] = "/tmp/azure_entra_tokenXXXXXX"; // NOSONAR(cpp:S5443): mkstemp() makes a new file with mode 0600.
	const int fd = mkstemp(token_file);
	if (fd >= 0) {
		(void)!write(fd, "federated-token\n", 16);
		close(fd);
	}
	setenv("AZURE_TENANT_ID", "11111111-2222-3333-4444-555555555555", 1);
	setenv("AZURE_CLIENT_ID", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 1);
	setenv("AZURE_FEDERATED_TOKEN_FILE", token_file, 1);
	ProxySQL_PluginManager mgr;
	std::string err;
	const bool ready = mgr.load(PROXYSQL_AZURE_ENTRA_PLUGIN_PATH, err) && mgr.init_all(err) &&
		mgr.start_all(err);
	ok(ready && acquire_backend_token_source(BackendTokenProvider::AZURE_ENTRA) &&
		!acquire_global_aws_iam_token_source(),
		"with workload identity settings the plugin installs into the Azure slot only");
	mgr.stop_all();
	shutdown_global_backend_token_sources();
	ok(!acquire_backend_token_source(BackendTokenProvider::AZURE_ENTRA),
		"shutdown retires the plugin's source");
	unset_env();
	unlink(token_file);
}

} // namespace

int main() {
	plan(3);
	test_init_minimal();
	test_missing_environment_fails_init();
	test_valid_environment_installs_source();
	test_cleanup_minimal();
	return exit_status();
}
