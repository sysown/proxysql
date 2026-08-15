// The AWS SDK is intentionally confined to the v4 AWS plugin. Exercise
// the real loader path and, critically, prove that the provider stays valid
// after PluginManager releases its own dlopen() handle.  Core must retain the
// module until its leased provider has been drained during shutdown.

#include "Aws_Iam_Provider.h"
#include "ProxySQL_PluginManager.h"
#include "tap.h"

#include <memory>
#include <string>
#include <vector>

#ifndef PROXYSQL_AWS_PLUGIN_PATH
#error "PROXYSQL_AWS_PLUGIN_PATH must be defined"
#endif

int main() {
	plan(11);

	// The unit binary starts with the SDK-free provider registry empty.
	shutdown_global_aws_iam_token_source();
	ok(!acquire_global_aws_iam_token_source(), "provider registry starts empty");

	std::unique_ptr<ProxySQL_PluginManager> manager;
	std::string error;
	const std::vector<std::string> paths { PROXYSQL_AWS_PLUGIN_PATH };
	const bool loaded = proxysql_load_configured_plugins(manager, paths, error);
	if (!loaded) diag("AWS plugin loader error: %s", error.c_str());
	ok(loaded, "loads AWS plugin");
	ok(proxysql_init_configured_plugins(manager.get(), error), "initializes AWS plugin");
	ok(proxysql_start_configured_plugins(manager.get(), error), "starts AWS plugin");

	{
		auto lease = acquire_global_aws_iam_token_source();
		ok(static_cast<bool>(lease), "plugin publishes an IAM provider");
		ok(lease && lease->support_compiled(), "published provider has SDK support");
	}

	// stop_configured_plugins destroys the manager and drops its dlopen()
	// reference. The source must remain callable through core's retained
	// handle until the ordinary provider shutdown point.
	ok(proxysql_stop_configured_plugins(manager, error), "stops and unloads plugin manager");
	ok(manager == nullptr, "plugin manager handle is released");
	{
		auto lease = acquire_global_aws_iam_token_source();
		ok(static_cast<bool>(lease), "core retains provider after plugin unload");
		ok(lease && lease->support_compiled(), "retained provider remains usable");
	}

	shutdown_global_aws_iam_token_source();
	ok(!acquire_global_aws_iam_token_source(), "shutdown drains and removes provider");

	return exit_status();
}
