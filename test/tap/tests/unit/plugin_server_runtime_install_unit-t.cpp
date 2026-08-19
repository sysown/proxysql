#include "tap.h"
#include "ProxySQL_PluginManager.h"
#include "ProxySQL_ServerDiscovery.h"

#include <cstdlib>
#include <fstream>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>

#ifndef PROXYSQL_FAKE_PLUGIN_PATH
#error "PROXYSQL_FAKE_PLUGIN_PATH must be defined"
#endif

namespace {

std::string g_log_path;

std::string read_log() {
	std::ifstream log(g_log_path);
	return std::string((std::istreambuf_iterator<char>(log)), std::istreambuf_iterator<char>());
}

size_t occurrences(const std::string& value, const std::string& needle) {
	size_t count = 0;
	for (size_t offset = 0; (offset = value.find(needle, offset)) != std::string::npos; offset += needle.size()) ++count;
	return count;
}

} // namespace

int main() {
	plan(10);
	char path[] = "/tmp/proxysql_server_runtime_install.XXXXXX";
	const int fd = mkstemp(path);
	if (fd >= 0) close(fd);
	g_log_path = path;
	setenv("PROXYSQL_FAKE_PLUGIN_LOG", g_log_path.c_str(), 1);
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_SERVER_DISCOVERY", "1", 1);
	setenv("PROXYSQL_FAKE_PLUGIN_INSTALL_SERVER_DISCOVERY_CONTROLLER", "1", 1);

	std::unique_ptr<ProxySQL_PluginManager> manager;
	std::string error;
	ok(proxysql_load_configured_plugins(manager, {PROXYSQL_FAKE_PLUGIN_PATH}, error) &&
		proxysql_init_configured_plugins(manager.get(), error),
		"loads an active server module and controller through the public lifecycle");

	ProxySQL_ServerRuntimeSnapshot snapshot {};
	snapshot.protocol = ProxySQL_ServerProtocol::mysql;
	snapshot.generation = proxysql_pending_server_runtime_generation(snapshot.protocol);
	snapshot.servers.push_back({17, "runtime.example", 3306, 0, "ONLINE", 5, 0, 100, 0, 1, 0, "complete"});
	const uint64_t candidate = snapshot.generation;
	ok(proxysql_prepare_server_runtime_install(snapshot),
		"the source-agnostic prepare dispatcher accepts the complete operator/Cluster snapshot");
	ok(proxysql_pending_server_runtime_generation(snapshot.protocol) == candidate,
		"preparation never consumes an installed generation before the HGM commit point");
	ok(read_log().find("server_controller_runtime") == std::string::npos,
		"prepare alone does not restart the controller");

	proxysql_commit_server_runtime_install(snapshot);
	const std::string after_first = read_log();
	ok(occurrences(after_first, "server_controller_runtime") == 1,
		"post-HGM commit publishes exactly one runtime installation event");
	ok(proxysql_pending_server_runtime_generation(snapshot.protocol) == candidate + 1,
		"a successful MySQL installation advances exactly one protocol generation");

	ProxySQL_ServerRuntimeSnapshot zero_servers {};
	zero_servers.protocol = ProxySQL_ServerProtocol::mysql;
	zero_servers.generation = proxysql_pending_server_runtime_generation(zero_servers.protocol);
	ok(proxysql_prepare_server_runtime_install(zero_servers),
		"zero-server runtime installations remain valid");
	proxysql_commit_server_runtime_install(std::move(zero_servers));
	ok(occurrences(read_log(), "server_controller_runtime") == 2,
		"zero-server post-commit installation restarts the controller without seeds");

	ProxySQL_ServerRuntimeSnapshot pgsql_snapshot {};
	pgsql_snapshot.protocol = ProxySQL_ServerProtocol::pgsql;
	pgsql_snapshot.generation = proxysql_pending_server_runtime_generation(pgsql_snapshot.protocol);
	const uint64_t pgsql_candidate = pgsql_snapshot.generation;
	ok(proxysql_prepare_server_runtime_install(pgsql_snapshot),
		"the identical dispatcher accepts a PostgreSQL runtime installation");
	proxysql_commit_server_runtime_install(std::move(pgsql_snapshot));
	ok(proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::pgsql) == pgsql_candidate + 1 &&
		proxysql_pending_server_runtime_generation(ProxySQL_ServerProtocol::mysql) == candidate + 2,
		"MySQL and PostgreSQL installed generations are independent and monotonic");

	(void)proxysql_stop_configured_plugins(manager, error);
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_PHASE_B");
	unsetenv("PROXYSQL_FAKE_PLUGIN_PHASE_B_SERVER_DISCOVERY");
	unsetenv("PROXYSQL_FAKE_PLUGIN_INSTALL_SERVER_DISCOVERY_CONTROLLER");
	unsetenv("PROXYSQL_FAKE_PLUGIN_LOG");
	unlink(g_log_path.c_str());
	return exit_status();
}
