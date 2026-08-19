#include "ProxySQL_PluginCLI.h"
#include "ProxySQL_PluginManager.h"
#include "tap.h"

#include <fstream>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

#ifndef PROXYSQL_FAKE_PLUGIN_PATH
#error "PROXYSQL_FAKE_PLUGIN_PATH must be defined"
#endif
#ifndef PROXYSQL_BINARY_PATH
#error "PROXYSQL_BINARY_PATH must be defined"
#endif

namespace {

struct ArgV {
	std::vector<std::string> values;
	std::vector<const char*> argv;

	ArgV(std::initializer_list<const char*> input) {
		for (const char* value : input) values.emplace_back(value);
		for (const auto& value : values) argv.push_back(value.c_str());
	}
};

std::string make_temp_dir() {
	char path[] = "/tmp/proxysql_plugin_cli.XXXXXX";
	return mkdtemp(path) != nullptr ? path : "";
}

std::string canonical(const std::string& path) {
	char* resolved = realpath(path.c_str(), nullptr);
	if (resolved == nullptr) return {};
	std::string out(resolved);
	free(resolved);
	return out;
}

bool write_config(const std::string& path, const std::string& contents) {
	std::ofstream file(path);
	file << contents;
	return file.good();
}

bool copy_file(const std::string& source, const std::string& destination) {
	std::ifstream input(source, std::ios::binary);
	std::ofstream output(destination, std::ios::binary);
	output << input.rdbuf();
	return input.good() || input.eof() ? output.good() : false;
}

struct CommandResult {
	int status {-1};
	std::string output;
};

CommandResult run_executable_help(const std::vector<std::string>& args) {
	int pipefd[2] {-1, -1};
	if (pipe(pipefd) != 0) return {};
	const pid_t child = fork();
	if (child == 0) {
		(void)dup2(pipefd[1], STDOUT_FILENO);
		(void)dup2(pipefd[1], STDERR_FILENO);
		(void)close(pipefd[0]);
		(void)close(pipefd[1]);
		setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_CLI", "1", 1);
		unsetenv("PROXYSQL_NO_PLUGINS");
		std::vector<char*> argv;
		for (const auto& arg : args) argv.push_back(const_cast<char*>(arg.c_str()));
		argv.push_back(nullptr);
		execv(argv.front(), argv.data());
		_exit(127);
	}
	(void)close(pipefd[1]);
	CommandResult result;
	char buffer[1024];
	ssize_t bytes = 0;
	while ((bytes = read(pipefd[0], buffer, sizeof(buffer))) > 0) {
		result.output.append(buffer, static_cast<size_t>(bytes));
	}
	(void)close(pipefd[0]);
	if (child > 0) (void)waitpid(child, &result.status, 0);
	return result;
}

void remove_tree(const std::string& root) {
	if (root.empty()) return;
	(void)unlink((root + "/plugins/proxysql_mysql_router.so").c_str());
	(void)unlink((root + "/plugins/proxysql_fake_plugin.so").c_str());
	(void)rmdir((root + "/plugins").c_str());
	(void)unlink((root + "/custom.so").c_str());
	(void)unlink((root + "/config.cnf").c_str());
	(void)rmdir(root.c_str());
}

void test_resolver_rejects_unsafe_names_and_canonicalizes() {
	const std::string root = make_temp_dir();
	const std::string plugins = root + "/plugins";
	(void)mkdir(plugins.c_str(), 0700);
	const std::string plugin = plugins + "/proxysql_mysql_router.so";
	std::ofstream(plugin).put('\n');
	const std::string outside = root + "/custom.so";
	std::ofstream(outside).put('\n');

	std::string err;
	ok(proxysql_resolve_plugin("mysql_router", plugins, err) == canonical(plugin),
	   "name resolves below canonical plugin directory");
	ok(proxysql_resolve_plugin(outside, plugins, err) == canonical(outside),
	   "explicit absolute existing .so path remains supported");
	ok(proxysql_resolve_plugin(outside, root + "/missing-plugin-dir", err) == canonical(outside),
	   "absolute .so path does not depend on the named plugin directory");
	ok(proxysql_resolve_plugin("../escape", plugins, err).empty(),
	   "relative traversal is rejected");
	ok(proxysql_resolve_plugin("", plugins, err).empty(), "empty plugin name is rejected");
	ok(proxysql_resolve_plugin("bad/name", plugins, err).empty(), "relative path separator is rejected");
	ok(proxysql_resolve_plugin("mysql-router", plugins, err).empty(), "characters outside safe name set are rejected");
	remove_tree(root);
}

void test_registry_rejects_duplicate_option_names() {
	ez::ezOptionParser parser;
	ProxySQL_PluginCLIOptionRegistry registry(parser);
	std::string err;
	ok(registry.add({"-B", "--bootstrap", 1, false, "first"}, err),
	   "first plugin option registers");
	ok(!registry.add({"", "--bootstrap", 1, false, "duplicate"}, err),
	   "duplicate long option is rejected");
	ok(!err.empty(), "duplicate option produces an error");
	ok(!registry.add({"-B", "--other", 1, false, "duplicate short"}, err),
	   "duplicate short option is rejected");
}

void test_prescan_honors_cli_config_datadir_plugin_dir_and_deduplicates() {
	const std::string root = make_temp_dir();
	const std::string plugins = root + "/plugins";
	(void)mkdir(plugins.c_str(), 0700);
	const std::string named = plugins + "/proxysql_fake_plugin.so";
	(void)copy_file(PROXYSQL_FAKE_PLUGIN_PATH, named);
	const std::string config = root + "/config.cnf";
	ok(write_config(config, "plugins=(\"fake_plugin\"); datadir=\"from-config\";"),
	   "temporary plugin config written");

	ArgV args { "proxysql", "-c" , config.c_str(), "-D", "from-cli", "--plugin-dir", plugins.c_str(),
	            "--load-plugin", "fake_plugin", "--load-plugin", "fake_plugin" };
	const ProxySQL_PluginDiscovery found = proxysql_prescan_plugins(
		static_cast<int>(args.argv.size()), args.argv.data(), nullptr, plugins.c_str());
	ok(found.error.empty(), "pre-scan accepts valid compact options (err='%s')", found.error.c_str());
	ok(found.config_file == config, "-c FILE selects config file");
	ok(found.datadir == "from-cli", "-D DIR overrides config datadir");
	ok(found.plugin_dir == canonical(plugins), "--plugin-dir canonicalizes plugin directory");
	ok(found.module_paths.size() == 1 && found.module_paths.front() == canonical(named),
	   "config and repeated --load-plugin entries deduplicate in first-seen order (err='%s')", found.error.c_str());
	ArgV long_config { "proxysql", "--config", config.c_str(), "--plugin-dir", plugins.c_str() };
	const ProxySQL_PluginDiscovery long_found = proxysql_prescan_plugins(
		static_cast<int>(long_config.argv.size()), long_config.argv.data(), nullptr, plugins.c_str());
	ok(long_found.error.empty() && long_found.config_file == config,
	   "--config FILE selects config and discovers its plugins");
	remove_tree(root);
}

void test_prescan_supports_compact_config_and_no_plugins_kill_switch() {
	const std::string root = make_temp_dir();
	const std::string plugins = root + "/plugins";
	(void)mkdir(plugins.c_str(), 0700);
	const std::string config = root + "/config.cnf";
	ok(write_config(config, "plugins=(\"fake_plugin\");"), "temporary config written");

	ArgV compact { "proxysql", ("-c" + config).c_str(), "--plugin-dir", plugins.c_str(), "--no-plugins" };
	const ProxySQL_PluginDiscovery found = proxysql_prescan_plugins(
		static_cast<int>(compact.argv.size()), compact.argv.data(), nullptr, plugins.c_str());
	ok(found.error.empty(), "compact -cFILE pre-scan succeeds");
	ok(found.config_file == config, "compact -cFILE selects config file");
	ok(found.disabled, "--no-plugins disables the chassis during pre-scan");
	ok(found.module_paths.empty(), "--no-plugins prevents plugin config discovery");
	remove_tree(root);
}

void test_manager_registers_abi6_options_without_reading_abi5_tail() {
	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_CLI", "1", 1);
	std::unique_ptr<ProxySQL_PluginManager> manager(new ProxySQL_PluginManager());
	std::string err;
	ok(manager->load(PROXYSQL_FAKE_PLUGIN_PATH, err), "ABI 6 fake plugin loads");
	ez::ezOptionParser parser;
	ok(manager->register_cli_options(parser, err), "ABI 6 plugin option registers");
	std::string usage;
	parser.getUsage(usage);
	ok(usage.find("--fake-plugin-action") != std::string::npos,
	   "plugin option appears in parser usage before definitive parse");
	ArgV args { "proxysql", "--fake-plugin-action", "bootstrap" };
	parser.parse(static_cast<int>(args.argv.size()), args.argv.data());
	std::string action;
	parser.get("--fake-plugin-action")->getString(action);
	ok(action == "bootstrap", "plugin option value is available after parse");
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_CLI");

	setenv("PROXYSQL_FAKE_PLUGIN_ENABLE_ABI5_TAIL_GUARD", "1", 1);
	std::unique_ptr<ProxySQL_PluginManager> abi5(new ProxySQL_PluginManager());
	ok(abi5->load(PROXYSQL_FAKE_PLUGIN_PATH, err), "ABI 5 fake plugin loads");
	ez::ezOptionParser abi5_parser;
	ok(abi5->register_cli_options(abi5_parser, err),
	   "ABI 5 descriptor is not read through the ABI 6 CLI tail");
	std::string abi5_usage;
	abi5_parser.getUsage(abi5_usage);
	ok(abi5_usage.find("--fake-plugin-action") == std::string::npos,
	   "ABI 5 plugin contributes no ABI 6 option");
	unsetenv("PROXYSQL_FAKE_PLUGIN_ENABLE_ABI5_TAIL_GUARD");
}

void test_executable_help_registers_plugin_options_unless_killed() {
	const std::string root = make_temp_dir();
	const std::string plugins = root + "/plugins";
	(void)mkdir(plugins.c_str(), 0700);
	const std::string named = plugins + "/proxysql_fake_plugin.so";
	(void)copy_file(PROXYSQL_FAKE_PLUGIN_PATH, named);
	const std::string config = root + "/config.cnf";
	(void)write_config(config, "");
	const char* inherited_no_plugins = getenv("PROXYSQL_NO_PLUGINS");
	const std::string saved_no_plugins = inherited_no_plugins != nullptr ? inherited_no_plugins : "";
	const bool had_no_plugins = inherited_no_plugins != nullptr;
	setenv("PROXYSQL_NO_PLUGINS", "1", 1);

	const std::vector<std::string> enabled_args {
		PROXYSQL_BINARY_PATH, "--config", config, "--plugin-dir", plugins,
		"--load-plugin", "fake_plugin", "--help"
	};
	const CommandResult enabled = run_executable_help(enabled_args);
	ok(WIFEXITED(enabled.status) && WEXITSTATUS(enabled.status) == 0,
	   "executable help with a discovered ABI 6 plugin exits cleanly");
	ok(enabled.output.find("--fake-plugin-action") != std::string::npos,
	   "executable help includes the discovered plugin option");

	const std::vector<std::string> disabled_args {
		PROXYSQL_BINARY_PATH, "--config", config, "--plugin-dir", plugins,
		"--load-plugin", "fake_plugin", "--no-plugins", "--help"
	};
	const CommandResult disabled = run_executable_help(disabled_args);
	ok(WIFEXITED(disabled.status) && WEXITSTATUS(disabled.status) == 0,
	   "executable help with --no-plugins exits cleanly");
	ok(disabled.output.find("--fake-plugin-action") == std::string::npos,
	   "--no-plugins suppresses the discovered plugin option from executable help");
	if (had_no_plugins) setenv("PROXYSQL_NO_PLUGINS", saved_no_plugins.c_str(), 1);
	else unsetenv("PROXYSQL_NO_PLUGINS");
	remove_tree(root);
}

} // namespace

int main() {
	plan(34);
	test_resolver_rejects_unsafe_names_and_canonicalizes();
	test_registry_rejects_duplicate_option_names();
	test_prescan_honors_cli_config_datadir_plugin_dir_and_deduplicates();
	test_prescan_supports_compact_config_and_no_plugins_kill_switch();
	test_manager_registers_abi6_options_without_reading_abi5_tail();
	test_executable_help_registers_plugin_options_unless_killed();
	return exit_status();
}
