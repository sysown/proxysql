#ifndef PROXYSQL_PLUGIN_CLI_H
#define PROXYSQL_PLUGIN_CLI_H

#ifdef PROXYSQL40

#include "ProxySQL_Plugin.h"
#include "ezOptionParser.hpp"

#include <string>
#include <vector>

constexpr const char* PROXYSQL_DEFAULT_PLUGIN_DIR = "/usr/lib/proxysql";

struct ProxySQL_PluginDiscovery {
	bool disabled {false};
	std::string config_file;
	std::string datadir;
	std::string plugin_dir;
	std::vector<std::string> module_paths;
	std::string error;
};

// Turns a safe logical plugin name into its canonical shared-object path.
// An existing absolute .so path remains valid for the established config
// contract. Every other path-like input is rejected.
std::string proxysql_resolve_plugin(const std::string& plugin,
	const std::string& plugin_dir, std::string& error);

// Narrow argv/config pre-scan used before the definitive ezOptionParser parse.
// It owns all returned strings and never retains argv pointers.
ProxySQL_PluginDiscovery proxysql_prescan_plugins(
	int argc, const char* const* argv, const char* default_config,
	const char* default_plugin_dir);

class ProxySQL_PluginCLIOptionRegistry {
public:
	explicit ProxySQL_PluginCLIOptionRegistry(ez::ezOptionParser& parser);
	bool add(const ProxySQL_PluginCLIOptionDef& option, std::string& error);
	ProxySQL_PluginCLIRegistry callback_registry();

private:
	static bool add_callback(void* opaque, const ProxySQL_PluginCLIOptionDef& option,
		const char** error);

	ez::ezOptionParser& parser_;
	std::string last_error_;
};

// Owns the parser-facing side of the parsed option context used by early
// actions. Plugins receive only callback-based reads through
// ProxySQL_PluginEarlyActionContext, never an ezOptionParser pointer.
class ProxySQL_PluginParsedOptionContext {
public:
	explicit ProxySQL_PluginParsedOptionContext(ez::ezOptionParser& parser);
	ProxySQL_PluginEarlyActionContext early_action_context(
		const char* config_file, const char* datadir);

private:
	static bool is_set_callback(void* opaque, const char* long_name);
	static bool get_string_callback(void* opaque, const char* long_name,
		std::string& value);

	ez::ezOptionParser& parser_;
};

#endif /* PROXYSQL40 */
#endif /* PROXYSQL_PLUGIN_CLI_H */
