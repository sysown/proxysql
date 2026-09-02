#ifdef PROXYSQL40

#include "ProxySQL_PluginCLI.h"

#include "configfile.hpp"

#include <cctype>
#include <cstring>
#include <cstdlib>
#include <set>
#include <sys/stat.h>

namespace {

std::string canonical_existing(const std::string& path) {
	char* resolved = realpath(path.c_str(), nullptr);
	if (resolved == nullptr) return {};
	std::string canonical_path(resolved);
	free(resolved);
	return canonical_path;
}

bool is_directory(const std::string& path) {
	struct stat st {};
	return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool is_regular_file(const std::string& path) {
	struct stat st {};
	return stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode);
}

bool has_so_suffix(const std::string& value) {
	return value.size() > 3 && value.compare(value.size() - 3, 3, ".so") == 0;
}

bool is_safe_plugin_name(const std::string& value) {
	if (value.empty() || value == "..") return false;
	for (unsigned char ch : value) {
		if (!std::isalnum(ch) && ch != '_') return false;
	}
	return true;
}

void append_module(const std::string& requested, const std::string& plugin_dir,
	std::set<std::string>& seen, ProxySQL_PluginDiscovery& found) {
	std::string error;
	const std::string resolved = proxysql_resolve_plugin(requested, plugin_dir, error);
	if (resolved.empty()) {
		found.error = error;
		return;
	}
	if (seen.insert(resolved).second) found.module_paths.push_back(resolved);
}

std::string first_existing_default_config() {
	static const char* candidates[] = {
		"proxysql.cnf", "proxysql.cfg", "/etc/proxysql.cnf", "/etc/proxysql.cfg"
	};
	for (const char* candidate : candidates) {
		if (is_regular_file(candidate)) return candidate;
	}
	return {};
}

void read_config_plugins(ProxySQL_PluginDiscovery& found, std::set<std::string>& seen) {
	if (found.config_file.empty()) return;
	Config config;
	try {
		config.readFile(found.config_file.c_str());
		const Setting& root = config.getRoot();
		std::string config_datadir;
		if (root.lookupValue("datadir", config_datadir) && found.datadir.empty()) {
			found.datadir = config_datadir;
		}
		if (!root.exists("plugins")) return;
		const Setting& plugins = root["plugins"];
		if (plugins.getType() != Setting::TypeList &&
			plugins.getType() != Setting::TypeArray) {
			found.error = "plugins must be a list in " + found.config_file;
			return;
		}
		for (int i = 0; i < plugins.getLength() && found.error.empty(); ++i) {
			if (plugins[i].isString()) append_module(plugins[i].c_str(), found.plugin_dir, seen, found);
		}
	} catch (const FileIOException&) {
		// The ordinary configuration phase retains the established fatal error
		// handling. A missing default config simply contributes no plugins.
	} catch (const ParseException& ex) {
		found.error = std::string("unable to parse plugin configuration ") +
			ex.getFile() + ":" + std::to_string(ex.getLine()) + ": " + ex.getError();
	}
}

bool valid_option_name(const char* name, const char* prefix, size_t min_length) {
	return name != nullptr && std::strlen(name) >= min_length &&
		std::strncmp(name, prefix, std::strlen(prefix)) == 0 &&
		std::strpbrk(name, " \t\r\n") == nullptr;
}

} // namespace

std::string proxysql_resolve_plugin(const std::string& plugin,
	const std::string& plugin_dir, std::string& error) {
	error.clear();
	if (!plugin.empty() && plugin.front() == '/') {
		if (!has_so_suffix(plugin)) {
			error = "plugin path must name an existing .so: " + plugin;
			return {};
		}
		const std::string canonical_path = canonical_existing(plugin);
		if (canonical_path.empty() || !is_regular_file(canonical_path)) {
			error = "plugin path does not exist: " + plugin;
			return {};
		}
		return canonical_path;
	}
	const std::string canonical_dir = canonical_existing(plugin_dir);
	if (canonical_dir.empty() || !is_directory(canonical_dir)) {
		error = "plugin directory does not exist: " + plugin_dir;
		return {};
	}

	if (!is_safe_plugin_name(plugin)) {
		error = "invalid plugin name: " + plugin;
		return {};
	}
	std::string filename = "proxysql_" + plugin + ".so";
	if (plugin == "mysqlx") filename = "ProxySQL_MySQLX_Plugin.so";
	else if (plugin == "genai") filename = "ProxySQL_GenAI_Plugin.so";
	const std::string candidate = canonical_dir + "/" + filename;
	const std::string canonical_candidate = canonical_existing(candidate);
	const std::string required_prefix = canonical_dir + "/";
	if (canonical_candidate.empty() || !is_regular_file(canonical_candidate) ||
		canonical_candidate.compare(0, required_prefix.size(), required_prefix) != 0) {
		error = "plugin name does not resolve below plugin directory: " + plugin;
		return {};
	}
	return canonical_candidate;
}

ProxySQL_PluginDiscovery proxysql_prescan_plugins(
	int argc, const char* const* argv, const char* default_config,
	const char* default_plugin_dir) {
	ProxySQL_PluginDiscovery found {};
	found.plugin_dir = default_plugin_dir != nullptr ? default_plugin_dir : "";

	for (int i = 1; i < argc; ++i) {
		if (argv[i] != nullptr && std::string(argv[i]) == "--no-plugins") found.disabled = true;
	}
	const char* disabled_env = std::getenv("PROXYSQL_NO_PLUGINS");
	if (disabled_env != nullptr && std::string(disabled_env) == "1") {
		found.disabled = true;
	}

	std::vector<std::string> requested_modules;
	for (int i = 1; i < argc; ++i) {
		if (argv[i] == nullptr) continue;
		const std::string arg(argv[i]);
		auto next_value = [&](std::string& output) -> bool {
			if (i + 1 >= argc || argv[i + 1] == nullptr) {
				found.error = "missing value for " + arg;
				return false;
			}
			output = argv[++i];
			return true;
		};
		if (arg == "-c" || arg == "--config") {
			if (!next_value(found.config_file)) return found;
		} else if (arg.rfind("--config=", 0) == 0) {
			found.config_file = arg.substr(std::strlen("--config="));
		} else if (arg.rfind("-c", 0) == 0 && arg.size() > 2) {
			found.config_file = arg.substr(2);
		} else if (arg == "-D") {
			if (!next_value(found.datadir)) return found;
		} else if (arg == "--plugin-dir") {
			if (!next_value(found.plugin_dir)) return found;
		} else if (arg.rfind("--plugin-dir=", 0) == 0) {
			found.plugin_dir = arg.substr(std::strlen("--plugin-dir="));
		} else if (arg == "--load-plugin") {
			std::string module;
			if (!next_value(module)) return found;
			requested_modules.push_back(module);
		} else if (arg.rfind("--load-plugin=", 0) == 0) {
			requested_modules.push_back(arg.substr(std::strlen("--load-plugin=")));
		}
	}

	if (found.config_file.empty()) {
		if (default_config != nullptr && *default_config != '\0') found.config_file = default_config;
		else found.config_file = first_existing_default_config();
	}
	// The kill switch may still need the selected config path for ordinary
	// core startup, but it deliberately performs neither directory
	// canonicalization nor config/plugin discovery.
	if (found.disabled) return found;
	const std::string canonical_dir = canonical_existing(found.plugin_dir);
	// A normal startup with no configured/requested plugins must not require
	// the distribution's optional plugin directory to exist. Once a module is
	// requested (from argv or config), resolution below a real canonical
	// directory is mandatory.
	if (!canonical_dir.empty() && is_directory(canonical_dir)) found.plugin_dir = canonical_dir;
	else found.plugin_dir.clear();

	std::set<std::string> seen;
	read_config_plugins(found, seen);
	for (const auto& requested : requested_modules) {
		if (!found.error.empty()) break;
		append_module(requested, found.plugin_dir, seen, found);
	}
	return found;
}

ProxySQL_PluginCLIOptionRegistry::ProxySQL_PluginCLIOptionRegistry(ez::ezOptionParser& parser) : parser_(parser) {}

bool ProxySQL_PluginCLIOptionRegistry::add(const ProxySQL_PluginCLIOptionDef& option,
	std::string& error) {
	error.clear();
	const bool has_short = option.short_name != nullptr && option.short_name[0] != '\0';
	if (!valid_option_name(option.long_name, "--", 3) ||
		(has_short && (!valid_option_name(option.short_name, "-", 2) ||
			std::strlen(option.short_name) != 2)) ||
		option.value_count > 1 || option.help == nullptr) {
		error = "invalid plugin CLI option";
		return false;
	}
	if (parser_.optionGroupIds.count(option.long_name) != 0 ||
		(has_short && parser_.optionGroupIds.count(option.short_name) != 0)) {
		error = "duplicate plugin CLI option";
		return false;
	}
	if (has_short) {
		parser_.add("", option.required, option.value_count, 0, option.help,
			option.short_name, option.long_name);
	} else {
		parser_.add("", option.required, option.value_count, 0, option.help, option.long_name);
	}
	return true;
}

bool ProxySQL_PluginCLIOptionRegistry::add_callback(void* opaque,
	const ProxySQL_PluginCLIOptionDef& option, const char** error) {
	if (error != nullptr) *error = nullptr;
	if (opaque == nullptr) {
		if (error != nullptr) *error = "plugin CLI registry is unavailable";
		return false;
	}
	auto* registry = static_cast<ProxySQL_PluginCLIOptionRegistry*>(opaque);
	const bool ok = registry->add(option, registry->last_error_);
	if (!ok && error != nullptr) *error = registry->last_error_.c_str();
	return ok;
}

ProxySQL_PluginCLIRegistry ProxySQL_PluginCLIOptionRegistry::callback_registry() {
	return {this, &ProxySQL_PluginCLIOptionRegistry::add_callback};
}

ProxySQL_PluginParsedOptionContext::ProxySQL_PluginParsedOptionContext(
	ez::ezOptionParser& parser) : parser_(parser) {}

bool ProxySQL_PluginParsedOptionContext::is_set_callback(void* opaque,
	const char* long_name) {
	if (opaque == nullptr || long_name == nullptr) return false;
	auto* context = static_cast<ProxySQL_PluginParsedOptionContext*>(opaque);
	return context->parser_.isSet(long_name) != 0;
}

bool ProxySQL_PluginParsedOptionContext::get_string_callback(void* opaque,
	const char* long_name, std::string& value) {
	if (opaque == nullptr || long_name == nullptr) return false;
	auto* context = static_cast<ProxySQL_PluginParsedOptionContext*>(opaque);
	auto* option = context->parser_.get(long_name);
	if (option == nullptr || !context->is_set_callback(opaque, long_name)) return false;
	option->getString(value);
	return true;
}

ProxySQL_PluginEarlyActionContext
ProxySQL_PluginParsedOptionContext::early_action_context(const char* config_file,
	const char* datadir) {
	return {this, &ProxySQL_PluginParsedOptionContext::is_set_callback,
		&ProxySQL_PluginParsedOptionContext::get_string_callback, config_file,
		datadir, nullptr};
}

#endif /* PROXYSQL40 */
