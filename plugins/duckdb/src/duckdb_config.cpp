#include "duckdb_config.h"

#include <cstdlib>
#include <sstream>

namespace {

// Defaults mirrored here (not just in the constructor) so the typed
// getters have something sane to fall back to if a stored value somehow
// fails to parse (e.g. corrupted via unforeseen code paths).
const char* const kDefaultDatabasePath   = ":memory:";
const char* const kDefaultMemoryLimit    = "1GB";
const int         kDefaultThreads        = 2;
const int         kDefaultMaxConnections = 100;
const bool        kDefaultReadOnly       = false;
const char* const kDefaultMysqlIfaces    = "0.0.0.0:6031";
const char* const kDefaultPgsqlIfaces    = "0.0.0.0:6032";

bool parse_int(const std::string& s, long& out) {
	if (s.empty()) return false;
	char* end = nullptr;
	const long v = std::strtol(s.c_str(), &end, 10);
	if (end == nullptr || *end != '\0') return false;
	out = v;
	return true;
}

bool parse_bool(const std::string& s, bool& out) {
	if (s == "true" || s == "1" || s == "on")   { out = true;  return true; }
	if (s == "false" || s == "0" || s == "off") { out = false; return true; }
	return false;
}

bool parse_one_iface(const std::string& entry, DuckDBIface& out, std::string& err) {
	std::string addr;
	std::string port_str;
	if (!entry.empty() && entry[0] == '[') {
		const auto close = entry.find(']');
		if (close == std::string::npos || close + 1 >= entry.size() || entry[close + 1] != ':') {
			err = "malformed bracketed iface '" + entry + "'; expected [addr]:port";
			return false;
		}
		addr = entry.substr(1, close - 1);
		port_str = entry.substr(close + 2);
	} else {
		const auto colon = entry.rfind(':');
		if (colon == std::string::npos || colon == 0 || colon + 1 >= entry.size()) {
			err = "malformed iface '" + entry + "'; expected addr:port";
			return false;
		}
		addr = entry.substr(0, colon);
		port_str = entry.substr(colon + 1);
	}
	long port = 0;
	if (!parse_int(port_str, port) || port < 1 || port > 65535) {
		err = "invalid port in iface '" + entry + "'; expected 1-65535";
		return false;
	}
	out.addr = addr;
	out.port = static_cast<uint16_t>(port);
	return true;
}

// Parses `spec` into `out`, falling back to `fallback_spec` if parsing
// somehow fails (should not happen for a value that already passed
// duckdb_parse_ifaces() in set()).
std::vector<DuckDBIface> parse_ifaces_or_default(const std::string& spec,
                                                  const char* fallback_spec) {
	std::vector<DuckDBIface> out;
	std::string err;
	if (duckdb_parse_ifaces(spec, out, err)) {
		return out;
	}
	out.clear();
	err.clear();
	duckdb_parse_ifaces(fallback_spec, out, err);
	return out;
}

} // namespace

bool duckdb_parse_ifaces(const std::string& spec,
                         std::vector<DuckDBIface>& out,
                         std::string& err) {
	out.clear();
	std::istringstream ss(spec);
	std::string entry;
	while (std::getline(ss, entry, ';')) {
		if (entry.empty()) continue;
		DuckDBIface iface;
		if (!parse_one_iface(entry, iface, err)) {
			// Guarantee out is left empty on any failure, even when an
			// earlier entry in a multi-entry spec already parsed
			// successfully -- callers rely on "false means out is
			// untouched" rather than partially populated.
			out.clear();
			return false;
		}
		out.push_back(iface);
	}
	return true;
}

DuckDBConfigStore::DuckDBConfigStore() {
	values_ = {
		{ "mysql_ifaces",    kDefaultMysqlIfaces },
		{ "pgsql_ifaces",    kDefaultPgsqlIfaces },
		{ "database_path",   kDefaultDatabasePath },
		{ "memory_limit",    kDefaultMemoryLimit },
		{ "threads",         std::to_string(kDefaultThreads) },
		{ "max_connections", std::to_string(kDefaultMaxConnections) },
		{ "read_only",       kDefaultReadOnly ? "true" : "false" },
	};
}

std::string DuckDBConfigStore::get_locked(const std::string& name) const {
	const auto it = values_.find(name);
	if (it == values_.end()) return std::string();
	return it->second;
}

bool DuckDBConfigStore::set(const std::string& name, const std::string& value, std::string& err) {
	std::lock_guard<std::mutex> lock(mutex_);

	if (values_.find(name) == values_.end()) {
		err = "unknown duckdb variable '" + name + "'";
		return false;
	}

	if (name == "threads" || name == "max_connections") {
		long v = 0;
		if (!parse_int(value, v) || v < 1) {
			err = "invalid value for '" + name + "': expected an integer >= 1";
			return false;
		}
	} else if (name == "read_only") {
		bool v = false;
		if (!parse_bool(value, v)) {
			err = "invalid value for 'read_only': expected a boolean";
			return false;
		}
	} else if (name == "mysql_ifaces" || name == "pgsql_ifaces") {
		std::vector<DuckDBIface> ifaces;
		if (!duckdb_parse_ifaces(value, ifaces, err)) {
			return false;
		}
	}
	// database_path and memory_limit are accepted as-is.

	values_[name] = value;
	return true;
}

std::string DuckDBConfigStore::get(const std::string& name) const {
	std::lock_guard<std::mutex> lock(mutex_);
	return get_locked(name);
}

std::vector<std::string> DuckDBConfigStore::variable_names() const {
	std::lock_guard<std::mutex> lock(mutex_);
	std::vector<std::string> names;
	names.reserve(values_.size());
	for (const auto& kv : values_) {
		names.push_back(kv.first);
	}
	return names;
}

bool DuckDBConfigStore::validate(std::string& err) const {
	std::lock_guard<std::mutex> lock(mutex_);

	bool read_only_v = kDefaultReadOnly;
	parse_bool(get_locked("read_only"), read_only_v);
	const std::string database_path_v = get_locked("database_path");

	if (read_only_v && database_path_v == ":memory:") {
		err = "read_only=true requires a file-backed database_path; ':memory:' cannot be opened read-only";
		return false;
	}

	return true;
}

std::string DuckDBConfigStore::database_path() const {
	std::lock_guard<std::mutex> lock(mutex_);
	const std::string v = get_locked("database_path");
	return v.empty() ? kDefaultDatabasePath : v;
}

std::string DuckDBConfigStore::memory_limit() const {
	std::lock_guard<std::mutex> lock(mutex_);
	const std::string v = get_locked("memory_limit");
	return v.empty() ? kDefaultMemoryLimit : v;
}

int DuckDBConfigStore::threads() const {
	std::lock_guard<std::mutex> lock(mutex_);
	long v = 0;
	if (!parse_int(get_locked("threads"), v) || v < 1) return kDefaultThreads;
	return static_cast<int>(v);
}

int DuckDBConfigStore::max_connections() const {
	std::lock_guard<std::mutex> lock(mutex_);
	long v = 0;
	if (!parse_int(get_locked("max_connections"), v) || v < 1) return kDefaultMaxConnections;
	return static_cast<int>(v);
}

bool DuckDBConfigStore::read_only() const {
	std::lock_guard<std::mutex> lock(mutex_);
	bool v = kDefaultReadOnly;
	if (!parse_bool(get_locked("read_only"), v)) return kDefaultReadOnly;
	return v;
}

std::vector<DuckDBIface> DuckDBConfigStore::mysql_ifaces() const {
	std::lock_guard<std::mutex> lock(mutex_);
	return parse_ifaces_or_default(get_locked("mysql_ifaces"), kDefaultMysqlIfaces);
}

std::vector<DuckDBIface> DuckDBConfigStore::pgsql_ifaces() const {
	std::lock_guard<std::mutex> lock(mutex_);
	return parse_ifaces_or_default(get_locked("pgsql_ifaces"), kDefaultPgsqlIfaces);
}
