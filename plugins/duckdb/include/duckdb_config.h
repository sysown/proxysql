#ifndef __DUCKDB_CONFIG_H
#define __DUCKDB_CONFIG_H

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

struct DuckDBIface {
	std::string addr;
	uint16_t port { 0 };
};

// Parses "addr:port" entries separated by ';'. IPv6 literals must be
// bracketed: "[::1]:6031". An empty spec is valid and yields no ifaces.
// Returns false and fills `err` on the first malformed entry; on failure,
// `out` is left empty (any entries parsed before the failing one are
// discarded, not left partially populated).
bool duckdb_parse_ifaces(const std::string& spec,
                         std::vector<DuckDBIface>& out,
                         std::string& err);

// Holds the plugin's variables. All access is under one mutex; the store
// is read from connection threads and written only during the lifecycle
// phases and LOAD ... TO RUNTIME.
class DuckDBConfigStore {
public:
	DuckDBConfigStore();

	bool set(const std::string& name, const std::string& value, std::string& err);
	std::string get(const std::string& name) const;
	std::vector<std::string> variable_names() const;

	// Cross-field checks that a per-variable set() cannot make.
	bool validate(std::string& err) const;

	std::string database_path() const;
	std::string memory_limit() const;
	int threads() const;
	int max_connections() const;
	bool read_only() const;
	std::vector<DuckDBIface> mysql_ifaces() const;
	std::vector<DuckDBIface> pgsql_ifaces() const;

private:
	mutable std::mutex mutex_;
	std::map<std::string, std::string> values_;

	std::string get_locked(const std::string& name) const;
};

#endif // __DUCKDB_CONFIG_H
