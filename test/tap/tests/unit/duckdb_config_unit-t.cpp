#include "duckdb_config.h"
#include "tap.h"

#include <climits>
#include <string>
#include <vector>

int main() {
	plan(21);

	// --- iface parsing -------------------------------------------------
	std::vector<DuckDBIface> ifaces;
	std::string err;

	ok(duckdb_parse_ifaces("127.0.0.1:6031", ifaces, err) && ifaces.size() == 1,
	   "single iface parses");
	ok(ifaces.size() == 1 && ifaces[0].addr == "127.0.0.1" && ifaces[0].port == 6031,
	   "single iface has the right addr and port");

	ifaces.clear(); err.clear();
	ok(duckdb_parse_ifaces("0.0.0.0:6031;127.0.0.1:6032", ifaces, err) && ifaces.size() == 2,
	   "semicolon-separated ifaces parse");

	ifaces.clear(); err.clear();
	ok(duckdb_parse_ifaces("[::1]:6031", ifaces, err) && ifaces.size() == 1 &&
	   ifaces[0].addr == "::1" && ifaces[0].port == 6031,
	   "bracketed IPv6 iface parses");

	ifaces.clear(); err.clear();
	ok(duckdb_parse_ifaces("", ifaces, err) && ifaces.empty(),
	   "empty iface spec yields no listeners and is not an error");

	ifaces.clear(); err.clear();
	ok(duckdb_parse_ifaces("127.0.0.1", ifaces, err) == false && !err.empty(),
	   "iface without a port is rejected with a message");

	ifaces.clear(); err.clear();
	ok(duckdb_parse_ifaces("127.0.0.1:0", ifaces, err) == false,
	   "port 0 is rejected");

	ifaces.clear(); err.clear();
	ok(duckdb_parse_ifaces("127.0.0.1:70000", ifaces, err) == false,
	   "port above 65535 is rejected");

	ifaces.clear(); err.clear();
	ok(duckdb_parse_ifaces("0.0.0.0:6031;bad", ifaces, err) == false && ifaces.empty(),
	   "a later malformed entry fails the whole spec and leaves out empty");

	// --- defaults ------------------------------------------------------
	DuckDBConfigStore cfg;
	ok(cfg.database_path() == ":memory:", "database_path defaults to :memory:");
	ok(cfg.read_only() == false, "read_only defaults to false");
	// I1 fix: DuckDB's own default is true (deny-by-default is a deliberate
	// override of DuckDB, not DuckDB's own default) -- see the comment on
	// kDefaultEnableExternalAccess in duckdb_config.cpp.
	ok(cfg.enable_external_access() == false, "enable_external_access defaults to false");
	ok(cfg.max_connections() > 0, "max_connections has a positive default");

	// --- set / get -----------------------------------------------------
	err.clear();
	ok(cfg.set("threads", "4", err) && cfg.threads() == 4, "threads round-trips");

	err.clear();
	ok(cfg.set("threads", "not-a-number", err) == false && !err.empty(),
	   "non-numeric threads is rejected with a message");

	const std::string above_int_max = std::to_string(static_cast<long long>(INT_MAX) + 1);
	err.clear();
	ok(cfg.set("threads", above_int_max, err) == false && !err.empty(),
	   "threads above INT_MAX is rejected instead of narrowing to int");

	err.clear();
	ok(cfg.set("max_connections", above_int_max, err) == false && !err.empty(),
	   "max_connections above INT_MAX is rejected instead of narrowing to int");

	// --- cross-field validation ----------------------------------------
	// READ_ONLY is meaningless for an in-memory database and DuckDB rejects
	// the combination at open time; catch it at config time with a clear
	// message instead.
	err.clear();
	cfg.set("database_path", ":memory:", err);
	cfg.set("read_only", "true", err);
	ok(cfg.validate(err) == false && err.find("read_only") != std::string::npos,
	   "read_only with :memory: fails validation and names the variable");

	// An empty database_path is normalized to :memory: by database_path(), so
	// validation must reject the effective path rather than only the raw value.
	err.clear();
	cfg.set("database_path", "", err);
	ok(cfg.validate(err) == false && err.find("read_only") != std::string::npos,
	   "read_only with an empty database_path rejects the effective :memory: path");

	// --- enable_external_access set/get ---------------------------------
	err.clear();
	ok(cfg.set("enable_external_access", "true", err) && cfg.enable_external_access() == true,
	   "enable_external_access round-trips to true");

	err.clear();
	ok(cfg.set("enable_external_access", "not-a-bool", err) == false && !err.empty(),
	   "non-boolean enable_external_access is rejected with a message");

	return exit_status();
}
