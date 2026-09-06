#include "duckdb_engine.h"
#include "duckdb_config.h"

#include <algorithm>
#include <cctype>
#include <climits>
#include <new>
#include <sstream>
#include <utility>

namespace {

std::string sql_quote(const std::string& value) {
	std::string out("'");
	for (char c : value) {
		out.push_back(c);
		if (c == '\'') out.push_back('\'');
	}
	out.push_back('\'');
	return out;
}

bool query_scalar(duckdb_connection conn, const char* setting,
	              std::string& value, std::string& err) {
	duckdb_result result;
	const std::string sql = std::string("SELECT current_setting('") + setting + "')::VARCHAR";
	if (duckdb_query(conn, sql.c_str(), &result) != DuckDBSuccess) {
		const char* message = duckdb_result_error(&result);
		err = message != nullptr ? message : std::string("failed reading ") + setting;
		duckdb_destroy_result(&result);
		return false;
	}
	char* raw = duckdb_value_varchar(&result, 0, 0);
	value = raw != nullptr ? raw : "";
	if (raw != nullptr) duckdb_free(raw);
	duckdb_destroy_result(&result);
	return true;
}

bool execute_control(duckdb_connection conn, const std::string& sql, std::string& err) {
	duckdb_result result;
	if (duckdb_query(conn, sql.c_str(), &result) != DuckDBSuccess) {
		const char* message = duckdb_result_error(&result);
		err = message != nullptr ? message : "DuckDB configuration statement failed";
		duckdb_destroy_result(&result);
		return false;
	}
	duckdb_destroy_result(&result);
	return true;
}

bool parse_positive_int(const std::string& value, int& out) {
	try {
		size_t used = 0;
		const long parsed = std::stol(value, &used);
		if (used != value.size() || parsed < 1 || parsed > INT_MAX) return false;
		out = static_cast<int>(parsed);
		return true;
	} catch (...) {
		return false;
	}
}

bool parse_setting_bool(std::string value, bool& out) {
	std::transform(value.begin(), value.end(), value.begin(),
	               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	if (value == "true" || value == "1" || value == "on") { out = true; return true; }
	if (value == "false" || value == "0" || value == "off") { out = false; return true; }
	return false;
}

bool read_effective(duckdb_connection conn, DuckDBEffectiveSettings& out,
	                std::string& err) {
	std::string threads;
	std::string access_mode;
	std::string external;
	if (!query_scalar(conn, "memory_limit", out.memory_limit, err) ||
	    !query_scalar(conn, "threads", threads, err) ||
	    !query_scalar(conn, "access_mode", access_mode, err) ||
	    !query_scalar(conn, "enable_external_access", external, err)) {
		return false;
	}
	if (!parse_positive_int(threads, out.threads)) {
		err = "DuckDB returned an invalid threads setting: " + threads;
		return false;
	}
	std::transform(access_mode.begin(), access_mode.end(), access_mode.begin(),
	               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	out.read_only = access_mode == "read_only";
	if (!parse_setting_bool(external, out.enable_external_access)) {
		err = "DuckDB returned an invalid enable_external_access setting: " + external;
		return false;
	}
	return true;
}

bool validate_live_settings(const DuckDBLiveSettings& desired, std::string& err) {
	duckdb_config config = nullptr;
	if (duckdb_create_config(&config) != DuckDBSuccess) {
		err = "duckdb_create_config failed while validating live settings";
		return false;
	}
	auto set = [&](const char* name, const std::string& value) {
		if (duckdb_set_config(config, name, value.c_str()) == DuckDBSuccess) return true;
		err = std::string("invalid DuckDB ") + name + " value '" + value + "'";
		return false;
	};
	bool ok = true;
	if (desired.memory_limit) ok = set("memory_limit", *desired.memory_limit);
	if (ok && desired.threads) ok = set("threads", std::to_string(*desired.threads));
	if (ok && desired.enable_external_access) {
		ok = set("enable_external_access", *desired.enable_external_access ? "true" : "false");
	}
	duckdb_destroy_config(&config);
	return ok;
}

} // namespace

DuckDBEngine::~DuckDBEngine() {
	close();
}

bool DuckDBEngine::open(const DuckDBConfigStore& cfg, std::string& err) {
	err.clear();
	if (!cfg.validate(err)) return false;

	std::lock_guard<std::mutex> lock(mutex_);
	if (database_ != nullptr) {
		err = "duckdb engine is already open";
		return false;
	}

	duckdb_config config = nullptr;
	if (duckdb_create_config(&config) != DuckDBSuccess) {
		err = "duckdb_create_config failed";
		return false;
	}

	// set_config failures are reported rather than ignored: a silently
	// dropped memory_limit would let a runaway query take the process down.
	auto set_or_fail = [&](const char* k, const std::string& v) -> bool {
		if (duckdb_set_config(config, k, v.c_str()) != DuckDBSuccess) {
			err = std::string("duckdb_set_config failed for '") + k + "'='" + v + "'";
			return false;
		}
		return true;
	};

	bool ok = set_or_fail("memory_limit", cfg.memory_limit())
	       && set_or_fail("threads", std::to_string(cfg.threads()));
	if (ok && cfg.read_only()) ok = set_or_fail("access_mode", "READ_ONLY");
	// DuckDB's own default for enable_external_access is true (deps/duckdb/
	// duckdb/src/include/duckdb/main/config.hpp); DuckDBConfigStore's
	// default is false (see the comment on kDefaultEnableExternalAccess in
	// duckdb_config.cpp), so this is always set explicitly rather than
	// only on a non-default value -- silently relying on DuckDB's own
	// default here would reopen the exact gap this setting exists to
	// close. Applied at open() time only: DuckDB accepts true->false on a
	// running database but throws on false->true (deps/duckdb/duckdb/src/
	// main/settings/custom_settings.cpp), so tightening this at runtime
	// could in principle be layered on top later, but loosening it always
	// requires the engine to reopen -- see the README's Security section.
	if (ok) ok = set_or_fail("enable_external_access", cfg.enable_external_access() ? "true" : "false");
	if (!ok) { duckdb_destroy_config(&config); return false; }

	char* open_err = nullptr;
	const std::string path = cfg.database_path();
	const duckdb_state st = duckdb_open_ext(path.c_str(), &database_, config, &open_err);
	duckdb_destroy_config(&config);

	if (st != DuckDBSuccess) {
		err = "duckdb_open_ext failed for '" + path + "'";
		if (open_err != nullptr) { err += ": "; err += open_err; duckdb_free(open_err); }
		database_ = nullptr;
		return false;
	}
	if (open_err != nullptr) duckdb_free(open_err);
	if (duckdb_connect(database_, &control_connection_) != DuckDBSuccess) {
		err = "duckdb_connect failed for internal configuration connection";
		duckdb_close(&database_);
		database_ = nullptr;
		return false;
	}

	database_path_ = path;
	max_connections_.store(static_cast<size_t>(cfg.max_connections()));
	return true;
}

void DuckDBEngine::close() {
	std::lock_guard<std::mutex> lock(mutex_);
	if (database_ == nullptr) return;
	if (control_connection_ != nullptr) duckdb_disconnect(&control_connection_);
	live_connections_.clear();
	database_path_.clear();
	duckdb_close(&database_);
	database_ = nullptr;
}

bool DuckDBEngine::is_open() const {
	std::lock_guard<std::mutex> lock(mutex_);
	return database_ != nullptr;
}

bool DuckDBEngine::connect(duckdb_connection* out, std::string& err) {
	if (out == nullptr) { err = "connect: null out parameter"; return false; }
	*out = nullptr;
	std::lock_guard<std::mutex> lock(mutex_);
	if (database_ == nullptr) { err = "duckdb engine is not open"; return false; }
	if (duckdb_connect(database_, out) != DuckDBSuccess) {
		*out = nullptr;
		err = "duckdb_connect failed";
		return false;
	}
	try {
		live_connections_.push_back(*out);
	} catch (const std::bad_alloc&) {
		// Do not hand an untracked connection to the caller: close it while
		// still holding the engine lock so close()/interrupt_all() cannot race.
		duckdb_disconnect(out);
		*out = nullptr;
		err = "connect: unable to track the DuckDB connection";
		return false;
	}
	open_connections_.fetch_add(1);
	return true;
}

void DuckDBEngine::disconnect(duckdb_connection* conn) {
	if (conn == nullptr || *conn == nullptr) return;
	{
		std::lock_guard<std::mutex> lock(mutex_);
		for (auto it = live_connections_.begin(); it != live_connections_.end(); ++it) {
			if (*it == *conn) {
				live_connections_.erase(it);
				break;
			}
		}
	}
	duckdb_disconnect(conn);
	*conn = nullptr;
	open_connections_.fetch_sub(1);
}

void DuckDBEngine::interrupt_all() {
	std::lock_guard<std::mutex> lock(mutex_);
	for (duckdb_connection conn : live_connections_) {
		if (conn != nullptr) duckdb_interrupt(conn);
	}
}

std::string DuckDBEngine::database_path() const {
	std::lock_guard<std::mutex> lock(mutex_);
	return database_path_;
}

bool DuckDBEngine::effective_settings(DuckDBEffectiveSettings& out, std::string& err) {
	err.clear();
	std::lock_guard<std::mutex> lock(mutex_);
	if (database_ == nullptr || control_connection_ == nullptr) {
		err = "duckdb engine is not open";
		return false;
	}
	DuckDBEffectiveSettings current;
	if (!read_effective(control_connection_, current, err)) return false;
	current.database_path = database_path_;
	current.max_connections = max_connections_.load();
	out = std::move(current);
	return true;
}

bool DuckDBEngine::apply_live_settings(const DuckDBLiveSettings& desired,
	                                   std::string& err,
	                                   std::vector<std::string>* applied) {
	err.clear();
	if (applied != nullptr) applied->clear();
	if (desired.threads && *desired.threads < 1) {
		err = "invalid DuckDB threads value: expected an integer greater than zero";
		return false;
	}
	if (desired.max_connections && *desired.max_connections < 1) {
		err = "invalid DuckDB max_connections value: expected an integer greater than zero";
		return false;
	}
	if (!validate_live_settings(desired, err)) return false;

	std::lock_guard<std::mutex> lock(mutex_);
	if (database_ == nullptr || control_connection_ == nullptr) {
		err = "duckdb engine is not open";
		return false;
	}
	DuckDBEffectiveSettings before;
	if (!read_effective(control_connection_, before, err)) return false;
	before.max_connections = max_connections_.load();
	if (desired.enable_external_access && *desired.enable_external_access &&
	    !before.enable_external_access) {
		err = "enable_external_access cannot be enabled while the DuckDB database is open";
		return false;
	}

	std::vector<std::pair<std::string, std::string>> rollback;
	std::vector<std::string> changed;
	auto apply_reversible = [&](const char* name, const std::string& value,
	                          const std::string& old_value, const std::string& sql) {
		if (value == old_value) return true;
		std::string one_err;
		if (!execute_control(control_connection_, sql, one_err)) {
			err = std::string("failed applying duckdb-") + name + ": " + one_err;
			return false;
		}
		rollback.emplace_back(name, old_value);
		changed.emplace_back(name);
		return true;
	};

	bool ok = true;
	if (desired.memory_limit) {
		ok = apply_reversible("memory_limit", *desired.memory_limit, before.memory_limit,
		                      "SET GLOBAL memory_limit = " + sql_quote(*desired.memory_limit));
	}
	if (ok && desired.threads) {
		ok = apply_reversible("threads", std::to_string(*desired.threads),
		                      std::to_string(before.threads),
		                      "SET GLOBAL threads = " + std::to_string(*desired.threads));
	}
	if (!ok) {
		std::string rollback_errors;
		for (auto it = rollback.rbegin(); it != rollback.rend(); ++it) {
			std::string rollback_sql;
			if (it->first == "memory_limit") {
				rollback_sql = "SET GLOBAL memory_limit = " + sql_quote(it->second);
			} else {
				rollback_sql = "SET GLOBAL threads = " + it->second;
			}
			std::string one_err;
			if (!execute_control(control_connection_, rollback_sql, one_err)) {
				if (!rollback_errors.empty()) rollback_errors += "; ";
				rollback_errors += "failed restoring duckdb-" + it->first + ": " + one_err;
			}
		}
		if (!rollback_errors.empty()) err += "; " + rollback_errors;
		return false;
	}

	if (desired.max_connections && *desired.max_connections != before.max_connections) {
		max_connections_.store(*desired.max_connections);
		changed.emplace_back("max_connections");
	}

	if (desired.enable_external_access &&
	    *desired.enable_external_access != before.enable_external_access) {
		std::string one_err;
		if (!execute_control(control_connection_,
		                     "SET GLOBAL enable_external_access = false", one_err)) {
			max_connections_.store(before.max_connections);
			err = "failed disabling duckdb-enable_external_access: " + one_err;
			// Reversible engine settings are restored even though this step is
			// deliberately last. Report a rollback failure explicitly.
			for (auto it = rollback.rbegin(); it != rollback.rend(); ++it) {
				const std::string rollback_sql = it->first == "memory_limit"
					? "SET GLOBAL memory_limit = " + sql_quote(it->second)
					: "SET GLOBAL threads = " + it->second;
				std::string rollback_err;
				if (!execute_control(control_connection_, rollback_sql, rollback_err)) {
					err += "; failed restoring duckdb-" + it->first + ": " + rollback_err;
				}
			}
			return false;
		}
		changed.emplace_back("enable_external_access");
	}

	if (applied != nullptr) *applied = std::move(changed);
	return true;
}

size_t DuckDBEngine::open_connections() const { return open_connections_.load(); }

void DuckDBEngine::set_max_connections(size_t n) { max_connections_.store(n); }

bool DuckDBEngine::try_reserve_connection() {
	const size_t cap = max_connections_.load();
	size_t cur = reserved_.load();
	while (cur < cap) {
		if (reserved_.compare_exchange_weak(cur, cur + 1)) return true;
	}
	return false;
}

void DuckDBEngine::release_connection() {
	size_t cur = reserved_.load();
	while (cur > 0) {
		if (reserved_.compare_exchange_weak(cur, cur - 1)) return;
	}
}
