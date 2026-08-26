#include "duckdb_engine.h"
#include "duckdb_config.h"

#include <utility>

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

	max_connections_.store(static_cast<size_t>(cfg.max_connections()));
	return true;
}

void DuckDBEngine::close() {
	std::lock_guard<std::mutex> lock(mutex_);
	if (database_ == nullptr) return;
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
	open_connections_.fetch_add(1);
	return true;
}

void DuckDBEngine::disconnect(duckdb_connection* conn) {
	if (conn == nullptr || *conn == nullptr) return;
	duckdb_disconnect(conn);
	*conn = nullptr;
	open_connections_.fetch_sub(1);
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
