#ifndef DUCKDB_ENGINE_H
#define DUCKDB_ENGINE_H

#include "duckdb.h"

#include <atomic>
#include <cstddef>
#include <mutex>
#include <string>
#include <vector>

class DuckDBConfigStore;

// Owns the single process-wide duckdb_database. Connections are created
// per session; DuckDB's own concurrency control serialises them, so no
// external pool is needed.
class DuckDBEngine {
public:
	DuckDBEngine() = default;
	~DuckDBEngine();

	DuckDBEngine(const DuckDBEngine&) = delete;
	DuckDBEngine& operator=(const DuckDBEngine&) = delete;

	// Applies memory_limit, threads and access_mode from `cfg`, then opens
	// cfg.database_path(). Returns false with `err` set on failure; the
	// engine is left closed.
	bool open(const DuckDBConfigStore& cfg, std::string& err);

	// Safe to call when never opened, and safe to call twice.
	void close();
	bool is_open() const;

	bool connect(duckdb_connection* out, std::string& err);
	void disconnect(duckdb_connection* conn);

	// Interrupts every live connection. Safe to call from stop() so an
	// in-flight query cannot hold plugin unload / process shutdown.
	void interrupt_all();

	std::string database_path() const;

	size_t open_connections() const;

	// max_connections admission control, used by the accept loop before a
	// session object is built. Reserve on accept, release on thread exit.
	bool try_reserve_connection();
	void release_connection();

	void set_max_connections(size_t n);

private:
	mutable std::mutex mutex_;
	duckdb_database database_ { nullptr };
	std::string database_path_;
	std::vector<duckdb_connection> live_connections_;
	std::atomic<size_t> open_connections_ { 0 };
	std::atomic<size_t> reserved_ { 0 };
	std::atomic<size_t> max_connections_ { 100 };
};

#endif // DUCKDB_ENGINE_H
