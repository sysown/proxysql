#ifndef DUCKDB_REPLICA_BINLOG_H
#define DUCKDB_REPLICA_BINLOG_H

#include "duckdb_replica.h"

#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <utility>
#include <vector>

class DuckDBEngine;

// The connector decodes full images only; UPDATE must include every column
// in both bitmaps. Padding bits in the final bitmap byte are ignored.
bool duckdb_replica_full_row_images(const uint8_t* before, const uint8_t* after,
                                    uint32_t columns, bool update);

// A decoded binlog value, kept independent of the MariaDB connector types so
// the literal builder can be unit-tested without a server or a dump.
struct DuckDBReplicaValue {
	enum class Kind { null, integer, real, decimal_text, text, binary, date, datetime, time };
	Kind kind { Kind::null };
	int64_t integer { 0 };
	double real { 0 };
	std::string text;
};

// Returns a DuckDB SQL literal. `binary` becomes from_hex(...)::BLOB.
// Returns an empty string with `err` set for a value that cannot be
// represented as a literal (for example a VARCHAR containing NUL).
std::string duckdb_replica_value_literal(const DuckDBReplicaValue& value, std::string& err);

// Executed GTID set, compressed per source UUID. `add` accepts
// "uuid:sequence". Duplicate or out-of-order sequences are inserted without
// creating overlapping intervals.
class DuckDBReplicaGtidSet {
public:
	void add(const std::string& uuid, uint64_t sequence);
	void add_interval(const std::string& uuid, uint64_t first, uint64_t last);
	// Merges a set read from proxysql_replica.position.
	bool merge(const std::string& gtid_set, std::string& err);
	void merge(const DuckDBReplicaGtidSet& other);
	std::string to_string() const;
	bool empty() const;
private:
	std::map<std::string, std::vector<std::pair<uint64_t, uint64_t>>> intervals_;
};

// Parses a GTID string ("uuid:1-4:7") into intervals. Returns false on a
// malformed entry.
bool duckdb_replica_parse_gtid_set(const std::string& text,
                                   DuckDBReplicaGtidSet& out,
                                   std::string& err);

struct DuckDBReplicaApplyResult {
	enum class Code { stopped, failed } code { Code::failed };
	std::string error;
	DuckDBReplicaProbeResult position;
	uint64_t rows { 0 };
	uint64_t batches { 0 };
};

// Reads the binlog from `start.binlog_file`/`start.binlog_pos`, applies
// committed row changes to the already-snapshotted tables, and updates
// proxysql_replica.position in the same DuckDB transaction as each batch.
// Returns `stopped` when `stop_requested()` says so, otherwise `failed`.
DuckDBReplicaApplyResult duckdb_replica_apply_binlog(
	DuckDBEngine& engine,
	const DuckDBReplicaSource& source,
	const std::vector<DuckDBReplicaTable>& tables,
	const DuckDBReplicaProbeResult& start,
	const std::function<bool()>& stop_requested,
	const std::function<void(uint64_t, uint64_t, int64_t, const DuckDBReplicaProbeResult&)>& progress);

#endif // DUCKDB_REPLICA_BINLOG_H
