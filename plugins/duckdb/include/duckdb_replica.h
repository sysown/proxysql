#ifndef DUCKDB_REPLICA_H
#define DUCKDB_REPLICA_H

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

class SQLite3DB;
class DuckDBEngine;

// One MySQL source. v1 runs at most one enabled row. The password is held
// in memory the same way monitor credentials are; it is never copied into
// status, logs, or stats.
struct DuckDBReplicaSource {
	std::string source_id;
	std::string hostname;
	int port { 0 };
	std::string username;
	std::string password;
	int64_t server_id { 0 };
	bool enabled { false };
};

struct DuckDBReplicaTable {
	std::string source_id;
	std::string schema_name;
	std::string table_name;
	bool active { true };
};

struct DuckDBReplicaConfig {
	std::vector<DuckDBReplicaSource> sources;
	std::vector<DuckDBReplicaTable> tables;

	// nullptr when no row is enabled. Two enabled rows is a validation error,
	// not a silent pick.
	const DuckDBReplicaSource* enabled_source() const;
};

// Coordinates a later dump would start from. Filled by a successful probe.
// binlog_pos < 0 means the probe did not report a position.
struct DuckDBReplicaProbeResult {
	std::string gtid_executed;
	std::string binlog_file;
	int64_t binlog_pos { -1 };
	std::string server_uuid;
};

// Empty string means the source accepted the probe. A non-empty string is
// the operator-facing error and stops the replica in `error`.
using DuckDBReplicaProbe =
	std::function<std::string(const DuckDBReplicaSource&, DuckDBReplicaProbeResult&)>;

struct DuckDBReplicaStatus {
	std::string state { "stopped" };
	std::string source_id;
	std::string hostname;
	int port { 0 };
	int64_t server_id { 0 };
	std::string gtid_executed;
	std::string binlog_file;
	int64_t binlog_pos { -1 };
	int64_t seconds_behind_source { -1 };
	std::string last_error;
	std::string detail;
	std::string snapshot_table;
	uint64_t rows_applied { 0 };
	uint64_t batches { 0 };
	bool running { false };
};

enum class DuckDBReplicaTypeKind {
	int8, int16, int32, int64,
	uint8, uint16, uint32, uint64,
	float32, float64,
	decimal,
	date, timestamp,
	varchar, blob
};

struct DuckDBReplicaMappedColumn {
	std::string name;
	std::string duckdb_type;
	DuckDBReplicaTypeKind kind { DuckDBReplicaTypeKind::varchar };
	uint8_t width { 0 };
	uint8_t scale { 0 };
	bool not_null { false };
	bool primary_key { false };
};

// Empty string means the column can be snapshotted. `column_type` is MySQL's
// full type (`bigint(20) unsigned`, `decimal(10,2)`). `charset` is empty for
// non-character columns.
std::string duckdb_replica_map_column(const std::string& name,
                                      const std::string& data_type,
                                      const std::string& column_type,
                                      const std::string& charset,
                                      const std::string& column_key,
                                      bool nullable,
                                      DuckDBReplicaMappedColumn& out);

std::string duckdb_replica_create_table_sql(const std::string& schema,
                                            const std::string& table,
                                            const std::vector<DuckDBReplicaMappedColumn>& columns,
                                            const std::string& catalog = "");

std::string duckdb_replica_qualified_name(const std::string& catalog,
                                          const std::string& schema,
                                          const std::string& table);

// DuckDB folds ASCII identifier case, including quoted identifiers.
bool duckdb_replica_is_reserved_schema(const std::string& schema);

std::string duckdb_quote_mysql_ident(const std::string& name);
std::string duckdb_quote_duckdb_ident(const std::string& name);

struct DuckDBReplicaLoadResult {
	enum class Code { ok, already_loaded, stopped, failed } code { Code::failed };
	std::string error;
	DuckDBReplicaProbeResult position;
	uint64_t rows { 0 };
};

// Atomically drops manifest-owned tables and replica metadata. Unrelated
// tables survive. Empty string means success; failures preserve all storage.
std::string duckdb_replica_drop_snapshot(DuckDBEngine& engine);

// Injected by tests. Empty means the built-in snapshot, which requires
// `engine`. The built-in snapshot is not declared here so this header does
// not depend on duckdb.h.
using DuckDBReplicaSnapshotFn =
	std::function<DuckDBReplicaLoadResult(const DuckDBReplicaSource&,
	                                      const std::vector<DuckDBReplicaTable>&,
	                                      const DuckDBReplicaProbeResult&)>;

struct DuckDBReplicaStartRequest {
	// Effective open database, not the editable Main value. `:memory:` and a
	// read-only engine cannot hold a durable applied position.
	std::string database_path;
	bool read_only { false };
	DuckDBEngine* engine { nullptr };
	// Empty uses the MySQL probe. Tests inject a probe so lifecycle does not
	// require a server.
	DuckDBReplicaProbe probe;
	// Empty uses duckdb_replica_load_snapshot. Tests inject this to avoid a
	// server and a DuckDB file.
	DuckDBReplicaSnapshotFn snapshot;
};

// Pure check of SHOW GLOBAL VARIABLES output. Keys are matched
// case-insensitively. `replica_server_id` is the id this replica would
// register with, and must differ from the source's server_id.
// Empty string means the source meets the v1 requirements.
std::string duckdb_replica_check_source_settings(
	const std::map<std::string, std::string>& variables,
	int64_t replica_server_id);

// Empty string means the config can be installed. Does not dial the source.
std::string duckdb_replica_validate_config(const DuckDBReplicaConfig& config);

// Connects to the source, reads global variables and binary-log status, and
// fills `out` on success. Does not register as a replica and does not dump
// events. Call from a thread that has run mysql_thread_init().
std::string duckdb_replica_probe_mysql(const DuckDBReplicaSource& source,
                                       DuckDBReplicaProbeResult& out);

// Owns the replica thread. stop() joins it. After the source check, the
// thread snapshots opted-in tables and then follows the binary log until
// stop() is requested.
class DuckDBReplica {
public:
	DuckDBReplica();
	~DuckDBReplica();

	DuckDBReplica(const DuckDBReplica&) = delete;
	DuckDBReplica& operator=(const DuckDBReplica&) = delete;

	// Replaces the installed config only if validation succeeds.
	bool install(DuckDBReplicaConfig config, std::string& err);
	bool load_from_admin(SQLite3DB& admindb, std::string& err);

	bool start(const DuckDBReplicaStartRequest& request, std::string& err);
	// Joins the thread. Safe when never started, and safe to call twice.
	void stop();
	// Legal only when the thread is not running. Clears status, not the
	// installed source definition. A storage callback runs under the lifecycle
	// lock and must not re-enter this object; its failure preserves status.
	bool reset(std::string& err,
	           const std::function<std::string()>& reset_storage = {});
	DuckDBReplicaConfig installed_config() const;

	DuckDBReplicaStatus status() const;
	bool wait_until(const std::function<bool(const DuckDBReplicaStatus&)>& pred,
	                int timeout_ms) const;

private:
	struct Work;
	void thread_main(Work work);
	void publish(const DuckDBReplicaStatus& next);
	void note_snapshot(const std::string& table, uint64_t rows);
	void note_apply(uint64_t rows, uint64_t batches, int64_t lag,
	                const DuckDBReplicaProbeResult& position);
	void finish_stopped(DuckDBReplicaStatus next);
	void watch_connection(void* conn);
	void interrupt_snapshot();
	bool stop_requested() const;
	DuckDBReplicaStatus copy_status() const;

	mutable std::mutex life_mutex_;
	mutable std::mutex status_mutex_;
	std::mutex conn_mutex_;
	void* snapshot_conn_ { nullptr };
	mutable std::mutex stop_mutex_;
	std::condition_variable stop_cv_;
	mutable std::condition_variable status_cv_;
	bool stop_requested_ { false };
	std::atomic<bool> running_ { false };
	DuckDBReplicaConfig config_;
	DuckDBReplicaStatus status_;
	std::thread thread_;
};

bool duckdb_register_replica_admin(class ProxySQL_PluginServices& services);

#endif // DUCKDB_REPLICA_H
