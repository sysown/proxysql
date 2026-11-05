#include "duckdb_replica.h"

#include "duckdb_replica_binlog.h"
#include "sqlite3db.h"

#include <mysql.h>

#include <cctype>
#include <chrono>
#include <cstdlib>
#include <memory>

namespace {

std::string lower_copy(std::string value) {
	for (char& c : value) {
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}
	return value;
}

std::string trim_copy(const std::string& value) {
	size_t begin = 0;
	while (begin < value.size() &&
	       std::isspace(static_cast<unsigned char>(value[begin]))) {
		++begin;
	}
	size_t end = value.size();
	while (end > begin &&
	       std::isspace(static_cast<unsigned char>(value[end - 1]))) {
		--end;
	}
	return value.substr(begin, end - begin);
}

std::string canon(const std::string& value) {
	return lower_copy(trim_copy(value));
}

bool is_on(const std::string& value) {
	const std::string s = canon(value);
	return s == "on" || s == "1" || s == "true";
}

bool is_off(const std::string& value) {
	const std::string s = canon(value);
	return s.empty() || s == "off" || s == "0" || s == "false";
}

const std::string* find_var(const std::map<std::string, std::string>& variables,
                            const char* name) {
	const std::string key = canon(name);
	for (const auto& item : variables) {
		if (canon(item.first) == key) return &item.second;
	}
	return nullptr;
}

bool valid_identifier(const std::string& value, size_t max_len) {
	if (value.empty() || value.size() > max_len) return false;
	for (unsigned char c : value) {
		if (c < 0x20 || c == '\'' || c == '"' || c == '`' || c == '\\') return false;
	}
	return true;
}

std::string field_at(SQLite3_row* row, int index) {
	if (row == nullptr || row->fields == nullptr || row->fields[index] == nullptr) return "";
	return row->fields[index];
}

bool parse_int(const std::string& text, long long& out) {
	if (text.empty()) return false;
	char* end = nullptr;
	out = std::strtoll(text.c_str(), &end, 10);
	return end != text.c_str() && end != nullptr && *end == '\0';
}

struct MysqlCloser {
	void operator()(MYSQL* mysql) const {
		if (mysql != nullptr) mysql_close(mysql);
	}
};

bool query_variables(MYSQL* mysql, std::map<std::string, std::string>& out, std::string& err) {
	if (mysql_query(mysql, "SHOW GLOBAL VARIABLES") != 0) {
		err = std::string("SHOW GLOBAL VARIABLES failed: ") + mysql_error(mysql);
		return false;
	}
	std::unique_ptr<MYSQL_RES, decltype(&mysql_free_result)> result(
		mysql_store_result(mysql), mysql_free_result);
	if (!result) {
		err = std::string("SHOW GLOBAL VARIABLES returned no result: ") + mysql_error(mysql);
		return false;
	}
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result.get())) != nullptr) {
		if (row[0] == nullptr) continue;
		out[canon(row[0])] = row[1] != nullptr ? row[1] : "";
	}
	return true;
}

bool query_binlog_status(MYSQL* mysql, DuckDBReplicaProbeResult& out, std::string& err) {
	const char* sql = "SHOW BINARY LOG STATUS";
	if (mysql_query(mysql, sql) != 0) {
		sql = "SHOW MASTER STATUS";
		if (mysql_query(mysql, sql) != 0) {
			err = std::string("cannot read binary log status (REPLICATION CLIENT required): ") +
				mysql_error(mysql);
			return false;
		}
	}
	std::unique_ptr<MYSQL_RES, decltype(&mysql_free_result)> result(
		mysql_store_result(mysql), mysql_free_result);
	if (!result) {
		err = std::string("binary log status returned no result: ") + mysql_error(mysql);
		return false;
	}
	MYSQL_FIELD* fields = mysql_fetch_fields(result.get());
	const unsigned int nfields = mysql_num_fields(result.get());
	MYSQL_ROW row = mysql_fetch_row(result.get());
	if (row == nullptr) {
		err = "binary log status returned no row; log_bin may be off";
		return false;
	}
	for (unsigned int i = 0; i < nfields; ++i) {
		if (fields[i].name == nullptr || row[i] == nullptr) continue;
		const std::string name = canon(fields[i].name);
		if (name == "file") out.binlog_file = row[i];
		else if (name == "position") {
			long long pos = -1;
			if (!parse_int(row[i], pos)) {
				err = "binary log status returned a non-numeric position";
				return false;
			}
			out.binlog_pos = pos;
		} else if (name == "executed_gtid_set") {
			out.gtid_executed = row[i];
		}
	}
	if (out.binlog_file.empty() || out.binlog_pos < 0) {
		err = "binary log status did not report a file and position";
		return false;
	}
	return true;
}

} // namespace

const DuckDBReplicaSource* DuckDBReplicaConfig::enabled_source() const {
	const DuckDBReplicaSource* found = nullptr;
	for (const auto& source : sources) {
		if (!source.enabled) continue;
		if (found != nullptr) return nullptr;
		found = &source;
	}
	return found;
}

std::string duckdb_replica_check_source_settings(
	const std::map<std::string, std::string>& variables,
	int64_t replica_server_id) {
	if (replica_server_id <= 0) return "replica server_id must be a positive integer";

	const std::string* log_bin = find_var(variables, "log_bin");
	if (log_bin == nullptr) return "source did not report log_bin";
	if (!is_on(*log_bin)) return "source log_bin is not ON";

	const std::string* format = find_var(variables, "binlog_format");
	if (format == nullptr) return "source did not report binlog_format";
	if (canon(*format) != "row") return "source binlog_format must be ROW";

	const std::string* gtid = find_var(variables, "gtid_mode");
	if (gtid == nullptr) return "source did not report gtid_mode";
	if (canon(*gtid) != "on") return "source gtid_mode must be ON";

	const std::string* consistency = find_var(variables, "enforce_gtid_consistency");
	if (consistency == nullptr) return "source did not report enforce_gtid_consistency";
	if (canon(*consistency) != "on" && canon(*consistency) != "1") {
		return "source enforce_gtid_consistency must be ON";
	}

	const std::string* image = find_var(variables, "binlog_row_image");
	if (image == nullptr) return "source did not report binlog_row_image";
	if (canon(*image) != "full") return "source binlog_row_image must be FULL";

	const std::string* value_options = find_var(variables, "binlog_row_value_options");
	if (value_options != nullptr && !canon(*value_options).empty()) {
		return "source binlog_row_value_options must be empty";
	}

	const std::string* compression = find_var(variables, "binlog_transaction_compression");
	if (compression != nullptr && !is_off(*compression)) {
		return "source binlog_transaction_compression must be OFF";
	}

	const std::string* source_id = find_var(variables, "server_id");
	if (source_id == nullptr) return "source did not report server_id";
	long long source_server_id = 0;
	if (!parse_int(trim_copy(*source_id), source_server_id) || source_server_id <= 0) {
		return "source server_id is not a positive integer";
	}
	if (source_server_id == replica_server_id) {
		return "replica server_id collides with the source server_id";
	}
	if (source_server_id > 4294967295LL) return "source server_id is outside the MySQL range";
	return "";
}

std::string duckdb_replica_validate_config(const DuckDBReplicaConfig& config) {
	int enabled = 0;
	for (const auto& source : config.sources) {
		if (!valid_identifier(source.source_id, 64)) {
			return "replica source_id must be a non-empty identifier of at most 64 characters";
		}
		if (source.hostname.empty() || source.hostname.size() > 255) {
			return "replica hostname is empty or longer than 255 characters";
		}
		if (source.port < 1 || source.port > 65535) {
			return "replica port must be between 1 and 65535";
		}
		if (source.username.empty() || source.username.size() > 128) {
			return "replica username is empty or longer than 128 characters";
		}
		if (source.server_id <= 0 || source.server_id > 4294967295LL) {
			return "replica server_id must be in the MySQL range 1..4294967295";
		}
		if (source.enabled) ++enabled;
	}
	if (enabled > 1) return "only one DuckDB replica source may be enabled";

	for (const auto& table : config.tables) {
		if (!valid_identifier(table.schema_name, 64) || !valid_identifier(table.table_name, 64)) {
			return "replica schema_name and table_name must be identifiers of at most 64 characters";
		}
		if (table.schema_name == "proxysql_replica") {
			return "schema proxysql_replica is reserved for replica metadata";
		}
		bool known = false;
		for (const auto& source : config.sources) {
			if (source.source_id == table.source_id) {
				known = true;
				break;
			}
		}
		if (!known) {
			return "replica table " + table.schema_name + "." + table.table_name +
				" references unknown source '" + table.source_id + "'";
		}
	}
	return "";
}

std::string duckdb_replica_probe_mysql(const DuckDBReplicaSource& source,
                                       DuckDBReplicaProbeResult& out) {
	out = DuckDBReplicaProbeResult {};
	// The replica thread is not a ProxySQL worker. The client library tracks
	// per-thread state, so init here rather than in every probe, including
	// the ones tests inject.
	mysql_thread_init();
	struct ThreadEnd {
		~ThreadEnd() { mysql_thread_end(); }
	} thread_end;
	std::unique_ptr<MYSQL, MysqlCloser> mysql(mysql_init(nullptr));
	if (!mysql) return "mysql_init failed";

	unsigned int timeout = 5;
	mysql_options(mysql.get(), MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	mysql_options(mysql.get(), MYSQL_OPT_READ_TIMEOUT, &timeout);
	mysql_options(mysql.get(), MYSQL_OPT_WRITE_TIMEOUT, &timeout);

	if (mysql_real_connect(mysql.get(), source.hostname.c_str(), source.username.c_str(),
	                       source.password.c_str(), nullptr,
	                       static_cast<unsigned int>(source.port), nullptr, 0) == nullptr) {
		return std::string("connection to replica source failed: ") + mysql_error(mysql.get());
	}

	std::map<std::string, std::string> variables;
	std::string err;
	if (!query_variables(mysql.get(), variables, err)) return err;
	err = duckdb_replica_check_source_settings(variables, source.server_id);
	if (!err.empty()) return err;
	if (!query_binlog_status(mysql.get(), out, err)) return err;

	const std::string* uuid = find_var(variables, "server_uuid");
	if (uuid != nullptr) out.server_uuid = *uuid;
	if (out.gtid_executed.empty()) {
		const std::string* executed = find_var(variables, "gtid_executed");
		if (executed != nullptr) out.gtid_executed = *executed;
	}
	return "";
}

DuckDBReplica::DuckDBReplica() = default;

DuckDBReplica::~DuckDBReplica() {
	stop();
}

bool DuckDBReplica::install(DuckDBReplicaConfig config, std::string& err) {
	err = duckdb_replica_validate_config(config);
	if (!err.empty()) return false;
	std::lock_guard<std::mutex> lock(life_mutex_);
	if (running_.load()) {
		err = "cannot install DuckDB replica configuration while the replica thread is running";
		return false;
	}
	config_ = std::move(config);
	return true;
}

bool DuckDBReplica::load_from_admin(SQLite3DB& admindb, std::string& err) {
	std::unique_ptr<SQLite3_result> sources;
	std::unique_ptr<SQLite3_result> tables;
	char* raw_error = nullptr;
	sources.reset(admindb.execute_statement(
		"SELECT source_id, hostname, port, username, password, server_id, enabled "
		"FROM main.duckdb_replica_sources ORDER BY source_id",
		&raw_error));
	if (raw_error != nullptr) {
		err = raw_error;
		free(raw_error);
		return false;
	}
	raw_error = nullptr;
	tables.reset(admindb.execute_statement(
		"SELECT source_id, schema_name, table_name, active "
		"FROM main.duckdb_replica_tables ORDER BY source_id, schema_name, table_name",
		&raw_error));
	if (raw_error != nullptr) {
		err = raw_error;
		free(raw_error);
		return false;
	}
	if (!sources || !tables) {
		err = "DuckDB replica tables did not return a result";
		return false;
	}

	DuckDBReplicaConfig config;
	for (auto* row : sources->rows) {
		DuckDBReplicaSource source;
		source.source_id = field_at(row, 0);
		source.hostname = field_at(row, 1);
		long long port = 0;
		long long server_id = 0;
		long long enabled = 0;
		if (!parse_int(field_at(row, 2), port) || !parse_int(field_at(row, 5), server_id) ||
		    !parse_int(field_at(row, 6), enabled)) {
			err = "DuckDB replica source row has a non-numeric port, server_id, or enabled flag";
			return false;
		}
		source.port = static_cast<int>(port);
		source.username = field_at(row, 3);
		source.password = field_at(row, 4);
		if (server_id <= 0 || server_id > 4294967295LL) {
			err = "DuckDB replica server_id is outside the MySQL range";
			return false;
		}
		source.server_id = server_id;
		source.enabled = enabled != 0;
		config.sources.push_back(std::move(source));
	}
	for (auto* row : tables->rows) {
		DuckDBReplicaTable table;
		table.source_id = field_at(row, 0);
		table.schema_name = field_at(row, 1);
		table.table_name = field_at(row, 2);
		long long active = 1;
		if (!field_at(row, 3).empty() && !parse_int(field_at(row, 3), active)) {
			err = "DuckDB replica table row has a non-numeric active flag";
			return false;
		}
		table.active = active != 0;
		config.tables.push_back(std::move(table));
	}
	return install(std::move(config), err);
}

void DuckDBReplica::publish(const DuckDBReplicaStatus& next) {
	{
		std::lock_guard<std::mutex> lock(status_mutex_);
		status_ = next;
	}
	status_cv_.notify_all();
}

DuckDBReplicaStatus DuckDBReplica::copy_status() const {
	std::lock_guard<std::mutex> lock(status_mutex_);
	return status_;
}

DuckDBReplicaStatus DuckDBReplica::status() const {
	return copy_status();
}

bool DuckDBReplica::wait_until(const std::function<bool(const DuckDBReplicaStatus&)>& pred,
                               int timeout_ms) const {
	std::unique_lock<std::mutex> lock(status_mutex_);
	return status_cv_.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] {
		return pred(status_);
	});
}

struct DuckDBReplica::Work {
	DuckDBReplicaSource source;
	std::vector<DuckDBReplicaTable> tables;
	DuckDBEngine* engine { nullptr };
	DuckDBReplicaProbe probe;
	DuckDBReplicaSnapshotFn snapshot;
};

DuckDBReplicaLoadResult duckdb_replica_load_snapshot(
	DuckDBEngine& engine,
	const DuckDBReplicaSource& source,
	const std::vector<DuckDBReplicaTable>& tables,
	const DuckDBReplicaProbeResult& probed,
	const std::function<bool()>& stop_requested,
	const std::function<void(void*)>& watch_connection,
	const std::function<void(const std::string&, uint64_t)>& progress);

// Overridden by duckdb_replica_snapshot.cpp in the plugin. These weak bodies
// let unit tests link this file without libduckdb or libmariadb.
__attribute__((weak))
DuckDBReplicaLoadResult duckdb_replica_load_snapshot(
	DuckDBEngine&, const DuckDBReplicaSource&, const std::vector<DuckDBReplicaTable>&,
	const DuckDBReplicaProbeResult&, const std::function<bool()>&,
	const std::function<void(void*)>&,
	const std::function<void(const std::string&, uint64_t)>&) {
	DuckDBReplicaLoadResult result;
	result.code = DuckDBReplicaLoadResult::Code::failed;
	result.error = "snapshot loader is not linked";
	return result;
}

__attribute__((weak))
DuckDBReplicaApplyResult duckdb_replica_apply_binlog(
	DuckDBEngine&, const DuckDBReplicaSource&, const std::vector<DuckDBReplicaTable>&,
	const DuckDBReplicaProbeResult&, const std::function<bool()>&,
	const std::function<void(uint64_t, uint64_t, int64_t)>&) {
	DuckDBReplicaApplyResult result;
	result.code = DuckDBReplicaApplyResult::Code::failed;
	result.error = "binlog applier is not linked";
	return result;
}

// Overridden by duckdb_replica_snapshot.cpp in the plugin. The weak body
// lets unit tests link this file without libduckdb.
extern "C" __attribute__((weak)) void duckdb_replica_interrupt_connection(void* conn) {
	(void)conn;
}

void DuckDBReplica::note_snapshot(const std::string& table, uint64_t rows) {
	std::lock_guard<std::mutex> lock(status_mutex_);
	status_.state = "snapshotting";
	status_.snapshot_table = table;
	status_.rows_applied = rows;
	status_.detail = "snapshotting " + table;
	status_cv_.notify_all();
}

void DuckDBReplica::note_apply(uint64_t rows, uint64_t batches, int64_t lag) {
	std::lock_guard<std::mutex> lock(status_mutex_);
	status_.state = "applying";
	status_.rows_applied = rows;
	status_.batches = batches;
	status_.seconds_behind_source = lag;
	status_.snapshot_table.clear();
	status_.detail = "applying binlog";
	status_cv_.notify_all();
}

void DuckDBReplica::watch_connection(void* conn) {
	std::lock_guard<std::mutex> lock(conn_mutex_);
	snapshot_conn_ = conn;
}

void DuckDBReplica::interrupt_snapshot() {
	std::lock_guard<std::mutex> lock(conn_mutex_);
	if (snapshot_conn_ != nullptr && duckdb_replica_interrupt_connection != nullptr) {
		duckdb_replica_interrupt_connection(snapshot_conn_);
	}
}

bool DuckDBReplica::stop_requested() const {
	std::lock_guard<std::mutex> lock(stop_mutex_);
	return stop_requested_;
}

void DuckDBReplica::finish_stopped(DuckDBReplicaStatus next) {
	next.state = "stopped";
	next.running = false;
	next.snapshot_table.clear();
	running_.store(false);
	publish(next);
}

void DuckDBReplica::thread_main(Work work) {
	DuckDBReplicaStatus next;
	next.running = true;
	next.state = "checking";
	next.source_id = work.source.source_id;
	next.hostname = work.source.hostname;
	next.port = work.source.port;
	next.server_id = work.source.server_id;
	running_.store(true);
	publish(next);

	DuckDBReplicaProbeResult probed;
	const std::string err = work.probe(work.source, probed);
	if (stop_requested()) {
		finish_stopped(next);
		return;
	}
	if (!err.empty()) {
		next.state = "error";
		next.last_error = err;
		next.detail.clear();
		publish(next);
	} else {
		next.state = "snapshotting";
		next.gtid_executed = probed.gtid_executed;
		next.binlog_file = probed.binlog_file;
		next.binlog_pos = probed.binlog_pos;
		next.last_error.clear();
		next.detail = "snapshotting";
		publish(next);

		DuckDBReplicaLoadResult loaded;
		if (work.snapshot) {
			loaded = work.snapshot(work.source, work.tables, probed);
		} else {
			loaded = duckdb_replica_load_snapshot(
				*work.engine, work.source, work.tables, probed,
				[this] { return stop_requested(); },
				[this](void* conn) { watch_connection(conn); },
				[this](const std::string& table, uint64_t rows) { note_snapshot(table, rows); });
		}
		if (loaded.code == DuckDBReplicaLoadResult::Code::stopped || stop_requested()) {
			finish_stopped(next);
			return;
		}
		if (loaded.code == DuckDBReplicaLoadResult::Code::failed) {
			next.state = "error";
			next.last_error = loaded.error;
			next.detail.clear();
			publish(next);
		} else {
			next.state = "snapshotted";
			next.gtid_executed = loaded.position.gtid_executed.empty() ? probed.gtid_executed : loaded.position.gtid_executed;
			next.binlog_file = loaded.position.binlog_file.empty() ? probed.binlog_file : loaded.position.binlog_file;
			next.binlog_pos = loaded.position.binlog_pos < 0 ? probed.binlog_pos : loaded.position.binlog_pos;
			next.rows_applied = loaded.rows;
			next.snapshot_table.clear();
			next.last_error.clear();
			next.detail = loaded.code == DuckDBReplicaLoadResult::Code::already_loaded
				? "snapshot already present"
				: "snapshot complete";
			publish(next);

			bool has_active = false;
			for (const auto& table : work.tables) {
				if (table.active && table.source_id == work.source.source_id) {
					has_active = true;
					break;
				}
			}
			if (work.engine != nullptr && has_active) {
				next.state = "applying";
				next.detail = "applying binlog";
				publish(next);
				const DuckDBReplicaApplyResult applied = duckdb_replica_apply_binlog(
					*work.engine, work.source, work.tables, loaded.position,
					[this] { return stop_requested(); },
					[this](uint64_t rows, uint64_t batches, int64_t lag) {
						note_apply(rows, batches, lag);
					});
				if (applied.code == DuckDBReplicaApplyResult::Code::stopped || stop_requested()) {
					finish_stopped(next);
					return;
				}
				if (applied.code == DuckDBReplicaApplyResult::Code::failed) {
					next.state = "error";
					next.last_error = applied.error;
					next.detail.clear();
					publish(next);
				} else {
					next.state = "applying";
					next.rows_applied = applied.rows;
					next.batches = applied.batches;
					publish(next);
				}
			}
		}
	}

	{
		std::unique_lock<std::mutex> lock(stop_mutex_);
		stop_cv_.wait(lock, [&] { return stop_requested_; });
	}
	finish_stopped(next);
}

bool DuckDBReplica::start(const DuckDBReplicaStartRequest& request, std::string& err) {
	if (request.database_path.empty() || request.database_path == ":memory:") {
		err = "DuckDB replica requires a file-backed database_path; :memory: cannot resume a position";
		return false;
	}
	if (request.read_only) {
		err = "DuckDB replica requires a read-write engine; duckdb-read_only is true";
		return false;
	}

	std::lock_guard<std::mutex> lock(life_mutex_);
	if (thread_.joinable() || running_.load()) {
		err = "DuckDB replica is already running";
		return false;
	}
	const DuckDBReplicaSource* enabled = config_.enabled_source();
	if (enabled == nullptr) {
		err = "no enabled DuckDB replica source is installed; add a row to duckdb_replica_sources and LOAD DUCKDB REPLICA TO RUNTIME";
		return false;
	}
	if (!request.snapshot && request.engine == nullptr) {
		err = "DuckDB engine is not open";
		return false;
	}

	DuckDBReplicaProbe probe = request.probe ? request.probe : DuckDBReplicaProbe(duckdb_replica_probe_mysql);
	stop_requested_ = false;
	DuckDBReplicaStatus next;
	next.running = true;
	next.state = "checking";
	next.source_id = enabled->source_id;
	next.hostname = enabled->hostname;
	next.port = enabled->port;
	next.server_id = enabled->server_id;
	running_.store(true);
	publish(next);
	Work work;
	work.source = *enabled;
	work.tables = config_.tables;
	work.engine = request.engine;
	work.probe = std::move(probe);
	work.snapshot = request.snapshot;
	try {
		thread_ = std::thread(&DuckDBReplica::thread_main, this, std::move(work));
	} catch (const std::exception& ex) {
		running_.store(false);
		next.running = false;
		next.state = "error";
		next.last_error = std::string("failed to start DuckDB replica thread: ") + ex.what();
		publish(next);
		err = next.last_error;
		return false;
	}
	return true;
}

void DuckDBReplica::stop() {
	std::thread joining;
	{
		std::lock_guard<std::mutex> lock(life_mutex_);
		if (!thread_.joinable()) {
			running_.store(false);
			std::lock_guard<std::mutex> status_lock(status_mutex_);
			status_.running = false;
			if (status_.state == "checking" || status_.state == "snapshotting" ||
			    status_.state == "snapshotted") {
				status_.state = "stopped";
			}
			return;
		}
		{
			std::lock_guard<std::mutex> stop_lock(stop_mutex_);
			stop_requested_ = true;
		}
		stop_cv_.notify_all();
		joining = std::move(thread_);
	}
	interrupt_snapshot();
	if (joining.joinable()) joining.join();
	std::lock_guard<std::mutex> lock(life_mutex_);
	std::lock_guard<std::mutex> status_lock(status_mutex_);
	running_.store(false);
	status_.running = false;
	status_.state = "stopped";
	stop_requested_ = false;
}

bool DuckDBReplica::reset(std::string& err) {
	std::lock_guard<std::mutex> lock(life_mutex_);
	if (thread_.joinable() || running_.load()) {
		err = "cannot reset DuckDB replica while it is running; STOP DUCKDB REPLICA first";
		return false;
	}
	status_ = DuckDBReplicaStatus {};
	return true;
}

DuckDBReplicaConfig DuckDBReplica::installed_config() const {
	std::lock_guard<std::mutex> lock(life_mutex_);
	return config_;
}
