#include "duckdb_replica_binlog.h"
#include "duckdb_replica_catalog.h"

#include "duckdb_engine.h"

#include <mysql.h>
#include <mariadb_rpl.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace {

constexpr size_t kBatchRows = 50000;
constexpr size_t kBatchBytes = 64 * 1024 * 1024;
constexpr int kFlushIntervalMs = 200;

std::string sql_literal(const std::string& value) {
	std::string out("'");
	for (char c : value) {
		out.push_back(c);
		if (c == '\'') out.push_back('\'');
	}
	out.push_back('\'');
	return out;
}

bool exec_duckdb(duckdb_connection conn, const std::string& sql, std::string& err) {
	duckdb_result result;
	if (duckdb_query(conn, sql.c_str(), &result) != DuckDBSuccess) {
		const char* message = duckdb_result_error(&result);
		err = message != nullptr ? message : "DuckDB statement failed";
		duckdb_destroy_result(&result);
		return false;
	}
	duckdb_destroy_result(&result);
	return true;
}

std::string uuid_text(const char source_id[16]) {
	static const char digits[] = "0123456789abcdef";
	std::string out;
	out.reserve(36);
	for (int i = 0; i < 16; ++i) {
		if (i == 4 || i == 6 || i == 8 || i == 10) out.push_back('-');
		const unsigned char c = static_cast<unsigned char>(source_id[i]);
		out.push_back(digits[c >> 4]);
		out.push_back(digits[c & 0x0f]);
	}
	return out;
}

std::string date_only_text(const MYSQL_TIME& tm) {
	char buf[32];
	std::snprintf(buf, sizeof(buf), "%04u-%02u-%02u", tm.year, tm.month, tm.day);
	return buf;
}

std::string datetime_text(const MYSQL_TIME& tm) {
	char buf[64];
	if (tm.second_part != 0) {
		std::snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u.%06lu",
		              tm.year, tm.month, tm.day, tm.hour, tm.minute, tm.second,
		              static_cast<unsigned long>(tm.second_part));
	} else {
		std::snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u",
		              tm.year, tm.month, tm.day, tm.hour, tm.minute, tm.second);
	}
	return buf;
}

std::string epoch_text(uint64_t seconds, uint32_t micros) {
	const time_t value = static_cast<time_t>(seconds);
	struct tm tm_value {};
	gmtime_r(&value, &tm_value);
	char buf[64];
	if (micros != 0) {
		std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%06u",
		              tm_value.tm_year + 1900, tm_value.tm_mon + 1, tm_value.tm_mday,
		              tm_value.tm_hour, tm_value.tm_min, tm_value.tm_sec, micros);
	} else {
		std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
		              tm_value.tm_year + 1900, tm_value.tm_mon + 1, tm_value.tm_mday,
		              tm_value.tm_hour, tm_value.tm_min, tm_value.tm_sec);
	}
	return buf;
}

std::string time_text(const MYSQL_TIME& tm) {
	char buf[48];
	if (tm.second_part != 0) {
		std::snprintf(buf, sizeof(buf), "%s%02u:%02u:%02u.%06lu", tm.neg ? "-" : "",
		              tm.hour, tm.minute, tm.second,
		              static_cast<unsigned long>(tm.second_part));
	} else {
		std::snprintf(buf, sizeof(buf), "%s%02u:%02u:%02u", tm.neg ? "-" : "",
		              tm.hour, tm.minute, tm.second);
	}
	return buf;
}

std::string unsigned_bytes_text(const std::string& bytes) {
	unsigned __int128 value = 0;
	for (unsigned char c : bytes) value = (value << 8) | c;
	char buf[64];
	const unsigned long long lo = static_cast<unsigned long long>(value);
	const unsigned long long hi = static_cast<unsigned long long>(value >> 64);
	if (hi == 0) {
		std::snprintf(buf, sizeof(buf), "%llu", lo);
	} else {
		std::snprintf(buf, sizeof(buf), "%llu%020llu", hi, lo);
	}
	return buf;
}

bool is_unsigned_duckdb(const std::string& type) {
	return !type.empty() && (type[0] == 'U' || type[0] == 'u');
}

bool target_is_varchar(const std::string& type) {
	return type == "VARCHAR";
}

bool target_is_blob(const std::string& type) {
	return type == "BLOB";
}

DuckDBReplicaValue decode_value(const MARIADB_RPL_VALUE& value,
                                uint8_t mysql_type,
                                const std::string& duckdb_type) {
	DuckDBReplicaValue out;
	if (value.is_null) return out;

	const bool unsigned_target = is_unsigned_duckdb(duckdb_type);
	const bool varchar_target = target_is_varchar(duckdb_type);
	const bool blob_target = target_is_blob(duckdb_type);

	switch (mysql_type) {
	case MYSQL_TYPE_YEAR:
		out.kind = DuckDBReplicaValue::Kind::integer;
		out.integer = static_cast<int64_t>(value.val.ull);
		break;
	case MYSQL_TYPE_TINY:
	case MYSQL_TYPE_SHORT:
	case MYSQL_TYPE_INT24:
	case MYSQL_TYPE_LONG:
	case MYSQL_TYPE_LONGLONG: {
		// Connector/C fills the union with the unsigned representation, even
		// for signed narrow columns. Recover the sign using snapshot metadata.
		int64_t signed_value = value.val.ll;
		switch (mysql_type) {
		case MYSQL_TYPE_TINY: signed_value = static_cast<int8_t>(value.val.ull); break;
		case MYSQL_TYPE_SHORT: signed_value = static_cast<int16_t>(value.val.ull); break;
		case MYSQL_TYPE_INT24:
			signed_value = static_cast<int64_t>(value.val.ull & 0xffffff) -
				((value.val.ull & 0x800000) ? 0x1000000 : 0);
			break;
		case MYSQL_TYPE_LONG: signed_value = static_cast<int32_t>(value.val.ull); break;
		default: break;
		}
		if (varchar_target) {
			out.kind = DuckDBReplicaValue::Kind::text;
			out.text = std::to_string(unsigned_target ? static_cast<unsigned long long>(value.val.ull)
			                                          : static_cast<long long>(signed_value));
		} else if (unsigned_target && value.val.ull > static_cast<uint64_t>(INT64_MAX)) {
			out.kind = DuckDBReplicaValue::Kind::decimal_text;
			out.text = std::to_string(static_cast<unsigned long long>(value.val.ull));
		} else {
			out.kind = DuckDBReplicaValue::Kind::integer;
			out.integer = unsigned_target ? static_cast<int64_t>(value.val.ull) : signed_value;
		}
		break;
	}
	case MYSQL_TYPE_FLOAT:
		out.kind = DuckDBReplicaValue::Kind::real;
		out.real = value.val.f;
		break;
	case MYSQL_TYPE_DOUBLE:
		out.kind = DuckDBReplicaValue::Kind::real;
		out.real = value.val.d;
		break;
	case MYSQL_TYPE_NEWDECIMAL:
	case MYSQL_TYPE_DECIMAL:
		out.kind = DuckDBReplicaValue::Kind::decimal_text;
		out.text.assign(value.val.str.str != nullptr ? value.val.str.str : "", value.val.str.length);
		break;
	case MYSQL_TYPE_DATE:
		out.kind = DuckDBReplicaValue::Kind::date;
		out.text = date_only_text(value.val.tm);
		break;
	case MYSQL_TYPE_DATETIME:
	case MYSQL_TYPE_DATETIME2:
		out.kind = DuckDBReplicaValue::Kind::datetime;
		out.text = datetime_text(value.val.tm);
		break;
	case MYSQL_TYPE_TIMESTAMP:
		out.kind = DuckDBReplicaValue::Kind::datetime;
		out.text = epoch_text(value.val.ull, 0);
		break;
	case MYSQL_TYPE_TIMESTAMP2: {
		// The connector renders TIMESTAMP2 as "<seconds>.<microseconds>".
		std::string raw(value.val.str.str != nullptr ? value.val.str.str : "", value.val.str.length);
		unsigned long long seconds = 0;
		unsigned micros = 0;
		if (std::sscanf(raw.c_str(), "%llu.%u", &seconds, &micros) != 2) {
			out.kind = DuckDBReplicaValue::Kind::text;
			out.text = raw;
		} else {
			out.kind = DuckDBReplicaValue::Kind::datetime;
			out.text = epoch_text(seconds, micros);
		}
		break;
	}
	case MYSQL_TYPE_TIME:
	case MYSQL_TYPE_TIME2:
		out.kind = DuckDBReplicaValue::Kind::text;
		out.text = time_text(value.val.tm);
		break;
	case MYSQL_TYPE_BIT: {
		std::string bytes(value.val.str.str != nullptr ? value.val.str.str : "", value.val.str.length);
		out.kind = DuckDBReplicaValue::Kind::text;
		out.text = unsigned_bytes_text(bytes);
		break;
	}
	case MYSQL_TYPE_ENUM:
	case MYSQL_TYPE_SET:
		out.kind = DuckDBReplicaValue::Kind::text;
		out.text = std::to_string(static_cast<unsigned long long>(value.val.ull));
		break;
	case MYSQL_TYPE_TINY_BLOB:
	case MYSQL_TYPE_MEDIUM_BLOB:
	case MYSQL_TYPE_LONG_BLOB:
	case MYSQL_TYPE_BLOB:
		if (blob_target) {
			out.kind = DuckDBReplicaValue::Kind::binary;
		} else if (varchar_target) {
			out.kind = DuckDBReplicaValue::Kind::text;
		} else {
			out.kind = DuckDBReplicaValue::Kind::binary;
		}
		out.text.assign(value.val.str.str != nullptr ? value.val.str.str : "", value.val.str.length);
		break;
	case MYSQL_TYPE_VARCHAR:
	case MYSQL_TYPE_VAR_STRING:
	case MYSQL_TYPE_STRING:
	default:
		out.kind = blob_target ? DuckDBReplicaValue::Kind::binary : DuckDBReplicaValue::Kind::text;
		out.text.assign(value.val.str.str != nullptr ? value.val.str.str : "", value.val.str.length);
		break;
	}
	return out;
}

bool supported_binlog_type(uint8_t type) {
	switch (type) {
	case MYSQL_TYPE_TINY:
	case MYSQL_TYPE_SHORT:
	case MYSQL_TYPE_INT24:
	case MYSQL_TYPE_LONG:
	case MYSQL_TYPE_LONGLONG:
	case MYSQL_TYPE_YEAR:
	case MYSQL_TYPE_FLOAT:
	case MYSQL_TYPE_DOUBLE:
	case MYSQL_TYPE_NEWDECIMAL:
	case MYSQL_TYPE_DATE:
	case MYSQL_TYPE_DATETIME:
	case MYSQL_TYPE_DATETIME2:
	case MYSQL_TYPE_TIMESTAMP:
	case MYSQL_TYPE_TIMESTAMP2:
	case MYSQL_TYPE_TIME:
	case MYSQL_TYPE_TIME2:
	case MYSQL_TYPE_BIT:
	case MYSQL_TYPE_ENUM:
	case MYSQL_TYPE_SET:
	case MYSQL_TYPE_TINY_BLOB:
	case MYSQL_TYPE_MEDIUM_BLOB:
	case MYSQL_TYPE_LONG_BLOB:
	case MYSQL_TYPE_BLOB:
	case MYSQL_TYPE_VARCHAR:
	case MYSQL_TYPE_VAR_STRING:
	case MYSQL_TYPE_STRING:
		return true;
	default:
		return false;
	}
}

std::string join_names(const std::vector<std::string>& names) {
	std::string out;
	for (size_t i = 0; i < names.size(); ++i) {
		if (i != 0) out += ", ";
		out += duckdb_quote_duckdb_ident(names[i]);
	}
	return out;
}

struct TableMap {
	std::string schema;
	std::string table;
	uint32_t column_count { 0 };
	std::string column_types;
	std::string metadata;
};

struct TableInfo {
	std::string schema;
	std::string table;
	std::vector<std::string> columns;
	std::vector<std::string> types;
	std::vector<size_t> primary_key;
};

class Applier {
public:
	Applier(DuckDBEngine& engine, const DuckDBReplicaSource& source,
	        const std::vector<DuckDBReplicaTable>& tables,
	        const DuckDBReplicaProbeResult& start,
	        const std::function<bool()>& stop_requested,
	        const std::function<void(uint64_t, uint64_t, int64_t, const DuckDBReplicaProbeResult&)>& progress)
		: engine_(engine), source_(source), tables_(tables), start_(start), applied_position_(start),
		  stop_requested_(stop_requested), progress_(progress) {}
	~Applier() {
		if (rpl_ != nullptr) mariadb_rpl_close(rpl_);
		if (mysql_ != nullptr) mysql_close(mysql_);
		if (thread_init_) mysql_thread_end();
	}

	DuckDBReplicaApplyResult run();

private:
	bool connect_source(std::string& err);
	bool load_metadata(std::string& err);
	TableInfo* info_for(const std::string& schema, const std::string& table);
	bool handle_table_map(const MARIADB_RPL_EVENT& event, std::string& err);
	bool handle_rows(const MARIADB_RPL_EVENT& event, std::string& err);
	bool build_statement(TableInfo& info, const TableMap& map,
	                     uint8_t row_kind, const MARIADB_RPL_ROW& before,
	                     const MARIADB_RPL_ROW* after, std::string& out, std::string& err);
	bool commit_transaction(std::string& err);
	bool flush(std::string& err);

	DuckDBEngine& engine_;
	const DuckDBReplicaSource& source_;
	const std::vector<DuckDBReplicaTable>& tables_;
	DuckDBReplicaProbeResult start_;
	DuckDBReplicaProbeResult applied_position_;
	const std::function<bool()>& stop_requested_;
	const std::function<void(uint64_t, uint64_t, int64_t, const DuckDBReplicaProbeResult&)>& progress_;

	std::string catalog_;
	duckdb_connection conn_ { nullptr };
	MYSQL* mysql_ { nullptr };
	MARIADB_RPL* rpl_ { nullptr };
	bool thread_init_ { false };

	std::map<uint64_t, TableMap> table_maps_;
	std::map<std::string, TableInfo> tables_info_;
	std::set<std::string> wanted_;
	std::set<std::string> ignored_;

	std::vector<std::string> batch_;
	size_t batch_bytes_ { 0 };
	std::string batch_file_;
	int64_t batch_pos_ { -1 };
	DuckDBReplicaGtidSet batch_gtids_;
	DuckDBReplicaGtidSet applied_gtids_;

	std::string pending_gtid_;
	std::vector<std::string> txn_sql_;
	std::string txn_file_;
	int64_t txn_pos_ { -1 };
	bool txn_open_ { false };

	uint64_t rows_ { 0 };
	uint64_t batches_ { 0 };
	std::chrono::steady_clock::time_point last_flush_ { std::chrono::steady_clock::now() };
	std::string current_file_;
	int64_t current_pos_ { -1 };
	int64_t last_event_ts_ { 0 };
};

std::string table_key(const std::string& schema, const std::string& table) {
	return schema + "." + table;
}

bool Applier::connect_source(std::string& err) {
	mysql_thread_init();
	thread_init_ = true;
	mysql_ = mysql_init(nullptr);
	if (mysql_ == nullptr) {
		err = "mysql_init failed for the replica dump";
		return false;
	}
	unsigned int connect_timeout = 10;
	unsigned int read_timeout = 5;
	mysql_options(mysql_, MYSQL_OPT_CONNECT_TIMEOUT, &connect_timeout);
	mysql_options(mysql_, MYSQL_OPT_READ_TIMEOUT, &read_timeout);
	if (mysql_real_connect(mysql_, source_.hostname.c_str(), source_.username.c_str(),
	                       source_.password.c_str(), nullptr,
	                       static_cast<unsigned int>(source_.port), nullptr, 0) == nullptr) {
		err = std::string("replica dump connection failed: ") + mysql_error(mysql_);
		return false;
	}
	const char* setup[] = {
		"SET NAMES utf8mb4",
		"SET @master_binlog_checksum = @@global.binlog_checksum",
		"SET @master_heartbeat_period = 1000000000",
	};
	for (const char* sql : setup) {
		if (mysql_query(mysql_, sql) != 0) {
			err = std::string("replica dump setup failed: ") + mysql_error(mysql_);
			return false;
		}
		std::unique_ptr<MYSQL_RES, decltype(&mysql_free_result)> ignored(mysql_store_result(mysql_), mysql_free_result);
	}
	rpl_ = mariadb_rpl_init(mysql_);
	if (rpl_ == nullptr) {
		err = "mariadb_rpl_init failed";
		return false;
	}
	rpl_->server_id = static_cast<uint32_t>(source_.server_id);
	rpl_->filename = strdup(start_.binlog_file.c_str());
	rpl_->filename_length = static_cast<uint32_t>(start_.binlog_file.size());
	rpl_->start_position = static_cast<unsigned long>(start_.binlog_pos);
	rpl_->flags = MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;
	if (mariadb_rpl_open(rpl_) != 0) {
		err = std::string("COM_BINLOG_DUMP failed at ") + start_.binlog_file + ":" +
			std::to_string(start_.binlog_pos) + ": " + mariadb_rpl_error(rpl_);
		return false;
	}
	current_file_ = start_.binlog_file;
	current_pos_ = start_.binlog_pos;
	return true;
}

bool Applier::load_metadata(std::string& err) {
	for (const auto& table : tables_) {
		if (table.active && table.source_id == source_.source_id) {
			wanted_.insert(table_key(table.schema_name, table.table_name));
		}
	}
	duckdb_result result;
	const std::string metadata_sql =
		"SELECT schema_name, table_name, primary_key FROM " +
		duckdb_replica_qualified_name(catalog_, "proxysql_replica", "tables") + " WHERE source_id = " + sql_literal(source_.source_id);
	if (duckdb_query(conn_, metadata_sql.c_str(), &result) != DuckDBSuccess) {
		const char* message = duckdb_result_error(&result);
		err = message != nullptr ? message : "cannot read proxysql_replica.tables";
		duckdb_destroy_result(&result);
		return false;
	}
	std::vector<std::pair<std::string, std::pair<std::string, std::string>>> metadata;
	const idx_t count = duckdb_row_count(&result);
	for (idx_t r = 0; r < count; ++r) {
		char* schema = duckdb_value_varchar(&result, 0, r);
		char* table = duckdb_value_varchar(&result, 1, r);
		char* pk = duckdb_value_varchar(&result, 2, r);
		metadata.emplace_back(schema != nullptr ? schema : "",
		                      std::make_pair(table != nullptr ? table : "", pk != nullptr ? pk : ""));
		if (schema) duckdb_free(schema);
		if (table) duckdb_free(table);
		if (pk) duckdb_free(pk);
	}
	duckdb_destroy_result(&result);

	for (const auto& item : metadata) {
		const std::string& schema = item.first;
		const std::string& table = item.second.first;
		const std::string& pk_names = item.second.second;
		bool wanted = false;
		for (const auto& wanted_table : tables_) {
			if (wanted_table.active && wanted_table.schema_name == schema && wanted_table.table_name == table) {
				wanted = true;
				break;
			}
		}
		if (!wanted) {
			ignored_.insert(table_key(schema, table));
			continue;
		}
		wanted_.insert(table_key(schema, table));
		TableInfo info;
		info.schema = schema;
		info.table = table;
		duckdb_result columns;
		const std::string sql =
			"SELECT column_name, data_type::VARCHAR FROM system.information_schema.columns "
			"WHERE table_catalog = " + sql_literal(catalog_) + " AND table_schema = " + sql_literal(schema) +
			" AND table_name = " + sql_literal(table) + " ORDER BY ordinal_position";
		if (duckdb_query(conn_, sql.c_str(), &columns) != DuckDBSuccess) {
			const char* message = duckdb_result_error(&columns);
			err = message != nullptr ? message : "cannot read DuckDB column metadata";
			duckdb_destroy_result(&columns);
			return false;
		}
		const idx_t n = duckdb_row_count(&columns);
		for (idx_t r = 0; r < n; ++r) {
			char* name = duckdb_value_varchar(&columns, 0, r);
			char* type = duckdb_value_varchar(&columns, 1, r);
			info.columns.push_back(name != nullptr ? name : "");
			std::string t = type != nullptr ? type : "";
			for (char& c : t) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
			info.types.push_back(t);
			if (name) duckdb_free(name);
			if (type) duckdb_free(type);
		}
		duckdb_destroy_result(&columns);
		if (info.columns.empty()) {
			err = "no DuckDB columns for " + schema + "." + table;
			return false;
		}
		size_t pos = 0;
		while (pos <= pk_names.size() && !pk_names.empty()) {
			const size_t comma = pk_names.find(',', pos);
			const std::string name = pk_names.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
			if (!name.empty()) {
				const auto it = std::find(info.columns.begin(), info.columns.end(), name);
				if (it == info.columns.end()) {
					err = "primary key column " + name + " is missing from " + schema + "." + table;
					return false;
				}
				info.primary_key.push_back(static_cast<size_t>(it - info.columns.begin()));
			}
			if (comma == std::string::npos) break;
			pos = comma + 1;
		}
		if (info.primary_key.empty()) {
			err = "no primary key recorded for " + schema + "." + table;
			return false;
		}
		tables_info_[table_key(schema, table)] = std::move(info);
	}
	for (const auto& key : wanted_) {
		if (tables_info_.count(key) == 0) {
			err = "no snapshot metadata for replicated table " + key +
				"; RESET DUCKDB REPLICA and snapshot again";
			return false;
		}
	}
	return true;
}

TableInfo* Applier::info_for(const std::string& schema, const std::string& table) {
	const std::string key = table_key(schema, table);
	const auto it = tables_info_.find(key);
	return it == tables_info_.end() ? nullptr : &it->second;
}

bool Applier::handle_table_map(const MARIADB_RPL_EVENT& event, std::string& err) {
	TableMap map;
	map.schema.assign(event.event.table_map.database.str != nullptr ? event.event.table_map.database.str : "",
	                  event.event.table_map.database.length);
	map.table.assign(event.event.table_map.table.str != nullptr ? event.event.table_map.table.str : "",
	                 event.event.table_map.table.length);
	map.column_count = event.event.table_map.column_count;
	if (event.event.table_map.column_types.str != nullptr) {
		map.column_types.assign(event.event.table_map.column_types.str,
		                        event.event.table_map.column_types.length);
	}
	if (event.event.table_map.metadata.str != nullptr) {
		map.metadata.assign(event.event.table_map.metadata.str, event.event.table_map.metadata.length);
	}
	if (map.column_types.size() < map.column_count) {
		err = "TABLE_MAP for " + table_key(map.schema, map.table) + " has a short column type list";
		return false;
	}
	const std::string key = table_key(map.schema, map.table);
	const bool wanted = wanted_.count(key) != 0;
	for (uint32_t i = 0; i < map.column_count; ++i) {
		const uint8_t type = static_cast<uint8_t>(map.column_types[i]);
		if (wanted && !supported_binlog_type(type)) {
			err = "table " + key + " has a column type the replica cannot decode (" +
				std::to_string(static_cast<int>(type)) + ")";
			return false;
		}
	}
	if (!wanted && ignored_.count(key) == 0) {
		// A table that was never opted in. Rows are ignored, but remember it
		// so an unsupported type in a filtered table does not stop the stream.
		ignored_.insert(key);
	}
	table_maps_[event.event.table_map.table_id] = std::move(map);
	return true;
}

bool Applier::handle_rows(const MARIADB_RPL_EVENT& event, std::string& err) {
	const auto map_it = table_maps_.find(event.event.rows.table_id);
	if (map_it == table_maps_.end()) {
		err = "row event references an unknown table id " + std::to_string(event.event.rows.table_id);
		return false;
	}
	TableMap& map = map_it->second;
	TableInfo* info = info_for(map.schema, map.table);
	if (info == nullptr) return true; // filtered out
	if (event.event.rows.compressed != 0) {
		err = "compressed row events are not supported for " + table_key(map.schema, map.table);
		return false;
	}
	const bool is_update = event.event_type == UPDATE_ROWS_EVENT ||
		event.event_type == UPDATE_ROWS_EVENT_V1 ||
		event.event_type == UPDATE_ROWS_COMPRESSED_EVENT ||
		event.event_type == UPDATE_ROWS_COMPRESSED_EVENT_V1;
	// The connector ignores the image bitmaps. Validate both UPDATE images
	// before it can read a partial image as a full row.
	if (event.event.rows.column_count != map.column_count ||
	    !duckdb_replica_full_row_images(event.event.rows.column_bitmap,
	                                    event.event.rows.column_update_bitmap,
	                                    map.column_count, is_update)) {
		err = "partial row image for " + table_key(map.schema, map.table) +
			"; binlog_row_image must stay FULL";
		return false;
	}

	MARIADB_RPL_EVENT synthetic {};
	synthetic.event_type = TABLE_MAP_EVENT;
	synthetic.event.table_map.table_id = event.event.rows.table_id;
	synthetic.event.table_map.column_count = map.column_count;
	synthetic.event.table_map.column_types.str = const_cast<char*>(map.column_types.data());
	synthetic.event.table_map.column_types.length = map.column_types.size();
	synthetic.event.table_map.metadata.str = const_cast<char*>(map.metadata.data());
	synthetic.event.table_map.metadata.length = map.metadata.size();

	MARIADB_RPL_ROW* rows = mariadb_rpl_extract_rows(rpl_, &synthetic, const_cast<MARIADB_RPL_EVENT*>(&event));
	if (rows == nullptr) {
		err = "cannot decode rows for " + table_key(map.schema, map.table) + ": " + mariadb_rpl_error(rpl_);
		return false;
	}


	const bool is_delete = event.event_type == DELETE_ROWS_EVENT ||
		event.event_type == DELETE_ROWS_EVENT_V1 ||
		event.event_type == DELETE_ROWS_COMPRESSED_EVENT ||
		event.event_type == DELETE_ROWS_COMPRESSED_EVENT_V1;
	const uint8_t kind = is_update ? UPDATE_ROWS : (is_delete ? DELETE_ROWS : WRITE_ROWS);

	MARIADB_RPL_ROW* row = rows;
	while (row != nullptr) {
		if (stop_requested_ && stop_requested_()) return true;
		std::string sql;
		if (is_update) {
			// UPDATE_ROWS carries a before image followed by an after image
			// for each row, in that order.
			if (row->next == nullptr) {
				err = "UPDATE row image for " + table_key(map.schema, map.table) + " has no after image";
				return false;
			}
			if (!build_statement(*info, map, kind, *row, row->next, sql, err)) return false;
			row = row->next->next;
		} else {
			if (!build_statement(*info, map, kind, *row, nullptr, sql, err)) return false;
			row = row->next;
		}
		if (!sql.empty()) txn_sql_.push_back(std::move(sql));
	}
	txn_open_ = true;
	return true;
}

bool Applier::build_statement(TableInfo& info, const TableMap& map,
                              uint8_t row_kind, const MARIADB_RPL_ROW& before,
                              const MARIADB_RPL_ROW* after, std::string& out, std::string& err) {
	if (before.column_count != info.columns.size() || before.column_count != map.column_count) {
		err = "column count changed for " + table_key(info.schema, info.table) +
			"; the snapshot is stale (DDL?) and the replica cannot apply this row";
		return false;
	}
	const MARIADB_RPL_ROW& values = row_kind == UPDATE_ROWS ? *after : before;

	std::vector<std::string> literals(info.columns.size());
	for (size_t i = 0; i < info.columns.size(); ++i) {
		const DuckDBReplicaValue value = decode_value(values.columns[i],
			static_cast<uint8_t>(map.column_types[i]), info.types[i]);
		literals[i] = duckdb_replica_value_literal(value, err);
		if (!err.empty()) {
			err = table_key(info.schema, info.table) + "." + info.columns[i] + ": " + err;
			return false;
		}
	}

	const std::string target = duckdb_replica_qualified_name(catalog_, info.schema, info.table);

	if (row_kind == WRITE_ROWS) {
		out = "INSERT INTO " + target + " (" + join_names(info.columns) + ") VALUES (";
		for (size_t i = 0; i < literals.size(); ++i) {
			if (i != 0) out += ", ";
			out += literals[i];
		}
		out += ")";
		return true;
	}

	std::vector<std::string> pk_literals;
	std::vector<std::string> pk_names;
	for (size_t index : info.primary_key) {
		if (index >= before.column_count) {
			err = "primary key index out of range for " + table_key(info.schema, info.table);
			return false;
		}
		const DuckDBReplicaValue value = decode_value(before.columns[index],
			static_cast<uint8_t>(map.column_types[index]), info.types[index]);
		pk_literals.push_back(duckdb_replica_value_literal(value, err));
		if (!err.empty()) {
			err = table_key(info.schema, info.table) + " primary key: " + err;
			return false;
		}
		pk_names.push_back(info.columns[index]);
	}

	if (row_kind == DELETE_ROWS) {
		out = "DELETE FROM " + target + " WHERE ";
		for (size_t i = 0; i < pk_names.size(); ++i) {
			if (i != 0) out += " AND ";
			out += duckdb_quote_duckdb_ident(pk_names[i]) + " = " + pk_literals[i];
		}
		return true;
	}

	out = "UPDATE " + target + " SET ";
	for (size_t i = 0; i < info.columns.size(); ++i) {
		if (i != 0) out += ", ";
		out += duckdb_quote_duckdb_ident(info.columns[i]) + " = " + literals[i];
	}
	out += " WHERE ";
	for (size_t i = 0; i < pk_names.size(); ++i) {
		if (i != 0) out += " AND ";
		out += duckdb_quote_duckdb_ident(pk_names[i]) + " = " + pk_literals[i];
	}
	return true;
}

bool Applier::commit_transaction(std::string& err) {
	if (!txn_open_ && txn_sql_.empty()) return true;
	if (!pending_gtid_.empty()) {
		const size_t colon = pending_gtid_.rfind(':');
		if (colon == std::string::npos) {
			err = "malformed GTID '" + pending_gtid_ + "'";
			return false;
		}
		DuckDBReplicaGtidSet one;
		if (!one.merge(pending_gtid_, err)) return false;
		batch_gtids_.merge(one);
		pending_gtid_.clear();
	}
	if (!txn_sql_.empty() && txn_pos_ < 0) {
		err = "a committed transaction has no binlog position; non-transactional row events are not supported";
		return false;
	}
	for (auto& sql : txn_sql_) {
		batch_bytes_ += sql.size();
		batch_.push_back(std::move(sql));
	}
	txn_sql_.clear();
	txn_open_ = false;
	if (txn_pos_ >= 0) {
		batch_file_ = txn_file_;
		batch_pos_ = txn_pos_;
	}
	return true;
}

bool Applier::flush(std::string& err) {
	if (batch_.empty() && batch_pos_ < 0 && batch_gtids_.empty()) return true;
	if (!exec_duckdb(conn_, "BEGIN TRANSACTION", err)) return false;
	for (const auto& sql : batch_) {
		if (!exec_duckdb(conn_, sql, err)) {
			std::string ignored;
			exec_duckdb(conn_, "ROLLBACK", ignored);
			return false;
		}
	}
	if (batch_pos_ >= 0) {
		// Persist the union, not just this batch: a restart must still know
		// about every GTID the snapshot and earlier batches already applied.
		DuckDBReplicaGtidSet combined = applied_gtids_;
		combined.merge(batch_gtids_);
		const std::string sql =
			"UPDATE " + duckdb_replica_qualified_name(catalog_, "proxysql_replica", "position") + " SET gtid_executed = " +
			sql_literal(combined.to_string()) + ", binlog_file = " + sql_literal(batch_file_) +
			", binlog_pos = " + std::to_string(batch_pos_) + ", updated_at = now() "
			"WHERE source_id = " + sql_literal(source_.source_id);
		if (!exec_duckdb(conn_, sql, err)) {
			std::string ignored;
			exec_duckdb(conn_, "ROLLBACK", ignored);
			return false;
		}
	}
	if (!exec_duckdb(conn_, "COMMIT", err)) {
		std::string ignored;
		exec_duckdb(conn_, "ROLLBACK", ignored);
		return false;
	}
	applied_gtids_.merge(batch_gtids_);
	if (batch_pos_ >= 0) {
		applied_position_.binlog_file = batch_file_;
		applied_position_.binlog_pos = batch_pos_;
	}
	applied_position_.gtid_executed = applied_gtids_.to_string();
	rows_ += batch_.size();
	batch_.clear();
	batch_bytes_ = 0;
	batch_gtids_ = DuckDBReplicaGtidSet {};
	batch_file_.clear();
	batch_pos_ = -1;
	++batches_;
	last_flush_ = std::chrono::steady_clock::now();
	int64_t lag = -1;
	if (last_event_ts_ > 0) {
		const int64_t now = static_cast<int64_t>(std::time(nullptr));
		lag = now > last_event_ts_ ? now - last_event_ts_ : 0;
	}
	if (progress_) progress_(rows_, batches_, lag, applied_position_);
	return true;
}

DuckDBReplicaApplyResult Applier::run() {
	DuckDBReplicaApplyResult result;
	std::string err;
	if (!connect_source(err)) {
		result.code = DuckDBReplicaApplyResult::Code::failed;
		result.error = err;
		return result;
	}
	if (!engine_.connect(&conn_, err)) {
		result.code = DuckDBReplicaApplyResult::Code::failed;
		result.error = err;
		return result;
	}
	struct Guard {
		DuckDBEngine& engine;
		duckdb_connection* conn;
		~Guard() { engine.disconnect(conn); }
	} guard { engine_, &conn_ };

	if (!duckdb_replica_current_catalog(conn_, catalog_, err) || !load_metadata(err)) {
		result.code = DuckDBReplicaApplyResult::Code::failed;
		result.error = err;
		return result;
	}

	applied_gtids_.merge(start_.gtid_executed, err);
	if (!err.empty()) {
		result.code = DuckDBReplicaApplyResult::Code::failed;
		result.error = err;
		return result;
	}

	while (true) {
		if (stop_requested_ && stop_requested_()) {
			if (!flush(err)) {
				result.code = DuckDBReplicaApplyResult::Code::failed;
				result.error = err;
				return result;
			}
			result.code = DuckDBReplicaApplyResult::Code::stopped;
			result.position = applied_position_;
			result.rows = rows_;
			result.batches = batches_;
			return result;
		}
		MARIADB_RPL_EVENT* event = mariadb_rpl_fetch(rpl_, nullptr);
		if (event == nullptr) {
			if (stop_requested_ && stop_requested_()) {
				flush(err);
				result.code = DuckDBReplicaApplyResult::Code::stopped;
				result.rows = rows_;
				result.batches = batches_;
				return result;
			}
			result.code = DuckDBReplicaApplyResult::Code::failed;
			const char* detail = mariadb_rpl_error(rpl_);
			if (detail == nullptr || *detail == '\0') detail = mysql_error(mysql_);
			result.error = std::string("binlog stream ended: ") + (detail != nullptr ? detail : "");
			return result;
		}
		const int64_t next_pos = static_cast<int64_t>(event->next_event_pos);
		const bool is_rotate = event->event_type == ROTATE_EVENT;
		if (event->timestamp > 0) last_event_ts_ = event->timestamp;
		const bool ok = [&] {
			switch (event->event_type) {
			case ROTATE_EVENT:
				current_file_.assign(event->event.rotate.filename.str != nullptr ? event->event.rotate.filename.str : "",
				                     event->event.rotate.filename.length);
				current_pos_ = static_cast<int64_t>(event->event.rotate.position);
				return true;
			case FORMAT_DESCRIPTION_EVENT:
			case HEARTBEAT_LOG_EVENT:
			case HEARTBEAT_LOG_EVENT_V2:
			case ANNOTATE_ROWS_EVENT:
			case INTVAR_EVENT:
			case RAND_EVENT:
			case USER_VAR_EVENT:
			case PREVIOUS_GTIDS_LOG_EVENT:
				return true;
			case TABLE_MAP_EVENT:
				return handle_table_map(*event, err);
			case WRITE_ROWS_EVENT:
			case WRITE_ROWS_EVENT_V1:
			case WRITE_ROWS_COMPRESSED_EVENT:
			case WRITE_ROWS_COMPRESSED_EVENT_V1:
			case UPDATE_ROWS_EVENT:
			case UPDATE_ROWS_EVENT_V1:
			case UPDATE_ROWS_COMPRESSED_EVENT:
			case UPDATE_ROWS_COMPRESSED_EVENT_V1:
			case DELETE_ROWS_EVENT:
			case DELETE_ROWS_EVENT_V1:
			case DELETE_ROWS_COMPRESSED_EVENT:
			case DELETE_ROWS_COMPRESSED_EVENT_V1:
				return handle_rows(*event, err);
			case GTID_LOG_EVENT: {
				const std::string uuid = uuid_text(event->event.gtid_log.source_id);
				pending_gtid_ = uuid + ":" + std::to_string(event->event.gtid_log.sequence_nr);
				txn_file_ = current_file_;
				txn_pos_ = static_cast<int64_t>(event->next_event_pos);
				return true;
			}
			case ANONYMOUS_GTID_LOG_EVENT:
				err = "source produced an anonymous GTID; GTID mode is required";
				return false;
			case XID_EVENT:
				if (!commit_transaction(err)) return false;
				txn_file_ = current_file_;
				txn_pos_ = static_cast<int64_t>(event->next_event_pos);
				batch_file_ = txn_file_;
				batch_pos_ = txn_pos_;
				return true;
			case QUERY_EVENT: {
				std::string statement(event->event.query.statement.str != nullptr ? event->event.query.statement.str : "",
				                      event->event.query.statement.length);
				size_t begin = statement.find_first_not_of(" \t\r\n");
				size_t end = statement.find_last_not_of(" \t\r\n");
				const std::string trimmed = begin == std::string::npos ? std::string()
					: statement.substr(begin, end - begin + 1);
				std::string upper;
				upper.reserve(trimmed.size());
				for (char c : trimmed) upper.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
				statement = trimmed;
				if (upper == "BEGIN") {
					txn_open_ = true;
					return true;
				}
				if (upper == "COMMIT") {
					if (!commit_transaction(err)) return false;
					txn_pos_ = static_cast<int64_t>(event->next_event_pos);
					batch_file_ = current_file_;
					batch_pos_ = txn_pos_;
					return true;
				}
				if (upper == "ROLLBACK") {
					txn_sql_.clear();
					txn_open_ = false;
					pending_gtid_.clear();
					return true;
				}
				err = "unsupported DDL in the binlog: " + statement.substr(0, 200) +
					"; STOP, resnapshot, and START again";
				return false;
			}
			case XA_PREPARE_LOG_EVENT:
				err = "XA transactions are not supported by the replica";
				return false;
			default:
				err = "unsupported binlog event type " + std::to_string(static_cast<int>(event->event_type));
				return false;
			}
		}();
		mariadb_free_rpl_event(event);
		if (!ok) {
			result.code = DuckDBReplicaApplyResult::Code::failed;
			result.error = err;
			return result;
		}
		// A ROTATE already installed the position inside the new file; the
		// generic next_event_pos belongs to the old file.
		if (!is_rotate) current_pos_ = next_pos;
		if (batch_.size() >= kBatchRows || batch_bytes_ >= kBatchBytes ||
		    (batch_pos_ >= 0 &&
		     std::chrono::duration_cast<std::chrono::milliseconds>(
			     std::chrono::steady_clock::now() - last_flush_).count() >= kFlushIntervalMs)) {
			if (!flush(err)) {
				result.code = DuckDBReplicaApplyResult::Code::failed;
				result.error = err;
				return result;
			}
		}
	}
}

} // namespace


DuckDBReplicaApplyResult duckdb_replica_apply_binlog(
	DuckDBEngine& engine,
	const DuckDBReplicaSource& source,
	const std::vector<DuckDBReplicaTable>& tables,
	const DuckDBReplicaProbeResult& start,
	const std::function<bool()>& stop_requested,
	const std::function<void(uint64_t, uint64_t, int64_t, const DuckDBReplicaProbeResult&)>& progress) {
	Applier applier(engine, source, tables, start, stop_requested, progress);
	return applier.run();
}
