#include "duckdb_replica.h"
#include "duckdb_replica_catalog.h"

#include "duckdb_engine.h"

#include <mysql.h>

#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <utility>

namespace {

struct MysqlCloser {
	void operator()(MYSQL* mysql) const {
		if (mysql != nullptr) mysql_close(mysql);
	}
};

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
		err = message != nullptr ? message : "DuckDB snapshot statement failed";
		duckdb_destroy_result(&result);
		return false;
	}
	duckdb_destroy_result(&result);
	return true;
}

bool query_mysql(MYSQL* mysql, const std::string& sql, std::string& err) {
	if (mysql_real_query(mysql, sql.c_str(), static_cast<unsigned long>(sql.size())) != 0) {
		err = mysql_error(mysql);
		return false;
	}
	return true;
}

DuckDBReplicaLoadResult failed(const std::string& error) {
	DuckDBReplicaLoadResult out;
	out.code = DuckDBReplicaLoadResult::Code::failed;
	out.error = error;
	return out;
}

DuckDBReplicaLoadResult stopped() {
	DuckDBReplicaLoadResult out;
	out.code = DuckDBReplicaLoadResult::Code::stopped;
	return out;
}

int days_from_civil(int year, unsigned month, unsigned day) {
	year -= month <= 2;
	const int era = (year >= 0 ? year : year - 399) / 400;
	const unsigned yoe = static_cast<unsigned>(year - era * 400);
	const unsigned doy = (153 * (month + (month > 2 ? -3 : 9)) + 2) / 5 + day - 1;
	const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	return era * 146097 + static_cast<int>(doe) - 719468;
}

bool parse_i64(const char* text, unsigned long length, int64_t& out) {
	if (text == nullptr) return false;
	std::string s(text, length);
	char* end = nullptr;
	errno = 0;
	const long long value = std::strtoll(s.c_str(), &end, 10);
	if (end == s.c_str() || end == nullptr || *end != '\0' || errno == ERANGE) return false;
	out = value;
	return true;
}

bool parse_u64(const char* text, unsigned long length, uint64_t& out) {
	if (text == nullptr || length == 0 || text[0] == '-') return false;
	std::string s(text, length);
	char* end = nullptr;
	errno = 0;
	const unsigned long long value = std::strtoull(s.c_str(), &end, 10);
	if (end == s.c_str() || end == nullptr || *end != '\0' || errno == ERANGE) return false;
	out = value;
	return true;
}

bool in_range(int64_t value, int64_t lo, int64_t hi) {
	return value >= lo && value <= hi;
}

bool append_integer(duckdb_appender appender, const DuckDBReplicaMappedColumn& column,
                    const char* text, unsigned long length, std::string& err) {
	switch (column.kind) {
	case DuckDBReplicaTypeKind::int8: {
		int64_t value = 0;
		if (!parse_i64(text, length, value) || !in_range(value, -128, 127)) break;
		if (duckdb_append_int8(appender, static_cast<int8_t>(value)) == DuckDBSuccess) return true;
		break;
	}
	case DuckDBReplicaTypeKind::uint8: {
		uint64_t value = 0;
		if (!parse_u64(text, length, value) || value > 255) break;
		if (duckdb_append_uint8(appender, static_cast<uint8_t>(value)) == DuckDBSuccess) return true;
		break;
	}
	case DuckDBReplicaTypeKind::int16: {
		int64_t value = 0;
		if (!parse_i64(text, length, value) || !in_range(value, -32768, 32767)) break;
		if (duckdb_append_int16(appender, static_cast<int16_t>(value)) == DuckDBSuccess) return true;
		break;
	}
	case DuckDBReplicaTypeKind::uint16: {
		uint64_t value = 0;
		if (!parse_u64(text, length, value) || value > 65535) break;
		if (duckdb_append_uint16(appender, static_cast<uint16_t>(value)) == DuckDBSuccess) return true;
		break;
	}
	case DuckDBReplicaTypeKind::int32: {
		int64_t value = 0;
		if (!parse_i64(text, length, value) ||
		    !in_range(value, std::numeric_limits<int32_t>::min(), std::numeric_limits<int32_t>::max())) break;
		if (duckdb_append_int32(appender, static_cast<int32_t>(value)) == DuckDBSuccess) return true;
		break;
	}
	case DuckDBReplicaTypeKind::uint32: {
		uint64_t value = 0;
		if (!parse_u64(text, length, value) || value > 4294967295ULL) break;
		if (duckdb_append_uint32(appender, static_cast<uint32_t>(value)) == DuckDBSuccess) return true;
		break;
	}
	case DuckDBReplicaTypeKind::int64: {
		int64_t value = 0;
		if (!parse_i64(text, length, value)) break;
		if (duckdb_append_int64(appender, value) == DuckDBSuccess) return true;
		break;
	}
	case DuckDBReplicaTypeKind::uint64: {
		uint64_t value = 0;
		if (!parse_u64(text, length, value)) break;
		if (duckdb_append_uint64(appender, value) == DuckDBSuccess) return true;
		break;
	}
	default:
		break;
	}
	const char* message = duckdb_appender_error(appender);
	err = message != nullptr && *message != '\0' ? message : "integer value does not fit the DuckDB column";
	return false;
}

bool parse_decimal(const char* text, unsigned long length, uint8_t width, uint8_t scale,
                   duckdb_decimal& out, std::string& err) {
	if (text == nullptr) {
		err = "empty decimal";
		return false;
	}
	std::string s(text, length);
	size_t i = 0;
	bool neg = false;
	if (i < s.size() && (s[i] == '-' || s[i] == '+')) {
		neg = s[i] == '-';
		++i;
	}
	unsigned __int128 value = 0;
	int seen_frac = -1;
	int digits = 0;
	bool any = false;
	for (; i < s.size(); ++i) {
		if (s[i] == '.') {
			if (seen_frac >= 0) {
				err = "invalid decimal";
				return false;
			}
			seen_frac = 0;
			continue;
		}
		if (s[i] < '0' || s[i] > '9') {
			err = "invalid decimal";
			return false;
		}
		any = true;
		if (seen_frac >= 0) {
			if (seen_frac == scale) continue;
			++seen_frac;
		}
		if (++digits > width) {
			err = "decimal exceeds DECIMAL(" + std::to_string(width) + "," + std::to_string(scale) + ")";
			return false;
		}
		value = value * 10 + static_cast<unsigned>(s[i] - '0');
	}
	if (!any) {
		err = "invalid decimal";
		return false;
	}
	const int frac = seen_frac < 0 ? 0 : seen_frac;
	for (int pad = frac; pad < scale; ++pad) value *= 10;
	if (neg) value = -value;
	out.width = width;
	out.scale = scale;
	out.value.lower = static_cast<uint64_t>(value);
	out.value.upper = static_cast<int64_t>(static_cast<uint64_t>(value >> 64));
	return true;
}

bool parse_date(const char* text, unsigned long length, int& year, unsigned& month, unsigned& day, size_t& used) {
	if (text == nullptr || length < 10) return false;
	if (text[4] != '-' || text[7] != '-') return false;
	year = 0;
	month = 0;
	day = 0;
	for (int i = 0; i < 4; ++i) {
		if (text[i] < '0' || text[i] > '9') return false;
		year = year * 10 + (text[i] - '0');
	}
	for (int i = 5; i < 7; ++i) {
		if (text[i] < '0' || text[i] > '9') return false;
		month = month * 10 + static_cast<unsigned>(text[i] - '0');
	}
	for (int i = 8; i < 10; ++i) {
		if (text[i] < '0' || text[i] > '9') return false;
		day = day * 10 + static_cast<unsigned>(text[i] - '0');
	}
	used = 10;
	return month >= 1 && month <= 12 && day >= 1 && day <= 31 && year >= 1;
}

bool parse_time_micros(const char* text, unsigned long length, int64_t& micros) {
	if (length < 8 || text[2] != ':' || text[5] != ':') return false;
	unsigned hour = 0;
	unsigned min = 0;
	unsigned sec = 0;
	for (int i = 0; i < 2; ++i) {
		if (text[i] < '0' || text[i] > '9') return false;
		hour = hour * 10 + static_cast<unsigned>(text[i] - '0');
	}
	for (int i = 3; i < 5; ++i) {
		if (text[i] < '0' || text[i] > '9') return false;
		min = min * 10 + static_cast<unsigned>(text[i] - '0');
	}
	for (int i = 6; i < 8; ++i) {
		if (text[i] < '0' || text[i] > '9') return false;
		sec = sec * 10 + static_cast<unsigned>(text[i] - '0');
	}
	if (hour > 23 || min > 59 || sec > 59) return false;
	int64_t frac = 0;
	if (length > 8) {
		if (text[8] != '.') return false;
		int digits = 0;
		for (unsigned long i = 9; i < length && digits < 6; ++i, ++digits) {
			if (text[i] < '0' || text[i] > '9') return false;
			frac = frac * 10 + (text[i] - '0');
		}
		while (digits < 6) {
			frac *= 10;
			++digits;
		}
	}
	micros = (static_cast<int64_t>(hour) * 3600 + static_cast<int64_t>(min) * 60 + sec) * 1000000 + frac;
	return true;
}

bool append_value(duckdb_appender appender, const DuckDBReplicaMappedColumn& column,
                  const char* text, unsigned long length, std::string& err) {
	if (text == nullptr) {
		if (duckdb_append_null(appender) == DuckDBSuccess) return true;
		err = "failed to append NULL";
		return false;
	}
	switch (column.kind) {
	case DuckDBReplicaTypeKind::int8:
	case DuckDBReplicaTypeKind::int16:
	case DuckDBReplicaTypeKind::int32:
	case DuckDBReplicaTypeKind::int64:
	case DuckDBReplicaTypeKind::uint8:
	case DuckDBReplicaTypeKind::uint16:
	case DuckDBReplicaTypeKind::uint32:
	case DuckDBReplicaTypeKind::uint64:
		return append_integer(appender, column, text, length, err);
	case DuckDBReplicaTypeKind::float32:
	case DuckDBReplicaTypeKind::float64: {
		std::string s(text, length);
		char* end = nullptr;
		const double value = std::strtod(s.c_str(), &end);
		if (end == s.c_str() || end == nullptr || *end != '\0') {
			err = "invalid floating-point value";
			return false;
		}
		const duckdb_state rc = column.kind == DuckDBReplicaTypeKind::float32
			? duckdb_append_float(appender, static_cast<float>(value))
			: duckdb_append_double(appender, value);
		if (rc == DuckDBSuccess) return true;
		break;
	}
	case DuckDBReplicaTypeKind::decimal: {
		duckdb_decimal decimal {};
		if (!parse_decimal(text, length, column.width, column.scale, decimal, err)) return false;
		duckdb_value value = duckdb_create_decimal(decimal);
		const duckdb_state rc = duckdb_append_value(appender, value);
		duckdb_destroy_value(&value);
		if (rc == DuckDBSuccess) return true;
		break;
	}
	case DuckDBReplicaTypeKind::date: {
		int year = 0;
		unsigned month = 0;
		unsigned day = 0;
		size_t used = 0;
		if (!parse_date(text, length, year, month, day, used) || used != length) {
			err = "invalid DATE value";
			return false;
		}
		duckdb_date date;
		date.days = days_from_civil(year, month, day);
		if (duckdb_append_date(appender, date) == DuckDBSuccess) return true;
		break;
	}
	case DuckDBReplicaTypeKind::timestamp: {
		int year = 0;
		unsigned month = 0;
		unsigned day = 0;
		size_t used = 0;
		if (!parse_date(text, length, year, month, day, used)) {
			err = "invalid TIMESTAMP value";
			return false;
		}
		int64_t tod = 0;
		if (used < length) {
			if (text[used] != ' ' && text[used] != 'T') {
				err = "invalid TIMESTAMP value";
				return false;
			}
			if (!parse_time_micros(text + used + 1, length - used - 1, tod)) {
				err = "invalid TIMESTAMP value";
				return false;
			}
		}
		duckdb_timestamp ts;
		ts.micros = static_cast<int64_t>(days_from_civil(year, month, day)) * 86400000000LL + tod;
		if (duckdb_append_timestamp(appender, ts) == DuckDBSuccess) return true;
		break;
	}
	case DuckDBReplicaTypeKind::varchar:
		if (duckdb_append_varchar_length(appender, text, length) == DuckDBSuccess) return true;
		break;
	case DuckDBReplicaTypeKind::blob:
		if (duckdb_append_blob(appender, text, length) == DuckDBSuccess) return true;
		break;
	}
	if (err.empty()) {
		const char* message = duckdb_appender_error(appender);
		err = message != nullptr && *message != '\0' ? message : "failed to append snapshot value";
	}
	return false;
}

std::string select_expr(const std::string& data_type, const std::string& name) {
	const std::string quoted = duckdb_quote_mysql_ident(name);
	std::string type = data_type;
	for (char& c : type) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	if (type == "bit") return "CAST(" + quoted + " AS UNSIGNED)";
	return quoted;
}

bool load_columns(MYSQL* mysql, const DuckDBReplicaTable& table,
                  std::vector<DuckDBReplicaMappedColumn>& columns,
                  std::vector<std::string>& data_types, std::string& err) {
	const std::string sql =
		"SELECT COLUMN_NAME, DATA_TYPE, COLUMN_TYPE, IS_NULLABLE, "
		"IFNULL(CHARACTER_SET_NAME, ''), COLUMN_KEY "
		"FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = " + sql_literal(table.schema_name) +
		" AND TABLE_NAME = " + sql_literal(table.table_name) + " ORDER BY ORDINAL_POSITION";
	if (!query_mysql(mysql, sql, err)) return false;
	std::unique_ptr<MYSQL_RES, decltype(&mysql_free_result)> result(mysql_store_result(mysql), mysql_free_result);
	if (!result) {
		err = mysql_error(mysql);
		return false;
	}
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result.get())) != nullptr) {
		DuckDBReplicaMappedColumn column;
		const std::string mapped = duckdb_replica_map_column(
			row[0] != nullptr ? row[0] : "",
			row[1] != nullptr ? row[1] : "",
			row[2] != nullptr ? row[2] : "",
			row[4] != nullptr ? row[4] : "",
			row[5] != nullptr ? row[5] : "",
			row[3] != nullptr && std::string(row[3]) == "YES",
			column);
		if (!mapped.empty()) {
			err = table.schema_name + "." + table.table_name + ": " + mapped;
			return false;
		}
		data_types.push_back(row[1] != nullptr ? row[1] : "");
		columns.push_back(std::move(column));
	}
	if (columns.empty()) {
		err = "table " + table.schema_name + "." + table.table_name + " has no columns or does not exist";
		return false;
	}
	bool has_pk = false;
	for (const auto& column : columns) has_pk = has_pk || column.primary_key;
	if (!has_pk) {
		err = "table " + table.schema_name + "." + table.table_name + " has no primary key";
		return false;
	}
	return true;
}

bool read_locked_position(MYSQL* mysql, DuckDBReplicaProbeResult& out, std::string& err) {
	const char* sql = "SHOW BINARY LOG STATUS";
	if (mysql_query(mysql, sql) != 0) {
		sql = "SHOW MASTER STATUS";
		if (mysql_query(mysql, sql) != 0) {
			err = std::string("cannot read binary log status under the snapshot lock: ") + mysql_error(mysql);
			return false;
		}
	}
	std::unique_ptr<MYSQL_RES, decltype(&mysql_free_result)> result(mysql_store_result(mysql), mysql_free_result);
	if (!result) {
		err = std::string("binary log status returned no result: ") + mysql_error(mysql);
		return false;
	}
	MYSQL_FIELD* fields = mysql_fetch_fields(result.get());
	const unsigned int nfields = mysql_num_fields(result.get());
	MYSQL_ROW row = mysql_fetch_row(result.get());
	if (row == nullptr) {
		err = "binary log status returned no row under the snapshot lock";
		return false;
	}
	for (unsigned int i = 0; i < nfields; ++i) {
		if (fields[i].name == nullptr || row[i] == nullptr) continue;
		std::string name = fields[i].name;
		for (char& c : name) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
		if (name == "file") out.binlog_file = row[i];
		else if (name == "position") out.binlog_pos = std::strtoll(row[i], nullptr, 10);
		else if (name == "executed_gtid_set") out.gtid_executed = row[i];
	}
	if (out.binlog_file.empty() || out.binlog_pos < 0) {
		err = "snapshot lock did not report a binary log file and position";
		return false;
	}
	return true;
}

} // namespace

bool duckdb_replica_current_catalog(duckdb_connection connection,
                                    std::string& catalog, std::string& error) {
	catalog.clear();
	duckdb_result result;
	if (duckdb_query(connection, "SELECT current_database()", &result) != DuckDBSuccess) {
		const char* message = duckdb_result_error(&result);
		error = message ? message : "cannot read replica catalog";
		duckdb_destroy_result(&result);
		return false;
	}
	char* value = duckdb_value_varchar(&result, 0, 0);
	if (value) { catalog = value; duckdb_free(value); }
	duckdb_destroy_result(&result);
	if (catalog.empty()) { error = "replica connection has no current catalog"; return false; }
	return true;
}

std::string duckdb_replica_drop_snapshot(DuckDBEngine& engine) {
	std::string err;
	duckdb_connection conn = nullptr;
	if (!engine.connect(&conn, err)) return err;
	struct Guard {
		DuckDBEngine& engine;
		duckdb_connection* conn;
		~Guard() { engine.disconnect(conn); }
	} guard { engine, &conn };
	std::string catalog;
	if (!duckdb_replica_current_catalog(conn, catalog, err)) return err;
	const std::string manifest = duckdb_replica_qualified_name(catalog, "proxysql_replica", "tables");
	const std::string position = duckdb_replica_qualified_name(catalog, "proxysql_replica", "position");
	if (!exec_duckdb(conn, "BEGIN TRANSACTION", err)) return err;
	auto fail = [&](const std::string& message) {
		std::string ignored;
		exec_duckdb(conn, "ROLLBACK", ignored);
		return "RESET DUCKDB REPLICA: " + message;
	};
	duckdb_result exists;
	const std::string probe =
		"SELECT COUNT(*) FROM system.information_schema.tables WHERE table_catalog = " +
		sql_literal(catalog) + " AND table_schema = 'proxysql_replica' AND table_name = 'tables'";
	if (duckdb_query(conn, probe.c_str(), &exists) != DuckDBSuccess) {
		const char* message = duckdb_result_error(&exists);
		err = message ? message : "cannot inspect replica manifest";
		duckdb_destroy_result(&exists);
		return fail(err);
	}
	const bool has_manifest = duckdb_value_int64(&exists, 0, 0) != 0;
	duckdb_destroy_result(&exists);
	std::vector<std::pair<std::string, std::string>> owned;
	if (has_manifest) {
		duckdb_result tables;
		const std::string sql = "SELECT schema_name,table_name FROM " + manifest + " ORDER BY schema_name,table_name";
		if (duckdb_query(conn, sql.c_str(), &tables) != DuckDBSuccess) {
			const char* message = duckdb_result_error(&tables);
			err = message ? message : "cannot read replica manifest";
			duckdb_destroy_result(&tables);
			return fail(err);
		}
		for (idx_t row = 0; row < duckdb_row_count(&tables); ++row) {
			char* schema = duckdb_value_varchar(&tables, 0, row);
			char* table = duckdb_value_varchar(&tables, 1, row);
			owned.emplace_back(schema ? schema : "", table ? table : "");
			if (schema) duckdb_free(schema);
			if (table) duckdb_free(table);
		}
		duckdb_destroy_result(&tables);
	}
	for (const auto& table : owned) {
		const std::string target = duckdb_replica_qualified_name(catalog, table.first, table.second);
		if (!exec_duckdb(conn, "DROP TABLE IF EXISTS " + target, err)) return fail(err);
	}
	if (!exec_duckdb(conn, "DROP TABLE IF EXISTS " + position, err) ||
	    !exec_duckdb(conn, "DROP TABLE IF EXISTS " + manifest, err) ||
	    !exec_duckdb(conn, "COMMIT", err)) return fail(err);
	return "";
}

extern "C" void duckdb_replica_interrupt_connection(void* conn) {
	if (conn != nullptr) duckdb_interrupt(static_cast<duckdb_connection>(conn));
}

DuckDBReplicaLoadResult duckdb_replica_load_snapshot(
	DuckDBEngine& engine,
	const DuckDBReplicaSource& source,
	const std::vector<DuckDBReplicaTable>& tables,
	const DuckDBReplicaProbeResult& probed,
	const std::function<bool()>& stop_requested,
	const std::function<void(void*)>& watch_connection,
	const std::function<void(const std::string&, uint64_t)>& progress) {
	for (const auto& table : tables) {
		if (duckdb_replica_is_reserved_schema(table.schema_name)) {
			return failed("schema proxysql_replica is reserved for replica metadata");
		}
	}

	std::string err;
	duckdb_connection conn = nullptr;
	if (!engine.connect(&conn, err)) return failed(err);
	if (watch_connection) watch_connection(conn);
	struct ConnGuard {
		DuckDBEngine& engine;
		duckdb_connection* conn;
		const std::function<void(void*)>& watch;
		~ConnGuard() {
			if (watch) watch(nullptr);
			engine.disconnect(conn);
		}
	} guard { engine, &conn, watch_connection };

	std::string catalog;
	if (!duckdb_replica_current_catalog(conn, catalog, err)) return failed(err);
	const std::string position_table = duckdb_replica_qualified_name(catalog, "proxysql_replica", "position");
	const std::string tables_table = duckdb_replica_qualified_name(catalog, "proxysql_replica", "tables");
	{
		duckdb_result result;
		const std::string catalog_sql =
			"SELECT COUNT(*)::VARCHAR FROM system.information_schema.tables "
			"WHERE table_catalog = " + sql_literal(catalog) +
			" AND table_schema = 'proxysql_replica' AND table_name = 'position'";
		if (duckdb_query(conn, catalog_sql.c_str(), &result) != DuckDBSuccess) {
			const char* message = duckdb_result_error(&result);
			err = message != nullptr ? message : "failed reading snapshot position catalog";
			duckdb_destroy_result(&result);
			return failed(err);
		}
		char* raw = duckdb_value_varchar(&result, 0, 0);
		const bool exists = raw != nullptr && std::string(raw) != "0";
		if (raw != nullptr) duckdb_free(raw);
		duckdb_destroy_result(&result);
		if (exists) {
			duckdb_result pos;
			const std::string sql =
				"SELECT gtid_executed, binlog_file, binlog_pos::VARCHAR, server_uuid "
				"FROM " + position_table + " WHERE source_id = " + sql_literal(source.source_id);
			if (duckdb_query(conn, sql.c_str(), &pos) != DuckDBSuccess) {
				const char* message = duckdb_result_error(&pos);
				err = message != nullptr ? message : "failed reading proxysql_replica.position";
				duckdb_destroy_result(&pos);
				return failed(err);
			}
			if (duckdb_row_count(&pos) > 0) {
				DuckDBReplicaLoadResult out;
				out.code = DuckDBReplicaLoadResult::Code::already_loaded;
				char* gtid = duckdb_value_varchar(&pos, 0, 0);
				char* file = duckdb_value_varchar(&pos, 1, 0);
				char* position = duckdb_value_varchar(&pos, 2, 0);
				char* uuid = duckdb_value_varchar(&pos, 3, 0);
				out.position.gtid_executed = gtid != nullptr ? gtid : "";
				out.position.binlog_file = file != nullptr ? file : "";
				out.position.binlog_pos = position != nullptr ? std::strtoll(position, nullptr, 10) : -1;
				out.position.server_uuid = uuid != nullptr ? uuid : "";
				if (gtid) duckdb_free(gtid);
				if (file) duckdb_free(file);
				if (position) duckdb_free(position);
				if (uuid) duckdb_free(uuid);
				duckdb_destroy_result(&pos);
				if (!probed.server_uuid.empty() && !out.position.server_uuid.empty() &&
				    probed.server_uuid != out.position.server_uuid) {
					return failed("source server_uuid changed since the snapshot; RESET DUCKDB REPLICA and snapshot again");
				}
				return out;
			}
			duckdb_destroy_result(&pos);
		}
	}

	if (stop_requested && stop_requested()) return stopped();

	mysql_thread_init();
	struct ThreadEnd {
		~ThreadEnd() { mysql_thread_end(); }
	} thread_end;
	std::unique_ptr<MYSQL, MysqlCloser> mysql(mysql_init(nullptr));
	if (!mysql) return failed("mysql_init failed");
	unsigned int connect_timeout = 10;
	unsigned int read_timeout = 30;
	mysql_options(mysql.get(), MYSQL_OPT_CONNECT_TIMEOUT, &connect_timeout);
	mysql_options(mysql.get(), MYSQL_OPT_READ_TIMEOUT, &read_timeout);
	if (mysql_real_connect(mysql.get(), source.hostname.c_str(), source.username.c_str(),
	                       source.password.c_str(), nullptr,
	                       static_cast<unsigned int>(source.port), nullptr, 0) == nullptr) {
		return failed(std::string("snapshot connection failed: ") + mysql_error(mysql.get()));
	}
	const char* setup[] = {
		"SET NAMES utf8mb4",
		"SET SESSION time_zone = '+00:00'",
		"SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ",
		"FLUSH TABLES WITH READ LOCK",
		"START TRANSACTION WITH CONSISTENT SNAPSHOT",
	};
	for (const char* sql : setup) {
		if (!query_mysql(mysql.get(), sql, err)) {
			std::string prefix = std::string(sql).find("FLUSH TABLES") == 0
				? "snapshot lock failed (RELOAD required): "
				: "snapshot setup failed: ";
			return failed(prefix + err);
		}
		std::unique_ptr<MYSQL_RES, decltype(&mysql_free_result)> ignored(mysql_store_result(mysql.get()), mysql_free_result);
	}

	DuckDBReplicaProbeResult locked = probed;
	if (!read_locked_position(mysql.get(), locked, err)) return failed(err);
	if (!query_mysql(mysql.get(), "UNLOCK TABLES", err)) {
		return failed(std::string("UNLOCK TABLES failed: ") + err);
	}
	std::unique_ptr<MYSQL_RES, decltype(&mysql_free_result)> unlocked(mysql_store_result(mysql.get()), mysql_free_result);

	if (!exec_duckdb(conn, "BEGIN TRANSACTION", err)) return failed(err);
	bool committed = false;
	auto rollback = [&] {
		if (committed) return;
		std::string ignored;
		exec_duckdb(conn, "ROLLBACK", ignored);
	};

	if (!exec_duckdb(conn, "CREATE SCHEMA IF NOT EXISTS " + duckdb_quote_duckdb_ident(catalog) + ".proxysql_replica", err) ||
	    !exec_duckdb(conn,
	                 "CREATE TABLE IF NOT EXISTS " + position_table + " ("
	                 "source_id VARCHAR PRIMARY KEY, server_uuid VARCHAR, gtid_executed VARCHAR, "
	                 "binlog_file VARCHAR, binlog_pos BIGINT, updated_at TIMESTAMP)",
	                 err) ||
	    !exec_duckdb(conn,
	                 "CREATE TABLE IF NOT EXISTS " + tables_table + " ("
	                 "source_id VARCHAR, schema_name VARCHAR, table_name VARCHAR, "
	                 "primary_key VARCHAR, PRIMARY KEY (source_id, schema_name, table_name))",
	                 err) ||
	    !exec_duckdb(conn, "DELETE FROM " + tables_table + " WHERE source_id = " +
	                           sql_literal(source.source_id),
	                 err)) {
		rollback();
		return failed(err);
	}

	uint64_t rows = 0;
	for (const auto& table : tables) {
		if (!table.active || table.source_id != source.source_id) continue;
		if (stop_requested && stop_requested()) {
			rollback();
			return stopped();
		}
		const std::string qualified = table.schema_name + "." + table.table_name;
		if (progress) progress(qualified, rows);
		std::vector<DuckDBReplicaMappedColumn> columns;
		std::vector<std::string> data_types;
		if (!load_columns(mysql.get(), table, columns, data_types, err)) {
			rollback();
			return failed(err);
		}
		std::string pk_names;
		for (const auto& column : columns) {
			if (!column.primary_key) continue;
			if (column.name.find(',') != std::string::npos) {
				rollback();
				return failed("primary key column " + column.name +
					" contains a comma; the replica cannot record it");
			}
			if (!pk_names.empty()) pk_names += ",";
			pk_names += column.name;
		}
		if (!exec_duckdb(conn, "CREATE SCHEMA IF NOT EXISTS " + duckdb_quote_duckdb_ident(catalog) + "." + duckdb_quote_duckdb_ident(table.schema_name), err) ||
		    !exec_duckdb(conn, "DROP TABLE IF EXISTS " + duckdb_replica_qualified_name(catalog, table.schema_name, table.table_name),
		                err) ||
		    !exec_duckdb(conn, duckdb_replica_create_table_sql(table.schema_name, table.table_name, columns, catalog), err) ||
		    !exec_duckdb(conn,
		                 "INSERT INTO " + tables_table + " (source_id, schema_name, table_name, primary_key) VALUES (" +
		                     sql_literal(source.source_id) + ", " + sql_literal(table.schema_name) + ", " +
		                     sql_literal(table.table_name) + ", " + sql_literal(pk_names) + ")",
		                 err)) {
			rollback();
			return failed(err);
		}

		std::string select = "SELECT ";
		for (size_t i = 0; i < columns.size(); ++i) {
			if (i != 0) select += ", ";
			select += select_expr(data_types[i], columns[i].name);
		}
		select += " FROM " + duckdb_quote_mysql_ident(table.schema_name) + "." +
			duckdb_quote_mysql_ident(table.table_name);
		if (!query_mysql(mysql.get(), select, err)) {
			rollback();
			return failed(qualified + ": " + err);
		}
		MYSQL_RES* raw_rows = mysql_use_result(mysql.get());
		if (raw_rows == nullptr) {
			err = mysql_error(mysql.get());
			rollback();
			return failed(qualified + ": " + err);
		}
		duckdb_appender appender = nullptr;
		if (duckdb_appender_create_ext(conn, catalog.c_str(), table.schema_name.c_str(), table.table_name.c_str(), &appender) != DuckDBSuccess) {
			mysql_free_result(raw_rows);
			err = "failed to create DuckDB appender for " + qualified;
			rollback();
			return failed(err);
		}
		MYSQL_ROW row;
		bool row_failed = false;
		while ((row = mysql_fetch_row(raw_rows)) != nullptr) {
			if (stop_requested && stop_requested()) {
				row_failed = true;
				err = "stopped";
				break;
			}
			unsigned long* lengths = mysql_fetch_lengths(raw_rows);
			for (size_t i = 0; i < columns.size(); ++i) {
				const unsigned long length = lengths != nullptr ? lengths[i] : 0;
				if (!append_value(appender, columns[i], row[i], length, err)) {
					err = qualified + "." + columns[i].name + ": " + err;
					row_failed = true;
					break;
				}
			}
			if (row_failed) break;
			if (duckdb_appender_end_row(appender) != DuckDBSuccess) {
				const char* message = duckdb_appender_error(appender);
				err = qualified + ": " + (message != nullptr ? message : "appender end_row failed");
				row_failed = true;
				break;
			}
			++rows;
			if (progress && rows % 1000 == 0) progress(qualified, rows);
		}
		if (!row_failed && mysql_errno(mysql.get()) != 0) {
			err = qualified + ": " + mysql_error(mysql.get());
			row_failed = true;
		}
		const bool want_stop = err == "stopped";
		if (!row_failed && duckdb_appender_close(appender) != DuckDBSuccess) {
			const char* message = duckdb_appender_error(appender);
			err = qualified + ": " + (message != nullptr ? message : "appender close failed");
			row_failed = true;
		}
		duckdb_appender_destroy(&appender);
		mysql_free_result(raw_rows);
		if (row_failed) {
			rollback();
			return want_stop ? stopped() : failed(err);
		}
	}

	if (stop_requested && stop_requested()) {
		rollback();
		return stopped();
	}
	const std::string insert =
		"INSERT INTO " + position_table + " (source_id, server_uuid, gtid_executed, binlog_file, binlog_pos, updated_at) VALUES (" +
		sql_literal(source.source_id) + ", " + sql_literal(locked.server_uuid.empty() ? probed.server_uuid : locked.server_uuid) +
		", " + sql_literal(locked.gtid_executed) + ", " + sql_literal(locked.binlog_file) + ", " +
		std::to_string(locked.binlog_pos) + ", now())";
	if (!exec_duckdb(conn, insert, err) || !exec_duckdb(conn, "COMMIT", err)) {
		rollback();
		return failed(err);
	}
	committed = true;
	if (!query_mysql(mysql.get(), "COMMIT", err)) {
		// The DuckDB snapshot is already durable. A failure to end the source
		// read transaction does not roll it back; the connection close will.
		err.clear();
	}

	DuckDBReplicaLoadResult out;
	out.code = DuckDBReplicaLoadResult::Code::ok;
	out.position = locked;
	out.position.server_uuid = probed.server_uuid;
	out.rows = rows;
	return out;
}
