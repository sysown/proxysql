#include "duckdb_replica.h"
#include "duckdb_replica_binlog.h"
#include "tap.h"
#include <mysql.h>
#include <mariadb_rpl.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>
#include <thread>

namespace {

std::map<std::string, std::string> good_variables() {
	return {
		{"log_bin", "ON"},
		{"binlog_format", "ROW"},
		{"gtid_mode", "ON"},
		{"enforce_gtid_consistency", "ON"},
		{"binlog_row_image", "FULL"},
		{"binlog_row_value_options", ""},
		{"binlog_transaction_compression", "OFF"},
		{"server_id", "1"},
	};
}

DuckDBReplicaConfig one_source() {
	DuckDBReplicaConfig config;
	DuckDBReplicaSource source;
	source.source_id = "oltp";
	source.hostname = "127.0.0.1";
	source.port = 3306;
	source.username = "repl";
	source.password = "secret";
	source.server_id = 100;
	source.enabled = true;
	config.sources.push_back(source);
	DuckDBReplicaTable table;
	table.source_id = "oltp";
	table.schema_name = "app";
	table.table_name = "events";
	table.active = true;
	config.tables.push_back(table);
	return config;
}

DuckDBReplicaStartRequest file_request() {
	DuckDBReplicaStartRequest request;
	request.database_path = "/var/lib/proxysql/replica.duckdb";
	request.read_only = false;
	return request;
}

} // namespace

int main() {
	plan(68);
	const uint8_t full = 0xff, padded = 0x7f, partial = 0x3f;
	ok(duckdb_replica_full_row_images(&full, &full, 7, true), "full UPDATE bitmaps are accepted");
	ok(duckdb_replica_full_row_images(&padded, &full, 7, true), "unused bitmap padding bits are ignored");
	ok(!duckdb_replica_full_row_images(&full, &partial, 7, true), "partial UPDATE after image is rejected before decoding");
	ok(!duckdb_replica_full_row_images(&partial, nullptr, 7, false), "partial INSERT or DELETE image is rejected");
	ok(!duckdb_replica_full_row_images(&full, nullptr, 7, true), "missing UPDATE after bitmap is rejected");
	ok(!duckdb_replica_full_row_images(nullptr, nullptr, 7, false), "missing row bitmap is rejected");
	for (unsigned year : {0u, 1u}) {
		MARIADB_RPL rpl {};
		MARIADB_RPL_EVENT map {};
		map.event_type = TABLE_MAP_EVENT;
		map.event.table_map.table_id = 1;
		map.event.table_map.column_count = 2;
		char types[] = {MYSQL_TYPE_YEAR, MYSQL_TYPE_LONG};
		map.event.table_map.column_types = {types, sizeof(types)};
		auto* event = static_cast<MARIADB_RPL_EVENT*>(std::calloc(1, sizeof(MARIADB_RPL_EVENT)));
		event->event_type = WRITE_ROWS_EVENT;
		event->event.rows.table_id = 1;
		unsigned char bytes[] = {0, static_cast<unsigned char>(year), 42, 0, 0, 0};
		event->event.rows.row_data = bytes;
		event->event.rows.row_data_size = sizeof(bytes);
		MARIADB_RPL_ROW* row = mariadb_rpl_extract_rows(&rpl, &map, event);
		ok(row && !row->next && row->columns[0].val.ull == (year ? 1901 : 0) && row->columns[1].val.ull == 42,
		   "YEAR encoded byte %u preserves zero or the 1900 offset", year);
		mariadb_free_rpl_event(event);
	}

	// Bytes copied from MySQL's big-endian TIMESTAMP2 format, followed by
	// an integer sentinel so an incorrect fractional byte count is visible.
	const unsigned micros[] = {0, 100000, 120000, 123000, 123400, 123450, 123456};
	for (unsigned precision = 0; precision <= 6; ++precision) {
		MARIADB_RPL rpl {};
		MARIADB_RPL_EVENT map {};
		map.event_type = TABLE_MAP_EVENT;
		map.event.table_map.table_id = 1;
		map.event.table_map.column_count = 2;
		char types[] = {MYSQL_TYPE_TIMESTAMP2, MYSQL_TYPE_LONG};
		char metadata[] = {static_cast<char>(precision)};
		map.event.table_map.column_types = {types, sizeof(types)};
		map.event.table_map.metadata = {metadata, sizeof(metadata)};
		auto* event = static_cast<MARIADB_RPL_EVENT*>(std::calloc(1, sizeof(MARIADB_RPL_EVENT)));
		event->event_type = WRITE_ROWS_EVENT;
		event->event.rows.table_id = 1;
		unsigned char bytes[32] = {0, 0x6a, 0xeb, 0xd5, 0x8b}; // 1793840523 seconds
		const unsigned n = (precision + 1) / 2;
		unsigned fraction = micros[precision] / (n == 1 ? 10000 : n == 2 ? 100 : 1);
		for (unsigned j = 0; j < n; ++j) bytes[5 + j] = fraction >> (8 * (n - j - 1));
		bytes[5 + n] = 42;
		event->event.rows.row_data = bytes;
		event->event.rows.row_data_size = 9 + n;
		MARIADB_RPL_ROW* row = mariadb_rpl_extract_rows(&rpl, &map, event);
		char expected[32];
		std::snprintf(expected, sizeof(expected), "1793840523.%06u", micros[precision]);
		ok(row && row->next == nullptr && row->columns[1].val.ull == 42 &&
		   std::string(row->columns[0].val.str.str, row->columns[0].val.str.length) == expected,
		   "TIMESTAMP2(%u) decodes big-endian seconds, scaled microseconds and next column", precision);
		mariadb_free_rpl_event(event);
	}
	for (unsigned precision = 0; precision <= 6; ++precision) {
		MARIADB_RPL rpl {};
		MARIADB_RPL_EVENT map {};
		map.event_type = TABLE_MAP_EVENT;
		map.event.table_map.table_id = 1;
		map.event.table_map.column_count = 2;
		char types[] = {static_cast<char>(MYSQL_TYPE_TIME2), MYSQL_TYPE_LONG};
		char metadata[] = {static_cast<char>(precision)};
		map.event.table_map.column_types = {types, sizeof(types)};
		map.event.table_map.metadata = {metadata, sizeof(metadata)};
		auto* event = static_cast<MARIADB_RPL_EVENT*>(std::calloc(1, sizeof(MARIADB_RPL_EVENT)));
		event->event_type = WRITE_ROWS_EVENT;
		event->event.rows.table_id = 1;
		const unsigned n = (precision + 1) / 2;
		const unsigned micros[] = {0,100000,120000,123000,123400,123450,123456};
		const unsigned fraction = micros[precision] / (n == 1 ? 10000 : n == 2 ? 100 : 1);
		const unsigned integral = 0x800000 - ((12 << 12) | (34 << 6) | 56) - (fraction ? 1 : 0);
		unsigned char bytes[11] = {};
		for (unsigned j = 0; j < 3; ++j) bytes[1+j] = integral >> (8*(2-j));
		const unsigned encoded = fraction ? (1u << (8*n)) - fraction : 0;
		for (unsigned j = 0; j < n; ++j) bytes[4+j] = encoded >> (8*(n-j-1));
		bytes[4+n] = 42;
		event->event.rows.row_data = bytes;
		event->event.rows.row_data_size = 8+n;
		MARIADB_RPL_ROW* row = mariadb_rpl_extract_rows(&rpl,&map,event);
		ok(row && !row->next && row->columns[1].val.ull == 42 && row->columns[0].val.tm.neg &&
		   row->columns[0].val.tm.hour == 12 && row->columns[0].val.tm.minute == 34 &&
		   row->columns[0].val.tm.second == 56 && row->columns[0].val.tm.second_part == micros[precision],
		   "negative TIME2(%u) preserves integral and fractional magnitude and next column", precision);
		mariadb_free_rpl_event(event);
	}

	{
		MARIADB_RPL rpl {};
		MARIADB_RPL_EVENT map {};
		map.event_type = TABLE_MAP_EVENT;
		map.event.table_map.table_id = 1;
		map.event.table_map.column_count = 2;
		char types[] = {static_cast<char>(MYSQL_TYPE_NEWDECIMAL), MYSQL_TYPE_LONG};
		char metadata[] = {18, 4};
		map.event.table_map.column_types = {types, sizeof(types)};
		map.event.table_map.metadata = {metadata, sizeof(metadata)};
		auto* event = static_cast<MARIADB_RPL_EVENT*>(std::calloc(1, sizeof(MARIADB_RPL_EVENT)));
		event->event_type = WRITE_ROWS_EVENT;
		event->event.rows.table_id = 1;
		unsigned char bytes[] = {0, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xfc, 0x24, 0xe6, 0x70, 42, 0, 0, 0};
		event->event.rows.row_data = bytes;
		event->event.rows.row_data_size = sizeof(bytes);
		MARIADB_RPL_ROW* row = mariadb_rpl_extract_rows(&rpl, &map, event);
		ok(row && !row->next && row->columns[1].val.ull == 42 &&
		   std::string(row->columns[0].val.str.str, row->columns[0].val.str.length) == "-987.6543",
		   "negative DECIMAL(18,4) sign-extends its three-byte group without corrupting memory");
		mariadb_free_rpl_event(event);
	}

	DuckDBReplicaMappedColumn column;
	ok(duckdb_replica_map_column("id", "int", "int(10) unsigned", "", "PRI", false, column).empty() &&
	   column.duckdb_type == "UINTEGER" && column.primary_key && column.not_null,
	   "unsigned int maps to UINTEGER and keeps the primary key");
	ok(duckdb_replica_map_column("n", "bigint", "bigint(20) unsigned", "", "", true, column).empty() &&
	   column.duckdb_type == "UBIGINT",
	   "unsigned bigint maps to UBIGINT");
	ok(duckdb_replica_map_column("amount", "decimal", "decimal(10,2)", "", "", true, column).empty() &&
	   column.duckdb_type == "DECIMAL(10,2)" && column.width == 10 && column.scale == 2,
	   "decimal(10,2) keeps its precision");
	ok(duckdb_replica_map_column("wide", "decimal", "decimal(65,0)", "", "", true, column).find("1..38") != std::string::npos,
	   "a MySQL decimal wider than DuckDB is rejected");
	ok(duckdb_replica_map_column("name", "varchar", "varchar(64)", "utf8mb4", "", true, column).empty() &&
	   column.kind == DuckDBReplicaTypeKind::varchar,
	   "utf8mb4 varchar is accepted");
	ok(duckdb_replica_map_column("name", "varchar", "varchar(64)", "latin1", "", true, column).find("latin1") != std::string::npos,
	   "latin1 is rejected");
	ok(duckdb_replica_map_column("payload", "blob", "blob", "binary", "", true, column).empty() &&
	   column.kind == DuckDBReplicaTypeKind::blob,
	   "blob maps to BLOB");
	ok(duckdb_replica_map_column("doc", "json", "json", "utf8mb4", "", true, column).find("JSON") != std::string::npos,
	   "json is rejected because its row image is not decoded");
	ok(duckdb_replica_map_column("ts", "datetime", "datetime", "", "", false, column).empty() &&
	   column.duckdb_type == "TIMESTAMP" && column.not_null,
	   "datetime maps to TIMESTAMP and honors NOT NULL");
	ok(duckdb_replica_map_column("span", "time", "time", "", "", true, column).empty() &&
	   column.duckdb_type == "VARCHAR",
	   "MySQL TIME is stored as VARCHAR because it can exceed a time of day");
	ok(duckdb_replica_create_table_sql("app", "events", {column}).find("PRIMARY KEY") == std::string::npos &&
	   duckdb_replica_create_table_sql("app", "a\"b", {column}).find("\"a\"\"b\"") != std::string::npos,
	   "DuckDB identifiers are quoted and internal quotes are doubled");

	{
		std::string value_err;
		DuckDBReplicaValue value;
		value.kind = DuckDBReplicaValue::Kind::null;
		ok(duckdb_replica_value_literal(value, value_err) == "NULL" && value_err.empty(),
		   "a binlog NULL becomes an SQL NULL literal");
		value_err.clear();
		value.kind = DuckDBReplicaValue::Kind::text;
		value.text = "O'Reilly";
		ok(duckdb_replica_value_literal(value, value_err) == "'O''Reilly'",
		   "text values escape single quotes");
		value_err.clear();
		value.kind = DuckDBReplicaValue::Kind::binary;
		value.text = std::string("\x01\xff", 2);
		ok(duckdb_replica_value_literal(value, value_err) == "from_hex('01ff')",
		   "blob values use from_hex");
		value_err.clear();
		value.kind = DuckDBReplicaValue::Kind::decimal_text;
		value.text = "12.50";
		ok(duckdb_replica_value_literal(value, value_err) == "12.50" && value_err.empty(),
		   "decimal text is emitted as a numeric literal");
		value_err.clear();
		value.text = "12; DROP TABLE t";
		ok(duckdb_replica_value_literal(value, value_err).empty() && !value_err.empty(),
		   "non-numeric decimal text is refused instead of injected");
		value_err.clear();
		value.kind = DuckDBReplicaValue::Kind::text;
		value.text = std::string("a\0b", 3);
		ok(duckdb_replica_value_literal(value, value_err).empty() && !value_err.empty(),
		   "a VARCHAR containing NUL is refused");
	}

	{
		std::string gtid_err;
		DuckDBReplicaGtidSet set;
		set.add("11111111-1111-1111-1111-111111111111", 1);
		set.add("11111111-1111-1111-1111-111111111111", 2);
		set.add("11111111-1111-1111-1111-111111111111", 4);
		ok(set.to_string() == "11111111-1111-1111-1111-111111111111:1-2,11111111-1111-1111-1111-111111111111:4",
		   "GTID sequences compress into intervals");
		DuckDBReplicaGtidSet parsed;
		ok(duckdb_replica_parse_gtid_set("11111111-1111-1111-1111-111111111111:1-4,22222222-2222-2222-2222-222222222222:7",
		                                 parsed, gtid_err) &&
		   parsed.to_string() == "11111111-1111-1111-1111-111111111111:1-4,22222222-2222-2222-2222-222222222222:7",
		   "a GTID set round-trips through parse and render");
		gtid_err.clear();
		DuckDBReplicaGtidSet bad;
		ok(!duckdb_replica_parse_gtid_set("not-a-gtid", bad, gtid_err) && !gtid_err.empty(),
		   "a malformed GTID set is refused");
	}

	ok(duckdb_replica_check_source_settings(good_variables(), 100).empty(),
	   "a ROW/GTID/FULL source passes the prerequisite check");

	auto vars = good_variables();
	vars["binlog_format"] = "STATEMENT";
	ok(duckdb_replica_check_source_settings(vars, 100).find("ROW") != std::string::npos,
	   "statement-based logging is rejected");

	vars = good_variables();
	vars["gtid_mode"] = "OFF";
	ok(duckdb_replica_check_source_settings(vars, 100).find("gtid_mode") != std::string::npos,
	   "gtid_mode OFF is rejected");

	vars = good_variables();
	vars["binlog_row_image"] = "MINIMAL";
	ok(duckdb_replica_check_source_settings(vars, 100).find("FULL") != std::string::npos,
	   "binlog_row_image MINIMAL is rejected");

	vars = good_variables();
	vars["binlog_transaction_compression"] = "ON";
	ok(duckdb_replica_check_source_settings(vars, 100).find("compression") != std::string::npos,
	   "binlog transaction compression is rejected");

	vars = good_variables();
	vars.erase("binlog_transaction_compression");
	ok(duckdb_replica_check_source_settings(vars, 100).empty(),
	   "a source that does not advertise compression is accepted");

	ok(duckdb_replica_check_source_settings(good_variables(), 1).find("collides") != std::string::npos,
	   "a replica server_id equal to the source server_id is rejected");

	DuckDBReplicaConfig two = one_source();
	two.sources.push_back(two.sources.front());
	two.sources.back().source_id = "other";
	two.sources.back().server_id = 101;
	ok(duckdb_replica_validate_config(two).find("only one") != std::string::npos,
	   "two enabled sources are rejected");

	DuckDBReplicaConfig unknown = one_source();
	unknown.tables.front().source_id = "missing";
	ok(duckdb_replica_validate_config(unknown).find("unknown source") != std::string::npos,
	   "a table for an unknown source is rejected");

	for (const char* schema : {"proxysql_replica", "ProxySQL_Replica", "PROXYSQL_REPLICA"}) {
		DuckDBReplicaConfig reserved = one_source();
		reserved.tables.front().schema_name = schema;
		reserved.tables.front().table_name = "tables";
		ok(duckdb_replica_validate_config(reserved).find("reserved") != std::string::npos,
		   "reserved metadata schema %s is rejected regardless of identifier case", schema);
	}

	DuckDBReplica replica;
	std::string err;
	DuckDBReplicaStartRequest memory = file_request();
	memory.database_path = ":memory:";
	ok(!replica.start(memory, err) && err.find(":memory:") != std::string::npos,
	   "an in-memory database cannot start a replica");

	err.clear();
	DuckDBReplicaStartRequest readonly = file_request();
	readonly.read_only = true;
	ok(!replica.start(readonly, err) && err.find("read-write") != std::string::npos,
	   "a read-only engine cannot start a replica");

	err.clear();
	ok(!replica.start(file_request(), err) && err.find("no enabled") != std::string::npos,
	   "start without an installed source fails");

	err.clear();
	ok(replica.install(one_source(), err), "a single enabled source installs");
	err.clear();
	ok(!replica.start(file_request(), err) && err.find("not open") != std::string::npos,
	   "start without an engine or a snapshot hook fails");

	std::atomic<bool> release { false };
	DuckDBReplicaStartRequest request = file_request();
	request.probe = [&](const DuckDBReplicaSource&, DuckDBReplicaProbeResult& probed) {
		probed.gtid_executed = "11111111-1111-1111-1111-111111111111:1-4";
		probed.binlog_file = "binlog.000003";
		probed.binlog_pos = 154;
		while (!release.load()) std::this_thread::sleep_for(std::chrono::milliseconds(10));
		return std::string();
	};
	request.snapshot = [](const DuckDBReplicaSource&, const std::vector<DuckDBReplicaTable>&,
	                      const DuckDBReplicaProbeResult& probed) {
		DuckDBReplicaLoadResult out;
		out.code = DuckDBReplicaLoadResult::Code::ok;
		out.position = probed;
		out.rows = 3;
		return out;
	};
	err.clear();
	ok(replica.start(request, err), "start with an injected probe succeeds");
	ok(replica.wait_until([](const DuckDBReplicaStatus& st) { return st.state == "checking"; }, 2000),
	   "the replica thread reports checking before the probe returns");
	bool reset_callback = false;
	ok(!replica.reset(err, [&] { reset_callback = true; return std::string(); }) && !reset_callback,
	   "RESET refuses running replicas before attempting storage changes");
	release.store(true);
	ok(replica.wait_until([](const DuckDBReplicaStatus& st) { return st.state == "snapshotted"; }, 2000),
	   "a successful snapshot ends in snapshotted, not applying");
	const DuckDBReplicaStatus checked = replica.status();
	ok(checked.binlog_file == "binlog.000003" && checked.binlog_pos == 154 &&
	   checked.rows_applied == 3 &&
	   checked.detail.find("snapshot complete") != std::string::npos &&
	   checked.last_error.empty() && checked.detail.find("secret") == std::string::npos,
	   "snapshotted status keeps the coordinates and does not claim apply has started");

	replica.stop();
	ok(replica.status().state == "stopped" && !replica.status().running,
	   "stop joins the thread and leaves the replica stopped");

	const DuckDBReplicaStatus before_reset = replica.status();
	err.clear();
	ok(!replica.reset(err, [] { return std::string("storage dependency"); }) && err == "storage dependency" &&
	   replica.status().binlog_pos == before_reset.binlog_pos && replica.status().binlog_file == before_reset.binlog_file &&
	   replica.status().gtid_executed == before_reset.gtid_executed,
	   "failed storage reset preserves the published durable checkpoint");
	reset_callback = false;
	ok(replica.reset(err, [&] { reset_callback = true; return std::string(); }) && reset_callback &&
	   replica.status().binlog_pos == -1 && replica.status().gtid_executed.empty(),
	   "successful storage reset clears lifecycle state after the callback commits");
	return exit_status();
}
