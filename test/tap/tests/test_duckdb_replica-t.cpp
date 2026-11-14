// Live MySQL 8.4 binlog coverage. Run in duckdb-e2e-g1 against a dedicated
// source: FLUSH BINARY LOGS and DDL deliberately exercise stream boundaries.
#include "mysql.h"
#include "tap.h"
#include "command_line.h"

#include <chrono>
#include <cstdlib>
#include <functional>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>

namespace {
using Rows = std::vector<std::vector<std::string>>;

std::string quote(const std::string& value) {
	std::string out = "'";
	for (char c : value) { out += c; if (c == '\'') out += c; }
	return out + "'";
}

MYSQL* connect(const char* host, int port, const char* user, const char* password) {
	MYSQL* c = mysql_init(nullptr);
	unsigned int timeout = 2;
	mysql_options(c, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	if (!mysql_real_connect(c, host, user, password, nullptr, port, nullptr, 0)) {
		mysql_close(c);
		return nullptr;
	}
	return c;
}

bool execute(MYSQL* c, const std::string& sql) {
	if (mysql_query(c, sql.c_str())) {
		// Do not log statements: source configuration includes credentials.
		diag("query failed (%u): %s", mysql_errno(c), mysql_error(c));
		return false;
	}
	if (MYSQL_RES* r = mysql_store_result(c)) mysql_free_result(r);
	return true;
}

bool query(MYSQL* c, const std::string& sql, Rows& rows) {
	rows.clear();
	if (mysql_query(c, sql.c_str())) return false;
	MYSQL_RES* r = mysql_store_result(c);
	if (!r) return false;
	while (MYSQL_ROW row = mysql_fetch_row(r)) {
		const unsigned long* lengths = mysql_fetch_lengths(r);
		std::vector<std::string> fields;
		for (unsigned int i = 0; i < mysql_num_fields(r); ++i)
			fields.push_back(row[i] ? std::string(row[i], lengths[i]) : "<NULL>");
		rows.push_back(std::move(fields));
	}
	const bool success = mysql_errno(c) == 0;
	mysql_free_result(r);
	return success;
}

std::string cell(MYSQL* c, const std::string& sql) {
	Rows rows;
	return query(c, sql, rows) && !rows.empty() && !rows[0].empty() ? rows[0][0] : "";
}

bool wait_for(const std::function<bool()>& pred, int seconds = 20) {
	const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
	do {
		if (pred()) return true;
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	} while (std::chrono::steady_clock::now() < end);
	return false;
}

// Preserve SQL NULLs and quoting in configuration across the process restart.
bool backup(MYSQL* c, const std::string& table, const std::string& columns,
            const std::string& where, std::vector<std::string>& out) {
	std::string expr;
	size_t begin = 0;
	do {
		const size_t end = columns.find(',', begin);
		if (!expr.empty()) expr += "||','||";
		expr += "quote(" + columns.substr(begin, end - begin) + ")";
		if (end == std::string::npos) break;
		begin = end + 1;
	} while (true);
	Rows rows;
	if (!query(c, "SELECT " + expr + " FROM " + table + where, rows)) return false;
	out.push_back("DELETE FROM " + table + where);
	for (const auto& row : rows)
		out.push_back("INSERT INTO " + table + " (" + columns + ") VALUES(" + row[0] + ")");
	return true;
}

struct Fixture {
	CommandLine& cl;
	MYSQL* admin = nullptr;
	MYSQL* source = nullptr;
	MYSQL* duck = nullptr;
	std::vector<std::string> restore_main;
	std::vector<std::string> restore_disk;
	std::string data_dir;
	std::string schema = "duckdb_replica_e2e_" + std::to_string(getpid());
	bool changed = false;
	int duck_port = 6031;

	explicit Fixture(CommandLine& c) : cl(c) {
		std::string pattern = (std::filesystem::temp_directory_path() / "proxysql-replica-live-XXXXXX").string();
		char* created = mkdtemp(pattern.data());
		if (!created) BAIL_OUT("cannot create private replica directory");
		data_dir = created;
		if (const char* port = std::getenv("TAP_DUCKDB_PORT")) duck_port = std::atoi(port);
	}
	bool reconnect() {
		if (admin) { mysql_close(admin); admin = nullptr; }
		if (duck) { mysql_close(duck); duck = nullptr; }
		return wait_for([&] {
			if (!admin) admin = connect(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
			if (!duck) duck = connect(cl.host, duck_port, cl.username, cl.password);
			return admin && duck;
		});
	}
	bool restart() {
		// RESTART closes its caller without an OK packet. Wait for the old
		// DuckDB session to close before accepting connections to the new one.
		mysql_query(admin, "PROXYSQL RESTART");
		if (!wait_for([&] { return mysql_ping(duck) != 0; })) return false;
		return reconnect();
	}
	bool state(const char* expected) {
		const bool result = wait_for([&] {
			return cell(admin, "SELECT state FROM stats_duckdb_replica") == expected;
		});
		if (!result) diag("replica state=%s error=%s", cell(admin, "SELECT state FROM stats_duckdb_replica").c_str(),
		                  cell(admin, "SELECT last_error FROM stats_duckdb_replica").c_str());
		return result;
	}
	bool matches() {
		const std::string sql = "SELECT id,amount,note,created,ts,HEX(payload),u FROM " + schema + ".events ORDER BY id";
		Rows expected;
		if (!query(source, sql, expected)) return false;
		auto normalize = [](Rows& rows) {
			for (auto& row : rows) for (size_t i : {size_t(3), size_t(4)}) {
				if (row[i].find('.') != std::string::npos) {
					while (row[i].back() == '0') row[i].pop_back();
					if (row[i].back() == '.') row[i].pop_back();
				}
			}
		};
		normalize(expected);
		const bool matched = wait_for([&] {
			Rows actual;
			const std::string duck_sql = "SELECT id,amount,note,created,ts,HEX(payload),u FROM " +
				schema + "." + schema + ".events ORDER BY id";
			if (!query(duck, duck_sql, actual)) return false;
			normalize(actual);
			return actual == expected;
		});
		if (!matched) diag("row mismatch: state=%s error=%s", cell(admin, "SELECT state FROM stats_duckdb_replica").c_str(),
		                   cell(admin, "SELECT last_error FROM stats_duckdb_replica").c_str());
		return matched;
	}
	Rows position() {
		Rows rows;
		query(duck, "SELECT binlog_file,binlog_pos,gtid_executed FROM proxysql_replica.position", rows);
		return rows;
	}
	void cleanup() {
		if (changed && admin) {
			execute(admin, "STOP DUCKDB REPLICA");
			if (duck) {
				execute(duck, "DROP TABLE IF EXISTS " + schema + "." + schema + ".reset_blocker");
				execute(duck, "DROP TABLE IF EXISTS " + schema + ".main.rollback_keep_" + std::to_string(getpid()));
			}
			execute(admin, "RESET DUCKDB REPLICA");
			auto restore_rows = [&](const std::vector<std::string>& statements) {
				bool restored = execute(admin, "BEGIN");
				for (const auto& sql : statements) restored = execute(admin, sql) && restored;
				return execute(admin, restored ? "COMMIT" : "ROLLBACK") && restored;
			};
			bool restored = restore_rows(restore_disk) && restart();
			// Restart restores Disk into Main. Replay the original Main slice
			// afterwards to preserve any unsaved edits present before this test.
			if (restored) restored = execute(admin, "STOP DUCKDB REPLICA") &&
			                         restore_rows(restore_main) && execute(admin, "LOAD DUCKDB REPLICA TO RUNTIME");
			ok(restored, "restore persistent configuration, unsaved Main edits and original DuckDB engine");
		}
		if (source) { execute(source, "DROP DATABASE IF EXISTS " + schema); mysql_close(source); }
		if (duck) mysql_close(duck);
		if (admin) mysql_close(admin);
	}
	~Fixture() {
		try {
			cleanup();
			std::error_code error;
			std::filesystem::remove_all(data_dir, error);
		} catch (...) {
			ok(false, "live replica cleanup raised an exception; artifacts retained");
		}
	}

};

bool check(bool success, const char* description) {
	ok(success, "%s", description);
	return success;
}

bool run(Fixture& f) {
	f.source = connect(f.cl.mysql_host, f.cl.mysql_port, f.cl.mysql_username, f.cl.mysql_password);
	if (!check(f.source && f.reconnect(), "connect to source, Admin and DuckDB listeners")) return false;
	if (!check(cell(f.admin, "SELECT state FROM stats_duckdb_replica") == "stopped",
	        "replica is initially stopped")) return false;
	for (const std::string schema : {"main", "disk"}) {
		auto& restore = schema == "main" ? f.restore_main : f.restore_disk;
		if (!backup(f.admin, schema + ".global_variables", "variable_name,variable_value",
		            " WHERE variable_name LIKE 'duckdb-%'", restore) ||
		    !backup(f.admin, schema + ".duckdb_replica_sources", "source_id,hostname,port,username,password,server_id,enabled", "", restore) ||
		    !backup(f.admin, schema + ".duckdb_replica_tables", "source_id,schema_name,table_name,active", "", restore)) return false;
	}
	f.changed = true;
	const std::string db = f.data_dir + "/" + f.schema + ".duckdb";
	if (!check(execute(f.admin, "UPDATE global_variables SET variable_value=" + quote(db) +
	                         " WHERE variable_name='duckdb-database_path'") &&
	        execute(f.admin, "SAVE DUCKDB VARIABLES TO DISK") && f.restart(),
	        "restart opens a durable DuckDB database")) return false;
	if (!check(execute(f.source, "CREATE DATABASE " + f.schema + " CHARACTER SET utf8mb4") &&
	        execute(f.source, "CREATE TABLE " + f.schema + ".events (id INT PRIMARY KEY, amount DECIMAL(18,4),"
	                          "note VARCHAR(100), created DATETIME(6), ts TIMESTAMP(6) NULL, payload BLOB, u INT UNSIGNED) ENGINE=InnoDB") &&
	        execute(f.source, "CREATE TABLE " + f.schema + ".time_keys (k TIME(3) PRIMARY KEY,v INT) ENGINE=InnoDB") &&
	        execute(f.source, "INSERT INTO " + f.schema + ".time_keys VALUES ('12:34:56.123',1),('12:34:56',2),('-12:34:56.123',3),('123:45:56.789',4)") &&
	        execute(f.source, "SET SESSION binlog_rows_query_log_events=ON") &&
	        execute(f.source, "CREATE TABLE " + f.schema + ".guard (id INT,part INT,PRIMARY KEY(id,part)) ENGINE=InnoDB") &&
	        execute(f.source, "INSERT INTO " + f.schema + ".guard VALUES(1,2)") &&
	        execute(f.source, "CREATE TABLE " + f.schema + ".ignored (id INT PRIMARY KEY,doc JSON) ENGINE=InnoDB") &&
	        execute(f.source, "SET time_zone='+00:00'") &&
	        execute(f.source, "INSERT INTO " + f.schema + ".events VALUES"
	                          "(1,-12.3400,'snapshot','2026-11-05 12:34:56.123456','2026-11-05 12:34:56.654321',X'00FF',4294967295),"
	                          "(2,0,NULL,NULL,NULL,NULL,0)"), "create typed source snapshot fixture")) return false;
	if (!check(execute(f.admin, "DELETE FROM duckdb_replica_sources") &&
	        execute(f.admin, "DELETE FROM duckdb_replica_tables") &&
	        execute(f.admin, "INSERT INTO duckdb_replica_sources VALUES('e2e'," + quote(f.cl.mysql_host) + "," +
	                         std::to_string(f.cl.mysql_port) + "," + quote(f.cl.mysql_username) + "," + quote(f.cl.mysql_password) + ",424242,1)") &&
	        execute(f.admin, "INSERT INTO duckdb_replica_tables VALUES('e2e'," + quote(f.schema) + ",'events',1)") &&
	        execute(f.admin, "INSERT INTO duckdb_replica_tables VALUES('e2e'," + quote(f.schema) + ",'guard',1)") &&
	        execute(f.admin, "INSERT INTO duckdb_replica_tables VALUES('e2e'," + quote(f.schema) + ",'time_keys',1)") &&
	        execute(f.admin, "SAVE DUCKDB REPLICA TO DISK") && execute(f.admin, "START DUCKDB REPLICA"),
	        "configure and start the replica")) return false;
	if (!check(f.state("applying") && f.matches(), "consistent snapshot matches source typed rows")) return false;

	auto time_matches = [&] {
		Rows expected;
		if (!query(f.source, "SELECT TIME_FORMAT(k,'%H:%i:%s.%f'),v FROM " + f.schema + ".time_keys ORDER BY v", expected)) return false;
		Rows actual;
		const bool matched = wait_for([&] {
			return query(f.duck, "SELECT k,v FROM " + f.schema + "." + f.schema + ".time_keys ORDER BY v", actual) && actual == expected;
		});
		if (!matched) {
			diag("TIME replay state=%s error=%s", cell(f.admin,"SELECT state FROM stats_duckdb_replica").c_str(), cell(f.admin,"SELECT last_error FROM stats_duckdb_replica").c_str());
			for (const auto& row : actual) diag("target TIME=%s value=%s", row[0].c_str(),row[1].c_str());
		}
		return matched;
	};
	if (!check(time_matches(), "snapshot canonicalizes fractional, whole, negative and long-hour TIME primary keys")) return false;
	if (!check(execute(f.source, "UPDATE " + f.schema + ".time_keys SET v=v+10") && time_matches(),
	           "annotated row events update snapshot TIME primary keys without losing matches")) return false;
	if (!check(execute(f.source, "DELETE FROM " + f.schema + ".time_keys") && time_matches(),
	           "annotated DELETE events remove snapshot TIME primary keys")) return false;

	// Reactivating a table omitted from an active source's durable checkpoint must
	// be rejected rather than silently skipping its accumulated changes.
	if (!check(execute(f.source, "UPDATE " + f.schema + ".events SET note='before active-set change' WHERE id=1") && f.matches(),
	           "advance an active sibling table before changing the active set")) return false;
	if (!check(execute(f.admin, "STOP DUCKDB REPLICA") &&
	           execute(f.admin, "UPDATE duckdb_replica_tables SET active=0 WHERE source_id='e2e' AND table_name='time_keys'") &&
	           execute(f.admin, "SAVE DUCKDB REPLICA TO DISK") &&
	           execute(f.admin, "START DUCKDB REPLICA") && f.state("error") &&
	           cell(f.admin, "SELECT last_error FROM stats_duckdb_replica").find("RESET") != std::string::npos,
	           "deactivating a snapshotted table is refused before replay can skip it")) return false;
	if (!check(execute(f.admin, "STOP DUCKDB REPLICA") &&
	           execute(f.admin, "UPDATE duckdb_replica_tables SET active=1 WHERE source_id='e2e' AND table_name='time_keys'") &&
	           execute(f.admin, "SAVE DUCKDB REPLICA TO DISK") &&
	           execute(f.admin, "START DUCKDB REPLICA") && f.state("applying"),
	           "restoring the original active set resumes replication")) return false;
	if (!check(execute(f.source, "INSERT INTO " + f.schema + ".events VALUES"
	                         "(-3,987.6543,'O''Reilly','2026-11-05 01:02:03.000004','2026-11-05 01:02:03.000005',X'0100FE',3000000000)") &&
	        f.matches(), "INSERT decodes decimal, text, DATETIME2, TIMESTAMP2, blob and unsigned values")) return false;
	if (!check(execute(f.source, "UPDATE " + f.schema + ".events SET id=id+10,amount=-amount,note='updated' WHERE id IN (1,-3)") &&
	        f.matches(), "multi-row UPDATE pairs before/after images including primary-key changes")) return false;
	if (!check(execute(f.source, "DELETE FROM " + f.schema + ".events WHERE id=2") && f.matches(), "DELETE applies by primary key")) return false;
	if (!check(execute(f.source, "BEGIN") && execute(f.source, "DELETE FROM " + f.schema + ".events") &&
	        execute(f.source, "ROLLBACK") && execute(f.source, "UPDATE " + f.schema + ".events SET note='after rollback' WHERE id=11") &&
	        f.matches(), "rolled-back changes never reach DuckDB")) return false;
	if (!check(execute(f.source, "INSERT INTO " + f.schema + ".ignored VALUES(1,JSON_OBJECT('v',1))") &&
	           execute(f.source, "UPDATE " + f.schema + ".events SET note='after ignored table' WHERE id=11") && f.matches() &&
	           cell(f.duck, "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=" + quote(f.schema) +
	                        " AND table_name='ignored'") == "0",
	           "unselected JSON tables are ignored without stopping selected-table changes")) return false;
	const Rows before_rotate = f.position();
	if (!check(before_rotate.size() == 1, "one durable source position exists")) return false;
	if (!check(execute(f.source, "FLUSH BINARY LOGS") &&
	        execute(f.source, "UPDATE " + f.schema + ".events SET note='after rotate' WHERE id=7") && f.matches() &&
	        wait_for([&] { const Rows p = f.position(); return p.size() == 1 && p[0][0] != before_rotate[0][0]; }),
	        "ROTATE follows the new binlog file and commits its position with data")) return false;
	const Rows durable = f.position();
	Rows source_position;
	if (!check(query(f.source, "SHOW BINARY LOG STATUS", source_position) && source_position.size() == 1 &&
	           durable.size() == 1 && durable[0][0] == source_position[0][0] && durable[0][1] == source_position[0][1] &&
	           cell(f.source, "SELECT GTID_SUBSET(" + quote(source_position[0][4]) + "," + quote(durable[0][2]) + ")") == "1",
	           "durable file, position and GTID include every committed source change")) return false;
	if (!check(wait_for([&] {
		Rows stats;
		return query(f.admin, "SELECT binlog_file,binlog_pos,gtid_executed FROM stats_duckdb_replica", stats) && stats == durable;
	}), "Admin statistics publish the durable applied position")) return false;
	if (!check(f.restart() && f.state("applying"), "ProxySQL restart resumes the enabled replica automatically")) return false;
	if (!check(f.position() == durable && f.matches(), "restart preserves the durable position with no duplicate rows")) return false;
	if (!check(execute(f.source, "UPDATE " + f.schema + ".events SET note='after restart' WHERE id=11") && f.matches(),
	        "binlog apply continues after restart")) return false;
	const Rows before_ddl = f.position();
	if (!check(execute(f.source, "ALTER TABLE " + f.schema + ".events ADD COLUMN extra INT") && f.state("error"),
	        "DDL stops replication with a sticky error")) return false;
	if (!check(f.position() == before_ddl && cell(f.admin, "SELECT last_error FROM stats_duckdb_replica").find("ALTER TABLE") != std::string::npos,
	        "DDL error reports the statement and never advances the durable position")) return false;
	if (!check(!execute(f.admin, "START DUCKDB REPLICA") && execute(f.admin, "STOP DUCKDB REPLICA") &&
	        execute(f.admin, "RESET DUCKDB REPLICA") && execute(f.admin, "START DUCKDB REPLICA") && f.state("applying") && f.matches() &&
	        cell(f.duck, "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema=" + quote(f.schema) +
	                     " AND table_name='events' AND column_name='extra'") == "1",
	        "STOP, RESET and START take a fresh snapshot with the altered schema")) return false;
	const Rows before_partial = f.position();
	if (!check(execute(f.source, "SET SESSION binlog_row_image='MINIMAL'") &&
	           execute(f.source, "UPDATE " + f.schema + ".guard SET id=2 WHERE id=1") && f.state("error") &&
	           f.position() == before_partial &&
	           cell(f.admin, "SELECT last_error FROM stats_duckdb_replica").find("partial row image") != std::string::npos,
	           "partial UPDATE after image is rejected without advancing the checkpoint")) return false;
	if (!check(execute(f.admin, "STOP DUCKDB REPLICA") &&
	           execute(f.duck, "CREATE TABLE " + f.schema + "." + f.schema +
	                           ".reset_blocker(id INT,part INT,FOREIGN KEY(id,part) REFERENCES " + f.schema + ".guard(id,part))"),
	           "create a genuine unrelated dependency that prevents RESET")) return false;
	if (!check(execute(f.admin, "DELETE FROM duckdb_replica_tables WHERE source_id='e2e' AND table_name='events'") &&
	           execute(f.admin, "LOAD DUCKDB REPLICA TO RUNTIME"),
	           "edit installed configuration after snapshot without changing persisted ownership")) return false;
	const Rows reset_position = f.position();
	Rows reset_stats;
	if (!query(f.admin, "SELECT binlog_file,binlog_pos,gtid_executed FROM stats_duckdb_replica", reset_stats)) return false;
	const bool reset_failed = !execute(f.admin, "RESET DUCKDB REPLICA");
	Rows after_reset_stats;
	if (!check(reset_failed && f.position() == reset_position &&
	           query(f.admin, "SELECT binlog_file,binlog_pos,gtid_executed FROM stats_duckdb_replica", after_reset_stats) &&
	           after_reset_stats == reset_stats,
	           "failed RESET preserves data, durable checkpoint and published lifecycle status")) return false;
	if (!check(execute(f.duck, "DROP TABLE " + f.schema + "." + f.schema + ".reset_blocker") && execute(f.admin, "RESET DUCKDB REPLICA") &&
	           cell(f.duck, "SELECT COUNT(*) FROM system.information_schema.tables WHERE table_schema='proxysql_replica'") == "0" &&
	           cell(f.duck, "SELECT COUNT(*) FROM system.information_schema.tables WHERE table_schema=" + quote(f.schema) +
	                        " AND table_name IN ('events','guard')") == "0",
	           "RESET removes manifest-owned tables and metadata after dependency removal despite configuration edits")) return false;
	const std::string keeper = "rollback_keep_" + std::to_string(getpid());
	if (!check(execute(f.duck, "CREATE TABLE " + f.schema + ".main." + keeper + "(id INT)") &&
	           execute(f.duck, "INSERT INTO " + f.schema + ".main." + keeper + " VALUES(42)") &&
	           execute(f.admin, "INSERT INTO duckdb_replica_tables VALUES('e2e'," + quote(f.schema) + ",'ignored',1)") &&
	           execute(f.admin, "INSERT INTO duckdb_replica_tables VALUES('e2e','main'," + quote(keeper) + ",0)"),
	           "prepare an unsupported source table and an unrelated inactive target")) return false;
	if (!check(execute(f.admin, "START DUCKDB REPLICA") && f.state("error") &&
	           cell(f.admin, "SELECT last_error FROM stats_duckdb_replica").find("JSON") != std::string::npos &&
	           cell(f.duck, "SELECT id FROM " + f.schema + ".main." + keeper) == "42" &&
	           cell(f.duck, "SELECT COUNT(*) FROM system.information_schema.tables WHERE table_schema='proxysql_replica'") == "0" &&
	           cell(f.duck, "SELECT COUNT(*) FROM system.information_schema.tables WHERE table_schema=" + quote(f.schema) +
	                        " AND table_name='guard'") == "0",
	           "failed snapshot rolls back its tables and metadata while preserving unrelated inactive data")) return false;
	if (!check(execute(f.admin, "STOP DUCKDB REPLICA") && execute(f.admin, "RESET DUCKDB REPLICA") &&
	           cell(f.duck, "SELECT id FROM " + f.schema + ".main." + keeper) == "42",
	           "RESET after failed snapshot is idempotent and preserves unowned tables")) return false;
	return true;
}
} // namespace

int main() {
	CommandLine cl;
	if (cl.getEnv()) return EXIT_FAILURE;
	plan(NO_PLAN);
	{ Fixture fixture(cl); ok(run(fixture), "live replica scenario completed"); }
	return exit_status();
}
