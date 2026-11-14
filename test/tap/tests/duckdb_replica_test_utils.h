#ifndef DUCKDB_REPLICA_TEST_UTILS_H
#define DUCKDB_REPLICA_TEST_UTILS_H
// Shared real child/source fixture. Signals must never target the test-group server.
#include "mysql.h"
#include "tap.h"
#include "command_line.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#ifdef __linux__
#include <sys/prctl.h>
#endif
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#ifndef PROXYSQL_TEST_BINARY
#define PROXYSQL_TEST_BINARY "../../../src/proxysql"
#endif
#ifndef DUCKDB_TEST_PLUGIN
#define DUCKDB_TEST_PLUGIN "../../../plugins/duckdb/ProxySQL_DuckDB_Plugin.so"
#endif

namespace duckdb_replica_test {
using Rows = std::vector<std::vector<std::string>>;
constexpr int kRows = 200000;
inline std::string quote(const std::string& s) {
	std::string out = "'";
	for (char c : s) {
		out += c;
		if (c == '\'')
			out += c;
	}
	return out + '\'';
}
inline std::string config_string(const std::string& s) {
	std::string out = "\"";
	for (char c : s) {
		if (c == '"' || c == '\\')
			out += '\\';
		out += c;
	}
	return out + '"';
}
inline MYSQL* connect(const char* host, int port, const char* user, const char* password) {
	MYSQL* c = mysql_init(nullptr);
	unsigned timeout = 2, read_timeout = 30;
	mysql_options(c, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	mysql_options(c, MYSQL_OPT_READ_TIMEOUT, &read_timeout);
	if (!mysql_real_connect(c, host, user, password, nullptr, port, nullptr, 0)) {
		mysql_close(c);
		return nullptr;
	}
	fcntl(mysql_get_socket(c), F_SETFD, FD_CLOEXEC);
	return c;
}
inline bool query(MYSQL* c, const std::string& sql, Rows* rows = nullptr) {
	if (!c || mysql_query(c, sql.c_str())) {
		// Statements can contain credentials; print only the server error.
		if (c)
			diag("query error %u: %s", mysql_errno(c), mysql_error(c));
		return false;
	}
	MYSQL_RES* r = mysql_store_result(c);
	if (!r)
		return rows == nullptr && mysql_errno(c) == 0;
	if (rows) {
		rows->clear();
		while (MYSQL_ROW row = mysql_fetch_row(r)) {
			auto lengths = mysql_fetch_lengths(r);
			std::vector<std::string> cells;
			for (unsigned i = 0; i < mysql_num_fields(r); ++i)
				cells.push_back(row[i] ? std::string(row[i], lengths[i]) : "<NULL>");
			rows->push_back(std::move(cells));
		}
	}
	mysql_free_result(r);
	return mysql_errno(c) == 0;
}
inline std::string cell(MYSQL* c, const std::string& sql) {
	Rows rows;
	return query(c, sql, &rows) && rows.size() == 1 && !rows[0].empty() ? rows[0][0] : "";
}
inline bool wait_for(const std::function<bool()>& predicate, int seconds = 45) {
	auto end = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
	do {
		if (predicate())
			return true;
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	} while (std::chrono::steady_clock::now() < end);
	return false;
}
inline bool check(bool value, const char* description) {
	ok(value, "%s", description);
	return value;
}

struct Fixture {
	CommandLine& cl;
	std::string dir, binary, plugin;
	std::string schema = "replica_recovery_" + std::to_string(getpid());
	std::string account = "recovery_" + std::to_string(getpid());
	MYSQL *source = nullptr, *admin = nullptr, *duck = nullptr;
	pid_t pid = -1;
	std::vector<int> leases;
	int admin_port, mysql_port, pgsql_port, sqlite_port, duck_port, duck_pg_port;
	bool own_schema = false, own_account = false, complete = false;

	int port() {
		int fd = socket(AF_INET, SOCK_STREAM, 0);
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		socklen_t len = sizeof(addr);
		if (fd < 0 || bind(fd, reinterpret_cast<sockaddr*>(&addr), len) != 0 ||
			getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0)
			BAIL_OUT("cannot reserve a loopback port");
		fcntl(fd, F_SETFD, FD_CLOEXEC);
		leases.push_back(fd);
		return ntohs(addr.sin_port);
	}
	explicit Fixture(CommandLine& c) : cl(c) {
		const char* temp_dir = std::getenv("TMPDIR");
		std::string pattern = std::string(temp_dir ? temp_dir : "/tmp") + "/proxysql-replica-recovery-XXXXXX";
		char* created = mkdtemp(pattern.data());
		if (!created)
			BAIL_OUT("mkdtemp failed");
		dir = created;
		binary = std::getenv("TAP_PROXYSQL_BINARY") ? std::getenv("TAP_PROXYSQL_BINARY")
													: PROXYSQL_TEST_BINARY;
		plugin = std::getenv("TAP_DUCKDB_PLUGIN") ? std::getenv("TAP_DUCKDB_PLUGIN")
												  : DUCKDB_TEST_PLUGIN;
		binary = std::filesystem::absolute(binary).string();
		plugin = std::filesystem::absolute(plugin).string();
		admin_port = port();
		mysql_port = port();
		pgsql_port = port();
		sqlite_port = port();
		duck_port = port();
		duck_pg_port = port();
	}
	std::string table(const std::string& name, bool target = false) const {
		return (target ? "replica." : "") + schema + "." + name;
	}
	void close_clients() {
		if (admin)
			mysql_close(admin);
		if (duck)
			mysql_close(duck);
		admin = duck = nullptr;
	}
	bool write_config(bool with_plugin) {
		std::ofstream f(dir + "/proxysql.cnf");
		f << "admin_variables={admin_credentials=\"radmin:recovery_admin\";mysql_ifaces=\"127.0.0."
			 "1:"
		  << admin_port << "\";}\n"
		  << "mysql_variables={threads=2;interfaces=\"127.0.0.1:" << mysql_port << "\";}\n"
		  << "pgsql_variables={threads=2;interfaces=\"127.0.0.1:" << pgsql_port << "\";}\n"
		  << "sqliteserver_variables={mysql_ifaces=\"127.0.0.1:" << sqlite_port << "\";}\n"
		  << "mysql_users=({username=\"recovery_client\";password=\"recovery_client\";active=1;"
			 "default_hostgroup=0;})\n";
		if (with_plugin)
			f << "plugins=(" << config_string(plugin) << ")\n";
		return bool(f);
	}
	bool start(bool with_plugin = true) {
		close_clients();
		if (pid > 0 || !write_config(with_plugin))
			return false;
		for (int fd : leases)
			close(fd);
		leases.clear();
		fflush(nullptr);
#ifdef __linux__
		const pid_t parent = getpid();
#endif
		pid = fork();
		if (pid == 0) {
#ifdef __linux__
			// CI timeouts can SIGKILL the TAP parent, bypassing its destructor.
			// The PID check closes the race where it dies before prctl runs.
			if (prctl(PR_SET_PDEATHSIG, SIGKILL) != 0 || getppid() != parent)
				_exit(125);
#endif
			rlimit limit{0, 0};
			setrlimit(RLIMIT_CORE, &limit);
			int log = open((dir + "/proxysql.log").c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
			if (log < 0)
				_exit(126);
			dup2(log, STDOUT_FILENO);
			dup2(log, STDERR_FILENO);
			close(log);
			execl(binary.c_str(), binary.c_str(), "-f", "-M", "-c", (dir + "/proxysql.cnf").c_str(),
				  "-D", dir.c_str(), static_cast<char*>(nullptr));
			_exit(127);
		}
		if (pid < 0)
			return false;
		const bool ready = wait_for([&] {
			if (!admin)
				admin = connect("127.0.0.1", admin_port, "radmin", "recovery_admin");
			if (with_plugin && !duck)
				duck = connect("127.0.0.1", duck_port, "recovery_client", "recovery_client");
			return admin && (!with_plugin || duck);
		});
		if (!ready)
			diag("child not ready; log: %s/proxysql.log", dir.c_str());
		return ready;
	}
	bool crash() {
		if (pid <= 0 || kill(pid, SIGKILL) != 0)
			return false;
		int status = 0;
		pid_t result;
		do {
			result = waitpid(pid, &status, 0);
		} while (result < 0 && errno == EINTR);
		pid = -1;
		close_clients();
		return result > 0 && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL;
	}
	bool shutdown() {
		if (pid <= 0)
			return true;
		kill(pid, SIGCONT); // Cleanup must also handle a failed assertion while paused.
		if (admin)
			mysql_query(admin, "PROXYSQL SHUTDOWN");
		int status = 0;
		bool exited = wait_for([&] { return waitpid(pid, &status, WNOHANG) == pid; }, 10);
		if (exited) {
			pid = -1;
			close_clients();
			return WIFEXITED(status) && WEXITSTATUS(status) == 0;
		}
		crash();
		return false;
	}
	bool bootstrap() {
		if (access(binary.c_str(), X_OK) != 0 || access(plugin.c_str(), R_OK) != 0 || !start(false))
			return false;
		return query(admin, "INSERT OR REPLACE INTO disk.global_variables VALUES"
							"('duckdb-database_path'," +
								quote(dir + "/replica.duckdb") +
								"),"
								"('duckdb-mysql_ifaces'," +
								quote("127.0.0.1:" + std::to_string(duck_port)) +
								"),"
								"('duckdb-pgsql_ifaces'," +
								quote("127.0.0.1:" + std::to_string(duck_pg_port)) +
								"),"
								"('duckdb-threads','2')") &&
			   shutdown() && start();
	}
	bool privilege(const std::string& sql) {
		// Account changes are fixture setup, not workload DDL for the applier.
		if (!query(source, "SET SESSION sql_log_bin=0"))
			return false;
		bool result = query(source, sql);
		return query(source, "SET SESSION sql_log_bin=1") && result;
	}
	bool source_setup(int rows = kRows) {
		if (rows < 1 || rows > 1000000)
			return false;
		source = connect(cl.mysql_host, cl.mysql_port, cl.mysql_username, cl.mysql_password);
		if (!source || !query(source, "CREATE DATABASE " + schema))
			return false;
		own_schema = true;
		if (!privilege("CREATE USER " + quote(account) + "@'%' IDENTIFIED BY 'recovery_source'"))
			return false;
		own_account = true;
		if (!privilege("GRANT REPLICATION SLAVE,REPLICATION CLIENT,RELOAD ON *.* TO " +
					   quote(account) + "@'%'") ||
			!privilege("GRANT SELECT ON " + schema + ".* TO " + quote(account) + "@'%'") ||
			!query(source, "CREATE TABLE " + table("a_bulk") +
							   "(id INT PRIMARY KEY,val BIGINT,note VARCHAR(256)) ENGINE=InnoDB") ||
			!query(source, "CREATE TABLE " + table("z_tail") +
							   "(id INT PRIMARY KEY,val BIGINT,note VARCHAR(256)) ENGINE=InnoDB") ||
			!query(source, "INSERT INTO " + table("z_tail") + " VALUES(1,0,'initial')"))
			return false;
		const std::string digits =
			"(SELECT 0 n UNION ALL SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT "
			"4 UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 UNION "
			"ALL SELECT 9)";
		return query(source, "INSERT INTO " + table("a_bulk") +
								 " SELECT n+1,0,REPEAT('snapshot',32) FROM (SELECT "
								 "a.n+10*b.n+100*c.n+1000*d.n+10000*e.n+100000*f.n n FROM " +
								 digits + " a CROSS JOIN " + digits + " b CROSS JOIN " + digits +
								 " c CROSS JOIN " + digits + " d CROSS JOIN " + digits +
								 " e CROSS JOIN " + digits + " f) numbers WHERE n<" +
								 std::to_string(rows));
	}
	bool configure() {
		return query(admin, "INSERT INTO duckdb_replica_sources VALUES('recovery'," +
								quote(cl.mysql_host) + "," + std::to_string(cl.mysql_port) + "," +
								quote(account) + ",'recovery_source'," +
								std::to_string(100000 + getpid()) + ",1)") &&
			   query(admin, "INSERT INTO duckdb_replica_tables VALUES('recovery'," + quote(schema) +
								",'a_bulk',1),('recovery'," + quote(schema) + ",'z_tail',1)") &&
			   query(admin, "SAVE DUCKDB REPLICA TO DISK");
	}
	bool copying() {
		return wait_for([&] {
			Rows r;
			return query(admin,
						 "SELECT state,snapshot_table,rows_applied FROM stats_duckdb_replica",
						 &r) &&
				   r.size() == 1 && r[0][0] == "snapshotting" && r[0][1] == schema + ".a_bulk" &&
				   std::stoull(r[0][2]) >= 1000;
		});
	}
	Rows position() {
		Rows r;
		query(duck,
			  "SELECT binlog_file,binlog_pos,gtid_executed FROM replica.proxysql_replica.position",
			  &r);
		return r;
	}
	Rows source_position() {
		Rows r;
		if (!query(source, "SHOW BINARY LOG STATUS", &r) || r.size() != 1 || r[0].size() < 5)
			return {};
		return {{r[0][0], r[0][1], r[0][4]}};
	}
	bool read_data(MYSQL* c, bool target, Rows& out) {
		return query(c, "SELECT id,val,note FROM " + table("a_bulk", target) + " ORDER BY id",
					 &out);
	}
	bool matches() {
		Rows expected_bulk, expected_tail;
		if (!read_data(source, false, expected_bulk) ||
			!query(source, "SELECT id,val,note FROM " + table("z_tail") + " ORDER BY id",
				   &expected_tail))
			return false;
		const Rows expected_position = source_position();
		if (expected_position.empty())
			return false;
		bool matched = false;
		wait_for(
			[&] {
				const std::string state = cell(admin, "SELECT state FROM stats_duckdb_replica");
				if (state == "error")
					return true;
				Rows bulk, tail;
				matched =
					state == "applying" && read_data(duck, true, bulk) && bulk == expected_bulk &&
					query(duck, "SELECT id,val,note FROM " + table("z_tail", true) + " ORDER BY id",
						  &tail) &&
					tail == expected_tail && position() == expected_position;
				return matched;
			},
			90);
		if (!matched)
			diag("replica state=%s error=%s",
				 cell(admin, "SELECT state FROM stats_duckdb_replica").c_str(),
				 cell(admin, "SELECT last_error FROM stats_duckdb_replica").c_str());
		return matched;
	}
	~Fixture() {
		bool cleaned = pid <= 0 || shutdown();
		for (int fd : leases)
			close(fd);
		if (source) {
			cleaned = query(source, "ROLLBACK") && cleaned;
			if (own_schema)
				cleaned = query(source, "DROP DATABASE " + schema) && cleaned;
			if (own_account)
				cleaned = privilege("DROP USER " + quote(account) + "@'%'") && cleaned;
			mysql_close(source);
		}
		if (complete && cleaned) {
			std::error_code error;
			std::filesystem::remove_all(dir, error);
			cleaned = !error;
		} else
			diag("recovery artifacts retained at %s", dir.c_str());
		ok(cleaned, "reap the owned child and remove only fixture-owned source objects and files");
	}
};

} // namespace duckdb_replica_test
#endif
