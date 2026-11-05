// Differential MySQL SELECT coverage through the direct DuckDB listener and
// a normal ProxySQL hostgroup targeting that listener on this same instance.
#include "mysql.h"
#include "tap.h"
#include "command_line.h"
#include <chrono>
#include <cstdlib>
#include <functional>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>
namespace {
using Rows = std::vector<std::vector<std::string>>;
std::string quote(const std::string &s) {
	std::string out = "'";
	for (char c : s) {
		out += c;
		if (c == '\'')
			out += c;
	}
	return out + "'";
}
MYSQL *connect(const char *host, int port, const char *user, const char *pass) {
	MYSQL *c = mysql_init(nullptr);
	unsigned timeout = 2;
	mysql_options(c, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
	if (!mysql_real_connect(c, host, user, pass, nullptr, port, nullptr, 0)) {
		mysql_close(c);
		return nullptr;
	}
	return c;
}
bool query(MYSQL *c, const std::string &sql, Rows *out = nullptr) {
	if (mysql_query(c, sql.c_str()))
		return false;
	MYSQL_RES *r = mysql_store_result(c);
	if (!r)
		return out == nullptr;
	if (out) {
		out->clear();
		while (MYSQL_ROW row = mysql_fetch_row(r)) {
			auto lengths = mysql_fetch_lengths(r);
			std::vector<std::string> cells;
			for (unsigned i = 0; i < mysql_num_fields(r); ++i)
				cells.push_back(row[i] ? std::string(row[i], lengths[i]) : "<NULL>");
			out->push_back(std::move(cells));
		}
	}
	mysql_free_result(r);
	return mysql_errno(c) == 0;
}
std::string cell(MYSQL *c, const std::string &sql) {
	Rows r;
	return query(c, sql, &r) && r.size() == 1 ? r[0][0] : "";
}
bool wait_for(const std::function<bool()> &fn) {
	auto end = std::chrono::steady_clock::now() + std::chrono::seconds(20);
	do {
		if (fn())
			return true;
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	} while (std::chrono::steady_clock::now() < end);
	return false;
}
bool check(bool value, const char *msg) {
	ok(value, "%s", msg);
	return value;
}
struct Fixture {
	CommandLine &cl;
	MYSQL *admin = nullptr;
	MYSQL *source = nullptr;
	MYSQL *duck = nullptr;
	MYSQL *front = nullptr;
	std::string schema = "mysql_compat_e2e_" + std::to_string(getpid());
	std::string old_main, old_disk;
	bool changed = false, own_server = false, own_rule = false, own_user = false,
		 own_source_schema = false, own_duck_schema = false;
	int duck_port = 6031;
	explicit Fixture(CommandLine &c) : cl(c) {
		if (auto p = std::getenv("TAP_DUCKDB_PORT"))
			duck_port = std::atoi(p);
	}
	bool reconnect() {
		if (admin)
			mysql_close(admin);
		if (duck)
			mysql_close(duck);
		admin = duck = nullptr;
		return wait_for([&] {
			if (!admin)
				admin = connect(cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
			if (!duck)
				duck = connect(cl.host, duck_port, cl.username, cl.password);
			return admin && duck;
		});
	}
	bool restart() {
		mysql_query(admin, "PROXYSQL RESTART");
		if (!wait_for([&] { return mysql_ping(duck) != 0; }))
			return false;
		return reconnect();
	}
	~Fixture() {
		if (front)
			mysql_close(front);
		if (changed && admin) {
			if (own_rule) {
				query(admin, "DELETE FROM mysql_query_rules WHERE rule_id=19400");
				query(admin, "LOAD MYSQL QUERY RULES TO RUNTIME");
			}
			if (own_server) {
				query(admin, "DELETE FROM mysql_servers WHERE hostgroup_id=19400 AND "
							 "hostname='127.0.0.1' AND port=" +
								 std::to_string(duck_port));
				query(admin, "LOAD MYSQL SERVERS TO RUNTIME");
			}
			if (own_user) {
				query(admin, "DELETE FROM mysql_users WHERE username='duckdb_compat_e2e'");
				query(admin, "LOAD MYSQL USERS TO RUNTIME");
			}
			if (own_duck_schema)
				query(duck, "DROP SCHEMA IF EXISTS " + schema + " CASCADE");
			bool restored = query(admin, "DELETE FROM disk.global_variables WHERE "
										 "variable_name='duckdb-mysql_compatibility'");
			if (!old_disk.empty())
				restored =
					query(admin,
						  "INSERT INTO disk.global_variables VALUES('duckdb-mysql_compatibility'," +
							  quote(old_disk) + ")") &&
					restored;
			restored = restart() && restored;
			if (restored)
				restored =
					query(admin, "UPDATE global_variables SET variable_value=" + quote(old_main) +
									 " WHERE variable_name='duckdb-mysql_compatibility'");
			ok(restored,
			   "restore compatibility setting and original engine after persistence test");
		}
		if (source) {
			if (own_source_schema)
				query(source, "DROP DATABASE IF EXISTS " + schema);
			mysql_close(source);
		}
		if (duck)
			mysql_close(duck);
		if (admin)
			mysql_close(admin);
	}
};
bool run(Fixture &f) {
	f.source = connect(f.cl.mysql_host, f.cl.mysql_port, f.cl.mysql_username, f.cl.mysql_password);
	if (!check(f.source && f.reconnect(),
			   "connect to MySQL source, Admin and native DuckDB listener"))
		return false;
	f.old_main = cell(f.admin, "SELECT variable_value FROM global_variables WHERE "
							   "variable_name='duckdb-mysql_compatibility'");
	f.old_disk = cell(f.admin, "SELECT variable_value FROM disk.global_variables WHERE "
							   "variable_name='duckdb-mysql_compatibility'");
	if (!check(f.old_main == "false" && !query(f.duck, "SELECT 1 AS `native_is_not_mysql`"),
			   "native SQL is the default and does not silently enable MySQL translation"))
		return false;
	if (!check(
			cell(f.admin, "SELECT COUNT(*) FROM mysql_servers WHERE hostgroup_id=19400") == "0" &&
				cell(f.admin, "SELECT COUNT(*) FROM mysql_query_rules WHERE rule_id=19400") ==
					"0" &&
				cell(f.admin,
					 "SELECT COUNT(*) FROM mysql_users WHERE username='duckdb_compat_e2e'") == "0",
			"fixture hostgroup, rule and username are unused before changing configuration"))
		return false;
	f.changed = true;
	if (!check(query(f.admin, "UPDATE global_variables SET variable_value='true' WHERE "
							  "variable_name='duckdb-mysql_compatibility'") &&
				   !query(f.admin, "LOAD DUCKDB VARIABLES TO RUNTIME") &&
				   cell(f.admin, "SELECT variable_value FROM runtime_global_variables WHERE "
								 "variable_name='duckdb-mysql_compatibility'") == "false",
			   "compatibility changes require reopening the listener and do not affect existing "
			   "sessions"))
		return false;
	if (!check(query(f.admin, "DELETE FROM disk.global_variables WHERE "
							  "variable_name='duckdb-mysql_compatibility'") &&
				   query(f.admin, "INSERT INTO disk.global_variables "
								  "VALUES('duckdb-mysql_compatibility','true')") &&
				   f.restart() &&
				   cell(f.admin, "SELECT variable_value FROM runtime_global_variables WHERE "
								 "variable_name='duckdb-mysql_compatibility'") == "true",
			   "restart enables persisted MySQL compatibility"))
		return false;
	if (!check(query(f.source, "SET SESSION sql_mode=''") &&
				   query(f.source, "SET NAMES utf8mb4 COLLATE utf8mb4_bin") &&
				   query(f.source, "SET time_zone='+00:00'") &&
				   (f.own_source_schema =
						query(f.source, "CREATE DATABASE " + f.schema +
											" CHARACTER SET utf8mb4 COLLATE utf8mb4_bin")) &&
				   (f.own_duck_schema = query(f.duck, "CREATE SCHEMA " + f.schema)),
			   "create source and DuckDB comparison schemas with documented source semantics"))
		return false;
	const std::vector<std::string> fixture = {
		"CREATE TABLE " + f.schema +
			".sales(id INT,customer INT,amount DECIMAL(10,2),ts DATETIME,note VARCHAR(100))",
		"INSERT INTO " + f.schema +
			".sales VALUES(1,1,10.00,'2026-11-05 12:34:56','Ada'),(2,1,5.00,'2026-11-06 "
			"00:00:01','Bob'),(3,2,NULL,NULL,NULL),(4,2,20.00,'2026-11-07','Cid')",
		"CREATE TABLE " + f.schema + ".customers(id INT,name VARCHAR(100))",
		"INSERT INTO " + f.schema + ".customers VALUES(1,'one'),(2,'two'),(3,'three')"};
	for (const auto &sql : fixture)
		if (!check(query(f.source, sql) && query(f.duck, sql),
				   "install identical analytical fixture on both engines"))
			return false;
	if (!check(
			(f.own_server = query(
				 f.admin,
				 "INSERT INTO mysql_servers(hostgroup_id,hostname,port) VALUES(19400,'127.0.0.1'," +
					 std::to_string(f.duck_port) + ")")) &&
				query(f.admin, "LOAD MYSQL SERVERS TO RUNTIME") &&
				(f.own_user =
					 query(f.admin, "INSERT INTO mysql_users(username,password,default_hostgroup) "
									"VALUES('duckdb_compat_e2e','duckdb_compat_e2e',0)")) &&
				query(f.admin, "LOAD MYSQL USERS TO RUNTIME") &&
				(f.own_rule = query(
					 f.admin, "INSERT INTO "
							  "mysql_query_rules(rule_id,active,username,destination_hostgroup,"
							  "apply) VALUES(19400,1,'duckdb_compat_e2e',19400,1)")) &&
				query(f.admin, "LOAD MYSQL QUERY RULES TO RUNTIME") &&
				(f.front = connect(f.cl.host, f.cl.port, "duckdb_compat_e2e", "duckdb_compat_e2e")),
			"regular query rule routes a client to this instance's DuckDB backend listener"))
		return false;
	const std::string sales = "`" + f.schema + "`.`sales`",
					  customers = "`" + f.schema + "`.`customers`";
	const std::vector<std::string> queries = {
		"SELECT `id`,`note` FROM " + sales + " WHERE id=1",
		"SELECT id FROM " + sales + " WHERE amount <=> NULL OR id <=> 2 ORDER BY id",
		"SELECT id FROM " + sales + " ORDER BY id LIMIT 1,2",
		"SELECT customer,SUM(amount),CAST(AVG(amount) AS DECIMAL(10,2)),COUNT(*) FROM " + sales +
			" GROUP BY customer HAVING COUNT(*)>1 ORDER BY customer",
		"SELECT c.name,IFNULL(SUM(s.amount),0) FROM " + customers + " c LEFT JOIN " + sales +
			" s ON s.customer=c.id GROUP BY c.name ORDER BY c.name",
		"SELECT CAST('-12' AS SIGNED INTEGER),CAST('42' AS UNSIGNED),IF(1=1,'yes','no')",
		"SELECT DATEDIFF('2026-11-06 00:01:00','2026-11-05 23:59:00'),DATEDIFF(NULL,'2026-11-05')",
		"SELECT DATE_FORMAT(ts,'%Y-%m-%d %H:%i:%s.%f') FROM " + sales + " WHERE id=1",
		"SELECT id FROM " + sales + " ORDER BY amount,id",
		"SELECT id FROM " + sales + " ORDER BY amount DESC,id DESC",
		"SELECT id FROM (SELECT id,amount FROM " + sales +
			" ORDER BY amount LIMIT 0,2) q ORDER BY amount DESC",
		"WITH x AS(SELECT id FROM " + sales + " ORDER BY id LIMIT 1,2) SELECT SUM(id) FROM x",
		"SELECT \"hello\",'O\\'Reilly','a\\\\b','`id` <=> LIMIT 1,2'",
		"SELECT CAST((1=1)&&(2=2) AS SIGNED),CAST((1=0)||(2=2) AS SIGNED)",
		"SELECT NULL <=> NULL,NULL <=> 1,TRUE,FALSE,NULL,'true'",
		"SELECT CAST(-1 AS UNSIGNED),CAST(18446744073709551615 AS SIGNED),CAST(-SUM(id) AS "
		"UNSIGNED) FROM " +
			sales,
		"SELECT 'a_b' LIKE 'a\\_b','a_b' NOT LIKE CONCAT('a','\\_','b'),'hello' 'world'",
		"SELECT (2 <=> 2) = 1",
		"SELECT CASE WHEN NULL <=> NULL THEN 7 ELSE 9 END",
		"SELECT YEAR(ts),MONTH(ts),DAY(ts) FROM " + sales + " WHERE id=1"};
	for (const auto &sql : queries) {
		Rows expected, direct, routed;
		bool a = query(f.source, sql, &expected), b = query(f.duck, sql, &direct),
			 c = query(f.front, sql, &routed);
		ok(a && b && c && expected == direct && expected == routed,
		   "source, direct and routed results agree: %s", sql.c_str());
		if (!a || !b || !c)
			diag("source=%s direct=%s routed=%s", mysql_error(f.source), mysql_error(f.duck),
				 mysql_error(f.front));
	}
	for (const char *sql :
		 {"SELECT DATE_FORMAT('2026-11-05','%V')", "SELECT @unsupported", "SELECT 2 <=> 2 = 1",
		  "SELECT 2 <=> CASE WHEN TRUE THEN 2 ELSE 3 END = 1", "SELECT 1;SELECT 2",
		  "SELECT 1 FOR UPDATE"})
		ok(!query(f.duck, sql) && mysql_errno(f.duck) == 1235,
		   "unsupported syntax gets an explicit compatibility error: %s", sql);
	return true;
}
} // namespace
int main() {
	CommandLine cl;
	if (cl.getEnv())
		return EXIT_FAILURE;
	plan(NO_PLAN);
	{
		Fixture f(cl);
		ok(run(f), "MySQL compatibility scenario completed");
	}
	return exit_status();
}
