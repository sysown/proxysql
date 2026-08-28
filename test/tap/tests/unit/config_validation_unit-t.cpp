/**
 * @file config_validation_unit-t.cpp
 * @brief Unit tests for ProxySQL_Config validation and formatting functions.
 *
 * Tests the following functions:
 * - addField(): string formatting/escaping for config file output (public)
 * - validate_backend_users(): duplicate user detection (private)
 * - validate_backend_servers(): duplicate server detection (private)
 * - validate_proxysql_servers(): duplicate ProxySQL server detection (private)
 *
 * The validate_* methods are private; we access them via a friend class
 * (ProxySQL_Config_TestHelper) declared in proxysql_config.h.
 *
 * ProxySQL_Config requires a non-null SQLite3DB*, so we create a real
 * in-memory SQLite3DB for the constructor.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "proxysql_config.h"
#include "sqlite3db.h"

#include <libconfig.h++>
#include <string>
#include <cstring>

using libconfig::Config;
using libconfig::Setting;

/**
 * @brief Test helper that exposes ProxySQL_Config private methods.
 *
 * Declared as a friend class in proxysql_config.h.
 */
class ProxySQL_Config_TestHelper {
public:
	static bool validate_backend_users(
		ProxySQL_Config& cfg, proxysql_config_type type,
		const Setting& config, std::string& error)
	{
		return cfg.validate_backend_users(type, config, error);
	}

	static bool validate_backend_servers(
		ProxySQL_Config& cfg, proxysql_config_type type,
		const Setting& config, std::string& error)
	{
		return cfg.validate_backend_servers(type, config, error);
	}

	static bool validate_proxysql_servers(
		ProxySQL_Config& cfg, const Setting& config, std::string& error)
	{
		return cfg.validate_proxysql_servers(config, error);
	}
};


// ============================================================
// addField() — config field formatting and escaping
// ============================================================

static SQLite3DB* create_test_db() {
	SQLite3DB* db = new SQLite3DB();
	db->open((char*)":memory:", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
	return db;
}

static void test_addField_basic() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string data;

	cfg.addField(data, "username", "admin");
	ok(data.find("username") != std::string::npos,
		"addField: field name present in output");
	ok(data.find("admin") != std::string::npos,
		"addField: field value present in output");
	ok(data.find("\"admin\"") != std::string::npos,
		"addField: value is double-quoted by default");
	// Should have tab indentation
	ok(data.substr(0, 2) == "\t\t",
		"addField: output starts with double-tab indentation");
	// Should end with newline
	ok(data.back() == '\n',
		"addField: output ends with newline");

	delete db;
}

static void test_addField_null_value() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string data;

	cfg.addField(data, "username", nullptr);
	ok(data.empty(), "addField: null value produces no output");

	delete db;
}

static void test_addField_empty_value() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string data;

	cfg.addField(data, "username", "");
	ok(data.empty(), "addField: empty string value produces no output");

	delete db;
}

static void test_addField_custom_delimiter() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string data;

	cfg.addField(data, "port", "3306", "");
	ok(data.find("\"") == std::string::npos,
		"addField: empty delimiter produces no quotes");
	ok(data.find("3306") != std::string::npos,
		"addField: value present with custom delimiter");

	delete db;
}

static void test_addField_escapes_quotes() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string data;

	cfg.addField(data, "comment", "say \"hello\"");
	// The embedded quotes should be escaped: " becomes \"
	ok(data.find("\\\"hello\\\"") != std::string::npos,
		"addField: embedded double quotes are escaped");

	delete db;
}

static void test_addField_accumulates() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string data;

	cfg.addField(data, "username", "admin");
	cfg.addField(data, "password", "secret");

	ok(data.find("username") != std::string::npos,
		"addField: first field present after accumulation");
	ok(data.find("password") != std::string::npos,
		"addField: second field present after accumulation");

	delete db;
}

static void test_addField_equals_format() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string data;

	cfg.addField(data, "key", "val");
	ok(data.find("key=\"val\"") != std::string::npos,
		"addField: format is name=dq+value+dq");

	delete db;
}


// ============================================================
// validate_backend_users() — duplicate user detection
// ============================================================

static void test_validate_users_unique_mysql() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"users = ( { username = \"admin\"; backend = 1; },"
		"          { username = \"reader\"; backend = 1; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& users = root["users"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_users(
		cfg, PROXYSQL_CONFIG_MYSQL_USERS, users, error);
	ok(result == true, "validate_backend_users: unique mysql users pass");
	ok(error.empty(), "validate_backend_users: no error on unique users");

	delete db;
}

static void test_validate_users_duplicate_mysql() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"users = ( { username = \"admin\"; backend = 1; },"
		"          { username = \"admin\"; backend = 1; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& users = root["users"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_users(
		cfg, PROXYSQL_CONFIG_MYSQL_USERS, users, error);
	ok(result == false, "validate_backend_users: duplicate mysql users detected");
	ok(error.find("duplicate") != std::string::npos,
		"validate_backend_users: error mentions 'duplicate'");
	ok(error.find("mysql_users") != std::string::npos,
		"validate_backend_users: error mentions 'mysql_users'");

	delete db;
}

static void test_validate_users_duplicate_pgsql() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"users = ( { username = \"admin\"; backend = 1; },"
		"          { username = \"admin\"; backend = 1; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& users = root["users"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_users(
		cfg, PROXYSQL_CONFIG_PGSQL_USERS, users, error);
	ok(result == false, "validate_backend_users: duplicate pgsql users detected");
	ok(error.find("pgsql_users") != std::string::npos,
		"validate_backend_users: error mentions 'pgsql_users'");

	delete db;
}

static void test_validate_users_same_name_different_backend() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"users = ( { username = \"admin\"; backend = 1; },"
		"          { username = \"admin\"; backend = 0; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& users = root["users"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_users(
		cfg, PROXYSQL_CONFIG_MYSQL_USERS, users, error);
	ok(result == true,
		"validate_backend_users: same name different backend is valid");

	delete db;
}

static void test_validate_users_missing_username() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"users = ( { backend = 1; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& users = root["users"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_users(
		cfg, PROXYSQL_CONFIG_MYSQL_USERS, users, error);
	ok(result == false,
		"validate_backend_users: missing username rejected");
	ok(error.find("mandatory") != std::string::npos,
		"validate_backend_users: error mentions 'mandatory'");

	delete db;
}

static void test_validate_users_default_backend() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	// Two users with same name, no explicit backend => both default to 1 => duplicate
	Config lc;
	lc.readString(
		"users = ( { username = \"admin\"; },"
		"          { username = \"admin\"; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& users = root["users"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_users(
		cfg, PROXYSQL_CONFIG_MYSQL_USERS, users, error);
	ok(result == false,
		"validate_backend_users: default backend causes duplicate detection");

	delete db;
}

static void test_validate_users_empty_list() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString("users = ( );");
	const Setting& root = lc.getRoot();
	const Setting& users = root["users"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_users(
		cfg, PROXYSQL_CONFIG_MYSQL_USERS, users, error);
	ok(result == true, "validate_backend_users: empty list is valid");

	delete db;
}

static void test_validate_users_single_entry() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString("users = ( { username = \"solo\"; } );");
	const Setting& root = lc.getRoot();
	const Setting& users = root["users"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_users(
		cfg, PROXYSQL_CONFIG_MYSQL_USERS, users, error);
	ok(result == true, "validate_backend_users: single entry is valid");

	delete db;
}


// ============================================================
// validate_backend_servers() — duplicate server detection
// ============================================================

static void test_validate_servers_unique_mysql() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"servers = ( { hostgroup_id = 1; hostname = \"10.0.0.1\"; port = 3306; },"
		"            { hostgroup_id = 1; hostname = \"10.0.0.2\"; port = 3306; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_servers(
		cfg, PROXYSQL_CONFIG_MYSQL_SERVERS, servers, error);
	ok(result == true, "validate_backend_servers: unique mysql servers pass");

	delete db;
}

static void test_validate_servers_duplicate_mysql() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"servers = ( { hostgroup_id = 1; hostname = \"10.0.0.1\"; port = 3306; },"
		"            { hostgroup_id = 1; hostname = \"10.0.0.1\"; port = 3306; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_servers(
		cfg, PROXYSQL_CONFIG_MYSQL_SERVERS, servers, error);
	ok(result == false, "validate_backend_servers: duplicate mysql servers detected");
	ok(error.find("duplicate") != std::string::npos,
		"validate_backend_servers: error mentions 'duplicate'");
	ok(error.find("mysql_servers") != std::string::npos,
		"validate_backend_servers: error mentions 'mysql_servers'");

	delete db;
}

static void test_validate_servers_duplicate_pgsql() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"servers = ( { hostgroup_id = 1; hostname = \"10.0.0.1\"; port = 5432; },"
		"            { hostgroup_id = 1; hostname = \"10.0.0.1\"; port = 5432; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_servers(
		cfg, PROXYSQL_CONFIG_PGSQL_SERVERS, servers, error);
	ok(result == false, "validate_backend_servers: duplicate pgsql servers detected");
	ok(error.find("pgsql_servers") != std::string::npos,
		"validate_backend_servers: error mentions 'pgsql_servers'");

	delete db;
}

static void test_validate_servers_same_host_different_hostgroup() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"servers = ( { hostgroup_id = 1; hostname = \"10.0.0.1\"; port = 3306; },"
		"            { hostgroup_id = 2; hostname = \"10.0.0.1\"; port = 3306; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_servers(
		cfg, PROXYSQL_CONFIG_MYSQL_SERVERS, servers, error);
	ok(result == true,
		"validate_backend_servers: same host different hostgroup is valid");

	delete db;
}

static void test_validate_servers_same_host_different_port() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"servers = ( { hostgroup_id = 1; hostname = \"10.0.0.1\"; port = 3306; },"
		"            { hostgroup_id = 1; hostname = \"10.0.0.1\"; port = 3307; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_servers(
		cfg, PROXYSQL_CONFIG_MYSQL_SERVERS, servers, error);
	ok(result == true,
		"validate_backend_servers: same host different port is valid");

	delete db;
}

static void test_validate_servers_missing_hostgroup() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"servers = ( { hostname = \"10.0.0.1\"; port = 3306; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_servers(
		cfg, PROXYSQL_CONFIG_MYSQL_SERVERS, servers, error);
	ok(result == false,
		"validate_backend_servers: missing hostgroup rejected");
	ok(error.find("hostgroup_id") != std::string::npos,
		"validate_backend_servers: error mentions 'hostgroup_id'");

	delete db;
}

static void test_validate_servers_missing_hostname() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"servers = ( { hostgroup_id = 1; port = 3306; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_servers(
		cfg, PROXYSQL_CONFIG_MYSQL_SERVERS, servers, error);
	ok(result == false,
		"validate_backend_servers: missing hostname rejected");
	ok(error.find("hostname") != std::string::npos,
		"validate_backend_servers: error mentions 'hostname'");

	delete db;
}

static void test_validate_servers_address_alias() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	// 'address' is an alias for 'hostname'
	Config lc;
	lc.readString(
		"servers = ( { hostgroup_id = 1; address = \"10.0.0.1\"; port = 3306; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_servers(
		cfg, PROXYSQL_CONFIG_MYSQL_SERVERS, servers, error);
	ok(result == true,
		"validate_backend_servers: 'address' accepted as alias for 'hostname'");

	delete db;
}

static void test_validate_servers_hostgroup_alias() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	// 'hostgroup' is an alias for 'hostgroup_id'
	Config lc;
	lc.readString(
		"servers = ( { hostgroup = 1; hostname = \"10.0.0.1\"; port = 3306; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_servers(
		cfg, PROXYSQL_CONFIG_MYSQL_SERVERS, servers, error);
	ok(result == true,
		"validate_backend_servers: 'hostgroup' accepted as alias for 'hostgroup_id'");

	delete db;
}

static void test_validate_servers_default_port_mysql() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	// Two servers with same hostgroup and hostname, no port => both default to 3306 => duplicate
	Config lc;
	lc.readString(
		"servers = ( { hostgroup_id = 1; hostname = \"10.0.0.1\"; },"
		"            { hostgroup_id = 1; hostname = \"10.0.0.1\"; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_servers(
		cfg, PROXYSQL_CONFIG_MYSQL_SERVERS, servers, error);
	ok(result == false,
		"validate_backend_servers: default mysql port 3306 causes duplicate detection");

	delete db;
}

static void test_validate_servers_default_port_pgsql() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	// Two servers with same hostgroup and hostname, no port => both default to 5432 => duplicate
	Config lc;
	lc.readString(
		"servers = ( { hostgroup_id = 1; hostname = \"10.0.0.1\"; },"
		"            { hostgroup_id = 1; hostname = \"10.0.0.1\"; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_servers(
		cfg, PROXYSQL_CONFIG_PGSQL_SERVERS, servers, error);
	ok(result == false,
		"validate_backend_servers: default pgsql port 5432 causes duplicate detection");

	delete db;
}

static void test_validate_servers_empty_list() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString("servers = ( );");
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_backend_servers(
		cfg, PROXYSQL_CONFIG_MYSQL_SERVERS, servers, error);
	ok(result == true, "validate_backend_servers: empty list is valid");

	delete db;
}


// ============================================================
// validate_proxysql_servers() — duplicate ProxySQL server detection
// ============================================================

static void test_validate_proxysql_servers_unique() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"servers = ( { hostname = \"10.0.0.1\"; port = 6032; },"
		"            { hostname = \"10.0.0.2\"; port = 6032; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_proxysql_servers(
		cfg, servers, error);
	ok(result == true, "validate_proxysql_servers: unique servers pass");

	delete db;
}

static void test_validate_proxysql_servers_duplicate() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"servers = ( { hostname = \"10.0.0.1\"; port = 6032; },"
		"            { hostname = \"10.0.0.1\"; port = 6032; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_proxysql_servers(
		cfg, servers, error);
	ok(result == false, "validate_proxysql_servers: duplicate servers detected");
	ok(error.find("duplicate") != std::string::npos,
		"validate_proxysql_servers: error mentions 'duplicate'");
	ok(error.find("proxysql_servers") != std::string::npos,
		"validate_proxysql_servers: error mentions 'proxysql_servers'");

	delete db;
}

static void test_validate_proxysql_servers_same_host_different_port() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"servers = ( { hostname = \"10.0.0.1\"; port = 6032; },"
		"            { hostname = \"10.0.0.1\"; port = 6033; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_proxysql_servers(
		cfg, servers, error);
	ok(result == true,
		"validate_proxysql_servers: same host different port is valid");

	delete db;
}

static void test_validate_proxysql_servers_missing_hostname() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"servers = ( { port = 6032; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_proxysql_servers(
		cfg, servers, error);
	ok(result == false,
		"validate_proxysql_servers: missing hostname rejected");
	ok(error.find("hostname") != std::string::npos,
		"validate_proxysql_servers: error mentions 'hostname'");

	delete db;
}

static void test_validate_proxysql_servers_missing_port() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"servers = ( { hostname = \"10.0.0.1\"; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_proxysql_servers(
		cfg, servers, error);
	ok(result == false,
		"validate_proxysql_servers: missing port rejected");
	ok(error.find("port") != std::string::npos,
		"validate_proxysql_servers: error mentions 'port'");

	delete db;
}

static void test_validate_proxysql_servers_address_alias() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString(
		"servers = ( { address = \"10.0.0.1\"; port = 6032; } );"
	);
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_proxysql_servers(
		cfg, servers, error);
	ok(result == true,
		"validate_proxysql_servers: 'address' accepted as alias for 'hostname'");

	delete db;
}

static void test_validate_proxysql_servers_empty_list() {
	SQLite3DB* db = create_test_db();
	ProxySQL_Config cfg(db);
	std::string error;

	Config lc;
	lc.readString("servers = ( );");
	const Setting& root = lc.getRoot();
	const Setting& servers = root["servers"];

	bool result = ProxySQL_Config_TestHelper::validate_proxysql_servers(
		cfg, servers, error);
	ok(result == true, "validate_proxysql_servers: empty list is valid");

	delete db;
}


// ============================================================
// main
// ============================================================

int main() {
	plan(54);

	test_init_minimal();

	// addField tests (12)
	test_addField_basic();          // 5 checks
	test_addField_null_value();     // 1 check
	test_addField_empty_value();    // 1 check
	test_addField_custom_delimiter(); // 2 checks
	test_addField_escapes_quotes(); // 1 check
	test_addField_accumulates();    // 2 checks
	test_addField_equals_format();  // 1 check (subtotal: 13 -- recount below)

	// validate_backend_users tests
	test_validate_users_unique_mysql();             // 2
	test_validate_users_duplicate_mysql();           // 3
	test_validate_users_duplicate_pgsql();           // 2
	test_validate_users_same_name_different_backend(); // 1
	test_validate_users_missing_username();           // 2
	test_validate_users_default_backend();            // 1
	test_validate_users_empty_list();                 // 1
	test_validate_users_single_entry();               // 1

	// validate_backend_servers tests
	test_validate_servers_unique_mysql();             // 1
	test_validate_servers_duplicate_mysql();           // 3
	test_validate_servers_duplicate_pgsql();           // 2
	test_validate_servers_same_host_different_hostgroup(); // 1
	test_validate_servers_same_host_different_port(); // 1
	test_validate_servers_missing_hostgroup();         // 2
	test_validate_servers_missing_hostname();          // 2
	test_validate_servers_address_alias();             // 1
	test_validate_servers_hostgroup_alias();           // 1
	test_validate_servers_default_port_mysql();        // 1
	test_validate_servers_default_port_pgsql();        // 1
	test_validate_servers_empty_list();                // 1

	// validate_proxysql_servers tests
	test_validate_proxysql_servers_unique();           // 1
	test_validate_proxysql_servers_duplicate();         // 3
	test_validate_proxysql_servers_same_host_different_port(); // 1
	test_validate_proxysql_servers_missing_hostname();  // 2
	test_validate_proxysql_servers_missing_port();      // 2
	test_validate_proxysql_servers_address_alias();     // 1
	test_validate_proxysql_servers_empty_list();        // 1

	test_cleanup_minimal();
	return exit_status();
}
