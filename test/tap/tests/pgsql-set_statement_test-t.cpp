/**
 * @file pgsql-set_statement_test-t.cpp
 * @brief Intention: not to test every PostgreSQL variable, but to ensure different forms of SET statements
 *        are parsed correctly and not wrongly locked on a hostgroup. Covers common syntaxes (`=`, TO,
 *        multi-word params, aliases) and checks that unsupported forms like LOCAL or function-style values
 *        trigger the expected hostgroup lock behavior.
 */

#include <unistd.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType {
    ADMIN,
    BACKEND
};

PGConnPtr createNewConnection(ConnType conn_type, const std::string& options = "", bool with_ssl = false) {
    
    const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
    int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
    const char* username = (conn_type == BACKEND) ? cl.pgsql_root_username : cl.admin_username;
    const char* password = (conn_type == BACKEND) ? cl.pgsql_root_password : cl.admin_password;

    std::stringstream ss;

    ss << "host=" << host << " port=" << port;
    ss << " user=" << username << " password=" << password;
    ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

    if (options.empty() == false) {
		ss << " options='" << options << "'";
    }

    PGconn* conn = PQconnectdb(ss.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection failed to '%s': %s", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
        PQfinish(conn);
        return PGConnPtr(nullptr, &PQfinish);
    }
    return PGConnPtr(conn, &PQfinish);
}

struct TestCase {
    std::string sql;
    bool should_not_lock_on_hostgroup;
    std::string description;
};

std::fstream f_proxysql_log{};

bool check_logs_for_command(const std::string& command_regex) {
    const auto& [_, cmd_lines] { get_matching_lines(f_proxysql_log, command_regex) };
    return !cmd_lines.empty();
}

bool run_set_statement(const std::string& stmt, ConnType type = BACKEND) {
    PGConnPtr conn = createNewConnection(type);
    if (!conn) return false;

    PGresult* res = PQexec(conn.get(), stmt.c_str());
    if (PQresultStatus(res) != PGRES_COMMAND_OK) {
        PQclear(res);
        return false;
    }
    PQclear(res);

    return check_logs_for_command(".*\\[WARNING\\] Unable to parse unknown SET query from client.*") == false;
}

int main(int argc, char** argv) {

    std::vector<TestCase> tests = {
        // Standard param/value
        {"SET datestyle = 'ISO, MDY';", true, "datestyle with ="},
        {"SET datestyle TO 'ISO,MDY';", true, "datestyle with TO"},
        {"SET standard_conforming_strings TO on;", true, "boolean ON"},
        {"SET enable_seqscan = off;", true, "boolean OFF"},
        {"SET SESSION datestyle = 'ISO, DMY';", true, "SESSION prefix"},

        // TIME ZONE
        {"SET TIME ZONE 'UTC';", true, "TIME ZONE UTC"},
        {"SET TIME ZONE DEFAULT;", true, "TIME ZONE DEFAULT"},
        {"SET TIME ZONE -7;", true, "TIME ZONE numeric offset"},
        {"SET TIME ZONE INTERVAL '+02:30' HOUR TO MINUTE;", true, "TIME ZONE interval"},

        // TRANSACTION ISOLATION LEVEL
        {"SET TRANSACTION ISOLATION LEVEL READ UNCOMMITTED;", false, "TX ISOLATION READ UNCOMMITTED"},
        {"SET TRANSACTION ISOLATION LEVEL READ COMMITTED;", false, "TX ISOLATION READ COMMITTED"},
        {"SET TRANSACTION ISOLATION LEVEL REPEATABLE READ;", false, "TX ISOLATION REPEATABLE READ"},
        {"SET TRANSACTION ISOLATION LEVEL SERIALIZABLE;", false, "TX ISOLATION SERIALIZABLE"},

        // XML OPTION
        {"SET XML OPTION DOCUMENT;", false, "XML OPTION DOCUMENT"},
        {"SET XML OPTION CONTENT;", false, "XML OPTION CONTENT"},

        // SESSION AUTHORIZATION
        {"SET SESSION AUTHORIZATION DEFAULT;", false, "SESSION AUTHORIZATION DEFAULT"},

        // ROLE
        {"SET ROLE NONE;", false, "ROLE NONE"},

        // SCHEMA
        {"SET SCHEMA 'pg_catalog';", false, "SCHEMA valid"},

        // NAMES
        {"SET NAMES SQL_ASCII;", true, "NAMES SQL_ASCII"},
        {"SET NAMES UTF8;", true, "NAMES UTF8"},

        // SEARCH_PATH
		{"SET search_path TO 'pg_catalog';", true, "search_path single schema"},
		{"SET search_path TO 'schema1, schema2';", true, "search_path multiple schemas"},
		{"SET search_path TO '\"MySchema\"';", true, "search_path quoted identifier"},
		{"SET search_path TO 'schema1, \"MySchema\"';", true, "search_path mixed identifiers"},
		{"SET search_path TO 'schema1, pg_catalog';", true, "search_path with pg_catalog"},
		{"SET search_path TO '$user, public';", true, "search_path with $user"},
		{"SET search_path TO 'public, $user';", true, "search_path with $user at end"},
		{"SET search_path TO 'public, $user, pg_catalog';", true, "search_path with $user and pg_catalog"},
		{"SET search_path TO '\"$user\"';", true, "search_path with quoted $user"},
		{"SET search_path TO '\"$user\", pg_catalog';", true, "search_path with quoted $user and pg_catalog"},
		{"SET search_path TO '\"$user\", public';", true, "search_path with quoted $user and public"},
		{"SET search_path TO 'public, \"$user\"';", true, "search_path with public and quoted $user"},
		{"SET search_path TO '\"$user\", public, pg_catalog';", true, "search_path with quoted $user, public and pg_catalog"},
		{"SET search_path = 'public, \"$user\", pg_catalog';", true, "search_path with public, quoted $user and pg_catalog"},
		{"SET search_path = '\"MySchema\", pg_catalog';", true, "search_path with quoted identifier and pg_catalog"},
		{"SET search_path = '\"MySchema\", public';", true, "search_path with quoted identifier and public"},
		{"SET search_path = 'public, \"MySchema\"';", true, "search_path with public and quoted identifier"},
		{"SET search_path = '\"MySchema\", public, pg_catalog';", true, "search_path with quoted identifier, public and pg_catalog"},
		{"SET search_path = 'public, \"MySchema\", pg_catalog';", true, "search_path with public, quoted identifier and pg_catalog"},
		{"SET search_path = 'schema1, \"MySchema\", schema2';", true, "search_path multiple mixed identifiers"},
		{"SET search_path = ''; ", true, "search_path empty string"},
		{"SET search_path = ' , , '; ", true, "search_path only commas and spaces"},
		{"SET search_path = ',public,'; ", true, "search_path leading and trailing commas"},

        // SEED
        {"SET SEED 0.5;", false, "SEED 0.5"},
        {"SET SEED 0;", false, "SEED 0"},
        {"SET SEED 1;", false, "SEED 1"},
        {"SET SEED 1.5;", false, "SEED out of range"},

        // Failure cases
        {"SET ALL TO DEFAULT;", false, "ALL should fail"},
        {"SET LOCAL datestyle TO 'ISO,MDY';", false, "LOCAL should fail"},
        {"SET search_path TO current_schemas(true);", false, "function value should fail"},
        {"SET datestyle = ;", false, "missing value"}
    };
   
    plan(tests.size());

    if (cl.getEnv())
        return exit_status();

    std::string f_path{ get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log" };

    int of_err = open_file_and_seek_end(f_path, f_proxysql_log);
    if (of_err != EXIT_SUCCESS) {
        return exit_status();
    }

    for (const auto& t : tests) {
        f_proxysql_log.clear(f_proxysql_log.rdstate() & ~std::ios_base::failbit);
        f_proxysql_log.seekg(f_proxysql_log.tellg());
        bool result = run_set_statement(t.sql);
        ok(result == t.should_not_lock_on_hostgroup, "%s", t.description.c_str());
        usleep(10000);
    }

    f_proxysql_log.close();
    return exit_status();
}
