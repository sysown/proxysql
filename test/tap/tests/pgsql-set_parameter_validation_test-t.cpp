/**
 * @file pgsql-set_parameter_validation_test-t.cpp
 * @brief This TAP test validates if session parameter validation is working correctly.
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

struct SetCommandTest {
    std::string command;
    bool expect_success;
    std::string expected_value;
};

struct SetTestCase {
    std::string param_name;
    std::vector<SetCommandTest> commands;
};

std::vector<SetTestCase> test_cases = {
    {"client_encoding", {
        // Valid values
        { "SET client_encoding TO 'UTF8'", true, "UTF8" },
        {"SET client_encoding = 'LATIN1'", true, "LATIN1"},
        {"SET client_encoding = 'WIN1252'", true, "WIN1252"},
        {"SET client_encoding = 'SQL_ASCII'", true, "SQL_ASCII"},
        {"SET client_encoding = 'UNICODE'", true, "UNICODE"},
        // Invalid values
        {"SET client_encoding = 1234", false, ""},
        {"SET client_encoding = true", false, ""}
    }},
    {"datestyle", {
        // Valid combinations
        {"SET datestyle = 'ISO, MDY'", true, "ISO, MDY"},
        {"SET datestyle TO 'Postgres, DMY'", true, "Postgres, DMY"},
        {"SET datestyle TO 'YMD'", true, "Postgres, YMD"},
        {"SET datestyle = 'German, YMD'", true, "German, YMD"},
        {"SET datestyle = 'DMY'", true, "German, DMY"},
        {"SET datestyle = 'SQL, YMD'", true, "SQL, YMD"},
        {"SET datestyle TO 'PostgreSQL, DMY'", true, "Postgres, DMY"},
        {"SET datestyle TO 'PostgreSQL, NONEUROPEAN'", true, "Postgres, MDY"},
        {"SET datestyle TO 'PostgreSQL, US'", true, "Postgres, MDY"},
        {"SET datestyle TO 'PostgreSQL, European'", true, "Postgres, DMY"},
        // Invalid combinations
        {"SET datestyle = 'INVALID'", false, ""},
        {"SET datestyle = 'ISO, INVALID'", false, ""},
        {"SET datestyle = 'Postgres, YODA'", false, ""},
        {"SET datestyle = 1234", false, ""},
        {"SET datestyle = 'InvalidStyle'", false, ""}
    }},
    {"intervalstyle", {
        // Valid values
        {"SET intervalstyle = 'iso_8601'", true, "iso_8601"},
        {"SET intervalstyle TO 'postgres'", true, "postgres"},
        {"SET intervalstyle = 'postgres_verbose'", true, "postgres_verbose"},
        {"SET intervalstyle = 'sql_standard'", true, "sql_standard"},
        // Invalid values
        {"SET intervalstyle = 'invalid_style'", false, ""},
        {"SET intervalstyle = 1234", false, ""},
        {"SET intervalstyle = true", false, ""}
    }},
    {"standard_conforming_strings", {
        // Valid values
        {"SET standard_conforming_strings = on", true, "on"},
        {"SET standard_conforming_strings TO off", true, "off"},
        {"SET standard_conforming_strings = true", true, "on"},
        {"SET standard_conforming_strings = false", true, "off"},
        {"SET standard_conforming_strings = '1'", true, "on"},
        {"SET standard_conforming_strings = '0'", true, "off"},
        {"SET standard_conforming_strings = 'yes'", true, "on"},
        {"SET standard_conforming_strings = 'no'", true, "off"},
        // Invalid values
        {"SET standard_conforming_strings = 'maybe'", false, ""}
    }},
    /*{"timezone", {
        // Valid values
        {"SET timezone TO 'UTC'", true, "UTC"},
        {"SET timezone = 'Europe/Berlin'", true, "Europe/Berlin"},
        {"SET timezone = 'America/New_York'", true, "America/New_York"},
        {"SET timezone = 'PST8PDT'", true, "PST8PDT"},
        // Invalid values
        {"SET timezone = 'Invalid/Zone'", false, ""},
        {"SET timezone = 1234", false, ""},
        {"SET timezone = 'NOW'", false, ""}  // 'NOW' is only valid for time zone
    }},
    {"time zone", {
        // Valid values
        {"SET TIME ZONE 'UTC'", true, "UTC"},
        {"SET TIME ZONE LOCAL", true, "LOCAL"},
        {"SET TIME ZONE DEFAULT", true, "DEFAULT"},
        {"SET TIME ZONE INTERVAL '+02:00'", true, "02:00"},
        // Invalid values
        {"SET TIME ZONE 'Invalid/Zone'", false, ""},
        {"SET TIME ZONE 1234", false, ""},
        {"SET TIME ZONE 'PST8PDT WITH SPACE'", false, ""}
    }},*/
    {"allow_in_place_tablespaces", {
        // Valid values
        {"SET allow_in_place_tablespaces = on", true, "on"},
        {"SET allow_in_place_tablespaces TO off", true, "off"},
        {"SET allow_in_place_tablespaces = 'yes'", true, "on"},
        {"SET allow_in_place_tablespaces = 1", true, "on"},
		{"SET allow_in_place_tablespaces = 'no'", true, "off"},
		{"SET allow_in_place_tablespaces = 0", true, "off"},
        // Invalid values
        {"SET allow_in_place_tablespaces = 'toggle'", false, ""}
    }},
    {"bytea_output", {
        // Valid values
        {"SET bytea_output = 'hex'", true, "hex"},
        {"SET bytea_output TO 'escape'", true, "escape"},
        // Invalid values
        {"SET bytea_output = 'base64'", false, ""},
        {"SET bytea_output = 1234", false, ""},
        {"SET bytea_output = true", false, ""}
    }},
    {"client_min_messages", {
        // Valid values
        {"SET client_min_messages = 'debug5'", true, "debug5"},
        {"SET client_min_messages TO 'debug4'", true, "debug4"},
        {"SET client_min_messages = 'debug3'", true, "debug3"},
        {"SET client_min_messages = 'debug2'", true, "debug2"},
        {"SET client_min_messages = 'debug1'", true, "debug1"},
        {"SET client_min_messages = 'log'", true, "log"},
        {"SET client_min_messages = 'notice'", true, "notice"},
        {"SET client_min_messages = 'warning'", true, "warning"},
        {"SET client_min_messages = 'error'", true, "error"},
        // Invalid values
        {"SET client_min_messages = 'critical'", false, ""},
        {"SET client_min_messages = 5", false, ""},
        {"SET client_min_messages = true", false, ""}
    }},
    {"enable_bitmapscan", {
        // Valid values
        {"SET enable_bitmapscan = on", true, "on"},
        {"SET enable_bitmapscan TO off", true, "off"},
         {"SET enable_bitmapscan = 'yes'", true, "on"},
		{"SET enable_bitmapscan = 1", true, "on"},
		{"SET enable_bitmapscan = 'no'", true, "off"},
        // Invalid values
        {"SET enable_bitmapscan = 'toggle'", false, ""}
    }},
    {"enable_hashjoin", {
        // Valid values
        {"SET enable_hashjoin = on", true, "on"},
        {"SET enable_hashjoin TO off", true, "off"},
        {"SET enable_hashjoin = true", true, "on"},
        {"SET enable_hashjoin = false", true, "off"},
        {"SET enable_hashjoin = '1'", true, "on"},
        {"SET enable_hashjoin = '0'", true, "off"},
        {"SET enable_hashjoin = 'yes'", true, "on"},
        {"SET enable_hashjoin = 'no'", true, "off"},
        // Invalid values
        {"SET enable_hashjoin = 'maybe'", false, ""},
        {"SET enable_hashjoin = 1234", false, ""},
    }},
    {"enable_indexscan", {
        // Valid values
        {"SET enable_indexscan = on", true, "on"},
        {"SET enable_indexscan TO off", true, "off"},
        {"SET enable_indexscan = 'yes'", true, "on"},
		{"SET enable_indexscan = 1", true, "on"},
		{"SET enable_indexscan = 'no'", true, "off"},
        // Invalid values
        {"SET enable_indexscan = 'disabled'", false, ""}
    }},
    {"enable_nestloop", {
        // Valid values
        {"SET enable_nestloop TO on", true, "on"},
        {"SET enable_nestloop = off", true, "off"},
		{"SET enable_nestloop = 'yes'", true, "on"},
		{"SET enable_nestloop = 1", true, "on"},
		{"SET enable_nestloop = 'no'", true, "off"},
        // Invalid values
        {"SET enable_nestloop = 'sometimes'", false, ""},
        {"SET enable_nestloop = 1234", false, ""},
    }},
    {"enable_seqscan", {
        // Valid values
        {"SET enable_seqscan = on", true, "on"},
        {"SET enable_seqscan TO off", true, "off"},
		{"SET enable_seqscan = 'yes'", true, "on"},
		{"SET enable_seqscan = 1", true, "on"},
		{"SET enable_seqscan = 'no'", true, "off"},
        {"SET enable_seqscan = 0", true, "off"},
        {"SET enable_seqscan = 'false'", true, "off"},
        // Invalid values
        {"SET enable_seqscan = 'never'", false, ""},
    }},
    {"enable_sort", {
        // Valid values
        {"SET enable_sort TO on", true, "on"},
        {"SET enable_sort = off", true, "off"},
		{"SET enable_sort = 'yes'", true, "on"},
		{"SET enable_sort = 1", true, "on"},
		{"SET enable_sort = 'no'", true, "off"},
        // Invalid values
        {"SET enable_sort = 'maybe'", false, ""},
        {"SET enable_sort = 1234", false, ""},
    }},
    {"escape_string_warning", {
        // Valid values
        {"SET escape_string_warning = on", true, "on"},
        {"SET escape_string_warning TO off", true, "off"},
		{"SET escape_string_warning = true", true, "on"},
		{"SET escape_string_warning = false", true, "off"},
		{"SET escape_string_warning = '1'", true, "on"},
		{"SET escape_string_warning = '0'", true, "off"},
		{"SET escape_string_warning = 'yes'", true, "on"},
		{"SET escape_string_warning = 'no'", true, "off"},
        // Invalid values
        {"SET escape_string_warning = 'ignore'", false, ""}
    }},
    {"extra_float_digits", {
        // Valid range -15 to 3
        {"SET extra_float_digits TO 1", true, "1"},
        {"SET extra_float_digits = 3", true, "3"},
        {"SET extra_float_digits = -15", true, "-15"},
        {"SET extra_float_digits TO 0", true, "0"},
		{"SET extra_float_digits = 2", true, "2"},
		{"SET extra_float_digits = -5", true, "-5"},
        {"SET extra_float_digits = 2.4", true, "2"},
        {"SET extra_float_digits = 2.51", true, "3"},
        {"SET extra_float_digits = -5.5", true, "-6"},
        // Invalid values
        {"SET extra_float_digits = 4", false, ""},
        {"SET extra_float_digits = '-16'", false, ""},
        {"SET extra_float_digits = 'five'", false, ""},
		{"SET extra_float_digits = 1234", false, ""}
    }},
    {"maintenance_work_mem", {
        // Valid values
        {"SET maintenance_work_mem = '64MB'", true, "64MB"},
        {"SET maintenance_work_mem TO '128MB'", true, "128MB"},
        {"SET maintenance_work_mem = '1GB'", true, "1GB"},
		{"SET maintenance_work_mem = '1024kB'", true, "1MB"},
		{"SET maintenance_work_mem = '1TB'", true, "1TB"},
		{"SET maintenance_work_mem = '1.5GB'", true, "1536MB"},
        // Invalid values
        {"SET maintenance_work_mem = '64XB'", false, ""},
        {"SET maintenance_work_mem = '-128MB'", false, ""},
        {"SET maintenance_work_mem = 'invalid'", false, ""},
        {"SET maintenance_work_mem = 128", false, ""},
        {"SET maintenance_work_mem = 12345678901", false, ""}
    }},
    {"synchronous_commit", {
        // Valid values
        {"SET synchronous_commit TO on", true, "on"},
        {"SET synchronous_commit = 'off'", true, "off"},
        {"SET synchronous_commit = 'local'", true, "local"},
        {"SET synchronous_commit = 'remote_apply'", true, "remote_apply"},
        {"SET synchronous_commit TO 'remote_write'", true, "remote_write"},
        // Invalid values
        {"SET synchronous_commit = 'maybe'", false, ""},
        {"SET synchronous_commit = 1", false, ""},
        {"SET synchronous_commit = 'sync'", false, ""}
    }},
    { "search_path", {
        // Valid values
        {"SET search_path TO \"$user\", public", true, "\"$user\", public"},
        {"SET search_path TO \"$user\",public", true, "\"$user\", public"},
        {"SET search_path = '\"$user\"   ,    public'", true, "\"\"\"$user\"\" , public\""},
        {"SET search_path = 'public '", true, "\"public \""},
        {"SET search_path = \"$user\"", true, "\"$user\""},
        {"SET search_path = '$user'", true, "\"$user\""},
        {"SET search_path = ''", true, "\"\""},
        {"SET search_path = 'public,,schema1'", true, "\"public,,schema1\""},
        {"SET search_path = 'public , , schema1'", true, "\"public , , schema1\""},
        {"SET search_path = public", true, "public"},
        {"SET search_path = unquoted_schema, public", true, "unquoted_schema, public"},
        {"SET search_path = \"MixedCase\", public", true, "\"MixedCase\", public"},
        {"SET search_path = pg_catalog, \"$user\"", true, "pg_catalog, \"$user\""},
        {"SET search_path = 'pg_catalog , \"$user\"'", true, "\"pg_catalog , \"\"$user\"\"\""},
        {"SET search_path = \"sch-1\", \"sch 2\"", true, "\"sch-1\", \"sch 2\""},
        {"SET search_path TO \"$USER\"", true, "\"$USER\""}, // quoted USER, case-sensitive
        {"SET search_path = ',public'", true, "\",public\""},
        {"SET search_path = public,schema1", true, "public, schema1"},
        {"SET search_path = ',,'", true, "\",,\""},
        {"SET search_path = '123schema, public'", true, "\"123schema, public\""},
        {"SET search_path = ' '", true, "\" \""},
        {"SET search_path = schema$1", true, "\"schema$1\""},
        {"SET search_path TO \"123456789012345678901234567890123456789012345678901234567890123\"", true, "\"123456789012345678901234567890123456789012345678901234567890123\""},
        {"SET search_path TO \"$user\" ,", true, "\"$user\""}, // trailing comma will be stripped
        // Invalid values
        {"SET search_path = \"unclosed_quote, public", false, ""},
        {"SET search_path = ,public", false, ""},
        {"SET search_path = public,,schema1", false, ""},
        {"SET search_path = ,,", false, ""},
        {"SET search_path = \"$user\", \"$invalid\"@schema", false, ""},
        {"SET search_path = 123schema, public", false, ""},
        {"SET search_path = $user", false, ""},
        {"SET search_path = \"unclosed_quote, public", false, ""},
        {"SET search_path = \"schema1\" \"schema2\"", false, ""},
        {"SET search_path = \"\\\"unterminated\"", false, ""},
        {"SET search_path = \"valid\",, \"invalid\"", false, ""},
        {"SET search_path = $schema1", false, ""},
        {"SET search_path TO \"1234567890123456789012345678901234567890123456789012345678901234\"", false, ""}, // 63 chars max length
        {"SET search_path TO `123`", false, ""}  // backticks, invalid characters
    }}
};

int main(int argc, char** argv) {
    int total_tests = 0;

	for (const auto& test_case : test_cases) {
		total_tests += test_case.commands.size();
	}
   
    plan(total_tests);

    if (cl.getEnv())
        return exit_status();

    PGConnPtr conn = createNewConnection(ConnType::BACKEND, "", false);
    if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
        BAIL_OUT("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
        return exit_status();
    }

    for (const auto& test_case : test_cases) {
        for (const auto& cmd_test : test_case.commands) {
           
            bool test_ok = true;
            std::string error_msg;


            // Get initial parameter value
            std::string show_cmd;
            if (test_case.param_name.find(' ') != std::string::npos) {
                show_cmd = "SHOW \"" + test_case.param_name + "\"";
            }
            else {
                show_cmd = "SHOW " + test_case.param_name;
            }

            PGresult* res_initial = PQexec(conn.get(), show_cmd.c_str());
            if (PQresultStatus(res_initial) != PGRES_TUPLES_OK || PQntuples(res_initial) < 1) {
                error_msg = "Initial SHOW failed: " + std::string(PQerrorMessage(conn.get()));
                test_ok = false;
            }

            std::string initial_value = test_ok ? PQgetvalue(res_initial, 0, 0) : "";
            PQclear(res_initial);

            if (test_ok) {
                // Execute SET command
                PGresult* res_set = PQexec(conn.get(), cmd_test.command.c_str());
                const bool actual_success = PQresultStatus(res_set) == PGRES_COMMAND_OK;

                if (actual_success != cmd_test.expect_success) {
                    error_msg = "Expected " + std::string(cmd_test.expect_success ? "success" : "failure") +
                        " but got " + std::string(actual_success ? "success" : "failure");
                    test_ok = false;
                }

                // Get new parameter value
                PGresult* res_new = PQexec(conn.get(), show_cmd.c_str());
                if (PQresultStatus(res_new) != PGRES_TUPLES_OK || PQntuples(res_new) < 1) {
                    error_msg += " Post-SHOW failed: " + std::string(PQerrorMessage(conn.get()));
                    test_ok = false;
                }

                const std::string new_value = test_ok ? PQgetvalue(res_new, 0, 0) : "";
                PQclear(res_new);

                if (cmd_test.expect_success) {
                    if (new_value != cmd_test.expected_value) {
                        error_msg = "Expected '" + cmd_test.expected_value +
                            "' got '" + new_value + "'";
                        test_ok = false;
                    }
                }
                else {
                    if (new_value != initial_value) {
                        error_msg = "Value changed unexpectedly from '" +
                            initial_value + "' to '" + new_value + "'";
                        test_ok = false;
                    }
                }
                PQclear(res_set);
            }

            ok(test_ok, "%s: %s (%s)", test_case.param_name.c_str(), cmd_test.command.c_str(), error_msg.c_str());
        }
    }
    return exit_status();
}
