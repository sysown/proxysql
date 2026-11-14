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
#include "json.hpp"

using nlohmann::json;

CommandLine cl;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType {
    ADMIN,
    BACKEND,
    CLIENT
};

PGConnPtr createNewConnection(ConnType conn_type, const std::string& options = "", bool with_ssl = false) {
    const char* host = (conn_type == ADMIN) ? cl.pgsql_admin_host : cl.pgsql_host;
    int port = (conn_type == ADMIN) ? cl.pgsql_admin_port : cl.pgsql_port;
    const char* username = (conn_type == ADMIN) ? cl.admin_username :
        (conn_type == BACKEND ? cl.pgsql_root_username : cl.pgsql_username);
    const char* password = (conn_type == ADMIN) ? cl.admin_password :
        (conn_type == BACKEND ? cl.pgsql_root_password : cl.pgsql_password);
    const char* connection_name = (conn_type == ADMIN) ? "Admin" :
        (conn_type == BACKEND ? "Backend" : "Client");

    std::stringstream ss;

    ss << "host=" << host << " port=" << port;
    ss << " user=" << username << " password=" << password;
    ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

    if (options.empty() == false) {
		ss << " options='" << options << "'";
    }

    PGconn* conn = PQconnectdb(ss.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection failed to '%s': %s", connection_name, PQerrorMessage(conn));
        PQfinish(conn);
        return PGConnPtr(nullptr, &PQfinish);
    }
    return PGConnPtr(conn, &PQfinish);
}

std::string queryCurrentUser(PGconn* conn) {
    PGresult* res = PQexec(conn, "SELECT current_user");
    std::string username;
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {
        username = PQgetvalue(res, 0, 0);
    }
    PQclear(res);
    return username;
}

struct SetCommandTest {
    std::string command;
    bool expect_success;
    std::string expected_value;
    // Optional override for `pgsql-set_parser_algorithm = 3` (the ParserSQL
    // walker path). Some cases like #150 below have algorithm-dependent SHOW
    // output: under algorithms 0/1/2 the regex-based SET parser runs
    // remove_spaces() on the whole query (including inside string literals,
    // which is destructive but historical), so values like
    // `'"$user"   ,    public'` reach PG already collapsed to
    // `'"$user" , public'`. The walker (algo 3) keeps the original input,
    // so PG stores and SHOWs the multi-space version verbatim -- which is
    // actually PG's correct behaviour, but diverges from algorithms 0/1/2.
    // If `expected_value_algo3` is non-empty, the test uses it when running
    // against a proxysql configured with algo 3; otherwise the same
    // `expected_value` is used regardless of algorithm.
    std::string expected_value_algo3;
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
        {"SET timezone = 'INTERVALfoo'", false, ""},
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
        // Algorithm-dependent: under algo 0/1/2 proxysql's remove_spaces()
        // destructively collapses internal whitespace inside the string
        // literal before sending to PG, so PG sees `'"$user" , public'` and
        // SHOWs `"""$user"" , public"`. Under algo 3 (ParserSQL walker)
        // the original multi-space input reaches PG unchanged and SHOW
        // returns `"""$user""   ,    public"`. Both are accepted; the
        // walker's behaviour is closer to what PG would do without proxysql
        // in the path.
        {"SET search_path = '\"$user\"   ,    public'", true,
            "\"\"\"$user\"\" , public\"",
            "\"\"\"$user\"\"   ,    public\""},
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

// Query proxysql admin for the currently-configured pgsql-set_parser_algorithm.
// Returns 0/1/2/3 or -1 if the lookup fails (treated as "use default expected"
// downstream, which is the algo 0/1/2 column).
static int query_pgsql_set_parser_algorithm() {
    PGConnPtr admin = createNewConnection(ConnType::ADMIN, "", false);
    if (!admin || PQstatus(admin.get()) != CONNECTION_OK) return -1;
    PGresult* r = PQexec(admin.get(),
        "SELECT variable_value FROM global_variables "
        "WHERE variable_name = 'pgsql-set_parser_algorithm'");
    int algo = -1;
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) >= 1) {
        try { algo = std::stoi(PQgetvalue(r, 0, 0)); } catch (...) {}
    }
    PQclear(r);
    return algo;
}

// ---------------------------------------------------------------------------
// SET of a setting ProxySQL does not track, whose name starts with one it does
// (issue #6431). Such a SET used to take the tracked-variable path, where the
// unknown name made ProxySQL forward it without locking the hostgroup: the
// backend connection went back to the pool still carrying the setting, and the
// next client to get it inherited it. Now the session must be locked on its
// hostgroup, so the connection is reset before anyone else can use it.
//
// To make the leak observable the client's hostgroup is limited to a single
// backend connection, so client B can only get the one client A used.
// ---------------------------------------------------------------------------

struct UntrackedSetCase {
    std::string set;        // run by client A
    std::string name;       // setting read back by client B
    std::string leaked;     // what B sees if A's setting reached it
};

static const std::vector<UntrackedSetCase> untracked_set_cases = {
    { "SET timezone_abbreviations = 'India'", "timezone_abbreviations", "India" },
    { "SET timezone.foo = 'x'", "timezone.foo", "x" },
};
static const int UNTRACKED_SET_TESTS_PER_CASE = 3;

static bool execAdmin(PGconn* admin, const std::string& q) {
    PGresult* r = PQexec(admin, q.c_str());
    const ExecStatusType st = PQresultStatus(r);
    const bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
    if (!good) diag("admin failed: %s -- %s", q.c_str(), PQerrorMessage(admin));
    PQclear(r);
    return good;
}

static std::string sqlQuote(const std::string& v) {
    std::string out = "'";
    for (char c : v) { if (c == '\'') out += "''"; else out += c; }
    out += "'";
    return out;
}

static std::string adminGet(PGconn* admin, const std::string& name) {
    PGresult* r = PQexec(admin, ("SELECT variable_value FROM global_variables WHERE variable_name=" + sqlQuote(name)).c_str());
    const std::string v = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) ? PQgetvalue(r, 0, 0) : "";
    PQclear(r);
    return v;
}

static bool adminSet(PGconn* admin, const std::string& name, const std::string& value) {
    return execAdmin(admin, "SET " + name + "=" + sqlQuote(value)) && execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

static const char* SERVER_COLS =
    "hostgroup_id,hostname,port,status,weight,compression,max_connections,"
    "max_replication_lag,use_ssl,max_latency_ms,comment";

// The hostgroup's servers, as the INSERT statements that recreate them.
static std::vector<std::string> snapshotServers(PGconn* admin, int hg) {
    std::vector<std::string> inserts;
    const std::string sel = "SELECT " + std::string(SERVER_COLS) +
        " FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(hg);
    PGresult* res = PQexec(admin, sel.c_str());
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        for (int r = 0; r < PQntuples(res); r++) {
            std::string ins = "INSERT INTO pgsql_servers (" + std::string(SERVER_COLS) + ") VALUES (";
            for (int c = 0; c < PQnfields(res); c++) {
                if (c) ins += ",";
                ins += PQgetisnull(res, r, c) ? "NULL" : sqlQuote(PQgetvalue(res, r, c));
            }
            inserts.push_back(ins + ")");
        }
    } else {
        diag("cannot read pgsql_servers for hostgroup %d: %s", hg, PQerrorMessage(admin));
    }
    PQclear(res);
    return inserts;
}

// Puts the hostgroup's servers back as 'inserts', or with 'single_conn' only the first of
// them, capped at one connection: max_connections is per server, so with a second endpoint
// client B could reach another backend and pass without ever reusing A's connection.
// Removing them first closes every pooled connection, so the cap holds from here on.
static bool reloadServers(PGconn* admin, int hg, const std::vector<std::string>& inserts, bool single_conn) {
    const std::string hg_s = std::to_string(hg);
    if (!execAdmin(admin, "DELETE FROM pgsql_servers WHERE hostgroup_id=" + hg_s)) return false;
    if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    for (const auto& q : inserts) {
        if (!execAdmin(admin, q)) return false;
        if (single_conn) break;
    }
    if (single_conn &&
        !execAdmin(admin, "UPDATE pgsql_servers SET max_connections=1 WHERE hostgroup_id=" + hg_s)) {
        return false;
    }
    if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    usleep(200000); // let the servers come back online before anyone connects
    return true;
}

static int lockedOnHostgroup(PGconn* conn) {
    PGresult* res = PQexec(conn, "PROXYSQL INTERNAL SESSION");
    int hg = -2;
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {
        try {
            const json j = json::parse(PQgetvalue(res, 0, 0));
            hg = j.at("locked_on_hostgroup").get<int>();
        } catch (const std::exception& e) {
            diag("cannot parse PROXYSQL INTERNAL SESSION: %s", e.what());
        }
    } else {
        diag("PROXYSQL INTERNAL SESSION failed: %s", PQerrorMessage(conn));
    }
    PQclear(res);
    return hg;
}

// Schema-qualified on purpose: ProxySQL answers a bare 'SELECT pg_backend_pid()'
// itself, with an id of its own rather than the backend's.
static std::string backendPid(PGconn* conn) {
    PGresult* res = PQexec(conn, "SELECT pg_catalog.pg_backend_pid()");
    std::string pid = (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) ? PQgetvalue(res, 0, 0) : "";
    PQclear(res);
    return pid;
}

// The default hostgroup of the root user, the one BACKEND connections use; -1 if unknown.
static int rootDefaultHostgroup(PGconn* admin) {
    std::string hg_s;
    if (admin) {
        PGresult* res = PQexec(admin, ("SELECT default_hostgroup FROM runtime_pgsql_users WHERE username=" +
            sqlQuote(cl.pgsql_root_username) + " LIMIT 1").c_str());
        if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) hg_s = PQgetvalue(res, 0, 0);
        PQclear(res);
    }
    return hg_s.empty() ? -1 : std::stoi(hg_s);
}

static void test_untracked_set_does_not_leak() {
    PGConnPtr admin = createNewConnection(ConnType::ADMIN);
    const int hg = rootDefaultHostgroup(admin.get());
    const std::vector<std::string> servers = (hg >= 0) ? snapshotServers(admin.get(), hg) : std::vector<std::string>{};
    const bool capped = !servers.empty() && reloadServers(admin.get(), hg, servers, true);
    if (!capped) {
        skip(untracked_set_cases.size() * UNTRACKED_SET_TESTS_PER_CASE,
            "cannot limit hostgroup %d to one backend connection", hg);
        const bool restored = servers.empty() || reloadServers(admin.get(), hg, servers, false);
        ok(restored, "servers of hostgroup %d restored", hg);
        return;
    }
    diag("hostgroup %d limited to one server and one backend connection", hg);

    for (const auto& c : untracked_set_cases) {
        std::string a_pid;
        {
            PGConnPtr a = createNewConnection(ConnType::BACKEND);
            PGresult* res = a ? PQexec(a.get(), c.set.c_str()) : nullptr;
            const bool set_ok = res && PQresultStatus(res) == PGRES_COMMAND_OK;
            ok(set_ok, "client A: %s (%s)", c.set.c_str(), set_ok ? "" : (a ? PQerrorMessage(a.get()) : "no connection"));
            PQclear(res);

            a_pid = a ? backendPid(a.get()) : "";
            const int locked = a ? lockedOnHostgroup(a.get()) : -2;
            ok(locked == hg, "client A: '%s' locks the session on hostgroup %d (locked_on_hostgroup=%d)",
                c.set.c_str(), hg, locked);
        } // A disconnects: a locked connection is reset before it goes back to the pool

        PGConnPtr b = createNewConnection(ConnType::BACKEND);
        std::string b_pid, value = "<no result>";
        if (b) {
            const std::string q = "SELECT pg_catalog.pg_backend_pid(), current_setting(" + sqlQuote(c.name) + ", true)";
            PGresult* res = PQexec(b.get(), q.c_str());
            if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {
                b_pid = PQgetvalue(res, 0, 0);
                value = PQgetisnull(res, 0, 1) ? "<null>" : PQgetvalue(res, 0, 1);
            } else {
                diag("client B query failed: %s", PQerrorMessage(b.get()));
            }
            PQclear(res);
        }
        ok(value != c.leaked && value != "<no result>",
            "client B: %s is '%s', not client A's '%s' (A on backend pid %s, B on %s)",
            c.name.c_str(), value.c_str(), c.leaked.c_str(), a_pid.c_str(), b_pid.c_str());
    }

    ok(reloadServers(admin.get(), hg, servers, false), "servers of hostgroup %d restored", hg);
}

// ---------------------------------------------------------------------------
// The protocol the SET phases below send their statements over, and the label of the run.
// PIPELINE sends SELECT 1, the statement and SELECT 2 before one Sync: with the native backend
// the unit is batched, and a SET has to leave the batch to be recorded.
// ---------------------------------------------------------------------------

enum class Proto { SIMPLE, EXTENDED, PIPELINE };
static Proto g_proto = Proto::SIMPLE;
static std::string g_mode = "native simple";

// The statement's own result; the caller frees it.
static PGresult* execMode(PGconn* c, const std::string& sql) {
    if (g_proto == Proto::SIMPLE) return PQexec(c, sql.c_str());
    if (g_proto == Proto::EXTENDED) return PQexecParams(c, sql.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0);
    if (PQenterPipelineMode(c) != 1) return nullptr;
    const char* q[3] = { "SELECT 1", sql.c_str(), "SELECT 2" };
    for (const char* one : q) PQsendQueryParams(c, one, 0, nullptr, nullptr, nullptr, nullptr, 0);
    PQpipelineSync(c);
    PGresult* mine = nullptr;
    for (int i = 0; i < 3; i++) {
        for (PGresult* r = PQgetResult(c); r != nullptr; r = PQgetResult(c)) {
            if (i == 1 && mine == nullptr) mine = r; else PQclear(r);
        }
    }
    for (PGresult* r = PQgetResult(c); r != nullptr; r = PQgetResult(c)) PQclear(r); // the Sync's
    PQexitPipelineMode(c);
    return mine;
}

static bool execModeOk(PGconn* c, const std::string& sql) {
    PGresult* r = execMode(c, sql);
    const bool good = PQresultStatus(r) == PGRES_COMMAND_OK || PQresultStatus(r) == PGRES_TUPLES_OK;
    if (!good) diag("[%s] %s: %s", g_mode.c_str(), sql.c_str(), PQerrorMessage(c));
    PQclear(r);
    return good;
}

// ---------------------------------------------------------------------------
// A client that connects with an empty search_path ('-c search_path=', what pg_dump files
// set) gets a pooled backend opened with another path. The sync must send
// SET search_path TO '' -- a SET with no value at all is a syntax error (42601) and the
// client's first query fails. One backend connection, so B must reuse A's.
// ---------------------------------------------------------------------------

static const int EMPTY_SEARCH_PATH_TESTS = 4; // query ok, value, same backend, servers restored

static void test_empty_search_path_syncs() {
    PGConnPtr admin = createNewConnection(ConnType::ADMIN);
    const int hg = rootDefaultHostgroup(admin.get());
    const std::vector<std::string> servers = (hg >= 0) ? snapshotServers(admin.get(), hg) : std::vector<std::string>{};
    if (servers.empty() || !reloadServers(admin.get(), hg, servers, true)) {
        skip(EMPTY_SEARCH_PATH_TESTS - 1, "cannot limit hostgroup %d to one backend connection", hg);
        ok(servers.empty() || reloadServers(admin.get(), hg, servers, false), "[%s] servers of hostgroup %d restored", g_mode.c_str(), hg);
        return;
    }

    std::string a_pid;
    {
        PGConnPtr a = createNewConnection(ConnType::BACKEND);
        a_pid = a ? backendPid(a.get()) : "";
    }
    usleep(200000); // let A's backend connection go back to the pool

    PGConnPtr b = createNewConnection(ConnType::BACKEND, "-c search_path=");
    std::string err = b ? "" : "no connection", value = "<no result>", b_pid;
    if (b) {
        PGresult* res = execMode(b.get(), "SELECT pg_catalog.pg_backend_pid(), current_setting('search_path')");
        if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {
            b_pid = PQgetvalue(res, 0, 0);
            value = PQgetvalue(res, 0, 1);
        } else {
            err = PQerrorMessage(b.get());
        }
        PQclear(res);
    }
    ok(err.empty(), "[%s] empty search_path: first query of the client succeeds (%s)", g_mode.c_str(), err.c_str());
    ok(value == "\"\"", "[%s] empty search_path: backend search_path is '\"\"' (got '%s')", g_mode.c_str(), value.c_str());
    ok(!a_pid.empty() && b_pid == a_pid, "[%s] empty search_path: the sync ran on the reused backend (A pid %s, B pid %s)",
        g_mode.c_str(), a_pid.c_str(), b_pid.c_str());
    b.reset();
    usleep(200000);
    ok(reloadServers(admin.get(), hg, servers, false), "[%s] servers of hostgroup %d restored", g_mode.c_str(), hg);
}

// ---------------------------------------------------------------------------
// Only the unquoted keyword DEFAULT resets a setting. A quoted 'DEFAULT' is an ordinary
// value: PostgreSQL refuses it for TimeZone and bytea_output, stores it as a schema name
// for search_path, and reads it as the word DEFAULT inside a DateStyle list (the session's
// reset value, which a later word in the list still overrides). Expectations measured on
// PostgreSQL 16.
// ---------------------------------------------------------------------------

struct QuotedDefaultCase {
    std::string options;     // connect-time options
    std::string setup;       // run first on the same connection, "" for none
    std::string set;
    std::string sqlstate;    // "" = the SET must succeed
    std::string message;     // primary error message when sqlstate is set, "" not checked
    std::string show;        // setting read back with SHOW on success
    std::string expected;    // its expected value
};

static const std::vector<QuotedDefaultCase> quoted_default_cases = {
    { "", "", "SET TimeZone = 'DEFAULT'", "22023",
        "invalid value for parameter \"TimeZone\": \"DEFAULT\"", "", "" },
    { "", "", "SET bytea_output = 'DEFAULT'", "22023",
        "invalid value for parameter \"bytea_output\": \"DEFAULT\"", "", "" },
    { "", "", "SET search_path = 'DEFAULT'", "", "", "search_path", "\"DEFAULT\"" },
    { "", "SET DateStyle = 'SQL, DMY'", "SET DateStyle = 'DEFAULT'", "", "", "DateStyle", "ISO, MDY" },
    { "", "", "SET DateStyle = 'DEFAULT, DMY'", "", "", "DateStyle", "ISO, DMY" },
    { "", "", "SET DateStyle = 'DEFAULT, BOGUS'", "22023",
        "invalid value for parameter \"DateStyle\": \"DEFAULT, BOGUS\"", "", "" },
    // DEFAULT in a DateStyle list is the session's reset value: the connect-time DateStyle.
    { "-c DateStyle=SQL,DMY", "SET DateStyle = 'Postgres, YMD'", "SET DateStyle = 'DEFAULT'", "", "",
        "DateStyle", "SQL, DMY" },
    // The unquoted keyword still resets to the connect-time value.
    { "-c TimeZone=Asia/Tokyo", "SET TimeZone = 'UTC'", "SET TimeZone TO DEFAULT", "", "",
        "TimeZone", "Asia/Tokyo" },
};

// Every tracked setting, in both forms: a quoted 'DEFAULT' is a value (refused by all but
// search_path and DateStyle), the bare keyword resets to the connect-time value. Only the
// SQLSTATE of a refusal is checked: PostgreSQL words a boolean's refusal differently.
struct DefaultVar { const char* name; const char* connect; const char* other; const char* shown; };

static const DefaultVar default_vars[] = {
    { "client_encoding", "LATIN1", "LATIN9", "LATIN1" },
    { "DateStyle", "SQL,DMY", "German", "SQL, DMY" },
    { "IntervalStyle", "sql_standard", "iso_8601", "sql_standard" },
    { "standard_conforming_strings", "off", "on", "off" },
    { "TimeZone", "UTC", "Asia/Tokyo", "UTC" },
    { "search_path", "zz_a", "zz_b", "zz_a" },
    { "allow_in_place_tablespaces", "on", "off", "on" },
    { "bytea_output", "escape", "hex", "escape" },
    { "client_min_messages", "warning", "error", "warning" },
    { "enable_bitmapscan", "off", "on", "off" },
    { "enable_hashjoin", "off", "on", "off" },
    { "enable_indexscan", "off", "on", "off" },
    { "enable_nestloop", "off", "on", "off" },
    { "enable_seqscan", "off", "on", "off" },
    { "enable_sort", "off", "on", "off" },
    { "escape_string_warning", "off", "on", "off" },
    { "extra_float_digits", "2", "0", "2" },
    { "maintenance_work_mem", "32MB", "128MB", "32MB" },
    { "synchronous_commit", "off", "local", "off" },
};

static std::vector<QuotedDefaultCase> all_default_cases() {
    std::vector<QuotedDefaultCase> v = quoted_default_cases;
    for (const auto& d : default_vars) {
        const std::string name = d.name;
        const std::string opts = "-c " + name + "=" + d.connect;
        const std::string setup = "SET " + name + " = '" + d.other + "'";
        if (name == "search_path") {
            v.push_back({ opts, setup, "SET search_path = 'DEFAULT'", "", "", name, "\"DEFAULT\"" });
        } else if (name == "DateStyle") {
            v.push_back({ opts, setup, "SET DateStyle = 'DEFAULT'", "", "", name, d.shown });
        } else {
            v.push_back({ opts, setup, "SET " + name + " = 'DEFAULT'", "22023", "", "", "" });
        }
        v.push_back({ opts, setup, "SET " + name + " TO DEFAULT", "", "", name, d.shown });
    }
    return v;
}

static std::string resultField(const PGresult* res, int field) {
    const char* v = res ? PQresultErrorField(res, field) : nullptr;
    return v ? v : "";
}

static void test_quoted_default_is_a_value() {
    for (const auto& c : all_default_cases()) {
        PGConnPtr conn = createNewConnection(ConnType::BACKEND, c.options);
        if (!conn) {
            ok(false, "[%s] quoted DEFAULT: %s (no connection)", g_mode.c_str(), c.set.c_str());
            continue;
        }
        std::string err;
        if (!c.setup.empty()) {
            PGresult* r = execMode(conn.get(), c.setup);
            if (PQresultStatus(r) != PGRES_COMMAND_OK) err = "setup failed: " + std::string(PQerrorMessage(conn.get()));
            PQclear(r);
        }
        if (err.empty()) {
            PGresult* r = execMode(conn.get(), c.set);
            const ExecStatusType st = PQresultStatus(r);
            if (c.sqlstate.empty()) {
                if (st != PGRES_COMMAND_OK) err = "SET failed: " + std::string(PQerrorMessage(conn.get()));
            } else {
                const std::string state = resultField(r, PG_DIAG_SQLSTATE);
                const std::string msg = resultField(r, PG_DIAG_MESSAGE_PRIMARY);
                if (st != PGRES_FATAL_ERROR || state != c.sqlstate || (!c.message.empty() && msg != c.message)) {
                    err = "expected " + c.sqlstate + " '" + c.message + "', got status " + PQresStatus(st) +
                        " " + state + " '" + msg + "'";
                }
            }
            PQclear(r);
        }
        if (err.empty() && !c.show.empty()) {
            PGresult* r = PQexec(conn.get(), ("SHOW " + c.show).c_str());
            const std::string v = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) ? PQgetvalue(r, 0, 0) : "<no result>";
            if (v != c.expected) err = "SHOW " + c.show + " is '" + v + "', expected '" + c.expected + "'";
            PQclear(r);
        }
        // Rows that hit a bug not fixed yet run as todo: a reset over the extended protocol goes to
        // the backend's own default, and a new backend connection gets a quoted search_path with
        // its quotes (the value is sent raw at connect time).
        const bool reset_by_backend = g_proto != Proto::SIMPLE && c.sqlstate.empty() &&
            (c.set.find(" TO DEFAULT") != std::string::npos ||
             (c.show == "DateStyle" && c.set.find("'DEFAULT'") != std::string::npos));
        const bool quoted_search_path = c.show == "search_path" && c.set.find('\'') != std::string::npos;
        if (reset_by_backend) todo_start("extended protocol: the backend resets to its own default");
        else if (quoted_search_path) todo_start("a new backend connection gets the quoted search_path raw");
        ok(err.empty(), "[%s] quoted DEFAULT: [%s] %s%s%s %s", g_mode.c_str(), c.options.c_str(), c.setup.c_str(),
            c.setup.empty() ? "" : "; ", c.set.c_str(), err.c_str());
        if (reset_by_backend || quoted_search_path) todo_end();
    }
}

// The value ProxySQL records for the client (PROXYSQL INTERNAL SESSION, client.conn.<name>).
static std::string stored(PGconn* conn, const std::string& name) {
    PGresult* res = PQexec(conn, "PROXYSQL INTERNAL SESSION");
    std::string v = "<no result>";
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {
        try {
            const json j = json::parse(PQgetvalue(res, 0, 0));
            v = j.at("client").at("conn").at(name).get<std::string>();
        } catch (const std::exception& e) {
            v = std::string("<") + e.what() + ">";
        }
    }
    PQclear(res);
    return v;
}

// ---------------------------------------------------------------------------
// ProxySQL must record extra_float_digits and maintenance_work_mem in the form PostgreSQL
// prints them. Two spellings of one value ('1024MB' and '1GB') are then the same string,
// so pooled connections carrying either match. Expectations measured on PostgreSQL 16.
// ---------------------------------------------------------------------------

// expected "": PostgreSQL refuses the value (22023) and the recorded value must not change.
struct StoredFormCase { std::string name, input, expected; };

static const std::vector<StoredFormCase> stored_form_cases = {
    { "extra_float_digits", "'03'", "3" },
    { "extra_float_digits", "'-02'", "-2" },
    { "extra_float_digits", "'-010'", "-8" },      // octal, as PostgreSQL reads it
    { "extra_float_digits", "'0x3'", "3" },
    { "extra_float_digits", "2.5", "2" },          // rounded half to even
    { "extra_float_digits", "3.4", "3" },
    { "maintenance_work_mem", "'1024MB'", "1GB" },
    { "maintenance_work_mem", "'65536'", "64MB" },
    { "maintenance_work_mem", "'2048kB'", "2MB" },
    { "maintenance_work_mem", "'1025kB'", "1025kB" },
    { "maintenance_work_mem", "'1.5GB'", "1536MB" },
    { "maintenance_work_mem", "'1.0001GB'", "1GB" },
    { "maintenance_work_mem", "'1048576B'", "1MB" },
    { "maintenance_work_mem", "'02000'", "1MB" },
    { "maintenance_work_mem", "'1.5MB'", "1536kB" },
    { "maintenance_work_mem", "'1024.5'", "1MB" },
    { "maintenance_work_mem", "'2 GB'", "2GB" },
    { "extra_float_digits", "-15.4", "-15" },
    { "extra_float_digits", "'+2'", "2" },
    { "extra_float_digits", "' 2 '", "2" },
    { "extra_float_digits", "'1e0'", "1" },
    { "extra_float_digits", "3.5", "" },           // rounds to 4, out of range
    { "extra_float_digits", "-15.5", "" },         // rounds to -16, out of range
    { "extra_float_digits", "'2abc'", "" },
    { "extra_float_digits", "'0x'", "" },
    { "extra_float_digits", "''", "" },
    { "extra_float_digits", "'08'", "" },          // 8 is no octal digit
    { "maintenance_work_mem", "'1TB'", "1TB" },
    { "maintenance_work_mem", "'1GB '", "1GB" },
    { "maintenance_work_mem", "' 1GB'", "1GB" },
    { "maintenance_work_mem", "'0x400'", "1MB" },
    { "maintenance_work_mem", "'1e3MB'", "1000MB" },
    { "maintenance_work_mem", "'1023'", "" },      // below the 1024 kB minimum
    { "maintenance_work_mem", "'0.5MB'", "" },
    { "maintenance_work_mem", "'1.5kB'", "" },     // rounds to 2 kB
    { "maintenance_work_mem", "'-1MB'", "" },
    { "maintenance_work_mem", "'64 MB x'", "" },
    { "maintenance_work_mem", "''", "" },
};

static void test_stored_form_matches_postgresql() {
    PGConnPtr conn = createNewConnection(ConnType::BACKEND);
    for (const auto& c : stored_form_cases) {
        const std::string set = "SET " + c.name + " = " + c.input;
        std::string err, v;
        const bool refused = c.expected.empty();
        std::string want = c.expected;
        if (!conn) {
            err = "no connection";
        } else {
            if (refused) want = stored(conn.get(), c.name);
            PGresult* r = execMode(conn.get(), set);
            if (refused) {
                const std::string state = resultField(r, PG_DIAG_SQLSTATE);
                if (PQresultStatus(r) != PGRES_FATAL_ERROR || state != "22023") err = "expected 22023, got '" + state + "'";
            } else if (PQresultStatus(r) != PGRES_COMMAND_OK) {
                err = PQerrorMessage(conn.get());
            }
            PQclear(r);
            v = stored(conn.get(), c.name);
        }
        ok(err.empty() && v == want, "[%s] stored form: %s -> %s '%s' (got '%s') %s", g_mode.c_str(), set.c_str(),
            refused ? "refused, keeps" : "", want.c_str(), v.c_str(), err.c_str());
    }

    PGConnPtr a = createNewConnection(ConnType::BACKEND);
    PGConnPtr b = createNewConnection(ConnType::BACKEND);
    std::string va = "<no connection>", vb = "<no connection>";
    if (a && b) {
        PQclear(execMode(a.get(), "SET maintenance_work_mem = '1024MB'"));
        PQclear(execMode(b.get(), "SET maintenance_work_mem = '1GB'"));
        va = stored(a.get(), "maintenance_work_mem");
        vb = stored(b.get(), "maintenance_work_mem");
    }
    ok(va == "1GB" && vb == "1GB", "[%s] stored form: '1024MB' and '1GB' are recorded alike (A '%s', B '%s')",
        g_mode.c_str(), va.c_str(), vb.c_str());
}

// ---------------------------------------------------------------------------
// PostgreSQL keeps the current DateStyle on SET DateStyle = ''. Over the extended protocol
// ProxySQL recorded '' as the client's DateStyle, so the next DateStyle SET read an empty
// current style.
// ---------------------------------------------------------------------------

static const int EXTENDED_EMPTY_DATESTYLE_TESTS = 3;

static void test_extended_empty_datestyle() {
    PGConnPtr conn = createNewConnection(ConnType::BACKEND);
    if (!conn) {
        skip(EXTENDED_EMPTY_DATESTYLE_TESTS, "no connection");
        return;
    }
    const bool set_ok = execModeOk(conn.get(), "SET DateStyle = 'SQL, DMY'") && execModeOk(conn.get(), "SET DateStyle = ''");
    const std::string after_empty = stored(conn.get(), "DateStyle");
    ok(set_ok && after_empty == "SQL, DMY", "[%s] SET DateStyle = '' keeps the recorded DateStyle (got '%s')", g_mode.c_str(), after_empty.c_str());
    const bool next_ok = execModeOk(conn.get(), "SET DateStyle = 'YMD'");
    const std::string after_next = stored(conn.get(), "DateStyle");
    ok(next_ok && after_next == "SQL, YMD", "[%s] the next DateStyle SET keeps the style (got '%s')", g_mode.c_str(), after_next.c_str());
    PGresult* r = PQexec(conn.get(), "SHOW DateStyle");
    const std::string shown = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) ? PQgetvalue(r, 0, 0) : "<no result>";
    PQclear(r);
    ok(shown == "SQL, YMD", "[%s] the backend agrees (SHOW DateStyle is '%s')", g_mode.c_str(), shown.c_str());
}


// ---------------------------------------------------------------------------
// set_config() tracking. With the ParserSQL gate on, a set_config() call ProxySQL can follow
// is recorded like SET and answered locally; any other one locks the session on its
// hostgroup. Before, every call was forwarded untracked: the backend kept the new value and
// the next client to get that connection inherited it (P1-52). Expectations measured on
// PostgreSQL 16. Runs in both backend modes.
// ---------------------------------------------------------------------------

using PGResPtr = std::unique_ptr<PGresult, decltype(&PQclear)>;

static PGResPtr run(PGconn* c, const std::string& q) {
    return PGResPtr(PQexec(c, q.c_str()), &PQclear);
}

// The single value a query returns, or "<error: ...>".
static std::string oneValue(PGconn* c, const std::string& q) {
    PGResPtr r = run(c, q);
    if (PQresultStatus(r.get()) != PGRES_TUPLES_OK || PQntuples(r.get()) != 1 || PQnfields(r.get()) < 1) {
        return std::string("<error: ") + PQerrorMessage(c) + ">";
    }
    return PQgetisnull(r.get(), 0, 0) ? "<null>" : PQgetvalue(r.get(), 0, 0);
}

// A one-row, one-column local reply: column name, value, text type, "SELECT 1", no lock.
static std::string checkReply(PGconn* c, PGresult* r, const char* column, const char* value) {
    if (PQresultStatus(r) != PGRES_TUPLES_OK) return std::string("failed: ") + PQerrorMessage(c);
    std::string err;
    if (PQnfields(r) != 1 || PQntuples(r) != 1) return "not one row of one column";
    if (std::string(PQfname(r, 0)) != column) err += std::string(" column '") + PQfname(r, 0) + "'";
    if (PQftype(r, 0) != 25) err += " type " + std::to_string(PQftype(r, 0));
    if (std::string(PQcmdStatus(r)) != "SELECT 1") err += std::string(" tag '") + PQcmdStatus(r) + "'";
    if (std::string(PQgetvalue(r, 0, 0)) != value) err += std::string(" value '") + PQgetvalue(r, 0, 0) + "'";
    const int locked = lockedOnHostgroup(c);
    if (locked != -1) err += " locked " + std::to_string(locked);
    return err;
}

struct ScReplyCase {
    const char* options;
    const char* setup;      // "" for none
    const char* query;
    const char* column;
    const char* value;      // the row: the value ProxySQL stored
    const char* name;       // tracked variable read back from PROXYSQL INTERNAL SESSION
    const char* show;       // SHOW <name> afterwards on the backend, "" to skip
};

static const ScReplyCase sc_reply_cases[] = {
    // Equivalent memory units are recorded in PostgreSQL's canonical form.
    { "", "", "SELECT set_config('maintenance_work_mem','1024MB',false)", "set_config", "1GB", "maintenance_work_mem", "1GB" },
    { "", "", "SELECT set_config('DateStyle','iso',false) AS tz", "tz", "ISO, MDY", "DateStyle", "ISO, MDY" },
    { "", "", "SELECT pg_catalog.set_config('maintenance_work_mem','1024MB',false) AS \"MyCol\"", "MyCol", "1GB",
        "maintenance_work_mem", "1GB" },
    { "", "SET DateStyle = 'SQL, DMY'", "SELECT set_config('DateStyle','',false)", "set_config", "SQL, DMY", "DateStyle", "SQL, DMY" },
    { "", "", "/* c */ SELECT set_config('bytea_output','escape',false) -- t", "set_config", "escape", "bytea_output", "escape" },
    // search_path is a raw list to set_config: rewritten as SET writes it.
    { "", "", "SELECT set_config('search_path','a-b;c, \"X y\", B',false)", "set_config", "\"a-b;c\", \"X y\", \"b\"",
        "search_path", "\"a-b;c\", \"X y\", b" },
    { "", "", "SELECT set_config('search_path','\xd1\x81\xd1\x85\xd0\xb5\xd0\xbc\xd0\xb0, public',false)", "set_config",
        "\"\xd1\x81\xd1\x85\xd0\xb5\xd0\xbc\xd0\xb0\", \"public\"", "search_path", "\"\xd1\x81\xd1\x85\xd0\xb5\xd0\xbc\xd0\xb0\", public" },
    { "", "", "SELECT set_config('search_path','',false)", "set_config", "", "search_path", "\"\"" },
    { "", "", "SELECT set_config('search_path','DEFAULT',false)", "set_config", "\"default\"", "search_path", "\"default\"" },
    // NULL: back to the client's connect-time value.
    { "-c DateStyle=ISO,DMY", "SET DateStyle = 'SQL, MDY'", "SELECT set_config('DateStyle',NULL,false)", "set_config", "ISO, DMY",
        "DateStyle", "ISO, DMY" },
    // standard_conforming_strings off changes only what a '\' means: without one, tracked as usual.
    { "-c standard_conforming_strings=off", "", "SELECT set_config('DateStyle','SQL,DMY',false)", "set_config", "SQL, DMY",
        "DateStyle", "SQL, DMY" },
};

struct ScErrorCase { const char* query; const char* sqlstate; const char* message; };

static const ScErrorCase sc_error_cases[] = {
    { "SELECT set_config('TimeZone',42,false)", "42883", "function set_config(unknown, integer, boolean) does not exist" },
    { "SELECT set_config('TimeZone','UTC','maybe')", "22P02", "invalid input syntax for type boolean: \"maybe\"" },
    { "SELECT set_config(NULL,'UTC',false)", "22004", "SET requires parameter name" },
    { "SELECT set_config('','UTC',false)", "42704", "unrecognized configuration parameter \"\"" },
    { "SELECT set_config('search_path','a b',false)", "22023", "invalid value for parameter \"search_path\": \"a b\"" },
    { "SELECT set_config('bytea_output','base64',false)", "22023", "invalid value for parameter \"bytea_output\": \"base64\"" },
};

struct ScLockCase { const char* options; const char* query; bool succeeds; };

static const ScLockCase sc_lock_cases[] = {
    { "", "SELECT set_config('TimeZone','UTC',false)", true },
    { "", "SELECT set_config('TimeZone','asia/tokyo',false)", true },
    { "", "SELECT set_config('TimeZone','Mars/Olympus',false)", false },
    { "", "SELECT set_config('TimeZone','Invalid Zone!',false)", false },
    { "", "SELECT set_config('TimeZone','DEFAULT',false)", false },
    { "", "SELECT WHERE set_config('search_path','public',false) IS NOT NULL", true },
    { "", "SELECT set_config('TimeZone','UTC',true)", true },
    { "", "SELECT set_config('TimeZone','UTC',false), 1", true },
    { "", "SELECT * FROM set_config('TimeZone','UTC',false)", true },
    { "", "EXPLAIN ANALYZE SELECT set_config('TimeZone','UTC',false)", true },
    { "", "UPDATE pg_settings SET setting='UTC' WHERE name='TimeZone'", true },
    { "", "DO $$BEGIN PERFORM set_config('TimeZone','UTC',false); END$$", true },
    { "", "SELECT 1; SELECT set_config('TimeZone','UTC',false)", true },
    { "", "PREPARE zz_sc AS SELECT set_config('TimeZone','UTC',false)", true },
    { "", "CALL set_config('TimeZone','UTC',false)", false },
    { "", "SELECT set_config('TimeZone','INTERVAL ''+02:30''',false)", true },
    { "", "SELECT set_config('names','UTF8',false)", false },
    { "", "SELECT set_config('TIME ZONE','UTC',false)", false },
    { "", "SELECT set_config('app.tenant_id','42',false)", true },
    { "", "SELECT set_config('statement_timeout','5s',false)", true },
    { "", "SELECT set_config('bytea_output',NULL,false)", true },
    // standard_conforming_strings off: PostgreSQL then reads '\' in strings as an escape, and
    // stores zz\q here where ParserSQL reads zz\\q. Connected with 'false', stored as 'off'.
    { "-c standard_conforming_strings=off", "SELECT set_config('search_path','zz\\\\q',false)", true },
    { "-c standard_conforming_strings=false", "SELECT set_config('search_path','zz\\\\q',false)", true },
};

// Every tracked variable, for the injection check.
static const char* sc_tracked_names[] = {
    "client_encoding", "DateStyle", "IntervalStyle", "standard_conforming_strings", "TimeZone", "search_path",
    "allow_in_place_tablespaces", "bytea_output", "client_min_messages", "enable_bitmapscan", "enable_hashjoin",
    "enable_indexscan", "enable_nestloop", "enable_seqscan", "enable_sort", "escape_string_warning",
    "extra_float_digits", "maintenance_work_mem", "synchronous_commit",
};

// Values that would run a statement if pasted into the sync's SET unescaped.
static const char* sc_injection_values[] = {
    "'X''; CREATE TEMP TABLE zz_pwned(); --'",
    "'X\\''; CREATE TEMP TABLE zz_pwned(); --'",
    "'X\"; CREATE TEMP TABLE zz_pwned(); --'",
    "'\"a\"\";CREATE TEMP TABLE zz_pwned();--\"'",
    "'UTC; CREATE TEMP TABLE zz_pwned()'",
};

static const int SC_LEAK_TESTS = 6;
static const int SC_OTHER_TESTS = 1 /* application_name */ + 4 /* scs via SET / set_config */ + 3 /* txn */ +
    1 /* already locked */ + 3 /* gates */;
static const int SC_PHASE_TESTS = SC_LEAK_TESTS + (int)std::size(sc_reply_cases) + (int)std::size(sc_error_cases) +
    (int)std::size(sc_lock_cases) + 1 /* long query */ + SC_OTHER_TESTS + (int)std::size(sc_tracked_names);
static const int SC_TESTS = 2 /* setup, restore */ + 2 * SC_PHASE_TESTS;

// Two clients on a one-connection pool, both connected with `options`: A changes `name` with
// set_config, B must still see its own value on the backend A used, and A must keep its own.
static void sc_leak_case(const char* options, const char* name, const char* a_value, const char* b_value) {
    PGConnPtr a = createNewConnection(ConnType::BACKEND, options);
    PGConnPtr b = createNewConnection(ConnType::BACKEND, options);
    std::string got_b = "<no connection>", got_a = "<no connection>", pid_a, pid_b;
    if (a && b) {
        PQclear(execMode(a.get(), std::string("SELECT set_config('") + name + "','" + a_value + "',false)"));
        pid_b = backendPid(b.get());
        got_b = oneValue(b.get(), std::string("SHOW ") + name);
        pid_a = backendPid(a.get());
        got_a = oneValue(a.get(), std::string("SHOW ") + name);
    }
    ok(got_b == b_value, "[%s] set_config leak: client B's %s is '%s' (got '%s')", g_mode.c_str(), name, b_value, got_b.c_str());
    ok(got_a == a_value, "[%s] set_config leak: client A keeps its %s '%s' (got '%s')", g_mode.c_str(), name, a_value, got_a.c_str());
    ok(!pid_a.empty() && pid_a == pid_b, "[%s] set_config leak: both on one backend (A %s, B %s)", g_mode.c_str(),
        pid_a.c_str(), pid_b.c_str());
}

// A long SELECT list: its digest is cut at query_digests_max_query_length (65000) before the call.
static std::string sc_long_query() {
    const std::string col = "1 AS " + std::string(60, 'a');
    std::string q = "SELECT " + col;
    while (q.size() < 70000) q += ", " + col;
    return q + ", set_config('TimeZone','UTC',false)";
}

static void sc_phase(PGconn* admin, int hg, const std::vector<std::string>& servers, bool native) {
    const char* mode = native ? "native" : "libpq";
    g_proto = Proto::SIMPLE;
    g_mode = std::string(mode) + " simple";
    diag("set_config tracking, %s backend mode", mode);

    // P1-52: the leak, on a one-connection pool.
    const bool capped = !servers.empty() && reloadServers(admin, hg, servers, true);
    if (capped) {
        sc_leak_case("-c search_path=zz_a", "search_path", "zz_b", "zz_a");
        sc_leak_case("-c maintenance_work_mem=64MB", "maintenance_work_mem", "128MB", "64MB");
    } else {
        skip(SC_LEAK_TESTS, "cannot limit hostgroup %d to one backend connection", hg);
    }

    // Injection: no value reaches the sync's SET unescaped. On the one-connection pool, so the
    // check runs on the backend that took the sync.
    for (const char* name : sc_tracked_names) {
        std::string err;
        if (!capped) { err = "not capped"; }
        for (const char* v : sc_injection_values) {
            if (!capped) break;
            PGConnPtr c = createNewConnection(ConnType::BACKEND);
            if (!c) { err += " no connection"; continue; }
            run(c.get(), std::string("SELECT set_config('") + name + "'," + v + ",false)");
            const std::string pwned = oneValue(c.get(), "SELECT pg_catalog.to_regclass('pg_temp.zz_pwned') IS NULL");
            if (pwned != "t") err += std::string(" [") + v + " -> " + pwned + " stored '" + stored(c.get(), name) + "']";
        }
        ok(err.empty(), "set_config injection, %s: no value ran a statement %s", name, err.c_str());
    }
    if (capped) reloadServers(admin, hg, servers, false);

    for (const auto& c : sc_reply_cases) {
        PGConnPtr conn = createNewConnection(ConnType::BACKEND, c.options);
        std::string err = conn ? "" : "no connection";
        if (conn) {
            if (*c.setup) run(conn.get(), c.setup);
            PGResPtr r = run(conn.get(), c.query);
            err = checkReply(conn.get(), r.get(), c.column, c.value);
            const std::string st = stored(conn.get(), c.name);
            if (st != c.value) err += " stored '" + st + "'";
            if (std::string(c.name) == "TimeZone" || std::string(c.name) == "DateStyle") {
                const char* ps = PQparameterStatus(conn.get(), c.name);
                if (!ps || std::string(ps) != c.value) err += std::string(" ParameterStatus '") + (ps ? ps : "<none>") + "'";
            }
            if (*c.show) {
                const std::string shown = oneValue(conn.get(), std::string("SHOW ") + c.name);
                if (shown != c.show) err += " SHOW '" + shown + "'";
            }
        }
        ok(err.empty(), "set_config %s, local reply: [%s] %s %s", mode, c.options, c.query, err.c_str());
    }

    for (const auto& c : sc_error_cases) {
        PGConnPtr conn = createNewConnection(ConnType::BACKEND);
        std::string err = conn ? "" : "no connection";
        if (conn) {
            PGResPtr r = run(conn.get(), c.query);
            const std::string state = resultField(r.get(), PG_DIAG_SQLSTATE);
            const std::string msg = resultField(r.get(), PG_DIAG_MESSAGE_PRIMARY);
            if (PQresultStatus(r.get()) != PGRES_FATAL_ERROR || state != c.sqlstate || msg != c.message) {
                err = "got " + std::string(PQresStatus(PQresultStatus(r.get()))) + " " + state + " '" + msg + "'";
            }
            const int locked = lockedOnHostgroup(conn.get());
            if (locked != -1) err += " locked " + std::to_string(locked);
            if (oneValue(conn.get(), "SELECT 1") != "1") err += " connection unusable";
        }
        ok(err.empty(), "set_config %s, local error %s: %s %s", mode, c.sqlstate, c.query, err.c_str());
    }

    for (const auto& c : sc_lock_cases) {
        PGConnPtr conn = createNewConnection(ConnType::BACKEND, c.options);
        std::string err = conn ? "" : "no connection";
        if (conn) {
            PGResPtr r = run(conn.get(), c.query);
            if (strstr(c.query, "Mars/Olympus")) {
                if (resultField(r.get(), PG_DIAG_SQLSTATE) != "22023") err += " wrong SQLSTATE";
                if (stored(conn.get(), "TimeZone") == "Mars/Olympus") err += " invalid zone recorded";
                if (oneValue(conn.get(), "SELECT 1") != "1") err += " connection unusable after invalid zone";
            }
            const bool good = PQresultStatus(r.get()) != PGRES_FATAL_ERROR;
            if (good != c.succeeds) err = std::string(good ? "succeeded" : "failed: ") + (good ? "" : PQerrorMessage(conn.get()));
            const int locked = lockedOnHostgroup(conn.get());
            if (locked < 0) err += " not locked (" + std::to_string(locked) + ")";
        }
        ok(err.empty(), "set_config %s, locks: [%s] %s %s", mode, c.options, c.query, err.c_str());
    }
    {
        PGConnPtr conn = createNewConnection(ConnType::BACKEND);
        const int locked = conn ? (PQresultStatus(run(conn.get(), sc_long_query()).get()) == PGRES_TUPLES_OK ? lockedOnHostgroup(conn.get()) : -3) : -2;
        ok(locked >= 0, "set_config %s, locks: the call after byte 70000 of a query (locked_on_hostgroup=%d)", mode, locked);
    }
    {
        // Ignored by ProxySQL, as SET application_name: forwarded, no lock.
        PGConnPtr conn = createNewConnection(ConnType::BACKEND);
        const std::string v = conn ? oneValue(conn.get(), "SELECT set_config('application_name','zz_app',false)") : "<no connection>";
        const int locked = conn ? lockedOnHostgroup(conn.get()) : -2;
        ok(v == "zz_app" && locked == -1, "set_config %s: application_name forwarded without a lock (got '%s', locked %d)", mode, v.c_str(), locked);
    }
    {
        PGConnPtr a = createNewConnection(ConnType::BACKEND);
        PGConnPtr b = createNewConnection(ConnType::BACKEND);
        // Off from inside the session: a call without '\' is still tracked, one with '\' locks.
        int la = -2, lb = -2, la2 = -2, lb2 = -2;
        const char* with_backslash = "SELECT set_config('search_path','zz\\\\q',false)";
        if (a) {
            run(a.get(), "SET standard_conforming_strings = 'no'");
            run(a.get(), "SELECT set_config('DateStyle','SQL,DMY',false)"); la = lockedOnHostgroup(a.get());
            run(a.get(), with_backslash); la2 = lockedOnHostgroup(a.get());
        }
        if (b) {
            run(b.get(), "SELECT set_config('standard_conforming_strings','off',false)");
            run(b.get(), "SELECT set_config('DateStyle','SQL,DMY',false)"); lb = lockedOnHostgroup(b.get());
            run(b.get(), with_backslash); lb2 = lockedOnHostgroup(b.get());
        }
        ok(la == -1, "set_config %s: tracked after SET standard_conforming_strings = 'no' (%d)", mode, la);
        ok(la2 >= 0, "set_config %s: a '\\' then locks (%d)", mode, la2);
        ok(lb == -1, "set_config %s: tracked after set_config('standard_conforming_strings','off') (%d)", mode, lb);
        ok(lb2 >= 0, "set_config %s: a '\\' then locks (%d)", mode, lb2);
    }
    {
        PGConnPtr c = createNewConnection(ConnType::BACKEND);
        std::string err = c ? "" : "no connection";
        if (c) {
            const std::string before = stored(c.get(), "TimeZone");
            run(c.get(), "BEGIN");
            run(c.get(), "SELECT set_config('TimeZone','Asia/Tokyo',false)");
            if (PQtransactionStatus(c.get()) != PQTRANS_INTRANS) err += " not in a transaction after the reply";
            run(c.get(), "ROLLBACK");
            if (stored(c.get(), "TimeZone") != before) err += " stored '" + stored(c.get(), "TimeZone") + "', not '" + before + "'";
            if (oneValue(c.get(), "SHOW TimeZone") != before) err += " SHOW '" + oneValue(c.get(), "SHOW TimeZone") + "'";
        }
        ok(err.empty(), "set_config %s: ROLLBACK restores TimeZone %s", mode, err.c_str());
        err = c ? "" : "no connection";
        if (c) {
            const std::string before = stored(c.get(), "TimeZone");
            run(c.get(), "BEGIN");
            run(c.get(), "SAVEPOINT s");
            run(c.get(), "SELECT set_config('TimeZone','Asia/Tokyo',false)");
            run(c.get(), "ROLLBACK TO SAVEPOINT s");
            if (stored(c.get(), "TimeZone") != before) err += " stored '" + stored(c.get(), "TimeZone") + "', not '" + before + "'";
            run(c.get(), "COMMIT");
        }
        ok(err.empty(), "set_config %s: ROLLBACK TO SAVEPOINT restores TimeZone %s", mode, err.c_str());
        err = c ? "" : "no connection";
        if (c) {
            run(c.get(), "BEGIN");
            run(c.get(), "SELECT 1/0");
            PGResPtr r = run(c.get(), "SELECT set_config('TimeZone','Asia/Tokyo',false)");
            if (resultField(r.get(), PG_DIAG_SQLSTATE) != "25P02") err = "got '" + resultField(r.get(), PG_DIAG_SQLSTATE) + "'";
            run(c.get(), "ROLLBACK");
        }
        ok(err.empty(), "set_config %s: in a failed transaction the backend refuses it (25P02) %s", mode, err.c_str());
    }
    {
        // Already locked: forwarded, PostgreSQL answers, nothing recorded.
        PGConnPtr c = createNewConnection(ConnType::BACKEND);
        std::string err = c ? "" : "no connection";
        if (c) {
            run(c.get(), "SET zz.locked = '1'");
            const std::string before = stored(c.get(), "TimeZone");
            const std::string v = oneValue(c.get(), "SELECT set_config('TimeZone','asia/tokyo',false)");
            if (v != "Asia/Tokyo") err += " row '" + v + "'";
            if (stored(c.get(), "TimeZone") != before) err += " stored '" + stored(c.get(), "TimeZone") + "'";
        }
        ok(err.empty(), "set_config %s: a locked session forwards it untracked %s", mode, err.c_str());
    }

    // The gates. Only the ParserSQL paths track set_config; tracking no longer needs digests.
    const std::string algo = adminGet(admin, "pgsql-set_parser_algorithm");
    const std::string qpp = adminGet(admin, "pgsql-query_processor_parser");
    struct Gate { const char* what; const char* var; const char* value; const char* algo; bool tracked; };
    const Gate gates[] = {
        { "query digests off", "pgsql-query_digests", "false", "3", true },
        { "legacy SET parser", "pgsql-query_processor_parser", "0", "2", false },
        { "query_processor_parser=1", "pgsql-query_processor_parser", "1", "2", true },
    };
    for (const auto& g : gates) {
        const std::string saved = adminGet(admin, g.var);
        const bool both_digest_gates = (std::string(g.var) == "pgsql-query_digests");
        const std::string saved_cs = both_digest_gates ? adminGet(admin, "pgsql-commands_stats") : std::string();
        adminSet(admin, "pgsql-set_parser_algorithm", g.algo);
        adminSet(admin, g.var, g.value);
        if (both_digest_gates) adminSet(admin, "pgsql-commands_stats", "false");
        PGConnPtr c = createNewConnection(ConnType::BACKEND);
        const std::string v = c ? oneValue(c.get(), "SELECT set_config('maintenance_work_mem','1024MB',false)") : "<no connection>";
        const std::string st = c ? stored(c.get(), "maintenance_work_mem") : "";
        const int locked = c ? lockedOnHostgroup(c.get()) : -2;
        bool good = g.tracked ? (v == "1GB" && st == "1GB" && locked == -1)
                              : (v == "1GB" && st != "1GB" && locked == -1);
        if (both_digest_gates) {
            PGConnPtr e = createNewConnection(ConnType::BACKEND);
            if (!e) good = false;
            else {
                PGResPtr r(PQexecParams(e.get(), "SELECT set_config('maintenance_work_mem','1024MB',false)",
                    0, nullptr, nullptr, nullptr, nullptr, 0), &PQclear);
                good = good && PQresultStatus(r.get()) == PGRES_TUPLES_OK &&
                    stored(e.get(), "maintenance_work_mem") == "1GB" && lockedOnHostgroup(e.get()) == -1;
            }
        }
        ok(good, "set_config %s, %s: %s (row '%s', stored '%s', locked %d)", mode, g.what,
            g.tracked ? "tracked" : "forwarded untracked, no lock", v.c_str(), st.c_str(), locked);
        adminSet(admin, g.var, saved);
        if (both_digest_gates) adminSet(admin, "pgsql-commands_stats", saved_cs);
    }
    adminSet(admin, "pgsql-set_parser_algorithm", algo);
    adminSet(admin, "pgsql-query_processor_parser", qpp);
}

static void test_set_config_tracking() {
    PGConnPtr admin = createNewConnection(ConnType::ADMIN);
    const int hg = rootDefaultHostgroup(admin.get());
    const std::vector<std::string> servers = (hg >= 0) ? snapshotServers(admin.get(), hg) : std::vector<std::string>{};
    const std::string saved_algo = adminGet(admin.get(), "pgsql-set_parser_algorithm");
    const std::string saved_native = adminGet(admin.get(), "pgsql-use_native_backend_protocol");
    ok(admin && !saved_algo.empty() && adminSet(admin.get(), "pgsql-set_parser_algorithm", "3"),
        "set_config: pgsql-set_parser_algorithm=3 (was %s), native mode was '%s'", saved_algo.c_str(), saved_native.c_str());
    for (const bool native : { true, false }) {
        adminSet(admin.get(), "pgsql-use_native_backend_protocol", native ? "true" : "false");
        // Pooled connections keep the mode they were opened in.
        if (!servers.empty()) reloadServers(admin.get(), hg, servers, false);
        sc_phase(admin.get(), hg, servers, native);
    }
    const bool restored = adminSet(admin.get(), "pgsql-use_native_backend_protocol", saved_native) &&
        adminSet(admin.get(), "pgsql-set_parser_algorithm", saved_algo) &&
        (servers.empty() || reloadServers(admin.get(), hg, servers, false));
    ok(restored, "set_config: variables and servers restored");
}

// ---------------------------------------------------------------------------
// set_config() over the extended protocol: recorded like extended SET, ParameterStatus sent by
// ProxySQL, the statement forwarded (PostgreSQL builds the row). Errors PostgreSQL raises at
// Parse come from it; the ones it raises at Execute are answered by ProxySQL.
// ---------------------------------------------------------------------------

static const int SC_EXT_PHASE_TESTS = 9;
static const int SC_EXT_TESTS = 2 /* setup, restore */ + 2 * SC_EXT_PHASE_TESTS;

static PGResPtr runParams(PGconn* c, const char* sql, int n = 0, const char* const* values = nullptr) {
    return PGResPtr(PQexecParams(c, sql, n, nullptr, values, nullptr, nullptr, 0), &PQclear);
}

// The row is PostgreSQL's: the statement was forwarded.
static std::string checkExtTracked(PGconn* c, PGresult* r, const char* row, const char* stored_tz) {
    if (PQresultStatus(r) != PGRES_TUPLES_OK) return std::string("failed: ") + PQerrorMessage(c);
    std::string err;
    if (PQntuples(r) != 1 || std::string(PQgetvalue(r, 0, 0)) != row) err += std::string(" row '") + (PQntuples(r) ? PQgetvalue(r, 0, 0) : "") + "'";
    const std::string st = stored(c, "DateStyle");
    if (st != stored_tz) err += " stored '" + st + "'";
    const char* ps = PQparameterStatus(c, "DateStyle");
    if (!ps || std::string(ps) != stored_tz) err += std::string(" ParameterStatus '") + (ps ? ps : "<none>") + "'";
    const int locked = lockedOnHostgroup(c);
    if (locked != -1) err += " locked " + std::to_string(locked);
    return err;
}

static void sc_ext_phase(bool native) {
    const char* mode = native ? "native" : "libpq";
    {
        PGConnPtr c = createNewConnection(ConnType::BACKEND);
        std::string err1 = c ? "" : "no connection", err2 = err1;
        if (c) {
            PGResPtr p(PQprepare(c.get(), "zz_sc1", "SELECT set_config('DateStyle','SQL, DMY',false)", 0, nullptr), &PQclear);
            if (PQresultStatus(p.get()) != PGRES_COMMAND_OK) err1 = std::string("prepare failed: ") + PQerrorMessage(c.get());
            PGResPtr r1(PQexecPrepared(c.get(), "zz_sc1", 0, nullptr, nullptr, nullptr, 0), &PQclear);
            err1 += checkExtTracked(c.get(), r1.get(), "SQL, DMY", "SQL, DMY");
            run(c.get(), "SET DateStyle = 'ISO, MDY'");
            PGResPtr r2(PQexecPrepared(c.get(), "zz_sc1", 0, nullptr, nullptr, nullptr, 0), &PQclear);
            err2 += checkExtTracked(c.get(), r2.get(), "SQL, DMY", "SQL, DMY");
        }
        ok(err1.empty(), "set_config %s, extended: named statement tracked and forwarded %s", mode, err1.c_str());
        ok(err2.empty(), "set_config %s, extended: tracked again on its second Execute %s", mode, err2.c_str());
    }
    {
        PGConnPtr c = createNewConnection(ConnType::BACKEND);
        std::string err = c ? "" : "no connection";
        if (c) {
            PGResPtr r = runParams(c.get(), "SELECT set_config('DateStyle','SQL, DMY',false)");
            err = checkExtTracked(c.get(), r.get(), "SQL, DMY", "SQL, DMY");
        }
        ok(err.empty(), "set_config %s, extended: unnamed statement tracked and forwarded %s", mode, err.c_str());
    }
    {
        PGConnPtr c = createNewConnection(ConnType::BACKEND);
        int locked = -2;
        std::string row;
        if (c) {
            const char* values[2] = { "DateStyle", "SQL, DMY" };
            PGResPtr r = runParams(c.get(), "SELECT set_config($1,$2,false)", 2, values);
            row = PQresultStatus(r.get()) == PGRES_TUPLES_OK ? PQgetvalue(r.get(), 0, 0) : PQerrorMessage(c.get());
            locked = lockedOnHostgroup(c.get());
        }
        ok(locked >= 0 && row == "SQL, DMY", "set_config %s, extended: $1 arguments lock (row '%s', locked %d)", mode, row.c_str(), locked);
    }
    {
        // Batched: the batching gate must send the call down the one-message path.
        PGConnPtr c = createNewConnection(ConnType::BACKEND);
        std::string err = c ? "" : "no connection";
        if (c) {
            run(c.get(), "SET DateStyle = 'SQL, DMY'");
            if (!PQenterPipelineMode(c.get())) err = "no pipeline mode";
            const char* qs[] = { "SELECT 1", "SELECT set_config('DateStyle','ISO, MDY',false)", "SHOW DateStyle" };
            for (const char* q : qs) PQsendQueryParams(c.get(), q, 0, nullptr, nullptr, nullptr, nullptr, 0);
            if (PQpipelineSync(c.get()) != 1) {
                err += " pipeline sync failed";
            } else {
                std::string shown;
                int results = 0;
                for (;;) {
                    PGresult* r = PQgetResult(c.get());
                    if (r == nullptr) { if (results >= 4) break; continue; }
                    const ExecStatusType st = PQresultStatus(r);
                    if (st == PGRES_PIPELINE_SYNC) { PQclear(r); results++; break; }
                    if (st == PGRES_TUPLES_OK) { results++; if (results == 3) shown = PQgetvalue(r, 0, 0); }
                    else if (st == PGRES_FATAL_ERROR || st == PGRES_PIPELINE_ABORTED) { err += std::string(" error: ") + PQresultErrorMessage(r); results++; }
                    PQclear(r);
                }
                if (shown != "ISO, MDY") err += " SHOW '" + shown + "'";
            }
            PQexitPipelineMode(c.get());
            if (stored(c.get(), "DateStyle") != "ISO, MDY") err += " stored '" + stored(c.get(), "DateStyle") + "'";
        }
        ok(err.empty(), "set_config %s, extended: in a pipeline, the next statement sees the value %s", mode, err.c_str());
    }
    {
        PGConnPtr c = createNewConnection(ConnType::BACKEND);
        std::string state;
        if (c) {
            PGResPtr p(PQprepare(c.get(), "zz_sc2", "SELECT set_config('DateStyle',42,false)", 0, nullptr), &PQclear);
            state = resultField(p.get(), PG_DIAG_SQLSTATE);
        }
        ok(state == "42883", "set_config %s, extended: a wrong argument type fails at Parse, from PostgreSQL (got '%s')", mode, state.c_str());
    }
    const struct { const char* query; const char* sqlstate; const char* message; } errs[] = {
        { "SELECT set_config('DateStyle','Invalid Zone!',false)", "22023", "invalid value for parameter \"DateStyle\": \"Invalid Zone!\"" },
        { "SELECT set_config(NULL,'ISO, MDY',false)", "22004", "SET requires parameter name" },
    };
    for (const auto& e : errs) {
        PGConnPtr c = createNewConnection(ConnType::BACKEND);
        std::string err = c ? "" : "no connection";
        if (c) {
            const std::string before = stored(c.get(), "DateStyle");
            PGResPtr r = runParams(c.get(), e.query);
            const std::string state = resultField(r.get(), PG_DIAG_SQLSTATE), msg = resultField(r.get(), PG_DIAG_MESSAGE_PRIMARY);
            if (state != e.sqlstate || msg != e.message) err = "got " + state + " '" + msg + "'";
            if (stored(c.get(), "DateStyle") != before) err += " stored '" + stored(c.get(), "DateStyle") + "'";
            if (lockedOnHostgroup(c.get()) != -1) err += " locked";
            if (oneValue(c.get(), "SELECT 1") != "1") err += " connection unusable";
        }
        ok(err.empty(), "set_config %s, extended: %s at Execute: %s %s", mode, e.sqlstate, e.query, err.c_str());
    }
    {
        // NULL over the extended protocol is unsupported: PostgreSQL would reset the backend to
        // its own default, so ProxySQL refuses it without mutating the client value.
        PGConnPtr c = createNewConnection(ConnType::BACKEND, "-c DateStyle=SQL,DMY");
        std::string state = "<no connection>";
        std::string before = "<no connection>";
        std::string after = "<no connection>";
        int locked = -2;
        bool usable = false;
        if (c) {
            run(c.get(), "SET DateStyle = 'ISO, MDY'");
            before = stored(c.get(), "DateStyle");
            PGResPtr r = runParams(c.get(), "SELECT set_config('DateStyle',NULL,false)");
            state = resultField(r.get(), PG_DIAG_SQLSTATE);
            after = stored(c.get(), "DateStyle");
            locked = lockedOnHostgroup(c.get());
            usable = (oneValue(c.get(), "SELECT 1") == "1");
            const std::string bytea_before = stored(c.get(), "bytea_output");
            PGResPtr no_startup = runParams(c.get(), "SELECT set_config('bytea_output',NULL,false)");
            usable = usable && resultField(no_startup.get(), PG_DIAG_SQLSTATE) == "0A000" &&
                stored(c.get(), "bytea_output") == bytea_before && oneValue(c.get(), "SELECT 1") == "1";
        }
        ok(state == "0A000" && before == after && locked == -1 && usable,
            "set_config %s, extended: NULL is unsupported (state '%s', stored '%s'->'%s', locked %d, usable %d)",
            mode, state.c_str(), before.c_str(), after.c_str(), locked, usable);
    }
}

static void test_set_config_extended() {
    PGConnPtr admin = createNewConnection(ConnType::ADMIN);
    const int hg = rootDefaultHostgroup(admin.get());
    const std::vector<std::string> servers = (hg >= 0) ? snapshotServers(admin.get(), hg) : std::vector<std::string>{};
    const std::string saved_algo = adminGet(admin.get(), "pgsql-set_parser_algorithm");
    const std::string saved_native = adminGet(admin.get(), "pgsql-use_native_backend_protocol");
    ok(admin && !saved_algo.empty() && adminSet(admin.get(), "pgsql-set_parser_algorithm", "3"),
        "set_config extended: pgsql-set_parser_algorithm=3 (was %s)", saved_algo.c_str());
    for (const bool native : { true, false }) {
        adminSet(admin.get(), "pgsql-use_native_backend_protocol", native ? "true" : "false");
        if (!servers.empty()) reloadServers(admin.get(), hg, servers, false);
        sc_ext_phase(native);
    }
    const bool restored = adminSet(admin.get(), "pgsql-use_native_backend_protocol", saved_native) &&
        adminSet(admin.get(), "pgsql-set_parser_algorithm", saved_algo) &&
        (servers.empty() || reloadServers(admin.get(), hg, servers, false));
    ok(restored, "set_config extended: variables and servers restored");
}

// set_config() inside a pipeline (SELECT 1, the call and SELECT 2 before one Sync): the native
// backend batches such a unit, and the call has to leave the batch to be followed.
static const int SC_PIPE_PHASE_TESTS = 3 /* tracked */ + 3 /* leak */ + 1 /* lock */ + 1 /* error */;
static const int SC_PIPE_TESTS = 1 /* setup */ + 2 * SC_PIPE_PHASE_TESTS + 1 /* restore */;

static void sc_pipe_phase(PGconn* admin, int hg, const std::vector<std::string>& servers, bool native) {
    g_proto = Proto::PIPELINE;
    g_mode = std::string(native ? "native" : "libpq") + " pipeline";
    const char* m = g_mode.c_str();
    {
        PGConnPtr c = createNewConnection(ConnType::BACKEND, "-c DateStyle=ISO,MDY");
        std::string row = "<no connection>", st = "<no connection>", shown = "<no connection>";
        int locked = -2;
        if (c) {
            PGresult* r = execMode(c.get(), "SELECT set_config('DateStyle','SQL, DMY',false)");
            row = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) ? PQgetvalue(r, 0, 0) : PQerrorMessage(c.get());
            PQclear(r);
            st = stored(c.get(), "DateStyle");
            locked = lockedOnHostgroup(c.get());
            shown = oneValue(c.get(), "SHOW DateStyle");
        }
        ok(row == "SQL, DMY", "[%s] set_config: the call returns 'SQL, DMY' (got '%s')", m, row.c_str());
        ok(st == "SQL, DMY" && locked == -1, "[%s] set_config: recorded, no lock (stored '%s', locked %d)", m, st.c_str(), locked);
        ok(shown == "SQL, DMY", "[%s] set_config: the backend agrees (SHOW DateStyle '%s')", m, shown.c_str());
    }
    const bool capped = !servers.empty() && reloadServers(admin, hg, servers, true);
    if (capped) {
        sc_leak_case("-c maintenance_work_mem=64MB", "maintenance_work_mem", "128MB", "64MB");
        reloadServers(admin, hg, servers, false);
    } else {
        skip(3, "cannot limit hostgroup %d to one backend connection", hg);
    }
    {
        PGConnPtr c = createNewConnection(ConnType::BACKEND);
        int locked = -2;
        if (c) {
            PQclear(execMode(c.get(), "SELECT set_config('DateStyle','ISO, MDY',false), 1"));
            locked = lockedOnHostgroup(c.get());
        }
        ok(locked >= 0, "[%s] set_config: a form it cannot follow locks (locked %d)", m, locked);
    }
    {
        PGConnPtr c = createNewConnection(ConnType::BACKEND);
        std::string state = "<no connection>";
        if (c) {
            PGresult* r = execMode(c.get(), "SELECT set_config(NULL,'x',false)");
            state = resultField(r, PG_DIAG_SQLSTATE);
            PQclear(r);
        }
        ok(state == "22004", "[%s] set_config: a NULL name is refused with 22004 (got '%s')", m, state.c_str());
    }
    g_proto = Proto::SIMPLE;
}

static void test_set_config_pipeline() {
    PGConnPtr admin = createNewConnection(ConnType::ADMIN);
    const int hg = rootDefaultHostgroup(admin.get());
    const std::vector<std::string> servers = (hg >= 0) ? snapshotServers(admin.get(), hg) : std::vector<std::string>{};
    const std::string saved_algo = adminGet(admin.get(), "pgsql-set_parser_algorithm");
    const std::string saved_native = adminGet(admin.get(), "pgsql-use_native_backend_protocol");
    ok(admin && !saved_algo.empty() && adminSet(admin.get(), "pgsql-set_parser_algorithm", "3"),
        "set_config pipeline: pgsql-set_parser_algorithm=3 (was %s)", saved_algo.c_str());
    for (const bool native : { true, false }) {
        adminSet(admin.get(), "pgsql-use_native_backend_protocol", native ? "true" : "false");
        if (!servers.empty()) reloadServers(admin.get(), hg, servers, false);
        sc_pipe_phase(admin.get(), hg, servers, native);
    }
    const bool restored = adminSet(admin.get(), "pgsql-use_native_backend_protocol", saved_native) &&
        adminSet(admin.get(), "pgsql-set_parser_algorithm", saved_algo) &&
        (servers.empty() || reloadServers(admin.get(), hg, servers, false));
    ok(restored, "set_config pipeline: variables and servers restored");
}

// The four SET phases (empty search_path, quoted DEFAULT, stored form, empty DateStyle) in
// every backend mode and protocol.
static const int SET_MODES = 6;

static void test_set_phases_in_every_mode() {
    PGConnPtr admin = createNewConnection(ConnType::ADMIN);
    const int hg = rootDefaultHostgroup(admin.get());
    const std::vector<std::string> servers = (hg >= 0) ? snapshotServers(admin.get(), hg) : std::vector<std::string>{};
    const std::string saved_native = adminGet(admin.get(), "pgsql-use_native_backend_protocol");
    const char* proto_name[3] = { "simple", "extended", "pipeline" };
    for (const bool native : { true, false }) {
        adminSet(admin.get(), "pgsql-use_native_backend_protocol", native ? "true" : "false");
        // Pooled connections keep the mode they were opened in.
        if (!servers.empty()) reloadServers(admin.get(), hg, servers, false);
        for (int p = 0; p < 3; p++) {
            g_proto = (Proto)p;
            g_mode = std::string(native ? "native " : "libpq ") + proto_name[p];
            test_quoted_default_is_a_value();
            test_stored_form_matches_postgresql();
            test_extended_empty_datestyle();
            usleep(500000);
            test_empty_search_path_syncs();
            usleep(500000);
        }
    }
    g_proto = Proto::SIMPLE;
    const bool restored = adminSet(admin.get(), "pgsql-use_native_backend_protocol", saved_native) &&
        (servers.empty() || reloadServers(admin.get(), hg, servers, false));
    ok(restored, "SET phases: pgsql-use_native_backend_protocol restored to '%s'", saved_native.c_str());
}

// Query rules that rewrite a statement into, out of, or within a set_config() call. The rewritten
// text is what runs, so it is what ProxySQL must follow. The rewrite cleared the query's scan, and
// a rewritten call went untracked.
struct ScRwRule { int id; const char* match; const char* replace; };
static const ScRwRule sc_rw_rules[] = {
    { 9071, "128MB", "256MB" },
    { 9072, "'zz_rw_into'", "set_config('maintenance_work_mem','256MB',false)" },
    { 9073, "set_config\\W+maintenance_work_mem\\W+512MB\\W+false\\W", "'zz_rw_out'" },
    { 9074, " AS zz_rw_lock", ", 1 AS zz_rw_lock" },
};
// `stored` is what is recorded while tracking is on; nullptr: the session locks instead.
struct ScRwCase { const char* label; const char* sql; const char* row; const char* stored; };
static const ScRwCase sc_rw_cases[] = {
    { "the value rewritten", "SELECT set_config('maintenance_work_mem','128MB',false)", "256MB", "256MB" },
    { "a query rewritten into a call", "SELECT 'zz_rw_into'", "256MB", "256MB" },
    { "a call rewritten into a query", "SELECT set_config('maintenance_work_mem','512MB',false)", "zz_rw_out", "64MB" },
    { "a call rewritten into a form that locks", "SELECT set_config('maintenance_work_mem','768MB',false) AS zz_rw_lock",
        "768MB", nullptr },
};
// Tracking by pgsql-set_parser_algorithm=3, by pgsql-query_processor_parser=1, and off.
struct ScRwConfig { const char* name; const char* algo; const char* qpp; bool tracks; };
static const ScRwConfig sc_rw_configs[] = {
    { "set_parser_algorithm=3", "3", "0", true },
    { "query_processor_parser=1", "2", "1", true },
    { "tracking off", "2", "0", false },
};
static const int SC_RW_TESTS = 1 /* setup */ + (int)std::size(sc_rw_configs) * SET_MODES * (int)std::size(sc_rw_cases) +
    2 * 2 /* statement reuse, native and libpq */ + 1 /* restore */;

static int sc_rw_seq = 0;
// The same statement with a text no earlier statement had: a cached statement brings its own scan.
static std::string sc_rw_unique(const char* sql) {
    return "SELECT /* rw " + std::to_string(getpid()) + "-" + std::to_string(++sc_rw_seq) + " */ " + std::string(sql + 7);
}

static void sc_rw_case(const ScRwConfig& cfg, const ScRwCase& k) {
    PGConnPtr c = createNewConnection(ConnType::BACKEND, "-c maintenance_work_mem=64MB");
    std::string row = "<no connection>", st = "<no connection>", shown = "<no connection>";
    int locked = -2;
    if (c) {
        PGresult* r = execMode(c.get(), sc_rw_unique(k.sql));
        row = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) ? PQgetvalue(r, 0, 0) : PQerrorMessage(c.get());
        PQclear(r);
        st = stored(c.get(), "maintenance_work_mem");
        locked = lockedOnHostgroup(c.get());
        shown = oneValue(c.get(), "SHOW maintenance_work_mem");
    }
    bool good = row == k.row;
    if (!cfg.tracks) good = good && st == "64MB" && locked == -1;  // forwarded untracked, as documented
    else if (k.stored == nullptr) good = good && locked >= 0;
    else good = good && st == k.stored && locked == -1 && shown == k.stored;
    ok(good, "[%s] set_config rewrite, %s: %s (row '%s', stored '%s', locked %d, SHOW '%s')", g_mode.c_str(), cfg.name,
        k.label, row.c_str(), st.c_str(), locked, shown.c_str());
}

// One statement executed twice, the second time after a SET put maintenance_work_mem back: the second Execute
// must be recorded as well. By an unnamed statement parsed again (a cache hit) and a named one.
static void sc_rw_reuse_case(bool named) {
    PGConnPtr c = createNewConnection(ConnType::BACKEND, "-c maintenance_work_mem=64MB");
    std::string st1 = "<no connection>", st2 = "<no connection>";
    if (c) {
        const std::string q = sc_rw_unique("SELECT set_config('maintenance_work_mem','128MB',false)");
        if (named) PQclear(PQprepare(c.get(), "zz_rw_named", q.c_str(), 0, nullptr));
        for (int i = 0; i < 2; i++) {
            PQclear(named ? PQexecPrepared(c.get(), "zz_rw_named", 0, nullptr, nullptr, nullptr, 0) :
                PQexecParams(c.get(), q.c_str(), 0, nullptr, nullptr, nullptr, nullptr, 0));
            (i == 0 ? st1 : st2) = stored(c.get(), "maintenance_work_mem");
            if (i == 0) PQclear(PQexec(c.get(), "SET maintenance_work_mem TO '64MB'"));
        }
    }
    ok(st1 == "256MB" && st2 == "256MB", "[%s] set_config rewrite: %s executed twice is recorded both times "
        "(stored '%s', then '%s')", g_mode.c_str(), named ? "a named statement" : "an unnamed statement parsed again",
        st1.c_str(), st2.c_str());
}

static void test_set_config_rewritten() {
    PGConnPtr admin = createNewConnection(ConnType::ADMIN);
    const int hg = rootDefaultHostgroup(admin.get());
    const std::vector<std::string> servers = (hg >= 0) ? snapshotServers(admin.get(), hg) : std::vector<std::string>{};
    const std::string saved_algo = adminGet(admin.get(), "pgsql-set_parser_algorithm");
    const std::string saved_qpp = adminGet(admin.get(), "pgsql-query_processor_parser");
    const std::string saved_native = adminGet(admin.get(), "pgsql-use_native_backend_protocol");
    bool rules = admin && !saved_algo.empty() && !saved_qpp.empty();
    for (const auto& r : sc_rw_rules) {
        rules = rules && execAdmin(admin.get(), "INSERT INTO pgsql_query_rules (rule_id,active,match_pattern,replace_pattern,apply) "
            "VALUES (" + std::to_string(r.id) + ",1," + sqlQuote(r.match) + "," + sqlQuote(r.replace) + ",1)");
    }
    rules = rules && execAdmin(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME");
    ok(rules, "set_config rewrite: %zu query rules loaded", std::size(sc_rw_rules));
    const char* proto_name[3] = { "simple", "extended", "pipeline" };
    for (const auto& cfg : sc_rw_configs) {
        adminSet(admin.get(), "pgsql-set_parser_algorithm", cfg.algo);
        adminSet(admin.get(), "pgsql-query_processor_parser", cfg.qpp);
        for (const bool native : { true, false }) {
            adminSet(admin.get(), "pgsql-use_native_backend_protocol", native ? "true" : "false");
            if (!servers.empty()) reloadServers(admin.get(), hg, servers, false);
            for (int p = 0; p < 3; p++) {
                g_proto = (Proto)p;
                g_mode = std::string(native ? "native " : "libpq ") + proto_name[p];
                for (const auto& k : sc_rw_cases) sc_rw_case(cfg, k);
            }
            g_proto = Proto::SIMPLE;
            if (cfg.tracks && std::string(cfg.algo) == "3") {
                g_mode = std::string(native ? "native" : "libpq") + " extended";
                sc_rw_reuse_case(false);
                sc_rw_reuse_case(true);
            }
        }
    }
    g_proto = Proto::SIMPLE;
    bool restored = true;
    for (const auto& r : sc_rw_rules) {
        restored = execAdmin(admin.get(), "DELETE FROM pgsql_query_rules WHERE rule_id=" + std::to_string(r.id)) && restored;
    }
    // With tracking off the rewritten calls changed backends ProxySQL does not know about: drop them.
    restored = execAdmin(admin.get(), "LOAD PGSQL QUERY RULES TO RUNTIME") &&
        adminSet(admin.get(), "pgsql-use_native_backend_protocol", saved_native) &&
        adminSet(admin.get(), "pgsql-query_processor_parser", saved_qpp) &&
        adminSet(admin.get(), "pgsql-set_parser_algorithm", saved_algo) &&
        (servers.empty() || reloadServers(admin.get(), hg, servers, false)) && restored;
    ok(restored, "set_config rewrite: rules removed, variables and servers restored");
}

int main(int argc, char** argv) {
    int total_tests = 2 + untracked_set_cases.size() * UNTRACKED_SET_TESTS_PER_CASE + 1; // + servers restored
    total_tests += SC_TESTS;
    total_tests += SC_EXT_TESTS;
    total_tests += SC_PIPE_TESTS;
    total_tests += SC_RW_TESTS;
    total_tests += SET_MODES * (stored_form_cases.size() + 1 + all_default_cases().size() +
        EXTENDED_EMPTY_DATESTYLE_TESTS + EMPTY_SEARCH_PATH_TESTS) + 1;

	for (const auto& test_case : test_cases) {
		total_tests += test_case.commands.size();
	}

    plan(total_tests);

    if (cl.getEnv())
        return exit_status();

    const int parser_algorithm = query_pgsql_set_parser_algorithm();

    // The one-connection pools below park a backend for the next client. With max_connections=1
    // the default free_connections_pct (10) keeps no free connection: an idle round closes it,
    // and the next client gets a new backend instead of the one it must reuse.
    PGConnPtr pct_admin = createNewConnection(ConnType::ADMIN);
    const std::string saved_free_pct = pct_admin ? adminGet(pct_admin.get(), "pgsql-free_connections_pct") : "";
    if (pct_admin) adminSet(pct_admin.get(), "pgsql-free_connections_pct", "100");
    diag("pgsql-set_parser_algorithm = %d (per-case algo3 override %s)",
         parser_algorithm, parser_algorithm == 3 ? "ACTIVE" : "ignored");

    PGConnPtr client_conn = createNewConnection(ConnType::CLIENT, "", false);
    if (!client_conn || PQstatus(client_conn.get()) != CONNECTION_OK) {
        BAIL_OUT("Error: failed to create an unprivileged PostgreSQL connection");
        return exit_status();
    }
    const std::string client_user = queryCurrentUser(client_conn.get());
    ok(client_user == cl.pgsql_username,
        "unprivileged frontend retains its backend identity (expected '%s', got '%s')",
        cl.pgsql_username, client_user.c_str());
    client_conn.reset();

    PGConnPtr conn = createNewConnection(ConnType::BACKEND, "", false);
    if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
        BAIL_OUT("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
        return exit_status();
    }
    const std::string backend_user = queryCurrentUser(conn.get());
    ok(backend_user == cl.pgsql_root_username,
        "privileged frontend does not reuse the unprivileged backend identity (expected '%s', got '%s')",
        cl.pgsql_root_username, backend_user.c_str());

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
                    // Pick algo3 override only when (a) the proxysql we are
                    // talking to is configured with pgsql-set_parser_algorithm=3
                    // AND (b) the test case actually provided one. Otherwise
                    // fall back to the standard expected value.
                    const std::string& effective_expected =
                        (parser_algorithm == 3 && !cmd_test.expected_value_algo3.empty())
                            ? cmd_test.expected_value_algo3
                            : cmd_test.expected_value;
                    if (new_value != effective_expected) {
                        error_msg = "Expected '" + effective_expected +
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

    // Close the connection first: an earlier case may have locked it on the hostgroup,
    // holding a backend connection that would leave none for the single-connection pool.
    conn.reset();
    usleep(500000); // let its backend connection finish resetting before the pool is flushed
    test_untracked_set_does_not_leak();
    usleep(500000);
    test_set_phases_in_every_mode();
    usleep(500000);
    test_set_config_tracking();
    test_set_config_extended();
    usleep(500000);
    test_set_config_pipeline();
    test_set_config_rewritten();

    if (pct_admin && !saved_free_pct.empty()) adminSet(pct_admin.get(), "pgsql-free_connections_pct", saved_free_pct);
    return exit_status();
}
