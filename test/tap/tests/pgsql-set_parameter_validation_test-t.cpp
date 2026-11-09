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
        ok(servers.empty() || reloadServers(admin.get(), hg, servers, false), "servers of hostgroup %d restored", hg);
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
        PGresult* res = PQexec(b.get(), "SELECT pg_catalog.pg_backend_pid(), current_setting('search_path')");
        if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) == 1) {
            b_pid = PQgetvalue(res, 0, 0);
            value = PQgetvalue(res, 0, 1);
        } else {
            err = PQerrorMessage(b.get());
        }
        PQclear(res);
    }
    ok(err.empty(), "empty search_path: first query of the client succeeds (%s)", err.c_str());
    ok(value == "\"\"", "empty search_path: backend search_path is '\"\"' (got '%s')", value.c_str());
    ok(!a_pid.empty() && b_pid == a_pid, "empty search_path: the sync ran on the reused backend (A pid %s, B pid %s)",
        a_pid.c_str(), b_pid.c_str());
    b.reset();
    usleep(200000);
    ok(reloadServers(admin.get(), hg, servers, false), "servers of hostgroup %d restored", hg);
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
            ok(false, "quoted DEFAULT: %s (no connection)", c.set.c_str());
            continue;
        }
        std::string err;
        if (!c.setup.empty()) {
            PGresult* r = PQexec(conn.get(), c.setup.c_str());
            if (PQresultStatus(r) != PGRES_COMMAND_OK) err = "setup failed: " + std::string(PQerrorMessage(conn.get()));
            PQclear(r);
        }
        if (err.empty()) {
            PGresult* r = PQexec(conn.get(), c.set.c_str());
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
        ok(err.empty(), "quoted DEFAULT: [%s] %s%s%s %s", c.options.c_str(), c.setup.c_str(),
            c.setup.empty() ? "" : "; ", c.set.c_str(), err.c_str());
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
            PGresult* r = PQexec(conn.get(), set.c_str());
            if (refused) {
                const std::string state = resultField(r, PG_DIAG_SQLSTATE);
                if (PQresultStatus(r) != PGRES_FATAL_ERROR || state != "22023") err = "expected 22023, got '" + state + "'";
            } else if (PQresultStatus(r) != PGRES_COMMAND_OK) {
                err = PQerrorMessage(conn.get());
            }
            PQclear(r);
            v = stored(conn.get(), c.name);
        }
        ok(err.empty() && v == want, "stored form: %s -> %s '%s' (got '%s') %s", set.c_str(),
            refused ? "refused, keeps" : "", want.c_str(), v.c_str(), err.c_str());
    }

    PGConnPtr a = createNewConnection(ConnType::BACKEND);
    PGConnPtr b = createNewConnection(ConnType::BACKEND);
    std::string va = "<no connection>", vb = "<no connection>";
    if (a && b) {
        PQclear(PQexec(a.get(), "SET maintenance_work_mem = '1024MB'"));
        PQclear(PQexec(b.get(), "SET maintenance_work_mem = '1GB'"));
        va = stored(a.get(), "maintenance_work_mem");
        vb = stored(b.get(), "maintenance_work_mem");
    }
    ok(va == "1GB" && vb == "1GB", "stored form: '1024MB' and '1GB' are recorded alike (A '%s', B '%s')",
        va.c_str(), vb.c_str());
}

int main(int argc, char** argv) {
    int total_tests = 2 + untracked_set_cases.size() * UNTRACKED_SET_TESTS_PER_CASE + 1; // + servers restored
    total_tests += stored_form_cases.size() + 1;
    total_tests += all_default_cases().size();
    total_tests += EMPTY_SEARCH_PATH_TESTS;

	for (const auto& test_case : test_cases) {
		total_tests += test_case.commands.size();
	}

    plan(total_tests);

    if (cl.getEnv())
        return exit_status();

    const int parser_algorithm = query_pgsql_set_parser_algorithm();
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
    test_quoted_default_is_a_value();
    test_stored_form_matches_postgresql();
    usleep(500000); // let its backend connection finish resetting before the pool is flushed
    test_untracked_set_does_not_leak();
    usleep(500000);
    test_empty_search_path_syncs();

    return exit_status();
}
