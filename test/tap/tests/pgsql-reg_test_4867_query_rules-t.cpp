/**
 * @file pgsql-reg_test_4867_query_rules-t-t.cpp
 * @brief This TAP test ensures that the main.pgsql_query_rules table is correctly synchronized with both runtime_pgsql_query_rules 
 *  and disk_pgsql_query_rules, while also verifying that values are not swapped between columns.
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
    const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
    const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;

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

bool executeQueries(PGconn* conn, const std::vector<std::string>& queries) {
    for (const auto& query : queries) {
        diag("Running: %s", query.c_str());
        PGresult* res = PQexec(conn, query.c_str());
        bool success = PQresultStatus(res) == PGRES_COMMAND_OK ||
            PQresultStatus(res) == PGRES_TUPLES_OK;
        if (!success) {
            diag("Failed to execute query '%s': %s",
                query.c_str(), PQerrorMessage(conn));
            PQclear(res);
            return false;
        }
        PQclear(res);
    }
    return true;
}

typedef struct {
    int rule_id;
    int active;
    char* username;
    char* database;
    int flagIN;
    char* client_addr;
    char* proxy_addr;
    int proxy_port;
    unsigned int digest;
    char* match_digest;
    char* match_pattern;
    int negate_match_pattern;
    const char* re_modifiers;
    int flagOUT;
    char* replace_pattern;
    int destination_hostgroup;
    int cache_ttl;
    int cache_empty_result;
    int cache_timeout;
    int reconnect;
    unsigned int timeout;
    int retries;
    unsigned int delay;
    unsigned int next_query_flagIN;
    unsigned int mirror_flagOUT;
    unsigned int mirror_hostgroup;
    char* error_msg;
    char* OK_msg;
    int sticky_conn;
    int multiplex;
    int log;
    int apply;
    char* attributes;
    char* comment;
} RuleData;

// Unique value generator with offsets
typedef struct {
    int base;
    int offset;
} ValueGenerator;

// Compare two strings considering NULL
bool compare_str(const char* a, const char* b) {
    if (a == NULL && b == NULL) return true;
    if (a == NULL || b == NULL) return false;
    return strcmp(a, b) == 0;
}

int next_val(ValueGenerator* vg) {
    return vg->base + (vg->offset++);
}

char* unique_str(ValueGenerator* vg, const char* field) {
    char* str = (char*)malloc(32);
    sprintf(str, "%s_%d", field, next_val(vg));
    return str;
}

char* unique_ip(ValueGenerator* vg) {
    char* ip = (char*)malloc(16);
    int octet = vg->base + vg->offset++;
    sprintf(ip, "%d.%d.%d.%d",
        octet % 256, (octet + 1) % 256, (octet + 2) % 256, (octet + 3) % 256);
    return ip;
}

char* unique_json(ValueGenerator* vg) {
    char* json = (char*)malloc(50);
    sprintf(json, "{\"%s\":%d}", "unique_key", next_val(vg));
    return json;
}

char* pvsprintf(const char* fmt, va_list args) {
    va_list args_copy;
    int len;
    size_t size;
    char* buffer;

    // Create a copy of args to determine the length
    va_copy(args_copy, args);
    len = vsnprintf(NULL, 0, fmt, args_copy);
    va_end(args_copy);

    if (len < 0) {
        return NULL; // Formatting error occurred
    }

    size = len + 1; // +1 for the null terminator
    buffer = (char*)malloc(size);
    if (buffer == NULL) {
        return NULL; // Memory allocation failed
    }

    // Now format the string into the allocated buffer
    len = vsnprintf(buffer, size, fmt, args);
    if (len < 0) {
        free(buffer);
        return NULL; // Formatting error occurred
    }

    return buffer;
}

char* psprintf(const char* fmt, ...) {
    va_list args;
    char* result;

    va_start(args, fmt);
    result = pvsprintf(fmt, args);
    va_end(args);

    return result;
}

char* escape_str(PGconn* conn, const char* str) {
    if (!str) return strdup("NULL");
    char* esc = PQescapeLiteral(conn, str, strlen(str));
    return esc ? esc : strdup("NULL");
}

// Build INSERT query for a rule
char* build_insert_query(PGconn* conn, RuleData* rule) {
    char* query = NULL;
    char* esc_username = escape_str(conn, rule->username);
    char* esc_database = escape_str(conn, rule->database);
    char* esc_client_addr = escape_str(conn, rule->client_addr);
    char* esc_proxy_addr = escape_str(conn, rule->proxy_addr);
    char* esc_proxy_port = (rule->proxy_port != -1) ? psprintf("%d", rule->proxy_port) : strdup("NULL");
    char* esc_match_digest = escape_str(conn, rule->match_digest);
    char* esc_match_pattern = escape_str(conn, rule->match_pattern);
    char* esc_replace_pattern = escape_str(conn, rule->replace_pattern);
    char* esc_destination_hostgroup = (rule->destination_hostgroup != -1) ? psprintf("%d", rule->destination_hostgroup) : strdup("NULL");
    char* esc_cache_ttl = (rule->cache_ttl != -1) ? psprintf("%d", rule->cache_ttl) : strdup("NULL");
    char* esc_cache_empty_result = (rule->cache_empty_result != -1) ? psprintf("%d", rule->cache_empty_result) : strdup("NULL");
    char* esc_cache_timeout = (rule->cache_timeout != -1) ? psprintf("%d", rule->cache_timeout) : strdup("NULL");
    char* esc_reconnect = (rule->reconnect != -1) ? psprintf("%d", rule->reconnect) : strdup("NULL");
    char* esc_flagOUT = (rule->flagOUT != -1) ? psprintf("%d", rule->flagOUT) : strdup("NULL");
    char* esc_error_msg = escape_str(conn, rule->error_msg);
    char* esc_OK_msg = escape_str(conn, rule->OK_msg);
    char* esc_attributes = escape_str(conn, rule->attributes);
    char* esc_comment = escape_str(conn, rule->comment);

    query = psprintf(
        "INSERT INTO pgsql_query_rules ("
        "active, username, database, flagIN, client_addr, proxy_addr, proxy_port, "
        "digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, "
        "destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, "
        "next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, log, apply, attributes, comment"
        ") VALUES ("
        "%d, %s, %s, %d, %s, %s, %s, "
        "%u, %s, %s, %d, '%s', %s, %s, "
        "%s, %s, %s, %s, %s, %u, %d, %u, "
        "%u, %u, %u, %s, %s, %d, %d, %d, %d, %s, %s"
        ") RETURNING rule_id",
        rule->active, esc_username, esc_database, rule->flagIN, esc_client_addr, esc_proxy_addr, esc_proxy_port,
        rule->digest, esc_match_digest, esc_match_pattern, rule->negate_match_pattern, rule->re_modifiers, esc_flagOUT, esc_replace_pattern,
        esc_destination_hostgroup, esc_cache_ttl, esc_cache_empty_result, esc_cache_timeout, esc_reconnect, rule->timeout, rule->retries, rule->delay,
        rule->next_query_flagIN, rule->mirror_flagOUT, rule->mirror_hostgroup, esc_error_msg, esc_OK_msg, rule->sticky_conn, rule->multiplex, rule->log, rule->apply, esc_attributes, esc_comment
    );

    // Free all allocated strings
    free(esc_username);
    free(esc_database);
    free(esc_client_addr);
    free(esc_proxy_addr);
    free(esc_proxy_port);
    free(esc_match_digest);
    free(esc_match_pattern);
    free(esc_replace_pattern);
    free(esc_destination_hostgroup);
    free(esc_cache_ttl);
    free(esc_cache_empty_result);
    free(esc_cache_timeout);
    free(esc_reconnect);
    free(esc_flagOUT);
    free(esc_error_msg);
    free(esc_OK_msg);
    free(esc_attributes);
    free(esc_comment);

    return query;
}


void generate_rule(RuleData* rule, int base) {
    ValueGenerator vg = { base, 0 };

    // Generate unique values for each field
    rule->active = 1;  
    rule->username = unique_str(&vg, "user");
    rule->database = unique_str(&vg, "db");
    rule->flagIN = next_val(&vg);
    rule->client_addr = unique_ip(&vg);
    rule->proxy_addr = unique_ip(&vg);
    rule->proxy_port = next_val(&vg) % 65536;
    rule->digest = next_val(&vg);
    rule->match_digest = unique_str(&vg, "match_dig");
    rule->match_pattern = unique_str(&vg, "pattern");
    rule->negate_match_pattern = next_val(&vg) % 2;
    rule->re_modifiers = "CASELESS";  // Keep simple for demo
    rule->flagOUT = next_val(&vg);
    rule->replace_pattern = unique_str(&vg, "replace");
    rule->destination_hostgroup = next_val(&vg);
    rule->cache_ttl = next_val(&vg);
    rule->cache_empty_result = next_val(&vg) % 2;
    rule->cache_timeout = next_val(&vg);
    rule->reconnect = next_val(&vg) % 2;
    rule->timeout = next_val(&vg);
    rule->retries = next_val(&vg) % 1001;
    rule->delay = next_val(&vg);
    rule->next_query_flagIN = next_val(&vg);
    rule->mirror_flagOUT = next_val(&vg);
    rule->mirror_hostgroup = next_val(&vg);
    rule->error_msg = unique_str(&vg, "err");
    rule->OK_msg = unique_str(&vg, "ok");
    rule->sticky_conn = next_val(&vg) % 2;
    rule->multiplex = next_val(&vg) % 3;
    rule->log = next_val(&vg) % 2;
    rule->apply = next_val(&vg) % 2;
    rule->attributes = unique_json(&vg);
    rule->comment = unique_str(&vg, "comment");
}

bool check_result(PGresult* res, RuleData* expected, bool runtime_table) {
    bool match = true;
    int f;

    // Compare each field
#define COMPARE_INT(col, field) \
            f = PQfnumber(res, col); \
            if (atoi(PQgetvalue(res, 0, f)) != expected->field) { \
                match = false; \
                diag("Expected %s to be %d. Actual %s", col, expected->field, PQgetvalue(res, 0, f)); \
            }
#define COMPARE_STR(col, field) \
            f = PQfnumber(res, col); \
            if (PQgetisnull(res, 0, f)) { \
                if (expected->field != NULL) {\
                    match = false; \
                    diag("Expected %s to be NULL. Actual %s", col, PQgetvalue(res, 0, f)); \
                } \
            } else { \
                if (!compare_str(PQgetvalue(res, 0, f), expected->field)) { \
                    match = false; \
                    diag("Expected %s to be %s. Actual %s", col, expected->field, PQgetvalue(res, 0, f)); \
                } \
            }

        // Compare each field systematically
    COMPARE_INT("active", active);
    COMPARE_STR("username", username);
    COMPARE_STR("database", database);
    COMPARE_INT("\"flagIN\"", flagIN);
    COMPARE_STR("client_addr", client_addr);
    COMPARE_STR("proxy_addr", proxy_addr);

    // proxy_port (nullable)
    f = PQfnumber(res, "proxy_port");
    if (PQgetisnull(res, 0, f)) {
        if (expected->proxy_port != -1) {
            match = false;
            diag("Expected proxy_port to be NULL. Actual %s", PQgetvalue(res, 0, f));
        }
    }
    else {
        if (atoi(PQgetvalue(res, 0, f)) != expected->proxy_port) {
            match = false;
            diag("Expected proxy_port to be %d. Actual %s", expected->proxy_port, PQgetvalue(res, 0, f));
        }
    }

    if (runtime_table == true) {

        // converting digest to hex string
        char hex_string[20];
        sprintf(hex_string, "0x%016X", expected->digest);
        f = PQfnumber(res, "digest");
        if (!compare_str(PQgetvalue(res, 0, f), hex_string)) {
            match = false;
            diag("Expected digest to be %s. Actual %s", hex_string, PQgetvalue(res, 0, f));
        }
	} else {
		COMPARE_INT("digest", digest);
	}

    COMPARE_STR("match_digest", match_digest);
    COMPARE_STR("match_pattern", match_pattern);
    COMPARE_INT("negate_match_pattern", negate_match_pattern);
    COMPARE_STR("re_modifiers", re_modifiers);

    // flagOUT (nullable)
    f = PQfnumber(res, "\"flagOUT\"");
    if (PQgetisnull(res, 0, f)) {
        if (expected->flagOUT != -1) {
            match = false;
            diag("Expected flagOUT to be NULL. Actual %s", PQgetvalue(res, 0, f));
        }
    }
    else {
        if (atoi(PQgetvalue(res, 0, f)) != expected->flagOUT) {
            match = false;
            diag("Expected flagOUT to be %d. Actual %s", expected->flagOUT, PQgetvalue(res, 0, f));
        }
    }

    COMPARE_STR("replace_pattern", replace_pattern);

    // destination_hostgroup (nullable)
    f = PQfnumber(res, "destination_hostgroup");
    if (PQgetisnull(res, 0, f)) {
        if (expected->destination_hostgroup != -1) {
            match = false;
            diag("Expected destination_hostgroup to be NULL. Actual %s", PQgetvalue(res, 0, f));
        }
    }
    else {
        if (atoi(PQgetvalue(res, 0, f)) != expected->destination_hostgroup) {
            match = false;
            diag("Expected destination_hostgroup to be %d. Actual %s", expected->destination_hostgroup, PQgetvalue(res, 0, f));
        }
    }

    // cache_ttl (nullable)
    f = PQfnumber(res, "cache_ttl");
    if (PQgetisnull(res, 0, f)) {
        if (expected->cache_ttl != -1) {
            match = false;
            diag("Expected cache_ttl to be NULL. Actual %s", PQgetvalue(res, 0, f));
        }
    }
    else {
        if (atoi(PQgetvalue(res, 0, f)) != expected->cache_ttl) {
            match = false;
            diag("Expected cache_ttl to be %d. Actual %s", expected->cache_ttl, PQgetvalue(res, 0, f));
        }
    }

    // cache_empty_result (nullable)
    f = PQfnumber(res, "cache_empty_result");
    if (PQgetisnull(res, 0, f)) {
        if (expected->cache_empty_result != -1) {
            match = false;
            diag("Expected cache_empty_result to be NULL. Actual %s", PQgetvalue(res, 0, f));
        }
    }
    else {
        if (atoi(PQgetvalue(res, 0, f)) != expected->cache_empty_result) {
            match = false;
            diag("Expected cache_empty_result to be %d. Actual %s", expected->cache_empty_result, PQgetvalue(res, 0, f));
        }
    }

    // cache_timeout (nullable)
    f = PQfnumber(res, "cache_timeout");
    if (PQgetisnull(res, 0, f)) {
        if (expected->cache_timeout != -1) {
            match = false;
            diag("Expected cache_timeout to be NULL. Actual %s", PQgetvalue(res, 0, f));
        }
    }
    else {
        if (atoi(PQgetvalue(res, 0, f)) != expected->cache_timeout) {
            match = false;
            diag("Expected cache_timeout to be %d. Actual %s", expected->cache_timeout, PQgetvalue(res, 0, f));
        }
    }

    // reconnect (nullable)
    f = PQfnumber(res, "reconnect");
    if (PQgetisnull(res, 0, f)) {
        if (expected->reconnect != -1) {
            match = false;
            diag("Expected reconnect to be NULL. Actual %s", PQgetvalue(res, 0, f));
        }
    }
    else {
        if (atoi(PQgetvalue(res, 0, f)) != expected->reconnect) {
            match = false;
            diag("Expected reconnect to be %d. Actual %s", expected->reconnect, PQgetvalue(res, 0, f));
        }
    }

    COMPARE_INT("timeout", timeout);
    COMPARE_INT("retries", retries);
    COMPARE_INT("delay", delay);
    COMPARE_INT("\"next_query_flagIN\"", next_query_flagIN);
    COMPARE_INT("\"mirror_flagOUT\"", mirror_flagOUT);
    COMPARE_INT("mirror_hostgroup", mirror_hostgroup);
    COMPARE_STR("error_msg", error_msg);
    COMPARE_STR("\"OK_msg\"", OK_msg);
    COMPARE_INT("sticky_conn", sticky_conn);
    COMPARE_INT("multiplex", multiplex);
    COMPARE_INT("log", log);
    COMPARE_INT("apply", apply);
    COMPARE_STR("attributes", attributes);
    COMPARE_STR("comment", comment);

    PQclear(res);
    return match;
}

int main() {
    int num_tests = 3;
    plan(num_tests * 2);

    if (cl.getEnv())
        return exit_status();

    PGConnPtr conn = createNewConnection(ConnType::ADMIN, "", false);
    if (!conn || PQstatus(conn.get()) != CONNECTION_OK) {
        BAIL_OUT("Error: failed to connect to the database in file %s, line %d", __FILE__, __LINE__);
        return exit_status();
    }

    srand(time(NULL));
    RuleData* rules = (RuleData*)malloc(num_tests * sizeof(RuleData));
    int* rule_ids = (int*)malloc(num_tests * sizeof(int));

    if (!executeQueries(conn.get(), { "DELETE FROM pgsql_query_rules",
                                      "LOAD PGSQL QUERY RULES TO RUNTIME" })) {
        goto cleanup;
    }

    // Insert test rules
    for (int i = 0; i < num_tests; i++) {
        generate_rule(&rules[i], (i + 1) * 1000); // Unique base per rule
        char* query = build_insert_query(conn.get(), &rules[i]);
        PGresult* res = PQexec(conn.get(), query);
        if (PQresultStatus(res) != PGRES_TUPLES_OK) {
            fprintf(stderr, "INSERT failed for rule %d: %s\n", i, PQerrorMessage(conn.get()));
            free(query);
            PQclear(res);
            continue;
        }
        rule_ids[i] = atoi(PQgetvalue(res, 0, 0));
        PQclear(res);
        free(query);
    }

    if (!executeQueries(conn.get(), { "LOAD PGSQL QUERY RULES TO RUNTIME" })) {
        goto cleanup;
    }

    diag(">>>> Checking runtime_pgsql_query_rules table...");
    // Check rules in runtime table
    for (int i = 0; i < num_tests; i++) {
        char query[256];
        sprintf(query, "SELECT * FROM runtime_pgsql_query_rules WHERE rule_id = %d", rule_ids[i]);
        PGresult* res = PQexec(conn.get(), query);
        if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
            fprintf(stderr, "Rule %d not found\n", rule_ids[i]);
            PQclear(res);
            continue;
        }

       ok(check_result(res, &rules[i], true), "Rule should match (%d)", rule_ids[i]);
    }

    if (!executeQueries(conn.get(), { "DROP TABLE IF EXISTS pgsql_query_rules_4867",
                                      "CREATE TABLE pgsql_query_rules_4867 AS SELECT * FROM disk.pgsql_query_rules",
                                      "SAVE PGSQL QUERY RULES TO DISK" })) {
        goto cleanup;
    }

    diag(">>>> Checking disk.pgsql_query_rules table...");
    // Check rules in runtime table
    for (int i = 0; i < num_tests; i++) {
        char query[256];
        sprintf(query, "SELECT * FROM disk.pgsql_query_rules WHERE rule_id = %d", rule_ids[i]);
        PGresult* res = PQexec(conn.get(), query);
        if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
            fprintf(stderr, "Rule %d not found\n", rule_ids[i]);
            PQclear(res);
            continue;
        }

        ok(check_result(res, &rules[i], false), "Rule should match (%d)", rule_ids[i]);
    }

restore_pgsql_query_rules:
    if (!executeQueries(conn.get(), { "DELETE FROM disk.pgsql_query_rules",
                                      "INSERT INTO disk.pgsql_query_rules SELECT * FROM pgsql_query_rules_4867" })) {
        goto cleanup;
    }

cleanup:
    for (int i = 0; i < num_tests; i++) {
        free(rules[i].username);
        free(rules[i].database);
        free(rules[i].client_addr);
        free(rules[i].proxy_addr);
        free(rules[i].match_digest);
        free(rules[i].match_pattern);
        free(rules[i].replace_pattern);
        free(rules[i].error_msg);
        free(rules[i].OK_msg);
        free(rules[i].attributes);
        free(rules[i].comment);
    }
    free(rules);
    free(rule_ids);

    return exit_status();
}
