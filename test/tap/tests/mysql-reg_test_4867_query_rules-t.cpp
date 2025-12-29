/**
 * @file mysql-reg_test_4867_query_rules-t-t.cpp
 * @brief This TAP test ensures that the main.mysql_query_rules table is correctly synchronized with both runtime_mysql_query_rules
 *  and disk_mysql_query_rules, while also verifying that values are not swapped between columns.
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

using MySQLConnPtr = std::unique_ptr<MYSQL, decltype(&mysql_close)>;

typedef struct {
    int rule_id;
    int active;
    char* username;
    char* schemaname;
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
    int gtid_from_hostgroup;
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

char* escape_str(MYSQL* mysql, const char* str) {
    if (!str) return strdup("NULL");
    char* escaped = (char*)malloc(2 * strlen(str) + 1);
    mysql_real_escape_string(mysql, escaped, str, strlen(str));
    char* result = (char*)malloc(strlen(escaped) + 3);
    sprintf(result, "'%s'", escaped);
    free(escaped);
    return result;
}

// Build INSERT query for a rule
char* build_insert_query(MYSQL* mysql, RuleData* rule) {
    char* query = NULL;
    char* esc_username = escape_str(mysql, rule->username);
    char* esc_schemaname = escape_str(mysql, rule->schemaname);
    char* esc_client_addr = escape_str(mysql, rule->client_addr);
    char* esc_proxy_addr = escape_str(mysql, rule->proxy_addr);
    char* esc_proxy_port = (rule->proxy_port != -1) ? psprintf("%d", rule->proxy_port) : strdup("NULL");
    char* esc_match_digest = escape_str(mysql, rule->match_digest);
    char* esc_match_pattern = escape_str(mysql, rule->match_pattern);
    char* esc_replace_pattern = escape_str(mysql, rule->replace_pattern);
    char* esc_destination_hostgroup = (rule->destination_hostgroup != -1) ? psprintf("%d", rule->destination_hostgroup) : strdup("NULL");
    char* esc_cache_ttl = (rule->cache_ttl != -1) ? psprintf("%d", rule->cache_ttl) : strdup("NULL");
    char* esc_cache_empty_result = (rule->cache_empty_result != -1) ? psprintf("%d", rule->cache_empty_result) : strdup("NULL");
    char* esc_cache_timeout = (rule->cache_timeout != -1) ? psprintf("%d", rule->cache_timeout) : strdup("NULL");
    char* esc_reconnect = (rule->reconnect != -1) ? psprintf("%d", rule->reconnect) : strdup("NULL");
    char* esc_flagOUT = (rule->flagOUT != -1) ? psprintf("%d", rule->flagOUT) : strdup("NULL");
    char* esc_error_msg = escape_str(mysql, rule->error_msg);
    char* esc_OK_msg = escape_str(mysql, rule->OK_msg);
    char* esc_attributes = escape_str(mysql, rule->attributes);
    char* esc_comment = escape_str(mysql, rule->comment);

    query = psprintf(
        "INSERT INTO mysql_query_rules ("
        "active, username, schemaname, flagIN, client_addr, proxy_addr, proxy_port, "
        "digest, match_digest, match_pattern, negate_match_pattern, re_modifiers, flagOUT, replace_pattern, "
        "destination_hostgroup, cache_ttl, cache_empty_result, cache_timeout, reconnect, timeout, retries, delay, "
        "next_query_flagIN, mirror_flagOUT, mirror_hostgroup, error_msg, OK_msg, sticky_conn, multiplex, gtid_from_hostgroup, log, apply, attributes, comment"
        ") VALUES ("
        "%d, %s, %s, %d, %s, %s, %s, "
        "%u, %s, %s, %d, '%s', %s, %s, "
        "%s, %s, %s, %s, %s, %u, %d, %u, "
        "%u, %u, %u, %s, %s, %d, %d, %d, %d, %d, %s, %s"
        ")",
        rule->active, esc_username, esc_schemaname, rule->flagIN, esc_client_addr, esc_proxy_addr, esc_proxy_port,
        rule->digest, esc_match_digest, esc_match_pattern, rule->negate_match_pattern, rule->re_modifiers, esc_flagOUT, esc_replace_pattern,
        esc_destination_hostgroup, esc_cache_ttl, esc_cache_empty_result, esc_cache_timeout, esc_reconnect, rule->timeout, rule->retries, rule->delay,
        rule->next_query_flagIN, rule->mirror_flagOUT, rule->mirror_hostgroup, esc_error_msg, esc_OK_msg, rule->sticky_conn, rule->multiplex, rule->gtid_from_hostgroup, rule->log, rule->apply, esc_attributes, esc_comment
    );

    // Free all allocated strings
    free(esc_username);
    free(esc_schemaname);
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
    rule->schemaname = unique_str(&vg, "schemaname");
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
	rule->gtid_from_hostgroup = next_val(&vg);
    rule->log = next_val(&vg) % 2;
    rule->apply = next_val(&vg) % 2;
    rule->attributes = unique_json(&vg);
    rule->comment = unique_str(&vg, "comment");
}

bool check_result(MYSQL_RES* res, RuleData* expected, bool runtime_table) {
    MYSQL_ROW row = mysql_fetch_row(res);
    unsigned long* lengths = mysql_fetch_lengths(res);
    bool match = true;

    int field_idx = 1; // excluding rule_id
#define COMPARE_INT(expected_val, col) \
        if (row[field_idx] == NULL) { \
            if (expected_val != -1) { \
                diag("Expected %s to be %d, got NULL", #col, expected_val); \
                match = false; \
            } \
        } else { \
            int val = atoi(row[field_idx]); \
            if (val != expected_val) { \
                diag("Expected %s to be %d, got %d", #col, expected_val, val); \
                match = false; \
            } \
        } \
        field_idx++;

#define COMPARE_STR(expected_str, col) \
        if (row[field_idx] == NULL) { \
            if (expected_str != NULL) { \
                diag("Expected %s to be '%s', got NULL", #col, expected_str); \
                match = false; \
            } \
        } else { \
            if (strcmp(row[field_idx], expected_str ? expected_str : "") != 0) { \
                diag("Expected %s to be '%s', got '%s'", #col, expected_str, row[field_idx]); \
                match = false; \
            } \
        } \
        field_idx++;

    COMPARE_INT(expected->active, active);
    COMPARE_STR(expected->username, username);
    COMPARE_STR(expected->schemaname, schemaname);
    COMPARE_INT(expected->flagIN, flagIN);
    COMPARE_STR(expected->client_addr, client_addr);
    COMPARE_STR(expected->proxy_addr, proxy_addr);
    COMPARE_INT(expected->proxy_port, proxy_port);


    if (runtime_table == true) {

        // converting digest to hex string
        char hex_string[20];
        sprintf(hex_string, "0x%016X", expected->digest);

        if (strcmp(row[field_idx], hex_string ? hex_string : "") != 0) {
                diag("Expected digest to be '%s', got '%s'", hex_string, row[field_idx]);
                match = false;
        }
        field_idx++;
    }
    else {
        COMPARE_INT(expected->digest, digest);
    }
    

    COMPARE_STR(expected->match_digest, match_digest);
    COMPARE_STR(expected->match_pattern, match_pattern);
    COMPARE_INT(expected->negate_match_pattern, negate_match_pattern);
    COMPARE_STR(expected->re_modifiers, re_modifiers);
    COMPARE_INT(expected->flagOUT, flagOUT);
    COMPARE_STR(expected->replace_pattern, replace_pattern);
    COMPARE_INT(expected->destination_hostgroup, destination_hostgroup);
    COMPARE_INT(expected->cache_ttl, cache_ttl);
    COMPARE_INT(expected->cache_empty_result, cache_empty_result);
    COMPARE_INT(expected->cache_timeout, cache_timeout);
    COMPARE_INT(expected->reconnect, reconnect);
    COMPARE_INT(expected->timeout, timeout);
    COMPARE_INT(expected->retries, retries);
    COMPARE_INT(expected->delay, delay);
    COMPARE_INT(expected->next_query_flagIN, next_query_flagIN);
    COMPARE_INT(expected->mirror_flagOUT, mirror_flagOUT);
    COMPARE_INT(expected->mirror_hostgroup, mirror_hostgroup);
    COMPARE_STR(expected->error_msg, error_msg);
    COMPARE_STR(expected->OK_msg, OK_msg);
    COMPARE_INT(expected->sticky_conn, sticky_conn);
    COMPARE_INT(expected->multiplex, multiplex);
    COMPARE_INT(expected->gtid_from_hostgroup, gtid_from_hostgroup);
    COMPARE_INT(expected->log, log);
    COMPARE_INT(expected->apply, apply);
    COMPARE_STR(expected->attributes, attributes);
    COMPARE_STR(expected->comment, comment);

    return match;
}

#define MYSQL_QUERY_ON_ERR_CLEANUP(mysql, query) \
	do { \
		if (mysql_query(mysql, query)) { \
			fprintf(stderr, "File %s, line %d, Error: %s (%s)\n", __FILE__, __LINE__, mysql_error(mysql), query); \
			goto cleanup; \
		} \
	} while(0)

int main() {
    int num_tests = 3;
    plan(num_tests * 2);

    if (cl.getEnv())
        return exit_status();

	MySQLConnPtr conn(mysql_init(NULL), mysql_close);
    MYSQL* proxysql_admin = conn.get();

    // Initialize connections
    if (!proxysql_admin) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
        return -1;
    }

    if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
        return -1;
    }

    srand(time(NULL));
    RuleData* rules = (RuleData*)calloc(num_tests, sizeof(RuleData));
    int* rule_ids = (int*)malloc(num_tests * sizeof(int));

    MYSQL_QUERY_ON_ERR_CLEANUP(proxysql_admin, "DELETE FROM mysql_query_rules");
    MYSQL_QUERY_ON_ERR_CLEANUP(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

    // Insert test rules
    for (int i = 0; i < num_tests; i++) {
        generate_rule(&rules[i], (i + 1) * 1000); // Unique base per rule
        char* query = build_insert_query(proxysql_admin, &rules[i]);
        MYSQL_QUERY_ON_ERR_CLEANUP(proxysql_admin, query);
        free(query);

        // Get last insert ID
        MYSQL_RES* res = mysql_store_result(proxysql_admin);
        if (!res && mysql_field_count(proxysql_admin) == 0) {
            mysql_free_result(res);
            //rule_ids[i] = mysql_insert_id(proxysql_admin); // not supported in admin
            MYSQL_QUERY_ON_ERR_CLEANUP(proxysql_admin, "SELECT MAX(rule_id) FROM mysql_query_rules");
            MYSQL_ROW row;
            res = mysql_store_result(proxysql_admin);
            while ((row = mysql_fetch_row(res))) {
                rule_ids[i] = atoll(row[0]);
            }
            mysql_free_result(res);
        } else {
            diag("Failed to get rule_id for rule %d", i);
            if (res) mysql_free_result(res);
            continue;
        }
    }

    MYSQL_QUERY_ON_ERR_CLEANUP(proxysql_admin, "LOAD MYSQL QUERY RULES TO RUNTIME");

    diag(">>>> Checking runtime_mysql_query_rules table...");
    // Check rules in runtime table
    for (int i = 0; i < num_tests; i++) {
        char query[256];
        sprintf(query, "SELECT * FROM runtime_mysql_query_rules WHERE rule_id = %d", rule_ids[i]);
        MYSQL_QUERY_ON_ERR_CLEANUP(proxysql_admin, query);
        MYSQL_RES* res = mysql_store_result(proxysql_admin);
        if (!res || mysql_num_rows(res) == 0) {
            fprintf(stderr, "Rule %d not found\n", rule_ids[i]);
            if (res) mysql_free_result(res);
            continue;
        }

       ok(check_result(res, &rules[i], true), "Rule should match (%d)", rule_ids[i]);
       mysql_free_result(res);
    }

    MYSQL_QUERY_ON_ERR_CLEANUP(proxysql_admin, "DROP TABLE IF EXISTS mysql_query_rules_4867");
    MYSQL_QUERY_ON_ERR_CLEANUP(proxysql_admin, "CREATE TABLE mysql_query_rules_4867 AS SELECT * FROM disk.mysql_query_rules");
    MYSQL_QUERY_ON_ERR_CLEANUP(proxysql_admin, "SAVE MYSQL QUERY RULES TO DISK");

    diag(">>>> Checking disk.mysql_query_rules table...");
    // Check rules in runtime table
    for (int i = 0; i < num_tests; i++) {
        char query[256];
        sprintf(query, "SELECT * FROM disk.mysql_query_rules WHERE rule_id = %d", rule_ids[i]);

        if (mysql_query(proxysql_admin, query)) {
            fprintf(stderr, "File %s, line %d, Error: %s (%s)\n", __FILE__, __LINE__, mysql_error(proxysql_admin), query);
			goto restore_mysql_query_rules;
        } 
        MYSQL_RES* res = mysql_store_result(proxysql_admin);
        if (!res || mysql_num_rows(res) == 0) {
            fprintf(stderr, "Rule %d not found\n", rule_ids[i]);
            if (res) mysql_free_result(res);
            continue;
        }
        ok(check_result(res, &rules[i], false), "Rule should match (%d)", rule_ids[i]);
        mysql_free_result(res);
    }

restore_mysql_query_rules:
    MYSQL_QUERY_ON_ERR_CLEANUP(proxysql_admin, "DELETE FROM disk.mysql_query_rules");
    MYSQL_QUERY_ON_ERR_CLEANUP(proxysql_admin, "INSERT INTO disk.mysql_query_rules SELECT * FROM mysql_query_rules_4867");

cleanup:
    for (int i = 0; i < num_tests; i++) {
        free(rules[i].username);
        free(rules[i].schemaname);
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
