#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <string>
#include <sstream>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "noise_utils.h"
#include "utils.h"

int main(int argc, char** argv) {
    CommandLine cl;

    if(cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return exit_status();
    }

    diag("=== MySQL init_connect Test (Hostgroup Attributes) ===");
    diag("This test validates the functionality of 'mysql_hostgroup_attributes.init_connect'.");
    diag("It checks four scenarios:");
    diag("  1. Valid init_connect (DO 1): Connections should succeed.");
    diag("  2. Resultset-returning init_connect (SELECT 1): Connection should fail (PMC-10003).");
    diag("  3. High-latency init_connect (SELECT SLEEP(3)): Validates timeout/latency tracking.");
    diag("  4. Syntax error in init_connect: Connection should fail.");
    diag("========================================================");

    spawn_internal_noise(cl, internal_noise_random_stats_poller);
    spawn_internal_noise(cl, internal_noise_rest_prometheus_poller, {{"enable_rest_api", "true"}});
    spawn_internal_noise(cl, internal_noise_pgsql_traffic_v2, {{"num_connections", "100"}, {"reconnect_interval", "100"}, {"avg_delay_ms", "300"}});

    if (cl.use_noise) {
        plan(8 + 3);
    } else {
        plan(8);
    }

    MYSQL* mysqladmin = mysql_init(NULL);
    if (!mysqladmin) return exit_status();

    diag("Connecting to ProxySQL Admin: %s:%d as %s", cl.host, cl.admin_port, cl.admin_username);
    if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
        fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysqladmin));
        return exit_status();
    } else {
    diag("Configuring ProxySQL for the test requirements...");
    // Clear existing rules to avoid interference
    MYSQL_QUERY(mysqladmin, "DELETE FROM mysql_query_rules");
    
    // Create a rule to send all SELECTs from testuser to hostgroup 1
    MYSQL_QUERY(mysqladmin, "INSERT INTO mysql_query_rules(rule_id, active, username, match_digest, destination_hostgroup, apply) VALUES (1, 1, 'testuser', '^SELECT', 1, 1)");
    
    MYSQL_QUERY(mysqladmin, "LOAD MYSQL QUERY RULES TO RUNTIME");
    }

    MYSQL* mysql = mysql_init(NULL);
    if (!mysql) return exit_status();

    diag("Connecting to ProxySQL Frontend: %s:%d as %s", cl.host, cl.port, cl.username);
    if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
        fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
        return exit_status();
    }

    diag("Setting mysql_hostgroup_attributes.init_connect to DO 1");
    MYSQL_QUERY(mysqladmin, "DELETE FROM mysql_hostgroup_attributes");
    MYSQL_QUERY(mysqladmin, "INSERT INTO mysql_hostgroup_attributes(hostgroup_id, init_connect) VALUES (1,'DO 1')");
    MYSQL_QUERY(mysqladmin, "INSERT INTO mysql_hostgroup_attributes(hostgroup_id, init_connect) SELECT 0, init_connect FROM mysql_hostgroup_attributes");
    MYSQL_QUERY(mysqladmin, "LOAD MYSQL SERVERS TO RUNTIME");

    MYSQL_RES *res;

    {
        const char *q = "SELECT /* create_new_connection=1 */ 100";
        diag("Running query: %s", q);
        MYSQL_QUERY(mysql, q);
        res = mysql_store_result(mysql);
        MYSQL_ROW row;
        unsigned long long num_rows = mysql_num_rows(res);
        ok(num_rows == 1, "mysql_num_rows() , expected: 1 , actual: %llu", num_rows);
        while ((row = mysql_fetch_row(res))) {
            ok(strcmp(row[0],"100")==0, "row: expected: \"100\" , actual: \"%s\"", row[0]);
        }
        mysql_free_result(res);
    }

    diag("Setting mysql_hostgroup_attributes.init_connect to SELECT 1");
    MYSQL_QUERY(mysqladmin, "DELETE FROM mysql_hostgroup_attributes");
    MYSQL_QUERY(mysqladmin, "INSERT INTO mysql_hostgroup_attributes(hostgroup_id, init_connect) VALUES (1,'SELECT 1')");
    MYSQL_QUERY(mysqladmin, "INSERT INTO mysql_hostgroup_attributes(hostgroup_id, init_connect) SELECT 0, init_connect FROM mysql_hostgroup_attributes");
    MYSQL_QUERY(mysqladmin, "LOAD MYSQL SERVERS TO RUNTIME");

    {
        const char *q = "SELECT /* create_new_connection=1 */ 200";
        diag("Running query: %s", q);
        int rc=mysql_query(mysql,q);
        ok(rc!=0, "Query should fail. Error: %s", mysql_error(mysql));
        if (rc==0) return exit_status();
        mysql_close(mysql);
    }

    diag("Setting mysql_hostgroup_attributes.init_connect to SELECT SLEEP(3)");
    MYSQL_QUERY(mysqladmin, "DELETE FROM mysql_hostgroup_attributes");
    MYSQL_QUERY(mysqladmin, "INSERT INTO mysql_hostgroup_attributes(hostgroup_id, init_connect) VALUES (1,'SELECT SLEEP(3)')");
    MYSQL_QUERY(mysqladmin, "INSERT INTO mysql_hostgroup_attributes(hostgroup_id, init_connect) SELECT 0, init_connect FROM mysql_hostgroup_attributes");
    MYSQL_QUERY(mysqladmin, "LOAD MYSQL SERVERS TO RUNTIME");

    {
        MYSQL* mysql_re = mysql_init(NULL);
        if (!mysql_re) return exit_status();
        if (!mysql_real_connect(mysql_re, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
            fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql_re));
            return exit_status();
        }
        const char *q = "SELECT /* create_new_connection=1 */ 300";
        diag("Running query: %s", q);
        unsigned long long begin = monotonic_time();
        int rc=mysql_query(mysql_re,q);
        ok(rc!=0, "Query should fail. Error: %s", mysql_error(mysql_re));
        if (rc==0) return exit_status();
        mysql_close(mysql_re);
        unsigned long long end = monotonic_time();
        unsigned long time_diff_ms = (end-begin)/1000;
        ok(time_diff_ms>2900 && time_diff_ms < 3200 , "Total query execution time should be around 3 seconds. Actual : %lums", time_diff_ms);
    }

    diag("Setting mysql_hostgroup_attributes.init_connect to Syntax Error");
    MYSQL_QUERY(mysqladmin, "DELETE FROM mysql_hostgroup_attributes");
    MYSQL_QUERY(mysqladmin, "INSERT INTO mysql_hostgroup_attributes(hostgroup_id, init_connect) VALUES (1,'Syntax Error')");
    MYSQL_QUERY(mysqladmin, "INSERT INTO mysql_hostgroup_attributes(hostgroup_id, init_connect) SELECT 0, init_connect FROM mysql_hostgroup_attributes");
    MYSQL_QUERY(mysqladmin, "LOAD MYSQL SERVERS TO RUNTIME");

    {
        MYSQL* mysql_re2 = mysql_init(NULL);
        if (!mysql_re2) return exit_status();
        if (!mysql_real_connect(mysql_re2, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
            fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql_re2));
            return exit_status();
        }
        const char *q = "SELECT /* create_new_connection=1 */ 400";
        diag("Running query: %s", q);
        int rc=mysql_query(mysql_re2,q);
        ok(rc!=0, "Query should fail. Error: %s", mysql_error(mysql_re2));
        if (rc==0) return exit_status();
        mysql_close(mysql_re2);
    }

    diag("Setting mysql_hostgroup_attributes.init_connect to DO 1");
    MYSQL_QUERY(mysqladmin, "DELETE FROM mysql_hostgroup_attributes");
    MYSQL_QUERY(mysqladmin, "INSERT INTO mysql_hostgroup_attributes(hostgroup_id, init_connect) VALUES (1,'DO 1')");
    MYSQL_QUERY(mysqladmin, "INSERT INTO mysql_hostgroup_attributes(hostgroup_id, init_connect) SELECT 0, init_connect FROM mysql_hostgroup_attributes");
    MYSQL_QUERY(mysqladmin, "LOAD MYSQL SERVERS TO RUNTIME");

    {
        MYSQL* mysql_re3 = mysql_init(NULL);
        if (!mysql_re3) return exit_status();
        if (!mysql_real_connect(mysql_re3, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
            fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql_re3));
            return exit_status();
        }
        const char *q = "SELECT /* create_new_connection=1 */ 500";
        diag("Running query: %s", q);
        MYSQL_QUERY(mysql_re3, q);
        res = mysql_store_result(mysql_re3);
        MYSQL_ROW row;
        unsigned long long num_rows = mysql_num_rows(res);
        ok(num_rows == 1, "mysql_num_rows() , expected: 1 , actual: %llu", num_rows);
        while ((row = mysql_fetch_row(res))) {
            ok(strcmp(row[0],"500")==0, "row: expected: \"500\" , actual: \"%s\"", row[0]);
        }
        mysql_free_result(res);
        mysql_close(mysql_re3);
    }

    MYSQL_QUERY(mysqladmin, "DELETE FROM mysql_hostgroup_attributes");
    MYSQL_QUERY(mysqladmin, "LOAD MYSQL SERVERS TO RUNTIME");
    mysql_close(mysqladmin);

    return exit_status();
}
