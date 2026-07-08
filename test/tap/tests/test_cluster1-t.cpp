#include <memory>
#include <vector>
#include <string>
#include <stdio.h>
#include <cstring>
#include <set>
#include <unistd.h>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"


/*
 * this test assumes that this proxysql instance is part of a 10 nodes cluster
 * there are 4 core nodes and 6 satellite nodes
 * 127.0.0.1:6032 : this proxy (core node 0)
 * 127.0.0.1:26001 : core node1
 * 127.0.0.1:26002 : core node2
 * 127.0.0.1:26003 : core node3
 * 127.0.0.1:26004 : satellite node1
 * 127.0.0.1:26005 : satellite node2
 * 127.0.0.1:26006 : satellite node3
 * 127.0.0.1:26007 : satellite node4
 * 127.0.0.1:26008 : satellite node5
 * 127.0.0.1:26009 : satellite node6
*/

void get_time(std::string& s) {
	time_t timer_var;
	char buffer_var[30];
	struct tm tm_info_var;
	time(&timer_var);
	localtime_r(&timer_var, &tm_info_var);
	strftime(buffer_var, 25, "%Y-%m-%d %H:%M:%S", &tm_info_var);
	s = std::string(buffer_var);
}



// we make the very simple assumptions that all proxies are running
// on 127.0.0.1 , therefore we only specify the ports
std::vector<int> cluster_ports = {
	6032,
	26001,
	26002,
	26003,
	26004,
	26005,
	26006,
	26007,
	26008,
	26009
};

// New vector for node hosts
std::vector<std::pair<std::string, int>> cluster_nodes;

// these simply queries update a variable to make sure that a resync is triggered
const char * update_admin_variables_1 = "UPDATE global_variables SET variable_value=variable_value+1 WHERE variable_name='admin-refresh_interval'";
const char * update_mysql_variables_1 = "UPDATE global_variables SET variable_value=variable_value+1 WHERE variable_name='mysql-monitor_connect_interval'";
const char * update_mysql_query_rules_1 = "UPDATE mysql_query_rules SET comment = IFNULL(comment,'') || 'a'";
const char * update_mysql_users_1 = "UPDATE mysql_users SET max_connections = max_connections + 1";
const char * update_mysql_servers_1 = "UPDATE mysql_servers SET max_connections = max_connections + 1";
std::vector<MYSQL *> conns;


int dumping_checksums_return_uniq(MYSQL_RES *res, std::set<std::string>& checksums) {
        MYSQL_ROW row;
        while ((row = mysql_fetch_row(res))) {
                diag("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s", row[0], row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8]);
                std::string chk = row[5];
                checksums.insert(chk);
        }
	return static_cast<int>(checksums.size());
}

int get_checksum_impl(MYSQL* mysql, const std::string& name, std::string& value) {
        std::string query { "SELECT checksum FROM runtime_checksums_values WHERE name='" + name + "'" };

        if (mysql_query(mysql, query.c_str())) {
                fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
                return -1;
        }

        MYSQL_RES * res = mysql_store_result(mysql);
	int rr = static_cast<int>(mysql_num_rows(res));
        MYSQL_ROW row;
        while ((row = mysql_fetch_row(res))) {
                value = std::string(row[0]);
        }
        mysql_free_result(res);

        return rr;
}

int get_checksum(MYSQL *mysql, const std::string& name, std::string& value) {
	int rr = get_checksum_impl(mysql, name, value);
        ok(rr == 1 && value.length() > 0, "Checksum for %s = %s" , name.c_str(), value.c_str());
        if (rr == 1 && value.length() > 0) return 0;
        return 1;
}

int module_in_sync(
        MYSQL* tg_admin, MYSQL* fetch_conn, const std::string& name, const std::string& init_chk, int num_retries, int& i
) {
        std::string query = "SELECT hostname, port, name, version, epoch, checksum, changed_at, updated_at, diff_check FROM stats_proxysql_servers_checksums WHERE name='" + name + "'";
        std::string checksum { init_chk };
        int rc = 0;

        while (i< num_retries && rc != 1) {
                std::set<std::string> checksums;
                MYSQL_QUERY(tg_admin, query.c_str());
                MYSQL_RES * res = mysql_store_result(tg_admin);
                std::string s;
                get_time(s);
                diag("%s: Dumping %s", s.c_str(), query.c_str());
                int rc = dumping_checksums_return_uniq(res, checksums);
                mysql_free_result(res);
                if (rc == 1) {
                        std::set<std::string>::iterator it = checksums.begin();
                        if (*it == checksum) {
                                return 0;
                        } else {
				int chk_res = get_checksum_impl(fetch_conn, name, checksum);
                                if (chk_res != -1) {
                                        diag("Fetched new '%s' target checksum '%s'", name.c_str(), checksum.c_str());
                                } else {
                                        diag("Fetching new checksum for module '%s' failed", name.c_str());
                                }
                        }
                }
                sleep(1);
                i++;
        }

        return 1;
}

int create_connections(CommandLine& cl) {
        if (cluster_nodes.empty()) {
                for (size_t i = 0; i < cluster_ports.size() ; i++) {
                        MYSQL * mysql = mysql_init(NULL);
                        if (!mysql) {
                                fprintf(stderr, "File %s, line %d, Error: mysql_init failed for port %d\n",
                                        __FILE__, __LINE__, cluster_ports[i]);
                                return exit_status();
                        }

                        mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
                        if (!mysql_real_connect(mysql, cl.host, cl.admin_username, cl.admin_password, NULL, cluster_ports[i], NULL, CLIENT_SSL|CLIENT_COMPRESS)) {
                                fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysql));
                                mysql_close(mysql);
                                return exit_status();
                        }
                        conns.push_back(mysql);
                }
        } else {
                for (size_t i = 0; i < cluster_nodes.size(); i++) {
                        MYSQL * mysql = mysql_init(NULL);
                        if (!mysql) {
                                fprintf(stderr, "File %s, line %d, Error: mysql_init failed for node %s:%d\n",
                                        __FILE__, __LINE__, cluster_nodes[i].first.c_str(), cluster_nodes[i].second);
                                return exit_status();
                        }
                        mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
                        if (!mysql_real_connect(mysql, cluster_nodes[i].first.c_str(), cl.admin_username, cl.admin_password, NULL, cluster_nodes[i].second, NULL, CLIENT_SSL|CLIENT_COMPRESS)) {
                                fprintf(stderr, "File %s, line %d, Node %s:%d, Error: %s\n", __FILE__, __LINE__, cluster_nodes[i].first.c_str(), cluster_nodes[i].second, mysql_error(mysql));
                                mysql_close(mysql);
                                return exit_status();
                        }
                        conns.push_back(mysql);
                }
        }
        return 0;
}

// Close and drop every connection that create_connections() opened. Safe to
// call multiple times; the vector is cleared after closing.
static void close_all_connections() {
        for (MYSQL* m : conns) {
                if (m) mysql_close(m);
        }
        conns.clear();
}

int trigger_sync_and_check(MYSQL *mysql, const std::string& modname, const char *update_query, const char *load_query) {
        int rc;
        std::string chk1;
        std::string chk2;
        get_checksum(mysql, modname , chk1);
        MYSQL_QUERY(mysql, update_query);
        MYSQL_QUERY(mysql, load_query);
        get_checksum(mysql, modname, chk2);
        ok(chk1 != chk2 , "%s checksums. Before: %s , after: %s", modname.c_str(), chk1.c_str(), chk2.c_str());
        int retries = 0;
        rc = module_in_sync(mysql, mysql, modname, chk2, 30, retries);
        ok (rc == 0, "Module %s %sin sync after %d seconds" , modname.c_str() , rc == 0 ? "" : "NOT " , retries);
        for (size_t i = 4 ; i<conns.size() ; i++) {
                diag("Checking satellite node %zu", i);
                int retries = 0;
                rc = module_in_sync(conns[i], mysql, modname, chk2, 30, retries);
                ok (rc == 0, "On satellite %zu: Module %s %sin sync after %d seconds" , i, modname.c_str() , rc == 0 ? "" : "NOT " , retries);
        }
        return 0;
}

int main(int argc, char** argv) {
        CommandLine cl;

        if (cl.getEnv()) {
                diag("Failed to get the required environmental variables.");
                return -1;
        }

        // Parse cluster_nodes from env if present
        if (cl.cluster_nodes && strlen(cl.cluster_nodes) > 0) {
                char* nodes_str = strdup(cl.cluster_nodes);
                char* token = strtok(nodes_str, ",");
                while (token != NULL) {
                        char* colon = strchr(token, ':');
                        if (colon) {
                                *colon = '\0';
                                cluster_nodes.push_back({token, atoi(colon + 1)});
                        } else {
                                cluster_nodes.push_back({token, 6032});
                        }
                        token = strtok(NULL, ",");
                }
                free(nodes_str);
        }

        size_t total_nodes = cluster_nodes.empty() ? cluster_ports.size() : cluster_nodes.size();
        int np = 8;
	np += static_cast<int>(static_cast<size_t>(4)*5*(4+(total_nodes-4)));

        plan(np);

        // RAII wrapper so proxysql_admin is closed on every exit path, including
        // the early returns triggered by the MYSQL_QUERY macro on query failure.
        std::unique_ptr<MYSQL, decltype(&mysql_close)> proxysql_admin_owner{
                mysql_init(NULL), &mysql_close
        };
        MYSQL* proxysql_admin = proxysql_admin_owner.get();
        // Initialize connections. mysql_init returns NULL on failure; do not
        // call mysql_error on a NULL handle (undefined behavior).
        if (!proxysql_admin) {
                fprintf(stderr, "File %s, line %d, Error: mysql_init failed for 'proxysql_admin'\n",
                        __FILE__, __LINE__);
                return -1;
        }

        if (!mysql_real_connect(proxysql_admin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
                fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(proxysql_admin));
                return -1;
        }

        std::vector<std::string> modules = {
                "admin_variables",
                "ldap_variables",
                "mysql_variables",
                "mysql_query_rules",
                "mysql_servers",
                "mysql_users",
                "proxysql_servers",
        };

        std::string chk1;
        std::string chk2;
        get_checksum(proxysql_admin, "admin_variables", chk1);
        // we set all the admin-cluster_xxxx_save_to_disk to false to prevent that resync affects our testing proxy
        for (std::vector<std::string>::iterator it = modules.begin() ; it != modules.end() ; it++) {
                std::string q = "SET admin-cluster_" + *it + "_save_to_disk='false'";
                MYSQL_QUERY(proxysql_admin, q.c_str());
        }
        MYSQL_QUERY(proxysql_admin, update_admin_variables_1);
        MYSQL_QUERY(proxysql_admin, "LOAD ADMIN VARIABLES TO RUNTIME");
        get_checksum(proxysql_admin, "admin_variables", chk2);
        ok(chk1 != chk2 , "admin_variables checksums. Before: %s , after: %s", chk1.c_str(), chk2.c_str());

        get_checksum(proxysql_admin, "mysql_variables", chk1);
        MYSQL_QUERY(proxysql_admin, "SET mysql-have_ssl='true'");
        MYSQL_QUERY(proxysql_admin, "SET mysql-have_compress='true'");
        MYSQL_QUERY(proxysql_admin, "SET mysql-auditlog_filename=\"proxy-audit\"");
        MYSQL_QUERY(proxysql_admin, update_mysql_variables_1);
        MYSQL_QUERY(proxysql_admin, "LOAD MYSQL VARIABLES TO RUNTIME");
        get_checksum(proxysql_admin, "mysql_variables", chk2);
        ok(chk1 != chk2 , "mysql_variables checksums. Before: %s , after: %s", chk1.c_str(), chk2.c_str());



        // Probe every cluster admin port before opening the real SSL+COMPRESS
        // connections used by the test. Without this, a slow-to-start
        // secondary proxysql triggers a cryptic 'Can't connect to server
        // (115)' deep inside create_connections() — see issue #5782.
        int probe_rc;
        if (cluster_nodes.empty()) {
                probe_rc = wait_for_proxysql_cluster(
                        cl.host, cluster_ports, cl.admin_username, cl.admin_password);
        } else {
                probe_rc = wait_for_proxysql_cluster(
                        cluster_nodes, cl.admin_username, cl.admin_password);
        }
        if (probe_rc != 0) {
                diag("Cluster readiness probe failed; aborting before create_connections()");
                return exit_status();
        }

        int rc = create_connections(cl);
        if (rc != 0) {
                close_all_connections();
                return exit_status();
        }
        ok(conns.size() == total_nodes , "Known nodes: %lu . Connected nodes: %lu", total_nodes, conns.size());

        int retries = 0;
        rc = module_in_sync(proxysql_admin, proxysql_admin, "mysql_variables", chk2, 30, retries);
        ok (rc == 0, "Module mysql_variables %sin sync after %d seconds" , rc == 0 ? "" : "NOT " , retries);


        // The workflow here is simple, for each proxy:
        //      - Get the checksum of the module
        //      - Update the module
        //      - Get the new checksum
        //      - Now retry the following until success or timeout:
        //              1. Wait for all the other core nodes to sync and check the checksums.
        //              2. If the sync failed, refetch the target checksum from the node that received the change.
        for (int i = 0; i < 4; i++) {
                diag("Running changes on server node %d", i);
                trigger_sync_and_check(conns[i], "admin_variables", update_admin_variables_1, "LOAD ADMIN VARIABLES TO RUNTIME");
        }
        for (int i = 0; i < 4; i++) {
                diag("Running changes on server node %d", i);
                trigger_sync_and_check(conns[i], "mysql_variables", update_mysql_variables_1, "LOAD MYSQL VARIABLES TO RUNTIME");
        }
        for (int i = 0; i < 4; i++) {
                diag("Running changes on server node %d", i);
                trigger_sync_and_check(conns[i], "mysql_query_rules", update_mysql_query_rules_1, "LOAD MYSQL QUERY RULES TO RUNTIME");
        }
        for (int i = 0; i < 4; i++) {
                diag("Running changes on server node %d", i);
                trigger_sync_and_check(conns[i], "mysql_users", update_mysql_users_1, "LOAD MYSQL USERS TO RUNTIME");
        }
        // Check mysql_servers_v2 (config) instead of mysql_servers (runtime).
        // The cluster sync properly syncs mysql_servers_v2 (the config table)
        // between nodes. The runtime mysql_servers checksum is modified
        // independently on each node by the monitor (GR discovery, read-only
        // detection, etc.), so runtime checksums legitimately differ and
        // will never converge. Checking the config checksum is the correct
        // way to verify cluster sync with an active monitor.
        for (int i = 0; i < 4; i++) {
                diag("Running changes on server node %d", i);
                trigger_sync_and_check(conns[i], "mysql_servers_v2", update_mysql_servers_1, "LOAD MYSQL SERVERS TO RUNTIME");
        }

        close_all_connections();
        return exit_status();
}
