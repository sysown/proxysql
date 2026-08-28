#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <unistd.h>

#include <vector>
#include <string>
#include <sstream>
#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "mariadb_rpl.h"

MYSQL * mysqladmin = NULL;
CommandLine cl;

#define NHB	10	// the number of heartbeat to wait

int run_queries_sets(std::vector<std::string>& queries, MYSQL *my, const std::string& message_prefix) {
	for (std::vector<std::string>::iterator it = queries.begin(); it != queries.end(); it++) {
		std::string q = *it;
		diag("%s: %s", message_prefix.c_str(), q.c_str());
		MYSQL_QUERY(my, q.c_str());
	}
	return 0;
}

std::vector<std::string> adminQ_set1 = {
	"SET mysql-have_ssl='false'",
	"LOAD MYSQL VARIABLES TO RUNTIME",
	"UPDATE mysql_servers SET use_ssl=1",
	"LOAD MYSQL SERVERS TO RUNTIME",
};


int pull_replication(MYSQL *mysql, int server_id) {
	MARIADB_RPL_EVENT *event= NULL;
	MARIADB_RPL *rpl= mariadb_rpl_init(mysql);
	if (!rpl) {
		fprintf(stderr, "File %s, line %d, Error: mariadb_rpl_init failed\n", __FILE__, __LINE__);
		return exit_status();
	}
	rpl->server_id= server_id;
	rpl->start_position= 4;
	rpl->flags= MARIADB_RPL_BINLOG_SEND_ANNOTATE_ROWS;
	if (mariadb_rpl_open(rpl)) {
		fprintf(stderr, "File %s, line %d, Error: '%d':%s\n", __FILE__, __LINE__, mysql_errno(rpl->mysql), mysql_error(rpl->mysql));
		return exit_status();
	}
	int num_heartbeats = 0;
	int num_events = 0;

	diag("Pulling all binlog events, it may take some time, be patient...");
	/*
	*  we iterate through all the events,
	*  and then wait NHB heartbeats
	*/
	while(num_heartbeats < NHB && (event= mariadb_rpl_fetch(rpl, event)))
	{
		num_events++;
		bool print_diag = false;
		if (event->event_type == HEARTBEAT_LOG_EVENT_V2 || event->event_type == HEARTBEAT_LOG_EVENT) {
			num_heartbeats++;
			print_diag = true;
		}
		if (print_diag == false) {
			// we try to not flood the log
			if (num_events < 10) {
				print_diag = true;
			} else if (num_events < 100) {
				if (num_events % 10 == 0) {
					print_diag = true;
				}
			} else if (num_events < 1000) {
				if (num_events % 100 == 0) {
					print_diag = true;
				}
			} else {
				if (num_events % 1000 == 0) {
					print_diag = true;
				}
			}
		}
		if (print_diag == true)
			diag("server_id %d , event: %d , received events: %d , received heartbeats: %d", server_id, event->event_type, num_events, num_heartbeats);
	}
	if (num_heartbeats < NHB && event == nullptr) {
		diag("'mariadb_rpl_fetch': Repl log ended before exp   error=\"%s\"", mysql_error(mysql));
	}
	// we expects NHB heartbeats
	ok(num_heartbeats == NHB , "For server_id %d received %d heartbeats", server_id, num_heartbeats);
	mariadb_free_rpl_event(event);
	mariadb_rpl_close(rpl);
	if (num_heartbeats != NHB) {
		return 1;
	}
	return 0;
}


std::vector<std::string> repl_queries_set1 = { // only 1 set, maybe more later
	"SET NAMES latin1",
	"SET NAMES utf8",
	"SET @master_binlog_checksum = 'NONE'",
	"SET @master_heartbeat_period=2000000000", // 2 seconds heartbeat
};

int setup_replication(int server_id, bool frontend_ssl, bool backend_ssl, std::vector<std::string>& mysql_queries) {
	diag("Running %s using server_id %d , frontend_ssl = %s , backend_ssl = %s", __func__ , server_id, (frontend_ssl ? "TRUE" : "FALSE") , (backend_ssl ? "TRUE" : "FALSE"));
	MYSQL * mysql = mysql_init(NULL);

	std::vector<std::string> admin_queries = {};
	admin_queries.push_back(std::string("SET mysql-have_ssl='") + std::string(frontend_ssl ? "true" : "false") + "'");
	admin_queries.push_back("LOAD MYSQL VARIABLES TO RUNTIME");
	admin_queries.push_back(std::string("UPDATE mysql_servers SET use_ssl=") + std::string(backend_ssl ? "1" : "0"));
	admin_queries.push_back("LOAD MYSQL SERVERS TO RUNTIME");

	if (!mysql)
		return exit_status();

	// NOTE: This must be forced. ProxySQL is going to honor CLIENT_DEPRECATE_EOF for fast-forward conns, and
	// during fast-forward conns transitions. This test attempts to convert a conn with mismatched
	// capabilities, '!CLIENT_DEPRECATE_EOF' on frontend and 'CLIENT_DEPRECATE_EOF' on backend, into a
	// fast-forward one, resulting in a disconnect.
	mysql->options.client_flag |= CLIENT_DEPRECATE_EOF;

	if (frontend_ssl) {
		mysql_ssl_set(mysql, NULL, NULL, NULL, NULL, NULL);
	}
	if (!mysql_real_connect(mysql, cl.root_host, cl.root_username, cl.root_password, NULL, cl.root_port, NULL, 0)) {
		fprintf(stderr, "Failed to connect to database: Error: %s\n", mysql_error(mysql));
		return exit_status();
	}
	if (run_queries_sets(admin_queries, mysqladmin, "Running on Admin"))
		return exit_status();
	if (run_queries_sets(mysql_queries, mysql, "Running on MySQL"))
		return exit_status();
	int rc = pull_replication(mysql, server_id);
	ok(rc==0,"Result with server_id %d , frontend_ssl = %s , backend_ssl = %s , rc = %d", server_id, (frontend_ssl ? "TRUE" : "FALSE") , (backend_ssl ? "TRUE" : "FALSE") , rc);
	if (rc != 0)
		return exit_status();
	mysql_close(mysql);
	return 0;
}

int main(int argc, char** argv) {
	diag("================================================================================");
	diag("TEST DESCRIPTION: ProxySQL Binlog Fast Forward Validation");
	diag("This test verifies ProxySQL's ability to handle MySQL replication traffic");
	diag("using the 'Fast Forward' mode. It tests the protocol transparency when");
	diag("streaming binlogs through ProxySQL with various SSL configurations.");
	diag("================================================================================");

	if (cl.getEnv()) {
		diag("ERROR: Failed to get the required environmental variables.");
		return exit_status();
	}

	plan(8); // each test has 2 OK

	mysqladmin = mysql_init(NULL);
	if (!mysqladmin)
		return exit_status();

	if (!mysql_real_connect(mysqladmin, cl.host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		fprintf(stderr, "File %s, line %d, Error: %s\n", __FILE__, __LINE__, mysql_error(mysqladmin));
		return exit_status();
	}
	diag("Successfully connected to ProxySQL Admin.");

	// DYNAMIC DISCOVERY: Find the correct default hostgroup for the root user
	int target_hg = 0;
	std::string hg_query = "SELECT default_hostgroup FROM mysql_users WHERE username='" + std::string(cl.root_username) + "' LIMIT 1";
	if (mysql_query(mysqladmin, hg_query.c_str()) == 0) {
		MYSQL_RES *res = mysql_store_result(mysqladmin);
		if (res) {
			MYSQL_ROW row = mysql_fetch_row(res);
			if (row) target_hg = atoi(row[0]);
			mysql_free_result(res);
		}
	}
	diag("Discovered target hostgroup for root user: %d", target_hg);

	// Create rules using the DISCOVERED hostgroup instead of hardcoded 0
	std::string rule_sql = "INSERT OR IGNORE INTO mysql_query_rules (rule_id,active,match_digest,destination_hostgroup,multiplex,apply) VALUES (-1,1,'^(SELECT @rpl_semi_sync_slave=\\?.*|SET @rpl_semi_sync_slave=\\?.*)$', " + std::to_string(target_hg) + ", 0, 1)";
	
	diag("Configuring ProxySQL rules for replication commands...");
	MYSQL_QUERY(mysqladmin, "DELETE FROM mysql_query_rules");
	MYSQL_QUERY(mysqladmin, rule_sql.c_str());
	MYSQL_QUERY(mysqladmin, "LOAD MYSQL QUERY RULES TO RUNTIME");

	// we now test various combination
	setup_replication(11, false, false, repl_queries_set1);
	setup_replication(12, true,  false, repl_queries_set1);
	setup_replication(13, false, true,  repl_queries_set1);
	setup_replication(14, true,  true,  repl_queries_set1);

	mysql_close(mysqladmin);

	return exit_status();
}
