/**
 * @file pgsql-copy_from_stdin_session_parameter-t.cpp
 * @brief Verifies whether the session parameter 'intervalstyle' is correctly set on the 
 *      backend connection when the connection switches to dynamic fast-forward mode during COPY FROM STDIN.
 */

#include <unistd.h>
#include <arpa/inet.h>
#include <string>
#include <sstream>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

constexpr unsigned int MAX_ITERATION = 10;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

enum ConnType {
    ADMIN,
    BACKEND
};

PGConnPtr createNewConnection(ConnType conn_type, bool with_ssl) {
    
    const char* host = (conn_type == BACKEND) ? cl.pgsql_host : cl.pgsql_admin_host;
    int port = (conn_type == BACKEND) ? cl.pgsql_port : cl.pgsql_admin_port;
    const char* username = (conn_type == BACKEND) ? cl.pgsql_username : cl.admin_username;
    const char* password = (conn_type == BACKEND) ? cl.pgsql_password : cl.admin_password;
    
    std::stringstream ss;

    ss << "host=" << host << " port=" << port;
    ss << " user=" << username << " password=" << password;
    ss << (with_ssl ? " sslmode=require" : " sslmode=disable");

    PGconn* conn = PQconnectdb(ss.str().c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "Connection failed to '%s': %s", (conn_type == BACKEND ? "Backend" : "Admin"), PQerrorMessage(conn));
        PQfinish(conn);
        return PGConnPtr(nullptr, &PQfinish);
    }
    return PGConnPtr(conn, &PQfinish);
}

bool executeQueries(PGconn* conn, const std::vector<std::string>& queries) {
    auto fnResultType = [](const char* query) -> int {
        const char* fs = strchr(query, ' ');
        size_t qtlen = strlen(query);
        if (fs != NULL) {
            qtlen = (fs - query) + 1;
        }
        char buf[qtlen];
        memcpy(buf, query, qtlen - 1);
        buf[qtlen - 1] = 0;

        if (strncasecmp(buf, "SHOW", sizeof("SHOW") - 1) == 0) {
            return PGRES_TUPLES_OK;
        }
        else if (strncasecmp(buf, "COPY", sizeof("COPY") - 1) == 0) {
			if (strstr(query, "FROM") && (strstr(query, "STDIN") || strstr(query, "STDOUT"))) {
				return PGRES_COPY_IN;
            }
        }

        return PGRES_COMMAND_OK;
        };


    for (const auto& query : queries) {
        diag("Running: %s", query.c_str());
        PGresult* res = PQexec(conn, query.c_str());
        bool success = PQresultStatus(res) == fnResultType(query.c_str());
        if (!success) {
            fprintf(stderr, "Failed to execute query '%s': %s",
                query.c_str(), PQerrorMessage(conn));
            PQclear(res);
            return false;
        }
        PQclear(res);
    }
    return true;
}

bool sendCopyData(PGconn* conn, const char* data, int size, bool last) {

    if (data != nullptr && size > 0) {
        if (PQputCopyData(conn, data, size) != 1) {
            fprintf(stderr, "Failed to send data: %s", PQerrorMessage(conn));
            return false;
        }
    }
    if (last) {
        if (PQputCopyEnd(conn, NULL) != 1) {
            fprintf(stderr, "Failed to send end of data: %s", PQerrorMessage(conn));
            return false;
        }
    }
    return true;
}

bool check_logs_for_command(std::fstream& f_proxysql_log, const std::string& command_regex) {
    const auto& [_, cmd_lines] { get_matching_lines(f_proxysql_log, command_regex) };
	return cmd_lines.empty() ? false : true;
}

bool setupTestTable(PGconn* conn) {
	return executeQueries(conn, { 
        "DROP TABLE IF EXISTS copy_in_test",
		"CREATE TABLE copy_in_test (column1 INT,column2 TEXT,column3 NUMERIC(10, 2),column4 BOOLEAN,column5 DATE)"
	});
}

std::vector<std::string> interval_style = {
	"sql_standard",
	"postgres",
	"postgres_verbose",
    "iso_8601"
};

std::string setIntervalStyle(PGconn* conn, int idx, std::fstream& f_proxysql_log) {
	const std::string& val = interval_style[idx % interval_style.size()];
	std::string query = "SET intervalstyle TO " + val;
	if (!executeQueries(conn, { query.c_str() }))
        return "";
    ok(check_logs_for_command(f_proxysql_log, ".*\\[WARNING\\] Unable to parse unknown SET query from client.*") == false, "Should not be locked on a hostgroup");
    f_proxysql_log.clear(f_proxysql_log.rdstate() & ~std::ios_base::failbit);
    f_proxysql_log.seekg(f_proxysql_log.tellg());
    return val;
}

std::vector<const char*> test_data = { "1\tHello\t123.45\tt\t2024-01-01\n",
									   "2\tWorld\t678.90\tf\t2024-02-15\n",
									   "3\tTest\t0.00\tt\t2023-12-25\n",
									   //"4\tSample\t-42.42\tf\t2024-11-27\n" 
                                       "4\tSample\t142.42\tf\t2024-11-27\n"
};

void copy_stdin_test(PGconn* conn, const std::string& set_val, std::fstream& f_proxysql_log) {
    // Multistatement query: First a SHOW, then COPY TO STDIN
    const char* query = "SHOW intervalstyle; COPY copy_in_test(column1,column2,column3,column4,column5) FROM STDIN (FORMAT TEXT);";
    if (PQsendQuery(conn, query) == 0) {
        fprintf(stderr, "Error sending query: %s\n", PQerrorMessage(conn));
        return;
    }

    PQconsumeInput(conn);
    while (PQisBusy(conn)) {
        PQconsumeInput(conn);
    }

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\].* Switching to Fast Forward mode \\(Session Type:0x06\\)"), "Session Switched to fast forward mode");

    // Check first result (SHOW statement)
    PGresult* res = PQgetResult(conn);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "SHOW failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return;
    }

    int rows = PQntuples(res);
    ok(rows == 1, "Expected 1 row from SHOW. Actual: %d", rows);

    // Check the data returned by SHOW
    char* value = PQgetvalue(res, 0, 0);
    ok(strncasecmp(value, set_val.c_str(), set_val.size()) == 0, "Expected value:'%s' , Actual Value:'%s'", set_val.c_str(), value);
    PQclear(res); // Clear result

    // Check second result (COPY FROM STDIN)
    res = PQgetResult(conn);
    if (PQresultStatus(res) != PGRES_COPY_IN) {
        fprintf(stderr, "COPY IN failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return;
    }

    bool success = true;
    for (unsigned int i = 0; i < test_data.size(); i++) {
        const char* data = test_data[i];
        bool last = (i == (test_data.size() - 1));
        if (!sendCopyData(conn, data, strlen(data), last)) {
            success = false;
            break;
        }
    }

    ok(success, "Copy data transmission should be successful");
    PQclear(res); // Clear result

    res = PQgetResult(conn);
    ok((PQresultStatus(res) == PGRES_COMMAND_OK), "Rows successfully inserted. %s", PQerrorMessage(conn));

    const char* row_count_str = PQcmdTuples(res);
    int row_count = atoi(row_count_str);
    ok(row_count == test_data.size(), "Total rows inserted: %d. Expected: %ld", row_count, test_data.size());
    PQclear(res);

    ok(check_logs_for_command(f_proxysql_log, ".*\\[INFO\\] Switching back to Normal mode \\(Session Type:0x06\\).*"), "Switching back to Normal mode");
    
    // Cleanup
    PQclear(PQgetResult(conn));
}

void execute_test(bool with_ssl, bool diff_conn, std::fstream& f_proxysql_log) {

    if (diff_conn == false) {
        PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, with_ssl);
		if (!backend_conn) {
			BAIL_OUT("Error: failed to connect to the database in file %s, line %d\n", __FILE__, __LINE__);
			return;
		}
        for (int i = 0; i < MAX_ITERATION; i++) {
            if (!setupTestTable(backend_conn.get()))
                return;
            usleep(1000);
            const std::string& value = setIntervalStyle(backend_conn.get(), i, f_proxysql_log);
 
            if (value.empty())
                return;

            diag(">>>> Running Test:%d - Shared Connection <<<<", i+1);
            copy_stdin_test(backend_conn.get(), value, f_proxysql_log);
            f_proxysql_log.clear(f_proxysql_log.rdstate() & ~std::ios_base::failbit);
            f_proxysql_log.seekg(f_proxysql_log.tellg());
            diag(">>>> Done <<<<");
        }
    } else {
        for (int i = 0; i < MAX_ITERATION; i++) {
            diag(">>>> Running Test:%d - Different Connection <<<<", i+1);
            PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, with_ssl);

            if (!backend_conn) {
                BAIL_OUT("Error: failed to connect to the database in file %s, line %d\n", __FILE__, __LINE__);
                return;
            }

            if (!setupTestTable(backend_conn.get()))
                return;
            usleep(1000);
            const std::string& value = setIntervalStyle(backend_conn.get(), i, f_proxysql_log);

            if (value.empty())
                return;

            copy_stdin_test(backend_conn.get(), value, f_proxysql_log);
            f_proxysql_log.clear(f_proxysql_log.rdstate() & ~std::ios_base::failbit);
            f_proxysql_log.seekg(f_proxysql_log.tellg());
            diag(">>>> Done <<<<");
        }
    }
}

int main(int argc, char** argv) {

	plan(MAX_ITERATION * 2 * 8); // Max Iteration, For Shared and Different Connections, 7 checks

    if (cl.getEnv())
        return exit_status();

    std::string f_path{ get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log" };
    std::fstream f_proxysql_log{};

    int of_err = open_file_and_seek_end(f_path, f_proxysql_log);
    if (of_err != EXIT_SUCCESS) {
        return exit_status();
    }

    PGConnPtr admin_conn = createNewConnection(ConnType::ADMIN, false);

    if (!executeQueries(admin_conn.get(), {
           "DELETE FROM pgsql_query_rules",
           "LOAD PGSQL QUERY RULES TO RUNTIME",
           "UPDATE pgsql_users SET fast_forward=0" ,
           "LOAD PGSQL USERS TO RUNTIME"
        }))
        return exit_status();

	execute_test(false, false, f_proxysql_log);
    execute_test(false, true, f_proxysql_log);

    f_proxysql_log.close();
    return exit_status();
}
