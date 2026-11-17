/**
 * @file pgsql-copy_to_test-t.cpp
 * @brief Tests COPY TO functionality in ProxySQL
 */

#include <sys/wait.h>
#include <unistd.h>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include <functional>
#include <memory>
#include <vector>
#include "libpq-fe.h"
#include "command_line.h"
#include "noise_utils.h"
#include "tap.h"
#include "utils.h"
#include "pgsql_native_tier.h"

CommandLine cl;

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

        if (strncasecmp(buf, "SELECT", sizeof("SELECT") - 1) == 0) {
            return PGRES_TUPLES_OK;
        }
        if (strncasecmp(buf, "COPY", sizeof("COPY") - 1) == 0) {
            return PGRES_COPY_OUT;
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

size_t recvCopyData(PGconn* conn, char** output) {

    char* buffer = NULL;
    int bytesRead;
    size_t totalBytes = 0;
    size_t outputBuffCapacity = 1024;
    char* outputBuff = (char*)malloc(outputBuffCapacity); 

    if (!outputBuff) {
        fprintf(stderr, "Out of memory. %ld", outputBuffCapacity);
        return 0;
    }

    while ((bytesRead = PQgetCopyData(conn, &buffer, 0)) > 0) {
        if (totalBytes + bytesRead >= outputBuffCapacity) {
            outputBuffCapacity *= 2;
            if (outputBuffCapacity <= totalBytes + bytesRead)
                outputBuffCapacity = totalBytes + bytesRead + 1;

            char *tempBuff = (char*)realloc(outputBuff, outputBuffCapacity);
            if (!tempBuff) {
                fprintf(stderr, "Out of memory. %ld", outputBuffCapacity);
                free(outputBuff);
                PQfreemem(buffer);
                return 0;
            }
            outputBuff = tempBuff;
        }
        memcpy(outputBuff + totalBytes, buffer, bytesRead);
        totalBytes += bytesRead;
        PQfreemem(buffer);
        buffer = NULL;
    }
    outputBuff[totalBytes] = '\0';  // Null-terminate the output string

    ok(bytesRead == -1, "COPY OUT data retrieved successfully");

    // Verify no more results are pending
    PGresult *res = PQgetResult(conn);
    if (PQresultStatus(res) == PGRES_COMMAND_OK) {
        ok(true, "Expected Command OK");
    } else {
        ok(false, "Expected Command OK");
        free(outputBuff);
        PQclear(res);
        return 0;
    }
    PQclear(res);

    if (PQgetResult(conn) == NULL) {
        ok(true, "Expected no more results after COPY OUT");
    } else {
        ok(false, "Expected no more results after COPY OUT");
        free(outputBuff);
        return 0;
    }

    if (output && totalBytes > 0)
        *output = outputBuff;
	else {
		free(outputBuff);
	}
    return totalBytes;
}

bool setupTestTable(PGconn* conn) {
	return executeQueries(conn, { 
        "DROP TABLE IF EXISTS copy_test",
		"CREATE TABLE copy_test (id SERIAL PRIMARY KEY, name TEXT, value INT, active BOOLEAN, created_at TIMESTAMP)"
	});
}

void testDataIntegrity(PGconn* admin_conn, PGconn* conn) {

    if (!executeQueries(conn, { "INSERT INTO copy_test (name, value, active, created_at) VALUES ('Alice', 42, TRUE, NOW())" }))
        return;

    // Test COPY OUT
	if (!executeQueries(conn, { "COPY copy_test TO STDOUT" }))
		return;

    // Read data from COPY OUT
	char* output = NULL;
    if (recvCopyData(conn, &output) == 0)
        return;

    // Check output matches inserted values
    ok(strstr(output, "1\tAlice\t42\tt\t") != NULL, "Data integrity check");
    free(output);
}

void testCopyOutWithHeader(PGconn* admin_conn, PGconn* conn) {

    if (!executeQueries(conn, { "INSERT INTO copy_test (name, value, active, created_at) VALUES ('Eve', 35, FALSE, NOW())" }))
        return;

    // Test COPY OUT
    if (!executeQueries(conn, { "COPY copy_test TO STDOUT WITH (FORMAT TEXT, HEADER)" }))
        return;

    // Read data from COPY OUT
    char* output = NULL;
    if (recvCopyData(conn, &output) == 0)
        return;

    // Check output includes the header
    ok(strstr(output, "id\tname\tvalue\tactive\tcreated_at") != NULL,
        "Expected header in COPY OUT output");
    free(output);
}

void testCopyOutLargeBinary(PGconn* admin_conn, PGconn* conn) {
    if (!executeQueries(admin_conn, { 
        "SET pgsql-threshold_resultset_size=536870911",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;
    
    if (!executeQueries(conn, { 
        "DROP TABLE IF EXISTS copy_test_large",
        "CREATE TABLE copy_test_large (id SERIAL PRIMARY KEY, data BYTEA)" 
        }))
        return;
    
    // Insert a large binary object
    constexpr unsigned int data_len = 1024 * 1024;
    char* largeData = (char*)malloc(data_len + 1); // 1MB
    memset(largeData, 'A', data_len);
    largeData[data_len] = '\0';

    // Escape the large data string to ensure safety
    char* escapedData = PQescapeLiteral(conn, largeData, data_len);

    if (escapedData == NULL) {
        // Handle escaping error, if needed
        fprintf(stderr, "Escaping error: %s\n", PQerrorMessage(conn));
        free(largeData);
        return;
    }

    // Create query string with escaped data embedded
    std::string query = "INSERT INTO copy_test_large (data) VALUES (" + std::string(escapedData) + ")";
    
    // Free resources
    PQfreemem(escapedData);
    free(largeData);

    if (!executeQueries(conn, { query.c_str() } ))
        return;

    // Test COPY OUT
    if (!executeQueries(conn, { "COPY copy_test_large TO STDOUT" }))
        return;

    // Read data from COPY OUT
    size_t bytesRecv = recvCopyData(conn, NULL);

    // Verify that binary data is read
    ok(bytesRecv > 0, "Expected non-zero binary output");
    
    if (!executeQueries(conn, {
        "DROP TABLE IF EXISTS copy_test_large"
    }))
        return;
}

void testTransactionHandling(PGconn* admin_conn, PGconn* conn) {

    // Use a transaction
    if (!executeQueries(conn, {
        "BEGIN",
        "INSERT INTO copy_test (name, value, active, created_at) VALUES ('Frank', 29, TRUE, NOW())",
        "ROLLBACK"
        }))
        return;

    // Test COPY OUT
    if (!executeQueries(conn, { "COPY copy_test TO STDOUT" }))
        return;

    // Read data from COPY OUT
    size_t bytesRecv = recvCopyData(conn, NULL);

    // Verify no data is present due to rollback
    ok(bytesRecv == 0, "Expected zero output after rollback");
}

void testErrorHandling(PGconn* admin_conn, PGconn* conn) {
    // Attempt to copy from a non-existent table
    PGresult *res = PQexec(conn, "COPY non_existent_table TO STDOUT");
    ok(PQresultStatus(res) != PGRES_COPY_OUT, "Expected COPY to fail on non-existent table");
    PQclear(res);
}

void testLargeDataVolume(PGconn* admin_conn, PGconn* conn) {

    if (!executeQueries(admin_conn, {
      "SET pgsql-threshold_resultset_size=536870911",
      "LOAD PGSQL VARIABLES TO RUNTIME",
        }))
        return;

    // Insert a large number of rows
	for (int i = 0; i < 1000; i++) {
		char query[256];
		snprintf(query, sizeof(query), "INSERT INTO copy_test (name, value, active, created_at) VALUES ('User%d', %d, %s, NOW())",
			i, i * 10, (i % 2 == 0) ? "TRUE" : "FALSE");
		if (!executeQueries(conn, {
			query
            }))
            return;
    }

    // Test COPY OUT
    if (!executeQueries(conn, { "COPY copy_test TO STDOUT" }))
        return;

    // Read data from COPY OUT
    size_t bytesRecv = recvCopyData(conn, NULL);

    // Verify output matches number of inserted rows
    ok(bytesRecv > 0, "Expected non-zero output for large data volume");
}

void testTransactionStatus(PGconn* admin_conn, PGconn* conn) {

    // Test COPY OUT
    if (!executeQueries(conn, {
        "BEGIN",
        "COPY copy_test TO STDOUT" }))
        return;

    // Read data from COPY OUT
    recvCopyData(conn, NULL);

    ok(PQtransactionStatus(conn) == PQTRANS_INTRANS, "Expected In Transaction Status");

    if (!executeQueries(conn, { "ROLLBACK" }))
        return;
}

void testThresholdResultsetSize(PGconn* admin_conn, PGconn* conn) {

    if (!executeQueries(admin_conn, {
        "SET pgsql-poll_timeout=2000",
        "SET pgsql-threshold_resultset_size=1024",
        "LOAD PGSQL VARIABLES TO RUNTIME"
        }))
        return;

    {
        auto startTime = std::chrono::high_resolution_clock::now();
        if (!executeQueries(conn, { "COPY (SELECT REPEAT('X', 1000)) TO STDOUT" }))
            return;
        // Read data from COPY OUT
        size_t bytesRecv = recvCopyData(conn, NULL);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
        ok(duration < 10, "Threshold check should not be triggered. Duration:%ld, Total Bytes Received:%ld", duration, bytesRecv);
    }
    {
        auto startTime = std::chrono::high_resolution_clock::now();
        if (!executeQueries(conn, { "COPY (SELECT REPEAT('X', 9999)) TO STDOUT" }))
            return;
        // Read data from COPY OUT
        size_t bytesRecv = recvCopyData(conn, NULL);
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
        ok(duration >= 2000, "Threshold check should be triggered. Duration:%ld, Total Bytes Received:%ld", duration, bytesRecv);
    }
}

void testMultistatementWithCopy(PGconn* admin_conn, PGconn* conn) {

    if (!executeQueries(conn, { "INSERT INTO copy_test(name, value) VALUES ('Alice', 10), ('Bob', 20)" }))
        return;

    // Multistatement query: First a SELECT, then COPY TO STDOUT
    if (PQsendQuery(conn, "SELECT * FROM copy_test; COPY copy_test TO STDOUT") == 0) {
        fprintf(stderr, "Error sending query: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return;
    }
    
    PQconsumeInput(conn);
    while (PQisBusy(conn)) {
        PQconsumeInput(conn);
    }

    // Check first result (SELECT statement)
    PGresult* res = PQgetResult(conn);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "SELECT failed\n");
        PQclear(res);
        return;
    }

    int rows = PQntuples(res);
    ok(rows == 2, "Expected 2 rows from SELECT");

    // Check the data returned by SELECT
    char* name1 = PQgetvalue(res, 0, 1);
    char* value1 = PQgetvalue(res, 0, 2);
    ok(strcmp(name1, "Alice") == 0, "Expected 'Alice' in first row");
    ok(atoi(value1) == 10, "Expected value 10 in first row");

    char* name2 = PQgetvalue(res, 1, 1);
    char* value2 = PQgetvalue(res, 1, 2);
    ok(strcmp(name2, "Bob") == 0, "Expected 'Bob' in second row");
    ok(atoi(value2) == 20, "Expected value 20 in second row");

    PQclear(res); // Clear SELECT result

    // Check second result (COPY TO STDOUT)
    res = PQgetResult(conn);
    if (PQresultStatus(res) != PGRES_COPY_OUT) {
        fprintf(stderr, "COPY OUT failed\n");
        PQclear(res);
        return;
    }

    // Read data from COPY OUT
    char* buffer = NULL;
    int bytesRead;
    size_t totalBytes = 0;
    char output[1024] = { 0 };

    while ((bytesRead = PQgetCopyData(conn, &buffer, 0)) > 0) {
        memcpy(output + totalBytes, buffer, bytesRead);
        totalBytes += bytesRead;
        PQfreemem(buffer);
        buffer = NULL;
    }

    output[totalBytes] = '\0'; // Null-terminate output for easier checking

    // Expected output format: "id\tname\tvalue\n1\tAlice\t10\n2\tBob\t20\n"
    ok(strstr(output, "1\tAlice\t10") != NULL, "Expected '1\tAlice\t10' in COPY OUT output");
    ok(strstr(output, "2\tBob\t20") != NULL, "Expected '2\tBob\t20' in COPY OUT output");

    // Finish COPY operation
    PQclear(res);

    // Verify no more results are pending
    res = PQgetResult(conn);
    ok(PQresultStatus(res) == PGRES_COMMAND_OK, "Expected Command OK");
    PQclear(res);
    ok(PQgetResult(conn) == NULL, "Expected no more results after COPY OUT");
}

std::vector<std::pair<std::string, void (*)(PGconn*, PGconn*)>> tests = {
    { "Data Intergrity Test", testDataIntegrity },
    { "Copy Out With Header Test", testCopyOutWithHeader },
    { "Copy Out With Large Data Test", testCopyOutLargeBinary },
    { "Transaction Handling Test", testTransactionHandling },
    { "Error Handling Test", testErrorHandling },
	{ "Large Data Volume Test", testLargeDataVolume },
    { "Transaction Status Test", testTransactionStatus },
    { "Threshold Result Size Test", testThresholdResultsetSize },
    { "Multi Statement With Copy Test", testMultistatementWithCopy }
};

/**
 * Regression #6628: a session torn down in the middle of a COPY must not return its backend connection
 * to the pool.
 *
 * A COPY switches the session to fast forward. ProxySQL then stops reading the protocol and only relays
 * bytes, so the connection's own state still describes it as it was before the COPY: idle, healthy,
 * reusable. When such a session was torn down mid-COPY, reset_connection() trusted that state and
 * pooled the connection:
 * - **backend killed:** a dead connection went into the pool. The next session's query failed on it
 *   (hidden only by a query retry) until the idle ping found it, about 10 s later;
 * - **client gone:** a connection whose backend was still running the COPY went into the pool. The
 *   next session got its output, and the ping later failed with 08P01.
 * A connection whose session is still in fast forward is now destroyed instead.
 *
 * Each case starts a COPY from a client process and, one second later, ends it from one side:
 * - it kills the backend over a direct connection, or it kills the client process;
 * - at that point PostgreSQL is still building the COPY's result. That is the window in which the
 *   connection was pooled. (Once rows were flowing, the connection was already destroyed before the
 *   fix, by a path this test does not cover.)
 *
 * It then checks:
 * - the COPY's connection, found by its backend pid, never shows up among the free connections. A
 *   torn-down session's connection first goes to its worker thread's cache, which these stats do not
 *   show, and reaches the pool on a later pass, so the check watches for a few seconds;
 * - a new session's query works with query retries off.
 * The same two endings run for:
 * - a COPY (SELECT ...) TO STDOUT, which goes through fast forward in both modes;
 * - a COPY FROM STDIN that the client keeps streaming;
 * - a COPY table TO STDOUT read slowly by the client, so that rows are still flowing. In native mode
 *   this form takes the native drive, not fast forward.
 * A last case sends the COPY with the extended protocol. ProxySQL refuses a COPY at Parse, so it
 * never reaches fast forward; the case checks that the refusal holds and leaves the session usable.
 *
 * Scope:
 * - It runs for libpq and for native mode (when the build has it).
 * - It uses a role of its own, named after the run, so the backend lookups see only this test and no
 *   connection pooled by an earlier run can be handed to it.
 * - Variables are changed at runtime only and restored.
 */
namespace teardown {

static const int   HG   = 0;
// Named after this run, so a connection ProxySQL still pools from an earlier run is never handed to this one.
static const std::string USER = "copy_teardown_" + std::to_string(getpid());
static const char* PASS = "copy_teardown_pass";
// generate_series() in FROM builds the whole set before the first row goes out, which takes a few
// seconds for 50 million rows: one second in, the COPY is under way and no row has been sent.
static const char* COPY_SQL = "COPY (SELECT g, repeat('x', 1000) FROM generate_series(1, 50000000) g) TO STDOUT";
// The tables of the COPY FROM and COPY table TO cases, named after this run like the role.
static const std::string SINK = "copy_teardown_sink_" + std::to_string(getpid());
static const std::string SRC = "copy_teardown_src_" + std::to_string(getpid());
// More than ProxySQL and the kernel buffer, so a slow reader leaves the backend in the middle of it.
static const int SRC_ROWS = 100000;

struct CopyKind {
	const char* label;
	std::string sql;
	bool from;  // the client streams CopyData until it fails
	bool slow;  // the client reads its first rows at one per millisecond
};

// Exit codes of the client process.
static const int CHILD_COPY_ERROR = 3, CHILD_COPY_DONE = 4, CHILD_NO_COPY = 5;

static void silenceNotices(void*, const char*) {}

static std::string connInfo(const char* h, int p, const char* u, const char* pw, const char* db) {
	std::stringstream ss;
	ss << "host=" << h << " port=" << p << " user=" << u << " password=" << pw;
	if (db && *db) ss << " dbname=" << db;
	ss << " sslmode=disable connect_timeout=10";
	return ss.str();
}

static PGConnPtr openConn(const char* h, int p, const char* u, const char* pw, const char* db) {
	PGConnPtr c(PQconnectdb(connInfo(h, p, u, pw, db).c_str()), &PQfinish);
	if (c) PQsetNoticeProcessor(c.get(), &silenceNotices, nullptr);
	return c;
}
static PGConnPtr openAdmin()   { return openConn(cl.pgsql_admin_host, cl.pgsql_admin_port, cl.admin_username, cl.admin_password, ""); }
static PGConnPtr openBackend() { return openConn(cl.pgsql_server_host, cl.pgsql_server_port, cl.pgsql_server_username, cl.pgsql_server_password, "postgres"); }
static PGConnPtr openClient()  { return openConn(cl.pgsql_host, cl.pgsql_port, USER.c_str(), PASS, "postgres"); }

static bool execOk(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	const ExecStatusType st = PQresultStatus(r);
	const bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
	if (!good) diag("query failed: %s -- %s", q.c_str(), PQerrorMessage(c));
	PQclear(r);
	return good;
}

static std::string scalar(PGconn* c, const std::string& q) {
	PGresult* r = PQexec(c, q.c_str());
	std::string out;
	if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0))
		out = PQgetvalue(r, 0, 0);
	PQclear(r);
	return out;
}

static bool setVar(PGconn* admin, const std::string& name, const std::string& value) {
	return execOk(admin, "SET " + name + "='" + value + "'") && execOk(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}

static std::string runtimeVar(PGconn* admin, const std::string& name) {
	return scalar(admin, "SELECT variable_value FROM runtime_global_variables WHERE variable_name='" + name + "'");
}

static bool waitFor(const std::function<bool()>& cond, int seconds) {
	const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
	while (std::chrono::steady_clock::now() < end) {
		if (cond()) return true;
		usleep(100000);
	}
	return cond();
}

// Whether the connection to backend `pid` shows up among the free connections within `seconds`.
static bool pooledWithin(PGconn* admin, const std::string& pid, int seconds) {
	const std::string q = "SELECT count(*) FROM stats_pgsql_free_connections WHERE pgsql_info LIKE '%\"backend_pid\":" + pid + ",%'";
	const bool seen = waitFor([&]() { return scalar(admin, q) != "0"; }, seconds);
	if (seen) diag("the connection to backend %s is in the pool as free", pid.c_str());
	return seen;
}

// Backend protocol of this role's free connections, as ProxySQL records it.
static std::string poolMode(PGconn* admin) {
	const std::string info = scalar(admin, std::string("SELECT group_concat(pgsql_info) FROM stats_pgsql_free_connections WHERE user='") + USER + "'");
	const bool native = info.find("\"native_mode\":true") != std::string::npos;
	const bool libpq = info.find("\"native_mode\":false") != std::string::npos;
	return native && !libpq ? "native" : libpq && !native ? "libpq" : "(" + info + ")";
}

// A query from a new session. With query retries off, a session handed the pooled connection fails
// instead of quietly retrying on another one.
static bool newQueryWorks() {
	auto c = openClient();
	if (PQstatus(c.get()) != CONNECTION_OK) {
		diag("new client connect failed: %s", PQerrorMessage(c.get()));
		return false;
	}
	const std::string v = scalar(c.get(), "SELECT 1");
	if (v != "1") diag("new session's SELECT 1 failed: %s", PQerrorMessage(c.get()));
	return v == "1";
}

// A client process that runs the COPY: it reads a COPY TO to the end, and streams a COPY FROM until that
// fails. Its exit code says how the COPY ended.
static pid_t startCopyClient(const std::string& conninfo, const CopyKind& k) {
	const pid_t child = fork();
	if (child != 0) return child;
	PGconn* c = PQconnectdb(conninfo.c_str());
	if (PQstatus(c) != CONNECTION_OK) {
		fprintf(stderr, "# copy client: connect failed: %s\n", PQerrorMessage(c));
		_exit(CHILD_NO_COPY);
	}
	PGresult* r = PQexec(c, k.sql.c_str());
	if (k.from) {
		if (PQresultStatus(r) != PGRES_COPY_IN) {
			fprintf(stderr, "# copy client: COPY did not start (%s): %s\n", PQresStatus(PQresultStatus(r)), PQerrorMessage(c));
			_exit(CHILD_COPY_ERROR);
		}
		const std::string row = "1\t" + std::string(1000, 'x') + "\n";
		while (PQputCopyData(c, row.data(), (int)row.size()) == 1) {}
		_exit(CHILD_COPY_ERROR);
	}
	if (PQresultStatus(r) != PGRES_COPY_OUT) {
		fprintf(stderr, "# copy client: COPY did not start (%s): %s\n", PQresStatus(PQresultStatus(r)), PQerrorMessage(c));
		_exit(CHILD_COPY_ERROR);
	}
	char* buf = nullptr;
	int n;
	// Slow for the first 2 s only: rows still flow when the case ends the COPY, and a client still
	// reading what was buffered reaches the error soon after.
	long read = 0;
	while ((n = PQgetCopyData(c, &buf, 0)) > 0) {
		PQfreemem(buf);
		buf = nullptr;
		if (k.slow && read++ < 2000) usleep(1000);
	}
	if (n == -1) {
		r = PQgetResult(c);
		if (r != nullptr && PQresultStatus(r) == PGRES_COMMAND_OK) _exit(CHILD_COPY_DONE);
	}
	_exit(CHILD_COPY_ERROR);
}

// The child's exit code, or -1 if it is still running after `seconds` (it is then killed).
static int waitChild(pid_t child, int seconds) {
	int status = 0;
	const bool exited = waitFor([&]() { return waitpid(child, &status, WNOHANG) == child; }, seconds);
	if (!exited) {
		kill(child, SIGKILL);
		waitpid(child, &status, 0);
		return -1;
	}
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// The backend running this role's COPY.
static std::string copyBackendPid(PGconn* be) {
	return scalar(be, std::string("SELECT pid FROM pg_stat_activity WHERE usename='") + USER
		+ "' AND query LIKE 'COPY%' AND state='active' ORDER BY backend_start DESC LIMIT 1");
}

// What the backend and ProxySQL show for this role, for a failure report.
static void diagState(PGconn* admin, PGconn* be) {
	diag("backend sees: %s", scalar(be, std::string("SELECT string_agg(pid || ' ' || state || ' ' || coalesce(wait_event, '-') || ' '"
		" || left(query, 40), '; ') FROM pg_stat_activity WHERE usename='") + USER + "'").c_str());
	diag("ProxySQL sees: %s", scalar(admin, std::string("SELECT group_concat(SessionID || ' ' || command || ' ' || backend_pid || ' '"
		" || coalesce(backend_state, '-'), '; ') FROM stats_pgsql_processlist WHERE user='") + USER + "'").c_str());
}

// Starts the COPY and returns its backend pid once the COPY has run for a second ("" if it never shows up).
// A COPY of an earlier case may still be finishing on the backend; it is waited out first, so the pid
// found is this COPY's.
// *early_rc is the client's exit code if it already ended while the COPY was awaited, else -2.
static std::string startCopy(PGconn* admin, PGconn* be, const CopyKind& k, pid_t* child, int* early_rc) {
	*early_rc = -2;
	if (!waitFor([&]() { return copyBackendPid(be).empty(); }, 15)) diag("a COPY of an earlier case is still running on the backend");
	*child = startCopyClient(connInfo(cl.pgsql_host, cl.pgsql_port, USER.c_str(), PASS, "postgres"), k);
	std::string pid;
	int status = 0;
	if (*child > 0) waitFor([&]() {
		pid = copyBackendPid(be);
		if (pid.empty() && waitpid(*child, &status, WNOHANG) == *child) *early_rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
		return !pid.empty() || *early_rc != -2;
	}, 15);
	if (pid.empty()) {
		diag("the COPY never showed up on the backend (client exit %d)", *early_rc);
		diagState(admin, be);
	}
	sleep(1);
	return pid;
}

// A hostgroup no server is in, used to move the servers out of HG for a moment.
static const int SPARE_HG = 9628;

// Drops the hostgroup's free connections, so the next ones are opened in the backend mode now set.
// A server taken out of the hostgroup has them dropped at once. OFFLINE_HARD would leave them to a
// later maintenance pass, which skips the server once its status is back to ONLINE. Moving the rows
// keeps every column as it was.
static bool flushPool(PGconn* admin) {
	const std::string hg = std::to_string(HG), spare = std::to_string(SPARE_HG);
	const bool out = execOk(admin, "UPDATE pgsql_servers SET hostgroup_id=" + spare + " WHERE hostgroup_id=" + hg)
		&& execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	// Moved back even if the step above failed, so the hostgroup is not left empty.
	const bool back = execOk(admin, "UPDATE pgsql_servers SET hostgroup_id=" + hg + " WHERE hostgroup_id=" + spare)
		&& execOk(admin, "LOAD PGSQL SERVERS TO RUNTIME");
	usleep(300000);
	return out && back;
}

static void cleanupRole(PGconn* admin, PGconn* be) {
	execOk(admin, std::string("DELETE FROM pgsql_users WHERE username='") + USER + "'");
	execOk(admin, "LOAD PGSQL USERS TO RUNTIME");
	scalar(be, std::string("SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename='") + USER + "'");
	execOk(be, "DROP TABLE IF EXISTS " + SINK + ", " + SRC);
	execOk(be, "DROP FUNCTION IF EXISTS " + SINK + "_drop()");
	execOk(be, std::string("DROP ROLE IF EXISTS ") + USER);
}

// Roles of earlier runs that did not get to clean up, found by their name.
static void cleanupLeftovers(PGconn* admin, PGconn* be) {
	execOk(admin, "DELETE FROM pgsql_users WHERE username LIKE 'copy\\_teardown\\_%' ESCAPE '\\'");
	execOk(admin, "LOAD PGSQL USERS TO RUNTIME");
	scalar(be, "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE usename LIKE 'copy\\_teardown\\_%'");
	execOk(be, "DO $$DECLARE r text; BEGIN FOR r IN SELECT tablename FROM pg_tables WHERE tablename LIKE 'copy\\_teardown\\_%' LOOP"
		" EXECUTE format('DROP TABLE %I', r); END LOOP; END$$");
	execOk(be, "DO $$DECLARE r text; BEGIN FOR r IN SELECT rolname FROM pg_roles WHERE rolname LIKE 'copy\\_teardown\\_%' LOOP"
		" EXECUTE format('DROP ROLE %I', r); END LOOP; END$$");
}

// One COPY ended from one side: the backend is killed, or the client process is. 3 checks.
static void teardownCase(PGconn* admin, PGconn* be, const std::string& mode, const CopyKind& k, bool kill_backend) {
	const std::string what = mode + ", " + k.label + (kill_backend ? ", backend killed" : ", client gone");
	pid_t child = -1;
	int early_rc;
	const std::string pid = startCopy(admin, be, k, &child, &early_rc);
	if (kill_backend) {
		const std::string terminated = pid.empty() ? "" : scalar(be, "SELECT pg_terminate_backend(" + pid + ")");
		const int rc = early_rc != -2 ? early_rc : child > 0 ? waitChild(child, 15) : -1;
		if (rc != CHILD_COPY_ERROR) {
			diag("pg_terminate_backend(%s) returned '%s'; the client exited with %d (-1: still running after 15 s)",
				pid.c_str(), terminated.c_str(), rc);
			diagState(admin, be);
		}
		ok(!pid.empty() && rc == CHILD_COPY_ERROR, "%s: the COPY ended with an error (backend pid %s, client exit %d)",
			what.c_str(), pid.empty() ? "not found" : pid.c_str(), rc);
		ok(!pid.empty() && !pooledWithin(admin, pid, 4), "%s: the dead connection was not pooled (watched for 4 s)", what.c_str());
	} else {
		// The backend keeps running the COPY.
		const bool killed = child > 0 && early_rc == -2 && kill(child, SIGKILL) == 0;
		if (child > 0 && early_rc == -2) waitpid(child, nullptr, 0);
		ok(!pid.empty() && killed, "%s: the client process was killed during the COPY (backend pid %s)",
			what.c_str(), pid.empty() ? "not found" : pid.c_str());
		ok(!pid.empty() && !pooledWithin(admin, pid, 4),
			"%s: the connection whose backend is still in the COPY was not pooled (watched for 4 s)", what.c_str());
	}
	ok(newQueryWorks(), "%s: a new session's query right after works, with query retries off", what.c_str());
	if (!pid.empty()) scalar(be, "SELECT pg_terminate_backend(" + pid + ")");  // it would run the whole COPY first
}

static void runMode(PGconn* admin, PGconn* be, const std::string& mode) {
	diag("---- %s mode ----", mode.c_str());
	const std::vector<CopyKind> kinds = {
		{ "COPY (SELECT ...) TO", COPY_SQL, false, false },
		{ "COPY FROM STDIN", "COPY " + SINK + " FROM STDIN", true, false },
		{ "COPY table TO, read slowly", "COPY " + SRC + " TO STDOUT", false, true },
	};
	for (const CopyKind& k : kinds) {
		teardownCase(admin, be, mode, k, true);
		if (&k == &kinds[0]) {
			// That query's connection is pooled once its client is gone; it shows the mode really under test.
			std::string pm;
			waitFor([&]() { pm = poolMode(admin); return pm == "native" || pm == "libpq"; }, 5);
			ok(pm == mode, "%s: the pooled connections use the mode under test (%s)", mode.c_str(), pm.c_str());
		}
		teardownCase(admin, be, mode, k, false);
	}

	// The COPY (SELECT ...) TO sent with the extended protocol (Parse/Bind/Describe/Execute/Sync). ProxySQL
	// refuses a COPY at Parse, so it never switches to fast forward and no session can be torn down
	// in the middle of one. This checks that the refusal holds and leaves nothing behind.
	{
		auto c = openClient();
		std::string sqlstate;
		if (PQstatus(c.get()) == CONNECTION_OK) {
			PGresult* r = PQexecParams(c.get(), COPY_SQL, 0, nullptr, nullptr, nullptr, nullptr, 0);
			const char* st = PQresultErrorField(r, PG_DIAG_SQLSTATE);
			sqlstate = st ? st : PQresStatus(PQresultStatus(r));
			PQclear(r);
		} else {
			diag("client connect failed: %s", PQerrorMessage(c.get()));
		}
		ok(sqlstate == "0A000", "%s, extended query: ProxySQL refuses the COPY with 0A000 (got %s)", mode.c_str(), sqlstate.c_str());
		ok(copyBackendPid(be).empty(), "%s, extended query: no backend runs the refused COPY", mode.c_str());
		ok(scalar(c.get(), "SELECT 1") == "1", "%s, extended query: the session still works after the refusal", mode.c_str());
	}
}


// Checks per backend mode: 3 kinds x 2 endings x 3, the pool mode, 3 for the extended query. run() adds
// one for the setup.
static const int TESTS_PER_MODE = 3 * 2 * 3 + 1 + 3;

static void run(PGconn* admin, bool native_supported) {
	diag(">>>> Running a COPY torn down mid-stream <<<<");
	PGConnPtr be = openBackend();
	if (PQstatus(be.get()) != CONNECTION_OK) { BAIL_OUT("direct backend connect failed: %s", PQerrorMessage(be.get())); return; }

	const std::vector<std::string> modes = native_supported ? std::vector<std::string> { "libpq", "native" } : std::vector<std::string> { "libpq" };
	const std::string saved_retries = runtimeVar(admin, "pgsql-query_retries_on_failure");
	const std::string saved_native = runtimeVar(admin, "pgsql-use_native_backend_protocol");
	const std::string servers = scalar(admin, "SELECT count(*) FROM pgsql_servers WHERE hostgroup_id=" + std::to_string(HG));
	if (servers.empty() || servers == "0") { BAIL_OUT("no pgsql_servers rows in hostgroup %d", HG); return; }

	cleanupLeftovers(admin, be.get());  // roles left by aborted runs
	const bool role_ok = execOk(be.get(), std::string("CREATE ROLE ") + USER + " LOGIN PASSWORD '" + PASS + "'")
		&& execOk(admin, std::string("INSERT INTO pgsql_users (username,password,active,default_hostgroup) VALUES ('")
			+ USER + "','" + PASS + "',1," + std::to_string(HG) + ")")
		&& execOk(admin, "LOAD PGSQL USERS TO RUNTIME")
		&& setVar(admin, "pgsql-query_retries_on_failure", "0")
		&& execOk(be.get(), "CREATE UNLOGGED TABLE " + SINK + " (a int, b text)")
		// The sink keeps nothing.
		&& execOk(be.get(), "CREATE OR REPLACE FUNCTION " + SINK + "_drop() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$")
		&& execOk(be.get(), "CREATE TRIGGER " + SINK + "_drop BEFORE INSERT ON " + SINK + " FOR EACH ROW EXECUTE FUNCTION " + SINK + "_drop()")
		&& execOk(be.get(), "CREATE UNLOGGED TABLE " + SRC + " AS SELECT g, repeat('x', 1000) AS b FROM generate_series(1, "
			+ std::to_string(SRC_ROWS) + ") g")
		&& execOk(be.get(), "GRANT INSERT ON " + SINK + " TO " + USER)
		&& execOk(be.get(), "GRANT SELECT ON " + SRC + " TO " + USER);
	ok(role_ok, "test role %s, its tables created and query retries turned off", USER.c_str());

	if (role_ok) {
		for (const auto& mode : modes) {
			if (native_supported) setVar(admin, "pgsql-use_native_backend_protocol", mode == "native" ? "true" : "false");
			flushPool(admin);
			runMode(admin, be.get(), mode);
		}
	}

	if (!saved_retries.empty()) setVar(admin, "pgsql-query_retries_on_failure", saved_retries);
	if (native_supported && !saved_native.empty()) setVar(admin, "pgsql-use_native_backend_protocol", saved_native);
	flushPool(admin);  // nothing of this test's role stays pooled
	cleanupRole(admin, be.get());
	diag(">>>> Done <<<<");
}

} // namespace teardown

/**
 * More of COPY TO STDOUT, for each backend protocol. Both forms run: a COPY table TO has no FROM, so it does
 * not go through fast forward, while a COPY (SELECT ... FROM ...) TO does.
 *  - the query digests count each COPY, and the rows a COPY table TO sends;
 *  - 8 sessions, half of them over TLS and half of each form, COPY at the same time: each must get every
 *    byte of its own result, and keep working;
 *  - where the build has the fast forward traffic observer (FFTO), both forms with it on.
 */
namespace more_to {

static const std::string SRC = "copy_more_to_src";
static const int SRC_ROWS = 1000;
static const int PAR_SESSIONS = 8;
static const int PAR_ROWS = 50000;
// Per backend protocol: 2 digest + 1 parallel, and 1 with FFTO where the build has it.
static const int TESTS_PER_PROTOCOL = 3;

static std::string scalar(PGconn* c, const std::string& q) {
    PGresult* r = PQexec(c, q.c_str());
    std::string out;
    if (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) > 0 && !PQgetisnull(r, 0, 0)) out = PQgetvalue(r, 0, 0);
    PQclear(r);
    return out;
}

// Runs a COPY TO STDOUT. Returns "<rows> <bytes>", or "ERR ..." on failure.
static std::string copy_out(PGconn* c, const std::string& sql) {
    PGresult* r = PQexec(c, sql.c_str());
    const bool started = PQresultStatus(r) == PGRES_COPY_OUT;
    PQclear(r);
    if (!started) return std::string("ERR start: ") + PQerrorMessage(c);
    long rows = 0, bytes = 0;
    char* buf = nullptr;
    int n;
    while ((n = PQgetCopyData(c, &buf, 0)) > 0) {
        rows++;
        bytes += n;
        PQfreemem(buf);
        buf = nullptr;
    }
    std::string out = std::to_string(rows) + " " + std::to_string(bytes);
    while ((r = PQgetResult(c)) != nullptr) {
        if (PQresultStatus(r) != PGRES_COMMAND_OK) out = std::string("ERR ") + PQerrorMessage(c);
        PQclear(r);
    }
    return n == -1 ? out : std::string("ERR ") + PQerrorMessage(c);
}

// "<rows> <bytes>" of a COPY of generate_series(1, n) with each number and its md5.
static std::string series_size(int n) {
    long bytes = 0;
    for (int g = 1; g <= n; g++) bytes += std::to_string(g).size() + 1 + 32 + 1;
    return std::to_string(n) + " " + std::to_string(bytes);
}

static std::string series_sql(int n) {
    return "COPY (SELECT g, md5(g::text) FROM generate_series(1, " + std::to_string(n) + ") g) TO STDOUT";
}

static void run_protocol(PGconn* admin, const std::string& protocol, bool ffto) {
    PGConnPtr c = createNewConnection(ConnType::BACKEND, false);
    if (!c || !executeQueries(c.get(), { "DROP TABLE IF EXISTS " + SRC,
            "CREATE TABLE " + SRC + " AS SELECT g, md5(g::text) AS h FROM generate_series(1, " + std::to_string(SRC_ROWS) + ") g" })) {
        BAIL_OUT("could not create %s", SRC.c_str());
        return;
    }
    const std::string table_sql = "COPY " + SRC + " TO STDOUT";
    const std::string expect_table = series_size(SRC_ROWS);

    executeQueries(admin, { "SELECT * FROM stats_pgsql_query_digest_reset" });
    std::string got;
    for (int i = 0; i < 2; i++) got += copy_out(c.get(), table_sql) + ";";
    for (int i = 0; i < 3; i++) got += copy_out(c.get(), series_sql(100)) + ";";
    std::string table_n, series_n, table_rows;
    for (int i = 0; i < 30 && !(table_n == "2" && series_n == "3"); i++) {
        table_n = scalar(admin, "SELECT COALESCE(SUM(count_star),0) FROM stats_pgsql_query_digest WHERE digest_text LIKE 'COPY " + SRC + " TO STDOUT'");
        table_rows = scalar(admin, "SELECT COALESCE(SUM(sum_rows_sent),0) FROM stats_pgsql_query_digest WHERE digest_text LIKE 'COPY " + SRC + " TO STDOUT'");
        series_n = scalar(admin, "SELECT COALESCE(SUM(count_star),0) FROM stats_pgsql_query_digest WHERE digest_text LIKE 'COPY (SELECT g,md5(%'"
            " OR digest_text LIKE 'COPY (SELECT g, md5(%'");
        if (!(table_n == "2" && series_n == "3")) usleep(100000);
    }
    ok(table_n == "2" && series_n == "3", "%s: the query digests count each COPY TO STDOUT (table form %s of 2, query form"
        " %s of 3; results %s)", protocol.c_str(), table_n.c_str(), series_n.c_str(), got.c_str());
    // A COPY in fast forward is relayed without being read, so only the table form has its rows counted. With
    // libpq each row used to be counted twice.
    ok(table_rows == std::to_string(2 * SRC_ROWS), "%s: the digest of COPY table TO counts the rows sent (%s of %d)",
        protocol.c_str(), table_rows.c_str(), 2 * SRC_ROWS);

    std::vector<std::string> results(PAR_SESSIONS), after(PAR_SESSIONS);
    std::vector<std::thread> threads;
    for (int t = 0; t < PAR_SESSIONS; t++) {
        threads.emplace_back([&, t]() {
            PGConnPtr p = createNewConnection(ConnType::BACKEND, t % 2 == 1);
            if (!p) { results[t] = "no connection"; return; }
            results[t] = copy_out(p.get(), t % 4 < 2 ? series_sql(PAR_ROWS) : table_sql);
            after[t] = scalar(p.get(), "SELECT 1");
        });
    }
    for (auto& th : threads) th.join();
    bool all = true;
    std::string report;
    for (int t = 0; t < PAR_SESSIONS; t++) {
        const bool good = results[t] == (t % 4 < 2 ? series_size(PAR_ROWS) : expect_table) && after[t] == "1";
        all = all && good;
        if (!good) report += " session " + std::to_string(t) + ": '" + results[t] + "', then '" + after[t] + "';";
    }
    ok(all, "%s: %d sessions COPY TO STDOUT at once: each gets its whole result and keeps working%s",
        protocol.c_str(), PAR_SESSIONS, report.c_str());

    if (ffto) {
        executeQueries(admin, { "SET pgsql-ffto_enabled='true'", "LOAD PGSQL VARIABLES TO RUNTIME" });
        std::string ff;
        bool good = true;
        for (bool client_tls : { false, true }) {
            PGConnPtr f = createNewConnection(ConnType::BACKEND, client_tls);
            const std::string a = f ? copy_out(f.get(), table_sql) : "no connection";
            const std::string b = f ? copy_out(f.get(), series_sql(PAR_ROWS)) : "no connection";
            const std::string v = f ? scalar(f.get(), "SELECT 1") : "";
            good = good && a == expect_table && b == series_size(PAR_ROWS) && v == "1";
            ff += std::string(client_tls ? " TLS: " : " plain: ") + a + " / " + b + " / " + v + ";";
        }
        executeQueries(admin, { "SET pgsql-ffto_enabled='false'", "LOAD PGSQL VARIABLES TO RUNTIME" });
        ok(good, "%s, FFTO on: both COPY TO forms deliver every byte, over plain and TLS clients (%s)", protocol.c_str(), ff.c_str());
    }

    executeQueries(c.get(), { "DROP TABLE IF EXISTS " + SRC });
}

} // namespace more_to

void execute_tests(bool with_ssl, bool diff_conn) {

    PGConnPtr admin_conn_1 = createNewConnection(ConnType::ADMIN, with_ssl);

    if (!executeQueries(admin_conn_1.get(), {
       "DELETE FROM pgsql_query_rules",
       "LOAD PGSQL QUERY RULES TO RUNTIME"
        }))
        return;

    if (diff_conn == false) {
        PGConnPtr admin_conn = createNewConnection(ConnType::ADMIN, with_ssl);
        PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, with_ssl);

        if (!admin_conn || !backend_conn) {
            BAIL_OUT("Error: failed to connect to the database in file %s, line %d\n", __FILE__, __LINE__);
            return;
        }

        for (const auto& test : tests) {
            if (!setupTestTable(backend_conn.get())) 
                return;
            diag(">>>> Running %s - Shared Connection: %s <<<<", test.first.c_str(), !diff_conn ? "True" : "False");
            test.second(admin_conn.get(), backend_conn.get());
            diag(">>>> Done <<<<");
        }
    }
    else {
        for (const auto& test : tests) {
            diag(">>>> Running %s - Shared Connection: %s <<<<", test.first.c_str(), diff_conn ? "False" : "True");

            PGConnPtr admin_conn = createNewConnection(ConnType::ADMIN, with_ssl);
            PGConnPtr backend_conn = createNewConnection(ConnType::BACKEND, with_ssl);

            if (!admin_conn || !backend_conn) {
                BAIL_OUT("Error: failed to connect to the database in file %s, line %d\n", __FILE__, __LINE__);
                return;
            }
            if (!setupTestTable(backend_conn.get()))
                return;
            test.second(admin_conn.get(), backend_conn.get());
            diag(">>>> Done <<<<");
        }
    }
}

int main(int argc, char** argv) {
    if (cl.getEnv())
        return exit_status();

	spawn_internal_noise(cl, internal_noise_mysql_traffic_v2, {{"num_connections", "100"}, {"reconnect_interval", "100"}, {"avg_delay_ms", "300"}});
	spawn_internal_noise(cl, internal_noise_prometheus_poller);
	spawn_internal_noise(cl, internal_noise_rest_prometheus_poller, {{"enable_rest_api", "true"}});

	PGConnPtr admin = createNewConnection(ConnType::ADMIN, false);
	if (!admin) { BAIL_OUT("Error: failed to connect to admin in file %s, line %d\n", __FILE__, __LINE__); return exit_status(); }
	const bool native_supported = pgsql_native_supported(admin.get());
	const std::vector<std::string> protocols = native_supported
		? std::vector<std::string> { "libpq", "native" } : std::vector<std::string> { "libpq" };
	const int teardown_tests = 1 + (int)protocols.size() * teardown::TESTS_PER_MODE;
	const bool ffto_supported = teardown::scalar(admin.get(),
		"SELECT count(*) FROM global_variables WHERE variable_name='pgsql-ffto_enabled'") == "1";
	const int per_protocol = 42 * 2 + more_to::TESTS_PER_PROTOCOL + (ffto_supported ? 1 : 0);

	if (cl.use_noise) {
		plan((int)protocols.size() * per_protocol + 3 + teardown_tests);
	} else {
		plan((int)protocols.size() * per_protocol + teardown_tests);
	}

	const std::string saved_native = teardown::runtimeVar(admin.get(), "pgsql-use_native_backend_protocol");
	for (const std::string& protocol : protocols) {
		diag("==== backend protocol: %s ====", protocol.c_str());
		// Dropping the servers drops their pooled connections, so the next ones use the protocol set here. The
		// harness loads the config from disk before every test, so the disk copy is the one to put back.
		if (native_supported && !executeQueries(admin.get(), {
				"SET pgsql-use_native_backend_protocol='" + std::string(protocol == "native" ? "true" : "false") + "'",
				"LOAD PGSQL VARIABLES TO RUNTIME", "DELETE FROM pgsql_servers", "LOAD PGSQL SERVERS TO RUNTIME",
				"LOAD PGSQL SERVERS FROM DISK", "LOAD PGSQL SERVERS TO RUNTIME" }))
			BAIL_OUT("could not switch the backend protocol to %s", protocol.c_str());
		usleep(300000);
		execute_tests(true, false);
		execute_tests(false, false);
		more_to::run_protocol(admin.get(), protocol, ffto_supported);
	}
	if (native_supported && !saved_native.empty()) teardown::setVar(admin.get(), "pgsql-use_native_backend_protocol", saved_native);

    // Runs last: it changes query retries, the backend protocol and the server statuses, and restores them.
    teardown::run(admin.get(), native_supported);

    return exit_status();
}
