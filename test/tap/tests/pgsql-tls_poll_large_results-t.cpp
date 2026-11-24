/**
 * @file pgsql-tls_poll_large_results-t.cpp
 * @brief A libpq client that waits on PQsocket() itself must not hang over TLS
 *        on large results (issue #6721).
 *
 * libpq's pqReadData() guarantees 8 KiB of free input buffer and calls
 * SSL_read() once, and SSL_read() returns data from a single TLS record. When
 * ProxySQL sent 16 KiB records, the last record of a response could be larger
 * than that free space: its tail stayed decrypted inside OpenSSL, the socket
 * was empty, and a client that polls the socket (pgbench, async drivers) waited
 * forever. psql is not affected because it blocks inside libpq, which checks
 * SSL_pending() first. Upstream libpq fixed this in July 2026, but this test
 * links the vendored libpq, which predates that fix, so it reproduces the hang
 * whenever ProxySQL sends a record larger than 8 KiB.
 *
 * The test drives libpq the way pgbench does: non-blocking PQsendQuery(), then
 * PQconsumeInput() / PQisBusy() / PQgetResult(), and poll() on PQsocket() when
 * libpq needs more input. A poll() that times out is a hang. It sweeps result
 * sizes, because whether the last record of a response is too large depends on
 * the exact byte count. Before the fix, these sweeps hung at several sizes on
 * both the Stable and the v3.1 tier.
 */
#include <poll.h>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/ssl.h>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;
CommandLine cl;

// A response that has not progressed in this long is treated as a hang. A
// healthy result of a few hundred KiB over loopback takes milliseconds.
static const int POLL_TIMEOUT_MS = 5000;

struct Sweep {
	int row_len;
	int min_rows;
	int max_rows;
};

// 4 KiB rows: before the fix, sizes hung every ~16 KiB on Stable and at 15
// sizes in 1..64 on v3.1. 1.5 KB rows: hung at 21, 32, 43, 54 (Stable) and 21,
// 42, 58 (v3.1). Both tiers fail somewhere in each range.
static const std::vector<Sweep> SWEEPS = {
	{ 4096, 1, 64 },
	{ 1500, 1, 60 },
};

static PGConnPtr open_tls_conn() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username
	   << " sslmode=require connect_timeout=10";
	PGConnPtr conn(PQconnectdb(ss.str().c_str()), &PQfinish);
	if (PQstatus(conn.get()) != CONNECTION_OK) {
		diag("TLS connection to ProxySQL failed: %s", PQerrorMessage(conn.get()));
		return PGConnPtr(nullptr, &PQfinish);
	}
	if (PQsetnonblocking(conn.get(), 1) != 0) {
		diag("PQsetnonblocking failed: %s", PQerrorMessage(conn.get()));
		return PGConnPtr(nullptr, &PQfinish);
	}
	return conn;
}

enum class QueryOutcome { OK, HANG, ERROR };

/**
 * @brief Run one query the way an event-loop client does and report whether it
 *        completed, hung, or failed.
 *
 * @param conn      Non-blocking TLS connection.
 * @param query     Query to send.
 * @param rows      Out: number of rows received.
 * @param detail    Out: diagnostic text for a hang or an error.
 */
static QueryOutcome run_polling_query(PGconn* conn, const std::string& query, int& rows, std::string& detail) {
	rows = 0;
	if (!PQsendQuery(conn, query.c_str())) {
		detail = std::string("PQsendQuery: ") + PQerrorMessage(conn);
		return QueryOutcome::ERROR;
	}
	// The query is tiny, but in non-blocking mode it must still be flushed.
	int flush_rc;
	while ((flush_rc = PQflush(conn)) == 1) {
		struct pollfd pfd = { PQsocket(conn), POLLOUT, 0 };
		if (poll(&pfd, 1, POLL_TIMEOUT_MS) <= 0) {
			detail = "timed out flushing the query";
			return QueryOutcome::ERROR;
		}
	}
	if (flush_rc == -1) {
		detail = std::string("PQflush: ") + PQerrorMessage(conn);
		return QueryOutcome::ERROR;
	}

	bool failed = false;
	for (;;) {
		if (!PQconsumeInput(conn)) {
			detail = std::string("PQconsumeInput: ") + PQerrorMessage(conn);
			return QueryOutcome::ERROR;
		}
		while (!PQisBusy(conn)) {
			PGresult* res = PQgetResult(conn);
			if (res == nullptr) {
				return failed ? QueryOutcome::ERROR : QueryOutcome::OK;
			}
			if (PQresultStatus(res) == PGRES_TUPLES_OK) {
				rows += PQntuples(res);
			} else {
				failed = true;
				detail = std::string("query failed: ") + PQresultErrorMessage(res);
			}
			PQclear(res);
		}
		struct pollfd pfd = { PQsocket(conn), POLLIN, 0 };
		const int rc = poll(&pfd, 1, POLL_TIMEOUT_MS);
		if (rc == 0) {
			// The signature of #6721: nothing on the socket, libpq still busy,
			// and the rest of the response decrypted inside OpenSSL.
			SSL* ssl = static_cast<SSL*>(PQsslStruct(conn, "OpenSSL"));
			std::stringstream ss;
			ss << "no input for " << POLL_TIMEOUT_MS << " ms, rows so far=" << rows
			   << ", SSL_pending=" << (ssl ? SSL_pending(ssl) : -1);
			detail = ss.str();
			return QueryOutcome::HANG;
		}
		if (rc < 0) {
			detail = "poll() failed";
			return QueryOutcome::ERROR;
		}
	}
}

int main(int argc, char** argv) {
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(1 + 2 * SWEEPS.size());

	PGConnPtr conn = open_tls_conn();
	ok(conn != nullptr && PQsslInUse(conn.get()) == 1,
		"Client connection to ProxySQL uses TLS");
	if (conn == nullptr || PQsslInUse(conn.get()) != 1) {
		for (size_t i = 0; i < SWEEPS.size(); i++) {
			ok(false, "Sweep %zu skipped: no TLS connection", i);
			ok(false, "Sweep %zu skipped: no TLS connection", i);
		}
		return exit_status();
	}

	for (const Sweep& sweep : SWEEPS) {
		std::string hung_at;
		std::string errors;
		int wrong_rows = 0;
		for (int n = sweep.min_rows; n <= sweep.max_rows; n++) {
			if (conn == nullptr) {
				conn = open_tls_conn();
				if (conn == nullptr) {
					errors += " reconnect-failed@" + std::to_string(n);
					break;
				}
			}
			std::stringstream q;
			q << "SELECT repeat('x'," << sweep.row_len << ") FROM generate_series(1," << n << ")";
			int rows = 0;
			std::string detail;
			// Run each size twice on one connection: the first hang seen during
			// the investigation was on the second query of a connection.
			for (int iter = 0; iter < 2; iter++) {
				const QueryOutcome outcome = run_polling_query(conn.get(), q.str(), rows, detail);
				if (outcome == QueryOutcome::HANG) {
					diag("HANG: row_len=%d rows=%d iteration=%d: %s",
						sweep.row_len, n, iter + 1, detail.c_str());
					hung_at += " " + std::to_string(n);
					// The connection is stuck mid-response; start a fresh one.
					conn.reset();
					break;
				}
				if (outcome == QueryOutcome::ERROR) {
					diag("ERROR: row_len=%d rows=%d iteration=%d: %s",
						sweep.row_len, n, iter + 1, detail.c_str());
					errors += " " + std::to_string(n);
					conn.reset();
					break;
				}
				if (rows != n) {
					diag("Wrong row count: row_len=%d expected=%d got=%d", sweep.row_len, n, rows);
					wrong_rows++;
				}
			}
		}
		ok(hung_at.empty(),
			"No hang for %d-byte rows, %d..%d rows per result (hung at:%s)",
			sweep.row_len, sweep.min_rows, sweep.max_rows, hung_at.empty() ? " none" : hung_at.c_str());
		ok(errors.empty() && wrong_rows == 0,
			"Every %d-byte-row result completed with the right row count (errors at:%s, wrong counts: %d)",
			sweep.row_len, errors.empty() ? " none" : errors.c_str(), wrong_rows);
	}

	return exit_status();
}
