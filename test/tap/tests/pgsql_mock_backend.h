/**
 * @file pgsql_mock_backend.h
 * @brief A scriptable fake PostgreSQL backend for TAP tests.
 *
 * WHY THIS EXISTS
 * ---------------
 * Some ProxySQL failure modes can only be reached from a backend that behaves
 * in a way a real PostgreSQL never does. The one this file exists for is a
 * server that VANISHES IN THE MIDDLE OF A RESULT — TCP close with no
 * ErrorResponse, after rows have already gone out.
 *
 * A real PostgreSQL cannot be asked to do that. pg_terminate_backend() and a
 * graceful shutdown both send a FATAL ErrorResponse before closing, which puts
 * ProxySQL on its ordinary error path; the defect under test needs
 * PQconsumeInput() to FAIL, which only happens on a raw transport close. The
 * alternative — a real server behind a killable TCP relay — reproduces it but
 * depends on killing at the exact instant rows are in flight, which is the kind
 * of timing dependency that makes tests flaky. This harness hits the same state
 * deterministically.
 *
 * USAGE
 * -----
 *   PgSQL_Mock_Backend mock;
 *   if (!mock.start()) BAIL_OUT("mock backend failed to listen");
 *   mock.set_script({ step_expect_startup(), step_send(handshake),
 *                     step_expect_query(), step_send(partial_result),
 *                     step_close() });
 *   // ... register mock.host() : mock.port() in pgsql_servers, drive traffic ...
 *   mock.stop();
 *
 * A script is a list of Steps executed in order per accepted connection. The
 * connection handler runs on its own thread, so several ProxySQL connections can
 * be in flight at once; each gets a fresh copy of the script.
 *
 * WHAT THIS IS NOT
 * ----------------
 * Not a PostgreSQL implementation. It answers a startup packet with a trust-style
 * AuthenticationOk and does not execute SQL — every result it returns is canned
 * bytes. Plaintext only; it speaks no TLS and no MD5/SCRAM authentication.
 *
 * SCOPE NOTE
 * ----------
 * This is a deliberately reduced version, carrying only what
 * pgsql-midresult_disconnect-t needs. The fuller harness it came from also
 * drives the SCRAM server side (including forged signatures and non-extending
 * nonces), builds malformed frames with arbitrary declared lengths, and delivers
 * payloads byte-by-byte — all of which exist to test a native backend protocol
 * that this branch does not have.
 */
#ifndef PGSQL_MOCK_BACKEND_H
#define PGSQL_MOCK_BACKEND_H

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// ---------------------------------------------------------------- primitives
//
// Builders for the backend-direction messages a script needs. All lengths are
// big-endian and include the 4-byte length field itself but not the type byte,
// per the PostgreSQL protocol. Deliberately independent of ProxySQL's own
// encoders: a test that used the code under test to build its fixtures could not
// detect an encoding bug in it.

// Append a framed message: type byte, int32 length, payload.
void pgmb_append_msg(std::string& out, char type, const std::string& payload);

std::string pgmb_be32(uint32_t v);
std::string pgmb_be16(uint16_t v);

// AuthenticationOk -- the only authentication this harness performs.
std::string pgmb_auth_ok();

std::string pgmb_parameter_status(const std::string& name, const std::string& value);
std::string pgmb_backend_key_data(int32_t pid, int32_t secret);
std::string pgmb_ready_for_query(char txn_state);          // 'I' | 'T' | 'E'
std::string pgmb_row_description_1col(const std::string& colname, uint32_t type_oid);
std::string pgmb_data_row_1col(const std::string& value);
std::string pgmb_command_complete(const std::string& tag);

// CopyOutResponse ('H') for a text-format copy with `ncols` columns, and one
// CopyData ('d') payload. Used to drive ProxySQL's PGRES_COPY_OUT path, which is
// the only way to set is_copy_out.
std::string pgmb_copy_out_response(int ncols);
std::string pgmb_copy_data(const std::string& payload);

// A complete, well-formed single-column result: RowDescription, `rows` DataRows
// each carrying `value`, CommandComplete, ReadyForQuery('I').
std::string pgmb_simple_result(const std::string& colname, const std::string& value, int rows);

// ---------------------------------------------------------------------- steps

struct Step {
    enum Kind {
        SEND,              // write `data` to the client
        // Read frontend messages until a simple Query ('Q') arrives, generically
        // acknowledging anything else along the way. ProxySQL may legitimately
        // send its own statements (session-variable replay, transaction control)
        // before the client's query; a step that stopped at the first message
        // would answer one of those with the canned result and then leave the
        // real query unanswered, which looks like a hang in the code under test
        // rather than a scripting mistake in the fixture.
        EXPECT_QUERY,
        EXPECT_STARTUP,    // read the startup packet (no type byte, length-prefixed)
        CLOSE,             // close the connection immediately (FIN)
        SLEEP_MS           // pause, e.g. to let ProxySQL sit on an unfinished message
    };
    Kind kind = SEND;
    std::string data;      // SEND payload
    int ms = 0;            // SLEEP_MS duration
};

// Convenience constructors.
Step step_send(const std::string& data);
Step step_expect_startup();
Step step_expect_query();
Step step_close();
Step step_sleep(int ms);

// ------------------------------------------------------------------ the mock

class PgSQL_Mock_Backend {
public:
    PgSQL_Mock_Backend() = default;
    ~PgSQL_Mock_Backend();
    PgSQL_Mock_Backend(const PgSQL_Mock_Backend&) = delete;
    PgSQL_Mock_Backend& operator=(const PgSQL_Mock_Backend&) = delete;

    // Bind an ephemeral port on all interfaces and start accepting. Returns
    // false if the socket could not be set up.
    bool start();
    void stop();

    // The address ProxySQL should be pointed at. host() is this container's
    // routable IP on the shared Docker network, discovered at runtime rather
    // than via Docker DNS so the test does not depend on how the runner
    // container's name or hostname is registered.
    const std::string& host() const { return host_; }
    uint16_t port() const { return port_; }

    // Replace the script future connections will run. Connections already in
    // progress keep the script they started with.
    void set_script(const std::vector<Step>& steps);

    // Connections accepted since the last reset_stats().
    int connections_accepted() const { return conns_accepted_.load(); }
    void reset_stats() { conns_accepted_.store(0); }

    // Diagnostics from the most recent connection handler, for failure output.
    std::string last_error();

private:
    void accept_loop();
    void handle_conn(int fd, std::vector<Step> script);

    int listen_fd_ = -1;
    uint16_t port_ = 0;
    std::string host_;
    std::thread acceptor_;
    std::vector<std::thread> workers_;
    std::atomic<bool> running_{false};
    std::atomic<int> conns_accepted_{0};
    std::mutex script_mtx_;
    std::vector<Step> script_;
    std::mutex err_mtx_;
    std::string last_error_;
};

// Best-effort discovery of this container's IP on the shared Docker network:
// the source address the kernel would use to reach `peer_host`. Falls back to
// an empty string, which callers must treat as fatal.
std::string pgmb_local_ip_towards(const char* peer_host, uint16_t peer_port);

#endif // PGSQL_MOCK_BACKEND_H
