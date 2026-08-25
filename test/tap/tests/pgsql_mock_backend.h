/**
 * @file pgsql_mock_backend.h
 * @brief A scriptable, deliberately hostile PostgreSQL backend for TAP tests.
 *
 * WHY THIS EXISTS
 * ---------------
 * ProxySQL's native backend protocol handles malformed framing, truncated
 * messages, forged authentication, unexpected message types and mid-stream
 * disconnects. None of those branches can be reached from a real PostgreSQL,
 * because a real PostgreSQL does not emit those bytes. Every existing
 * native-path test uses a healthy backend as its oracle, so the entire error
 * surface of PgSQL_Connection.cpp and PgSQL_Backend_Protocol.cpp is untested.
 *
 * This harness is the missing half: a listener that speaks just enough of the
 * wire protocol to be accepted as a backend, then emits whatever the test tells
 * it to. It is registered in `pgsql_servers` like any other backend, so
 * ProxySQL reaches it through the ordinary connect/auth/query path.
 *
 * USAGE
 * -----
 *   PgSQL_Mock_Backend mock;
 *   if (!mock.start()) BAIL_OUT("mock backend failed to listen");
 *   mock.set_script(script_that_sends_garbage_during_auth());
 *   // ... register mock.host() : mock.port() in pgsql_servers, drive traffic ...
 *   mock.stop();
 *
 * A script is a list of Steps executed in order per accepted connection. The
 * connection handler runs on its own thread, so several ProxySQL connections
 * can be in flight at once; each gets a fresh copy of the script.
 *
 * DELIVERY GRANULARITY
 * --------------------
 * Step::chunk_bytes controls how the payload reaches the wire: 0 means one
 * write(), N means N bytes per write() with a short pause between. That is how
 * partial-message framing gets exercised — the framer must cope with a length
 * field split across reads.
 *
 * WHAT THIS IS NOT
 * ----------------
 * Not a PostgreSQL implementation. It answers a startup packet and can drive a
 * real SCRAM-SHA-256 server side far enough to test ProxySQL's client side, but
 * it does not execute SQL. Every result it returns is canned bytes. It is
 * plaintext only — TLS backends are covered against the real server by
 * pgsql-native_tls-t.
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
// encoders: a test that used the code under test to build its fixtures could
// not detect an encoding bug in it.

// Append a framed message: type byte, int32 length, payload.
void pgmb_append_msg(std::string& out, char type, const std::string& payload);

// Append a message with an ARBITRARY declared length, ignoring the real payload
// size. This is how truncation, over-long and under-long frames are built.
void pgmb_append_msg_raw_len(std::string& out, char type, uint32_t declared_len,
                             const std::string& payload);

std::string pgmb_be32(uint32_t v);
std::string pgmb_be16(uint16_t v);

// AuthenticationOk / AuthenticationCleartextPassword / AuthenticationMD5Password.
std::string pgmb_auth_ok();
std::string pgmb_auth_cleartext();
std::string pgmb_auth_md5(const unsigned char salt[4]);
// AuthenticationSASL advertising the given mechanism list (may be empty).
std::string pgmb_auth_sasl(const std::vector<std::string>& mechanisms);
// AuthenticationSASLContinue / AuthenticationSASLFinal with a raw body.
std::string pgmb_auth_sasl_continue(const std::string& body);
std::string pgmb_auth_sasl_final(const std::string& body);
// An Authentication message with an arbitrary subtype code (7=GSSAPI, 9=SSPI,
// or a value no PostgreSQL version defines).
std::string pgmb_auth_raw(uint32_t auth_type, const std::string& rest);

std::string pgmb_parameter_status(const std::string& name, const std::string& value);
std::string pgmb_backend_key_data(int32_t pid, int32_t secret);
std::string pgmb_ready_for_query(char txn_state);          // 'I' | 'T' | 'E'
std::string pgmb_error_response(const std::string& sqlstate, const std::string& message);
// ErrorResponse whose final field value is NOT NUL-terminated — the payload
// simply ends. Exercises the bounds checks in native_fill_error_from_E().
std::string pgmb_error_response_unterminated(const std::string& sqlstate);
std::string pgmb_row_description_1col(const std::string& colname, uint32_t type_oid);
std::string pgmb_data_row_1col(const std::string& value);
std::string pgmb_command_complete(const std::string& tag);
std::string pgmb_notification_response(int32_t pid, const std::string& channel,
                                       const std::string& payload);

// A complete, well-formed single-column result: RowDescription, `rows` DataRows
// each carrying `value`, CommandComplete, ReadyForQuery('I').
std::string pgmb_simple_result(const std::string& colname, const std::string& value, int rows);

// CopyOutResponse ('H') for a text-format copy with `ncols` columns, and one
// CopyData ('d') payload. Used to drive ProxySQL's PGRES_COPY_OUT path, which is
// the only way to set is_copy_out.
std::string pgmb_copy_out_response(int ncols);
std::string pgmb_copy_data(const std::string& payload);

// A well-formed result padded with NoticeResponse messages until the total byte
// count is EXACTLY `target_bytes`. Used to hit the exact-multiple-of-16384
// condition behind defect D4. Returns false if the target cannot be hit exactly
// (too small to fit the mandatory messages).
bool pgmb_result_of_exact_size(std::string& out, size_t target_bytes);

// ---------------------------------------------------------------------- steps

struct Step {
    enum Kind {
        SEND,              // write `data` to the client
        EXPECT_MESSAGE,    // read and discard one frontend message (any type)
        // Read frontend messages until a simple Query ('Q') arrives, generically
        // acknowledging anything else along the way. ProxySQL may legitimately
        // send its own statements (session-variable replay, init_connect, a
        // Sync) before the client's query; a fixed EXPECT_MESSAGE would answer
        // one of those with the canned result and then leave the real query
        // unanswered, which looks like a hang in the code under test rather
        // than a scripting mistake in the fixture.
        EXPECT_QUERY,
        EXPECT_STARTUP,    // read the startup packet (no type byte, length-prefixed)
        CLOSE,             // close the connection immediately (FIN)
        SLEEP_MS,          // pause, e.g. to let ProxySQL park the connection
        SCRAM_SERVER_FIRST,// read SASLInitialResponse, reply with a real server-first
        SCRAM_SERVER_FINAL // read SASLResponse, reply with server-final (see forge_signature)
    };
    Kind kind = SEND;
    std::string data;      // SEND payload
    int ms = 0;            // SLEEP_MS duration
    size_t chunk_bytes = 0;// SEND granularity: 0 = one write, N = N bytes per write
    int chunk_delay_us = 0;// pause between chunks when chunk_bytes > 0

    // SCRAM_SERVER_FINAL only. When true the server signature sent to ProxySQL
    // is deliberately wrong, simulating a server that cannot prove it knows the
    // shared secret. ProxySQL MUST reject it: this is the sole defence against
    // a spoofed or MITM'd backend. When false a correct signature is sent.
    bool forge_signature = false;

    // SCRAM_SERVER_FIRST only. When true the server nonce does NOT extend the
    // client nonce, violating RFC 5802. A correct client must abort.
    bool bad_nonce = false;
};

// Convenience constructors.
Step step_send(const std::string& data, size_t chunk_bytes = 0, int chunk_delay_us = 0);
Step step_expect_startup();
Step step_expect_message();
Step step_expect_query();
Step step_close();
Step step_sleep(int ms);
Step step_scram_server_first(bool bad_nonce = false);
Step step_scram_server_final(bool forge_signature = false);

// Scripts for the handshake shapes tests reuse.
//
// A trust-style handshake: startup -> AuthenticationOk -> ParameterStatus x2 ->
// BackendKeyData -> ReadyForQuery('I'). Leaves the connection ready for a query.
std::vector<Step> pgmb_script_accept_trust();

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

    // The password the SCRAM_SERVER_* steps derive keys from. Must match the
    // password ProxySQL is configured to use for this backend, otherwise even
    // the honest server-final is rejected and the forged-signature case proves
    // nothing.
    void set_scram_password(const std::string& pw);

    // Connections accepted since the last reset_stats().
    int connections_accepted() const { return conns_accepted_.load(); }

    // Client queries an EXPECT_QUERY step actually took delivery of since the last
    // reset_stats(), excluding the proxy's own housekeeping statements. Separates
    // "the scripted reply was delivered" from "the fixture never routed anything
    // here", which otherwise look identical from the client side.
    int queries_observed() const { return queries_observed_.load(); }

    void reset_stats() { conns_accepted_.store(0); queries_observed_.store(0); }

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
    std::atomic<int> queries_observed_{0};
    // Client sockets currently owned by worker threads. stop() shuts these down so a
    // worker blocked reading from a proxy that connected but never sent a query does
    // not make the join below hang the whole run.
    std::mutex conns_mtx_;
    std::vector<int> client_fds_;
    std::mutex script_mtx_;
    std::vector<Step> script_;
    std::string scram_password_ = "mockpw";
    std::mutex err_mtx_;
    std::string last_error_;
};

// Best-effort discovery of this container's IP on the shared Docker network:
// the source address the kernel would use to reach `peer_host`. Falls back to
// an empty string, which callers must treat as fatal.
std::string pgmb_local_ip_towards(const char* peer_host, uint16_t peer_port);

#endif // PGSQL_MOCK_BACKEND_H
