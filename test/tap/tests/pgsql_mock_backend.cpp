/**
 * @file pgsql_mock_backend.cpp
 * @brief Implementation of the scriptable hostile PostgreSQL backend.
 *
 * See pgsql_mock_backend.h for the rationale and usage.
 *
 * The message builders here are written from the protocol specification rather
 * than by calling ProxySQL's own encoders on purpose: a fixture built with the
 * code under test cannot detect a bug in that code.
 */
#include "pgsql_mock_backend.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

// ------------------------------------------------------------- byte builders

std::string pgmb_be32(uint32_t v) {
    std::string s;
    s.push_back((char)((v >> 24) & 0xff));
    s.push_back((char)((v >> 16) & 0xff));
    s.push_back((char)((v >> 8) & 0xff));
    s.push_back((char)(v & 0xff));
    return s;
}

std::string pgmb_be16(uint16_t v) {
    std::string s;
    s.push_back((char)((v >> 8) & 0xff));
    s.push_back((char)(v & 0xff));
    return s;
}

void pgmb_append_msg(std::string& out, char type, const std::string& payload) {
    out.push_back(type);
    out += pgmb_be32((uint32_t)(payload.size() + 4));
    out += payload;
}

void pgmb_append_msg_raw_len(std::string& out, char type, uint32_t declared_len,
                             const std::string& payload) {
    out.push_back(type);
    out += pgmb_be32(declared_len);
    out += payload;
}

// ------------------------------------------------------------ auth messages

std::string pgmb_auth_raw(uint32_t auth_type, const std::string& rest) {
    std::string out;
    pgmb_append_msg(out, 'R', pgmb_be32(auth_type) + rest);
    return out;
}
std::string pgmb_auth_ok()        { return pgmb_auth_raw(0, ""); }
std::string pgmb_auth_cleartext() { return pgmb_auth_raw(3, ""); }

std::string pgmb_auth_md5(const unsigned char salt[4]) {
    return pgmb_auth_raw(5, std::string((const char*)salt, 4));
}

std::string pgmb_auth_sasl(const std::vector<std::string>& mechanisms) {
    std::string body;
    for (const auto& m : mechanisms) { body += m; body.push_back('\0'); }
    body.push_back('\0');                       // terminating empty name
    return pgmb_auth_raw(10, body);
}

std::string pgmb_auth_sasl_continue(const std::string& body) { return pgmb_auth_raw(11, body); }
std::string pgmb_auth_sasl_final(const std::string& body)    { return pgmb_auth_raw(12, body); }

// ------------------------------------------------------- steady-state messages

std::string pgmb_parameter_status(const std::string& name, const std::string& value) {
    std::string payload = name;
    payload.push_back('\0');
    payload += value;
    payload.push_back('\0');
    std::string out;
    pgmb_append_msg(out, 'S', payload);
    return out;
}

std::string pgmb_backend_key_data(int32_t pid, int32_t secret) {
    std::string out;
    pgmb_append_msg(out, 'K', pgmb_be32((uint32_t)pid) + pgmb_be32((uint32_t)secret));
    return out;
}

std::string pgmb_ready_for_query(char txn_state) {
    std::string out;
    pgmb_append_msg(out, 'Z', std::string(1, txn_state));
    return out;
}

std::string pgmb_error_response(const std::string& sqlstate, const std::string& message) {
    std::string payload;
    payload.push_back('S'); payload += "ERROR";  payload.push_back('\0');
    payload.push_back('V'); payload += "ERROR";  payload.push_back('\0');
    payload.push_back('C'); payload += sqlstate; payload.push_back('\0');
    payload.push_back('M'); payload += message;  payload.push_back('\0');
    payload.push_back('\0');                     // field-list terminator
    std::string out;
    pgmb_append_msg(out, 'E', payload);
    return out;
}

std::string pgmb_error_response_unterminated(const std::string& sqlstate) {
    // Last field value runs to the end of the payload with no NUL and no
    // field-list terminator. A parser that scans for NUL without bounding on
    // payload_len walks off the end here.
    std::string payload;
    payload.push_back('S'); payload += "FATAL"; payload.push_back('\0');
    payload.push_back('C'); payload += sqlstate; payload.push_back('\0');
    payload.push_back('M'); payload += "unterminated message value";  // no NUL, no terminator
    std::string out;
    pgmb_append_msg(out, 'E', payload);
    return out;
}

std::string pgmb_row_description_1col(const std::string& colname, uint32_t type_oid) {
    std::string payload = pgmb_be16(1);          // one field
    payload += colname; payload.push_back('\0');
    payload += pgmb_be32(0);                     // table OID
    payload += pgmb_be16(0);                     // column attribute number
    payload += pgmb_be32(type_oid);
    payload += pgmb_be16(0xffff);                // type size (-1, variable)
    payload += pgmb_be32(0xffffffff);            // type modifier (-1)
    payload += pgmb_be16(0);                     // format code: text
    std::string out;
    pgmb_append_msg(out, 'T', payload);
    return out;
}

std::string pgmb_data_row_1col(const std::string& value) {
    std::string payload = pgmb_be16(1);
    payload += pgmb_be32((uint32_t)value.size());
    payload += value;
    std::string out;
    pgmb_append_msg(out, 'D', payload);
    return out;
}

std::string pgmb_command_complete(const std::string& tag) {
    std::string payload = tag;
    payload.push_back('\0');
    std::string out;
    pgmb_append_msg(out, 'C', payload);
    return out;
}

std::string pgmb_notification_response(int32_t pid, const std::string& channel,
                                       const std::string& payload_text) {
    std::string payload = pgmb_be32((uint32_t)pid);
    payload += channel; payload.push_back('\0');
    payload += payload_text; payload.push_back('\0');
    std::string out;
    pgmb_append_msg(out, 'A', payload);
    return out;
}

std::string pgmb_simple_result(const std::string& colname, const std::string& value, int rows) {
    std::string out = pgmb_row_description_1col(colname, 25 /* text */);
    for (int i = 0; i < rows; i++) out += pgmb_data_row_1col(value);
    out += pgmb_command_complete("SELECT " + std::to_string(rows));
    out += pgmb_ready_for_query('I');
    return out;
}

bool pgmb_result_of_exact_size(std::string& out, size_t target_bytes) {
    // Fixed parts, then a single DataRow sized to absorb the remainder exactly.
    const std::string rd  = pgmb_row_description_1col("c", 25);
    const std::string cc  = pgmb_command_complete("SELECT 1");
    const std::string rfq = pgmb_ready_for_query('I');
    // DataRow overhead: 1 type + 4 length + 2 ncols + 4 value-length.
    const size_t row_overhead = 11;
    const size_t fixed = rd.size() + cc.size() + rfq.size() + row_overhead;
    if (target_bytes < fixed) return false;
    const size_t vallen = target_bytes - fixed;

    out.clear();
    out.reserve(target_bytes);
    out += rd;
    out += pgmb_data_row_1col(std::string(vallen, 'x'));
    out += cc;
    out += rfq;
    return out.size() == target_bytes;
}

// ------------------------------------------------------------------- steps

Step step_send(const std::string& data, size_t chunk_bytes, int chunk_delay_us) {
    Step s; s.kind = Step::SEND; s.data = data;
    s.chunk_bytes = chunk_bytes; s.chunk_delay_us = chunk_delay_us;
    return s;
}
Step step_expect_startup() { Step s; s.kind = Step::EXPECT_STARTUP; return s; }
Step step_expect_message() { Step s; s.kind = Step::EXPECT_MESSAGE; return s; }
Step step_expect_query()   { Step s; s.kind = Step::EXPECT_QUERY; return s; }
Step step_close()          { Step s; s.kind = Step::CLOSE; return s; }
Step step_sleep(int ms)    { Step s; s.kind = Step::SLEEP_MS; s.ms = ms; return s; }
Step step_scram_server_first(bool bad_nonce) {
    Step s; s.kind = Step::SCRAM_SERVER_FIRST; s.bad_nonce = bad_nonce; return s;
}
Step step_scram_server_final(bool forge_signature) {
    Step s; s.kind = Step::SCRAM_SERVER_FINAL; s.forge_signature = forge_signature; return s;
}

std::vector<Step> pgmb_script_accept_trust() {
    std::string post_auth =
        pgmb_auth_ok() +
        pgmb_parameter_status("server_version", "16.2") +
        pgmb_parameter_status("client_encoding", "UTF8") +
        pgmb_backend_key_data(4242, 987654321) +
        pgmb_ready_for_query('I');
    return { step_expect_startup(), step_send(post_auth) };
}

// ---------------------------------------------------------------- crypto bits

static std::string b64_encode(const std::string& in) {
    if (in.empty()) return "";
    std::string out((((in.size() + 2) / 3) * 4) + 1, '\0');
    int n = EVP_EncodeBlock((unsigned char*)&out[0], (const unsigned char*)in.data(),
                            (int)in.size());
    if (n < 0) return "";
    out.resize((size_t)n);
    return out;
}

static std::string hmac_sha256(const std::string& key, const std::string& data) {
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int mdlen = 0;
    HMAC(EVP_sha256(), key.data(), (int)key.size(),
         (const unsigned char*)data.data(), data.size(), md, &mdlen);
    return std::string((const char*)md, mdlen);
}

// SCRAM-SHA-256 server-side key derivation (RFC 5802 / RFC 7677).
static std::string scram_server_key(const std::string& password, const std::string& salt,
                                    int iterations) {
    unsigned char salted[32];
    PKCS5_PBKDF2_HMAC(password.data(), (int)password.size(),
                      (const unsigned char*)salt.data(), (int)salt.size(),
                      iterations, EVP_sha256(), sizeof(salted), salted);
    return hmac_sha256(std::string((const char*)salted, sizeof(salted)), "Server Key");
}

// Extract the value of `key=` from a comma-separated SCRAM attribute list.
static std::string scram_attr(const std::string& msg, char key) {
    size_t i = 0;
    while (i < msg.size()) {
        size_t end = msg.find(',', i);
        if (end == std::string::npos) end = msg.size();
        if (end - i >= 2 && msg[i] == key && msg[i + 1] == '=')
            return msg.substr(i + 2, end - i - 2);
        i = end + 1;
    }
    return "";
}

// --------------------------------------------------------------- socket I/O

static bool write_all(int fd, const char* p, size_t n) {
    while (n > 0) {
        ssize_t w = ::send(fd, p, n, MSG_NOSIGNAL);
        if (w > 0) { p += w; n -= (size_t)w; continue; }
        if (w < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        return false;
    }
    return true;
}

static bool read_exact(int fd, char* p, size_t n) {
    while (n > 0) {
        ssize_t r = ::recv(fd, p, n, 0);
        if (r > 0) { p += r; n -= (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        return false;   // EOF or error
    }
    return true;
}

// Read a frontend message that HAS a type byte. Returns false on EOF/error.
static bool read_frontend_msg(int fd, char* type, std::string& payload) {
    char hdr[5];
    if (!read_exact(fd, hdr, 5)) return false;
    *type = hdr[0];
    uint32_t len = ((uint32_t)(unsigned char)hdr[1] << 24) |
                   ((uint32_t)(unsigned char)hdr[2] << 16) |
                   ((uint32_t)(unsigned char)hdr[3] << 8)  |
                    (uint32_t)(unsigned char)hdr[4];
    if (len < 4 || len > (1u << 28)) return false;
    payload.assign(len - 4, '\0');
    if (len > 4 && !read_exact(fd, &payload[0], len - 4)) return false;
    return true;
}

// Read the startup packet, which has NO type byte.
static bool read_startup(int fd, std::string& payload) {
    char hdr[4];
    if (!read_exact(fd, hdr, 4)) return false;
    uint32_t len = ((uint32_t)(unsigned char)hdr[0] << 24) |
                   ((uint32_t)(unsigned char)hdr[1] << 16) |
                   ((uint32_t)(unsigned char)hdr[2] << 8)  |
                    (uint32_t)(unsigned char)hdr[3];
    if (len < 4 || len > (1u << 20)) return false;
    payload.assign(len - 4, '\0');
    if (len > 4 && !read_exact(fd, &payload[0], len - 4)) return false;
    return true;
}

// ------------------------------------------------------------- local IP probe

std::string pgmb_local_ip_towards(const char* peer_host, uint16_t peer_port) {
    // Connect a UDP socket (no packets are sent) and ask the kernel which
    // source address it chose. Works without DNS and without assuming the
    // container's hostname resolves.
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo* res = nullptr;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)peer_port);
    if (getaddrinfo(peer_host, portstr, &hints, &res) != 0 || !res) return "";

    std::string ip;
    int s = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (s >= 0) {
        if (::connect(s, res->ai_addr, res->ai_addrlen) == 0) {
            struct sockaddr_in local;
            socklen_t sl = sizeof(local);
            if (::getsockname(s, (struct sockaddr*)&local, &sl) == 0) {
                char buf[INET_ADDRSTRLEN] = {0};
                if (inet_ntop(AF_INET, &local.sin_addr, buf, sizeof(buf))) ip = buf;
            }
        }
        ::close(s);
    }
    freeaddrinfo(res);
    return ip;
}

// -------------------------------------------------------------- the listener

PgSQL_Mock_Backend::~PgSQL_Mock_Backend() { stop(); }

void PgSQL_Mock_Backend::set_script(const std::vector<Step>& steps) {
    std::lock_guard<std::mutex> g(script_mtx_);
    script_ = steps;
}

void PgSQL_Mock_Backend::set_scram_password(const std::string& pw) {
    std::lock_guard<std::mutex> g(script_mtx_);
    scram_password_ = pw;
}

std::string PgSQL_Mock_Backend::last_error() {
    std::lock_guard<std::mutex> g(err_mtx_);
    return last_error_;
}

bool PgSQL_Mock_Backend::start() {
    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) return false;
    int one = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = 0;                                  // ephemeral
    if (::bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        ::close(listen_fd_); listen_fd_ = -1; return false;
    }
    socklen_t sl = sizeof(addr);
    if (::getsockname(listen_fd_, (struct sockaddr*)&addr, &sl) != 0) {
        ::close(listen_fd_); listen_fd_ = -1; return false;
    }
    port_ = ntohs(addr.sin_port);
    if (::listen(listen_fd_, 32) != 0) {
        ::close(listen_fd_); listen_fd_ = -1; return false;
    }
    running_.store(true);
    acceptor_ = std::thread(&PgSQL_Mock_Backend::accept_loop, this);
    return true;
}

void PgSQL_Mock_Backend::stop() {
    if (!running_.exchange(false)) return;
    if (listen_fd_ >= 0) { ::shutdown(listen_fd_, SHUT_RDWR); ::close(listen_fd_); listen_fd_ = -1; }
    // Unblock workers parked in recv() on a proxy that never sent a query, so the
    // join below cannot hang the whole run.
    {
        std::lock_guard<std::mutex> g(conns_mtx_);
        for (int cfd : client_fds_) ::shutdown(cfd, SHUT_RDWR);
    }
    if (acceptor_.joinable()) acceptor_.join();
    for (auto& t : workers_) if (t.joinable()) t.join();
    workers_.clear();
}

std::string pgmb_copy_out_response(int ncols) {
    std::string payload;
    payload.push_back('\0');                      // overall format: 0 = text
    payload += pgmb_be16((uint16_t)ncols);
    for (int i = 0; i < ncols; i++) payload += pgmb_be16(0);   // per-column: text
    std::string out;
    pgmb_append_msg(out, 'H', payload);
    return out;
}

std::string pgmb_copy_data(const std::string& payload) {
    std::string out;
    pgmb_append_msg(out, 'd', payload);
    return out;
}

void PgSQL_Mock_Backend::accept_loop() {
    while (running_.load()) {
        int fd = ::accept(listen_fd_, nullptr, nullptr);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;                                       // listener closed
        }
        int one = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        conns_accepted_.fetch_add(1);
        std::vector<Step> script;
        {
            std::lock_guard<std::mutex> g(script_mtx_);
            script = script_;
        }
        workers_.emplace_back(&PgSQL_Mock_Backend::handle_conn, this, fd, script);
    }
}

void PgSQL_Mock_Backend::handle_conn(int fd, std::vector<Step> script) {
    {
        std::lock_guard<std::mutex> g(conns_mtx_);
        client_fds_.push_back(fd);
    }
    std::string password;
    {
        std::lock_guard<std::mutex> g(script_mtx_);
        password = scram_password_;
    }

    // SCRAM exchange state, carried across the two SCRAM steps.
    std::string client_first_bare, server_first, salt;
    const int iterations = 4096;

    auto fail = [&](const char* what) {
        std::lock_guard<std::mutex> g(err_mtx_);
        last_error_ = what;
    };

    for (const Step& s : script) {
        switch (s.kind) {
        case Step::SEND: {
            if (s.chunk_bytes == 0) {
                if (!write_all(fd, s.data.data(), s.data.size())) { fail("write failed"); goto done; }
            } else {
                size_t off = 0;
                while (off < s.data.size()) {
                    const size_t n = std::min(s.chunk_bytes, s.data.size() - off);
                    if (!write_all(fd, s.data.data() + off, n)) { fail("chunked write failed"); goto done; }
                    off += n;
                    if (s.chunk_delay_us > 0) usleep((useconds_t)s.chunk_delay_us);
                }
            }
            break;
        }
        case Step::EXPECT_STARTUP: {
            std::string payload;
            if (!read_startup(fd, payload)) { fail("startup read failed"); goto done; }
            break;
        }
        case Step::EXPECT_MESSAGE: {
            char type = 0; std::string payload;
            if (!read_frontend_msg(fd, &type, payload)) { fail("frontend message read failed"); goto done; }
            break;
        }
        case Step::EXPECT_QUERY: {
            // Swallow and generically acknowledge anything the proxy sends
            // ahead of the client's query, so a canned result is never handed
            // to the wrong message. See the header for why this matters.
            //
            // ProxySQL's own housekeeping (session-variable replay, DISCARD,
            // transaction control) arrives as a simple Query too, so stopping
            // at the first 'Q' is not enough — the caller's canned RESULTSET
            // would then answer a proxy SET. That is not a harmless mismatch:
            // it drives ProxySQL into an unbounded error loop (see the
            // async_send_simple_command finding). Housekeeping is acknowledged
            // with a COMMAND response and skipped.
            for (;;) {
                char type = 0; std::string payload;
                if (!read_frontend_msg(fd, &type, payload)) { fail("query read failed"); goto done; }
                if (type == 'X') goto done;              // Terminate
                if (type == 'Q') {
                    // Payload is the NUL-terminated query text.
                    std::string q(payload.c_str());
                    size_t i = q.find_first_not_of(" \t\r\n");
                    if (i == std::string::npos) i = 0;
                    std::string head = q.substr(i, 8);
                    for (char& ch : head) ch = (char)toupper((unsigned char)ch);
                    const bool housekeeping =
                        head.rfind("SET ", 0) == 0     || head.rfind("RESET", 0) == 0 ||
                        head.rfind("DISCARD", 0) == 0  || head.rfind("BEGIN", 0) == 0 ||
                        head.rfind("COMMIT", 0) == 0   || head.rfind("ROLLBACK", 0) == 0 ||
                        head.rfind("START TR", 0) == 0;
                    if (!housekeeping) {                 // the client's query
                        queries_observed_.fetch_add(1);
                        break;
                    }
                    const std::string ack =
                        pgmb_command_complete("SET") + pgmb_ready_for_query('I');
                    if (!write_all(fd, ack.data(), ack.size())) { fail("housekeeping ack failed"); goto done; }
                    continue;
                }
                const std::string ack = pgmb_command_complete("SET") + pgmb_ready_for_query('I');
                if (!write_all(fd, ack.data(), ack.size())) { fail("pre-query ack failed"); goto done; }
            }
            break;
        }
        case Step::CLOSE:
            goto done;
        case Step::SLEEP_MS:
            usleep((useconds_t)s.ms * 1000);
            break;

        case Step::SCRAM_SERVER_FIRST: {
            // SASLInitialResponse: mechanism\0 | int32 len | client-first-message
            char type = 0; std::string payload;
            if (!read_frontend_msg(fd, &type, payload)) { fail("SASLInitialResponse read failed"); goto done; }
            size_t z = payload.find('\0');
            if (z == std::string::npos || payload.size() < z + 5) { fail("malformed SASLInitialResponse"); goto done; }
            const std::string client_first = payload.substr(z + 5);
            // client-first-bare is everything after the gs2 header ("n,," / "y,," / "p=...,,").
            size_t bare = client_first.find(",,");
            client_first_bare = (bare == std::string::npos) ? client_first : client_first.substr(bare + 2);
            const std::string client_nonce = scram_attr(client_first_bare, 'r');

            unsigned char rnd[18];
            RAND_bytes(rnd, sizeof(rnd));
            const std::string server_nonce_part = b64_encode(std::string((const char*)rnd, sizeof(rnd)));
            unsigned char saltb[16];
            RAND_bytes(saltb, sizeof(saltb));
            salt.assign((const char*)saltb, sizeof(saltb));

            // RFC 5802: the server nonce MUST begin with the client nonce. With
            // bad_nonce we deliberately violate that, which a correct client
            // must detect and abort on.
            const std::string combined_nonce = s.bad_nonce
                ? server_nonce_part
                : client_nonce + server_nonce_part;

            server_first = "r=" + combined_nonce + ",s=" + b64_encode(salt) +
                           ",i=" + std::to_string(iterations);
            const std::string msg = pgmb_auth_sasl_continue(server_first);
            if (!write_all(fd, msg.data(), msg.size())) { fail("server-first write failed"); goto done; }
            break;
        }

        case Step::SCRAM_SERVER_FINAL: {
            char type = 0; std::string client_final;
            if (!read_frontend_msg(fd, &type, client_final)) { fail("SASLResponse read failed"); goto done; }
            // client-final-without-proof is everything before ",p=".
            const size_t ppos = client_final.rfind(",p=");
            const std::string cf_without_proof = (ppos == std::string::npos)
                ? client_final : client_final.substr(0, ppos);

            const std::string auth_message =
                client_first_bare + "," + server_first + "," + cf_without_proof;
            std::string sig = hmac_sha256(scram_server_key(password, salt, iterations), auth_message);

            if (s.forge_signature) {
                // Flip every bit. A client that verifies the server signature
                // rejects this; a client that skips verification accepts a
                // server that cannot prove it knows the secret.
                for (char& c : sig) c = (char)(~(unsigned char)c);
            }
            const std::string msg = pgmb_auth_sasl_final("v=" + b64_encode(sig));
            if (!write_all(fd, msg.data(), msg.size())) { fail("server-final write failed"); goto done; }
            break;
        }
        }
    }

    // Script exhausted: hold the connection open briefly so ProxySQL observes
    // whatever final state the script left, rather than an immediate FIN that
    // could be misread as the thing under test.
    usleep(200000);

done:
    // Deregister BEFORE closing: once this fd is closed the OS can hand the same
    // number to a new socket, and stop() would then ::shutdown() an unrelated
    // connection belonging to the test process.
    {
        std::lock_guard<std::mutex> g(conns_mtx_);
        auto it = std::find(client_fds_.begin(), client_fds_.end(), fd);
        if (it != client_fds_.end()) client_fds_.erase(it);
    }
    ::close(fd);
}
