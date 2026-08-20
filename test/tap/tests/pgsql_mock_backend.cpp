/**
 * @file pgsql_mock_backend.cpp
 * @brief Implementation of the scriptable fake PostgreSQL backend.
 *
 * See pgsql_mock_backend.h for the rationale and usage.
 *
 * The message builders here are written from the protocol specification rather
 * than by calling ProxySQL's own encoders on purpose: a fixture built with the
 * code under test cannot detect a bug in that code.
 */
#include "pgsql_mock_backend.h"

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
    out += pgmb_be32((uint32_t)payload.size() + 4);
    out += payload;
}

// ------------------------------------------------------ backend-side messages

std::string pgmb_auth_ok() {
    std::string out;
    pgmb_append_msg(out, 'R', pgmb_be32(0));
    return out;
}

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

std::string pgmb_simple_result(const std::string& colname, const std::string& value, int rows) {
    std::string out = pgmb_row_description_1col(colname, 25 /* text */);
    for (int i = 0; i < rows; i++) out += pgmb_data_row_1col(value);
    out += pgmb_command_complete("SELECT " + std::to_string(rows));
    out += pgmb_ready_for_query('I');
    return out;
}

// ------------------------------------------------------------------- steps

Step step_send(const std::string& data) {
    Step s; s.kind = Step::SEND; s.data = data;
    return s;
}
Step step_expect_startup() { Step s; s.kind = Step::EXPECT_STARTUP; return s; }
Step step_expect_query()   { Step s; s.kind = Step::EXPECT_QUERY; return s; }
Step step_close()          { Step s; s.kind = Step::CLOSE; return s; }
Step step_sleep(int ms)    { Step s; s.kind = Step::SLEEP_MS; s.ms = ms; return s; }

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
    if (acceptor_.joinable()) acceptor_.join();
    for (auto& t : workers_) if (t.joinable()) t.join();
    workers_.clear();
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
    auto fail = [&](const char* what) {
        std::lock_guard<std::mutex> g(err_mtx_);
        last_error_ = what;
    };

    for (const Step& s : script) {
        switch (s.kind) {
        case Step::SEND: {
            if (!write_all(fd, s.data.data(), s.data.size())) { fail("write failed"); goto done; }
            break;
        }
        case Step::EXPECT_STARTUP: {
            std::string payload;
            if (!read_startup(fd, payload)) { fail("startup read failed"); goto done; }
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
            // it drives ProxySQL into an unbounded error loop. Housekeeping is
            // acknowledged with a COMMAND response and skipped.
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
            // Slept in slices, watching running_, so a script that deliberately holds
            // a socket open for seconds does not make stop() -- which joins these
            // threads -- block for the remainder of it.
            for (int slept = 0; slept < s.ms && running_.load(); slept += 100) {
                usleep(100000);
            }
            break;
        }
    }

    // Script exhausted: hold the connection open briefly so ProxySQL observes
    // whatever final state the script left, rather than an immediate FIN that
    // could be misread as the thing under test.
    usleep(200000);

done:
    ::close(fd);
}
