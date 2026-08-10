#include "proxysql.h"
#include "PgSQL_HostGroups_Manager.h"
#include "PgSQL_Thread.h"
#include "PgSQL_Session.h"
#include "PgSQL_Data_Stream.h"
#include "PgSQL_Query_Processor.h"
#include "PgSQLFFTO.hpp"
#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif
#include "c_tokenizer.h"
#include "PgSQLErrorFields.h"
#include <arpa/inet.h>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string_view>

extern class PgSQL_Query_Processor* GloPgQPro;
extern PgSQL_HostGroups_Manager* PgHGM;

/**
 * @brief Parses the PostgreSQL CommandComplete ('C') message payload to extract row counts.
 *
 * PostgreSQL encodes row counts into the message tag string (e.g., "INSERT 0 10", "SELECT 50").
 * This function performs lightweight token parsing to extract these values and determine if
 * the message corresponds to a result-generating command (SELECT, FETCH, MOVE) or a DML command.
 *
 * @param payload Pointer to the CommandComplete message payload (the tag string).
 * @param len Length of the payload.
 * @param is_select [OUT] Boolean flag set to true if the command is a result-set operation.
 * @return The number of rows affected or sent.
 */
static uint64_t extract_pg_rows_affected(const unsigned char* payload, size_t len, bool& is_select) {
    is_select = false;
    if (len == 0) return 0;

    size_t begin = 0;
    while (begin < len && std::isspace(payload[begin])) begin++;
    while (len > begin && (payload[len - 1] == '\0' || std::isspace(payload[len - 1]))) len--;
    if (begin >= len) return 0;

    std::string command_tag(reinterpret_cast<const char*>(payload + begin), len - begin);

    size_t first_space = command_tag.find(' ');
    if (first_space == std::string::npos) return 0;

    std::string command_type = command_tag.substr(0, first_space);
    if (command_type == "SELECT" || command_type == "FETCH" || command_type == "MOVE") {
        is_select = true;
    } else if (command_type != "INSERT" && command_type != "UPDATE" &&
               command_type != "DELETE" && command_type != "COPY" &&
               command_type != "MERGE") {
        return 0;
    }

    size_t last_space = command_tag.rfind(' ');
    if (last_space == std::string::npos || last_space + 1 >= command_tag.size()) return 0;

    const char* rows_str = command_tag.c_str() + last_space + 1;
    char* endptr = nullptr;
    unsigned long long rows = std::strtoull(rows_str, &endptr, 10);
    if (endptr == rows_str || *endptr != '\0') {
        return 0;
    }
    return rows;
}

static size_t bounded_cstr_len(const char* s, size_t max_len) {
    if (s == nullptr || max_len == 0) {
        return 0;
    }
    const void* null_pos = memchr(s, '\0', max_len);
    return null_pos ? static_cast<const char *>(null_pos) - s : max_len;
}

PgSQLFFTO::PgSQLFFTO(PgSQL_Session* session)
    : m_session(session), m_state(IDLE), m_query_start_time(0), m_affected_rows(0), m_rows_sent(0) {
    m_client_buffer.reserve(1024);
    m_server_buffer.reserve(4096);
}

PgSQLFFTO::~PgSQLFFTO() {
    on_close();
}

void PgSQLFFTO::on_client_data(const char* buf, std::size_t len) {
    if (!buf || len == 0) return;
    m_client_buffer.insert(m_client_buffer.end(), buf, buf + len);
    while (m_client_buffer.size() - m_client_offset >= 5) {
        char type = m_client_buffer[m_client_offset];
        uint32_t msg_len; memcpy(&msg_len, &m_client_buffer[m_client_offset + 1], 4); msg_len = ntohl(msg_len);
        if (msg_len > (uint32_t)pgsql_thread___ffto_max_buffer_size) {
            m_session->ffto_bypassed = true;
            on_close();
            return;
        }
        if (msg_len < 4 || msg_len > 1024 * 1024 * 1024) { // Sanity check
            on_close();
            m_client_buffer.clear(); m_client_offset = 0;
            return;
        }
        if (m_client_buffer.size() - m_client_offset < 1 + msg_len) break;
        const unsigned char* payload = reinterpret_cast<const unsigned char*>(m_client_buffer.data()) + m_client_offset + 5;
        process_client_message(type, payload, msg_len - 4);
        m_client_offset += 1 + msg_len;
    }
    if (m_client_offset > 0) {
        if (m_client_offset >= m_client_buffer.size()) {
            m_client_buffer.clear();
            m_client_offset = 0;
        } else if (m_client_offset > 1024) {
            m_client_buffer.erase(m_client_buffer.begin(), m_client_buffer.begin() + m_client_offset);
            m_client_offset = 0;
        }
    }
}

void PgSQLFFTO::on_server_data(const char* buf, std::size_t len) {
    if (!buf || len == 0) return;
    m_server_buffer.insert(m_server_buffer.end(), buf, buf + len);
    while (m_server_buffer.size() - m_server_offset >= 5) {
        char type = m_server_buffer[m_server_offset];
        uint32_t msg_len; memcpy(&msg_len, &m_server_buffer[m_server_offset + 1], 4); msg_len = ntohl(msg_len);
        if (msg_len > (uint32_t)pgsql_thread___ffto_max_buffer_size) {
            if (m_session) m_session->ffto_bypassed = true;
            on_close();
            return;
        }
        if (msg_len < 4 || msg_len > 1024 * 1024 * 1024) { // Sanity check
            on_close();
            m_server_buffer.clear(); m_server_offset = 0;
            return;
        }
        if (m_server_buffer.size() - m_server_offset < 1 + msg_len) break;
        const unsigned char* payload = reinterpret_cast<const unsigned char*>(m_server_buffer.data()) + m_server_offset + 5;
        process_server_message(type, payload, msg_len - 4);
        m_server_offset += 1 + msg_len;
    }
    if (m_server_offset > 0) {
        if (m_server_offset >= m_server_buffer.size()) {
            m_server_buffer.clear();
            m_server_offset = 0;
        } else if (m_server_offset > 1024) {
            m_server_buffer.erase(m_server_buffer.begin(), m_server_buffer.begin() + m_server_offset);
            m_server_offset = 0;
        }
    }
}

void PgSQLFFTO::on_close() {
    if (m_state == AWAITING_RESPONSE && !m_current_query.empty() && m_query_start_time != 0) {
        unsigned long long duration = monotonic_time() - m_query_start_time;
        report_query_stats(m_current_query, duration, m_affected_rows, m_rows_sent);
    }
    clear_current_query();
    m_pending_queries.clear();
    m_state = IDLE;
}

void PgSQLFFTO::track_query(std::string query, bool finalize_on_sync) {
    if (query.empty()) return;

    PendingQuery pending { std::move(query), monotonic_time(), finalize_on_sync };
    if (m_state == IDLE || m_current_query.empty()) {
        m_current_query = std::move(pending.query);
        m_query_start_time = pending.start_time;
        m_current_finalize_on_sync = pending.finalize_on_sync;
        m_affected_rows = 0;
        m_rows_sent = 0;
        m_response_seen = false;
        m_state = AWAITING_RESPONSE;
        return;
    }

    m_pending_queries.emplace_back(std::move(pending));
}

void PgSQLFFTO::clear_current_query() {
    m_current_query.clear();
    m_query_start_time = 0;
    m_affected_rows = 0;
    m_rows_sent = 0;
    m_current_finalize_on_sync = false;
    m_response_seen = false;
}

void PgSQLFFTO::activate_next_query() {
    if (m_pending_queries.empty()) {
        clear_current_query();
        m_state = IDLE;
        return;
    }

    PendingQuery next_query = std::move(m_pending_queries.front());
    m_pending_queries.pop_front();
    m_current_query = std::move(next_query.query);
    m_query_start_time = next_query.start_time;
    m_current_finalize_on_sync = next_query.finalize_on_sync;
    m_affected_rows = 0;
    m_rows_sent = 0;
    m_response_seen = false;
    m_state = AWAITING_RESPONSE;
}

void PgSQLFFTO::finalize_current_query() {
    if (!m_current_query.empty() && m_query_start_time != 0) {
        unsigned long long duration = monotonic_time() - m_query_start_time;
        report_query_stats(m_current_query, duration, m_affected_rows, m_rows_sent);
    }
    activate_next_query();
}

void PgSQLFFTO::process_client_message(char type, const unsigned char* payload, size_t len) {
    if (type == 'Q') {
        size_t query_len = (len > 0 && payload[len - 1] == 0) ? len - 1 : len;
        track_query(std::string(reinterpret_cast<const char*>(payload), query_len), true);
    } else if (type == 'P') {
        const char* p = reinterpret_cast<const char*>(payload);
        size_t name_len = bounded_cstr_len(p, len);
        if (name_len >= len) return; // No null terminator
        std::string stmt_name(p, name_len);
        const char* query_ptr = p + name_len + 1;
        size_t rem = len - (name_len + 1);
        size_t query_text_len = bounded_cstr_len(query_ptr, rem);
        if (query_text_len >= rem) return;
        m_statements[stmt_name] = std::string(query_ptr, query_text_len);
    } else if (type == 'B') {
        const char* p = reinterpret_cast<const char*>(payload);
        size_t portal_len = bounded_cstr_len(p, len);
        if (portal_len >= len) return;
        std::string portal_name(p, portal_len);
        const char* stmt_ptr = p + portal_len + 1;
        size_t rem = len - (portal_len + 1);
        size_t stmt_name_len = bounded_cstr_len(stmt_ptr, rem);
        if (stmt_name_len >= rem) return;
        m_portals[portal_name] = std::string(stmt_ptr, stmt_name_len);
    } else if (type == 'E') {
        const char* p = reinterpret_cast<const char*>(payload);
        size_t portal_len = bounded_cstr_len(p, len);
        if (portal_len >= len) return;
        if (len < portal_len + 1 + 4) return; // portal name + '\0' + max-rows
        std::string portal_name(p, portal_len);
        auto pit = m_portals.find(portal_name);
        if (pit != m_portals.end()) {
            auto sit = m_statements.find(pit->second);
            if (sit != m_statements.end()) {
                track_query(sit->second, false);
            }
        }
    } else if (type == 'C') { // Frontend Close
        if (len < 2) return;
        char close_type = static_cast<char>(payload[0]);
        const char* name_ptr = reinterpret_cast<const char*>(payload) + 1;
        size_t name_len = bounded_cstr_len(name_ptr, len - 1);
        if (name_len >= len - 1) return;
        std::string name(name_ptr, name_len);
        if (close_type == 'S') m_statements.erase(name);
        else if (close_type == 'P') m_portals.erase(name);
    } else if (type == 'X') {
        on_close();
    }
}

void PgSQLFFTO::process_server_message(char type, const unsigned char* payload, size_t len) {
    if (m_state == IDLE) return;
    if (type == 'C') {
        bool is_select = false;
        uint64_t rows = extract_pg_rows_affected(payload, len, is_select);
        if (is_select) m_rows_sent += rows;
        else m_affected_rows += rows;
        m_response_seen = true;
        if (!m_current_finalize_on_sync) {
            finalize_current_query();
        }
    } else if (type == 'I' || type == 's') {
        // EmptyQueryResponse ('I') replaces CommandComplete when the query text
        // is empty once comments/whitespace are stripped, and PortalSuspended
        // ('s') replaces it when a row-limited Execute stops early. Both
        // terminate the current query's response just as CommandComplete does,
        // with no row counts to add. Without this, an extended Execute answered
        // by either one would never be finalized -- neither branch below fires
        // for it -- and the stalled query would block the pending queue and
        // swallow the NEXT query's CommandComplete.
        //
        // ProxySQL does not emit PortalSuspended today (Execute's max-rows
        // field is parsed but never acted on, issue #5900), so 's' is inert
        // until that is fixed; handling it now costs two lines and avoids
        // reintroducing the stall when it is.
        m_response_seen = true;
        if (!m_current_finalize_on_sync) {
            finalize_current_query();
        }
    } else if (type == 'Z') {
        // ReadyForQuery terminates an exchange, and is the finalizer for SIMPLE
        // queries -- their CommandComplete deliberately does not finalize (see
        // the m_current_finalize_on_sync check above).
        //
        // The qualifying condition is m_response_seen, NOT
        // m_current_finalize_on_sync. A ReadyForQuery belongs to the exchange
        // that produced it, but the query that happens to be current when it
        // arrives may already belong to the NEXT one: a client that pipelines
        // without reading its replies leaves an earlier exchange's
        // ReadyForQuery in flight, and an extended CommandComplete can activate
        // the following queued query before it lands. Finalizing then reports
        // that query with zeroed counters and pops the queue, so its real
        // response is attributed to whatever comes after and the last response
        // in the batch is dropped once the queue drains to IDLE -- silent,
        // plausible-looking corruption of stats_pgsql_query_digest rather than
        // an obvious failure.
        //
        // Gating on "has this query actually seen its own response terminator"
        // is correct for every ordering: a simple query that got its
        // CommandComplete finalizes here as before; an extended Execute has
        // already finalized itself above and cannot still be current; and a
        // query still awaiting its first response is left alone for the
        // CommandComplete that is genuinely its own. An abandoned batch is
        // still cleared by ErrorResponse ('E' below).
        if (m_response_seen) {
            finalize_current_query();
        }
    } else if (type == 'E') {
        if (!m_current_query.empty() && m_query_start_time != 0) {
            unsigned long long duration = monotonic_time() - m_query_start_time;
            report_query_stats(m_current_query, duration, m_affected_rows, m_rows_sent);
        }
        report_error(payload, len);
        clear_current_query();
        m_pending_queries.clear();
        m_state = IDLE;
    }
}

void PgSQLFFTO::report_query_stats(const std::string& query, unsigned long long duration_us, uint64_t affected_rows, uint64_t rows_sent) {
    if (query.empty() || !GloPgQPro || !m_session) return;
    if (!m_session->client_myds || !m_session->client_myds->myconn || !m_session->client_myds->myconn->userinfo) return;
    auto* ui = m_session->client_myds->myconn->userinfo;
    if (!ui->username) return;
    char empty_schema[] = "";
    char* schemaname = ui->schemaname ? ui->schemaname : empty_schema;

    options opts;
    opts.lowercase = pgsql_thread___query_digests_lowercase;
    opts.replace_null = pgsql_thread___query_digests_replace_null;
    opts.replace_number = pgsql_thread___query_digests_no_digits;
    opts.keep_comment = pgsql_thread___query_digests_keep_comment;
    opts.grouping_limit = pgsql_thread___query_digests_grouping_limit;
    opts.groups_grouping_limit = pgsql_thread___query_digests_groups_grouping_limit;
    opts.max_query_length = pgsql_thread___query_digests_max_query_length;

    SQP_par_t qp; memset(&qp, 0, sizeof(qp));
    char* fst_cmnt = NULL;
    char* digest_text = pgsql_query_digest_and_first_comment(query.c_str(), query.length(), &fst_cmnt,
        ((query.length() < QUERY_DIGEST_BUF) ? qp.buf : NULL), &opts);
    if (digest_text) {
        qp.digest_text = digest_text;
		const int digest_len = static_cast<int>(strnlen(digest_text, pgsql_thread___query_digests_max_digest_length));
        qp.digest = SpookyHash::Hash64(digest_text, digest_len, 0);
        char* ca = (char*)"";
        if (pgsql_thread___query_digests_track_hostname && m_session->client_myds->addr.addr) ca = m_session->client_myds->addr.addr;
        uint64_t hash2; SpookyHash myhash; myhash.Init(19, 3);
        const std::string_view username_view = ui->username ? std::string_view{ui->username} : std::string_view{};
        const size_t username_len = username_view.size();
        myhash.Update(username_view.data(), username_len);
        myhash.Update(&qp.digest, sizeof(qp.digest));
        const std::string_view schemaname_view = schemaname ? std::string_view{schemaname} : std::string_view{};
        const size_t schemaname_len = schemaname_view.size();
        myhash.Update(schemaname_view.data(), schemaname_len);
        myhash.Update(&m_session->current_hostgroup, sizeof(m_session->current_hostgroup));
        const std::string_view ca_view = ca ? std::string_view{ca} : std::string_view{};
        const size_t ca_len = ca_view.size();
        myhash.Update(ca_view.data(), ca_len);
        myhash.Final(&qp.digest_total, &hash2);
        GloPgQPro->update_query_digest(qp.digest_total, qp.digest, qp.digest_text, m_session->current_hostgroup, ui, duration_us, m_session->thread->curtime, ca, affected_rows, rows_sent);
        if (digest_text != qp.buf) free(digest_text);
    }
    if (fst_cmnt) free(fst_cmnt);
}

void PgSQLFFTO::report_error(const unsigned char* payload, size_t len) {
    if (!m_session || !PgHGM) return;
    if (!m_session->client_myds || !m_session->client_myds->myconn ||
        !m_session->client_myds->myconn->userinfo) return;

    PgSQLErrorResult err = pgsql_parse_error_response(payload, len);
    if (!err.parsed) return;

    auto* ui = m_session->client_myds->myconn->userinfo;
    if (!ui->username) return;
    /* database/schemaname may be unset early in the session; still record */
    char* schemaname = ui->schemaname ? ui->schemaname : (char*)"";

    // Build a null-terminated copy of the error message
    std::string msg(err.message ? err.message : "", err.message_len);

    // Get backend server info if available
    const char* hostname = "";
    int port = 0;
    int hostgroup = m_session->current_hostgroup;
    if (m_session->mybe && m_session->mybe->server_myds &&
        m_session->mybe->server_myds->myconn &&
        m_session->mybe->server_myds->myconn->parent) {
        auto* parent = m_session->mybe->server_myds->myconn->parent;
        hostname = parent->address ? parent->address : "";
        port = parent->port;
        hostgroup = parent->myhgc->hid;
    }

    const char* client_addr = "unknown";
    if (m_session->client_myds->addr.addr) {
        client_addr = m_session->client_myds->addr.addr;
    }

    // ui->schemaname and ui->dbname are the same field (union in PgSQL_Connection_userinfo)
    PgHGM->add_pgsql_errors(
        hostgroup, hostname, port,
        ui->username, client_addr, schemaname,
        err.sqlstate, msg.c_str()
    );
}

std::size_t PgSQLFFTO::get_buffered_size() const {
	return m_client_buffer.size() + m_server_buffer.size();
}
