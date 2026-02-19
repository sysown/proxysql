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
#include <arpa/inet.h>
#include <cstring>
#include <regex>

extern class PgSQL_Query_Processor* GloPgQPro;

/**
 * @brief Parses the PostgreSQL CommandComplete ('C') message payload to extract row counts.
 * 
 * PostgreSQL encodes row counts into the message tag string (e.g., "INSERT 0 10", "SELECT 50").
 * This function uses regular expressions to extract these values and determine if the message
 * corresponds to a result-generating command (SELECT, FETCH, MOVE) or a DML command.
 * 
 * @param payload Pointer to the CommandComplete message payload (the tag string).
 * @param len Length of the payload.
 * @param is_select [OUT] Boolean flag set to true if the command is a result-set operation.
 * @return The number of rows affected or sent.
 */
static uint64_t extract_pg_rows_affected(const unsigned char* payload, size_t len, bool& is_select) {
    if (len == 0) return 0;
    std::string command_tag(reinterpret_cast<const char*>(payload), len);
    is_select = false;
    static const std::regex re("(INSERT|UPDATE|DELETE|SELECT|MOVE|FETCH)\\b.*?\\b(\\d+)$");
    std::smatch matches;
    if (std::regex_search(command_tag, matches, re)) {
        if (matches.size() == 3) {
            std::string command_type = matches[1].str();
            uint64_t rows = std::stoull(matches[2].str());
            if (command_type == "SELECT" || command_type == "FETCH" || command_type == "MOVE") is_select = true;
            return rows;
        }
    }
    return 0;
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
        } else if (m_client_offset > 4096) {
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
        } else if (m_server_offset > 4096) {
            m_server_buffer.erase(m_server_buffer.begin(), m_server_buffer.begin() + m_server_offset);
            m_server_offset = 0;
        }
    }
}

void PgSQLFFTO::on_close() {
    if (m_state != IDLE && m_query_start_time != 0) {
        unsigned long long duration = monotonic_time() - m_query_start_time;
        report_query_stats(m_current_query, duration, m_affected_rows, m_rows_sent);
        m_state = IDLE;
    }
}

void PgSQLFFTO::process_client_message(char type, const unsigned char* payload, size_t len) {
    if (type == 'Q') {
        size_t query_len = (len > 0 && payload[len - 1] == 0) ? len - 1 : len;
        m_current_query = std::string(reinterpret_cast<const char*>(payload), query_len);
        m_query_start_time = monotonic_time();
        m_state = AWAITING_RESPONSE;
        m_affected_rows = 0; m_rows_sent = 0;
    } else if (type == 'P') {
        const char* p = reinterpret_cast<const char*>(payload);
        size_t name_len = strnlen(p, len);
        if (name_len >= len) return; // No null terminator
        std::string stmt_name(p, name_len);
        const char* query_ptr = p + name_len + 1;
        size_t rem = len - (name_len + 1);
        size_t query_text_len = strnlen(query_ptr, rem);
        m_statements[stmt_name] = std::string(query_ptr, query_text_len);
    } else if (type == 'B') {
        const char* p = reinterpret_cast<const char*>(payload);
        size_t portal_len = strnlen(p, len);
        if (portal_len >= len) return;
        std::string portal_name(p, portal_len);
        const char* stmt_ptr = p + portal_len + 1;
        size_t rem = len - (portal_len + 1);
        size_t stmt_name_len = strnlen(stmt_ptr, rem);
        if (stmt_name_len >= rem) return;
        m_portals[portal_name] = std::string(stmt_ptr, stmt_name_len);
    } else if (type == 'E') {
        const char* p = reinterpret_cast<const char*>(payload);
        size_t portal_len = strnlen(p, len);
        std::string portal_name(p, std::min(portal_len, len));
        auto pit = m_portals.find(portal_name);
        if (pit != m_portals.end()) {
            auto sit = m_statements.find(pit->second);
            if (sit != m_statements.end()) {
                if (m_state == AWAITING_RESPONSE) {
                    on_close(); // Finalize previous if any
                }
                m_current_query = sit->second;
                m_query_start_time = monotonic_time();
                m_state = AWAITING_RESPONSE;
                m_affected_rows = 0; m_rows_sent = 0;
            }
        }
    } else if (type == 'C') { // Frontend Close
        if (len < 1) return;
        char close_type = static_cast<char>(payload[0]);
        const char* name_ptr = reinterpret_cast<const char*>(payload) + 1;
        size_t name_len = strnlen(name_ptr, len - 1);
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
    } else if (type == 'Z' || type == 'E') {
        // ReadyForQuery or ErrorResponse
        if (m_state == AWAITING_RESPONSE) {
            unsigned long long duration = monotonic_time() - m_query_start_time;
            report_query_stats(m_current_query, duration, m_affected_rows, m_rows_sent);
        }
        m_state = IDLE;
        m_affected_rows = 0; m_rows_sent = 0;
    }
}

void PgSQLFFTO::report_query_stats(const std::string& query, unsigned long long duration_us, uint64_t affected_rows, uint64_t rows_sent) {
    if (query.empty() || !GloPgQPro || !m_session) return;
    if (!m_session->client_myds || !m_session->client_myds->myconn || !m_session->client_myds->myconn->userinfo) return;
    auto* ui = m_session->client_myds->myconn->userinfo;
    if (!ui->username || !ui->schemaname) return;

    options opts;
    opts.lowercase = pgsql_thread___query_digests_lowercase;
    opts.replace_null = pgsql_thread___query_digests_replace_null;
    opts.replace_number = !pgsql_thread___query_digests_no_digits;
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
        qp.digest = SpookyHash::Hash64(digest_text, strlen(digest_text), 0);
        char* ca = (char*)"";
        if (pgsql_thread___query_digests_track_hostname && m_session->client_myds->addr.addr) ca = m_session->client_myds->addr.addr;
        uint64_t hash2; SpookyHash myhash; myhash.Init(19, 3);
        myhash.Update(ui->username, strlen(ui->username));
        myhash.Update(&qp.digest, sizeof(qp.digest));
        myhash.Update(ui->schemaname, strlen(ui->schemaname));
        myhash.Update(&m_session->current_hostgroup, sizeof(m_session->current_hostgroup));
        myhash.Update(ca, strlen(ca));
        myhash.Final(&qp.digest_total, &hash2);
        GloPgQPro->update_query_digest(qp.digest_total, qp.digest, qp.digest_text, m_session->current_hostgroup, ui, duration_us, m_session->thread->curtime, ca, affected_rows, rows_sent);
        if (digest_text != qp.buf) free(digest_text);
    }
    if (fst_cmnt) free(fst_cmnt);
}
