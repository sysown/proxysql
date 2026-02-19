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
    std::string command_tag(reinterpret_cast<const char*>(payload), len);
    is_select = false;
    std::regex re("(INSERT|UPDATE|DELETE|SELECT|MOVE|FETCH)\\s+\\S*\\s*(\\d+)");
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
    : m_session(session), m_state(IDLE), m_query_start_time(0) {
    m_client_buffer.reserve(1024);
    m_server_buffer.reserve(4096);
}

PgSQLFFTO::~PgSQLFFTO() {
    on_close();
}

void PgSQLFFTO::on_client_data(const char* buf, size_t len) {
    if (!buf || len == 0) return;
    m_client_buffer.insert(m_client_buffer.end(), buf, buf + len);
    while (m_client_buffer.size() >= 5) {
        char type = m_client_buffer[0];
        uint32_t msg_len; memcpy(&msg_len, &m_client_buffer[1], 4); msg_len = ntohl(msg_len);
        if (m_client_buffer.size() < 1 + msg_len) break;
        const unsigned char* payload = reinterpret_cast<const unsigned char*>(m_client_buffer.data()) + 5;
        process_client_message(type, payload, msg_len - 4);
        m_client_buffer.erase(m_client_buffer.begin(), m_client_buffer.begin() + 1 + msg_len);
    }
}

void PgSQLFFTO::on_server_data(const char* buf, size_t len) {
    if (!buf || len == 0) return;
    m_server_buffer.insert(m_server_buffer.end(), buf, buf + len);
    while (m_server_buffer.size() >= 5) {
        char type = m_server_buffer[0];
        uint32_t msg_len; memcpy(&msg_len, &m_server_buffer[1], 4); msg_len = ntohl(msg_len);
        if (m_server_buffer.size() < 1 + msg_len) break;
        const unsigned char* payload = reinterpret_cast<const unsigned char*>(m_server_buffer.data()) + 5;
        process_server_message(type, payload, msg_len - 4);
        m_server_buffer.erase(m_server_buffer.begin(), m_server_buffer.begin() + 1 + msg_len);
    }
}

void PgSQLFFTO::on_close() {
    if (m_state != IDLE && m_query_start_time != 0) {
        unsigned long long duration = monotonic_time() - m_query_start_time;
        report_query_stats(m_current_query, duration);
        m_state = IDLE;
    }
}

void PgSQLFFTO::process_client_message(char type, const unsigned char* payload, size_t len) {
    if (type == 'Q') {
        m_current_query = std::string(reinterpret_cast<const char*>(payload), len);
        m_query_start_time = monotonic_time();
        m_state = AWAITING_RESPONSE;
    } else if (type == 'P') {
        std::string stmt_name = reinterpret_cast<const char*>(payload);
        const char* query = reinterpret_cast<const char*>(payload) + stmt_name.length() + 1;
        m_statements[stmt_name] = query;
    } else if (type == 'B') {
        std::string portal_name = reinterpret_cast<const char*>(payload);
        const char* stmt_ptr = reinterpret_cast<const char*>(payload) + portal_name.length() + 1;
        std::string stmt_name = stmt_ptr;
        m_portals[portal_name] = stmt_name;
    } else if (type == 'E') {
        std::string portal_name = reinterpret_cast<const char*>(payload);
        auto pit = m_portals.find(portal_name);
        if (pit != m_portals.end()) {
            auto sit = m_statements.find(pit->second);
            if (sit != m_statements.end()) {
                m_current_query = sit->second;
                m_query_start_time = monotonic_time();
                m_state = AWAITING_RESPONSE;
            }
        }
    } else if (type == 'X') {
        on_close();
    }
}

void PgSQLFFTO::process_server_message(char type, const unsigned char* payload, size_t len) {
    if (m_state == IDLE) return;
    if (type == 'C') {
        unsigned long long duration = monotonic_time() - m_query_start_time;
        bool is_select = false;
        uint64_t rows = extract_pg_rows_affected(payload, len, is_select);
        if (is_select) report_query_stats(m_current_query, duration, 0, rows);
        else report_query_stats(m_current_query, duration, rows, 0);
        m_state = IDLE;
    } else if (type == 'Z' || type == 'E') {
        // ReadyForQuery or ErrorResponse. We don't always want to report stats here if 'C' already did it.
        // But if we didn't get 'C', report what we have.
        if (m_state == AWAITING_RESPONSE) {
            unsigned long long duration = monotonic_time() - m_query_start_time;
            report_query_stats(m_current_query, duration);
        }
        m_state = IDLE;
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
