#include "proxysql.h"
#include "MySQL_HostGroups_Manager.h"
#include "MySQL_Thread.h"
#include "MySQL_Session.h"
#include "MySQL_Data_Stream.h"
#include "MySQL_Query_Processor.h"
#include "MySQL_Protocol.h"
#include "MySQL_Variables.h"
#include "MySQLFFTO.hpp"
#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif
#include "c_tokenizer.h"
#include <iostream>
#include <cstring>

extern MySQL_Query_Processor* GloMyQPro;

MySQLFFTO::MySQLFFTO(MySQL_Session* session) 
    : m_session(session), m_state(IDLE), m_query_start_time(0) {
    m_client_buffer.reserve(1024);
    m_server_buffer.reserve(4096);
}

MySQLFFTO::~MySQLFFTO() {
    on_close();
}

void MySQLFFTO::on_client_data(const char* buf, size_t len) {
    if (!buf || len == 0) return;

    m_client_buffer.insert(m_client_buffer.end(), buf, buf + len);

    while (m_client_buffer.size() >= sizeof(mysql_hdr)) {
        const mysql_hdr* hdr = reinterpret_cast<const mysql_hdr*>(m_client_buffer.data());
        uint32_t pkt_len = hdr->pkt_length;
        
        if (m_client_buffer.size() < sizeof(mysql_hdr) + pkt_len) {
            break; 
        }

        const unsigned char* payload = reinterpret_cast<const unsigned char*>(m_client_buffer.data()) + sizeof(mysql_hdr);
        process_client_packet(payload, pkt_len);

        m_client_buffer.erase(m_client_buffer.begin(), m_client_buffer.begin() + sizeof(mysql_hdr) + pkt_len);
    }
}

void MySQLFFTO::on_server_data(const char* buf, size_t len) {
    if (!buf || len == 0) return;

    m_server_buffer.insert(m_server_buffer.end(), buf, buf + len);

    while (m_server_buffer.size() >= sizeof(mysql_hdr)) {
        const mysql_hdr* hdr = reinterpret_cast<const mysql_hdr*>(m_server_buffer.data());
        uint32_t pkt_len = hdr->pkt_length;
        
        if (m_server_buffer.size() < sizeof(mysql_hdr) + pkt_len) {
            break; 
        }

        const unsigned char* payload = reinterpret_cast<const unsigned char*>(m_server_buffer.data()) + sizeof(mysql_hdr);
        process_server_packet(payload, pkt_len);

        m_server_buffer.erase(m_server_buffer.begin(), m_server_buffer.begin() + sizeof(mysql_hdr) + pkt_len);
    }
}

void MySQLFFTO::on_close() {
    if (m_state != IDLE && m_query_start_time != 0) {
        unsigned long long duration = monotonic_time() - m_query_start_time;
        report_query_stats(m_current_query, duration);
        m_state = IDLE;
    }
}

void MySQLFFTO::process_client_packet(const unsigned char* data, size_t len) {
    if (len == 0) return;

    uint8_t command = data[0];
    if (command == _MYSQL_COM_QUERY || command == _MYSQL_COM_STMT_EXECUTE || command == _MYSQL_COM_STMT_PREPARE) {
        if (len > 1) {
            m_current_query = std::string(reinterpret_cast<const char*>(data + 1), len - 1);
            m_query_start_time = monotonic_time();
            m_state = AWAITING_RESULTSET;
        }
    } else if (command == _MYSQL_COM_QUIT) {
        on_close();
    }
}

void MySQLFFTO::process_server_packet(const unsigned char* data, size_t len) {
    if (len == 0 || m_state == IDLE) return;

    uint8_t first_byte = data[0];
    
    if (m_state == AWAITING_RESULTSET || m_state == READING_RESULTSET) {
        if (first_byte == 0x00 || first_byte == 0xFF) {
            unsigned long long duration = monotonic_time() - m_query_start_time;
            report_query_stats(m_current_query, duration);
            m_state = IDLE;
        } else if (first_byte == 0xFE && len < 9) { 
            unsigned long long duration = monotonic_time() - m_query_start_time;
            report_query_stats(m_current_query, duration);
            m_state = IDLE;
        } else {
            m_state = READING_RESULTSET;
        }
    }
}

void MySQLFFTO::report_query_stats(const std::string& query, unsigned long long duration_us) {
    if (query.empty() || !GloMyQPro) return;

    options opts;
    opts.lowercase = mysql_thread___query_digests_lowercase;
    opts.replace_null = mysql_thread___query_digests_replace_null;
    opts.replace_number = !mysql_thread___query_digests_no_digits;
    opts.keep_comment = mysql_thread___query_digests_keep_comment;
    opts.grouping_limit = mysql_thread___query_digests_grouping_limit;
    opts.groups_grouping_limit = mysql_thread___query_digests_groups_grouping_limit;
    opts.max_query_length = mysql_thread___query_digests_max_query_length;

    SQP_par_t qp;
    memset(&qp, 0, sizeof(qp));
    char* fst_cmnt = NULL;
    
    char* digest_text = mysql_query_digest_and_first_comment(query.c_str(), query.length(), &fst_cmnt, qp.buf, &opts);
    if (digest_text) {
        qp.digest_text = digest_text;
        qp.digest = SpookyHash::Hash64(digest_text, strlen(digest_text), 0);
        
        char* ca = (char*)"";
        if (mysql_thread___query_digests_track_hostname) {
            if (m_session->client_myds && m_session->client_myds->addr.addr) {
                ca = m_session->client_myds->addr.addr;
            }
        }

        uint64_t hash2;
        SpookyHash myhash;
        myhash.Init(19, 3);
        auto* ui = m_session->client_myds->myconn->userinfo;
        myhash.Update(ui->username, strlen(ui->username));
        myhash.Update(&qp.digest, sizeof(qp.digest));
        myhash.Update(ui->schemaname, strlen(ui->schemaname));
        myhash.Update(&m_session->current_hostgroup, sizeof(m_session->current_hostgroup));
        myhash.Update(ca, strlen(ca));
        myhash.Final(&qp.digest_total, &hash2);

        GloMyQPro->update_query_digest(qp.digest_total, qp.digest, qp.digest_text, m_session->current_hostgroup, ui, duration_us, m_session->thread->curtime, ca, 0, 0);
        
        free(digest_text);
    }
    if (fst_cmnt) free(fst_cmnt);
}
