#include "proxysql.h"
#include "MySQL_HostGroups_Manager.h"
#include "MySQL_Thread.h"
#include "MySQL_Session.h"
#include "MySQL_Data_Stream.h"
#include "MySQL_Query_Processor.h"
#include "MySQL_Protocol.h"
#include "MySQL_Variables.h"
#include "MySQLFFTO.hpp"
#include "MySQLProtocolUtils.h"
#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif
#include "c_tokenizer.h"
#include <iostream>
#include <cstring>
#include <algorithm>
#include <string_view>

extern class MySQL_Query_Processor* GloMyQPro;
extern MySQL_HostGroups_Manager* MyHGM;

MySQLFFTO::MySQLFFTO(MySQL_Session* session)
    : m_session(session), m_state(IDLE), m_query_start_time(0), m_affected_rows(0), m_rows_sent(0) {
    m_client_buffer.reserve(1024);
    m_server_buffer.reserve(4096);
}

MySQLFFTO::~MySQLFFTO() {
    on_close();
}

void MySQLFFTO::on_client_data(const char* buf, std::size_t len) {
    if (!buf || len == 0) return;
    m_client_buffer.insert(m_client_buffer.end(), buf, buf + len);
	while (m_client_buffer.size() - m_client_offset >= sizeof(mysql_hdr)) {
		const mysql_hdr* hdr = reinterpret_cast<const mysql_hdr*>(m_client_buffer.data() + m_client_offset);
		uint32_t pkt_len = hdr->pkt_length;
		if (pkt_len > (uint32_t)mysql_thread___ffto_max_buffer_size) {
			m_session->ffto_bypassed = true;
			on_close();
			return;
		}
		if (m_client_buffer.size() - m_client_offset < sizeof(mysql_hdr) + pkt_len) break;
		const unsigned char* payload = reinterpret_cast<const unsigned char*>(m_client_buffer.data()) + m_client_offset + sizeof(mysql_hdr);
		process_client_packet(payload, pkt_len);
		m_client_offset += sizeof(mysql_hdr) + pkt_len;
    }
    if (m_client_offset > 0) {
        if (m_client_offset >= m_client_buffer.size()) {
            m_client_buffer.clear();
            m_client_offset = 0;
        } else if (m_client_offset > 1024) { // Compact if offset is significant
            m_client_buffer.erase(m_client_buffer.begin(), m_client_buffer.begin() + m_client_offset);
            m_client_offset = 0;
        }
    }
}

void MySQLFFTO::on_server_data(const char* buf, std::size_t len) {
    if (!buf || len == 0) return;
    m_server_buffer.insert(m_server_buffer.end(), buf, buf + len);
    while (m_server_buffer.size() - m_server_offset >= sizeof(mysql_hdr)) {
        const mysql_hdr* hdr = reinterpret_cast<const mysql_hdr*>(m_server_buffer.data() + m_server_offset);
        uint32_t pkt_len = hdr->pkt_length;
        if (pkt_len > (uint32_t)mysql_thread___ffto_max_buffer_size) {
            if (m_session) m_session->ffto_bypassed = true;
            on_close();
            return;
        }
        if (m_server_buffer.size() - m_server_offset < sizeof(mysql_hdr) + pkt_len) break;
        const unsigned char* payload = reinterpret_cast<const unsigned char*>(m_server_buffer.data()) + m_server_offset + sizeof(mysql_hdr);
        process_server_packet(payload, pkt_len);
        m_server_offset += sizeof(mysql_hdr) + pkt_len;
    }
    if (m_server_offset > 0) {
        if (m_server_offset >= m_server_buffer.size()) {
            m_server_buffer.clear();
            m_server_offset = 0;
        } else if (m_server_offset > 1024) { // Compact if offset is significant
            m_server_buffer.erase(m_server_buffer.begin(), m_server_buffer.begin() + m_server_offset);
            m_server_offset = 0;
        }
    }
}

void MySQLFFTO::on_close() {
    if (is_in_flight_query_state() && m_query_start_time != 0) {
        unsigned long long duration = monotonic_time() - m_query_start_time;
        report_query_stats(m_current_query, duration, m_affected_rows, m_rows_sent);
    }
    m_state = IDLE;
    clear_active_query();
    m_pending_prepare_query.clear();
}

bool MySQLFFTO::is_in_flight_query_state() const {
    return m_state == AWAITING_RESPONSE || m_rs.active();
}

void MySQLFFTO::clear_active_query() {
    m_current_query.clear();
    m_query_start_time = 0;
    m_affected_rows = 0;
    m_rows_sent = 0;
    m_rs.reset();
}

bool MySQLFFTO::client_deprecate_eof() const {
    if (m_session && m_session->client_myds && m_session->client_myds->myconn)
        return (m_session->client_myds->myconn->options.client_flag & CLIENT_DEPRECATE_EOF);
    return false;
}

void MySQLFFTO::finalize_in_flight_best_effort() {
    if (m_state == AWAITING_RESPONSE && m_query_start_time != 0) {
        unsigned long long duration = monotonic_time() - m_query_start_time;
        report_query_stats(m_current_query, duration, m_affected_rows, m_rows_sent);
    }
    m_state = IDLE;
    clear_active_query();
}

void MySQLFFTO::begin_tracked_query(const std::string& query, bool binary_protocol) {
    if (m_state == AWAITING_RESPONSE || m_rs.active()) {
        finalize_in_flight_best_effort();
    }
    m_current_query = query;
    m_query_start_time = monotonic_time();
    m_affected_rows = 0;
    m_rows_sent = 0;
    m_state = AWAITING_RESPONSE;
    m_rs.begin(binary_protocol, client_deprecate_eof());
}

void MySQLFFTO::process_client_packet(const unsigned char* data, size_t len) {
    if (len == 0) return;
    uint8_t command = data[0];
    if (command == _MYSQL_COM_QUERY) {
        begin_tracked_query(std::string(reinterpret_cast<const char*>(data + 1), len - 1), false);
    } else if (command == _MYSQL_COM_STMT_PREPARE) {
        if (m_state == AWAITING_RESPONSE || m_rs.active()) {
            finalize_in_flight_best_effort();
        }
        m_rs.reset();
        m_pending_prepare_query = std::string(reinterpret_cast<const char*>(data + 1), len - 1);
        m_state = AWAITING_PREPARE_OK;
    } else if (command == _MYSQL_COM_STMT_EXECUTE) {
        if (len >= 5) {
            uint32_t stmt_id; memcpy(&stmt_id, data + 1, 4);
            auto it = m_statements.find(stmt_id);
            if (it != m_statements.end()) {
                begin_tracked_query(it->second, true);
            }
        }
    } else if (command == _MYSQL_COM_STMT_FETCH) {
        if (len >= 5) {
            uint32_t stmt_id; memcpy(&stmt_id, data + 1, 4);
            auto it = m_statements.find(stmt_id);
            if (it != m_statements.end()) {
                begin_tracked_query(it->second, true);
            }
        }
    } else if (command == _MYSQL_COM_STMT_CLOSE) {
        if (len >= 5) {
            uint32_t stmt_id; memcpy(&stmt_id, data + 1, 4);
            m_statements.erase(stmt_id);
        }
    } else if (command == _MYSQL_COM_QUIT) {
        on_close();
    }
}

void MySQLFFTO::process_server_packet(const unsigned char* data, size_t len) {
    if (len == 0 || m_state == IDLE) return;

    if (m_state == AWAITING_PREPARE_OK) {
        uint8_t first_byte = data[0];
        if (first_byte == 0x00 && len >= 9) {
            uint32_t stmt_id; memcpy(&stmt_id, data + 1, 4);
            m_statements[stmt_id] = m_pending_prepare_query;
            m_state = IDLE;
            m_pending_prepare_query.clear();
        } else if (first_byte == 0xFF) {
            report_error(data, len);
            m_state = IDLE;
            m_pending_prepare_query.clear();
        }
        return;
    }

    // AWAITING_RESPONSE or framer active
    if (m_state != AWAITING_RESPONSE && !m_rs.active()) return;

    MySQLRSEvent ev = m_rs.on_payload(data, len);

    switch (ev.kind) {
    case MySQLRSEventKind::None:
    case MySQLRSEventKind::Row:
        // Accumulate only on Complete/OK/Error via rows_sent_total
        break;
    case MySQLRSEventKind::OKNoResultset:
        m_affected_rows += ev.affected_rows;
        if (!ev.more_results) {
            unsigned long long duration = monotonic_time() - m_query_start_time;
            report_query_stats(m_current_query, duration, m_affected_rows, m_rows_sent);
            m_state = IDLE;
            clear_active_query();
        }
        break;
    case MySQLRSEventKind::ResultsetComplete:
        m_rows_sent += ev.rows_sent_total;
        if (ev.affected_rows) m_affected_rows += ev.affected_rows;
        if (!ev.more_results) {
            unsigned long long duration = monotonic_time() - m_query_start_time;
            report_query_stats(m_current_query, duration, m_affected_rows, m_rows_sent);
            m_state = IDLE;
            clear_active_query();
        }
        break;
    case MySQLRSEventKind::Error:
        {
            unsigned long long duration = monotonic_time() - m_query_start_time;
            m_rows_sent += ev.rows_sent_total;
            report_query_stats(m_current_query, duration, m_affected_rows, m_rows_sent);
            report_error(data, len);
            m_state = IDLE;
            clear_active_query();
        }
        break;
    }
}

void MySQLFFTO::report_query_stats(const std::string& query, unsigned long long duration_us, uint64_t affected_rows, uint64_t rows_sent) {
    if (query.empty() || !GloMyQPro || !m_session) return;
    if (!m_session->client_myds || !m_session->client_myds->myconn || !m_session->client_myds->myconn->userinfo) return;
    auto* ui = m_session->client_myds->myconn->userinfo;
    if (!ui->username) return;
    char empty_schema[] = "";
    char* schemaname = ui->schemaname ? ui->schemaname : empty_schema;

	options opts;
	opts.lowercase = mysql_thread___query_digests_lowercase;
	opts.replace_null = mysql_thread___query_digests_replace_null;
	opts.replace_number = mysql_thread___query_digests_no_digits;
	opts.keep_comment = mysql_thread___query_digests_keep_comment;
	opts.grouping_limit = mysql_thread___query_digests_grouping_limit;
	opts.groups_grouping_limit = mysql_thread___query_digests_groups_grouping_limit;
	opts.max_query_length = mysql_thread___query_digests_max_query_length;

    SQP_par_t qp; memset(&qp, 0, sizeof(qp));
    char* fst_cmnt = NULL;
	char* digest_text = mysql_query_digest_and_first_comment(query.c_str(), query.length(), &fst_cmnt,
		((query.length() < QUERY_DIGEST_BUF) ? qp.buf : NULL), &opts);
	if (digest_text) {
		qp.digest_text = digest_text;
		const int digest_len = static_cast<int>(strnlen(digest_text, mysql_thread___query_digests_max_digest_length));
		qp.digest = SpookyHash::Hash64(digest_text, digest_len, 0);
	    char* ca = (char*)"";
        if (mysql_thread___query_digests_track_hostname && m_session->client_myds->addr.addr) ca = m_session->client_myds->addr.addr;
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
        GloMyQPro->update_query_digest(qp.digest_total, qp.digest, qp.digest_text, m_session->current_hostgroup, ui, duration_us, m_session->thread->curtime, ca, affected_rows, rows_sent);
        if (digest_text != qp.buf) free(digest_text);
    }
    if (fst_cmnt) free(fst_cmnt);
}

void MySQLFFTO::report_error(const unsigned char* data, size_t len) {
    if (!m_session || !MyHGM) return;
    if (!m_session->client_myds || !m_session->client_myds->myconn ||
        !m_session->client_myds->myconn->userinfo) return;

    uint16_t err_no = 0;
    const char* errmsg = nullptr;
    size_t errmsg_len = 0;
    if (!mysql_parse_err_packet(data, len, &err_no, &errmsg, &errmsg_len)) return;

    auto* ui = m_session->client_myds->myconn->userinfo;
    if (!ui->username) return;
    /* schemaname may be unset before COM_INIT_DB; still record the error */
    char* schemaname = ui->schemaname ? ui->schemaname : (char*)"";

    // Build a null-terminated copy of the error message
    std::string msg(errmsg ? errmsg : "", errmsg_len);

    // Get backend server info if available
    char* hostname = (char*)"";
    int port = 0;
    int hostgroup = m_session->current_hostgroup;
    if (m_session->mybe && m_session->mybe->server_myds &&
        m_session->mybe->server_myds->myconn &&
        m_session->mybe->server_myds->myconn->parent) {
        auto* parent = m_session->mybe->server_myds->myconn->parent;
        hostname = parent->address;
        port = parent->port;
        hostgroup = parent->myhgc->hid;
    }

    char* client_addr = (char*)"unknown";
    if (m_session->client_myds->addr.addr) {
        client_addr = m_session->client_myds->addr.addr;
    }

    MyHGM->add_mysql_errors(
        hostgroup, hostname, port,
        ui->username, client_addr, schemaname,
        err_no, (char*)msg.c_str()
    );
}

std::size_t MySQLFFTO::get_buffered_size() const {
	return m_client_buffer.size() + m_server_buffer.size();
}
