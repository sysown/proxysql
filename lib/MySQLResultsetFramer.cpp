#include "MySQLResultsetFramer.h"
#include "MySQLProtocolUtils.h"
#include <cstring>

static constexpr uint16_t kServerMoreResultsExist = 8;

void MySQLResultsetFramer::reset() {
	m_state = State::Idle;
	m_binary = false;
	m_deprecate_eof = false;
	m_column_count = 0;
	m_columns_seen = 0;
	m_rows_sent = 0;
	m_saw_intermediate_eof = false;
}

bool MySQLResultsetFramer::active() const {
	return m_state != State::Idle;
}

void MySQLResultsetFramer::begin(bool binary_protocol, bool deprecate_eof) {
	reset();
	m_binary = binary_protocol;
	m_deprecate_eof = deprecate_eof;
	m_state = State::AwaitingFirst;
}

MySQLRSEvent MySQLResultsetFramer::on_first_payload(const unsigned char* p, size_t n) {
	if (m_state != State::AwaitingFirst || !p || n == 0) return {};

	if (p[0] == 0xFF) {
		uint16_t code = (n >= 3) ? (uint16_t)(p[1] | (p[2] << 8)) : 0;
		reset();
		return make_error(code);
	}

	if (p[0] == 0x00) {
		MySQLOkFields okf{};
		if (!mysql_parse_ok_payload(p, n, &okf)) {
			reset();
			return {};
		}
		const bool more = (okf.status_flags & kServerMoreResultsExist) != 0;
		MySQLRSEvent ev;
		ev.kind = MySQLRSEventKind::OKNoResultset;
		ev.affected_rows = okf.affected_rows;
		ev.status_flags = okf.status_flags;
		ev.more_results = more;
		if (more) {
			m_rows_sent = 0;
			m_columns_seen = 0;
			m_column_count = 0;
			m_saw_intermediate_eof = false;
			m_state = State::AwaitingFirst;
		} else {
			reset();
		}
		return ev;
	}

	const unsigned char* cur = p;
	size_t rem = n;
	m_column_count = mysql_read_lenenc_int(cur, rem);
	m_columns_seen = 0;
	m_rows_sent = 0;
	m_saw_intermediate_eof = false;
	m_state = State::ReadingColumns;
	return {};
}

MySQLRSEvent MySQLResultsetFramer::on_payload(const unsigned char* p, size_t n) {
	if (m_state == State::Idle) return {};
	if (m_state == State::AwaitingFirst) return on_first_payload(p, n);
	if (!p || n == 0) return {};

	if (m_state == State::ReadingColumns) {
		if (p[0] == 0xFF) {
			uint16_t code = (n >= 3) ? (uint16_t)(p[1] | (p[2] << 8)) : 0;
			reset();
			return make_error(code);
		}
		if (!m_deprecate_eof && mysql_is_eof_payload(p, n)) {
			m_saw_intermediate_eof = true;
			m_state = State::ReadingRows;
			return {};
		}
		m_columns_seen++;
		if (m_columns_seen >= m_column_count) {
			if (m_deprecate_eof) {
				m_state = State::ReadingRows;
			}
		}
		return {};
	}

	if (m_state == State::ReadingRows) {
		if (p[0] == 0xFF) {
			uint16_t code = (n >= 3) ? (uint16_t)(p[1] | (p[2] << 8)) : 0;
			MySQLRSEvent ev = make_error(code);
			ev.rows_sent_total = m_rows_sent;
			reset();
			return ev;
		}
		if (!m_deprecate_eof && mysql_is_eof_payload(p, n)) {
			uint16_t st = 0, wr = 0;
			mysql_parse_eof_payload(p, n, &wr, &st);
			return make_complete(st, 0);
		}
		if (m_deprecate_eof && looks_like_ok_terminator(p, n)) {
			MySQLOkFields okf{};
			mysql_parse_ok_payload(p, n, &okf);
			return make_complete(okf.status_flags, okf.affected_rows);
		}
		m_rows_sent++;
		MySQLRSEvent ev;
		ev.kind = MySQLRSEventKind::Row;
		ev.rows_sent_total = m_rows_sent;
		return ev;
	}

	return {};
}

MySQLRSEvent MySQLResultsetFramer::make_complete(uint16_t status, uint64_t affected) {
	MySQLRSEvent ev;
	ev.kind = MySQLRSEventKind::ResultsetComplete;
	ev.rows_sent_total = m_rows_sent;
	ev.affected_rows = affected;
	ev.status_flags = status;
	ev.more_results = (status & kServerMoreResultsExist) != 0;
	if (ev.more_results) {
		m_rows_sent = 0;
		m_columns_seen = 0;
		m_column_count = 0;
		m_saw_intermediate_eof = false;
		m_state = State::AwaitingFirst;
	} else {
		reset();
	}
	return ev;
}

MySQLRSEvent MySQLResultsetFramer::make_error(uint16_t code) {
	MySQLRSEvent ev;
	ev.kind = MySQLRSEventKind::Error;
	ev.error_code = code;
	return ev;
}

bool MySQLResultsetFramer::looks_like_ok_terminator(const unsigned char* p, size_t n) const {
	MySQLOkFields okf{};
	if (!mysql_parse_ok_payload(p, n, &okf)) return false;
	// Text protocol: successful OK parse is sufficient.
	// Binary row vs OK disambiguation is refined in a later task.
	(void)okf;
	return true;
}
