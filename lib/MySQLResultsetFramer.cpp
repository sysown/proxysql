#include "MySQLResultsetFramer.h"
#include "MySQLProtocolUtils.h"
#include <cstring>

static constexpr uint16_t kServerMoreResultsExist = 8;
static constexpr uint16_t kServerSessionStateChanged = 0x4000;
static constexpr uint16_t kServerCursorExists = 0x40;
static constexpr uint16_t kServerLastRowSent = 0x80;

// True when payload is exactly m_column_count text-protocol fields (length-encoded
// strings / 0xFB NULL), with nothing left over.
static bool text_row_consumes_payload(const unsigned char* p, size_t n, uint64_t column_count) {
	if (!p || column_count == 0) return false;
	const unsigned char* cur = p;
	size_t rem = n;
	for (uint64_t i = 0; i < column_count; i++) {
		if (rem == 0) return false;
		if (cur[0] == 0xFB) { // NULL
			cur++;
			rem--;
			continue;
		}
		const uint8_t fb = cur[0];
		if (fb == 0xFF) return false;
		if (fb == 0xFC && rem < 3) return false;
		if (fb == 0xFD && rem < 4) return false;
		if (fb == 0xFE && rem < 9) return false;
		const uint64_t flen = mysql_read_lenenc_int(cur, rem);
		if (flen > rem) return false;
		cur += flen;
		rem -= flen;
	}
	return rem == 0;
}

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

void MySQLResultsetFramer::begin_rows(bool binary_protocol, bool deprecate_eof, uint64_t column_count) {
	reset();
	m_binary = binary_protocol;
	m_deprecate_eof = deprecate_eof;
	m_column_count = column_count;
	m_columns_seen = column_count;
	m_state = State::ReadingRows;
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

	if (m_state == State::ReadingColumns) return on_column_payload(p, n);
	if (m_state == State::ReadingRows) return on_row_payload(p, n);
	return {};
}

MySQLRSEvent MySQLResultsetFramer::on_column_payload(const unsigned char* p, size_t n) {
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

MySQLRSEvent MySQLResultsetFramer::on_row_payload(const unsigned char* p, size_t n) {
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
		if (cursor_intermediate(st)) {
			m_saw_intermediate_eof = true;
			return {};
		}
		return make_complete(st, 0);
	}
	if (m_deprecate_eof && looks_like_ok_terminator(p, n)) {
		MySQLOkFields okf{};
		mysql_parse_ok_payload(p, n, &okf);
		if (cursor_intermediate(okf.status_flags)) {
			m_saw_intermediate_eof = true;
			return {};
		}
		return make_complete(okf.status_flags, okf.affected_rows);
	}
	m_rows_sent++;
	MySQLRSEvent ev;
	ev.kind = MySQLRSEventKind::Row;
	ev.rows_sent_total = m_rows_sent;
	return ev;
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

bool MySQLResultsetFramer::cursor_intermediate(uint16_t status) const {
	// COM_STMT_FETCH batches: an EOF/OK carrying SERVER_STATUS_CURSOR_EXISTS
	// without SERVER_STATUS_LAST_ROW_SENT means more rows are still pending via
	// subsequent FETCH commands. Stay in ReadingRows; do not complete.
	return (status & kServerCursorExists) != 0 && (status & kServerLastRowSent) == 0;
}

bool MySQLResultsetFramer::looks_like_ok_terminator(const unsigned char* p, size_t n) const {
	if (!p || n < 1 || p[0] != 0x00) return false;
	MySQLOkFields okf{};
	if (!mysql_parse_ok_payload(p, n, &okf)) return false;

	if (!m_binary) {
		// Text row may start with 0x00 (empty first column). If the payload is
		// exactly column_count length-encoded fields, it is a row, not OK.
		if (text_row_consumes_payload(p, n, m_column_count)) return false;
		return true;
	}

	// Binary: 0x00 + null_bitmap[(cols+9)/8] + typed values. OK also starts 0x00.
	const size_t nb = (size_t)((m_column_count + 9) / 8);
	if (m_column_count > 0 && n >= 1 + nb) {
		// Measure minimal OK size (header + 2 lenenc + status/warnings).
		const unsigned char* cur = p + 1;
		size_t rem = n - 1;
		mysql_read_lenenc_int(cur, rem); // affected_rows
		mysql_read_lenenc_int(cur, rem); // last_insert_id
		if (rem < 4) return false;
		const size_t min_ok = n - rem + 4;
		if (n == min_ok) {
			// Exact classic OK. Binary rows of the same size can alias the layout
			// (e.g. non-zero value bytes misread as last_insert_id) — SELECT end
			// terminators always carry affected=0 and last_insert_id=0.
			return okf.affected_rows == 0 && okf.last_insert_id == 0;
		}
		// Longer than min OK: session-track OK, or binary row with value bytes.
		if ((okf.status_flags & kServerSessionStateChanged) != 0) return true;
		return false;
	}
	return true;
}
