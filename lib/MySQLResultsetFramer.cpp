#include "MySQLResultsetFramer.h"
#include "MySQLProtocolUtils.h"
#include <cstring>

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
	(void)p; (void)n;
	return {};
}

MySQLRSEvent MySQLResultsetFramer::on_payload(const unsigned char* p, size_t n) {
	(void)p; (void)n;
	return {};
}

MySQLRSEvent MySQLResultsetFramer::make_complete(uint16_t status, uint64_t affected) {
	(void)status; (void)affected;
	return {};
}

MySQLRSEvent MySQLResultsetFramer::make_error(uint16_t code) {
	(void)code;
	return {};
}

bool MySQLResultsetFramer::looks_like_ok_terminator(const unsigned char* p, size_t n) const {
	(void)p; (void)n;
	return false;
}
