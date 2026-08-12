#ifndef MYSQL_RESULTSET_FRAMER_H
#define MYSQL_RESULTSET_FRAMER_H

#include <cstdint>
#include <cstddef>

enum class MySQLRSEventKind {
	None = 0,
	Row,
	OKNoResultset,
	ResultsetComplete,
	Error
};

struct MySQLRSEvent {
	MySQLRSEventKind kind { MySQLRSEventKind::None };
	uint64_t rows_sent_total { 0 };
	uint64_t affected_rows { 0 };
	uint16_t status_flags { 0 };
	uint16_t error_code { 0 };
	bool more_results { false };
};

class MySQLResultsetFramer {
public:
	void reset();
	bool active() const;
	void begin(bool binary_protocol, bool deprecate_eof);
	MySQLRSEvent on_first_payload(const unsigned char* p, size_t n);
	MySQLRSEvent on_payload(const unsigned char* p, size_t n);

private:
	enum class State {
		Idle,
		AwaitingFirst,
		ReadingColumns,
		ReadingRows
	};

	State m_state { State::Idle };
	bool m_binary { false };
	bool m_deprecate_eof { false };
	uint64_t m_column_count { 0 };
	uint64_t m_columns_seen { 0 };
	uint64_t m_rows_sent { 0 };
	bool m_saw_intermediate_eof { false };

	MySQLRSEvent make_complete(uint16_t status, uint64_t affected);
	MySQLRSEvent make_error(uint16_t code);
	bool looks_like_ok_terminator(const unsigned char* p, size_t n) const;
};

#endif
