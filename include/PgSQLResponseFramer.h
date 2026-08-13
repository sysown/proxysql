#ifndef PGSQL_RESPONSE_FRAMER_H
#define PGSQL_RESPONSE_FRAMER_H

#include <cstdint>
#include <cstddef>

enum class PgSQLRSEventKind {
	None = 0,
	CommandComplete,
	EmptyQuery,
	PortalSuspended,
	ReadyForQuery,
	Error
};

struct PgSQLRSEvent {
	PgSQLRSEventKind kind { PgSQLRSEventKind::None };
	uint64_t rows { 0 };
	bool is_select { false };
};

class PgSQLResponseFramer {
public:
	void reset();
	void set_finalize_on_sync(bool v);
	bool response_seen() const { return m_response_seen; }
	bool finalize_on_sync() const { return m_finalize_on_sync; }

	PgSQLRSEvent on_message(char type, const unsigned char* payload, size_t len);

	void on_query_activated(bool finalize_on_sync);

private:
	bool m_finalize_on_sync { false };
	bool m_response_seen { false };
};

#endif
