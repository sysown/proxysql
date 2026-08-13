#include "PgSQLResponseFramer.h"
#include "PgSQLCommandComplete.h"

void PgSQLResponseFramer::reset() {
	m_finalize_on_sync = false;
	m_response_seen = false;
}

void PgSQLResponseFramer::on_query_activated(bool finalize_on_sync) {
	m_finalize_on_sync = finalize_on_sync;
	m_response_seen = false;
}

void PgSQLResponseFramer::set_finalize_on_sync(bool v) {
	m_finalize_on_sync = v;
}

PgSQLRSEvent PgSQLResponseFramer::on_message(char type, const unsigned char* payload, size_t len) {
	PgSQLRSEvent ev;
	switch (type) {
	case 'C': {
		auto r = parse_pgsql_command_complete(payload, len);
		ev.kind = PgSQLRSEventKind::CommandComplete;
		ev.rows = r.rows;
		ev.is_select = r.is_select;
		m_response_seen = true;
		return ev;
	}
	case 'I':
		ev.kind = PgSQLRSEventKind::EmptyQuery;
		m_response_seen = true;
		return ev;
	case 's':
		ev.kind = PgSQLRSEventKind::PortalSuspended;
		m_response_seen = true;
		return ev;
	case 'Z':
		ev.kind = PgSQLRSEventKind::ReadyForQuery;
		return ev;
	case 'E':
		ev.kind = PgSQLRSEventKind::Error;
		return ev;
	default:
		return ev;
	}
}
