#include "PgSQL_Extq_Batch.h"
#include "PgSQLCommandComplete.h"

void PgSQL_Extq_Registry::clear() {
	slots_.clear();
	events_.clear();
	complete_ = false;
	aborted_ = false;
	need_sync_ = false;
	sync_sent_ = false;
	local_error_ = false;
	local_error_bytes_.clear();
	saw_param_desc_ = false;
	rows_ = 0;
	affected_rows_ = UINT64_MAX;
}

bool PgSQL_Extq_Registry::needs_backend() const {
	for (const Extq_Slot& s : slots_) {
		if (s.reply == Extq_Reply::RELAY || s.reply == Extq_Reply::DROP) {
			return true;
		}
	}
	return false;
}

void PgSQL_Extq_Registry::start(std::string& out) {
	emit_due(out);
}

bool PgSQL_Extq_Registry::next_event(Extq_Event& ev) {
	if (events_.empty()) {
		return false;
	}
	ev = events_.front();
	events_.pop_front();
	return true;
}

void PgSQL_Extq_Registry::event(const Extq_Slot& s, Extq_Outcome o) {
	if (s.kind == Extq_Kind::SYNC) {
		return;   // a Sync answers no client message the session has to settle
	}
	const bool own = (o == Extq_Outcome::OK || o == Extq_Outcome::ERROR);
	events_.push_back({ s.entry, s.kind, s.reply, o, own ? rows_ : 0, own ? affected_rows_ : UINT64_MAX });
}

// ProxySQL's own replies go out as soon as everything before them is answered, never earlier:
// an earlier message may still fail, and then PostgreSQL would not have answered them.
void PgSQL_Extq_Registry::emit_due(std::string& out) {
	while (slots_.empty() == false) {
		const Extq_Slot& s = slots_.front();
		if (s.reply == Extq_Reply::LOCAL) {
			out += s.bytes;
			event(s, Extq_Outcome::OK);
			slots_.pop_front();
			continue;
		}
		if (s.reply == Extq_Reply::LOCAL_ERROR) {
			local_error_bytes_ = s.bytes;
			event(s, Extq_Outcome::ERROR);
			slots_.pop_front();
			local_error_ = true;
			while (slots_.empty() == false) {
				event(slots_.front(), Extq_Outcome::SKIPPED);
				slots_.pop_front();
			}
			complete_ = true;
			return;
		}
		break;
	}
	if (slots_.empty()) {
		complete_ = true;   // a batch sent without a Sync ends with its last reply
	}
}

Extq_Verdict PgSQL_Extq_Registry::complete_head(std::string& out) {
	const Extq_Reply reply = slots_.front().reply;
	event(slots_.front(), Extq_Outcome::OK);
	slots_.pop_front();
	rows_ = 0;
	affected_rows_ = UINT64_MAX;
	saw_param_desc_ = false;
	emit_due(out);
	return reply == Extq_Reply::DROP ? Extq_Verdict::DROP : Extq_Verdict::RELAY;
}

// After an ErrorResponse PostgreSQL skips every message until the next Sync. The slot at the head
// failed; every later one is skipped, ProxySQL's own replies included.
void PgSQL_Extq_Registry::on_error() {
	aborted_ = true;
	if (slots_.front().kind == Extq_Kind::SYNC) {
		return;   // the error came at the Sync itself, as a failed commit does
	}
	event(slots_.front(), Extq_Outcome::ERROR);
	slots_.pop_front();
	rows_ = 0;
	affected_rows_ = UINT64_MAX;
	while (slots_.empty() == false && slots_.front().kind != Extq_Kind::SYNC) {
		event(slots_.front(), Extq_Outcome::SKIPPED);
		slots_.pop_front();
	}
	if (slots_.empty()) {
		need_sync_ = true;
	}
}

Extq_Verdict PgSQL_Extq_Registry::on_message(char type, const unsigned char* payload, uint32_t len, std::string& out) {
	if (complete_) {
		return Extq_Verdict::BAD;
	}
	// Notices, parameter changes and notifications can come at any point and answer nothing.
	if (type == 'N' || type == 'S' || type == 'A') {
		return Extq_Verdict::RELAY;
	}
	if (aborted_) {
		// After an error only the ReadyForQuery that ends the batch may come. The client gets it:
		// it follows the error the client was given.
		if (type != 'Z') {
			return Extq_Verdict::BAD;
		}
		if (slots_.empty() == false) {
			slots_.pop_front();   // the Sync, the only slot on_error() leaves
		} else if (sync_sent_ == false) {
			return Extq_Verdict::BAD;
		}
		complete_ = true;
		return Extq_Verdict::RELAY;
	}
	if (slots_.empty()) {
		return Extq_Verdict::BAD;
	}
	if (type == 'E') {
		on_error();
		return Extq_Verdict::RELAY;
	}
	const Extq_Slot& head = slots_.front();
	const Extq_Verdict partial = (head.reply == Extq_Reply::DROP) ? Extq_Verdict::DROP : Extq_Verdict::RELAY;
	switch (head.kind) {
	case Extq_Kind::PARSE:
		if (type == '1') return complete_head(out);
		break;
	case Extq_Kind::BIND:
		if (type == '2') return complete_head(out);
		break;
	case Extq_Kind::CLOSE:
		if (type == '3') return complete_head(out);
		break;
	case Extq_Kind::DESCRIBE_S:
		if (type == 't' && saw_param_desc_ == false) {
			saw_param_desc_ = true;
			return partial;
		}
		if ((type == 'T' || type == 'n') && saw_param_desc_) return complete_head(out);
		break;
	case Extq_Kind::DESCRIBE_P:
		if (type == 'T' || type == 'n') return complete_head(out);
		break;
	case Extq_Kind::EXECUTE:
		if (type == 'D') {
			rows_++;
			return partial;
		}
		if (type == 'C') {
			const PgSQLCommandResult r = parse_pgsql_command_complete(payload, len);
			affected_rows_ = r.is_select ? UINT64_MAX : r.rows;
			return complete_head(out);
		}
		if (type == 'I' || type == 's') return complete_head(out);
		break;
	case Extq_Kind::SYNC:
		if (type == 'Z') {
			complete_ = true;
			slots_.pop_front();
			return partial;
		}
		break;
	}
	return Extq_Verdict::BAD;
}
