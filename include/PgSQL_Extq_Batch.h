#ifndef __CLASS_PGSQL_EXTQ_BATCH_H
#define __CLASS_PGSQL_EXTQ_BATCH_H

// The replies a batch of extended-query messages expects from a native backend, in the order the
// messages were sent. The session queues one slot for each message it sends and one for each reply
// it gives itself; the connection passes every backend message to on_message(), which says whether
// it reaches the client. No I/O and no session state.

#include <cstdint>
#include <deque>
#include <string>

enum class Extq_Kind : uint8_t { PARSE, BIND, DESCRIBE_S, DESCRIBE_P, EXECUTE, CLOSE, SYNC };

// How a slot is answered.
//   RELAY        the backend's reply goes to the client
//   DROP         ProxySQL's own message: success is dropped, an error goes to the client
//   LOCAL        ProxySQL's own reply, in bytes, sent once every earlier slot is answered
//   SUBSTITUTE   ProxySQL's own message, sent to fail on the backend: the backend's error is
//                replaced by these bytes, ProxySQL's own error, and the rest is skipped as usual.
enum class Extq_Reply : uint8_t { RELAY, DROP, LOCAL, SUBSTITUTE };

struct Extq_Slot {
	Extq_Kind kind;
	Extq_Reply reply;
	uint32_t entry;       // the client message the slot belongs to
	std::string bytes;    // LOCAL and SUBSTITUTE: complete wire messages
};

enum class Extq_Outcome : uint8_t { OK, ERROR, SKIPPED };

// What became of one slot. Events come out in slot order.
struct Extq_Event {
	uint32_t entry;
	Extq_Kind kind;
	Extq_Reply reply;
	Extq_Outcome outcome;
	uint64_t rows;           // DataRows of an Execute
	uint64_t affected_rows;  // from an Execute's CommandComplete; UINT64_MAX when it has none
	bool suspended;          // an Execute that stopped at its row limit (PortalSuspended)
};

enum class Extq_Verdict : uint8_t { RELAY, DROP, BAD };

class PgSQL_Extq_Registry {
public:
	void clear();
	void push(Extq_Slot slot) { slots_.push_back(std::move(slot)); }
	// Appends to out ProxySQL's replies that come before any backend reply.
	void start(std::string& out);
	// Judges one backend message. ProxySQL's replies that became due after it are appended to
	// out and go to the client after the message itself.
	Extq_Verdict on_message(char type, const unsigned char* payload, uint32_t len, std::string& out);
	bool next_event(Extq_Event& ev);
	bool complete() const { return complete_; }
	// Whether anything was answered yet, by the backend or by ProxySQL's own replies.
	bool answered() const { return answered_; }
	// An error came back in a batch sent without a Sync. The backend skips everything until it
	// gets one, so the caller sends a Sync and then calls sync_sent().
	bool needs_sync() const { return need_sync_ && !sync_sent_; }
	void sync_sent() { sync_sent_ = true; }
private:
	void emit_due(std::string& out);
	void on_error();
	Extq_Verdict complete_head(std::string& out);
	void event(const Extq_Slot& s, Extq_Outcome o);

	std::deque<Extq_Slot> slots_;
	std::deque<Extq_Event> events_;
	bool complete_ = false;
	bool answered_ = false;
	bool aborted_ = false;       // an ErrorResponse came; only ReadyForQuery may follow
	bool need_sync_ = false;
	bool sync_sent_ = false;
	bool saw_param_desc_ = false;
	uint64_t rows_ = 0;
	uint64_t affected_rows_ = UINT64_MAX;
	bool suspended_ = false;
};

#endif // __CLASS_PGSQL_EXTQ_BATCH_H
