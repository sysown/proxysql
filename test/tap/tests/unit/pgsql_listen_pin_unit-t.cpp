/**
 * @file pgsql_listen_pin_unit-t.cpp
 * @brief A LISTEN anywhere in a multi-statement Simple Query pins the backend
 *        connection, and the last LISTEN or UNLISTEN * of the message decides
 *        whether it stays pinned (issue #6438).
 *
 * STATUS_PGSQL_CONNECTION_LISTEN keeps a subscribed connection with the session
 * that subscribed. It used to be set only when the digest STARTED with LISTEN, so
 * "SELECT 1; LISTEN ch" subscribed on the backend without pinning: the client got
 * none of its notifications and the connection went back to the pool subscribed.
 * These cases pin both ways the flag is now taken, without a server:
 *   - ProcessQueryAndSetStatusFlags() walks every statement of the digest;
 *   - native_fetch_result_cont() sets it from a CommandComplete tagged LISTEN, which
 *     does not depend on a digest, and before ReadyForQuery, so a notification in
 *     the same reply is forwarded rather than dropped.
 * The end-to-end cases live in pgsql-native_notify-t and pgsql-listen_notify_contract-t.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Protocol.h"

#include <fcntl.h>
#include <unistd.h>
#include <string>

// get_resultset() hands the collected bytes over only when a protocol is attached; the native
// drain itself never calls into it.
static PgSQL_Protocol g_proto;

static PgSQL_Connection* make_conn() {
	PgSQL_Connection* c = new PgSQL_Connection(false);
	c->native_mode = true;
	c->fd = ::open("/dev/null", O_RDONLY);
	c->native_st = PgSQL_Connection::PG_Native_Conn_St::DONE;
	c->native_connected = true;
	c->set_ready_for_query_status('I');
	c->query_result = new PgSQL_Query_Result();
	c->query_result->init(&g_proto, nullptr, c);
	return c;
}

static void destroy(PgSQL_Connection* c) {
	if (c->fd >= 0) { ::close(c->fd); c->fd = -1; }
	c->native_connected = false;
	delete c; // also deletes query_result
}

static bool pinned(PgSQL_Connection* c) {
	return c->get_status(STATUS_PGSQL_CONNECTION_LISTEN);
}

// ---------------------------------------------------------------------------
// From the digest. No data stream is attached, so only the digest drives the flags.
// ---------------------------------------------------------------------------

// The flag after running `digest` on a connection that starts pinned or not.
static bool pin_after(bool pinned_before, const char* digest) {
	PgSQL_Connection* c = make_conn();
	c->set_status(pinned_before, STATUS_PGSQL_CONNECTION_LISTEN);
	c->ProcessQueryAndSetStatusFlags(digest, -1);
	const bool r = pinned(c);
	destroy(c);
	return r;
}

static void test_digest_pins() {
	ok(pin_after(false, "listen ch"), "digest: a lone LISTEN pins");
	ok(pin_after(false, "select ?; listen ch"), "digest: LISTEN behind another statement pins");
	ok(pin_after(false, "select ?;listen ch"), "digest: LISTEN right after the ';' pins");
	ok(!pin_after(false, "select ? as \"a; listen b\""),
	   "digest: a ';' inside a quoted identifier is no statement boundary");
	ok(!pin_after(false, "select ?; select listener from t"),
	   "digest: an identifier starting with LISTEN does not pin");
}

// Individual channels are not tracked, so only UNLISTEN * may release the pin, and only
// when no LISTEN follows it in the same message.
static void test_digest_last_statement_decides() {
	ok(!pin_after(false, "listen a; unlisten *"), "digest: LISTEN a; UNLISTEN * leaves nothing pinned");
	ok(pin_after(true, "unlisten *; listen b"), "digest: UNLISTEN *; LISTEN b keeps the pin");
	ok(pin_after(true, "listen a; unlisten *; listen b"), "digest: LISTEN a; UNLISTEN *; LISTEN b keeps the pin");
	ok(!pin_after(true, "select ?; unlisten *"), "digest: UNLISTEN * behind another statement releases the pin");
	ok(!pin_after(true, "unlisten*"), "digest: UNLISTEN* with no space releases the pin");
	ok(pin_after(true, "unlisten ch"), "digest: UNLISTEN <channel> keeps the pin");
	ok(pin_after(true, "select ?"), "digest: an unrelated statement keeps the pin");
}

// With query_digests_keep_comment the digest keeps each statement's leading comments.
static void test_digest_kept_comments() {
	ok(pin_after(false, "/*c*/ listen ch"), "digest: LISTEN behind a kept comment pins");
	ok(pin_after(false, "select ?; /*c*/ listen ch"), "digest: a later LISTEN behind a kept comment pins");
	ok(!pin_after(true, "/*c*/ unlisten *"), "digest: UNLISTEN * behind a kept comment releases the pin");
	ok(!pin_after(true, "unlisten /*c*/ *"), "digest: so does UNLISTEN /*c*/ *");
	ok(!pin_after(false, "select ?; /* listen ch */ select ?"), "digest: LISTEN only inside a kept comment does not pin");
}

// A kept comment longer than FIRST_COMMENT_MAX_LENGTH is cut before its "*/". Past it the
// statements cannot be told apart: a LISTEN anywhere pins, and nothing unpins.
static void test_digest_lost_scan() {
	ok(pin_after(false, "/*xxx select ?; listen ch"), "digest: LISTEN after a comment cut short pins");
	ok(pin_after(false, "/*xxx listen ch"), "digest: LISTEN right after a comment cut short pins");
	ok(pin_after(true, "/*xxx select ?; unlisten *"), "digest: UNLISTEN * after a comment cut short keeps the pin");
	ok(!pin_after(false, "/*xxx select ?; select ?"), "digest: a comment cut short alone does not pin");
}

// ---------------------------------------------------------------------------
// With pgsql-query_digests off. The LISTEN tag pins; the query text releases.
// ---------------------------------------------------------------------------

static bool pin_after_query(bool pinned_before, const char* query) {
	PgSQL_Connection* c = make_conn();
	c->set_status(pinned_before, STATUS_PGSQL_CONNECTION_LISTEN);
	c->update_listen_status_from_query(query);
	const bool r = pinned(c);
	destroy(c);
	return r;
}

static void test_no_digest_unlisten() {
	ok(!pin_after_query(true, "UNLISTEN *"), "no digest: UNLISTEN * releases the pin");
	ok(!pin_after_query(true, "SELECT 1;\n unlisten\t*"), "no digest: so does a later UNLISTEN * of the message");
	ok(pin_after_query(true, "UNLISTEN ch"), "no digest: UNLISTEN <channel> keeps the pin");
	ok(pin_after_query(true, "UNLISTEN *; LISTEN ch"), "no digest: UNLISTEN *; LISTEN ch keeps the pin");
	ok(pin_after_query(true, "SELECT 'unlisten *'") && pin_after_query(true, "SELECT 1 /* UNLISTEN * */"),
	   "no digest: UNLISTEN * inside a literal or a comment keeps the pin");
	ok(!pin_after_query(false, "UNLISTEN *") && !pin_after_query(false, "SELECT 1"),
	   "no digest: an unpinned connection stays unpinned");
	// A nested comment whose "*/*/" closes twice right before the keyword: the full digest
	// used to be empty, so the pin was never released.
	ok(!pin_after_query(true, "/*/*n*/*/UNLISTEN *"),
	   "no digest: UNLISTEN * right after a nested comment releases the pin");
}

// ---------------------------------------------------------------------------
// From the native result stream.
// ---------------------------------------------------------------------------

static std::string wire(char type, const std::string& payload) {
	std::string s(1, type);
	const uint32_t L = (uint32_t)(payload.size() + 4);
	s.push_back((char)((L >> 24) & 0xff));
	s.push_back((char)((L >> 16) & 0xff));
	s.push_back((char)((L >> 8) & 0xff));
	s.push_back((char)(L & 0xff));
	s += payload;
	return s;
}

static std::string wire_C(const char* tag) { return wire('C', std::string(tag) + '\0'); }
static std::string wire_Z() { return wire('Z', std::string("I", 1)); }
// NotificationResponse: be32 pid, channel\0, payload\0 (sizeof keeps the last NUL).
static std::string wire_A() {
	static const char a[] = "\0\0\0\x01" "chan\0" "payload";
	return wire('A', std::string(a, sizeof(a)));
}

// Drain the framed bytes. native_fetch_paused makes the drain read only what is
// already framed, so nothing touches the (dummy) socket.
static void drain(PgSQL_Connection* c, const std::string& bytes) {
	c->native_framer.feed((const unsigned char*)bytes.data(), bytes.size());
	c->native_fetch_paused = true;
	c->native_fetch_result_cont(0, nullptr);
}

// Whether the NotificationResponse of wire_A() is among the bytes the result hands to the
// client: the flag alone says nothing about what actually reaches the result stream.
static bool result_carries_notification(PgSQL_Connection* c) {
	PtrSizeArray out;
	c->query_result->get_resultset(&out);
	std::string bytes;
	for (unsigned int i = 0; i < out.len; i++) {
		const PtrSize_t* p = out.index(i);
		bytes.append((const char*)p->ptr, p->size);
		free(p->ptr);
	}
	return bytes.find(wire_A()) != std::string::npos;
}

static void test_command_complete_tag() {
	PgSQL_Connection* c = make_conn();
	drain(c, wire_C("SELECT 1") + wire_C("LISTEN") + wire_Z());
	ok(c->native_result_complete && pinned(c),
	   "native: a CommandComplete tagged LISTEN pins, with no digest involved");
	destroy(c);

	// LISTEN ch; NOTIFY ch: the notification comes after the LISTEN tag, in the same reply.
	c = make_conn();
	drain(c, wire_C("LISTEN") + wire_C("NOTIFY") + wire_A() + wire_Z());
	ok(c->native_result_complete && pinned(c) && c->native_result_had_notification &&
	   result_carries_notification(c),
	   "native: a notification after the LISTEN tag in the same reply is forwarded");
	destroy(c);

	// Control: with no LISTEN in the reply the notification belongs to nobody here.
	c = make_conn();
	drain(c, wire_C("NOTIFY") + wire_A() + wire_Z());
	ok(c->native_result_complete && !pinned(c) && !c->native_result_had_notification &&
	   !result_carries_notification(c),
	   "native control: without a LISTEN tag the notification is discarded and nothing is pinned");
	destroy(c);

	c = make_conn();
	drain(c, wire_C("UNLISTEN") + wire_C("LISTENER") + wire_Z());
	ok(c->native_result_complete && !pinned(c),
	   "native: UNLISTEN and other tags that merely contain the word do not pin");
	destroy(c);
}

int main() {
	plan(32);
	test_init_minimal();

	test_digest_pins();                    // 5
	test_digest_last_statement_decides();  // 7
	test_digest_kept_comments();           // 5
	test_digest_lost_scan();               // 4
	test_no_digest_unlisten();             // 7
	test_command_complete_tag();           // 4

	test_cleanup_minimal();
	return exit_status();
}
