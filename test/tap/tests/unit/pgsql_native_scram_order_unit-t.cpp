/**
 * @file pgsql_native_scram_order_unit-t.cpp
 * @brief A backend must not finish SCRAM without proving it knows the password.
 *
 * SCRAM proves both sides. The native handshake acted on each Authentication
 * message's type alone, never on whether it was due, so a backend could answer the
 * client's proof with a bare AuthenticationOk -- skipping its own half -- and be
 * believed. Driving that end to end needs a lying server under Docker; here it is
 * offline, by handing a connection an unverified exchange and an AuthenticationOk.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Connection.h"
#include "PgSQL_Backend_Protocol.h"

#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <string>

// AuthenticationOk on the wire: 'R', a length that counts itself, then subtype 0.
static std::string auth_ok() {
	std::string m;
	m.push_back('R');
	const uint32_t L = 8;
	m.push_back((char)((L >> 24) & 0xff));
	m.push_back((char)((L >> 16) & 0xff));
	m.push_back((char)((L >> 8) & 0xff));
	m.push_back((char)(L & 0xff));
	m.append(4, '\0');
	return m;
}

// A connection parked mid-authentication with `msg` already waiting on its socket.
static PgSQL_Connection* armed(const std::string& msg, int sv[2]) {
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) BAIL_OUT("socketpair failed");
	fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL, 0) | O_NONBLOCK);
	if (::send(sv[1], msg.data(), msg.size(), 0) != (ssize_t)msg.size()) BAIL_OUT("send failed");
	PgSQL_Connection* c = new PgSQL_Connection(false);
	c->fd = sv[0];
	c->native_mode = true;
	c->native_st = PgSQL_Connection::PG_Native_Conn_St::AUTH;
	return c;
}

static void teardown(PgSQL_Connection* c, int sv[2]) {
	if (c->fd >= 0) { close(c->fd); c->fd = -1; }   // only reached when the refusal did not
	delete c;
	close(sv[1]);
}

int main(int, char**) {
	plan(3);

	// ---- the backend skips its half of the proof ---------------------------
	int sv[2];
	PgSQL_Connection* c = armed(auth_ok(), sv);
	c->native_scram = pg_scram_new();
	if (c->native_scram == nullptr) BAIL_OUT("pg_scram_new failed");
	// Our proof has gone out; the server owes one back, and instead says "you're in".
	c->native_scram_step = PgSQL_Connection::PG_Native_Scram_Step::CLIENT_FINAL_SENT;

	c->native_drive_auth(0);

	ok(c->is_error_present() && !c->native_connected,
	   "AuthenticationOk with the exchange unverified is REFUSED%s",
	   c->is_error_present() ? "" : "  <-- accepted; the backend never proved it knows the password");

	// Refusing has to destroy the connection, not just flag it: this socket must
	// never be handed to a client or returned to the pool.
	ok(c->fd < 0, "and the connection is torn down (fd %d)", c->fd);
	teardown(c, sv);

	// Control: no exchange to verify, so nothing to refuse. A guard that rejected
	// these would break every trust- or password-authenticated backend.
	int sv2[2];
	PgSQL_Connection* c2 = armed(auth_ok(), sv2);   // native_scram stays null
	c2->native_drive_auth(0);

	ok(!c2->is_error_present() &&
	   c2->native_st == PgSQL_Connection::PG_Native_Conn_St::STARTUP_TAIL,
	   "a backend with no SCRAM exchange (trust or password auth) is still accepted%s",
	   c2->is_error_present() ? "  <-- the guard rejects a legitimate login" : "");
	teardown(c2, sv2);

	return exit_status();
}
