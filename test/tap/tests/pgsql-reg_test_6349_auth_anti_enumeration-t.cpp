/**
 * @file pgsql-reg_test_6349_auth_anti_enumeration-t.cpp
 * @brief Regression test for issue #6349.
 *
 * PostgreSQL frontend authentication must not reveal whether a user exists:
 * a known user with a wrong password and an unknown user must see the same
 * challenge and the same failure on the wire.
 *
 * Issue #6349: under the cleartext and md5 floors, a known user answering the
 * challenge with an empty PasswordMessage got an extra, distinct
 * 'FATAL 08P01 "empty password returned by client"' before the generic
 * 'Access denied', while an unknown user only got the generic failure.
 *
 * For each floor (cleartext, md5) and each answer (empty password, wrong
 * password) the test runs the raw handshake for a known user and for an
 * unknown user, records the authentication request code and every
 * ErrorResponse (severity, SQLSTATE, message with the username masked), and
 * checks that both transcripts are identical.
 *
 * The known user is stored with a plaintext password, so it is challenged with
 * the floor's method like an unknown user. A user stored with a SCRAM verifier
 * (or an md5 hash under the cleartext floor) is still challenged differently
 * from an unknown user; that limitation is documented in
 * PgSQL_Protocol::generate_pkt_initial_handshake() and not covered here.
 */

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "pg_lite_client.h" // must precede mysql.h: mariadb_version.h #defines
                            // PROTOCOL_VERSION, colliding with PgConnection's
                            // static member of the same name
#include <mysql.h>          // admin interface is reached via the MySQL client
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

static const char* UNKNOWN_USER = "reg_test_6349_no_such_user";
static const int READ_TIMEOUT_MS = 2000;

static MYSQL* admin_connect() {
	MYSQL* conn = mysql_init(NULL);
	if (!mysql_real_connect(conn, cl.admin_host, cl.admin_username, cl.admin_password,
	                        NULL, cl.admin_port, NULL, 0)) {
		diag("admin connect failed: %s", mysql_error(conn));
		mysql_close(conn);
		return NULL;
	}
	return conn;
}

static bool set_frontend_auth_method(MYSQL* admin, int method) {
	const std::string q = "SET pgsql-authentication_method=" + std::to_string(method);
	if (mysql_query(admin, q.c_str())) { diag("SET failed: %s", mysql_error(admin)); return false; }
	if (mysql_query(admin, "LOAD PGSQL VARIABLES TO RUNTIME")) { diag("LOAD failed: %s", mysql_error(admin)); return false; }
	return true;
}

static void replace_all(std::string& s, const std::string& from, const std::string& to) {
	if (from.empty()) return;
	size_t pos = 0;
	while ((pos = s.find(from, pos)) != std::string::npos) {
		s.replace(pos, from.size(), to);
		pos += to.size();
	}
}

/**
 * @brief Renders an ErrorResponse as "S=<severity> C=<sqlstate> M=<message>",
 *  with the username masked so transcripts of different users compare equal.
 */
static std::string render_error(const std::vector<uint8_t>& buf, const std::string& user) {
	std::string severity {}, code {}, message {};
	size_t i = 0;
	while (i < buf.size() && buf[i] != 0) {
		const char field = (char)buf[i++];
		std::string value {};
		while (i < buf.size() && buf[i] != 0) value += (char)buf[i++];
		i++; // field terminator
		if (field == 'S') severity = value;
		else if (field == 'C') code = value;
		else if (field == 'M') message = value;
	}
	replace_all(message, "'" + user + "'", "'<user>'");
	return "S=" + severity + " C=" + code + " M=" + message;
}

/**
 * @brief Runs the handshake for 'user' answering the challenge with 'password'
 *  (a PasswordMessage, valid for the cleartext and md5 challenges) and returns
 *  the transcript of what the server sent back.
 */
static std::string handshake_transcript(const std::string& user, const std::string& password) {
	std::string transcript {};
	PgConnection c(READ_TIMEOUT_MS);
	try {
		c.rawConnectStartup(cl.pgsql_host, cl.pgsql_port, user, user);

		char type = 0;
		std::vector<uint8_t> buf {};
		c.readMessage(type, buf);
		if (type != 'R' || buf.size() < 4) {
			return transcript + "unexpected first message '" + std::string(1, type) + "'";
		}
		const int32_t auth_code = (int32_t)(((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
			((uint32_t)buf[2] << 8) | (uint32_t)buf[3]);
		transcript += "R(" + std::to_string(auth_code) + ")";

		// PasswordMessage: the password and its NUL terminator. For md5 a wrong
		// password is simply a wrong digest; an empty one is just the terminator.
		std::vector<uint8_t> answer(password.begin(), password.end());
		answer.push_back(0);
		c.sendMessage('p', answer);

		while (true) {
			c.readMessage(type, buf);
			if (type == 'E') {
				transcript += " E[" + render_error(buf, user) + "]";
			} else {
				transcript += " " + std::string(1, type);
			}
		}
	} catch (const PgException& e) {
		// The server closes the connection after a failed login, or nothing more arrives.
		transcript += " <end>";
	}
	return transcript;
}

int main(int, char**) {
	if (cl.getEnv()) return exit_status();

	const int floors[] = { 1, 2 }; // cleartext, md5
	const char* floor_names[] = { "cleartext", "md5" };
	struct Answer { const char* label; std::string password; };
	const Answer answers[] = { { "empty password", "" }, { "wrong password", "reg_test_6349_wrong_pw" } };

	plan(1 + 2 * 2 * 2);

	MYSQL* admin = admin_connect();
	if (!admin) BAIL_OUT("cannot reach admin");

	char* orig_floor = NULL;
	if (mysql_query(admin, "SELECT variable_value FROM global_variables WHERE variable_name='pgsql-authentication_method'") == 0) {
		MYSQL_RES* r = mysql_store_result(admin);
		MYSQL_ROW row = r ? mysql_fetch_row(r) : NULL;
		if (row && row[0]) orig_floor = strdup(row[0]);
		if (r) mysql_free_result(r);
	}
	if (orig_floor == NULL) {
		mysql_close(admin);
		BAIL_OUT("cannot read pgsql-authentication_method");
	}

	for (int f = 0; f < 2; f++) {
		if (!set_frontend_auth_method(admin, floors[f])) {
			set_frontend_auth_method(admin, atoi(orig_floor));
			BAIL_OUT("could not configure pgsql-authentication_method=%d", floors[f]);
		}
		for (const Answer& a : answers) {
			const std::string known = handshake_transcript(cl.pgsql_username, a.password);
			const std::string unknown = handshake_transcript(UNKNOWN_USER, a.password);
			diag("%s floor, %s: known   -> %s", floor_names[f], a.label, known.c_str());
			diag("%s floor, %s: unknown -> %s", floor_names[f], a.label, unknown.c_str());
			ok(known.find(" E[") != std::string::npos,
				"%s floor, %s: the login is rejected with an ErrorResponse", floor_names[f], a.label);
			ok(known == unknown,
				"%s floor, %s: a known and an unknown user get the same challenge and failure",
				floor_names[f], a.label);
		}
	}

	ok(set_frontend_auth_method(admin, atoi(orig_floor)), "Restored pgsql-authentication_method=%s", orig_floor);
	free(orig_floor);
	mysql_close(admin);
	return exit_status();
}
