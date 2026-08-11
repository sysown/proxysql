/**
 * @file test_ed25519_auth-t.cpp
 * @brief End-to-end MariaDB ed25519 authentication (frontend + backend).
 * @details Requires a MariaDB backend (mariadb10-galera infra): installs the
 *   auth_ed25519 server plugin, creates ed25519 backend users, and exercises:
 *     1. cleartext-stored user: frontend ed25519 auth AND backend ed25519 auth
 *        (query reaches the backend);
 *     2. $ED$-stored user: frontend auth succeeds, backend query fails with the
 *        backend's own 1045 "Access denied" (public key cannot drive backend auth --
 *        documented limitation; asserted on the specific errno/message, not just
 *        "the query failed", so a Galera blip or backend outage cannot pass this check);
 *     3. wrong password -> 1045;
 *     4. COM_CHANGE_USER into an ed25519 user via Auth Switch;
 *     5. additional-password (attributes JSON) retry;
 *     6. malformed "$ED$"-prefixed stored credential ("$ED$short", wrong
 *        length): connecting with the literal stored string as the password
 *        must be denied with 1045, never accepted as a cleartext match
 *        (regression coverage for the fail-closed prefix-routing fix).
 */
#include <cstdlib>
#include <cstring>
#include <string>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

const char* ED_PASS = "ed25519_pass_1";
const char* ED_PUBKEY = "5TBW79xTAMbhi8QKQtLLVS0V0b2w9mlKnRG6c+2NxTQ";
// Confirmed empirically against the mariadb10-galera infra (see task-5-report.md):
// when ProxySQL retries the backend connection for a $ED$ (public-key-only) user, the
// backend itself rejects the retry with its native 1045 access-denied error, and
// ProxySQL propagates that same errno/message straight through to the client -- this
// is not a ProxySQL-specific connect-timeout code, it is the backend's own "Access
// denied for user ..." response, forwarded verbatim.
#define ED25519_PK_BACKEND_ERRNO 1045

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(11);

	// ---- fixture: backend plugin + users, via ProxySQL default routing ----
	MYSQL* wr = mysql_init(NULL);
	if (!mysql_real_connect(wr, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("Failed to connect to ProxySQL: %s", mysql_error(wr));
		return EXIT_FAILURE;
	}
	// tolerate "already installed"
	if (mysql_query(wr, "INSTALL SONAME 'auth_ed25519'")) {
		diag("INSTALL SONAME: %s (tolerated if already installed)", mysql_error(wr));
	}
	{
		MYSQL_RES* res = NULL;
		MYSQL_QUERY(wr, "SELECT COUNT(*) FROM information_schema.plugins WHERE plugin_name='ed25519'");
		res = mysql_store_result(wr);
		MYSQL_ROW row = mysql_fetch_row(res);
		bool plugin_ok = row && strcmp(row[0], "1") == 0;
		mysql_free_result(res);
		if (!plugin_ok) {
			diag("auth_ed25519 server plugin unavailable on this backend");
			return EXIT_FAILURE;
		}
	}
	// NOTE: fixture is created through ProxySQL as 'testuser' (cl.username), which on the
	// mariadb10-galera infra has ALL PRIVILEGES ON *.* but NOT WITH GRANT OPTION (verified via
	// `SHOW GRANTS FOR testuser@%` against the running infra), so it cannot execute a GRANT
	// statement to hand out privileges on a schema to ed_user/ed_user_pk. Rather than depend on
	// a schema-level grant, the ed25519 users below are created with no default database and
	// every connection/change_user call in this test passes a NULL db -- this still exercises
	// the full frontend+backend authentication path (the thing under test) without requiring
	// object-level privileges that the fixture-creating account does not have.
	std::string create_user =
		std::string("CREATE USER IF NOT EXISTS 'ed_user'@'%' IDENTIFIED VIA ed25519 USING '") + ED_PUBKEY + "'";
	MYSQL_QUERY(wr, create_user.c_str());
	std::string create_user_pk =
		std::string("CREATE USER IF NOT EXISTS 'ed_user_pk'@'%' IDENTIFIED VIA ed25519 USING '") + ED_PUBKEY + "'";
	MYSQL_QUERY(wr, create_user_pk.c_str());

	// ---- proxysql users ----
	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Failed to connect to ProxySQL admin: %s", mysql_error(admin));
		return EXIT_FAILURE;
	}
	int def_hg = 0;
	{
		MYSQL_QUERY(admin, "SELECT MIN(hostgroup_id) FROM runtime_mysql_servers WHERE status='ONLINE'");
		MYSQL_RES* res = mysql_store_result(admin);
		MYSQL_ROW row = mysql_fetch_row(res);
		if (row && row[0]) { def_hg = atoi(row[0]); }
		mysql_free_result(res);
	}
	std::string q1 =
		"INSERT OR REPLACE INTO mysql_users (username,password,active,default_hostgroup) VALUES"
		" ('ed_user','" + std::string(ED_PASS) + "',1," + std::to_string(def_hg) + ")";
	MYSQL_QUERY(admin, q1.c_str());
	std::string q2 =
		"INSERT OR REPLACE INTO mysql_users (username,password,active,default_hostgroup) VALUES"
		" ('ed_user_pk','$ED$" + std::string(ED_PUBKEY) + "',1," + std::to_string(def_hg) + ")";
	MYSQL_QUERY(admin, q2.c_str());
	// Malformed "$ED$"-prefixed credential: wrong length, not a valid 47-char
	// public key. No backend user is needed -- the fail-closed fix denies
	// this at the frontend, before any backend connection is attempted.
	const char* ED_BAD_STORED = "$ED$short";
	std::string q3 =
		"INSERT OR REPLACE INTO mysql_users (username,password,active,default_hostgroup) VALUES"
		" ('ed_user_bad','" + std::string(ED_BAD_STORED) + "',1," + std::to_string(def_hg) + ")";
	MYSQL_QUERY(admin, q3.c_str());
	MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");

	// ---- 1-2: cleartext-stored user, full frontend+backend path ----
	{
		MYSQL* c = mysql_init(NULL);
		bool conn_ok = mysql_real_connect(c, cl.host, "ed_user", ED_PASS, NULL, cl.port, NULL, 0) != NULL;
		ok(conn_ok, "cleartext-stored user connects via ed25519 auth switch (err: %s)", conn_ok ? "-" : mysql_error(c));
		if (conn_ok) {
			int rc = mysql_query(c, "SELECT CURRENT_USER()");
			ok(rc == 0, "query reaches the ed25519 backend user (err: %s)", rc ? mysql_error(c) : "-");
			if (rc == 0) { mysql_free_result(mysql_store_result(c)); }
		} else {
			ok(false, "query skipped: connection failed");
		}
		mysql_close(c);
	}

	// ---- 3: wrong password -> 1045 ----
	{
		MYSQL* c = mysql_init(NULL);
		bool conn_ok = mysql_real_connect(c, cl.host, "ed_user", "wrong_password", NULL, cl.port, NULL, 0) != NULL;
		ok(conn_ok == false && mysql_errno(c) == 1045,
			"wrong password denied with 1045 (got errno %u)", mysql_errno(c));
		mysql_close(c);
	}

	// ---- 4-5: $ED$-stored user: frontend OK, backend query fails ----
	{
		MYSQL* c = mysql_init(NULL);
		bool conn_ok = mysql_real_connect(c, cl.host, "ed_user_pk", ED_PASS, NULL, cl.port, NULL, 0) != NULL;
		ok(conn_ok, "$ED$-stored user passes frontend verification (err: %s)", conn_ok ? "-" : mysql_error(c));
		if (conn_ok) {
			int rc = mysql_query(c, "SELECT 1");
			if (rc == 0) { mysql_free_result(mysql_store_result(c)); }
			unsigned int eno = mysql_errno(c);
			const char* emsg = mysql_error(c);
			diag("$ED$ backend query result: rc=%d errno=%u error='%s'", rc, eno, emsg ? emsg : "");
			// Distinguish the intended "backend rejects the public key" failure from generic
			// connectivity loss (Galera blip, backend outage, unrelated regression): both the
			// specific errno AND a stable substring of the backend's own access-denied text
			// must match, not just "some error occurred".
			bool is_access_denied = emsg && strstr(emsg, "Access denied") != NULL;
			ok(rc != 0 && eno == ED25519_PK_BACKEND_ERRNO && is_access_denied,
				"backend query fails for public-key-only credential with errno %d and 'Access denied' "
				"(documented limitation; got errno %u, error '%s')",
				ED25519_PK_BACKEND_ERRNO, eno, emsg ? emsg : "");
		} else {
			ok(false, "backend check skipped: connection failed");
		}
		mysql_close(c);
	}

	// ---- 6: bad frontend password for $ED$ user ----
	{
		MYSQL* c = mysql_init(NULL);
		bool conn_ok = mysql_real_connect(c, cl.host, "ed_user_pk", "wrong_password", NULL, cl.port, NULL, 0) != NULL;
		ok(conn_ok == false && mysql_errno(c) == 1045,
			"$ED$ user, wrong password denied with 1045 (got errno %u)", mysql_errno(c));
		mysql_close(c);
	}

	// ---- 6b: malformed "$ED$"-prefixed stored credential is never treated
	// as cleartext. Before the fail-closed fix, is_pubkey_format() rejected
	// "$ED$short" as not-a-valid-key, so it fell through to plain cleartext
	// comparison and a client sending the literal stored string as its
	// password would authenticate successfully. It must now be denied with
	// the standard 1045, exactly like any other credential mismatch.
	{
		MYSQL* c = mysql_init(NULL);
		bool conn_ok = mysql_real_connect(c, cl.host, "ed_user_bad", ED_BAD_STORED, NULL, cl.port, NULL, 0) != NULL;
		ok(conn_ok == false && mysql_errno(c) == 1045,
			"malformed $ED$ credential ('%s') denied with 1045, not accepted as cleartext (got errno %u)",
			ED_BAD_STORED, mysql_errno(c));
		mysql_close(c);
	}

	// ---- 7-8: COM_CHANGE_USER into the ed25519 user ----
	{
		MYSQL* c = mysql_init(NULL);
		bool conn_ok = mysql_real_connect(c, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0) != NULL;
		if (!conn_ok) {
			ok(false, "base connection for change_user failed: %s", mysql_error(c));
			ok(false, "change_user skipped");
		} else {
			int rc = mysql_change_user(c, "ed_user", ED_PASS, NULL);
			ok(rc == 0, "COM_CHANGE_USER into ed25519 user succeeds (err: %s)", rc ? mysql_error(c) : "-");
			rc = mysql_query(c, "SELECT 1");
			if (rc == 0) { mysql_free_result(mysql_store_result(c)); }
			ok(rc == 0, "query works after change_user (err: %s)", rc ? mysql_error(c) : "-");
		}
		mysql_close(c);
	}

	// ---- 9-10: additional-password retry (attributes JSON, hex-encoded) ----
	{
		// primary password wrong on purpose; additional_password holds the real one
		char hexpass[64] = { 0 };
		for (size_t i = 0; i < strlen(ED_PASS); i++) {
			sprintf(hexpass + 2 * i, "%02x", (unsigned char)ED_PASS[i]);
		}
		std::string q =
			"UPDATE mysql_users SET password='not_the_real_password',"
			" attributes='{\"additional_password\":\"" + std::string(hexpass) + "\"}'"
			" WHERE username='ed_user'";
		MYSQL_QUERY(admin, q.c_str());
		MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");

		MYSQL* c = mysql_init(NULL);
		bool conn_ok = mysql_real_connect(c, cl.host, "ed_user", ED_PASS, NULL, cl.port, NULL, 0) != NULL;
		ok(conn_ok, "additional-password retry verifies ed25519 signature (err: %s)", conn_ok ? "-" : mysql_error(c));
		if (conn_ok) {
			int rc = mysql_query(c, "SELECT 1");
			if (rc == 0) { mysql_free_result(mysql_store_result(c)); }
			ok(rc == 0, "query works on additional password (err: %s)", rc ? mysql_error(c) : "-");
		} else {
			ok(false, "query skipped: connection failed");
		}
		mysql_close(c);
	}

	// ---- cleanup ----
	MYSQL_QUERY(admin, "DELETE FROM mysql_users WHERE username IN ('ed_user','ed_user_pk','ed_user_bad')");
	MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");
	mysql_query(wr, "DROP USER IF EXISTS 'ed_user'@'%'");
	mysql_query(wr, "DROP USER IF EXISTS 'ed_user_pk'@'%'");
	mysql_close(admin);
	mysql_close(wr);

	return exit_status();
}
