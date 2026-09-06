/**
 * @file pgsql_reconcile_unit-t.cpp
 * @brief Unit tests for pgsql_reconcile_auth_method() — auth-method selection.
 *
 * The function is defined at file scope in lib/PgSQL_Protocol.cpp; we declare it locally with plain
 * int values instead of including the protocol/thread headers.
 */
#include "tap.h"

// Defined in libproxysql.a (lib/PgSQL_Protocol.cpp). C++ name mangling depends only on the
// (int,int,bool*) parameter types, so this local declaration links to the real definition.
int pgsql_reconcile_auth_method(int floor, int stored, bool* reject);

// libscram PasswordType values (deps/libscram/include/scram.h):
enum { PT_PLAINTEXT = 0, PT_MD5 = 1, PT_SCRAM = 2 };
// AUTHENTICATION_METHOD values (include/PgSQL_Thread.h):
enum { AM_CLEARTEXT = 1, AM_MD5 = 2, AM_SCRAM = 3 };

int main() {
	plan(9);
	bool rj = false;

	// SCRAM verifier -> always SCRAM, never reject (meets/exceeds any floor)
	ok(pgsql_reconcile_auth_method(1, PT_SCRAM, &rj) == AM_SCRAM && !rj, "scram secret, cleartext floor -> SCRAM");
	ok(pgsql_reconcile_auth_method(2, PT_SCRAM, &rj) == AM_SCRAM && !rj, "scram secret, md5 floor -> SCRAM (upgrade)");
	ok(pgsql_reconcile_auth_method(3, PT_SCRAM, &rj) == AM_SCRAM && !rj, "scram secret, scram floor -> SCRAM");

	// md5 hash -> md5 when floor<=md5; reject when floor=scram
	ok(pgsql_reconcile_auth_method(1, PT_MD5, &rj) == AM_MD5 && !rj, "md5 secret, cleartext floor -> MD5");
	ok(pgsql_reconcile_auth_method(2, PT_MD5, &rj) == AM_MD5 && !rj, "md5 secret, md5 floor -> MD5");
	ok(pgsql_reconcile_auth_method(3, PT_MD5, &rj) == AM_SCRAM && rj, "md5 secret, scram floor -> REJECT (mock under SCRAM)");

	// plaintext -> the floor's method, never reject
	ok(pgsql_reconcile_auth_method(1, PT_PLAINTEXT, &rj) == AM_CLEARTEXT && !rj, "plaintext, cleartext floor -> CLEAR_TEXT");
	ok(pgsql_reconcile_auth_method(2, PT_PLAINTEXT, &rj) == AM_MD5 && !rj, "plaintext, md5 floor -> MD5");
	ok(pgsql_reconcile_auth_method(3, PT_PLAINTEXT, &rj) == AM_SCRAM && !rj, "plaintext, scram floor -> SCRAM");

	return exit_status();
}
