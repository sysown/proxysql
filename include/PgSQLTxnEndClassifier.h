/**
 * @file PgSQLTxnEndClassifier.h
 * @brief Recognises a plain, single-statement PostgreSQL transaction end.
 *
 * pgsql_classify_plain_txn_end() accepts exactly one of
 *
 *     COMMIT | END | ROLLBACK | ABORT  [ WORK | TRANSACTION ]  [ ; ]
 *
 * surrounded only by whitespace and SQL comments, and rejects everything
 * else: COMMIT PREPARED / ROLLBACK PREPARED, ROLLBACK TO SAVEPOINT,
 * AND [NO] CHAIN, a second statement after the ';', and words that merely
 * start with one of the verbs (ENDx, COMMITTED, ...).
 *
 * PgSQL_Session uses it in two places where ProxySQL answers a transaction
 * end itself instead of sending it to a backend:
 *   - the poisoned-session recovery (handler_poisoned_simple_query and the
 *     extended-query equivalent);
 *   - handler_CommitRollback, when the session holds no backend transaction.
 * In both places answering anything wider than a plain transaction end would
 * silently drop work the client asked PostgreSQL to do.
 *
 * Header-only and free of ProxySQL state, so it can be unit tested directly.
 */

#ifndef PGSQL_TXN_END_CLASSIFIER_H
#define PGSQL_TXN_END_CLASSIFIER_H

#include <strings.h>

/**
 * @brief Classify a statement as a plain transaction end.
 *
 * @param sql      Statement text. May end with the null byte of a Simple Query
 *                 packet body; that byte is ignored.
 * @param sql_len  Length of @p sql in bytes, including that null byte if present.
 * @return 'C' for a plain COMMIT / END, 'R' for a plain ROLLBACK / ABORT,
 *         0 for anything else.
 */
inline char pgsql_classify_plain_txn_end(const char* sql, unsigned int sql_len) {
	// A Simple Query packet body, and a prepared statement's text, is a null-terminated
	// string. Trim it so the "is any non-whitespace content remaining?" check does not
	// treat the null byte itself as trailing junk and reject an otherwise-valid
	// statement (e.g. "ROLLBACK\0" or "ROLLBACK WORK\0").
	if (sql_len > 0 && sql[sql_len - 1] == '\0') {
		sql_len--;
	}

	// skip whitespace and SQL comments (-- to EOL, /* ... */ non-nesting) in-place.
	auto skip_ws_and_comments = [](const char*& p, unsigned int& n) {
		for (;;) {
			while (n > 0 && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) { p++; n--; }
			if (n >= 2 && p[0] == '-' && p[1] == '-') {
				p += 2; n -= 2;
				while (n > 0 && *p != '\n') { p++; n--; }
				continue;
			}
			if (n >= 2 && p[0] == '/' && p[1] == '*') {
				p += 2; n -= 2;
				while (n >= 2 && !(p[0] == '*' && p[1] == '/')) { p++; n--; }
				if (n >= 2) { p += 2; n -= 2; } else { n = 0; }
				continue;
			}
			break;
		}
	};

	// Skip leading whitespace and comments. An ORM-prepended `/* query tag */ ROLLBACK`
	// must recover, not be rejected.
	skip_ws_and_comments(sql, sql_len);

	char kind = 0;

	// Case-insensitive prefix match, followed by a word boundary so "ROLLBACKET"
	// doesn't get classified as ROLLBACK.
	auto matches_kw = [](const char* p, unsigned int n, const char* kw, unsigned int klen) -> bool {
		if (n < klen) return false;
		if (strncasecmp(p, kw, klen) != 0) return false;
		if (n == klen) return true;
		char ch = p[klen];
		return !(ch == '_' || (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9'));
	};

	// ABORT is a Postgres synonym for ROLLBACK. END is a Postgres synonym for COMMIT.
	// Both ROLLBACK and COMMIT recover the session to IDLE.
	unsigned int verb_len = 0;
	if (matches_kw(sql, sql_len, "ROLLBACK", 8)) { kind = 'R'; verb_len = 8; }
	else if (matches_kw(sql, sql_len, "ABORT", 5)) { kind = 'R'; verb_len = 5; }
	else if (matches_kw(sql, sql_len, "COMMIT", 6)) { kind = 'C'; verb_len = 6; }
	else if (matches_kw(sql, sql_len, "END", 3))    { kind = 'C'; verb_len = 3; }

	// Having identified a transaction-end verb, verify the rest of the statement
	// is a *plain* whole-tx end: no modifiers that change the semantics into
	// something ProxySQL cannot answer by itself, and no second statement
	// pipelined after it. The only modifiers we accept are:
	//   WORK | TRANSACTION   (Postgres noise-word aliases; no semantic effect)
	// Anything else is rejected, specifically:
	//   - ROLLBACK TO SAVEPOINT (partial rollback, keeps tx open);
	//   - AND CHAIN (ends the tx and opens a new one) and AND NO CHAIN;
	//   - COMMIT PREPARED / ROLLBACK PREPARED (two-phase commit: they act on a
	//     prepared transaction stored in the server, not on the session's own).
	// A poisoned session answers those with 25P02 and stays poisoned (the client
	// can then issue a plain ROLLBACK); handler_CommitRollback forwards them.
	//
	// Multi-statement Simple Query (e.g. "ROLLBACK; SELECT 1;") is rejected for
	// the same reason: answering it locally would synthesize one ROLLBACK
	// response and silently drop the second statement.
	if (kind != 0) {
		const char* rest = sql + verb_len;
		unsigned int rest_len = sql_len - verb_len;
		skip_ws_and_comments(rest, rest_len);
		// Optionally consume a single WORK or TRANSACTION noise word.
		if (matches_kw(rest, rest_len, "WORK", 4)) {
			rest += 4; rest_len -= 4;
			skip_ws_and_comments(rest, rest_len);
		} else if (matches_kw(rest, rest_len, "TRANSACTION", 11)) {
			rest += 11; rest_len -= 11;
			skip_ws_and_comments(rest, rest_len);
		}
		// Optional trailing semicolon.
		if (rest_len > 0 && *rest == ';') {
			rest++; rest_len--;
			skip_ws_and_comments(rest, rest_len);
		}
		// Anything remaining is either a savepoint/chain modifier or a second
		// pipelined statement. Either way, reject.
		if (rest_len > 0) {
			kind = 0;
		}
	}
	// RELEASE SAVEPOINT and anything else: rejected. Matches Postgres: only
	// plain ROLLBACK / COMMIT / ABORT / END end an aborted tx cleanly.
	return kind;
}

#endif // PGSQL_TXN_END_CLASSIFIER_H
