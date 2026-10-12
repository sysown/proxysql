/**
 * @file pgsql-listen_notify_contract-t.cpp
 * @brief Pins the LISTEN refusal contract on both wire protocols.
 *
 * On the libpq path ProxySQL answers LISTEN with 0A000, because libpq never
 * surfaces a NotificationResponse to ProxySQL at all: the subscription would be
 * accepted and then deliver nothing. The refusal has to hold for every spelling of
 * the statement, not just the one with a single space after the keyword.
 *
 * This test forces the libpq path. LISTEN is supported on the native backend
 * protocol -- that is covered by pgsql-native_notify-t -- so without pinning the
 * mode here every assertion below would flip the moment the default changes.
 *
 * PostgreSQL's lexer skips leading whitespace and comments before the first
 * token, and accepts any whitespace between the keyword and the channel. Each
 * case below is therefore the same statement to the backend, and each one used
 * to be a different statement to ProxySQL -- four of them reached the backend and
 * registered a real subscription.
 *
 * Both gates now run after the query processor and read the normalized digest,
 * which is what collapses those spellings into one. They are still asserted
 * separately, because they live in different functions and can drift apart.
 *
 * A Simple Query can carry several statements, and a LISTEN behind another one
 * subscribes just the same, so the simple-query gate checks every statement of the
 * digest (issue #6438). The extended protocol cannot: PostgreSQL rejects a Parse
 * holding more than one statement.
 *
 * With pgsql-query_digests_keep_comment the digest keeps block comments, so the
 * keyword of a statement is the first token past them; and a comment longer than
 * the tokenizer keeps (FIRST_COMMENT_MAX_LENGTH, 1024) reaches the digest without its
 * terminator, after which the gates look for LISTEN anywhere. Both used to let a LISTEN
 * through, and are exercised with the variable switched on for this test only.
 */

#include <string>
#include <sstream>
#include <memory>
#include <vector>
#include <unistd.h>
#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include "pgsql_native_tier.h"

CommandLine cl;
using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

static PGConnPtr mk() {
	std::stringstream ss;
	ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
	   << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
	   << " dbname=" << cl.pgsql_username << " sslmode=disable";
	return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}

static std::string sqlstate_of(PGresult* r) {
	const char* s = PQresultErrorField(r, PG_DIAG_SQLSTATE);
	return s ? s : "";
}

// A rejected statement can leave the connection unusable; reconnect if so, so one
// failure does not cascade into every later assertion.
static void ensure_usable(PGConnPtr& c) {
	if (!c || PQstatus(c.get()) != CONNECTION_OK) c = mk();
}

// PQexec sends a Query message; PQexecParams with zero parameters sends
// Parse/Bind/Describe/Execute/Sync. The two gates are in different functions.
static std::string run_simple(PGConnPtr& c, const char* q) {
	ensure_usable(c);
	PGresult* r = PQexec(c.get(), q);
	std::string st = sqlstate_of(r);
	PQclear(r);
	return st;
}

static std::string run_extended(PGConnPtr& c, const char* q) {
	ensure_usable(c);
	PGresult* r = PQexecParams(c.get(), q, 0, NULL, NULL, NULL, NULL, 0);
	std::string st = sqlstate_of(r);
	PQclear(r);
	return st;
}

struct Case { const char* sql; const char* label; };

// Every spelling PostgreSQL accepts as "LISTEN <channel>".
static const Case REFUSED[] = {
	{ "LISTEN lnc_plain",            "plain" },
	{ " LISTEN lnc_lead_space",      "leading space" },
	{ "\tLISTEN lnc_lead_tab",       "leading tab" },
	{ "\nLISTEN lnc_lead_nl",        "leading newline" },
	{ "LISTEN\tlnc_sep_tab",         "tab between keyword and channel" },
	{ "/*x*/LISTEN lnc_blockcmt",    "leading block comment" },
	{ "--c\nLISTEN lnc_linecmt",     "leading line comment" },
	{ "LISTEN\"lnc_quoted\"",        "quoted channel, no space" },
	{ "LISTEN/*c*/lnc_cmtsep",       "block comment between keyword and channel" },
	{ "LISTEN",                      "bare LISTEN" },
	{ "/*/*n*/*/LISTEN lnc_nested",  "leading nested block comment" },
};

// Statements that merely start with or contain the letters; refusing any of these
// would mean the keyword match is too greedy.
static const Case NOT_REFUSED[] = {
	{ "UNLISTEN lnc_plain",          "UNLISTEN" },
	{ "SELECT 'LISTEN x'",           "LISTEN inside a string literal" },
	{ "SELECT 1 AS listener",        "identifier starting with LISTEN" },
	{ "/*unterminated LISTEN x",     "unterminated comment" },
};

// A LISTEN that is not the first statement of a Simple Query (issue #6438).
static const Case MULTI_REFUSED[] = {
	{ "SELECT 1; LISTEN lnc_multi",          "after another statement" },
	{ "SELECT 1;LISTEN lnc_multi_nosp",      "right after the ';'" },
	{ "SELECT 1;\n\tLISTEN lnc_multi_ws",    "after a newline and a tab" },
	{ "SELECT 1; /*c*/ LISTEN lnc_multi_cmt", "behind a comment" },
	{ "SELECT 1; SELECT 2; LISTEN lnc_multi3", "as the third statement" },
	{ "UNLISTEN *; LISTEN lnc_multi_un",     "after UNLISTEN *" },
};

// A ';' that is not a statement boundary, before something that reads like LISTEN.
static const Case MULTI_NOT_REFUSED[] = {
	{ "SELECT 'a; LISTEN b'",                "inside a string literal" },
	{ "SELECT 1 AS \"a; LISTEN b\"",         "inside a quoted identifier" },
	{ "SELECT $$a; LISTEN b$$",              "inside a dollar-quoted string" },
	{ "SELECT 1; SELECT 2 AS listener",      "identifier starting with LISTEN" },
	{ "SELECT 1; UNLISTEN lnc_multi",        "UNLISTEN after another statement" },
};

static const size_t N_REFUSED = sizeof(REFUSED) / sizeof(REFUSED[0]);
static const size_t N_NOT_REFUSED = sizeof(NOT_REFUSED) / sizeof(NOT_REFUSED[0]);
static const size_t N_MULTI_REFUSED = sizeof(MULTI_REFUSED) / sizeof(MULTI_REFUSED[0]);
static const size_t N_MULTI_NOT_REFUSED = sizeof(MULTI_NOT_REFUSED) / sizeof(MULTI_NOT_REFUSED[0]);

// Longer than the 1023 bytes of a block comment the digest keeps with keep_comment.
static const std::string LONG_CMT = "/*" + std::string(1100, 'x') + "*/";

// With pgsql-query_digests_keep_comment=true. Refused on both protocols.
static const std::vector<std::pair<std::string, std::string>> KEEP_REFUSED = {
	{ "/*c*/ LISTEN lnc_kc_lead",                  "behind a kept comment" },
	{ LONG_CMT + " LISTEN lnc_kc_long",            "behind a kept comment cut short" },
};
// Simple Query only: a Parse cannot hold more than one statement.
static const std::vector<std::pair<std::string, std::string>> KEEP_MULTI_REFUSED = {
	{ "SELECT 1; /*c*/ LISTEN lnc_kc_multi",       "after another statement, behind a kept comment" },
	{ LONG_CMT + " SELECT 1; LISTEN lnc_kc_long2", "after a kept comment cut short and another statement" },
};
static const std::vector<std::pair<std::string, std::string>> KEEP_NOT_REFUSED = {
	{ "SELECT 1; /* LISTEN x */ SELECT 2",         "LISTEN only inside a kept comment" },
	{ LONG_CMT + " SELECT 1; SELECT 2",            "a kept comment cut short, no LISTEN" },
};

// With pgsql-query_digests=false there is no digest: the gate reads the query itself.
// Without one it used to check only the first statement (#6438 review).
static const std::vector<std::pair<std::string, std::string>> NODIGEST_MULTI_REFUSED = {
	{ "SELECT 1; LISTEN lnc_nd_multi",         "after another statement" },
	{ "SELECT 1;\n\tLISTEN lnc_nd_ws",         "after a newline and a tab" },
	{ "SELECT 1; /*c*/ LISTEN lnc_nd_cmt",     "behind a comment" },
};
static const std::vector<std::pair<std::string, std::string>> NODIGEST_NOT_REFUSED = {
	{ "SELECT 'a; LISTEN b'",                  "inside a string literal" },
	{ "SELECT $$a; LISTEN b$$",                "inside a dollar-quoted string" },
	{ "SELECT 1 -- ; LISTEN b",                "inside a line comment" },
};

static std::string admin_scalar(PGconn* admin, const char* q) {
	PGresult* r = PQexec(admin, q);
	std::string v = (PQresultStatus(r) == PGRES_TUPLES_OK && PQntuples(r) == 1) ? PQgetvalue(r, 0, 0) : "";
	PQclear(r);
	return v;
}

int main(int, char**) {
	if (cl.getEnv()) return exit_status();
	plan(1 + (int)(N_REFUSED * 2) + (int)(N_NOT_REFUSED * 2) +
	     (int)N_MULTI_REFUSED + (int)N_MULTI_NOT_REFUSED + 1 +
	     1 + (int)(KEEP_REFUSED.size() * 2) + (int)KEEP_MULTI_REFUSED.size() + (int)KEEP_NOT_REFUSED.size() + 1 +
	     1 + (int)NODIGEST_MULTI_REFUSED.size() + (int)NODIGEST_NOT_REFUSED.size() + 1 + 1);

	// Pin the backend protocol: the refusals below are the libpq contract.
	std::stringstream as;
	as << "host=" << cl.pgsql_admin_host << " port=" << cl.pgsql_admin_port
	   << " user=" << cl.admin_username << " password=" << cl.admin_password;
	PGConnPtr admin(PQconnectdb(as.str().c_str()), &PQfinish);
	if (admin && PQstatus(admin.get()) == CONNECTION_OK) {
		if (pgsql_native_supported(admin.get())) {
			PQclear(PQexec(admin.get(), "SET pgsql-use_native_backend_protocol='false'"));
			PQclear(PQexec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME"));
		}
	} else {
		diag("could not reach admin to pin the backend protocol");
	}

	PGConnPtr c = mk();
	ok(c && PQstatus(c.get()) == CONNECTION_OK, "connected for listen/notify contract");
	if (!c || PQstatus(c.get()) != CONNECTION_OK) return exit_status();

	for (size_t i = 0; i < N_REFUSED; i++) {
		std::string st = run_simple(c, REFUSED[i].sql);
		ok(st == "0A000", "simple LISTEN refused with 0A000 -- %s (got '%s')",
		   REFUSED[i].label, st.c_str());
	}
	for (size_t i = 0; i < N_REFUSED; i++) {
		std::string st = run_extended(c, REFUSED[i].sql);
		ok(st == "0A000", "extended LISTEN refused with 0A000 -- %s (got '%s')",
		   REFUSED[i].label, st.c_str());
	}
	for (size_t i = 0; i < N_NOT_REFUSED; i++) {
		std::string st = run_simple(c, NOT_REFUSED[i].sql);
		ok(st != "0A000", "simple statement not refused as LISTEN -- %s (got '%s')",
		   NOT_REFUSED[i].label, st.c_str());
	}
	for (size_t i = 0; i < N_NOT_REFUSED; i++) {
		std::string st = run_extended(c, NOT_REFUSED[i].sql);
		ok(st != "0A000", "extended statement not refused as LISTEN -- %s (got '%s')",
		   NOT_REFUSED[i].label, st.c_str());
	}
	for (size_t i = 0; i < N_MULTI_REFUSED; i++) {
		std::string st = run_simple(c, MULTI_REFUSED[i].sql);
		ok(st == "0A000", "multi-statement LISTEN refused with 0A000 -- %s (got '%s')",
		   MULTI_REFUSED[i].label, st.c_str());
	}
	for (size_t i = 0; i < N_MULTI_NOT_REFUSED; i++) {
		std::string st = run_simple(c, MULTI_NOT_REFUSED[i].sql);
		ok(st != "0A000", "multi-statement query not refused as LISTEN -- %s (got '%s')",
		   MULTI_NOT_REFUSED[i].label, st.c_str());
	}

	// pgsql-query_digests_keep_comment, for this block only. A worker thread picks up new
	// variables between two of its loops, so the session's own thread is waited for: a
	// marker comment shows up in the digest once it digests with comments kept.
	{
		const std::string prev = admin_scalar(admin.get(),
			"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-query_digests_keep_comment'");
		PQclear(PQexec(admin.get(), "SET pgsql-query_digests_keep_comment='true'"));
		PQclear(PQexec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME"));
		const std::string marker = "lnc_kc_probe_" + std::to_string(getpid());
		const std::string probe = "SELECT /*" + marker + "*/ 1";
		const std::string seen = "SELECT COUNT(*) FROM stats_pgsql_query_digest WHERE digest_text LIKE '%" + marker + "%'";
		bool kept = false;
		for (int i = 0; i < 50 && !kept; i++) {
			run_simple(c, probe.c_str());
			// An empty answer is a failed query, not a kept comment.
			const std::string count = admin_scalar(admin.get(), seen.c_str());
			kept = !count.empty() && count != "0";
			if (!kept) usleep(100000);
		}
		ok(kept, "digests keep comments after enabling pgsql-query_digests_keep_comment");

		for (const auto& k : KEEP_REFUSED) {
			std::string st = run_simple(c, k.first.c_str());
			ok(st == "0A000", "keep_comment: simple LISTEN refused with 0A000 -- %s (got '%s')",
			   k.second.c_str(), st.c_str());
			st = run_extended(c, k.first.c_str());
			ok(st == "0A000", "keep_comment: extended LISTEN refused with 0A000 -- %s (got '%s')",
			   k.second.c_str(), st.c_str());
		}
		for (const auto& k : KEEP_MULTI_REFUSED) {
			std::string st = run_simple(c, k.first.c_str());
			ok(st == "0A000", "keep_comment: multi-statement LISTEN refused with 0A000 -- %s (got '%s')",
			   k.second.c_str(), st.c_str());
		}
		for (const auto& k : KEEP_NOT_REFUSED) {
			std::string st = run_simple(c, k.first.c_str());
			ok(st != "0A000", "keep_comment: query not refused as LISTEN -- %s (got '%s')",
			   k.second.c_str(), st.c_str());
		}

		const std::string restore = "SET pgsql-query_digests_keep_comment='" + (prev.empty() ? std::string("false") : prev) + "'";
		// Left enabled, it would change the digests every later test in the group sees.
		bool restored = true;
		for (const char* q : { restore.c_str(), "LOAD PGSQL VARIABLES TO RUNTIME" }) {
			PGresult* r = PQexec(admin.get(), q);
			if (PQresultStatus(r) != PGRES_COMMAND_OK) {
				diag("restore failed: %s -- %s", q, PQerrorMessage(admin.get()));
				restored = false;
			}
			PQclear(r);
		}
		ok(restored, "pgsql-query_digests_keep_comment restored to '%s'", prev.c_str());
	}

	// pgsql-query_digests=false, for this block only. The session's thread has picked it up
	// once a query with a fresh marker no longer shows up among the digests.
	{
		const std::string prev = admin_scalar(admin.get(),
			"SELECT variable_value FROM global_variables WHERE variable_name='pgsql-query_digests'");
		PQclear(PQexec(admin.get(), "SET pgsql-query_digests='false'"));
		PQclear(PQexec(admin.get(), "LOAD PGSQL VARIABLES TO RUNTIME"));
		bool off = false;
		for (int i = 0; i < 50 && !off; i++) {
			const std::string marker = "lnc_nd_probe_" + std::to_string(getpid()) + "_" + std::to_string(i);
			const std::string probe = "SELECT 1 AS " + marker; // an identifier stays in the digest
			run_simple(c, probe.c_str());
			const std::string seen = "SELECT COUNT(*) FROM stats_pgsql_query_digest WHERE digest_text LIKE '%" +
				marker + "%'";
			const std::string count = admin_scalar(admin.get(), seen.c_str());
			off = count == "0";
			if (!off) usleep(100000);
		}
		ok(off, "queries are no longer digested after disabling pgsql-query_digests");

		for (const auto& k : NODIGEST_MULTI_REFUSED) {
			std::string st = run_simple(c, k.first.c_str());
			ok(st == "0A000", "no digest: multi-statement LISTEN refused with 0A000 -- %s (got '%s')",
			   k.second.c_str(), st.c_str());
		}
		for (const auto& k : NODIGEST_NOT_REFUSED) {
			std::string st = run_simple(c, k.first.c_str());
			ok(st != "0A000", "no digest: query not refused as LISTEN -- %s (got '%s')",
			   k.second.c_str(), st.c_str());
		}
		{
			std::string st = run_extended(c, "/*c*/ LISTEN lnc_nd_ext");
			ok(st == "0A000", "no digest: extended LISTEN behind a comment refused with 0A000 (got '%s')", st.c_str());
		}

		const std::string restore = "SET pgsql-query_digests='" + (prev.empty() ? std::string("true") : prev) + "'";
		bool restored = true;
		for (const char* q : { restore.c_str(), "LOAD PGSQL VARIABLES TO RUNTIME" }) {
			PGresult* r = PQexec(admin.get(), q);
			if (PQresultStatus(r) != PGRES_COMMAND_OK) {
				diag("restore failed: %s -- %s", q, PQerrorMessage(admin.get()));
				restored = false;
			}
			PQclear(r);
		}
		ok(restored, "pgsql-query_digests restored to '%s'", prev.c_str());
	}

	// NOTIFY is a plain statement and stays supported; only delivery is not.
	{
		PGConnPtr c2 = mk();
		PGresult* rn = PQexec(c2.get(), "NOTIFY lnc_plain, 'hello'");
		bool notify_ok = (PQresultStatus(rn) == PGRES_COMMAND_OK);
		PQclear(rn);
		PGresult* rq = PQexec(c2.get(), "SELECT 1");
		bool still_usable = (PQresultStatus(rq) == PGRES_TUPLES_OK);
		PQclear(rq);
		ok(notify_ok && still_usable, "NOTIFY completes cleanly and connection remains usable");
	}

	return exit_status();
}
