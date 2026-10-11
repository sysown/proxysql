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
 */

#include <string>
#include <sstream>
#include <memory>
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

int main(int, char**) {
	if (cl.getEnv()) return exit_status();
	plan(1 + (int)(N_REFUSED * 2) + (int)(N_NOT_REFUSED * 2) +
	     (int)N_MULTI_REFUSED + (int)N_MULTI_NOT_REFUSED + 2 + 1);

	// Pin the backend protocol: the refusals below are the libpq contract.
	{
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

	// Known gap, asserted as ACCEPTED so that closing it has to come back here. The gate
	// runs after the query processor and reads the digest, so it only sees what the digest
	// sees: a query opening with a NESTED block comment digests to the empty string, so the
	// gate falls back to the raw text, which starts with the comment.
	// It is inert: the NotificationResponse such a subscription produces is discarded
	// rather than handed to another client. Channel names carry the pid because the
	// subscription outlives this test on whichever pooled connection ran it.
	{
		std::string q = "/*/*n*/*/LISTEN lnc_nested_" + std::to_string(getpid());
		std::string st = run_simple(c, q.c_str());
		ok(st != "0A000", "simple LISTEN behind a nested block comment is accepted (known gap, got '%s')",
		   st.c_str());
		st = run_extended(c, q.c_str());
		ok(st != "0A000", "extended LISTEN behind a nested block comment is accepted (known gap, got '%s')",
		   st.c_str());
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
