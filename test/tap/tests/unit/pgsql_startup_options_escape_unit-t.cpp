/**
 * @file pgsql_startup_options_escape_unit-t.cpp
 * @brief A tracked variable value must stay a single "-c" option in the backend startup
 *        'options' string.
 *
 * When ProxySQL opens a backend connection it sends the client's tracked variables
 * (DateStyle, IntervalStyle, standard_conforming_strings, TimeZone, search_path) as
 * "-c name=value" tokens in the startup 'options' value, escaped by
 * pg_append_escaped_option_value(). The backend splits that string with pg_split_opts()
 * (src/backend/utils/init/postinit.c), which ends a token at ANY isspace() character
 * unless it is preceded by a backslash.
 *
 * The escaper used to protect only ' ' and '\\'. A client could therefore send
 * TimeZone="UTC\t-c\tstatement_timeout=1" in its startup packet: the tab passed through
 * unescaped, the backend saw an extra "-c statement_timeout=1", and since ProxySQL did not
 * track that setting, the pooled connection carried it to every later client of the same
 * user and database.
 *
 * This test checks the two layers of the fix:
 *  1. pg_append_escaped_option_value(): every value, including every single byte and the
 *     injection payload, is round-tripped through a faithful copy of pg_split_opts() and
 *     must come back as exactly one token, byte for byte.
 *  2. The validators: TimeZone now has one (the tracked-variable table entry must point to
 *     it) that rejects control characters, and the search_path validator rejects control
 *     characters inside a quoted part. Ordinary values ('UTC', 'America/New_York',
 *     '+02:00', '"my schema", public', ...) are still accepted unchanged.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "gen_utils.h"
#include "PgSQL_Variables_Validator.h"

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

// ============================================================
// Copy of PostgreSQL 16 pg_split_opts() (postinit.c), returning the tokens instead of
// filling an argv array. Kept byte-for-byte equivalent in its splitting and unescaping.
// ============================================================

static std::vector<std::string> pg_split_opts_copy(const char* optstr) {
	std::vector<std::string> argv;
	std::string s;

	while (*optstr) {
		bool last_was_escape = false;

		s.clear();

		/* skip over leading space */
		while (isspace((unsigned char)*optstr))
			optstr++;

		if (*optstr == '\0')
			break;

		/*
		 * Parse a single option, stopping at the first space, unless it's
		 * escaped.
		 */
		while (*optstr) {
			if (isspace((unsigned char)*optstr) && !last_was_escape)
				break;

			if (!last_was_escape && *optstr == '\\')
				last_was_escape = true;
			else {
				last_was_escape = false;
				s += *optstr;
			}

			optstr++;
		}

		argv.push_back(s);
	}
	return argv;
}

// Builds "-c <name>=<escaped value>" exactly like build_and_record_startup_session_params()
// and returns true when the backend would see exactly the two tokens "-c" and
// "<name>=<value>", with the value unchanged.
static bool single_option_round_trip(const char* name, const std::string& value) {
	std::string opts = "-c ";
	opts += name;
	opts += "=";
	pg_append_escaped_option_value(opts, value.c_str());
	const std::vector<std::string> argv = pg_split_opts_copy(opts.c_str());
	return argv.size() == 2 && argv[0] == "-c" && argv[1] == std::string(name) + "=" + value;
}

static std::string printable(const std::string& v) {
	std::string out;
	for (unsigned char c : v) {
		if (c >= 0x20 && c < 0x7f && c != '\\') {
			out += (char)c;
		} else {
			char buf[8];
			snprintf(buf, sizeof(buf), "\\x%02x", c);
			out += buf;
		}
	}
	return out;
}

// ============================================================
// Layer 1: escaping
// ============================================================

static const std::vector<std::string> escape_cases = {
	"GMT",
	"UTC",
	"America/New_York",
	"+02:00",
	"EST5EDT,M3.2.0,M11.1.0",
	"ISO, MDY",
	"\"$user\", public",
	"\"my schema\", public",
	"a\\b",
	"trailing\\",
	"\\",
	"",
	"  leading and trailing  ",
	"tab\there",
	"nl\nhere",
	"cr\rhere",
	"vt\vhere",
	"ff\fhere",
	" \t\n\v\f\r\\ ",
	"UTC\t-c\tstatement_timeout=1",
	"UTC\n-c\ndefault_transaction_read_only=on",
	"'a\t-c\tstatement_timeout=1\t-c\tsearch_path=b'",
};

static void test_escape_round_trip() {
	for (const auto& v : escape_cases) {
		ok(single_option_round_trip("TimeZone", v),
		   "escape: '%s' stays one option and round-trips unchanged", printable(v).c_str());
	}
}

// Every possible single byte, alone and between two letters, must survive as one token.
static void test_escape_every_byte() {
	int failures = 0;
	int first_bad = -1;
	for (int b = 1; b < 256; b++) {
		const std::string alone(1, (char)b);
		const std::string mid = std::string("a") + (char)b + "b";
		if (!single_option_round_trip("TimeZone", alone) || !single_option_round_trip("TimeZone", mid)) {
			if (first_bad < 0) first_bad = b;
			failures++;
		}
	}
	ok(failures == 0, "escape: all bytes 0x01-0xff round-trip as one option (failures=%d, first=0x%02x)",
	   failures, first_bad < 0 ? 0 : first_bad);
}

// The whole tracked-variable block: a list of options must keep its option count.
static void test_escape_option_count() {
	const char* names[] = { "DateStyle", "TimeZone", "search_path" };
	const char* values[] = { "ISO, MDY", "UTC\t-c\tstatement_timeout=1", "\"a b\",\tpublic" };
	std::string opts;
	const char* sep = "";
	for (int i = 0; i < 3; i++) {
		opts += sep;
		opts += "-c ";
		opts += names[i];
		opts += "=";
		pg_append_escaped_option_value(opts, values[i]);
		sep = " ";
	}
	const std::vector<std::string> argv = pg_split_opts_copy(opts.c_str());
	ok(argv.size() == 6, "escape: three -c options give six tokens (got %zu)", argv.size());
	bool same = argv.size() == 6;
	for (int i = 0; same && i < 3; i++) {
		same = argv[2 * i] == "-c" && argv[2 * i + 1] == std::string(names[i]) + "=" + values[i];
	}
	ok(same, "escape: every option value comes back unchanged");
}

// The fast path: a value needing no escape is appended as is, and output is appended.
static void test_escape_appends() {
	std::string out = "prefix:";
	pg_append_escaped_option_value(out, "on");
	ok(out == "prefix:on", "escape: plain value appended unchanged (got '%s')", out.c_str());
	out = "p:";
	pg_append_escaped_option_value(out, "a b\tc\\");
	ok(out == "p:a\\ b\\\tc\\\\", "escape: space, tab and backslash each get one backslash");
}

// ============================================================
// Layer 2: validators
// ============================================================

static bool validate(const pgsql_variable_validator* v, const char* value, std::string* transformed_out = nullptr) {
	char* transformed = nullptr;
	const bool r = v->validate(value, &v->params, nullptr, &transformed);
	if (transformed_out) *transformed_out = transformed ? transformed : value;
	free(transformed);
	return r;
}

static void test_timezone_validator() {
	const pgsql_variable_validator* v = pgsql_tracked_variables[PGSQL_TIMEZONE].validator;
	ok(v != nullptr && v->validate != nullptr, "TimeZone: tracked variable has a validator");
	if (v == nullptr || v->validate == nullptr) {
		// Keep the plan: the remaining checks cannot run without a validator.
		for (int i = 0; i < 1 + 11 + 5; i++) ok(0, "TimeZone: skipped, no validator");
		return;
	}
	ok(v == &pgsql_variable_validator_timezone, "TimeZone: validator is pgsql_variable_validator_timezone");

	const char* good[] = {
		"GMT", "UTC", "America/New_York", "Europe/Rome", "+02:00", "-5", "5.5",
		"EST5EDT,M3.2.0,M11.1.0", "<+0330>-3:30", "INTERVAL '+02:00' HOUR TO MINUTE", "LOCAL",
	};
	for (const char* g : good) {
		std::string t;
		const bool r = validate(v, g, &t);
		ok(r && t == g, "TimeZone: '%s' accepted unchanged", g);
	}

	const char* bad[] = {
		"UTC\t-c\tstatement_timeout=1",
		"UTC\n-c\nrole=admin",
		"UTC\r",
		"\x01UTC",
		"UTC\x7f",
	};
	for (const char* b : bad) {
		ok(validate(v, b) == false, "TimeZone: '%s' rejected", printable(b).c_str());
	}
}

static void test_search_path_validator() {
	const pgsql_variable_validator* v = &pgsql_variable_validator_search_path;
	std::string t;

	ok(validate(v, "\"my schema\", public", &t) && t == "\"my schema\", public",
	   "search_path: quoted name with a space accepted (got '%s')", t.c_str());
	ok(validate(v, "\"$user\", public", &t) && t == "\"$user\", public",
	   "search_path: default value accepted (got '%s')", t.c_str());
	// Whitespace between items is a separator, and is not kept in the normalized value.
	ok(validate(v, "a,\tb", &t) && t == "a, b",
	   "search_path: tab between items still accepted, normalized to 'a, b' (got '%s')", printable(t).c_str());

	ok(validate(v, "'a\t-c\tstatement_timeout=1\t-c\tsearch_path=b'") == false,
	   "search_path: tab inside a quoted part rejected");
	ok(validate(v, "\"a\nb\"") == false, "search_path: newline inside a quoted part rejected");
	ok(validate(v, "\"a\x7f" "b\"") == false, "search_path: DEL inside a quoted part rejected");
}

int main() {
	plan(
		22      // test_escape_round_trip
		+ 1     // test_escape_every_byte
		+ 2     // test_escape_option_count
		+ 2     // test_escape_appends
		+ 2 + 11 + 5 // test_timezone_validator
		+ 6     // test_search_path_validator
	);
	test_init_minimal();

	test_escape_round_trip();
	test_escape_every_byte();
	test_escape_option_count();
	test_escape_appends();
	test_timezone_validator();
	test_search_path_validator();

	test_cleanup_minimal();
	return exit_status();
}
