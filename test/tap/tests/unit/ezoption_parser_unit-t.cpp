/**
 * @file ezoption_parser_unit-t.cpp
 * @brief Unit tests for ezOptionParser (include/ezOptionParser.hpp).
 *
 * This is a standalone header-only CLI option parser. Tests exercise:
 *   - Flag options (--help), isSet() checks
 *   - String options with values (--config <path>)
 *   - Integer options with values (--port <num>)
 *   - Default values when option not provided
 *   - Required option missing detection (gotRequired)
 *   - Unknown option handling
 *   - Short option aliases (-h for --help)
 *   - Multiple values for same option (repeated flags)
 *   - Delimiter-separated multi-value args
 *   - Usage/overview string generation
 *   - prettyPrint output
 *   - exportFile / importFile round-trip
 *   - gotExpected validation
 *   - gotValid with ezOptionValidator
 *   - resetArgs preserving option definitions
 *   - firstArgs / lastArgs capture
 *   - Three-flag and four-flag add() overloads
 *   - Float and double option get
 *   - getMultiInts for repeated delimited options
 */

#include "tap.h"
#include "ezOptionParser.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <cstdlib>

using namespace ez;

/* ------------------------------------------------------------------ */
/* Helper: build a const char* argv[] from an initializer-style list. */
/* ------------------------------------------------------------------ */
struct ArgV {
	std::vector<std::string> store;
	std::vector<const char*> ptrs;

	ArgV(std::initializer_list<const char*> args) {
		for (auto a : args) store.emplace_back(a);
		for (auto& s : store) ptrs.push_back(s.c_str());
	}
	int argc() const { return static_cast<int>(ptrs.size()); }
	const char** argv() { return ptrs.data(); }
};

/* ================================================================== */
/* 1. Flag option: --help present / absent via isSet()                */
/* ================================================================== */
static void test_flag_is_set() {
	{
		ezOptionParser opt;
		opt.add("", false, 0, 0, "Show help", "--help");

		ArgV a{"prog", "--help"};
		opt.parse(a.argc(), a.argv());

		ok(opt.isSet("--help") != 0, "isSet returns true when --help present");
	}
	{
		ezOptionParser opt;
		opt.add("", false, 0, 0, "Show help", "--help");

		ArgV a{"prog"};
		opt.parse(a.argc(), a.argv());

		ok(opt.isSet("--help") == 0, "isSet returns false when --help absent");
	}
}

/* ================================================================== */
/* 2. String option: --config <path>                                  */
/* ================================================================== */
static void test_string_option() {
	ezOptionParser opt;
	opt.add("", false, 1, 0, "Config path", "--config", "-c");

	ArgV a{"prog", "--config", "/etc/proxysql.cnf"};
	opt.parse(a.argc(), a.argv());

	ok(opt.isSet("--config") != 0, "--config is set after parse");

	std::string val;
	opt.get("--config")->getString(val);
	ok(val == "/etc/proxysql.cnf", "getString returns correct config path");
}

/* ================================================================== */
/* 3. Integer option: --port <num>                                    */
/* ================================================================== */
static void test_integer_option() {
	ezOptionParser opt;
	opt.add("3306", false, 1, 0, "Port number", "--port", "-p");

	ArgV a{"prog", "--port", "6033"};
	opt.parse(a.argc(), a.argv());

	int port = 0;
	opt.get("--port")->getInt(port);
	ok(port == 6033, "getInt returns parsed port value 6033");
}

/* ================================================================== */
/* 4. Default values when option not provided                         */
/* ================================================================== */
static void test_default_values() {
	ezOptionParser opt;
	opt.add("3306", false, 1, 0, "Port number", "--port");
	opt.add("/etc/proxysql.cnf", false, 1, 0, "Config path", "--config");

	ArgV a{"prog"};
	opt.parse(a.argc(), a.argv());

	ok(opt.isSet("--port") == 0, "--port is not set (default only)");

	int port = 0;
	opt.get("--port")->getInt(port);
	ok(port == 3306, "getInt returns default 3306 when --port not given");

	std::string cfg;
	opt.get("--config")->getString(cfg);
	ok(cfg == "/etc/proxysql.cnf", "getString returns default config path");
}

/* ================================================================== */
/* 5. Required option missing -> gotRequired reports it               */
/* ================================================================== */
static void test_required_missing() {
	ezOptionParser opt;
	opt.add("", true, 1, 0, "Required input file", "--input");

	ArgV a{"prog"};
	opt.parse(a.argc(), a.argv());

	std::vector<std::string> bad;
	bool allGood = opt.gotRequired(bad);
	ok(!allGood, "gotRequired returns false when required option missing");
	ok(bad.size() == 1, "gotRequired reports exactly one missing option");
	ok(bad.size() > 0 && bad[0] == "--input",
	   "gotRequired names --input as the missing option");
}

/* ================================================================== */
/* 6. Required option present -> gotRequired passes                   */
/* ================================================================== */
static void test_required_present() {
	ezOptionParser opt;
	opt.add("", true, 1, 0, "Required input file", "--input");

	ArgV a{"prog", "--input", "data.csv"};
	opt.parse(a.argc(), a.argv());

	std::vector<std::string> bad;
	bool allGood = opt.gotRequired(bad);
	ok(allGood, "gotRequired returns true when required option is present");
	ok(bad.empty(), "gotRequired reports no missing options");
}

/* ================================================================== */
/* 7. Unknown option handling                                         */
/* ================================================================== */
static void test_unknown_options() {
	// Unknown args between known flags are captured in unknownArgs.
	// Args after the last known flag go to lastArgs instead.
	ezOptionParser opt;
	opt.add("", false, 0, 0, "Help", "--help");
	opt.add("", false, 0, 0, "Verbose", "--verbose");

	// --bogus sits between --help and --verbose, so it's a true unknown arg
	ArgV a{"prog", "--help", "--bogus", "--verbose"};
	opt.parse(a.argc(), a.argv());

	ok(opt.unknownArgs.size() == 1,
	   "One unknown arg captured (--bogus between known flags)");
	ok(opt.unknownArgs.size() >= 1 && *opt.unknownArgs[0] == "--bogus",
	   "Unknown arg is --bogus");

	// Args after last flag go to lastArgs
	ArgV b{"prog", "--help", "trailing"};
	ezOptionParser opt2;
	opt2.add("", false, 0, 0, "Help", "--help");
	opt2.parse(b.argc(), b.argv());
	ok(opt2.lastArgs.size() == 1 && *opt2.lastArgs[0] == "trailing",
	   "Args after last flag go to lastArgs, not unknownArgs");
}

/* ================================================================== */
/* 8. Short option alias (-h for --help)                              */
/* ================================================================== */
static void test_short_alias() {
	ezOptionParser opt;
	opt.add("", false, 0, 0, "Show help", "-h", "--help");

	{
		ArgV a{"prog", "-h"};
		opt.parse(a.argc(), a.argv());
		ok(opt.isSet("-h") != 0, "-h is set when short alias used");
		ok(opt.isSet("--help") != 0, "--help also set via alias");
	}
}

/* ================================================================== */
/* 9. Multiple values for same option (repeated flag)                 */
/* ================================================================== */
static void test_multiple_values() {
	ezOptionParser opt;
	opt.add("", false, 1, 0, "Include path", "--include", "-I");

	ArgV a{"prog", "--include", "/usr/include", "--include", "/usr/local/include"};
	opt.parse(a.argc(), a.argv());

	ok(opt.isSet("--include") != 0, "--include is set");

	std::vector< std::vector<std::string> > multi;
	opt.get("--include")->getMultiStrings(multi);
	ok(multi.size() == 2, "Two instances of --include captured");
	ok(multi.size() >= 1 && multi[0].size() >= 1 && multi[0][0] == "/usr/include",
	   "First --include value is /usr/include");
	ok(multi.size() >= 2 && multi[1].size() >= 1 && multi[1][0] == "/usr/local/include",
	   "Second --include value is /usr/local/include");
}

/* ================================================================== */
/* 10. Usage/overview string generation                               */
/* ================================================================== */
static void test_usage_generation() {
	ezOptionParser opt;
	opt.overview = "My Tool Description";
	opt.syntax   = "mytool [OPTIONS]";
	opt.example  = "  mytool --help\n\n";
	opt.footer   = "Copyright 2025\n";

	opt.add("", false, 0, 0, "Display help", "-h", "--help");
	opt.add("6033", false, 1, 0, "Listen port", "-p", "--port");

	std::string usage;
	opt.getUsage(usage);

	ok(usage.find("My Tool Description") != std::string::npos,
	   "Usage contains overview text");
	ok(usage.find("mytool [OPTIONS]") != std::string::npos,
	   "Usage contains syntax text");
	ok(usage.find("--help") != std::string::npos,
	   "Usage contains --help flag");
	ok(usage.find("--port") != std::string::npos,
	   "Usage contains --port flag");
	ok(usage.find("Display help") != std::string::npos,
	   "Usage contains help description for --help");
	ok(usage.find("Listen port") != std::string::npos,
	   "Usage contains help description for --port");
	ok(usage.find("EXAMPLES:") != std::string::npos,
	   "Usage contains EXAMPLES section");
	ok(usage.find("Copyright 2025") != std::string::npos,
	   "Usage contains footer text");
}

/* ================================================================== */
/* 11. Delimiter-separated multi-value args (--dims 100,200,300)      */
/* ================================================================== */
static void test_delimited_args() {
	ezOptionParser opt;
	opt.add("10,20,30", false, -1, ',', "Dimensions", "--dims");

	ArgV a{"prog", "--dims", "100,200,300"};
	opt.parse(a.argc(), a.argv());

	std::vector<int> vals;
	opt.get("--dims")->getInts(vals);
	ok(vals.size() == 3, "getInts returns 3 delimited values");
	ok(vals.size() >= 3 && vals[0] == 100, "First dim is 100");
	ok(vals.size() >= 3 && vals[1] == 200, "Second dim is 200");
	ok(vals.size() >= 3 && vals[2] == 300, "Third dim is 300");
}

/* ================================================================== */
/* 12. Delimited defaults when option not provided                    */
/* ================================================================== */
static void test_delimited_defaults() {
	ezOptionParser opt;
	opt.add("10,20,30", false, -1, ',', "Dimensions", "--dims");

	ArgV a{"prog"};
	opt.parse(a.argc(), a.argv());

	std::vector<int> vals;
	opt.get("--dims")->getInts(vals);
	ok(vals.size() == 3, "Default getInts returns 3 values");
	ok(vals.size() >= 3 && vals[0] == 10, "Default first dim is 10");
	ok(vals.size() >= 3 && vals[1] == 20, "Default second dim is 20");
	ok(vals.size() >= 3 && vals[2] == 30, "Default third dim is 30");
}

/* ================================================================== */
/* 13. prettyPrint produces non-empty output                          */
/* ================================================================== */
static void test_pretty_print() {
	ezOptionParser opt;
	opt.add("", false, 0, 0, "Help", "--help");
	opt.add("42", false, 1, 0, "Port", "--port");

	ArgV a{"prog", "--port", "8080"};
	opt.parse(a.argc(), a.argv());

	std::string out;
	opt.prettyPrint(out);
	ok(!out.empty(), "prettyPrint produces non-empty output");
	ok(out.find("--port") != std::string::npos, "prettyPrint contains --port");
	ok(out.find("8080") != std::string::npos, "prettyPrint contains value 8080");
}

/* ================================================================== */
/* 14. exportFile / importFile round-trip                             */
/* ================================================================== */
static void test_export_import() {
	const char* tmpfile = "/tmp/ezoption_test_export.txt";

	// Export
	{
		ezOptionParser opt;
		opt.add("", false, 1, 0, "Name", "--name");
		opt.add("99", false, 1, 0, "Count", "--count");

		ArgV a{"prog", "--name", "hello", "--count", "42"};
		opt.parse(a.argc(), a.argv());

		bool exported = opt.exportFile(tmpfile);
		ok(exported, "exportFile succeeds");
	}

	// Import into fresh parser
	{
		ezOptionParser opt;
		opt.add("", false, 1, 0, "Name", "--name");
		opt.add("99", false, 1, 0, "Count", "--count");

		bool imported = opt.importFile(tmpfile);
		ok(imported, "importFile succeeds");

		std::string name;
		opt.get("--name")->getString(name);
		ok(name == "hello", "Imported --name is 'hello'");

		int count = 0;
		opt.get("--count")->getInt(count);
		ok(count == 42, "Imported --count is 42");
	}

	// Cleanup
	std::remove(tmpfile);
}

/* ================================================================== */
/* 15. importFile returns false for non-existent file                 */
/* ================================================================== */
static void test_import_nonexistent() {
	ezOptionParser opt;
	bool imported = opt.importFile("/tmp/nonexistent_ezoption_file_12345.txt");
	ok(!imported, "importFile returns false for non-existent file");
}

/* ================================================================== */
/* 16. gotExpected: option expects arg but none provided              */
/* ================================================================== */
static void test_got_expected() {
	ezOptionParser opt;
	opt.add("", false, 1, 0, "Config path", "--config");

	// --config is the last arg, so there's no value following it
	ArgV a{"prog", "--config"};
	opt.parse(a.argc(), a.argv());

	std::vector<std::string> bad;
	bool ok_result = opt.gotExpected(bad);
	ok(!ok_result, "gotExpected returns false when --config has no argument");
	ok(bad.size() >= 1, "gotExpected reports at least one bad option");
}

/* ================================================================== */
/* 17. resetArgs clears parsed values but keeps option definitions    */
/* ================================================================== */
static void test_reset_args() {
	ezOptionParser opt;
	opt.add("", false, 1, 0, "Name", "--name");

	ArgV a{"prog", "--name", "hello"};
	opt.parse(a.argc(), a.argv());
	ok(opt.isSet("--name") != 0, "--name is set before resetArgs");

	opt.resetArgs();
	ok(opt.isSet("--name") == 0, "--name is not set after resetArgs");

	// Re-parse with different value
	ArgV b{"prog", "--name", "world"};
	opt.parse(b.argc(), b.argv());

	std::string val;
	opt.get("--name")->getString(val);
	ok(val == "world", "After resetArgs + re-parse, --name is 'world'");
}

/* ================================================================== */
/* 18. firstArgs / lastArgs capture                                   */
/* ================================================================== */
static void test_first_last_args() {
	ezOptionParser opt;
	opt.add("", false, 0, 0, "Verbose", "--verbose");

	ArgV a{"prog", "--verbose", "trailing1", "trailing2"};
	opt.parse(a.argc(), a.argv());

	ok(opt.firstArgs.size() == 1, "firstArgs has 1 entry (program name)");
	ok(opt.firstArgs.size() >= 1 && *opt.firstArgs[0] == "prog",
	   "firstArgs[0] is 'prog'");

	ok(opt.lastArgs.size() == 2, "lastArgs has 2 trailing entries");
	ok(opt.lastArgs.size() >= 1 && *opt.lastArgs[0] == "trailing1",
	   "lastArgs[0] is 'trailing1'");
	ok(opt.lastArgs.size() >= 2 && *opt.lastArgs[1] == "trailing2",
	   "lastArgs[1] is 'trailing2'");
}

/* ================================================================== */
/* 19. Three-flag add() overload                                      */
/* ================================================================== */
static void test_three_flag_add() {
	ezOptionParser opt;
	opt.add("", false, 0, 0, "Verbose output", "-v", "--verbose", "--verb");

	ArgV a{"prog", "--verb"};
	opt.parse(a.argc(), a.argv());

	ok(opt.isSet("-v") != 0, "-v set via --verb alias (3-flag overload)");
	ok(opt.isSet("--verbose") != 0, "--verbose set via --verb alias");
	ok(opt.isSet("--verb") != 0, "--verb itself is set");
}

/* ================================================================== */
/* 20. Four-flag add() overload                                       */
/* ================================================================== */
static void test_four_flag_add() {
	ezOptionParser opt;
	opt.add("", false, 0, 0, "Debug mode", "-d", "-D", "--debug", "--dbg");

	ArgV a{"prog", "-D"};
	opt.parse(a.argc(), a.argv());

	ok(opt.isSet("-d") != 0, "-d set via -D alias (4-flag overload)");
	ok(opt.isSet("-D") != 0, "-D itself is set");
	ok(opt.isSet("--debug") != 0, "--debug set via -D alias");
	ok(opt.isSet("--dbg") != 0, "--dbg set via -D alias");
}

/* ================================================================== */
/* 21. Float option get                                               */
/* ================================================================== */
static void test_float_option() {
	ezOptionParser opt;
	opt.add("1.5", false, 1, 0, "Threshold", "--threshold");

	// Test with explicit value
	{
		ArgV a{"prog", "--threshold", "3.14"};
		opt.parse(a.argc(), a.argv());

		float val = 0.0f;
		opt.get("--threshold")->getFloat(val);
		ok(val > 3.13f && val < 3.15f, "getFloat returns ~3.14");
	}
}

/* ================================================================== */
/* 22. Double option default                                          */
/* ================================================================== */
static void test_double_default() {
	ezOptionParser opt;
	opt.add("2.718", false, 1, 0, "Base", "--base");

	ArgV a{"prog"};
	opt.parse(a.argc(), a.argv());

	double val = 0.0;
	opt.get("--base")->getDouble(val);
	ok(val > 2.717 && val < 2.719, "getDouble returns default ~2.718");
}

/* ================================================================== */
/* 23. Long and unsigned long getters                                 */
/* ================================================================== */
static void test_long_getters() {
	ezOptionParser opt;
	opt.add("100", false, 1, 0, "Limit", "--limit");

	ArgV a{"prog", "--limit", "999999"};
	opt.parse(a.argc(), a.argv());

	long lval = 0;
	opt.get("--limit")->getLong(lval);
	ok(lval == 999999L, "getLong returns 999999");

	unsigned long ulval = 0;
	opt.get("--limit")->getULong(ulval);
	ok(ulval == 999999UL, "getULong returns 999999");
}

/* ================================================================== */
/* 24. LongLong and ULongLong getters                                 */
/* ================================================================== */
static void test_longlong_getters() {
	ezOptionParser opt;
	opt.add("0", false, 1, 0, "Big number", "--big");

	ArgV a{"prog", "--big", "9876543210"};
	opt.parse(a.argc(), a.argv());

	long long llval = 0;
	opt.get("--big")->getLongLong(llval);
	ok(llval == 9876543210LL, "getLongLong returns 9876543210");

	unsigned long long ullval = 0;
	opt.get("--big")->getULongLong(ullval);
	ok(ullval == 9876543210ULL, "getULongLong returns 9876543210");
}

/* ================================================================== */
/* 25. getMultiInts for repeated delimited option                     */
/* ================================================================== */
static void test_get_multi_ints() {
	ezOptionParser opt;
	opt.add("", false, -1, ',', "Coordinates", "--coord");

	ArgV a{"prog", "--coord", "1,2,3", "--coord", "4,5,6"};
	opt.parse(a.argc(), a.argv());

	std::vector< std::vector<int> > multi;
	opt.get("--coord")->getMultiInts(multi);
	ok(multi.size() == 2, "getMultiInts returns 2 sets");
	ok(multi.size() >= 1 && multi[0].size() == 3, "First set has 3 ints");
	ok(multi.size() >= 1 && multi[0].size() >= 3 &&
	   multi[0][0] == 1 && multi[0][1] == 2 && multi[0][2] == 3,
	   "First set is {1,2,3}");
	ok(multi.size() >= 2 && multi[1].size() >= 3 &&
	   multi[1][0] == 4 && multi[1][1] == 5 && multi[1][2] == 6,
	   "Second set is {4,5,6}");
}

/* ================================================================== */
/* 26. get() returns NULL for unknown option name                     */
/* ================================================================== */
static void test_get_unknown_returns_null() {
	ezOptionParser opt;
	opt.add("", false, 0, 0, "Help", "--help");

	OptionGroup *g = opt.get("--nonexistent");
	ok(g == nullptr, "get() returns NULL for unregistered option");
}

/* ================================================================== */
/* 27. isSet with std::string overload                                */
/* ================================================================== */
static void test_isset_string_overload() {
	ezOptionParser opt;
	opt.add("", false, 0, 0, "Debug", "--debug");

	ArgV a{"prog", "--debug"};
	opt.parse(a.argc(), a.argv());

	std::string name("--debug");
	ok(opt.isSet(name) != 0, "isSet(std::string&) returns true for --debug");

	std::string name2("--missing");
	ok(opt.isSet(name2) == 0, "isSet(std::string&) returns false for --missing");
}

/* ================================================================== */
/* 28. Parse with no arguments (argc=1, just program name)            */
/* ================================================================== */
static void test_parse_no_args() {
	ezOptionParser opt;
	opt.add("", false, 0, 0, "Help", "--help");

	ArgV a{"prog"};
	opt.parse(a.argc(), a.argv());

	ok(opt.isSet("--help") == 0, "No options set when only program name given");
	ok(opt.unknownArgs.empty(), "No unknown args when only program name given");
}

/* ================================================================== */
/* 29. Usage with INTERLEAVE layout                                   */
/* ================================================================== */
static void test_usage_interleave() {
	ezOptionParser opt;
	opt.overview = "Interleave Test";
	opt.syntax   = "test [OPTIONS]";
	opt.add("", false, 0, 0, "Show help message", "--help");

	std::string usage;
	opt.getUsage(usage, 80, ezOptionParser::INTERLEAVE);
	ok(usage.find("--help") != std::string::npos,
	   "INTERLEAVE layout contains --help");
	ok(usage.find("Show help message") != std::string::npos,
	   "INTERLEAVE layout contains help description");
}

/* ================================================================== */
/* 30. Usage with STAGGER layout                                      */
/* ================================================================== */
static void test_usage_stagger() {
	ezOptionParser opt;
	opt.overview = "Stagger Test";
	opt.syntax   = "test [OPTIONS]";
	opt.add("", false, 0, 0, "Show help message", "--help");

	std::string usage;
	opt.getUsage(usage, 80, ezOptionParser::STAGGER);
	ok(usage.find("--help") != std::string::npos,
	   "STAGGER layout contains --help");
}

/* ================================================================== */
/* 31. gotValid with ezOptionValidator                                */
/* ================================================================== */
static void test_got_valid() {
	// Validator: integer in range [1, 65535]
	int range[] = { 1, 65535 };
	ezOptionValidator *v = new ezOptionValidator(
		ezOptionValidator::S4,
		ezOptionValidator::GELE,
		range, 2
	);

	ezOptionParser opt;
	opt.add("8080", false, 1, 0, "Port", "--port", v);

	// Valid value
	{
		ArgV a{"prog", "--port", "443"};
		opt.parse(a.argc(), a.argv());

		std::vector<std::string> badOpts, badArgs;
		bool valid = opt.gotValid(badOpts, badArgs);
		ok(valid, "gotValid returns true for port=443 in [1,65535]");
	}

	// Invalid value
	opt.resetArgs();
	{
		ArgV a{"prog", "--port", "0"};
		opt.parse(a.argc(), a.argv());

		std::vector<std::string> badOpts, badArgs;
		bool valid = opt.gotValid(badOpts, badArgs);
		ok(!valid, "gotValid returns false for port=0 outside [1,65535]");
		ok(badOpts.size() >= 1 && badOpts[0] == "--port",
		   "gotValid reports --port as the bad option");
	}
}

/* ================================================================== */
/* 32. Doublespace toggle in usage                                    */
/* ================================================================== */
static void test_doublespace() {
	ezOptionParser opt;
	opt.overview = "Test";
	opt.syntax   = "test";
	opt.doublespace = 0; // Disable double spacing
	opt.add("", false, 0, 0, "Help", "--help");

	std::string usage;
	opt.getUsage(usage);
	// Should still produce valid output; just no double-spacing
	ok(usage.find("--help") != std::string::npos,
	   "Usage with doublespace=0 still contains --help");
}

/* ================================================================== */
/* 33. Empty parse (argc < 1)                                        */
/* ================================================================== */
static void test_parse_empty() {
	ezOptionParser opt;
	opt.add("", false, 0, 0, "Help", "--help");

	// argc=0 should be a no-op (early return)
	opt.parse(0, nullptr);
	ok(opt.isSet("--help") == 0, "parse with argc=0 is a no-op");
}

/* ================================================================== */
/* 34. getStrings (vector<string>) from delimited option              */
/* ================================================================== */
static void test_get_strings_vector() {
	ezOptionParser opt;
	opt.add("", false, -1, ',', "Tags", "--tags");

	ArgV a{"prog", "--tags", "alpha,beta,gamma"};
	opt.parse(a.argc(), a.argv());

	std::vector<std::string> tags;
	opt.get("--tags")->getStrings(tags);
	ok(tags.size() == 3, "getStrings returns 3 tags");
	ok(tags.size() >= 3 && tags[0] == "alpha", "First tag is alpha");
	ok(tags.size() >= 3 && tags[1] == "beta", "Second tag is beta");
	ok(tags.size() >= 3 && tags[2] == "gamma", "Third tag is gamma");
}

/* ================================================================== */
/* 35. getLongs vector from delimited defaults                        */
/* ================================================================== */
static void test_get_longs_defaults() {
	ezOptionParser opt;
	opt.add("10,20,30", false, -1, ',', "Sizes", "--sizes");

	ArgV a{"prog"};
	opt.parse(a.argc(), a.argv());

	std::vector<long> vals;
	opt.get("--sizes")->getLongs(vals);
	ok(vals.size() == 3, "Default getLongs returns 3 values");
	ok(vals.size() >= 3 && vals[0] == 10L, "Default first is 10");
}

/* ================================================================== */
/* 36. getULongs vector from delimited option                         */
/* ================================================================== */
static void test_get_ulongs() {
	ezOptionParser opt;
	opt.add("", false, -1, ',', "IDs", "--ids");

	ArgV a{"prog", "--ids", "100,200,300"};
	opt.parse(a.argc(), a.argv());

	std::vector<unsigned long> vals;
	opt.get("--ids")->getULongs(vals);
	ok(vals.size() == 3, "getULongs returns 3 values");
	ok(vals.size() >= 1 && vals[0] == 100UL, "First ID is 100");
}

/* ================================================================== */
/* 37. getFloats vector from delimited option                         */
/* ================================================================== */
static void test_get_floats_vector() {
	ezOptionParser opt;
	opt.add("", false, -1, ',', "Weights", "--weights");

	ArgV a{"prog", "--weights", "1.5,2.5,3.5"};
	opt.parse(a.argc(), a.argv());

	std::vector<float> vals;
	opt.get("--weights")->getFloats(vals);
	ok(vals.size() == 3, "getFloats returns 3 values");
	ok(vals.size() >= 1 && vals[0] > 1.4f && vals[0] < 1.6f,
	   "First weight is ~1.5");
}

/* ================================================================== */
/* 38. getDoubles vector from delimited option                        */
/* ================================================================== */
static void test_get_doubles_vector() {
	ezOptionParser opt;
	opt.add("", false, -1, ',', "Coords", "--coords");

	ArgV a{"prog", "--coords", "1.1,2.2"};
	opt.parse(a.argc(), a.argv());

	std::vector<double> vals;
	opt.get("--coords")->getDoubles(vals);
	ok(vals.size() == 2, "getDoubles returns 2 values");
	ok(vals.size() >= 1 && vals[0] > 1.09 && vals[0] < 1.11,
	   "First coord is ~1.1");
}

/* ================================================================== */
/* 39. getMultiLongs for repeated delimited option                    */
/* ================================================================== */
static void test_get_multi_longs() {
	ezOptionParser opt;
	opt.add("", false, -1, ',', "Ranges", "--range");

	ArgV a{"prog", "--range", "10,20", "--range", "30,40"};
	opt.parse(a.argc(), a.argv());

	std::vector< std::vector<long> > multi;
	opt.get("--range")->getMultiLongs(multi);
	ok(multi.size() == 2, "getMultiLongs returns 2 sets");
	ok(multi.size() >= 1 && multi[0].size() == 2, "First set has 2 longs");
}

/* ================================================================== */
/* 40. getMultiULongs for repeated delimited option                   */
/* ================================================================== */
static void test_get_multi_ulongs() {
	ezOptionParser opt;
	opt.add("", false, -1, ',', "Counts", "--cnt");

	ArgV a{"prog", "--cnt", "1,2", "--cnt", "3,4"};
	opt.parse(a.argc(), a.argv());

	std::vector< std::vector<unsigned long> > multi;
	opt.get("--cnt")->getMultiULongs(multi);
	ok(multi.size() == 2, "getMultiULongs returns 2 sets");
}

/* ================================================================== */
/* 41. getMultiFloats for repeated delimited option                   */
/* ================================================================== */
static void test_get_multi_floats() {
	ezOptionParser opt;
	opt.add("", false, -1, ',', "Points", "--pt");

	ArgV a{"prog", "--pt", "1.0,2.0", "--pt", "3.0,4.0"};
	opt.parse(a.argc(), a.argv());

	std::vector< std::vector<float> > multi;
	opt.get("--pt")->getMultiFloats(multi);
	ok(multi.size() == 2, "getMultiFloats returns 2 sets");
}

/* ================================================================== */
/* 42. getMultiDoubles for repeated delimited option                  */
/* ================================================================== */
static void test_get_multi_doubles() {
	ezOptionParser opt;
	opt.add("", false, -1, ',', "Values", "--val");

	ArgV a{"prog", "--val", "1.1,2.2", "--val", "3.3,4.4"};
	opt.parse(a.argc(), a.argv());

	std::vector< std::vector<double> > multi;
	opt.get("--val")->getMultiDoubles(multi);
	ok(multi.size() == 2, "getMultiDoubles returns 2 sets");
}

/* ================================================================== */
/* 43. No flags at all (all args are firstArgs/lastArgs)              */
/* ================================================================== */
static void test_no_flags_all_last_args() {
	ezOptionParser opt;
	opt.add("", false, 0, 0, "Help", "--help");

	ArgV a{"prog", "file1.txt", "file2.txt"};
	opt.parse(a.argc(), a.argv());

	ok(opt.firstArgs.size() == 1, "firstArgs has program name");
	ok(opt.lastArgs.size() == 2, "lastArgs has the two trailing files");
}

/* ================================================================== */
/* 44. ezOptionValidator with string constructor                      */
/* ================================================================== */
static void test_validator_string_ctor() {
	// Validate that value is in list
	ezOptionValidator *v = new ezOptionValidator("t", "in", "red,green,blue", false);

	ezOptionParser opt;
	opt.add("red", false, 1, 0, "Color", "--color", v);

	ArgV a{"prog", "--color", "green"};
	opt.parse(a.argc(), a.argv());

	std::vector<std::string> badOpts, badArgs;
	bool valid = opt.gotValid(badOpts, badArgs);
	ok(valid, "gotValid passes for 'green' in {red,green,blue}");

	opt.resetArgs();
	ArgV b{"prog", "--color", "purple"};
	opt.parse(b.argc(), b.argv());

	badOpts.clear();
	badArgs.clear();
	valid = opt.gotValid(badOpts, badArgs);
	ok(!valid, "gotValid fails for 'purple' not in {red,green,blue}");
}

/* ================================================================== */
/* 45. Usage with ARG indicator for options expecting arguments       */
/* ================================================================== */
static void test_usage_arg_indicator() {
	ezOptionParser opt;
	opt.overview = "Test";
	opt.syntax   = "test";
	opt.add("", false, 1, 0, "Output file", "--output");

	std::string usage;
	opt.getUsage(usage);
	ok(usage.find("ARG") != std::string::npos,
	   "Usage shows ARG indicator for options expecting arguments");
}

/* ================================================================== */
/* 46. Usage with delimited ARG indicator                             */
/* ================================================================== */
static void test_usage_delim_arg_indicator() {
	ezOptionParser opt;
	opt.overview = "Test";
	opt.syntax   = "test";
	opt.add("", false, -1, ',', "Values", "--values");

	std::string usage;
	opt.getUsage(usage);
	ok(usage.find("ARG1[") != std::string::npos,
	   "Usage shows ARG1[,ARGn] for delimited options");
}

/* ================================================================== */
/* 47. exportFile returns false for invalid path                      */
/* ================================================================== */
static void test_export_bad_path() {
	ezOptionParser opt;
	opt.add("", false, 0, 0, "Help", "--help");

	bool result = opt.exportFile("/nonexistent/dir/file.txt");
	ok(!result, "exportFile returns false for invalid path");
}

/* ================================================================== */
/* main                                                               */
/* ================================================================== */
int main() {
	plan(110);

	test_flag_is_set();           // 2
	test_string_option();         // 2
	test_integer_option();        // 1
	test_default_values();        // 3
	test_required_missing();      // 3
	test_required_present();      // 2
	test_unknown_options();       // 3
	test_short_alias();           // 2
	test_multiple_values();       // 4
	test_usage_generation();      // 8
	test_delimited_args();        // 4
	test_delimited_defaults();    // 4
	test_pretty_print();          // 3
	test_export_import();         // 4
	test_import_nonexistent();    // 1
	test_got_expected();          // 2
	test_reset_args();            // 3
	test_first_last_args();       // 5
	test_three_flag_add();        // 3
	test_four_flag_add();         // 4
	test_float_option();          // 1
	test_double_default();        // 1
	test_long_getters();          // 2
	test_longlong_getters();      // 2
	test_get_multi_ints();        // 4
	test_get_unknown_returns_null(); // 1
	test_isset_string_overload(); // 2
	test_parse_no_args();         // 2
	test_usage_interleave();      // 2
	test_usage_stagger();         // 1
	test_got_valid();             // 3
	test_doublespace();           // 1
	test_parse_empty();           // 1
	test_get_strings_vector();    // 4
	test_get_longs_defaults();    // 2
	test_get_ulongs();            // 2
	test_get_floats_vector();     // 2
	test_get_doubles_vector();    // 2
	test_get_multi_longs();       // 2
	test_get_multi_ulongs();      // 1
	test_get_multi_floats();      // 1
	test_get_multi_doubles();     // 1
	test_no_flags_all_last_args();// 2
	test_validator_string_ctor(); // 2
	test_usage_arg_indicator();   // 1
	test_usage_delim_arg_indicator(); // 1
	test_export_bad_path();       // 1

	return exit_status();
}
