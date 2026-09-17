/**
 * @file mysql_router_routing_guidelines_unit-t.cpp
 * @brief Unit tests for the MySQL Router Routing Guidelines engine (#6145).
 *
 * Covers the expression language (lexer, precedence, typing, functions, NULL
 * semantics, tags for document versions 1.0/1.1, LIKE translation), document
 * validation with JSON paths, the MySQL Shell default guidelines, destination
 * classification, route matching and runtime error handling. Many vectors are
 * ported from MySQL Router's routing_guidelines tests (test_parser.cc,
 * test_classifier.cc).
 */

#include "tap.h"

#include "mysql_router_routing_guidelines.h"

#include <atomic>
#include <cmath>
#include <map>
#include <string>
#include <thread>
#include <vector>

using namespace mysql_router::rg;

namespace {

ServerInfo g_server;
SessionInfo g_session;
RouterInfo g_router;
std::map<std::string, int> g_resolve_calls;

std::optional<std::string> fake_resolver(const std::string& host, bool ipv6) {
	g_resolve_calls[host + (ipv6 ? "/6" : "/4")]++;
	if (host == "abra" && !ipv6) return std::string("123.12.13.11");
	if (host == "cadabra" && ipv6) return std::string("::ffff:3.3.3.3");
	if (host == "abracadabra" && ipv6) return std::string("::ffff:4.4.4.4");
	if (host == "localhost" && !ipv6) return std::string("7.7.7.7");
	if (host == "localhost" && ipv6) return std::string("2001:db8::1428:57ab");
	return std::nullopt;
}

void reset_context() {
	g_server = ServerInfo();
	g_server.label = "NumberOne";
	g_server.address = "127.0.0.1";
	g_server.port = 3306;
	g_server.uuid = "123e4567-e89b-12d3-a456-426614174000";
	g_server.version = 80023;
	g_server.member_role = MemberRole::secondary;
	g_server.cluster_role = ClusterRole::replica;
	g_server.cluster_name = "Unnamed";
	g_server.cluster_set_name = "Set1";
	g_server.tags = {{"uptime", "2 years"}, {"alarm", "9PM"}};

	g_session = SessionInfo();
	g_session.target_ip = "196.0.0.1";
	g_session.target_port = 6446;
	g_session.source_ip = "123.222.111.12";
	g_session.user = "root";
	g_session.schema = "test";
	g_session.random_value = 0.25;
	g_session.connect_attrs = {
		{"web", "www.mysql.com"}, {"mysql", "MySQL"}, {"microsoft", "SQL Server"},
		{"postgres", "Postgres"}, {"right", "777"}, {"wrong", "77a"}, {"fun", "%_%_%"},
		{"a", "a"}, {"empty", ""}, {"wrong_address", "matata"}, {"regex", "SQL.*"},
		{"bad_regex", "[a-b][a"},
	};

	g_router = RouterInfo();
	g_router.port_ro = 6447;
	g_router.port_rw = 6446;
	g_router.port_rw_split = 6450;
	g_router.local_cluster = "Cluster0";
	g_router.hostname = "mysql.oracle.com";
	g_router.bind_address = "192.168.0.123";
	g_router.route_name = "routing_ro";
	g_router.name = "test-router";
	g_router.tags = {{"uptime", "2 years"}};
}

bool contains(const std::string& haystack, const std::string& needle) {
	return haystack.find(needle) != std::string::npos;
}

std::string join(const std::vector<std::string>& v) {
	std::string out;
	for (const auto& s : v) out += (out.empty() ? "" : " | ") + s;
	return out;
}

std::string join(const std::vector<Error>& v) {
	std::string out;
	for (const auto& e : v) out += (out.empty() ? "" : " | ") + format_error(e);
	return out;
}

std::optional<Expression> compile_any(const std::string& code, std::vector<std::string>& errors,
	const char* version = "1.0") {
	return Expression::compile(code, ExpressionScope::any, version, errors, fake_resolver);
}

bool eval(const std::string& code, Value& out, std::string& error, const char* version = "1.0") {
	std::vector<std::string> errors;
	auto e = compile_any(code, errors, version);
	if (!e) {
		error = "compile: " + join(errors);
		return false;
	}
	try {
		out = e->evaluate(&g_server, &g_session, &g_router);
	} catch (const std::exception& ex) {
		error = std::string("eval: ") + ex.what();
		return false;
	}
	return true;
}

void expect_num(double expected, const std::string& code) {
	Value v;
	std::string err;
	const bool good = eval(code, v, err);
	ok(good && v.type == ValueType::number && v.number == expected,
		"number %s == %g (got %g %s)", code.c_str(), expected, v.number, err.c_str());
}

void expect_str(const std::string& expected, const std::string& code, const char* version = "1.0") {
	Value v;
	std::string err;
	const bool good = eval(code, v, err, version);
	ok(good && v.type == ValueType::string && v.string == expected,
		"string %s == '%s' (got '%s' %s)", code.c_str(), expected.c_str(), v.string.c_str(), err.c_str());
}

void expect_role(const std::string& expected, const std::string& code) {
	Value v;
	std::string err;
	const bool good = eval(code, v, err);
	ok(good && v.type == ValueType::role && v.string == expected,
		"role %s == %s (got '%s' %s)", code.c_str(), expected.c_str(), v.string.c_str(), err.c_str());
}

void expect_bool(bool expected, const std::string& code, const char* version = "1.0") {
	Value v;
	std::string err;
	const bool good = eval(code, v, err, version);
	ok(good && v.truthy() == expected, "%s %s is %s %s", version, code.c_str(),
		expected ? "true" : "false", err.c_str());
}

void T(const std::string& code, const char* version = "1.0") { expect_bool(true, code, version); }
void F(const std::string& code, const char* version = "1.0") { expect_bool(false, code, version); }

void expect_null(const std::string& code) {
	Value v;
	std::string err;
	const bool good = eval(code, v, err);
	ok(good && v.type == ValueType::null, "%s is NULL %s", code.c_str(), err.c_str());
}

void expect_type(ValueType expected, const std::string& code) {
	Value v;
	std::string err;
	const bool good = eval(code, v, err);
	ok(good && v.type == expected, "%s has type %d (got %d) %s", code.c_str(),
		static_cast<int>(expected), static_cast<int>(v.type), err.c_str());
}

// parse error containing `needle`
void PE(const std::string& code, const std::string& needle, const char* version = "1.0") {
	std::vector<std::string> errors;
	auto e = compile_any(code, errors, version);
	const std::string msg = join(errors);
	ok(!e && errors.size() == 1 && contains(msg, needle), "parse error for %s contains \"%s\" (got \"%s\")",
		code.c_str(), needle.c_str(), msg.c_str());
}

// exact parse error
void PEX(const std::string& code, const std::string& expected, const char* version = "1.0") {
	std::vector<std::string> errors;
	auto e = compile_any(code, errors, version);
	const std::string msg = join(errors);
	ok(!e && msg == expected, "parse error for %s is \"%s\" (got \"%s\")",
		code.c_str(), expected.c_str(), msg.c_str());
}

// evaluation error containing `needle`
void EE(const std::string& code, const std::string& needle) {
	Value v;
	std::string err;
	const bool good = eval(code, v, err);
	ok(!good && contains(err, "eval: ") && contains(err, needle), "eval error for %s contains \"%s\" (got \"%s\")",
		code.c_str(), needle.c_str(), err.c_str());
}

std::vector<std::string> scoped_errors(const std::string& code, ExpressionScope scope, const char* version = "1.0") {
	std::vector<std::string> errors;
	(void)Expression::compile(code, scope, version, errors, fake_resolver);
	return errors;
}

std::shared_ptr<const Guideline> parse_doc(const std::string& doc, std::vector<Error>& errors) {
	return Guideline::parse(doc, errors, fake_resolver);
}

bool has_error(const std::vector<Error>& errors, const std::string& path, const std::string& needle) {
	for (const auto& e : errors) {
		if (e.path == path && contains(e.message, needle)) return true;
	}
	return false;
}

void expect_doc_error(const std::string& doc, const std::string& path, const std::string& needle, const char* what) {
	std::vector<Error> errors;
	const auto g = parse_doc(doc, errors);
	ok(!g && has_error(errors, path, needle), "%s: '%s: %s' reported (got %s)", what, path.c_str(), needle.c_str(),
		join(errors).c_str());
}

std::string doc_with(const std::string& destinations, const std::string& routes, const std::string& extra = "\"version\": \"1.1\",") {
	return "{" + extra + "\"destinations\": " + destinations + ", \"routes\": " + routes + "}";
}

const char* kDests = R"([{"name": "Primary", "match": "$.server.memberRole = PRIMARY"},
	{"name": "Secondary", "match": "$.server.memberRole = SECONDARY"}])";
const char* kRoutes = R"([{"name": "rw", "match": "$.session.targetPort = $.router.port.rw",
	"destinations": [{"classes": ["Primary"], "strategy": "round-robin", "priority": 0}]}])";

// ---------------------------------------------------------------------------

void test_lexer() {
	diag("lexer");
	expect_num(10, "10.0");
	expect_num(10, "10");
	expect_num(-10, "-10.0");
	expect_num(1000, "1e3");
	expect_num(0.15, "1.5e-1");
	expect_num(16, "0x10");
	expect_num(7, " \t\n 7 \r\n");
	expect_str("Windows XP", "'Windows XP'");
	expect_str("Windows XP", "\"Windows XP\"");
	expect_str("Windows7", "Windows7");
	expect_str("abc.def_1", "abc.def_1");
	expect_str("it's", "'it\\'s'");
	expect_str("say \"hi\"", "\"say \\\"hi\\\"\"");
	expect_str("a\bcdefghijklm\nopq\rs\tuvwxyz", R"('\a\b\c\d\e\f\g\h\i\j\k\l\m\n\o\p\q\r\s\t\u\v\w\x\y\z')");
	expect_str("ABCDEFGHIJKLMNOPQRSTUVWXY\032", R"('\A\B\C\D\E\F\G\H\I\J\K\L\M\N\O\P\Q\R\S\T\U\V\W\X\Y\Z')");
	{
		std::string res {"\\123456789"};
		res.push_back('\0');
		expect_str(res, R"('\\\1\2\3\4\5\6\7\8\9\0')");
	}
	expect_str("MySQL", "$.session.connectAttrs.mysql");
	// keywords, functions and roles are case-insensitive
	T("tRuE");
	F("False");
	expect_null("nUlL");
	expect_num(9, "sQrT(81)");
	expect_role("primary", "primary");
	expect_role("READ_REPLICA", "READ_REPLICA");
	// dotted identifiers are strings, never keywords
	expect_str("true.x", "true.x");
	// empty expression evaluates to NULL
	expect_null("");
	expect_null("   ");

	PEX("a!=2", "syntax error, unexpected character: '!' (character 2)");
	PEX("endswith(2, 'dwa)", "syntax error, unclosed ' (character 13)");
	PEX("$x", "syntax error, $ not starting variable reference (character 1)");
	PEX("$.1a", "syntax error, Id not starting with a letter (character 1)");
	PEX("1 + $._a", "syntax error, Id not starting with a letter (character 5)");
	PEX("_abc", "syntax error, unexpected character: '_' (character 1)");
	PEX("{\"a\": 1}", "syntax error, unexpected character: '{' (character 1)");
	PEX("[1]", "syntax error, unexpected character: '[' (character 1)");
	PE("10.0.0.1 = '10.0.0.1'", "syntax error, unexpected character: '.'");
	PEX("'abc\\'", "syntax error, unclosed ' (character 1)");
	PEX("a==2", "syntax error, unexpected = (character 3)");
	PE("$.session.targetPort ! 3", "unexpected character: '!'");
	// variable names are case-sensitive
	PEX("$.session.User = 'x'", "undefined variable: session.User in '$.session.User'");
}

void test_syntax_errors() {
	diag("syntax errors");
	PEX("SQR()", "syntax error, unexpected (, expecting end of expression or error (character 4)");
	PEX("SQRT()", "syntax error, function SQRT expected 1 argument but got none in 'SQRT()'");
	PEX("network('127.0.0.1')", "syntax error, function NETWORK expected 2 arguments but got 1 in 'network('127.0.0.1')'");
	PE("RESOLVE_V4('127.0.0.1', 12)", "syntax error, function RESOLVE_V4 expected 1 argument but got 2");
	PE("RESOLVE_V6('127.0.0.1', 12)", "syntax error, function RESOLVE_V6 expected 1 argument but got 2");
	PE("regexp_like('127.0.0.1', 12, 13)", "syntax error, function REGEXP_LIKE expected 2 arguments but got 3");
	PEX("2+3=", "syntax error, unexpected end of expression (character 4)");
	PEX("sqrt(2", "syntax error, unexpected end of expression, expecting ) or \",\" (character 6)");
	PEX("sqrt(2 3)", "syntax error, unexpected number, expecting ) or \",\" (character 8)");
	PEX("3 in resolve_v4(localhost)", "syntax error, unexpected function name, expecting ( in 'resolve_v4'");
	PEX("3 in resolve_v6(localhost)", "syntax error, unexpected function name, expecting ( in 'resolve_v6'");
	PEX("3 < 4 > 5", "syntax error, unexpected > (character 7)");
	PEX("1 = 1 = TRUE", "syntax error, unexpected = (character 7)");
	PEX("'a' = 'b' IN ('c')", "syntax error, unexpected T_IN in 'IN'");
	PEX("'a' LIKE 'b' = TRUE", "syntax error, unexpected = (character 14)");
	PEX("$.session.user in a", "syntax error, unexpected identifier, expecting ( (character 19)");
	PEX("$.session.user not in a", "syntax error, unexpected identifier, expecting ( (character 23)");
	PEX("$.session.user NOT 'a'", "syntax error, unexpected string, expecting T_IN or T_LIKE in ''a''");
	PEX("NOT $.session.user NOT LIKE 'a'", "syntax error, unexpected T_NOT in 'NOT'");
	PEX("1 2", "syntax error, unexpected number, expecting end of expression or error (character 3)");
	PEX("(1 2)", "syntax error, unexpected number (character 4)");
	PEX(")", "syntax error, unexpected ), expecting end of expression or error (character 1)");
	PEX("1 +", "syntax error, unexpected end of expression (character 3)");
	PEX("()", "syntax error, unexpected ) (character 2)");
	PEX("1 in ()", "syntax error, unexpected ) (character 7)");
	PEX("concat()", "CONCAT function, no arguments provided in 'concat()'");
	PEX("$.server.role = PRIMARY", "undefined variable: server.role in '$.server.role'");
}

void test_precedence() {
	diag("precedence and arithmetic");
	expect_num(22, "10 + 3*4");
	expect_num(26, "(10 + 3)*2");
	expect_num(0, "12 - 3*4");
	expect_num(14, "(10 - 3)*2");
	expect_num(12, "10 + 8/4");
	expect_num(3, "(2 + 4)/2");
	expect_num(11.5, "12 - 4/8");
	expect_num(2, "(10 - 8) % 3");
	expect_num(2, "(10 + 8)%4");
	expect_num(9, "12 - 3%4");
	expect_num(14, "12 + 6%4");
	expect_num(3, "10 - 4 - 3");
	expect_num(1, "12 / 4 / 3");
	expect_num(63, "123/3*4-78*2+56%70-6*6/3%11");
	expect_num(-635344.2, "-(11*12/6*8%43 + 65.5 * 78.8) * (124 - sqrt(10 *2.5) % 4)");
	expect_num(-7, "-($.session.targetPort / 6446 * 10 + 4)/2");
	expect_num(11, "1 + sqrt(10*9 + $.session.targetPort - 6436)");
	expect_num(22, "$.session.targetPort - 6436 + 3*4");
	expect_num(-2, "$.session.targetPort - 6436 - 3*4");
	expect_num(12, "$.session.targetPort - 6436 + 8/4");
	expect_num(2, "($.session.targetPort - 6444) % 4 + 0 * 1");
	expect_num(-6, "-2*3");
	expect_num(-1, "-7 % 3");
	expect_num(6446 + 6447, "$.router.port.rw + $.router.port.ro");
	expect_num(0.25, "$.session.randomValue");
	expect_num(80023, "$.server.version");
	{
		Value v;
		std::string err;
		ok(eval("1/0", v, err) && v.type == ValueType::number && std::isinf(v.number), "division by zero is inf");
		ok(eval("0/0", v, err) && v.type == ValueType::number && std::isnan(v.number), "0/0 is nan");
		ok(eval("5 % 0", v, err) && v.type == ValueType::number && std::isnan(v.number), "modulo by zero is nan");
	}
	T("1/0 = 1/0");
	F("0/0 = 0/0");
	// logical precedence: NOT > AND > OR
	F("NOT TRUE AND FALSE");
	T("TRUE OR FALSE AND FALSE");
	T("NOT FALSE OR FALSE");
	F("NOT (FALSE OR TRUE)");
	T("NOT 1 = 2");
	T("NOT 'a' LIKE 'b'");
	T("NOT 3 IN (1, 2)");
	T("2+2 > 2-2 AND Abba < Beatles");
	T("2/2 < 2%4 AND NOT Abba >= Beatles");
	F("2*2 <= 2%4 OR Abba >= $.session.connectAttrs.mysql");
	// IN result may be compared further (Router's grammar)
	T("1 IN (1) = TRUE");
	T("(1 = 1) = TRUE");
	T("1 + 2 NOT IN (4)");
	T("TRUE AND 'x' NOT IN ('y')");
	T("'a' NOT IN ('b') NOT IN (FALSE)");
}

void test_comparisons() {
	diag("comparisons");
	T("10 < 11");
	T("10 <= 11");
	T("10 <= 10");
	F("10 < 9");
	F("10 <= 9");
	T("11 > 10");
	T("11 >= 10");
	T("10 >= 10");
	F("8 > 9");
	F("8 >= 9");
	T("$.server.port < 3307");
	T("$.server.port <= 3306");
	F("$.server.port > 3306");
	T("$.server.port >= 3306");
	F("11 -1 = 10*0.5");
	T("11 /2 <> 10 *2");
	T("10 = 10");
	F("8 <> 8");
	T("4 * $.server.port = ($.server.port + $.server.port) * 2");
	F("$.server.port = $.server.port + 1");
	// strings compare case-insensitively
	T("'MySQL' = mysql");
	T("MySQL = \"mysql\"");
	F("'MySQL' <> mysql");
	F("'Postgres' = mysql");
	T("postgres <> \"mysql\"");
	T("$.session.connectAttrs.mysql = mysql");
	T("POSTGRES = $.session.connectAttrs.postgres");
	T("Anna < Maria");
	F("'Maria' <= \"Anna\"");
	T("Anna < $.session.connectAttrs.mysql");
	T("$.session.connectAttrs.postgres > $.session.connectAttrs.mysql");
	T("mongo <= MONGO");
	T("mongo >= MONGO");
	T("'abc' < 'abcd'");
	T("'ABC' < 'abd'");
	// booleans
	T("TRUE = TRUE");
	T("TRUE <> FALSE");
	T("$.server.isClusterInvalidated = FALSE");
	F("$.server.isClusterInvalidated");
}

void test_logical() {
	diag("logical operators");
	T("true or false");
	F("true and false");
	F("false or false");
	T("true and true");
	T("'' or 'stg'");
	F("'' and 'stg'");
	T("0 or 11");
	F("2.2 and 0");
	T("'' or 1");
	F("0 and 'stg'");
	T("NOT ''");
	F("NOT 'stg'");
	T("NOT 0");
	F("NOT 1.1");
	T("NOT null");
	F("TRUE AND NULL");
	T("FALSE OR NOT NULL");
	F("null or false");
	F("PRIMARY AND UNDEFINED");
	T("PRIMARY");
	F("UNDEFINED");
	F("0.00000000000000001");
	// short-circuit: the right side is not evaluated
	T("true or $.server.port = 1 or network($.session.connectAttrs.wrong_address, 16) = 'x'");
	F("false and 9 = $.server.port/0 and network($.session.connectAttrs.wrong_address, 16) = 'x'");
	T("true or resolve_v4('oracle.com') > '123'");
	F("false and NUMBER($.session.connectAttrs.wrong) = 1");
	T("TRUE OR NUMBER($.session.connectAttrs.wrong) = 1");
	EE("FALSE OR NUMBER($.session.connectAttrs.wrong) = 1", "unable to convert '77a' to number");
	// Router keeps the raw left operand when short-circuiting
	expect_type(ValueType::string, "'' AND TRUE");
	expect_type(ValueType::number, "7 OR FALSE");
	expect_type(ValueType::boolean, "'x' AND TRUE");
	expect_type(ValueType::null, "$.session.connectAttrs.missing AND TRUE");
	expect_type(ValueType::string, "'' AND TRUE AND TRUE");
	expect_type(ValueType::boolean, "FALSE OR '' OR 'x'");
	expect_type(ValueType::boolean, "'x' AND 'y' AND ''");
	F("'x' AND 'y' AND ''");
	T("'' OR 0 OR 'x' OR NUMBER($.session.connectAttrs.wrong) = 1");
	T("(FALSE OR 'x') OR FALSE");
	T("FALSE OR ('' OR 'x')");
}

void test_limits() {
	diag("nesting limits");
	std::string chain = "$.session.user = 'u0'";
	for (int i = 1; i < 5000; i++) chain += " OR $.session.user = 'u" + std::to_string(i) + "'";
	chain += " OR $.session.user = 'root'";
	T(chain);
	std::string and_chain = "TRUE";
	for (int i = 0; i < 5000; i++) and_chain += " AND $.session.targetPort > " + std::to_string(i % 100);
	T(and_chain);
	std::string list = "$.session.user IN ('x'";
	for (int i = 0; i < 5000; i++) list += ", 'u" + std::to_string(i) + "'";
	T(list + ", 'ROOT')");
	std::string parens(150, '(');
	T(parens + "TRUE" + std::string(150, ')'));
	PE(std::string(300, '(') + "TRUE" + std::string(300, ')'), "syntax error, expression nesting exceeds 200 levels");
	std::string sum = "$.server.port";
	for (int i = 0; i < 300; i++) sum += " + 1";
	PE(sum + " > 0", "syntax error, expression nesting exceeds 200 levels");
	std::string nots;
	for (int i = 0; i < 300; i++) nots += "NOT ";
	PE(nots + "$.server.isClusterInvalidated", "syntax error, expression nesting exceeds 200 levels");
	std::string ok_sum = "$.server.port";
	for (int i = 0; i < 100; i++) ok_sum += " + 1";
	expect_num(3406, ok_sum);
}

void test_in() {
	diag("IN / NOT IN");
	T("a in (a)");
	T("a IN (b, a)");
	F("a in (b, c)");
	T("'a' In ('b', c, $.session.connectAttrs.a)");
	F("a not in (a)");
	F("a NOT IN (b, a)");
	T("a not in (b, c)");
	F("a Not In ('b', 'c', $.session.connectAttrs.a)");
	T("10 in (1, 3+4, 2*5)");
	F("10 in (10-1, 3+4, 2*6)");
	T("10 not in (10-1, sqrt(3+4), 2*6)");
	T("MYSQL in ($.session.connectAttrs.mysql, postgres, mongo) AND $.session.connectAttrs.postgres not in (\"Linux\", 'Windows XP', MacOS)");
	T("$.session.targetPort in ($.router.port.ro, $.router.port.rw)");
	T("$.server.memberRole IN (PRIMARY, SECONDARY)");
	F("$.server.memberRole IN (PRIMARY, READ_REPLICA)");
	T("$.session.user IN ('ROOT')");
	PEX("3 in (2-$.server.port, true)", "type error, in operator, type of element at offset 1 does not match the type of searched element, expected NUMBER but got BOOLEAN in '3 in (2-$.server.port, true)'");
	PE("abra in (PRIMARY)", "in operator, type of element at offset 0 does not match the type of searched element, expected STRING but got ROLE");
	PE("abra not in ('a', b, sqrt($.server.port))", "in operator, type of element at offset 2 does not match the type of searched element, expected STRING but got NUMBER");
}

void test_null_semantics() {
	diag("NULL semantics");
	expect_null("null");
	expect_null("NULL");
	expect_null("$.session.connectAttrs.missing");
	expect_null("$.server.tags.missing");
	expect_null("NUMBER($.session.connectAttrs.missing) + 2");
	expect_null("2 - NUMBER($.session.connectAttrs.missing)");
	expect_null("NUMBER($.session.connectAttrs.missing) * 5");
	expect_null("6 / NUMBER($.session.connectAttrs.missing)");
	expect_null("4 % NUMBER($.session.connectAttrs.missing)");
	expect_null("-NUMBER($.session.connectAttrs.missing)");
	expect_null("sqrt(NUMBER($.session.connectAttrs.missing))");
	PE("NULL + 2", "type error, + operator, left operand, expected NUMBER but got NULL");
	PE("1 % NULL", "type error, % operator, right operand, expected NUMBER but got NULL");
	PE("-NULL", "type error, - operator, expected NUMBER but got NULL");
	F("null = 3");
	F("'string' = $.session.connectAttrs.missing");
	T("$.session.connectAttrs.missing = null");
	F("NULL <> $.session.connectAttrs.missing");
	T("3 <> null");
	T("null = null");
	T("sqrt(NUMBER($.session.connectAttrs.missing)) = NULL");
	F("NULL <> sqrt(NUMBER($.session.connectAttrs.missing))");
	F("$.session.connectAttrs.missing < 'abradab'");
	F("'abradab' >= $.session.connectAttrs.missing");
	F("$.session.connectAttrs.missing <= 'abradab'");
	F("'abradab' > $.session.connectAttrs.missing");
	PE("NULL > 2", "type error, NULL type arguments cannot be compared with > operator");
	PE("'abra' <= NULL", "<= operator, the type of left operand does not match right, expected STRING but got NULL");
	T("1 in (2, null, 2-1)");
	F("NULL in (2, 3, 2-1)");
	T("null in ('dwa', trzy, $.session.connectAttrs.missing)");
	F("$.session.connectAttrs.missing in ('ene', 'due')");
	T("null in ($.session.connectAttrs.missing)");
	T("$.session.connectAttrs.missing in ('root', NULL)");
	expect_null("REGEXP_LIKE($.session.connectAttrs.missing, 'SQL.*')");
	expect_null("REGEXP_LIKE('MySQL', $.session.connectAttrs.missing)");
	expect_null("STARTSWITH($.session.connectAttrs.missing, 'a')");
	expect_null("CONCAT('a', $.session.connectAttrs.missing)");
	expect_null("SUBSTRING_INDEX($.session.connectAttrs.missing, '.', 1)");
	expect_null("$.session.connectAttrs.missing LIKE 'a%'");
	PE("REGEXP_LIKE('MySQL', NULL)", "REGEXP_LIKE function, 2nd argument, expected STRING but got NULL");
	PE("RESOLVE_V4(NULL)", "got NULL");
	PE("RESOLVE_V6(NULL)", "got NULL");
	PE("RESOLVE_V4($.session.user)", "RESOLVE_V4 function only accepts string literals as its parameter");
	PE("RESOLVE_V6($.session.user)", "RESOLVE_V6 function only accepts string literals as its parameter");
	// Router: NETWORK() on a NULL address is an evaluation error
	EE("NETWORK($.session.connectAttrs.missing, 24) = 'x'", "Type error, expected string");
	// variables of a missing scope evaluate to NULL
	std::vector<std::string> errors;
	auto e = Expression::compile("$.server.address", ExpressionScope::any, "1.0", errors);
	ok(e && e->evaluate(nullptr, &g_session, &g_router).type == ValueType::null,
		"a server variable without server info is NULL");
	ok(e && e->evaluate(&g_server, nullptr, nullptr).string == "127.0.0.1",
		"a server variable with server info has its value");
}

void test_variables() {
	diag("variables");
	expect_str("NumberOne", "$.server.label");
	expect_str("127.0.0.1", "$.server.address");
	expect_num(3306, "$.server.port");
	expect_str("123e4567-e89b-12d3-a456-426614174000", "$.server.uuid");
	expect_num(80023, "$.server.version");
	expect_role("SECONDARY", "$.server.memberRole");
	expect_role("REPLICA", "$.server.clusterRole");
	expect_str("Unnamed", "$.server.clusterName");
	expect_str("Set1", "$.server.clusterSetName");
	expect_type(ValueType::boolean, "$.server.isClusterInvalidated");
	expect_str("2 years", "$.server.tags.uptime");
	expect_str("9PM", "$.server.tags.alarm");
	expect_str("196.0.0.1", "$.session.targetIP");
	expect_num(6446, "$.session.targetPort");
	expect_str("123.222.111.12", "$.session.sourceIP");
	expect_str("root", "$.session.user");
	expect_str("test", "$.session.schema");
	expect_num(0.25, "$.session.randomValue");
	expect_str("www.mysql.com", "$.session.connectAttrs.web");
	expect_num(6447, "$.router.port.ro");
	expect_num(6446, "$.router.port.rw");
	expect_num(6450, "$.router.port.rw_split");
	expect_str("Cluster0", "$.router.localCluster");
	expect_str("mysql.oracle.com", "$.router.hostname");
	expect_str("192.168.0.123", "$.router.bindAddress");
	expect_str("routing_ro", "$.router.routeName");
	expect_str("test-router", "$.router.name");
	expect_str("2 years", "$.router.tags.uptime");
	expect_null("$.sql.queryTags.x");
	expect_null("$.sql.queryHints.x");
	PEX("$.router.port", "undefined variable: router.port in '$.router.port'");
	PEX("$.session.port", "undefined variable: session.port in '$.session.port'");
	PEX("$.router.tags", "undefined variable: router.tags in '$.router.tags'");
	PEX("$.sql.foo", "undefined variable: sql.foo in '$.sql.foo'");
	PEX("$.x", "undefined variable: x in '$.x'");
	PE("$.server.tags.1x", "undefined variable: server.tags");
	g_server.member_role = MemberRole::primary;
	g_server.cluster_role = ClusterRole::undefined;
	expect_role("PRIMARY", "$.server.memberRole");
	expect_role("UNDEFINED", "$.server.clusterRole");
	g_server.member_role = MemberRole::read_replica;
	g_server.cluster_role = ClusterRole::primary;
	expect_role("READ_REPLICA", "$.server.memberRole");
	expect_role("PRIMARY", "$.server.clusterRole");
	g_server.member_role = MemberRole::undefined;
	expect_role("UNDEFINED", "$.server.memberRole");
	reset_context();

	std::vector<std::string> errors;
	auto e = Expression::compile("$.router.routeName = 'x' AND $.session.connectAttrs.p = 'y'",
		ExpressionScope::any, "1.0", errors);
	ok(e && e->references("router.routeName") && e->references("session.connectAttrs.p") &&
		!e->references("router.name"), "references() reports referenced variables");
	e = Expression::compile("1 + 2 = 3", ExpressionScope::any, "1.0", errors);
	ok(e && e->is_constant() && e->text() == "1 + 2 = 3", "constant expressions are folded");
	e = Expression::compile("$.session.user LIKE '%'", ExpressionScope::any, "1.0", errors);
	ok(e && e->is_constant() && !e->references("session.user"), "a trivial LIKE folds to TRUE (Router)");
}

void test_roles() {
	diag("roles");
	expect_role("UNDEFINED", "UNDEFINED");
	expect_role("PRIMARY", "PRIMARY");
	expect_role("REPLICA", "REPLICA");
	F("PRIMARY = SECONDARY");
	T("PRIMARY <> secondary");
	F("UNDEFINED = SECONDARY");
	T("PRIMARY = primary");
	F("REPLICA = UNDEFINED");
	T("$.server.clusterRole");
	T("REPLICA = $.server.clusterRole");
	F("$.server.memberRole = PRIMARY");
	T("$.server.memberRole = SECONDARY");
	F("$.server.clusterRole = PRIMARY");
	T("$.server.memberRole <> UNDEFINED");
	T("$.server.clusterRole <> UNDEFINED");
	T("SECONDARY = $.server.memberRole");
	T("$.server.memberRole = $.server.memberRole");
	PE("$.server.clusterRole = SECONDARY", "type error, incompatible operands for comparison: 'CLUSTER ROLE' vs 'MEMBER ROLE'");
	PE("SECONDARY <> $.server.clusterRole", "type error, incompatible operands for comparison: 'MEMBER ROLE' vs 'CLUSTER ROLE'");
	PE("$.server.memberRole <> $.server.clusterRole", "type error, incompatible operands for comparison: 'MEMBER ROLE' vs 'CLUSTER ROLE'");
	PE("$.server.memberRole = REPLICA", "'MEMBER ROLE' vs 'CLUSTER ROLE'");
	PE("READ_REPLICA = REPLICA", "'MEMBER ROLE' vs 'CLUSTER ROLE'");
	PE("$.server.memberRole = 'undefined'", "the type of left operand does not match right, expected ROLE but got STRING");
	PE("$.server.clusterRole <> 0", "left operand does not match right, expected ROLE but got NUMBER");
	PE("PRIMARY >= SECONDARY", "type error, ROLE type arguments cannot be compared with >= operator");
	expect_str("primary,REPLICA", "concat(primary, ',', REPLICA)");
}

void test_functions() {
	diag("functions");
	expect_num(9, "sqrt(81)");
	expect_num(3, "SQRT($.server.port - 3297)");
	expect_num(10.123, "number('10.123')");
	expect_num(-10, "number('-10')");
	expect_num(112, "number('112')");
	expect_num(-123.123, "number('-123.123')");
	expect_num(0, "number('')");
	expect_num(777, "number($.session.connectAttrs.right)");
	PEX("number('17a')", "Function execution failed with error: NUMBER function, unable to convert '17a' to number in 'number('17a')'");
	EE("number($.session.connectAttrs.wrong)", "NUMBER function, unable to convert '77a' to number in 'number($.session.connectAttrs.wrong)'");

	T("REGEXP_LIKE('PostgreSQL', '.*SQL')");
	F("REGEXP_LIKE($.session.connectAttrs.microsoft, '.*SQL')");
	T("REGEXP_LIKE($.session.connectAttrs.microsoft, 'SQL.*')");
	T("REGEXP_LIKE($.session.connectAttrs.microsoft, 'sql.*')");
	F("REGEXP_LIKE($.session.connectAttrs.microsoft, 'SQL')");
	T("REGEXP_LIKE($.session.connectAttrs.microsoft, $.session.connectAttrs.regex)");
	T("REGEXP_LIKE($.server.uuid, '[0-9a-f]{8}-[0-9a-f]{4}-.*')");
	PE("regexp_like($.session.connectAttrs.web, '[a-b][a')", "REGEXP_LIKE function invalid regular expression");
	PE("regexp_like('abc', '[a-b][a')", "Function execution failed with error");
	EE("regexp_like($.session.connectAttrs.web, $.session.connectAttrs.bad_regex)", "in 'regexp_like(");

	expect_str("", "SUBSTRING_INDEX('www.mysql.com', '.', 0)");
	expect_str("", "SUBSTRING_INDEX($.session.connectAttrs.web, '.', 0)");
	expect_str("www.mysql.com", "SUBSTRING_INDEX('www.mysql.com', '.', 3)");
	expect_str("www.mysql.com", "SUBSTRING_INDEX($.session.connectAttrs.web, '.', 3)");
	expect_str("www.mysql", "SUBSTRING_INDEX('www.mysql.com', '.', 2)");
	expect_str("www.mysql", "SUBSTRING_INDEX($.session.connectAttrs.web, '.', 2)");
	expect_str("www", "SUBSTRING_INDEX('www.mysql.com', '.', 1)");
	expect_str("www", "SUBSTRING_INDEX($.session.connectAttrs.web, '.', 1)");
	expect_str("www.mysql.com", "SUBSTRING_INDEX('www.mysql.com', '.', 20)");
	expect_str("www.mysql.com", "SUBSTRING_INDEX('www.mysql.com', ',', 1)");
	expect_str("www.mysql.com", "SUBSTRING_INDEX($.session.connectAttrs.web, ',', -1)");
	expect_str("www.mysql.com", "SUBSTRING_INDEX('www.mysql.com', '.', -3)");
	expect_str("mysql.com", "SUBSTRING_INDEX('www.mysql.com', '.', -2)");
	expect_str("mysql.com", "SUBSTRING_INDEX($.session.connectAttrs.web, '.', -2)");
	expect_str("com", "SUBSTRING_INDEX('www.mysql.com', '.', -1)");
	expect_str("www.mysql.com", "SUBSTRING_INDEX('www.mysql.com', '.', -20)");
	expect_str(".a.b", "SUBSTRING_INDEX('.a.b', '.', -3)");
	expect_str("www", "SUBSTRING_INDEX('wwwXmysql', 'X', 1)");
	expect_str("wwwXmysql", "SUBSTRING_INDEX('wwwXmysql', 'x', 1)");
	expect_str("192.168", "SUBSTRING_INDEX($.router.bindAddress, '.', 2)");
	expect_str("www", "SUBSTRING_INDEX('www.mysql.com', '.', 1.9)");

	T("STARTSWITH('www.mysql.com', 'www.mysql')");
	T("STARTSWITH($.session.connectAttrs.web, 'www.')");
	T("STARTSWITH('www.Mysql.com', 'Www.mysql')");
	F("STARTSWITH('www.mysql.com', 'www,')");
	F("STARTSWITH($.session.connectAttrs.web, 'mysql')");
	T("STARTSWITH($.session.connectAttrs.web, '')");
	T("ENDSWITH('www.mysql.com', 'mysql.com')");
	T("ENDSWITH($.session.connectAttrs.web, '.com')");
	T("ENDSWITH('www.Mysql.Com', 'mysqL.com')");
	T("ENDSWITH($.session.connectAttrs.web, 'COM')");
	F("ENDSWITH('www.mysql.com', '.con')");
	F("ENDSWITH('com', 'www.mysql.com')");
	F("ENDSWITH('.com', $.session.connectAttrs.web)");
	T("CONTAINS('www.mysql.com.pl', 'mysql.COM')");
	T("CONTAINS('www.mysql.com', 'WWW')");
	T("CONTAINS($.session.connectAttrs.web, '.Com')");
	T("CONTAINS('www.Mysql.Com', $.session.connectAttrs.web)");
	T("CONTAINS($.session.connectAttrs.web, 'w.M')");
	T("CONTAINS($.session.connectAttrs.web, '')");
	F("CONTAINS($.session.connectAttrs.web, 'www.mysql.com1')");
	F("CONTAINS('www.mysql.org', $.session.connectAttrs.web)");
	F("CONTAINS('', $.session.connectAttrs.web)");

	expect_null("CONCAT (NULL)");
	expect_null("CONCAT(1, NULL)");
	expect_null("CONCAT(NULL, 'ele')");
	expect_null("CONCAT(1, 'ele', NULL)");
	expect_str("abra", "concat('abra')");
	expect_str("abracadabra,elemele", "concat(abra, cadabra, ',', ele, 'mele')");
	expect_str("1", "concat (true)");
	expect_str("0", "concat(false)");
	expect_str("777", "concat (777)");
	expect_str("777.777", "CONCAT (777.777)");
	expect_str("1.23457e+06", "CONCAT(1234567)");
	expect_str("abra1123.123cadabra1230", "concat('abra', TRUE, 123.123, cadabra, 123, FALSE)");
	expect_str("root@123.222.111.12:3306", "CONCAT($.session.user, '@', $.session.sourceIP, ':', $.server.port)");
	T("CONCAT($.session.user, 'x') = 'ROOTX'");

	expect_str("128.128.0.0", "network ('128.128.128.128', 16)");
	expect_str("221.221.221.0", "network('221.221.221.128', 24)");
	expect_str("221.0.0.0", "network('221.221.221.128', 8)");
	expect_str("127.0.0.1", "network('127.0.0.1', 32)");
	expect_str("192.168.0.0", "network($.router.bindAddress, 16)");
	expect_str("192.168.0.0", "network($.router.bindAddress, 4 * 4)");
	EE("network('foo', 16)", "Network function called on invalid IPv4 address: 'foo'");
	EE("network('::1', 16)", "invalid IPv4");
	PE("network($.router.bindAddress, $.router.port.ro)", "NETWORK function only accepts number literals as its 2nd argument");
	{
		const auto errors = scoped_errors("network($.server.address, 33) = '127.0.0.1'", ExpressionScope::destination);
		ok(errors.size() == 1 && errors[0] == "NETWORK function invalid netmask value: 33",
			"NETWORK netmask above 32 is rejected at load time (%s)", join(errors).c_str());
		const auto errors0 = scoped_errors("network($.server.address, 0) = '127.0.0.1'", ExpressionScope::destination);
		ok(errors0.size() == 1 && errors0[0] == "NETWORK function invalid netmask value: 0",
			"NETWORK netmask below 1 is rejected at load time (%s)", join(errors0).c_str());
	}

	T("is_ipv4('0.0.0.0')");
	T("is_ipv4('127.0.0.1')");
	T("is_ipv4('255.255.255.255')");
	T("is_ipv4('000.000.000.000')");
	T("is_ipv4($.server.address)");
	F("is_ipv4('')");
	F("is_ipv4('localhost')");
	F("is_ipv4('google.pl')");
	F("is_ipv4('::8.8.8.8')");
	F("is_ipv4('255.255.255.256')");
	F("is_ipv4('2010:836B:4179::836B:4179')");
	T("is_ipv6('FEDC:BA98:7654:3210:FEDC:BA98:7654:3210')");
	T("is_ipv6('1080:0:0:0:8:800:200C:4171')");
	T("is_ipv6('3ffe:2a00:100:7031::1')");
	T("is_ipv6('1080::8:800:200C:417A')");
	T("is_ipv6('::192.9.5.5')");
	T("is_ipv6('::1')");
	T("is_ipv6('fe80::850a:5a7c:6ab7:aec4%1')");
	T("is_ipv6('fe80::850a:5a7c:6ab7:aec4%eth0')");
	F("is_ipv6('')");
	F("is_ipv6('[::1]')");
	F("is_ipv6('localhost')");
	F("is_ipv6('unknown_host')");
	F("is_ipv6('127.0.0.1')");
	F("is_ipv6('FEDC:BA98:7654:3210:FEDC:BA98:7654:3210:')");
	F("is_ipv6('FEDC:BA98:7654:3210:GEDC:BA98:7654:3210')");
	F("is_ipv6($.server.address)");

	g_resolve_calls.clear();
	expect_str("7.7.7.7", "resolve_v4 ('localhost')");
	expect_str("2001:db8::1428:57ab", "resolve_v6(localhost)");
	expect_str("123.12.13.11", "RESOLVE_V4(ABRA)");
	ok(g_resolve_calls["abra/4"] == 1, "RESOLVE_V4 lower-cases the host name before resolving");
	EE("resolve_v4('oracle.com')", "No cache entry to resolve host: oracle.com");
	EE("resolve_v6('abra')", "No cache entry to resolve host: abra");
	PEX("resolve_v4('oracle_com')", "RESOLVE_V4 function, invalid hostname: 'oracle_com' in 'resolve_v4('oracle_com')'");
	PE("resolve_v6('-oracle.com')", "RESOLVE_V6 function, invalid hostname: '-oracle.com'");
	PE("resolve_v6('oracle..com')", "RESOLVE_V6 function, invalid hostname");
	PE("resolve_v4($.router.hostname)", "RESOLVE_V4 function only accepts string literals as its parameter");
	expect_str("7.7.7.7", "resolve_v4(SUBSTRING_INDEX('localhost.x', '.', 1))");
	{
		std::vector<std::string> errors;
		auto e = Expression::compile("resolve_v4('localhost') = '127.0.0.1'", ExpressionScope::any, "1.0", errors);
		ok(e && e->evaluate(nullptr, nullptr, nullptr).truthy(), "the default resolver resolves localhost");
	}
}

void test_type_errors() {
	diag("type errors");
	PE("sqrt('a')", "type error, SQRT function, expected NUMBER but got STRING");
	PE("sqrt(PRIMARY)", "got ROLE");
	PE("regexp_like('a', 2)", "REGEXP_LIKE function, 2nd argument, expected STRING but got NUMBER");
	PE("regexp_like(TRUE, 3)", "REGEXP_LIKE function, 1st argument, expected STRING but got BOOLEAN");
	PE("resolve_v4(1.1)", "RESOLVE_V4 function, expected STRING but got NUMBER");
	PE("resolve_v6(1.1)", "RESOLVE_V6 function, expected STRING but got NUMBER");
	PE("network('a', TRUE)", "NETWORK function, 2nd argument, expected NUMBER but got BOOLEAN");
	PE("network(1, 3)", "NETWORK function, 1st argument, expected STRING but got NUMBER");
	PE("SUBSTRING_INDEX('www.mysql.com', '.', '-3')", "SUBSTRING_INDEX function, 3rd argument, expected NUMBER but got STRING");
	PE("substring_index('www.mysql.com', 2, -3)", "SUBSTRING_INDEX function, 2nd argument, expected STRING but got NUMBER");
	PE("startswith('www.mysql.com', 2)", "STARTSWITH function, 2nd argument, expected STRING but got NUMBER");
	PE("endswith(2, 'dwa')", "ENDSWITH function, 1st argument, expected STRING but got NUMBER");
	PE("is_ipv4(4)", "IS_IPV4 function, expected STRING but got NUMBER");
	PE("number(4)", "NUMBER function, expected STRING but got NUMBER");
	PEX("2+'a'", "type error, + operator, right operand, expected NUMBER but got STRING in '2+'a''");
	PE("PRIMARY * 3", "* operator, left operand, expected NUMBER but got ROLE");
	PE("abra / 3", "/ operator, left operand, expected NUMBER but got STRING");
	PE("3 - true", "- operator, right operand, expected NUMBER but got BOOLEAN");
	PE("12 % abra", "% operator, right operand, expected NUMBER but got STRING");
	PE("-abra", "- operator, expected NUMBER but got STRING");
	PE("$.session.user + 1", "+ operator, left operand, expected NUMBER but got STRING");
	PE("2='a'", "= operator, the type of left operand does not match right, expected NUMBER but got STRING");
	PE("PRIMARY <> 3", "<> operator, the type of left operand does not match right, expected ROLE but got NUMBER");
	PE("abra >= 3", ">= operator, the type of left operand does not match right, expected STRING but got NUMBER");
	PE("3 > true", "> operator, the type of left operand does not match right, expected NUMBER but got BOOLEAN");
	PE("abra <= 3", "<= operator, the type of left operand does not match right, expected STRING but got NUMBER");
	PE("3 < true", "< operator, the type of left operand does not match right, expected NUMBER but got BOOLEAN");
	PE("false < true", "type error, BOOLEAN type arguments cannot be compared with < operator");
	PE("$.session.targetPort = '6446'", "expected NUMBER but got STRING");
	PE("1 like ala", "LIKE operator, left operand, expected STRING but got NUMBER");
	PE("ala like 1", "LIKE operator, right operand, expected STRING but got NUMBER");
	PEX("(1 + 2) * 'x' = 3", "type error, * operator, right operand, expected NUMBER but got STRING in '(1 + 2) * 'x''");
}

void test_like() {
	diag("LIKE");
	T("$.session.connectAttrs.web like ''");
	T("$.session.connectAttrs.fun like '%'");
	T("$.session.connectAttrs.web LIKE '%mysql%'");
	T("$.session.connectAttrs.web LIKE '%MySQL.COM'");
	T("$.session.connectAttrs.web LIKE 'WWW.%'");
	F("$.session.connectAttrs.web LIKE 'mysql%'");
	F("$.session.connectAttrs.web LIKE '%mysql'");
	F("$.session.connectAttrs.web LIKE '%oracle%'");
	T(R"($.session.connectAttrs.fun LIKE '\\%\\_%')");
	T(R"($.session.connectAttrs.fun LIKE '%\\_\\%')");
	F(R"($.session.connectAttrs.web LIKE '\\%%')");
	T("$.session.connectAttrs.web LIKE '___.%.___'");
	F("$.session.connectAttrs.web not LIKE '___.%.___'");
	F("$.session.connectAttrs.web NOT like '___.%.___'");
	T("$.session.connectAttrs.fun LIKE '%\\\\__\\\\_\\\\%'");
	F("$.session.connectAttrs.fun NOT LIKE '%\\\\__\\\\_\\\\%'");
	F("$.session.connectAttrs.fun LIKE '.*'");
	T("$.session.connectAttrs.fun not like '.*'");
	F("$.session.connectAttrs.web LIKE 'www_mysql_co'");
	T("$.session.connectAttrs.web LIKE 'www_mysql_com'");
	F("'abc' LIKE 'a.c'");
	T("'a.c' LIKE 'a.c'");
	T("'a+b(c)' LIKE 'A+B(C)'");
	T("'abc' LIKE 'ABC'");
	F("'abcd' LIKE 'abc'");
	// single character prefix/suffix/infix and '%%'
	T("'abc' LIKE 'a%'");
	T("'abc' LIKE '%c'");
	T("'abc' LIKE '%b%'");
	F("'abc' LIKE 'b%'");
	T("'abc' LIKE '%%'");
	T("'' LIKE '%%'");
	T("'abc' LIKE 'a%c'");
	F("'abc' LIKE 'a%d'");
	T("$.session.user LIKE 'r%t'");
	T("'100%' LIKE '%\\\\%'");
	F("'100' LIKE '%\\\\%'");
	T("'a\\\\b' LIKE 'a\\\\b'");
	T("'user_1' LIKE 'user\\\\_%'");
	F("'userX1' LIKE 'user\\\\_%'");
	PEX("'abradab' LIKE $.session.connectAttrs.fun", "LIKE operator only accepts string literals as its right operand in ''abradab' LIKE $.session.connectAttrs.fun'");
	PE("'abradab' LIKE CONCAT('a', '%')", "LIKE operator only accepts string literals as its right operand");
	T("'abradab' LIKE SUBSTRING_INDEX('abra%.x', '.', 1)");
}

void test_tags() {
	diag("tags 1.0 / 1.1");
	g_server.tags = {{"region", "\"EU\""}, {"weight", "41"}, {"active", "true"}, {"obj", "{\"a\":1}"},
		{"list", "[1,2]"}, {"plain", "EU"}};
	g_router.tags = {{"dc", "\"dc1\""}};
	// 1.1: the literal following a tag reference is compared as JSON text
	T("$.server.tags.region = 'EU'", "1.1");
	T("$.server.tags.region = \"EU\"", "1.1");
	T("$.server.tags.region = 'eu'", "1.1");
	F("$.server.tags.region = 'US'", "1.1");
	T("$.server.tags.weight = 41", "1.1");
	F("$.server.tags.weight = 42", "1.1");
	T("$.server.tags.active = true", "1.1");
	T("$.server.tags.active = TRUE", "1.1");
	T("$.server.tags.obj = {\"a\":1}", "1.1");
	T("$.server.tags.list = [1,2]", "1.1");
	T("$.router.tags.dc = 'dc1'", "1.1");
	T("$.router.tags.dc = 'dc1' AND $.server.tags.region = 'EU'", "1.1");
	T("$.server.tags.region <> 'US'", "1.1");
	T("$.server.tags.missing = 'x' OR TRUE", "1.1");
	// the literal after a tag reference keeps its quotes wherever it appears
	expect_str("\"EU\"\"x\"", "CONCAT($.server.tags.region, 'x')", "1.1");
	expect_str("\"EU\"x", "CONCAT($.server.tags.region, x)", "1.1");
	PE("NUMBER($.server.tags.weight) > 1", "> operator, the type of left operand does not match right, expected NUMBER but got STRING", "1.1");
	T("NUMBER($.server.tags.weight) > 1", "1.0");
	// connect attributes are not tags
	T("$.session.connectAttrs.mysql = 'MySQL'", "1.1");
	// 1.0: no translation, Shell escapes the JSON text explicitly
	F("$.server.tags.region = 'EU'", "1.0");
	T("$.server.tags.region = '\"EU\"'", "1.0");
	T("$.server.tags.plain = 'EU'", "1.0");
	T("$.server.tags.weight = '41'", "1.0");
	PE("$.server.tags.weight = 41", "= operator, the type of left operand does not match right, expected STRING but got NUMBER", "1.0");
	PE("$.server.tags.obj = {\"a\":1}", "unexpected character: '{'", "1.0");
	PE("$.server.tags.obj = {\"a\":1", "syntax error, unclosed {", "1.1");
	// Router quirks in 1.1: identifiers do not consume the tag mode, keywords do
	PE("$.server.tags.region IN ('EU')", "syntax error, unexpected string, expecting end of expression or error", "1.1");
	PE("$.server.tags.plain = EU AND TRUE", "syntax error, unexpected string", "1.1");
	T("$.server.tags.plain = EU", "1.1");
	T("$.server.tags.region IN ('\"EU\"')", "1.0");
	PE("$.server.tags.weight = SQRT(4)", "SQRT function, expected NUMBER but got STRING", "1.1");
	reset_context();
}

void test_context() {
	diag("context restrictions");
	auto errors = scoped_errors("$.session.user = 'x'", ExpressionScope::destination);
	ok(errors.size() == 1 && errors[0] == "session.user may not be used in 'destinations' context",
		"session variables are rejected in destinations (%s)", join(errors).c_str());
	errors = scoped_errors("$.server.address = 'x'", ExpressionScope::route);
	ok(errors.size() == 1 && errors[0] == "server.address may not be used in 'routes' context",
		"server variables are rejected in routes (%s)", join(errors).c_str());
	errors = scoped_errors("$.server.port = $.server.port AND $.session.targetPort = 1 AND $.session.user = 'a'", ExpressionScope::destination);
	ok(errors.size() == 2 && errors[0] == "session.targetPort may not be used in 'destinations' context" &&
		errors[1] == "session.user may not be used in 'destinations' context",
		"every forbidden reference is reported in order (%s)", join(errors).c_str());
	errors = scoped_errors("$.router.port.ro = 1 AND $.router.name = 'x'", ExpressionScope::destination);
	ok(errors.empty(), "router variables are allowed in destinations (%s)", join(errors).c_str());
	errors = scoped_errors("$.router.port.ro = 1 AND $.router.routeName = 'x'", ExpressionScope::route);
	ok(errors.empty(), "router variables are allowed in routes (%s)", join(errors).c_str());
	errors = scoped_errors("$.session.connectAttrs.x = 'x'", ExpressionScope::destination);
	ok(errors.empty(), "tag references are not context checked (Router) (%s)", join(errors).c_str());
	errors = scoped_errors("$.server.port", ExpressionScope::destination);
	ok(errors.size() == 1 && errors[0] == "match does not evaluate to boolean",
		"a non boolean match is rejected (%s)", join(errors).c_str());
	errors = scoped_errors("   ", ExpressionScope::route);
	ok(errors.size() == 1 && errors[0] == "match does not evaluate to boolean",
		"an empty match is rejected (%s)", join(errors).c_str());
	errors = scoped_errors("CONTAINS($.server.tags.x, 'a')", ExpressionScope::destination);
	ok(errors.size() == 1 && errors[0] == "match does not evaluate to boolean",
		"a match that is NULL for untagged servers is rejected (Router dry run) (%s)", join(errors).c_str());
	errors = scoped_errors("$.server.tags.x = 'a'", ExpressionScope::destination);
	ok(errors.empty(), "a tag comparison is a valid match (%s)", join(errors).c_str());
	std::vector<std::string> errs;
	ok(!Expression::compile("$.session.user = 'x'", ExpressionScope::destination, "1.1", errs),
		"compile() fails on context errors");
	errs.clear();
	ok(Expression::compile("$.session.user = 'x'", ExpressionScope::route, "1.1", errs) && errs.empty(),
		"compile() succeeds for a valid route match");
}

// ---------------------------------------------------------------------------
// Documents.
// ---------------------------------------------------------------------------

void test_document_validation() {
	diag("document validation");
	std::vector<Error> errors;
	ok(!parse_doc("", errors) && errors.size() == 1 && contains(errors[0].message, "The document is empty"),
		"empty document (%s)", join(errors).c_str());
	errors.clear();
	ok(!parse_doc("{", errors) && errors.size() == 1 && contains(errors[0].message, "incorrect JSON"),
		"malformed JSON (%s)", join(errors).c_str());
	errors.clear();
	ok(!parse_doc("[]", errors) && errors.size() == 1 &&
		errors[0].message == "routing guidelines needs to be specified as a JSON document",
		"non object document (%s)", join(errors).c_str());
	errors.clear();
	ok(!parse_doc("{}", errors) && errors.size() == 2 &&
		format_error(errors[0]) == "no destination classes defined by the document" &&
		format_error(errors[1]) == "no routes defined by the document", "empty object (%s)", join(errors).c_str());
	expect_doc_error("{\"routes\": 3}", "routes", "field is expected to be an array", "routes not an array");

	// Router's incomplete_document vectors
	const std::string bad = R"json({
"name": 1,
"version" : "1.0",
"destinations": [
  {"klass": "primary", "match": "$.server.role = PRIMARY"},
  {"name": "secondary", "match": ""},
  {"name": "", "match": 5}],
"routes": [
  {"name": "rw", "match": "$.session.targetPort = $.router.port.rw",
   "destinations": {"classes": ["primary"], "strategy": "round-robin", "priority": 0}},
  {"name": "3", "match": 3,
   "destination": [{"classes" : ["secondary"], "strategy": "round-robin", "priority": 0},
                   {"classes": ["primary"], "strategy": "first-available", "priority": 1}]},
  {"name": "ro", "match": "$.session.targetPort = $.router.port.ro and $.server.targetPort = $.router.port.ro",
   "destinations": [{"classes": [], "strategy": "roundrobin", "priority": 0},{"classes": ["primary"]}]}
]})json";
	errors.clear();
	const auto g = parse_doc(bad, errors);
	const std::vector<std::string> expected {
		"name: field is expected to be a string",
		"destinations[0].klass: unexpected field name, only 'name' and 'match' are allowed",
		"destinations[0].match: undefined variable: server.role in '$.server.role'",
		"destinations[0]: 'name' field not defined",
		"destinations[0]: 'match' field not defined",
		"destinations[1].match: field is expected to be a non empty string",
		"destinations[1]: 'match' field not defined",
		"destinations[2].name: field is expected to be a non empty string",
		"destinations[2].match: field is expected to be a string",
		"destinations[2]: 'name' field not defined",
		"destinations[2]: 'match' field not defined",
		"routes[0].destinations: field is expected to be an array",
		"routes[1].match: field is expected to be a string",
		"routes[1].destination: unexpected field, only 'name', 'connectionSharingAllowed', 'enabled', 'match' and 'destinations' are allowed",
		"routes[1]: 'destinations' field not defined",
		"routes[2].match: undefined variable: server.targetPort in '$.server.targetPort'",
		"routes[2].destinations[0].classes: field is expected to be a non empty array",
		"routes[2].destinations[0].strategy: unexpected value 'roundrobin', supported strategies: round-robin, first-available",
		"routes[2].destinations[1]: 'strategy' field not defined",
		"routes[2].destinations[1]: 'priority' field not defined",
		"no destination classes defined by the document",
		"no routes defined by the document",
		"routes[2].destinations[1].classes[0]: undefined destination class 'primary' found in route 'ro'",
	};
	std::vector<std::string> got;
	for (const auto& e : errors) got.push_back(format_error(e));
	ok(!g && got == expected, "all errors are collected with JSON paths");
	if (got != expected) {
		for (size_t i = 0; i < std::max(got.size(), expected.size()); i++) {
			diag("  got[%zu]=%s | expected=%s", i, i < got.size() ? got[i].c_str() : "-",
				i < expected.size() ? expected[i].c_str() : "-");
		}
	}

	errors.clear();
	ok(!parse_doc(R"json({"version" : "1.0",
"destinations": [{"name": "primary", "match": "true"},
  {"name": "wc", "match": "$.server.clusterRole = SECONDARY"},
  {"name": "wm", "match": "$.server.memberRole = REPLICA"}],
"routes": [{"name": "rw", "match": "true",
  "destinations": [{"classes": ["primary"], "strategy": "first-available", "priority": 0}]}]})json", errors) &&
		errors.size() == 4 &&
		format_error(errors[0]) == "destinations[1].match: type error, incompatible operands for comparison: 'CLUSTER ROLE' vs 'MEMBER ROLE' in '$.server.clusterRole = SECONDARY'" &&
		format_error(errors[1]) == "destinations[1]: 'match' field not defined" &&
		format_error(errors[2]) == "destinations[2].match: type error, incompatible operands for comparison: 'MEMBER ROLE' vs 'CLUSTER ROLE' in '$.server.memberRole = REPLICA'" &&
		format_error(errors[3]) == "destinations[2]: 'match' field not defined",
		"role type errors in destinations (%s)", join(errors).c_str());

	// unknown fields at every level
	expect_doc_error(doc_with(kDests, kRoutes, "\"version\": \"1.1\", \"extra\": 1,"), "extra",
		"Unexpected field, only 'version', 'name', 'destinations', and 'routes' are allowed", "top level unknown field");
	expect_doc_error(doc_with(R"([{"name": "Primary", "match": "TRUE", "prio": 1}])", kRoutes), "destinations[0].prio",
		"unexpected field name, only 'name' and 'match' are allowed", "destination unknown field");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE", "shared": true,
		"destinations": [{"classes": ["Primary"], "strategy": "round-robin", "priority": 0}]}])"), "routes[0].shared",
		"unexpected field, only 'name', 'connectionSharingAllowed', 'enabled', 'match' and 'destinations' are allowed", "route unknown field");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE",
		"destinations": [{"classes": ["Primary"], "strategy": "round-robin", "priority": 0, "weight": 3}]}])"),
		"routes[0].destinations[0].weight", "unexpected field name", "destination group unknown field");
	// duplicates
	expect_doc_error(doc_with(R"([{"name": "Primary", "match": "TRUE"}, {"name": "Primary", "match": "FALSE"}])", kRoutes),
		"destinations[1]", "'Primary' class was already defined", "duplicate destination");
	expect_doc_error(doc_with(kDests, R"([
		{"name": "rw", "match": "TRUE", "destinations": [{"classes": ["Primary"], "strategy": "round-robin", "priority": 0}]},
		{"name": "rw", "match": "FALSE", "destinations": [{"classes": ["Primary"], "strategy": "round-robin", "priority": 0}]}])"),
		"routes[1]", "'rw' route was already defined", "duplicate route");
	// undefined classes
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE",
		"destinations": [{"classes": ["Primary", "Nope"], "strategy": "round-robin", "priority": 0}]}])"),
		"routes[0].destinations[0].classes[1]", "undefined destination class 'Nope' found in route 'rw'", "undefined class");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE",
		"destinations": [{"classes": ["primary"], "strategy": "round-robin", "priority": 0}]}])"),
		"routes[0].destinations[0].classes[0]", "undefined destination class 'primary'", "class names are case-sensitive");
	// strategy / priority / classes
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE",
		"destinations": [{"classes": ["Primary"], "strategy": "random", "priority": 0}]}])"),
		"routes[0].destinations[0].strategy", "unexpected value 'random', supported strategies: round-robin, first-available", "bad strategy");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE",
		"destinations": [{"classes": ["Primary"], "strategy": 1, "priority": 0}]}])"),
		"routes[0].destinations[0].strategy", "field is expected to be a string", "non string strategy");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE",
		"destinations": [{"classes": ["Primary"], "strategy": "round-robin", "priority": -1}]}])"),
		"routes[0].destinations[0].priority", "field is expected to be a positive integer", "negative priority");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE",
		"destinations": [{"classes": ["Primary"], "strategy": "round-robin", "priority": 1.5}]}])"),
		"routes[0].destinations[0].priority", "field is expected to be a positive integer", "fractional priority");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE",
		"destinations": [{"classes": ["Primary"], "strategy": "round-robin", "priority": "0"}]}])"),
		"routes[0].destinations[0].priority", "field is expected to be a positive integer", "string priority");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE",
		"destinations": [{"classes": ["Primary"], "strategy": "round-robin"}]}])"),
		"routes[0].destinations[0]", "'priority' field not defined", "missing priority");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE",
		"destinations": [{"strategy": "round-robin", "priority": 0}]}])"),
		"routes[0].destinations[0]", "'classes' field not defined", "missing classes");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE",
		"destinations": [{"classes": [""], "strategy": "round-robin", "priority": 0}]}])"),
		"routes[0].destinations[0].classes[0]", "field is expected to be a non empty string", "empty class name");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE",
		"destinations": [{"classes": "Primary", "strategy": "round-robin", "priority": 0}]}])"),
		"routes[0].destinations[0].classes", "field is expected to be an array", "classes not an array");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE", "destinations": []}])"),
		"routes[0].destinations", "field is expected to be a non empty array", "empty route destinations");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE", "destinations": [3]}])"),
		"routes[0].destinations[0]", "field is expected to be an object", "route destination not an object");
	expect_doc_error(doc_with("[]", kRoutes), "destinations", "field is expected to be a non empty array", "empty destinations");
	expect_doc_error(doc_with(kDests, "[]"), "routes", "field is expected to be a non empty array", "empty routes");
	expect_doc_error(doc_with("[1]", kRoutes), "destinations[0]", "field is expected to be an object", "destination not an object");
	expect_doc_error(doc_with(kDests, "[\"rw\"]"), "routes[0]", "field is expected to be an object", "route not an object");
	// route fields
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE", "enabled": "yes",
		"destinations": [{"classes": ["Primary"], "strategy": "round-robin", "priority": 0}]}])"),
		"routes[0].enabled", "field is expected to be boolean", "non boolean enabled");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "TRUE", "connectionSharingAllowed": 1,
		"destinations": [{"classes": ["Primary"], "strategy": "round-robin", "priority": 0}]}])"),
		"routes[0].connectionSharingAllowed", "field is expected to be boolean", "non boolean connectionSharingAllowed");
	expect_doc_error(doc_with(kDests, R"([{"match": "TRUE",
		"destinations": [{"classes": ["Primary"], "strategy": "round-robin", "priority": 0}]}])"),
		"routes[0]", "'name' field not defined", "route without name");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw",
		"destinations": [{"classes": ["Primary"], "strategy": "round-robin", "priority": 0}]}])"),
		"routes[0]", "'match' field not defined", "route without match");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "$.server.port = 1",
		"destinations": [{"classes": ["Primary"], "strategy": "round-robin", "priority": 0}]}])"),
		"routes[0].match", "server.port may not be used in 'routes' context", "server variable in route");
	expect_doc_error(doc_with(R"([{"name": "Primary", "match": "$.session.user = 'x'"}])", kRoutes),
		"destinations[0].match", "session.user may not be used in 'destinations' context", "session variable in destination");
	expect_doc_error(doc_with(R"([{"name": "Primary", "match": "$.server.port"}])", kRoutes),
		"destinations[0].match", "match does not evaluate to boolean", "non boolean destination");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "$.session.targetPort + 1",
		"destinations": [{"classes": ["Primary"], "strategy": "round-robin", "priority": 0}]}])"),
		"routes[0].match", "match does not evaluate to boolean", "non boolean route");
	expect_doc_error(doc_with(kDests, R"([{"name": "rw", "match": "$.session.targetPort = ",
		"destinations": [{"classes": ["Primary"], "strategy": "round-robin", "priority": 0}]}])"),
		"routes[0].match", "syntax error, unexpected end of expression", "route syntax error");
	expect_doc_error(doc_with(kDests, kRoutes, "\"version\": \"1.1\", \"name\": \"\","), "name",
		"field is expected to be a non empty string", "empty name");

	// versions
	auto version_ok = [](const std::string& extra, const char* expected_version, const char* what) {
		std::vector<Error> errs;
		const auto gl = parse_doc(doc_with(kDests, kRoutes, extra), errs);
		ok(gl && errs.empty() && gl->version() == expected_version, "%s accepted as version %s (%s)", what,
			expected_version, join(errs).c_str());
	};
	version_ok("", "1.0", "missing version");
	version_ok("\"version\": \"1.0\",", "1.0", "1.0");
	version_ok("\"version\": \"1.1\",", "1.1", "1.1");
	version_ok("\"version\": \"0.9\",", "0.9", "0.9 (Router compatibility rule)");
	expect_doc_error(doc_with(kDests, kRoutes, "\"version\": \"1.2\","), "version",
		"routing guidelines version not supported, supported version is 1.1 but got 1.2", "newer minor version");
	expect_doc_error(doc_with(kDests, kRoutes, "\"version\": \"2.0\","), "version", "not supported", "newer major version");
	expect_doc_error(doc_with(kDests, kRoutes, "\"version\": \"1.1o\","), "version",
		"Invalid routing guidelines version format. Expected <major>.<minor> got 1.1o", "invalid version");
	for (const char* v : {".1", "v2.4", "1.o", "2,2", "3.", "-1.9", "1.-9", "1", "1.1.1", ""}) {
		expect_doc_error(doc_with(kDests, kRoutes, std::string("\"version\": \"") + v + "\","), "version",
			"Invalid routing guidelines version format", v);
	}
	expect_doc_error(doc_with(kDests, kRoutes, "\"version\": 1.1,"), "version", "field is expected to be a string", "numeric version");
}

// Shell's default guideline for an InnoDB Cluster (read_only_targets = secondaries)
const char* kShellClusterDefault = R"json({
  "destinations": [
    {"match": "$.server.memberRole = PRIMARY", "name": "Primary"},
    {"match": "$.server.memberRole = SECONDARY", "name": "Secondary"},
    {"match": "$.server.memberRole = READ_REPLICA", "name": "ReadReplica"}
  ],
  "name": "default",
  "routes": [
    {"connectionSharingAllowed": true,
     "destinations": [{"classes": ["Primary"], "priority": 0, "strategy": "round-robin"}],
     "enabled": true, "match": "$.session.targetPort = $.router.port.rw", "name": "rw"},
    {"connectionSharingAllowed": true,
     "destinations": [{"classes": ["Secondary"], "priority": 0, "strategy": "round-robin"},
                      {"classes": ["Primary"], "priority": 1, "strategy": "round-robin"}],
     "enabled": true, "match": "$.session.targetPort = $.router.port.ro", "name": "ro"}
  ],
  "version": "1.1"
})json";

const char* kShellClusterSetDefault = R"json({
  "destinations": [
    {"match": "$.server.memberRole = PRIMARY AND ($.server.clusterRole = PRIMARY OR $.server.clusterRole = UNDEFINED)", "name": "Primary"},
    {"match": "$.server.memberRole = SECONDARY AND ($.server.clusterRole = PRIMARY OR $.server.clusterRole = UNDEFINED)", "name": "PrimaryClusterSecondary"},
    {"match": "$.server.memberRole = READ_REPLICA AND ($.server.clusterRole = PRIMARY OR $.server.clusterRole = UNDEFINED)", "name": "PrimaryClusterReadReplica"}
  ],
  "name": "default",
  "routes": [
    {"connectionSharingAllowed": true,
     "destinations": [{"classes": ["Primary"], "priority": 0, "strategy": "round-robin"}],
     "enabled": true, "match": "$.session.targetPort = $.router.port.rw", "name": "rw"},
    {"connectionSharingAllowed": true,
     "destinations": [{"classes": ["PrimaryClusterSecondary"], "priority": 0, "strategy": "round-robin"},
                      {"classes": ["Primary"], "priority": 1, "strategy": "round-robin"}],
     "enabled": true, "match": "$.session.targetPort = $.router.port.ro", "name": "ro"}
  ],
  "version": "1.1"
})json";

const char* kShellReplicaSetDefault = R"json({
  "destinations": [
    {"match": "$.server.memberRole = PRIMARY", "name": "Primary"},
    {"match": "$.server.memberRole = SECONDARY", "name": "Secondary"}
  ],
  "name": "default",
  "routes": [
    {"connectionSharingAllowed": true,
     "destinations": [{"classes": ["Primary"], "priority": 0, "strategy": "round-robin"}],
     "enabled": true, "match": "$.session.targetPort = $.router.port.rw", "name": "rw"},
    {"connectionSharingAllowed": true,
     "destinations": [{"classes": ["Secondary"], "priority": 0, "strategy": "round-robin"},
                      {"classes": ["Primary"], "priority": 1, "strategy": "round-robin"}],
     "enabled": true, "match": "$.session.targetPort = $.router.port.ro", "name": "ro"}
  ],
  "version": "1.1"
})json";

std::vector<std::string> classify(const Guideline& g, MemberRole member, ClusterRole cluster = ClusterRole::undefined) {
	ServerInfo s = g_server;
	s.member_role = member;
	s.cluster_role = cluster;
	std::vector<Error> errors;
	auto classes = g.classify(s, g_router, errors);
	if (!errors.empty()) classes.push_back("ERROR:" + join(errors));
	return classes;
}

std::string route_for_port(const Guideline& g, uint16_t port) {
	SessionInfo s = g_session;
	s.target_port = port;
	std::vector<Error> errors;
	const auto idx = g.match_route(s, g_router, errors);
	if (!errors.empty()) return "ERROR:" + join(errors);
	return idx ? g.routes()[*idx].name : std::string("<none>");
}

using Names = std::vector<std::string>;

void test_shell_defaults() {
	diag("MySQL Shell default guidelines");
	std::vector<Error> errors;
	const auto ic = parse_doc(kShellClusterDefault, errors);
	ok(ic && errors.empty(), "InnoDB Cluster default guideline parses (%s)", join(errors).c_str());
	if (ic) {
		ok(ic->name() == "default" && ic->version() == "1.1", "name and version");
		ok(ic->destinations().size() == 3 && ic->destinations()[2].name == "ReadReplica" &&
			ic->destinations()[2].match == "$.server.memberRole = READ_REPLICA", "destinations in document order");
		ok(ic->routes().size() == 2 && ic->routes()[1].groups.size() == 2 &&
			ic->routes()[1].groups[0].classes == Names {"Secondary"} && ic->routes()[1].groups[1].priority == 1 &&
			ic->routes()[1].groups[0].strategy == Strategy::round_robin, "ro route groups");
		ok(ic->routes()[0].connection_sharing_allowed == std::optional<bool>(true) && ic->routes()[0].enabled,
			"route flags");
		ok(!ic->uses_router_route_name_in_destinations(), "routeName not used in destinations");
		ok(classify(*ic, MemberRole::primary) == Names {"Primary"}, "primary classified as Primary");
		ok(classify(*ic, MemberRole::secondary) == Names {"Secondary"}, "secondary classified as Secondary");
		ok(classify(*ic, MemberRole::read_replica) == Names {"ReadReplica"}, "read replica classified as ReadReplica");
		ok(classify(*ic, MemberRole::undefined).empty(), "undefined member role matches no class");
		ok(route_for_port(*ic, 6446) == "rw", "rw port matches the rw route");
		ok(route_for_port(*ic, 6447) == "ro", "ro port matches the ro route");
		ok(route_for_port(*ic, 6450) == "<none>", "rw_split port matches no default route");
		ok(route_for_port(*ic, 3306) == "<none>", "unknown port matches no route");
	}
	errors.clear();
	const auto cs = parse_doc(kShellClusterSetDefault, errors);
	ok(cs && errors.empty(), "ClusterSet default guideline parses (%s)", join(errors).c_str());
	if (cs) {
		ok(classify(*cs, MemberRole::primary, ClusterRole::primary) == Names {"Primary"}, "global primary");
		ok(classify(*cs, MemberRole::primary, ClusterRole::undefined) == Names {"Primary"}, "primary of a plain cluster");
		ok(classify(*cs, MemberRole::primary, ClusterRole::replica).empty(), "primary of a replica cluster");
		ok(classify(*cs, MemberRole::secondary, ClusterRole::primary) == Names {"PrimaryClusterSecondary"}, "secondary of the primary cluster");
		ok(classify(*cs, MemberRole::secondary, ClusterRole::replica).empty(), "secondary of a replica cluster");
		ok(classify(*cs, MemberRole::read_replica, ClusterRole::primary) == Names {"PrimaryClusterReadReplica"}, "read replica of the primary cluster");
		ok(classify(*cs, MemberRole::read_replica, ClusterRole::replica).empty(), "read replica of a replica cluster");
		ok(route_for_port(*cs, 6446) == "rw" && route_for_port(*cs, 6447) == "ro", "ClusterSet routes by port");
	}
	errors.clear();
	const auto rs = parse_doc(kShellReplicaSetDefault, errors);
	ok(rs && errors.empty(), "ReplicaSet default guideline parses (%s)", join(errors).c_str());
	if (rs) {
		ok(classify(*rs, MemberRole::primary) == Names {"Primary"}, "ReplicaSet primary");
		ok(classify(*rs, MemberRole::secondary) == Names {"Secondary"}, "ReplicaSet secondary");
		ok(classify(*rs, MemberRole::read_replica).empty(), "ReplicaSet has no read replica class");
		ok(route_for_port(*rs, 6446) == "rw" && route_for_port(*rs, 6447) == "ro", "ReplicaSet routes by port");
	}
	// Shell 1.0 documents (auto-escaped tags) still parse
	errors.clear();
	const auto v10 = parse_doc(R"json({"version": "1.0", "name": "tags",
		"destinations": [{"name": "EU", "match": "$.server.tags.region = '\"EU\"'"},
		                 {"name": "Any", "match": "TRUE"}],
		"routes": [{"name": "eu", "match": "$.router.tags.dc = '\"dc1\"'",
		            "destinations": [{"classes": ["EU"], "strategy": "first-available", "priority": 0}]}]})json", errors);
	ok(v10 && errors.empty(), "1.0 document with escaped tags parses (%s)", join(errors).c_str());
	if (v10) {
		ServerInfo s = g_server;
		s.tags = {{"region", "\"EU\""}};
		RouterInfo r = g_router;
		r.tags = {{"dc", "\"dc1\""}};
		std::vector<Error> errs;
		ok(v10->classify(s, r, errs) == Names({"EU", "Any"}) && errs.empty(), "1.0 tag classification");
		ok(v10->match_route(g_session, r, errs) == std::optional<size_t>(0), "1.0 router tag route");
		ok(v10->match_route(g_session, g_router, errs) == std::nullopt && errs.empty(), "missing router tag does not match");
	}
	errors.clear();
	const auto v11 = parse_doc(R"json({"version": "1.1", "name": "tags",
		"destinations": [{"name": "EU", "match": "$.server.tags.region = 'EU'"}],
		"routes": [{"name": "eu", "match": "$.router.tags.dc = 'dc1'",
		            "destinations": [{"classes": ["EU"], "strategy": "first-available", "priority": 0}]}]})json", errors);
	ok(v11 && errors.empty(), "1.1 document with tags parses (%s)", join(errors).c_str());
	if (v11) {
		ServerInfo s = g_server;
		s.tags = {{"region", "\"EU\""}};
		RouterInfo r = g_router;
		r.tags = {{"dc", "\"dc1\""}};
		std::vector<Error> errs;
		ok(v11->classify(s, r, errs) == Names {"EU"} && errs.empty(), "1.1 tag classification");
		ok(v11->match_route(g_session, r, errs) == std::optional<size_t>(0), "1.1 router tag route");
	}
}

const char* kClusterSets = R"^({
  "name": "Cluster sets",
  "version": "1.0",
  "destinations":[
    {"name":"serverB", "match":"$.server.address = '192.168.5.5'"},
    {"name":"globalPrimary", "match":"$.server.memberRole = PRIMARY and $.server.clusterRole = PRIMARY"},
    {"name":"otherPrimary", "match":"$.server.memberRole = PRIMARY and $.server.clusterRole <> PRIMARY"},
    {"name":"localSecondaries", "match":"$.server.memberRole = SECONDARY and network($.server.address, 24) = network($.router.bindAddress, 24)"},
    {"name":"remoteSecondaries", "match":"$.server.memberRole = SECONDARY and network($.server.address, 24) <> network($.router.bindAddress, 24)"}
  ],
  "routes":[
    {"name": "192.168.1.13", "match":"$.session.sourceIP = '192.168.1.13'",
     "destinations":  [{"classes": ["serverB"], "strategy": "first-available", "priority": 0},
                       {"classes": ["globalPrimary"], "strategy": "first-available", "priority": 1}]},
    {"name": "app_sync", "match":"$.session.user = 'app_sync'",
     "destinations": [{"classes": ["localSecondaries"], "strategy": "round-robin", "priority": 0},
                      {"classes": ["otherPrimary"], "strategy": "first-available", "priority": 1}]},
    {"name": "reads", "match":"$.session.targetPort in ($.router.port.ro)",
     "destinations": [{"classes": ["localSecondaries", "remoteSecondaries"], "strategy": "round-robin", "priority": 0},
                      {"classes": ["globalPrimary"], "strategy": "round-robin", "priority": 1},
                      {"classes": ["serverB"], "strategy": "round-robin", "priority": 2}]},
    {"name": "writes", "match":"$.session.targetPort in ($.router.port.rw)",
     "destinations": [{"classes": ["globalPrimary"], "strategy": "first-available", "priority": 0}]}
  ]
})^";

void test_classification_and_routes() {
	diag("classification and route matching");
	std::vector<Error> errors;
	const auto g = parse_doc(kClusterSets, errors);
	ok(g && errors.empty(), "Router cluster set document parses (%s)", join(errors).c_str());
	if (g) {
		RouterInfo r;
		r.port_ro = 3306;
		r.port_rw = 3307;
		r.port_rw_split = 3308;
		r.bind_address = "192.168.0.123";
		ServerInfo s;
		s.address = "192.168.5.5";
		s.member_role = MemberRole::primary;
		s.cluster_role = ClusterRole::undefined;
		std::vector<Error> errs;
		ok(g->classify(s, r, errs) == Names({"serverB", "otherPrimary"}), "serverB + otherPrimary");
		s.address = "192.168.5.4";
		ok(g->classify(s, r, errs) == Names {"otherPrimary"}, "otherPrimary");
		s.cluster_role = ClusterRole::primary;
		ok(g->classify(s, r, errs) == Names {"globalPrimary"}, "globalPrimary");
		s.member_role = MemberRole::secondary;
		ok(g->classify(s, r, errs) == Names {"remoteSecondaries"}, "remoteSecondaries");
		s.address = "192.168.0.12";
		ok(g->classify(s, r, errs) == Names {"localSecondaries"}, "localSecondaries");
		s.member_role = MemberRole::undefined;
		ok(g->classify(s, r, errs).empty() && errs.empty(), "no class");

		SessionInfo se;
		se.target_ip = "192.168.0.123";
		se.target_port = 3306;
		se.source_ip = "192.168.1.13";
		se.user = "root";
		const auto name = [&](void) -> std::string {
			const auto idx = g->match_route(se, r, errs);
			return idx ? g->routes()[*idx].name : "<none>";
		};
		ok(name() == "192.168.1.13", "source IP route wins (first match)");
		se.source_ip = "192.168.0.55";
		ok(name() == "reads", "reads route");
		se.target_port = 3307;
		ok(name() == "writes", "writes route");
		se.user = "app_sync";
		ok(name() == "app_sync", "user route precedes port routes");
		se.user = "APP_SYNC";
		ok(name() == "app_sync", "user comparison is case-insensitive");
		se.user = "other";
		se.target_port = 1;
		ok(name() == "<none>" && errs.empty(), "no route matches");
		ok(g->routes()[2].groups.size() == 3 && g->routes()[2].groups[2].classes == Names {"serverB"} &&
			g->routes()[0].groups[0].strategy == Strategy::first_available, "route groups preserved");
	}

	// route order, enabled flag and priority sorting
	errors.clear();
	const auto order = parse_doc(R"json({"version": "1.1",
		"destinations": [{"name": "A", "match": "$.server.port = 1"}, {"name": "B", "match": "$.server.port = 2"},
		                 {"name": "C", "match": "$.server.port < 3"}],
		"routes": [
		  {"name": "disabled", "enabled": false, "match": "TRUE",
		   "destinations": [{"classes": ["A"], "strategy": "round-robin", "priority": 0}]},
		  {"name": "user", "match": "$.session.user = 'app'", "connectionSharingAllowed": false,
		   "destinations": [{"classes": ["B"], "strategy": "round-robin", "priority": 5},
		                    {"classes": ["A"], "strategy": "first-available", "priority": 1},
		                    {"classes": ["C"], "strategy": "round-robin", "priority": 5},
		                    {"classes": ["A", "B"], "strategy": "round-robin", "priority": 0}]},
		  {"name": "all", "match": "TRUE",
		   "destinations": [{"classes": ["C"], "strategy": "round-robin", "priority": 18446744073709551615}]}
		]})json", errors);
	ok(order && errors.empty(), "route order document parses (%s)", join(errors).c_str());
	if (order) {
		const auto& routes = order->routes();
		ok(routes.size() == 3 && !routes[0].enabled && routes[1].enabled, "enabled flags");
		ok(!routes[0].connection_sharing_allowed.has_value() &&
			routes[1].connection_sharing_allowed == std::optional<bool>(false), "connectionSharingAllowed is optional");
		const auto& gr = routes[1].groups;
		ok(gr.size() == 4 && gr[0].priority == 0 && gr[0].classes == Names({"A", "B"}) &&
			gr[1].priority == 1 && gr[2].priority == 5 && gr[2].classes == Names {"B"} &&
			gr[3].priority == 5 && gr[3].classes == Names {"C"}, "groups are stable sorted by priority");
		ok(routes[2].groups[0].priority == UINT64_MAX, "uint64 priority");
		SessionInfo se = g_session;
		std::vector<Error> errs;
		se.user = "app";
		ok(order->match_route(se, g_router, errs) == std::optional<size_t>(1), "disabled route is skipped");
		se.user = "other";
		ok(order->match_route(se, g_router, errs) == std::optional<size_t>(2) && errs.empty(), "catch-all route");
		ServerInfo s = g_server;
		s.port = 1;
		ok(order->classify(s, g_router, errs) == Names({"A", "C"}), "classes in destination order");
	}

	// uses_router_route_name_in_destinations
	errors.clear();
	auto rn = parse_doc(doc_with(R"([{"name": "Primary", "match": "$.router.routeName = 'x' OR $.server.memberRole = PRIMARY"}])",
		kRoutes), errors);
	ok(rn && rn->uses_router_route_name_in_destinations(), "routeName detected in destinations (%s)", join(errors).c_str());
	errors.clear();
	rn = parse_doc(doc_with(kDests, R"([{"name": "rw", "match": "$.router.routeName = 'x'",
		"destinations": [{"classes": ["Primary"], "strategy": "round-robin", "priority": 0}]}])"), errors);
	ok(rn && !rn->uses_router_route_name_in_destinations(), "routeName in routes is not reported (%s)", join(errors).c_str());
	if (rn) {
		RouterInfo r = g_router;
		r.route_name = "X";
		std::vector<Error> errs;
		ok(rn->match_route(g_session, r, errs) == std::optional<size_t>(0), "routeName is available in routes");
	}
}

void test_runtime_errors() {
	diag("runtime errors");
	std::vector<Error> errors;
	const auto g = parse_doc(R"json({"version": "1.0",
		"destinations": [
		  {"name": "bad", "match": "NUMBER($.server.tags.weight) > 1"},
		  {"name": "good", "match": "$.server.port = 3306"},
		  {"name": "resolved", "match": "$.server.address = RESOLVE_V4('abra')"},
		  {"name": "unresolved", "match": "$.server.address = RESOLVE_V4('unknown.host')"}],
		"routes": [
		  {"name": "first", "match": "$.session.user = 'vip'",
		   "destinations": [{"classes": ["good"], "strategy": "round-robin", "priority": 0}]},
		  {"name": "broken", "match": "NUMBER($.session.connectAttrs.n) > 1",
		   "destinations": [{"classes": ["good"], "strategy": "round-robin", "priority": 0}]},
		  {"name": "all", "match": "TRUE",
		   "destinations": [{"classes": ["good"], "strategy": "round-robin", "priority": 0}]}]})json", errors);
	ok(g && errors.empty(), "document with runtime-failing expressions parses (%s)", join(errors).c_str());
	if (!g) return;
	ServerInfo s = g_server;
	s.tags = {{"weight", "heavy"}};
	std::vector<Error> errs;
	auto classes = g->classify(s, g_router, errs);
	ok(classes == Names {"good"}, "classification continues after an error (%s)", join(classes).c_str());
	ok(errs.size() == 2 && errs[0].path == "destinations.bad" &&
		errs[0].message == "NUMBER function, unable to convert 'heavy' to number in 'NUMBER($.server.tags.weight)'" &&
		errs[1].path == "destinations.unresolved" &&
		errs[1].message == "No cache entry to resolve host: unknown.host",
		"destination errors carry the class name (%s)", join(errs).c_str());
	errs.clear();
	s.address = "123.12.13.11";
	s.tags = {{"weight", "7"}};
	classes = g->classify(s, g_router, errs);
	ok(classes == Names({"bad", "good", "resolved"}) && errs.size() == 1, "resolved host matches (%s)", join(classes).c_str());

	SessionInfo se = g_session;
	se.connect_attrs = {{"n", "x"}};
	errs.clear();
	ok(g->match_route(se, g_router, errs) == std::nullopt && errs.size() == 1 && errs[0].path == "route.broken" &&
		contains(errs[0].message, "unable to convert 'x' to number"),
		"a route evaluation error fails the match even if a later route matches (%s)", join(errs).c_str());
	errs.clear();
	se.user = "vip";
	ok(g->match_route(se, g_router, errs) == std::optional<size_t>(0) && errs.empty(),
		"routes after the first match are not evaluated");
	errs.clear();
	se.user = "other";
	se.connect_attrs = {{"n", "5"}};
	ok(g->match_route(se, g_router, errs) == std::optional<size_t>(1) && errs.empty(), "numeric attribute matches");
	se.connect_attrs.clear();
	ok(g->match_route(se, g_router, errs) == std::optional<size_t>(2) && errs.empty(),
		"a NULL attribute makes the comparison false");

	// resolver results are cached per document
	g_resolve_calls.clear();
	errors.clear();
	const auto cache = parse_doc(R"json({"version": "1.0",
		"destinations": [{"name": "abra", "match": "$.server.address = resolve_v4('abra') "},
		                 {"name": "abra2", "match": "$.server.address = resolve_v4('ABRA') "},
		                 {"name": "cadabra", "match": "$.server.address = resolve_v6('cadabra') "}],
		"routes": [{"name": "AB", "match": "$.session.sourceIP = resolve_v4(Abra) ",
		            "destinations": [{"classes": ["abra"], "strategy": "first-available", "priority": 0}]},
		           {"name": "CD", "match": "$.session.sourceIP = resolve_v6(abracadabra) ",
		            "destinations": [{"classes": ["cadabra"], "strategy": "round-robin", "priority": 0}]}]})json", errors);
	ok(cache && errors.empty() && g_resolve_calls["abra/4"] == 1 && g_resolve_calls["cadabra/6"] == 1 &&
		g_resolve_calls["abracadabra/6"] == 1, "each host is resolved once per document");
	if (cache) {
		ServerInfo sv = g_server;
		sv.address = "::ffff:3.3.3.3";
		errs.clear();
		ok(cache->classify(sv, g_router, errs) == Names {"cadabra"}, "IPv6 resolution classification");
		SessionInfo ss = g_session;
		ss.source_ip = "123.12.13.11";
		ok(cache->match_route(ss, g_router, errs) == std::optional<size_t>(0), "route AB");
		ss.source_ip = "::ffff:4.4.4.4";
		ok(cache->match_route(ss, g_router, errs) == std::optional<size_t>(1) && errs.empty(), "route CD");
	}
}

void test_concurrency() {
	diag("concurrent evaluation");
	std::vector<Error> errors;
	const auto g = parse_doc(kClusterSets, errors);
	if (!g) {
		ok(false, "concurrency document parses");
		return;
	}
	std::atomic<int> mismatches {0};
	std::vector<std::thread> threads;
	for (int t = 0; t < 8; t++) {
		threads.emplace_back([&g, &mismatches, t]() {
			RouterInfo r;
			r.port_ro = 3306;
			r.port_rw = 3307;
			r.bind_address = "192.168.0.123";
			SessionInfo se;
			se.source_ip = "192.168.0.55";
			ServerInfo s;
			s.member_role = MemberRole::secondary;
			for (int i = 0; i < 2000; i++) {
				std::vector<Error> errs;
				se.target_port = (i + t) % 2 ? 3306 : 3307;
				se.user = (i % 7 == 0) ? "app_sync" : "u";
				const auto idx = g->match_route(se, r, errs);
				const size_t expected = se.user == "app_sync" ? 1 : (se.target_port == 3306 ? 2 : 3);
				if (!idx || *idx != expected || !errs.empty()) mismatches++;
				s.address = (i % 3 == 0) ? "192.168.0.7" : "10.0.0.7";
				const auto classes = g->classify(s, r, errs);
				const Names expected_classes {(i % 3 == 0) ? "localSecondaries" : "remoteSecondaries"};
				if (classes != expected_classes || !errs.empty()) mismatches++;
			}
		});
	}
	for (auto& th : threads) th.join();
	ok(mismatches == 0, "8 threads x 2000 evaluations give consistent results (%d mismatches)", mismatches.load());
}

} // namespace

int main() {
	plan(710);
	reset_context();
	test_lexer();
	test_syntax_errors();
	test_precedence();
	test_comparisons();
	test_logical();
	test_limits();
	test_in();
	test_null_semantics();
	test_variables();
	test_roles();
	test_functions();
	test_type_errors();
	test_like();
	test_tags();
	test_context();
	test_document_validation();
	test_shell_defaults();
	test_classification_and_routes();
	test_runtime_errors();
	test_concurrency();
	return exit_status();
}
