/**
 * @file pcre1_query_rule_limits_unit-t.cpp
 * @brief Engine 1 (PCRE 8.45) query rules run with recursion/match limits
 *        (issue #6466).
 *
 * PCRE 8.45 recurses on the C stack of the thread that matches. Without a
 * recursion limit, '^(.|\n)*FOR UPDATE' on a query of a few KB overflowed a
 * worker thread's stack (1 MiB by default, 256 KiB minimum) and crashed
 * ProxySQL. The rules now run with a recursion limit derived from the stack
 * of the thread that compiles and matches them, and a limit hit means "the
 * rule is not applied to this query", negated or not, as on engine 3.
 *
 * Each case runs in a forked child, in a thread with the stack size of a
 * ProxySQL worker, so that a stack overflow (the bug) fails the case instead
 * of killing the test. The rules are compiled in that thread, as a worker
 * compiles its own copy of the rules.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"

#include "proxysql.h"
#include "cpp.h"
#include "query_processor.h"
#include "QP_rule_text.h"

#include <pthread.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <functional>
#include <string>

#ifdef DEBUG
// Debug-only seam in Query_Processor.cpp: the engine 1 replace_pattern path
// of process_query(), on a rule compiled in the calling thread.
extern bool pcre1_query_rule_replace_for_test(
	const char* pattern,
	const char* rewrite,
	bool global,
	std::string* query,
	int* limit_rc
);
#endif

namespace {

// PCRE_ERROR_RECURSIONLIMIT in PCRE 8.45's pcre.h, which is not on the unit
// tests' include path.
constexpr int kPcreErrorRecursionLimit = -21;

constexpr size_t KiB = 1024;
constexpr size_t MiB = 1024 * 1024;
// mysql-stacksize / pgsql-stacksize: default, minimum and maximum.
constexpr size_t kDefaultStack = 1 * MiB;
constexpr size_t kMinStack = 256 * KiB;
constexpr size_t kMaxStack = 4 * MiB;

QP_rule_t make_rule(const char* pattern, bool negate = false, int modifiers = 0) {
	QP_rule_t rule {};
	rule.flagIN = 0;
	rule.proxy_port = -1;
	rule.match_pattern = const_cast<char*>(pattern);
	rule.negate_match_pattern = negate;
	rule.re_modifiers = modifiers;
	qp_addr_predicate_init(&rule.client_addr_pred, NULL, QP_ADDR_FIELD_CLIENT);
	qp_addr_predicate_init(&rule.proxy_addr_pred, NULL, QP_ADDR_FIELD_PROXY);
	return rule;
}

// Engine 1, regex compiled on the fly in the calling thread.
bool engine1_matches(const QP_rule_t& rule, const std::string& query) {
	return rule_matches_query(&rule, 0, "u", "d", "1.2.3.4", nullptr, "127.0.0.1", nullptr, 6033,
		0, nullptr, query.c_str(), nullptr, 1);
}

struct thread_job {
	std::function<int()> fn;
	int result;
};

void* thread_main(void* arg) {
	thread_job* job = static_cast<thread_job*>(arg);
	job->result = job->fn();
	return nullptr;
}

/**
 * @brief Runs @p fn in a forked child, in a thread with a @p stack_size stack.
 * @param result Receives fn()'s result (0..255) when the child exited normally.
 * @return false when the child did not exit normally (e.g. SIGSEGV).
 */
bool run_isolated(size_t stack_size, std::function<int()> fn, int* result) {
	fflush(stdout);
	fflush(stderr);
	const pid_t pid = fork();
	if (pid < 0) {
		diag("fork() failed: %s", strerror(errno));
		return false;
	}
	if (pid == 0) {
		thread_job job { fn, 0 };
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setstacksize(&attr, stack_size);
		pthread_t thread;
		if (pthread_create(&thread, &attr, thread_main, &job) != 0) _exit(254);
		pthread_join(thread, nullptr);
		_exit(job.result & 0xff);
	}
	int status = 0;
	if (waitpid(pid, &status, 0) != pid) return false;
	if (WIFSIGNALED(status)) {
		diag("child killed by signal %d", WTERMSIG(status));
		return false;
	}
	if (!WIFEXITED(status)) return false;
	*result = WEXITSTATUS(status);
	return true;
}

std::string pathological_query(size_t len) {
	return "SELECT '" + std::string(len, 'x') + "' FOR UPDATE";
}

// --------------------------------------------------------------------------
// A limit hit is "not applied", negated or not, and does not crash.
// --------------------------------------------------------------------------

void test_pathological_match(size_t stack_size, const char* stack_name) {
	const std::string query = pathological_query(100 * KiB);
	int result = -1;
	const bool alive = run_isolated(stack_size, [&query]() {
		// The unlimited match would succeed: the query ends with FOR UPDATE.
		const QP_rule_t rule = make_rule("^(.|\\n)*FOR UPDATE");
		const QP_rule_t negated = make_rule("^(.|\\n)*FOR UPDATE", true);
		return (engine1_matches(rule, query) ? 1 : 0) | (engine1_matches(negated, query) ? 2 : 0);
	}, &result);
	ok(alive, "%s stack: '^(.|\\n)*FOR UPDATE' on a 100 KB query does not overflow the stack", stack_name);
	ok(alive && (result & 1) == 0, "%s stack: the rule hitting the recursion limit is not applied", stack_name);
	ok(alive && (result & 2) == 0, "%s stack: the negated rule hitting the recursion limit is not applied", stack_name);
}

// The crash reported in #6466: a query of a few KB is enough without a limit.
void test_small_pathological_query() {
	const std::string query = pathological_query(4 * KiB);
	int result = -1;
	const bool alive = run_isolated(kDefaultStack, [&query]() {
		const QP_rule_t negated = make_rule("^(.|\\n)*FOR UPDATE", true);
		return engine1_matches(negated, query) ? 1 : 0;
	}, &result);
	ok(alive && result == 0, "1 MiB stack: a negated '^(.|\\n)*FOR UPDATE' on a 4 KB query is not applied, no crash");
}

// --------------------------------------------------------------------------
// Ordinary rules still match large queries, on the smallest worker stack.
// --------------------------------------------------------------------------

void test_normal_rules_on_large_queries() {
	const std::string value(1 * MiB, 'a');
	const std::string select_t = "SELECT c FROM t WHERE c='" + value + "'";
	const std::string select_value_first = "SELECT c, '" + value + "' FROM t";
	const std::string for_update = "SELECT '" + value + "' FOR UPDATE";
	std::string in_list = "SELECT * FROM t WHERE id IN (";
	for (int i = 0; i < 20; i++) in_list += std::to_string(i) + ",";
	in_list += "20)";

	int result = -1;
	const bool alive = run_isolated(kMinStack, [&]() {
		int bits = 0;
		const QP_rule_t r1 = make_rule("^SELECT\\s.*\\sFROM\\s+t\\b");
		if (engine1_matches(r1, select_t)) bits |= 1;
		if (engine1_matches(r1, select_value_first)) bits |= 2;
		const QP_rule_t r1_neg = make_rule("^SELECT\\s.*\\sFROM\\s+t\\b", true);
		if (engine1_matches(r1_neg, select_t) == false) bits |= 4;
		const QP_rule_t r2 = make_rule("^select\\s.*\\sfrom\\s+t\\b", false, QP_RE_MOD_CASELESS);
		if (engine1_matches(r2, select_value_first)) bits |= 8;
		const QP_rule_t r3 = make_rule("[\\s\\S]*FOR UPDATE$");
		if (engine1_matches(r3, for_update)) bits |= 16;
		const QP_rule_t r4 = make_rule("\\bIN\\s*\\((\\d+,)*\\d+\\)");
		if (engine1_matches(r4, in_list)) bits |= 32;
		const QP_rule_t r5 = make_rule("^SELECT\\s.*\\sFROM\\s+other\\b");
		if (engine1_matches(r5, select_t) == false) bits |= 64;
		return bits;
	}, &result);
	ok(alive, "256 KiB stack: matching 1 MB queries completes");
	ok(alive && (result & 1), "'^SELECT\\s.*\\sFROM\\s+t\\b' matches a query with a 1 MB value after FROM t");
	ok(alive && (result & 2), "'^SELECT\\s.*\\sFROM\\s+t\\b' matches a query with a 1 MB value before FROM t");
	ok(alive && (result & 4), "the negated rule is not applied to the matching 1 MB query");
	ok(alive && (result & 8), "a CASELESS rule matches the 1 MB query");
	ok(alive && (result & 16), "'[\\s\\S]*FOR UPDATE$' matches a 1 MB query");
	ok(alive && (result & 32), "a repeated group matches a short IN list");
	ok(alive && (result & 64), "a non-matching rule still does not match the 1 MB query");
}

// The limit follows the stack: a larger mysql-stacksize allows deeper matches.
void test_limit_scales_with_stack() {
	std::string in_list = "SELECT * FROM t WHERE id IN (";
	for (int i = 0; i < 500; i++) in_list += std::to_string(i) + ",";
	in_list += "500)";
	auto fn = [&in_list]() {
		const QP_rule_t rule = make_rule("\\bIN\\s*\\((\\d+,)*\\d+\\)");
		const QP_rule_t negated = make_rule("\\bIN\\s*\\((\\d+,)*\\d+\\)", true);
		return (engine1_matches(rule, in_list) ? 1 : 0) | (engine1_matches(negated, in_list) ? 2 : 0);
	};
	int result = -1;
	bool alive = run_isolated(kMaxStack, fn, &result);
	ok(alive && result == 1, "4 MiB stack: a repeated group matches a 500-item IN list");
	result = -1;
	alive = run_isolated(kMinStack, fn, &result);
	ok(alive && result == 0, "256 KiB stack: the same rule hits the recursion limit and is not applied, negated or not");
}

#ifdef DEBUG
// --------------------------------------------------------------------------
// replace_pattern
// --------------------------------------------------------------------------

void test_replace() {
	// The first match ('abc') is short; the second one recurses once per
	// 'ab'. Without the limit check, a GLOBAL rule would rewrite the first
	// match and stop at the second one, a partially rewritten query.
	const std::string runs(100 * KiB, 'a');
	std::string tail;
	for (size_t i = 0; i < 50 * KiB; i++) tail += "ab";
	const std::string global_subject = "abc " + tail + "c";
	const std::string single_subject = tail + "c";
	const std::string spaces_subject = "SELECT  1,   '" + runs + "'  FROM   t";
	const std::string value(1 * MiB, 'v');
	const std::string backref_subject = "SELECT '" + value + "' FROM t";

	int result = -1;
	const bool alive = run_isolated(kMinStack, [&]() {
		int bits = 0;
		std::string q = global_subject;
		int limit_rc = 0;
		bool rc = pcre1_query_rule_replace_for_test("(a|b)+c", "X", true, &q, &limit_rc);
		if (!rc && limit_rc == kPcreErrorRecursionLimit && q == global_subject) bits |= 1;

		q = single_subject;
		limit_rc = 0;
		rc = pcre1_query_rule_replace_for_test("(a|b)+c", "X", false, &q, &limit_rc);
		if (!rc && limit_rc == kPcreErrorRecursionLimit && q == single_subject) bits |= 2;

		q = spaces_subject;
		limit_rc = 0;
		rc = pcre1_query_rule_replace_for_test("\\s+", " ", true, &q, &limit_rc);
		if (rc && limit_rc == 0 && q == "SELECT 1, '" + runs + "' FROM t") bits |= 4;

		q = backref_subject;
		limit_rc = 0;
		rc = pcre1_query_rule_replace_for_test("^SELECT (.*) FROM t$", "SELECT \\1 FROM t2", false, &q, &limit_rc);
		if (rc && limit_rc == 0 && q == "SELECT '" + value + "' FROM t2") bits |= 8;

		// No match is not a limit hit, as before.
		q = "SELECT 1";
		limit_rc = 0;
		rc = pcre1_query_rule_replace_for_test("FROM", "X", false, &q, &limit_rc);
		if (rc && limit_rc == 0 && q == "SELECT 1") bits |= 16;
		return bits;
	}, &result);
	ok(alive, "256 KiB stack: engine 1 rewrites complete without overflowing the stack");
	ok(alive && (result & 1), "GLOBAL rewrite hitting the limit on a later match leaves the query unchanged");
	ok(alive && (result & 2), "rewrite hitting the limit leaves the query unchanged and reports the limit");
	ok(alive && (result & 4), "GLOBAL '\\s+' rewrite of a 100 KB query is unchanged by the limit");
	ok(alive && (result & 8), "'^SELECT (.*) FROM t$' rewrite with a back-reference works on a 1 MB query");
	ok(alive && (result & 16), "a rewrite that does not match is not reported as a limit hit");
}
#endif

} // namespace

int main() {
#ifdef DEBUG
	plan(23);
#else
	plan(17);
#endif
	test_init_minimal();

	test_pathological_match(kMinStack, "256 KiB");
	test_pathological_match(kDefaultStack, "1 MiB");
	test_small_pathological_query();
	test_normal_rules_on_large_queries();
	test_limit_scales_with_stack();
#ifdef DEBUG
	test_replace();
#endif

	test_cleanup_minimal();
	return exit_status();
}
