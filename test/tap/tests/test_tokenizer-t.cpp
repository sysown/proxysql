#include <vector>
#include <string>
#include <cstring>

#include "proxysql.h"

#include "tap.h"
#include "command_line.h"

#include "utils.h"

#include <ctype.h>

__thread int mysql_thread___query_digests_max_query_length = 65000;
__thread bool mysql_thread___query_digests_lowercase = false;
__thread bool mysql_thread___query_digests_replace_null = false;
__thread bool mysql_thread___query_digests_no_digits = false;

const std::vector<std::string> queries {
	// floats
	"select 1.1",
	"select 1192.1102",
	"select 99.1929",
	// exponentials
	"select 1.1e9",
	"select 1.1e+9",
	"select 1.1e-9",
	// operators
	"select 1 +1",
	"select 1+ 1",
	"select 1- 1",
	"select 1 -1",
	"select 1* 1",
	"select 1 *1",
	"select 1/ 1",
	"select 1 /1",
	"select 1% 1",
	"select 1 %1",
	// operators and commas
	"select 1+ 1, 1 -1, 1 * 1 , 1/1 , 100 % 3",
	"SELECT * FROM t t1, t t2 ,t t3,t t4 LIMIT 0",
	// strings
	"select * from t where t = \"foo\"",
	"select \"1+ 1, 1 -1, 1 * 1 , 1/1 , 100 % 3\"",
	// not modified
	"select * fromt t"
};

const std::vector<std::string> exp_results {
	// floats
	"select ?",
	"select ?",
	"select ?",
	// exponentials
	"select ?",
	"select ?",
	"select ?",
	// operators
	"select ?+?",
	"select ?+?",
	"select ?-?",
	"select ?-?",
	"select ?*?",
	"select ?*?",
	"select ?/?",
	"select ?/?",
	"select ?%?",
	"select ?%?",
	// operators and commas
	"select ?+?,?-?,?*?,?/?,?%?",
	"SELECT * FROM t t1,t t2,t t3,t t4 LIMIT ?",
	// strings
	"select * from t where t = ?",
	"select ?",
	// not modified
	"select * fromt t"
};

int main(int argc, char** argv) {
	if (queries.size() != exp_results.size()) {
		ok(0, "queries and exp_results sizes doesn't match");
		return exit_status();
	}

	char buf[QUERY_DIGEST_BUF];

	for (size_t i = 0; i < queries.size(); i++) {
		const auto& query = queries[i];
		const auto& exp_res = exp_results[i];

		char* c_res = mysql_query_digest_and_first_comment(const_cast<char*>(query.c_str()), query.length(), NULL, buf);
		std::string result(c_res);

		ok(result == exp_res, "result isn't equal to exp result: '%s' != '%s'", result.c_str(), exp_res.c_str());
	}

	return exit_status();
}