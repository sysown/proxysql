#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <iostream>

#include "proxysql.h"

#include "tap.h"
#include "command_line.h"

#include "utils.h"

#include <ctype.h>

__thread int mysql_thread___query_digests_max_query_length = 65000;
__thread bool mysql_thread___query_digests_lowercase = false;
__thread bool mysql_thread___query_digests_replace_null = false;
__thread bool mysql_thread___query_digests_no_digits = false;
__thread int mysql_thread___query_digests_grouping_limit = 3;

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
	"select * fromt t",
	// test query_digest reduction
	"SELECT * FROM tablename WHERE id IN (1,2,3,4,5,6,7,8,9,10)",
	"SELECT * FROM tablename WHERE id IN (1,2,3,4)",
	// invalid request grouping
	"SELECT * tablename where id IN (1,2,3,4,5,6,7,8,  AND j in (1,2,3,4,5,6  and k=1",
	// more random requests
	"SELECT * FROM tablename WHERE id IN (1, 212312,3,4, 51231,6,7,8,9,10)",
	"select concat(@@version, ' ',@@version_comment)",
	"select concat(@@version, \" \",@@version_comment)",
	"select concat(@@version, '',@@version_comment)",
	"select (abc)",
	"select schema()",
	"SELECT * FROM tbl AS t1 JOIN (SELECT id FROM tbl ORDER BY RAND() LIMIT 10) as t2 ON t1.id=t2.id",
	"SELECT c FROM sbtest1 WHERE id=2396269\\G",
	"CREATE TABLE `authors` (`id` INT(11) NOT NULL AUTO_INCREMENT, `first_name` VARCHAR(50) NOT NULL COLLATE 'utf8_unicode_ci', `last_name` VARCHAR(50) NOT NULL COLLATE 'utf8_unicode_ci', `email` VARCHAR(100) NOT NULL COLLATE 'utf8_unicode_ci', `birthdate` DATE NOT NULL, `added` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (`id`), UNIQUE INDEX `email` (`email`)",
	"IN (1,2,3,4,@var1)",
	"IN 'foo', 'foo'",
	"IN 'foo', 21019, 91293"
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
	"select * fromt t",
	// test query_digest reduction
	"SELECT * FROM tablename WHERE id IN (?,?,?,...)",
	"SELECT * FROM tablename WHERE id IN (?,?,?,...)",
	// invalid request grouping
	"SELECT * tablename where id IN (?,?,?,... AND j in (?,?,?,... and k=?",
	// more random requests
	"SELECT * FROM tablename WHERE id IN (?,?,?,...)",
	"select concat(@@version,?,@@version_comment)",
	"select concat(@@version,?,@@version_comment)",
	"select concat(@@version,?,@@version_comment)",
	"select (abc)",
	"select schema()",
	"SELECT * FROM tbl AS t1 JOIN (SELECT id FROM tbl ORDER BY RAND() LIMIT ?) as t2 ON t1.id=t2.id",
	"SELECT c FROM sbtest1 WHERE id=?\\G",
	"CREATE TABLE `authors` (`id` INT(?) NOT NULL AUTO_INCREMENT,`first_name` VARCHAR(?) NOT NULL COLLATE ?,`last_name` VARCHAR(?) NOT NULL COLLATE ?,`email` VARCHAR(?) NOT NULL COLLATE ?,`birthdate` DATE NOT NULL,`added` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY (`id`),UNIQUE INDEX `email` (`email`)",
	"IN (?,?,?,...,@var1)",
	"IN ?,?",
	"IN ?,?,?"
};

const std::vector<std::string> queries_grouping {
	// test query_digest reduction
	"SELECT * FROM tablename WHERE id IN (1,2, 3,4 ,5 ,6,7,8,9,10)",
	// invalid request grouping
	"SELECT * tablename where id IN (1,2,3,4,5 , 6,7,8,  AND j in (1, 2,3, 4 ,5,6,7,8,9  and k=1",
	"SELECT (1.1, 1, 2, 13, 4.81, 12) FROM db.table",
	"SELECT (1.1, 1.12934 , 21.32 , 91, 91, 12.93 ) FROM db.table2",
	"SELECT (1.1, 1.12934 , 21.32 , 91.2 , 91, 12 ) FROM db.table7",
	"SELECT (1.1, 1.12934, 21.32, 391,2381,28.493,1283 ) FROM db.table2",
	"SELECT (1.1, 1.12934, 21.32 , 91, 91, 12.1 ) FROM db.table3"
};

const std::vector<std::string> exp_queries_grouping {
	// test query_digest reduction
	"SELECT * FROM tablename WHERE id IN (?,...)",
	// invalid request grouping
	"SELECT * tablename where id IN (?,... AND j in (?,... and k=?",
	"SELECT (?,...) FROM db.table",
	"SELECT (?,...) FROM db.table2",
	"SELECT (?,...) FROM db.table7",
	"SELECT (?,...) FROM db.table2",
	"SELECT (?,...) FROM db.table3"
};

std::string replace_str(const std::string& str, const std::string& match, const std::string& repl) {
	if(match.empty()) {
		return str;
	}

	std::string result = str;
	size_t start_pos = 0;

	while((start_pos = result.find(match, start_pos)) != std::string::npos) {
		result.replace(start_pos, match.length(), repl);
		start_pos += repl.length();
	}

	return result;
}

std::string increase_mark_num(const std::string query, uint32_t num) {
	std::string result = query;
	std::string marks = "";

	for (uint32_t i = 0; i < num - 1; i++) {
		marks += "?,";
	}
	marks += "?,...";

	result = replace_str(result, "?,...", marks);

	return result;
}

const int QUERY_BUFFER_SIZE = 512;

int main(int argc, char** argv) {
	if (queries.size() != exp_results.size()) {
		ok(0, "queries and exp_results sizes doesn't match");
		return exit_status();
	}

	char buf[QUERY_BUFFER_SIZE];

	for (size_t i = 0; i < queries.size(); i++) {
		const auto& query = queries[i];
		const auto& exp_res = exp_results[i];

		char* c_res = mysql_query_digest_and_first_comment(const_cast<char*>(query.c_str()), query.length(), NULL, buf);
		std::string result(c_res);

		ok(result == exp_res, "Digest should be equal to exp result: '%s' == '%s'", result.c_str(), exp_res.c_str());
	}

	for (size_t i = 0; i < queries_grouping.size(); i++) {
		for (int j = 1; j <= 5; j++) {
			mysql_thread___query_digests_grouping_limit = j;
	
			const auto& query = queries_grouping[i];
			const auto& exp_res = increase_mark_num(exp_queries_grouping[i], j);
	
			char* c_res = mysql_query_digest_and_first_comment(const_cast<char*>(query.c_str()), query.length(), NULL, buf);
			std::string result(c_res);
	
			ok(result == exp_res, "Grouping digest should be equal to exp result: '%s' == '%s'", result.c_str(), exp_res.c_str());
		}
	}

	return exit_status();
}
