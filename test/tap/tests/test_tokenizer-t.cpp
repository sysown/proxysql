#include <utility>
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
__thread bool mysql_thread___query_digests_keep_comment = false;
__thread int mysql_thread___query_digests_grouping_limit = 3;
__thread int mysql_thread___query_digests_groups_grouping_limit = 1;

using std::vector;
using std::pair;
using std::string;
using std::tuple;

const vector<pair<string, string>> query_digest_pairs {
	// TODO: KnownIssue - 10
	// {
	// 	"select /* COMMENT */ 1",
	// 	"select ?"
	// 	// Actual: "select  ?# final_comment"
	// },
	{
		"select/* COMMENT */ 1",
		"select ?"
	},
	{
		"select/* COMMENT */1",
		"select ?"
	},
	// initial '#' comments
	{
		"# random_comment \n   select 1.1",
		"select ?"
	},
	{
		"#random_comment \nselect 1.1",
		"select ?"
	},
	{
		"#random_comment\nselect 1.1",
		"select ?"
	},
	// initial '--' comments
	{
		"-- random_comment \n select 1.1",
		"select ?"
	},
	{
		"--random_comment \nselect 1.1",
		"select ?"
	},
	{
		"--random_comment\nselect 1.1",
		"select ?"
	},
	// final/initial '#|--' comments
	{
		"# random_comment\n select 1.1 #final_comment\n   ",
		"select ?"
	},
	// TODO: KnownIssue - 1
	// {
	// 	"# random_comment\n select 1.1# final_comment   \n",
	// 	"select ?"
	// 	// Actual: "select ?# final_comment"
	// },
	{
		"# random_comment\n select 1.1   #final_comment  \n  ",
		"select ?"
	},
	{
		"-- random_comment\n select 1.1 --final_comment\n   ",
		"select ?"
	},
	{
		"-- random_comment\n select 1.1-- final_comment   \n",
		"select ?"
	},
	// NOTE: Comments with '--' should always be followed by an space.
	// {
	// 	"-- random_comment\n select 1.1--final_comment   \n",
	// 	"select ?"
	// },
	{
		"-- random_comment\n select 1.1   --final_comment  \n  ",
		"select ?"
	},
	// floats
	{ "select 1.1", "select ?" },
	{ "select 99.1929", "select ?" },
	// exponentials
	{ "select 1.1e9", "select ?" },
	{ "select 1.1e+9", "select ?" },
	{ "select 1.1e-9", "select ?" },
	// TODO: KnownIssue - 2: Exponentials are case sensitive
	// { "select 1.1E9", "select ?" },
	// { "select 1.1E+9", "select ?" },
	// { "select 1.1E-9", "select ?" },
	// operators
	{ "select 1 +1", "select ?+?" },
	{ "select 1+ 1", "select ?+?" },
	{ "select 1- 1", "select ?-?" },
	{ "select 1 -1", "select ?-?" },
	{ "select 1* 1", "select ?*?" },
	{ "select 1 *1", "select ?*?" },
	{ "select 1/ 1", "select ?/?" },
	{ "select 1 /1", "select ?/?" },
	{ "select 1% 1", "select ?%?" },
	{ "select 1 %1", "select ?%?" },
	// operators and commas
	{
		"select 1+ 1, 1 -1, 1 * 1 , 1/1 , 100 % 3",
		"select ?+?,?-?,?*?,?/?,?%?",
	},
	{
		"SELECT * FROM t t1, t t2 ,t t3,t t4 LIMIT 0",
		"SELECT * FROM t t1,t t2,t t3,t t4 LIMIT ?"
	},
	// mixing operators, commas and literals
	{
		"select 1+ 1,'1 -1', 1 * 1 , '1/1 ',100 % 3",
		"select ?+?,?,?*?,?,?%?"
	},
	{
		"select 1+ 1    ,'1 -1' ,1 * 1 , '1 '  , 100 % 3",
		"select ?+?,?,?*?,?,?%?"
	},
	{
		"select   1 + 1    , '1 - 1' , 1 * 1 , '1 '  , 100 % 3      ",
		"select ?+?,?,?*?,?,?%?"
	},
	// TODO: KnownIssue - 8: Operators not removed when extra space precedes the value
	{
		"select  + 1",
		"select +?"
	},
	// strings - simple
	{
		"select * from t where t = \"foo\"",
		"select * from t where t = ?",
	},
	{
		"select \"1+ 1, 1 -1, 1 * 1 , 1/1 , 100 % 3\"",
		"select ?",
	},
	// string - preceded by signs - outside parenthesis, not preceded by commas
	{ "select -\"1\"", "select -?", },
	{ "select +\"1\",'foo'", "select +?,?", },
	// string - preceded by signs - inside parenthesis, or preceded by commas
	{ "select (-'89')", "select (?)", },
	{ "select 10,-'89'", "select ?,?", },
	{ "select  10, -'89' ", "select ?,?", },
	// string - leading strings get it's extra spaces removed, but not firsts
	{ "select  '10', -'89' ", "select ?,?", },
	{ "select  10,  -'89 ',+'5'", "select ?,?,?", },
	// TODO: KnownIssue - 7: Spaces not removed after parenthesis when literal strings are preceded by '+|-'
	{ "select CONCAT( -'89'+'10')", "select CONCAT( ?+?)", },
	//               ^ preserved space
	{ "select CONCAT( -'89'+'10')", "select CONCAT( ?+?)", },
	{ "select CONCAT(  -'89'   +  '10' )", "select CONCAT( ?+?)", },
	// TODO: KnownIssue - 8: Operators not removed when extra space precedes the literal (value)
	{ "select CONCAT(- '89')", "select CONCAT(-?)", },
	//               ^ preserved operator

	// not modified
	{ "select * fromt t", "select * fromt t" },
	// test query_digest reduction
	{
		"SELECT * FROM tablename WHERE id IN (1,2,3,4,5,6,7,8,9,10)",
		"SELECT * FROM tablename WHERE id IN (?,?,?,...)"
	},
	{
		"SELECT * FROM tablename WHERE id IN (1,2,3,4)",
		"SELECT * FROM tablename WHERE id IN (?,?,?,...)"
	},
	// invalid request grouping
	{
		"SELECT * tablename where id IN (1,2,3,4,5,6,7,8,  AND j in (1,2,3,4,5,6  and k=1",
		"SELECT * tablename where id IN (?,?,?,...,AND j in (?,?,?,... and k=?"
	},
	// random insert queries
	{
		"INSERT INTO db.table(col1) VALUES ('val')",
		"INSERT INTO db.table(col1) VALUES (?)"
	},
	{
		"INSERT INTO db.table (col1) VALUES ('val')",
		"INSERT INTO db.table (col1) VALUES (?)"
	},
	{
		"INSERT INTO db.table( col1) VALUES ( 'val' )",
		"INSERT INTO db.table( col1) VALUES (?)"
	},
	{
		"INSERT INTO db.table( col1) VALUES ( 'val' )",
		"INSERT INTO db.table( col1) VALUES (?)"
	},
	// TODO: KnownIssue - 6: When 'no-digits' is enabled, space before parenthesis closing brakcet is
	// collapsed when an identifier name finish with a number.
	// {
	// 	"INSERT INTO db.table  ( col1 )  VALUES ( 'val' )",
	// 	"INSERT INTO db.table ( col1 ) VALUES (?)"
	// },
	{
		"INSERT INTO db.table (col1, col2,col3,col4) VALUES ('val',2,3,'foo')",
		"INSERT INTO db.table (col1,col2,col3,col4) VALUES (?,?,?,...)"
	},
	// TODO: KnownIssue - 6: When 'no-digits' is enabled, space before parenthesis closing brakcet is
	// collapsed when an identifier name finish with a number.
	// {
	// 	"INSERT INTO db.table ( col1, col2,col3,col4 ) VALUES ('val',2,3,'foo')",
	// 	"INSERT INTO db.table ( col1,col2,col3,col4 ) VALUES (?,?,?,...)"
	// },
	{
		"INSERT INTO db.table_25 (col1, col2,col3,col4) VALUES ('val',2,3,'foo')",
		"INSERT INTO db.table_25 (col1,col2,col3,col4) VALUES (?,?,?,...)"
	},
	{
		"INSERT INTO db.table1_25 ( col_121,col2121  ,col12_3, col41203_   ) VALUES (?,?,?,...)",
		"INSERT INTO db.table1_25 ( col_121,col2121,col12_3,col41203_ ) VALUES (?,?,?,...)"
	},
	// TODO: KnownIssue - 5: Arithmetics operators breaks grouping
	// {
	// 	"INSERT INTO db.table ( col1, col2,col3,col4, col5 ) VALUES ('val',2,3,'foo', 5 + 10, 6 - 9)",
	// 	"INSERT INTO db.table ( col1,col2,col3,col4,col5 ) VALUES (?,?,?,...)"
	// 	// Actual: "INSERT INTO db.table ( col1,col2,col3,col4,col5 ) VALUES (?,?,?,... + -)"
	// },
};

const vector<pair<string, string>> queries_digests_grouping {
	// test query_digest reduction
	{
		"SELECT * FROM tablename WHERE id IN (1,2, 3,4 ,5 ,6,7,8,9,10)",
		"SELECT * FROM tablename WHERE id IN (?,...)"
	},
	// invalid request grouping
	{
		"SELECT * tablename where id IN (1,2,3,4,5 , 6,7,8,  AND j in (1, 2,3, 4 ,5,6,7,8,9  and k=1",
		"SELECT * tablename where id IN (?,...,AND j in (?,... and k=?"
	},
	// more random grouping
	{
		"SELECT (1.1, 1, 2, 13, 4.81, 12) FROM db.table",
		"SELECT (?,...) FROM db.table"
	},
	{
		"SELECT (1.1, 1.12934 , 21.32 , 91, 91, 12.93 ) FROM db.table2",
		"SELECT (?,...) FROM db.table2"
	},
	{
		"SELECT (1.1, 1.12934 , 21.32 , 91.2 , 91, 12 ) FROM db.table7",
		"SELECT (?,...) FROM db.table7"
	},
	{
		"SELECT (1.1, 1.12934, 21.32, 391,2381,28.493,1283 ) FROM db.table2",
		"SELECT (?,...) FROM db.table2"
	},
	{
		"SELECT (1.1, 1.12934, 21.32 , 91, 91, 12.1 ) FROM db.table3",
		"SELECT (?,...) FROM db.table3"
	}
};

const vector<tuple<string,string,string>> null_queries_digests {
	{
		"select   Null    , '1*2/2',NULL,null , '1 '  , 100 % 3      ",
		"select Null,?,NULL,null,?,?%?",
		"select ?,?,?,?,?,?%?"
	},
	// TODO: KnownIssue - 3: Grouping count isn't reset by NULL.
	// {
	// 	"INSERT INTO db.table VALUES ( Null , NULL, '',NULL, 'a', 'b', 'z',nuLL)",
	// 	"INSERT INTO db.table VALUES (Null,NULL,?,NULL,?,?,?,nuLL)",
	// 	"INSERT INTO db.table VALUES (?,?,?,...)"
	// 	// Act: INSERT INTO db.table VALUES ( Null,NULL,?,NULL,?,?,...,nuLL)
	// },
	{
		"INSERT INTO db.table VALUES ( NULL, 'a', 'b', 'z', -4, nuLL)",
		// TODO: KnownIssue - 4: Spaces preceding NULL values are not properly removed
		"INSERT INTO db.table VALUES ( NULL,?,?,?,...,nuLL)",
		"INSERT INTO db.table VALUES (?,?,?,...)"
	},
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

char is_digit_char(char c) {
	if(c >= '0' && c <= '9') {
		return 1;
	}
	return 0;
}

vector<string> extract_numbers(const string query) {
	vector<string> numbers {};
	string number {};

	for (const char c : query) {
		if (is_digit_char(c)) {
			number += c;
		} else {
			if (!number.empty()) {
				numbers.push_back(number);
				number.clear();
			}
		}
	}

	return numbers;
}

string replace_numbers(const string query, const char mark) {
	vector<string> numbers { extract_numbers(query) };
	std::sort(
		numbers.begin(), numbers.end(),
		[](const string& s1, const string& s2) -> bool { return s1.size() > s2.size(); }
	);

	string query_res { query };

	for (const string& num : numbers) {
		query_res = replace_str(query_res, num, string { mark });
	}

	return query_res;
}

int main(int argc, char** argv) {
	if (query_digest_pairs.size() != query_digest_pairs.size()) {
		ok(0, "queries and exp_results sizes doesn't match");
		return exit_status();
	}

	plan(
		query_digest_pairs.size()*2 + queries_digests_grouping.size()*5 + null_queries_digests.size()*2
	);

	char buf[QUERY_DIGEST_BUF];

	const auto test_query_digests = [&](bool replace_digits) -> void {
		mysql_thread___query_digests_no_digits=replace_digits;

		for (size_t i = 0; i < query_digest_pairs.size(); i++) {
			const auto& query = query_digest_pairs[i].first;
			const auto& query_str_rep = replace_str(query_digest_pairs[i].first, "\n", "\\n");
			char* first_comment = NULL;
			std::string exp_res {};

			if (replace_digits == false) {
				exp_res = query_digest_pairs[i].second;
			} else {
				exp_res = replace_numbers(query_digest_pairs[i].second, '?');
			}

			char* c_res = mysql_query_digest_and_first_comment(const_cast<char*>(query.c_str()), query.length(), &first_comment, buf);
			const std::string result(c_res);
			std::string ok_msg {};

			if (replace_digits == false) {
				ok_msg = "Digest should be equal to exp result:\n * Query: `%s`,\n * Act: `%s`,\n * Exp: `%s`";
			} else {
				ok_msg = "No-Digits digest should be equal to exp result:\n * Query: `%s`,\n * Act: `%s`,\n * Exp: `%s`";
			}

			ok(
				result == exp_res, ok_msg.c_str(),
				query_str_rep.c_str(), result.c_str(), exp_res.c_str()
			);
		}

		mysql_thread___query_digests_no_digits=0;
	};

	/* Test queries without replacing digits */
	test_query_digests(false);
	/* Test queries replacing digits */
	test_query_digests(true);

	const auto test_null_replacting = [&](bool replace_nulls) -> void {
		mysql_thread___query_digests_replace_null=replace_nulls;

		for (size_t i = 0; i < null_queries_digests.size(); i++) {
			const auto& query = std::get<0>(null_queries_digests[i]);
			std::string exp_res {};

			if (replace_nulls) {
				exp_res = std::get<2>(null_queries_digests[i]);
			} else {
				exp_res = std::get<1>(null_queries_digests[i]);
			}

			char* c_res = mysql_query_digest_and_first_comment(const_cast<char*>(query.c_str()), query.length(), NULL, buf);
			std::string result(c_res);

			ok(
				result == exp_res,
				"Replaced NULL values digest should be equal to exp result:"
					"\n * Query: `%s`,\n * Act: `%s`,\n * Exp: `%s`",
				query.c_str(), result.c_str(), exp_res.c_str()
			);
		}

		mysql_thread___query_digests_replace_null=0;
	};

	/* Test queries containing 'NULL', NOT replacing the 'NULL' values */
	test_null_replacting(false);
	/* Test queries containing 'NULL', replacing the 'NULL' values */
	test_null_replacting(true);

	for (size_t i = 0; i < queries_digests_grouping.size(); i++) {
		for (int j = 1; j <= 5; j++) {
			mysql_thread___query_digests_grouping_limit = j;
	
			const auto& query = queries_digests_grouping[i].first;
			const auto& exp_res = increase_mark_num(queries_digests_grouping[i].second, j);

			char* c_res = mysql_query_digest_and_first_comment(const_cast<char*>(query.c_str()), query.length(), NULL, buf);
			std::string result(c_res);

			ok(
				result == exp_res,
				"Grouping digest should be equal to exp result:"
					"\n * Query: `%s`,\n * Act: `%s`,\n * Exp: `%s`",
				query.c_str(), result.c_str(), exp_res.c_str()
			);
		}
	}

	return exit_status();
}
