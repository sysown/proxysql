#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <random>

#include <unistd.h>

#include <string>
#include <mysql.h>

#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "json.hpp"
#include "re2/re2.h"
#include "re2/regexp.h"

using nlohmann::json;

int main(int argc, char** argv) {
	CommandLine cl;

	if(cl.getEnv())
		return exit_status();

	plan(6);
	diag("Testing query rules fast routing");

	MYSQL* mysql = mysql_init(NULL);
	if (!mysql) return exit_status();
	if (!mysql_real_connect(mysql, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) return exit_status();

	MYSQL_QUERY(mysql, "set global innodb_stats_on_metadata=1");
	int rc = mysql_query(mysql, "PROXYSQL INTERNAL SESSION");
	ok(rc==0, "We should be able to query internal proxysql session [set global innodb_stats_on_metadata=1]");

	if (rc == 0) {
		json internal_session;
		MYSQL_RES* result = mysql_store_result(mysql);
		ok(result != NULL, "We should be able to get resultset");

		MYSQL_ROW row;
		while ((row = mysql_fetch_row(result)))
		{
			internal_session = json::parse(row[0]);
		}
		mysql_free_result(result);
		int locked_on_hostgroup = internal_session["locked_on_hostgroup"];
		ok(locked_on_hostgroup == -1,"Hostgroup should not be locked. Current hostgroup [%d]", locked_on_hostgroup);
	}

	MYSQL_QUERY(mysql, "set @@global.innodb_stats_on_metadata=1");
	rc = mysql_query(mysql, "PROXYSQL INTERNAL SESSION");
	ok(rc==0, "We should be able to query internal proxysql session [set @@global.innodb_stats_on_metadata=1]");

	if (rc == 0) {
		json internal_session;
		MYSQL_RES* result = mysql_store_result(mysql);
		ok(result != NULL, "We should be able to get resultset");

		MYSQL_ROW row;
		while ((row = mysql_fetch_row(result)))
		{
			internal_session = json::parse(row[0]);
		}
		mysql_free_result(result);
		int locked_on_hostgroup = internal_session["locked_on_hostgroup"];
		ok(locked_on_hostgroup == -1,"Hostgroup should not be locked. Current hostgroup [%d]", locked_on_hostgroup);
	}

	re2::RE2::Options *opt2=new re2::RE2::Options(RE2::Quiet);
	opt2->set_case_sensitive(false);
	auto opt=(void *)opt2;
	auto re=(RE2 *)new RE2("^SET(?: +)((GLOBAL( +))|(@@GLOBAL.))([[:alnum:]_]+)( *)(:|)=( *)", *opt2);

	MYSQL_QUERY(mysql, "select variable_name from performance_schema.global_variables");
	{
		MYSQL_RES* result = mysql_store_result(mysql);
		MYSQL_ROW row;
		bool is_matched = true;
		while ((row = mysql_fetch_row(result))) {
			std::string variable_name = row[0];
			std::string query1 = std::string("set global ") + variable_name + " = foo";
			std::string query2 = std::string("set @@global.") + variable_name + " = foo";
			if (!RE2::PartialMatch(query1.c_str(),*(RE2 *)re)) {
				is_matched = false;
			}
			if (!RE2::PartialMatch(query2.c_str(),*(RE2 *)re)) {
				is_matched = false;
			}
		}
		mysql_free_result(result);
		ok(is_matched, "All global variables should match to regex");
	}
	delete re;
	delete opt2;

	mysql_close(mysql);
	return exit_status();
}

