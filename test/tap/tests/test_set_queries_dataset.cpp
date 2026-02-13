#include "test_set_queries_dataset.h"

#include <string>
#include <vector>

using std::string;
using std::vector;

const vector<string> set_queries {
	// Basic User Variable Assignments
	"SET @my_user_var = 'hello world';",
	"SET @anotherVar = 12345;",
	"SET @thirdVar = `ident_value`;", // Using identifier as value
	"SET @complex_var = @@global.max_connections;", // Setting user var to sys var value (expr placeholder)

	// System Variable Assignments
	"SET global max_connections = 1000;",
	"SET session sort_buffer_size = 200000;",
	"SET GLOBAL sort_buffer_size = 400000;", // Case-insensitivity for scope
	"SET SESSION wait_timeout = 180;",
	"SET @@global.tmp_table_size = 32000000;",
	"SET @@session.net_write_timeout = 120;",
	"SET @@net_read_timeout = 60;", // Implicit SESSION scope for @@
	"SET max_allowed_packet = 64000000;", // Implicit SESSION scope for simple sysvar

	// PERSIST / PERSIST_ONLY (if supported by your current grammar for scope)
	"SET persist character_set_server = 'utf8mb4';",
	"SET persist_only innodb_buffer_pool_size = '1G';", // String literal for value

	// SET NAMES and CHARACTER SET
	"SET NAMES 'utf8mb4';",
	"SET NAMES `latin1`;",
	"SET NAMES DEFAULT;",
	"SET NAMES 'gbk' COLLATE 'gbk_chinese_ci';",
	"SET CHARACTER SET 'utf8';",
	"SET CHARACTER SET DEFAULT;",

	// Comma-separated list (testing set_option_list)
	"SET @a = 1, @b = 'two', global max_heap_table_size = 128000000;",
	"SET sql_mode = 'STRICT_TRANS_TABLES', character_set_client = 'utf8mb4';",

	// Statements without trailing semicolon (should work with optional_semicolon)
	"SET @no_semicolon = 'works'",
};

const vector<string> setparser_queries {
	"SET @@sql_mode = 'TRADITIONAL'",
	"SET SESSION sql_mode = 'TRADITIONAL'",
	"SET @@session.sql_mode = 'TRADITIONAL'",
	"SET @@local.sql_mode = 'TRADITIONAL'",
	"SET sql_mode = 'TRADITIONAL'",
	"SET SQL_MODE   ='TRADITIONAL'",
	"SET SQL_MODE  = \"TRADITIONAL\"",
	"SET SQL_MODE  = TRADITIONAL",
	"SET @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ', STRICT_ALL_TABLES'), ', NO_AUTO_VALUE_ON_ZERO')",
	"SET @@LOCAL.sql_mode = CONCAT(CONCAT(@@sql_mode, ', STRICT_ALL_TABLES'), ', NO_AUTO_VALUE_ON_ZERO')",
	"SET sql_mode = 'NO_ZERO_DATE,STRICT_ALL_TABLES,ONLY_FULL_GROUP_BY'",
	"SET @@sql_mode = CONCAT(@@sql_mode, ',', 'ONLY_FULL_GROUP_BY')",
	"SET @@sql_mode = REPLACE(REPLACE(REPLACE(@@sql_mode, 'ONLY_FULL_GROUP_BY,', ''),',ONLY_FULL_GROUP_BY', ''),'ONLY_FULL_GROUP_BY', '')",
	"SET @@sql_mode = REPLACE( REPLACE( REPLACE( @@sql_mode, 'ONLY_FULL_GROUP_BY,', ''),',ONLY_FULL_GROUP_BY', ''),'ONLY_FULL_GROUP_BY', '')",
	"SET @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ', STRICT_ALL_TABLES'), ', NO_AUTO_VALUE_ON_ZERO')",
	"SET SQL_MODE=IFNULL(@@sql_mode,'')",
	"SET SQL_MODE=IFNULL(@old_sql_mode,'')",
	"SET SQL_MODE=IFNULL(@OLD_SQL_MODE,'')",
	"SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))",
	"SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION')), time_zone = '+00:00', NAMES utf8mb4 COLLATE utf8mb4_unicode_ci",
	"SET sql_mode=''",
	"SET sql_mode=(SELECT CONCA(@@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))",
	"SET sql_mode=(SELECT CONCAT(@sql_mode, ',PIPES_AS_CONCAT,NO_ENGINE_SUBSTITUTION'))",
	"SET sql_mode=(SELECT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT[,NO_ENGINE_SUBSTITUTION'))",
	"SET sql_mode=(SELCT CONCAT(@@sql_mode, ',PIPES_AS_CONCAT[,NO_ENGINE_SUBSTITUTION'))",
	"SET @@time_zone = 'Europe/Paris'",
	"SET @@time_zone = '+00:00'",
	"SET @@time_zone = \"Europe/Paris\"",
	"SET @@time_zone = \"+00:00\"",
	"SET @@time_zone = @OLD_TIME_ZONE",
	"SET @@TIME_ZONE = @OLD_TIME_ZONE",
	"SET @@session_track_gtids = OFF",
	"SET @@session_track_gtids = OWN_GTID",
	"SET @@SESSION.session_track_gtids = OWN_GTID",
	"SET @@LOCAL.session_track_gtids = OWN_GTID",
	"SET SESSION session_track_gtids = OWN_GTID",
	"SET @@session_track_gtids = ALL_GTIDS",
	"SET @@SESSION.session_track_gtids = ALL_GTIDS",
	"SET @@LOCAL.session_track_gtids = ALL_GTIDS",
	"SET SESSION session_track_gtids = ALL_GTIDS",
	"SET @@character_set_results = utf8",
	"SET @@character_set_results = NULL",
	"SET character_set_results = NULL",
	"SET @@session.character_set_results = NULL",
	"SET @@local.character_set_results = NULL",
	"SET session character_set_results = NULL",
	"SET NAMES utf8",
	"SET NAMES 'utf8'",
	"SET NAMES \"utf8\"",
	"SET NAMES utf8 COLLATE unicode_ci",
	"SET @@SESSION.SQL_SELECT_LIMIT= DEFAULT",
	"SET @@LOCAL.SQL_SELECT_LIMIT= DEFAULT",
	"SET @@SQL_SELECT_LIMIT= DEFAULT",
	"SET SESSION SQL_SELECT_LIMIT   = DEFAULT",
	"SET @@SESSION.SQL_SELECT_LIMIT= 1234",
	"SET @@LOCAL.SQL_SELECT_LIMIT= 1234",
	"SET @@SQL_SELECT_LIMIT= 1234",
	"SET SESSION SQL_SELECT_LIMIT   = 1234",
	"SET @@SESSION.SQL_SELECT_LIMIT= 1234",
	"SET @@LOCAL.SQL_SELECT_LIMIT= 1234",
	"SET @@SESSION.SQL_SELECT_LIMIT= @old_sql_select_limit",
	"SET @@LOCAL.SQL_SELECT_LIMIT= @old_sql_select_limit",
	"SET SQL_SELECT_LIMIT= @old_sql_select_limit",
	"SET @@SESSION.sql_auto_is_null = 0",
	"SET @@LOCAL.sql_auto_is_null = 0",
	"SET SESSION sql_auto_is_null = 1",
	"SET sql_auto_is_null = OFF",
	"SET @@sql_auto_is_null = ON",
	"SET @@SESSION.sql_safe_updates = 0",
	"SET @@LOCAL.sql_safe_updates = 0",
	"SET SESSION sql_safe_updates = 1",
	"SET SQL_SAFE_UPDATES = OFF",
	"SET @@sql_safe_updates = ON",
	"SET time_zone = 'Europe/Paris', sql_mode = 'TRADITIONAL'",
	"SET time_zone = 'Europe/Paris', sql_mode = IFNULL(NULL,\"STRICT_TRANS_TABLES\")",
	"SET sql_mode = 'TRADITIONAL', NAMES 'utf8 COLLATE 'unicode_ci'",
	"SET  @@SESSION.sql_mode = CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO'),  @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 2147483",
	"SET  @@LOCAL.sql_mode = CONCAT(CONCAT(@@sql_mode, ',STRICT_ALL_TABLES'), ',NO_AUTO_VALUE_ON_ZERO'),  @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 2147483",
	"SET NAMES utf8, @@SESSION.sql_mode = CONCAT(REPLACE(REPLACE(REPLACE(@@sql_mode, 'STRICT_TRANS_TABLES', ''), 'STRICT_ALL_TABLES', ''), 'TRADITIONAL', ''), ',NO_AUTO_VALUE_ON_ZERO'), @@SESSION.sql_auto_is_null = 0, @@SESSION.wait_timeout = 3600",
	"SET NAMES utf8, @@LOCAL.sql_mode = CONCAT(REPLACE(REPLACE(REPLACE(@@sql_mode, 'STRICT_TRANS_TABLES', ''), 'STRICT_ALL_TABLES', ''), 'TRADITIONAL', ''), ',NO_AUTO_VALUE_ON_ZERO'), @@LOCAL.sql_auto_is_null = 0, @@LOCAL.wait_timeout = 3600",
	"SET character_set_results=NULL, NAMES latin7, character_set_client='utf8mb4'",
	"SET character_set_results=NULL,NAMES latin7,character_set_client='utf8mb4'"
};

const vector<string> exhaustive_queries {
	"SET @my_user_variable = 123;", // 1
	"SET @my_user_variable = + 123;", // 1
	"SET @my_user_variable = - 123;", // 1
	"SET @my_user_variable = 123, @@GLOBAL.max_connections = 200;", // 2
	"SET @my_custom_var = 'Test Value';", // 3
	"SET P_param_name = 100;", // 4
	"SET my_local_variable = NOW();", // 5
	"SET GLOBAL sort_buffer_size = 512000;", // 6
	"SET @@GLOBAL.sort_buffer_size = 512000;", // 7
	"SET PERSIST max_allowed_packet = 1073741824;", // 8
	"SET @@PERSIST.max_allowed_packet = 1073741824;", // 9
	"SET PERSIST_ONLY sql_mode = 'STRICT_TRANS_TABLES';", // 10
	"SET @@PERSIST_ONLY.sql_mode = 'STRICT_TRANS_TABLES';", // 11
	"SET SESSION sql_select_limit = 100;", // 12
	"SET @@SESSION.sql_select_limit = 100;", // 13
	"SET @@sql_select_limit = 100;", // 14
	"SET sql_select_limit = 100;", // 15
	"SET @generic_var = TRUE OR FALSE;", // 16
	"SET @generic_var = TRUE XOR FALSE;", // 17
	"SET @generic_var = 1 AND 0;", // 18
	"SET @generic_var = NOT TRUE;", // 19
	"SET @generic_var = (5 > 1) IS TRUE;", // 20
	"SET @generic_var = (1 = 0) IS NOT TRUE;", // 21
	"SET @generic_var = (1 = 0) IS FALSE;", // 22
	"SET @generic_var = (5 > 1) IS NOT FALSE;", // 23
	"SET @generic_var = (NULL + 1) IS UNKNOWN;", // 24
	"SET @generic_var = (1 IS NOT NULL) IS NOT UNKNOWN;", // 25
	"SET @generic_var = (col_a < col_b);", // 26
	"SET @generic_var = (0/0) IS NULL;", // 29
	"SET @generic_var = 'hello' IS NOT NULL;", // 30
	"SET @generic_var = (1=1) = ('a' LIKE 'a%');", // 31
	"SET @generic_var = my_value > ALL (SELECT limit_value FROM active_limits WHERE group_id = 'A');", // 32
	"SET @generic_var = (5 BETWEEN 1 AND 10);", // 33
	"SET @generic_var = current_user_id IN (SELECT user_id FROM course_enrollments WHERE course_id = 789);", // 41
	"SET @generic_var = 'PROD123' NOT IN (SELECT product_sku FROM discontinued_products WHERE reason_code = 'OBSOLETE');", // 42
	"SET @generic_var = 5 IN (5);", // 43
	"SET @generic_var = 'apple' IN ('orange', 'apple', 'banana');", // 44
	"SET @generic_var = 10 NOT IN (5);", // 45
	"SET @generic_var = 'grape' NOT IN ('orange', 'apple', 'banana');", // 46
	"SET @generic_var = 'b' MEMBER OF ('[\"a\", \"b\", \"c\"]');", // 47
	"SET @generic_var = 'b' MEMBER ('[\"a\", \"b\", \"c\"]');", // 48
	"SET @generic_var = 7 BETWEEN 5 AND (5 + 5);", // 49
	"SET @generic_var = 3 NOT BETWEEN 5 AND (10 - 2);", // 50
	"SET @generic_var = 'knight' SOUNDS LIKE 'night';", // 51
	"SET @generic_var = 'banana' LIKE 'ba%';", // 52
	"SET @generic_var = 'data_value_100%' LIKE 'data\\_value\\_100\\%' ESCAPE '\\\\';", // 53
	"SET @generic_var = 'apple' NOT LIKE 'ora%';", // 54
	"SET @generic_var = 'test_string%' NOT LIKE 'prod\\_string\\%' ESCAPE '\\\\';", // 55
	"SET @generic_var = 'abcde' REGEXP '^a.c';", // 56
	"SET @generic_var = 'xyz123' NOT REGEXP '[0-9]$';", // 57
	"SET @generic_var = (100 + 200);", // 58
	"SET @generic_var = 5 | 2;", // 61
	"SET @generic_var = 5 & 2;", // 62
	"SET @generic_var = 5 << 1;", // 63
	"SET @generic_var = 10 >> 1;", // 64
	"SET @generic_var = 10.5 + 2;", // 65
	"SET @generic_var = 100 - 33;", // 66
	"SET @generic_var = NOW() + INTERVAL 1 DAY;", // 67
	"SET @generic_var = '2025-12-25' - INTERVAL 2 MONTH;", // 68
	"SET @generic_var = 7 * 6;", // 69
	"SET @generic_var = 100 / 4;", // 70
	"SET @generic_var = 10 % 3;", // 71
	"SET @generic_var = 10 DIV 3;", // 72
	"SET @generic_var = 10 MOD 3;", // 73
	"SET @generic_var = 5 ^ 2;", // 74
	"SET @generic_var = (SELECT SUM(amount) FROM sales WHERE sale_date = CURDATE());" // 75
};

const vector<string> valid_sql_mode_subexpr {
	// Valid cases FAILING under REGEX impl
	"SET sql_mode=(SELECT 'foo')",
	"SET sql_mode=(SELECT \"foo\")",
	"SET sql_mode=(SELECT 5)",
	"SET sql_mode=(SELECT NULL)",
	// Valid cases WORKING under REGEX impl
	"SET sql_mode=(SELECT CONCAT(@@sql_mode, NULL))",
	"SET sql_mode=(SELECT CONCAT(@@sql_mode, 'foo'))",
	// Valid cases FAILING under REGEX impl
	"SET sql_mode=(SELECT REPLACE(CONCAT(@@sql_mode, ''), '', (SELECT 'foo')))",
	"SET sql_mode=(SELECT REPLACE(CONCAT(@@sql_mode, ''), '', 5))"
};
