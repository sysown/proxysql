#include "Embedded_Admin_Statistics.h"
#include "tap.h"
#include <string>

int main() {
 plan(NO_PLAN);
 std::string out;
 ok(!embedded::admin_sqlite_statistics_refresh_query("SELECT 'stats_mysql_query_digest_reset', ?", out) && out.empty(),
    "literal reset names cannot request a destructive refresh");
 ok(!embedded::admin_sqlite_statistics_refresh_query("SELECT 1 AS stats_mysql_query_digest_reset", out) && out.empty(),
    "column aliases are not relation references");
 ok(!embedded::admin_sqlite_statistics_refresh_query("SELECT * FROM STATS_MYSQL_GLOBAL", out) && out == "SELECT * FROM stats_mysql_global",
    "uppercase relation requests the same statistics refresh");
 ok(!embedded::admin_sqlite_statistics_refresh_query("SELECT * FROM `stats_mysql_connection_pool`", out) && out == "SELECT * FROM stats_mysql_connection_pool",
    "ParserSQL handles identifier delimiters");
 ok(!embedded::admin_sqlite_statistics_refresh_query("SELECT * FROM stats_mysql_global a JOIN stats_mysql_global b ON 1=1", out) && out == "SELECT * FROM stats_mysql_global",
    "duplicate relation references refresh once");
 ok(!embedded::admin_sqlite_statistics_refresh_query("SELECT * FROM (SELECT * FROM stats_mysql_global) AS s", out) && out == "SELECT * FROM stats_mysql_global",
    "nested query relations are found structurally");
 ok(!embedded::admin_sqlite_statistics_refresh_query("SELECT 1 /* stats_mysql_query_digest_reset */", out) && out.empty(),
    "comment text cannot request a refresh");
 ok(!embedded::admin_sqlite_statistics_refresh_query("SELECT * FROM other_stats_mysql_query_digest_reset_suffix", out) && out.empty(),
    "arbitrary names never enter the substring-based legacy refresh routine");
 ok(bool(embedded::admin_sqlite_statistics_refresh_query("SELECT * FROM stats_mysql_query_digest_reset", out)) && out.empty(),
    "destructive reset projections are explicitly unsupported");
 ok(bool(embedded::admin_sqlite_statistics_refresh_query("WITH x AS (SELECT 1) SELECT * FROM x", out)) && out.empty(),
    "CTE scope is explicitly deferred for Admin refresh admission");
 ok(bool(embedded::admin_sqlite_statistics_refresh_query("SELECT 1; SELECT 2", out)) && out.empty(),
    "complete single-statement parsing is required");
 ok(embedded::admin_sqlite_statistics_reset_table("STATS_MYSQL_QUERY_DIGEST_RESET") &&
    !embedded::admin_sqlite_statistics_reset_table("other_stats_mysql_query_digest_reset_suffix"),
    "native authorization recognizes exact reset relation names");
 return exit_status();
}
