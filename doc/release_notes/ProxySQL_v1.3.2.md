## ProxySQL v1.3.1

Release date: 2016-12-29

Stable release v1.3.2 , released on 2016-12-29

Compared to v1.3.1, has the following bugs fixed / enhancements:

* Monitor: crashing bug and memory leak in `purge_idle_connection` fixed thanks to @efirs
* Query routing: query session variables, combined with `transaction_persistent==true` were incorrectly disabling query routing [#837](../../../../issues/837)
* Monitor/Galera: improvement on scheduler tool `proxysql_galera_checker.sh`  , thanks to @grypyrg
* MySQL Protocol: support for COM_QUERY + USE as equivalent to COM_INIT_DB [#718](../../../../issues/718)
* Admin: improved the speed time to populate tables `stats_mysql_query_digest` and `stats_mysql_query_digest_text`

Introduced two new variables, mainly to reduce memory footprint for wokload with a lot of unique queries [#766](../../../../issues/766):
* mysql-query_digests_max_digest_length : defines the maximum length of `digest_text` as reported in `stats_mysql_query_digest`
* mysql-query_digests_max_query_length : defines the maximum query length processed when computing query's `digest` and `digext_text`


* Prepared statements: memory leak on error during STMT_EXECUTE [#796](../../../../issues/796)
* Monitor: incorrectly reported timeout on check read_only [#836](../../../../issues/836)
* Monitor: crashing bug [#715](../../../../issues/715)
* MySQL Protocol: handles charset = 0 [#810](../../../../issues/810)
* MySQL Protocol: disables multiplexing for SET FOREIGN_KEY_CHECKS [#835](../../../../issues/835)
* MySQL Protocol: disables multiplexing for SET UNIQUE_CHECKS [#835](../../../../issues/835)
