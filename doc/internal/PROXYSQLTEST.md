## PROXYSQLTEST commands

ProxySQL Admin supports a series of PROXYSQLTEST commands that are used to run internal testing. They can be used for both benchmark, and to validate the correctness of certain algorithms.  

This document is a work in progress, and do not list all commands yet.  

## Commands related to `mysql_query_rules_fast_routing`

* PROXYSQLTEST 11 [arg1]

It creates _arg1_ random rows in `mysql_query_rules_fast_routing` . If _arg1_ is omitted, 10000 rows are created.

* PROXYSQLTEST 12 [arg1]

Like `PROXYSQLTEST 11`, but it also internally excutes `LOAD MYSQL QUERY RULES TO RUNTIME`.

* PROXYSQLTEST 13 [arg1]

It internally excutes `LOAD MYSQL QUERY RULES TO RUNTIME` _arg1_ times. If _arg1_ is omitted, 1 applies.

* PROXYSQLTEST 14 [arg1]

This run `SELECT username, schemaname, flagIN, destination_hostgroup FROM mysql_query_rules_fast_routing ORDER BY RANDOM()` , and then for each row it searches the `destination_hostgroup` for the given `username+schemaname+flagIN`. Therefore this function verify the correctness of the load algorithm and search algorithm.
The check is performed _arg1_ times. If _arg1_ is omitted, 1 applies. 


* PROXYSQLTEST 15 [arg1]

Like `PROXYSQLTEST 11`, it creates _arg1_ random rows in `mysql_query_rules_fast_routing` , but using an empty string for `username`. If _arg1_ is omitted, 10000 rows are created.

* PROXYSQLTEST 16 [arg1]

Like `PROXYSQLTEST 15`, but it also internally excutes `LOAD MYSQL QUERY RULES TO RUNTIME`.

* PROXYSQLTEST 17 [arg1]

This run `SELECT username, schemaname, flagIN, destination_hostgroup FROM mysql_query_rules_fast_routing ORDER BY RANDOM()` , and then for each row it searches the `destination_hostgroup` for the given `username+schemaname+flagIN`. Therefore this function verify the correctness of the load algorithm and search algorithm.  
In a way, this is almost identical to `PROXYSQLTEST 14` . The only difference compared to `PROXYSQLTEST 14` is that it calls a different function to perform the search.  
If the searching function receive a empty username, it first performs a search with a random username, and then it performs a search with an empty username. In other words, it will perform two searches. This is used to benchmark the new search algorithm introduced in 2.0.11 that allows empty usernames.  
The check is performed _arg1_ times. If _arg1_ is omitted, 1 applies.


