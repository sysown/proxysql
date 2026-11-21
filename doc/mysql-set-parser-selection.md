# MySQL SET parser selection

The SET parser and query-processor parser are separate runtime choices.
For ordinary system-variable SET statements that reach the general SET parser,
**an explicit `mysql-set_parser_algorithm` of 1 or 2 takes precedence over
`mysql-query_processor_parser=1`**. Selecting the query-processor parser does
not force these statements through algorithm 3.

This is the intended precedence, confirmed by the maintainer on 2026-10-18
([P1](internal/set-behavior-history-questions.md#p1--two-parser-selectors-now-have-precedence--may-2026)).
The implementation checks algorithms 1 and 2 before its ParserSQL branch:
[general SET dispatch](../lib/MySQL_Session.cpp#L8671).

## Ordinary system SET selection

| mysql-set_parser_algorithm | mysql-query_processor_parser | Parser used by the general system SET handler |
| --- | --- | --- |
| 1 | 0 or 1 | Legacy `parse1()` |
| 2 (default) | 0 or 1 | Legacy `parse1v2()` |
| 3 | 0 or 1 | ParserSQL SET extraction |

For example, setting only `mysql-query_processor_parser=1` while leaving
`mysql-set_parser_algorithm=2` selects query-processor ParserSQL behavior but
keeps algorithm 2 for ordinary system SETs reaching this handler. To select
ParserSQL for those SETs, explicitly set algorithm 3:

```sql
UPDATE global_variables
SET variable_value = '3'
WHERE variable_name = 'mysql-set_parser_algorithm';

LOAD MYSQL VARIABLES TO RUNTIME;
```

Changing either selector does not itself expand the supported SQL subset or
authorize forwarding a successfully tracked SET as original client SQL.
The [implementation review](internal/set-tracking-review.md) distinguishes
current behavior from the agreed frontend-local tracking requirement.

## User-variable analysis has a separate prerequisite

With `mysql-user_variable_tracking=1`, either
`mysql-set_parser_algorithm=3` **or** `mysql-query_processor_parser=1`
satisfies the ParserSQL prerequisite for user-variable analysis. Thus
query-processor parser 1 plus SET algorithm 2 can enable literal user-variable
analysis while keeping the general system SET parser on algorithm 2.

This is an admission condition, not a different precedence rule for ordinary
system SETs. It does not imply support for mixed user/system assignments or
arbitrary user-variable expressions. See the [user-variable feature reference](mysql-user-variable-tracking.md)
and [admission gate](../lib/MySQL_Session.cpp#L8501).

## Earlier handlers still matter

The table describes statements reaching the general parser. Dedicated handlers
run earlier; for example, eligible short `SET NAMES` and autocommit forms have
special handling. Their disposition is not determined solely by the two parser
selectors. See [special-query dispatch](../lib/MySQL_Session.cpp#L1735),
[short SET NAMES](../lib/MySQL_Session.cpp#L1879), and
[autocommit handling](../lib/MySQL_Session.cpp#L1475).

The May 2026 integration design described a broader query-processor override.
That historical proposal does not describe the implemented and now confirmed
MySQL precedence above. This reference does not establish PostgreSQL parser
selection behavior.
