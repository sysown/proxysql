/*
TAP Tests for Partitions 
*/

BEGIN;

SELECT tap.plan(92);

-- setup for tests
DROP DATABASE IF EXISTS taptest;
CREATE DATABASE taptest;

-- This will be rolled back. :-)

DROP TABLE IF EXISTS taptest.t1;
CREATE TABLE taptest.t1 (
    id   INT NOT NULL PRIMARY KEY,
    col1 INT NULL,
    col2 INT NULL,
    col3 INT NULL
)
PARTITION BY HASH (id)
PARTITIONS 4;


DROP TABLE IF EXISTS taptest.t2;
CREATE TABLE taptest.t2 (
    year_col  INT,
    some_data INT
)
PARTITION BY RANGE (year_col) (
    PARTITION p0 VALUES LESS THAN (1991),
    PARTITION p1 VALUES LESS THAN (1995),
    PARTITION p2 VALUES LESS THAN (1999),
    PARTITION p3 VALUES LESS THAN (2002),
    PARTITION p4 VALUES LESS THAN (2006),
    PARTITION p5 VALUES LESS THAN MAXVALUE
);

DROP TABLE IF EXISTS taptest.t3;
CREATE TABLE taptest.t3 (
    id INT,
    purchased DATE
)
PARTITION BY RANGE( YEAR(purchased) )
SUBPARTITION BY HASH( TO_DAYS(purchased) ) (
    PARTITION p0 VALUES LESS THAN (1990) (
        SUBPARTITION s0,
        SUBPARTITION s1
    ),
    PARTITION p1 VALUES LESS THAN (2000) (
        SUBPARTITION s2,
        SUBPARTITION s3
    ),
    PARTITION p2 VALUES LESS THAN MAXVALUE (
        SUBPARTITION s4,
        SUBPARTITION s5
    )
);

/****************************************************************************/
-- has_partition(sname VARCHAR(64), tname VARCHAR(64), part VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.has_partition('taptest', 't2', 'p0', ''),
    true,
    'has_partition() extant partition',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.has_partition('taptest', 't2', 'nonexistent', ''),
    false,
    'has_partition() nonexistent partition',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.has_partition('taptest', 't2', 'p0', ''),
    true,
    'has_partition() default description',
    'Partition t2.p0 should exist',
    null,
    0
);

SELECT tap.check_test(
    tap.has_partition('taptest', 't2', 'p0', 'desc'),
    true,
    'has_partition() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.has_partition('taptest', 'nonexistent', 'nonexistent', ''),
    false,
    'has_partition() Table not found diagnostic',
    null,
    'Table taptest.nonexistent does not exist',
    0
);


/****************************************************************************/
-- hasnt_partition(sname VARCHAR(64), tname VARCHAR(64), part VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.hasnt_partition('taptest', 't2', 'nonexistent', ''),
    true,
    'hasnt_partition() nonexistent partition',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_partition('taptest', 't2', 'p0', ''),
    false,
    'hasnt_partition() extant partition',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_partition('taptest', 't2', 'nonexistent', ''),
    true,
    'hasnt_partition() default description',
    'Partition t2.nonexistent should not exist',
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_partition('taptest', 't2', 'p0', 'desc'),
    false,
    'hasnt_partition() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_partition('taptest', 'nonexistent', 'p0', ''),
    false,
    'hasnt_partition() Table not found diagnostic',
    null,
    'Table taptest.nonexistent does not exist',
    0
);



/****************************************************************************/
-- has_subpartition(sname VARCHAR(64), tname VARCHAR(64), subp VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.has_subpartition('taptest', 't3', 's0', ''),
    true,
    'has_subpartition() extant subpartition',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.has_subpartition('taptest', 't3', 'nonexistent', ''),
    false,
    'has_subpartition() nonexistent subpartition',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.has_subpartition('taptest', 't3', 's0', ''),
    true,
    'has_subpartition() default description',
    'Subpartition t3.s0 should exist',
    null,
    0
);

SELECT tap.check_test(
    tap.has_subpartition('taptest', 't3', 's0', 'desc'),
    true,
    'has_subpartition() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.has_subpartition('taptest', 'nonexistent', 'nonexistent', ''),
    false,
    'has_subpartition() Table not found diagnostic',
    null,
    'Table taptest.nonexistent does not exist',
    0
);



/****************************************************************************/
-- hasnt_subpartition(sname VARCHAR(64), tname VARCHAR(64), subp VARCHAR(64), description TEXT)


SELECT tap.check_test(
    tap.hasnt_subpartition('taptest', 't3', 'nonexistent', ''),
    true,
    'hasnt_subpartition() nonexistent subpartition',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_subpartition('taptest', 't3', 's0', ''),
    false,
    'hasnt_subpartition() extant subpartition',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_subpartition('taptest', 't3', 'nonexistent', ''),
    true,
    'hasnt_subpartition() default description',
    'Subpartition t3.nonexistent should not exist',
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_subpartition('taptest', 't3', 'nonexistent', 'desc'),
    true,
    'hasnt_subpartition() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_subpartition('taptest', 'nonexistent', 's0', ''),
    false,
    'hasnt_subpartition() Table not found diagnostic',
    null,
    'Table taptest.nonexistent does not exist',
    0
);



/****************************************************************************/
-- partition_expression_is(sname VARCHAR(64), tname VARCHAR(64), part VARCHAR(64), expr LONGTEXT, description TEXT)
-- Subtle change in the way the value is stored in 8.0.11
-- previously the expression was stored as written in the create statement
-- post 8.0.11 the column name gets escaped with backticks whether they were included
-- in the create statement or not

SELECT
  CASE WHEN tap.mysql_version() < 800011 THEN
    tap.check_test(tap.partition_expression_is('taptest', 't3', 'p0', 'YEAR(purchased)' ,''),
    true,
    'partition_expression_is() correct specification',
    null,
    null,
    0)
  WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(tap.partition_expression_is('taptest', 't3', 'p0', 'YEAR(`purchased`)' ,''),
    true,
    'partition_expression_is() correct specification',
    null,
    null,
    0)
END;

SELECT
  CASE WHEN tap.mysql_version() < 800011 THEN
     tap.check_test(tap.partition_expression_is('taptest', 't3', 'p0', 'MONTH(purchased)', ''),
    false,
    'partition_expression_is() incorrect specification',
    null,
    null,
    0)
  WHEN tap.mysql_version() >= 800011 THEN
     tap.check_test(tap.partition_expression_is('taptest', 't3', 'p0', 'MONTH(`purchased`)', ''),
    false,
    'partition_expression_is() incorrect specification',
    null,
    null,
    0)
END;

SELECT
  CASE WHEN tap.mysql_version() < 800011 THEN
    tap.check_test(tap.partition_expression_is('taptest', 't3', 'p0', 'YEAR(purchased)', ''),
    true,
    'partition_expression_is() default description',
    'Partition t3.p0 should have partition expression \'YEAR(purchased)\'',
    null,
    0)
  WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(tap.partition_expression_is('taptest', 't3', 'p0', 'YEAR(`purchased`)', ''),
    true,
    'partition_expression_is() default description',
    'Partition t3.p0 should have partition expression \'YEAR(`purchased`)\'',
    null,
    0)
END;

SELECT
  CASE WHEN tap.mysql_version() < 800011 THEN
    tap.check_test(
    tap.partition_expression_is('taptest', 't3', 'p0', 'YEAR(purchased)', 'desc'),
    true,
    'partition_expression_is() description supplied',
    'desc',
    null,
    0)
  WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
    tap.partition_expression_is('taptest', 't3', 'p0', 'YEAR(`purchased`)', 'desc'),
    true,
    'partition_expression_is() description supplied',
    'desc',
    null,
    0)
END;

-- no case needed here as diag triggered
SELECT tap.check_test(
    tap.partition_expression_is('taptest', 't3', 'nonexistent', 'YEAR(purchased)', ''),
    false,
    'partition_expression_is() Partition not found diagnostic',
    null,
    'Partition t3.nonexistent does not exist',
    0
);


/****************************************************************************/
-- subpartition_expression_is(sname VARCHAR(64), tname VARCHAR(64), subp VARCHAR(64), expr LONGTEXT, description TEXT)

SELECT
  CASE WHEN tap.mysql_version() < 800011 THEN
    tap.check_test(tap.subpartition_expression_is('taptest', 't3', 's0', 'TO_DAYS(purchased)' ,''),
    true,
    'subpartition_expression_is() correct specification',
    null,
    null,
    0)
  WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(tap.subpartition_expression_is('taptest', 't3', 's0', 'TO_DAYS(`purchased`)' ,''),
    true,
    'subpartition_expression_is() correct specification',
    null,
    null,
    0)
END ;

-- expected to fail doesn't need case
SELECT
    tap.check_test(tap.subpartition_expression_is('taptest', 't3', 's0', 'YEAR(purchased)', ''),
    false,
    'subpartition_expression_is() incorrect specification',
    null,
    null,
    0
);

SELECT
  CASE WHEN tap.mysql_version() < 800011 THEN
    tap.check_test(tap.subpartition_expression_is('taptest', 't3', 's0', 'TO_DAYS(purchased)', ''),
    true,
    'subpartition_expression_is() default description',
    'Subpartition t3.s0 should have subpartition expression \'TO_DAYS(purchased)\'',
    null,
    0)
 WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(tap.subpartition_expression_is('taptest', 't3', 's0', 'TO_DAYS(`purchased`)', ''),
    true,
    'subpartition_expression_is() default description',
    'Subpartition t3.s0 should have subpartition expression \'TO_DAYS(`purchased`)\'',
    null,
    0)
END;

SELECT
  CASE WHEN tap.mysql_version() < 800011 THEN
    tap.check_test(tap.subpartition_expression_is('taptest', 't3', 's0', 'TO_DAYS(purchased)', 'desc'),
      true,
      'subpartition_expression_is() description supplied',
      'desc',
      null,
      0)
  WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(tap.subpartition_expression_is('taptest', 't3', 's0', 'TO_DAYS(`purchased`)', 'desc'),
      true,
      'subpartition_expression_is() description supplied',
      'desc',
      null,
      0)
END;

-- case not required diagnostic
SELECT tap.check_test(
    tap.subpartition_expression_is('taptest', 't3', 'nonexistent', 'TO_DAYS(purchased)', ''),
    false,
    'subpartition_expression_is() Subpartition not found diagnostic',
    null,
    'Subpartition t3.nonexistent does not exist',
    0
);


/****************************************************************************/
-- partition_method_is(sname VARCHAR(64), tname VARCHAR(64), part VARCHAR(64), pmeth VARCHAR(18), description TEXT)

SELECT tap.check_test(
    tap.partition_method_is('taptest', 't3', 'p0', 'RANGE' ,''),
    true,
    'partition_method_is() correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.partition_method_is('taptest', 't3', 'p0', 'KEY', ''),
    false,
    'partition_method_is() incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.partition_method_is('taptest', 't3', 'p0', 'RANGE', ''),
    true,
    'partition_method_is() default description',
    'Partition t3.p0 should have partition method \'RANGE\'',
    null,
    0
);

SELECT tap.check_test(
    tap.partition_method_is('taptest', 't3', 'p0', 'RANGE', 'desc'),
    true,
    'partition_method_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.partition_method_is('taptest', 't3', 'nonexistent', 'RANGE', ''),
    false,
    'partition_method_is() Partition not found diagnostic',
    null,
    'Partition t3.nonexistent does not exist',
    0
);

SELECT tap.check_test(
    tap.partition_method_is('taptest', 't3', 'p0', 'nonexistent', ''),
    false,
    'partition_method_is() Invalid Partition method diagnostic',
    null,
    'Partitioning Method must be { RANGE | LIST | HASH | LINEAR HASH | KEY | LINEAR KEY }',
    0
);


/****************************************************************************/
-- subpartition_method_is(sname VARCHAR(64), tname VARCHAR(64), subp VARCHAR(64), smeth VARCHAR(18), description TEXT)

SELECT tap.check_test(
    tap.subpartition_method_is('taptest', 't3', 's0', 'HASH' ,''),
    true,
    'subpartition_method_is() correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.subpartition_method_is('taptest', 't3', 's0', 'KEY', ''),
    false,
    'subpartition_method_is() incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.subpartition_method_is('taptest', 't3', 's0', 'HASH', ''),
    true,
    'subpartition_method_is() default description',
    'Subpartition t3.s0 should have subpartition method \'HASH\'',
    null,
    0
);

SELECT tap.check_test(
    tap.subpartition_method_is('taptest', 't3', 's0', 'RANGE', 'desc'),
    false,
    'subpartition_method_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.subpartition_method_is('taptest', 't3', 'nonexistent', 'HASH', ''),
    false,
    'subpartition_method_is() Subpartition not found diagnostic',
    null,
    'Subpartition t3.nonexistent does not exist',
    0
);

SELECT tap.check_test(
    tap.subpartition_method_is('taptest', 't3', 's0', 'nonexistent', ''),
    false,
    'subpartition_method_is() Invalid Subpartition method diagnostic',
    null,
    'Subpartition Method must be { HASH | LINEAR HASH | KEY | LINEAR KEY }',
    0
);


/****************************************************************************/
-- partition_count_is(sname VARCHAR(64), tname VARCHAR(64), cnt SMALLINT, description TEXT)

SELECT tap.check_test(
    tap.partition_count_is('taptest', 't1', 4, ''),
    true,
    'partition_count_is() correct specification one level',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.partition_count_is('taptest', 't3', 6, ''),
    true,
    'partition_count_is() correct specification two levels',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.partition_count_is('taptest', 't1', 3, ''),
    false,
    'partition_count_is() incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.partition_count_is('taptest', 't1', 4, ''),
    true,
    'partition_count_is() default description',
    'Table taptest.t1 should have a Partition count of 4',
    null,
    0
);

SELECT tap.check_test(
    tap.partition_count_is('taptest', 't1', 4, 'desc'),
    true,
    'partition_count_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.partition_count_is('taptest', 'nonexistent', 6, ''),
    false,
    'partition_count_is() Table not found diagnostic',
    null,
    'Table taptest.nonexistent does not exist',
    0
);


/****************************************************************************/
-- partitions_are(sname VARCHAR(64), tname VARCHAR(64), want TEXT, description TEXT)

SELECT tap.check_test(
    tap.partitions_are('taptest', 't2', '`p0`,`p1`,`p2`,`p3`,`p4`,`p5`', ''),
    true,
    'partitions_are() correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.partitions_are('taptest', 't2', '`p0`,`p1`,`p2`,`p3`,`p4`', ''),
    false,
    'partitions_are() incorrect specification',
    null,
    null,
    0
);

-- Note the diagnostic test here is dependent on the space after the hash
-- and before the line feed and the number of spaces before
-- the routine names, which must = 7
SELECT tap.check_test(
    tap.partitions_are('taptest', 't2', '`p0`,`p1`,`p2`,`p3`,`p4`,`nonexistent`', ''),
    false,
    'partitions_are() diagnostic',
    null,
    '# 
    Extra Partitions:
       `p5`
    Missing Partitions:
       `nonexistent`',
    0
);

SELECT tap.check_test(
    tap.partitions_are('taptest', 'nonexistent', '`p0`,`p1`,`p2`,`p3`,`p4`,`p5`', ''),
    false,
    'partitions_are() nonexistent table',
    null,
    'Table taptest.nonexistent does not exist',
    0
);

SELECT tap.check_test(
    tap.partitions_are('taptest', 't2', '`p0`,`p1`,`p2`,`p3`,`p4`,`p5`', ''),
    true,
    'partitions_are() default description',
    'Table taptest.t2 should have the correct partitions',
    null,
    0
);

SELECT tap.check_test(
    tap.partitions_are('taptest', 't2', '`p0`,`p1`,`p2`,`p3`,`p4`,`p5`', 'desc'),
    true,
    'partitions_are() description supplied',
    'desc',
    null,
    0
);




/****************************************************************************/
-- has_partitioning(description TEXT)
-- assume this will run if the others did
-- Version 8.0.11 removes generic partitioning so skip tests
-- which would otherwise fail because function is removed 

SELECT
  CASE WHEN tap.mysql_version() < 800011 THEN
    tap.check_test(tap.has_partitioning(''),
      true,
      'has partitioning() returns true',
      null,
      null,
    0)
 WHEN tap.mysql_version() >= 800011 THEN
    tap.skip(1,'Generic Partitioning removed in MySQL version 8.0.11')
END ;

SELECT
  CASE WHEN tap.mysql_version() < 800011 THEN
    tap.check_test(tap.has_partitioning(''),
      true,
      'has partitioning() default description',
      'Partitioning should be active',
      null,
      0)
  WHEN tap.mysql_version() >= 800011 THEN
    tap.skip(2,'Generic Partitioning removed in MySQL version 8.0.11')
END;

SELECT
  CASE WHEN tap.mysql_version() < 800011 THEN
    tap.check_test(tap.has_partitioning('desc'),
      true,
      'has partitioning() description supplied',
      'desc',
      null,
      0)
  WHEN tap.mysql_version() >= 800011 THEN
    tap.skip(2,'Generic Partitioning removed in MySQL version 8.0.11')
END;

/****************************************************************************/

-- Finish the tests and clean up.

call tap.finish();
DROP DATABASE taptest;
ROLLBACK;
