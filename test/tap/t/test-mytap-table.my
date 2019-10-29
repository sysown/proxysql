/*
TAP Tests for table functions 
*/

BEGIN;

-- setup for tests
DROP DATABASE IF EXISTS taptest;
CREATE DATABASE taptest;

-- This will be rolled back. :-)
DROP TABLE IF EXISTS taptest.sometab;
DROP TABLE IF EXISTS taptest.othertab;

CREATE TABLE taptest.sometab(
    id      INT NOT NULL PRIMARY KEY,
    name    TEXT,
    numb    FLOAT(10, 2) DEFAULT NULL,
    myNum   INT(8) DEFAULT 24,
    myat    TIMESTAMP DEFAULT NOW(),
    plain   INT
) ENGINE=INNODB, CHARACTER SET utf8, COLLATE utf8_general_ci;


DELIMITER //

DROP PROCEDURE IF EXISTS taptest.createtable //
CREATE PROCEDURE taptest.createtable()
DETERMINISTIC
BEGIN
  -- This procedure allows create table syntax to accomodate changes in
  -- in 5.7.6 for virtual columns
  DECLARE myver INT;

  SET myver = (SELECT tap.mysql_version());

  CASE WHEN myver > 507006 THEN -- virtual fields allowed in 5.7.6
    SET @sql1 = '
      CREATE TABLE taptest.othertab(
      id      INT NOT NULL PRIMARY KEY,
      name    TEXT,
      numb    FLOAT(10, 2) DEFAULT NULL,
      myNum   INT(8) DEFAULT 24,
      myat    TIMESTAMP DEFAULT NOW(),
      plain   INT,
      virt    INT AS (plain * 3) VIRTUAL
      ) ENGINE=INNODB, CHARACTER SET utf8, COLLATE utf8_general_ci';
  WHEN myver > 506004 THEN -- fractional seconds stored in 5.6.4
    SET @sql1 = '
      CREATE TABLE taptest.othertab(
      id      INT NOT NULL PRIMARY KEY,
      name    TEXT,
      numb    FLOAT(10, 2) DEFAULT NULL,
      myNum   INT(8) DEFAULT 24,
      myat    TIMESTAMP(6),
      plain   INT
      ) ENGINE=INNODB, CHARACTER SET utf8, COLLATE utf8_general_ci';
  ELSE 
    SET @sql1 = '
      CREATE TABLE taptest.othertab(
      id      INT NOT NULL PRIMARY KEY,
      name    TEXT,
      numb    FLOAT(10, 2) DEFAULT NULL,
      myNum   INT(8) DEFAULT 24,
      myat    TIMESTAMP DEFAULT NOW(),
      plain   INT
      ) ENGINE=INNODB, CHARACTER SET utf8, COLLATE utf8_general_ci';
  END CASE;

  PREPARE stmt1 FROM @sql1;
  EXECUTE stmt1;
  DEALLOCATE PREPARE stmt1;
END //

DELIMITER ;

CALL taptest.createtable();
DROP PROCEDURE IF EXISTS taptest.createtable;

SELECT tap.plan(57);

/****************************************************************************/
-- has_table(sname VARCHAR(64), tname VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.has_table('taptest', 'sometab', ''),
    true,
    'has_table() extant table',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.has_table('taptest', 'nonexistent', ''),
    false,
    'has_table() nonexistent table',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.has_table('taptest', 'sometab', ''),
    true,
    'has_table() default description',
    'Table taptest.sometab should exist',
    null,
    0
);

SELECT tap.check_test(
    tap.has_table('taptest', 'sometab', 'desc'),
    true,
    'has_table() description supplied',
    'desc',
    null,
    0
);



/****************************************************************************/
-- hasnt_table(sname VARCHAR(64), tname VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.hasnt_table('taptest', 'nonexistent', ''),
    true,
    'hasnt_table() with nonexistent table',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_table('taptest', 'sometab', ''),
    false,
    'hasnt_table() with extant table',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_table('taptest', 'nonexisting', ''),
    true,
    'hasnt_table() default description',
    'Table taptest.nonexisting should not exist',
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_table('taptest', 'nonexisting', 'desc'),
    true,
    'hasnt_table() description supplied',
    'desc',
    null,
    0
);



/****************************************************************************/
-- table_engine_is(sname VARCHAR(64), tname VARCHAR(64), ename VARCHAR(32), description TEXT)

SELECT tap.check_test(
    tap.table_engine_is('taptest', 'sometab', 'INNODB', ''),
    true,
    'table_engine_is() with correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.table_engine_is('taptest', 'sometab', 'MYISAM', ''),
    false,
    'table_engine_is() with incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.table_engine_is('taptest', 'sometab', 'INNODB', ''),
    true,
    'table_engine_is() default description',
    'Table taptest.sometab should have Storage Engine INNODB',
    null,
    0
);

SELECT tap.check_test(
    tap.table_engine_is('taptest', 'sometab', 'INNODB', 'desc'),
    true,
    'table_engine_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.table_engine_is('taptest', 'sometab', 'INVALID_ENGINE', ''),
    false,
    'table_engine_is() invalid engine supplied',
    null,
    'Storage Engine INVALID_ENGINE is not available',
    0
);

SELECT tap.check_test(
    tap.table_engine_is('taptest', 'nonexistant', 'INNODB', ''),
    false,
    'table_engine_is() invalid engine supplied',
    null,
    'Table taptest.nonexistant does not exist',
    0
);




/****************************************************************************/
-- table_collation_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.table_collation_is('taptest', 'sometab', 'utf8_general_ci', ''),
    true,
    'table_collation_is() with correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.table_collation_is('taptest', 'sometab', 'utf8_bin', ''),
    false,
    'table_collation_is() with incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.table_collation_is('taptest', 'sometab', 'utf8_general_ci', ''),
    true,
    'table_collation_is() default description',
    'Table taptest.sometab should have Collation \'utf8_general_ci\'',
    null,
    0
);

SELECT tap.check_test(
    tap.table_collation_is('taptest', 'sometab', 'utf8_general_ci', 'desc'),
    true,
    'table_collation_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.table_collation_is('taptest', 'sometab', 'INVALID_COLLATION', ''),
    false,
    'table_collation_is() invalid engine supplied',
    null,
    'Collation INVALID_COLLATION is not available',
    0
);

SELECT tap.check_test(
    tap.table_collation_is('taptest', 'nonexistent', 'utf8_general_ci', ''),
    false,
    'table_collation_is() nonexistent table supplied',
    null,
    'Table taptest.nonexistent does not exist',
    0
);



/****************************************************************************/
-- table_character_set_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(32), description TEXT)

SELECT tap.check_test(
    tap.table_character_set_is('taptest', 'sometab', 'utf8', ''),
    true,
    'table_character_set_is() with correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.table_character_set_is('taptest', 'sometab', 'latin1', ''),
    false,
    'table_character_set_is() with incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.table_character_set_is('taptest', 'sometab', 'utf8', ''),
    true,
    'table_character_set_is() default description',
    'Table taptest.sometab should have Character set \'utf8\'',
    null,
    0
);

SELECT tap.check_test(
    tap.table_character_set_is('taptest', 'sometab', 'utf8', 'desc'),
    true,
    'table_character_set_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.table_character_set_is('taptest', 'sometab', 'INVALID', ''),
    false,
    'table_character_set_is() invalid charset supplied',
    null,
    'Character set INVALID is not available',
    0
);

SELECT tap.check_test(
    tap.table_character_set_is('taptest', 'nonexistent', 'utf8', ''),
    false,
    'table_character_set_is() nonexistent table supplied',
    null,
    'Table taptest.nonexistent does not exist',
    0
);



/****************************************************************************/
-- tables_are(sname VARCHAR(64), want TEXT, description TEXT)


SELECT tap.check_test(
    tap.tables_are('taptest', '`sometab`,`othertab`', ''),
    true,
    'tables_are() correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.tables_are('taptest', '`sometab`,`nonexistent`', ''),
    false,
    'tables_are() incorrect specification',
    null,
    null,
    0
);


-- Note the diagnostic test here is dependent on the space after the hash
-- and before the line feed and the number of spaces before
-- the table names, which must = 7
SELECT tap.check_test(
    tap.tables_are('taptest', '`sometab`,`nonexistent`', ''),
    false,
    'tables_are() diagnostic',
    null,
    '# 
    Extra tables:
       `othertab`
    Missing tables:
       `nonexistent`',
    0
);

SELECT tap.check_test(
    tap.tables_are('taptest', '`sometab`,`othertab`', ''),
    true,
    'tables_are() default description',
    'Schema taptest should have the correct Tables',
    null,
    0
);

SELECT tap.check_test(
    tap.tables_are('taptest',  '`sometab`,`othertab`', 'desc'),
    true,
    'tables_are() description supplied',
    'desc',
    null,
    0
);


/****************************************************************************/
-- table_sha1_is(sname VARCHAR(64), tname VARCHAR(64), sha1 VARCHAR(40), description TEXT)

-- 5.5 version 90669b522441c2984644a96bf73b925c461d7ff9
-- 5.6.4 version 4a6803e5e0972b8dd96e05c59148187904678e7f
-- 5.7.6 version 9953062d687b36cfa4f1c83191708d55c7cfb976
-- if othertab definition is changed or the _table_sha1() definition changed,
-- rerun the tests with drop database disabled and recalculate sha1 in the database with
-- SELECT tap._table_sha1('taptest','othertab');

-- may require group_concat_max_len to be increased e.g.
-- SET SESSION group_concat_max_len = 1000000;

-- NB
-- 8.0.11 version adds columns.srs_id so this will have to change again
-- but appears to have a bug - so temporarily disabled

SELECT
   CASE WHEN tap.mysql_version() < 506004 THEN
      tap.check_test(
        tap.table_sha1_is('taptest', 'othertab', '90669b522441c2984644a96bf73b925c461d7ff9', ''),
        true,
        'table_sha1() full specification',
        null,
        null,
        0)
   WHEN tap.mysql_version() < 507006 THEN
      tap.check_test(
        tap.table_sha1_is('taptest', 'othertab', '4a6803e5e0972b8dd96e05c59148187904678e7f', ''),
        true,
        'table_sha1() full specification',
        null,
        null,
        0)
   WHEN tap.mysql_version() < 800011 THEN
      tap.check_test(
        tap.table_sha1_is('taptest', 'othertab', '9953062d687b36cfa4f1c83191708d55c7cfb976', ''),
        true,
        'table_sha1() full specification',
        null,
        null,
        0)
   WHEN tap.mysql_version() >= 800011 THEN
        tap.skip(1,'table_sha1_is() disabled due to MySQL bug in 8.0.11')
END ;


SELECT
   CASE WHEN tap.mysql_version() < 506004 THEN
      tap.check_test(
        tap.table_sha1_is('taptest', 'othertab', '90669b522', ''),
        true,
        'table_sha1() partial specification',
        null,
        null,
        0)
   WHEN tap.mysql_version() < 507006 THEN
      tap.check_test(
        tap.table_sha1_is('taptest', 'othertab', '4a6803e5', ''),
        true,
        'table_sha1() partial specification',
        null,
        null,
        0)
  WHEN tap.mysql_version() < 800011 THEN
      tap.check_test(
        tap.table_sha1_is('taptest', 'othertab', '9953062d', ''),
        true,
        'table_sha1() partial specification',
        null,
        null,
        0)
  WHEN tap.mysql_version() >= 800011 THEN
    tap.skip(1,'table_sha1_is() disabled due to MySQL bug in 8.0.11')
END ;


SELECT
  CASE WHEN tap.mysql_version() < 800011 THEN
    tap.check_test(
      tap.table_sha1_is('taptest', 'sometab', '0123456789',''),
      false,
      'table_sha1() incorrect specification',
      null,
      null,
      0)
  WHEN tap.mysql_version() >= 800011 THEN
    tap.skip(1,'table_sha1_is() disabled due to MySQL bug in 8.0.11')
END;

SELECT
  CASE WHEN tap.mysql_version() < 800011 THEN
    tap.check_test(
      tap.table_sha1_is('taptest', 'nonexistent', '1111111111',''),
      false,
      'table_sha1() nonexistent table',
      null,
      'Table taptest.nonexistent does not exist',
      0)
   WHEN tap.mysql_version() >= 800011 THEN
     tap.skip(2,'table_sha1_is() disabled due to MySQL bug in 8.0.11')
END;


SELECT
  CASE WHEN tap.mysql_version() < 800011 THEN
    tap.check_test(
      tap.table_sha1_is('taptest', 'sometab', '1111111111', ''),
      false,
      'table_sha1() default description',
      'Table taptest.sometab definition should match expected value',
      null,
      0)
   WHEN tap.mysql_version() >= 800011 THEN
     tap.skip(2,'table_sha1_is() disabled due to MySQL bug in 8.0.11')
END;


/****************************************************************************/
-- Finish the tests and clean up.

call tap.finish();
DROP DATABASE IF EXISTS taptest;
ROLLBACK;
