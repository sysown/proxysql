/*
TAP tests for column functions

*/

BEGIN;

-- required for sql_mode test
SET @mode = (SELECT @@session.sql_mode);
SET @@session.sql_mode = 'STRICT_ALL_TABLES';


SELECT tap.plan(222);
-- SELECT * from no_plan();

DROP DATABASE IF EXISTS taptest;
CREATE DATABASE taptest;

-- This will be rolled back. :-)
DROP TABLE IF EXISTS taptest.sometab;
CREATE TABLE taptest.sometab(
    id      INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    uint    INT(5) UNSIGNED,
    name    TEXT CHARACTER SET latin1 COLLATE latin1_general_ci ,
    charcol TEXT CHARACTER SET ASCII COLLATE ascii_bin ,
    numb    FLOAT(10, 2) DEFAULT NULL,
    myNum   INT(8) DEFAULT 24,
    myat    TIMESTAMP DEFAULT NOW() ON UPDATE CURRENT_TIMESTAMP,
    mydate  DATE DEFAULT '0000-00-00',
    plain   INT,
    enumCol enum('VAL1', 'VAL2', 'VAL3') NOT NULL,
    KEY `WeirdIndexName` (`myNum`),
    KEY `multiIndex` (`myNum`,`mydate`),
    UNIQUE KEY (plain)
) ENGINE Innodb CHARACTER SET utf8 COLLATE utf8_general_ci; 

CREATE OR REPLACE VIEW taptest.myView as
select id as viewID, mydate as viewDate, myNum as viewNum, charcol as viewCharcol, plain from taptest.sometab;


/****************************************************************************/
-- has_column(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)

SELECT tap.check_test(
  tap.has_column('taptest', 'sometab', 'id', ''),
  true,
  'has_column() with correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.has_column('taptest', 'sometab', 'nonexistent', ''),
  false,
  'has_column() with incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.has_column('taptest', 'sometab', 'id', ''),
  true,
  'has_column() default description',
  'Column sometab.id should exist',
  null,
  0
);

SELECT tap.check_test(
  tap.has_column('taptest', 'sometab', 'id', 'desc'),
  true,
  'has_column() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.has_column('taptest', 'nonexistent', 'id', ''),
  false,
  'has_column() nonexistent table diagnostic',
  null,
  'Table taptest.nonexistent does not exist',
  0
);

SELECT tap.check_test(
  tap.has_column('taptest', 'myView', 'viewNum', ''),
  true,
  'has_column() column in view',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.has_column('taptest', 'myView', 'myNum', ''),
  false,
  'has_column() underlying column',
  null,
  null,
  0
);


/****************************************************************************/
-- hasnt_column(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)

SELECT tap.check_test(
  tap.hasnt_column('taptest', 'sometab', 'nonexistent', ''),
  true,
  'hasnt_column() with correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.hasnt_column('taptest', 'sometab', 'id', ''),
  false,
  'hasnt_column() with incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.hasnt_column('taptest', 'sometab', 'nonexistent', ''),
  true,
  'hasnt_column() default description',
  'Column sometab.nonexistent should not exist',
  null,
  0
);

SELECT tap.check_test(
  tap.hasnt_column('taptest', 'sometab', 'nonexistent', 'desc'),
  true,
  'hasnt_column() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.hasnt_column('taptest', 'nonexistent', 'id', ''),
  false,
  'hasnt_column() nonexistent table diagnostic',
  null,
  'Table taptest.nonexistent does not exist',
  0
);

SELECT tap.check_test(
  tap.hasnt_column('taptest', 'myView', 'viewNum', ''),
  false,
  'hasnt_column() column in view',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.hasnt_column('taptest', 'myView', 'myNum', ''),
  true,
  'hasnt_column() aliased column in view',
  null,
  null,
  0
);


/****************************************************************************/
-- col_is_null(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)

SELECT tap.check_test(
  tap.col_is_null('taptest', 'sometab', 'name', ''),
  true,
  'col_is_null() with correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_is_null('taptest', 'sometab', 'id', ''),
  false,
  'col_is_null() with incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_is_null('taptest', 'sometab', 'name', ''),
  true,
  'col_is_null() default description',
  'Column sometab.name should allow NULL',
  null,
  0
);

SELECT tap.check_test(
  tap.col_is_null('taptest', 'sometab', 'name', 'desc'),
  true,
  'col_is_null() description supplied',
  'desc',
  null,
  0
);


SELECT tap.check_test(
  tap.col_is_null('taptest', 'sometable', 'nonexistent', ''),
  false,
  'col_is_null() nonexistent column diagnostic',
  null,
  'Column sometable.nonexistent does not exist',
  0
);

SELECT tap.check_test(
  tap.col_is_null('taptest', 'myView', 'viewNum', ''),
  true,
  'col_is_null() column in view',
  null,
  null,
  0
);


/****************************************************************************/
-- col_has_primary_key(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)

SELECT tap.check_test(
  tap.col_has_primary_key('taptest', 'sometab', 'id', ''),
  true,
  'col_has_primary_key() with correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_primary_key('taptest', 'sometab', 'name', ''),
  false,
  'col_has_primary_key() with incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_primary_key('taptest', 'sometab', 'id', ''),
  true,
  'col_has_primary_key() default description',
  'Column sometab.id should be a Primary Key (or part thereof)',
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_primary_key('taptest', 'sometab', 'id', 'desc'),
  true,
  'col_has_primary_key() description supplied',
  'desc',
  null,
  0
);


SELECT tap.check_test(
  tap.col_has_primary_key('taptest', 'sometable', 'nonexistent', ''),
  false,
  'col_has_primary_key() nonexistent column diagnostic',
  null,
  'Column sometable.nonexistent does not exist',
  0
);

SELECT tap.check_test(
  tap.col_has_primary_key('taptest', 'myView', 'viewNum', ''),
  false,
  'col_has_primary_key() column in view',
  null,
  null,
  0
);


/****************************************************************************/
-- col_hasnt_primary_key(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)

SELECT tap.check_test(
  tap.col_hasnt_primary_key('taptest', 'sometab', 'name', ''),
  true,
  'col_hasnt_primary_key() with correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_primary_key('taptest', 'sometab', 'id', ''),
  false,
  'col_hasnt_primary_key() with incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_primary_key('taptest', 'sometab', 'name', ''),
  true,
  'col_hasnt_primary_key() default description',
  'Column sometab.name should not be a Primary Key (or part thereof)',
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_primary_key('taptest', 'sometab', 'name', 'desc'),
  true,
  'col_hasnt_primary_key() description supplied',
  'desc',
  null,
  0
);


SELECT tap.check_test(
  tap.col_hasnt_primary_key('taptest', 'sometable', 'nonexistent', ''),
  false,
  'col_hasnt_primary_key() nonexistent column diagnostic',
  null,
  'Column sometable.nonexistent does not exist',
  0
);

SELECT tap.check_test(
  tap.col_hasnt_primary_key('taptest', 'myView', 'viewNum', ''),
  true,
  'col_hasnt_primary_key() column in view',
  null,
  null,
  0
);


/****************************************************************************/
-- col_has_index_key(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)

SELECT tap.check_test(
  tap.col_has_index_key('taptest', 'sometab', 'myNum', ''),
  true,
  'col_has_index_key() with correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_index_key('taptest', 'sometab', 'name', ''),
  false,
  'col_has_index_key() with incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_index_key('taptest', 'sometab', 'mydate', ''),
  true,
  'col_has_index_key() default description',
  'Column sometab.mydate should have Index Key',
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_index_key('taptest', 'sometab', 'myNum', 'desc'),
  true,
  'col_has_index_key() description supplied',
  'desc',
  null,
  0
);


SELECT tap.check_test(
  tap.col_has_index_key('taptest', 'sometable', 'nonexistent', ''),
  false,
  'col_has_index_key() nonexistent column diagnostic',
  null,
  'Column sometable.nonexistent does not exist',
  0
);

SELECT tap.check_test(
  tap.col_has_index_key('taptest', 'myView', 'viewNum', ''),
  false,
  'col_has_index_key() column in view',
  null,
  null,
  0
);


/****************************************************************************/
-- col_hasnt_index_key(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)

SELECT tap.check_test(
  tap.col_hasnt_index_key('taptest', 'sometab', 'name', ''),
  true,
  'col_hasnt_index_key() with correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_index_key('taptest', 'sometab', 'mydate', ''),
  false,
  'col_hasnt_index_key() with incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_index_key('taptest', 'sometab', 'name', ''),
  true,
  'col_hasnt_index_key() default description',
  'Column sometab.name should not have Index Key',
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_index_key('taptest', 'sometab', 'name', 'desc'),
  true,
  'col_hasnt_index_key() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_index_key('taptest', 'sometable', 'nonexistent', ''),
  false,
  'col_hasnt_index_key() nonexistent column diagnostic',
  null,
  'Column sometable.nonexistent does not exist',
  0
);

SELECT tap.check_test(
  tap.col_hasnt_index_key('taptest', 'myView', 'viewNum', ''),
  true,
  'col_hasnt_index_key() column in view',
  null,
  null,
  0
);


/****************************************************************************/
-- col_has_named_index(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), kname VARCHAR(64), description TEXT)

SELECT tap.check_test(
  tap.col_has_named_index('taptest', 'sometab', 'myNum', 'multiIndex', ''),
  true,
  'col_has_named_index() with correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_named_index('taptest', 'sometab', 'mydate', 'WeirdIndexName', ''),
  false,
  'col_has_named_index() with incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_named_index('taptest', 'sometab', 'mydate', 'multiIndex', ''),
  true,
  'col_has_named_index() default description',
  'Column sometab.mydate should have Index Key multiIndex',
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_named_index('taptest', 'sometab', 'myNum', 'multiIndex', 'desc'),
  true,
  'col_has_named_index() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_named_index('taptest', 'sometable', 'nonexistent', 'multiIndex', ''),
  false,
  'col_has_named_index() nonexistent column diagnostic',
  null,
  'Column sometable.nonexistent does not exist',
  0
);

SELECT tap.check_test(
  tap.col_has_named_index('taptest', 'myView', 'viewNum', 'multiIndex', ''),
  false,
  'col_has_named_index() column in view',
  null,
  null,
  0
);



/****************************************************************************/
-- col_hasnt_named_index(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), kname TEXT, description TEXT)

SELECT tap.check_test(
  tap.col_hasnt_named_index('taptest', 'sometab', 'mydate', 'WeirdIndexName', ''),
  true,
  'col_hasnt_named_index() with correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_named_index('taptest', 'sometab', 'myNum', 'WeirdIndexName', ''),
  false,
  'col_hasnt_named_index() with incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_named_index('taptest', 'sometab', 'name', 'multiIndex', ''),
  true,
  'col_hasnt_named_index() default description',
  'Column sometab.name should not have Index Key multiIndex',
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_named_index('taptest', 'sometab', 'name', 'multiIndex', 'desc'),
  true,
  'col_hasnt_named_index() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_named_index('taptest', 'sometable', 'nonexistent', 'multiIndex', ''),
  false,
  'col_hasnt_named_index() nonexistent column diagnostic',
  null,
  'Column sometable.nonexistent does not exist',
  0
);

SELECT tap.check_test(
  tap.col_hasnt_named_index('taptest', 'myView', 'viewNum', 'multiIndex', ''),
  true,
  'col_hasnt_named_index() column in view',
  null,
  null,
  0
);

/****************************************************************************/
-- Test col_has_unique_index

SELECT tap.check_test(
    tap.col_has_unique_index('taptest', 'sometab', 'myNum', ''),
    false,
    'col_has_unique_index() non unique index',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.col_has_unique_index('taptest', 'sometab', 'myNum', 'my own description'),
    false,
    'col_has_unique_index() user supplied description',
    'my own description',
    null,
    0
);

SELECT tap.check_test(
    tap.col_has_unique_index('taptest', 'sometab', 'plain', ''),
    true,
    'col_has_unique_index() default description',
    'Column sometab.plain should have unique INDEX',
    null,
    0
);

use taptest;
SELECT tap.check_test(
    tap.col_has_unique_index('taptest', 'sometab', 'plain', ''),
    true,
    'col_has_unique_index() with unique index key',
    null,
    null,
    0
);


-- Make sure failure is correct.
SELECT tap.check_test(
    tap.col_has_unique_index('taptest', 'sometab', 'name', ''),
    false,
    'col_has_unique_index() without unique key',
    null,
    null,
    0
);


-- Make sure nonexisting column is correctly detected
SELECT tap.check_test(
    tap.col_has_unique_index('taptest', 'sometab', 'foo', ''),
    false,
    'col_has_unique_index() diagnostic test',
    null,
    'Column sometab.foo does not exist',
    0
);

-- Make sure primary key is correctly detected as non-index
SELECT tap.check_test(
    tap.col_has_unique_index('taptest', 'sometab', 'id', ''),
    false,
    'col_has_unique_index() has primary key',
    null,
    null,
    0
);

/****************************************************************************/

-- Test col_hasnt_unique_index

SELECT tap.check_test(
    tap.col_hasnt_unique_index('taptest', 'sometab', 'enumcol', ''),
    true,
    'col_hasnt_unique_index() correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.col_hasnt_unique_index('taptest', 'sometab', 'plain', ''),
    false,
    'col_hasnt_unique_index() incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.col_hasnt_unique_index( 'taptest', 'sometab', 'myNum', 'my own description' ),
    true,
    'col_hasnt_unique_index() description supplied',
    'my own description',
    null,
    0
);

SELECT tap.check_test(
    tap.col_hasnt_unique_index('taptest', 'sometab', 'myNum', ''),
    true,
    'col_hasnt_unique_index() default description',
    'Column sometab.myNum should not have UNIQUE index',
    null,
    0
);

-- Make sure nonexisting column is correctly detected
SELECT tap.check_test(
    tap.col_hasnt_unique_index('taptest', 'sometab', 'foo', ''),
    false,
    'col_hasnt_unique_index() nonexistent column diagnostic',
    null,
    'Column sometab.foo does not exist',
    0
);


/****************************************************************************/
-- col_has_pos_in_named_index(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), kname VARCHAR(64), pos INT, description TEXT)

SELECT tap.check_test(
  tap.col_has_pos_in_named_index('taptest', 'sometab', 'mydate', 'multiIndex', 2, ''),
  true,
  'col_has_pos_in_named_index() with correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_pos_in_named_index('taptest', 'sometab', 'mydate', 'multiindex', 1, ''),
  false,
  'col_has_pos_in_named_index() with incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_pos_in_named_index('taptest', 'sometab', 'mydate', 'multiIndex', 2, ''),
  true,
  'col_has_pos_in_named_index() default description',
  'Column sometab.mydate should have position 2 in Index multiIndex',
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_pos_in_named_index('taptest', 'sometab', 'myNum', 'WeirdIndexName', 1, 'desc'),
  true,
  'col_has_pos_in_named_index() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_pos_in_named_index('taptest', 'sometable', 'nonexistent', 'multiIndex', 1, ''),
  false,
  'col_has_pos_in_named_index() nonexistent column diagnostic',
  null,
  'Column sometable.nonexistent does not exist',
  0
);

SELECT tap.check_test(
  tap.col_has_pos_in_named_index('taptest', 'myView', 'viewNum', 'multiIndex', 1, ''),
  false,
  'col_has_pos_in_named_index() column in view',
  null,
  null,
  0
);


/****************************************************************************/
-- col_hasnt_pos_in_named_index(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), kname VARCHAR(64), pos INT, description TEXT)

SELECT tap.check_test(
  tap.col_hasnt_pos_in_named_index('taptest', 'sometab', 'mydate', 'multiIndex', 1, ''),
  true,
  'col_hasnt_pos_in_named_index() with correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_pos_in_named_index('taptest', 'sometab', 'mydate', 'multiindex', 2, ''),
  false,
  'col_hasnt_pos_in_named_index() with incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_pos_in_named_index('taptest', 'sometab', 'mydate', 'multiIndex', 1, ''),
  true,
  'col_hasnt_pos_in_named_index() default description',
  'Column sometab.mydate should not have position 1 in Index multiIndex',
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_pos_in_named_index('taptest', 'sometab', 'mydate', 'WeirdIndexName', 1, 'desc'),
  true,
  'col_hasnt_pos_in_named_index() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_pos_in_named_index('taptest', 'sometable', 'nonexistent', 'multiIndex', 1, ''),
  false,
  'col_hasnt_pos_in_named_index() nonexistent column diagnostic',
  null,
  'Column sometable.nonexistent does not exist',
  0
);

SELECT tap.check_test(
  tap.col_hasnt_pos_in_named_index('taptest', 'myView', 'viewNum', 'multiIndex', 1, ''),
  true,
  'col_hasnt_pos_in_named_index() column in view',
  null,
  null,
  0
);


/****************************************************************************/
-- col_has_type(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), dtype VARCHAR(64), description TEXT)

SELECT tap.check_test(
  tap.col_has_type('taptest', 'sometab', 'myNum', 'INT(8)', ''),
  true,
  'col_has_type() TABLE column with correct specification INT(8)',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_type('taptest', 'myView', 'viewNum', 'INT(8)', ''),
  true,
  'col_has_type() VIEW column with correct specification INT(8)',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_type('taptest', 'sometab', 'myNum', 'INTEGER', ''),
  false,
  'col_has_type() INTEGER alias for INT(8) column',
  null,
  null,
  0
);


SELECT tap.check_test(
  tap.col_has_type('taptest', 'sometab', 'myNum', 'DOUBLE', ''),
  false,
  'col_has_type() incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_type('taptest', 'sometab', 'myNum', 'INT(8)', ''),
  true,
  'col_has_type() default description',
  'Column sometab.myNum should have column type \'INT(8)\'',
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_type('taptest', 'sometab', 'myNum', 'INT(8)', 'desc'),
  true,
  'col_has_type() description supplied',
  'desc',
  null,
  0
);


SELECT tap.check_test(
  tap.col_has_type('taptest', 'myView', 'myNum', 'INT(8)', ''),
  false,
  'col_has_type() column not found diagnostic',
  null,
  'Column myView.myNum does not exist',
  0
);


/****************************************************************************/
-- col_data_type_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), dtype VARCHAR(64), description TEXT)

SELECT tap.check_test(
  tap.col_data_type_is('taptest', 'sometab', 'myNum', 'INT', ''),
  true,
  'col_data_type_is() TABLE column with correct specification INT',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_data_type_is('taptest', 'myView', 'viewNum', 'INT', ''),
  true,
  'col_data_type_is() VIEW column with correct specification INT',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_data_type_is('taptest', 'sometab', 'myNum', 'INTEGER', ''),
  false,
  'col_data_type_is() INTEGER alias for INT column',
  null,
  null,
  0
);


SELECT tap.check_test(
  tap.col_data_type_is('taptest', 'sometab', 'myNum', 'DOUBLE', ''),
  false,
  'col_data_type_is() incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_data_type_is('taptest', 'sometab', 'myNum', 'INT', ''),
  true,
  'col_data_type_is() default description',
  'Column sometab.myNum should have data type \'INT\'',
  null,
  0
);


SELECT tap.check_test(
  tap.col_data_type_is('taptest', 'sometab', 'myNum', 'INT', 'desc'),
  true,
  'col_data_type_is() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.col_data_type_is('taptest', 'myView', 'myNum', 'INT', ''),
  false,
  'col_data_type_is() column not found diagnostic',
  null,
  'Column myView.myNum does not exist',
  0
);


/****************************************************************************/
-- col_column_type_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), ctype LONGTEXT, description TEXT)

SELECT tap.check_test(
  tap.col_column_type_is('taptest', 'sometab', 'myNum', 'INT(8)', ''),
  true,
  'col_column_type_is() TABLE column with correct specification INT(11)',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_column_type_is('taptest', 'myView', 'viewNum', 'INT(8)', ''),
  true,
  'col_column_type_is() VIEW column with correct specification INT(8)',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_column_type_is('taptest', 'sometab', 'myNum', 'INT', ''),
  false,
  'col_column_type_is() INT for for INT(8) column',
  null,
  null,
  0
);


SELECT tap.check_test(
  tap.col_column_type_is('taptest', 'sometab', 'myNum', 'DOUBLE', ''),
  false,
  'col_column_type_is() incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_column_type_is('taptest', 'sometab', 'myNum', 'INT(8)', ''),
  true,
  'col_column_type_is() default description',
  'Column sometab.myNum should have Column Type \'INT(8)\'',
  null,
  0
);

SELECT tap.check_test(
  tap.col_column_type_is('taptest', 'sometab', 'myNum', 'INT(8)', 'desc'),
  true,
  'col_column_type_is() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.col_column_type_is('taptest', 'myView', 'myNum', 'INT(8)', ''),
  false,
  'col_column_type_is() column not found diagnostic',
  null,
  'Column myView.myNum does not exist',
  0
);



/****************************************************************************/
-- col_has_default(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)

SELECT tap.check_test(
  tap.col_has_default('taptest', 'sometab', 'myNum', ''),
  true,
  'col_has_default() TABLE column with correct specification',
  null,
  null,
  0
);

-- get's the default of underlying table column
SELECT tap.check_test(
  tap.col_has_default('taptest', 'myView', 'viewNum', ''),
  true,
  'col_has_default() VIEW column',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_default('taptest', 'sometab', 'id', ''),
  false,
  'col_has_default() incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_default('taptest', 'myView', 'plain', ''),
  false,
  'col_has_default() VIEW incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_default('taptest', 'sometab', 'myNum', ''),
  true,
  'col_has_default() default description',
  'Column sometab.myNum should have a default',
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_default('taptest', 'sometab', 'myNum', 'desc'),
  true,
  'col_has_default() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.col_has_default('taptest', 'myView', 'myNum', ''),
  false,
  'col_has_default() column not found diagnostic',
  null,
  'Column myView.myNum does not exist',
  0
);


/****************************************************************************/
-- col_hasnt_default(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)

SELECT tap.check_test(
  tap.col_hasnt_default('taptest', 'sometab', 'numb', ''),
  true,
  'col_hasnt_default() TABLE column with correct specification',
  null,
  null,
  0
);

-- get's the default of underlying table column
SELECT tap.check_test(
  tap.col_hasnt_default('taptest', 'myView', 'plain', ''),
  true,
  'col_hasnt_default() VIEW column',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_default('taptest', 'sometab', 'myNumb', ''),
  false,
  'col_hasnt_default() incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_default('taptest', 'myView', 'viewNumb', ''),
  false,
  'col_hasnt_default() VIEW incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_default('taptest', 'sometab', 'numb', ''),
  true,
  'col_hasnt_default() default description',
  'Column sometab.numb should not have a default',
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_default('taptest', 'sometab', 'numb', 'desc'),
  true,
  'col_hasnt_default() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.col_hasnt_default('taptest', 'myView', 'myNum', ''),
  false,
  'col_hasnt_default() column not found diagnostic',
  null,
  'Column myView.myNum does not exist',
  0
);


/****************************************************************************/
-- col_default_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), cdefault LONGTEXT, description TEXT)

SELECT tap.check_test(
  tap.col_default_is('taptest', 'myView', 'plain', '24', ''),
  false,
  'col_default_is() VIEW column no default',
  null,
  null,
  0
);


SELECT tap.check_test(
  tap.col_default_is('taptest', 'sometab', 'myNum', '24', ''),
  true,
  'col_default_is() default description',
  'Column sometab.myNum should have DEFAULT 24',
  null,
  0
);

SELECT tap.check_test(
  tap.col_default_is('taptest', 'sometab', 'myNum', '24', 'desc'),
  true,
  'col_default_is() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.col_default_is('taptest', 'myView', 'myNum', '24', ''),
  false,
  'col_default_is() column not found diagnostic',
  null,
  'Column myView.myNum does not exist',
  0
);


/****************************************************************************/
-- col_extra_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), cextra VARCHAR(30), description TEXT)

SELECT tap.check_test(
  tap.col_extra_is('taptest', 'sometab', 'id', 'auto_increment', ''),
  true,
  'col_extra_is() column correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_extra_is('taptest', 'sometab', 'id', 'AUTO_INCREMENT', ''),
  true,
  'col_extra_is() column correct specification case-insensitive',
  null,
  null,
  0
);


-- EXTRA is not inherited here
SELECT tap.check_test(
  tap.col_extra_is('taptest', 'myView', 'viewID', 'auto_increment', ''),
  false,
  'col_extra_is() VIEW does not inherit underlying',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_extra_is('taptest', 'sometab', 'id', 'auto_increment', ''),
  true,
  'col_extra_is() extra description',
  'Column sometab.id should have EXTRA auto_increment',
  null,
  0
);

SELECT tap.check_test(
  tap.col_extra_is('taptest', 'sometab', 'id', 'auto_increment', 'desc'),
  true,
  'col_extra_is() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.col_extra_is('taptest', 'myView', 'id', 'auto_increment', ''),
  false,
  'col_extra_is() column not found diagnostic',
  null,
  'Column myView.id does not exist',
  0
);


/****************************************************************************/
-- col_charset_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), cset VARCHAR(32), description TEXT)

SELECT tap.check_test(
  tap.col_charset_is('taptest', 'sometab', 'charcol', 'ascii', ''),
  true,
  'col_charset_is() column correct specification',
  null,
  null,
  0
);

-- should be set for col and not inherited
SELECT tap.check_test(
  tap.col_charset_is('taptest', 'sometab', 'charcol', 'utf8', ''),
  false,
  'col_charset_is() incorrect specification',
  null,
  null,
  0
);


SELECT tap.check_test(
  tap.col_charset_is('taptest', 'myView', 'viewCharcol', 'ascii', ''),
  true,
  'col_charset_is() VIEW inherits charset',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_charset_is('taptest', 'sometab', 'charcol', 'ascii', ''),
  true,
  'col_charset_is() default description',
  'Column sometab.charcol should have CHARACTER SET ascii',
  null,
  0
);

SELECT tap.check_test(
  tap.col_charset_is('taptest', 'sometab', 'charcol', 'ascii', 'desc'),
  true,
  'col_charset_is() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.col_charset_is('taptest', 'myView', 'myNum', 'ascii', ''),
  false,
  'col_charset_is() column not found diagnostic',
  null,
  'Column myView.myNum does not exist',
  0
);



/****************************************************************************/
-- col_character_set_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), cset VARCHAR(32), description TEXT)
-- alias for charset

SELECT tap.check_test(
  tap.col_character_set_is('taptest', 'sometab', 'charcol', 'ascii', ''),
  true,
  'col_character_set_is() column correct specification',
  null,
  null,
  0
);

-- should be set for col and not inherited
SELECT tap.check_test(
  tap.col_character_set_is('taptest', 'sometab', 'charcol', 'utf8', ''),
  false,
  'col_character_set_is() incorrect specification',
  null,
  null,
  0
);


SELECT tap.check_test(
  tap.col_character_set_is('taptest', 'myView', 'viewCharcol', 'ascii', ''),
  true,
  'col_character_set_is() VIEW inherits character_set',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_character_set_is('taptest', 'sometab', 'charcol', 'ascii', ''),
  true,
  'col_character_set_is() default description',
  'Column sometab.charcol should have CHARACTER SET ascii',
  null,
  0
);

SELECT tap.check_test(
  tap.col_character_set_is('taptest', 'sometab', 'charcol', 'ascii', 'desc'),
  true,
  'col_character_set_is() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.col_character_set_is('taptest', 'myView', 'myNum', 'ascii', ''),
  false,
  'col_character_set_is() column not found diagnostic',
  null,
  'Column myView.myNum does not exist',
  0
);


/****************************************************************************/
-- col_collation_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), ccoll VARCHAR(32), description TEXT)


SELECT tap.check_test(
  tap.col_collation_is('taptest', 'sometab', 'charcol', 'ascii_bin', ''),
  true,
  'col_collation_is() column correct specification',
  null,
  null,
  0
);

-- should be set for col and not inherited
SELECT tap.check_test(
  tap.col_collation_is('taptest', 'sometab', 'charcol', 'utf8_general_ci', ''),
  false,
  'col_collation_is() incorrect specification',
  null,
  null,
  0
);


SELECT tap.check_test(
  tap.col_collation_is('taptest', 'myView', 'viewCharcol', 'ascii_bin', ''),
  true,
  'col_collation_is() VIEW inherits collation',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.col_collation_is('taptest', 'sometab', 'charcol', 'ascii_bin', ''),
  true,
  'col_collation_is() default description',
  'Column sometab.charcol should have COLLATION ascii_bin',
  null,
  0
);

SELECT tap.check_test(
  tap.col_collation_is('taptest', 'sometab', 'charcol', 'ascii_bin', 'desc'),
  true,
  'col_collation_is() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.col_collation_is('taptest', 'myView', 'myNum', 'ascii', ''),
  false,
  'col_collation_is() column not found diagnostic',
  null,
  'Column myView.myNum does not exist',
  0
);


/****************************************************************************/
-- columns_are(sname VARCHAR(64), tname VARCHAR(64), want TEXT, description TEXT)


SELECT tap.check_test(
    tap.columns_are('taptest', 'sometab', '`id`,`uint`,`charcol`,`name`,`numb`,`myNum`,`myat`,`mydate`,`plain`,`enumCol`', ''),
    true,
    'columns_are() correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.columns_are('taptest', 'sometab', '`id`,`uint`,`name`,`numb`,`myNum`,`myat`,`mydate`,`plain`,`nonexistent`', ''),
    false,
    'columns_are() incorrect specification',
    null,
    null,
    0
);


-- Note the diagnostic test here is dependent on the space after the hash
-- and before the line feed and the number of spaces before
-- the routine names, which must = 7
SELECT tap.check_test(
    tap.columns_are('taptest', 'sometab', '`id`,`uint`,`name`,`charcol`,`numb`,`myNum`,`myat`,`mydate`,`plain`,`nonexistent`', ''),
    false,
    'columns_are() diagnostic',
    null,
    '# 
    Extra Columns:
       `enumCol`
    Missing Columns:
       `nonexistent`',
    0
);

SELECT tap.check_test(
    tap.columns_are('taptest', 'nonexistent', '`id`,`uint`,`name`,`numb`,`myNum`,`myat`,`mydate`,`plain`,`enumcol`', ''),
    false,
    'columns_are() nonexistent table',
    null,
    'Table taptest.nonexistent does not exist',
    0
);

SELECT tap.check_test(
    tap.columns_are('taptest', 'sometab', '`id`,`uint`,`name`,`numb`,`myNum`,`myat`,`mydate`,`plain`,`charcol`,`enumCol`', ''),
    true,
    'columns_are() default description',
    'Table taptest.sometab should have the correct columns',
    null,
    0
);

SELECT tap.check_test(
    tap.columns_are('taptest', 'sometab', '`id`,`uint`,`name`,`numb`,`myNum`,`myat`,`charcol`,`mydate`,`plain`,`enumCol`', 'desc'),
    true,
    'columns_are() description supplied',
    'desc',
    null,
    0
);



/****************************************************************************/


-- Finish the tests and clean up.
call tap.finish();
DROP DATABASE IF EXISTS taptest;
ROLLBACK;


SET @@session.sql_mode = @mode;
