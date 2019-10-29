/*
TAP Tests for routines table functions 

NB
Test have been rewritten to attempt to only
test one aspect of the routine definition at a time despite
the fact that check_test can in theory test success/fail, description
and disgnostic message simultaneously.
*/

-- setup for tests

-- required for sql_mode test
SET @mode = (SELECT @@session.sql_mode);
SET @@session.sql_mode = 'REAL_AS_FLOAT';


BEGIN;


SELECT tap.plan(121);
-- SELECT * from tap.no_plan();

DROP DATABASE IF EXISTS taptest;
CREATE DATABASE taptest;

-- This will be rolled back. :-)
DROP TABLE IF EXISTS taptest.sometab;
CREATE TABLE taptest.sometab(
    id      INT NOT NULL PRIMARY KEY,
    name    TEXT,
    numb    FLOAT(10, 2) DEFAULT NULL,
    myNum   INT(8) DEFAULT 24,
    myat    TIMESTAMP DEFAULT NOW(),
    plain   INT
);

DELIMITER //

DROP FUNCTION IF EXISTS taptest.intFunction  //
CREATE FUNCTION taptest.intFunction (param varchar(10) )
RETURNS INT
DETERMINISTIC
SQL SECURITY INVOKER
CONTAINS SQL
BEGIN
    DECLARE ret int(10);
  
    SELECT 12 into ret;
    RETURN ret;
END //

-- this next is only for testing routines_are
DROP FUNCTION IF EXISTS taptest.varFunction  //
CREATE FUNCTION taptest.varFunction (param varchar(10) )
RETURNS VARCHAR(256)
DETERMINISTIC
SQL SECURITY INVOKER
CONTAINS SQL
BEGIN
    DECLARE ret VARCHAR(256);
  
    SELECT 'varchar(256)' into ret;
    RETURN ret;
END //

DROP PROCEDURE IF EXISTS taptest.myProc //
CREATE PROCEDURE taptest.myProc ( param TEXT )
DETERMINISTIC
SQL SECURITY DEFINER
READS SQL DATA
BEGIN
    SELECT * from taptest.sometab;
END //

DELIMITER ;


/****************************************************************************/
-- has_function(sname VARCHAR(64), rname VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.has_function('taptest', 'intFunction', ''),
    true,
    'has_function() default desc',
    'Function taptest.intFunction should exist',
    null,
    0
);

SELECT tap.check_test(
    tap.has_function('taptest', 'intFunction', 'description supplied'),
    true,
    'has_function() with desc supplied',
    'description supplied',
    null,
    0
);

SELECT tap.check_test(
    tap.has_function('taptest', 'myProc', ''),
    false,
    'has_function() matching procedure',
    null,
    null,
    0
);

/****************************************************************************/
-- hasnt_function(sname VARCHAR(64), rname VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.hasnt_function('taptest', 'myFun', ''),
    true,
    'hasnt_function() for nonexistent function',
    null,
    null,
    0
);
 
SELECT tap.check_test(
    tap.hasnt_function('taptest', 'intFunction', ''),
    false,
    'hasnt_function() for extant function',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_function('taptest', 'myFun', ''),
    true,
    'hasnt_function() default description',
    'Function taptest.myFun should not exist',
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_function('taptest', 'myFun', 'mydesc'),
    true,
    'hasnt_function() description supplied',
    'mydesc',
    null,
    0
);

/****************************************************************************/
-- has_procedure(sname VARCHAR(64), rname VARCHAR(64), description TEXT)
SELECT tap.check_test(
    tap.has_procedure('taptest', 'myProc', ''),
    true,
    'has_procedure()',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.has_procedure('taptest', 'myProc', 'desc'),
    true,
    'has_procedure() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.has_procedure('taptest', 'myProc', ''),
    true,
    'has_procedure() default description',
    'Procedure taptest.myProc should exist',
    null,
    0
);

--
SELECT tap.check_test(
    tap.has_procedure('taptest', 'intFunction', ''),
    false,
    'has_procedure() match function',
    null,
    null,
    0
);

/****************************************************************************/
-- hasnt_procedure(sname VARCHAR(64), rname VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.hasnt_procedure('taptest', 'nonexistent', ''),
    true,
    'hasnt_procedure() nonexistent procedure',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_procedure('taptest', 'myProc', ''),
    false,
    'hasnt_procedure() extant procedure',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_procedure('taptest', 'nonexistent', ''),
    true,
    'hasnt_procedure() default description',
    'Procedure taptest.nonexistent should not exist',
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_procedure('taptest', 'nonexistent', 'desc'),
    true,
    'hasnt_procedure() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_procedure('taptest', 'intFunction', ''),
    true,
    'hasnt_procedure() matching Function',
    null,
    null,
    0
);


/****************************************************************************/
-- function_data_type_is(sname VARCHAR(64), rname VARCHAR(64), dtype VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.function_data_type_is('taptest', 'intFunction', 'INT', ''),
    true,
    'function_data_type()',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.function_data_type_is('taptest', 'intFunction', 'INTEGER', ''),
    true,
    'function_data_type() against INT function allows INTEGER synonym',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.function_data_type_is('taptest', 'intFunction', 'VARCHAR', ''),
    false,
    'function_data_type_is() INT function returning VARCHAR',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.function_data_type_is('taptest', 'intFunction', 'INTEGER', ''),
    true,
    'function_data_type_is() default description',
    'Function taptest.intFunction should return `INT`',
    null,
    0
);

SELECT tap.check_test(
    tap.function_data_type_is('taptest', 'intFunction', 'INTEGER', 'desc'),
    true,
    'function_data_type_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.function_data_type_is('taptest', 'myFunc', 'INT', ''),
    false,
    'function_data_type_is() for nonexistent function',
    null,
    'Function taptest.myFunc does not exist',
    0
);



/****************************************************************************/
-- function_is_deterministic(sname VARCHAR(64), rname VARCHAR(64), val VARCHAR(3), description TEXT)

SELECT tap.check_test(
    tap.function_is_deterministic('taptest', 'intFunction', 'YES', ''),
    true,
    'function_is_deterministic_type() correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.function_is_deterministic('taptest', 'intFunction', 'XXX', ''),
    false,
    'function_is_deterministic() non-valid specification',
    null,
    'Is Deterministic must be { YES | NO }',
    0
);

SELECT tap.check_test(
    tap.function_is_deterministic('taptest', 'nonexistent', 'YES', ''),
    false,
    'function_is_deterministic() nonexistent function',
    null,
    'Function taptest.nonexistent does not exist',
    0
);

SELECT tap.check_test(
    tap.function_is_deterministic('taptest', 'intFunction', 'YES', ''),
    true,
    'function_is_deterministic() default description',
    'Function taptest.intFunction should have IS_DETERMINISTIC YES',
    null,
    0
);

SELECT tap.check_test(
    tap.function_is_deterministic('taptest', 'intFunction', 'YES', 'desc'),
    true,
    'function_is_deterministic() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.function_is_deterministic('taptest', 'myProc', 'YES', ''),
    false,
    'function_is_deterministic() matching procedure',
    null,
    null,
    0
);




/****************************************************************************/
-- procedure_is_deterministic(sname VARCHAR(64), rname VARCHAR(64), val VARCHAR(3), description TEXT)

SELECT tap.check_test(
    tap.procedure_is_deterministic('taptest', 'myProc', 'YES', ''),
    true,
    'procedure_is_deterministic_type() correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.procedure_is_deterministic('taptest', 'myProc', 'NO', ''),
    false,
    'procedure_is_deterministic_type() incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.procedure_is_deterministic('taptest', 'myProc', 'XXX', ''),
    false,
    'procedure_is_deterministic() non-valid specification',
    null,
    'Is Deterministic must be { YES | NO }',
    0
);

SELECT tap.check_test(
    tap.procedure_is_deterministic('taptest', 'nonexistent', 'YES', ''),
    false,
    'procedure_is_deterministic() nonexistent procedure',
    null,
    'Procedure taptest.nonexistent does not exist',
    0
);

SELECT tap.check_test(
    tap.procedure_is_deterministic('taptest', 'myProc', 'YES', ''),
    true,
    'procedure_is_deterministic() default description',
    'Procedure taptest.myProc should have IS_DETERMINISTIC YES',
    null,
    0
);

SELECT tap.check_test(
    tap.procedure_is_deterministic('taptest', 'myProc', 'YES', 'desc'),
    true,
    'procedure_is_deterministic() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.procedure_is_deterministic('taptest', 'intFunction', 'YES', ''),
    false,
    'procedure_is_deterministic() matching function',
    null,
    null,
    0
);





/****************************************************************************/
-- function_security_type_is(sname VARCHAR(64), rname VARCHAR(64), stype VARCHAR(7), description TEXT)

SELECT tap.check_test(
    tap.function_security_type_is('taptest', 'intFunction', 'INVOKER', ''),
    true,
    'function_security_type_is() correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.function_security_type_is('taptest', 'intFunction', 'DEFINER', ''),
    false,
    'function_security_type_is() incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.function_security_type_is('taptest', 'intFunction', 'XXX', ''),
    false,
    'function_security_type_is() non-valid specification',
    null,
    'Security type must be { INVOKER | DEFINER }',
    0
);

SELECT tap.check_test(
    tap.function_security_type_is('taptest', 'nonexistent', 'INVOKER', ''),
    false,
    'function_security_type_is() nonexistent function',
    null,
    'Function taptest.nonexistent does not exist',
    0
);

SELECT tap.check_test(
    tap.function_security_type_is('taptest', 'intFunction', 'INVOKER', ''),
    true,
    'function_security_type_is() default description',
    'Function taptest.intFunction should have SECURITY TYPE INVOKER',
    null,
    0
);

SELECT tap.check_test(
    tap.function_security_type_is('taptest', 'intFunction', 'INVOKER', 'desc'),
    true,
    'function_security_type_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.function_security_type_is('taptest', 'myProc', 'INVOKER', ''),
    false,
    'function_security_type_is() matching procedure',
    null,
    null,
    0
);


/****************************************************************************/
-- procedure_security_type_is(sname VARCHAR(64), rname VARCHAR(64), stype VARCHAR(7), description TEXT)

SELECT tap.check_test(
    tap.procedure_security_type_is('taptest', 'myProc', 'DEFINER', ''),
    true,
    'procedure_security_type_is() correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.procedure_security_type_is('taptest', 'myProc', 'INVOKER', ''),
    false,
    'procedure_security_type_is() incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.procedure_security_type_is('taptest', 'myProc', 'XXX', ''),
    false,
    'procedure_security_type_is() non-valid specification',
    null,
    'Security type must be { INVOKER | DEFINER }',
    0
);

SELECT tap.check_test(
    tap.procedure_security_type_is('taptest', 'nonexistent', 'DEFINER', ''),
    false,
    'procedure_security_type_is() nonexistent procedure',
    null,
    'Procedure taptest.nonexistent does not exist',
    0
);

SELECT tap.check_test(
    tap.procedure_security_type_is('taptest', 'myProc', 'DEFINER', ''),
    true,
    'procedure_security_type_is() default description',
    'Procedure taptest.myProc should have SECURITY TYPE DEFINER',
    null,
    0
);

SELECT tap.check_test(
    tap.procedure_security_type_is('taptest', 'myProc', 'DEFINER', 'desc'),
    true,
    'procedure_security_type_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.procedure_security_type_is('taptest', 'intFunction', 'DEFINER', ''),
    false,
    'procedure_security_type_is() matching function',
    null,
    null,
    0
);


/****************************************************************************/
-- function_sql_data_access_is(sname VARCHAR(64), rname VARCHAR(64), sda VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.function_sql_data_access_is('taptest', 'intFunction', 'CONTAINS SQL', ''),
    true,
    'function_sql_data_access_is() correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.function_sql_data_access_is('taptest', 'intFunction', 'NO SQL', ''),
    false,
    'function_sql_data_access_is() incorrect specification 1',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.function_sql_data_access_is('taptest', 'intFunction', 'MODIFIES SQL DATA', ''),
    false,
    'function_sql_data_access_is() incorrect specification 2',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.function_sql_data_access_is('taptest', 'intFunction', 'READS SQL DATA', ''),
    false,
    'function_sql_data_access_is() incorrect specification 3',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.function_sql_data_access_is('taptest', 'intFunction', 'XXX', ''),
    false,
    'function_sql_data_access_is() non-valid specification',
    null,
    'SQL Data Access must be { CONTAINS SQL | NO SQL | READS SQL DATA | MODIFIES SQL DATA }',
    0
);

SELECT tap.check_test(
    tap.function_sql_data_access_is('taptest', 'nonexistent', 'CONTAINS SQL', ''),
    false,
    'function_sql_data_access_is() nonexistent function',
    null,
    'Function taptest.nonexistent does not exist',
    0
);

SELECT tap.check_test(
    tap.function_sql_data_access_is('taptest', 'intFunction', 'CONTAINS SQL', ''),
    true,
    'function_sql_data_access_is() default description',
    'Function taptest.intFunction should have SQL Data Access CONTAINS SQL',
    null,
    0
);

SELECT tap.check_test(
    tap.function_sql_data_access_is('taptest', 'intFunction', 'CONTAINS SQL', 'desc'),
    true,
    'function_sql_data_access_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.function_sql_data_access_is('taptest', 'myProc', 'CONTAINS SQL', ''),
    false,
    'function_sql_data_access_is() matching procedure',
    null,
    null,
    0
);


/****************************************************************************/
-- procedure_sql_data_access_is(sname VARCHAR(64), rname VARCHAR(64), sda VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.procedure_sql_data_access_is('taptest', 'myProc', 'READS SQL DATA', ''),
    true,
    'procedure_sql_data_access_is() correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.procedure_sql_data_access_is('taptest', 'myProc', 'NO SQL', ''),
    false,
    'procedure_sql_data_access_is() incorrect specification 1',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.procedure_sql_data_access_is('taptest', 'myProc', 'CONTAINS SQL', ''),
    false,
    'procedure_sql_data_access_is() incorrect specification 2',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.procedure_sql_data_access_is('taptest', 'myProc', 'MODIFIES SQL DATA', ''),
    false,
    'procedure_sql_data_access_is() incorrect specification 3',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.procedure_sql_data_access_is('taptest', 'myProc', 'XXX', ''),
    false,
    'procedure_sql_data_access_is() non-valid specification',
    null,
    'SQL Data Access must be { CONTAINS SQL | NO SQL | READS SQL DATA | MODIFIES SQL DATA }',
    0
);

SELECT tap.check_test(
    tap.procedure_sql_data_access_is('taptest', 'nonexistent', 'READS SQL DATA', ''),
    false,
    'procedure_sql_data_access_is() nonexistent procedure',
    null,
    'Procedure taptest.nonexistent does not exist',
    0
);

SELECT tap.check_test(
    tap.procedure_sql_data_access_is('taptest', 'myProc', 'READS SQL DATA', ''),
    true,
    'procedure_sql_data_access_is() default description',
    'Procedure taptest.myProc should have SQL Data Access READS SQL DATA',
    null,
    0
);

SELECT tap.check_test(
    tap.procedure_sql_data_access_is('taptest', 'myProc', 'READS SQL DATA', 'desc'),
    true,
    'procedure_sql_data_access_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.procedure_sql_data_access_is('taptest', 'intFunction', 'READS SQL DATA', ''),
    false,
    'procedure_sql_data_access_is() matching function',
    null,
    null,
    0
);



/****************************************************************************/


-- routine_has_sql_mode(sname VARCHAR(64), rname VARCHAR(64), rtype VARCHAR(64), smode VARCHAR(8192), description TEXT)
SELECT tap.check_test(
    tap.routine_has_sql_mode('taptest', 'intFunction', 'FUNCTION', 'REAL_AS_FLOAT', ''),
    true,
    'routine_has_sql_mode() correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.routine_has_sql_mode('taptest', 'intFunction', 'FUNCTION', 'STRICT_TRANS_TABLES', ''),
    false,
    'routine_has_sql_mode() incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.routine_has_sql_mode('taptest', 'intFunction', 'FUNCTION', 'XXX', ''),
    false,
    'routine_has_sql_mode() non-valid specification',
    null,
    'SQL Mode XXX is invalid',
    0
);


/****************************************************************************/
-- routines_are(sname VARCHAR(64), rtype VARCHAR(9), want TEXT, description TEXT)

SELECT tap.check_test(
    tap.routines_are('taptest', 'FUNCTION', '`intFunction`,`varFunction`', ''),
    true,
    'routines_are() correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.routines_are('taptest', 'FUNCTION', '`intFunction`,`nonexistent`', ''),
    false,
    'routines_are() incorrect specification',
    null,
    null,
    0
);


-- Note the diagnostic test here is dependent on the space after the hash
-- and before the line feed and the number of spaces before
-- the routine names, which must = 7
SELECT tap.check_test(
    tap.routines_are('taptest', 'FUNCTION', '`intFunction`,`nonexistent`', ''),
    false,
    'routines_are() diagnostic',
    null,
    '# 
    Extra FUNCTIONs:
       `varFunction`
    Missing FUNCTIONs:
       `nonexistent`',
    0
);

SELECT tap.check_test(
    tap.routines_are('taptest', 'FUNCTION', '`intFunction`,`varFunction`', ''),
    true,
    'routines_are() default description',
    'Schema taptest should have the correct functions',
    null,
    0
);

SELECT tap.check_test(
    tap.routines_are('taptest', 'FUNCTION', '`intFunction`,`varFunction`', 'desc'),
    true,
    'routines_are() default description',
    'desc',
    null,
    0
);



/****************************************************************************/
-- routine_sha1_is(sname VARCHAR(64), rname VARCHAR(64), rtype VARCHAR(9), sha1 VARCHAR(40), description TEXT)

SELECT tap.check_test(
    tap.routine_sha1_is('taptest', 'intFunction', 'FUNCTION', 'e03203790b3ef45f28753efff6d52f5255e32b2e', ''),
    true,
    'routine_sha1() full specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.routine_sha1_is('taptest', 'intFunction', 'FUNCTION', 'e03203790b', ''),
    true,
    'routine_sha1() partial specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.routine_sha1_is('taptest', 'intFunction', 'FUNCTION', '0123456789',''),
    false,
    'routine_sha1() incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.routine_sha1_is('taptest', 'nonexistent', 'FUNCTION', '0123456789',''),
    false,
    'routine_sha1() nonexistent function',
    null,
    'Function taptest.nonexistent does not exist',
    0
);


SELECT tap.check_test(
    tap.routine_sha1_is('taptest', 'intFunction', 'FUNCTION', 'e03203790b3ef45f28753efff6d52f5255e32b2e', ''),
    true,
    'routine_sha1() default description',
    'Function taptest.intFunction definition should match expected value',
    null,
    0
);

/****************************************************************************/

-- Finish the tests and clean up.
call tap.finish();
DROP DATABASE IF EXISTS taptest;
ROLLBACK;


SET @@session.sql_mode = @mode;
