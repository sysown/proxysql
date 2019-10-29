-- ROUTINES
-- ========

USE tap;

DELIMITER //

-- work around for STRICT MODE in 5.7
SELECT tap.mysql_version() INTO @version //
SET @mode = (SELECT @@SESSION.sql_mode) //
SET @@SESSION.sql_mode = '' //


/****************************************************************************/

-- internal function to check
DROP FUNCTION IF EXISTS _has_routine //
CREATE FUNCTION _has_routine(sname VARCHAR(64), rname VARCHAR(64), rtype VARCHAR(9))
RETURNS BOOLEAN
DETERMINISTIC
COMMENT 'Internal boolean test for the existence of a named routine within the given schema.'
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `information_schema`.`routines`
  WHERE `routine_schema` = sname
  AND `routine_name` = rname
  AND `routine_type` = rtype;

  RETURN COALESCE(ret,0);
END //

-- has_routine(schema, routine, type, description)
DROP FUNCTION IF EXISTS has_routine //
CREATE FUNCTION has_routine(sname VARCHAR(64), rname VARCHAR(64), rtype VARCHAR(9), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Test for the existence of a named routine within a given schema.'
BEGIN
  IF description = '' THEN
    SET description = CONCAT(rtype ,' ',
      quote_ident(sname), '.', quote_ident(rname), ' should exist');
  END IF;

  RETURN ok(_has_routine(sname, rname, rtype), description);
END //

-- hasnt_routine(schema, name, type, description)
DROP FUNCTION IF EXISTS hasnt_routine //
CREATE FUNCTION hasnt_routine(sname VARCHAR(64), rname VARCHAR(64), rtype VARCHAR(9), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Check that a named routine does not exist within the given schema.'
BEGIN
  IF description = '' THEN
    SET description = CONCAT(rtype ,' ',
      quote_ident(sname), '.', quote_ident(rname), ' should not exist');
  END IF;

  RETURN ok(NOT _has_routine(sname, rname, rtype), description);
END //


DROP FUNCTION IF EXISTS has_function //
CREATE FUNCTION has_function(sname VARCHAR(64), rname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Check that a named function exists within the given schema.'
BEGIN
  RETURN has_routine(sname, rname, 'Function', description);
END //

DROP FUNCTION IF EXISTS has_procedure //
CREATE FUNCTION has_procedure(sname VARCHAR(64), rname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Check that a named procedure exists within the given schema.'
BEGIN
  RETURN has_routine(sname, rname, 'Procedure', description);
END //


DROP FUNCTION IF EXISTS hasnt_function //
CREATE FUNCTION hasnt_function(sname VARCHAR(64), rname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Check that a named function does not exist within the given schema.'
BEGIN
  RETURN hasnt_routine(sname, rname, 'Function', description);
END //

DROP FUNCTION IF EXISTS hasnt_procedure //
CREATE FUNCTION hasnt_procedure(sname VARCHAR(64), rname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Check that a named procedure does not exist within the given schema.'
BEGIN
  RETURN hasnt_routine(sname, rname, 'Procedure', description);
END //


/****************************************************************************/

-- FUNCTION DATA_TYPE i.e. return type
-- NB Procedures have no data_type so only deal with Functions

-- _function_data_type(schema, function, returns, description)
DROP FUNCTION IF EXISTS _function_data_type  //
CREATE FUNCTION _function_data_type(sname VARCHAR(64), rname VARCHAR(64))
RETURNS VARCHAR(64)
DETERMINISTIC
COMMENT 'Internal function to return the data type returned by a function.'
BEGIN
  DECLARE ret VARCHAR(64);

  SELECT `data_type` INTO ret
  FROM `information_schema`.`routines`
  WHERE `routine_schema` = sname
  AND `routine_name` = rname
  AND `routine_type` = 'FUNCTION';

  RETURN COALESCE(ret, NULL);
END //

-- function_data_type_is(schema, function, returns, description)
DROP FUNCTION IF EXISTS function_data_type_is//
CREATE FUNCTION function_data_type_is(sname VARCHAR(64), rname VARCHAR(64), dtype VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Check that a named function returns the given data type.'
BEGIN
  IF description = '' THEN
    SET description = concat('Function ', quote_ident(sname), '.', quote_ident(rname),
      ' should return ', quote_ident(_datatype(dtype)));
  END IF;

  IF NOT _has_routine(sname, rname, 'FUNCTION') THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Function ', quote_ident(sname),'.', quote_ident(rname),
        ' does not exist')));
  END IF;

  RETURN eq(_function_data_type(sname, rname), _datatype(dtype), description);
END //


/****************************************************************************/

-- IS_DETERMINISTIC YES/NO

-- _routine_is_deterministic(schema, name, type, description)
DROP FUNCTION IF EXISTS _routine_is_deterministic  //
CREATE FUNCTION _routine_is_deterministic(sname VARCHAR(64), rname VARCHAR(64), rtype VARCHAR(9))
RETURNS VARCHAR(3)
DETERMINISTIC
COMMENT 'Internal function to return whether a routine is deterministic.'
BEGIN
  DECLARE ret VARCHAR(3);

  SELECT `is_deterministic` INTO ret
  FROM `information_schema`.`routines`
  WHERE `routine_schema` = sname
  AND `routine_name` = rname
  AND `routine_type` = rtype;

  RETURN COALESCE(ret, NULL);
END //

-- routine_is_deterministic(schema, name, type, val, description)
DROP FUNCTION IF EXISTS routine_is_deterministic //
CREATE FUNCTION routine_is_deterministic(sname VARCHAR(64), rname VARCHAR(64), rtype VARCHAR(9), val VARCHAR(3), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Check that a routine is deterministic.'
BEGIN
  IF description = '' THEN
    SET description = CONCAT(rtype, ' ', quote_ident(sname), '.', quote_ident(rname),
      ' should have IS_DETERMINISTIC ', quote_ident(val));
  END IF;

  IF val NOT IN('YES','NO') THEN
    RETURN CONCAT(ok(FALSE, description),'\n',
      diag('Is Deterministic must be { YES | NO }'));
  END IF;

  IF NOT _has_routine(sname, rname, rtype) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT(ucf(rtype), ' ', quote_ident(sname), '.', quote_ident(rname),
        ' does not exist')));
  END IF;

  RETURN eq(_routine_is_deterministic(sname, rname, rtype), val, description);
END //

DROP FUNCTION IF EXISTS function_is_deterministic //
CREATE FUNCTION function_is_deterministic(sname VARCHAR(64), rname VARCHAR(64), val VARCHAR(3), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Check that a function is deterministic.'
BEGIN
  RETURN routine_is_deterministic(sname, rname, 'Function', val, description);
END //

DROP FUNCTION IF EXISTS procedure_is_deterministic //
CREATE FUNCTION procedure_is_deterministic(sname VARCHAR(64), rname VARCHAR(64), val VARCHAR(3), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Check that a procedure is deterministic.'
BEGIN
  RETURN routine_is_deterministic(sname, rname, 'Procedure', val, description);
END //



/****************************************************************************/

-- SECURITY TYPE
-- { INVOKER | DEFINER }

-- _routine_security_type(schema, routine, security_type, description)
DROP FUNCTION IF EXISTS _routine_security_type //
CREATE FUNCTION _routine_security_type(sname VARCHAR(64), rname VARCHAR(64), rtype VARCHAR(9))
RETURNS VARCHAR(7)
DETERMINISTIC
COMMENT 'Internal function to return the security type of a routine.'
BEGIN
  DECLARE ret VARCHAR(7);

  SELECT `security_type` INTO ret
  FROM `information_schema`.`routines`
  WHERE `routine_schema` = sname
  AND `routine_name` = rname
  AND `routine_type` = rtype ;

  RETURN COALESCE(ret, NULL);
END //


-- routine_security_type_is(schema, name, type, security type , description)
DROP FUNCTION IF EXISTS routine_security_type_is //
CREATE FUNCTION routine_security_type_is(sname VARCHAR(64), rname VARCHAR(64), rtype VARCHAR(9), stype VARCHAR(7), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Confirm the security type of a routine matches the value provided.'
BEGIN
  IF description = '' THEN
    SET description = CONCAT(rtype, ' ', quote_ident(sname), '.', quote_ident(rname),
      ' should have Security Type ' , quote_ident(stype));
  END IF;

  IF stype NOT IN('INVOKER','DEFINER') THEN
    RETURN CONCAT(ok(FALSE, description),'\n',
      diag('Security Type must be { INVOKER | DEFINER }'));
  END IF;

  IF NOT _has_routine(sname, rname, rtype) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT(ucf(rtype), ' ', quote_ident(sname), '.', quote_ident(rname), ' does not exist')));
  END IF;

  RETURN eq(_routine_security_type(sname, rname, rtype), stype, description);
END //


DROP FUNCTION IF EXISTS function_security_type_is //
CREATE FUNCTION function_security_type_is(sname VARCHAR(64), rname VARCHAR(64), stype VARCHAR(7), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Confirm the security type of a function matches the value provided.'
BEGIN
  RETURN routine_security_type_is(sname, rname, 'Function', stype, description);
END //

DROP FUNCTION IF EXISTS procedure_security_type_is //
CREATE FUNCTION procedure_security_type_is(sname VARCHAR(64), rname VARCHAR(64), stype VARCHAR(7), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Confirm the security type of a procedure matches the value provided.'
BEGIN
  RETURN routine_security_type_is(sname, rname, 'Procedure', stype, description);
END //


/****************************************************************************/

-- SQL_DATA_ACCESS
-- { CONTAINS SQL | NO SQL | READS SQL DATA | MODIFIES SQL DATA }

-- _routine_sql_data_access(schema, routine, type, description)
DROP FUNCTION IF EXISTS _routine_sql_data_access  //
CREATE FUNCTION _routine_sql_data_access(sname VARCHAR(64), rname VARCHAR(64), rtype VARCHAR(9))
RETURNS VARCHAR(64)
DETERMINISTIC
COMMENT 'Internal function to return the SQL data access value for a named routine within the given schema.'
BEGIN
  DECLARE ret VARCHAR(64);

  SELECT `sql_data_access` INTO ret
  FROM `information_schema`.`routines`
  WHERE `routine_schema` = sname
  AND `routine_name` = rname
  AND `routine_type` = rtype ;

  RETURN COALESCE(ret, NULL);
END //


-- function_sql_data_access_is(schema, function, sql data access , description)
DROP FUNCTION IF EXISTS routine_sql_data_access_is //
CREATE FUNCTION routine_sql_data_access_is(sname VARCHAR(64), rname VARCHAR(64), rtype VARCHAR(9), sda VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Confirm the SQL data access value of a routine matches that provided.'
BEGIN
  IF description = '' THEN
    SET description = CONCAT(rtype ,' ', quote_ident(sname), '.', quote_ident(rname),
      ' should have SQL Data Access ', quote_ident(sda));
  END IF;

  IF NOT rtype IN('FUNCTION','PROCEDURE') THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag('Routine Type must be { FUNCTION | PROCEDURE }'));
  END IF;

  IF NOT sda IN('CONTAINS SQL','NO SQL','READS SQL DATA','MODIFIES SQL DATA') THEN
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag('SQL Data Access must be { CONTAINS SQL | NO SQL | READS SQL DATA | MODIFIES SQL DATA }'));
  END IF;

  IF NOT _has_routine(sname, rname, rtype) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT(ucf(rtype), ' ', quote_ident(sname), '.', quote_ident(rname), ' does not exist')));
  END IF;

  RETURN eq(_routine_sql_data_access(sname, rname, rtype), sda, description);
END //

DROP FUNCTION IF EXISTS function_sql_data_access_is //
CREATE FUNCTION function_sql_data_access_is(sname VARCHAR(64), rname VARCHAR(64), sda VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Confirm the SQL data access value of a function matches that provided.'
BEGIN
  RETURN routine_sql_data_access_is(sname, rname, 'Function', sda, description);
END //

DROP FUNCTION IF EXISTS procedure_sql_data_access_is //
CREATE FUNCTION procedure_sql_data_access_is(sname VARCHAR(64), rname VARCHAR(64), sda VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Confirm the SQL data access value of a procedure matches that provided.'
BEGIN
  RETURN routine_sql_data_access_is(sname, rname, 'Procedure', sda, description);
END //


/*******************************************************************/
-- Check that the proper routines are defined

DROP FUNCTION IF EXISTS routines_are //
CREATE FUNCTION routines_are(sname VARCHAR(64), rtype VARCHAR(9), want TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  SET @want = want;
  SET @have = (SELECT GROUP_CONCAT('`',routine_name,'`')
               FROM `information_schema`.`routines`
	       WHERE `routine_schema` = sname
	       AND `routine_type` = rtype);

  IF description = '' THEN
    SET description = CONCAT('Schema ', quote_ident(sname),
      ' should have the correct ', LOWER(rtype), 's');
  END IF;

  IF NOT _has_schema(sname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Schema ', quote_ident(sname), ' does not exist')));
  END IF;

  CALL _populate_want(@want);
  CALL _populate_have(@have);

  SET @missing = (SELECT _missing(@have)); 
  SET @extras  = (SELECT _extra(@want));

  RETURN _are(CONCAT(rtype, 's'), @extras, @missing, description);

END //


/****************************************************************************/

-- SQL_MODE
-- Checks to ensure appropriate sql mode is available for a function or procedure

-- _routine_has_sql_mode(schema, routine, mode)
DROP FUNCTION IF EXISTS _routine_has_sql_mode  //
CREATE FUNCTION _routine_has_sql_mode(sname VARCHAR(64), rname VARCHAR(64), rtype VARCHAR(9), smode VARCHAR(8192))
RETURNS BOOLEAN
DETERMINISTIC
COMMENT 'Internal function to return the SQL mode which will apply to a routine.'
BEGIN
  DECLARE ret BOOLEAN;

  SELECT LOCATE(smode, `sql_mode`) INTO ret
  FROM `information_schema`.`routines`
  WHERE `routine_schema` = sname
  AND `routine_name` = rname
  AND `routine_type` = rtype;

  RETURN COALESCE(ret, 0);
END //


-- routine_has_sql_mode(schema, name, type, sql_mode , description)
DROP FUNCTION IF EXISTS routine_has_sql_mode //
CREATE FUNCTION routine_has_sql_mode(sname VARCHAR(64), rname VARCHAR(64), rtype VARCHAR(64), smode VARCHAR(8192), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Check that a particular SQL mode will apply to a named routine within the given schema.'
BEGIN

  -- this 5.7 list of sql_modes
  -- should be fine as a test provide it is superset of previous modes
  -- we're only interesed in the name rather than what it does (which does change)
  DECLARE valid ENUM('REAL_AS_FLOAT','PIPES_AS_CONCAT','ANSI_QUOTES','IGNORE_SPACE',
      'NOT_USED','ONLY_FULL_GROUP_BY','NO_UNSIGNED_SUBTRACTION','NO_DIR_IN_CREATE',
      'POSTGRESQL','ORACLE','MSSQL','DB2','MAXDB','NO_KEY_OPTIONS','NO_TABLE_OPTIONS',
      'NO_FIELD_OPTIONS','MYSQL323','MYSQL40','ANSI','NO_AUTO_VALUE_ON_ZERO','NO_BACKSLASH_ESCAPES',
      'STRICT_TRANS_TABLES','STRICT_ALL_TABLES','NO_ZERO_IN_DATE','NO_ZERO_DATE','INVALID_DATES',
      'ERROR_FOR_DIVISION_BY_ZERO','TRADITIONAL','NO_AUTO_CREATE_USER','HIGH_NOT_PRECEDENCE',
      'NO_ENGINE_SUBSTITUTION','PAD_CHAR_TO_FULL_LENGTH');

  DECLARE EXIT HANDLER FOR 1265 -- invalid assignment to enum
    RETURN CONCAT(ok(FALSE,description), '\n',
      diag(CONCAT('SQL Mode ', quote_ident(smode), ' is invalid')));

  IF description = '' THEN
    SET description = CONCAT(UPPER(rtype), ' ', quote_ident(sname), '.', quote_ident(rname),
      ' requires SQL Mode ', quote_ident(smode));
  END IF;

  SET valid = smode;

  IF NOT _has_routine(sname, rname, 'FUNCTION') THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT(UPPER(rtype),' ', quote_ident(sname), '.', quote_ident(rname), ' does not exist')));
  END IF;

  RETURN ok(_routine_has_sql_mode(sname, rname, rtype, smode), description);
END //


/****************************************************************************/
-- ROUTINE BODY
-- Get the SHA-1 of the routine body to compare for changes
-- allows match against partial value to save typing
-- You can run _routine_sha1 to get the SHA-1, how much of it is used is down to
-- the individual, we can probably ignore the likelihood of collisions.

DROP FUNCTION IF EXISTS _routine_sha1 //
CREATE FUNCTION _routine_sha1(sname VARCHAR(64), rname VARCHAR(64), rtype VARCHAR(9))
RETURNS CHAR(40)
DETERMINISTIC
COMMENT 'Internal function to return a SHA1 of the routine body to check for changes over time. This should be easier to maintain than dumping the routine body into the test script.'
BEGIN
  DECLARE ret CHAR(40);

  SELECT SHA1(`routine_definition`) INTO ret
  FROM `information_schema`.`routines`
  WHERE `routine_schema` = sname
  AND `routine_name` = rname;

  RETURN COALESCE(ret, NULL);
END //

DROP FUNCTION IF EXISTS routine_sha1_is //
CREATE FUNCTION routine_sha1_is(sname VARCHAR(64), rname VARCHAR(64), rtype VARCHAR(9), sha1 VARCHAR(40), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Get the SHA1 value of a routine body to compare against a previous value.'
BEGIN
  IF description = '' THEN
    SET description = CONCAT(ucf(rtype), ' ', quote_ident(sname), '.', quote_ident(rname),
      ' definition should match expected value');
  END IF;

  IF NOT _has_routine(sname, rname, rtype) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT(ucf(rtype), ' ', quote_ident(sname), '.', quote_ident(rname), ' does not exist')));
  END IF;

  -- NB length of supplied value not of a SHA-1
  RETURN eq(LEFT(_routine_sha1(sname, rname, rtype), LENGTH(sha1)), sha1, description);
END //


DELIMITER ;

SET @@SESSION.sql_mode = @mode;
