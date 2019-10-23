/*
Test user and role privileges

We are not so much interested in whether a given user can access a particular
object but rather in whether a privilege has been defined for a user. We also
allow for the cascade of privileges from global to columns. Users can,
also gain access via roles and proxies, these can be tested separately.
*/

USE tap;

/*****************************************************************************************/
-- Check that the pytpe is valid for the test
-- There are different privileges that operate at the various object levels

DELIMITER //
DROP FUNCTION IF EXISTS _global_privs //
CREATE FUNCTION _global_privs(ptype VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  RETURN FIND_IN_SET(ptype,
  'ALTER,ALTER ROUTINE,CREATE,CREATE ROUTINE,CREATE TABLESPACE,CREATE TEMPORARY TABLES,CREATE USER,CREATE VIEW,DELETE,DROP,EVENT,EXECUTE,FILE,GRANT,INDEX,INSERT,LOCK TABLES,PROCESS,REFERENCES,RELOAD,REPLICATION CLIENT,REPLICATION SLAVE,SELECT,SHOW DATABASES,SHOW VIEW,SHUTDOWN,SUPER,TRIGGER,UPDATE,USAGE');
END //

DROP FUNCTION IF EXISTS _schema_privs //
CREATE FUNCTION _schema_privs(ptype VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  RETURN FIND_IN_SET(ptype,
    'ALTER,ALTER ROUTINE,CREATE,CREATE ROUTINE,CREATE TEMPORARY TABLES,CREATE VIEW,DELETE,DROP,EVENT,EXECUTE,GRANT,INDEX,INSERT,LOCK TABLES,REFERENCES,SELECT,SHOW VIEW,TRIGGER,UPDATE'); 
END //


DROP FUNCTION IF EXISTS _table_privs //
CREATE FUNCTION _table_privs(ptype VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  RETURN FIND_IN_SET(ptype,
    'ALTER,CREATE,CREATE VIEW,DELETE,DROP,GRANT,INDEX,INSERT,REFERENCES,SELECT,SHOW VIEW,TRIGGER,UPDATE'); 
END //


DROP FUNCTION IF EXISTS _column_privs //
CREATE FUNCTION _column_privs(ptype VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  RETURN FIND_IN_SET(ptype, 'INSERT,REFERENCES,SELECT,UPDATE');
END //


-- NB CREATE ROUTINE will never appear in procs_priv, only in user and schema level privs
-- but it's needed here to identify those values. 
DROP FUNCTION IF EXISTS _routine_privs //
CREATE FUNCTION _routine_privs(ptype VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  RETURN FIND_IN_SET(ptype, 'ALTER ROUTINE,CREATE ROUTINE,EXECUTE,GRANT');
END //


/***********************************************************************************/
-- has_privilege 
-- This is irrespective of level, does the priv exist in any context

DROP FUNCTION IF EXISTS _has_priv //
CREATE FUNCTION _has_priv(gtee VARCHAR(81), ptype VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE rtn INT;
  SELECT SUM(priv) INTO rtn
  FROM
  ( 
    SELECT 1 AS priv
    FROM `information_schema`.`user_privileges`
    WHERE `grantee` = gtee
    AND `privilege_type` = ptype
  UNION ALL
    SELECT 1 AS priv
    FROM `information_schema`.`schema_privileges`
    WHERE `grantee` = gtee
    AND `privilege_type` = ptype
  UNION ALL
    SELECT 1 AS priv
    FROM `information_schema`.`table_privileges`
    WHERE `grantee` = gtee
    AND `privilege_type` = ptype
  UNION ALL
    SELECT 1 AS priv
    FROM `information_schema`.`column_privileges`
    WHERE `grantee` = gtee
    AND `privilege_type` = ptype
  ) a;

  RETURN IF(rtn > 0, 1, 0);
END //


DROP FUNCTION IF EXISTS has_privilege //
CREATE FUNCTION has_privilege(gtee VARCHAR(81), ptype VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  -- normalize the input
  SET @gtee = _format_user(gtee);

  IF description = '' THEN
    SET description = CONCAT('Account ', gtee, ' should have privilege ''', ptype, '''');
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description),'\n',
      diag (CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  RETURN ok(_has_priv(@gtee, ptype), description);
END //


DROP FUNCTION IF EXISTS hasnt_privilege //
CREATE FUNCTION hasnt_privilege(gtee VARCHAR(81), ptype VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  -- normalize the input
  SET @gtee = _format_user(gtee);

  IF description = '' THEN
    SET description = concat('Account ', gtee, ' should not have privilege ''', ptype, '''');
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  RETURN ok(NOT _has_priv(@gtee, ptype), description);
END //

/***********************************************************************************/

DROP FUNCTION IF EXISTS _has_global_priv //
CREATE FUNCTION _has_global_priv(gtee VARCHAR(81), ptype VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE rtn INT DEFAULT 0;

  SELECT 1 INTO rtn
  FROM `information_schema`.`user_privileges`
  WHERE `grantee` = gtee
  AND `privilege_type` = ptype;

  RETURN rtn;
END //


DROP FUNCTION IF EXISTS has_global_privilege //
CREATE FUNCTION has_global_privilege(gtee VARCHAR(81), ptype VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  -- normalize the input
  SET @gtee = _format_user(gtee);

  IF description = '' THEN
    SET description = concat('Account ', gtee, ' should have global privilege ''', ptype, '''');
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  IF NOT _global_privs(ptype) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Privilege ''', ptype, ''' is not a valid global privilege type')));
  END IF;

  RETURN ok(_has_global_priv(@gtee, ptype), description);
END //


DROP FUNCTION IF EXISTS hasnt_global_privilege //
CREATE FUNCTION hasnt_global_privilege(gtee VARCHAR(81), ptype VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  -- normalize the input
  SET @gtee = _format_user(gtee);

  IF description = '' THEN
    SET description = concat('Account ', gtee, ' should not have global privilege ''', ptype, '''');
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  IF NOT _global_privs(ptype) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Privilege ''', ptype, ''' is not a valid global privilege type')));
  END IF;

  RETURN ok(NOT _has_global_priv(@gtee, ptype), description);
END //


/***********************************************************************************/

DROP FUNCTION IF EXISTS _has_schema_priv //
CREATE FUNCTION _has_schema_priv(sname VARCHAR(64), gtee VARCHAR(81), ptype VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE rtn INT;

  IF @rollup = 1 THEN
    SELECT SUM(priv) INTO rtn
    FROM
    (
      SELECT 1 AS priv
      FROM `information_schema`.`user_privileges`
      WHERE `grantee` = gtee
      AND `privilege_type` = ptype
    UNION ALL
      SELECT 1 AS priv
      FROM `information_schema`.`schema_privileges`
      WHERE `grantee` = gtee
      AND `privilege_type` = ptype
      AND `table_schema` = sname
    ) a;
  ELSE
    SELECT 1 INTO rtn
    FROM `information_schema`.`schema_privileges`
    WHERE `grantee` = gtee
    AND `privilege_type` = ptype
    AND `table_schema` = sname;
  END IF;

  RETURN IF(rtn > 0, 1, 0);
END //


DROP FUNCTION IF EXISTS has_schema_privilege //
CREATE FUNCTION has_schema_privilege(sname VARCHAR(64), gtee VARCHAR(81), ptype VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  -- normalize the input
  SET @gtee = _format_user(gtee);

  IF description = '' THEN
    SET description = concat('Account ', gtee, ' should have schema privilege ''', ptype, '''');
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  IF NOT _has_schema(sname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Schema ', sname, ' does not exist')));
  END IF;

  IF NOT _schema_privs(ptype) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Privilege ''', ptype, ''' is not a valid schema privilege type')));
  END IF;

  RETURN ok(_has_schema_priv(sname, @gtee, ptype), description);
END //


DROP FUNCTION IF EXISTS hasnt_schema_privilege //
CREATE FUNCTION hasnt_schema_privilege(sname VARCHAR(64), gtee VARCHAR(81), ptype VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  -- normalize the input
  SET @gtee = _format_user(gtee);

  IF description = '' THEN
    SET description = concat('Account ', gtee, ' should not have schema privilege ''', ptype, '''');
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  IF NOT _has_schema(sname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Schema ', sname, ' does not exist')));
  END IF;

  IF NOT _schema_privs(ptype) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Privilege ''', ptype, ''' is not a valid schema privilege type')));
  END IF;

  RETURN ok(NOT _has_schema_priv(sname, @gtee, ptype), description);
END //


/***********************************************************************************/

DROP FUNCTION IF EXISTS _has_table_priv //
CREATE FUNCTION _has_table_priv(sname VARCHAR(64), tname VARCHAR(64), gtee VARCHAR(81), ptype VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE rtn INT;

  IF @rollup = 1 THEN
    SELECT SUM(priv) INTO rtn
    FROM
    (
      SELECT 1 AS priv
      FROM `information_schema`.`user_privileges`
      WHERE `grantee` = gtee
      AND `privilege_type` = ptype
    UNION ALL
      SELECT 1 AS priv
      FROM `information_schema`.`schema_privileges`
      WHERE `grantee` = gtee
      AND `privilege_type` = ptype
      AND `table_schema` = sname
    UNION ALL
      SELECT 1 AS priv
      FROM `information_schema`.`table_privileges`
      WHERE `grantee` = gtee
      AND `privilege_type` = ptype
      AND `table_schema` = sname
      AND `table_name` = tname
     ) a;
  ELSE
    SELECT 1 INTO rtn
    FROM `information_schema`.`table_privileges`
    WHERE `grantee` = gtee
    AND `privilege_type` = ptype
    AND `table_schema` = sname
    AND `table_name` = tname;
  END IF;
  
  RETURN IF(rtn > 0, 1, 0);
END //


DROP FUNCTION IF EXISTS has_table_privilege //
CREATE FUNCTION has_table_privilege(sname VARCHAR(64), tname VARCHAR(64), gtee VARCHAR(81), ptype VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  -- normalize the input
  SET @gtee = _format_user(gtee);

  IF description = '' THEN
    SET description = concat('Account ', gtee, ' should have table privilege ''', ptype, '''');
  END IF;

  IF NOT _has_table(sname,tname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table `', sname, '`.`', tname, '` does not exist')));
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  IF NOT _table_privs(ptype) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Privilege ''', ptype, ''' is not a valid table privilege type')));
  END IF;

  RETURN ok(_has_table_priv(sname, tname, @gtee, ptype), description);
END //


DROP FUNCTION IF EXISTS hasnt_table_privilege //
CREATE FUNCTION hasnt_table_privilege(sname VARCHAR(64), tname VARCHAR(64), gtee VARCHAR(81), ptype VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  -- normalize the input
  SET @gtee = _format_user(gtee);

  IF description = '' THEN
    SET description = concat('Account ', gtee, ' should not have table privilege ''', ptype, '''');
  END IF;

  IF NOT _has_table(sname,tname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table `', sname, '`.`', tname, '` does not exist')));
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  IF NOT _table_privs(ptype) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Privilege ''', ptype, ''' is not a valid table privilege type')));
  END IF;

  RETURN ok(NOT _has_table_priv(sname, tname, @gtee, ptype), description);
END //


/***********************************************************************************/

DROP FUNCTION IF EXISTS _has_column_priv //
CREATE FUNCTION _has_column_priv(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), gtee VARCHAR(81), ptype VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE rtn INT;

  IF @rollup = 1 THEN
    SELECT SUM(priv) INTO rtn
    FROM
    (
      SELECT 1 AS priv
      FROM `information_schema`.`user_privileges`
      WHERE `grantee` = gtee
      AND `privilege_type` = ptype
    UNION ALL
      SELECT 1 AS priv
      FROM `information_schema`.`schema_privileges`
      WHERE `grantee` = gtee
      AND `privilege_type` = ptype
      AND `table_schema` = sname
   UNION ALL
     SELECT 1 AS priv
     FROM `information_schema`.`table_privileges`
     WHERE `grantee` = gtee
     AND `privilege_type` = ptype
     AND `table_schema` = sname
     AND `table_name` = tname
   UNION ALL
     SELECT 1 AS priv
     FROM `information_schema`.`column_privileges`
     WHERE `grantee` = gtee
     AND `privilege_type` = ptype
     AND `table_schema` = sname
     AND `table_name` = tname
     AND `column_name` = cname
   ) a;
  ELSE
    SELECT 1 INTO rtn
    FROM `information_schema`.`column_privileges`
    WHERE `grantee` = gtee
    AND `privilege_type` = ptype
    AND `table_schema` = sname
    AND `table_name` = tname
    AND `column_name` = cname;
  END IF;

  RETURN IF(rtn > 0, 1, 0);
END //


DROP FUNCTION IF EXISTS has_column_privilege //
CREATE FUNCTION has_column_privilege(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), gtee VARCHAR(81), ptype VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  -- normalize the input
  SET @gtee = _format_user(gtee);

  IF description = '' THEN
    SET description = concat('Account ', gtee, ' should have column privilege ''', ptype, '''');
  END IF;

  IF NOT _has_column(sname,tname,cname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Column `', tname, '`.`', cname, '` does not exist')));
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  IF NOT _column_privs(ptype) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Privilege ''', ptype, ''' is not a valid column privilege type')));
  END IF;

  RETURN ok(_has_column_priv(sname, tname, cname, @gtee, ptype), description);
END //


DROP FUNCTION IF EXISTS hasnt_column_privilege //
CREATE FUNCTION hasnt_column_privilege(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), gtee VARCHAR(81), ptype VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  -- normalize the input
  SET @gtee = _format_user(gtee);

  IF description = '' THEN
    SET description = concat('Account ', gtee,
       ' should not have column privilege ''', ptype, '''');
  END IF;

  IF NOT _has_column(sname,tname,cname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Column `', tname, '`.`', cname, '` does not exist')));
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  IF NOT _column_privs(ptype) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Privilege ''', ptype, ''' is not a valid column privilege type')));
  END IF;

  RETURN ok(NOT _has_column_priv(sname, tname, cname, @gtee, ptype), description);
END //



/****************************************************************************/
-- *_privileges_are
-- Tests that accounts and roles have the appropriate privileges and
-- only those privileges.

-- The way I have coded this takes in to consideration those privileges that
-- are suitable to the level being tested (e.g. table) but which may be defined
-- at a higher level (e.g. global or schema). The effect of the privileges
-- defined at the higher levels, cascades to the lower levels, so a SELECT
-- granted to a user at the global level will imply a SELECT privilege all
-- the way down to column level
-- require _missing, _extra, _populate functions defined in mytap.sql
/****************************************************************************/

DROP FUNCTION IF EXISTS _global_privileges //
CREATE FUNCTION _global_privileges(gtee VARCHAR(81))
RETURNS TEXT
DETERMINISTIC
BEGIN
   DECLARE rtn TEXT;
   SELECT GROUP_CONCAT(`privilege_type`) INTO rtn
   FROM `information_schema`.`user_privileges`
   WHERE `grantee` = gtee;

   RETURN rtn;
END //


DROP FUNCTION IF EXISTS global_privileges_are //
CREATE FUNCTION global_privileges_are(gtee VARCHAR(81), ptypes TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
 
  SET @gtee = _format_user(gtee);
  SET @want = ptypes;
  SET @have = _global_privileges(@gtee);

  IF description = '' THEN
    SET description = CONCAT('Account ', gtee, ' should have the correct global privileges');
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  CALL _populate_want(@want);
  CALL _populate_have(@have);

  SET @missing = (SELECT _missing(@have)); 
  SET @extras  = (SELECT _extra(@want));

  RETURN _are('Global Privileges', @extras, @missing, description);

END //


/***********************************************************************************/

DROP FUNCTION IF EXISTS _schema_privileges //
CREATE FUNCTION _schema_privileges(sname VARCHAR(64), gtee VARCHAR(81))
RETURNS TEXT
DETERMINISTIC
BEGIN
   DECLARE rtn TEXT;
   
   IF @rollup = 1 THEN
     SELECT GROUP_CONCAT(`privilege_type`) INTO rtn
     FROM
     ( SELECT `privilege_type`
       FROM `information_schema`.`user_privileges`
       WHERE `grantee` = gtee AND _schema_privs(`privilege_type`) > 0 
     UNION -- will make results distinct
       SELECT `privilege_type`
       FROM `information_schema`.`schema_privileges`
       WHERE `grantee` = gtee AND `table_schema` = sname
     ) u;
   ELSE
     SELECT GROUP_CONCAT(`privilege_type`) INTO rtn
     FROM `information_schema`.`schema_privileges`
     WHERE `grantee` = gtee AND `table_schema` = sname;
   END IF;
   
   RETURN rtn;
END //


DROP FUNCTION IF EXISTS schema_privileges_are //
CREATE FUNCTION schema_privileges_are(sname VARCHAR(64), gtee VARCHAR(81), ptypes TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
 
  SET @gtee = _format_user(gtee);
  SET @want = ptypes;
  SET @have = _schema_privileges(sname, @gtee);

  IF description = '' THEN
    SET description = CONCAT('Account ', gtee, ' should have the correct schema privileges');
  END IF;

  IF NOT _has_schema(sname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Schema ', sname, ' does not exist')));
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  -- todo diagnostic does the expected list only contain schema level privs

  CALL _populate_want(@want);
  CALL _populate_have(@have);

  SET @missing = (SELECT _missing(@have)); 
  SET @extras  = (SELECT _extra(@want));

  RETURN _are('Schema Privileges', @extras, @missing, description);

END //


/***********************************************************************************/
-- table level privileges for an account

DROP FUNCTION IF EXISTS _table_privileges //
CREATE FUNCTION _table_privileges(sname VARCHAR(64), tname VARCHAR(64), gtee VARCHAR(81))
RETURNS TEXT
DETERMINISTIC
BEGIN
  DECLARE rtn TEXT;
   
  IF @rollup = 1 THEN    
    SELECT GROUP_CONCAT(`privilege_type`) INTO rtn
    FROM
     ( SELECT `privilege_type`
       FROM `information_schema`.`user_privileges`
       WHERE `grantee` = gtee AND _table_privs(`privilege_type`) > 0 
     UNION -- will make results distinct
       SELECT `privilege_type`
       FROM `information_schema`.`schema_privileges`
       WHERE `grantee` = gtee AND `table_schema` = sname AND _table_privs (`privilege_type`) > 0
     UNION
       SELECT `privilege_type`
       FROM `information_schema`.`table_privileges`
       WHERE `grantee` = gtee AND `table_schema` = sname AND `table_name` = tname
     ) u;
  ELSE
    SELECT GROUP_CONCAT(`privilege_type`) INTO rtn
    FROM `information_schema`.`table_privileges`
    WHERE `grantee` = gtee AND `table_schema` = sname AND `table_name` = tname;
  END IF;
  
  RETURN rtn;
END //


DROP FUNCTION IF EXISTS table_privileges_are //
CREATE FUNCTION table_privileges_are(sname VARCHAR(64), tname VARCHAR(64), gtee VARCHAR(81), ptypes TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
 
  SET @gtee = _format_user(gtee);
  SET @want = ptypes;
  SET @have = _table_privileges(sname, tname, @gtee);

  IF description = '' THEN
    SET description = CONCAT('Account ', gtee, ' should have the correct table privileges');
  END IF;

  IF NOT _has_table(sname, tname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table `', sname,'`.`', tname, '` does not exist')));
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  -- todo diagnostic, does the expected list only contain table level privs

  CALL _populate_want(@want);
  CALL _populate_have(@have);

  SET @missing = (SELECT _missing(@have)); 
  SET @extras  = (SELECT _extra(@want));

  RETURN _are('Table Privileges', @extras, @missing, description);

END //


/***********************************************************************************/
-- column level privileges for an account

DROP FUNCTION IF EXISTS _column_privileges //
CREATE FUNCTION _column_privileges(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), gtee VARCHAR(81))
RETURNS TEXT
DETERMINISTIC
BEGIN
  DECLARE rtn TEXT;
   
  IF @rollup = 1 THEN
    SELECT GROUP_CONCAT(`privilege_type`) INTO rtn
    FROM
      ( SELECT `privilege_type`
        FROM `information_schema`.`user_privileges`
        WHERE `grantee` = gtee AND _column_privs(`privilege_type`) > 0 
      UNION
        SELECT `privilege_type`
        FROM `information_schema`.`schema_privileges`
        WHERE `grantee` = gtee AND `table_schema` = sname AND _column_privs (`privilege_type`) > 0
      UNION
        SELECT `privilege_type`
        FROM `information_schema`.`table_privileges`
        WHERE `grantee` = gtee AND `table_schema` = sname AND `table_name` = tname AND _column_privs (`privilege_type`) > 0
      UNION
        SELECT `privilege_type`
        FROM `information_schema`.`column_privileges`
        WHERE `grantee` = gtee AND `table_schema` = sname AND `table_name` = tname AND `column_name` = cname
      ) u;
   ELSE
     SELECT GROUP_CONCAT(`privilege_type`) INTO rtn
     FROM `information_schema`.`column_privileges`
     WHERE `grantee` = gtee AND `table_schema` = sname AND `table_name` = tname AND `column_name` = cname;
  END IF;

  RETURN rtn;
END //


DROP FUNCTION IF EXISTS column_privileges_are //
CREATE FUNCTION column_privileges_are(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), gtee VARCHAR(81), ptypes TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
 
  SET @gtee = _format_user(gtee);
  SET @want = ptypes;
  SET @have = _column_privileges(sname, tname, cname, @gtee);

  IF description = '' THEN
    SET description = CONCAT('Account ', gtee, ' should have the correct column privileges');
  END IF;

  IF NOT _has_column(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Column `', tname,'`.`', cname, '` does not exist')));
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  -- todo diagnostic, does the expected list only contain table level privs

  CALL _populate_want(@want);
  CALL _populate_have(@have);

  SET @missing = (SELECT _missing(@have)); 
  SET @extras  = (SELECT _extra(@want));

  RETURN _are('Column Privileges', @extras, @missing, description);

END //


/***********************************************************************************/
-- As of v8, no informtion schema equivalent of procs_priv
-- so this is based on mysql.procs_priv which doesn't have the same structure
-- as the info_schema tables

-- use view to simulate privilege table
-- NB 5.5 friendly views cannot have sub-selects in the from clause hence long-winded
-- aliasing for all parts of the UNION

DROP VIEW IF EXISTS tap.proc_privileges //

CREATE VIEW `tap`.`proc_privileges` AS
SELECT CONCAT('''',`user`,'''@''',`host`,'''') AS `GRANTEE`, `db` AS `ROUTINE_SCHEMA`, `ROUTINE_NAME`, `ROUTINE_TYPE`, 'EXECUTE' AS `PRIVILEGE_TYPE`
FROM `mysql`.`procs_priv`
WHERE FIND_IN_SET('EXECUTE', `Proc_priv`) > 0
UNION
SELECT CONCAT('''',`user`,'''@''',`host`,'''') AS `GRANTEE`, `db` AS `ROUTINE_SCHEMA`, `ROUTINE_NAME`, `ROUTINE_TYPE`,'ALTER ROUTINE' AS `PRIVILEGE_TYPE`
FROM `mysql`.`procs_priv`
WHERE FIND_IN_SET('ALTER ROUTINE', `Proc_priv`) > 0
UNION
SELECT CONCAT('''',`user`,'''@''',`host`,'''') AS `GRANTEE`, `db` AS `ROUTINE_SCHEMA`, `ROUTINE_NAME`, `ROUTINE_TYPE`, 'GRANT' AS `PRIVILEGE_TYPE`
FROM `mysql`.`procs_priv`
WHERE FIND_IN_SET('GRANT', `Proc_priv`) > 0;


DROP FUNCTION IF EXISTS _routine_privileges //
CREATE FUNCTION _routine_privileges(sname VARCHAR(64), rtype VARCHAR(9), rname VARCHAR(64), gtee VARCHAR(81))
RETURNS TEXT
DETERMINISTIC
BEGIN
  DECLARE rtn TEXT;

  IF @rollup = 1 THEN
  SELECT GROUP_CONCAT(`privilege_type`) INTO rtn
  FROM
    ( SELECT `privilege_type`
      FROM `information_schema`.`user_privileges`
      WHERE `grantee` = gtee AND _routine_privs(`privilege_type`) > 0   
    UNION
      SELECT `privilege_type`
      FROM `information_schema`.`schema_privileges`
      WHERE `table_schema` = sname AND `grantee` = gtee AND _routine_privs(`privilege_type`) > 0
    UNION
      SELECT `privilege_type`
      FROM `tap`.`proc_privileges`
      WHERE `routine_schema` = sname AND `routine_name` = rname AND `routine_type` = rtype AND `grantee` = gtee
    ) u;
  ELSE
    SELECT GROUP_CONCAT(`privilege_type`) INTO rtn
    FROM `tap`.`proc_privileges`
    WHERE `routine_schema` = sname AND `routine_name` = rname AND `routine_type` = rtype AND `grantee` = gtee;
  END IF;  

  RETURN rtn;
END //


DROP FUNCTION IF EXISTS routine_privileges_are //
CREATE FUNCTION routine_privileges_are(sname VARCHAR(64), rtype VARCHAR(9), rname VARCHAR(64), gtee VARCHAR(81), ptypes TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
 
  SET @gtee = _format_user(gtee);
  SET @want = ptypes;
  SET @have = _routine_privileges(sname, rtype, rname, @gtee);

  IF description = '' THEN
    SET description = CONCAT('Account ', gtee, ' should have the correct routine privileges');
  END IF;

  IF NOT _has_routine(sname, rname, rtype) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT(rtype, ' `', sname, '`.`', rname, '` does not exist')));
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  -- todo diagnostic does the expected list only contain routine level privs

  CALL _populate_want(@want);
  CALL _populate_have(@have);

  SET @missing = (SELECT _missing(@have)); 
  SET @extras  = (SELECT _extra(@want));

  RETURN _are('Routine Privileges', @extras, @missing, description);

END //


/***********************************************************************************/
DROP FUNCTION IF EXISTS _single_table_priv //
CREATE FUNCTION _single_table_priv(sname VARCHAR(64), tname VARCHAR(64), gtee VARCHAR(81))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE rtn INT;

  SELECT COUNT(DISTINCT `table_name`) INTO rtn
  FROM `information_schema`.`table_privileges`
  WHERE `grantee` = gtee
  AND `table_schema` = sname
  AND `table_name` = tname
  AND NOT EXISTS (
    SELECT *
    FROM `information_schema`.`table_privileges`
    WHERE `grantee` = gtee
    AND `table_name` != tname
  )
  AND NOT EXISTS (
    SELECT *
    FROM `information_schema`.`user_privileges`
    WHERE `grantee` = gtee
    AND _table_privs(`privilege_type`) > 0 
  )
  AND NOT EXISTS (
    SELECT *
    FROM `information_schema`.`schema_privileges`
    WHERE `grantee` = gtee
    AND _table_privs(`privilege_type`) > 0
  )
  AND NOT EXISTS (
    SELECT *
    FROM `information_schema`.`column_privileges`
    WHERE `grantee` = gtee
    AND `table_name` != tname
  );
  
  RETURN rtn; 
END //


DROP FUNCTION IF EXISTS single_table_privileges //
CREATE FUNCTION single_table_privileges(sname VARCHAR(64), tname VARCHAR(64), gtee VARCHAR(81), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  -- normalize the input
  SET @gtee = _format_user(gtee);

  IF description = '' THEN
    SET description = concat('Account ', gtee, ' should have privileges on a single table');
  END IF;

  IF NOT _has_table(sname,tname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table `', sname, '`.`', tname, '` does not exist')));
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  RETURN ok(_single_table_priv(sname, tname, @gtee), description);
END //


/***********************************************************************************/
DROP FUNCTION IF EXISTS _single_schema_priv //
CREATE FUNCTION _single_schema_priv(sname VARCHAR(64), gtee VARCHAR(81))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE rtn INT;

  SELECT COUNT(DISTINCT `table_schema`) INTO rtn
  FROM `information_schema`.`schema_privileges`
  WHERE `grantee` = gtee
  AND `table_schema` = sname
  AND NOT EXISTS (
    SELECT *
    FROM information_schema.schema_privileges
    WHERE `grantee` = gtee
    AND `table_schema` != sname
  )
  AND NOT EXISTS (
    SELECT *
    FROM `information_schema`.`user_privileges`
    WHERE `grantee` = gtee
    AND _schema_privs(`privilege_type`) > 0
  )
  AND NOT EXISTS (
    SELECT *
    FROM `information_schema`.`table_privileges`
    WHERE `grantee` = gtee
    AND `table_schema` != sname
  )
  AND NOT EXISTS (
  SELECT *
  FROM `information_schema`.`column_privileges`
  WHERE `grantee` = gtee
  AND `table_schema` != sname
  )
  AND NOT EXISTS (
  SELECT *
  FROM `tap`.`proc_privileges`
  WHERE `grantee` = gtee
  AND `routine_schema` != sname
  );
  
  RETURN rtn; 
END //


DROP FUNCTION IF EXISTS single_schema_privileges //
CREATE FUNCTION single_schema_privileges(sname VARCHAR(64), gtee VARCHAR(81), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  -- normalize the input
  SET @gtee = _format_user(gtee);

  IF description = '' THEN
    SET description = concat('Account ', gtee, ' should have privileges on a single schema');
  END IF;

  IF NOT _has_schema(sname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Schema `', sname, '` does not exist')));
  END IF;

  IF NOT _has_user_at_host(@gtee) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Account ', gtee, ' does not exist')));
  END IF;

  RETURN ok(_single_schema_priv(sname, @gtee), description);
END //




DELIMITER ;
