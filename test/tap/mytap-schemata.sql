-- SCHEMA
-- ======


USE tap;

DELIMITER //

/****************************************************************************/
-- has_schema( schema)
DROP FUNCTION IF EXISTS _has_schema //
CREATE FUNCTION _has_schema(sname VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
COMMENT 'Boolean test for existence of named schema.'
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `information_schema`.`schemata`
  WHERE `schema_name` = sname;

  RETURN COALESCE(ret, 0);
END //


-- has_schema( schema, description )
DROP FUNCTION IF EXISTS has_schema //
CREATE FUNCTION has_schema(sname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Confirm named schema exists.'
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Schema ', quote_ident(sname), ' should exist');
  END IF;

  RETURN ok(_has_schema(sname), description);
END //


-- hasnt_schema( schema, description )
DROP FUNCTION IF EXISTS hasnt_schema //
CREATE FUNCTION hasnt_schema(sname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Confirm named schema does not exist.'
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Schema ', quote_ident(sname), ' should not exist');
  END IF;

  RETURN ok(NOT _has_schema(sname), description);
END //

/****************************************************************************/

-- DEFAULT SCHEMA COLLATION DEFINITIONS

-- _schema_collation_is( schema, collation )
DROP FUNCTION IF EXISTS _schema_collation_is //
CREATE FUNCTION _schema_collation_is(sname VARCHAR(64))
RETURNS VARCHAR(32)
DETERMINISTIC
COMMENT 'Internal function to get the default collation for a named schema.'
BEGIN
  DECLARE ret VARCHAR(32);

  SELECT `default_collation_name` INTO ret
  FROM `information_schema`.`schemata`
  WHERE `schema_name` = sname;

  RETURN COALESCE(ret, NULL);
END //


-- schema_collation_is( schema, collation, description )
DROP FUNCTION IF EXISTS schema_collation_is //
CREATE FUNCTION schema_collation_is(sname VARCHAR(64), cname VARCHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Confirm the default collation for a schema matches value provided.'
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Schema ', quote_ident(sname), ' should have Collation ',  qv(cname));
  END IF;

  IF NOT _has_schema(sname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Schema ', quote_ident(sname), ' does not exist')));
  END IF;

  IF NOT _has_collation(cname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Collation ', quote_ident(cname), ' is not available')));
  END IF;

  RETURN eq(_schema_collation_is(sname), cname , description);
END //


/****************************************************************************/

-- DEFAULT CHARACTER SET DEFINITION

-- _schema_charset_is( schema, charset )
DROP FUNCTION IF EXISTS _schema_charset_is //
CREATE FUNCTION _schema_charset_is(sname VARCHAR(64))
RETURNS VARCHAR(32)
DETERMINISTIC
COMMENT 'Internal fuction to return the default collation for a named schema.'
BEGIN
  DECLARE ret VARCHAR(32);

  SELECT `default_character_set_name` INTO ret
  FROM `information_schema`.`schemata`
  WHERE `schema_name` = sname;

  RETURN COALESCE(ret, NULL);
END //


-- schema_charset_is( schema, charset, description )
DROP FUNCTION IF EXISTS schema_charset_is //
CREATE FUNCTION schema_charset_is(sname VARCHAR(64), cname VARCHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Confirm the default character set for a schema matches value provided.'
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Schema ', quote_ident(sname),
      ' should use Character Set ',  quote_ident(cname));
  END IF;

  IF NOT _has_schema(sname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Schema ', quote_ident(sname), ' does not exist')));
  END IF;

  IF NOT _has_charset(cname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Character Set ', quote_ident(cname), ' is not available')));
  END IF;

  RETURN eq(_schema_charset_is(sname), cname, description);
END //

-- alias
DROP FUNCTION IF EXISTS schema_character_set_is //
CREATE FUNCTION schema_character_set_is(sname VARCHAR(64), cname VARCHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
COMMENT 'Alias for schema_charset_is(sname, cname, description).'
BEGIN
  RETURN schema_charset_is(sname, cname, description);
END //

/****************************************************************/

DROP FUNCTION IF EXISTS schemas_are //
CREATE FUNCTION schemas_are(want TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  SET @want = want;
  SET @have = (SELECT GROUP_CONCAT('`', `schema_name` ,'`')
               FROM `information_schema`.`schemata`);
	  
  IF description = '' THEN
    SET description = 'The correct Schemas should be defined';
  END IF;

  CALL _populate_want(@want);
  CALL _populate_have(@have);

  SET @missing = (SELECT _missing(@have)); 
  SET @extras  = (SELECT _extra(@want));

  RETURN _are('schemas', @extras, @missing, description);
END //


DELIMITER ;
