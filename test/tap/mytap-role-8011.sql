-- ROLE
-- ====

USE tap;

DELIMITER //

/****************************************************************************/
-- MySQL role definitions

-- A role isn't a role unless it is assigned to a user or a role
-- mariadb has is_role
-- https://bugs.mysql.com/bug.php?id=84244

-- Roles can either be in the short form with just the user portion in which
-- case they get a default @% added or the long-form user@host (since it's
-- defined as a user and can be a user.

-- NB We test against a normalized single-quoted user with default hostname if one
-- is not supplied (@rname), we mirror the entered parameter string (rname) in all
-- messages, this way the user shouldn't be confused by the output not reflecting
-- their input.


DROP FUNCTION IF EXISTS _has_role //
CREATE FUNCTION _has_role(rname CHAR(93))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret BOOLEAN;

  SELECT COUNT(*) INTO ret
  FROM `mysql`.`role_edges`
  WHERE CONCAT('''', `from_user`, '''@''', from_host, '''') = rname;

  RETURN IF(ret > 0, 1, 0);
END //


-- has_role(userdef, description)
-- 97 chars if everthing is quoted with ' or `
DROP FUNCTION IF EXISTS has_role //
CREATE FUNCTION has_role(rname CHAR(97), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  SET @rname = _format_user(rname);

  IF description = '' THEN
    SET description = CONCAT('Role ', rname, ' should be active');
  END IF;

  IF NOT _has_user_at_host(@rname) THEN
    RETURN CONCAT(ok(FALSE, description),'\n',
      diag (CONCAT('Role ', rname, ' is not defined')));
  END IF;

  RETURN ok(_has_role(@rname), description);
END //

-- hasnt_role(userdef, description)
DROP FUNCTION IF EXISTS hasnt_role //
CREATE FUNCTION hasnt_role(rname CHAR(97), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  SET @rname = _format_user(rname);

  IF description = '' THEN
    SET description = CONCAT('Role ', rname, ' should not be active');
  END IF;

  -- NB no diagnostic required here
  RETURN ok(NOT _has_role(@rname), description);
END //


/********************************************************************/
-- _role_is_default (role_name)
-- Again, it's not a default until it's assigned to at least one user

DROP FUNCTION IF EXISTS _role_is_default //
CREATE FUNCTION _role_is_default(rname CHAR(93))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret BOOLEAN;

  SELECT COUNT(*) INTO ret
  FROM `mysql`.`default_roles`
  WHERE CONCAT('''', `default_role_user`, '''@''', `default_role_host`, '''') = rname;

  RETURN IF(ret > 0, 1, 0);
END //


-- role_is_default(userdef, description)
DROP FUNCTION IF EXISTS role_is_default //
CREATE FUNCTION role_is_default(rname CHAR(97), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  SET @rname = _format_user(rname);

  IF description = '' THEN
    SET description = CONCAT('Role ', rname, ' should be a DEFAULT role');
  END IF;

  IF NOT _has_user_at_host(@rname) THEN
    RETURN CONCAT(ok(FALSE, description),'\n',
      diag (CONCAT('Role ', rname, ' is not defined')));
  END IF;

  RETURN ok(_role_is_default(@rname), description);
END //

-- role_isnt_default(userdef, description)
DROP FUNCTION IF EXISTS role_isnt_default //
CREATE FUNCTION role_isnt_default(rname CHAR(97), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  SET @rname = _format_user(rname);

  IF description = '' THEN
    SET description = CONCAT('Role ', rname, ' should not be a DEFAULT role');
  END IF;

  -- also here, no diagnostic necessary
  RETURN ok(NOT _role_is_default(@rname), description);
END //


/********************************************************************/

DELIMITER ;
