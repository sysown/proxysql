-- USER
-- ====

USE tap;

DELIMITER //

/****************************************************************************/

DROP FUNCTION IF EXISTS _has_user //
CREATE FUNCTION _has_user(hname CHAR(60), uname CHAR(32))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `mysql`.`user`
  WHERE `host` = hname
  AND `user` = uname;

  RETURN COALESCE(ret, 0);
END //


-- has_user( host, user, description )
DROP FUNCTION IF EXISTS has_user //
CREATE FUNCTION has_user(hname CHAR(60), uname CHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('User \'', uname, '\'@\'', quote_ident(hname), '\' should exist');
  END IF;

  RETURN ok(_has_user (hname, uname), description);
END //


-- hasnt_user(host, user, description)
DROP FUNCTION IF EXISTS hasnt_user //
CREATE FUNCTION hasnt_user(hname CHAR(60), uname CHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('User \'', uname, '\'@\'', hname, '\' should not exist');
  END IF;

  RETURN ok(NOT _has_user(hname, uname), description);
END //


/****************************************************************************/
-- long-form user definition

-- _format_user
-- This function is intended to make sure that the user/role name conforms
-- to the expected form of 'user'@'host' to test with.

-- That this should be remotely difficult is down to the fact that mysql
-- allows users to be created with no quoting, single-quoting (literals),
-- back-ticking (identifiers), double-quoting (ANSI STYLE) and reports in
-- multiple formats and then also allows for users and roles to be defined
-- with no host part whatsoever but then defaults both to @'%' despite the host
-- having no relevance to roles whatsoever.

-- Note MySQL will return user@host as VARCHAR(81) and VARCHAR(93),
-- sometimes quoted, sometimes not, where mysql.user has a CHAR(32) user
-- and a CHAR(60) host which would be 97 characters once all quotes
-- and the @ are added. It's a mess.
-- See https://bugs.mysql.com/bug.php?id=91981


DROP FUNCTION IF EXISTS _format_user //
CREATE FUNCTION _format_user(uname CHAR(97))
RETURNS CHAR(97)
DETERMINISTIC
BEGIN

  SET @uname = uname;
  SET @uname = REPLACE(@uname, '"','''');
  SET @uname = REPLACE(@uname, '`','''');

  IF @uname REGEXP '@' = 0 THEN
    SET @uname = CONCAT(@uname, '@\'%\'');
  END IF;

  IF LEFT(@uname,1) != '''' THEN
    SET @uname = CONCAT('''', @uname);
  END IF;

  IF LOCATE('''@', @uname) = 0 THEN
    SET @uname = REPLACE(@uname, '@', '''@');
  END IF;

  IF LOCATE('@''', @uname) = 0 THEN
    SET @uname = REPLACE(@uname, '@', '@''');
  END IF;

  IF RIGHT(@uname,1) != '''' THEN
    SET @uname = CONCAT(@uname,'''');
  END IF;

  RETURN @uname;
END //


DROP FUNCTION IF EXISTS _has_user_at_host //
CREATE FUNCTION _has_user_at_host(uname CHAR(97))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `mysql`.`user`
  WHERE CONCAT('\'',`user`, '\'@\'', `host`, '\'') = uname;

  RETURN COALESCE(ret, 0);
END //


-- has_user@host(userdef, description )
DROP FUNCTION IF EXISTS has_user_at_host //
CREATE FUNCTION has_user_at_host(uname CHAR(97), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN

  SET @uname = _format_user(uname);

  IF description = '' THEN
    SET description = CONCAT('User ', uname, ' should exist');
  END IF;

  RETURN ok(_has_user_at_host(@uname), description);
END //


-- hasnt_user_at_host(userdef, description)
DROP FUNCTION IF EXISTS hasnt_user_at_host //
CREATE FUNCTION hasnt_user_at_host(uname CHAR(97), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN

  SET @uname = _format_user(uname);

  IF description = '' THEN
    SET description = CONCAT('User ', uname, ' should not exist');
  END IF;

  RETURN ok(NOT _has_user_at_host(@uname), description);
END //


/****************************************************************************/

-- function prototypes for features in 5.7.6

-- user_ok(host, user, description )
DROP FUNCTION IF EXISTS user_ok //
CREATE FUNCTION user_ok(hname CHAR(60), uname CHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  RETURN 'Requires MySQL version >= 5.7.6';
END //


DROP FUNCTION IF EXISTS user_not_ok //
CREATE FUNCTION user_not_ok(hname CHAR(60), uname CHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  RETURN 'Requires MySQL version >= 5.7.6';
END //


/****************************************************************************/

-- PASSWORD LIFETIME

-- user_has_lifetime( host, user, description )
DROP FUNCTION IF EXISTS user_has_lifetime//
CREATE FUNCTION user_has_lifetime(hname CHAR(60), uname CHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  RETURN 'Requires MySQL version >= 5.7.6';
END //


-- user_hasnt_lifetime( host, user, description )
DROP FUNCTION IF EXISTS user_hasnt_lifetime //
CREATE FUNCTION user_hasnt_lifetime(hname CHAR(60), uname CHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  RETURN 'Requires MySQL version >= 5.7.6';
END //


/****************************************************************************/

DELIMITER ;
