/*
User features introduced in MySQL 5.7.6
Schema changes added columns

password_expired
password_last_changed
password_lifetime
account_locked

*/

USE tap;

DELIMITER //

/****************************************************************************/

-- check user is not disabled 

-- _user_ok( host, user )
DROP FUNCTION IF EXISTS _user_ok //
CREATE FUNCTION _user_ok(hname CHAR(60), uname CHAR(32))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `mysql`.`user`
  WHERE `host` = hname
  AND `user` = uname
  AND `password_expired` <> 'Y'
  AND `account_locked` <> 'Y';

  RETURN COALESCE(ret, 0);
END //


-- user_ok(host, user, description )
DROP FUNCTION IF EXISTS user_ok //
CREATE FUNCTION user_ok(hname CHAR(60), uname CHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('User \'', uname, '\'@\'',
      hname, '\' should not be locked or have expired password');
  END IF;

  IF NOT _has_user(hname, uname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('User \'', uname, '\'@\'', hname, '\' does not exist')));
  END IF;

  RETURN ok(_user_ok(hname, uname), description);
END //


-- user_not_ok(host, user, description )
DROP FUNCTION IF EXISTS user_not_ok //
CREATE FUNCTION user_not_ok(hname CHAR(60), uname CHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('User \'', uname, '\'@\'',
      hname, '\' should be locked out or have an expired password');
  END IF;

  IF NOT _has_user(hname, uname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('User \'', uname, '\'@\'', hname, '\' does not exist')));
  END IF;

  RETURN ok(NOT _user_ok( hname, uname ), description);
END //


/****************************************************************************/

-- PASSWORD LIFETIME

-- _user_has_lifetime( host, user )
DROP FUNCTION IF EXISTS _user_has_lifetime //
CREATE FUNCTION _user_has_lifetime (hname CHAR(60), uname CHAR(32))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `mysql`.`user`
  WHERE `Host` = hname
  AND `User` = uname
  AND `password_lifetime` IS NOT NULL AND `password_lifetime` != 0;

  RETURN COALESCE(ret, 0);
END //


-- user_has_lifetime( host, user, description )
DROP FUNCTION IF EXISTS user_has_lifetime//
CREATE FUNCTION user_has_lifetime(hname CHAR(60), uname CHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('User \'', uname, '\'@\'', hname, '\' Password should expire');
  END IF;

  IF NOT _has_user(hname, uname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('User \'', uname, '\'@\'', hname, '\' does not exist')));
  END IF;

  RETURN ok(_user_has_lifetime(hname, uname), description);
END //


-- user_hasnt_lifetime( host, user, description )
DROP FUNCTION IF EXISTS user_hasnt_lifetime //
CREATE FUNCTION user_hasnt_lifetime(hname CHAR(60), uname CHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('User \'', uname, '\'@\'', hname, '\' Password should not expire');
  END IF;

  IF NOT _has_user(hname, uname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('User \'', uname, '\'@\'', hname, '\' does not exist')));
  END IF;

  RETURN ok(NOT _user_has_lifetime(hname, uname), description);
END //


/****************************************************************************/


DELIMITER ;
