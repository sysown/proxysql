/*
TAP Tests for user functions 
*/

BEGIN;
CREATE DATABASE IF NOT EXISTS taptest;

-- setup for tests
DELIMITER //
DROP PROCEDURE IF EXISTS taptest.dropusers //
CREATE PROCEDURE taptest.dropusers()
DETERMINISTIC
BEGIN
  -- This procedure is only here in the event that the tests
  -- fail due to a syntax error in which case IF EXISTS (> 5.6) will not work to tidy up
  -- extant user records and we do want the tests to run in ALL versions
  -- removing the record from mysql.user cleans up the role tables as well
  IF (SELECT COUNT(*) FROM mysql.user WHERE user = '__tapuser__' AND host = 'localhost') > 0 THEN
    DROP USER '__tapuser__'@'localhost';
  END IF;

  IF (SELECT COUNT(*) FROM mysql.user WHERE user = '__nohost__' AND host = '%') > 0 THEN
    DROP USER '__nohost__'@'%';
  END IF;
  IF (SELECT COUNT(*) FROM mysql.user WHERE user = '__taprole__' AND host = 'localhost') > 0 THEN
    DROP USER '__taprole__'@'localhost';
  END IF;
END //

DELIMITER ;

CALL taptest.dropusers();

CREATE USER '__tapuser__'@'localhost';


-- only dyn sql will allow use of v8 sysntax in earler versions
DELIMITER //

DROP PROCEDURE IF EXISTS taptest.createroles //
CREATE PROCEDURE taptest.createroles()
DETERMINISTIC
BEGIN

  IF (SELECT tap.mysql_version()) >= 800011 THEN
    SET @sql1 = 'CREATE USER ''__taprole__''@''localhost''';
    SET @sql2 = 'CREATE USER __nohost__';
    SET @sql3 = 'GRANT ''__taprole__''@''localhost'', __nohost__ TO ''__tapuser__''@''localhost''';
    SET @sql4 = 'SET DEFAULT ROLE __nohost__ TO ''__tapuser__''@''localhost''';

    PREPARE stmt1 FROM @sql1;
    EXECUTE stmt1;
    DEALLOCATE PREPARE stmt1;

    PREPARE stmt2 FROM @sql2;
    EXECUTE stmt2;
    DEALLOCATE PREPARE stmt2;

    PREPARE stmt3 FROM @sql3;
    EXECUTE stmt3;
    DEALLOCATE PREPARE stmt3;

    PREPARE stmt4 FROM @sql4;
    EXECUTE stmt4;
    DEALLOCATE PREPARE stmt4;
  END IF;

END //

DELIMITER ;

CALL taptest.createroles();
DROP PROCEDURE IF EXISTS taptest.createroles;


SELECT tap.plan(33);

/****************************************************************************/
-- has_role(uname CHAR(97), description TEXT)

SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.has_role('__taprole__@localhost', ''),
      true,
      'has_role() extant role (not escaped)',
      null,
      null,
      0)
  ELSE
/*  WHEN tap.mysql_version() < 800011 THEN */
    tap.skip(1,'Requires MySQL version >= 8.0.11')
  END ;


SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.has_role('__nohost__', ''),
      true,
      'has_role() extant role (no host)',
      null,
      null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(1,'Requires MySQL version >= 8.0.11')
END ;


SELECT CASE WHEN tap.mysql_version() >= 800011 THEN
  tap.check_test(
    tap.has_role('''__taprole__''@''localhost''', ''),
    true,
    'has_role() extant role single quote escaped',
    null,
    null,
    0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(1,'Requires MySQL version >= 8.0.11')
END ;


SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.has_role('__tapuser__@localhost', ''),
      false,
      'has_role() nonexistent role',
      null,
      null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(1,'Requires MySQL version >= 8.0.11')
END ;


SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.has_role('__nouser__@localhost', ''),
      false,
      'has_role() nonexistent account diagnostic',
      null,
      'Role __nouser__@localhost is not defined',
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(2,'Requires MySQL version >= 8.0.11')
END ;


SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.has_role('__taprole__@localhost', ''),
      true,
      'has_role() default description',
      'Role __taprole__@localhost should be active',
      null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(2,'Requires MySQL version >= 8.0.11')
END ;


SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.has_role('__taprole__@localhost', 'desc'),
      true,
      'has_role() description supplied',
      'desc',
      null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(2,'Requires MySQL version >= 8.0.11')
END ;


/****************************************************************************/
-- hasnt_role(hname CHAR(60), uname CHAR(32), description TEXT)

SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.hasnt_role("'__tapuser__'@'localhost'", ''),
      true,
      'hasnt_role() on user account',
      null,
      null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(1,'Requires MySQL version >= 8.0.11')
END ;


SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.hasnt_role("'__taprole__'@'localhost'", ''),
      false,
      'hasnt_role() extant role',
      null,
      null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(1,'Requires MySQL version >= 8.0.11')
END ;


SELECT CASE WHEN tap.mysql_version() >= 800011 THEN
  tap.check_test(
    tap.hasnt_role('__tapuser__@localhost', ''),
    true,
    'hasnt_role() default description',
    'Role __tapuser__@localhost should not be active',
    null,
    0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(2,'Requires MySQL version >= 8.0.11')
END ;


SELECT 
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.hasnt_role('__taprole__@localhost', 'desc'),
      false,
      'hasnt_role() description supplied',
      'desc',
      null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(2,'Requires MySQL version >= 8.0.11')
END ;


/****************************************************************************/
-- role_is_default(uname CHAR(97), description TEXT)

SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.role_is_default("'__nohost__'@'%'", ''),
      true,
      'role_is_default() extant default role not escaped',
      null,
      null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(1,'Requires MySQL version >= 8.0.11')
END ;


SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.role_is_default('__nohost__', ''),
      true,
      'role_is_default() extant default role no host supplied',
      null,
      null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(1,'Requires MySQL version >= 8.0.11')
END ;


SELECT CASE WHEN tap.mysql_version() >= 800011 THEN
  tap.check_test(
    tap.role_is_default('''__nohost__''@''%''', ''),
    true,
    'role_is_default() extant default role single quote escaped',
    null,
    null,
    0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(1,'Requires MySQL version >= 8.0.11')
END ;


SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.role_is_default('__taprole__@localhost', ''),
      false,
      'role_is_default() non default role',
      null,
      null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(1,'Requires MySQL version >= 8.0.11')
END ;


SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.role_is_default('__tapuse__@localhost', ''),
      false,
      'role_is_default() non role user account',
      null,
      null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(1,'Requires MySQL version >= 8.0.11')
END ;


SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.role_is_default('__nouser__@localhost', ''),
      false,
      'role_is_default() nonexistent account diagnostic',
      null,
      'Role __nouser__@localhost is not defined',
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(2,'Requires MySQL version >= 8.0.11')
END ;


SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.role_is_default('__taprole__@localhost', ''),
      false,
      'role_is_default() default description',
      'Role __taprole__@localhost should be a DEFAULT role',
      null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(2,'Requires MySQL version >= 8.0.11')
END ;


SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.role_is_default('__nohost__', 'desc'),
      true,
      'role_is_default() description supplied',
      'desc',
      null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(2,'Requires MySQL version >= 8.0.11')
END ;


/****************************************************************************/
-- role_isnt_default(hname CHAR(60), uname CHAR(32), description TEXT)

SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.role_isnt_default('__tapuser__@localhost', ''),
      true,
      'role_isnt_default() on user account',
      null,
      null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(1,'Requires MySQL version >= 8.0.11')
END ;


SELECT
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.role_isnt_default('__taprole__@localhost', ''),
      true,
      'role_isnt_default() extant role',
      null,
      null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(1,'Requires MySQL version >= 8.0.11')
END ;


SELECT CASE WHEN tap.mysql_version() >= 800011 THEN
  tap.check_test(
    tap.role_isnt_default('__nohost__', ''),
    false,
    'role_isnt_default() default description',
    'Role __nohost__ should not be a DEFAULT role',
    null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(2,'Requires MySQL version >= 8.0.11')
END ;


SELECT 
  CASE WHEN tap.mysql_version() >= 800011 THEN
    tap.check_test(
      tap.role_isnt_default('__taprole__@localhost', 'desc'),
      true,
      'role_isnt_default() description supplied',
      'desc',
      null,
      0)
  WHEN tap.mysql_version() < 800011 THEN
    tap.skip(2,'Requires MySQL version >= 8.0.11')
END ;


/****************************************************************************/

-- Finish the tests and clean up.

call tap.finish();
-- CALL taptest.dropusers();
DROP PROCEDURE IF EXISTS taptest.dropusers;
DROP DATABASE taptest;
ROLLBACK;
