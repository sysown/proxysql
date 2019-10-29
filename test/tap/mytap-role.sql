-- ROLE
-- ====

/*
Feature added in v8
Dummy functions to act as placeholders so that
tests will complile
*/

USE tap;

DELIMITER //

DROP FUNCTION IF EXISTS has_role //
CREATE FUNCTION has_role(rname CHAR(92), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  RETURN 'Requires MySQL version >= 8.0.11'; 
END //

DROP FUNCTION IF EXISTS hasnt_role //
CREATE FUNCTION hasnt_role(rname CHAR(92), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  RETURN 'Requires MySQL version >= 8.0.11'; 
END //

DROP FUNCTION IF EXISTS role_is_default //
CREATE FUNCTION role_is_default(rname CHAR(92), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  RETURN 'Requires MySQL version >= 8.0.11'; 
END //

DROP FUNCTION IF EXISTS role_isnt_default //
CREATE FUNCTION role_isnt_default(rname CHAR(92), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  RETURN 'Requires MySQL version >= 8.0.11'; 
END //


DELIMITER ;
