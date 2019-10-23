-- COLLATION
-- =========

USE tap;

DELIMITER //

/****************************************************************************/

-- _has_collation(collation)
DROP FUNCTION IF EXISTS _has_collation //
CREATE FUNCTION _has_collation(cname VARCHAR(32))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `information_schema`.`collations`
  WHERE `collation_name` = cname
  AND `is_compiled` = 'YES';

  RETURN COALESCE(ret, 0);
END //


-- has_collation(collation, description)
DROP FUNCTION IF EXISTS has_collation //
CREATE FUNCTION has_collation(cname VARCHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = concat('Collation ', quote_ident(cname), ' should be available');
  END IF; 

  RETURN ok(_has_collation(cname), description);
END //


-- hasnt_collation( collation_name, description )
DROP FUNCTION IF EXISTS hasnt_collation //
CREATE FUNCTION hasnt_collation(cname VARCHAR(32), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = concat('Collation ', quote_ident(cname), ' should not be available');
  END IF;

  RETURN ok(NOT _has_collation(cname), description);
END //


DELIMITER ;
