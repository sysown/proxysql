-- TIMEZONE
-- ========

USE tap;

DELIMITER //

/****************************************************************************/

-- _has_timezones()
DROP FUNCTION IF EXISTS _has_timezones //
CREATE FUNCTION _has_timezones()
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret INT;

  SELECT count(*) INTO ret
  FROM `mysql`.`time_zone_name`;

  RETURN IF(ret > 0, 1, 0);
END //


-- has_timezones()
DROP FUNCTION IF EXISTS has_timezones //
CREATE FUNCTION has_timezones(description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = concat('Table `mysql`.`time_zone_data` should be populated');
  END IF; 

  RETURN ok(_has_timezones(), description);
END //


-- hasnt_timezones()
DROP FUNCTION IF EXISTS hasnt_timezones //
CREATE FUNCTION hasnt_timezones(description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = concat('Table `mysql`.`time_zone_data` should be empty');
  END IF;

  RETURN ok(NOT _has_timezones(), description);
END //


-- _timezones_updated()
DROP FUNCTION IF EXISTS _timezones_updated //
CREATE FUNCTION _timezones_updated()
RETURNS BOOLEAN
DETERMINISTIC
BEGIN

  DECLARE pre DATETIME;
  DECLARE post DATETIME;
  -- use example from https://dev.mysql.com/doc/refman/5.7/en/time-zone-upgrades.html
  SET pre =  (SELECT CONVERT_TZ('2007-03-11 2:00:00','US/Eastern','US/Central'));
  SET post = (SELECT CONVERT_TZ('2007-03-11 3:00:00','US/Eastern','US/Central'));
 
  RETURN IF(pre = post, 1, 0);
END //


-- timezones_updated()
DROP FUNCTION IF EXISTS timezones_updated //
CREATE FUNCTION timezones_updated(description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = concat('Timezones data should be updated for changes');
  END IF; 

  IF NOT _has_timezones() THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table `mysql`.`time_zone_data` is empty')));
  END IF;

  RETURN ok(_timezones_updated(), description);
END //


DELIMITER ;
