-- 5.7.6 and upwards
USE tap;

DELIMITER //


/************************************************************************************/
-- Check the state of GLOBAL variables
DROP FUNCTION IF EXISTS _global_var //
CREATE FUNCTION _global_var(var VARCHAR(64))
RETURNS VARCHAR(1024)
DETERMINISTIC
BEGIN
  DECLARE ret VARCHAR(1024);

  SELECT `variable_value` INTO ret
  FROM `performance_schema`.`global_variables`
  WHERE `variable_name` = var;

  RETURN COALESCE(ret, 0);
END //


DROP FUNCTION IF EXISTS global_is //
CREATE FUNCTION global_is(var VARCHAR(64), want VARCHAR(1024), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('@@GLOBAL.' , var, ' should be correctly set');
  END IF;

  IF NOT tap.mysql_version() >= 507006 THEN
    RETURN CONCAT(ok(FALSE, description),'\n',
      diag (CONCAT('This version of MySQL requires the previous version of this function')));
  END IF;

  RETURN eq(_global_var(var), want, description);
END //

DELIMITER ;
