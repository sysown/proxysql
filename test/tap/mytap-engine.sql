-- ENGINE
-- ======

USE tap;

DELIMITER //

/****************************************************************************/
-- STORAGE ENGINE DEFINITIONS

DROP FUNCTION IF EXISTS _has_engine //
CREATE FUNCTION _has_engine(ename VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `information_schema`.`engines`
  WHERE `engine` = ename
  AND (`support` = 'YES' OR `support` = 'DEFAULT');

  RETURN COALESCE(ret, 0);
END //


-- has_engine( storage_engine, description )
DROP FUNCTION IF EXISTS has_engine //
CREATE FUNCTION has_engine(ename VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Storage Engine ', quote_ident(ename), ' should be available');
  END IF;

  RETURN ok(_has_engine(ename), description);
END //


-- _engine_is_default ( storage_engine )
DROP FUNCTION IF EXISTS _engine_default //
CREATE FUNCTION _engine_default()
RETURNS VARCHAR(64)
DETERMINISTIC
BEGIN
  DECLARE ret VARCHAR(64);

  SELECT `engine` INTO ret
  FROM `information_schema`.`engines`
  WHERE `support` = 'DEFAULT';

  RETURN COALESCE(ret, 0);
END //


-- engine_is_default ( storage_engine, description )
-- only one engine will be the default so no isnt check required
DROP FUNCTION IF EXISTS engine_is_default //
CREATE FUNCTION engine_is_default(ename VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
  SET description = CONCAT('Storage Engine ', quote_ident(ename),
    ' should be the default');
  END IF;

  IF NOT _has_engine(ename) THEN
    RETURN CONCAT(ok(FALSE, description),'\n',
      diag (CONCAT('Storage engine ', quote_ident(ename), ' is not available')));
  END IF;

  RETURN eq(_engine_default(), ename, description);
END //


DELIMITER ;
