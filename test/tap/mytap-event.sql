-- EVENTS
-- ======
-- >= 5.5

USE tap;

DELIMITER //

/************************************************************************************/
-- Is the scheduler process running

DROP FUNCTION IF EXISTS _scheduler //
CREATE FUNCTION _scheduler()
RETURNS VARCHAR(3)
DETERMINISTIC
BEGIN
  DECLARE ret VARCHAR(3);
    
  SELECT @@GLOBAL.event_scheduler INTO ret;

  RETURN ret;
END //

DROP FUNCTION IF EXISTS scheduler_is //
CREATE FUNCTION scheduler_is(want VARCHAR(3), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = 'Event scheduler process should be correctly set';
  END IF;

  RETURN eq(_scheduler(), want, description);
END //


DROP FUNCTION IF EXISTS _has_event //
CREATE FUNCTION _has_event(sname VARCHAR(64), ename VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `information_schema`.`events`
  WHERE `event_schema` = sname
  AND `event_name` = ename;

  RETURN COALESCE(ret, 0);
END //

DROP FUNCTION IF EXISTS has_event //
CREATE FUNCTION has_event(sname VARCHAR(64), ename VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Event ', quote_ident(sname), '.', quote_ident(ename),
      ' should exist');
  END IF;

  IF NOT _has_schema(sname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Schema ', quote_ident(sname), ' does not exist')));
    END IF;

    RETURN ok(_has_event(sname, ename), description);
END //


DROP FUNCTION IF EXISTS hasnt_event //
CREATE FUNCTION hasnt_event(sname VARCHAR(64), ename VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Event ', quote_ident(sname), '.', quote_ident(ename),
      ' should not exist');
  END IF;

  IF NOT _has_schema(sname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Schema ', quote_ident(sname), ' does not exist')));
    END IF;

  RETURN ok(NOT _has_event(sname, ename), description);
END //


/****************************************************************************/
-- EVENT TYPE
-- { ONE TIME | RECURRING }

DROP FUNCTION IF EXISTS _event_type //
CREATE FUNCTION _event_type(sname VARCHAR(64), ename VARCHAR(64))
RETURNS VARCHAR(9)
DETERMINISTIC
BEGIN
  DECLARE ret VARCHAR(9);

  SELECT `event_type` INTO ret
  FROM `information_schema`.`events`
  WHERE `event_schema` = sname
  AND `event_name` = ename;

  RETURN ret;
END //

DROP FUNCTION IF EXISTS event_type_is //
CREATE FUNCTION event_type_is(sname VARCHAR(64), ename VARCHAR(64), etype VARCHAR(9), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  DECLARE valid ENUM('ONE TIME','RECURRING');
  
  DECLARE CONTINUE HANDLER FOR 1265
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag('Event Type must be { ONE TIME | RECURRING }'));
  
  IF description = '' THEN
    SET description = CONCAT('Event ', quote_ident(sname), '.', quote_ident(ename),
      ' should have Event Type ', qv(etype));
  END IF;

  SET valid = etype;

  IF NOT _has_event(sname,ename) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Event ', quote_ident(sname), '.', quote_ident(ename),
        ' does not exist')));
  END IF;

  RETURN eq(_event_type(sname, ename), etype, description);
END //


/****************************************************************************/
-- INTERVAL_VALUE for recurring events
-- VARCHAR(256) ALLOWS NULL
-- stores a number as a string!

DROP FUNCTION IF EXISTS _event_interval_value //
CREATE FUNCTION _event_interval_value(sname VARCHAR(64), ename VARCHAR(64))
RETURNS VARCHAR(256)
DETERMINISTIC
BEGIN
  DECLARE ret VARCHAR(256);

  SELECT `interval_value` INTO ret
  FROM `information_schema`.`events`
  WHERE `event_schema` = sname
  AND `event_name` = ename;

  RETURN ret;
END //

DROP FUNCTION IF EXISTS event_interval_value_is //
CREATE FUNCTION event_interval_value_is(sname VARCHAR(64), ename VARCHAR(64), ivalue VARCHAR(256), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Event ', quote_ident(sname), '.', quote_ident(ename),
      ' should have Interval Value ', qv(ivalue));
  END IF;

  IF NOT _has_event(sname,ename) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Event ', quote_ident(sname), '.', quote_ident(ename),
        ' does not exist')));
  END IF;

  RETURN eq(_event_interval_value(sname, ename), ivalue, description);
END //

/****************************************************************************/
-- INTERVAL_FIELD for recurring events
-- VARCHAR(18) ALLOWS NULL
-- HOUR, DAY, WEEK etc 

DROP FUNCTION IF EXISTS _event_interval_field //
CREATE FUNCTION _event_interval_field(sname VARCHAR(64), ename VARCHAR(64))
RETURNS VARCHAR(18)
DETERMINISTIC
BEGIN
  DECLARE ret VARCHAR(18);

  SELECT `interval_field` INTO ret
  FROM `information_schema`.`events`
  WHERE `event_schema` = sname
  AND `event_name` = ename;

  RETURN ret;
END //

DROP FUNCTION IF EXISTS event_interval_field_is //
CREATE FUNCTION event_interval_field_is(sname VARCHAR(64), ename VARCHAR(64), ifield VARCHAR(18), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  DECLARE valid ENUM('YEAR','QUARTER','MONTH','DAY','HOUR','MINUTE ',
              'WEEK','SECOND','YEAR_MONTH','DAY_HOUR','DAY_MINUTE',
	      'DAY_SECOND','HOUR_MINUTE','HOUR_SECOND','MINUTE_SECOND');
  
  DECLARE CONTINUE HANDLER FOR 1265
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag('Event Interval must be { YEAR | QUARTER | MONTH | DAY | HOUR | MINUTE |
              WEEK | SECOND | YEAR_MONTH | DAY_HOUR | DAY_MINUTE |
              DAY_SECOND | HOUR_MINUTE | HOUR_SECOND | MINUTE_SECOND }'));
  
  IF description = '' THEN
    SET description = CONCAT('Event ', quote_ident(sname), '.', quote_ident(ename),
      ' should have Interval Field ', qv(ifield));
  END IF;

  SET valid = ifield;

  IF NOT _has_event(sname,ename) THEN
    RETURN CONCAT(ok(FALSE, description), '\n', 
      diag(CONCAT('Event ', quote_ident(sname), '.', quote_ident(ename),
        ' does not exist')));
    END IF;

    RETURN eq(_event_interval_field(sname, ename), ifield, description);
END //


/****************************************************************************/
-- STATUS
-- { ENABLED | DISABLED | SLAVESIDE DISABLED }

DROP FUNCTION IF EXISTS _event_status //
CREATE FUNCTION _event_status(sname VARCHAR(64), ename VARCHAR(64))
RETURNS VARCHAR(18)
DETERMINISTIC
BEGIN
  DECLARE ret VARCHAR(18);

  SELECT `status` INTO ret
  FROM `information_schema`.`events`
  WHERE `event_schema` = sname
  AND `event_name` = ename;

  RETURN ret;
END //

DROP FUNCTION IF EXISTS event_status_is //
CREATE FUNCTION event_status_is(sname VARCHAR(64), ename VARCHAR(64), stat VARCHAR(18), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  DECLARE valid ENUM('ENABLED','DISABLED','SLAVESIDE DISABLED');
  
  DECLARE CONTINUE HANDLER FOR 1265
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag('Event Status must be { ENABLED | DISABLED | SLAVESIDE DISABLED }'));

  IF description = '' THEN
    SET description = CONCAT('Event ', quote_ident(sname), '.', quote_ident(ename),
      ' should have Status ', qv(stat));
  END IF;

  SET valid = stat;

  IF NOT _has_event(sname,ename) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Event ', quote_ident(sname), '.', quote_ident(ename),
        ' does not exist')));
  END IF;

  RETURN eq(_event_status(sname, ename), stat, description);
END //


/****************************************************************************/
-- Check that the proper events are defined

DROP FUNCTION IF EXISTS events_are //
CREATE FUNCTION events_are(sname VARCHAR(64), want TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  SET @want = want;
  SET @have = (SELECT GROUP_CONCAT('`',`event_name`,'`')
               FROM `information_schema`.`events`
               WHERE `event_schema` = sname);

  IF description = '' THEN
    SET description = CONCAT('Schema ', quote_ident(sname), ' should have the correct Events');
  END IF;

  IF NOT _has_schema(sname) THEN
    RETURN CONCAT( ok(FALSE, description), '\n',
      diag(CONCAT('Schema ', quote_ident(sname), ' does not exist' )));
  END IF;

  CALL _populate_want(@want);
  CALL _populate_have(@have);

  SET @missing = (SELECT _missing(@have)); 
  SET @extras  = (SELECT _extra(@want));

  RETURN _are('events', @extras, @missing, description);
END //


DELIMITER ;
