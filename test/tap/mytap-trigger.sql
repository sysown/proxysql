-- TRIGGERS
-- ========

-- Table level checks

USE tap;

DELIMITER //

/************************************************************************************/
-- _has_trigger( schema, table, trigger, description )
DROP FUNCTION IF EXISTS _has_trigger //
CREATE FUNCTION _has_trigger(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret BOOLEAN;

  SELECT 1 INTO ret
  FROM `information_schema`.`triggers`
  WHERE `trigger_schema` = sname
  AND `event_object_table` = tname
  AND `trigger_name` = trgr;

  RETURN COALESCE(ret, 0);
END //

-- has_trigger( schema, table, trigger, description)
DROP FUNCTION IF EXISTS has_trigger //
CREATE FUNCTION has_trigger(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Trigger ', quote_ident(tname), '.', quote_ident(trgr),
      ' should exist');
  END IF;

  IF NOT _has_table(sname, tname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
        ' does not exist')));
  END IF;

    RETURN ok(_has_trigger(sname, tname, trgr), description);
END //


-- hasnt_trigger( schema, table, trigger, description)
DROP FUNCTION IF EXISTS hasnt_trigger //
CREATE FUNCTION hasnt_trigger(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Trigger ', quote_ident(tname), '.', quote_ident(trgr),
      ' should not exist');
  END IF;

  IF NOT _has_table(sname, tname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
        ' does not exist')));
    END IF;

    RETURN ok(NOT _has_trigger(sname, tname, trgr), description);
END //


/****************************************************************************/
-- EVENT MANIPULATION
-- { INSERT | UPDATE | DELETE }

DROP FUNCTION IF EXISTS _trigger_event  //
CREATE FUNCTION _trigger_event(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64))
RETURNS VARCHAR(6)
DETERMINISTIC
BEGIN
  DECLARE ret VARCHAR(6);

  SELECT `event_manipulation` INTO ret
  FROM `information_schema`.`triggers`
  WHERE `event_object_schema` = sname
  AND `event_object_table` = tname
  AND `trigger_name` = trgr;

  RETURN COALESCE(ret, NULL);
END //

DROP FUNCTION IF EXISTS trigger_event_is//
CREATE FUNCTION trigger_event_is(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64), evnt VARCHAR(6), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = concat('Trigger ', quote_ident(tname), '.', quote_ident(trgr),
      ' Event should occur for ', qv(UPPER(evnt)));
  END IF;

  IF NOT _has_trigger(sname, tname, trgr) THEN
    RETURN CONCAT(ok( FALSE, description), '\n',
      diag(CONCAT('Trigger ', quote_ident(tname),'.', quote_ident(trgr),
        ' does not exist')));
  END IF;

  RETURN eq(_trigger_event(sname, tname, trgr), evnt, description);
END //


/****************************************************************************/
-- ACTION_TIMING
-- { BEFORE | AFTER }

DROP FUNCTION IF EXISTS _trigger_timing  //
CREATE FUNCTION _trigger_timing(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64))
RETURNS VARCHAR(6)
DETERMINISTIC
BEGIN
  DECLARE ret VARCHAR(6);

  SELECT `action_timing` INTO ret
  FROM `information_schema`.`triggers`
  WHERE `event_object_schema` = sname
  AND `event_object_table` = tname
  AND `trigger_name` = trgr;

  RETURN COALESCE(ret, NULL);
END //

DROP FUNCTION IF EXISTS trigger_timing_is//
CREATE FUNCTION trigger_timing_is(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64), timing VARCHAR(6), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Trigger ', quote_ident(tname), '.', quote_ident(trgr),
      ' should have Timing ', qv(UPPER(timing)));
  END IF;

  IF NOT _has_trigger(sname, tname, trgr) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Trigger ', quote_ident(tname),'.', quote_ident(trgr),
        ' does not exist')));
  END IF;

  RETURN eq(_trigger_timing(sname, tname, trgr), timing, description);
END //


/****************************************************************************/
-- ACTION_ORDER
-- Number

DROP FUNCTION IF EXISTS _trigger_order  //
CREATE FUNCTION _trigger_order(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64))
RETURNS BIGINT
DETERMINISTIC
BEGIN
  DECLARE ret BIGINT;

  SELECT `action_order` INTO ret
  FROM `information_schema`.`triggers`
  WHERE `event_object_schema` = sname
  AND `event_object_table` = tname
  AND `trigger_name` = trgr;

  RETURN COALESCE(ret, NULL);
END //



-- Support for multiple triggers for the same event and action time was introduced in MySQL 5.7.2
-- Supported in the information_schema prior to that release so does not require splitting
-- to a separte version file but will always return 1 prior to version 5.7.2

DROP FUNCTION IF EXISTS trigger_order_is//
CREATE FUNCTION trigger_order_is(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64), seq BIGINT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Trigger ', quote_ident(tname), '.', quote_ident(trgr),
      ' should have Action Order ', qv(seq));
  END IF;

  IF NOT _has_trigger(sname, tname, trgr) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Trigger ', quote_ident(tname),'.', quote_ident(trgr),
        ' does not exist')));
  END IF;

  RETURN eq(_trigger_order(sname, tname, trgr), seq, description);
END //


/****************************************************************************/
-- ACTION STATEMENT
-- What the trigger does. This might be difficult to test if the statement
-- list is long. 

DROP FUNCTION IF EXISTS _trigger_is //
CREATE FUNCTION _trigger_is(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64))
RETURNS LONGTEXT
DETERMINISTIC
BEGIN
  DECLARE ret LONGTEXT;

  SELECT `action_statement` INTO ret
  FROM `information_schema`.`triggers`
  WHERE `event_object_schema` = sname
  AND `event_object_table` = tname
  AND `trigger_name` = trgr;

  RETURN COALESCE(ret, NULL);
END //

DROP FUNCTION IF EXISTS trigger_is//
CREATE FUNCTION trigger_is(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64), act_state LONGTEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Trigger ', quote_ident(tname), '.', quote_ident(trgr), 
      ' should have the correct action');
  END IF;

  IF NOT _has_trigger(sname, tname, trgr) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Trigger ', quote_ident(tname),'.', quote_ident(trgr),
        ' does not exist')));
  END IF;

  RETURN eq(_trigger_is(sname, tname, trgr), act_state, description);
END //


/****************************************************************************/

-- Check that the proper triggers are defined

DROP FUNCTION IF EXISTS triggers_are //
CREATE FUNCTION triggers_are(sname VARCHAR(64), tname VARCHAR(64), want TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  SET @want = want;
  SET @have = (SELECT GROUP_CONCAT('`', `trigger_name` ,'`')
               FROM `information_schema`.`triggers`
               WHERE `trigger_schema` = sname
               AND `event_object_table` = tname);
	  
  IF description = '' THEN 
     SET description = CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
      ' should have the correct Triggers');
  END IF;

  IF NOT _has_table(sname,tname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
        ' does not exist')));
  END IF;

  CALL _populate_want(@want);
  CALL _populate_have(@have);

  SET @missing = (SELECT _missing(@have)); 
  SET @extras  = (SELECT _extra(@want));

  RETURN _are('triggers', @extras, @missing, description);
END //


DELIMITER ;
