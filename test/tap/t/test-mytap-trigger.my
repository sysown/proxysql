/*
TAP tests for trigger functions

*/

BEGIN;

-- required for sql_mode test
SET @mode = (SELECT @@session.sql_mode);
SET @@session.sql_mode = 'STRICT_ALL_TABLES';


SELECT tap.plan(58);
-- SELECT * from no_plan();

DROP DATABASE IF EXISTS taptest;
CREATE DATABASE taptest;

-- This will be rolled back. :-)
DROP TABLE IF EXISTS taptest.sometab;
CREATE TABLE taptest.sometab(
    id      INT NOT NULL PRIMARY KEY AUTO_INCREMENT,
    uint    INT(5) UNSIGNED,
    name    TEXT CHARACTER SET latin1 COLLATE latin1_general_ci ,
    charcol TEXT CHARACTER SET ASCII COLLATE ascii_bin ,
    numb    FLOAT(10, 2) DEFAULT NULL,
    myNum   INT(8) DEFAULT 24,
    myat    TIMESTAMP DEFAULT NOW() ON UPDATE CURRENT_TIMESTAMP,
    mydate  DATE DEFAULT '0000-00-00',
    plain   INT,
    enumCol enum('VAL1', 'VAL2', 'VAL3') NOT NULL,
    KEY `WeirdIndexName` (`myNum`),
    KEY `multiIndex` (`myNum`,`mydate`)
) ENGINE Innodb CHARACTER SET utf8 COLLATE utf8_general_ci; 

DROP TRIGGER IF EXISTS `taptest`.`testtrigger`;

CREATE TRIGGER `taptest`.`testtrigger`
BEFORE INSERT ON `taptest`.`sometab`
FOR EACH ROW set @tmp := 1;


DROP TRIGGER IF EXISTS `taptest`.`othertrigger`;

CREATE TRIGGER `taptest`.`othertrigger`
BEFORE UPDATE ON `taptest`.`sometab`
FOR EACH ROW set @tmp := 1;

-- NB
-- Needs more than 1 trigger defined on the same event to properly test
-- trigger_order_is()

/***************************************************************************/
-- has_trigger(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64), description TEXT)

SELECT tap.check_test(
  tap.has_trigger('taptest', 'sometab', 'testtrigger', ''),
  true,
  'has_trigger() with correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.has_trigger('taptest', 'sometab', 'nonexistent', ''),
  false,
  'has_trigger() with incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.has_trigger('taptest', 'sometab', 'testtrigger', ''),
  true,
  'has_trigger() default description',
  'Trigger sometab.testtrigger should exist',
  null,
  0
);

SELECT tap.check_test(
  tap.has_trigger('taptest', 'sometab', 'testtrigger', 'desc'),
  true,
  'has_trigger() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.has_trigger('taptest', 'nonexistent', 'testtrigger', ''),
  false,
  'has_trigger() nonexistent table diagnostic',
  null,
  'Table taptest.nonexistent does not exist',
  0
);



/***************************************************************************/
-- hasnt_trigger(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64), description TEXT)

SELECT tap.check_test(
  tap.hasnt_trigger('taptest', 'sometab', 'nonexistent', ''),
  true,
  'hasnt_trigger() with correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.hasnt_trigger('taptest', 'sometab', 'testtrigger', ''),
  false,
  'hasnt_trigger() with incorrect specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.hasnt_trigger('taptest', 'sometab', 'nonexistent', ''),
  true,
  'hasnt_trigger() default description',
  'Trigger sometab.nonexistent should not exist',
  null,
  0
);

SELECT tap.check_test(
  tap.hasnt_trigger('taptest', 'sometab', 'nonexistent', 'desc'),
  true,
  'hasnt_trigger() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.hasnt_trigger('taptest', 'nonexistent', 'testtrigger', ''),
  false,
  'hasnt_trigger() nonexistent table diagnostic',
  null,
  'Table taptest.nonexistent does not exist',
  0
);


/***************************************************************************/
-- trigger_event_is(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64), evnt VARCHAR(6), description TEXT)

SELECT tap.check_test(
  tap.trigger_event_is('taptest', 'sometab', 'testtrigger', 'INSERT', ''),
  true,
  'trigger_event_is() with correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.trigger_event_is('taptest', 'sometab', 'testtrigger', 'UPDATE', ''),
  false,
  'trigger_event_is() with incorrect specification',
  null,
  null,
  0
);


SELECT tap.check_test(
  tap.trigger_event_is('taptest', 'sometab', 'testtrigger', 'INSERT', ''),
  true,
  'trigger_event_is() default description',
  'Trigger sometab.testtrigger Event should occur for \'INSERT\'',
  null,
  0
);

SELECT tap.check_test(
  tap.trigger_event_is('taptest', 'sometab', 'testtrigger', 'INSERT', 'desc'),
  true,
  'trigger_event_is() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.trigger_event_is('taptest', 'sometab', 'nonexistent', 'INSERT', ''),
  false,
  'trigger_event_is() nonexistent trigger diagnostic',
  null,
  'Trigger sometab.nonexistent does not exist',
  0
);



/***************************************************************************/
-- trigger_timing_is(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64), timing VARCHAR(6), description TEXT)

SELECT tap.check_test(
  tap.trigger_timing_is('taptest', 'sometab', 'testtrigger', 'BEFORE', ''),
  true,
  'trigger_timimg_is() with correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.trigger_timing_is('taptest', 'sometab', 'testtrigger', 'AFTER', ''),
  false,
  'trigger_timimg_is() with incorrect specification',
  null,
  null,
  0
);


SELECT tap.check_test(
  tap.trigger_timing_is('taptest', 'sometab', 'testtrigger', 'BEFORE', ''),
  true,
  'trigger_timimg_is() default description',
  'Trigger sometab.testtrigger should have Timing \'BEFORE\'',
  null,
  0
);

SELECT tap.check_test(
  tap.trigger_timing_is('taptest', 'sometab', 'testtrigger', 'BEFORE', 'desc'),
  true,
  'trigger_timimg_is() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.trigger_timing_is('taptest', 'sometab', 'nonexistent', 'BEFORE',''),
  false,
  'trigger_timimg_is() nonexistent trigger diagnostic',
  null,
  'Trigger sometab.nonexistent does not exist',
  0
);



/***************************************************************************/
-- trigger_order_is(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64), seq BIGINT, description TEXT)

SELECT CASE WHEN tap.mysql_version() >= 507002 THEN
  tap.check_test(
    tap.trigger_order_is('taptest', 'sometab', 'testtrigger', 1, ''),
    true,
   'trigger_order_is() with correct specification',
    null,
    null,
    0
  )
ELSE
  tap.skip(1,"trigger_order_is() requires MySQL version >= 5.7.2")
END;



SELECT CASE WHEN tap.mysql_version() >= 507002 THEN
  tap.check_test(
    tap.trigger_order_is('taptest', 'sometab', 'testtrigger', 2, ''),
    false,
    'trigger_order_is() with incorrect specification',
    null,
    null,
    0
  )
ELSE
 tap.skip(1,"trigger_order_is() requires MySQL version >= 5.7.2")
END;


SELECT CASE WHEN tap.mysql_version() >= 507002 THEN
  tap.check_test(
    tap.trigger_order_is('taptest', 'sometab', 'testtrigger', 1, ''),
    true,
    'trigger_order_is() default description',
    'Trigger sometab.testtrigger should have Action Order 1',
    null,
    0
  )
ELSE
  tap.skip(2,"trigger_order_is() requires MySQL version >= 5.7.2")
END;

SELECT CASE WHEN tap.mysql_version() >= 507002 THEN
  tap.check_test(
    tap.trigger_order_is('taptest', 'sometab', 'testtrigger', 1, 'desc'),
    true,
    'trigger_order_is() description supplied',
    'desc',
    null,
    0
  )
ELSE
  tap.skip(2,"trigger_order_is() requires MySQL version >= 5.7.2")
END;

SELECT CASE WHEN tap.mysql_version() >= 507002 THEN
  tap.check_test(
    tap.trigger_order_is('taptest', 'sometab', 'nonexistent', 1, ''),
    false,
    'trigger_order_is() nonexistent trigger diagnostic',
    null,
    'Trigger sometab.nonexistent does not exist',
    0
  )
ELSE
  tap.skip(2,"trigger_order_is() requires MySQL version >= 5.7.2")
END;


/***************************************************************************/
-- trigger_is(sname VARCHAR(64), tname VARCHAR(64), trgr VARCHAR(64), act_state LONGTEXT, description TEXT)

SELECT tap.check_test(
  tap.trigger_is('taptest', 'sometab', 'testtrigger', 'set @tmp := 1', ''),
  true,
  'trigger_is() with correct specification',
  null,
  null,
  0
);

SELECT tap.check_test(
  tap.trigger_is('taptest', 'sometab', 'testtrigger', 'set @tmp := 2', ''),
  false,
  'trigger_is() with incorrect specification',
  null,
  null,
  0
);


SELECT tap.check_test(
  tap.trigger_is('taptest', 'sometab', 'testtrigger', 'set @tmp := 1', ''),
  true,
  'trigger_is() default description',
  'Trigger sometab.testtrigger should have the correct action',
  null,
  0
);

SELECT tap.check_test(
  tap.trigger_is('taptest', 'sometab', 'testtrigger', 'set @tmp := 1', 'desc'),
  true,
  'trigger_is() description supplied',
  'desc',
  null,
  0
);

SELECT tap.check_test(
  tap.trigger_is('taptest', 'sometab', 'nonexistent', 'set @tmp := 1', ''),
  false,
  'trigger_is() nonexistent trigger diagnostic',
  null,
  'Trigger sometab.nonexistent does not exist',
  0
);



/***************************************************************************/
-- triggers_are(sname VARCHAR(64), tname VARCHAR(64), want TEXT, description TEXT)


SELECT tap.check_test(
    tap.triggers_are('taptest', 'sometab', '`testtrigger`,`othertrigger`', ''),
    true,
    'triggers_are() correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.triggers_are('taptest', 'sometab', '`testtrigger`,`nonexistent`', ''),
    false,
    'triggers_are() incorrect specification',
    null,
    null,
    0
);


-- Note the diagnostic test here is dependent on the space after the hash
-- and before the line feed and the number of spaces before
-- the routine names, which must = 7
SELECT tap.check_test(
    tap.triggers_are('taptest', 'sometab', '`testtrigger`,`nonexistent`', ''),
    false,
    'triggers_are() diagnostic',
    null,
    '# 
    Extra Triggers:
       `othertrigger`
    Missing Triggers:
       `nonexistent`',
    0
);

SELECT tap.check_test(
    tap.triggers_are('taptest', 'nonexistent', '`testtrigger`,`othertrigger`', ''),
    false,
    'triggers_are() nonexistent table',
    null,
    'Table taptest.nonexistent does not exist',
    0
);

SELECT tap.check_test(
    tap.triggers_are('taptest', 'sometab', '`testtrigger`,`othertrigger`', ''),
    true,
    'triggers_are() default description',
    'Table taptest.sometab should have the correct triggers',
    null,
    0
);

SELECT tap.check_test(
    tap.triggers_are('taptest', 'sometab', '`testtrigger`,`othertrigger`', 'desc'),
    true,
    'triggers_are() description supplied',
    'desc',
    null,
    0
);



/****************************************************************************/


-- Finish the tests and clean up.
call tap.finish();
DROP DATABASE IF EXISTS taptest;
ROLLBACK;


SET @@session.sql_mode = @mode;
