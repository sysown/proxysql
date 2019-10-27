/*
TAP Tests for event functions 

*/

BEGIN;

SELECT tap.plan(64);

-- setup for tests
DROP DATABASE IF EXISTS taptest;
CREATE DATABASE taptest;

CREATE EVENT taptest.myEvent
ON SCHEDULE EVERY 1 HOUR
  DO
    SELECT 1;

CREATE EVENT taptest.otherevent
ON SCHEDULE AT CURRENT_TIMESTAMP + INTERVAL 1 HOUR
  DO
    SELECT 1;


/****************************************************************************/
-- has_event(sname VARCHAR(64), ename VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.has_event('taptest', 'myEvent', ''),
    true,
    'has_event() extant event',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.has_event('taptest', 'nonexistent', ''),
    false,
    'has_event() nonexistent event',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.has_event('taptest', 'myEvent', ''),
    true,
    'has_event() default description',
    'Event taptest.myEvent should exist',
    null,
    0
);

SELECT tap.check_test(
    tap.has_event('taptest', 'myEvent', 'desc'),
    true,
    'has_event() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.has_event('nonexistent', 'myEvent', ''),
    false,
    'has_event() diagnostic invalid schema supplied',
    null,
    'Schema nonexistent does not exist',
    0
);


/****************************************************************************/
-- hasnt_event(sname VARCHAR(64), ename VARCHAR(64), description TEXT)

SELECT tap.check_test(
    tap.hasnt_event('taptest', 'nonexistent', ''),
    true,
    'hasnt_event() with nonexistent event',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_event('taptest', 'myEvent', ''),
    false,
    'hasnt_event() with extant event',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_event('taptest', 'nonexisting', ''),
    true,
    'hasnt_event() default description',
    'Event taptest.nonexisting should not exist',
    null,
    0
);

SELECT tap.check_test(
    tap.hasnt_event('taptest', 'nonexisting', 'desc'),
    true,
    'hasnt_event() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.has_event('nonexistent', 'myEvent', ''),
    false,
    'hasnt_event() diagnostic invalid schema supplied',
    null,
    'Schema nonexistent does not exist',
    0
);


/****************************************************************************/
-- event_type_is(sname VARCHAR(64), ename VARCHAR(64), etype VARCHAR(9), description TEXT)

SELECT tap.check_test(
    tap.event_type_is('taptest', 'myEvent', 'RECURRING', ''),
    true,
    'event_type_is() with correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.event_type_is('taptest', 'myEvent', 'ONE TIME', ''),
    false,
    'event_type_is() with incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.event_type_is('taptest', 'myEvent', 'RECURRING', ''),
    true,
    'event_type_is() default description',
    'Event taptest.myEvent should have Event type \'RECURRING\'',
    null,
    0
);

SELECT tap.check_test(
    tap.event_type_is('taptest', 'myEvent', 'RECURRING', 'desc'),
    true,
    'event_type_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.event_type_is('taptest', 'myEvent', 'INVALID', ''),
    false,
    'event_type_is() invalid event type supplied',
    null,
    'Event Type must be { ONE TIME | RECURRING }',
    0
);

SELECT tap.check_test(
    tap.event_type_is('taptest', 'nonEvent', 'RECURRING', ''),
    false,
    'event_type_is() invalid event name supplied',
    null,
    'Event taptest.nonEvent does not exist',
    0
);


/****************************************************************************/
-- event_interval_value_is(sname VARCHAR(64), ename VARCHAR(64), ivalue VARCHAR(256), description TEXT)

SELECT tap.check_test(
    tap.event_interval_value_is('taptest', 'myEvent', '1', ''),
    true,
    'event_interval_value_is() with correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.event_interval_value_is('taptest', 'myEvent', '0', ''),
    false,
    'event_interval_value_is() with incorrect specification zero',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.event_interval_value_is('taptest', 'myEvent', 'one', ''),
    false,
    'event_interval_value_is() with incorrect specification alpha',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.event_interval_value_is('taptest', 'myEvent', '-1', ''),
    false,
    'event_interval_value_is() with incorrect specification negative',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.event_interval_value_is('taptest', 'myEvent', '1', ''),
    true,
    'event_interval_value_is() default description',
    'Event taptest.myEvent should have Interval Value 1',
    null,
    0
);

SELECT tap.check_test(
    tap.event_interval_value_is('taptest', 'myEvent', '1', 'desc'),
    true,
    'event_interval_value_is() description supplied',
    'desc',
    null,
    0
);


SELECT tap.check_test(
    tap.event_interval_value_is('taptest', 'nonEvent', '1', ''),
    false,
    'event_interval_value_is() nonexistent event supplied',
    null,
    'Event taptest.nonEvent does not exist',
    0
);


/****************************************************************************/
-- event_interval_field_is(sname VARCHAR(64), ename VARCHAR(64), ifield VARCHAR(18), description TEXT)

SELECT tap.check_test(
    tap.event_interval_field_is('taptest', 'myEvent', 'HOUR', ''),
    true,
    'event_interval_field_is() with correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.event_interval_field_is('taptest', 'myEvent', 'MINUTE', ''),
    false,
    'event_interval_field_is() with incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.event_interval_field_is('taptest', 'myEvent', 'HOUR', ''),
    true,
    'event_interval_field_is() default description',
    'Event taptest.myEvent should have Interval Field \'HOUR\'',
    null,
    0
);

SELECT tap.check_test(
    tap.event_interval_field_is('taptest', 'myEvent', 'HOUR', 'desc'),
    true,
    'event_interval_field_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.event_interval_field_is('taptest', 'myEvent', 'INVALID', ''),
    false,
    'event_interval_field_is() invalid interval supplied',
    null,
    'Event Interval must be { YEAR | QUARTER | MONTH | DAY | HOUR | MINUTE |
              WEEK | SECOND | YEAR_MONTH | DAY_HOUR | DAY_MINUTE |
              DAY_SECOND | HOUR_MINUTE | HOUR_SECOND | MINUTE_SECOND }',
    0
);

SELECT tap.check_test(
    tap.event_interval_field_is('taptest', 'nonexistent', 'HOUR', ''),
    false,
    'event_interval_field_is() nonexistent event supplied',
    null,
    'Event taptest.nonexistent does not exist',
    0
);


/****************************************************************************/
-- event_status_is(sname VARCHAR(64), ename VARCHAR(64), stat VARCHAR(18), description TEXT)

-- { ENABLED | DISABLED | SLAVESIDE DISABLED }

SELECT tap.check_test(
    tap.event_status_is('taptest', 'myEvent', 'ENABLED', ''),
    true,
    'event_status_is() with correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.event_status_is('taptest', 'myEvent', 'DISABLED', ''),
    false,
    'event_status_is() with incorrect specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.event_status_is('taptest', 'myEvent', 'ENABLED', ''),
    true,
    'event_status_is() default description',
    'Event taptest.myEvent should have Status \'ENABLED\'',
    null,
    0
);

SELECT tap.check_test(
    tap.event_status_is('taptest', 'myEvent', 'ENABLED', 'desc'),
    true,
    'event_status_is() description supplied',
    'desc',
    null,
    0
);

SELECT tap.check_test(
    tap.event_status_is('taptest', 'myEvent', 'INVALID', ''),
    false,
    'event_status_is() invalid interval supplied',
    null,
    'Event Status must be { ENABLED | DISABLED | SLAVESIDE DISABLED }',
    0
);

SELECT tap.check_test(
    tap.event_status_is('taptest', 'nonexistent', 'ENABLED', ''),
    false,
    'event_status_is() nonexistent event supplied',
    null,
    'Event taptest.nonexistent does not exist',
    0
);



/****************************************************************************/
-- events_are(sname VARCHAR(64), want TEXT, description TEXT)

SELECT tap.check_test(
    tap.events_are('taptest', '`myEvent`,`otherevent`', ''),
    true,
    'events_are() correct specification',
    null,
    null,
    0
);

SELECT tap.check_test(
    tap.events_are('taptest', '`myEvent`,`nonexistent`', ''),
    false,
    'events_are() incorrect specification',
    null,
    null,
    0
);

-- Note the diagnostic test here is dependent on the space after the hash
-- and before the line feed and the number of spaces before
-- the event names, which must = 7
SELECT tap.check_test(
    tap.events_are('taptest', '`myEvent`,`nonexistent`', ''),
    false,
    'events_are() diagnostic',
    null,
    '# 
    Extra events:
       `otherevent`
    Missing events:
       `nonexistent`',
    0
);

SELECT tap.check_test(
    tap.events_are('taptest', '`myEvent`,`otherevent`', ''),
    true,
    'events_are() default description',
    'Schema taptest should have the correct Events',
    null,
    0
);

SELECT tap.check_test(
    tap.events_are('taptest',  '`myEvent`,`otherevent`', 'desc'),
    true,
    'events_are() description supplied',
    'desc',
    null,
    0
);


/****************************************************************************/

-- Finish the tests and clean up.

call tap.finish();
DROP DATABASE IF EXISTS taptest;
ROLLBACK;
