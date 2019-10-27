-- CONSTRAINTS
-- ===========
-- PRIMARY KEY, FOREIGN KEY and UNIQUE constraints

USE tap;

DELIMITER //

-- Simple check on existence of named constraint without being concerned for its
-- composition
DROP FUNCTION IF EXISTS _has_constraint //
CREATE FUNCTION _has_constraint(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret INT;

  SELECT COUNT(*) INTO ret
  FROM `information_schema`.`table_constraints`
  WHERE `constraint_schema` = sname
  AND `table_name` = tname
  AND `constraint_name` = cname;

  RETURN IF(ret > 0 , 1, 0);
END //

-- check for the existence of named constraint
DROP FUNCTION IF EXISTS has_constraint //
CREATE FUNCTION has_constraint(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Constraint ', quote_ident(tname), '.', quote_ident(cname),
      ' should exist');
  END IF;

  IF NOT _has_table(sname, tname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
        ' does not exist')));
  END IF;

  RETURN ok(_has_constraint(sname, tname, cname), description);
END //

-- test for when constraint has been removed
DROP FUNCTION IF EXISTS hasnt_constraint //
CREATE FUNCTION hasnt_constraint(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Constraint ', quote_ident(tname),'.',quote_ident(cname),
      ' should not exist');
  END IF;

  IF NOT _has_table( sname, tname ) THEN
    RETURN CONCAT( ok( FALSE, description), '\n',
      diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
        ' does not exist')));
  END IF;

  RETURN ok(NOT _has_constraint(sname, tname, cname), description);
END //

/********************************************************************************/


DROP FUNCTION IF EXISTS _has_constraint_type //
CREATE FUNCTION _has_constraint_type(sname VARCHAR(64), tname VARCHAR(64), ctype VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret INT;

  SELECT COUNT(*) INTO ret
  FROM `information_schema`.`table_constraints`
  WHERE `constraint_schema` = sname
  AND `table_name` = tname
  AND `constraint_type` = ctype;

  RETURN IF(ret > 0 , 1, 0);
END //



-- PRIMARY KEY exists
DROP FUNCTION IF EXISTS has_pk //
CREATE FUNCTION has_pk(sname VARCHAR(64), tname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
      ' should have a Primary Key');
  END IF;

  IF NOT _has_table(sname, tname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
        ' does not exist')));
  END IF;

  RETURN ok(_has_constraint(sname, tname, 'PRIMARY'), description);
END //


DROP FUNCTION IF EXISTS hasnt_pk //
CREATE FUNCTION hasnt_pk(sname VARCHAR(64), tname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
      ' should not have a Primary Key');
  END IF;

  IF NOT _has_table(sname, tname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
        ' does not exist')));
  END IF;
  -- PK is ALWAYS called PRIMARY but could have used _has_constraint_type here
  RETURN ok(NOT _has_constraint(sname, tname, 'PRIMARY'), description);
END //

-- Loose check on the existence of an FK on the table
DROP FUNCTION IF EXISTS has_fk //
CREATE FUNCTION has_fk(sname VARCHAR(64), tname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
      ' should have a Foreign Key');
  END IF;

  IF NOT _has_table(sname, tname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
        ' does not exist')));
  END IF;

  RETURN ok(_has_constraint_type(sname, tname, 'FOREIGN KEY'), description);
END //

DROP FUNCTION IF EXISTS hasnt_fk //
CREATE FUNCTION hasnt_fk(sname VARCHAR(64), tname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
      ' should not have a Foreign Key');
  END IF;

  IF NOT _has_table(sname, tname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
        ' does not exist')));
  END IF;

  RETURN ok(NOT _has_constraint_type(sname, tname, 'FOREIGN KEY'), description);
END //

-- Check composition of an index is unique
-- This is an index check rather than a column test since we can test multiple cols
DROP FUNCTION IF EXISTS _col_is_unique //
CREATE FUNCTION _col_is_unique(sname VARCHAR(64), tname VARCHAR(64), want TEXT)
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret BOOLEAN;

  SELECT COUNT(`indexdef`) INTO ret
  FROM
    (
      SELECT `table_name`, `index_name`,
      GROUP_CONCAT(CONCAT('`', `column_name`, '`') ORDER BY `seq_in_index`) AS `indexdef`
      FROM `information_schema`.`statistics`
      WHERE `table_schema` = sname
      AND `table_name` = tname
      AND `non_unique` = 0
      GROUP BY `table_name`,`index_name`
     ) indices 
  WHERE `indexdef` = want;

  RETURN IF(ret > 0 , 1, 0);
END //

-- Does the column or column list have an index that is unique (ie UNIQUE or PRIMARY),
-- save for later an intelligent way of testing the existence of the cols in want
-- Oh for a postgres array
DROP FUNCTION IF EXISTS col_is_unique //
CREATE FUNCTION col_is_unique(sname VARCHAR(64), tname VARCHAR(64), want TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  -- quote a single identifier if the user forgot
  IF NOT LOCATE(',', want) AND NOT LOCATE('`', want) THEN
    SET want = CONCAT('`', want, '`');
  END IF;

  IF description = '' THEN
    SET description = CONCAT('Unique Index for ', quote_ident(sname), '.', quote_ident(tname),
      ' should exist on ', want);
  END IF;

  IF NOT _has_table(sname, tname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
        ' does not exist')));
  END IF;
  
  RETURN ok(_col_is_unique( sname, tname, want), description);
END //


-- Check cols make a PRIMARY KEY
-- This is an index check rather than a column test since we can test multiple cols
-- pgTAP functions index_is_clustered() and index_is_primary() on named index are not
-- required because the PK is always clustered and it's always called 'PRIMARY'
DROP FUNCTION IF EXISTS _col_is_pk //
CREATE FUNCTION _col_is_pk(sname VARCHAR(64), tname VARCHAR(64), want TEXT)
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret BOOLEAN;

  SELECT COUNT(`indexdef`) INTO ret
  FROM 
    (
      SELECT `table_name`, `index_name`,
      GROUP_CONCAT(CONCAT('`', `column_name`, '`') ORDER BY `seq_in_index`) AS `indexdef`
      FROM `information_schema`.`statistics`
      WHERE `table_schema` = sname
      AND `table_name` = tname
      GROUP BY `table_name`,`index_name`
    ) indices
  WHERE `index_name` = 'PRIMARY'
  AND `indexdef` = want;

  RETURN IF(ret <> 0 , TRUE, FALSE);
END //

-- Does the column or column list form a PK
DROP FUNCTION IF EXISTS col_is_pk //
CREATE FUNCTION col_is_pk(sname VARCHAR(64), tname VARCHAR(64), want TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF NOT LOCATE(',', want) AND NOT LOCATE('`', want) THEN
    SET want = CONCAT('`', want, '`'); --  quote_ident(want);
  END IF;

  IF description = '' THEN
    SET description = CONCAT('Primary Key for ', quote_ident(sname), '.', quote_ident(tname),
      ' should exist on ', want);
  END IF;

  IF NOT _has_table( sname, tname ) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
      ' does not exist')));
  END IF;

  RETURN ok(_col_is_pk( sname, tname, want), description);
END //


-- Check a unique index exists on a table - it will if there's a PK
-- perhaps relocate to mysql-table
DROP FUNCTION IF EXISTS _has_unique //
CREATE FUNCTION _has_unique(sname VARCHAR(64), tname VARCHAR(64))
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret BOOLEAN;

  SELECT COUNT(`table_name`) INTO ret
  FROM `information_schema`.`statistics`
  WHERE `table_schema` = sname
  AND `table_name` = tname
  AND `non_unique` = 0;

  RETURN IF(ret <> 0 , TRUE, FALSE);
END //

-- Does a table have an index that is unique (ie UNIQUE or PRIMARY),
DROP FUNCTION IF EXISTS has_unique //
CREATE FUNCTION has_unique(sname VARCHAR(64), tname VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN 
    SET description = CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
      ' should have a Unique Index');
  END IF;

  IF NOT _has_table(sname, tname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
        ' does not exist')));
  END IF;

  RETURN ok(_has_unique(sname, tname), description);
END //


/***************************************************************************/
-- Constraint Type
-- FK, PK or UNIQUE 

DROP FUNCTION IF EXISTS _constraint_type //
CREATE FUNCTION _constraint_type(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS VARCHAR(64)
DETERMINISTIC
BEGIN
  DECLARE ret VARCHAR(64);

  SELECT `constraint_type` INTO ret
  FROM `information_schema`.`table_constraints`
  WHERE `constraint_schema` = sname
  AND `table_name` = tname
  AND `constraint_name` = cname;

  RETURN ret;
END //

DROP FUNCTION IF EXISTS constraint_type_is //
CREATE FUNCTION constraint_type_is(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), ctype VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Constraint ', quote_ident(tname), '.', quote_ident(cname),
      ' should have Constraint Type ' , qv(ctype));
  END IF;
    
  IF NOT _has_constraint(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Constraint ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN eq(_constraint_type(sname, tname, cname), ctype, description);
END //

/***************************************************************************/

-- FK Properties
-- on delete, on update. on match is ALWAYS None 

DROP FUNCTION IF EXISTS _fk_on_delete //
CREATE FUNCTION _fk_on_delete(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS VARCHAR(64)
DETERMINISTIC
BEGIN
  DECLARE ret VARCHAR(64);

  SELECT `delete_rule` INTO ret
  FROM `information_schema`.`referential_constraints`
  WHERE `constraint_schema` = sname
  AND `table_name` = tname
  AND `constraint_name` = cname;

  RETURN ret;
END //

-- check for rule ON DELETE
DROP FUNCTION IF EXISTS fk_on_delete //
CREATE FUNCTION fk_on_delete(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), rule VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Constraint ', quote_ident(tname), '.', quote_ident(cname),
      ' should have rule ON DELETE ', qv(rule));
  END IF;

  IF NOT _has_constraint(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Constraint ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN eq(_fk_on_delete(sname, tname, cname), rule, description);
END //

DROP FUNCTION IF EXISTS _fk_on_update //
CREATE FUNCTION _fk_on_update(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64))
RETURNS VARCHAR(64)
DETERMINISTIC
BEGIN
  DECLARE ret VARCHAR(64);

  SELECT `update_rule` INTO ret
  FROM `information_schema`.`referential_constraints`
  WHERE `constraint_schema` = sname
  AND `table_name` = tname
  AND `constraint_name` = cname;

  RETURN ret;
END //

-- check for rule ON UPDATE
DROP FUNCTION IF EXISTS fk_on_update //
CREATE FUNCTION fk_on_update(sname VARCHAR(64), tname VARCHAR(64), cname VARCHAR(64), rule VARCHAR(64), description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  IF description = '' THEN
    SET description = CONCAT('Constraint ', quote_ident(tname), '.', quote_ident(cname),
      ' should have rule ON UPDATE ' , qv(rule));
  END IF;

  IF NOT _has_constraint(sname, tname, cname) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Constraint ', quote_ident(tname), '.', quote_ident(cname),
        ' does not exist')));
  END IF;

  RETURN eq(_fk_on_update(sname, tname, cname), rule, description);
END //

/***************************************************************************/

DROP FUNCTION IF EXISTS _fk_ok //
CREATE FUNCTION _fk_ok(csch VARCHAR(64), ctab VARCHAR(64), ccol TEXT,
                       usch VARCHAR(64), utab VARCHAR(64), ucol TEXT)
RETURNS BOOLEAN
DETERMINISTIC
BEGIN
  DECLARE ret BOOLEAN;

  SELECT COUNT(*) INTO ret
  FROM 
    (
      SELECT kc.`constraint_schema` AS `csch`,
             kc.`table_name` AS `ctab`,
             GROUP_CONCAT(CONCAT('`',kc.`column_name`,'`') ORDER BY kc.`ordinal_position`) AS `cols1`,
             kc.`referenced_table_schema` AS `usch`,
             kc.`referenced_table_name` AS `utab`,
             GROUP_CONCAT(CONCAT('`',kc.`referenced_column_name`,'`') ORDER BY `position_in_unique_constraint`) AS `cols2`
      FROM `information_schema`.`key_column_usage` kc 
      WHERE kc.`constraint_schema` = csch AND kc.`referenced_table_schema` = usch
      AND kc.`table_name` = ctab AND kc.`referenced_table_name` = utab
      GROUP BY 1,2,4,5
      HAVING GROUP_CONCAT(CONCAT('`',kc.`column_name`,'`') ORDER BY kc.`ordinal_position`) = ccol
         AND GROUP_CONCAT(CONCAT('`',kc.`referenced_column_name`,'`') ORDER BY `position_in_unique_constraint`) = ucol
    ) fkey;

  RETURN COALESCE(ret,0);
END //

-- check that a foreign key points to the correct table and indexed columns key
-- cname and uname will likly be single columns but they may not be, the index
-- references will therefore have to be resolved before they can be compared

-- ccols an ucols must be quoted for comparison!
DROP FUNCTION IF EXISTS fk_ok //
CREATE FUNCTION fk_ok(csch VARCHAR(64), ctab VARCHAR(64), ccol TEXT,
                      usch VARCHAR(64), utab VARCHAR(64), ucol TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN

  IF NOT LOCATE(',', ccol) AND NOT LOCATE('`', ccol) THEN
    SET ccol = CONCAT('`', ccol, '`');
  END IF;

  IF NOT LOCATE(',', ucol) AND NOT LOCATE('`', ucol) THEN
    SET ucol = CONCAT('`', ucol, '`');
  END IF;

  IF description = '' THEN
    SET description = CONCAT('Constraint Foreign Key ', quote_ident(ctab), '(', ccol,
      ') should reference ' , quote_ident(utab), '(', ucol, ')');
  END IF;

  IF NOT _has_table(csch, ctab) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table ', quote_ident(csch), '.', quote_ident(ctab),
        ' does not exist')));
  END IF;

  IF NOT _has_table(usch, utab) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table ', quote_ident(usch), '.', quote_ident(utab),
        ' does not exist')));
  END IF;

  RETURN ok(_fk_ok(csch, ctab, ccol, usch, utab, ucol), description);
END //

/*******************************************************************/
-- Check that the proper constraints are defined
/*
DROP FUNCTION IF EXISTS _missing_constraints //
CREATE FUNCTION _missing_constraints(sname VARCHAR(64), tname VARCHAR(64))
RETURNS TEXT
DETERMINISTIC
BEGIN 
  DECLARE ret TEXT;

  SELECT GROUP_CONCAT(quote_ident(`ident`)) INTO ret
  FROM
    (
      SELECT `ident`
      FROM `idents1`
      WHERE `ident` NOT IN
        (
          SELECT `constraint_name`
          FROM `information_schema`.`table_constraints`
          WHERE `table_schema` = sname
          AND `table_name` = tname
        )
    ) msng;

  RETURN COALESCE(ret, '');
END //

DROP FUNCTION IF EXISTS _extra_constraints //
CREATE FUNCTION _extra_constraints(sname VARCHAR(64), tname VARCHAR(64))
RETURNS TEXT
DETERMINISTIC
BEGIN
  DECLARE ret TEXT;

  SELECT GROUP_CONCAT(quote_ident(`ident`)) into ret FROM
    (
      SELECT DISTINCT `constraint_name` AS `ident`
      FROM `information_schema`.`table_constraints`
      WHERE `table_schema` = sname
      AND `table_name` = tname
      AND `constraint_name` NOT IN
        (
          SELECT `ident`
          FROM `idents2`
        )
    ) xtra;

  RETURN COALESCE(ret, '');
END //


DROP FUNCTION IF EXISTS constraints_are //
CREATE FUNCTION constraints_are(sname VARCHAR(64), tname VARCHAR(64),  want TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  DECLARE sep       CHAR(1) DEFAULT ',';
  DECLARE seplength INTEGER DEFAULT CHAR_LENGTH(sep);

  IF description = '' THEN
    SET description = CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
      ' should have the correct Constraints');
  END IF;

  IF NOT _has_table( sname, tname ) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
        ' does not exist' )));
  END IF;

  SET want = _fixCSL(want);

  IF want IS NULL THEN
    RETURN CONCAT(ok(FALSE,description),'\n',
      diag(CONCAT('Invalid character in comma separated list of expected schemas\n',
                  'Identifier must not contain NUL Byte or extended characters (> U+10000)')));
  END IF;

  DROP TEMPORARY TABLE IF EXISTS idents1;
  CREATE TEMPORARY TABLE tap.idents1 (ident VARCHAR(64) PRIMARY KEY)
    ENGINE MEMORY CHARSET utf8 COLLATE utf8_general_ci;
  DROP TEMPORARY TABLE IF EXISTS idents2;
  CREATE TEMPORARY TABLE tap.idents2 (ident VARCHAR(64) PRIMARY KEY)
    ENGINE MEMORY CHARSET utf8 COLLATE utf8_general_ci;

  WHILE want != '' > 0 DO
    SET @val = TRIM(SUBSTRING_INDEX(want, sep, 1));
    SET @val = uqi(@val);
    IF  @val <> '' THEN
        INSERT IGNORE INTO idents1 VALUE(@val);
        INSERT IGNORE INTO idents2 VALUE(@val);
    END IF;
    SET want = SUBSTRING(want, CHAR_LENGTH(@val) + seplength + 1);
  END WHILE;

  SET @missing = _missing_constraints(sname, tname);
  SET @extras  = _extra_constraints(sname, tname);
        
  RETURN _are('constraints', @extras, @missing, description);
END //

*/

DROP FUNCTION IF EXISTS constraints_are //
CREATE FUNCTION constraints_are(sname VARCHAR(64), tname VARCHAR(64),  want TEXT, description TEXT)
RETURNS TEXT
DETERMINISTIC
BEGIN
  SET @want = want;
  SET @have = (SELECT GROUP_CONCAT('`', `constraint_name`,'`')
               FROM `information_schema`.`table_constraints`
               WHERE `table_schema` = sname
               AND `table_name` = tname);

  IF description = '' THEN
    SET description = CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
      ' should have the correct Constraints');
  END IF;

  IF NOT _has_table( sname, tname ) THEN
    RETURN CONCAT(ok(FALSE, description), '\n',
      diag(CONCAT('Table ', quote_ident(sname), '.', quote_ident(tname),
        ' does not exist' )));
  END IF;

  CALL _populate_want(@want);
  CALL _populate_have(@have);

  SET @missing = (SELECT _missing(@have)); 
  SET @extras  = (SELECT _extra(@want));

  RETURN _are('constraints', @extras, @missing, description);
END //



DELIMITER ;
