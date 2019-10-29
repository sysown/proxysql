-- 5.6.4 version file
-- Added datetime_precision

USE tap;

DELIMITER //

/****************************************************************************/
-- CHECK FOR SCHEMA CHANGES
-- Get the SHA-1 from the table definition and it's constituent schema objects 
-- to for a simple test for changes. Excludes partitioning since the names might
-- change over the course of time through normal DLM operations.
-- Allows match against partial value to save typing as
-- 8 characters will give 16^8 combinations.

DROP FUNCTION IF EXISTS _table_sha1 //
CREATE FUNCTION _table_sha1(sname VARCHAR(64), tname VARCHAR(64))
RETURNS CHAR(40)
DETERMINISTIC
BEGIN
  DECLARE ret CHAR(40);

  SELECT SHA1(GROUP_CONCAT(sha)) INTO ret
  FROM 
    (   
      (SELECT SHA1( -- COLUMNS
        GROUP_CONCAT(
          SHA1(
            -- > 5.6.4 version
	    CONCAT_WS('',`table_catalog`,`table_schema`,`table_name`,`column_name`,
              `ordinal_position`,`column_default`,`is_nullable`,`data_type`,
              `character_set_name`,`character_maximum_length`,`character_octet_length`,
              `numeric_precision`,`numeric_scale`,`datetime_precision`,`collation_name`,
              `column_type`,`column_key`,`extra`,`privileges`,`column_comment`)
          ))) sha
      FROM `information_schema`.`columns`
      WHERE `table_schema` = sname
      AND `table_name` = tname
      ORDER BY `table_name` ASC,`column_name` ASC)
  UNION ALL
      (SELECT SHA1( -- CONSTRAINTS
        GROUP_CONCAT(
          SHA1(
            CONCAT_WS('',`constraint_catalog`,`constraint_schema`,`constraint_name`,
            `unique_constraint_catalog`,`unique_constraint_schema`,`unique_constraint_name`,
            `match_option`,`update_rule`,`delete_rule`,`table_name`,`referenced_table_name`)
      ))) sha
      FROM `information_schema`.`referential_constraints`
      WHERE `constraint_schema` = sname
      AND `table_name` = tname
      ORDER BY `table_name` ASC,`constraint_name` ASC)
  UNION ALL
      (SELECT SHA1( -- INDEXES
        GROUP_CONCAT(
          SHA1(
            CONCAT_WS('',`table_catalog`,`table_schema`,`table_name`,`non_unique`,
              `index_schema`,`index_name`,`seq_in_index`,`column_name`,`collation`,`cardinality`,
              `sub_part`,`packed`,`nullable`,`index_type`,`comment`,`index_comment`)
      ))) sha
      FROM `information_schema`.`statistics`
      WHERE `table_schema` = sname
      AND `table_name` = tname
      ORDER BY `table_name` ASC,`index_name` ASC,`seq_in_index` ASC)
  UNION ALL
      (SELECT SHA1( -- TRIGGERS
        GROUP_CONCAT(
          SHA1(
           CONCAT_WS('',`trigger_catalog`,`trigger_schema`,`trigger_name`,`event_manipulation`,
            `event_object_catalog`,`event_object_schema`,`event_object_table`,`action_order`,
            `action_condition`,`action_statement`,`action_orientation`,`action_timing`,
            `action_reference_old_table`,`action_reference_new_table`,`action_reference_old_row`,
            `action_reference_new_row`,`sql_mode`,`definer`,`database_collation`)
      ))) sha
      FROM `information_schema`.`triggers`
      WHERE `trigger_schema` = sname
      AND `event_object_table` = tname
      ORDER BY `event_object_table` ASC,`trigger_name` ASC)
  ) objects;

  RETURN COALESCE(ret, NULL);
END //

DELIMITER ;
