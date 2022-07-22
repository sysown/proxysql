#!/usr/bin/env php

<?php

/**
 * Test written in a TAP alike format checking that PHP connector is able to connect to ClickHouse through
 * ProxySQL and that it receives the correct types for the supported types. The test operations are:
 *
 * 1. Create a connection to ClickHouse through ProxySQL using PHP connector.
 * 2. Creates a table holding the supported types: [EventDate,DateTime,TINTYINT(Int8),SMALLINT(Int16),INT(Int32),BIGINT(Int64),FLOAT(Float32),DOUBLE(Float64)]
 * 3. Insert data in the table through: INSERT * SELECT.
 * 4. Query the table data checking:
 *   4.1 - The types correctly matches the expected ones (not mangled into 'string').
 *   4.2 - NULL types are supported and are properly represented and retrieved.
 *   4.3 - Values are properly received, being able to be casted and compared with inserting values.
 */

error_reporting(E_ALL ^ E_NOTICE);

$username="cuser";
$password="cpass";
$port=6090;

#$username="sbtest1";
#$password="sbtest1";
#$port=13306;

$admin_user = getenv("TAP_ADMINUSERNAME");
$admin_user = $admin_user == false ? "admin" : $admin_user;

$admin_pass = getenv("TAP_ADMINPASSWORD");
$admin_pass = $admin_pass == false ? "admin" : $admin_pass;

$admin_port = getenv("TAP_ADMINPORT");
$admin_port = $admin_port == false ? 6032 : $admin_port;

echo ":: Creating ProxySQL Admin connection...".PHP_EOL;
$proxy_admin = new mysqli("127.0.0.1", $admin_user, $admin_pass, "", $admin_port);
if ($proxy_admin->connect_errno) {
    die("PorxySQL connect failed: " . $proxy->connect_error);
}
echo ":: ProxySQL ProxySQL Admin connection completed".PHP_EOL;

echo ":: Creating required users for test...".PHP_EOL;
$proxy_admin->query("INSERT OR REPLACE INTO clickhouse_users (username,password,active,max_connections) VALUES ('{$username}','{$password}',1,100)");
$proxy_admin->query("LOAD CLICKHOUSE USERS TO RUNTIME");
echo ":: Finished creating users".PHP_EOL;

echo ":: Creating ProxySQL connection...".PHP_EOL;
$proxy = new mysqli("127.0.0.1", $username, $password, "", $port);
if ($proxy->connect_errno) {
    die("PorxySQL connect failed: " . $proxy->connect_error);
}
echo ":: ProxySQL connection completed".PHP_EOL;


echo ":: Starting schema and table creation...".PHP_EOL;
if ($port !== 6090) {
	$proxy->query("CREATE DATABASE IF NOT EXISTS test_clickhouse_types_php");
	$proxy->query("USE test_clickhouse_types_php");
	$proxy->query("DROP TABLE IF EXISTS types_table");

	$proxy->query("CREATE TABLE IF NOT EXISTS types_table (EventDate DATE, DateTime DATETIME, col1 TINYINT, col2 SMALLINT, col3 INT, col4 BIGINT, col5 FLOAT, col6 DOUBLE)");

	echo ":: Inserting data directly to MySQL".PHP_EOL;
	$proxy->query("INSERT INTO types_table SELECT NOW(),NOW(),127,-32768,2147483647,9223372036854775807,340282346638528859811704183484516925440.0,340282346638528859811704183484516925440.0");

	echo ":: Fetching inserted data".PHP_EOL;
	$result = $proxy->query("SELECT EventDate,DateTime,col1,col2,col3,col4,col5,round(col6,0) FROM types_table");
	while ($row = mysqli_fetch_row($result)) {
		echo "  * ROW: [";

		foreach ($row as $val) {
			echo $val.",";
		}

		echo "]".PHP_EOL;
	}

	echo ":: Finished operations on MySQL conn".PHP_EOL;
	exit(0);
} else {
	$proxy->query("CREATE DATABASE IF NOT EXISTS test_clickhouse_types_php");
	$proxy->query("USE test_clickhouse_types_php");
	$proxy->query("DROP TABLE IF EXISTS types_table");
	$proxy->query("CREATE TABLE IF NOT EXISTS types_table (EventDate DATE, DateTime DATETIME, col1 UInt8, col2 Int16, col3 Int32, col4 Int64, col5 Nullable(Float32), col6 Float64) ENGINE=MergeTree(EventDate, (EventDate), 8192)");
}

$shortName = exec('date +%Z');
$longName = timezone_name_from_abbr($shortName);
$timezone = timezone_open($longName);
$datetime_db = date_create("now", timezone_open("UTC"));
$timezone_off = timezone_offset_get($timezone, $datetime_db);

$cur_date = date("Y-m-d");
$cur_datetime = date("Y-m-d H:i:s");

echo ":: Schema and table creation completed".PHP_EOL;

$exp_rows = [
	[
		"insert" => "INSERT INTO types_table SELECT '{$cur_date}','{$cur_datetime}',127,-32768,2147483647,9223372036854775807,340282346638528859811704183484516925440,340282346638528859811704183484516925440.0",
		"select" => "SELECT EventDate,DateTime,col1,col2,col3,col4,col5,round(col6,0) FROM types_table",
		"types" => [10, 12, 1, 2, 3, 8, 4, 5],
		"vals" => [$cur_date, $cur_datetime, 127,  -32768, 2147483647, 9223372036854775807, 340282346638528859811704183484516925440, 340282346638528859811704183484516925440.0]
	],
	[
		"insert" => "INSERT INTO types_table SELECT '{$cur_date}','{$cur_datetime}',127,-32768,2147483647,9223372036854775807,1.2,340282346638528859811704183484516925440.0",
		"select" => "SELECT EventDate,DateTime,col1,col2,col3,col4,ROUND(col5,20),round(col6,0) FROM types_table",
		"types" => [10, 12, 1, 2, 3, 8, 4, 5],
		"vals" => [$cur_date, $cur_datetime, 127,  -32768, 2147483647, 9223372036854775807, 1.2, 340282346638528859811704183484516925440.0]
	],
	[
		"insert" => "INSERT INTO types_table SELECT '{$cur_date}','{$cur_datetime}',127,-32768,2147483647,9223372036854775807,NULL,340282346638528859811704183484516925440.0",
		"select" => "SELECT EventDate,DateTime,col1,col2,col3,col4,col5,round(col6,0) FROM types_table",
		"types" => [10, 12, 1, 2, 3, 8, 4, 5],
		"vals" => [$cur_date, $cur_datetime, 127,  -32768, 2147483647, 9223372036854775807, NULL, 340282346638528859811704183484516925440.0]
	]
];

echo ":: Checking expected data definition...".PHP_EOL;

foreach ($exp_rows as $row) {
	$c_row_types = count($row["types"]);
	$c_row_vals = count($row["vals"]);

	if ($c_row_types !== $c_row_vals) {
		echo " * Invalid exp row definition for query '{$row["select"]}'. Expected type count '{$c_row_types}' != '{$c_row_vals}'".PHP_EOL;
		exit(1);
	}
}
echo ":: Checking expected data completed".PHP_EOL;

$exit_code = 0;

$count = 0;
foreach ($exp_rows as $exp_row) {
	echo ":: Performing operation for payload num '$count'".PHP_EOL;
	echo " * Issuing INSERT query '{$exp_row["insert"]}'".PHP_EOL;
	$proxy->query($exp_row["insert"]);

	echo " * Issuing SELECT query '{$exp_row["select"]}'".PHP_EOL;
	$result = $proxy->query($exp_row["select"]);

	/* Get field information for all columns */
	$finfo = $result->fetch_fields();

	echo " * START: Received columns info".PHP_EOL;

	$act_col_defs = array();

	foreach ($finfo as $val) {
	    printf("   - Name:      %s\n",   $val->name);
	    printf("   - Table:     %s\n",   $val->table);
	    printf("   - Max. Len:  %d\n",   $val->max_length);
	    printf("   - Length:    %d\n",   $val->length);
	    printf("   - charsetnr: %d\n",   $val->charsetnr);
	    printf("   - Flags:     %d\n",   $val->flags);
	    printf("   - Type:      %d\n\n", $val->type);

		array_push($act_col_defs, $val);
	}

	echo " * END: Received columns info".PHP_EOL;

	echo ":: Checking fetched data...".PHP_EOL;

	$fetch_rows = array();
	while ($row = mysqli_fetch_row($result)) {
		array_push($fetch_rows, $row);
	}

	$c_exp_rows = 1;
	$c_fetch_rows = count($fetch_rows);

	if ($c_exp_rows !== $c_fetch_rows) {
		echo "Expected received row number doesn't match actual received rows - exp: {$c_exp_rows}, act: {$c_fetch_rows}".PHP_EOL;
		exit(1);
	}

	$types_match = true;
	$type_count = 0;

	foreach ($act_col_defs as $act_col_def) {
		$act_type = $act_col_def->type;
		$exp_type = $exp_row["types"][$type_count];

		$type_match = $act_type === $exp_type;

		if ($type_match) {
			$ok_msg = "ok";
		} else {
			$ok_msg = "not ok";
		}

		echo "  {$ok_msg} -  Type match result for column '{$act_col_def->name}' was '{$type_match}'.";
		echo " ExpType: '{$exp_type}'. ActType '{$act_type}'".PHP_EOL;

		$type_count += 1;
		$types_match &= $type_match;
	}
	echo PHP_EOL;

	$vals_match = true;
	$val_count = 0;
	foreach ($fetch_rows as $row) {
		foreach ($row as $val) {
			$col_name = $act_col_defs[$val_count]->name;

			$exp_val = $exp_row["vals"][$val_count];
			$exp_type = $exp_row["types"][$val_count];

			if (is_null($exp_val) == false) {
				if ($exp_type == 1 || $exp_type == 2 || $exp_type == 3 || $exp_type == 8) {
					$cast_val = (int)$val;
				} else if ($exp_type == 4 | $exp_type == 5) {
					$cast_val = (float)$val;
				} else if ($exp_type == 12) {
					$timestamp = strtotime($val) - $timezone_off;
					$cast_val = date("Y-m-d H:i:s", $timestamp);
				} else {
					$cast_val = $val;
				}
			} else {
				$cast_val = $val;
			}

			$val_match = $exp_val === $cast_val;

			if ($val_match) {
				$ok_msg = "ok";
			} else {
				$ok_msg = "not ok";
			}

			echo "  {$ok_msg} - Value result match for column '{$col_name}' was '{$val_match}'.";
			echo " ExpVal: '{$exp_val}'. ActVal '{$cast_val}'".PHP_EOL;

			$vals_match &= $val_match;
			$val_count += 1;
		}
		$val_count = 0;
		break;
	}

	$count += 1;

	echo ":: Cleaning up table before next queries...".PHP_EOL;
	$proxy->query("ALTER TABLE types_table DELETE WHERE 1=1");

	$result = $proxy->query("SELECT COUNT(*) FROM types_table");
	$row = mysqli_fetch_row($result);
	echo ":: Waiting for table cleaning";

	while ($row[0] != 0) {
		echo ".";
		sleep(1);

		$result = $proxy->query("SELECT COUNT(*) FROM types_table");
		$row = mysqli_fetch_row($result);
	}

	echo PHP_EOL;
	echo ":: Table cleaning completed".PHP_EOL;

	$exit_code |= !($types_match & $vals_match);
}

$proxy->query("DROP DATABASE IF EXISTS test_clickhouse_types_php");
$result->free();

exit($exit_code);

?>
