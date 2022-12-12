#!/usr/bin/env php
<?php

/**
 * @file reg_test_stmt_resultset_err_no_rows.php
 * @brief Checks handling of STMT binary resultsets with errors without rows.
 * @details Performs an analogous logic to test 'reg_test_stmt_resultset_err_no_rows-t'
 */

error_reporting(E_ALL ^ E_NOTICE);

$res = 0;
$cases = 0;

function ok($sucess, $message) {
    global $res;
    global $cases;

    $ok_msg = "";

    if ($sucess) {
        $ok_msg = "ok";
    } else {
        $ok_msg = "not ok";
        $res = 1;
    }

    $cases += 1;

    echo $ok_msg, " - ", $message, "\n";
}

function diag($message) {
    echo ":: ", $message, "\n";
}

$test_cases = [[true, '$.', ""], [true, '$', "[\"a\", \"b\"]"], [true, '$.', ""], [false, '$.b', "[\"c\"]"]];
$plan_tests =  count($test_cases);

echo "1..".$plan_tests.PHP_EOL;

$admin_user = getenv("TAP_ADMINUSERNAME");
$admin_user = $admin_user == false ? "admin" : $admin_user;

$admin_pass = getenv("TAP_ADMINPASSWORD");
$admin_pass = $admin_pass == false ? "admin" : $admin_pass;

$admin_port = getenv("TAP_ADMINPORT");
$admin_port = $admin_port == false ? 6032 : $admin_port;

$username = getenv("TAP_USERNAME");
$username = $username == false ? "root" : $username;

$password = getenv("TAP_PASSWORD");
$password = $password == false ? "root" : $password;

$port = getenv("TAP_PORT");
$port = $port == false ? "6033" : $port;

echo ":: Creating ProxySQL Admin connection...".PHP_EOL;
$proxy_admin = new mysqli("127.0.0.1", $admin_user, $admin_pass, "", $admin_port);
if ($proxy_admin->connect_errno) {
    die("PorxySQL connect failed: " . $proxy->connect_error);
}
echo ":: ProxySQL Admin connection completed".PHP_EOL;

echo ":: Creating ProxySQL connection...".PHP_EOL;
$proxy = new mysqli("127.0.0.1", $username, $password, "", $port);
if ($proxy->connect_errno) {
    die("PorxySQL connect failed: " . $proxy->connect_error);
}
echo ":: ProxySQL connection completed".PHP_EOL;

$stmt = $proxy->prepare("SELECT json_keys('{\"a\": 1, \"b\": {\"c\": 30}}', ?)");

foreach ($test_cases as $test_case) {
    [$exp_fail, $param, $exp_res] = $test_case;

    try {
        echo ":: Binding param: '", $param, "'\n";

        $sql_select_limit = $param;
        $stmt->bind_param('s', $sql_select_limit);

        $stmt->execute();

        $result = $stmt->get_result();

        if ($result->num_rows == 1) {
            $row = $result->fetch_array(MYSQLI_NUM);
            $field_count = $result->field_count;
            $field_val = $row[0];

            ok(
                $field_count == 1 && $field_val == $exp_res,
                "Fetch value should match expected - ".
                    "FieldCount: '".$field_count."', Exp: '".$exp_res."', Act: '".$field_val
            );
        } else {
            diag("Received invalid number of rows '".$result->num_rows."'");
        }
    } catch (Exception $e) {
        ok($exp_fail == true, "Operation failed with error: '".$e->getMessage()."'");
    }
}

$success = ($plan_tests == $cases && $res == 0);
$exit_code = $success == false ? 1 : 0;

exit($exit_code);
?>
