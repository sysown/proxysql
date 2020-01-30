<?php
$servername = getenv("TAP_HOST");
$username = getenv("TAP_USERNAME");
$password = getenv("TAP_PASSWORD");
$dbport = getenv("TAP_PORT");
$dbname = "test";
$num_ps = 2;

if (isset($argv[1])) {
	$np = intval($argv[1]);
	if ($np > 0) {
		$num_ps = $np;
	}
}

$conn = new mysqli($servername, $username, $password, $dbname, $dbport);
if ($conn->connect_error)
	die("Connection failed: " . $conn->connect_error);

	// prepare, bind and execute
	for ($i=0 ; $i<$num_ps; $i++) {
		$stmt[$i] = $conn->prepare("SELECT ".rand().", id,c FROM sbtest1 WHERE id= ?");
		$stmt[$i]->bind_param("i",$id[$i]);
		$id[$i] = $i;
		$stmt[$i]->execute();
		$stmt[$i]->bind_result($d[$i], $e[$i], $c[$i]);
		while ($stmt[$i]->fetch())
			printf("%d %d %s\n", $d[$i] ,$e[$i], $c[$i]);
	}

$stmta = $conn->prepare("SELECT ".rand().", id,c FROM not_exist_table_a WHERE id= ?");
$conn->close();
?>
