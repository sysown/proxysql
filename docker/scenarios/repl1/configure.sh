set -e
. ./vars

declare -a AIPS
declare -a DIPS
declare -a PIPS


echo Retrieving IPs
for i in `seq 1 ${NUMSERVERS}` ; do
	DIPS[$i]=`$USESUDO docker inspect -f '{{.NetworkSettings.IPAddress}}' db$i`
done


configure_mysql() {
	echo Setting my.cnf
	for i in `seq 1 ${NUMSERVERS}` ; do
		$USESUDO docker exec db$i bash -c "echo -e \"[client]\npassword=$ROOTPASS\" > /root/.my.cnf"
	done
	
	
	echo "retrieving GTID executed"
	GES=`$USESUDO docker exec -it db1 mysql -e "SHOW GLOBAL VARIABLES LIKE 'gtid_executed'" -NB | awk '{print $2}'`
	
	echo Setting grants on db1
	$USESUDO docker exec db1 mysql -u root -e "GRANT ALL PRIVILEGES ON *.* TO root@$DOCNET IDENTIFIED BY \"$ROOTPASS\" WITH GRANT OPTION"
	for h in ${DIPS[*]} ; do
		$USESUDO docker exec db1 mysql -u root -e "GRANT ALL PRIVILEGES ON *.* TO root@$h IDENTIFIED BY \"$ROOTPASS\" WITH GRANT OPTION"
		$USESUDO docker exec db1 mysql -u root -e "GRANT REPLICATION SLAVE ON *.* TO replication@$h IDENTIFIED BY \"$REPLPASS\""
	done
	
	echo Setting replication
	for i in `seq 2 ${NUMSERVERS}` ; do
		$USESUDO docker exec db$i mysql -u root -e "STOP SLAVE"
		$USESUDO docker exec db$i mysql -u root -e "RESET SLAVE"
		$USESUDO docker exec db$i mysql -u root -e "RESET MASTER"
		$USESUDO docker exec db$i mysql -u root -e "SET GLOBAL gtid_purged=\"$GES\""
		$USESUDO docker exec db$i mysql -u root -e "CHANGE MASTER TO MASTER_HOST=\"${DIPS[1]}\" , MASTER_USER='replication', MASTER_PASSWORD=\"$REPLPASS\" , MASTER_AUTO_POSITION=1"
		$USESUDO docker exec db$i mysql -u root -e "START SLAVE"
	done
}

install_proxy_app() {
	echo "Installing standard ProxySQL on apps"
	for i in `seq 1 ${NUMAPPS}` ; do
		$USESUDO docker cp proxysql*deb app$i:/tmp
		$USESUDO docker exec app$i sh -c "dpkg -i /tmp/proxysql*deb"
	done
}

install_proxy_cluster() {
	echo "Installing standard ProxySQL on cluster layer"
	for i in `seq 1 ${NUMPROXIES}` ; do
		$USESUDO docker cp proxysql*deb proxy$i:/tmp
		$USESUDO docker exec proxy$i sh -c "dpkg -i /tmp/proxysql*deb"
	done
## This is optional
	echo "Replacing binaries in cluster layer"
	for i in `seq 1 ${NUMPROXIES}` ; do
  	$USESUDO docker cp proxysql proxy$i:/usr/bin/proxysql
	done
}

start_proxy_cluster() {
	echo "Starting ProxySQL in cluster layer"
	for i in `seq 1 ${NUMPROXIES}` ; do
		$USESUDO docker exec proxy$i service proxysql start
		sleep 3 # wait some time for proxysql to start
		## this is already an important testing: proxysql allows to change listening port at runtime
		$USESUDO docker exec proxy$i mysql -u admin -padmin -h 127.0.0.1 -P6032 -e "UPDATE global_variables SET variable_value='0.0.0.0:6032' WHERE variable_name='admin-mysql_ifaces'; SAVE ADMIN VARIABLES TO DISK; LOAD ADMIN VARIABLES TO RUNTIME;"
	done
	sleep 1 # wait some time for proxysql to bind on new port
}

start_proxy_app() {
	echo "Starting ProxySQL on Apps"
	for i in `seq 1 ${NUMAPPS}` ; do
	  $USESUDO docker exec app$i service proxysql start
		sleep 3 # wait some time for proxysql to start
		## this is already an important testing: proxysql allows to change listening port at runtime
		$USESUDO docker exec app$i mysql -u admin -padmin -h 127.0.0.1 -P6032 -e "UPDATE global_variables SET variable_value='0.0.0.0:6032' WHERE variable_name='admin-mysql_ifaces'; SAVE ADMIN VARIABLES TO DISK; LOAD ADMIN VARIABLES TO RUNTIME;"
	done
	sleep 1 # wait some time for proxysql to bind on new port
}


configure_proxy_app() {
	echo Configure ProxySQL on Apps
	for i in ${AIPS[*]} ; do
		echo "DELETE FROM mysql_servers;" | mysql -u admin -h $i -P6032
		for h in ${PIPS[*]} ; do
			echo "INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (0,\"$h\",6033);" | mysql -u admin -h $i -P6032
		done
		echo "LOAD MYSQL SERVERS TO RUNTIME; SAVE MYSQL SERVERS TO DISK;" | mysql -u admin -h $i -P6032
	echo "DELETE FROM mysql_users; INSERT INTO mysql_users (username, password) VALUES ('root',\"$ROOTPASS\"); LOAD MYSQL USERS TO RUNTIME; SAVE MYSQL USERS TO DISK;" | mysql -u admin -h $i -P6032
	done
}

configure_proxy_cluster() {
	echo Configure ProxySQL on Cluster Layer
	for i in ${PIPS[*]} ; do
		echo "DELETE FROM mysql_servers;" | mysql -u admin -h $i -P6032
		for h in ${DIPS[*]} ; do
			echo "INSERT INTO mysql_servers (hostgroup_id, hostname, port) VALUES (0,\"$h\",3306);" | mysql -u admin -h $i -P6032
		done
		echo "LOAD MYSQL SERVERS TO RUNTIME; SAVE MYSQL SERVERS TO DISK;" | mysql -u admin -h $i -P6032
	echo "DELETE FROM mysql_users; INSERT INTO mysql_users (username, password) VALUES ('root',\"$ROOTPASS\"); LOAD MYSQL USERS TO RUNTIME; SAVE MYSQL USERS TO DISK;" | mysql -u admin -h $i -P6032
	done
}

echo Retrieving Application IPs
for i in `seq 1 ${NUMAPPS}` ; do
  AIPS[$i]=`$USESUDO docker inspect -f '{{.NetworkSettings.IPAddress}}' app$i`
done

echo Retrieving ProxySQL IPs
for i in `seq 1 ${NUMPROXIES}` ; do
  PIPS[$i]=`$USESUDO docker inspect -f '{{.NetworkSettings.IPAddress}}' proxy$i`
done


#configure_mysql
#install_proxy_app
#install_proxy_cluster
#start_proxy_cluster
#start_proxy_app

export MYSQL_PWD="admin"

echo APP IPs: ${AIPS[*]}
echo ProxySQL IPs: ${PIPS[*]}

configure_proxy_app
configure_proxy_cluster
