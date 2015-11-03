set -e
. ./vars

declare -a AIPS
declare -a DIPS
declare -a PIPS


echo Retrieving IPs
for i in `seq 1 ${NUMSERVERS}` ; do
	DIPS[$i]=`$USESUDO docker inspect -f '{{.NetworkSettings.IPAddress}}' db$i`
done

echo Retrieving Application IPs
for i in `seq 1 ${NUMAPPS}` ; do
  AIPS[$i]=`$USESUDO docker inspect -f '{{.NetworkSettings.IPAddress}}' app$i`
done

echo Retrieving ProxySQL IPs
for i in `seq 1 ${NUMPROXIES}` ; do
  PIPS[$i]=`$USESUDO docker inspect -f '{{.NetworkSettings.IPAddress}}' proxy$i`
done


configure_ro_dbs() {
	export MYSQL_PWD=$ROOTPASS
	for i in ${DIPS[*]} ; do
		echo "Configuring read_only=$1 on $i"
		mysql -u root -h $i -P3306 -e "SET GLOBAL read_only=$1"
	done
}


dump_ro_proxies() {
	echo "Dumping mysql_servers table"
	for i in ${PIPS[*]} ; do
		mysql -u admin -h $i -P6032 -e "SELECT * FROM mysql_servers"
	done
}

configure_repl_hostgroup() {
	echo Configure Replication topology on Cluster Layer
	for i in ${PIPS[*]} ; do
		echo "Processing ProxySQL on $i"
		echo "Configuring monitoring users"
		echo "UPDATE global_variables SET variable_value='root' WHERE variable_name='mysql-monitor_username';" | mysql -u admin -h $i -P6032
		echo "UPDATE global_variables SET variable_value=\"$ROOTPASS\" WHERE variable_name='mysql-monitor_password';" | mysql -u admin -h $i -P6032
		echo "LOAD MYSQL VARIABLES TO RUNTIME" | mysql -u admin -h $i -P6032
		echo "SAVE MYSQL VARIABLES TO DISK" | mysql -u admin -h $i -P6032
		echo "Setting hostgroups"
		echo "DELETE FROM mysql_replication_hostgroups;" | mysql -u admin -h $i -P6032
		echo "INSERT INTO mysql_replication_hostgroups VALUES(0,1);" | mysql -u admin -h $i -P6032
		echo "LOAD MYSQL SERVERS TO RUNTIME" | mysql -u admin -h $i -P6032
		echo "SAVE MYSQL SERVERS TO DISK" | mysql -u admin -h $i -P6032
	done
}


export MYSQL_PWD="admin"
configure_repl_hostgroup

configure_ro_dbs 0
export MYSQL_PWD="admin"
echo "ProxySQL should reconfigure the servers"
echo "All servers must be at least in hostgroup 0 , and optionally in hostgroup 1"
echo "We sleep few seconds..."
sleep 5
dump_ro_proxies

configure_ro_dbs 1
export MYSQL_PWD="admin"
echo "ProxySQL should reconfigure the servers"
echo "All servers must be in hostgroup 1 , **NONE** in hostgroup 0"
echo "We sleep few seconds..."
sleep 5
dump_ro_proxies





#echo APP IPs: ${AIPS[*]}
#echo ProxySQL IPs: ${PIPS[*]}


configure_repl_hostgroup

