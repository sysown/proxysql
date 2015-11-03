set -e
. ./vars

destroy() {
	for i in `seq 1 ${NUMSERVERS}` ; do
		echo -n "Destroying container db$i ... "
		ID=`$USESUDO docker ps -a -f name=db$i -q`
		if [ -z "$ID" ]; then
			echo "not found"
		else
			$USESUDO docker rm db$i
			echo "done"
	fi
	done
}

prepare() {
	for i in `seq 1 ${NUMSERVERS}` ; do
		echo Creating container db$i
		$USESUDO docker create --hostname=db$i --name=db$i -e MYSQL_ROOT_PASSWORD=${ROOTPASS} mysql:latest
		RANID=$(($RANDOM*32768+$RANDOM))
		echo "Using random server_id $RANID"
		sed -e "s/XXXX/$RANID/" mysql_add.cnf_ > mysql_add.cnf
		$USESUDO docker cp mysql_add.cnf db$i:/etc/mysql/conf.d/	
	done
	rm mysql_add.cnf
	for i in `seq 1 ${NUMSERVERS}` ; do
		echo Starting container db$i
		$USESUDO docker start db$i
	done
}

shutdown() {
	for i in `seq 1 ${NUMSERVERS}` ; do
		echo -n "Stopping container db$i ... "
		ID=`$USESUDO docker ps -f name=db$i -q`
		if [ -z "$ID" ]; then
			echo "not found"
		else
			$USESUDO docker stop db$i
			echo "done"
	fi
	done
}

case $1 in
	destroy)
		destroy
		;;
	prepare)
		prepare
		;;
	shutdown)
		shutdown
		;;
	*)
		echo "Invalid argument"
		;;
esac
