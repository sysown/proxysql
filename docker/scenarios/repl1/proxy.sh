set -e
. ./vars


destroy() {
	for i in `seq 1 ${NUMPROXIES}` ; do
		echo -n "Destroying container proxy$i ... "
		ID=`$USESUDO docker ps -a -f name=proxy$i -q`
		if [ -z "$ID" ]; then
			echo "not found"
		else
			$USESUDO docker rm proxy$i
			echo "done"
 	 fi
	done
}

prepare() {
	for i in `seq 1 ${NUMPROXIES}` ; do
		echo Creating and running container proxy$i
		$USESUDO docker create --hostname=proxy$i --name=proxy$i renecannao/proxysql:dev /bin/sh -c "while true; do sleep 3600; done"
		$USESUDO docker start proxy$i
	done
}

shutdown() {
	for i in `seq 1 ${NUMPROXIES}` ; do
		echo -n "Stopping container proxy$i ... "
		ID=`$USESUDO docker ps -f name=proxy$i -q`
		if [ -z "$ID" ]; then
			echo "not found"
		else
			$USESUDO docker stop proxy$i
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
