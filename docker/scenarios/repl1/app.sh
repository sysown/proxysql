set -e
. ./vars

destroy() {
	for i in `seq 1 ${NUMAPPS}` ; do
		echo -n "Destroying container app$i ... "
		ID=`$USESUDO docker ps -a -f name=app$i -q`
		if [ -z "$ID" ]; then
			echo "not found"
		else
			$USESUDO docker rm app$i
			echo "done"
		fi
	done
}

prepare() {
	for i in `seq 1 ${NUMAPPS}` ; do
		echo Creating and running container app$i
		$USESUDO docker create --hostname=app$i --name=app$i renecannao/proxysql:dev /bin/sh -c "while true; do sleep 3600; done"
		$USESUDO docker start app$i
	done
}

shutdown() {
	for i in `seq 1 ${NUMAPPS}` ; do
		echo -n "Stopping container app$i ... "
		ID=`$USESUDO docker ps -f name=app$i -q`
		if [ -z "$ID" ]; then
			echo "not found"
		else
			$USESUDO docker stop app$i
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
