while true; do
    echo "Stoping the host"
    docker stop reproduce_pxc-node2_1

    while true; do
        RESULT=`docker-compose exec proxysql mysql -h127.0.0.1 -P6032 -uadmin -padmin -e "select * from myhgm.mysql_servers where hostgroup_id = 3308 and hostname = '172.28.1.2' and status = 0;" | tail -n +2`
        if [ -z "$RESULT" ]
        then
            break
        fi
        echo "The host isn't stoped, sleeping 5 seconds"
        sleep 5
    done

    echo "Starting the host"
    docker start reproduce_pxc-node2_1
    while true; do
        RESULT=`docker-compose exec proxysql mysql -h127.0.0.1 -P6032 -uadmin -padmin -e "select * from myhgm.mysql_servers where hostgroup_id = 3308 and hostname = '172.28.1.2' and status = 0;" | tail -n +2`
        if [ ! -z "$RESULT" ]
        then
            break
        fi
        echo "The host isn't ready, sleeping 5 seconds"
        sleep 5
    done
done
