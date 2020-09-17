while true; do
    mysql -h 127.0.0.1 -P 3302 -u root -ptoor -e 'create database if not exists test_me; drop table test_me.sbtest'
    sysbench --mysql-host=127.0.0.1 --mysql-user=root --mysql-password=toor --mysql-port=3302 --mysql-db=test_me --oltp-table-size=1000000 --test=oltp prepare
    sysbench --mysql-host=127.0.0.1 --mysql-user=root --mysql-password=toor --mysql-port=3302 --mysql-db=test_me --oltp-table-size=1000000 --max-time=999999 --num-threads=50 --max-requests=99999999 --test=oltp --db-ps-mode=disable --oltp-reconnect-mode=random run
done
