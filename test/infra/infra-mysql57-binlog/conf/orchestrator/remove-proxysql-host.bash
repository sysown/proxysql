#!/bin/bash
mysql -hproxysql -P6032 -uradmin -pradmin -e"select * from mysql_servers" >> /tmp/proxysql.info
