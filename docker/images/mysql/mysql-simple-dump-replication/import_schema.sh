cat /tmp/schema.sql | mysql -h 127.0.0.1 -u root -proot
cat /tmp/my.cnf | sed -e "s/XXXX/$MYSQL_SERVER_ID/" > /etc/mysql/conf.d/my.cnf