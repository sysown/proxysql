#!/usr/bin/env python

# This is a regression test for issues #3992 and #4047. Test checks if queries
# are executed successfully with MariaDB server via PyMySQL client having fast
# forward flag set to true and false.

import pymysql
import sys
import os

proxy_addr = os.environ['TAP_HOST']
proxy_port = int(os.environ['TAP_PORT'])

users = ['mariadbuser', 'mariadbuserff']

db = 'information_schema'

error_count = 0

for user in users:
    connection = pymysql.connect(host=proxy_addr, port=proxy_port, user=user, passwd=user, db=db,
                                 charset='utf8')
    with connection.cursor() as cursor:
        error = None

        try:
            cursor.execute('select * from information_schema.GLOBAL_VARIABLES '
                           'where variable_name =\'sql_mode\';')
        except Exception as e:
            ok_msg = 'not ok'
            error_count += 1
            error = e
        else:
            ok_msg = 'ok'

        print('{} - \'PyMySQL\' select command should be correctly executed. Error was: {}'
              .format(ok_msg, error))

sys.exit(error_count)
