#!/usr/bin/env python
#
#./scripts/export_users.py '{"db":{"user":"root", "password":"a", "port":"3306", "host":"127.0.0.1"},"admin":{"user":"admin","password":"admin","port":"6032","host":"127.0.0.1"}}'
#

import sys
import subprocess
import json
from MySQLdb import _mysql

if len(sys.argv) > 1:
  params=json.loads(sys.argv[1])
  db_mysql=_mysql.connect(host=params['db']['host'],user=params['db']['user'],passwd=params['db']['password'],port=int(params['db']['port']))
  db_mysql.query('SELECT user, authentication_string from mysql.user')
  records=db_mysql.store_result().fetch_row(maxrows=0)
  db_proxy_admin=_mysql.connect(host=params['admin']['host'],user=params['admin']['user'],passwd=params['admin']['password'],port=int(params['admin']['port']))
  for row in records:
    db_proxy_admin.query('INSERT OR REPLACE INTO mysql_users (username, password) values ("'+str(row[0])+'","'+str(row[1])+'")')

  result='{"num_records":"'+str(len(records))+'"}'
  try:
    subprocess.check_output(['mysql', '-u'+params['admin']['user'], '-p'+params['admin']['password'], '-h'+params['admin']['host'], '-P'+params['admin']['port'], '-e', 'load mysql users to runtime'],stderr= subprocess.STDOUT)
  except subprocess.CalledProcessError as e:
    result='"Error calling mysql: ' + e.output.replace("'", "") + '"'

  print('{"params":'+str(sys.argv[1])+', "result":'+result+'}')

