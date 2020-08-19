#!/usr/bin/env python

import sys
import subprocess
import json

if len(sys.argv) > 1:
  params=json.loads(sys.argv[1])
  out=''
  try:
    out=subprocess.check_output(['mysql', '-u'+params['user'], '-p'+params['password'], '-h'+params['host'], '-P'+params['port'], '-e', 'select * from stats.stats_memory_metrics'],stderr= subprocess.STDOUT)
  except subprocess.CalledProcessError as e:
    out="Error calling mysql: " + e.output.replace("'", "")
  print('{"params":'+sys.argv[1].encode('string-escape')+', "result":"'+out.encode('string-escape')+'"}')

