#!/usr/bin/env python
import MySQLdb
import os
import sys
import thread
import time
import signal
import threading

qcounter = 0
qcounter_lock = threading.Lock()
qOK = 0
qOK_lock = threading.Lock()
qERR = 0
qERR_lock = threading.Lock()



# config
mysqluser = os.getenv('MYSQL_USER')
mysqlpass = os.getenv('MYSQL_PASS')
app_ips = os.getenv('APP_IPS')
database_ips = os.getenv('DATABASE_IPS')
proxy_ips = os.getenv('PROXY_IPS')

app_list = []
database_list = []
proxy_list = []

def sigterm_handler(_signo, _stack_frame):
	# Raises SystemExit(0):
	sys.exit(0)



def print_exception(e):
	line_number = sys.exc_info()[2].tb_lineno
	print "Line: " + str(line_number)
	print e

def thread_client_conn(app_ip):
	conn = None
	try:
		conn = MySQLdb.connect(host=app_ip, port=6033, user=mysqluser, passwd=mysqlpass)
		#conn = MySQLdb.connect(host="172.17.0.139", port=6033, user=mysqluser, passwd=mysqlpass)

		cur = conn.cursor()
		while True:
#		for x in range(0, 100):
			global qcounter
			global qOK
			global qERR
			qcounter_lock.acquire()
			qcounter += 1
			x = qcounter
			qcounter_lock.release()
			time.sleep(1)
			query = "SELECT " + str(x)
			try:
				cur.execute(query)
				res = cur.fetchone()
#				print res[0]
				qOK_lock.acquire()
				qOK += 1
				qOK_lock.release()
			except Exception, e:
				qERR_lock.acquire()
				qERR += 1
				qERR_lock.release()
				#print "Query failed"
	except Exception, e:
		print "Failed to connect"
		print_exception(e)
	finally:
		if conn:
			conn.close()

def main():
#	signal.signal(signal.SIGTERM, sigterm_handler)
	if not mysqluser or not mysqlpass or not database_ips or not app_ips or not proxy_ips:
		sys.exit("environment incorrectly configured; aborting!")
	app_list = app_ips.split()	
	database_list = database_ips.split()	
	proxy_list = proxy_ips.split()	
	try:
		threads = [threading.Thread(target=thread_client_conn) for t in range(10)]
		for t in threads:
			t.setDaemon(True)
			t.start()
#		for t in threads:
#			t.join()
		while True:
			time.sleep(1)
	finally:
		print "Queries result. OK: " , qOK , " ERR: " , qERR 

if __name__ == '__main__':
    main()
