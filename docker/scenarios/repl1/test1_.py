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


def sigterm_handler(_signo, _stack_frame):
	# Raises SystemExit(0):
	sys.exit(0)



def print_exception(e):
	line_number = sys.exc_info()[2].tb_lineno
	print "Line: " + str(line_number)
	print e

def thread_client_conn():
	conn = None
	try:
		conn = MySQLdb.connect(host="127.0.0.1", port=6033, user=mysqluser, passwd=mysqlpass)
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
	signal.signal(signal.SIGTERM, sigterm_handler)
	if not mysqluser or not mysqlpass:
		sys.exit("environment incorrectly configured; aborting!")
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
