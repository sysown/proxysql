#!/usr/bin/env python3

import pymysql
import time

def open_mysql_conn(host, port=3306, user=None, passwd=None, timeout=60):
	conn = None
	try:
		if user is None and passwd is None:
			conn = pymysql.connect( host=host, port=port, read_default_group='client',
									connect_timeout=timeout, cursorclass=pymysql.cursors.DictCursor,
									defer_connect=True)
		else:
			conn = pymysql.connect( host=host, port=port, user=user, passwd=passwd,
									connect_timeout=timeout, cursorclass=pymysql.cursors.DictCursor,
									defer_connect=True)
		conn.client_flag |= pymysql.constants.CLIENT.MULTI_STATEMENTS
		conn.connect()
		conn.autocommit(True)
	except Exception as e:
		print(e)
		raise

	return conn

def padmin_command(command, display=False):
	with padmin_conn.cursor() as cursor:
		cursor.execute(command)
		result = cursor.fetchall()
	if display:
		print(result)
	return result

def pmysql_command(command, display=False):
	with pmysql_conn.cursor() as cursor:
		cursor.execute(command)
		result = cursor.fetchall()
	if display:
		print(result)
	return result

admin_conn_args = { 'host':'127.0.0.1', 'port':6032, 'user':'admin', 'passwd':'admin' }
mysql_conn_args = { 'host':'127.0.0.1', 'port':6033, 'user':'root',  'passwd':'root' }
puser_conn_args = { 'host':'127.0.0.1', 'port':6033, 'user':'user',  'passwd':'user' }


if __name__ == '__main__':

	padmin_conn = open_mysql_conn(**admin_conn_args)

	# test edge cases
	assert padmin_command('SELECT from_unixtime();', display=True) == [{'from_unixtime()': None}]
	assert padmin_command('SELECT from_unixtime(0);', display=True) == [{'from_unixtime(0)': '1970-01-01 00:00:00'}]
	assert padmin_command('SELECT from_unixtime(-1);', display=True) == [{'from_unixtime(-1)': '1969-12-31 23:59:59'}]
	assert padmin_command('SELECT from_unixtime(2147483647);', display=True) == [{'from_unixtime(2147483647)': '2038-01-19 03:14:07'}]
	assert padmin_command('SELECT from_unixtime(2147483648);', display=True) == [{'from_unixtime(2147483648)': '2038-01-19 03:14:08'}]
	# test values from monitor.mysql_server_ping_log
	results = padmin_command('SELECT time_start_us/1000000, from_unixtime(time_start_us/1000000) FROM monitor.mysql_server_ping_log;', display=True)
	for res in results:
		assert time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(int(res['time_start_us/1000000']))) == res['from_unixtime(time_start_us/1000000)']

	# PASS
	exit(0)
