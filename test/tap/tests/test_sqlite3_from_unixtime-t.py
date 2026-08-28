#!/usr/bin/env python3

import os
import pymysql
import time

def get_env_with_default(key, default):
	return os.environ.get(key, default)

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

# Connection arguments from environment variables (with defaults for local testing)
admin_conn_args = {
	'host': get_env_with_default('TAP_ADMINHOST', '127.0.0.1'),
	'port': int(get_env_with_default('TAP_ADMINPORT', '6032')),
	'user': get_env_with_default('TAP_ADMINUSERNAME', 'radmin'),
	'passwd': get_env_with_default('TAP_ADMINPASSWORD', 'radmin')
}
mysql_conn_args = {
	'host': get_env_with_default('TAP_HOST', '127.0.0.1'),
	'port': int(get_env_with_default('TAP_PORT', '6033')),
	'user': get_env_with_default('TAP_USERNAME', 'root'),
	'passwd': get_env_with_default('TAP_PASSWORD', 'root')
}
puser_conn_args = {
	'host': get_env_with_default('TAP_HOST', '127.0.0.1'),
	'port': int(get_env_with_default('TAP_PORT', '6033')),
	'user': get_env_with_default('TAP_USERNAME', 'user'),
	'passwd': get_env_with_default('TAP_PASSWORD', 'user')
}


if __name__ == '__main__':
	# Verbose test header
	print("================================================================================")
	print("Test: test_sqlite3_from_unixtime-t")
	print("================================================================================")
	print("This test verifies the SQLite3 Server's FROM_UNIXTIME function integration")
	print("with ProxySQL admin interface.")
	print("")
	print("Test scenarios:")
	print("  - FROM_UNIXTIME() with no arguments returns NULL")
	print("  - FROM_UNIXTIME(0) returns '1970-01-01 00:00:00'")
	print("  - FROM_UNIXTIME(-1) returns '1969-12-31 23:59:59'")
	print("  - FROM_UNIXTIME(2147483647) handles 32-bit timestamp limit")
	print("  - FROM_UNIXTIME(2147483648) handles 64-bit timestamps")
	print("  - FROM_UNIXTIME on monitor.mysql_server_ping_log data")
	print("")
	print("Connection parameters:")
	print("  - Admin Host: {}".format(admin_conn_args['host']))
	print("  - Admin Port: {}".format(admin_conn_args['port']))
	print("  - Admin User: {}".format(admin_conn_args['user']))
	print("================================================================================")
	print("")

	print("Attempting to connect to admin interface at {}:{}".format(admin_conn_args['host'], admin_conn_args['port']))
	padmin_conn = open_mysql_conn(**admin_conn_args)
	print("Successfully connected to admin interface")
	print("")

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
