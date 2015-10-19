import os
import os.path
import subprocess
import time
from unittest import TestCase

from docker import Client
from docker.utils import kwargs_from_env
import MySQLdb

from docker_fleet import DockerFleet
from proxysql_ping_thread import ProxySQL_Ping_Thread
from proxysql_tests_config import ProxySQL_Tests_Config

class ProxySQLBaseTest(TestCase):

	SCENARIO = None
	# TODO(andrei): make it possible to turn this to True as well
	INTERACTIVE_TEST = False
	# Custom, per-test, config overrides
	CONFIG_OVERRIDES = {}

	def setUp(self):
		self.docker_fleet = DockerFleet(config_overrides=ProxySQLBaseTest.CONFIG_OVERRIDES)

		# TODO(aismail): revive interactive mode
		#if cls.INTERACTIVE_TEST:
		#	cls._compile_host_proxysql()
		#	cls._connect_gdb_to_proxysql_within_container()
		#self._start_proxysql_pings()

	def tearDown(self):
		# TODO(aismail): revive interactive mode
		#if cls.INTERACTIVE_TEST:
		#	cls._gdb_process.wait()

		# It's essential that pings are stopped __after__ the gdb process has
		# finished. This allows them to keep pinging ProxySQL in the background
		# while it's stuck waiting for user interaction (user interaction needed
		# in order to debug the problem causing it to crash).
		#self._stop_proxysql_pings()
		pass

		shutil.rmtree('/tmp/proxysql-tests/')
	
	@classmethod
	def run_query_proxysql(cls, query, db, 
							hostname=None, port=None,
							username=None, password=None,
							return_result=True):
		"""Run a query against the ProxySQL proxy and optionally return its
		results as a set of rows."""
		credentials = cls.get_proxysql_connection_credentials()
		proxy_connection = MySQLdb.connect(hostname or credentials['hostname'],
											username or credentials['username'],
											password or credentials['password'],
											port=int(port or credentials['port']),
											db=db)
		cursor = proxy_connection.cursor()
		cursor.execute(query)
		if return_result:
			rows = cursor.fetchall()
		cursor.close()
		proxy_connection.close()
		if return_result:
			return rows

	@classmethod
	def run_query_proxysql_admin(cls, query, return_result=True):
		"""Run a query against the ProxySQL admin.

		Note: we do not need to specify a db for this query, as it's always
		against the "main" database.
		TODO(andrei): revisit db assumption once stats databases from ProxySQL
		are accessible via the MySQL interface.
		"""
		credentials = cls.get_proxysql_admin_connection_credentials()
		proxy_connection = MySQLdb.connect(credentials['hostname'],
											credentials['username'],
											credentials['password'],
											port=int(credentials['port']),
											db='main')
		cursor = proxy_connection.cursor()
		cursor.execute(query)
		if return_result:
			rows = cursor.fetchall()
		cursor.close()
		proxy_connection.close()
		if return_result:
			return rows

	@classmethod
	def mysql_connection_ok(cls, hostname, port, username, password, schema):
		"""Checks whether the MySQL server reachable at (hostname, port) is
		up or not. This is useful for waiting for ProxySQL/MySQL containers to
		start up correctly (meaning that the daemons running inside them have
		started to be able to respond to queries).
		"""
		try:
			db = MySQLdb.connect(host=hostname,
									user=username,
									passwd=password,
									db=schema,
									port=int(port))
			cursor = db.cursor() 
			cursor.execute("select @@version_comment limit 1")
			results = cursor.fetchone()
			# Check if anything at all is returned
			if results:
				return True
			else:
				return False
		except MySQLdb.Error, e:
			pass

		return False

	@classmethod
	def wait_for_mysql_connection_ok(cls, hostname, port, username, password,
									max_retries=500, time_between_retries=1):

		retries = 0
		result = False

		while (not result) and (retries < max_retries):
			result = ProxySQLBaseTest.mysql_connection_ok(
				hostname=hostname,
				port=port,
				username=username,
				password=password,
				schema="information_schema"
			)
			if not result:
				retries += 1
				time.sleep(1)
				print("Trying again to connect to %s:%s (retries=%d)" % (hostname, port, retries))

		return result

	@classmethod
	def get_all_mysql_connection_credentials(cls, hostgroup=None):
		# Figure out which are the containers for the specified hostgroup
		mysql_backends = cls._get_mysql_containers()
		mysql_backends_in_hostgroup = []
		for backend in mysql_backends:
			container_name = backend['Names'][0][1:].upper()
			backend_hostgroup = cls._extract_hostgroup_from_container_name(container_name)

			mysql_port_exposed=False
			if not backend.get('Ports'):
				continue
			for exposed_port in backend.get('Ports', []):
				if exposed_port['PrivatePort'] == 3306:
					mysql_port_exposed = True

			if ((backend_hostgroup == hostgroup) or (hostgroup is None)) and mysql_port_exposed:
				mysql_backends_in_hostgroup.append(backend)

		config = ProxySQL_Tests_Config(overrides=cls.CONFIG_OVERRIDES)
		hostname = config.get('ProxySQL', 'hostname')
		username = config.get('ProxySQL', 'username')
		password = config.get('ProxySQL', 'password')

		result = []
		for container in mysql_backends_in_hostgroup:
			for exposed_port in container.get('Ports', []):
				if exposed_port['PrivatePort'] == 3306:
					mysql_port = exposed_port['PublicPort']
					result.append({
						'hostname': hostname,
						'port': mysql_port,
						'username': username,
						'password': password
					})
		return result


	@classmethod
	def get_mysql_connection_credentials(cls, hostgroup=0):
		
		credentials = cls.get_all_mysql_connection_credentials(hostgroup=hostgroup)

		if len(credentials) == 0:
			raise Exception('No backends with a publicly exposed port were '
							'found in hostgroup %d' % hostgroup)

		return random.choice(credentials)

	@classmethod
	def get_proxysql_connection_credentials(cls):
		config = ProxySQL_Tests_Config(overrides=cls.CONFIG_OVERRIDES) 
		return {
			"hostname": config.get("ProxySQL", "hostname"),
			"port": config.get("ProxySQL", "port"),
			"username": config.get("ProxySQL", "username"),
			"password": config.get("ProxySQL", "password")
		}

	@classmethod
	def get_proxysql_admin_connection_credentials(cls):
		config = ProxySQL_Tests_Config(overrides=cls.CONFIG_OVERRIDES) 
		return {
			"hostname": config.get("ProxySQL", "hostname"),
			"port": config.get("ProxySQL", "admin_port"),
			"username": config.get("ProxySQL", "admin_username"),
			"password": config.get("ProxySQL", "admin_password")
		}

	@classmethod
	def run_query_mysql(cls, query, db, return_result=True, hostgroup=0,
					    username=None, password=None):
		"""Run a query against the MySQL backend and optionally return its
		results as a set of rows.

		IMPORTANT: since the queries are actually ran against the MySQL backend,
		that backend needs to expose its MySQL port to the outside through
		docker compose's port mapping mechanism.

		This will actually parse the docker-compose configuration file to
		retrieve the available backends and hostgroups and will pick a backend
		from the specified hostgroup."""

		credentials = ProxySQLBaseTest.get_mysql_connection_credentials()
		mysql_connection = MySQLdb.connect(host=credentials['hostname'],
											user=credentials['username'],
											passwd=credentials['password'],
											port=int(credentials['port']),
											db=db)
		cursor = mysql_connection.cursor()
		cursor.execute(query)
		if return_result:
			rows = cursor.fetchall()
		cursor.close()
		mysql_connection.close()
		if return_result:
			return rows

	@classmethod
	def run_sysbench_proxysql(cls, threads=4, time=60, db="test",
								username=None, password=None, port=None):
		"""Runs a sysbench test with the given parameters against the given
		ProxySQL instance.

		In this case, due to better encapsulation and reduced latency to
		ProxySQL, we are assuming that sysbench is installed on the same
		container with it.
		"""

		proxysql_container_id = ProxySQLBaseTest._get_proxysql_container()['Id']
		config = ProxySQL_Tests_Config(overrides=cls.CONFIG_OVERRIDES)
		hostname = config.get('ProxySQL', 'hostname')
		username = username or config.get('ProxySQL', 'username')
		password = password or config.get('ProxySQL', 'password')
		port = port or config.get('ProxySQL', 'port')

		params = [
				 	"sysbench",
					 "--test=/opt/sysbench/sysbench/tests/db/oltp.lua",
					 "--num-threads=%d" % threads,
					 "--max-requests=0",
					 "--max-time=%d" % time,
					 "--mysql-user=%s" % username,
					 "--mysql-password=%s" % password,
					 "--mysql-db=%s" % db,
					 "--db-driver=mysql",
					 "--oltp-tables-count=4",
					 "--oltp-read-only=on",
					 "--oltp-skip-trx=on",
					 "--report-interval=1",
					 "--oltp-point-selects=100",
					 "--oltp-table-size=400000",
					 "--mysql-host=%s" % hostname,
					 "--mysql-port=%s" % port
				 ]

		cls.run_bash_command_within_proxysql(params + ["prepare"])
		cls.run_bash_command_within_proxysql(params + ["run"])
		cls.run_bash_command_within_proxysql(params + ["cleanup"])

	@classmethod
	def run_bash_command_within_proxysql(cls, params):
		"""Run a bash command given as an array of tokens within the ProxySQL
		container.

		This is useful in a lot of scenarios:
		- running sysbench against the ProxySQL instance
		- getting environment variables from the ProxySQL container
		- running various debugging commands against the ProxySQL instance
		"""

		proxysql_container_id = cls._get_proxysql_container()['Id']
		exec_params = ["docker", "exec", proxysql_container_id] + params
		subprocess.call(exec_params)

	@classmethod
	def _compile_host_proxysql(cls):
		"""Compile ProxySQL on the Docker host from which we're running the
		tests.

		This is used for remote debugging, because that's how the
		gdb + gdbserver pair works:
		- local gdb with access to the binary with debug symbols
		- remote gdbserver which wraps the remote binary so that it can be
		debugged when it crashes.
		"""
		subprocess.call(["make", "clean"])
		subprocess.call(["make"])

	@classmethod
	def _connect_gdb_to_proxysql_within_container(cls):
		"""Connect a local gdb running on the docker host to the remote
		ProxySQL binary for remote debugging.

		This is useful in interactive mode, where we want to stop at a failing
		test and prompt the developer to debug the failing instance.

		Note: gdb is ran in a separate process because otherwise it will block
		the test running process, and it will not be able to run queries anymore
		and make assertions. However, we save the process handle so that we can
		shut down the process later on.
		"""

		cls._gdb_process = subprocess.Popen(["gdb", "--command=gdb-commands.txt",
											 "./proxysql"],
											cwd="./src")

	@classmethod
	def _start_proxysql_pings(cls):
		"""During the running of the tests, the test suite will continuously
		monitor the ProxySQL daemon in order to check that it's up.

		This special thread will do exactly that."""
		config = ProxySQL_Tests_Config(overrides=cls.CONFIG_OVERRIDES)
		cls.ping_thread = ProxySQL_Ping_Thread(config)
		cls.ping_thread.start()

	@classmethod
	def _stop_proxysql_pings(cls):
		"""Stop the special thread which pings the ProxySQL daemon."""
		cls.ping_thread.stop()
		cls.ping_thread.join()