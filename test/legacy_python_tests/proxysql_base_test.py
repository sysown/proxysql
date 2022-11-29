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

	def run_sysbench_proxysql(self, threads=4, time=60, db="test",
								username=None, password=None, port=None):
		"""Runs a sysbench test with the given parameters against the given
		ProxySQL instance.

		In this case, due to better encapsulation and reduced latency to
		ProxySQL, we are assuming that sysbench is installed on the same
		container with it.
		"""

		config = ProxySQL_Tests_Config(overrides=ProxySQLBaseTest.CONFIG_OVERRIDES)
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

		self.run_bash_command_within_proxysql(params + ["prepare"])
		self.run_bash_command_within_proxysql(params + ["run"])
		self.run_bash_command_within_proxysql(params + ["cleanup"])

	def run_bash_command_within_proxysql(self, params):
		"""Run a bash command given as an array of tokens within the ProxySQL
		container.

		This is useful in a lot of scenarios:
		- running sysbench against the ProxySQL instance
		- getting environment variables from the ProxySQL container
		- running various debugging commands against the ProxySQL instance
		"""

		proxysql_container_id = self.docker_fleet.get_proxysql_container()
		exec_params = ["docker", "exec", proxysql_container_id] + params
		subprocess.call(exec_params)

	def _compile_host_proxysql(self):
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

	def _connect_gdb_to_proxysql_within_container(self):
		"""Connect a local gdb running on the docker host to the remote
		ProxySQL binary for remote debugging.

		This is useful in interactive mode, where we want to stop at a failing
		test and prompt the developer to debug the failing instance.

		Note: gdb is ran in a separate process because otherwise it will block
		the test running process, and it will not be able to run queries anymore
		and make assertions. However, we save the process handle so that we can
		shut down the process later on.
		"""

		self._gdb_process = subprocess.Popen(["gdb", "--command=gdb-commands.txt",
												"./proxysql"],
												cwd="./src")

	def _start_proxysql_pings(self):
		"""During the running of the tests, the test suite will continuously
		monitor the ProxySQL daemon in order to check that it's up.

		This special thread will do exactly that."""
		config = ProxySQL_Tests_Config(overrides=ProxySQLBaseTest.CONFIG_OVERRIDES)
		self.ping_thread = ProxySQL_Ping_Thread(config)
		self.ping_thread.start()

	def _stop_proxysql_pings(self):
		"""Stop the special thread which pings the ProxySQL daemon."""
		self.ping_thread.stop()
		self.ping_thread.join()

	def run_query_proxysql(self, query, db, 
							hostname=None, port=None,
							username=None, password=None,
							return_result=True):
		return self.docker_fleet.run_query_proxysql(query, db,
													hostname, port,
													username, password,
													return_result)

	def run_query_proxysql_admin(self, query, return_result=True):
		return self.docker_fleet.run_query_proxysql_admin(query, return_result)

	def run_query_mysql(self, query, db, return_result=True, hostgroup=0,
					    username=None, password=None):
		return self.docker_fleet.run_query_mysql(query, db, return_result,
													hostgroup,
													username, password)

	def run_query_mysql_container(self, query, db, container_id, return_result=True):
		return self.docker_fleet.run_query_mysql_container(query=query,
															db=db,
															container_id=container_id,
															return_result=return_result)

	def get_proxysql_container(self):
		return self.docker_fleet.get_proxysql_container()

	def get_mysql_containers(self, hostgroup=0):
		return self.docker_fleet.get_mysql_containers(hostgroup=hostgroup)

	def get_environment_variables_from_container(self, container_id):
		return self.docker_fleet.get_environment_variables_from_container(container_id)

	def get_tests_config(self):
		return ProxySQL_Tests_Config(overrides=ProxySQLBaseTest.CONFIG_OVERRIDES)

	def docker_inspect(self, container_id):
		return self.docker_fleet.docker_inspect(container_id)

	def run_in_docker_scenarios(self, f, scenarios=[], proxysql_filters={}, mysql_filters={}):
		"""Runs a function in a number of docker scenarios.

		This is a helper for running your test assertions against different
		configurations without having to go the extra mile.
		"""
		
		print('##################### Running test %r' % f)

		scenarios = self.docker_fleet.generate_scenarios(scenarios=scenarios,
															proxysql_filters=proxysql_filters,
															mysql_filters=mysql_filters)
		committed_images = set()
		copy_folder = True
		delete_folder = True
		for (i, scenario) in enumerate(scenarios):
			print("******** Running scenario %s (proxysql_image=%s, mysql_image=%s)" % 
					(scenario['scenario_dir'], scenario['proxysql_image'], scenario['mysql_image']))
			copy_folder = (i == 0)
			delete_folder = (i == len(scenarios) - 1)

			folder = self.docker_fleet.start_temp_scenario(scenario, copy_folder)
			f()
			if scenario['proxysql_image'] not in committed_images:
				self.docker_fleet.commit_proxysql_image(scenario['proxysql_image'])
				committed_images.add(scenario['proxysql_image'])
			if scenario['mysql_image'] not in committed_images:
				self.docker_fleet.commit_proxysql_image(scenario['mysql_image'])
				committed_images.add(scenario['mysql_image'])
			self.docker_fleet.stop_temp_scenario(folder, delete_folder)