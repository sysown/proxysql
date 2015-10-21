from proxysql_base_test import ProxySQLBaseTest

# TODO(aismail): re-enable this test once ProxySQLBaseTest.run_in_docker_scenarios
# gets some filtering capabilities on which types of scenarios to run, etc.
"""
class ConfigFileParsingTest(ProxySQLBaseTest):
	
	# The complex config scenario includes a configuration file
	# where most of the values of the configurations are changed in order to
	# detect whether ProxySQL is actually able to parse them correctly from the
	# file or not.
	# 
	# As part of those modifications, the admin username and password
	# are changed from the default ones to others.
	CONFIG_OVERRIDES = {
		'ProxySQL': {
			'admin_username': 'admin2',
			'admin_password': 'admin2'
		}
	}

	def _test_parse_config_file_to_admin_db(self):
		ProxySQL keeps its configuration in an admin database, so that it
		is available for inspection at runtime as well.

		For the initial run, the configuration file is parsed into this admin
		database. We will test that the correct values of the variables
		exposed in the config file are exposed via the admin interface that
		is accessible through MySQL.

		users = self.run_query_proxysql_admin("SELECT COUNT(*) FROM mysql_users")
		self.assertEqual(int(users[0][0]), 2)

		servers = self.run_query_proxysql_admin("SELECT COUNT(*) FROM mysql_servers")
		# 3 in the config file, 1 auto-populated by the test
		self.assertEqual(int(servers[0][0]), 4)

		variables = self.run_query_proxysql_admin("SELECT * FROM global_variables")
		mysql_variables = {}
		admin_variables = {}
		for (k, v) in variables:
			if k.startswith('admin-'):
				admin_variables[k[6:]] = v
			elif k.startswith('mysql-'):
				mysql_variables[k[6:]] = v

		self.assertEqual(mysql_variables['connect_timeout_server'], '5000')
		self.assertEqual(mysql_variables['default_charset'], 'utf8')
		self.assertEqual(mysql_variables['have_compress'], 'false')
		self.assertEqual(mysql_variables['monitor_history'], '300000')
		self.assertEqual(mysql_variables['monitor_connect_interval'], '120000')
		self.assertEqual(mysql_variables['monitor_connect_timeout'], '200')
		self.assertEqual(mysql_variables['monitor_ping_interval'], '60000')
		self.assertEqual(mysql_variables['monitor_ping_timeout'], '150')
		self.assertEqual(mysql_variables['monitor_username'], 'root')
		self.assertEqual(mysql_variables['monitor_password'], 'root')
		self.assertEqual(mysql_variables['monitor_query_variables'], 'SELECT * FROM INFORMATION_SCHEMA.GLOBAL_VARIABLES')
		self.assertEqual(mysql_variables['monitor_query_status'], 'SELECT * FROM INFORMATION_SCHEMA.GLOBAL_STATUS')
		self.assertEqual(mysql_variables['monitor_query_interval'], '30000')
		self.assertEqual(mysql_variables['monitor_query_timeout'], '150')
		self.assertEqual(mysql_variables['monitor_timer_cached'], 'false')
		self.assertEqual(mysql_variables['ping_interval_server'], '2000')
		self.assertEqual(mysql_variables['ping_timeout_server'], '150')
		self.assertEqual(mysql_variables['default_schema'], 'test')
		self.assertEqual(mysql_variables['poll_timeout'], '1000')
		self.assertEqual(mysql_variables['poll_timeout_on_failure'], '150')
		self.assertEqual(mysql_variables['server_capabilities'], '47627')
		self.assertEqual(mysql_variables['server_version'], '5.1.31')
		self.assertEqual(mysql_variables['commands_stats'], 'true')
		self.assertEqual(mysql_variables['servers_stats'], 'false')
		self.assertEqual(mysql_variables['stacksize'], '2097152')
		self.assertEqual(mysql_variables['threads'], '2')

		self.assertEqual(admin_variables['admin_credentials'], 'admin2:admin2')
		self.assertEqual(admin_variables['mysql_ifaces'], '0.0.0.0:6032')
		self.assertEqual(admin_variables['refresh_interval'], '2000')

	def test_parse_config_file_to_admin_db(self):
		self.run_in_docker_scenarios(self._test_parse_config_file_to_admin_db)

"""