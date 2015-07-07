from ConfigParser import ConfigParser

class ProxySQL_Tests_Config(object):

	DEFAULT_PROXYSQL_TESTS_LOCATION = 'proxysql-tests.ini'

	def __init__(self, location=DEFAULT_PROXYSQL_TESTS_LOCATION):
		self.location = location
		self.config = ConfigParser()
		self.config.read(self.location)

	def get(self, section, variable, default=None):
		""" Returns the value of a variable in a given section, or the default
		value if the variable or section don't exist."""
		return self.config.get(section, variable)