from ConfigParser import ConfigParser

class ProxySQL_Tests_Config(object):

	DEFAULT_PROXYSQL_TESTS_LOCATION = 'proxysql-tests.ini'

	def __init__(self, location=DEFAULT_PROXYSQL_TESTS_LOCATION, overrides={}):
		self.location = location
		self.config = ConfigParser()
		self.config.read(self.location)
		self.overrides = overrides

	def get(self, section, variable, default=None):
		""" Returns the value of a variable in a given section, or the default
		value if the variable or section don't exist."""
		if section in self.overrides and variable in self.overrides[section]:
			return self.overrides[section][variable]

		return self.config.get(section, variable)