import MySQLdb
from MySQLdb import OperationalError
from nose.tools import raises

from proxysql_base_test import ProxySQLBaseTest

class AuthenticationTest(ProxySQLBaseTest):

	def test_existing_user_with_correct_password_works(self):
		version1 = self.run_query_mysql(
								"SELECT @@version_comment LIMIT 1", "test",
								return_result=True,
								username="john", password="doe")

		version2 = self.run_query_proxysql(
								"SELECT @@version_comment LIMIT 1", "test",
								return_result=True,
								username="john", password="doe")

		self.assertEqual(version1, version2)

	def test_existing_user_with_correct_password_but_not_registerd_within_proxysql_does_not_work(self):
		try:
			self.run_query_proxysql("SELECT @@version_comment LIMIT 1", "test",
									return_result=True, 
									username="danny", password="white")
			# We shouldn't reach this point successfully, because it means we
			# managed to authenticate with the wrong password
			self.assertEqual(1, 0)
		except OperationalError:
			self.assertEqual(1, 1)

	def test_existing_user_with_incorrect_password_does_not_work(self):
		try:
			self.run_query_proxysql("SELECT @@version_comment LIMIT 1", "test",
									return_result=True,
									username="john", password="doe2")
			# We shouldn't reach this point successfully, because it means we
			# managed to authenticate with the wrong password
			self.assertEqual(1, 0)
		except OperationalError:
			self.assertEqual(1, 1)

	def test_inexisting_user_with_random_password_does_not_work(self):
		try:
			self.run_query_proxysql("SELECT @@version_comment LIMIT 1", "test",
									return_result=True,
									username="johnny", password="randomdoe")
			self.assertEqual(1, 0)
		except OperationalError:
			self.assertEqual(1, 1)