from email.mime.text import MIMEText
import smtplib
from threading import Thread
import time

import MySQLdb

class ProxySQL_Ping_Thread(Thread):
	"""ProxySQL_Ping_Thread's purpose is to do a continuous health check of the
	ProxySQL daemon when tests are running against it. When it has crashed
	or it's simply not responding anymore, it will send an e-mail to draw the
	attention of the developer so that he or she will examine the situation.

	This is because the test suite is designed to be long running and we want
	to find out as quickly as possible when the tests ran into trouble without
	continuously keeping an eye on the tests.
	"""

	FAILED_CONNECTIONS_BEFORE_ALERT = 3

	def __init__(self, username, password,
				 hostname="127.0.0.1", port=6033, db="test",
				 ping_command="SELECT @@version_comment LIMIT 1",
				 interval=60, **kwargs):
		self.username = username
		self.password = password
		self.hostname = hostname
		self.port = port
		self.db = db
		self.ping_command = ping_command
		self.interval = interval
		self.running = False
		self.failed_connections = 0
		super(ProxySQL_Ping_Thread, self).__init__(**kwargs)

	def run(self):
		self.running = True

		while self.running:
			time.sleep(self.interval)

			if not self.running:
				return

			try:
				connection = MySQLdb.connect(self.hostname,
											 self.username,
											 self.password,
											 port=self.port,
											 db=self.db,
											 connect_timeout=30)
				cursor = connection.cursor()
				cursor.execute(self.ping_command)
				rows = cursor.fetchall()
				cursor.close()
				connection.close()
				print("ProxySQL server @ %s:%d responded to query %s with %r" % 
						(self.hostname, self.port, self.ping_command, rows))
				self.failed_connections = 0
			except:
				self.failed_connections = self.failed_connections + 1
				if self.failed_connections >= ProxySQL_Ping_Thread.FAILED_CONNECTIONS_BEFORE_ALERT:
					self.send_error_email()
					self.running = False

	def stop(self):
		self.running = False

	def send_error_email(self):
		msg = MIMEText("ProxySQL daemon stopped responding during tests.\n"
						"Please check if it has crashed and you have been left with a gdb console on!")

		# me == the sender's email address
		# you == the recipient's email address
		msg['Subject'] = 'Daemon has stopped responding'
		msg['From'] = 'ProxySQL Tests <proxysql.tests@gmail.com>'
		msg['To'] = 'Andrei-Adnan Ismail <iandrei@gmail.com>'

		# Send the message via our own SMTP server, but don't include the
		# envelope header.
		s = smtplib.SMTP('smtp.gmail.com', 587)
		s.ehlo()
		s.starttls()
		s.login('proxysql.tests', 'pr0xysql')
		s.sendmail('proxysql.tests@gmail.com', ['iandrei@gmail.com'], msg.as_string())
		s.quit()

