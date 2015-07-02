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

	def __init__(self, config, **kwargs):
		self.username = config.get('ProxySQL', 'username')
		self.password = config.get('ProxySQL', 'password')
		self.hostname = config.get('ProxySQL', 'hostname')
		self.port = int(config.get('ProxySQL', 'port'))
		self.db = config.get('Ping', 'db')
		self.ping_command = config.get('Ping', 'ping_command')
		self.interval = int(config.get('Ping', 'ping_interval'))
		self.max_failed_connections = int(config.get('Ping', 'failed_connections_before_alert'))
		self.config=config
		self.running = True
		self.failed_connections = 0
		super(ProxySQL_Ping_Thread, self).__init__(**kwargs)

	def run(self):
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
				if self.failed_connections >= self.max_failed_connections:
					self.send_error_email()
					self.running = False
					return

	def stop(self):
		self.running = False

	def send_error_email(self):
		msg = MIMEText("ProxySQL daemon stopped responding during tests.\n"
						"Please check if it has crashed and you have been left with a gdb console on!")

		# me == the sender's email address
		# you == the recipient's email address
		msg['Subject'] = 'Daemon has stopped responding'
		msg['From'] = self.config.get('Email', 'from')
		msg['To'] = self.config.get('Email', 'to')

		# Send the message via our own SMTP server, but don't include the
		# envelope header.
		s = smtplib.SMTP(self.config.get('Email', 'smtp_server'),
						 int(self.config.get('Email', 'smtp_port')))
		s.ehlo()
		s.starttls()
		s.login(self.config.get('Email', 'username'),
				self.config.get('Email', 'password'))
		s.sendmail(self.config.get('Email', 'from'),
					[self.config.get('Email', 'to')],
					msg.as_string())
		s.quit()

