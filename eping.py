#! /usr/bin/env python

import sys, re, os
import argparse
import time
import base64
import smtplib
import imaplib
from email.message import Message
from email.parser import FeedParser
from multiprocessing import Process, Lock, Queue

class Eping:
	def __init__(self):
		self.program = 'eping'
		self.protocol_version = 1
		self.version = '0.1'
		self.user_agent = '%s-%s' % (self.program, self.version)
		self.description = 'Email Ping Tool'

		self.args = self.parse_commandline()

		# These objects are only created if we pass the cmdline validation
		self.__shutdown = False
		self.__log_lock = Lock()
		self.smtp_queue = Queue()
		self.imap_queue = Queue()
		self.parent_queue = Queue()

	def parse_commandline(self):
		parser = argparse.ArgumentParser()

		parser.description = self.description
		parser.prog = self.program

		parser.add_argument('-U', '--user',
			required = True,
			type = str,
			action = 'store',
			dest = 'username')

		parser.add_argument('-P', '--pass',
			required = True,
			type = str,
			action = 'store',
			dest = 'password')

		parser.add_argument('-i', '--imaps_server',
			required = True,
			type = str,
			action = 'store',
			dest = 'imaps_server')

		parser.add_argument('-s', '--smtp_server',
			required = True,
			type = str,
			action = 'store',
			dest = 'smtp_server')

		parser.add_argument('-f', '--from',
			required = True,
			type = str,
			action = 'store',
			dest = 'mail_from')

		parser.add_argument('-t', '--to',
			required = False,
			type = str,
			action = 'append',
			dest = 'rcpt_to')

		parser.add_argument('--imaps_port',
			required = False,
			type = int,
			action = 'store',
			default = 993,
			dest = 'imaps_port')

		parser.add_argument('--smtp_port',
			required = False,
			type = int,
			action = 'store',
			default = 587,
			dest = 'smtp_port')

		parser.add_argument('--send_interval',
			required = False,
			type = int,
			action = 'store',
			default = 60,
			dest = 'send_interval')

		parser.add_argument('--verbose',
			required = False,
			action = 'store_true',
			default = False,
			dest = 'verbose')

		parser.add_argument('--debug',
			required = False,
			action = 'store_true',
			default = False,
			dest = 'debug')

		parser.add_argument('--debug_imap',
			required = False,
			action = 'store_true',
			default = False,
			dest = 'debug_imap')

		parser.add_argument('--debug_smtp',
			required = False,
			action = 'store_true',
			default = False,
			dest = 'debug_smtp')

		parser.add_argument('--debug_messages',
			required = False,
			action = 'store_true',
			default = False,
			dest = 'debug_messages')

		parser.add_argument('--version',
			action='version',
			version='%s %s' % (self.program, self.version))

		return parser.parse_args()

	def log(self, m):
		if self.args.verbose:
			self.__log_lock.acquire()
			print "%s(%i): %s" % (self.program, os.getpid(), m) 	
			self.__log_lock.release()

	def make_echo_request(self):
		t0 = time.gmtime()
		t0_str = time.asctime(t0) + ' +0000'
		t0_int = time.mktime(t0)

		msg = Message()

		msg.set_charset('utf-8')
		msg.set_type('text/plain')
		msg.add_header('User-agent', self.user_agent)
		msg.add_header('From', self.args.mail_from)
		for email_addr in self.args.rcpt_to:
			msg.add_header('To', email_addr)
		msg.add_header('X-eping-protocol-version', str(self.protocol_version))
		msg.add_header('X-eping-type', 'echo-request')
		msg.add_header('X-eping-t0', '%i' % t0_int)
		msg.add_header('Subject', 'echo-request %s' % t0_str)

		return msg

	def make_echo_reply(self, msg_request):
		t1 = time.gmtime()
		t1_str = time.asctime(t1) + ' +0000'
		t1_int = int(time.mktime(t1))

		try:
			t0_int = int(msg_request.get('X-eping-t0'))
		except TypeError as e:
			self.log('make_echo_reply(): missing header X-eping-t0')
			raise e
		ping_time = t1_int - t0_int
		
		ping_path = msg_request.get_all('Received')
		subject = 'Re: ' + msg_request.get('Subject')
		reply_to = msg_request.get('From')

		message_id = msg_request.get('Message-Id')

		msg = Message()
		msg.set_charset('utf-8')
		msg.set_type('text/plain')
		msg.add_header('User-agent', self.user_agent)
		msg.add_header('From', self.args.mail_from)
		msg.add_header('To', reply_to)
		msg.add_header('Subject', subject)
		if type(message_id) != type(None):
			msg.add_header('In-Reply-To', message_id)
		msg.add_header('X-eping-protocol-version', str(self.protocol_version))
		msg.add_header('X-eping-type', 'echo-reply')
		msg.add_header('X-eping-t0', '%i' % t0_int)
		msg.add_header('X-eping-t1', '%i' % t1_int)
		msg.add_header('X-eping-ping-time', '%i' % ping_time)
		msg.add_header('X-eping-ping-hops', '%i'% len(ping_path))

		payload = ''
		payload += '---- echo-request headers ----\n'
		for h in msg_request._headers:
			payload += '%s: %s\n' % h

		msg.set_payload(base64.encodestring(payload))

		return msg

	def consume_echo_reply(self, msg):
		t2 = time.gmtime()
		t2_str = time.asctime(t2) + ' +0000'
		t2_int = int(time.mktime(t2))

		t0_int = int(msg.get('X-eping-t0'))
		t1_int = int(msg.get('X-eping-t1'))

		rtt = t2_int - t0_int

		ping_time = int(msg.get('X-eping-ping-time'))
		pong_time = t2_int - t1_int
		pingpong = abs(ping_time) + abs(pong_time)

		pingpong_rtt = pingpong - rtt

		ping_hops = int(msg.get('X-eping-ping-hops'))

		received_path = msg.get_all('Received')
		pong_hops = len(received_path)

		rcvd_from = msg.get('From')

		results = (
			('From', rcvd_from),
			('GMT Time', t0_int),
			('Round Trip Time', rtt),
			('Ping Time', ping_time),
			('Pong Time', pong_time),
			('PingPong Time', pingpong),
			('PingPong - RTT', pingpong_rtt),
			('Ping Hops', ping_hops),
			('Pong Hops', pong_hops),
			('Round Trip Hops', ping_hops + pong_hops)
		)

		print results
		

	def imap_answerer(self, connection, msglist):

		processed_message_flags = '\\Deleted \\Answered \\Seen'
		if self.args.debug_messages:
			processed_message_flags = '\\Answered \\Seen'

		for msgnum in msglist:
			typ, data = connection.fetch(msgnum, '(RFC822)')
			msgstr = data[0][1]
			parser = FeedParser()
			parser.feed(msgstr)
			msg = parser.close()

			# process only our own messages
			try:
				protocol_version = int(msg.get('X-eping-protocol-version'))
			except TypeError: 
				continue
			if protocol_version != self.protocol_version:
				continue

			eping_type = msg.get('X-eping-type')
			if eping_type == 'echo-request':
				msg_reply = self.make_echo_reply(msg)
				self.smtp_queue.put(msg_reply)
				connection.store(msgnum, '+FLAGS', 
					processed_message_flags)
				continue
			elif eping_type == 'echo-reply':
				self.consume_echo_reply(msg)
				connection.store(msgnum, '+FLAGS',
					processed_message_flags)
				continue
			else:
				self.log('unknown X-eping-type: %s' % eping_type)
				continue

	def imap_client(self):
		self.program='eping-imap'
		self.log("started")

		try:
			connection = imaplib.IMAP4_SSL(self.args.imaps_server,
				self.args.imaps_port)
			if self.args.debug_imap:
				connection.debug=10
			connection.login(self.args.username, self.args.password)
			connection.select()
			self.log("connected to inbox")
		except imaplib.error as e:
			self.log(str(e))
			self.kill_parent()
			sys.exit()
		except KeyboardInterrupt:
			self.__shutdown = True

		while not self.__shutdown:
			try:
				connection.noop()
				typ, data = connection.search(None, 
					'(NOT DELETED NOT ANSWERED SUBJECT echo-)')
				if len(data[0]) > 0:
					self.imap_answerer(connection, 
						data[0].split())

				time.sleep(1)
			except KeyboardInterrupt:
				break
			except Exception as e:
				self.log(str(e))
				continue

		self.log("ended")

	def smtp_client(self):
		self.program = 'eping-smtp'
		self.log("started")

		if self.smtp_queue.empty():
			self.log('empty work queue, exitting')
			return

		try:
			connection = smtplib.SMTP()
			if self.args.debug_smtp:
				connection.set_debuglevel(1)
			connection.connect(self.args.smtp_server, self.args.smtp_port)
			connection.starttls()
			connection.login(self.args.username, self.args.password)
		except Exception as e:
			self.log(str(e))
			self.kill_parent()
			sys.exit()

		msgcounter = 0

		while not self.smtp_queue.empty():
			try:
				m = self.smtp_queue.get(True,1)
				mailfrom = m.get('From')
				rcptto = m.get_all('To')
				subject = m.get('Subject')
				# will raise exceptions if empty
				len(mailfrom)
				len(rcptto)
				len(subject)
				connection.sendmail(mailfrom, rcptto, 
					m.as_string())
				self.log('sent %i: %s' % (msgcounter, subject))
				msgcounter += 1
			except Exception as e:
				self.log('%s' % e)
				continue

		connection.quit()
		self.log('sent %i messages. ending.' % msgcounter)

	def spawn_smtp_client(self):
		# dont spawn children if main process is shutting down
		if self.__shutdown:
			return

		# dont spawn more than one smtp process
		try:
			if self.smtp_process.is_alive():
				return
		except AttributeError:
			pass

		self.log('spawning smtp_process')
		self.smtp_process = Process(target=self.smtp_client)
		self.smtp_process.daemon = True
		self.smtp_process.start()

	def spawn_imap_client(self):
		# dont spawn children if main process is shutting down
		if self.__shutdown:
			return

		# dont spawn more than one imap process
		try:
			if self.imap_process.is_alive():
				return
		except AttributeError:
			pass

		self.log('spawning imap_process')
		self.imap_process = Process(target=self.imap_client)
		self.imap_process.daemon = True
		self.imap_process.start()

	def consume_parent_queue(self):
		if self.parent_queue.empty():
			return
		cmd = self.parent_queue.get()
		if cmd == 'DIE':
			self.log('DIE received')
			self.__shutdown = True

	def consume_imap_queue(self):
		if self.imap_queue.empty():
			return
		cmd = self.imap_queue.get()
		if cmd == 'DIE':
			self.log('DIE received')
			self.__shutdown = True

	def consume_smtp_queue(self):
		if self.smtp_queue.empty():
			return
		cmd = self.smtp_queue.get()
		if cmd == 'DIE':
			self.log('DIE received')
			self.__shutdown = True
		else:
			self.log(cmd)

	def kill_parent(self):
		self.log('kill_parent()')
		m = 'DIE'
		self.parent_queue.put(m)

	def kill_imap(self):
		self.log('kill_imap()')
		m = 'DIE'
		self.imap_queue.put(m)

	def kill_smtp(self):
		self.log('kill_smtp()')
		m = 'DIE'
		self.smtp_queue.put(m)

	def nice_shutdown_process(self, process, queue):
		m = 'DIE'
		queue.put(m)
		process.join(5)
		if process.is_alive():
			self.log('terminating %s' % process.name)

	def main(self):
		self.program = 'eping-main'
		self.log('%s %s starting' % (self.program, self.version))
		self.log(self.args)

		last_sent_echo = 0

		while not self.__shutdown:
			now = time.time()
			self.consume_parent_queue()

			# queue echo-requests at regular intervals
			if ( (self.args.rcpt_to != None) &
				((now - last_sent_echo) > self.args.send_interval) ):
				last_sent_echo = now
				msg = self.make_echo_request()
				self.smtp_queue.put(msg)

			# spawn smtp client when needed
			if not self.smtp_queue.empty():
				self.spawn_smtp_client()

			# (re)spawn imap client
			self.spawn_imap_client()

			try:
				time.sleep(1)
			except KeyboardInterrupt:
				break

		self.log('exiting')

if __name__ == "__main__":
	eping = Eping()
	eping.main()
