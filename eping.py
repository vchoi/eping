#! /usr/bin/env python

import sys, re, os, time, math, types
import smtplib, imaplib, base64
from optparse import OptionParser, OptionGroup
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
		self.nsca_queue= Queue()
		self.parent_queue = Queue()

	def parse_commandline(self):
		version_string = "%s %s" % (self.program, self.version)
		parser = OptionParser(version=version_string)
		require_defined = (
			'username',
			'password',
			'imaps_server',
			'smtp_server',
			'mail_from',
			)

		require_or = (
			
			)

		require_xor = (

		)

		require_and = (

		)

		# general options
		parser.add_option('--verbose',
			action = 'store_true',
			default = False,
			dest = 'verbose')

		parser_credentials = OptionGroup(parser, 'Credentials')
		parser_credentials.add_option('-U', '--user',
			type = 'string',
			action = 'store',
			dest = 'username',
			help = 'Username used on all servers.')
		parser_credentials.add_option('-P', '--pass',
			type = 'string',
			action = 'store',
			dest = 'password',
			help = 'Password used on all servers.')


		parser_imap = OptionGroup(parser, 'IMAP server options')
		parser_imap.add_option('-i', '--imaps_server',
			type = 'string',
			action = 'store',
			dest = 'imaps_server',
			help = 'IMAP over SSL server.')
		parser_imap.add_option('--imaps_port',
			type = 'int',
			action = 'store',
			default = 993,
			dest = 'imaps_port',
			help = 'IMAP/S port. [default=%default]')
		parser_imap.add_option('--debug_imap',
			action = 'store_true',
			default = False,
			dest = 'debug_imap')

		parser_smtp = OptionGroup(parser, 'SMTP server options')
		parser_smtp.add_option('-f', '--from',
			type = 'string',
			action = 'store',
			dest = 'mail_from',
			help = 'Sender address')
		parser_smtp.add_option('-t', '--to',
			type = 'string',
			action = 'append',
			dest = 'rcpt_to',
			help = 'Where to send the email echo-requests.')
		parser_smtp.add_option('--send_interval',
			type = 'int',
			action = 'store',
			default = 60,
			dest = 'send_interval',
			help = 'Interval between echo-requests. [default=%default]')
		parser_smtp.add_option('-s', '--smtp_server',
			type = 'string',
			action = 'store',
			dest = 'smtp_server',
			help = 'SMTP Server (must support STARTTLS).')
		parser_smtp.add_option('--smtp_port',
			type = 'int',
			action = 'store',
			default = 587,
			dest = 'smtp_port',
			help = 'SMTP port. [default=%default]')
		parser_smtp.add_option('--debug_smtp',
			action = 'store_true',
			default = False,
			dest = 'debug_smtp')

		parser_debug = OptionGroup(parser, 'Other Debug Options')
		parser_debug.add_option('--debug_messages',
			action = 'store_true',
			default = False,
			dest = 'debug_messages',
			help = 'Keeps old echo requests and replies in mailbox. [default=%default]')

		parser_output = OptionGroup(parser, 'Output options')
		parser_output.add_option('--enable_csv',
			action = 'store_true',
			default = False,
			dest = 'enable_csv',
			help = 'Enable CSV output. ')
		parser_output.add_option('--csv_dir',
			action = 'store',
			default = '.',
			dest = 'csv_dir',
			help = 'Where to write CSV files. [default=%default]')
		parser_output.add_option('--enable_rrd',
			action = 'store_true',
			default = False,
			dest = 'enable_rrd',
			help = 'Enable RRD output.')
		parser_output.add_option('--rrd_dir',
			action = 'store',
			default = '.',
			dest = 'rrd_dir',
			help = 'Where to write RRD files. [default=%default]')
		parser_output.add_option('--enable_stdout',
			action = 'store_true',
			default = False,
			dest = 'enable_stdout',
			help = 'Enable output to stdout.')
		parser_output.add_option('--enable_nsca',
			action = 'store_true',
			default = False,
			dest = 'enable_nsca',
			help = 'Enable output to send_nsca.')
		parser_output.add_option('--nsca_cmd',
			action = 'store',
			default = '/usr/sbin/send_nsca',
			dest = 'nsca_cmd',
			help = 'Path to send_nsca. [default=%default]')
		parser_output.add_option('--nsca_config',
			action = 'store',
			default = '/etc/send_nsca.cfg',
			dest = 'nsca_config',
			help = 'Path to send_nsca.cfg. [default=%default]')
		parser_output.add_option('--nsca_host',
			action = 'store',
			dest = 'nsca_host',
			help = 'NSCA host address.')
		parser_output.add_option('--nsca_port',
			action = 'store',
			default = 5667,
			dest = 'nsca_port',
			help = 'NSCA port. [default=%default]')

		parser.add_option_group(parser_credentials)
		parser.add_option_group(parser_imap)
		parser.add_option_group(parser_smtp)
		parser.add_option_group(parser_output)
		parser.add_option_group(parser_debug)

		(options, args) = parser.parse_args()

		# do sanity checks on options passed by the user
		error_list = []
		# check for required arguments
		for k in require_defined:
			v = getattr(options, k)
			if type(v) == type(None):
				error_list.append('FATAL: option %s is required' % k)

		if len(error_list) > 0:
			for error in error_list:
				print(error)
			sys.exit(1)
		return options

	def log(self, m):
		if self.args.verbose:
			self.__log_lock.acquire()
			print "%s(%i): %s" % (self.program, os.getpid(), m) 	
			self.__log_lock.release()

	def rfc822_tzoffset(self):
		f = - float(time.timezone) / 3600.0
		if f < 0:
			signal = '-'
			f = -f
		else:
			signal = '+'
		(fractional, integer) = math.modf(f)
		hour = int(integer)
		minutes = int(fractional * 30.0)
		return "%s%02i%02i" % (signal, hour, minutes)

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


		ping_hops = int(msg.get('X-eping-ping-hops'))

		received_path = msg.get_all('Received')
		pong_hops = len(received_path)

		hops = ping_hops + pong_hops

		rcvd_from = msg.get('From').strip()
		l = rcvd_from.find('<')
		if l >= 0:
			r = rcvd_from.find('>')
			rcvd_from = rcvd_from[l+1:r]

		result = (
			'RESULT',
			{
			'from': rcvd_from,
			't0': t0_int,
			'rtt': rtt,
			'hops': hops,
			'ping': ping_time,
			'pong': pong_time,
			'ping_hops': ping_hops,
			'pong_hops': pong_hops,
			}
		)

		self.parent_queue.put(result)
		

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
				# re-queue message and exit
				self.smtp_queue.put(m)
				sys.exit()

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

	def spawn_nsca_client(self):
		# dont spawn children if main process is shutting down
		if self.__shutdown:
			return

		# dont spawn more than one nsca process
		try:
			if self.nsca_process.is_alive():
				return
		except AttributeError:
			pass

		self.log('spawning nsca_process')
		self.nsca_process = Process(target=self.nsca_client)
		self.nsca_process.daemon = True
		self.nsca_process.start()

	def nsca_client(self):
		self.program='eping-nsca'
		self.log("started")

		# TODO: Do something...

		self.log("ended")


	def consume_parent_queue(self):
		if self.parent_queue.empty():
			return
		msg = self.parent_queue.get()
		if msg == ('DIE'):
			self.log('DIE received')
			self.__shutdown = True
		if msg[0] == 'RESULT':
			self.output_result(msg[1])

	def consume_imap_queue(self):
		if self.imap_queue.empty():
			return
		cmd = self.imap_queue.get()
		if cmd == ('DIE'):
			self.log('DIE received')
			self.__shutdown = True

	def consume_smtp_queue(self):
		if self.smtp_queue.empty():
			return
		cmd = self.smtp_queue.get()
		if cmd == ('DIE'):
			self.log('DIE received')
			self.__shutdown = True
		else:
			self.log(cmd)

	def output_result(self, result):
		if type(result) != types.DictType:
			raise ValueError('result must be a dictionary')

		# stdout output
		if self.args.enable_stdout:
			self.output_stdout(result)

		# csv output
		if self.args.enable_csv:
			self.output_csv(result)

		# rrd output
		if self.args.enable_rrd:
			self.output_rrd(result)
	
		# nsca output
		if self.args.enable_nsca:
			self.nsca_queue.put(result)

	def output_stdout(self, result):

		t0 = time.localtime(result['t0'] - time.timezone)
		t0_str = time.strftime('%Y-%m-%d %H:%M:%S', t0) 
		t0_str += ' ' + self.rfc822_tzoffset()

		mail_from = result['from']
		rtt = result['rtt']
		ping = result['ping']
		pong = result['pong']
		hops = result['hops']
		ping_hops = result['ping_hops']
		pong_hops = result['pong_hops']
		
		s = '%s, %s: RTT:%i (PING:%i PONG:%i), HOPS:%i (PING:%i PONG:%i)' % (t0_str, mail_from, rtt, ping, pong, hops, ping_hops, pong_hops)
		print(s)
		
	def output_csv(self, result):

		t0 = time.localtime(result['t0'] - time.timezone)
		t0_date = time.strftime('%Y-%m-%d', t0) 
		t0_time = time.strftime('%H:%M:%S', t0) 
		tz_offset = self.rfc822_tzoffset()
	
		mail_from = result['from']
		rtt = result['rtt']
		ping = result['ping']
		pong = result['pong']
		hops = result['hops']
		ping_hops = result['ping_hops']
		pong_hops = result['pong_hops']

		s = '%s;%s;%s;%i;%i;%i;%i;%i;%i\n' % (t0_date, t0_time, tz_offset, rtt, ping, pong, hops, ping_hops, pong_hops)
		filename = os.path.join(self.args.csv_dir, mail_from + '.csv')

		if os.path.exists(filename):
			f = open(filename, 'ab')
		else:
			f = open(filename, 'wb')
			f.write('# eping data for: %s\n# (t0_date, t0_time, tz_offset, rtt, ping, pong, hops, ping_hops, pong_hops)\n' % mail_from)
		f.write(s)
		f.close()

	def output_rrd(self, result):
		pass

	def kill_parent(self):
		self.log('kill_parent()')
		m = ('DIE')
		self.parent_queue.put(m)

	def kill_imap(self):
		self.log('kill_imap()')
		m = ('DIE')
		self.imap_queue.put(m)

	def kill_smtp(self):
		self.log('kill_smtp()')
		m = ('DIE')
		self.smtp_queue.put(m)

	def nice_shutdown_process(self, process, queue):
		m = ('DIE')
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

			# spawn nsca client when needed
			if not self.nsca_queue.empty():
				self.spawn_nsca_client()

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

