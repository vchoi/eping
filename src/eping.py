#! /usr/bin/python

import sys, re
import argparse
from multiprocessing import Process, Queue

class Eping:
	def __init__(self):
		self.program = 'eping'
		self.version = '0.1'
		self.description = 'Email Ping Tool'

		self.args = self.parse_commandline()

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

		parser.add_argument('-t', '--to',
			required = False,
			type = str,
			action = 'store',
			dest = 'to')

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

		parser.add_argument('--version',
			action='version',
			version='%s %s' % (self.program, self.version))

		return parser.parse_args()

	def main(self):
		print self.args

if __name__ == "__main__":
	eping = Eping()
	eping.main()

