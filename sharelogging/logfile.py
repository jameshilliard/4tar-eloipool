# Eloipool - Python Bitcoin pool server
# Copyright (C) 2011-2012  Luke Dashjr <luke-jr+eloipool@utopios.org>
# Copyright (C) 2012  Peter Leurs <kinlo@triplemining.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.



from collections import deque
from datetime import date
from binascii import b2a_hex
from time import sleep, time
import threading
from util import shareLogFormatter
import logging
import traceback

_logger = logging.getLogger('sharelogging.logfile')

class logfile(threading.Thread):
	def __init__(self, filename, **ka):
		super().__init__(**ka.get('thropts', {}))
		self.fn = filename
		self.idx = 0
		if 'format' not in ka:
			_logger.warn('"format" not specified for logfile logger, but default may vary!')
			ka['format'] = "{time} {Q(remoteHost)} {username} {YN(not(rejectReason))} {dash(YN(upstreamResult))} {dash(rejectReason)} {solution} {target2pdiff(target)}\n"
		self.fmt = shareLogFormatter(ka['format'], '%s')
		self.queue = deque()
		self.start()

	def flushlog(self):
		logfile = None
		while len(self.queue) > 0:
			(idx, logline) = self.queue.popleft()
			if logfile is None or idx != self.idx:
				self.idx = idx
				logfile = open(self.fn + '.' + str(self.idx), 'a')
			logfile.write(logline)

	def run(self):
		while True:
			try:
				sleep(0.2)
				self.flushlog()
			except:
				_logger.critical(traceback.format_exc())

	def logJob(self, jobBytes, height):
		logitem = (height, jobBytes.decode('ascii'))
		self.queue.append(logitem)

	def logShare(self, share):
		logitem = (share['height'], self.fmt.formatShare(share))
		self.queue.append(logitem)
