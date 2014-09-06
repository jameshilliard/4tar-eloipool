# Eloipool - Python Bitcoin pool server
# Copyright (C) 2011-2013  Luke Dashjr <luke-jr+eloipool@utopios.org>
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

#import agplcompliance
import threading
from binascii import b2a_hex
import collections
from copy import deepcopy
import json
import logging
import networkserver
import socket
import struct
from time import time
from math import ceil
import traceback
from util import RejectedShare, swap32, target2bdiff

class StratumError(BaseException):
	def __init__(self, errno, msg, trace = False, extraMsg = None, disconnect = False):
		self.error = (errno, msg, trace)
		self.extraMsg = extraMsg
		self.disconnect = disconnect

StratumCodes = {
	'unknown': 20,
	'stale-prevblk': 21,
	'stale-work': 21,
	'duplicate': 22,
	'h-not-zero': 23,
	'high-hash': 23,
	'unauthorized': 24,
	'not-subscribed': 25,
	'no-txlist-for-vpm': 26,
	'stale-txlist-req': 26,
	'too-frequent-txlist-req': 26
}

class StratumHandler(networkserver.SocketHandler):
	logger = logging.getLogger('StratumHandler')

	def __init__(self, *a, **ka):
		super().__init__(*a, **ka)
		self.remoteHost = self.addr[0]
		self.changeTask(None)
		self.target = self.server.defaultTarget
		# targetUp targetUpCount targetIncCount
		self.targetUp = [ 0, 0, 8 ]
		#self.server.schedule(self.sendLicenseNotice, time() + 4, errHandler=self)
		self.set_terminator(b"\n")
		self.submitError = 0
		self.submitTimeCount = 0
		self.lastSubmitTime = 0
		self.lastSubmitJobId = 0
		self.lastGetTxnsJobId = 0
		self.JobTargets = collections.OrderedDict()
		self.UN = self.UA = None
		self.VPM = self.Authorized = self.Subscribed = False
		#self.LicenseSent = agplcompliance._SourceFiles is None

	def sendReply(self, ob):
		return self.push(json.dumps(ob).encode('ascii') + b"\n")

	def found_terminator(self):
		inbuf = b"".join(self.incoming).decode('ascii')
		self.incoming = []

		if not inbuf:
			return

		self.logger.debug("%s< %s" % (str(self.addr), inbuf))

		try:
			rpc = json.loads(inbuf)
		except ValueError:
			self.boot()
			return
		if 'method' not in rpc:
			# Assume this is a reply to our request
			funcname = '_stratumreply_%s' % (rpc['id'],)
			if not hasattr(self, funcname):
				return
			try:
				getattr(self, funcname)(rpc)
			except BaseException as e:
				self.logger.debug(traceback.format_exc())
			return

		funcname = '_stratum_%s' % (rpc['method'].replace('.', '_'),)
		if not hasattr(self, funcname):
			self.sendReply({
				'error': [-3, "Method '%s' not found" % (rpc['method'],), None],
				'id': rpc['id'],
				'result': None,
			})
			return

		try:
			rv = getattr(self, funcname)(*rpc['params'])
		except StratumError as e:
			self.sendReply({
				'error': (e.error[0], e.error[1], traceback.format_exc() if e.error[2] else None),
				'id': rpc['id'],
				'result': None,
			})
			if e.extraMsg:
				self.sendReply({
					'id': 8,
					'method': 'client.show_message',
					'params': (e.extraMsg,),
				})
			if e.disconnect:
				self.boot()
			return
		except BaseException as e:
			fexc = traceback.format_exc()
			self.sendReply({
				'error': (20, str(e), fexc),
				'id': rpc['id'],
				'result': None,
			})
			if not hasattr(e, 'StratumQuiet'):
				self.logger.debug(fexc)
			return

		if rpc['id'] is None:
			return

		self.sendReply({
			'error': None,
			'id': rpc['id'],
			'result': rv,
		})

#	def sendLicenseNotice(self):
#		if self.fd == -1:
#			return
#		if not self.LicenseSent:
#			self.sendReply({
#				'id': 8,
#				'method': 'client.show_message',
#				'params': ('This stratum server is licensed under the GNU Affero General Public License, version 3. You may download source code over stratum using the server.get_source method.',),
#			})
#		self.LicenseSent = True

	def sendJob(self):
		if self.server.JobId in self.JobTargets:
			return

		if not len(self.JobTargets):
			diff = target2bdiff(self.target)
			self.logger.debug("Initialize difficulty to %s for %d/%s@%s" % (diff, self._sid, self.UN, str(self.addr)))
			self.sendReply({
				'id': None,
				'method': 'mining.set_difficulty',
				'params': [ diff ],
			})

		#self.logger.debug("sendJob to %s@%s" % (self.UN, str(self.addr)))

		userName = self.UN.split('.')[0]
		if userName in self.server.PrivateMining:
			if self.server.PrivateMining[userName][1]:
				self.VPM = True
				self.push(self.server.PrivateMining[userName][1])
		else:
			if self.VPM:
				self.VPM = False
				self.push(self.server.JobBytesRestart)
			else:
				self.push(self.server.JobBytes)

		if len(self.JobTargets) > 4:
			self.JobTargets.popitem(False)
		self.JobTargets[self.server.JobId] = self.target

	def _stratumreply_7(self, rpc):
		self.UA = rpc.get('result') or rpc

	def _stratum_mining_authorize(self, username, password = None):
		self.UN = username
		self.Authorized = True
		if self.Subscribed:
			self.changeTask(self.sendJob, 0)
		return True

	def _stratum_mining_subscribe(self, UA = None, xid = None):
		if not UA is None:
			self.UA = UA
		if not self.UA:
			self.sendReply({
				'id': 7,
				'method': 'client.get_version',
				'params': (),
			})

		if not hasattr(self, '_sid'):
			self._sid = self.server.sidMgr.get()
		if self.server._Clients.get(self._sid) not in (self, None):
			del self._sid
			raise self.server.RaiseRedFlags(RuntimeError('issuing duplicate sessionid'))

		self.Subscribed = True
		if self.Authorized:
			self.changeTask(self.sendJob, 0)

		xid = struct.pack('=I', self._sid)  # NOTE: Assumes sessionids are 4 bytes
		self.extranonce1 = xid
		xid = b2a_hex(xid).decode('ascii')
		self.server._Clients[id(self)] = self
		return [
			[
				['mining.notify', '%s1' % (xid,)],
				['mining.set_difficulty', '%s2' % (xid,)],
			],
			xid,
			4,
		]

	def close(self):
		if hasattr(self, '_sid'):
			self.server.sidMgr.put(self._sid)
			delattr(self, '_sid')
		try:
			del self.server._Clients[id(self)]
		except:
			pass
		super().close()

	def _stratum_mining_submit(self, username, jobid, extranonce2, ntime, nonce):
		#if username not in self.Usernames:
		#	raise StratumError(24, 'unauthorized-user')
		submitTime = time()
		newBdiff = 0
		targetUp = False
		if self.server.MinSubmitInterval:
			if submitTime - self.lastSubmitTime < self.server.MinSubmitInterval:
				if self.submitTimeCount > 0:
					if self.target != self.server.networkTarget:
						targetUp = True

						self.target /= 2
						if self.target < self.server.networkTarget:
							self.target = self.server.networkTarget
						newBdiff = target2bdiff(self.target)
						self.logger.debug("Increase difficulty to %s for %d/%s@%s" % (newBdiff, self._sid, username, str(self.addr)))
					self.submitTimeCount = 0
				else:
					self.submitTimeCount = 1
			elif self.submitTimeCount > 0:
				self.submitTimeCount = 0
		if not newBdiff and self.server.MaxSubmitInterval:
			if submitTime - self.lastSubmitTime > self.server.MaxSubmitInterval:
				if self.submitTimeCount < 0:
					if self.target != self.server.defaultTarget:
						self.target *= 2
						if self.target > self.server.defaultTarget:
							self.target = self.server.defaultTarget
						newBdiff = target2bdiff(self.target)
						self.logger.debug("Decrease difficulty to %s for %d/%s@%s" % (newBdiff, self._sid, username, str(self.addr)))
					self.submitTimeCount = 0
				else:
					self.submitTimeCount = -1
			elif self.submitTimeCount < 0:
				self.submitTimeCount = 0
		if newBdiff:
			self.sendReply({
				'id': None,
				'method': 'mining.set_difficulty',
				'params': [ newBdiff ],
			})
		self.server.lastSubmitTime = self.lastSubmitTime = submitTime

		self.lastSubmitJobId = jobid = int(jobid)
		if jobid != self.server.JobId and self.server.JobId not in self.JobTargets:
			self.sendJob()

		share = {
			'username': username,
			'remoteHost': self.remoteHost,
			'jobid': jobid,
			'extranonce1': self.extranonce1,
			'extranonce2': bytes.fromhex(extranonce2),
			'ntime': bytes.fromhex(ntime),
			'nonce': bytes.fromhex(nonce),
			'height': self.server.Height,
			'time': submitTime,
			'targetUp': self.targetUp[0] if self.targetUp[1] else 0
		}
		if jobid in self.JobTargets:
			share['target'] = self.JobTargets[jobid]

		if self.targetUp[0] and self.targetUp[1]:
			self.targetUp[1] -= 1
			if not self.targetUp[1]:
				self.targetUp[0] = 0

		if newBdiff:
			self.JobTargets[jobid] = self.target
			if targetUp:
				self.targetUp[0] += 1
				self.targetUp[1] += self.targetUp[2]
				if self.targetUp[2] > 1:
					self.targetUp[2] = int(self.targetUp[2] / 2)

		try:
			self.server.receiveShare(share)
		except RejectedShare as rej:
			rej = str(rej)
			errno = StratumCodes.get(rej, 20)
			self.submitError += 1
			if self.submitError < 10:
				raise StratumError(errno, rej)
			raise StratumError(errno, rej, False, 'Too many errors found in your submitted shares, disconnect now.', True)

		if self.targetUp[0]:
			self.targetUp[0] -= share['targetUp']

		if self.submitError:
			self.submitError -= 1

		return True

	def _stratum_mining_get_transactions(self, jobid):
		if self.VPM:
			raise StratumError(26, 'no-txlist-for-vpm')

		jobid = int(jobid)
		if jobid != self.server.JobId or jobid == self.lastSubmitJobId:
			raise StratumError(26, 'stale-txlist-req')
		if self.lastGetTxnsJobId and jobid - self.lastGetTxnsJobId < self.server.GetTxnsInterval:
			raise StratumError(26, 'too-frequent-txlist-req')

		self.lastGetTxnsJobId = jobid

		try:
			(MC, now) = self.server.getExistingStratumJob(jobid)
		except KeyError as e:
			e.StratumQuiet = True
			raise
		(height, merkleTree, cb, prevBlock, bits) = MC[:5]
		return list(b2a_hex(txn.data).decode('ascii') for txn in merkleTree.data[1:])

#	def _stratum_server_get_source(self, path = ''):
#		s = agplcompliance.get_source(path.encode('utf8'))
#		if s:
#			s = list(s)
#			s[1] = s[1].decode('latin-1')
#		return s


class StratumServer(networkserver.AsyncSocketServer):
	logger = logging.getLogger('StratumServer')

	waker = True
	schMT = True

	extranonce1null = struct.pack('=I', 0)  # NOTE: Assumes sessionids are 4 bytes

	def __init__(self, *a, **ka):
		ka.setdefault('RequestHandlerClass', StratumHandler)
		super().__init__(*a, **ka)

		self._Clients = {}
		self.JobId = -1
		self.Height = 0
		self.UpdateTask = None
		self.networkTarget = None
		self.MinSubmitInterval = 0
		self.MaxSubmitInterval = 0
		self.GetTxnsInterval = 0
		self.lastSubmitTime = time()
		self.PrivateMining = {}
		#self.sidMgr = UniqueIdManager()
		self.RestartClientJobEvent = threading.Event()
		threading.Thread(target = self._RestartClientJob).start() 

	def checkAuthentication(self, username, password):
		return True

	def updateJobOnly(self, wantClear = False):
		JobId = self.JobId + 1 if self.JobId < 999 else 0
		(MC, now) = self.getStratumJob(JobId, wantClear=wantClear)
		(height, merkleTree, cb, prevBlock, bits) = MC[:5]

		if len(cb) > 96 - len(self.extranonce1null) - 4:
			if not self.rejecting:
				self.logger.warning('Coinbase too big for stratum: disabling')
			self.rejecting = True
			self.boot_all()
			now = time()
			self.UpdateTask = self.schedule(self.updateJob, now + 10)
			return now

		if self.rejecting:
			self.rejecting = False
			self.logger.info('Coinbase small enough for stratum again: re-enabling')

		txn = deepcopy(merkleTree.data[0])
		cb += self.extranonce1null + b'4tar'
		txn.setCoinbase(cb)
		txn.assemble()
		pos = txn.data.index(cb) + len(cb)

		steps = list(b2a_hex(h).decode('ascii') for h in merkleTree._steps)

		Restart = wantClear or not self.IsJobValid(self.JobId, now)
		self.JobBytes = json.dumps({
			'id': None,
			'method': 'mining.notify',
			'params': [
				"%d" % (JobId),
				b2a_hex(swap32(prevBlock)).decode('ascii'),
				b2a_hex(txn.data[:pos - len(self.extranonce1null) - 4]).decode('ascii'),
				b2a_hex(txn.data[pos:]).decode('ascii'),
				steps,
				'00000002',
				b2a_hex(bits[::-1]).decode('ascii'),
				b2a_hex(struct.pack('>L', int(now))).decode('ascii'),
				Restart
			],
		}).encode('ascii') + b"\n"

		if Restart:
			self.JobBytesRestart = self.JobBytes
		else:
			self.JobBytesRestart = json.dumps({
				'id': None,
				'method': 'mining.notify',
				'params': [
					"%d" % (JobId),
					b2a_hex(swap32(prevBlock)).decode('ascii'),
					b2a_hex(txn.data[:pos - len(self.extranonce1null) - 4]).decode('ascii'),
					b2a_hex(txn.data[pos:]).decode('ascii'),
					steps,
					'00000002',
					b2a_hex(bits[::-1]).decode('ascii'),
					b2a_hex(struct.pack('>L', int(now))).decode('ascii'),
					True
				],
			}).encode('ascii') + b"\n"

		payoutCount = len(txn.outputs)		# Should always be 1 in our implementation
		(cbValue, ourAddr) = txn.outputs[0]	# So should be the only one
		for username in self.PrivateMining:
			(pmConfig, JobBytes, refreshed) = self.PrivateMining[username]
			if pmConfig[1]:
				profit = ceil(cbValue  * pmConfig[1])
				if payoutCount == len(txn.outputs):
					txn.addOutput(profit, ourAddr)
				else:
					txn.outputs[payoutCount] = (profit, ourAddr)
				txn.outputs[0] = (cbValue - profit, pmConfig[0])
			else:
				if payoutCount < len(txn.outputs):
					txn.outputs = txn.outputs[:-1]
				txn.outputs[0] = (cbValue, pmConfig[0])
			txn.assemble()
			JobBytes = json.dumps({
				'id': None,
				'method': 'mining.notify',
				'params': [
					"%d" % (JobId),
					b2a_hex(swap32(prevBlock)).decode('ascii'),
					b2a_hex(txn.data[:pos - len(self.extranonce1null) - 4]).decode('ascii'),
					b2a_hex(txn.data[pos:]).decode('ascii'),
					steps,
					'00000002',
					b2a_hex(bits[::-1]).decode('ascii'),
					b2a_hex(struct.pack('>L', int(now))).decode('ascii'),
					Restart or refreshed > 0
				],
			}).encode('ascii') + b"\n"
			self.PrivateMining[username] = (pmConfig, JobBytes, 0)

		job = {
			'bytes': self.JobBytes,
			'id': JobId,
			'blkid': height,
			'reward': cbValue,
			'time': now
		}
		self.logJob(job)

		self.JobId = JobId
		self.Height = height

		return now

	def _RestartClientJob(self):
		while self.keepgoing:
			self.RestartClientJobEvent.wait()
			if self.keepgoing and self.RestartClientJobEvent.is_set():
				C = self._Clients
				if not C:
					self.logger.debug('Nobody to wake up')
					return
				OC = len(C)
				self.logger.debug("%d clients to wake up..." % (OC,))

				now = time()

				# There is a possibility that in the below loop, the updateJob() has updated the
				# current job to a non-restart-one, that may cause all after-changing clients not
				# to get a restart notifcation.
				# However, current implementation of cgminer/bfgminer would switch to the new job
				# no matter it is asking for a restart or not, so it should be just fine.
				# If any problem related to restarting request found, we should check the possiblity.
				for ic in list(C.values()):
					try:
						ic.sendJob()
					except socket.error:
						OC -= 1
						# Ignore socket errors; let the main event loop take care of them later
					except:
						OC -= 1
						self.logger.debug('Error sending new job:\n' + traceback.format_exc())

				self.logger.debug('Restart job sent to %d clients in %.3f seconds' % (OC, time() - now))

	def updateJob(self, wantClear = False, networkTarget = None, refreshVPM = False):
		if self.UpdateTask:
			try:
				self.rmSchedule(self.UpdateTask)
			except:
				pass

		if networkTarget:
			self.networkTarget = networkTarget

		now = self.updateJobOnly(wantClear = wantClear)
		if wantClear or refreshVPM:
			if now - self.lastSubmitTime > self.RestartInterval:
				self.restartApp(True, True)
				return

			self.RestartClientJobEvent.set()

		self.UpdateTask = self.schedule(self.updateJob, now + 55)
