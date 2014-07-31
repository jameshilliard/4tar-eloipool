#!/usr/bin/python3
# Eloipool - Python Bitcoin pool server
# Copyright (C) 2011-2013  Luke Dashjr <luke-jr+eloipool@utopios.org>
# Portions written by Peter Leurs <kinlo@triplemining.com>
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

import argparse
import importlib
argparser = argparse.ArgumentParser()
argparser.add_argument('-d', '--daemon', help='Run in daemon mode', action="store_true")
argparser.add_argument('-c', '--config', help='Config name to load from config_<ARG>.py')
args = argparser.parse_args()
configmod = 'config'
if not args.config is None:
	configmod = 'config_%s' % (args.config,)

def loadConfig(config, confMod, update = True):
	__import__(confMod)
	conf = importlib.import_module(confMod)

	if not hasattr(conf, 'ServerName'):
		conf.ServerName = '37pool.com'
	#gotwork = None
	#if hasattr(conf, 'GotWorkURI'):
	#	gotwork = jsonrpc.ServiceProxy(conf.GotWorkURI)
	#if not hasattr(conf, 'GotWorkTarget'):
	#	conf.GotWorkTarget = 0
	if not hasattr(conf, 'ShareTarget'):
		conf.ShareTarget = 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
	if not hasattr(conf, 'DelayLogForUpstream'):
		conf.DelayLogForUpstream = False
	if not hasattr(conf, 'MinSubmitInterval'):
		conf.MinSubmitInterval = 3
	if not hasattr(conf, 'MaxSubmitInterval'):
		conf.MaxSubmitInterval = 100
	if not hasattr(conf, 'GetTxnsInterval'):
		conf.GetTxnsInterval = 10

	if not update:
		return conf

	config.ServerName = conf.ServerName
	config.ShareTarget = conf.ShareTarget
	config.DelayLogForUpstream = conf.DelayLogForUpstream
	config.MinSubmitInterval = conf.MinSubmitInterval
	config.MaxSubmitInterval = conf.MaxSubmitInterval
	config.GetTxnsInterval = conf.GetTxnsInterval

config = loadConfig(None, configmod, False)

import logging
import logging.handlers

rootlogger = logging.getLogger(None)
logformat = getattr(config, 'LogFormat', '%(asctime)s\t%(name)s\t%(levelname)s\t%(message)s')
logformatter = logging.Formatter(logformat)
if len(rootlogger.handlers) == 0:
	logging.basicConfig(
		format=logformat,
		level=logging.DEBUG,
	)
	for infoOnly in (
		'checkShare',
		#'JSONRPCHandler',
		#'JSONRPCServer',
		'merkleMaker',
		'StratumServer',
		#'Waker for JSONRPCServer',
		'Waker for StratumServer',
		'poolWorker'
	):
		logging.getLogger(infoOnly).setLevel(logging.INFO)
if getattr(config, 'LogToSysLog', False):
	sysloghandler = logging.handlers.SysLogHandler(address = '/dev/log')
	rootlogger.addHandler(sysloghandler)
if hasattr(config, 'LogFile'):
	if isinstance(config.LogFile, str):
		filehandler = logging.FileHandler(config.LogFile)
	else:
		filehandler = logging.handlers.TimedRotatingFileHandler(**config.LogFile)
	filehandler.setFormatter(logformatter)
	rootlogger.addHandler(filehandler)

def RaiseRedFlags(reason):
	logging.getLogger('redflag').critical(reason)
	return reason


from bitcoin.node import BitcoinLink, BitcoinNode
bcnode = BitcoinNode(config.UpstreamNetworkId)
bcnode.userAgent += b'37pool:0.1/'
bcnode.newBlock = lambda blkhash: MM.updateMerkleTree()

import jsonrpc

try:
	import jsonrpc.authproxy
	jsonrpc.authproxy.USER_AGENT = '37pool/0.1'
except:
	pass


from bitcoin.script import BitcoinScript
from bitcoin.txn import Txn
from base58 import b58decode
from binascii import b2a_hex
from struct import pack
import subprocess
from time import time, sleep

def makeCoinbaseTxn(coinbaseValue, useCoinbaser = True, prevBlockHex = None):
	txn = Txn.new()

	if useCoinbaser and hasattr(config, 'CoinbaserCmd') and config.CoinbaserCmd:
		coinbased = 0
		try:
			cmd = config.CoinbaserCmd
			cmd = cmd.replace('%d', str(coinbaseValue))
			cmd = cmd.replace('%p', prevBlockHex or '""')
			p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
			nout = int(p.stdout.readline())
			for i in range(nout):
				amount = int(p.stdout.readline())
				addr = p.stdout.readline().rstrip(b'\n').decode('utf8')
				pkScript = BitcoinScript.toAddress(addr)
				txn.addOutput(amount, pkScript)
				coinbased += amount
		except:
			coinbased = coinbaseValue + 1
		if coinbased >= coinbaseValue:
			logging.getLogger('makeCoinbaseTxn').error('Coinbaser failed!')
			txn.outputs = []
		else:
			coinbaseValue -= coinbased

	pkScript = BitcoinScript.toAddress(config.TrackerAddr)
	txn.addOutput(coinbaseValue, pkScript)

	# TODO
	# TODO: red flag on dupe coinbase
	return txn


from util import Bits2Target

workLog = {}
networkTarget = None
DupeShareHACK = {}

stratumsrv = None
def updateBlocks():
	stratumsrv.updateJob()

def blockChanged():
	global MM, networkTarget
	bits = MM.currentBlock[2]
	if bits is None:
		networkTarget = None
	else:
		networkTarget = Bits2Target(bits)
	if MM.lastBlock != (None, None, None):
		global DupeShareHACK
		DupeShareHACK = {}
		workLog.clear()
	stratumsrv.updateJob(wantClear=True, networkTarget=networkTarget)


from time import sleep, time
import traceback

def poolWorker(wl, ss):
	i = 0
	while True:
		try:
			sleep(5)

			refreshConf = ""
			loadConfig(config, configmod)
			if ss.defaultTarget != config.ShareTarget:
				refreshConf = "defaultTarget"
				ss.defaultTarget = config.ShareTarget
			if ss.MinSubmitInterval != config.MinSubmitInterval:
				refreshConf += (", " if refreshConf else "") + "MinSubmitInterval"
				ss.MinSubmitInterval = config.MinSubmitInterval
			if ss.MaxSubmitInterval != config.MaxSubmitInterval:
				refreshConf += (", " if refreshConf else "") + "MaxSubmitInterval"
				ss.MaxSubmitInterval = config.MaxSubmitInterval
			if ss.GetTxnsInterval != config.GetTxnsInterval:
				refreshConf += (", " if refreshConf else "") + "GetTxnsInterval"
				ss.GetTxnsInterval = config.GetTxnsInterval
			if 	refreshConf:
				poolWorker.logger.info('Refresh config item %s' % (refreshConf,))

			i += 1
			if i == 12:
				i = 0

				now = time()
				pruned = 0
				for username in wl:
					userwork = wl[username]
					for wli in tuple(userwork.keys()):
						if now > userwork[wli][1] + 120:
							del userwork[wli]
							pruned += 1
				if pruned:
					poolWorker.logger.debug('Pruned %d jobs' % (pruned,))
		except:
			poolWorker.logger.error(traceback.format_exc())
poolWorker.logger = logging.getLogger('poolWorker')


from merklemaker import merkleMaker
MM = merkleMaker()
MM.__dict__.update(config.__dict__)
MM.makeCoinbaseTxn = makeCoinbaseTxn
MM.onBlockChange = blockChanged
MM.onBlockUpdate = updateBlocks


from binascii import b2a_hex
from copy import deepcopy
from math import ceil, log
from merklemaker import MakeBlockHeader
from struct import pack, unpack
import threading
from time import time
from util import PendingUpstream, RejectedShare, bdiff1target, dblsha, LEhash2int, swap32, target2bdiff, target2pdiff
import jsonrpc
import traceback

def getStratumJob(jobid, wantClear = False):
	MC = MM.getMC(wantClear)
	(dummy, merkleTree, coinbase, prevBlock, bits) = MC[:5]
	now = time()
	workLog.setdefault(None, {})[jobid] = (MC, now)
	return (MC, workLog[None][jobid])

def getExistingStratumJob(jobid):
	wld = workLog[None][jobid]
	return (wld[0], wld)

loggersShare = []
authenticators = []

RBDs = []
RBPs = []

from bitcoin.varlen import varlenEncode, varlenDecode
import bitcoin.txn
from merklemaker import assembleBlock

if not hasattr(config, 'BlockSubmissions'):
	config.BlockSubmissions = None

RBFs = []
def blockSubmissionThread(payload, blkhash, share):
	if config.BlockSubmissions is None:
		servers = list(a for b in MM.TemplateSources for a in b)
	else:
		servers = list(config.BlockSubmissions)

	if hasattr(share['merkletree'], 'source_uri'):
		servers.insert(0, {
			'access': jsonrpc.ServiceProxy(share['merkletree'].source_uri),
			'name': share['merkletree'].source,
		})
	elif not servers:
		servers = list(a for b in MM.TemplateSources for a in b)

	myblock = (blkhash, payload[4:36])
	payload = b2a_hex(payload).decode('ascii')
	nexterr = 0
	tries = 0
	success = False
	while len(servers):
		tries += 1
		TS = servers.pop(0)
		UpstreamBitcoindJSONRPC = TS['access']
		try:
			# BIP 22 standard submitblock
			reason = UpstreamBitcoindJSONRPC.submitblock(payload)
		except BaseException as gbterr:
			now = time()
			if now > nexterr:
				# FIXME: This will show "Method not found" on pre-BIP22 servers
				RaiseRedFlags(traceback.format_exc())
				nexterr = now + 5
			if MM.currentBlock[0] not in myblock and tries > len(servers):
				RBFs.append( (('next block', MM.currentBlock, now, gbterr), payload, blkhash, share) )
				RaiseRedFlags('Giving up on submitting block to upstream \'%s\'' % (TS['name'],))
				if share['upstreamRejectReason'] is PendingUpstream:
					share['upstreamRejectReason'] = 'GAVE UP'
					share['upstreamResult'] = False
					logShare(share)
				return

			servers.append(TS)
			continue

		# At this point, we have a reason back
		if reason:
			# FIXME: The returned value could be a list of multiple responses
			msg = 'Upstream \'%s\' block submission failed: %s' % (TS['name'], reason,)
			if success and reason in ('stale-prevblk', 'bad-prevblk', 'orphan', 'duplicate'):
				# no big deal
				blockSubmissionThread.logger.debug(msg)
			else:
				RBFs.append( (('upstream reject', reason, time()), payload, blkhash, share) )
				RaiseRedFlags(msg)
		else:
			blockSubmissionThread.logger.debug('Upstream \'%s\' accepted block' % (TS['name'],))
			success = True
		if share['upstreamRejectReason'] is PendingUpstream:
			share['upstreamRejectReason'] = reason
			share['upstreamResult'] = not reason
			logShare(share)
blockSubmissionThread.logger = logging.getLogger('blockSubmission')

def buildStratumData(share, merkleroot):
	(prevBlock, height, bits) = MM.currentBlock

	data = b'\x02\0\0\0'
	data += prevBlock
	data += merkleroot
	data += share['ntime'][::-1]
	data += bits
	data += share['nonce'][::-1]

	share['data'] = data
	return data

def IsJobValid(wli, wluser = None):
	if wluser not in workLog:
		return False
	if wli not in workLog[wluser]:
		return False
	(wld, issueT) = workLog[wluser][wli]
	if time() < issueT - 120:
		return False
	return True

def checkShare(share):
	checkShare.logger.info("Share: %s" % (share))

	if None not in workLog:
		# We haven't yet sent any stratum work for this block
		raise RejectedShare('unknown-work')

	shareTime = share['time']
	username = share['username']

	# Stratum
	isstratum = True
	wli = share['jobid']
	#buildStratumData(share, b'\0' * 32)
	othertxndata = b''
	MWL = workLog[None]
	if wli not in MWL:
		raise RejectedShare('unknown-work')
	(wld, issueT) = MWL[wli]
	#mode = 'MC'
	share['MC'] = wld
	share['issuetime'] = issueT

	(workMerkleTree, workCoinbase) = wld[1:3]
	share['merkletree'] = workMerkleTree
	cbtxn = deepcopy(workMerkleTree.data[0])
	coinbase = workCoinbase + share['extranonce1'] + share['extranonce2']
	cbtxn.setCoinbase(coinbase)
	cbtxn.assemble()
	data = buildStratumData(share, workMerkleTree.withFirst(cbtxn))
	shareMerkleRoot = data[36:68]

	if data in DupeShareHACK:
		raise RejectedShare('duplicate')
	DupeShareHACK[data] = None

	blkhash = dblsha(data)
	if blkhash[28:] != b'\0\0\0\0':
		raise RejectedShare('H-not-zero')
	blkhashn = LEhash2int(blkhash)

	global networkTarget
	logfunc = getattr(checkShare.logger, 'info' if blkhashn <= networkTarget else 'debug')
	#logfunc = checkShare.logger.info
	logfunc('BLKHASH: %64x' % (blkhashn,))
	logfunc(' TARGET: %64x' % (networkTarget,))

	# NOTE: this isn't actually needed for MC mode, but we're abusing it for a trivial share check...
	txlist = workMerkleTree.data
	txlist = [deepcopy(txlist[0]),] + txlist[1:]
	cbtxn = txlist[0]
	cbtxn.setCoinbase(coinbase or workCoinbase)
	cbtxn.assemble()

	if blkhashn <= networkTarget:
		logfunc("Submitting upstream")
		RBDs.append( deepcopy( (data, txlist, share.get('blkdata', None), workMerkleTree, share, wld) ) )
		payload = share['data']
		if len(othertxndata):
			payload += share['blkdata']
		else:
			payload += assembleBlock(data, txlist)[80:]
		logfunc('Real block payload: %s' % (b2a_hex(payload).decode('utf8'),))
		RBPs.append(payload)
		threading.Thread(target=blockSubmissionThread, args=(payload, blkhash, share)).start()
		bcnode.submitBlock(payload)
		if config.DelayLogForUpstream:
			share['upstreamRejectReason'] = PendingUpstream
		else:
			share['upstreamRejectReason'] = None
			share['upstreamResult'] = True
		MM.updateBlock(blkhash)

	if not 'target' in share:
		raise RejectedShare('stale-work')
	workTarget = share['target']
	if blkhashn > workTarget:
		if blkhashn > config.ShareTarget or blkhashn > 2 * workTarget:
			raise RejectedShare('high-hash')
		workTarget *= 2
	share['target'] = workTarget
	#share['_targethex'] = '%064x' % (workTarget,)

	shareTimestamp = unpack('<L', data[68:72])[0]
	if shareTime < issueT - 120:
		raise RejectedShare('stale-work')
	if shareTimestamp < shareTime - 300:
		raise RejectedShare('time-too-old')
	if shareTimestamp > shareTime + 7200:
		raise RejectedShare('time-too-new')

	cbpre = workCoinbase
	cbpreLen = len(cbpre)
	if coinbase[:cbpreLen] != cbpre:
		raise RejectedShare('bad-cb-prefix')

	# Filter out known "I support" flags, to prevent exploits
	for ff in (b'/P2SH/', b'NOP2SH', b'p2sh/CHV', b'p2sh/NOCHV'):
		if coinbase.find(ff) > max(-1, cbpreLen - len(ff)):
			raise RejectedShare('bad-cb-flag')

	if len(coinbase) > 100:
		raise RejectedShare('bad-cb-length')

	if shareMerkleRoot != workMerkleTree.withFirst(cbtxn):
		raise RejectedShare('bad-txnmrklroot')

	if len(othertxndata):
		allowed = assembleBlock(data, txlist)[80:]
		if allowed != share['blkdata']:
			raise RejectedShare('bad-txns')

checkShare.logger = logging.getLogger('checkShare')

def logShare(share):
	#if '_origdata' in share:
	#	share['solution'] = share['_origdata']
	#else:
	#share['solution'] = b2a_hex(swap32(share['data'])).decode('utf8')
	#if 'target' in share:
	#	share['solution'] = '%s*%s' % (b2a_hex(share['data'][4:36]).decode('ascii'), target2bdiff(share['target']))
	#else:
	#	share['solution'] = 0
	share['height'] = share['height']
	share['diff'] = target2bdiff(share['target'] if 'target' in share else config.ShareTarget)
	for i in loggersShare:
		i.logShare(share)

def checkAuthentication(username, password):
	return True

	# HTTPServer uses bytes, and StratumServer uses str
	if hasattr(username, 'decode'): username = username.decode('utf8')
	if hasattr(password, 'decode'): password = password.decode('utf8')

	for i in authenticators:
		if i.checkAuthentication(username, password):
			return True
	return False

def receiveShare(share):
	# TODO: username => userid
	try:
		checkShare(share)
	except RejectedShare as rej:
		share['rejectReason'] = str(rej)
		raise
	except BaseException as e:
		share['rejectReason'] = 'ERROR'
		raise
	finally:
		if not share.get('upstreamRejectReason', None) is PendingUpstream:
			logShare(share)

def newBlockNotification():
	logging.getLogger('newBlockNotification').info('Received new block notification')
	MM.updateMerkleTree()
	# TODO: Force RESPOND TO LONGPOLLS?
	pass

def newBlockNotificationSIGNAL(signum, frame):
	# Use a new thread, in case the signal handler is called with locks held
	thr = threading.Thread(target=newBlockNotification, name='newBlockNotification via signal %s' % (signum,))
	thr.daemon = True
	thr.start()

from signal import signal, SIGUSR1
signal(SIGUSR1, newBlockNotificationSIGNAL)


import os
import os.path
import pickle
import signal
import sys
from time import sleep
import traceback

if getattr(config, 'SaveStateFilename', None) is None:
	config.SaveStateFilename = 'eloipool.worklog'

def stopServers():
	logger = logging.getLogger('stopServers')

	if hasattr(stopServers, 'already'):
		logger.debug('Already tried to stop servers before')
		return
	stopServers.already = True

	logger.info('Stopping servers...')
	global bcnode
	servers = (bcnode, stratumsrv)
	for s in servers:
		s.keepgoing = False
	for s in servers:
		try:
			s.wakeup()
		except:
			logger.error('Failed to stop server %s\n%s' % (s, traceback.format_exc()))
	i = 0
	while True:
		sl = []
		for s in servers:
			if s.running:
				sl.append(s.__class__.__name__)
		if not sl:
			break
		i += 1
		if i >= 0x100:
			logger.error('Servers taking too long to stop (%s), giving up' % (', '.join(sl)))
			break
		sleep(0.01)

	for s in servers:
		for fd in s._fd.keys():
			os.close(fd)

def stopLoggers():
	for i in loggersShare:
		if hasattr(i, 'stop'):
			i.stop()

def saveState(SAVE_STATE_FILENAME, t = None):
	logger = logging.getLogger('saveState')

	# Then, save data needed to resume work
	logger.info('Saving work state to \'%s\'...' % (SAVE_STATE_FILENAME,))
	i = 0
	while True:
		try:
			with open(SAVE_STATE_FILENAME, 'wb') as f:
				pickle.dump(t, f)
				pickle.dump(DupeShareHACK, f)
				pickle.dump(workLog, f)
			break
		except:
			i += 1
			if i >= 0x10000:
				logger.error('Failed to save work\n' + traceback.format_exc())
				try:
					os.unlink(SAVE_STATE_FILENAME)
				except:
					logger.error(('Failed to unlink \'%s\'; resume may have trouble\n' % (SAVE_STATE_FILENAME,)) + traceback.format_exc())

def exit():
	t = time()
	stopServers()
	stopLoggers()
	saveState(config.SaveStateFilename, t=t)
	logging.getLogger('exit').info('Goodbye...')
	os.kill(os.getpid(), signal.SIGTERM)
	sys.exit(0)

def restart():
	t = time()
	stopServers()
	stopLoggers()
	saveState(config.SaveStateFilename, t=t)
	logging.getLogger('restart').info('Restarting...')
	try:
		os.execv(sys.argv[0], sys.argv)
	except:
		logging.getLogger('restart').error('Failed to exec\n' + traceback.format_exc())

def restoreState(SAVE_STATE_FILENAME):
	if not os.path.exists(SAVE_STATE_FILENAME):
		return

	global workLog, DupeShareHACK

	logger = logging.getLogger('restoreState')
	s = os.stat(SAVE_STATE_FILENAME)
	logger.info('Restoring saved state from \'%s\' (%d bytes)' % (SAVE_STATE_FILENAME, s.st_size))
	try:
		with open(SAVE_STATE_FILENAME, 'rb') as f:
			t = pickle.load(f)
			if type(t) == tuple:
				if len(t) > 2:
					# Future formats, not supported here
					ver = t[3]
					# TODO

				# Old format, from 2012-02-02 to 2012-02-03
				workLog = t[0]
				DupeShareHACK = t[1]
				t = None
			else:
				if isinstance(t, dict):
					# Old format, from 2012-02-03 to 2012-02-03
					DupeShareHACK = t
					t = None
				else:
					# Current format, from 2012-02-03 onward
					DupeShareHACK = pickle.load(f)

				if t + 120 >= time():
					workLog = pickle.load(f)
				else:
					logger.debug('Skipping restore of expired workLog')
	except:
		logger.error('Failed to restore state\n' + traceback.format_exc())
		return
	logger.info('State restored successfully')
	if t:
		logger.info('Total downtime: %g seconds' % (time() - t,))


from networkserver import NetworkListener
import threading
import sharelogging
import authentication
from stratumserver import StratumServer
import imp

if args.daemon:
	import daemon
	daemon.daemonize(cdir = None)


if __name__ == "__main__":
	if not hasattr(config, 'ShareLogging'):
		config.ShareLogging = ()
	for i in config.ShareLogging:
		name = i['type']
		parameters = i
		try:
			fp, pathname, description = imp.find_module(name, sharelogging.__path__)
			m = imp.load_module(name, fp, pathname, description)
			lo = getattr(m, name)(**parameters)
			loggersShare.append(lo)
		except:
			logging.getLogger('sharelogging').error("Error setting up share logger %s: %s", name,  sys.exc_info())

	if not hasattr(config, 'Authentication'):
		config.Authentication = ({'module': 'allowall'},)

	for i in config.Authentication:
		name = i['module']
		parameters = i
		try:
			fp, pathname, description = imp.find_module(name, authentication.__path__)
			m = imp.load_module(name, fp, pathname, description)
			lo = getattr(m, name)(**parameters)
			authenticators.append(lo)
		except:
			logging.getLogger('authentication').error("Error setting up authentication module %s: %s", name, sys.exc_info())

	LSbc = []
	if not hasattr(config, 'BitcoinNodeAddresses'):
		config.BitcoinNodeAddresses = ()
	for a in config.BitcoinNodeAddresses:
		LSbc.append(NetworkListener(bcnode, a))

	if hasattr(config, 'UpstreamBitcoindNode') and config.UpstreamBitcoindNode:
		BitcoinLink(bcnode, dest=config.UpstreamBitcoindNode)

	stratumsrv = StratumServer()
	stratumsrv.defaultTarget = config.ShareTarget
	stratumsrv.MinSubmitInterval = config.MinSubmitInterval
	stratumsrv.MaxSubmitInterval = config.MaxSubmitInterval
	stratumsrv.GetTxnsInterval = config.GetTxnsInterval
	stratumsrv.getStratumJob = getStratumJob
	stratumsrv.getExistingStratumJob = getExistingStratumJob
	stratumsrv.receiveShare = receiveShare
	stratumsrv.RaiseRedFlags = RaiseRedFlags
	stratumsrv.IsJobValid = IsJobValid
	#stratumsrv.checkAuthentication = checkAuthentication
	if not hasattr(config, 'StratumAddresses'):
		config.StratumAddresses = ()
	for a in config.StratumAddresses:
		NetworkListener(stratumsrv, a)

	MM.start()

	restoreState(config.SaveStateFilename)

	worker_thr = threading.Thread(target=poolWorker, args=(workLog, stratumsrv))
	worker_thr.daemon = True
	worker_thr.start()

	bcnode_thr = threading.Thread(target=bcnode.serve_forever)
	bcnode_thr.daemon = True
	bcnode_thr.start()

	stratumsrv.serve_forever()
