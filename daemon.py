# Daemonize your python app.

import sys, os
from signal import SIGTERM

def daemonize(cdir = '/'):
	try:
		pid = os.fork()
		if pid > 0:
			sys.exit(0)
	except OSError as e:
		sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
		sys.exit(1)

	if cdir:
		os.chdir(cdir)
	os.setsid()
	os.umask(0)

	try:
		pid = os.fork()
		if pid > 0:
			sys.exit(0)
	except OSError as e:
		sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
		sys.exit(1)

	si = open('/dev/null', 'r')
	se = so = open('/dev/null', 'a+')
	os.dup2(si.fileno(), sys.stdin.fileno())
	os.dup2(so.fileno(), sys.stdout.fileno())
	os.dup2(se.fileno(), sys.stderr.fileno())
