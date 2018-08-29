#!/usr/bin/python

import subprocess
import re
CRED = '\033[91m'
CYELLO = '\033[33m'
CEND = '\033[0m'

# Find parent information
def find_parent(list, pid_tgid):
	p = re.compile('PID .*?,')
	m = p.search(pid_tgid)
	pid = m.group()

	for data in list:
		if pid in data:
			p = re.compile('\[.*?\]\[.*?\]')
			m = p.search(data)
			return m.group()

	return ""

# Main
if __name__ == "__main__":
	raw_data = subprocess.check_output(['journalctl', '-b'])
	raw_data = raw_data.split('\n')

	print "Extract Gatekeeper logs..."

	p = re.compile('VM \[.*?\] ')
	gatekeeper_log = []
	for data in raw_data:
		if 'shadow-box:' in data:
			data = p.sub('', data)
			gatekeeper_log.append(data)

	print "  [*] Complete\n"

	print "Find root..."
	count = 0

	p = re.compile('\[.*?\]\[.*?\]')
	for data in gatekeeper_log:
		if 'An abnormal privilege escalation' in data:
			m = p.search(data)
			print "  [%d] " % count + CRED + "ERR :", m.group(), "tried to get root abnormally" + CEND
			count = count + 1
		elif 'is executed and has privilege' in data:
			m = p.search(data)
			print "  [%d] " % count + CYELLO + "WARN:" + CEND, find_parent(gatekeeper_log, m.group()), "created", CYELLO + m.group() +CEND
			count = count + 1
		elif 'cred is changed,' in data:
			m = p.search(data)
			print "  [%d] " % count + CYELLO + "WARN:", m.group(), "got root" + CEND
			count = count + 1

	print "  [*] Complete"
