#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# List interfaces with addresses
# copyright ¢ 2013 by Domen Ipavec

import ethernet.interfaces as interfaces
from printformat import fancy_dict
import sys

def process_interface(interface):
	print "Interface name:", interface
	# print mac, ipv4 and ipv6 info for interface if available
	try:
		s = fancy_dict(interfaces.MAC(interface))
		print "MAC:", s
	except:
		pass
	try:
		s = fancy_dict(interfaces.IPv4(interface))
		print "IPv4:", s
	except:
		pass
	try:
		s = str(interfaces.IPv6(interface))
		print "IPv6:", s
	except:
		pass
	print ''

# if no arguments print all interface, otherwise print given interfaces
if len(sys.argv) == 1:
	for interface in interfaces.interfaces():
		process_interface(interface)
else:
	for arg in sys.argv[1:]:
		process_interface(interfaces.findInterface(arg))
