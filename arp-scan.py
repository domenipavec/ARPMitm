#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Scan hosts on network with arp
# copyright ¢ 2013 by Domen Ipavec

import ethernet.interfaces as interfaces
import ethernet.arpscan as arpscan

import sys

def process_scan(scan):
	for ip in scan:
		print "Host: %s MAC: %s (%s)" % (str(ip), str(scan[ip]), scan[ip].oui.registration().org)

if len(sys.argv) == 1:
	print "Usage: command network-interface(s)"
else:
	for arg in sys.argv[1:]:
		print "ARP scan for '%s':" % arg
		process_scan(arpscan.scan(interfaces.findInterface(arg)))
