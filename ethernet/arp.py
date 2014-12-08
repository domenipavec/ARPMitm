#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# arp packets
# copyright ¢ 2013 by Domen Ipavec

import struct
from __init__ import IPFromBin, MACFromBin

# Protocol types
HTYPE_ETHERNET = 1
PTYPE_IPv4 = 0x0800

# Length of addresses
HLEN_ETHERNET = 6
PLEN_IPv4 = 4

# Type of arp packet
ARP_REQUEST = 1
ARP_REPLY = 2

# Arp packet class
# sha - source hardware address
# spa - source protocol address
# tha - target hardware address
# tpa - target protocol address
# operation - ARP_REQUEST or ARP_REPLY
# htype - hardware type
# ptype - protocol type
# hlen - length of hardware address
# plen - length of protocol address
class ARP:
	def __init__(self, sha, spa = None, tha = None, tpa = None, operation = None, htype = HTYPE_ETHERNET, ptype = PTYPE_IPv4, hlen = HLEN_ETHERNET, plen = PLEN_IPv4):
		if spa == None:
			# init from binary in sha
			firstPart = struct.unpack("!HHBBH", sha[:8])
			self.htype = firstPart[0]
			self.ptype = firstPart[1]
			self.hlen = firstPart[2]
			self.plen = firstPart[3]
			self.operation = firstPart[4]
			secondPart = struct.unpack("%ds%ds%ds%ds" % (self.hlen, self.plen, self.hlen, self.plen), sha[8:28])
			
			# if ethernet store as EUI mac type
			if self.htype == HTYPE_ETHERNET:
				self.sha = MACFromBin(secondPart[0])
				self.tha = MACFromBin(secondPart[2])
			else:
				self.sha = secondPart[0]
				self.tha = secondPart[2]
				
			# if ipv4, store as IPAddress
			if self.ptype == PTYPE_IPv4:
				self.spa = IPFromBin(secondPart[1])
				self.tpa = IPFromBin(secondPart[3])
			else:
				self.spa = secondPart[1]
				self.tpa = secondPart[3]
		else:
			# init from vars
			self.operation = operation
			self.htype = htype
			self.ptype = ptype
			self.hlen = hlen
			self.plen = plen
			self.sha = sha
			self.tha = tha
			self.spa = spa
			self.tpa = tpa
	
	# get binary packet
	def __str__(self):
		# if ethernet, retrieve binary from EUI
		if self.htype == HTYPE_ETHERNET:
			sha = self.sha.packed
			tha = self.tha.packed
		else:
			sha = self.sha
			tha = self.tha
		# if ipv4, retrieve binary from IPAddress
		if self.ptype == PTYPE_IPv4:
			tpa = self.tpa.packed
			spa = self.spa.packed
		else:
			tpa = self.tpa
			spa = self.spa
		return struct.pack("!HHBBH%ds%ds%ds%ds" % (self.hlen, self.plen, self.hlen, self.plen), self.htype, self.ptype, self.hlen, self.plen, self.operation, sha, spa, tha, tpa)
	
	# enable concatenation with other strings
	def __add__(self, other):
		return str(self) + other
	
	def __radd__(self, other):
		return other + str(self)
