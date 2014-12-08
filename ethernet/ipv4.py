#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# ipv4 packets (only non divided)
# copyright ¢ 2013 by Domen Ipavec

import struct, copy
from __init__ import IPFromBin, checksum

# Upper layer protocols
PROTOCOL_TCP = 0x06

# ip packet
# ihl - internet header length
# dscp - Differentiated Services Code Point
# ecn - Explicit Congestion Notification
# ttl - Time to Live
class IPv4:
	def __init__(self, src, dst = None, data= None, ihl = None, dscp = None, ecn = None, ident = None, flags = None, fo = None, ttl = None, prot = None, options = ''):
		if dst == None:
			# init packet from binary in src
			header = struct.unpack("!BBHHBBBBH", src[:12])
			self.version = header[0] >> 4
			self.ihl = header[0] & 0b1111
			self.dscp = header[1] >> 2
			self.ecn = header[1] & 0b11
			self.identification = header[3]
			self.flags = header[4] >> 5
			self.fragmentOffset = (header[4] & 0b11111) | (header[5] << 5)
			self.ttl = header[6]
			self.protocol = header[7]
			self.sourceIP = IPFromBin(src[12:16])
			self.destinationIP = IPFromBin(src[16:20])
			self.options = src[20:self.ihl*4]
			self.data = src[self.ihl*4:header[2]]
		else:
			# init packet from vars
			self.version = 4
			self.ihl = ihl
			self.dscp = dscp
			self.ecn = ecn
			self.identification = ident
			self.flags = flags
			self.fragmentOffset = fo
			self.ttl = ttl
			self.protocol = prot
			self.sourceIP = src
			self.destinationIP = dst
			self.options = options
			self.data = data
			
	# make a packet for a reply with data
	def reply(self, data):
		r = copy.copy(self)
		r.sourceIP = self.destinationIP
		r.destinationIP = self.sourceIP
		r.data = data
		r.fragmentOffset = 0
		return r
			
	# binary packet
	def __str__(self):
		# combine bytes from multiple fields
		b0 = (self.version << 4) | self.ihl
		b1 = (self.dscp << 2) | self.ecn
		b5 = (self.flags << 5) | (self.fragmentOffset & 0b011111)
		b6 = self.fragmentOffset >> 5
		
		# total length = header + data
		totalLength = 4*self.ihl + len(self.data)
		
		# header with 0 for checksum
		header = struct.pack("!BBHHBBBBH", b0, b1, totalLength, self.identification, b5, b6, self.ttl, self.protocol, 0) + self.sourceIP.packed + self.destinationIP.packed + self.options
		
		header = header[0:10] + checksum(header) + header[12:]
		return header + self.data
	
	# enable concatenation with strings
	def __add__(self, other):
		return str(self) + other
	
	def __radd__(self, other):
		return other + str(self)
