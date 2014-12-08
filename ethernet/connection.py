#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# send ethernet packets
# copyright ¢ 2013 by Domen Ipavec

from __init__ import MACFromBin

import socket, struct

# differenc ethertypes
ETHERTYPE_IPv4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_WoL = 0x0842
ETHERTYPE_RARP = 0x8035
ETHERTYPE_IPv6 = 0x86DD

class EthernetConnection:
	def __init__(self, destination, ethertype, interface = "eth0", source = None):
		self.destination = destination
		
		# validate ethertype
		if not isinstance(ethertype, int) or ethertype < 0 or ethertype > 0xffff:
			raise Exception("Ethertype needs to be an integer between 0 and 0xffff.")
		self.ethertype = ethertype
		
		# make and bind rawsocket
		self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, self.ethertype)
		self.sock.bind((interface, self.ethertype))
		
		# get source mac from socket if not given
		if source == None:
			self.source = MACFromBin(self.sock.getsockname()[4])
		else:
			self.source = source

	# send ethernet packet
	def send(self, data, dst = None, src = None):
		# allow to set custom destination and/or source
		if dst == None:
			dst = self.destination
		if src == None:
			src = self.source
		
		self.sock.send(struct.pack("!6s6sH", dst.packed, src.packed, self.ethertype) + data)
	
	def setTimeout(self, t):
		self.sock.settimeout(t)
		
	def close(self):
		self.sock.close()
	
	# receive ethernet packet
	def receive(self):
		data = self.sock.recv(1514)
		header = struct.unpack("!6s6sH", data[:14])
		# return tuple: (destination, source, ethertype, data)
		return (MACFromBin(header[0]), MACFromBin(header[1]), header[2], data[14:])
