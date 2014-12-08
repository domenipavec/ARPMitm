#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# common functions
# copyright ¢ 2013 by Domen Ipavec

from netaddr import EUI, IPAddress
import struct, socket

# EUI MAC representation from binary MAC
def MACFromBin(mac_string):
    return EUI(':'.join('%02x' % ord(b) for b in mac_string))

# IPAddress from binary IP
def IPFromBin(ip_string):
	return IPAddress(socket.inet_ntoa(ip_string))

# 16-bit checksum for TCP and IP
def checksum(packet):
	# add '\0' byte if not dividable by 2
	if len(packet) % 2 != 0:
		packet += '\0'

	# split into 16-bit words and sum them
	words = struct.unpack("!%dH" % (len(packet) / 2), packet)
	s = sum(words)

	# compress in 16 bits if larger
	if s > 0xffff:
		hi = ((s >> 16) & 0xffff)
		lo = s & 0xffff
		s = hi + lo

	# return complement in binary form
	return struct.pack("!H", (~s) & 0xffff)
