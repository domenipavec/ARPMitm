#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# tcp packets
# copyright ¢ 2013 by Domen Ipavec

import struct, copy
from __init__ import checksum

# binary representation of bit from offset
def BIT(offset):
	return 1<<offset

# check if bit is set
def BITSET(int_type, offset):
	return bool(int_type & BIT(offset))

# set n-th bit if value == True
def SETBIT(int_type, offset, value = True):
	return int_type | (BIT(offset) * value)
	

# TCP packet
# NS - ECN-nonce
# CWR - Congestion Window Reduced
# ECE - ECN-Echo
# URG - Urgent
# ACK - Acknowledge
# PSH - Push function
# RST - Reset the connection
# SYN - Synchronize
# FIN - No more data from sender
class TCP:
	def __init__(self, srcPort, dstPort = None, data= None, seqNumber = None, ackNumber = None, dataOffset = None, NS = None, CWR = None, ECE = None, URG = None, ACK = None, PSH = None, RST = None, SYN = None, FIN = None, windowSize = None, urgentPointer = None, options = ''):
		if dstPort == None:
			# init tcp from binary in srcPort
			header = struct.unpack("!HHIIBBHHH", srcPort[:20])
			self.sourcePort = header[0]
			self.destinationPort = header[1]
			self.seqNumber = header[2]
			self.ackNumber = header[3]
			self.dataOffset = header[4] >> 4
			self.NS = BITSET(header[4], 0)
			self.CWR = BITSET(header[5], 7)
			self.ECE = BITSET(header[5], 6)
			self.URG = BITSET(header[5], 5)
			self.ACK = BITSET(header[5], 4)
			self.PSH = BITSET(header[5], 3)
			self.RST = BITSET(header[5], 2)
			self.SYN = BITSET(header[5], 1)
			self.FIN = BITSET(header[5], 0)
			self.windowSize = header[6]
			self.urgentPointer = header[8]
			self.options = srcPort[20:self.dataOffset*4]
			self.data = srcPort[self.dataOffset*4:]
		else:
			# init tcp from vars
			self.sourcePort = srcPort
			self.destinationPort = dstPort
			self.seqNumber = seqNumber
			self.ackNumber = ackNumber
			self.dataOffset = dataOffset
			self.NS = NS
			self.CWR = CWR
			self.ECE = ECE
			self.URG = URG
			self.ACK = ACK
			self.PSH = PSH
			self.RST = RST
			self.SYN = SYN
			self.FIN = FIN
			self.windowSize = windowSize
			self.urgentPointer = urgentPointer
			self.options = options
			self.data = data
	
	# make a reply packet with data
	def reply(self, data):
		r = copy.copy(self)
		r.data = data
		r.sourcePort = self.destinationPort
		r.destinationPort = self.sourcePort
		r.ACK = True
		r.seqNumber = self.ackNumber
		r.ackNumber = self.seqNumber + len(self.data)
		# remove options (may contain timestamp)
		r.options = ''
		r.dataOffset = 5
		return r
	
	# binary packet, need ip_packet to construct ip pseudo header
	def binary(self, ip_packet):
		# join multi-field bytes
		b0 = self.dataOffset << 4
		b0 = SETBIT(b0, 0, self.NS)
		b1 = 0
		b1 = SETBIT(b1, 7, self.CWR)
		b1 = SETBIT(b1, 6, self.ECE)
		b1 = SETBIT(b1, 5, self.URG)
		b1 = SETBIT(b1, 4, self.ACK)
		b1 = SETBIT(b1, 3, self.PSH)
		b1 = SETBIT(b1, 2, self.RST)
		b1 = SETBIT(b1, 1, self.SYN)
		b1 = SETBIT(b1, 0, self.FIN)
		
		# packet with 0 for checksum
		packet = struct.pack("!HHIIBBHHH", self.sourcePort, self.destinationPort, self.seqNumber, self.ackNumber, b0, b1, self.windowSize, 0, self.urgentPointer) + self.options + self.data
		
		ipPseudoHeader = ip_packet.sourceIP.packed + ip_packet.destinationIP.packed + '\x00\x06' + struct.pack("!H", len(packet))
		
		packet = packet[0:16] + checksum(ipPseudoHeader + packet) + packet[18:]
		return packet
