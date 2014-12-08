#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# scan network with arp requests
# copyright ¢ 2013 by Domen Ipavec

import interfaces, connection, arp
import threading, time

# scan network on interface ifname
def scan(ifname):
	# get interface and addresses
	interface = interfaces.findInterface(ifname)
	mac_addresses = interfaces.MAC(interface)
	ip_addresses = interfaces.IPv4(interface)
	
	# make ethernet connection with receive timeout
	c = connection.EthernetConnection(mac_addresses['broadcast'], connection.ETHERTYPE_ARP, interface)
	# need timeout on receive, so we can exit thread
	c.setTimeout(.1)

	# receive arp packets in seperate thread, save in data 
	receive = True
	data = {}
	def scan_receive_thread():
		while receive:
			try:
				packet = arp.ARP(c.receive()[3])
				data[packet.spa] = packet.sha
			except:
				pass

	# create and start receive thread
	t = threading.Thread(target = scan_receive_thread)
	t.start()
	
	# send arp request for all ips in network except broadcast and network
	for ip in ip_addresses['network']:
		if ip != ip_addresses['network'].network and ip != ip_addresses['network'].broadcast:
			c.send(arp.ARP(c.source, ip_addresses['network'].ip, mac_addresses['broadcast'], ip, arp.ARP_REQUEST))
	
	# wait a bit and stop receive thread
	time.sleep(.5)
	receive = False
	t.join()
	
	# close connection and return data
	c.close()
	return data
