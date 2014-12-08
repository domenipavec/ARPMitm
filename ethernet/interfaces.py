#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# netifaces with additional features
# copyright ¢ 2013 by Domen Ipavec

import netifaces, os, struct, socket
from __init__ import IPFromBin
from netaddr import IPAddress, IPNetwork, EUI

# list available interfaces
def interfaces():
	return netifaces.interfaces()

# get gateway of ifname
def gateway(ifname):
	if os.name == "posix":
		# based on http://stackoverflow.com/a/6556951
		f = os.popen("cat /proc/net/route | grep " + ifname)
		lines = f.readlines()
		f.close()
		for line in lines:
			fields = line.strip().split()
			if fields[1] != '00000000' or not int(fields[3], 16) & 2:
				continue
			return IPFromBin(struct.pack("<L", int(fields[2], 16)))
		raise Exception("Could not get gateway for: " + str(ifname))
	else:
		raise Exception("This OS is not supported.")

# get ipv4 data for interface
def IPv4(interface):
	data = netifaces.ifaddresses(interface)
	if netifaces.AF_INET not in data:
		raise Exception("IPv4 data for %s not available." % interface)
	ipv4 = {}
	ipv4['network'] = IPNetwork(data[netifaces.AF_INET][0]['addr'] + "/" + data[netifaces.AF_INET][0]['netmask'])
	try:
		ipv4['gateway'] = gateway(interface)
	except:
		pass
	return ipv4

# get ipv6 data for interface
def IPv6(interface):
	data = netifaces.ifaddresses(interface)
	if netifaces.AF_INET6 not in data:
		raise Exception("IPv6 data for %s not available." % interface)
	return IPNetwork(data[netifaces.AF_INET6][0]['addr'] + "/" + data[netifaces.AF_INET6][0]['netmask'])

# get mac data for interface
def MAC(interface):
	data = netifaces.ifaddresses(interface)
	mac = {}
	mac['addr'] = EUI(data[netifaces.AF_LINK][0]['addr'])
	# sometimes mac broadcast is not defined in netifaces data
	if 'broadcast' not in data[netifaces.AF_LINK][0]:
		mac['broadcast'] = EUI("ff:ff:ff:ff:ff:ff")
	else:
		mac['broadcast'] = EUI(data[netifaces.AF_LINK][0]['broadcast'])
	return mac

# find interface with name, mac or ip
def findInterface(feature):
	interfaces = netifaces.interfaces()
	
	# if feature is interface name, just return
	if feature in interfaces:
		return feature
	
	# try transforming feature to EUI mac address
	mac = ''
	try:
		mac = EUI(feature)
	except:
		pass
	
	# try transforming feature to IP
	ip = IPAddress("0.0.0.0")
	try:
		ip = IPAddress(feature)
	except:
		pass
	
	for interface in interfaces:
		# if mac's match
		if mac == MAC(interface)['addr']:
			return interface
		try:
			# if ip is in network range of this interface
			if ip in IPv4(interface)['network']:
				return interface
		except:
			pass
	
	raise Exception("Interface %s not found." % feature)
	
