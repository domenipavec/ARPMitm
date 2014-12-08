#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# http requests
# copyright ¢ 2013 by Domen Ipavec

from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
from cgi import parse_header, parse_multipart
from urlparse import parse_qs

# parse http request from string based on: 
# http://stackoverflow.com/a/5964334
# http://stackoverflow.com/a/13330449
class HTTPRequest(BaseHTTPRequestHandler):
	def __init__(self, request_text):
		self.rfile = StringIO(request_text)
		self.raw_requestline = self.rfile.readline()
		self.error_code = self.error_message = None
		self.parse_request()

	def send_error(self, code, message):
		self.error_code = code
		self.error_message = message
  
	def parsePOST(self):
		postvars = {}
		if 'content-type' in self.headers:
			ctype, pdict = parse_header(self.headers['content-type'])
			if ctype == 'multipart/form-data':
				postvars = parse_multipart(self.rfile, pdict)
			elif ctype == 'application/x-www-form-urlencoded':
				length = int(self.headers['content-length'])
				postvars = parse_qs(self.rfile.read(length), keep_blank_values=1)
		return postvars     
     
