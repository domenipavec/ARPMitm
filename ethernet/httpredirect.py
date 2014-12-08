#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# http redirect
# copyright ¢ 2013 by Domen Ipavec

def permanent(url):
	return """HTTP/1.1 301 Moved Permanently
Location: %s
Content-Type: text/html
Content-Length: 108

<html>
<head>
<title>Moved</title>
</head>
<body>
<h1>Moved</h1>
<p>This page has moved.</p>
</body>
</html>""" % url

def temporary(url):
	return """HTTP/1.1 302 Found
Location: %s
Content-Type: text/html
Content-Length: 108

<html>
<head>
<title>Moved</title>
</head>
<body>
<h1>Moved</h1>
<p>This page has moved.</p>
</body>
</html>""" % url

