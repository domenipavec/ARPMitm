#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# format for print
# copyright ¢ 2013 by Domen Ipavec

# comma seperated list values
def fancy_list(l):
	return ', '.join(str(x) for x in l)

# comma seperated key: value
def fancy_dict(d):
	s = ''
	for key in d.keys():
		s += key + ": " + str(d[key]) + ", "
	return s[:-2]

# byte size with postfix
def byte_size(num):
    for x in ['bytes','KB','MB','GB','TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0
