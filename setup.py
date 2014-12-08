#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# install script
# copyright ¢ 2013 by Domen Ipavec

from setuptools import setup, find_packages
setup(
    name = "Network arp tools",
    version = "0.1",
    packages = find_packages(),
    scripts = ['sendvic.py', 'list-interfaces.py', 'arp-scan.py', 'arp-dos.py'],

    # netifaces - get info on network interfaces
    # netaddr - representation classes for ip and mac addresses
    # tld - get top level domain from url
    install_requires = ['netifaces>=0.8', 'netaddr>=0.7.10', 'tld>=0.6.1'],
)
