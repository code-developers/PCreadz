#!/usr/bin/env python

#improts 
import sys
if (sys.version_info > (3, 0)):
    PY2OR3     = "PY3"
else:
    sys.exit("This version only supports python3.\nTry python3 ./Pcredz")
try:
    import pylibpcap as pcap
    from pylibpcap.pcap import rpacp
except ImportError:
    print("pylibpcap is not installed try install pip3 install pylibpcap")
    exit()

import logging
import argparse
import os
import re
import socket
import struct 
import subprocess
import threading
import time
import codecs
from base64 import b64decode
from threading import Thread

def ShowWelcome():
    	Message = 'Pcredz 2.0.2\nAuthor: Laurent Gaffie\nPlease send bugs/comments/pcaps to: laurent.gaffie@gmail.com\nThis script will extract NTLM (HTTP,LDAP,SMB,MSSQL,RPC, etc), Kerberos,\nFTP, HTTP Basic and credit card data from a given pcap file or from a live interface.\n'
	print(Message)

parser = argparse.ArgumentParser(description='Pcredz 1.0.0\nAuthor: Laurent Gaffie')
m_group=parser.add_mutually_exclusive_group()
m_group.add_argument('-f', type=str, dest="fname", default=None, help="Pcap file to parse")
m_group.add_argument('-d', type=str, dest="dir_path", default=None, help="Pcap directory to parse recursivly")
m_group.add_argument('-i', type=str, dest="interface", default=None, help="interface for live capture")
parser.add_argument('-c', action="store_false", dest="activate_cc", default=True, help="deactivate CC number scanning (Can gives false positives!)")
parser.add_argument('-t', action="store_true", dest="timestamp", help="Include a timestamp in all generated messages (useful for correlation)")
parser.add_argument('-v', action="store_true", dest="Verbose", help="More verbose.")

options = parser.parse_args()

if options.fname is None and options.dir_path is None and options.interface is None:
	print('\n\033[1m\033[31m -f or -d or -i mandatory option missing.\033[0m\n')
	parser.print_help()
	exit(-1)

ShowWelcome()
Verbose = options.Verbose
fname = options.fname
dir_path = options.dir_path
interface = options.interface
activate_cc = options.activate_cc
timestamp = options.timestamp
start_time = time.time()

PcredzPath = os.path.abspath(os.path.join(os.path.dirname(__file__)))+"/"
Filename = PcredzPath+"CredentialDump-Session.log"
l= logging.getLogger('Credential-Session')
l.addHandler(logging.FileHandler(Filename,'a'))

def WriteData(outfile, data, user):
	outfile = PcredzPath+outfile
	if type(user) is str:
		user = user.encode('latin-1')
	if not os.path.isfile(outfile):
		with open(outfile,"w") as outf:
			outf.write(data + '\n')
		return
	with open(outfile,"r") as filestr:
		if re.search(codecs.encode(user,'hex'), codecs.encode(filestr.read().encode('latin-1'),'hex')):
			return False
	with open(outfile,"a") as outf2:
		outf2.write(data + '\n')

if activate_cc:
	print("CC number scanning activated\n")
else:
	print("CC number scanning is deactivated\n")
