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

