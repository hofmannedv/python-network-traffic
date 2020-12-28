
# original Python code by Raul Becerra

import subprocess
import traceback
import time
import math
from scapy.utils import *

process = subprocess.Popen(['sudo', 'tcpdump', '-XX', '-i', ETHERNET_ADAPTER], bufsize=-1, stdout=subprocess.PIPE)
for linne in iter(process.stdout.readline, ''):
        linne = linne.decode('utf-8')
        print(linne)





# The below code also does the exact same output however I cannot turn off the print statement. It is an incorrect solution becuase of the failure to turn off the print statement

def pkt_callback(pkt):
        data = hexdump(pkt.payload)
        # For some reason it prints the output and I cannot turn it off

sniff(iface="enth0", prn=pkt_callback, store=0)
