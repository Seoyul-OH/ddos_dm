#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP


def main():

    if len(sys.argv)<3:
        exit(1)

    addr = socket.gethostbyname(sys.argv[1]) #srcaddr
    addr1 = socket.gethostbyname(sys.argv[2]) #dstaddr
    iface = sys.argv[3]

    print("sending on interface %s to %s" % (iface, str(addr)))
    pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt1 = pkt /IP(src=addr, dst=addr1) / TCP(dport=1234, sport=random.randint(49152,65535)) / "hi"
    pkt1.show2()
    sendp(pkt1, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
    
#usage: sudo python3 send.py src dst veth
