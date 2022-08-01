#!/usr/bin/env python

import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr, bind_layers 
from scapy.all import Packet, IPOption
from scapy.all import *
from scapy.layers.inet import _IPOption_HDR
from scapy.all import IP, TCP, UDP, Raw, Ether, Padding
from time import sleep
import argparse


parser = argparse.ArgumentParser(description='send entry packet')
parser.add_argument('--i', required=False, type=str, default='veth0', help='i')
a = parser.parse_args()
global count
count = 0



class frame_type(Packet):
    """ Frame_type Header """
    name = "frame_type"
    fields_desc = [
        BitField("frame_type", 0, 8),
        BitField("switch_id", 1, 8),
    ] 

class preamble(Packet):
    """ preamble Header """
    name = "preamble"
    fields_desc = [
        BitField("k", 0, 8),
        BitField("end", 0, 8),
        BitField("worker_id", 1, 8),
        BitField("epoch", 1, 16),
        IntField("seg_number", 0),
        BitField("pool_version", 1, 8),
        IntField("pool_index", 1),
    ] 

class ENTRY(Packet):
    name = "ENTRY"
    fields_desc = [
        SignedIntField("value", 0)
    ]

    def guess_payload_class(self, payload):
        return ENTRY

bind_layers(UDP, frame_type)
bind_layers(frame_type, preamble)
bind_layers(preamble, ENTRY)


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if iface in i:
            iface=i
            break;
    if not iface:
        print ("Cannot find %s interface" % (iface))
        exit(1)
    return iface

def handle_pkt(pkt):
    global count
    count = count + 1
    # print(count)
    pkt.show()
    
    ### Test ###
    #if (pkt[frame_type].frame_type == 2) and pkt[preamble].pool_index % 1024 == 0:
        # pkt.show()
     #   print(count, len((pkt[5])))


def main():
    
    iface = a.i
    print ("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface = iface,
          prn = lambda x: handle_pkt(x))
    



if __name__ == '__main__':
    main()


# sudo python receive.py -i veth1


