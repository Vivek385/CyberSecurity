from scapy.all import *

def print_pkt(pkt):
    pkt.show()

pkt = sniff(iface = 'br-6438effbf2d7', filter='icmp', prn=print_pkt)
