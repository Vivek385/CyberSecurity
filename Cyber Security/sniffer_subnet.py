import ipaddress
from scapy.all import *

subnet = "10.9.0.0/24"  # Replace with the subnet you want to capture (CIDR notation)
subnet_network = ipaddress.IPv4Network(subnet)

def packet_handler(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check if the source or destination IP is in the specified subnet
        if ipaddress.IPv4Address(src_ip) in subnet_network or ipaddress.IPv4Address(dst_ip) in subnet_network:
            print(f"Captured packet from {src_ip} to {dst_ip}:")
            print(packet.show())

# Sniff packets and apply the packet_handler function to each packet
packet = sniff(iface = 'br-6438effbf2d7', filter="ip", prn=packet_handler)

