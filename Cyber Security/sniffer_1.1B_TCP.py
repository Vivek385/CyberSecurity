from scapy.all import *

def print_pkt(packet):
    if packet.haslayer(TCP):
        print('found')
        src_ip = packet[IP].src
        dst_port = packet[TCP].dport
        print(src_ip, dst_port)
        # Define the IP address and destination port you want to filter
        target_ip = "10.9.0.5"  # Replace with the IP address you want to filter
        target_port = 23  # Destination port 23 (Telnet)

        if src_ip == target_ip and dst_port == target_port:
            print(packet.show())

# Sniff packets and apply the packet_handler function to each packet
packet = sniff(iface = 'br-6438effbf2d7', filter="tcp", prn=print_pkt)

