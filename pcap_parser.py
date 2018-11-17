import os
from scapy.all import *




packets = rdpcap('univ1_pt16')
counter = 0
tcp_count = 0
udp_count = 0
ethernet_count = 0
ip_count = 0
icmp_count = 0

for packet in packets:
    counter += 1

    if packet.haslayer(Ether):
        ethernet_count += 1

    if packet.haslayer(IP):
        ip_count += 1

    elif packet.haslayer(ICMP):
        icmp_count += 1


    if packet.haslayer(TCP):
        tcp_count += 1

    elif packet.haslayer(UDP):
        udp_count += 1


print("number of packets that use Ethernet: " + str(ethernet_count))
print("number of packets that use IP: " + str(ip_count))
print("number of packets that use ICMP: " + str(icmp_count))
print("number of packets that use TCP: " + str(tcp_count))
print("number of packets that use UDP: " + str(udp_count))
print("total number of packets: " + str(counter))
