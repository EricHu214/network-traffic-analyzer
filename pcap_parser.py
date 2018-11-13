import os
from scapy.all import *




packets = rdpcap('univ1_pt16')
counter = 0
tcp_count = 0
udp_count = 0

for packet in packets:
    counter += 1
    if packet.haslayer(TCP):
        tcp_count += 1

    if packet.haslayer(UDP):
        udp_count += 1


print(tcp_count)
print(udp_count)
print(counter)
