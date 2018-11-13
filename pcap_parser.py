import os
from scapy.all import *




packets = rdpcap('univ1_pt16')
counter = 0

for packet in packets:
    counter += 1


print(counter)
