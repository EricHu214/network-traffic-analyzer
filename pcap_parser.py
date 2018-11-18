import os
from scapy.all import *
import matplotlib.pyplot as plt




packets = rdpcap('univ1_pt16')



def plotCDF():
    plt.xlabel('max size')
    plt.ylabel('number of packets')

    x_data = []
    y_data = []


    for i in range(200):
        if i % 10 == 0:
            x_data.append(i)
            y_data.append(0)


    for packet in packets:
        counter = 0

        for size in x_data:

            if len(packet) <= size:
                y_data[counter] += 1

            counter += 1

    plt.plot(x_data, y_data)
    plt.show()




counter = 0
tcp_count = 0
tcp_bytes = 0
udp_count = 0
udp_bytes = 0
ethernet_count = 0
ethernet_bytes = 0
ip_count = 0
ip_bytes = 0
icmp_count = 0
icmp_bytes = 0
total_len = 0


#for packet in packets:
#    counter += 1
#
#    if packet.haslayer(Ether):
#        ethernet_count += 1
#        ethernet_bytes += len(packet)
#
#    if packet.haslayer(IP):
#        ip_count += 1
#        ip_bytes += len(packet)
#
#    elif packet.haslayer(ICMP):
#        icmp_count += 1
#        icmp_bytes += len(packet)
#
#
#    if packet.haslayer(TCP):
#        tcp_count += 1
#        tcp_bytes += len(packet)
#
#    elif packet.haslayer(UDP):
#        udp_count += 1
#        udp_bytes += len(packet)
#
#    total_len += len(packet)
#

plotCDF()


#file = open("data.txt", "w")
#
#file.write("number of packets that use Ethernet: " + str(ethernet_count) + " percentage is: " + str(ethernet_count/counter) + " and total bytes: " + str(ethernet_bytes) + "\n")
#file.write("number of packets that use IP: " + str(ip_count)  + " percentage is: " + str(ip_count/counter) + " and total bytes: " + str(ip_bytes) + "\n")
#file.write("number of packets that use ICMP: " + str(icmp_count)  + " percentage is: " + str(icmp_count/counter) + " and total bytes: " + str(icmp_bytes) + "\n")
#file.write("number of packets that use UDP: " + str(udp_count)  + " percentage is: " + str(udp_count/counter) + " and total bytes: " + str(udp_bytes) + "\n")
#file.write("number of packets that use TCP: " + str(tcp_count)  + " percentage is: " + str(tcp_count/counter) + " and total bytes: " + str(tcp_bytes) + "\n")
#file.write("total number of bytes of all packets: " + str(total_len) + "\n")
#file.write("total number of packets: " + str(counter) + "\n")
