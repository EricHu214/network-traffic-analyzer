import os
from scapy.all import *
import matplotlib.pyplot as plt
import dpkt

import pyshark
import numpy as np
from pylab import *




def partitionFile():
    packets = RawPcapReader('univ1_pt16')

    index = 0

    while (index+50000) < len(packets):
        pktdump = RawPcapWriter("partition/"+str(index), append=True, sync=True)
        pktdump.write(packets[index:index+50000][0])
        index+= 50000

    pktdump = PcapWriter("partition/"+str(index), append=True, sync=True)
    pktdump.write(packets[index:len(packets)])




#packets = rdpcap('univ1_pt16')

def plotCDF(step, packetSize, headerSize):
    x_data = []
    y_data = []
    y_data_tcp = []
    y_data_udp = []
    y_data_ip = []
    y_data_nonip = []

    x_header = []

    y_tcp_header = []
    y_udp_header = []
    y_ip_header = []


    for i in range(packetSize):
        if i % step == 0:
            x_data.append(i)
            y_data.append(0)
            y_data_nonip.append(0)
            y_data_ip.append(0)
            y_data_tcp.append(0)
            y_data_udp.append(0)

    for i in range(headerSize):
        if i % step == 0:
            x_header.append(i)
            y_tcp_header.append(0)
            y_udp_header.append(0)
            y_ip_header.append(0)


    pkts = dpkt.pcap.Reader(open('univ1_pt16', "rb"))

    for wirelen, ts, packet in pkts:
        counter = 0

        #header = dpkt.pcap.PktHdr(packet)
        eth=dpkt.ethernet.Ethernet(packet)

        for size in x_data:
            if size < headerSize:

                if eth.type == dpkt.ethernet.ETH_TYPE_IP:
                    ip = eth.data
                    transp = ip.data

                    if ip.hl*4 <= size:
                        y_ip_header[counter] += 1

                    if ip.p == dpkt.ip.IP_PROTO_TCP and ip.data.off * 4 <= size:
                        y_tcp_header[counter] += 1

                    elif ip.p == dpkt.ip.IP_PROTO_UDP and size >= 8:
                        y_udp_header[counter] += 1


            #if wirelen <= size:
            #    y_data[counter] += 1


            #if eth.type==dpkt.ethernet.ETH_TYPE_IP:
            #    ip = eth.data
            #    if ip.len <= size:
            #        y_data_ip[counter] += 1

            #    if size <= 200:
            #        if ip.p == dpkt.ip.IP_PROTO_TCP and (ip.len - ip.hl*4) <= size:
            #            y_data_tcp[counter] += 1

            #        elif ip.p == dpkt.ip.IP_PROTO_UDP and ip.data.ulen <= size:
            #            y_data_udp[counter] += 1

            #elif wirelen <= size:
            #    y_data_nonip[counter] += 1


            if wirelen <= size:
                y_data[counter] += 1


                if eth.type==dpkt.ethernet.ETH_TYPE_IP:
                    ip = eth.data

                    y_data_ip[counter] += 1

                    if ip.p == dpkt.ip.IP_PROTO_TCP:
                        y_data_tcp[counter] += 1

                    elif ip.p == dpkt.ip.IP_PROTO_UDP:
                        y_data_udp[counter] += 1
                else:
                    y_data_nonip[counter] += 1

            counter += 1

    y_data[:] = [x/967143 for x in y_data]
    y_data_tcp[:] = [x/967143 for x in y_data_tcp]
    y_data_udp[:] = [x/967143 for x in y_data_udp]
    y_data_ip[:] = [x/967143 for x in y_data_ip]
    y_data_nonip[:] = [x/967143 for x in y_data_nonip]

    y_ip_header[:] = [x/967143 for x in y_ip_header]
    y_tcp_header[:] = [x/967143 for x in y_tcp_header]
    y_udp_header[:] = [x/967143 for x in y_udp_header]


    plt.xlabel('max packet size')
    plt.ylabel('number of packets')
    plt.plot(x_data, y_data)
    plt.savefig("packet size of all packets.png")
    plt.clf()

    plt.xlabel('max TCP packet size')
    plt.ylabel('number of TCP packets')
    plt.plot(x_data, y_data_tcp)
    plt.savefig("packet size of tcp packets.png")
    plt.clf()

    plt.xlabel('max UDP packet size')
    plt.ylabel('number of UDP packets')
    plt.plot(x_data, y_data_udp)
    plt.savefig("packet size of udp packets.png")
    plt.clf()

    plt.xlabel('max IP packet size')
    plt.ylabel('number of IP packets')
    plt.plot(x_data, y_data_ip)
    plt.savefig("packet size of ip packets.png")
    plt.clf()

    plt.xlabel('max non-ip packet size')
    plt.ylabel('number of non-IP packets')
    plt.plot(x_data, y_data_nonip)
    plt.savefig("packet size of nonip packets.png")
    plt.clf()

    plt.xlabel('max IP header size')
    plt.ylabel('number of IP packets')
    plt.plot(x_header, y_ip_header)
    plt.savefig("header size of IP packets.png")
    plt.clf()

    plt.xlabel('max TCP header size')
    plt.ylabel('number of TCP packets')
    plt.plot(x_header, y_tcp_header)
    plt.savefig("header size of TCP packets.png")
    plt.clf()

    plt.xlabel('max UDP header size')
    plt.ylabel('number of UDP packets')
    plt.plot(x_header, y_udp_header)
    plt.savefig("header size of UDP packets.png")
    plt.clf()


def count_protocols():
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

    pkts = dpkt.pcap.Reader(open('../univ1_pt16', "rb"))

    for wirelen, ts, packet in pkts:
        counter += 1

        eth=dpkt.ethernet.Ethernet(packet)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_ARP or eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ethernet_count += 1
            #ethernet_bytes += len(packet)
            ethernet_bytes += wirelen


        if eth.type==dpkt.ethernet.ETH_TYPE_IP:
            ip_count += 1
            #ip_bytes += len(packet)
            ip_bytes += wirelen

            ip = eth.data

            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp_count += 1
                #tcp_bytes += len(packet)
                tcp_bytes += wirelen

            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                udp_count += 1
                #udp_bytes += len(packet)
                udp_bytes += wirelen

            elif ip.p == dpkt.ip.IP_PROTO_ICMP:
                icmp_count += 1
                #icmp_bytes += len(packet)
                icmp_bytes += wirelen

        #total_len += len(packet)
        total_len += wirelen


    print("number of packets that use Ethernet: " + str(ethernet_count) + " percentage is: " + str(ethernet_count/counter*100) + " and total bytes: " + str(ethernet_bytes) + "\n")
    print("number of packets that use IP: " + str(ip_count)  + " percentage is: " + str(ip_count/counter*100) + " and total bytes: " + str(ip_bytes) + "\n")
    print("number of packets that use ICMP: " + str(icmp_count)  + " percentage is: " + str(icmp_count/counter*100) + " and total bytes: " + str(icmp_bytes) + "\n")
    print("number of packets that use UDP: " + str(udp_count)  + " percentage is: " + str(udp_count/counter*100) + " and total bytes: " + str(udp_bytes) + "\n")
    print("number of packets that use TCP: " + str(tcp_count)  + " percentage is: " + str(tcp_count/counter*100) + " and total bytes: " + str(tcp_bytes) + "\n")
    print("total number of bytes of all packets: " + str(total_len) + "\n")
    print("total number of packets: " + str(counter) + "\n")



#count_protocols()
#plotCDF()
