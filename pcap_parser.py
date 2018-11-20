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


def pysharkCapture():
    cap = pyshark.FileCapture('univ1_pt16')
    total_len = 0
    for packet in cap:
        total_len += int(packet.length)

    print(total_len)

def plotCDF():
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


    for i in range(1000):
        if i % 5 == 0:
            x_data.append(i)
            y_data.append(0)
            y_data_tcp.append(0)
            y_data_udp.append(0)
            y_data_ip.append(0)
            y_data_nonip.append(0)

    for i in range(41):
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

            if wirelen <= size:
                y_data[counter] += 1


                if eth.type==dpkt.ethernet.ETH_TYPE_IP:
                    y_data_ip[counter] += 1

                    ip = eth.data
                    if ip.p == dpkt.ip.IP_PROTO_TCP:
                        y_data_tcp[counter] += 1

                    elif ip.p == dpkt.ip.IP_PROTO_UDP:
                        y_data_udp[counter] += 1
                else:
                    y_data_nonip[counter] += 1

            counter += 1
                #
                #if packet.haslayer(TCP):
                #    y_data_tcp[counter] += 1

                #elif packet.haslayer(UDP):
                #    y_data_udp[counter] += 1

                #if packet.haslayer(IP):
                #    y_data_ip[counter] += 1
                #else:
                #    y_data_nonip[counter] += 1

            #if size <= 40:
            #    if packet.haslayer(IP) and len(packet.getlayer(IP)) <= size:
            #        y_ip_header[counter] += 1

            #    if packet.haslayer(TCP) and len(packet.getlayer(TCP)) <= size:
            #        y_tcp_header[counter] += 1
            #    elif packet.haslayer(UDP) and len(packet.getlayer(UDP)) <= size:
            #        y_udp_header[counter] += 1

            #counter += 1


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


    #plt.xlabel('max IP header size')
    #plt.ylabel('number of IP packets')
    #plt.plot(x_data, y_ip_header)
    #plt.savefig("header size of IP packets.png")
    #plt.clf()

    #plt.xlabel('max TCP header size')
    #plt.ylabel('number of TCP packets')
    #plt.plot(x_data, y_tcp_header)
    #plt.savefig("header size of TCP packets.png")
    #plt.clf()

    #plt.xlabel('max UDP header size')
    #plt.ylabel('number of UDP packets')
    #plt.plot(x_data, y_udpheader)
    #plt.savefig("header size of UDP packets.png")
    #plt.clf()


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

        #if packet.haslayer(Ether):
        #    ethernet_count += 1
        #    ethernet_bytes += len(packet)

        #if packet.haslayer(IP):
        #    ip_count += 1
        #    ip_bytes += len(packet)

        #elif packet.haslayer(ICMP):
        #    icmp_count += 1
        #    icmp_bytes += len(packet)


        #if packet.haslayer(TCP):
        #    tcp_count += 1
        #    tcp_bytes += len(packet)

        #elif packet.haslayer(UDP):
        #    udp_count += 1
        #    udp_bytes += len(packet)

        #total_len += len(packet)

    #file = open("data.txt", "w")

    print("number of packets that use Ethernet: " + str(ethernet_count) + " percentage is: " + str(ethernet_count/counter*100) + " and total bytes: " + str(ethernet_bytes) + "\n")
    print("number of packets that use IP: " + str(ip_count)  + " percentage is: " + str(ip_count/counter*100) + " and total bytes: " + str(ip_bytes) + "\n")
    print("number of packets that use ICMP: " + str(icmp_count)  + " percentage is: " + str(icmp_count/counter*100) + " and total bytes: " + str(icmp_bytes) + "\n")
    print("number of packets that use UDP: " + str(udp_count)  + " percentage is: " + str(udp_count/counter*100) + " and total bytes: " + str(udp_bytes) + "\n")
    print("number of packets that use TCP: " + str(tcp_count)  + " percentage is: " + str(tcp_count/counter*100) + " and total bytes: " + str(tcp_bytes) + "\n")
    print("total number of bytes of all packets: " + str(total_len) + "\n")
    print("total number of packets: " + str(counter) + "\n")


def flow_rebuild():

    # header flag reference
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    TCP_flow_pc={}
    UDP_flow_pc={}

    TCP_flow_bs={}
    UDP_flow_bs={}

    TCP_flow_f={}

    counter = 0
    tcp_count = 0
    udp_count = 0


    pkts = dpkt.pcap.Reader(open('univ1_pt16', "rb"))

    for wirelen, ts, packet in pkts:
        counter += 1

        eth=dpkt.ethernet.Ethernet(packet)

        if eth.type==dpkt.ethernet.ETH_TYPE_IP:
            
            ip = eth.data

            if ip.p == dpkt.ip.IP_PROTO_TCP:
                tcp_count += 1
                # if not ((packet[IP].src,packet[IP].dst) in TCP_flow):
                #     TCP_flow[(packet[IP].src,packet[IP].dst)] = [[],[],[]]
                # # TCP_flow[(packet[IP].src,packet[IP].dst)][0].append([packet[TCP].time,wirelen,packet[TCP].flags]) 
                # TCP_flow[(packet[IP].src,packet[IP].dst)][0].append(packet[TCP].time) 
                # TCP_flow[(packet[IP].src,packet[IP].dst)][1].append(wirelen) 
                # TCP_flow[(packet[IP].src,packet[IP].dst)][2].append(packet[TCP].flags) 
                if not ((ip.src,ip.dst) in TCP_flow_pc):
                    TCP_flow_pc[(ip.src,ip.dst)] = 0
                    TCP_flow_bs[(ip.src,ip.dst)] = 0 
                TCP_flow_pc[(ip.src,ip.dst)] += 1
                TCP_flow_bs[(ip.src,ip.dst)] += wirelen
                TCP_flow_f[(ip.src,ip.dst)] = ip.data.flags
                
            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                udp_count += 1
                # if not ((packet[IP].src,packet[IP].dst) in UDP_flow):
                #     UDP_flow[(packet[IP].src,packet[IP].dst)] = [[],[]]
                # # UDP_flow[(packet[IP].src,packet[IP].dst)].append([packet[UDP].time,wirelen]) 
                # UDP_flow[(packet[IP].src,packet[IP].dst)][0].append(packet[UDP].time) 
                # UDP_flow[(packet[IP].src,packet[IP].dst)][1].append(wirelen)

                if not ((ip.src,ip.dst) in UDP_flow_pc):
                    UDP_flow_pc[(ip.src,ip.dst)] = 0
                    UDP_flow_bs[(ip.src,ip.dst)]= 0
                UDP_flow_pc[(ip.src,ip.dst)] += 1
                UDP_flow_bs[(ip.src,ip.dst)] += wirelen

    tcp_pc = list(TCP_flow_pc.values())   
    tcp_bs = list(TCP_flow_bs.values())
    udp_pc = list(UDP_flow_pc.values())    
    udp_bs = list(UDP_flow_bs.values())
    all_pc = tcp_pc + udp_pc 
    all_bs = tcp_bs + udp_bs

    # plt.xlabel('flow size in terms of packets number')
    # plt.ylabel('number of flow')
    # plt.plot(range(max(all_pc)), tcp_pc)
    # plt.savefig("number of packets in TCP flow.png")
    # plt.clf()









#partitionFile()
# count_protocols()
# plotCDF()
flow_rebuild()
#pysharkCapture()
