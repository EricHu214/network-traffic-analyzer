import os
from scapy.all import *
import matplotlib.pyplot as plt
import dpkt

import pyshark
import numpy as np
from pylab import *





class Flow:
    def __init__(self, count, ts, headerlength=0, dataCount=0):
        self.count = count
        self.headerCount = headerlength
        self.dataCount = dataCount
        self.ts = [ts]

    def output(self):
        if self.dataCount == 0:
            result = 9999

        else:
            result = float(self.headerCount) / self.dataCount


        return result

    def increaseOverheadCounts(self, headerBytes, dataBytes):
        self.headerCount += headerBytes
        self.dataCount += dataBytes

    def increaseCount(self, count):
        self.count += count

    def addTs(self, timestamp):
        self.ts.append(timestamp)

    def newFlowPacket(self, count, timeStamp):
        self.increaseCount(count)
        self.addTs(timeStamp)




def closestTimeStamp(list, currTime):
    result = -1

    for i in range(len(list)):
        #print(str(currTime) + ' : ' + str(list[i].ts[-1]))
        if abs(currTime - list[i].ts[-1]) < 5400:
            result = i
            break

    return result


def f_range(beginning, end, step):
    list = []
    i = beginning
    while i < end:
        list.append(i)
        i += step

    return list


def plotFlow(flowDict, max, step, protocol, flowType, mode):
    x_data = []
    y_data = []

    for i in f_range(0, max + 1, step):
        x_data.append(i)
        y_data.append(0)

    for key in flowDict:
        for i in range(len(flowDict[key])):
            counter = 0

            for size in x_data:
                if mode == 0:
                    if flowDict[key][i].count <= size:
                        y_data[counter] += 1
                else:
                    if flowDict[key][i].output() <= size:
                        y_data[counter] += 1

                counter += 1


    y_data[:] = [x/len(flowDict) for x in y_data]

    plt.xlabel('max '+ protocol +' flow size by ' + flowType + ' count')
    plt.ylabel('percentage of ' + protocol + ' flows')
    plt.plot(x_data, y_data)
    plt.savefig("flow size of " + protocol + " " + flowType + " count.png")
    plt.clf()


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
    TCP_flow_bs={}
    TCP_flow_f={}
    TCP_flow_dir={}


    UDP_flow_pc={}
    UDP_flow_bs={}
    UDP_flow_dir={}



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
                tcp = ip.data

                headerSize = 18 + ip.hl * 4 + ip.data.off * 4
                dataSize = ip.len - ip.hl * 4 - ip.data.off*4
                # if not ((packet[IP].src,packet[IP].dst) in TCP_flow):
                #     TCP_flow[(packet[IP].src,packet[IP].dst)] = [[],[],[]]

                # # TCP_flow[(packet[IP].src,packet[IP].dst)][0].append([packet[TCP].time,wirelen,packet[TCP].flags])
                # TCP_flow[(packet[IP].src,packet[IP].dst)][0].append(packet[TCP].time)
                # TCP_flow[(packet[IP].src,packet[IP].dst)][1].append(wirelen)
                # TCP_flow[(packet[IP].src,packet[IP].dst)][2].append(packet[TCP].flags)
                if not (((ip.src, ip.dst, tcp.sport, tcp.dport) in TCP_flow_pc) or ((ip.dst, ip.src, tcp.dport, tcp.sport) in TCP_flow_pc)):
                    TCP_flow_pc[(ip.src, ip.dst, tcp.sport, tcp.dport)] = [Flow(1, ts)]
                    TCP_flow_bs[(ip.src, ip.dst, tcp.sport, tcp.dport)] = [Flow(wirelen, ts, headerSize, dataSize)]
                    TCP_flow_f[(ip.src, ip.dst, tcp.sport, tcp.dport)] = []
                    TCP_flow_dir=[]

                elif (ip.src, ip.dst, tcp.sport, tcp.dport) in TCP_flow_pc:
                    index = closestTimeStamp(TCP_flow_pc[(ip.src, ip.dst, tcp.sport, tcp.dport)], ts)
                    if index == -1:
                        TCP_flow_pc[(ip.src, ip.dst, tcp.sport, tcp.dport)].append(Flow(1, ts))
                        TCP_flow_bs[(ip.src, ip.dst, tcp.sport, tcp.dport)].append(Flow(wirelen, ts))
                        index = len(TCP_flow_pc[(ip.src, ip.dst, tcp.sport, tcp.dport)]) - 1


                    TCP_flow_pc[(ip.src, ip.dst, tcp.sport, tcp.dport)][index].newFlowPacket(1, ts)
                    TCP_flow_bs[(ip.src, ip.dst, tcp.sport, tcp.dport)][index].newFlowPacket(wirelen, ts)
                    TCP_flow_bs[(ip.src, ip.dst, tcp.sport, tcp.dport)][index].increaseOverheadCounts(headerSize, dataSize)
                    TCP_flow_f[(ip.src, ip.dst, tcp.sport, tcp.dport)].append(ip.data.flags)
                    TCP_flow_dir.append((ip.src, ip.dst, tcp.sport, tcp.dport))

                else:
                    index = closestTimeStamp(TCP_flow_pc[(ip.dst, ip.src, tcp.dport, tcp.sport)], ts)
                    if index == -1:
                        TCP_flow_pc[(ip.dst, ip.src, tcp.dport, tcp.sport)].append(Flow(1, ts))
                        TCP_flow_bs[(ip.dst, ip.src, tcp.dport, tcp.sport)].append(Flow(wirelen, ts))
                        index = len(TCP_flow_pc[(ip.dst, ip.src, tcp.dport, tcp.sport)]) - 1

                    TCP_flow_pc[(ip.dst, ip.src, tcp.dport, tcp.sport)][index].newFlowPacket(1, ts)
                    TCP_flow_bs[(ip.dst, ip.src, tcp.dport, tcp.sport)][index].newFlowPacket(wirelen, ts)
                    TCP_flow_bs[(ip.dst, ip.src, tcp.dport, tcp.sport)][index].increaseOverheadCounts(headerSize, dataSize)
                    TCP_flow_f[(ip.dst, ip.src, tcp.dport, tcp.sport)].append(ip.data.flags)
                    TCP_flow_dir.append((ip.src, ip.dst, tcp.dport, tcp.sport))


            elif ip.p == dpkt.ip.IP_PROTO_UDP:
                udp_count += 1
                udp = ip.data
                # if not ((packet[IP].src,packet[IP].dst) in UDP_flow):
                #     UDP_flow[(packet[IP].src,packet[IP].dst)] = [[],[]]
                # # UDP_flow[(packet[IP].src,packet[IP].dst)].append([packet[UDP].time,wirelen])
                # UDP_flow[(packet[IP].src,packet[IP].dst)][0].append(packet[UDP].time)
                # UDP_flow[(packet[IP].src,packet[IP].dst)][1].append(wirelen)

                if not (((ip.src, ip.dst, udp.sport, udp.dport) in UDP_flow_pc) or ((ip.dst, ip.src, udp.dport, udp.sport) in UDP_flow_pc)):
                    UDP_flow_pc[(ip.src, ip.dst, udp.sport, udp.dport)] = [Flow(1, ts)]
                    UDP_flow_bs[(ip.src, ip.dst, udp.sport, udp.dport)] = [Flow(wirelen, ts)]
                    UDP_flow_dir=[]
                elif (ip.src, ip.dst, udp.sport, udp.dport) in UDP_flow_pc:
                    index = closestTimeStamp(UDP_flow_pc[(ip.src, ip.dst, udp.sport, udp.dport)], ts)
                    if index == -1:
                        UDP_flow_pc[(ip.src, ip.dst, udp.sport, udp.dport)].append(Flow(1, ts))
                        UDP_flow_bs[(ip.src, ip.dst, udp.sport, udp.dport)].append(Flow(wirelen, ts))
                        index = len(UDP_flow_pc[(ip.src, ip.dst, udp.sport, udp.dport)]) - 1

                    UDP_flow_pc[(ip.src, ip.dst, udp.sport, udp.dport)][index].newFlowPacket(1, ts)
                    UDP_flow_bs[(ip.src, ip.dst, udp.sport, udp.dport)][index].newFlowPacket(wirelen, ts)
                    UDP_flow_dir.append((ip.src, ip.dst, udp.sport, udp.dport))
                else:
                    index = closestTimeStamp(UDP_flow_pc[(ip.dst, ip.src, udp.dport, udp.sport)], ts)
                    if index == -1:
                        UDP_flow_pc[(ip.dst, ip.src, udp.dport, udp.sport)].append(Flow(1, ts))
                        UDP_flow_bs[(ip.dst, ip.src, udp.dport, udp.sport)].append(Flow(wirelen, ts))
                        index = len(UDP_flow_pc[(ip.dst, ip.src, udp.dport, udp.sport)]) - 1

                    UDP_flow_pc[(ip.dst, ip.src, udp.dport, udp.sport)][index].newFlowPacket(1, ts)
                    UDP_flow_bs[(ip.dst, ip.src, udp.dport, udp.sport)][index].newFlowPacket(wirelen, ts)
                    UDP_flow_dir.append((ip.dst, ip.src, udp.dport, udp.sport))

    #TCP_flow_pc.values()
    #TCP_flow_bs.values()

    #UDP_flow_pc.values()
    #UDP_flow_bs.values()

    plotFlow(TCP_flow_pc, 500, 10, "TCP", "packet", 0)
    plotFlow(TCP_flow_bs, 400000, 100, "TCP", "byte", 0)

    plotFlow(UDP_flow_pc, 50, 1, "UDP", "packet", 0)
    plotFlow(UDP_flow_bs, 4000, 1, "UDP", "byte", 0)

    plotFlow(TCP_flow_bs, 20, 0.1, "TCP", "overhead", 1)


flow_rebuild()
