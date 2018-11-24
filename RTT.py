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
        self.totalTs = 0

    def output(self):
        if self.dataCount == 0:
            result = 9999

        else:
            result = float(self.headerCount) / self.dataCount


        return result

    def averageInterPacketTime(self):
        result = float(self.totalTs)/len(self.ts)

        if result == 0:
            result = -9999
        else:
            result = log(result)

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
        self.totalTs += (timeStamp - self.ts[-1])
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


def plotFlow(flowDict, min, max, step, protocol, flowType, mode):
    x_data = []
    y_data = []

    for i in f_range(min, max + 1, step):
        x_data.append(i)
        y_data.append(0)

    for key in flowDict:
        for i in range(len(flowDict[key])):
            counter = 0

            for size in x_data:
                if mode == 0:
                    if flowDict[key][i].count <= size:
                        y_data[counter] += 1
                elif mode == 1:
                    if flowDict[key][i].output() <= size:
                        y_data[counter] += 1
                else:
                    if flowDict[key][i].averageInterPacketTime() <= size:
                        y_data[counter] += 1

                counter += 1


    y_data[:] = [x/len(flowDict) for x in y_data]

    plt.xlabel('max '+ protocol +' flow size by ' + flowType + ' count')
    plt.ylabel('percentage of ' + protocol + ' flows')
    plt.plot(x_data, y_data)
    plt.savefig("flow size of " + protocol + " " + flowType + " count.png")
    plt.clf()


def RTT_from_flow():

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
    top_pc_num = []
    top_pc_key = []
    top_bs_num = []
    top_bs_key = []
    top_ts_num = []
    top_ts_key = []


    counter = 0
    tcp_count = 0

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
                
                if not (((ip.src, ip.dst, tcp.sport, tcp.dport) in TCP_flow_pc) or ((ip.dst, ip.src, tcp.dport, tcp.sport) in TCP_flow_pc)):
                    TCP_flow_pc[(ip.src, ip.dst, tcp.sport, tcp.dport)] = [Flow(1, ts)]
                    TCP_flow_bs[(ip.src, ip.dst, tcp.sport, tcp.dport)] = [Flow(wirelen, ts, headerSize, dataSize)]
                    TCP_flow_f[(ip.src, ip.dst, tcp.sport, tcp.dport)] = [ip.data.flags]
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

    for flow_key in TCP_flow_pc:
        ps_total = TCP_flow_pc[flow_key][0].count
        dur = TCP_flow_bs[flow_key][0].ts[-1] - TCP_flow_bs[flow_key][0].ts[0]
        byte_total = TCP_flow_bs[flow_key][0].count

        if len(top_pc_num) < 3:
            if len(top_pc_num) == 2: 
                if ps_total <= top_pc_num[0]:
                    top_pc_num = [ps_total] + top_pc_num
                    top_pc_key = [flow_key] + top_pc_key

                elif ps_total >= top_pc_num[0] and ps_total <= top_pc_num[0]:
                    top_pc_num= [top_pc_num[0]] + [ps_total] + [top_pc_num[1]]
                    top_pc_key= [top_pc_key[0]] + [flow_key] + [top_pc_key[1]]

                else:
                    top_pc_num.append(ps_total)
                    top_pc_key.append(flow_key)

            elif len(top_pc_num) == 1:
                if ps_total >= top_pc_num[0]:
                    top_pc_num.append(ps_total)
                    top_pc_key.append(flow_key)
                else:
                    top_pc_num = [ps_total] + top_pc_num
                    top_pc_key = [flow_key] + top_pc_key
            else:
                top_pc_num.append(ps_total)
                top_pc_key.append(flow_key)

        else:
            if ps_total >= top_pc_num[2]:
                top_pc_num = top_pc_num[1:] + [ps_total]  
                top_pc_key = top_pc_key[1:] + [flow_key]
            elif ps_total >= top_pc_num[1]:
                top_pc_num = [top_pc_num[1]] + [ps_total] + [top_pc_num[2]]
                top_pc_key = [top_pc_num[1]]+ [flow_key] + [top_pc_key[2]]
            elif ps_total >= top_pc_num[0]:
                top_pc_num = [ps_total] + top_pc_num[1:]
                top_pc_key = [flow_key] + top_pc_key[1:]


        if len(top_bs_num) < 3:
            if len(top_bs_num) == 2: 
                if byte_total <= top_bs_num[0]:
                    top_bs_num =[ byte_total] + top_bs_num
                    top_bs_key = [flow_key] + top_bs_key

                elif byte_total >= top_bs_num[0] and byte_total <= top_bs_num[0]:
                    top_bs_num= [top_bs_num[0]] + [byte_total] + [top_bs_num[1]]
                    top_bs_key= [top_bs_key[0]] + [flow_key] + [top_bs_key[1]]

                else:
                    top_bs_num.append(byte_total)
                    top_bs_key.append(flow_key)

            elif len(top_bs_num) == 1:
                if byte_total >= top_bs_num[0]:
                    top_bs_num.append(byte_total)
                    top_bs_key.append(flow_key)
                else:
                    top_bs_num =[ byte_total] + top_bs_num
                    top_bs_key = [flow_key] + top_bs_key
            else:
                top_bs_num.append(byte_total)
                top_bs_key.append(flow_key)

        else:
            if byte_total >= top_bs_num[2]:
                top_bs_num = top_bs_num[1:] + [byte_total]  
                top_bs_key = top_bs_key[1:] + [flow_key]
            elif byte_total >= top_bs_num[1]:
                top_bs_num = [top_bs_num[1]] + [byte_total] + [top_bs_num[2]]
                top_bs_key = [top_bs_num[1]] + [flow_key] + [top_bs_key[2]]
            elif byte_total >= top_bs_num[0]:
                top_bs_num = [byte_total] + top_bs_num[1:]
                top_bs_key = [flow_key] + top_bs_key[1:]

        if len(top_ts_num) < 3:
            if len(top_ts_num) == 2: 
                if dur <= top_ts_num[0]:
                    top_ts_num = [dur] + top_ts_num
                    top_ts_key = [flow_key] + top_ts_key

                elif dur >= top_ts_num[0] and dur <= top_ts_num[0]:
                    top_ts_num= [top_ts_num[0]] + [dur] + [top_ts_num[1]]
                    top_ts_key= [top_ts_key[0]] + [flow_key] + [top_ts_key[1]]

                else:
                    top_ts_num.append(dur)
                    top_ts_key.append(flow_key)

            elif len(top_ts_num) == 1:
                if dur >= top_ts_num[0]:
                    top_ts_num.append(dur)
                    top_ts_key.append(flow_key)
                else:
                    top_ts_num = [dur] + top_ts_num
                    top_ts_key = [flow_key] + top_ts_key
            else:
                top_ts_num.append(dur)
                top_ts_key.append(flow_key)

        else:
            if dur >= top_ts_num[2]:
                top_ts_num = top_ts_num[1:] + [dur]  
                top_ts_key = top_ts_key[1:] + [flow_key]
            elif dur >= top_ts_num[1]:
                top_ts_num = [top_ts_num[1]] + [dur] + [top_ts_num[2]]
                top_ts_key = [top_ts_num[1]] + [flow_key] + [top_ts_key[2]]
            elif dur >= top_ts_num[0]:
                top_ts_num = [dur] + top_ts_num[1:]
                top_ts_key = [flow_key] + top_ts_key[1:]

    print("Top 3 packet size TCP: ")
    print(top_pc_key)
    print(top_pc_num)
    print("Top 3 byte size TCP: ")
    print(top_bs_key)
    print(top_bs_num)
    print("Top 3 duration TCP: ")
    print(top_ts_key)
    print(top_ts_num)
            


RTT_from_flow()

