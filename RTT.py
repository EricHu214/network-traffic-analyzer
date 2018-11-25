import os
from scapy.all import *
import matplotlib.pyplot as plt
import dpkt

import pyshark
import numpy as np
from pylab import *


class DirectionalFlow:
    def __init__(self, ts, seq, ack):
        self.pkts = {}
        self.pkts[seq] = [(ts, ack)]
        self.max_seq = seq
        self.index = {}
        self.index[seq] = 0

    def addNewPacket(self, ts, seq, ack):

        if seq in self.pkts and seq < self.max_seq:
            del self.pkts[seq]
            del self.index[seq]
        elif seq in self.pkts:
            self.pkts[seq].append((ts, ack))
        else:
            self.pkts[seq] = [(ts, ack)]
            self.index[seq] = 0


class Flow:
    def __init__(self, count, ts, dir = 0, seq = 1, ack = 1, headerlength=0, dataCount=0):
        self.count = count
        self.headerCount = headerlength
        self.dataCount = dataCount
        self.ts = [ts]
        self.totalTs = 0
        self.dir = [dir]
        self.seq_ack = [(seq, ack)]


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

    def addRttInfo(self, dir, seq, ack):
        self.dir.append(dir)
        self.seq_ack.append((seq, ack))

def closestTimeStamp(list, currTime):
    result = -1

    for i in range(len(list)):
        #print(str(currTime) + ' : ' + str(list[i].ts[-1]))
        if abs(currTime - list[i].ts[-1]) < 5400:
            result = i
            break

    return result

def createDirectionFlow(flowDict):
    dict = {}

    for key in flowDict:
        flow = flowDict[key][0]

        for i in range(len(flow.dir)):
            seq_num = flow.seq_ack[i][0]
            ack_num = flow.seq_ack[i][1]

            if flow.dir[i] == 0:
                if key not in dict:
                    dict[key] = DirectionalFlow(flow.ts[i], flow.seq_ack[i][0], flow.seq_ack[i][1])
                else:
                    dict[key].addNewPacket(flow.ts[i], flow.seq_ack[i][0], flow.seq_ack[i][1])

            else:
                newKey = (key[1], key[0], key[3], key[2])
                if newKey not in dict:
                    dict[newKey] = DirectionalFlow(flow.ts[i], flow.seq_ack[i][0], flow.seq_ack[i][1])
                else:
                    dict[newKey].addNewPacket(flow.ts[i], flow.seq_ack[i][0], flow.seq_ack[i][1])

    return dict

def createTopDict(flowDict, keys):
    dict = {}

    for key in keys:
        dict[key] = flowDict[key]

    return dict



def plotRTT(x, y, y2, filename):
    x_axis = []
    y_axis = []
    y_axis2 = []
    step = floor(float(len(x))/1000) + 1


    for i in range(len(x)):
        if i % step == 0:
            x_axis.append(x[i])
            y_axis.append(y[i])
            y_axis2.append(y2[i])


    plt.xlabel("time (sec)")
    plt.ylabel("RTT and SRTT (Sec)")
    plt.plot(x_axis, y_axis, "g", label="RTT")
    plt.plot(x_axis, y_axis2, "b", label="SRTT")
    plt.savefig(filename)
    plt.clf()


def matchAcks(dict, filename):
    seen = {}

    counter = 0
    for key in dict:
        if key not in seen:
            SRTT_list = []
            RTT_list = []
            x_axis = []

            flow1 = dict[key]

            oppKey = (key[1], key[0], key[3], key[2])
            flow2 = dict[oppKey]

            seen[key] = 0

            for seq in flow1.pkts:
                for i in range(len(flow1.pkts[seq])):
                    tup = flow1.pkts[seq][i]

                    ack = tup[1]
                    t_A = tup[0]
                    if ack in flow2.pkts:
                        currIndex = flow2.index[ack]

                        if currIndex < len(flow2.pkts[ack]):
                            t_B = flow2.pkts[ack][currIndex][0]

                            if t_B > t_A:
                                r = t_B - t_A
                            else:
                                while currIndex < len(flow2.pkts[ack]) and t_B <= t_A:
                                    t_B = flow2.pkts[ack][currIndex][0]
                                    flow2.index[ack]+=1
                                    currIndex = flow2.index[ack]


                                if currIndex < len(flow2.pkts[ack]):
                                    r = t_B - t_A
                                else:
                                    continue

                            alpha = 0.125

                            if len(SRTT_list) == 0:
                                srtt = r
                            else:
                                srtt = (1 - alpha) * SRTT_list[-1] + alpha * r

                            x_axis.append(t_A)
                            RTT_list.append(r)
                            SRTT_list.append(srtt)

                            flow2.index[ack]+=1



            plt.title("src: " + str(key[2]) + ", dst: " + str(key[3]))
            plotRTT(x_axis, RTT_list, SRTT_list, filename + " (" + str(counter) + ").png")
            counter += 1
            #print(SRTT_list)




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

    top_con_num = []
    top_con_key = []


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
                    TCP_flow_pc[(ip.src, ip.dst, tcp.sport, tcp.dport)] = [Flow(1, ts, 0, tcp.seq, tcp.ack)]
                    TCP_flow_bs[(ip.src, ip.dst, tcp.sport, tcp.dport)] = [Flow(wirelen, ts, 0, tcp.seq, tcp.ack, headerSize, dataSize)]
                    TCP_flow_f[(ip.src, ip.dst, tcp.sport, tcp.dport)] = [ip.data.flags]
                    TCP_flow_dir=[]

                elif (ip.src, ip.dst, tcp.sport, tcp.dport) in TCP_flow_pc:
                    index = closestTimeStamp(TCP_flow_pc[(ip.src, ip.dst, tcp.sport, tcp.dport)], ts)
                    if index == -1:
                        TCP_flow_pc[(ip.src, ip.dst, tcp.sport, tcp.dport)].append(Flow(1, ts, 0, tcp.seq, tcp.ack))
                        TCP_flow_bs[(ip.src, ip.dst, tcp.sport, tcp.dport)].append(Flow(wirelen, ts, 0, tcp.seq, tcp.ack))
                        index = len(TCP_flow_pc[(ip.src, ip.dst, tcp.sport, tcp.dport)]) - 1


                    TCP_flow_pc[(ip.src, ip.dst, tcp.sport, tcp.dport)][index].newFlowPacket(1, ts)
                    TCP_flow_bs[(ip.src, ip.dst, tcp.sport, tcp.dport)][index].newFlowPacket(wirelen, ts)
                    TCP_flow_pc[(ip.src, ip.dst, tcp.sport, tcp.dport)][index].addRttInfo(0, tcp.seq, tcp.ack)
                    TCP_flow_bs[(ip.src, ip.dst, tcp.sport, tcp.dport)][index].addRttInfo(0, tcp.seq, tcp.ack)
                    TCP_flow_bs[(ip.src, ip.dst, tcp.sport, tcp.dport)][index].increaseOverheadCounts(headerSize, dataSize)
                    TCP_flow_f[(ip.src, ip.dst, tcp.sport, tcp.dport)].append(ip.data.flags)
                    TCP_flow_dir.append((ip.src, ip.dst, tcp.sport, tcp.dport))

                else:
                    index = closestTimeStamp(TCP_flow_pc[(ip.dst, ip.src, tcp.dport, tcp.sport)], ts)
                    if index == -1:
                        TCP_flow_pc[(ip.dst, ip.src, tcp.dport, tcp.sport)].append(Flow(1, ts, 1, tcp.seq, tcp.ack))
                        TCP_flow_bs[(ip.dst, ip.src, tcp.dport, tcp.sport)].append(Flow(wirelen, ts, 1, tcp.seq, tcp.ack))
                        index = len(TCP_flow_pc[(ip.dst, ip.src, tcp.dport, tcp.sport)]) - 1

                    TCP_flow_pc[(ip.dst, ip.src, tcp.dport, tcp.sport)][index].newFlowPacket(1, ts)
                    TCP_flow_bs[(ip.dst, ip.src, tcp.dport, tcp.sport)][index].newFlowPacket(wirelen, ts)
                    TCP_flow_pc[(ip.dst, ip.src, tcp.dport, tcp.sport)][index].addRttInfo(1, tcp.seq, tcp.ack)
                    TCP_flow_bs[(ip.dst, ip.src, tcp.dport, tcp.sport)][index].addRttInfo(1, tcp.seq, tcp.ack)
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
                top_pc_key = [top_pc_key[1]]+ [flow_key] + [top_pc_key[2]]
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
                top_bs_key = [top_bs_key[1]] + [flow_key] + [top_bs_key[2]]
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

        # This is for the top connections pairs 
        connect = 0
        for f in TCP_flow_f[flow_key]:
            if ((f & dpkt.tcp.TH_SYN ) != 0):
                connect += 1

        if len(top_con_num) < 3:
            if len(top_con_num) == 2:
                if connect <= top_con_num[0]:
                    top_con_num = [connect] + top_con_num
                    top_con_key = [flow_key] + top_con_key

                elif connect >= top_con_num[0] and connect <= top_con_num[0]:
                    top_con_num= [top_con_num[0]] + [connect] + [top_con_num[1]]
                    top_con_key= [top_con_key[0]] + [flow_key] + [top_con_key[1]]

                else:
                    top_con_num.append(connect)
                    top_con_key.append(flow_key)

            elif len(top_con_num) == 1:
                if connect >= top_con_num[0]:
                    top_con_num.append(connect)
                    top_con_key.append(flow_key)
                else:
                    top_con_num = [connect] + top_con_num
                    top_con_key = [flow_key] + top_con_key
            else:
                top_con_num.append(connect)
                top_con_key.append(flow_key)

        else:
            if connect >= top_con_num[2]:
                top_con_num = top_con_num[1:] + [connect]
                top_con_key = top_con_key[1:] + [flow_key]
            elif connect >= top_con_num[1]:
                top_con_num = [top_con_num[1]] + [connect] + [top_con_num[2]]
                top_con_key = [top_con_key[1]] + [flow_key] + [top_con_key[2]]
            elif connect >= top_con_num[0]:
                top_con_num = [connect] + top_con_num[1:]
                top_con_key = [flow_key] + top_con_key[1:]

    #print("Top 3 packet size TCP: ")
    #print(top_pc_key)
    #print(top_pc_num)
    #print("Top 3 byte size TCP: ")
    #print(top_bs_key)
    #print(top_bs_num)
    #print("Top 3 duration TCP: ")
    #print(top_ts_key)
    #print(top_ts_num)

    topPc = createTopDict(TCP_flow_pc, top_pc_key)

    dict = createDirectionFlow(topPc)
    matchAcks(dict, "top 3 packet number")

    topBs = createTopDict(TCP_flow_pc, top_bs_key)
    dict = createDirectionFlow(topBs)
    matchAcks(dict, "top 3 byte size")


    topTs = createTopDict(TCP_flow_pc, top_ts_key)
    dict = createDirectionFlow(topTs)
    matchAcks(dict, "top 3 longest flow duration")




    # R = []

    # t1 = a.ts
    # t2 = b_of_flow[(a.sq_ac[1],a.sq_ac[0])].ts 

    # r = t2 -t1
    # alpha = 0.125

    # SRTT <- (1 - alpha) * SRTT + alpha * r

    # R.append(r)

    # top_pc_rtt_l[flow_key] = R 



RTT_from_flow()
