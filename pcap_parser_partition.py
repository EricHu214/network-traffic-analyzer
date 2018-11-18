import os
from scapy.all import *
import matplotlib.pyplot as plt
import threading


files = [0, 50000, 100000, 150000, 200000, 250000, 300000, 350000, 400000, 450000, 500000, 550000, 600000,
650000, 700000, 750000, 800000, 850000, 900000, 950000]

#packets = rdpcap('univ1_pt16')

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

threadlock = threading.Lock()
threads = []


#def plotCDF():
#    plt.xlabel('max size')
#    plt.ylabel('number of packets')
#
#    x_data = []
#    y_data = []
#
#
#    for i in range(150):
#        if i % 2 == 0:
#            x_data.append(i)
#            y_data.append(0)
#
#
#    for packet in packets:
#        counter = 0
#
#        for size in x_data:
#
#            if len(packet) <= size:
#                y_data[counter] += 1
#
#            counter += 1
#
#    plt.plot(x_data, y_data)
#    plt.show()
#




class myThread (threading.Thread):
    def __init__(self, list):
        threading.Thread.__init__(self)
        self.list = list

    def run(self):
        count_protocols(self.list)



def count_protocols(list):
    global counter
    global tcp_count
    global tcp_bytes
    global udp_count
    global udp_bytes
    global ethernet_count
    global ethernet_bytes
    global ip_count
    global ip_bytes
    global icmp_count
    global icmp_bytes
    global total_len


    for file in list:
        packets = rdpcap('partition/' + str(file))

        for packet in packets:
            threadlock.acquire()
            counter += 1
            threadlock.release()

            if packet.haslayer(Ether):
                threadlock.acquire()
                ethernet_count += 1
                ethernet_bytes += len(packet)
                threadlock.release()

            if packet.haslayer(IP):
                threadlock.acquire()
                ip_count += 1
                ip_bytes += len(packet)
                threadlock.release()

            elif packet.haslayer(ICMP):
                threadlock.acquire()
                icmp_count += 1
                icmp_bytes += len(packet)
                threadlock.release()


            if packet.haslayer(TCP):
                threadlock.acquire()
                tcp_count += 1
                tcp_bytes += len(packet)
                threadlock.release()

            elif packet.haslayer(UDP):
                threadlock.acquire()
                udp_count += 1
                udp_bytes += len(packet)
                threadlock.release()

            threadlock.acquire()
            total_len += len(packet)
            threadlock.release()

#counter = 0
#tcp_count = 0
#tcp_bytes = 0
#udp_count = 0
#udp_bytes = 0
#ethernet_count = 0
#ethernet_bytes = 0
#ip_count = 0
#ip_bytes = 0
#icmp_count = 0
#icmp_bytes = 0
#total_len = 0


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

#partitionFile()
#plotCDF()


#thread1 = myThread(files[0:5])
#thread2 = myThread(files[5:10])
#thread3 = myThread(files[10:15])
#thread4 = myThread(files[15:len(files)])
#
#
#thread1.start()
#thread2.start()
#thread3.start()
#thread4.start()
#
#
#threads.append(thread1)
#threads.append(thread2)
#threads.append(thread3)
#threads.append(thread4)
#
#
#for t in threads:
#    t.join()
#
#print("exiting main thread")



count_protocols(files)



file = open("data.txt", "w")

file.write("number of packets that use Ethernet: " + str(ethernet_count) + " percentage is: " + str(ethernet_count/counter) + " and total bytes: " + str(ethernet_bytes) + "\n")
file.write("number of packets that use IP: " + str(ip_count)  + " percentage is: " + str(ip_count/counter) + " and total bytes: " + str(ip_bytes) + "\n")
file.write("number of packets that use ICMP: " + str(icmp_count)  + " percentage is: " + str(icmp_count/counter) + " and total bytes: " + str(icmp_bytes) + "\n")
file.write("number of packets that use UDP: " + str(udp_count)  + " percentage is: " + str(udp_count/counter) + " and total bytes: " + str(udp_bytes) + "\n")
file.write("number of packets that use TCP: " + str(tcp_count)  + " percentage is: " + str(tcp_count/counter) + " and total bytes: " + str(tcp_bytes) + "\n")
file.write("total number of bytes of all packets: " + str(total_len) + "\n")
file.write("total number of packets: " + str(counter) + "\n")
