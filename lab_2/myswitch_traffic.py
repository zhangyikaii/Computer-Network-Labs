# -*- coding: utf-8 -*-

'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time
import heapq

# traffic: fowarding table 数据结构由 deque 换成 prio queue

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]

    # log_info("My Interfaces: {}".format([intf.name for intf in my_interfaces]))

    forwTable = [] # 转发表.
    maxEntries = 5
    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            # log_info("Hit except NoPackets.")
            continue
        except Shutdown:
            # log_info("Hit except Shutdown.")
            return

        # log_info("In ({}) received packet ({}) on ({})".format(net.name, packet, input_port))
        
        # Learning step: Update forwarding table:
        # 针对src。
        isFind = False

        for idx, (vol, curMac, port) in enumerate(forwTable):
            # 表中有，不用加入
            if curMac == packet[0].src:
                # 如果port不同，需要更新：
                if port != input_port:
                    forwTable.remove(forwTable[idx])
                    heapq.heappush(forwTable, (vol, packet[0].src, input_port))
                isFind = True
                break
        if isFind == False:
            # print("ADD: ", [packet[0].src, input_port])
            if len(forwTable) == maxEntries:
                heapq.heappop(forwTable)
            heapq.heappush(forwTable, (0, packet[0].src, input_port))

        if packet[0].dst in mymacs:
            # log_info("Packet intended for me")
            pass
        else:
            # 针对src：
            dstPort = None
            for idx, (vol, curMac, port) in enumerate(forwTable):
                if curMac == packet[0].dst:
                    # print("Hit: ", [curMac, port])
                    forwTable.remove(forwTable[idx])
                    heapq.heappush(forwTable, (vol + 1, curMac, port))
                    dstPort = port
                    break
            if dstPort != None:
                # log_info("(self-learning) Sending packet ({}) to ({})\n".format(packet, dstPort))
                net.send_packet(dstPort, packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        # log_info("(broadcast) Flooding packet ({}) to ({})\n".format(packet, intf.name))
                        net.send_packet(intf.name, packet)

    net.shutdown()
