# -*- coding: utf-8 -*-

'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time
from collections import deque

# LRU: fowarding table 数据结构由 dictionary 换成 deque

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]

    # log_info("My Interfaces: {}".format([intf.name for intf in my_interfaces]))

    forwTable = deque(maxlen=5) # 转发表.
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

        for idx, [val, port] in enumerate(forwTable):
            if val == packet[0].src:
                # 表中有，不用加入
                forwTable[idx] = [packet[0].src, input_port]
                isFind = True
                break
        if isFind == False:
            # print("ADD: ", [packet[0].src, input_port])
            forwTable.append([packet[0].src, input_port])

        if packet[0].dst in mymacs:
            # log_info("Packet intended for me")
            pass
        else:
            # 针对src，需要LRU更新：
            dstPort = None
            for val, port in list(forwTable):
                if val == packet[0].dst:
                    # print("Hit: ", [val, port])
                    forwTable.remove([val, port])
                    forwTable.append([val, port])
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
