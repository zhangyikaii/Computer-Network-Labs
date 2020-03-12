# -*- coding: utf-8 -*-

'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.userlib import *
import time

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]

    forwTable = {} # 转发表.
    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            log_info("Hit except NoPackets.")
            continue
        except Shutdown:
            log_info("Hit except Shutdown.")
            return

        log_info("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_info("Packet intended for me")
        else:
            isOk = False
            # 广播
            if str(packet[0].dst) == "ff:ff:ff:ff:ff:ff":
                log_info("Got the broadcast packet.")
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_info("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
                        isOk = True

            # 加入转发表，顺便存一下时间
            if packet[0].src not in forwTable.keys():
                forwTable[packet[0].src] = [input_port, time.time()]

            if isOk == False:
                # 看看转发表如果有直接发送
                if packet[0].dst in forwTable.keys():
                    net.send_packet(forwTable[packet[0].dst][0], packet)
                    isOk = True
            
            # if isOk == False:
            #     for intf in my_interfaces:
            #         if input_port != intf.name:
            #             log_info("Flooding packet {} to {}".format(packet, intf.name))
            #             net.send_packet(intf.name, packet)

    net.shutdown()
