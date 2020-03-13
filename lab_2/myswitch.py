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

        log_info("In ({}) received packet ({}) on ({})".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_info("Packet intended for me")
        else:
            # 广播
            if str(packet[0].dst) == "ff:ff:ff:ff:ff:ff" or packet[0].src not in forwTable.keys():
                log_info("Got the broadcast packet.")
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_info("Flooding packet ({}) to ({})".format(packet, intf.name))
                        net.send_packet(intf.name, packet)

            else:
                log_info("Got has been learned packet")
                # 在转发表中，直接发送
                if packet[0].dst in forwTable.keys():
                    net.send_packet(forwTable[packet[0].dst], packet)
            # 加入转发表，顺便存一下时间，self-learning
            if packet[0].src not in forwTable.keys():
                forwTable[packet[0].src] = input_port


    net.shutdown()
