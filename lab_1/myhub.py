#!/usr/bin/env python3

'''
Ethernet hub in Switchyard.
'''
from switchyard.lib.userlib import *

# net: 包含该设备的一些信息（网卡等）
def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]

    # 主要工作:
    while True:
        try:
            # 获得最先到达的包， 并返回 时间和对应的网卡
            timestamp,dev,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, dev))
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            continue

        if eth.dst in mymacs:
            log_info ("Received a packet intended for me")
        else:
            for intf in my_interfaces:
                if dev != intf.name:
                    log_info ("Flooding packet {} to {}".format(packet, intf.name))
                    # 将包从对应网卡发出去
                    net.send_packet(intf, packet)
    net.shutdown()
