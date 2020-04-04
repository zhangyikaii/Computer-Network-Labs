#!/usr/bin/env python3

# -*- coding: utf-8 -*-


'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
        self.arpTable = {}
        self.arpTblID = 0

    def print_arp_table(self):
        if self.arpTable:
            print("ID: {}".format(self.arpTblID))
            self.arpTblID += 1
            print("+" + "=" * 36 + "+")
            print("|" + " " * 7 + "一个精致的 ARP Table！" + " " * 7 + "|")
            print("|       IP                 MAC       |")
            print("+" + "-" * 36 + "+")

            for ip, mac in self.arpTable.items():
                print("|", str(ip).rjust(16, ' '), str(mac), "|")
                print("+" + "-" * 36 + "+")
            print("")


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        # for i in self.net.interfaces():
        #     print(i)
        while True:
            gotpkt = True
            try:
                timestamp,dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            # type(arp.targetprotoaddr): <class 'ipaddress.IPv4Address'>
            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                
                if pkt.has_header(Arp):
                    arp = pkt.get_header(Arp)

                    # 找目的地IP 对应的 路由器interface:
                    targetIntf = None
                    for i in self.net.interfaces():
                        if arp.targetprotoaddr == i.ipaddr:
                            targetIntf = i
                    if targetIntf != None:
                        if arp.operation == ArpOperation.Request:
                            # ARP请求来了：
                            # print(self.net.interface_by_ipaddr(arp.senderprotoaddr))
                            # print("Request create_ip_arp_reply: ({}, {}, {}, {})".format(targetIntf.ethaddr, arp.senderhwaddr, targetIntf.ipaddr, arp.senderprotoaddr))
                            arpReply = create_ip_arp_reply(targetIntf.ethaddr, arp.senderhwaddr, targetIntf.ipaddr, arp.senderprotoaddr)
                            self.net.send_packet(dev, arpReply)
                            self.arpTable[targetIntf.ipaddr] = targetIntf.ethaddr

                        elif arp.operation == ArpOperation.Reply:
                            self.arpTable[arp.senderprotoaddr] = arp.senderhwaddr
                    
                    self.print_arp_table()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
