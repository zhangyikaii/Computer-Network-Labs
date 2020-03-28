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

    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
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

                    targetIntf = None
                    for i in self.net.interfaces():
                        # 找目的地IP 对应的 路由器interface:
                        if arp.targetprotoaddr == i.ipaddr:
                            targetIntf = i
                    if targetIntf != None:
                        if arp.operation == ArpOperation.Request:
                            # ARP请求来了：
                            # print(self.net.interface_by_ipaddr(arp.senderprotoaddr))
                            arpReply = create_ip_arp_reply(targetIntf.ethaddr, arp.senderhwaddr, targetIntf.ipaddr, arp.senderprotoaddr)
                            self.net.send_packet(dev, arpReply)

                        elif arp.operation == ArpOperation.Reply:
                            pass





def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
