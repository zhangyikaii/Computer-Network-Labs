#!/usr/bin/env python3

# -*- coding: utf-8 -*-


'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.userlib import *


class IPv4PkgMsg():
    def __init__(self, IPv4PktQueue, timestamp, ARPRequest, outIntf, sendNum=0):
        self.IPv4PktQueue = IPv4PktQueue
        self.timestamp = timestamp
        self.ARPRequest = ARPRequest
        self.outIntf = outIntf
        self.sendNum = sendNum

    # def __iter__(self):
    #     return self
    # 重写lt方法(比较函数):
    def __lt__(self, other):
        return self.timestamp < other.timestamp

    def __str__(self):
        return "({})".format(", ".join("{}={}".format(key, getattr(self, key)) for key in self.__dict__.keys()))


class FwTableEntry():
    def __init__(self, netAddrSingle, subnetMask, nextHop, intf):
        self.netAddr = IPv4Network(str(netAddrSingle) + "/" + str(subnetMask), strict=False)
        self.nextHop = None if nextHop == None else ip_address(nextHop)
        self.intf = intf
    def __lt__(self, other):
        return self.netAddr.prefixlen > other.netAddr.prefixlen
    def __str__(self):
        return "({})".format(", ".join("{}={}".format(key, getattr(self, key)) for key in self.__dict__.keys()))

class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here
        self.arpTable = {}
        self.arpTblID = 0
        self.IPv4Queue = {}

        # lab 4 ---
        # 读文件建表：
        self.fwTable = []
        with open("forwarding_table.txt") as fwTxt:
            for line in fwTxt:
                # line = network address, subnet mask, next hop IP, Interface.
                msgArr = line.split()
                self.fwTable.append(FwTableEntry(msgArr[0], msgArr[1], msgArr[2], msgArr[3]))

        # 从路由器的接口建表
        for intf in self.net.interfaces():
            # Notes: strict = False
            self.fwTable.append(FwTableEntry(intf.ipaddr, intf.netmask, None, intf.name))
        # 最长前缀匹配的排序:
        self.fwTable.sort()
        print("self.fwTable: ")
        self.print_userDefined_table(self.fwTable)

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

    def print_userDefined_table(self, tb, isDict=False):
        if isDict == False:
            for i in tb:
                print(i)
        else:
            for i in tb:
                print(tb[i])
        print("")

    def router_main(self):
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        # for i in self.net.interfaces():
        #     print(i)
        dev, pkt = None, None
        while True:
            gotpkt = True
            try:
                timestamp, dev, pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            # 删过期的表项:
            # 1s之后没收到 并且 重发超过5次了.
            for key in list(self.IPv4Queue):
                if time.time() - self.IPv4Queue[key].timestamp > 1 and self.IPv4Queue[key].sendNum >= 5:
                    # print("Delete: ", self.IPv4Queue[key])
                    del self.IPv4Queue[key]

            # 重发ARP request:
            for nextHop in self.IPv4Queue:
                if time.time() - self.IPv4Queue[nextHop].timestamp > 1:
                    self.net.send_packet(self.IPv4Queue[nextHop].outIntf, self.IPv4Queue[nextHop].ARPRequest)
                    self.IPv4Queue[nextHop].sendNum += 1
                    self.IPv4Queue[nextHop].timestamp = time.time()
                    # print("Resend: ", self.IPv4Queue[nextHop])
            print("self.IPv4Queue: ")
            self.print_userDefined_table(self.IPv4Queue, True)

            # type(arp.targetprotoaddr): <class 'ipaddress.IPv4Address'>
            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                # print("Got")
                if pkt.has_header(Arp):
                    arp = pkt.get_header(Arp)
                    if arp.operation == ArpOperation.Request:
                        # print("ARP request")
                        # ARP请求来了：
                        # print(self.net.interface_by_ipaddr(arp.senderprotoaddr))
                        # print("Request create_ip_arp_reply: ({}, {}, {}, {})".format(targetIntf.ethaddr, arp.senderhwaddr, targetIntf.ipaddr, arp.senderprotoaddr))
                        # 找目的地IP 对应的 路由器interface:
                        targetIntf = None
                        for i in self.net.interfaces():
                            if arp.targetprotoaddr == i.ipaddr:
                                targetIntf = i
                        if targetIntf != None:
                            arpReply = create_ip_arp_reply(targetIntf.ethaddr, arp.senderhwaddr, targetIntf.ipaddr,
                                                           arp.senderprotoaddr)
                            self.net.send_packet(dev, arpReply)
                            self.arpTable[arp.senderprotoaddr] = arp.senderhwaddr

                    elif arp.operation == ArpOperation.Reply:
                        # print("ARP reply")
                        self.arpTable[arp.senderprotoaddr] = arp.senderhwaddr
                        # 收到一个ARP reply, 并且它解答了之前某个包不知道next hop对应的MAC的问题
                        # 所以要把self.IPv4Queue这个next hop对应的所有IP包按照顺序发出去:
                        if arp.senderprotoaddr in self.IPv4Queue.keys():
                            for curIPv4Pkg in self.IPv4Queue[arp.senderprotoaddr].IPv4PktQueue:
                                e = curIPv4Pkg.get_header(Ethernet)
                                e.dst = arp.senderhwaddr  # 填写MAC.
                                e.src = self.net.interface_by_name(dev).ethaddr
                                OkIPv4Pkg = e + curIPv4Pkg.get_header(IPv4) + curIPv4Pkg.get_header(ICMP)
                                # print("Send: ", OkIPv4Pkg)
                                # 包组装好了, 发送:
                                self.net.send_packet(dev, OkIPv4Pkg)
                            del self.IPv4Queue[arp.senderprotoaddr]

                    self.print_arp_table()

                # 处理IP包：
                elif pkt.has_header(IPv4):
                    ipv4 = pkt.get_header(IPv4)
                    # print("ipv4: ", ipv4)
                    ipv4.ttl -= 1

                    # 目标地址不是路由器上的接口:
                    if ipv4.dst not in [intf.ipaddr for intf in self.net.interfaces()]:
                        for i in self.fwTable:
                            if ipv4.dst in i.netAddr:
                                # 目前找到了最长匹配:
                                curNextHop = i.nextHop if i.nextHop != None else ipv4.dst
                                # 如果下一跳在ARP table中, 组装发送:
                                if curNextHop in self.arpTable.keys():
                                    e = pkt.get_header(Ethernet)
                                    e.dst = self.arpTable[curNextHop]
                                    e.src = self.net.interface_by_name(i.intf).ethaddr
                                    OkIPv4Pkg = e + pkt.get_header(IPv4) + pkt.get_header(ICMP)
                                    self.net.send_packet(i.intf, OkIPv4Pkg)
                                # 如果下一跳不在ARP table中:
                                else:
                                    if curNextHop in self.IPv4Queue.keys():
                                        self.IPv4Queue[curNextHop].IPv4PktQueue.append(pkt)
                                    else:
                                        arpRequest = create_ip_arp_request(
                                            self.net.interface_by_name(i.intf).ethaddr,
                                            self.net.interface_by_name(i.intf).ipaddr,
                                            ip_address(curNextHop)
                                        )
                                        self.net.send_packet(i.intf, arpRequest)
                                        self.IPv4Queue[curNextHop] = IPv4PkgMsg([pkt], time.time(), arpRequest, i.intf, 1)
                                break


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
