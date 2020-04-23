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
                print("建表读文件, 分割行: {}".format(msgArr))
                if len(msgArr) >= 4:
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
        self.print_userDefined_table(self.net.interfaces())
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
                    print("self.IPv4Queue中的: ", self.IPv4Queue[key], "已过期, 即将被删除.")
                    del self.IPv4Queue[key]

            # 重发ARP request:
            for nextHop in self.IPv4Queue:
                if time.time() - self.IPv4Queue[nextHop].timestamp > 1:
                    print("准备超时重发: ", self.IPv4Queue[nextHop])
                    self.net.send_packet(self.IPv4Queue[nextHop].outIntf, self.IPv4Queue[nextHop].ARPRequest)
                    self.IPv4Queue[nextHop].sendNum += 1
                    self.IPv4Queue[nextHop].timestamp = time.time()

            # type(arp.targetprotoaddr): <class 'ipaddress.IPv4Address'>
            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))
                print("Got a packet (from {}): {}".format(dev, pkt))
                if pkt.has_header(Arp):
                    arp = pkt.get_header(Arp)
                    if arp.operation == ArpOperation.Request:
                        print("收到 ARP request:")
                        print(arp)
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
                            print("准备从")
                            self.net.send_packet(dev, arpReply)
                            print("(ARP request) 更新ARP table: {} -> {}".format(arp.senderprotoaddr, arp.senderhwaddr))
                            self.arpTable[arp.senderprotoaddr] = arp.senderhwaddr

                    elif arp.operation == ArpOperation.Reply:
                        print("收到 ARP reply:")
                        print(arp)
                        self.arpTable[arp.senderprotoaddr] = arp.senderhwaddr
                        # 收到一个ARP reply, 并且它解答了之前某个包不知道next hop对应的MAC的问题
                        # 所以要把self.IPv4Queue这个next hop对应的所有IP包按照顺序发出去:
                        if arp.senderprotoaddr in self.IPv4Queue.keys():
                            print("(ARP reply) 应答了self.IPv4Queue的(找到下一跳的MAC): {} -> {}".format(arp.senderprotoaddr, arp.senderhwaddr))
                            for curIPv4Pkg in self.IPv4Queue[arp.senderprotoaddr].IPv4PktQueue:
                                e = curIPv4Pkg.get_header(Ethernet)
                                e.dst = arp.senderhwaddr  # 填写MAC.
                                e.src = self.net.interface_by_name(dev).ethaddr
                                OkIPv4Pkg = e + curIPv4Pkg.get_header(IPv4) + curIPv4Pkg.get_header(ICMP)
                                print("(ARP reply) [send1] 组装IP包完成并准备发送: ", OkIPv4Pkg)
                                # 包组装好了, 发送:
                                self.net.send_packet(dev, OkIPv4Pkg)
                            del self.IPv4Queue[arp.senderprotoaddr]

                    self.print_arp_table()

                # 处理IP包：
                elif pkt.has_header(IPv4):
                    ipv4 = pkt.get_header(IPv4)
                    print("收到 ipv4: ", ipv4)
                    ipv4.ttl -= 1

                    # 目标地址不是路由器上的接口:
                    if ipv4.dst not in [intf.ipaddr for intf in self.net.interfaces()]:
                        print("(IPv4) 目标地址不是路由器上的接口")
                        for i in self.fwTable:
                            if ipv4.dst in i.netAddr:
                                print("(IPv4) 找到self.fwTable中最长匹配: {} \in {}".format(ipv4.dst, i.netAddr))
                                # 目前找到了最长匹配:
                                curNextHop = i.nextHop if i.nextHop != None else ipv4.dst
                                print("(IPv4) 当前下一跳: {}".format(curNextHop))
                                # 如果下一跳在ARP table中, 组装发送:
                                if curNextHop in self.arpTable.keys():
                                    print("(IPv4) 下一跳在ARP table中")
                                    e = pkt.get_header(Ethernet)
                                    e.dst = self.arpTable[curNextHop]
                                    e.src = self.net.interface_by_name(i.intf).ethaddr
                                    OkIPv4Pkg = e + pkt.get_header(IPv4) + pkt.get_header(ICMP)
                                    print("(IPv4) [send2] 组装IP包完成并准备发送: ", OkIPv4Pkg)
                                    self.net.send_packet(i.intf, OkIPv4Pkg)
                                # 如果下一跳不在ARP table中:
                                else:
                                    print("(IPv4) 下一跳 不 在ARP table中, 准备存入等待队列..")
                                    if curNextHop in self.IPv4Queue.keys():
                                        print("(IPv4) 下一跳在等待队列中, 已存入.")
                                        self.IPv4Queue[curNextHop].IPv4PktQueue.append(pkt)
                                    else:
                                        arpRequest = create_ip_arp_request(
                                            self.net.interface_by_name(i.intf).ethaddr,
                                            self.net.interface_by_name(i.intf).ipaddr,
                                            curNextHop
                                        )
                                        print("(IPv4) 下一跳 不 在等待队列中, 准备发送ARP request并存入等待队列: {}, {}"
                                              .format(i.intf, arpRequest))
                                        self.net.send_packet(i.intf, arpRequest)
                                        self.IPv4Queue[curNextHop] = IPv4PkgMsg([pkt], time.time(), arpRequest, i.intf, 1)
                                break
                print("self.IPv4Queue: ")
                self.print_userDefined_table(self.IPv4Queue, True)


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
