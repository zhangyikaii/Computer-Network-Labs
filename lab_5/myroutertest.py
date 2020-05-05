#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from switchyard.lib.userlib import *


# --- lab 2 ---
def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet(src=hwsrc, dst=hwdst, ethertype=EtherType.IP)
    ippkt = IPv4(src=ipsrc, dst=ipdst, protocol=IPProtocol.ICMP, ttl=32)
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    return ether + ippkt + icmppkt


def broadcastTestCase(s, srcMac, srcIp, srcInterface):
    testpkt = mk_pkt(srcMac, "ff:ff:ff:ff:ff:ff", srcIp, "255.255.255.255")

    s.expect(PacketInputEvent(srcInterface, testpkt, display=Ethernet), "(BROADCAST) arrive on {}".format(srcInterface))

    for _, otherInterface in enumerate(s.interfaces()):
        # print(otherInterface)
        if otherInterface != srcInterface:
            s.expect(PacketOutputEvent(otherInterface, testpkt, display=Ethernet),
                     "(BROADCAST) flood out on {}.".format(otherInterface))


def dst2dstTestCase(s, srcMac, srcIp, dstMac, dstIp, srcInterface, dstInterface):
    reqpkt = mk_pkt(srcMac, dstMac, srcIp, dstIp, reply=True)
    s.expect(PacketInputEvent(srcInterface, reqpkt, display=Ethernet), "(DST2DST) arrive on {}".format(srcInterface))

    s.expect(PacketOutputEvent(dstInterface, reqpkt, display=Ethernet),
             "(DST2DST) flood out from {}".format(dstInterface))


def dst2broadcastTestCase(s, srcMac, srcIp, dstMac, dstIp, srcInterface, dstInterface):
    testpkt = mk_pkt(srcMac, dstMac, srcIp, dstIp, reply=True)
    s.expect(PacketInputEvent(srcInterface, testpkt, display=Ethernet),
             "(DST2BROADCAST) arrive on {}".format(srcInterface))

    for _, otherInterface in enumerate(s.interfaces()):
        # print(otherInterface)
        if otherInterface != srcInterface:
            s.expect(PacketOutputEvent(otherInterface, testpkt, display=Ethernet),
                     "(DST2BROADCAST) flood out on {}.".format(otherInterface))


# --- lab 3 ---
def arpRequestLab3TestCase(s, srcMac, dstMac, srcIp, dstIp, srcInterface):
    # create_ip_arp_request(senderhwaddr, senderprotoaddr, targetprotoaddr)
    testpkt = create_ip_arp_request(srcMac, srcIp, dstIp)
    s.expect(PacketInputEvent(srcInterface, testpkt, display=Ethernet),
             "(ARP Request) DST IP: {}, arrive on {}".format(dstIp, srcInterface))

    # create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)
    replypkt = create_ip_arp_reply(dstMac, srcMac, dstIp, srcIp)
    s.expect(PacketOutputEvent(srcInterface, replypkt, display=Ethernet),
             "(ARP Request) DST IP: {}, response from {}".format(dstIp, srcInterface))


def notRespondLab3TestCase(s, srcMac, dstMac, srcIp, dstIp, srcInterface, isArpRqst=False):
    if isArpRqst == False:
        testpkt = mk_pkt(srcMac, dstMac, srcIp, dstIp)
        s.expect(PacketInputEvent(srcInterface, testpkt, display=Ethernet),
                 "(ICMP NOT Respond) DST IP: {}, arrive on {}".format(dstIp, srcInterface))

    else:
        testpkt = create_ip_arp_request(srcMac, srcIp, dstIp)
        s.expect(PacketInputEvent(srcInterface, testpkt, display=Ethernet),
                 "(ARP NOT Respond) DST IP: {}, arrive on {}".format(dstIp, srcInterface))


# --- lab 4 ---

### 因为和lab5有点冲突, 暂时注释.
# def mk_arpreq(hwsrc, ipsrc, ipdst):
#     return create_ip_arp_request(hwsrc, ipsrc, ipdst)

# def mk_arpresp(arpreq, hwsrc, arphwsrc=None, arphwdst=None):
#     if arphwsrc is None:
#         arphwsrc = hwsrc
#     if arphwdst is None:
#         arphwdst = arpreq[1].senderhwaddr
#     srcip = arpreq[1].targetprotoaddr
#     targetip = arpreq[1].senderprotoaddr
#     return create_ip_arp_reply(hwsrc, arphwdst, srcip, targetip)


# def mk_ping(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl=64):
#     ether = Ethernet()
#     ether.src = hwsrc
#     ether.dst = hwdst
#     ippkt = IPv4()
#     ippkt.src = ipsrc
#     ippkt.dst = ipdst
#     ippkt.ttl = ttl
#     ippkt.ipid = 0
#     icmppkt = ICMP()
#     if reply:
#         icmppkt.icmptype = ICMPType.EchoReply
#     else:
#         icmppkt.icmptype = ICMPType.EchoRequest
#     icmppkt.icmpdata.sequence = 42
#     icmppkt.icmpdata.data = b'stuff!'
#     return ether + ippkt + icmppkt


def ARPreplyForAddEntryToARPTableLab4TestCase(addIP, addMAC):
    otroarp = mk_arpreq("10:00:00:00:00:02", "10.10.0.1", "10.10.1.254")
    otroarpresponse = mk_arpresp(otroarp, "11:22:33:44:55:66")

    # s.expect(PacketInputEvent("router-eth1", otroarpresponse, display=Arp),
    #     "Router should receive an unsolicited ARP response for 10.10.1.254 on router-eth1 and do nothing at all.")
    # s.expect(PacketInputTimeoutEvent(0.1),
    #         "Application should try to receive a packet, but then timeout")


# --- lab 5 ---

from copy import deepcopy

def get_raw_pkt(pkt, xlen):
    pkt = deepcopy(pkt)
    i = pkt.get_header_index(Ethernet)
    if i >= 0:
        del pkt[i]
    b = pkt.to_bytes()[:xlen]
    return b

def mk_arpreq(hwsrc, ipsrc, ipdst):
    arp_req = Arp()
    arp_req.operation = ArpOperation.Request
    arp_req.senderprotoaddr = IPAddr(ipsrc)
    arp_req.targetprotoaddr = IPAddr(ipdst)
    arp_req.senderhwaddr = EthAddr(hwsrc)
    arp_req.targethwaddr = EthAddr("ff:ff:ff:ff:ff:ff")
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr("ff:ff:ff:ff:ff:ff")
    ether.ethertype = EtherType.ARP
    return ether + arp_req

def mk_arpresp(arpreqpkt, hwsrc, arphwsrc=None, arphwdst=None):
    if arphwsrc is None:
        arphwsrc = hwsrc
    if arphwdst is None:
        arphwdst = arpreqpkt.get_header(Arp).senderhwaddr
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = arpreqpkt.get_header(Arp).senderhwaddr
    ether.ethertype = EtherType.ARP
    arp_reply = Arp()
    arp_reply.operation = ArpOperation.Reply
    arp_reply.senderprotoaddr = IPAddr(arpreqpkt.get_header(Arp).targetprotoaddr)
    arp_reply.targetprotoaddr = IPAddr(arpreqpkt.get_header(Arp).senderprotoaddr)
    arp_reply.senderhwaddr = EthAddr(arphwsrc)
    arp_reply.targethwaddr = EthAddr(arphwdst)
    return ether + arp_reply

def mk_ping(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl=64, payload=''):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP
    ippkt = IPv4()
    ippkt.src = IPAddr(ipsrc)
    ippkt.dst = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = ttl
    ippkt.ipid = 0
    if reply:
        icmppkt = ICMP()
        icmppkt.icmptype = ICMPType.EchoReply
        icmppkt.icmpcode = ICMPCodeEchoReply.EchoReply
    else:
        icmppkt = ICMP()
        icmppkt.icmptype = ICMPType.EchoRequest
        icmppkt.icmpcode = ICMPCodeEchoRequest.EchoRequest
    icmppkt.icmpdata.sequence = 42
    icmppkt.icmpdata.data = payload
    return ether + ippkt + icmppkt

def mk_icmperr(hwsrc, hwdst, ipsrc, ipdst, xtype, xcode=0, origpkt=None, ttl=64):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP
    ippkt = IPv4()
    ippkt.src = IPAddr(ipsrc)
    ippkt.dst = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = ttl
    ippkt.ipid = 0
    icmppkt = ICMP()
    icmppkt.icmptype = xtype
    icmppkt.icmpcode = xcode
    if origpkt is not None:
        xpkt = deepcopy(origpkt)
        i = xpkt.get_header_index(Ethernet)
        if i >= 0:
            del xpkt[i]
        icmppkt.icmpdata.data = b'E\x00\x00\x1c\x00\x00\x00\x00\x00\x01'
        icmppkt.icmpdata.origdgramlen = 28

    print("mk_icmperr 构造完成: ", ether + ippkt + icmppkt)
    return ether + ippkt + icmppkt

def mk_udp(hwsrc, hwdst, ipsrc, ipdst, ttl=64, srcport=10000, dstport=10000, payload=''):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP
    ippkt = IPv4()
    ippkt.src = IPAddr(ipsrc)
    ippkt.dst = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.UDP
    ippkt.ttl = ttl
    ippkt.ipid = 0
    udppkt = UDP()
    udppkt.src = srcport
    udppkt.dst = dstport
    return ether + ippkt + udppkt + RawPacketContents(payload)


def write_table():
    table = '''172.16.0.0 255.255.0.0 192.168.1.2 router-eth0
172.16.128.0 255.255.192.0 10.10.0.254 router-eth1
172.16.64.0 255.255.192.0 10.10.1.254 router-eth1
10.100.0.0 255.255.0.0 172.16.42.2 router-eth2
'''
    outfile = open('forwarding_table.txt', 'w')
    outfile.write(table)
    outfile.close()

def icmp_tests():
    s = TestScenario("IP forwarding and ARP requester tests")
    s.add_interface('router-eth0', '10:00:00:00:00:01', '192.168.1.1', '255.255.255.0')
    s.add_interface('router-eth1', '10:00:00:00:00:02', '10.10.0.1', '255.255.0.0')
    s.add_interface('router-eth2', '10:00:00:00:00:03', '172.16.42.1', '255.255.255.252')
    s.add_file('forwarding_table.txt', '''172.16.0.0 255.255.0.0 192.168.1.2 router-eth0
172.16.128.0 255.255.192.0 10.10.0.254 router-eth1
172.16.64.0 255.255.192.0 10.10.1.254 router-eth1
10.100.0.0 255.255.0.0 172.16.42.2 router-eth2
''')

    nottinyttl = '''lambda pkt: pkt.get_header(IPv4).ttl >= 8'''

    # Your tests here
    # ab:cd:00:00:00:47->10:00:00:00:00:01 IP | IPv4 172.16.111.222->192.168.1.1
    testpkt = mk_ping('ab:cd:00:00:00:47', '10:00:00:00:00:01', '172.16.111.222', '166.166.1.1', reply=False, ttl=1)
    testpkt_err = mk_icmperr('10:00:00:00:00:02', 'ab:cd:00:00:00:01', '192.168.1.1', '172.16.111.222',
                             ICMPType.DestinationUnreachable, origpkt=testpkt)
    # 10:00:00:00:00:02->ff:ff:ff:ff:ff:ff
    arpreq = mk_arpreq('10:00:00:00:00:02', '10.10.0.1', '10.10.1.254')
    s.expect(PacketInputEvent('router-eth0', testpkt, display=Ethernet),
             "(ICMP Echo Request) 先来一个 TTL==1 并且 在forwarding table中找不到表项的包, 这是综合助教哥的测试用例和FAQ里的内容得到的全新测试!")
    s.expect(PacketOutputEvent('router-eth1', arpreq, display=Ethernet),
             "(NetworkUnreachable) 这种情况下双重错误, 应该报出NetworkUnreachable, 因为最开始ARP table为空, 所以找不到吓一跳的MAC, 该报错包加入队列后, 发送ARP request")
    testpkt = mk_ping('ab:cd:00:00:00:47', '10:00:00:00:00:01', '172.16.111.222', '166.166.1.1', reply=False, ttl=1)
    s.expect(PacketInputEvent('router-eth0', testpkt, display=Ethernet),
             "(ICMP Echo Reply) 再来一个 TTL==1的Reply吧, 其他数据同上一个Request, 它应该和上一个Request一起进队.")
    testpkt = mk_udp('ab:cd:00:00:00:47', '10:00:00:00:00:03', '172.16.166.166', '172.16.128.0')
    s.expect(PacketInputEvent('router-eth2', testpkt, display=Ethernet),
             "(UDP) 玩点刺激的, 也是全新的测试用例! 再来一个需要转发的UDP包, 注意这里是转发而不是 不可处理的类型(在助教哥的测试用例里出现了)")
    # Ethernet 10:00:00:00:00:02->ff:ff:ff:ff:ff:ff ARP | Arp 10:00:00:00:00:02:10.10.0.1 ff:ff:ff:ff:ff:ff:10.10.0.254
    arpreq1 = mk_arpreq('10:00:00:00:00:02', '10.10.0.1', '10.10.0.254')
    s.expect(PacketOutputEvent('router-eth1', arpreq1, display=Ethernet),
             "(ARP Request) 在此之后会应答之前的在队列里的两个包, 他们会依次发送.")

    return s

scenario = icmp_tests()