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
def mk_arpreq(hwsrc, ipsrc, ipdst):
    return create_ip_arp_request(hwsrc, ipsrc, ipdst)


def mk_arpresp(arpreq, hwsrc, arphwsrc=None, arphwdst=None):
    if arphwsrc is None:
        arphwsrc = hwsrc
    if arphwdst is None:
        arphwdst = arpreq[1].senderhwaddr
    srcip = arpreq[1].targetprotoaddr
    targetip = arpreq[1].senderprotoaddr
    return create_ip_arp_reply(hwsrc, arphwdst, srcip, targetip)


def mk_ping(hwsrc, hwdst, ipsrc, ipdst, reply=False, ttl=64):
    ether = Ethernet()
    ether.src = hwsrc
    ether.dst = hwdst
    ippkt = IPv4()
    ippkt.src = ipsrc
    ippkt.dst = ipdst
    ippkt.ttl = ttl
    ippkt.ipid = 0
    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest
    icmppkt.icmpdata.sequence = 42
    icmppkt.icmpdata.data = b'stuff!'

    return ether + ippkt + icmppkt


def write_table():
    table = '''172.16.0.0 255.255.0.0 192.168.1.2 router-eth0
172.16.128.0 255.255.192.0 10.10.0.254 router-eth1
172.16.64.0 255.255.192.0 10.10.1.254 router-eth1
10.100.0.0 255.255.0.0 172.16.42.2 router-eth2
'''
    outfile = open('forwarding_table.txt', 'w')
    outfile.write(table)
    outfile.close()


def ARPreplyForAddEntryToARPTableLab4TestCase(addIP, addMAC):
    otroarp = mk_arpreq("10:00:00:00:00:02", "10.10.0.1", "10.10.1.254")
    otroarpresponse = mk_arpresp(otroarp, "11:22:33:44:55:66")

    # s.expect(PacketInputEvent("router-eth1", otroarpresponse, display=Arp),
    #     "Router should receive an unsolicited ARP response for 10.10.1.254 on router-eth1 and do nothing at all.")
    # s.expect(PacketInputTimeoutEvent(0.1),
    #         "Application should try to receive a packet, but then timeout")


def router_tests():
    s = TestScenario("Router stage 2 additional test 1")
    s.add_interface('router-eth0', '10:00:00:00:00:01', '192.168.1.1', '255.255.255.0')
    s.add_interface('router-eth1', '10:00:00:00:00:02', '10.10.0.1', '255.255.0.0')
    s.add_interface('router-eth2', '10:00:00:00:00:03', '172.16.42.1', '255.255.255.252')

    host = [
        ["20:00:00:00:00:01", "192.168.1.205", "192.168.1.1"],
        ["20:00:00:00:00:02", "202.168.1.206", "10.10.0.2"],
        ["30:00:00:00:00:01", "192.168.1.207", "10.10.0.1"],
        ["40:00:00:00:00:01", "192.168.1.208", "10.10.0.6"]
    ]

    notRespondLab3TestCase(s, host[1][0], '10:00:00:00:00:02', host[1][1], '9.8.7.6', 'router-eth1')

    srcMac, dstMac, srcIp, dstIp, srcInterface = host[0][0], host[2][0], host[0][1], host[2][1], 'router-eth0'
    testpkt = mk_pkt(srcMac, dstMac, srcIp, dstIp)

    arpRequest1 = create_ip_arp_request('10:00:00:00:00:01', '192.168.1.1', dstIp)

    s.expect(PacketInputEvent(srcInterface, testpkt, display=Ethernet),
             "(ICMP NOT Respond 但是需要被加入队列) DST IP: {}, arrive on {}".format(dstIp, srcInterface))

    s.expect(PacketOutputEvent(srcInterface, arpRequest1, display=Ethernet),
             "(ARP Request 加入队列后发送) DST IP: {}, send on {}".format(dstIp, srcInterface))
    for i in range(2):
        s.expect(PacketInputEvent(srcInterface, testpkt, display=Ethernet),
                 "(ICMP NOT Respond 但是需要被加入队列) DST IP: {}, arrive on {}".format(dstIp, srcInterface))

    srcMac, dstMac, srcIp, dstIp, srcInterface = host[0][0], host[3][0], host[0][1], host[3][1], 'router-eth0'
    testpkt = mk_pkt(srcMac, dstMac, srcIp, dstIp)

    arpRequest2 = create_ip_arp_request('10:00:00:00:00:01', '192.168.1.1', dstIp)

    s.expect(PacketInputEvent(srcInterface, testpkt, display=Ethernet),
             "(ICMP NOT Respond 但是需要被加入队列) DST IP: {}, arrive on {}".format(dstIp, srcInterface))

    s.expect(PacketOutputEvent(srcInterface, arpRequest2, display=Ethernet),
             "(ARP Request 加入队列后发送) DST IP: {}, send on {}".format(dstIp, srcInterface))

    arpReply = mk_arpresp(arpRequest2, "11:22:33:44:55:66")
    s.expect(PacketInputEvent("router-eth1", arpReply, display=Arp),
             "(ARP Reply) 命中队列中第二个吓一跳")

    srcMac, srcIp, dstMac, dstIp = "10:00:00:00:00:02", "192.168.1.205", "11:22:33:44:55:66", "192.168.1.208"
    IPv4Send = mk_pkt(srcMac, dstMac, srcIp, dstIp)
    IPv4Send.get_header(IPv4).ttl -= 1
    s.expect(PacketOutputEvent("router-eth1", IPv4Send, display=Ethernet),
             "(ICMP send) 得到MAC后队列中的发送，注意TTL-1")

    arpReply = mk_arpresp(arpRequest1, "10:20:30:40:50:60")
    s.expect(PacketInputEvent("router-eth1", arpReply, display=Arp),
             "(ARP Reply) 命中队列中第一个吓一跳")    

    srcMac, dstMac, srcIp, dstIp = "10:00:00:00:00:02", "10:20:30:40:50:60", "192.168.1.205", "192.168.1.207"
    IPv4Send = mk_pkt(srcMac, dstMac, srcIp, dstIp)
    IPv4Send.get_header(IPv4).ttl -= 1
    s.expect(PacketOutputEvent("router-eth1", IPv4Send, display=Ethernet),
             "(ICMP send) 得到MAC后队列中的发送，注意TTL-1")

    s.expect(PacketOutputEvent("router-eth1", IPv4Send, display=Ethernet),
             "(ICMP send) 得到MAC后队列中的发送，注意TTL-1")

    s.expect(PacketOutputEvent("router-eth1", IPv4Send, display=Ethernet),
             "(ICMP send) 得到MAC后队列中的发送，注意TTL-1")

    return s


write_table()
scenario = router_tests()