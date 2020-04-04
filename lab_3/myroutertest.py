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
            s.expect(PacketOutputEvent(otherInterface, testpkt, display=Ethernet), "(BROADCAST) flood out on {}.".format(otherInterface))

def dst2dstTestCase(s, srcMac, srcIp, dstMac, dstIp, srcInterface, dstInterface):
    reqpkt = mk_pkt(srcMac, dstMac, srcIp, dstIp, reply=True)
    s.expect(PacketInputEvent(srcInterface, reqpkt, display=Ethernet), "(DST2DST) arrive on {}".format(srcInterface))

    s.expect(PacketOutputEvent(dstInterface, reqpkt, display=Ethernet), "(DST2DST) flood out from {}".format(dstInterface))

def dst2broadcastTestCase(s, srcMac, srcIp, dstMac, dstIp, srcInterface, dstInterface):
    testpkt = mk_pkt(srcMac, dstMac, srcIp, dstIp, reply=True)
    s.expect(PacketInputEvent(srcInterface, testpkt, display=Ethernet), "(DST2BROADCAST) arrive on {}".format(srcInterface))

    for _, otherInterface in enumerate(s.interfaces()):
        # print(otherInterface)
        if otherInterface != srcInterface:
            s.expect(PacketOutputEvent(otherInterface, testpkt, display=Ethernet), "(DST2BROADCAST) flood out on {}.".format(otherInterface))

# --- lab 3 ---
def arpRequestLab3TestCase(s, srcMac, dstMac, srcIp, dstIp, srcInterface):
    # create_ip_arp_request(senderhwaddr, senderprotoaddr, targetprotoaddr)
    testpkt = create_ip_arp_request(srcMac, srcIp, dstIp)
    s.expect(PacketInputEvent(srcInterface, testpkt, display=Ethernet), "(ARP Request) DST IP: {}, arrive on {}".format(dstIp, srcInterface))

    # create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr, targetprotoaddr)
    replypkt = create_ip_arp_reply(dstMac, srcMac, dstIp, srcIp)
    s.expect(PacketOutputEvent(srcInterface, replypkt, display=Ethernet), "(ARP Request) DST IP: {}, response from {}".format(dstIp, srcInterface))

def notRespondLab3TestCase(s, srcMac, dstMac, srcIp, dstIp, srcInterface, isArpRqst=False):
    if isArpRqst == False:
        testpkt = mk_pkt(srcMac, dstMac, srcIp, dstIp)
        s.expect(PacketInputEvent(srcInterface, testpkt, display=Ethernet), "(ICMP NOT Respond) DST IP: {}, arrive on {}".format(dstIp, srcInterface))

    else:
        testpkt = create_ip_arp_request(srcMac, srcIp, dstIp)
        s.expect(PacketInputEvent(srcInterface, testpkt, display=Ethernet), "(ARP NOT Respond) DST IP: {}, arrive on {}".format(dstIp, srcInterface))

def router_tests():
    s = TestScenario("switch tests")

    s.add_interface('router-eth0', '10:00:00:00:00:01', ipaddr='192.168.1.1')
    s.add_interface('router-eth1', '10:00:00:00:00:02', ipaddr='10.10.0.1')

    host = [
        ["20:00:00:00:00:01", "192.168.1.205", "192.168.1.1"],
        ["20:00:00:00:00:02", "192.168.1.206", "10.10.0.2"],
        ["30:00:00:00:00:01", "192.168.1.207", "10.10.0.1"]
    ]

    arpRequestLab3TestCase(s, host[0][0], '10:00:00:00:00:01', host[0][1], host[0][2], 'router-eth0')

    notRespondLab3TestCase(s, host[1][0], '10:00:00:00:00:02', host[1][1], '10.10.12.34', 'router-eth1')
    
    notRespondLab3TestCase(s, host[1][0], '10:00:00:00:00:02', host[1][1], host[1][2], 'router-eth1', isArpRqst=True)

    arpRequestLab3TestCase(s, host[2][0], '10:00:00:00:00:02', host[2][1], host[2][2], 'router-eth1')

    return s

scenario = router_tests()
