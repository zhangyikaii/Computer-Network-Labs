#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from switchyard.lib.userlib import *

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

def switch_tests():
    s = TestScenario("switch_traffic tests")
    # 加入three device interfaces with name and MAC.
    s.add_interface('eth0', '10:00:00:00:00:01')
    s.add_interface('eth1', '10:00:00:00:00:02')
    s.add_interface('eth2', '10:00:00:00:00:03')
    s.add_interface('eth3', '10:00:00:00:00:04')
    # s.add_interface('eth4', '10:00:00:00:00:05')

    host = [
        ["20:00:00:00:00:01", "192.168.1.100"],
        ["20:00:00:00:00:02", "192.168.1.101"],
        ["30:00:00:00:00:01", "192.168.1.102"],
        ["30:00:00:00:00:02", "192.168.1.103"],
        ["40:00:00:00:00:01", "192.168.1.104"],
        ["40:00:00:00:00:02", "192.168.1.105"],
        ["50:00:00:00:00:01", "192.168.1.106"],
        ["50:00:00:00:00:02", "192.168.1.107"]
    ]

    # 设置部分主机位置，占满容量5的forwarding table 且每个表项traffic=0.
    broadcastTestCase(s, host[0][0], host[0][1], "eth0")
    broadcastTestCase(s, host[1][0], host[1][1], "eth0")
    broadcastTestCase(s, host[2][0], host[2][1], "eth1")
    broadcastTestCase(s, host[3][0], host[3][1], "eth1")
    broadcastTestCase(s, host[4][0], host[4][1], "eth2")
    # broadcastTestCase(s, host[5][0], host[5][1], "eth2")
    # broadcastTestCase(s, host[6][0], host[6][1], "eth3")
    # broadcastTestCase(s, host[7][0], host[7][1], "eth3")
    

    # 增加部分表项的traffic：
    for i in range(4):
        dst2dstTestCase(s, host[4][0], host[4][1], host[0][0], host[0][1], "eth2", "eth0")
    for i in range(3):
        dst2dstTestCase(s, host[4][0], host[4][1], host[1][0], host[1][1], "eth2", "eth0")
    for i in range(2):
        dst2dstTestCase(s, host[4][0], host[4][1], host[2][0], host[2][1], "eth2", "eth1")
    
    dst2dstTestCase(s, host[4][0], host[4][1], host[3][0], host[3][1], "eth2", "eth1")

    # 此时挤掉一个traffic最小的表项：
    broadcastTestCase(s, host[7][0], host[7][1], "eth3")

    # 测试一下是否被挤掉：
    dst2broadcastTestCase(s, host[0][0], host[0][1], host[4][0], host[4][1], "eth0", "eth2")

    # 增加host[7][0]表项的traffic：
    for i in range(5):
        dst2dstTestCase(s, host[0][0], host[0][1], host[7][0], host[7][1], "eth0", "eth3")

    # 此时挤掉一个traffic最小的表项：
    broadcastTestCase(s, host[6][0], host[6][1], "eth3")

    # 测试一下是否被挤掉：
    dst2broadcastTestCase(s, host[0][0], host[0][1], host[3][0], host[3][1], "eth0", "eth2")
    
    

    

    # resppkt = mk_pkt("30:00:00:00:00:02", "20:00:00:00:00:01", '172.16.42.2', '192.168.1.100', reply=True)
    # s.expect(PacketInputEvent("eth1", resppkt, display=Ethernet), "An Ethernet frame from 30:00:00:00:00:02 to 20:00:00:00:00:01 should arrive on eth1")
    # s.expect(PacketOutputEvent("eth0", resppkt, "eth2", resppkt, display=Ethernet), "Ethernet frame destined to 20:00:00:00:00:01 should be flooded out eth0 and eth2")

    # # test case 3: a frame with dest address of one of the interfaces should
    # # result in nothing happening
    # reqpkt = mk_pkt("20:00:00:00:00:01", "10:00:00:00:00:03", '192.168.1.100','172.16.42.2')
    # s.expect(PacketInputEvent("eth2", reqpkt, display=Ethernet), "An Ethernet frame should arrive on eth2 with destination address the same as eth2's MAC address")
    # s.expect(PacketInputTimeoutEvent(1.0), "The hub should not do anything in response to a frame arriving with a destination address referring to the hub itself.")

    # # test case 4: a frame with dest address of one of the interfaces should
    # # result in nothing happening
    # reqpkt = mk_pkt("20:00:00:00:00:01", "10:00:00:00:00:02", '192.168.1.100','172.16.42.2')
    # s.expect(PacketInputEvent("eth1", reqpkt, display=Ethernet), "An Ethernet frame should arrive on eth1 with destination address the same as eth1's MAC address")
    # s.expect(PacketInputTimeoutEvent(1.0), "The hub should not do anything in response to a frame arriving with a destination address referring to the hub itself.")
    return s

scenario = switch_tests()
