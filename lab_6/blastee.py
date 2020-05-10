#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
import time
import re
from base64 import b64encode

def parse_params():
    try:
        fp = open("blastee_params.txt")
        context = fp.read().replace(" ", "")
        para_b = re.findall("-b(.*?)[-\n]", context)
        para_n = re.findall("-n(.*?)[-\n]", context)
        print("解析参数结果： {}， {}".format(para_b, para_n))
        fp.close()
        return IPv4Address(para_b[0]), int(para_n[0])

    except FileNotFoundError:
        log_debug("ERROR: File not found.")

def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    curIntf = net.interface_by_name('blastee-eth0')
    middleboxEth = EthAddr('40:00:00:00:00:02')

    blasterIP, numPkt = parse_params()

    while True:
        gotpkt = True
        dev, pkt = None, None
        try:
            timestamp, dev, pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            if pkt[Ethernet].ethertype != EtherType.IPv4 or not pkt.has_header(IPv4) or not pkt.has_header(UDP):
                continue

            log_debug("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))

            print("Got a packet (from {}): {}".format(dev, pkt))

            hdr = pkt.get_header(RawPacketContents)
            seqNum = int.from_bytes(hdr.data[:4], 'big')
            payload = b64encode(hdr.data[6:]).decode('utf-8')
            payloadByte = hdr.data[6:]
            # 如果不够长要padding:
            if len(payloadByte) < 8:
                payloadByte += "\0".encode() * (8 - len(payloadByte))
            payloadByte = payloadByte[0:8]

            print("seqNum: {}, payload: {}".format(seqNum, payload))

            def mk_pkt(ethSrc, ethDst, ipSrc, ipDst, seqNum, payloadByte):
                eth = Ethernet()
                eth.src, eth.dst = ethSrc, ethDst

                ip = IPv4(protocol=IPProtocol.UDP)
                ip.src, ip.dst = ipSrc, ipDst

                udp = UDP()

                pkt = eth + ip + udp + seqNum.to_bytes(4, 'big') + payloadByte

                return pkt

            ack = mk_pkt(
                curIntf.ethaddr,
                middleboxEth,
                curIntf.ipaddr,
                blasterIP,
                seqNum,
                payloadByte
            )
            print("seqNum: ", seqNum)
            print("(blastee) 组装ACK完成并准备发送: ", ack)
            log_info("<- 当前时间 ->")
            net.send_packet(
                curIntf.name,
                ack
            )
            print("发送成功！\n")
    net.shutdown()