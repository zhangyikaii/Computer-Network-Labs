#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from random import randint
from collections import deque
import time
import re
import os


def parse_params():
    try:
        fp = open("blaster_params.txt")
        context = fp.read().replace(" ", "") + "-"
        fp.close()
        try:
            para_b = re.findall("-b(.*?)[-\n]", context)
            para_n = re.findall("-n(.*?)[-\n]", context)
            para_l = re.findall("-l(.*?)[-\n]", context)
            para_w = re.findall("-w(.*?)[-\n]", context)
            para_t = re.findall("-t(.*?)[-\n]", context)
            para_r = re.findall("-r(.*?)[-\n]", context)
            return IPv4Address(para_b[0]), int(para_n[0]), int(para_l[0]), int(para_w[0]), float(para_t[0]) / 1000, float(para_r[0]) / 1000
        except ValueError:
            print("ERROR: Invalid parameter!")

    except FileNotFoundError:
        log_debug("ERROR: File not found.")

class PktMsg():
    def __init__(self, pkt, seqNum):
        self.pkt = pkt
        self.isACK = False
        self.seqNum = seqNum
        self.resendNum = 0
        self.sendTime = time.time()

    def __str__(self):
        return "({})".format(", ".join("{}={}".format(key, getattr(self, key)) for key in self.__dict__.keys()))


class Blaster(object):
    def __init__(self, net):
        self.net = net
        self.blasteeIP, self.numPkt, self.payloadLength, self.sdrWindow, self.coarseTimeout, self.recvTimeout = parse_params()
        print("读取参数: self.blasteeIP, self.numPkt, self.payloadLength, self.sdrWindow, self.coarseTimeout, self.recvTimeout")
        print(self.blasteeIP, self.numPkt, self.payloadLength, self.sdrWindow, self.coarseTimeout, self.recvTimeout)
        self.middlboxEth = EthAddr('40:00:00:00:00:01')
        self.curIntf = net.interface_by_name('blaster-eth0')
        self.windowTimestampIdx = 0
        self.window = deque(maxlen=self.sdrWindow)

    def get_recv_timeout(self):
        return self.recvTimeout

    def update_windowTimestampIdx(self):
        ans = -1
        for i, v in enumerate(self.window):
            if v.isACK == False and (ans == -1 or v.sendTime < self.window[ans].sendTime):
                ans = i

        log_info(" <- 当前时间 ->")
        if ans != -1 and ans != self.windowTimestampIdx:
            print("\n===> window timestamp 被更新: {} -> {}. <===\n".format(self.windowTimestampIdx, ans))
            self.windowTimestampIdx = ans
        else:
            print("\n===> window timestamp 未被更新. <===\n")

    def recv_pkt(self, pkt):
        print("recv_pkt 开始!")
        hdr = pkt.get_header(RawPacketContents)
        seqNum = int.from_bytes(hdr.data[:4], 'big')
        print("接受到的 seqNum: ", seqNum)
        for i, v in enumerate(self.window):
            if v.seqNum == seqNum:
                print("ACK了包 {}.".format(i + 1))
                v.isACK = True
                self.update_windowTimestampIdx()

        print("recv_pkt 退出!\n")

    def check_shutdown(self):
        if self.numPkt != 0:
            return False
        for v in self.window:
            if v.isACK == False:
                return False
        return True

    def mk_pkt(self, seq_num):
        eth = Ethernet()
        eth.src = self.curIntf.ethaddr
        eth.dst = self.middlboxEth

        ip = IPv4(protocol=IPProtocol.UDP)
        ip.src = self.curIntf.ipaddr
        ip.dst = self.blasteeIP

        udp = UDP()
        pkt = eth + ip + udp + seq_num.to_bytes(4, 'big') + self.payloadLength.to_bytes(2, 'big') + os.urandom(self.payloadLength)
        return pkt

    def print_deque(self):
        if len(self.window) == 0:
            print("\n当前window为空.\n")
        else:
            print("\n当前window: ")
            for i in self.window:
                print(i)
            print()

    def send_pkt(self):
        print("send_pkt 开始!")
        if self.numPkt != 0 and (len(self.window) < self.window.maxlen or self.window[0].isACK == True):
            curSeqNum = 1
            if len(self.window) > 0:
                curSeqNum = self.window[len(self.window) - 1].seqNum + 1
            pkt = self.mk_pkt(curSeqNum)
            self.window.append(PktMsg(pkt, curSeqNum))

            print("(send_pkt) 组装完成并准备发送: ", pkt)
            log_info(" <- 当前时间 ->")
            self.net.send_packet(self.curIntf.name, pkt)
            print("发送成功!")
            self.numPkt -= 1
            self.update_windowTimestampIdx()

        print("send_pkt 退出!\n")


    def resend_pkt(self):
        if len(self.window) == 0:
            print("resend_pkt 中 window 为空.\n")
            return False

        print("resend_pkt 开始!")
        retIsResend = False
        curTime = time.time()
        print("(resend_pkt) 重传条件检测: {} VS. {}".format(
            curTime - self.window[self.windowTimestampIdx].sendTime,
            self.coarseTimeout
        ))
        if curTime - self.window[self.windowTimestampIdx].sendTime > self.coarseTimeout:
            # 重发:
            retIsResend = True
            for i in self.window:
                # 更新窗口内的记录元素:
                if i.isACK == False:
                    i.resendNum += 1
                    i.sendTime = time.time()
                    print("(resend_pkt) 准备发送window内元素: ", i)
                    log_info(" <- 当前时间 ->")
                    self.net.send_packet(self.curIntf.name, i.pkt)
                    print("发送成功!")
                    break
            # 更新窗口Timestamp
            self.update_windowTimestampIdx()
        print("resend_pkt 退出!\n")
        return retIsResend

def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    blaster = Blaster(net)

    dev, pkt = None, None
    while True:
        gotpkt = True
        try:
            # Timeout value will be parameterized!
            timestamp, dev, pkt = net.recv_packet(timeout=blaster.get_recv_timeout())
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet")
            log_info("Got a packet (from {}): {}".format(dev, pkt))

            blaster.recv_pkt(pkt)
            if blaster.check_shutdown():
                raise Shutdown("完成了!")

        if not blaster.resend_pkt():
            blaster.send_pkt()

        blaster.print_deque()

    net.shutdown()
