#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *
from threading import *
from random import randint
import random
import time
import re


def parse_params():
    try:
        fp = open("middlebox_params.txt")
        context = fp.read().replace(" ", "")
        para_d = re.findall("-d(.*?)[-\n]", context)

        fp.close()
        try:
            print("解析参数: ", para_d)
            return float(para_d[0])
        except ValueError:
            print("ERROR: Invalid parameter: ", para_d)

    except FileNotFoundError:
        log_debug("ERROR: File not found.")


def switchy_main(net):
    drop_rate = parse_params()

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

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
            log_debug("I got a packet {}".format(pkt))
            log_info("Got a packet (from {}): {}".format(dev, pkt))

        if dev == "middlebox-eth0":
            log_debug("Received from blaster")
            print("From blaster.")

            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''

            if random.random() <= drop_rate:
                print("丢包！")
                continue

            pkt[Ethernet].src = '40:00:00:00:00:02'
            pkt[Ethernet].dst = '20:00:00:00:00:01'
            net.send_packet("middlebox-eth1", pkt)
        elif dev == "middlebox-eth1":
            log_debug("Received from blastee")
            print("From blastee.")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''

            pkt[Ethernet].src = '40:00:00:00:00:01'
            pkt[Ethernet].dst = '10:00:00:00:00:01'

            net.send_packet("middlebox-eth0", pkt)
        else:
            log_debug("Oops :))")

    net.shutdown()
