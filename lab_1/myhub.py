#!/usr/bin/env python3

# Switchyard程序是一个简单的Python程序，它包含一个特定的入口点函数，该函数接受单个参数。启动函数可以简单地命名为main，但是也可以命名为switchy_main。该函数必须接受至少一个参数，该参数是对Switchyard **网络对象** 的引用(如下所述)。对网络对象的方法调用 用于在 网络端口之间发送和接收数据包。

# swyard用于启动Switchyard框架并加载代码。
# 当Switchyard启动您的代码时，它查找一个名为main的函数并调用它，将网络对象作为第一个参数传递。
# Switchyard程序通常还将导入其他Switchyard模块，例如用于解析和构造包、处理网络地址和其他功能的模块。

# Switchyard可用于针对来自第2层(链路层)及以上的网络协议栈层的系统构建项目。

'''
# 接收一个数据包，打印出来，把它发送回同一个接口。
from switchyard.lib.userlib import *

def main(net):
    timestamp,input_port,packet = net.recv_packet()
    print ("Received {} on {}".format(packet, input_port))
    net.send_packet(input_port, packet)

# 简单的例子，没有处理异常
def main(net):
    # below, recvdata is a namedtuple
    recvdata = net.recv_packet()
    print ("At {}, received {} on {}".format(
        recvdata.timestamp, recvdata.packet, recvdata.input_port))

    # alternatively, the above line could use indexing, although
    # readability suffers:
    #    recvdata[0], recvdata[2], recvdata[1]))
    
    net.send_packet(recvdata.input_port, recvdata.packet)

    # likewise, the above line could be written using indexing
'''

# Switchyard运行时环境提供一个具有一个或多个接口或端口的给定网络系统。端口可以表示到另一个设备的wired connection，也可以表示无线接口，也可以表示loopback接口。无论如何，数据包都是通过这些端口发送和接收的。每个端口至少有一个名称(如en0)和一个以太网地址。一个端口也可能有一个IPv4地址和与其相关联的子网掩码。


### 初始测试文件和设备逻辑是不完整的。你需要一步一步地修改它们。

'''
# RUN:
swyard -t hubtests.py myhub.py

# The argument to the -t option should be the name of the test scenario to be executed, and the final argument is the name of your code.
'''

### -------------------------
# 重点来了：
### 在测试环境中没有真正的流量。设备只接收 **我们提供的** 数据包。在start_mininet.py我们需要挑战真正的网络。

'''
sudo python start_mininet.py
1. 打开xterm看：
xterm hub
2. 在xterm里激活环境
source ...
3. 运行swyard
swyard myhub.py
### Now you have your topology ready and your hub running, let's see if it works.
'''


'''
Ethernet hub in Switchyard.
'''
from switchyard.lib.userlib import *


# net: 包含该设备的一些信息（网卡等）
def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    log_info("mymacs: {}".format(mymacs))

    inPkNum = 0
    outPkNum = 0
    # 主循环：
    while True:
        try:
            # 获得最先到达的包， 并返回 时间和对应的网卡
            timestamp,dev,packet = net.recv_packet()
            inPkNum += 1
        except NoPackets:
            continue
        except Shutdown:
            return

        log_debug ("In {} received packet {} on {}".format(net.name, packet, dev))
        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            continue

        if eth.dst in mymacs:
            log_info ("Received a packet intended for me")
        else:
            for intf in my_interfaces:
                if dev != intf.name:
                    log_info ("Flooding packet {} to {}".format(packet, intf.name))
                    # 将包从对应网卡发出去
                    net.send_packet(intf, packet)
                    outPkNum += 1
        log_info("{} in:{} out:{}".format(timestamp, inPkNum, outPkNum))
    net.shutdown()
