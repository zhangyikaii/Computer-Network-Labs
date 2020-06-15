from switchyard.lib.userlib import *
import time


# protocol 的通配符是 IPv4, port 的通配符是 None, tokbucket 的通配符是 None.
class RuleMsg():
    def __init__(self, protocol, isPermit, src, dst, srcport=None, dstport=None, ratelimit=None, impair=False):
        self.protocol = protocol # 协议
        self.isPermit = True if isPermit == "permit" else False # 是否允许转发

        self.src = self.process_addr(src) # 源IP
        self.dst = self.process_addr(dst) # 目的IP
        self.srcport = None if srcport == 'any' or srcport is None else int(srcport) # 源端口
        self.dstport = None if dstport == 'any' or dstport is None else int(dstport) # 目的端口
        self.tokbucket = None if ratelimit is None else int(ratelimit) * 2 # token桶, 初始化为2r
        self.addtok = None if ratelimit is None else int(ratelimit) // 2 # 一次加入的token量
        self.maxtok = None if ratelimit is None else int(ratelimit) * 2 # token桶内最大量.
        self.toktimestamp = time.time() # token桶的时间戳
        self.impair = impair # 是否需要impair

    def add_tokens(self, timestamp):
        # 更新时间戳并加入token.
        interval = timestamp - self.toktimestamp
        print("interval: {}".format(interval))
        isUpdate = False
        while interval - 0.5 > 0:
            isUpdate = True
            interval -= 0.5
            self.tokbucket += self.addtok
            if self.tokbucket > self.maxtok:
                self.tokbucket = self.maxtok
                break
        if isUpdate == True:
            print("允许更新, 更新后 tokbucket: {}".format(self.tokbucket))
            self.toktimestamp = time.time()
        else:
            print("未更新, tokbucket: {}".format(self.tokbucket))

    def process_addr(self, addr):
        # 预处理地址
        if addr == 'any':
            return IPv4Network('0.0.0.0/0')
        elif addr.find("/") == -1:
            return IPv4Network(addr, strict=False)
        else:
            return IPv4Network(addr)

    def __str__(self):
        # 自定义输出
        return "「 {} 」".format(", ".join("{}: {}".format(key, getattr(self, key)) for key in self.__dict__.keys()))

class Rules():
    def __init__(self, fileDir):
        # 读文件创建规则:
        self.protocol = {
            "ip": IPv4,
            "tcp": IPProtocol.TCP,
            "udp": IPProtocol.UDP,
            "icmp": IPProtocol.ICMP
        }

        print("开始读取 {} 文件".format(fileDir))
        self.rawRules = []
        with open(fileDir) as fwTxt:
            for line in fwTxt:
                line = line.strip()
                if not len(line) or line.startswith('#'):
                    continue
                print(line)
                self.rawRules.append(line)

        self.rules = []
        self.construct_rules()

    def print_rules(self):
        print("打印 Rules:")
        for i in self.rules:
            print(i)

    def construct_rules(self):
        for cur in self.rawRules:
            cur = cur.split()
            if len(cur) < 6:
                print("无法解析, Rule: {}".format(cur))
                continue
            try:
                src, dst = cur[cur.index('src') + 1], cur[cur.index('dst') + 1]
                srcport, dstport, ratelimit, impair = None, None, None, False
                isPermit, protocol = cur[0], self.protocol[cur[1]]
                if 'srcport' in cur:
                    srcport = cur[cur.index('srcport') + 1]
                if 'dstport' in cur:
                    dstport = cur[cur.index('dstport') + 1]
                if 'ratelimit' in cur:
                    ratelimit = cur[cur.index('ratelimit') + 1]
                if 'impair' in cur:
                    impair = True
                self.rules.append(RuleMsg(protocol, isPermit, src, dst, srcport, dstport, ratelimit, impair))
            except:
                print("解析出错, Rule: {}".format(cur))

        print("\n解析完成, self.rules: ")
        self.print_rules()


    def judge_permit(self, pkt):
        if pkt.has_header(IPv4):
            print("收到 ipv4:")
            header = pkt.get_header(IPv4)
            for idx, curRule in enumerate(self.rules):
                # print("处理 Rule {}".format(idx + 1))
                if curRule.protocol == IPv4 or curRule.protocol == header.protocol:
                    if header.src in curRule.src and header.dst in curRule.dst:
                        if (curRule.srcport is None or curRule.srcport == pkt[2].src) \
                            and (curRule.dstport is None or curRule.dstport == pkt[2].dst):
                            print("匹配到 Rule {}: {}".format(idx + 1, curRule))
                            # 检查 impair:
                            if curRule.impair == True:
                                return -1

                            # 检查 ratelimit:
                            if curRule.tokbucket is not None:
                                print("Rule {} 开始更新 timestamp.".format(idx + 1))
                                curRule.add_tokens(time.time())
                                pktLen = len(pkt) - len(pkt.get_header(Ethernet))
                                if pktLen <= curRule.tokbucket:
                                    print("pktLen: {}, curRule.tokbucket: {}; 足够, 允许转发.".format(pktLen, curRule.tokbucket))
                                    curRule.tokbucket -= pktLen
                                    return True
                                else:
                                    print("pktLen: {}, curRule.tokbucket: {}; 不够, 不允许转发.".format(pktLen, curRule.tokbucket))
                                    return False

                            return curRule.isPermit

            print("未匹配到 Rule.")
            return True
        elif pkt.has_header(Arp):
            print("收到 ARP")
            return True
        elif pkt.has_header(IPv6):
            print("收到 IPv6")
            return True

def main(net):
    # assumes that there are exactly 2 ports
    portnames = [ p.name for p in net.ports() ]
    portpair = dict(zip(portnames, portnames[::-1]))
    print("portnames: ", portnames)
    print("portpair: ", portpair)

    print(IPv4Address('149.43.80.25') in IPv4Network('149.43.80.25', strict=False))

    r = Rules("./firewall_rules.txt")

    while True:
        input_port, pkt = None, None
        try:
            timestamp, input_port, pkt = net.recv_packet(timeout=0.5)
        except NoPackets:
            pass
        except Shutdown:
            break

        if pkt is not None:
            # This is logically where you'd include some  firewall
            # rule tests.  It currently just forwards the packet
            # out the other port, but depending on the firewall rules
            # the packet may be dropped or mutilated.
            print("\nGot a packet (from {}): {}".format(input_port, pkt))

            curJudge = r.judge_permit(pkt)
            if curJudge == -1:
                import random
                # impairOpt = random.randint(1, 4) # 注意注意注意: 这里四个选项都实现了, 您可以让程序随机选择.
                impairOpt = 1
                if impairOpt == 1:
                    # 选项一: 设置概率(百分之十)丢包:
                    rand = random.uniform(0, 1)
                    if rand < 0.1:
                        print("impair 选项一: 丢包, rand: {}".format(rand))
                        continue
                    else:
                        print("impair 选项一: 未丢包")
                else:
                    def case2(pkt):
                        # Rewrite/overwrite the TCP advertised window to make it smaller.
                        if pkt.has_header(IPv4):
                            print("impair 选项二: TCP window: {}".format(pkt[2].window))
                            pkt[2].window = int(pkt[2].window * 0.6)

                        return pkt

                    def case3(pkt):
                        # Rewrite/overwrite the application payload contents of packets.
                        if pkt.has_header(IPv4) and pkt.get_header(IPv4).protocol == IPProtocol.TCP and pkt.has_header(RawPacketContents):
                            rand = random.uniform(0, 1)
                            if rand < 0.1:
                                print("impair 选项三 TCP 被改动.")
                                print("修改前:")
                                print(pkt)
                                hdr = pkt.get_header(RawPacketContents)
                                seqNum = int.from_bytes(hdr.data[:4], 'big')
                                from base64 import b64encode
                                payload = b64encode(hdr.data[6:]).decode('utf-8')
                                print("impair 选项三 pkt 解析: \nseqNum: {}, payload: {}".format(seqNum, payload))

                                payloadByte = hdr.data[6:]
                                # 如果不够长要padding:
                                if len(payloadByte) < 8:
                                    payloadByte += "\0".encode() * (8 - len(payloadByte))
                                payloadByte = payloadByte[0:8] + "China_Niu!_(zyk)".encode()

                                pkt = pkt.get_header(Ethernet) + pkt.get_header(IPv4) + pkt[2] + seqNum.to_bytes(4, 'big') + payloadByte

                                print("修改后:")
                                print(pkt)

                        return pkt

                    def case4(pkt):
                        # Randomly inject TCP RST packets to reset (and take down) traffic flows.
                        if pkt.has_header(IPv4) and pkt.get_header(IPv4).protocol == IPProtocol.TCP:
                            rand = random.uniform(0, 1)
                            if rand < 0.01:
                                print("RST 被改动.")
                                pkt[2].RST = True

                        return pkt

                    switch = {
                        2: case2,
                        3: case3,
                        4: case4
                    }

                    pkt = switch[impairOpt](pkt)
                print("impair 准备发送: ", pkt)
                net.send_packet(portpair[input_port], pkt)

            elif curJudge == True:
                net.send_packet(portpair[input_port], pkt)

    net.shutdown()

