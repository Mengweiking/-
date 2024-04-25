from scapy.all import *


def port_scan(ip, ports):
    for port in ports:
        # 构造TCP SYN包
        pkt = IP(dst=ip) / TCP(dport=port, flags='S')

        # 发送并接收数据包
        ans = sr1(pkt, timeout=2, verbose=0)

        # 检查返回的数据包
        if ans is not None:
            if ans.haslayer(TCP) and ans[TCP].flags & 0x12 == 0x12:
                print(f"Port {port} on {ip} is OPEN")
            elif ans.haslayer(TCP) and ans[TCP].flags & 0x14 == 0x14:
                print(f"Port {port} on {ip} is CLOSED")
        else:
            print(f'Port {port} on {ip} is UNKNOWN')


# 使用函数
ports_to_scan = [21, 22, 80, 135, 443, 445, 1025, 1026, 1027]  # 需要扫描的端口列表
# target_ip = "192.168.174.145"  # 需要扫描的目标IP地址
target_ip = "10.34.5.97"  # 需要扫描的目标IP地址
port_scan(target_ip, ports_to_scan)


