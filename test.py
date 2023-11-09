import scapy.all as scapy
import ipaddress

def generate_range(ip1_str, ip2_str):
    ip1_int = int(ipaddress.IPv4Address(ip1_str))
    ip2_int = int(ipaddress.IPv4Address(ip2_str))

    for ip in range(ip1_int, ip2_int+1):
        ip_str = str(ipaddress.IPv4Address(ip))

        ip = scapy.IP(dst="127.0.0.1")
        udp = scapy.UDP(sport=67, dport=68)
        bootp = scapy.BOOTP(op=2, yiaddr=ip_str)
        dhcp = scapy.DHCP(options=[("message-type", "ack"),('lease_time', 3600),"end"])
        
        scapy.send(ip/udp/bootp/dhcp)


def send_udp(port):
    scapy.send(scapy.IP(dst="127.0.0.1")/scapy.UDP(dport=port)/scapy.Raw(load="udp"))
    print("Packet type = UDP")


def send_tcp(port):
    scapy.send(scapy.IP(dst='127.0.0.1')/scapy.TCP(dport=port)/scapy.Raw(load="tcp"))
    print("Packet type = TCP")


def send_dhcp(ip_str, dhcp_type):
    ip = scapy.IP(dst="127.0.0.1")
    udp = scapy.UDP(sport=67, dport=68)
    bootp = scapy.BOOTP(op=2, yiaddr=ip_str)
    dhcp = scapy.DHCP(options=[('lease_time', 120), ('renewal_time', 60), ("message-type", dhcp_type),"end"])

    scapy.send(ip/udp/bootp/dhcp)


def test_01():
    # 192.168.0.0/22 1022 123 12.04%
    # 192.168.1.0/24 254 123 48.43%
    # 172.16.32.0/24 254 15 5.91%

    generate_range("192.168.1.1", "192.168.1.123")
    generate_range("172.16.32.1", "172.16.32.15")

def test_02():
    # 192.168.0.0/22 1022 24 2.35%
    # 192.168.1.0/24 254 12 4.72%
    # 172.16.32.0/24 254 0 0.00%

    generate_range("192.168.1.1", "192.168.1.12")
    generate_range("192.168.3.1", "192.168.3.12")

def test_03():
    # 192.168.0.0/22 1022 0 0.00%
    # 192.168.1.0/24 254 0 0.00%
    # 172.16.32.0/24 254 130 51.18%

    generate_range("172.16.32.1", "172.16.32.130")


def test_04():
    # 192.168.0.0/22 1022 11 1.08%
    # 192.168.1.0/24 254 5 1.97%
    # 172.16.32.0/24 254 133 52.36%

    send_dhcp("192.168.1.1", "discover")
    send_dhcp("192.168.1.1", "offer")
    send_dhcp("192.168.1.1", "request")
    send_dhcp("192.168.1.1", "ack")
    send_tcp(68)
    generate_range("192.168.1.1", "192.168.1.5")
    send_dhcp("192.168.1.5", "ack")
    send_tcp(68)
    send_dhcp("172.16.32.1", "discover")
    send_dhcp("172.16.32.1", "offer")
    send_dhcp("172.16.32.1", "request")
    send_dhcp("172.16.32.1", "ack")
    send_udp(68)
    generate_range("192.168.3.1", "192.168.3.5")
    send_dhcp("184.132.17.1", "ack")
    send_dhcp("194.232.17.1", "ack")
    generate_range("172.16.32.1", "172.16.32.127")
    send_tcp(68)
    send_dhcp("172.16.32.127", "ack")
    send_dhcp("172.16.32.128", "ack")
    generate_range("172.16.32.128", "172.16.32.133")
    send_udp(68)
    send_dhcp("0.0.0.0", "ack")
    send_dhcp("255.255.255.255", "ack")
    send_tcp(68)
    send_dhcp("192.168.3.166", "request")
    send_dhcp("192.168.3.166", "ack")
    send_dhcp("192.168.4.15", "request")
    send_dhcp("192.168.4.15", "ack")

def test_05():
    # 192.168.1.10/24 254 15 5.91%

    generate_range("192.168.1.1", "192.168.1.15")

# test_01()
# test_02()
# test_03()
# test_04()
test_05()