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
        

generate_range("192.168.1.1", "192.168.1.123")