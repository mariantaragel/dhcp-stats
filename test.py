import scapy.all as scapy

def send_dhcp(yiaddr):
    ip = scapy.IP(dst="127.0.0.1")
    udp = scapy.UDP(sport=67, dport=68)
    bootp = scapy.BOOTP(op=2, yiaddr=yiaddr)
    dhcp = scapy.DHCP(options=[("message-type", "ack"),"end"])

    scapy.send(ip/udp/bootp/dhcp)

send_dhcp("192.168.3.1")