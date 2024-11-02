# Implement your ICMP sender here
from scapy.all import *

# Implement your ICMP sender here
def send_icmp_request(target_ip):
    icmp_packet = IP(dst=target_ip, ttl=1)/ICMP()
    sr1(icmp_packet)


target_ip = "receiver"
send_icmp_request(target_ip)





