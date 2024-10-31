from scapy.all import *

# Implement your ICMP sender here
def send_icmp_request(target_ip):
    icmp_packet = IP(dst=target_ip, ttl=1)/ICMP()
    sr1(icmp_packet, timeout=1)

if __name__ == "__main__":
    target_ip = "receiver"
    send_icmp_request(target_ip)






