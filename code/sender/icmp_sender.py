from scapy.all import *

# Implement your ICMP sender here
def send_icmp_request(target_ip):
    icmp_packet = IP(dst=target_ip)/ICMP()

    sr1(icmp_packet, ttl=1)

if __name__ == "__main__":
    target_ip = "receiver"
    send_icmp_request(target_ip)






