# Implement your ICMP receiver here
from scapy.all import *

def receive_packet(packet):
    if packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        ip_layer = packet[IP]

        if ip_layer.ttl == 1 and icmp_layer.type == 8:
            icmp_layer.show()  


if __name__ == "__main__": 
	t = AsyncSniffer(filter="icmp", prn=receive_packet, count=1)
	t.start()
	t.join() 
