from scapy.all import *

def receive_packet(packet):
    if packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        ip_layer = packet[IP]

        if ip_layer.ttl == 1 and icmp_layer.type == 8:  
            print("Received ICMP request packet:")
            icmp_layer.show()  

def main():
    print("Listening for ICMP packet...")
    t = AsyncSniffer(filter="icmp", prn=receive_packet, count=1)
    t.start()
    t.join() 

if __name__ == "__main__":
    main()
