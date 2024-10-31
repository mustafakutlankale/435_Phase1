from scapy.all import *

def receive_packet(packet):
    # Check if the packet has an ICMP layer
    if packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        ip_layer = packet[IP]

        # Print only the incoming ICMP request with TTL=1
        if ip_layer.ttl == 1 and icmp_layer.type == 8:  # Type 8 indicates an ICMP Echo Request
            print("Received ICMP request packet:")
            icmp_layer.show()  # Display detailed information about the packet

def main():
    print("Listening for ICMP packet...")
    #sniff(filter="icmp", prn=receive_packet)
    t = AsyncSniffer(filter="icmp", prn=receive_packet, count=1)
    t.start()
    t.join() 

if __name__ == "__main__":
    main()
