from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import sys

def sniff_packets():
    def process_packet(packet):
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            proto = ip_layer.proto
            proto_str = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, str(proto))
            summary = f"IP {ip_layer.src} -> {ip_layer.dst} | Protocol: {proto_str} | TTL: {ip_layer.ttl}"
            
            if packet.haslayer(TCP):
                tcp_layer = packet.getlayer(TCP)
                summary += f" | TCP {tcp_layer.sport} -> {tcp_layer.dport} | Flags: {tcp_layer.flags}"
            
            if packet.haslayer(UDP):
                udp_layer = packet.getlayer(UDP)
                summary += f" | UDP {udp_layer.sport} -> {udp_layer.dport}"
            
            if packet.haslayer(ICMP):
                icmp_layer = packet.getlayer(ICMP)
                summary += f" | ICMP Type: {icmp_layer.type} Code: {icmp_layer.code}"
            
            print(summary)

            if packet.haslayer(Raw):
                raw_layer = packet.getlayer(Raw)
                raw_data = raw_layer.load
                hex_data = ' '.join(f'{byte:02x}' for byte in raw_data)
                printable_data = ''.join((chr(byte) if 32 <= byte <= 126 else '.') for byte in raw_data)
                print(f"Raw Data (Hex): {hex_data}")
                print(f"Raw Data (ASCII): {printable_data}")
                print("")

    print("Starting packet sniffing...")
    # Filter for broadcast and multicast packets
    sniff(filter="broadcast or multicast", prn=process_packet, store=0)

if __name__ == '__main__':
    sniff_packets()
