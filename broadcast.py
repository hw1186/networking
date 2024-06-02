from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP

def sniff_packets():
    def process_packet(packet):
        print("=== New Packet ===")
        if packet.haslayer(IP):
            ip_layer = packet.getlayer(IP)
            print(f"IP {ip_layer.src} -> {ip_layer.dst}")
            print(f"TTL: {ip_layer.ttl}")
            print(f"IP ID: {ip_layer.id}")
            print(f"IP Flags: {ip_layer.flags}")
            print(f"IP Fragment Offset: {ip_layer.frag}")
            print(f"IP Protocol: {ip_layer.proto}")
        
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            print(f"TCP {tcp_layer.sport} -> {tcp_layer.dport}")
            print(f"Sequence Number: {tcp_layer.seq}")
            print(f"Acknowledgment Number: {tcp_layer.ack}")
            print(f"Flags: {tcp_layer.flags}")
            print(f"Window Size: {tcp_layer.window}")
            print(f"Urgent Pointer: {tcp_layer.urgptr}")

        if packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            print(f"UDP {udp_layer.sport} -> {udp_layer.dport}")
            print(f"Length: {udp_layer.len}")
            print(f"Checksum: {udp_layer.chksum}")

        if packet.haslayer(ICMP):
            icmp_layer = packet.getlayer(ICMP)
            print(f"ICMP Type: {icmp_layer.type} Code: {icmp_layer.code}")
            print(f"ICMP ID: {icmp_layer.id} Sequence: {icmp_layer.seq}")

        # Print raw payload data if available
        if packet.haslayer(Raw):
            raw_layer = packet.getlayer(Raw)
            raw_data = raw_layer.load
            # Convert raw data to a hex dump
            hex_data = ' '.join(f'{byte:02x}' for byte in raw_data)
            # Convert raw data to printable ASCII characters, replace non-printable with '.'
            printable_data = ''.join((chr(byte) if 32 <= byte <= 126 else '.') for byte in raw_data)
            print(f"Raw Data (Hex): {hex_data}")
            print(f"Raw Data (ASCII): {printable_data}")

    print("Starting packet sniffing...")
    # Filter for broadcast and multicast packets
    sniff(filter="broadcast or multicast", prn=process_packet, store=0)

if __name__ == '__main__':
    sniff_packets()
