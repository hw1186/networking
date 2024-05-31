from scapy.all import *
from scapy.layers.l2 import ARP, Ether
import netifaces as ni
import ipaddress

def get_active_interface():
    interfaces = ni.interfaces()
    for iface in interfaces:
        if ni.AF_INET in ni.ifaddresses(iface):
            iface_info = ni.ifaddresses(iface)[ni.AF_INET][0]
            if 'addr' in iface_info and iface_info['addr'].startswith('192.168.0'):
                return iface, iface_info['addr'], iface_info['netmask']

def get_gateway_ip():
    gateways = ni.gateways()
    default_gateway = gateways['default'][ni.AF_INET][0]
    return default_gateway

def get_network_prefix(ip, netmask):
    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
    return network

def get_gateway_mac(gateway_ip):
    arp_request = ARP(pdst=gateway_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=5, retry=3, verbose=False)[0]

    for element in answered_list:
        return element[1].hwsrc

def scan_network(network):
    arp_request = ARP(pdst=str(network))
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = srp(arp_request_broadcast, timeout=5, retry=3, verbose=False)[0]

    devices = []
    for element in answered_list:
        device = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
        devices.append(device)
    return devices

def main():
    iface, ip, netmask = get_active_interface()
    gateway_ip = get_gateway_ip()
    network = get_network_prefix(ip, netmask)
    gateway_mac = get_gateway_mac(gateway_ip)
    
    print(f"Gateway IP: {gateway_ip}")
    print(f"Gateway MAC: {gateway_mac}")
    print(f"Network Prefix: {network}")

    devices = scan_network(network)
    
    print("IP Address\t\tMAC Address")
    print("-----------------------------------------")
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}")

if __name__ == "__main__":
    main()
