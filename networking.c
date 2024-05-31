#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>

// Function to get the active interface
int get_active_interface(char *iface_name, char *ip_str, char *netmask_str) {
    struct ifaddrs *ifaddr, *ifa;
    int family, s;
    char host[NI_MAXHOST], netmask[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET) {
            s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                            host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                return -1;
            }
            s = getnameinfo(ifa->ifa_netmask, sizeof(struct sockaddr_in),
                            netmask, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                return -1;
            }
            if (strncmp(host, "192.168.45", 10) == 0) { // 현재 IP 대역대에 맞게 수정
                strcpy(iface_name, ifa->ifa_name);
                strcpy(ip_str, host);
                strcpy(netmask_str, netmask);
                freeifaddrs(ifaddr);
                return 0;
            }
        }
    }

    freeifaddrs(ifaddr);
    return -1;
}

// Function to get the gateway IP
int get_gateway_ip(char *gateway_ip) {
    FILE *fp;
    char line[100], *p, *c, *g;

    fp = fopen("/proc/net/route", "r");
    if (fp == NULL) {
        perror("fopen");
        return -1;
    }

    while (fgets(line, 100, fp)) {
        p = strtok(line, "\t");
        c = strtok(NULL, "\t");
        g = strtok(NULL, "\t");
        if (c != NULL && strcmp(c, "00000000") == 0) {
            sprintf(gateway_ip, "%d.%d.%d.%d",
                    (int) strtol(g + 6, NULL, 16),
                    (int) strtol(g + 4, NULL, 16),
                    (int) strtol(g + 2, NULL, 16),
                    (int) strtol(g, NULL, 16));
            fclose(fp);
            return 0;
        }
    }

    fclose(fp);
    return -1;
}

// Function to get the MAC address of the gateway
int get_gateway_mac(const char *gateway_ip, char *gateway_mac, const char *iface_name) {
    struct ether_header *eth_hdr;
    struct ether_arp *arp_hdr;
    u_char packet[42];
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[50];
    struct pcap_pkthdr header;
    const u_char *received_packet;
    struct in_addr addr;

    addr.s_addr = inet_addr(gateway_ip);

    handle = pcap_open_live(iface_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", iface_name, errbuf);
        return -1;
    }

    eth_hdr = (struct ether_header *) packet;
    memset(eth_hdr->ether_dhost, 0xff, ETH_ALEN);  // Broadcast
    memset(eth_hdr->ether_shost, 0, ETH_ALEN);     // We'll fill this later
    eth_hdr->ether_type = htons(ETH_P_ARP);

    arp_hdr = (struct ether_arp *) (packet + sizeof(struct ether_header));
    arp_hdr->ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr->ea_hdr.ar_pro = htons(ETH_P_IP);
    arp_hdr->ea_hdr.ar_hln = ETHER_ADDR_LEN;
    arp_hdr->ea_hdr.ar_pln = 4;
    arp_hdr->ea_hdr.ar_op = htons(ARPOP_REQUEST);

    memset(arp_hdr->arp_tha, 0, ETH_ALEN);
    memcpy(arp_hdr->arp_tpa, &addr.s_addr, 4);
    memset(arp_hdr->arp_sha, 0, ETH_ALEN);         // We'll fill this later
    memset(arp_hdr->arp_spa, 0, 4);                // We'll fill this later

    // Get our MAC and IP addresses
    struct ifreq ifr;
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ - 1);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) == 0) {
        memcpy(eth_hdr->ether_shost, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
        memcpy(arp_hdr->arp_sha, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    } else {
        perror("ioctl");
        return -1;
    }

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) == 0) {
        struct sockaddr_in *ipaddr = (struct sockaddr_in *) &ifr.ifr_addr;
        memcpy(arp_hdr->arp_spa, &ipaddr->sin_addr, 4);
    } else {
        perror("ioctl");
        return -1;
    }

    close(sockfd);

    if (pcap_compile(handle, &fp, "arp", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }

    if (pcap_sendpacket(handle, packet, sizeof(packet)) != 0) {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(handle));
        return -1;
    }

    while ((received_packet = pcap_next(handle, &header)) != NULL) {
        struct ether_header *recv_eth_hdr = (struct ether_header *) received_packet;
        if (ntohs(recv_eth_hdr->ether_type) == ETH_P_ARP) {
            struct ether_arp *recv_arp_hdr = (struct ether_arp *) (received_packet + sizeof(struct ether_header));
            if (ntohs(recv_arp_hdr->ea_hdr.ar_op) == ARPOP_REPLY &&
                memcmp(recv_arp_hdr->arp_spa, &addr.s_addr, 4) == 0) {
                sprintf(gateway_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                        recv_arp_hdr->arp_sha[0], recv_arp_hdr->arp_sha[1],
                        recv_arp_hdr->arp_sha[2], recv_arp_hdr->arp_sha[3],
                        recv_arp_hdr->arp_sha[4], recv_arp_hdr->arp_sha[5]);
                pcap_close(handle);
                return 0;
            }
        }
    }

    pcap_close(handle);
    return -1;
}

// Function to scan the network
void scan_network(const char *network, const char *iface_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct bpf_program fp;
    char filter_exp[50];
    struct pcap_pkthdr header;
    const u_char *packet;
    struct ether_arp *arp_hdr;

    handle = pcap_open_live(iface_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", iface_name, errbuf);
        return;
    }

    snprintf(filter_exp, sizeof(filter_exp), "arp and src net %s", network);

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return;
    }

    printf("IP Address\t\tMAC Address\n");
    printf("-----------------------------------------\n");

    while ((packet = pcap_next(handle, &header)) != NULL) {
        struct ether_header *eth_hdr = (struct ether_header *) packet;
        if (ntohs(eth_hdr->ether_type) == ETH_P_ARP) {
            arp_hdr = (struct ether_arp *) (packet + sizeof(struct ether_header));
            printf("%s\t\t%02x:%02x:%02x:%02x:%02x:%02x\n",
                   inet_ntoa(*(struct in_addr *) arp_hdr->arp_spa),
                   arp_hdr->arp_sha[0], arp_hdr->arp_sha[1],
                   arp_hdr->arp_sha[2], arp_hdr->arp_sha[3],
                   arp_hdr->arp_sha[4], arp_hdr->arp_sha[5]);
        }
    }

    pcap_close(handle);
}

int main() {
    char iface_name[IFNAMSIZ], ip_str[NI_MAXHOST], netmask_str[NI_MAXHOST];
    char gateway_ip[NI_MAXHOST], gateway_mac[18];
    char network_prefix[NI_MAXHOST];

    if (get_active_interface(iface_name, ip_str, netmask_str) != 0) {
        fprintf(stderr, "Failed to get active interface\n");
        return 1;
    }

    if (get_gateway_ip(gateway_ip) != 0) {
        fprintf(stderr, "Failed to get gateway IP\n");
        return 1;
    }

    if (get_gateway_mac(gateway_ip, gateway_mac, iface_name) != 0) {
        fprintf(stderr, "Failed to get gateway MAC\n");
        return 1;
    }

    struct in_addr ip_addr, netmask_addr, network_addr;
    inet_aton(ip_str, &ip_addr);
    inet_aton(netmask_str, &netmask_addr);
    network_addr.s_addr = ip_addr.s_addr & netmask_addr.s_addr;
    inet_ntop(AF_INET, &network_addr, network_prefix, sizeof(network_prefix));

    printf("Gateway IP: %s\n", gateway_ip);
    printf("Gateway MAC: %s\n", gateway_mac);
    printf("Network Prefix: %s\n", network_prefix);

    scan_network(network_prefix, iface_name);

    return 0;
}
