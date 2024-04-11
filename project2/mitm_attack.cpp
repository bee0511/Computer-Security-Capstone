#include "mitm_attack.hpp"

// #define DEBUG 1

uint8_t *cal_base_ip(uint8_t *ip, sockaddr_in *netmask) {
    // return base ip
    uint8_t *base_ip = (uint8_t *)malloc(4 * sizeof(uint8_t));
    uint8_t *mask_addr = (uint8_t *)&netmask->sin_addr.s_addr;
    for (int i = 0; i < 4; i++) {
        base_ip[i] = ip[i] & mask_addr[i];
    }
    return base_ip;
}

void get_default_gateway(uint8_t gateway_ip[4]) {
    FILE *fp = fopen("gateway.txt", "r");
    if (fp == nullptr) {
        perror("fopen() failed");
        exit(EXIT_FAILURE);
    }

    int res = fscanf(fp, "%hhu.%hhu.%hhu.%hhu", &gateway_ip[0], &gateway_ip[1], &gateway_ip[2], &gateway_ip[3]);
    if (res != 4) {
        perror("fscanf() failed");
        exit(EXIT_FAILURE);
    }

    fclose(fp);
}

int main(int argc, char **argv) {
    char *interface;
    int i, frame_length, sd, bytes;
    arp_hdr arphdr;
    uint8_t src_ip[4], src_mac[6], dst_mac[6], ether_frame[IP_MAXPACKET];
    struct sockaddr_in *ipv4;
    struct sockaddr_ll device;
    struct ifreq ifr;
    struct sockaddr_in *netmask;

    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Interface to send packet through.
    interface = argv[1];

    // Submit request for a socket descriptor to look up interface.
    if ((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket() failed to get socket descriptor for using ioctl()");
        exit(EXIT_FAILURE);
    }

    // Use ioctl() to look up interface name and get its IPv4 address.
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl() failed to get source IP address");
        return (EXIT_FAILURE);
    }

    // Copy source IP address.
    ipv4 = (struct sockaddr_in *)&ifr.ifr_addr;
    memcpy(src_ip, &ipv4->sin_addr, 4 * sizeof(uint8_t));

    // Use ioctl() to look up interface name and get its MAC address.
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl() failed to get source MAC address");
        return (EXIT_FAILURE);
    }
    // Copy source MAC address.
    memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));

    // Use ioctl() to look up interface name and get its netmask.
    if (ioctl(sd, SIOCGIFNETMASK, &ifr) < 0) {
        perror("ioctl() failed to get netmask");
        exit(EXIT_FAILURE);
    }

    // Copy netmask.
    netmask = (struct sockaddr_in *)&ifr.ifr_netmask;

    close(sd);

    uint8_t *base_ip = cal_base_ip(src_ip, netmask);
    // Find interface index from interface name and store index in
    // struct sockaddr_ll device, which will be used as an argument of sendto().
    if ((device.sll_ifindex = if_nametoindex(interface)) == 0) {
        perror("if_nametoindex() failed to obtain interface index");
        exit(EXIT_FAILURE);
    }
#ifdef DEBUG
    printf("Netmask: %s\n", inet_ntoa(netmask->sin_addr));
    printf("Base IP: %d.%d.%d.%d\n", base_ip[0], base_ip[1], base_ip[2], base_ip[3]);
    // Report source MAC address to stdout.
    printf("MAC address for interface %s is ", interface);
    for (i = 0; i < 5; i++) {
        printf("%02x:", src_mac[i]);
    }
    printf("%02x\n", src_mac[5]);

    printf("Index for interface %s is %i\n", interface, device.sll_ifindex);
#endif

    // Set destination MAC address: broadcast address
    memset(dst_mac, 0xff, 6 * sizeof(uint8_t));

    memcpy(&arphdr.sender_ip, src_ip, 4 * sizeof(uint8_t));

    // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    memcpy(device.sll_addr, src_mac, 6 * sizeof(uint8_t));
    device.sll_halen = htons(6);

    // ARP header

    // Hardware type (16 bits): 1 for ethernet
    arphdr.htype = htons(1);

    // Protocol type (16 bits): 2048 for IP
    arphdr.ptype = htons(ETH_P_IP);

    // Hardware address length (8 bits): 6 bytes for MAC address
    arphdr.hlen = 6;

    // Protocol address length (8 bits): 4 bytes for IPv4 address
    arphdr.plen = 4;

    // OpCode: 1 for ARP request
    arphdr.opcode = htons(ARPOP_REQUEST);

    // Sender hardware address (48 bits): MAC address
    memcpy(&arphdr.sender_mac, src_mac, 6 * sizeof(uint8_t));

    // Target hardware address (48 bits): zero
    memset(&arphdr.target_mac, 0, 6 * sizeof(uint8_t));

    // Fill out ethernet frame header.

    // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
    frame_length = 6 + 6 + 2 + ARP_HDRLEN;

    // Destination and Source MAC addresses
    memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
    memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

    // Next is ethernet type code (ETH_P_ARP for ARP).
    // http://www.iana.org/assignments/ethernet-numbers
    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;

    // Next is ethernet frame data (ARP header).

    // Submit request for a raw socket descriptor.
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    uint8_t gateway_ip[4];
    get_default_gateway(gateway_ip);

    for (uint8_t i = base_ip[3] + 1; i < 255; i++) {
        uint8_t dest_ip[4] = {base_ip[0], base_ip[1], base_ip[2], i};

        // If dest_ip is equal to gateway_ip, skip this iteration
        if (std::equal(dest_ip, dest_ip + 4, gateway_ip)) {
            continue;
        }

        std::copy(dest_ip, dest_ip + 4, arphdr.target_ip);
        // ARP header
        memcpy(ether_frame + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof(uint8_t));
        // Send ethernet frame to socket.
        if ((bytes = sendto(sd, ether_frame, frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0) {
            perror("sendto() failed");
            exit(EXIT_FAILURE);
        }
    }
    // Receive ARP responses
    printf("Available devices:\n");
    printf("-----------------------------\n");
    printf("IP\t\tMAC\n");
    printf("-----------------------------\n");
    while (true) {
        uint8_t buffer[IP_MAXPACKET];
        struct sockaddr saddr;
        int saddr_len = sizeof(saddr);

        // Receive packet
        bytes = recvfrom(sd, buffer, IP_MAXPACKET, 0, &saddr, (socklen_t *)&saddr_len);
        if (bytes < 0) {
            perror("recvfrom() failed");
            exit(EXIT_FAILURE);
        }

        // Check if packet is an ARP packet
        if (buffer[12] == ETH_P_ARP / 256 && buffer[13] == ETH_P_ARP % 256) {
            arp_hdr *arphdr = (arp_hdr *)(buffer + ETH_HDRLEN);

            // Check if ARP packet is a response
            if (ntohs(arphdr->opcode) == ARPOP_REPLY) {
                // Print source IP address
                printf("%d.%d.%d.%d\t", arphdr->sender_ip[0], arphdr->sender_ip[1], arphdr->sender_ip[2], arphdr->sender_ip[3]);
                // Print source MAC address
                for (i = 0; i < 5; i++) {
                    printf("%02x:", arphdr->sender_mac[i]);
                }
                printf("%02x\n", arphdr->sender_mac[5]);
            }
        }
    }
    // Close socket descriptor.
    close(sd);

    return (EXIT_SUCCESS);
}