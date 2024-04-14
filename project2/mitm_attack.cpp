#include "mitm_attack.hpp"

// #define DEBUG 1

int main(int argc, char **argv) {
    char *interface;
    struct ifreq ifr;
    struct sockaddr_ll device;
    int i, frame_length, sd, bytes;
    arp_hdr arphdr;
    struct sockaddr_in src_ip;
    struct sockaddr_in netmask;
    std::array<uint8_t, 6> src_mac;
    std::array<uint8_t, 6> dst_mac;
    std::array<uint8_t, IP_MAXPACKET> ether_frame;

    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Interface to send packet through.
    interface = argv[1];

    // Copy source IP address.
    get_src_IP(interface, src_ip);

    // Copy source MAC address.
    get_mac_address(interface, src_mac);

    // Copy netmask.
    get_netmask(interface, netmask);

    // Find interface index from interface name and store index in
    // struct sockaddr_ll device, which will be used as an argument of sendto().
    if ((device.sll_ifindex = if_nametoindex(interface)) == 0) {
        perror("if_nametoindex() failed to obtain interface index");
        exit(EXIT_FAILURE);
    }
#ifdef DEBUG
    printf("Netmask: %s\n", inet_ntoa(netmask.sin_addr));
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
    std::fill(dst_mac.begin(), dst_mac.end(), 0xff);

    // Copy IP address from sockaddr_in to sender_ip
    std::copy_n(reinterpret_cast<uint8_t *>(&src_ip.sin_addr.s_addr), 4, arphdr.sender_ip.begin());

    // Fill out sockaddr_ll.
    device.sll_family = AF_PACKET;
    std::copy(src_mac.begin(), src_mac.end(), device.sll_addr);
    device.sll_halen = htons(6);

    // ARP header
    arphdr.htype = htons(1);                                               // Hardware type (16 bits): 1 for ethernet
    arphdr.ptype = htons(ETH_P_IP);                                        // Protocol type (16 bits): 2048 for IP
    arphdr.hlen = 6;                                                       // Hardware address length (8 bits): 6 bytes for MAC address
    arphdr.plen = 4;                                                       // Protocol address length (8 bits): 4 bytes for IPv4 address
    arphdr.opcode = htons(ARPOP_REQUEST);                                  // OpCode: 1 for ARP request
    std::copy(src_mac.begin(), src_mac.end(), arphdr.sender_mac.begin());  // Sender hardware address (48 bits): MAC address
    arphdr.target_mac.fill(0);                                             // Target hardware address (48 bits): zero

    // Fill out ethernet frame header.
    frame_length = 6 + 6 + 2 + ARP_HDRLEN;  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)

    // Destination and Source MAC addresses
    std::copy(dst_mac.begin(), dst_mac.end(), ether_frame.begin());
    std::copy(src_mac.begin(), src_mac.end(), ether_frame.begin() + 6);

    // Ethernet type code (ETH_P_ARP for ARP).
    // http://www.iana.org/assignments/ethernet-numbers
    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;

    // Submit request for a raw socket descriptor.
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    uint32_t gateway_ip;
    get_default_gateway(gateway_ip);

    uint32_t base_ip_net = ntohl(src_ip.sin_addr.s_addr) & ntohl(netmask.sin_addr.s_addr);
    uint32_t mask_net = ntohl(~netmask.sin_addr.s_addr);

    for (uint32_t i = 1; i < mask_net; i++) {
        uint32_t dest_ip = htonl(base_ip_net | i);

        // If dest_ip is equal to gateway_ip, skip this iteration
        if (dest_ip == gateway_ip) {
            continue;
        }

        std::copy_n(reinterpret_cast<uint8_t*>(&dest_ip), 4, arphdr.target_ip.begin());
        // ARP header
        memcpy(ether_frame.data() + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof(uint8_t));
        // Send ethernet frame to socket.
        if ((bytes = sendto(sd, ether_frame.data(), frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0) {
            perror("sendto() failed");
            exit(EXIT_FAILURE);
        }
    }
    // Receive ARP responses
    printf("Available devices:\n");
    printf("-----------------------------\n");
    printf("IP\t\tMAC\n");
    printf("-----------------------------\n");

    // Use a table to save IP-MAC pairs
    // std::vector<std::pair<uint8_t *, uint8_t *>> ip_mac_pairs;
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
                // Save IP-MAC pair
                // ip_mac_pairs.push_back(std::make_pair(arphdr->sender_ip, arphdr->sender_mac));
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