#include "local.hpp"

// Define a struct for ARP header
struct arp_hdr {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    std::array<uint8_t, 6> sender_mac;
    std::array<uint8_t, 4> sender_ip;
    std::array<uint8_t, 6> target_mac;
    std::array<uint8_t, 4> target_ip;
};

// Define a struct for local info
struct LocalInfo {
    std::array<uint8_t, 6> src_mac;
    struct sockaddr_in src_ip;
    struct sockaddr_in netmask;
    struct sockaddr_in gateway_ip;
    struct sockaddr_ll device;
};

// Define some constants.
#define ETH_HDRLEN 14    // Ethernet header length
#define IP4_HDRLEN 20    // IPv4 header length
#define ARP_HDRLEN 28    // ARP header length
#define ARPOP_REQUEST 1  // Taken from <linux/if_arp.h>

void parseARPReply(uint8_t *buffer, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);
bool modifyPacket(uint8_t *buffer, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);
void sendNonHttpPostPacket(uint8_t *buffer, int bytes, int sd, struct LocalInfo local_info);
void printUsernameAndPassword(uint8_t *payload, int payload_length);
void receiveHandler(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);
void sendSpoofedARPReply(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);
void sendARPRequest(int sd, struct LocalInfo local_info);