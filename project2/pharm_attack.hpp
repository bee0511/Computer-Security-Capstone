#include "local.hpp"

#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/if_arp.h>
#include <linux/netfilter.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <map>
#include <thread>

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

struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

struct dns_query {
    uint16_t qtype;
    uint16_t qclass;
};

struct dns_answer {
    uint16_t name;
    uint16_t type;
    uint16_t class_type;
    uint32_t ttl;
    uint16_t rdlength;
    uint32_t rdata;
};

// Define some constants.
#define ETH_HDRLEN 14    // Ethernet header length
#define IP4_HDRLEN 20    // IPv4 header length
#define ARP_HDRLEN 28    // ARP header length
#define ARPOP_REQUEST 1  // Taken from <linux/if_arp.h>

void parseARPReply(uint8_t *buffer, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);
bool modifyPacket(uint8_t *buffer, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);
void sendPacket(uint8_t *buffer, int bytes, int sd, struct LocalInfo local_info);
void receiveHandler(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);
void sendSpoofedARPReply(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);
void sendARPRequest(int sd, struct LocalInfo local_info);