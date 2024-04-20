#include "arp.hpp"

#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

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
#define IP4_HDRLEN 20    // IPv4 header length

bool modifyPacket(uint8_t *buffer, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);
void sendMarkedPacket(uint8_t *buffer, int bytes, int sd, struct LocalInfo local_info);
void receiveHandler(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);