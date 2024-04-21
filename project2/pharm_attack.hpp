#include "arp.hpp"

#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <csignal>
#include <string>
#include <vector>

struct dnshdr {
  char id[2];
  char flags[2];
  char qdcount[2];
  char ancount[2];
  char nscount[2];
  char arcount[2];
};

struct dnsquery {
  char *qname;
  char qtype[2];
  char qclass[2];
};

struct ether_header {
    uint8_t ether_dhost[ETH_ALEN]; // 目標 MAC 位址
    uint8_t ether_shost[ETH_ALEN]; // 來源 MAC 位址
    uint16_t ether_type; // 乙太網路類型
};

// Define some constants.
#define IP4_HDRLEN 20    // IPv4 header length

bool modifyPacket(uint8_t *buffer, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);
void sendMarkedPacket(uint8_t *buffer, int bytes, int sd, struct LocalInfo local_info);
void receiveHandler(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);