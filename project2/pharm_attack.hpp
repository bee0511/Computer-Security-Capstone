#include "arp.hpp"

#include <arpa/inet.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <csignal>
#include <string>
#include <vector>

struct NFQData{
  struct LocalInfo local_info;
  std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> ip_mac_pairs;
};

struct dnshdr {
  uint16_t id;        // identification number
  uint16_t flags;     // DNS flags
  uint16_t qd_count;  // number of question entries
  uint16_t ans_cnt;   // number of answer entries
  uint16_t authrr_cnt;// number of authority entries
  uint16_t addrr_cnt; // number of resource entries
};

struct __attribute__((packed, aligned(2))) resphdr {
  uint16_t name;
  uint16_t type;
  uint16_t cls; // class
  uint32_t ttl;
  uint16_t len;
};


// Define some constants.
#define ETH2_HEADER_LEN 14

bool modifyPacket(uint8_t *buffer, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);
void sendMarkedPacket(uint8_t *buffer, int bytes, int sd, struct LocalInfo local_info);
void receiveHandler(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);