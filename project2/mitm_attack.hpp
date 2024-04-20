#include "arp.hpp"

#include <arpa/inet.h>
#include <netinet/tcp.h>

bool modifyPacket(uint8_t *buffer, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);
void sendNonHttpPostPacket(uint8_t *buffer, int bytes, int sd, struct LocalInfo local_info);
void printUsernameAndPassword(uint8_t *payload, int payload_length);
void receiveHandler(int sd, std::map<std::array<uint8_t, 4>, std::array<uint8_t, 6>> &ip_mac_pairs, struct LocalInfo local_info);