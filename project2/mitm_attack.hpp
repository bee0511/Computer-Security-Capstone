#include "utils.hpp"

// Define a struct for ARP header
typedef struct _arp_hdr arp_hdr;
struct _arp_hdr {
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

// Define some constants.
#define ETH_HDRLEN 14    // Ethernet header length
#define IP4_HDRLEN 20    // IPv4 header length
#define ARP_HDRLEN 28    // ARP header length
#define ARPOP_REQUEST 1  // Taken from <linux/if_arp.h>
